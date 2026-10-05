-- resolvd §3.1 — subscription: the request resolvd writes on netd's
-- control socket, how it reads the stream, and every way the channel is
-- dropped. PSPU §6.9 `subscribe` (the request a resolver sends).
--
-- Harness: the scripted gateway (helpers.gateway) and a whole Peios
-- (helpers.network). The agent stands in for netd: netd's socket is
-- renamed aside (netd keeps running and keeps the lease, it just is not
-- at the path any more), the agent binds a listener of its own at
-- /run/netd/control.sock, and resolvd is restarted so that its first
-- attempt lands there. Every frame resolvd then reads is one the test
-- wrote, byte for byte, so the malformed, oversized, partial and refused
-- cases are all reachable. resolvd is read back through its native
-- socket (`status`) and its log (evctl).
--
-- Own VMs: resolvd is restarted onto a fake netd, and stays there. Once
-- netd's socket is aside, network.call/status without a `path` reach the
-- stand-in, not netd; nothing here asks netd anything after that.
--
-- Non-obvious: everything one test writes in a single write(2) is under
-- 8 KiB (one 64 KiB case aside), so resolvd takes it in one read — which
-- is what the "once the whole read has been taken" rules are about. A
-- dropped channel is reconnected 0.5 s later; a test that needs to see
-- resolvd disconnected closes the listener first, so that attempt fails.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local unixsock = require("helpers.unixsock")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")
local msgpack = require("helpers.msgpack")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
local sut = network.boot({ bridges = { lan }, gateway = gw })

local RSOCK = "/run/resolvd/resolv.sock"
local ASIDE = "/run/netd/control.pt-aside.sock"
local SOCK_SDDL = "O:SYG:SYD:(A;;GA;;;SY)(A;;GRGWGX;;;WD)"
local E = msgpack.array

-- ---- resolvd, read back ----------------------------------------------------

local function rstatus()
    local s, err = network.call(sut, { query = "status" }, { path = RSOCK })
    assert(s and s.ok, "resolvd status: " .. tostring(err or (s and s.error)))
    return s
end

--- The guest's wall clock in ns, the clock eventd stamps lines with.
local function now_ns()
    return assert(tonumber(sut:run("date +%s%N").stdout:match("%d+")), "guest clock")
end

--- resolvd's log lines after `since` (guest ns), oldest first, each
--- {ts, msg} with msg the whole line text (`resolvd: <level>: <text>`).
--- evctl lists newest first in the order eventd recorded them.
local function rlog(since)
    local r = sut:run("evctl 'LOGS FROM resolvd SINCE 1h ago TAKE 5000'")
    assert(r.exit_code == 0, "evctl: " .. r.stderr)
    local newest_first = {}
    for line in r.stdout:gmatch("[^\n]+") do
        local msg = line:match('message="(.-)"  origin=')
        local ts = tonumber(line:match("timestamp=(%d+)"))
        if msg and ts and ts > (since or 0) then
            newest_first[#newest_first + 1] = { ts = ts, msg = (msg:gsub("\\(.)", "%1")) }
        end
    end
    local out = {}
    for i = #newest_first, 1, -1 do out[#out + 1] = newest_first[i] end
    return out
end

local function find(lines, text, from)
    for i = from or 1, #lines do
        if lines[i].msg:find(text, 1, true) then return i end
    end
end

local function count(lines, text)
    local n = 0
    for _, l in ipairs(lines) do if l.msg:find(text, 1, true) then n = n + 1 end end
    return n
end

local function dump(t, lines)
    local out = {}
    for _, l in ipairs(lines) do out[#out + 1] = l.msg end
    t:log("resolvd log:\n" .. table.concat(out, "\n"))
end

local function names(st)
    local out = {}
    for _, s in ipairs(st.scopes or {}) do out[#out + 1] = s.interface end
    return table.concat(out, ",")
end

--- Wait until resolvd's status satisfies `pred`; returns it (or the last
--- one seen, and false).
local function status_until(pred, timeout)
    local last
    local ok = pcall(wait_until, function()
        last = rstatus()
        return pred(last)
    end, { timeout = timeout or 10, interval = 0.1, desc = "resolvd status" })
    return last, ok
end

-- ---- the stand-in netd -----------------------------------------------------

local fake = {}

--- Bind and listen at netd's path (replacing whatever file is there).
local function listen()
    sys.unlink(sut, network.CONTROL)
    local l = assert(unixsock.socket(sut, unixsock.AF_UNIX, unixsock.SOCK.STREAM))
    local r = unixsock.bind(sut, l, network.CONTROL)
    assert(r.ret == 0, "bind: " .. unixsock.errname(r.errno))
    -- netd's own descriptor on its socket (netd §9.1): without it the file
    -- inherits /run's SYSTEM-only one and resolvd's connect is refused.
    local sd = sut:run("sd set " .. network.CONTROL .. " '" .. SOCK_SDDL .. "'", { timeout = 15 })
    assert(sd.exit_code == 0, "sd set: " .. sd.stdout .. sd.stderr)
    r = unixsock.listen(sut, l, 16)
    assert(r.ret == 0, "listen: " .. unixsock.errname(r.errno))
    fake.l = l
end

--- Close the listener and remove the path: resolvd's attempts now fail.
local function unlisten()
    if fake.l then sys.close(sut, fake.l) end
    fake.l = nil
    sys.unlink(sut, network.CONTROL)
end

--- Read exactly `n` bytes from a connection (buffered), or nil, why.
local function read_n(c, n, timeout_ms)
    while #c.buf < n do
        local chunk, err = ntfe.recv(sut, c.fd, timeout_ms or 3000, 65536)
        if not chunk then return nil, tostring(err) end
        if #chunk == 0 then return nil, "closed" end
        c.buf = c.buf .. chunk
    end
    local out = c.buf:sub(1, n)
    c.buf = c.buf:sub(n + 1)
    return out
end

--- Wait for resolvd's next connection. Returns {fd, buf, at} with `at`
--- the guest wall clock when it arrived; `o.read` = false leaves the
--- request unread in the socket.
local function accept(timeout_ms, o)
    o = o or {}
    local ev = ntfe.poll(sut, fake.l, ntfe.POLLIN, timeout_ms or 15000)
    if ev == 0 then return nil, "no connection" end
    local at = sut:clock():get()
    local fd, e = unixsock.accept(sut, fake.l)
    if not fd then return nil, "accept: " .. unixsock.errname(e) end
    local c = { fd = fd, buf = "", at = at }
    if o.read ~= false then
        local head = read_n(c, 4)
        assert(head, "resolvd's request: no length")
        local body = assert(read_n(c, string.unpack("<I4", head)), "resolvd's request: short")
        c.request = head .. body
    end
    return c
end

--- Write `bytes`, in one write(2) when they fit in 8 KiB (every case
--- that depends on one read does), else in 8 KiB pieces.
local function send(c, bytes)
    local at = 1
    while at <= #bytes do
        local piece = bytes:sub(at, at + 8191)
        local r = ntfe.send(sut, c.fd, piece)
        assert(r.ret == #piece, "send: " .. tostring(r.ret) .. " errno " .. tostring(r.errno))
        at = at + #piece
    end
end

local function close(c) if c and c.fd then sys.close(sut, c.fd); c.fd = nil end end

--- Whether the connection has been closed by resolvd within `timeout_ms`.
local function closed_by_peer(c, timeout_ms)
    local deadline = sut:clock():get() + (timeout_ms or 3000) / 1000
    while sut:clock():get() < deadline do
        local chunk, err = ntfe.recv(sut, c.fd, 200, 65536)
        if chunk and #chunk == 0 then return true end
        if not chunk and err ~= "timeout" then return true end
        if chunk then c.buf = c.buf .. chunk end
    end
    return false
end

--- A frame: netd's framing of a table (msgpack) or of raw payload bytes.
local function frame(v)
    local p = type(v) == "string" and v or msgpack.encode(v)
    return string.pack("<I4", #p) .. p
end

--- A scope, netd's ten fields, defaults filled in.
local function scope(o)
    return {
        ifid = o.ifid or ("pt-ifid-" .. o.name), name = o.name,
        servers = E(o.servers or {}), domains = E(o.domains or {}), ntp = E({}),
        addresses = E(o.addresses or {}),
        default_route = o.default_route == true, exclusive = o.exclusive == true,
        metric = o.metric or 100, level = o.level or "routed",
    }
end

local function snapshot(scopes, hostname)
    return { ok = true, kind = "snapshot", hostname = hostname or "", scopes = E(scopes) }
end

--- One scope named `name` with one server: the shape most cases send.
local function marker(name, server)
    return snapshot({ scope({ name = name, servers = { server or "10.77.0.1" }, default_route = true }) })
end

local conn

--- (Re)attach resolvd to the stand-in: listen, restart resolvd, accept.
local function takeover(t)
    if not fake.moved then
        local r = sys.rename(sut, network.CONTROL, ASIDE)
        t:assert(r.ret == 0, "netd's socket moved aside: " .. sys.errname(r.errno or 0))
        fake.moved = true
    end
    listen()
    local since = now_ns()
    -- Not `svctl restart`: that leaves resolvd unable to bind its socket
    -- (PEI-1373).
    sut:run("svctl stop resolvd; rm -rf /run/resolvd; svctl start resolvd", { timeout = 30 }):assert_ok()
    local c, why = accept(15000)
    if not c then
        local d = sut:run("ls -la /run/netd /run/resolvd; sd show " .. ASIDE .. " --sddl; sd show "
            .. network.CONTROL .. " --sddl; svctl status resolvd", { timeout = 15 })
        t:log(d.stdout .. d.stderr)
        dump(t, rlog(since))
    end
    t:assert(c, "resolvd connected to the stand-in: " .. tostring(why))
    return c, since
end

-- ---------------------------------------------------------------------------

test("resolvd connects to /run/netd/control.sock, writes one framed {query: subscribe} and nothing after it, logs `subscribed to netd`, and holds the channel nonblocking",
    { spec = "resolvd *netd-subscribe.connect-and-send-subscribe resolvd *netd-subscribe.success-logged resolvd *netd-subscribe.writes-only-the-request PSPU *nri-manager.subscribe-request" },
    function(t)
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "netd bound")
        local since
        conn, since = takeover(t)
        local want = msgpack.encode({ query = "subscribe" })
        t:log("request bytes: " .. conn.request:gsub(".", function(ch) return string.format("%02x ", ch:byte()) end))
        t:assert_eq(conn.request, string.pack("<I4", #want) .. want,
            "a four-byte little-endian length, then the map {query: subscribe}")

        -- The first snapshot is an ordinary read on the channel.
        send(conn, frame(marker("pt-first")))
        local st = status_until(function(s) return names(s) == "pt-first" end)
        t:assert_eq(names(st), "pt-first", "the first snapshot applied")
        t:assert_eq(st.netd, true, "status: netd connected")

        local lines = rlog(since)
        dump(t, lines)
        local sub = find(lines, "subscribed to netd")
        t:assert(sub, "`subscribed to netd` logged")
        t:assert(lines[sub].msg:find("info: subscribed to netd", 1, true), "at info level: " .. lines[sub].msg)

        -- Several snapshots later, resolvd has still written nothing more.
        for i = 1, 3 do
            send(conn, frame(marker("pt-more" .. i)))
            status_until(function(s) return names(s) == "pt-more" .. i end)
        end
        local extra, why = ntfe.recv(sut, conn.fd, 2000, 65536)
        t:assert(extra == nil and why == "timeout",
            "resolvd wrote nothing after the request (" .. tostring(why) .. ", " .. tostring(extra and #extra) .. " bytes)")
        t:assert_eq(#conn.buf, 0, "and nothing is left unread from it")

        -- Nonblocking: the channel is resolvd's one socket that goes away
        -- when the channel is dropped. Read every socket's flags now, drop
        -- the channel with the listener gone (so no reconnection), and see
        -- which one went.
        local pid = assert(peinit.pid_of_comm(sut, "resolvd"), "resolvd's pid")
        local function sockets()
            local out = {}
            for fd, target in pairs(peinit.fds(sut, pid)) do
                if target:match("^socket:") then
                    local info = sut:read_file("/proc/" .. pid .. "/fdinfo/" .. fd)
                    out[target] = tonumber(info:match("flags:%s*(%d+)"), 8)
                end
            end
            return out
        end
        local before = sockets()
        unlisten()
        close(conn)
        status_until(function(s) return s.netd == false end)
        local after = sockets()
        local gone = {}
        for k, flags in pairs(before) do if after[k] == nil then gone[#gone + 1] = { k, flags } end end
        t:log("sockets that went with the channel: " .. json.encode(gone))
        t:assert_eq(#gone, 1, "exactly one socket was the channel")
        t:assert(gone[1][2] & 0x800 ~= 0, string.format("it was O_NONBLOCK (flags %o)", gone[1][2]))

        listen()
        conn = accept(15000)
        t:assert(conn, "resolvd reconnects")
    end)

test("several snapshots in one read are applied one after another, so the last wins",
    { spec = "resolvd *netd-subscribe.snapshots-applied-in-order" }, function(t)
        t:assert(conn, "attached to the stand-in")
        local since = now_ns()
        send(conn, frame(marker("pt-a", "10.77.0.11")) .. frame(marker("pt-b", "10.77.0.12"))
            .. frame(marker("pt-c", "10.77.0.13")))
        local st = status_until(function(s) return names(s) == "pt-c" end)
        t:assert_eq(names(st), "pt-c", "the last snapshot is the one in force")
        t:assert_eq(st.scopes[1].servers[1], "10.77.0.13", "with its server")
        local lines = rlog(since)
        dump(t, lines)
        local a, b, c = find(lines, "netd: pt-a:"), find(lines, "netd: pt-b:"), find(lines, "netd: pt-c:")
        t:assert(a and b and c, "each of the three was applied")
        t:assert(a < b and b < c, "in the order they were sent")
    end)

test("a well-formed reply that is not a snapshot or an error is ignored: the channel stays and nothing is applied from it",
    { spec = "resolvd *netd-subscribe.other-replies-ignored" }, function(t)
        t:assert(conn, "attached to the stand-in")
        send(conn, frame(snapshot({ scope({ name = "pt-before", servers = { "10.77.0.1" } }) }, "pt-before-host")))
        status_until(function(s) return names(s) == "pt-before" end)
        local since = now_ns()
        -- netd's plain {ok: true}, and a status-shaped reply carrying a
        -- hostname of its own.
        send(conn, frame({ ok = true }) .. frame({ ok = true, hostname = "pt-status-host", level = "routed",
            refusal = msgpack.NIL, interfaces = E({}) }))
        local _, why = ntfe.recv(sut, conn.fd, 1500, 65536)
        t:assert_eq(why, "timeout", "the connection is still open")
        local st = rstatus()
        t:assert_eq(st.netd, true, "still connected")
        t:assert_eq(names(st), "pt-before", "the scopes are untouched")
        t:assert_eq(st.hostname, "pt-before-host", "and so is the hostname")
        -- The channel still carries snapshots.
        send(conn, frame(marker("pt-after")))
        st = status_until(function(s) return names(s) == "pt-after" end)
        t:assert_eq(names(st), "pt-after", "a later snapshot is applied")
        local lines = rlog(since)
        dump(t, lines)
        t:assert(not find(lines, "lost the netd channel"), "the channel was never dropped")
        t:assert(not find(lines, "unreadable"), "nor anything called unreadable")
    end)

test("a partial frame stays buffered, through a split length as well as a split payload, until the rest arrives",
    { spec = "resolvd *netd-subscribe.partial-frame-buffered" }, function(t)
        t:assert(conn, "attached to the stand-in")
        local f = frame(marker("pt-partial", "10.77.0.21"))
        local since = now_ns()
        send(conn, f:sub(1, 2))
        sut:run("sleep 0.5")
        local st = rstatus()
        t:assert_eq(names(st), "pt-after", "half a length: nothing applied")
        t:assert_eq(st.netd, true, "and still connected")
        send(conn, f:sub(3, #f - 7))
        sut:run("sleep 0.5")
        st = rstatus()
        t:assert_eq(names(st), "pt-after", "all but the last 7 bytes: nothing applied")
        t:assert_eq(st.netd, true, "and still connected")
        send(conn, f:sub(#f - 6))
        st = status_until(function(s) return names(s) == "pt-partial" end)
        t:assert_eq(names(st), "pt-partial", "the rest arrives: the snapshot is applied")
        t:assert_eq(st.scopes[1].servers[1], "10.77.0.21", "intact")
        local lines = rlog(since)
        dump(t, lines)
        t:assert(not find(lines, "lost the netd channel"), "the channel was never dropped")
    end)

test("an error reply is logged and drops the channel, but the snapshot behind it in the same read is still applied — after the loss is logged, so status shows netd false with that snapshot's scopes",
    { spec = "resolvd *netd-subscribe.error-reply-drops-channel resolvd *netd-subscribe.frames-after-error-still-taken resolvd *netd-subscribe.drop-logged-before-snapshots-applied" },
    function(t)
        t:assert(conn, "attached to the stand-in")
        unlisten()   -- the reconnection 0.5 s later fails, so the dropped state can be seen
        local since = now_ns()
        send(conn, frame({ ok = false, error = "pt says no" }) .. frame(marker("pt-behind-error", "10.77.0.31")))
        t:assert(closed_by_peer(conn, 3000), "resolvd closed the channel")
        close(conn)
        local st = status_until(function(s) return names(s) == "pt-behind-error" end)
        t:assert_eq(names(st), "pt-behind-error", "the snapshot behind the error was applied")
        t:assert_eq(st.netd, false, "status: netd not connected, with that snapshot's scopes")
        local lines = rlog(since)
        dump(t, lines)
        local refused = find(lines, "netd refused the subscription: pt says no")
        local lost = find(lines, "lost the netd channel; reconnecting")
        local applied = find(lines, "netd: pt-behind-error:")
        t:assert(refused, "the refusal is logged with netd's message")
        t:assert(lines[refused].msg:find("warn: netd refused", 1, true), "at warn level")
        t:assert(lost and applied, "the loss and the snapshot are both logged")
        t:assert(refused < lost and lost < applied, "refusal, then the loss, then the snapshot's summary")
        sut:run("sleep 1")
        st = rstatus()
        t:assert_eq(st.netd, false, "still disconnected while nothing listens")
        t:assert_eq(names(st), "pt-behind-error", "and still holding those scopes")
        listen()
        conn = accept(15000)
        t:assert(conn, "resolvd reconnects once something listens")
    end)

test("a payload that does not decode is logged as unreadable and drops the channel; the snapshot behind it is still taken",
    { spec = "resolvd *netd-subscribe.undecodable-payload-drops-channel" }, function(t)
        t:assert(conn, "attached to the stand-in")
        local since = now_ns()
        -- 0xc1 is the one MessagePack byte that is never valid.
        send(conn, frame("\xc1\xc1\xc1") .. frame(marker("pt-behind-garbage", "10.77.0.41")))
        t:assert(closed_by_peer(conn, 3000), "resolvd closed the channel")
        close(conn)
        local st = status_until(function(s) return names(s) == "pt-behind-garbage" end)
        t:assert_eq(names(st), "pt-behind-garbage", "the snapshot behind it was applied")
        conn = accept(15000)
        t:assert(conn, "and resolvd reconnects")
        -- A map without `ok` is not a reply either.
        local since2 = now_ns()
        send(conn, frame({ kind = "snapshot", hostname = "", scopes = E({}) }))
        t:assert(closed_by_peer(conn, 3000), "a reply without ok also drops the channel")
        close(conn)
        conn = accept(15000)
        t:assert(conn, "and resolvd reconnects again")
        local lines = rlog(since)
        dump(t, lines)
        local i = find(lines, "netd sent something unreadable: ")
        t:assert(i, "the garbage is logged as unreadable")
        t:assert(lines[i].msg:find("warn: netd sent something unreadable: ", 1, true), "at warn level")
        t:assert(find(lines, "lost the netd channel; reconnecting", i), "and the channel is lost")
        local after = rlog(since2)
        t:assert(find(after, "netd sent something unreadable: "), "the ok-less map is unreadable too")
    end)

test("a length above 65 536 stops the taking: what came before it is applied, what follows it is discarded, and the channel is dropped; 65 536 itself is accepted",
    { spec = "resolvd *netd-subscribe.oversized-frame-drops-channel" }, function(t)
        t:assert(conn, "attached to the stand-in")
        -- Exactly 65 536 bytes of payload: a snapshot padded with a key
        -- resolvd skips.
        local base = snapshot({ scope({ name = "pt-at-limit", servers = { "10.77.0.51" } }) })
        base.pt_pad = string.rep("x", 60000)
        for _ = 1, 3 do
            base.pt_pad = string.rep("x", #base.pt_pad + 65536 - #msgpack.encode(base))
        end
        local p = msgpack.encode(base)
        t:assert_eq(#p, 65536, "the padded payload is exactly 65 536 bytes")
        send(conn, frame(p))
        local st = status_until(function(s) return names(s) == "pt-at-limit" end)
        t:assert_eq(names(st), "pt-at-limit", "a 65 536-byte frame is applied")
        t:assert_eq(st.netd, true, "and the channel kept")

        local since = now_ns()
        local over = string.pack("<I4", 65537) .. string.rep("y", 64)
        send(conn, frame(marker("pt-before-big", "10.77.0.52")) .. over .. frame(marker("pt-after-big", "10.77.0.53")))
        t:assert(closed_by_peer(conn, 3000), "resolvd closed the channel")
        close(conn)
        st = status_until(function(s) return names(s) == "pt-before-big" end)
        t:assert_eq(names(st), "pt-before-big", "the snapshot before the oversized length was applied")
        conn = accept(15000)
        t:assert(conn, "resolvd reconnects")
        sut:run("sleep 0.5")
        st = rstatus()
        t:assert_eq(names(st), "pt-before-big", "the one after it never was")
        local lines = rlog(since)
        dump(t, lines)
        t:assert(find(lines, "lost the netd channel; reconnecting"), "the loss is logged")
        t:assert(not find(lines, "pt-after-big"), "nothing of the discarded frame was applied")
        t:assert(not find(lines, "unreadable"), "and it is not reported as unreadable")
    end)

test("end of file, and a read error (a reset), each drop the channel",
    { spec = "resolvd *netd-subscribe.eof-or-read-error-drops-channel" }, function(t)
        t:assert(conn, "attached to the stand-in")
        -- End of file: the stand-in closes its end.
        local since = now_ns()
        close(conn)
        conn = accept(15000)
        t:assert(conn, "after an end of file, resolvd reconnects")
        local lines = rlog(since)
        dump(t, lines)
        t:assert_eq(count(lines, "lost the netd channel; reconnecting"), 1, "the end of file was a loss")

        -- A read error: closing a Unix stream socket with unread data in
        -- it resets the peer, whose next read fails ECONNRESET. Leave
        -- resolvd's request unread and close.
        close(conn)
        local c = accept(15000, { read = false })
        t:assert(c, "resolvd connected")
        since = now_ns()
        sut:run("sleep 0.2")   -- the request is in the socket by now
        close(c)
        conn = accept(15000)
        t:assert(conn, "after a reset, resolvd reconnects")
        lines = rlog(since)
        dump(t, lines)
        t:assert_eq(count(lines, "lost the netd channel; reconnecting"), 1, "the reset was a loss")
    end)

test("dropping logs `lost the netd channel; reconnecting` at warn once however many causes one read held, discards the buffer, and reconnects",
    { spec = "resolvd *netd-subscribe.drop-logged-and-reconnect-scheduled" }, function(t)
        t:assert(conn, "attached to the stand-in")
        local since = now_ns()
        -- An error, an unreadable payload, the first bytes of a snapshot
        -- frame, and then the end of file: four reasons in one read.
        local partial = frame(marker("pt-never", "10.77.0.61"))
        send(conn, frame({ ok = false, error = "pt one" }) .. frame("\xc1") .. partial:sub(1, 10))
        close(conn)
        conn = accept(15000)
        t:assert(conn, "resolvd reconnects")
        local lines = rlog(since)
        dump(t, lines)
        t:assert_eq(count(lines, "lost the netd channel; reconnecting"), 1, "one loss line")
        local lost = find(lines, "lost the netd channel; reconnecting")
        t:assert(lines[lost].msg:find("warn: lost the netd channel", 1, true), "at warn level")
        -- The ten buffered bytes were thrown away: a snapshot on the new
        -- connection is read from its own first byte.
        send(conn, frame(marker("pt-fresh", "10.77.0.62")))
        local st = status_until(function(s) return names(s) == "pt-fresh" end)
        t:assert_eq(names(st), "pt-fresh", "the new connection's snapshot is read cleanly")
        t:assert_eq(st.netd, true, "and the channel is kept")
    end)
