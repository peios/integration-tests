-- resolvd §5.1 and PSPU §6.4 (framing) — the native socket's wire: one
-- length-prefixed MessagePack map each way, one request and one reply per
-- connection, the size checks and the order they are made in, the exact
-- error replies, how unknown keys are skipped, what a connection that ends
-- early or takes too long gets, the cap on connections still sending, and
-- the reply that is never checked against the ceiling.
--
-- Harness: the scripted gateway (helpers.gateway) with its DNS server
-- (helpers.dns), and a whole Peios (helpers.network). Requests go out as
-- raw frames from the agent (SYSTEM, which the default control object
-- admits to everything), so a test can send what no client would.
--
-- Own VMs: the cap and burst tests stop resolvd with SIGSTOP, and the
-- gateway's DNS server holds some names unanswered on purpose.
--
-- Non-obvious:
-- * Several claims are about what one read finds: the trailing-bytes
--   ceiling, an end of file already waiting behind a request, 257
--   connections accepted at once. The agent sends those with resolvd
--   stopped (kill(2) SIGSTOP from the agent, as peinit/output-fairness
--   does), so every byte and every connection is queued before resolvd
--   looks; SIGCONT then lets it find them all in one pass.
-- * How much resolvd read before refusing is measured exactly: the agent
--   takes a duplicate of resolvd's accepted end of the connection
--   (pidfd_getfd), which keeps that socket alive after resolvd closes it,
--   and reading the duplicate dry afterwards gives what resolvd left
--   unread. (`rchar` in /proc/<resolvd>/io did not move across these
--   reads on the guest kernel, and FIONREAD counts a partly read buffer
--   whole, so neither can be used for the remainder.)
-- * A name in `hold` gets no answer from the gateway: resolvd has read
--   the request and is waiting upstream, which is how a test holds a
--   request "being answered".
-- * helpers.msgpack drops nil-valued map entries, so reply shapes are
--   read with a local walker that keeps every key.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local dns = require("helpers.dns")
local unixsock = require("helpers.unixsock")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")
local msgpack = require("helpers.msgpack")

peinit.claim(2)

local SOCK = "/run/resolvd/resolv.sock"
local NR_KILL, SIGSTOP, SIGCONT = 62, 19, 18
local NR_SHUTDOWN, SHUT_WR = 48, 1
local EPROTOTYPE = 91

-- A TXT RRset large enough that resolvd's native reply (each record as
-- `data` and as `text`) is well over 65 536 bytes, while the DNS message
-- itself fits TCP's 65 535.
local BIG_N = 220
local big = {}
for i = 1, BIG_N do
    big[i] = { type = "TXT", ttl = 60, data = string.format("%03d", i) .. string.rep("t", 237) }
end

local hold = {}   -- names the gateway leaves unanswered while listed

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
local zone = {
    ["www.example.test"] = { { type = "A", ttl = 60, data = "10.77.0.80" } },
    ["late.example.test"] = { { type = "A", ttl = 60, data = "10.77.0.81" } },
    ["gone.example.test"] = { { type = "A", ttl = 60, data = "10.77.0.82" } },
    ["big.example.test"] = big,
}
for i = 1, 3 do zone["slow" .. i .. ".example.test"] = { { type = "A", ttl = 60, data = "10.77.0.9" .. i } } end
dns.serve(gw, {
    zone = zone,
    soa = { name = "example.test", data = { minimum = 30 } },
    on = function(q)
        local qn = q.questions[1] and q.questions[1].name or ""
        for name in pairs(hold) do
            if dns.same_name(qn, name) then return false end
        end
        return nil
    end,
})
local sut = network.boot({ bridges = { lan }, gateway = gw })

-- ---------------------------------------------------------------------------
-- Local helpers
-- ---------------------------------------------------------------------------

-- Guest CLOCK_MONOTONIC, in seconds.
local function mono()
    local r = sut:syscall(228, { args = { 1, 0 }, bufs = { string.rep("\0", 16) }, ptrs = { 1 } })
    assert(r.ret == 0, "clock_gettime")
    local s, ns = string.unpack("<i8i8", r.out_bufs[1])
    return s + ns / 1e9
end

local E = msgpack.encode

--- A map built in wire order from key, encoded-value pairs (keys are
--- plain strings, encoded here; values are bytes).
local function M(...)
    local a = { ... }
    local n = #a // 2
    local out = { n < 16 and string.char(0x80 + n) or ("\xde" .. string.pack(">I2", n)) }
    for i = 1, #a, 2 do
        out[#out + 1] = E(a[i])
        out[#out + 1] = a[i + 1]
    end
    return table.concat(out)
end

local function frame(payload) return string.pack("<I4", #payload) .. payload end
local function request(tbl) return frame(E(tbl)) end
local function double(x) return "\xcb" .. string.pack(">d", x) end

local function open(who)
    who = who or sut
    local fd = assert(unixsock.socket(who, unixsock.AF_UNIX, unixsock.SOCK.STREAM))
    local c = unixsock.connect(who, fd, SOCK)
    assert(c.ret == 0, "connect: " .. unixsock.errname(c.errno))
    return fd
end

local function send_all(who, fd, bytes)
    local r = ntfe.send(who, fd, bytes)
    assert(r.ret == #bytes, string.format("wrote %d of %d bytes (%s)", r.ret, #bytes, sys.errname(r.errno or 0)))
end

local function read_exact(who, fd, n, timeout_ms)
    local got, have = {}, 0
    while have < n do
        local chunk, err = ntfe.recv(who, fd, timeout_ms or 5000, math.min(n - have, 262144))
        if not chunk then return nil, tostring(err) end
        if #chunk == 0 then return nil, "closed" end
        got[#got + 1] = chunk
        have = have + #chunk
    end
    return table.concat(got)
end

--- Read one framed reply from `fd`: `len`, `body`, `reply` (decoded), or
--- `err` ("closed" when the connection ended without one).
local function read_reply(who, fd, timeout_ms)
    local out = {}
    local head, err = read_exact(who, fd, 4, timeout_ms)
    if head then
        out.len = string.unpack("<I4", head)
        out.body, err = read_exact(who, fd, out.len, timeout_ms)
        if out.body then out.reply = msgpack.decode(out.body) end
    end
    out.err = err
    return out
end

--- Whether the peer has closed: the next read is end of file.
local function at_eof(who, fd, ms)
    local more = ntfe.recv(who, fd, ms or 1500, 64)
    return more == ""
end

--- Send `bytes` on a fresh connection and read one reply. `o.who`,
--- `o.shut` (shutdown(SHUT_WR) after sending), `o.keep` (return the fd).
local function raw(bytes, o)
    o = o or {}
    local who = o.who or sut
    local fd = open(who)
    local start = mono()
    send_all(who, fd, bytes)
    if o.shut then who:syscall(NR_SHUTDOWN, fd, SHUT_WR) end
    local out = read_reply(who, fd, o.timeout_ms)
    out.took = mono() - start
    if out.body and not o.keep then out.eof = at_eof(who, fd) end
    if o.keep then out.fd = fd else sys.close(who, fd) end
    return out
end

-- A MessagePack walker that keeps every map key, nil-valued ones too.
local function walk(b, at)
    local tag = b:byte(at)
    local n, from, kind
    if tag >= 0x80 and tag <= 0x8f then n, from, kind = tag - 0x80, at + 1, "map"
    elseif tag == 0xde then n, from, kind = string.unpack(">I2", b, at + 1), at + 3, "map"
    elseif tag == 0xdf then n, from, kind = string.unpack(">I4", b, at + 1), at + 5, "map"
    elseif tag >= 0x90 and tag <= 0x9f then n, from, kind = tag - 0x90, at + 1, "array"
    elseif tag == 0xdc then n, from, kind = string.unpack(">I2", b, at + 1), at + 3, "array"
    elseif tag == 0xdd then n, from, kind = string.unpack(">I4", b, at + 1), at + 5, "array"
    end
    if kind == "map" then
        local m = { _keys = {} }
        for _ = 1, n do
            local k, v
            k, from = msgpack.decode(b, from)
            v, from = walk(b, from)
            m._keys[#m._keys + 1] = k
            m[k] = v
        end
        return m, from
    elseif kind == "array" then
        local a = {}
        for i = 1, n do a[i], from = walk(b, from) end
        return a, from
    end
    return msgpack.decode(b, at)
end

local function keys_of(body)
    local m = walk(body, 1)
    local c = {}
    for i, k in ipairs(m._keys) do c[i] = k end
    table.sort(c)
    return table.concat(c, ","), m
end

local function resolvd_pid()
    local pid = peinit.pid_of_comm(sut, "resolvd")
    assert(pid, "resolvd is running")
    return tonumber(pid)
end

--- Run `fn(pid)` with resolvd stopped, then continue it.
local function with_resolvd_stopped(fn)
    local pid = resolvd_pid()
    local r = sut:syscall(NR_KILL, pid, SIGSTOP)
    assert(r.ret == 0, "SIGSTOP resolvd: " .. sys.errname(r.errno or 0))
    local ok, err = pcall(function()
        wait_until(function()
            local st = peinit.proc(sut, pid, "stat") or ""
            return st:match("^%d+ %b() (%a)") == "T"
        end, { timeout = 5, interval = 0.05, desc = "resolvd stopped" })
        return fn(pid)
    end)
    local c = sut:syscall(NR_KILL, pid, SIGCONT)
    assert(c.ret == 0, "SIGCONT resolvd: " .. sys.errname(c.errno or 0))
    if not ok then error(err, 0) end
    return pid
end

local NR_PIDFD_OPEN, NR_PIDFD_GETFD, NR_IOCTL, FIONREAD = 434, 438, 16, 0x541B

local function socket_fds(pid)
    local out = {}
    for fd, target in pairs(peinit.fds(sut, pid)) do
        if target:match("^socket:") then out[fd] = target end
    end
    return out
end

--- Connect, and take a duplicate of resolvd's accepted end of the
--- connection (pidfd_getfd). The duplicate keeps that socket alive after
--- resolvd closes it, so its receive queue still holds whatever resolvd
--- never read. Returns the client fd and the duplicate.
local function open_with_server_end(pid)
    local before = socket_fds(pid)
    local fd = open()
    local server_fd
    wait_until(function()
        for n, target in pairs(socket_fds(pid)) do
            if before[n] ~= target then server_fd = n; return true end
        end
        return false
    end, { timeout = 3, interval = 0.05, desc = "resolvd to accept" })
    local pidfd = sut:syscall(NR_PIDFD_OPEN, pid, 0)
    assert(pidfd.ret >= 0, "pidfd_open resolvd: " .. sys.errname(pidfd.errno or 0))
    local dup = sut:syscall(NR_PIDFD_GETFD, pidfd.ret, server_fd, 0)
    sys.close(sut, pidfd.ret)
    assert(dup.ret >= 0, "pidfd_getfd resolvd's fd " .. server_fd .. ": " .. sys.errname(dup.errno or 0))
    return fd, dup.ret
end

--- Bytes waiting in a socket's receive queue (FIONREAD). Exact while no
--- queued buffer has been partly read; once one has, this kernel counts
--- it whole, so the remainder is measured by `drain` instead.
local function unread(fd)
    local r = sut:syscall(NR_IOCTL, { args = { fd, FIONREAD, 0 }, bufs = { string.pack("<i4", -1) }, ptrs = { 2 } })
    assert(r.ret == 0, "FIONREAD: " .. sys.errname(r.errno or 0))
    return (string.unpack("<i4", r.out_bufs[1]))
end

--- Read everything left in `fd` without blocking; returns the byte count.
local function drain(fd)
    local total = 0
    for _ = 1, 64 do
        local r = sut:syscall(45, { args = { fd, 0, 16384, 0x40, 0, 0 }, bufs = { string.rep("\0", 16384) }, ptrs = { 1 } })
        if r.ret <= 0 then break end
        total = total + r.ret
    end
    return total
end

--- Send `bytes` as one burst on a connection resolvd has accepted, with
--- resolvd stopped while they are queued, and read the reply. `read` is
--- how many of the bytes resolvd read before it closed its end.
local function measured_burst(bytes)
    local pid = resolvd_pid()
    local fd, server_end = open_with_server_end(pid)
    local queued
    with_resolvd_stopped(function()
        send_all(sut, fd, bytes)
        queued = unread(server_end)
    end)
    local r = read_reply(sut, fd)
    r.eof = r.body and at_eof(sut, fd)
    sys.close(sut, fd)
    local left = drain(server_end)
    sys.close(sut, server_end)
    r.queued, r.read = queued, #bytes - left
    r.note = string.format("queued %d before resolvd ran; %d left unread after resolvd closed its end", queued, left)
    return r
end


local function resolvd_logs()
    local r = sut:run("evctl 'LOGS FROM resolvd SINCE 5m ago TAKE 300'")
    local out = {}
    for line in r.stdout:gmatch("[^\n]+") do
        local msg = line:match('message="(.-)"  origin=')
        if msg then out[#out + 1] = (msg:gsub('\\"', '"')) end
    end
    return out
end

local function logged(text)
    for _, l in ipairs(resolvd_logs()) do
        if l:find(text, 1, true) then return l end
    end
end

--- Pump the gateway until the server has been asked `name`.
local function asked(name, timeout)
    return gw:serve({ timeout = timeout or 10, until_ = function()
        for _, q in ipairs(dns.queries(gw)) do
            local qq = q.msg and q.msg.questions[1]
            if qq and dns.same_name(qq.name, name) then return true end
        end
        return false
    end })
end

--- Pump the gateway until `fd` is readable.
local function serve_until_readable(fd, timeout)
    return gw:serve({ timeout = timeout or 20, until_ = function()
        return ntfe.poll(sut, fd, ntfe.POLLIN, 0) ~= 0
    end })
end

local ready_done = false
--- netd bound and resolvd holds the gateway as a server.
local function ready(t)
    if ready_done then return end
    t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "netd bound a lease")
    local ok = pcall(wait_until, function()
        local s = network.call(sut, { query = "status" }, { path = SOCK })
        for _, sc in ipairs((s and s.scopes) or {}) do
            for _, a in ipairs(sc.servers or {}) do
                if a == "10.77.0.1" then return true end
            end
        end
        return false
    end, { timeout = 20, interval = 0.3, desc = "resolvd to hold 10.77.0.1" })
    t:assert(ok, "resolvd has a scope with server 10.77.0.1")
    ready_done = true
end

local TR = "malformed message: truncated message"
local UT = "malformed message: unexpected value type"
local US = "malformed message: unsupported value type"
local NU = "malformed message: string is not UTF-8"
local ND = "malformed message: nested too deeply"
local function MF(f) return "missing or malformed field " .. f end
local function DF(f) return "duplicate field " .. f end

--- Send each `{label, payload, want}`; `want` an error string, or true
--- for a successful reply. Every error reply is checked for its shape
--- (`ok` false and `error`, nothing else) and for the closed connection.
local function expect_all(t, cases)
    for _, c in ipairs(cases) do
        local label, payload, want = c[1], c[2], c[3]
        local r = raw(frame(payload))
        local shape = r.body and keys_of(r.body) or "-"
        t:log(string.format("%s: ok=%s error=%s keys=%s eof=%s", label, tostring(r.reply and r.reply.ok),
            tostring(r.reply and r.reply.error), shape, tostring(r.eof)))
        t:assert(r.reply, label .. ": a reply (" .. tostring(r.err) .. ")")
        if want == true then
            t:assert_eq(r.reply.ok, true, label .. ": answered")
        else
            t:assert_eq(r.reply.ok, false, label .. ": an error reply")
            t:assert_eq(r.reply.error, want, label)
            t:assert_eq(shape, "error,ok", label .. ": the reply is {ok, error} and nothing else")
        end
        t:assert(r.eof, label .. ": the connection is closed after the reply")
    end
end

-- ---------------------------------------------------------------------------
-- The frame, and one request per connection
-- ---------------------------------------------------------------------------

test("the native door is a SOCK_STREAM socket at /run/resolvd/resolv.sock carrying a 4-byte little-endian length and a MessagePack map each way, one request and one reply per connection",
    { spec = "PSPU *nri-native.stream-socket-at-configured-path PSPU *nri-native.length-prefixed-messagepack-framing PSPU *nri-native.length-is-little-endian PSPU *nri-native.one-request-per-connection" },
    function(t)
        ready(t)
        local st = assert(sys.stat(sut, SOCK), "stat " .. SOCK)
        t:log(string.format("%s mode %o", SOCK, st.mode))
        t:assert_eq(st.mode & 0xF000, sys.S_IFSOCK, SOCK .. " is a socket")
        -- Only a stream connection reaches it.
        for name, stype in pairs({ SEQPACKET = unixsock.SOCK.SEQPACKET, DGRAM = unixsock.SOCK.DGRAM }) do
            local fd = assert(unixsock.socket(sut, unixsock.AF_UNIX, stype))
            local c = unixsock.connect(sut, fd, SOCK)
            t:log("SOCK_" .. name .. " connect: ret " .. c.ret .. " " .. unixsock.errname(c.errno or 0))
            t:assert_eq(c.errno, EPROTOTYPE, "a SOCK_" .. name .. " connect is EPROTOTYPE: the socket is SOCK_STREAM")
            sys.close(sut, fd)
        end

        -- A request and its reply.
        local r = raw(request({ query = "status" }))
        t:assert(r.reply, "a status reply: " .. tostring(r.err))
        t:assert_eq(r.len, #r.body, "the reply's 4-byte little-endian length is its payload's")
        t:assert_eq(r.body:byte(1) & 0xF0, 0x80, "the payload is a MessagePack map")
        t:assert_eq(r.reply.ok, true, "ok")
        t:assert_eq(r.reply.kind, "status", "the status")

        -- The same request with its length big-endian is a 234-megabyte
        -- length to resolvd: the length is read little-endian.
        local p = E({ query = "status" })
        r = raw(string.pack(">I4", #p) .. p)
        t:log(string.format("big-endian length %d (as LE %d): %s", #p, string.unpack("<I4", string.pack(">I4", #p)),
            tostring(r.reply and r.reply.error)))
        t:assert_eq(r.reply and r.reply.error, "request too large", "a big-endian length is read as little-endian")

        -- A request delivered a few bytes at a time is still one request.
        local fd = open()
        local whole = request({ query = "status" })
        for _, piece in ipairs({ whole:sub(1, 2), whole:sub(3, 4), whole:sub(5, 9) }) do
            send_all(sut, fd, piece)
            -- A pause; nothing is due yet, so nothing becomes readable.
            t:assert_eq(ntfe.poll(sut, fd, ntfe.POLLIN, 200), 0, "no reply to a partial request")
        end
        send_all(sut, fd, whole:sub(10))
        local pr = read_reply(sut, fd)
        t:assert(pr.reply and pr.reply.ok == true and pr.reply.kind == "status", "a request sent in pieces is answered")
        sys.close(sut, fd)

        -- Two requests in one write: one reply, then the connection ends;
        -- the second is never answered.
        fd = open()
        send_all(sut, fd, request({ query = "status" }) .. request({ query = "flush" }))
        local first = read_reply(sut, fd)
        t:assert(first.reply and first.reply.kind == "status", "the first request is answered")
        local after = ntfe.recv(sut, fd, 2000, 4096)
        t:log("after the first reply: " .. (after and (#after .. " bytes") or "nothing"))
        t:assert_eq(after, "", "and then end of file: no second reply")
        sys.close(sut, fd)
    end)

test("each successful reply carries ok true and its kind — answer, addresses, status — or nothing more for flush",
    { spec = "PSPU *nri-native.success-reply-carries-kind" }, function(t)
        ready(t)
        local cases = {
            { "status", { query = "status" }, "status" },
            { "resolve localhost A", { query = "resolve", name = "localhost", type = 1 }, "answer" },
            { "reverse 127.0.0.1", { query = "reverse", address = "127.0.0.1" }, "answer" },
            { "lookup localhost", { query = "lookup", name = "localhost" }, "addresses" },
        }
        for _, c in ipairs(cases) do
            local r = raw(request(c[2]))
            local keys, m = keys_of(r.body)
            t:log(c[1] .. ": keys " .. keys)
            t:assert_eq(m.ok, true, c[1] .. ": ok is true")
            t:assert_eq(m.kind, c[3], c[1] .. ": kind " .. c[3])
            t:assert_eq(m.error, nil, c[1] .. ": no error")
        end
        local r = raw(request({ query = "flush" }))
        local keys, m = keys_of(r.body)
        t:log("flush: keys " .. keys)
        t:assert_eq(keys, "ok", "flush: a map holding only ok")
        t:assert_eq(m.ok, true, "flush: ok is true")
    end)

test("a reply is framed the same way, written, and the connection closed; a write that fails is logged",
    { spec = "resolvd *native-framing.reply-written-then-closed" }, function(t)
        ready(t)
        local r = raw(request({ query = "resolve", name = "localhost", type = 1 }))
        t:assert(r.reply and r.reply.ok, "an answer")
        t:assert_eq(r.len, #r.body, "length-prefixed, little-endian")
        t:assert(r.eof, "and the connection is closed after it")

        -- A client that has gone by the time its answer is ready: the
        -- write fails and is logged. (The question is not cancelled when
        -- the client leaves: PEI-1343.)
        hold["gone.example.test"] = true
        dns.forget(gw)
        local fd = open()
        send_all(sut, fd, request({ query = "resolve", name = "gone.example.test", type = 1, no_cache = true }))
        t:assert(asked("gone.example.test"), "resolvd asked upstream (it has read the request)")
        sys.close(sut, fd)
        hold["gone.example.test"] = nil
        local line
        local ok = gw:serve({ timeout = 20, until_ = function()
            line = logged("control: reply failed: ")
            return line ~= nil
        end })
        t:log("log: " .. tostring(line))
        t:assert(ok, "control: reply failed: <error> is logged")
    end)

-- ---------------------------------------------------------------------------
-- Decoding and the error replies
-- ---------------------------------------------------------------------------

test("every error reply is ok false with an error string and nothing else, and the connection is closed after it",
    { spec = "PSPU *nri-native.error-reply-carries-only-error resolvd *native-framing.connection-closed-after-error-reply" },
    function(t)
        ready(t)
        expect_all(t, {
            { "not a map at all", "\xc1", UT },
            { "an unknown query", M("query", E("nope")), 'unknown query "nope"' },
            { "a duplicate key", M("query", E("status"), "query", E("status")), DF("query") },
            { "a missing field", M("query", E("lookup")), MF("name") },
            { "a truncated map", "\x82\xa5query\xa6status", TR },
        })
        -- The size refusal too.
        local r = raw(string.pack("<I4", 65537))
        t:assert_eq(r.reply and r.reply.error, "request too large", "the size refusal is an error reply")
        t:assert_eq(keys_of(r.body), "error,ok", "of the same shape")
        t:assert(r.eof, "and closes the connection")
    end)

test("a request carries a query string naming it: without one, or with one that is not a string, it is refused",
    { spec = "PSPU *nri-native.request-carries-query-string resolvd *native-framing.missing-or-unknown-query-is-error" },
    function(t)
        ready(t)
        expect_all(t, {
            { "an empty map", "\x80", MF("query") },
            { "no query, other keys", M("name", E("localhost"), "zz", E(1)), MF("query") },
            { "query an integer", M("query", E(5)), UT },
            { "query nil", M("query", "\xc0"), UT },
            { "query binary", M("query", "\xc4\x06status"), UT },
            { "an unknown query", M("query", E("frobnicate")), 'unknown query "frobnicate"' },
            { "query names are case-sensitive", M("query", E("Status")), 'unknown query "Status"' },
            { "a query string", M("query", E("status")), true },
        })
    end)

test("truncated payloads: a value cut short, a map or array claiming more items than bytes remain, an empty payload",
    { spec = "resolvd *native-framing.error-truncated" }, function(t)
        ready(t)
        expect_all(t, {
            { "a map's second entry missing", "\x82\xa5query\xa6status", TR },
            { "a string cut short", "\x81\xa5query\xa6sta", TR },
            { "a map claiming 15 entries in 13 bytes", "\x8f\xa5query\xa6status", TR },
            { "an unknown key's array claiming a billion items",
                M("query", E("status"), "zz", "\xdd\x3b\x9a\xca\x00"), TR },
            -- 4 entries are 8 values: more than the 6 bytes left, though
            -- not more than 6 items.
            { "an unknown key's map of 4 entries in 6 bytes", M("query", E("status"), "zz", "\x84\xa1a\x01\xa1b\xc0"), TR },
            { "a zero-length payload", "", TR },
        })
    end)

test("wrong MessagePack types: the payload not a map, a key not a string, a known field of the wrong type, a type negative or beyond i64",
    { spec = "resolvd *native-framing.error-unexpected-type" }, function(t)
        ready(t)
        expect_all(t, {
            { "an array payload", "\x93\x01\x02\x03", UT },
            { "a string payload", E("status"), UT },
            { "an integer key", "\x81\x01\xa6status", UT },
            { "query an integer", M("query", E(5)), UT },
            { "name a float (a known field)", M("query", E("lookup"), "name", double(1.5)), UT },
            { "no_cache an integer", M("query", E("status"), "no_cache", E(1)), UT },
            { "family an integer", M("query", E("status"), "family", E(5)), UT },
            { "address a boolean", M("query", E("status"), "address", "\xc3"), UT },
            { "type -1", M("query", E("resolve"), "name", E("localhost"), "type", "\xff"), UT },
            { "type uint64 2^64-1", M("query", E("status"), "type", "\xcf" .. string.rep("\xff", 8)), UT },
            { "type uint64 2^63", M("query", E("status"), "type", "\xcf\x80" .. string.rep("\0", 7)), UT },
        })
    end)

test("floats and extension values are unsupported value types",
    { spec = "resolvd *native-framing.error-unsupported-type" }, function(t)
        ready(t)
        expect_all(t, {
            { "float64 under an unknown key", M("query", E("status"), "zz", double(0.5)), US },
            { "float32 under an unknown key", M("query", E("status"), "zz", "\xca" .. string.pack(">f", 0.5)), US },
            { "fixext1 under an unknown key", M("query", E("status"), "zz", "\xd4\x01\x00"), US },
            { "ext8 under an unknown key", M("query", E("status"), "zz", "\xc7\x01\x05\x00"), US },
            { "the reserved tag 0xc1 under an unknown key", M("query", E("status"), "zz", "\xc1"), US },
        })
    end)

test("a string that is not UTF-8 — a key, a known field, or one inside a skipped value — fails the decode",
    { spec = "resolvd *native-framing.error-not-utf8" }, function(t)
        ready(t)
        expect_all(t, {
            { "the query", M("query", "\xa2\xff\xfe"), NU },
            { "a key", "\x81\xa2\xff\xfe\xa6status", NU },
            { "an unknown key's string", M("query", E("status"), "zz", "\xa2\xff\xfe"), NU },
        })
    end)

test("nesting beyond 32 levels inside a skipped value is refused as nested too deeply",
    { spec = "resolvd *native-framing.error-nested-too-deeply" }, function(t)
        ready(t)
        expect_all(t, {
            { "33 arrays", M("query", E("status"), "zz", string.rep("\x91", 33) .. "\xc0"), ND },
            { "33 maps", M("query", E("status"), "zz", string.rep("\x81\xa1k", 33) .. "\xc0"), ND },
        })
    end)

test("missing or malformed field: a field the request needs, a type from 65 536 to i64::MAX in any request, a reverse address that is not an IP address",
    { spec = "resolvd *native-framing.error-missing-or-malformed-field" }, function(t)
        ready(t)
        expect_all(t, {
            { "resolve without name", M("query", E("resolve"), "type", E(1)), MF("name") },
            { "resolve without type", M("query", E("resolve"), "name", E("localhost")), MF("type") },
            { "lookup without name", M("query", E("lookup")), MF("name") },
            { "reverse without address", M("query", E("reverse")), MF("address") },
            { "reverse of a name", M("query", E("reverse"), "address", E("not-an-address")), MF("address") },
            { "reverse of a zoned address", M("query", E("reverse"), "address", E("fe80::1%eth0")), MF("address") },
            { "status with type 65536", M("query", E("status"), "type", E(65536)), MF("type") },
            { "status with type 70000", M("query", E("status"), "type", E(70000)), MF("type") },
            { "status with type i64::MAX", M("query", E("status"), "type", "\xd3\x7f" .. string.rep("\xff", 7)), MF("type") },
            { "status with type 65535", M("query", E("status"), "type", E(65535)), true },
        })
    end)

test("a repeated key is refused as a duplicate field, whatever the key",
    { spec = "resolvd *native-framing.error-duplicate-field" }, function(t)
        ready(t)
        expect_all(t, {
            { "query twice", M("query", E("status"), "query", E("status")), DF("query") },
            { "name twice", M("query", E("status"), "name", E("a"), "name", E("b")), DF("name") },
            { "an unknown key twice", M("zz", E(1), "query", E("status"), "zz", E(2)), DF("zz") },
        })
    end)

test("an unknown query is refused with its name quoted and escaped",
    { spec = "resolvd *native-framing.error-unknown-query" }, function(t)
        ready(t)
        expect_all(t, {
            { "frobnicate", M("query", E("frobnicate")), 'unknown query "frobnicate"' },
            { "a quote and a newline", M("query", E('a"b\n')), 'unknown query "a\\"b\\n"' },
            { "subscribe (netd's, not resolvd's)", M("query", E("subscribe")), 'unknown query "subscribe"' },
        })
    end)

test("a key repeated in the top-level map is an error; keys inside a skipped value are not checked for repeats",
    { spec = "resolvd *native-framing.duplicate-top-level-key-is-error PSPU *nri-native.duplicate-keys-rejected" },
    function(t)
        ready(t)
        expect_all(t, {
            { "query repeated", M("query", E("status"), "query", E("flush")), DF("query") },
            { "a known key the request does not take, repeated",
                M("query", E("status"), "family", E("inet"), "family", E("inet")), DF("family") },
            { "an unknown key repeated", M("zz", E(1), "query", E("status"), "zz", E(1)), DF("zz") },
            { "a repeat inside an unknown key's map", M("query", E("status"), "zz", "\x82\xa1a\x01\xa1a\x02"), true },
            { "a repeat two maps down", M("query", E("status"), "zz", "\x81\xa1x\x82\xa1a\x01\xa1a\x02"), true },
        })
    end)

-- PEI-1347 (widened): an unknown key holding a uint64 above i64::MAX is
-- not skipped: `skip` reads integers through `read_int`, which refuses
-- them, so the request fails with "malformed message: unexpected value
-- type", wherever in the value the integer sits. Every other value below
-- is skipped. The PSPU test `nri-native.unknown-keys-ignored` asserts the
-- spec.
test("an unknown key is skipped when its value is nil, boolean, integer, string, binary, array or map; an integer of 2^63 or more inside it fails as unexpected value type",
    { spec = "resolvd *native-framing.unknown-keys-skipped" }, function(t)
        ready(t)
        expect_all(t, {
            { "nil", M("query", E("status"), "zz", "\xc0"), true },
            { "booleans", M("query", E("status"), "za", "\xc3", "zb", "\xc2"), true },
            { "integers", M("query", E("status"), "za", E(-5), "zb", "\xd3\x80" .. string.rep("\0", 7),
                "zc", "\xcf\x7f" .. string.rep("\xff", 7), "zd", "\xcc\xff"), true },
            { "a string", M("query", E("status"), "zz", E(string.rep("s", 300))), true },
            { "binary", M("query", E("status"), "zz", "\xc4\x03abc"), true },
            { "an array", M("query", E("status"), "zz", E({ 1, "two", { 3 } })), true },
            { "a map", M("query", E("status"), "zz", "\x82\xa1a\x01\xa1b\x92\xc0\xc2"), true },
            { "every one at once, around the query", M("z1", "\xc0", "z2", "\xc3", "query", E("status"), "z3", "\xc4\x01x",
                "z4", "\x90", "z5", "\x80"), true },
            { "an integer above i64::MAX (uint64)", M("query", E("status"), "zz", "\xcf" .. string.rep("\xff", 8)), UT },
            { "2^63 exactly (uint64)", M("query", E("status"), "zz", "\xcf\x80" .. string.rep("\0", 7)), UT },
            { "2^63 two arrays down", M("query", E("status"), "zz", "\x91\x91\xcf\x80" .. string.rep("\0", 7)), UT },
            { "2^63 as a map key", M("query", E("status"), "zz", "\x81\xcf\x80" .. string.rep("\0", 7) .. "\xc0"), UT },
        })
    end)

test("inside an unknown key's value, a float, an extension or a non-UTF-8 string fails the decode, however deep",
    { spec = "resolvd *native-framing.unknown-key-unsupported-value-fails" }, function(t)
        ready(t)
        expect_all(t, {
            { "a float", M("query", E("status"), "zz", double(0.5)), US },
            { "an extension", M("query", E("status"), "zz", "\xd5\x01\x00\x00"), US },
            { "a float two arrays down", M("query", E("status"), "zz", "\x91\x91" .. double(2.5)), US },
            { "a float as a map key", M("query", E("status"), "zz", "\x81" .. double(1) .. "\xc0"), US },
            { "a non-UTF-8 string in a map", M("query", E("status"), "zz", "\x81\xa1k\xa1\xff"), NU },
        })
    end)

test("an array or map nested more than 32 levels inside an unknown key fails; 32, counting the value itself, is fine",
    { spec = "resolvd *native-framing.unknown-key-nesting-limit" }, function(t)
        ready(t)
        expect_all(t, {
            { "32 arrays", M("query", E("status"), "zz", string.rep("\x91", 32) .. "\xc0"), true },
            { "33 arrays", M("query", E("status"), "zz", string.rep("\x91", 33) .. "\xc0"), ND },
            { "32 maps", M("query", E("status"), "zz", string.rep("\x81\xa1k", 32) .. "\xc0"), true },
            { "33 maps", M("query", E("status"), "zz", string.rep("\x81\xa1k", 33) .. "\xc0"), ND },
            { "16 arrays and 17 maps", M("query", E("status"), "zz",
                string.rep("\x91", 16) .. string.rep("\x81\xa1k", 17) .. "\xc0"), ND },
            -- The top-level map is not a skipped value: it does not count.
            { "32 arrays under each of two keys", M("query", E("status"), "za", string.rep("\x91", 32) .. "\xc0",
                "zb", string.rep("\x91", 32) .. "\xc0"), true },
        })
    end)

test("every known key is type-checked in every request, the first error met is reported, and a missing field is looked for last",
    { spec = "resolvd *native-framing.wrong-field-type-is-error" }, function(t)
        ready(t)
        expect_all(t, {
            { "{query: status, name: 5}", M("query", E("status"), "name", E(5)), UT },
            { "{query: status, type: 70000}", M("query", E("status"), "type", E(70000)), MF("type") },
            { "{query: flush, no_cache: \"yes\"}", M("query", E("flush"), "no_cache", E("yes")), UT },
            { "{query: status, family: [ ]}", M("query", E("status"), "family", "\x90"), UT },
            -- family takes any string; address is parsed only in a reverse.
            { "lookup with family \"bogus\"", M("query", E("lookup"), "name", E("localhost"), "family", E("bogus")), true },
            { "status with address \"nope\"", M("query", E("status"), "address", E("nope")), true },
            { "status with every known key well typed", M("query", E("status"), "name", E("x"), "type", E(1),
                "no_cache", "\xc3", "family", E("inet"), "address", E("10.0.0.1")), true },
            -- In order: name's error comes before the unknown query.
            { "a bad name before an unknown query", M("name", E(5), "query", E("bogus")), UT },
            { "a duplicate before the query is judged", M("query", E("bogus"), "query", E("x")), DF("query") },
            -- The whole map is read before a missing name is noticed.
            { "resolve, no name, a float later", M("query", E("resolve"), "zz", double(1)), US },
        })
    end)

test("anything after the top-level map in the payload is ignored",
    { spec = "resolvd *native-framing.bytes-after-map-ignored" }, function(t)
        ready(t)
        expect_all(t, {
            { "a reserved byte after", E({ query = "status" }) .. "\xc1", true },
            { "a second map after", E({ query = "status" }) .. E({ query = "flush" }), true },
            { "a truncated value after", E({ query = "status" }) .. "\xdb\xff\xff\xff\xff", true },
            { "text after", E({ query = "status" }) .. "garbage", true },
        })
    end)

-- PEI-1347: resolvd fails the request with "malformed message: unsupported
-- value type" when an unknown key holds a float or an extension value;
-- PEI-1347 (widened): and with "unexpected value type" when it
-- holds a uint64 above i64::MAX. This test stops at the float; the uint64
-- refusal is shown by the `unknown-keys-skipped` test above.
test("a receiver ignores keys it does not know, whatever they hold",
    { spec = "PSPU *nri-native.unknown-keys-ignored", tags = { "known-bug" } }, function(t)
        ready(t)
        expect_all(t, {
            { "a string", M("query", E("status"), "weight", E("heavy")), true },
            { "a float", M("query", E("status"), "weight", double(0.5)), true },
            { "an extension value", M("query", E("status"), "stamp", "\xd6\xff\x00\x00\x00\x01"), true },
            { "a uint64 above i64::MAX", M("query", E("status"), "serial", "\xcf" .. string.rep("\xff", 8)), true },
        })
    end)

-- ---------------------------------------------------------------------------
-- Size
-- ---------------------------------------------------------------------------

--- A `{query = "status", pad = …}` payload of exactly `n` bytes.
local function status_of_size(n)
    local base = #E({ query = "status", pad = "" })
    for k = n - base - 8, n - base do
        local p = E({ query = "status", pad = string.rep("p", k) })
        if #p == n then return p end
    end
    error("could not build a " .. n .. "-byte request")
end

test("a length above 65 536 is refused with request too large, before any payload arrives; 65 536 is read and answered",
    { spec = "resolvd *native-framing.length-ceiling PSPU *nri-native.oversized-request-answered-with-error" },
    function(t)
        ready(t)
        local big = status_of_size(65536)
        local r = raw(frame(big))
        t:log("65536-byte request: " .. tostring(r.reply and (r.reply.kind or r.reply.error)))
        t:assert(r.reply and r.reply.ok == true, "a 65 536-byte request is answered")

        for _, n in ipairs({ 65537, 0x7fffffff, 0xffffffff }) do
            r = raw(string.pack("<I4", n))
            t:log(string.format("length %d, nothing after it: %s after %.3f s, eof %s", n,
                tostring(r.reply and r.reply.error), r.took or -1, tostring(r.eof)))
            t:assert_eq(r.reply and r.reply.ok, false, n .. ": an error reply, not a silent close")
            t:assert_eq(r.reply.error, "request too large", n .. ": request too large")
            t:assert(r.took < 1.0, n .. ": at once, without waiting for a payload")
            t:assert(r.eof, n .. ": and the connection is closed")
        end
    end)

test("more than 65 540 bytes buffered is request too large; bytes after a complete request are ignored while the total stays within it",
    { spec = "resolvd *native-framing.buffered-bytes-ceiling resolvd *native-framing.trailing-bytes-ignored" },
    function(t)
        ready(t)
        local status = request({ query = "status" })
        local function burst(label, bytes)
            local fd
            with_resolvd_stopped(function()
                fd = open()
                send_all(sut, fd, bytes)
            end)
            local r = read_reply(sut, fd)
            r.eof = r.body and at_eof(sut, fd)
            sys.close(sut, fd)
            t:log(string.format("%s (%d bytes): ok=%s kind=%s error=%s", label, #bytes, tostring(r.reply and r.reply.ok),
                tostring(r.reply and r.reply.kind), tostring(r.reply and r.reply.error)))
            return r
        end
        -- Trailing bytes after a complete request: ignored.
        local r = burst("status + 10 junk bytes", status .. string.rep("j", 10))
        t:assert(r.reply and r.reply.kind == "status", "a few trailing bytes are ignored")
        r = burst("status + junk to 65 540 in all", status .. string.rep("j", 65540 - #status))
        t:assert(r.reply and r.reply.kind == "status", "trailing bytes up to 65 540 in all are ignored")
        -- One byte more, and the buffered total is over the ceiling.
        r = burst("status + junk to 65 541 in all", status .. string.rep("j", 65541 - #status))
        t:assert_eq(r.reply and r.reply.error, "request too large", "65 541 bytes buffered: request too large (PEI-1346)")
        t:assert(r.eof, "and the connection is closed")
        -- The largest legal request, plus one byte.
        r = burst("a 65 536-byte request + 1 byte", frame(status_of_size(65536)) .. "j")
        t:assert_eq(r.reply and r.reply.error, "request too large", "65 540 + 1: request too large")
    end)

-- PEI-1346 is this behaviour; the TRM documents it, so the test passes.
test("resolvd reads what the client has sent before looking at the length: an oversized payload's first bytes are read, and a legal request in an over-long burst is refused",
    { spec = "resolvd *native-framing.payload-read-before-length-check" }, function(t)
        ready(t)
        local function burst(bytes)
            local r = measured_burst(bytes)
            t:log(r.note)
            t:assert_eq(r.queued, #bytes, "every byte was queued before resolvd ran")
            return r
        end
        -- An oversized length with 1 000 payload bytes behind it: all
        -- 1 004 are read, then the length is refused.
        local r = burst(string.pack("<I4", 70000) .. string.rep("x", 1000))
        t:log(string.format("length 70000 + 1000 bytes: %s; resolvd read %d bytes", tostring(r.reply and r.reply.error), r.read))
        t:assert_eq(r.reply and r.reply.error, "request too large", "refused")
        t:assert_eq(r.read, 1004, "but only after reading all 1 004 bytes sent")
        -- A 2 GB length with 80 000 bytes behind it: read in 4 096-byte
        -- chunks until more than 65 540 are buffered (17 chunks, 69 632
        -- bytes), refused before the length is looked at.
        r = burst(string.pack("<I4", 0x7fffffff) .. string.rep("x", 80000))
        t:log(string.format("length 2^31-1 + 80000 bytes: %s; resolvd read %d bytes", tostring(r.reply and r.reply.error), r.read))
        t:assert_eq(r.reply and r.reply.error, "request too large", "refused")
        t:assert_eq(r.read, 69632, "after reading 17 chunks of 4 096 bytes")
        -- A legal status request followed in the same burst by 70 000
        -- bytes: refused although its length is within the ceiling.
        local status = request({ query = "status" })
        r = burst(status .. string.rep("j", 70000))
        t:log("status + 70000 trailing bytes: " .. tostring(r.reply and (r.reply.kind or r.reply.error)))
        t:assert_eq(r.reply and r.reply.error, "request too large", "a legal request in an over-long burst is refused")
        t:assert_eq(r.read, 69632, "by the first check: 17 chunks read, the request never decoded")
    end)

-- PEI-1346: resolvd reads everything the client has sent (here all 65 004
-- bytes) before it looks at the length.
test("a request whose length exceeds the ceiling is refused without reading its payload",
    { spec = "PSPU *nri-native.oversized-request-refused-unread", tags = { "known-bug" } }, function(t)
        ready(t)
        local payload = 65000
        local r = measured_burst(string.pack("<I4", 0x7fffffff) .. string.rep("x", payload))
        local read = r.read
        t:log(r.note)
        t:assert_eq(r.queued, 4 + payload, "every byte was queued before resolvd ran")
        t:log(string.format("length 2^31-1 + %d bytes: %s; resolvd read %d bytes", payload,
            tostring(r.reply and r.reply.error), read))
        t:assert_eq(r.reply and r.reply.error, "request too large", "refused with an error reply")
        t:assert(read < 4 + payload, "without reading the payload (resolvd read " .. read .. " bytes)")
    end)

-- PEI-1355: this is the documented current behaviour (the reply is not
-- checked against the ceiling, and libresolv clients refuse it); the test
-- passes on it.
test("a reply is not checked against the 65 536-byte ceiling: a large TXT answer goes out whole",
    { spec = "resolvd *native-framing.reply-size-not-checked" }, function(t)
        ready(t)
        dns.forget(gw)
        local fd = open()
        send_all(sut, fd, request({ query = "resolve", name = "big.example.test", type = 16, no_cache = true }))
        t:assert(serve_until_readable(fd, 30), "resolvd answers")
        local r = read_reply(sut, fd, 10000)
        sys.close(sut, fd)
        local tcp = dns.queries(gw, function(q)
            return q.transport == "tcp" and q.msg and dns.same_name(q.msg.questions[1].name, "big.example.test")
        end)
        t:log(string.format("reply length %s; %d records; TCP questions %d; %s", tostring(r.len),
            r.reply and #(r.reply.records or {}) or -1, #tcp, tostring(r.err)))
        t:assert(r.reply, "the whole reply is read: " .. tostring(r.err))
        t:assert_eq(r.reply.ok, true, "an answer")
        t:assert_eq(r.reply.kind, "answer", "kind answer")
        t:assert_eq(#r.reply.records, BIG_N, "every TXT record")
        t:assert(r.len > 65536, "a payload over 65 536 bytes (" .. r.len .. ") is written as it is")
    end)

-- ---------------------------------------------------------------------------
-- Connections that end early, or take too long
-- ---------------------------------------------------------------------------

test("a connection that closes before its request is complete is dropped without a reply",
    { spec = "resolvd *native-framing.early-close-dropped" }, function(t)
        ready(t)
        local status = request({ query = "status" })
        for label, bytes in pairs({ ["nothing"] = "", ["half a length"] = status:sub(1, 2),
            ["the length and part of the payload"] = status:sub(1, #status - 3) }) do
            local fd = open()
            if #bytes > 0 then send_all(sut, fd, bytes) end
            local start = mono()
            sut:syscall(NR_SHUTDOWN, fd, SHUT_WR)
            local got, err = ntfe.recv(sut, fd, 3000, 4096)
            local took = mono() - start
            t:log(string.format("%s then end of file: read %s after %.3f s", label,
                got and (#got .. " bytes") or tostring(err), took))
            t:assert_eq(got, "", label .. ": the connection is closed with no reply")
            t:assert(took < 2.0, label .. ": at once, not at the 5 s bound")
            sys.close(sut, fd)
        end
    end)

-- PEI-1358: this is the documented current behaviour (the end of file
-- found with the request drops it); the test passes on it.
test("a request with the end of file already behind it gets no reply; one whose end of file comes after resolvd read it is answered",
    { spec = "resolvd *native-framing.request-then-half-close-dropped" }, function(t)
        ready(t)
        local fd
        with_resolvd_stopped(function()
            fd = open()
            send_all(sut, fd, request({ query = "status" }))
            sut:syscall(NR_SHUTDOWN, fd, SHUT_WR)
        end)
        local got, err = ntfe.recv(sut, fd, 3000, 4096)
        t:log("status then SHUT_WR, both queued: read " .. (got and (#got .. " bytes") or tostring(err)))
        t:assert_eq(got, "", "dropped: end of file, no reply")
        sys.close(sut, fd)

        -- Read first, end of file later: answered.
        hold["late.example.test"] = true
        dns.forget(gw)
        fd = open()
        send_all(sut, fd, request({ query = "resolve", name = "late.example.test", type = 1, no_cache = true }))
        t:assert(asked("late.example.test"), "resolvd read the request and asked upstream")
        sut:syscall(NR_SHUTDOWN, fd, SHUT_WR)
        hold["late.example.test"] = nil
        t:assert(serve_until_readable(fd, 20), "a reply comes")
        local r = read_reply(sut, fd)
        sys.close(sut, fd)
        t:log("late half-close: " .. tostring(r.reply and (r.reply.kind or r.reply.error)))
        t:assert(r.reply and r.reply.ok == true and r.reply.kind == "answer", "the request is answered as usual")
        t:assert_eq(r.reply.records and r.reply.records[1] and r.reply.records[1].text, "10.77.0.81", "with its answer")
    end)

test("a connection that has not delivered a whole request five seconds after it was accepted is closed without a reply",
    { spec = "resolvd *native-framing.five-second-delivery-bound PSPU *nri-native.request-delivery-bounded" },
    function(t)
        ready(t)
        local silent = open()
        local partial = open()
        local start = mono()
        send_all(sut, partial, string.pack("<I4", 20) .. "\x81")
        local function closed_after(fd)
            local got = ""
            while true do
                local d, e = ntfe.recv(sut, fd, 9000, 4096)
                if not d then return nil, got, e end
                if d == "" then return mono() - start, got end
                got = got .. d
            end
        end
        local t1, g1, e1 = closed_after(silent)
        local t2, g2, e2 = closed_after(partial)
        t:log(string.format("silent: closed after %s s (%d bytes, %s); partial: closed after %s s (%d bytes, %s)",
            tostring(t1), #g1, tostring(e1), tostring(t2), #g2, tostring(e2)))
        t:assert(t1 and t1 >= 4.5 and t1 < 6.5, "a silent connection is closed at about 5 s")
        t:assert(t2 and t2 >= 4.5 and t2 < 6.5, "a half-sent request is closed at about 5 s")
        t:assert_eq(#g1 + #g2, 0, "neither gets a reply")
        sys.close(sut, silent); sys.close(sut, partial)
        t:assert(raw(request({ query = "status" })).reply.ok, "resolvd answers others meanwhile and after")
    end)

test("with 256 accepted connections still sending, a newly accepted one is closed at once without a reply; requests already read do not count",
    { spec = "resolvd *native-framing.pending-connection-cap-closes-silently" }, function(t)
        ready(t)
        t:log("agent limits: " .. ((sut:read_file("/proc/self/limits"):match("Max open files[^\n]*")) or "?"))
        -- Three connections whose requests resolvd has read and is still
        -- answering (their names are held unanswered upstream).
        dns.forget(gw)
        local waiters = {}
        for i = 1, 3 do
            hold["slow" .. i .. ".example.test"] = true
            waiters[i] = open()
            send_all(sut, waiters[i], request({ query = "resolve", name = "slow" .. i .. ".example.test", type = 1, no_cache = true }))
        end
        for i = 1, 3 do
            t:assert(asked("slow" .. i .. ".example.test"), "resolvd read waiter " .. i .. "'s request")
        end
        local idle = {}
        local stopped_for
        with_resolvd_stopped(function()
            local s = mono()
            for i = 1, 257 do idle[i] = open() end
            stopped_for = mono() - s
            for i = 1, 3 do
                t:assert_eq(ntfe.poll(sut, waiters[i], ntfe.POLLIN, 0), 0, "waiter " .. i .. " is still unanswered")
            end
        end)
        t:log(string.format("opened 257 connections in %.2f s with resolvd stopped", stopped_for))
        -- resolvd now accepts all 257 in one pass.
        local last, err = ntfe.recv(sut, idle[257], 3000, 4096)
        t:log("connection 257: read " .. (last and (#last .. " bytes") or tostring(err)))
        t:assert_eq(last, "", "the 257th is closed at once, with no reply")
        for _, i in ipairs({ 256, 1 }) do
            send_all(sut, idle[i], request({ query = "status" }))
            local r = read_reply(sut, idle[i], 3000)
            t:log("connection " .. i .. ": " .. tostring(r.reply and r.reply.kind or r.err))
            t:assert(r.reply and r.reply.kind == "status", "connection " .. i .. " was accepted and is answered")
        end
        local closes = sut:batch(function(b)
            for i = 1, 257 do b:syscall(sys.NR.close, idle[i]) end
            for i = 1, 3 do b:syscall(sys.NR.close, waiters[i]) end
        end)
        t:log("closed " .. #closes .. " descriptors")
        for i = 1, 3 do hold["slow" .. i .. ".example.test"] = nil end
        t:assert(raw(request({ query = "status" })).reply.ok, "resolvd answers afterwards")
    end)
