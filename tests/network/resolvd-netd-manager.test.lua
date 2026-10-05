-- PSPU §6.9 — the network manager channel against the real pair: netd's
-- `subscribe` (a snapshot at once, then a whole snapshot on every change,
-- the one held connection, the query right), each snapshot field as the
-- table defines it, a manager dropping a subscriber it cannot write to;
-- and resolvd's TRM §3.2 behaviour when netd refuses it or goes away.
--
-- Harness: the scripted gateway (helpers.gateway) with its DNS server
-- (helpers.dns), and a whole Peios (helpers.network). The agent is a
-- subscriber of its own on netd's control socket, beside resolvd. Two
-- dummy links (the image's dummy module) give netd more scopes: dummy0,
-- joined to profile `ptdum` with a static address (level `addressed`),
-- and dummy1, joined to `ptlink` with none (level `link`). eth0 is on
-- the gateway's DHCP (level `routed`), its lease offering 10.77.0.1 and
-- the search list `lease.test`.
--
-- Own VMs: rules and profiles of its own, ControlSecurity rewritten,
-- netd stopped and restarted, and a hostname set (one-way, so it comes
-- after every test that expects none).
--
-- resolvd is restarted with `svctl stop; rm -rf /run/resolvd; svctl
-- start`, not `svctl restart` (PEI-1373).

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local unixsock = require("helpers.unixsock")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")
local msgpack = require("helpers.msgpack")
local rtnl = require("helpers.rtnl")
local dns = require("helpers.dns")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
local LEASE = { pool = { "10.77.0.50" }, lease = 3600, dns = { "10.77.0.1" },
    options = { { 119, gateway.opt.names({ "lease.test" }) } } }
gw:dhcp(LEASE)
local sut = network.boot({ bridges = { lan }, gateway = gw })

dns.serve(gw, { zone = {
    ["www.example.test"] = { { type = "A", ttl = 300, data = "10.77.9.1" } },
    ["new.example.test"] = { { type = "A", ttl = 300, data = "10.77.9.2" } },
    ["cached.example.test"] = { { type = "A", ttl = 300, data = "10.77.9.3" } },
} })

local RSOCK = "/run/resolvd/resolv.sock"
local RESTART = "svctl stop resolvd; rm -rf /run/resolvd; svctl start resolvd"
local NETWORK_QUERY, NETWORK_CONTROL, NETWORK_ALL_ACCESS = 0x1, 0x2, 0x000F0003

local function list(l) return "[" .. table.concat(l or {}, ", ") .. "]" end

-- ---- resolvd ----------------------------------------------------------------

local function rstatus()
    local s, err = network.call(sut, { query = "status" }, { path = RSOCK })
    assert(s and s.ok, "resolvd status: " .. tostring(err or (s and s.error)))
    return s
end

local function now()
    return assert(tonumber(sut:run("date +%s.%N").stdout:match("[%d%.]+")), "guest clock")
end

local function rlog(since)
    local r = sut:run("evctl 'LOGS FROM resolvd SINCE 1h ago TAKE 5000'")
    assert(r.exit_code == 0, "evctl: " .. r.stderr)
    local newest_first = {}
    for line in r.stdout:gmatch("[^\n]+") do
        local msg = line:match('message="(.-)"  origin=')
        local ts = tonumber(line:match("timestamp=(%d+)"))
        if msg and ts and ts / 1e9 > (since or 0) then
            newest_first[#newest_first + 1] = { ts = ts / 1e9, msg = (msg:gsub("\\(.)", "%1")) }
        end
    end
    local out = {}
    for i = #newest_first, 1, -1 do out[#out + 1] = newest_first[i] end
    return out
end

local function matching(lines, text)
    local out = {}
    for _, l in ipairs(lines) do if l.msg:find(text, 1, true) then out[#out + 1] = l end end
    return out
end

local function dump(t, lines)
    local out = {}
    for _, l in ipairs(lines) do out[#out + 1] = string.format("%.3f %s", l.ts, l.msg) end
    t:log("resolvd log:\n" .. table.concat(out, "\n"))
end

local function served(cmd, timeout)
    local p = sut:run_async("sh", { args = { "-c", cmd } })
    gw:serve({ timeout = timeout or 20, until_ = function() return p:status() == "exited" end })
    return p:wait(5)
end

local function ask(name)
    local r = served("resolv query " .. name .. " A")
    return { exit = r.exit_code, line = r.stdout:match("^[^\n]*") or "", out = r.stdout .. r.stderr }
end

local function asked(name)
    return dns.queries(gw, function(e)
        local qn = e.msg and e.msg.questions[1]
        return qn ~= nil and dns.same_name(qn.name, name)
    end)
end

-- ---- a subscriber of the agent's -------------------------------------------

local function subscribe()
    local fd = assert(unixsock.socket(sut, unixsock.AF_UNIX, unixsock.SOCK.STREAM))
    local c = unixsock.connect(sut, fd, network.CONTROL)
    assert(c.ret == 0, "connect: " .. unixsock.errname(c.errno))
    local payload = msgpack.encode({ query = "subscribe" })
    ntfe.send(sut, fd, string.pack("<I4", #payload) .. payload)
    return { fd = fd, buf = "" }
end

--- The next frame (decoded), or nil and "timeout" / "closed" / errno.
local function next_frame(s, timeout_ms)
    while true do
        if #s.buf >= 4 then
            local len = string.unpack("<I4", s.buf)
            if #s.buf >= 4 + len then
                local body = s.buf:sub(5, 4 + len)
                s.buf = s.buf:sub(5 + len)
                return msgpack.decode(body)
            end
        end
        local chunk, err = ntfe.recv(sut, s.fd, timeout_ms or 3000, 65536)
        if not chunk then return nil, tostring(err) end
        if #chunk == 0 then return nil, "closed" end
        s.buf = s.buf .. chunk
    end
end

local function close(s) sys.close(sut, s.fd) end

--- Pump until a frame satisfying `pred` arrives on `s`; returns it.
local function frame_until(s, pred, timeout)
    local got
    gw:serve({ timeout = timeout or 30, until_ = function()
        local f = next_frame(s, 100)
        while f do
            if pred(f) then got = f; return true end
            f = next_frame(s, 10)
        end
        return false
    end })
    return got
end

local function scope_of(snap, name)
    for _, sc in ipairs(snap.scopes or {}) do if sc.name == name then return sc end end
end

local function scope_names(snap)
    local out = {}
    for _, sc in ipairs(snap.scopes or {}) do out[#out + 1] = sc.name end
    return table.concat(out, ",")
end

--- A one-off request on its own connection: the reply, and whether netd
--- closed the connection after it.
local function one_shot(req)
    local fd = assert(unixsock.socket(sut, unixsock.AF_UNIX, unixsock.SOCK.STREAM))
    assert(unixsock.connect(sut, fd, network.CONTROL).ret == 0, "connect")
    local p = msgpack.encode(req)
    ntfe.send(sut, fd, string.pack("<I4", #p) .. p)
    local s = { fd = fd, buf = "" }
    local reply = next_frame(s, 5000)
    local _, why = next_frame(s, 1500)
    sys.close(sut, fd)
    return reply, why
end

local function ifindex(name)
    return tonumber((sut:read_file("/sys/class/net/" .. name .. "/ifindex"):gsub("%s+", "")))
end

--- A ControlSecurity: SYSTEM all access, and Everyone `mask`.
local function control_descriptor_hex(everyone)
    local system = string.pack("BB", 1, 1) .. string.pack(">I2>I4", 0, 5) .. string.pack("<I4", 18)
    local world = string.pack("BB", 1, 1) .. string.pack(">I2>I4", 0, 1) .. string.pack("<I4", 0)
    local aces = string.pack("<BBI2I4", 0, 0, 8 + #system, NETWORK_ALL_ACCESS) .. system
        .. string.pack("<BBI2I4", 0, 0, 8 + #world, everyone) .. world
    local acl = string.pack("<BBI2I2I2", 2, 0, 8 + #aces, 2, 0) .. aces
    local header = string.pack("<BBI2I4I4I4I4", 1, 0, 0x8004, 20, 20 + #system, 0, 20 + 2 * #system)
    return ((header .. system .. system .. acl):gsub(".", function(b) return string.format("%02x", b:byte()) end))
end

local function control_security(everyone)
    if everyone then
        network.reg(sut, { "set", network.KEY, "ControlSecurity", "hex:" .. control_descriptor_hex(everyone) }):assert_ok()
    else
        network.reg(sut, { "del", network.KEY, "ControlSecurity" })
    end
end

-- ---------------------------------------------------------------------------

test("subscribe is answered at once with a snapshot and held open, a fresh snapshot following each change; every other request gets one reply and its connection is closed",
    { spec = "PSPU *nri-manager.snapshot-at-once-then-on-every-change PSPU *nri-manager.only-subscribe-holds-a-connection" },
    function(t)
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "netd bound")
        local s = subscribe()
        local first = next_frame(s, 2000)
        t:assert(first, "a snapshot within 2 s of subscribing")
        t:assert_eq(first.ok, true, "ok: true")
        t:assert_eq(first.kind, "snapshot", "kind: snapshot")
        local _, why = next_frame(s, 1500)
        t:assert_eq(why, "timeout", "then the connection stays open, quiet while nothing changes")

        for _, req in ipairs({ { query = "status" }, { query = "reconcile" } }) do
            local reply, after = one_shot(req)
            t:log(req.query .. ": ok " .. tostring(reply and reply.ok) .. ", then " .. tostring(after))
            t:assert(reply and reply.ok, req.query .. " answered")
            t:assert_eq(after, "closed", req.query .. ": netd closes the connection after its reply")
        end
        _, why = next_frame(s, 500)
        t:assert_eq(why, "timeout", "the subscription is still open")

        -- A change: a profile with a static address joined to dummy0.
        network.write(sut, "Profiles\\ptdum", { ["Address.Static"] = "multi:10.99.0.1/24", ["Route.Metric"] = "dword:50" })
        network.write(sut, "Rules\\Interface\\pt-dum", { ["Interface.Equal"] = "multi:dummy0",
            Priority = "dword:20", Actions = "multi:JOIN(ptdum)" })
        network.write(sut, "Profiles\\ptlink", { ["Route.Metric"] = "dword:70" })
        network.write(sut, "Rules\\Interface\\pt-link", { ["Interface.Equal"] = "multi:dummy1",
            Priority = "dword:20", Actions = "multi:JOIN(ptlink)" })
        local mp = sut:run("modprobe dummy numdummies=2")
        t:assert_eq(mp.exit_code, 0, "dummy loads: " .. mp.stderr)
        local f = frame_until(s, function(x) return scope_of(x, "dummy0") ~= nil end)
        t:assert(f, "the new interface's scope arrives on the held connection, unasked")
        t:log("scopes now: " .. scope_names(f))
        close(s)
    end)

test("each snapshot is the whole picture: a change to one scope resends every scope in full, and resolvd's scopes are the latest snapshot's",
    { spec = "PSPU *nri-manager.snapshot-is-whole-picture" }, function(t)
        local s = subscribe()
        local before = next_frame(s, 2000)
        t:assert(before and scope_of(before, "eth0") and scope_of(before, "dummy0"), "eth0 and dummy0 both have scopes")
        network.reg(sut, { "set", network.KEY .. "\\Profiles\\ptdum", "Dns.Domains", "multi:whole.test" }):assert_ok()
        local f = frame_until(s, function(x)
            local d = scope_of(x, "dummy0")
            return d ~= nil and d.domains[1] == "whole.test"
        end)
        t:assert(f, "a snapshot for dummy0's change")
        t:log("scopes: " .. scope_names(before) .. " -> " .. scope_names(f))
        t:assert_eq(scope_names(f), scope_names(before), "every scope is in it, not just the one that changed")
        local e0, e1 = scope_of(before, "eth0"), scope_of(f, "eth0")
        t:assert_eq(msgpack.encode(e1), msgpack.encode(e0), "eth0's scope is resent whole and unchanged")
        local st
        pcall(wait_until, function()
            st = rstatus()
            for _, sc in ipairs(st.scopes) do
                if sc.interface == "dummy0" and sc.domains[1] == "whole.test" then return true end
            end
            return false
        end, { timeout = 10, interval = 0.2, desc = "resolvd follows" })
        local names = {}
        for _, sc in ipairs(st.scopes) do names[#names + 1] = sc.interface end
        t:assert_eq(table.concat(names, ","), scope_names(f), "resolvd holds the same scopes, in the same order")
        close(s)
    end)

test("snapshot fields: scopes in metric order; servers the profile's then the lease's; domains the profile's then the lease's search list; every unicast address in CIDR form; default_route Dns.Default, else whether there is a default route; exclusive Dns.Exclusive; metric the route metric; level link, addressed or routed",
    { spec = "PSPU *nri-manager.snapshot-scopes-in-metric-order PSPU *nri-manager.scope-servers-order PSPU *nri-manager.scope-domains-order PSPU *nri-manager.scope-addresses-cidr PSPU *nri-manager.scope-default-route PSPU *nri-manager.scope-exclusive PSPU *nri-manager.scope-metric PSPU *nri-manager.scope-level" },
    function(t)
        local s = subscribe()
        -- dummy1 must be up for netd to call it link; dummies have carrier.
        local snap = frame_until(s, function(x)
            local d1 = scope_of(x, "dummy1")
            return d1 ~= nil and d1.level == "link"
        end, 30)
        t:assert(snap, "dummy1 reaches link")
        t:log("order: " .. scope_names(snap))
        t:assert_eq(scope_names(snap), "dummy0,dummy1,eth0", "metric order: 50, 70, 100")
        local d0, d1, e = scope_of(snap, "dummy0"), scope_of(snap, "dummy1"), scope_of(snap, "eth0")
        t:assert_eq(d0.metric, 50, "dummy0's metric is its Route.Metric")
        t:assert_eq(d1.metric, 70, "dummy1's")
        t:assert_eq(e.metric, 100, "eth0's (the wired default)")
        t:assert_eq(d0.level, "addressed", "dummy0: an address, no default route")
        t:assert_eq(d1.level, "link", "dummy1: no usable address")
        t:assert_eq(e.level, "routed", "eth0: a default route")
        t:assert_eq(d0.default_route, false, "dummy0: no Dns.Default and no default route")
        t:assert_eq(e.default_route, true, "eth0: no Dns.Default, a default route")
        t:assert_eq(d0.exclusive, false, "no Dns.Exclusive")

        -- Addresses: every unicast address the kernel holds, CIDR form.
        local function kernel(name)
            local out = {}
            for _, a in ipairs(rtnl.addresses_of(sut, ifindex(name))) do out[#out + 1] = a.address .. "/" .. a.prefix end
            table.sort(out)
            return table.concat(out, " ")
        end
        local function sorted(l)
            local c = {}
            for i, v in ipairs(l) do c[i] = v end
            table.sort(c)
            return table.concat(c, " ")
        end
        t:log("dummy0 " .. list(d0.addresses) .. "; eth0 " .. list(e.addresses))
        t:assert_eq(sorted(d0.addresses), kernel("dummy0"), "dummy0: every address, address/prefix")
        t:assert_eq(sorted(e.addresses), kernel("eth0"), "eth0: every address, address/prefix")
        local has = false
        for _, a in ipairs(d0.addresses) do if a == "10.99.0.1/24" then has = true end end
        t:assert(has, "dummy0's static address as 10.99.0.1/24")

        -- Flags from the profile.
        network.write(sut, "Profiles\\ptdum", { ["Dns.Default"] = "dword:1", ["Dns.Exclusive"] = "dword:1",
            ["Route.Metric"] = "dword:150" })
        snap = frame_until(s, function(x)
            local d = scope_of(x, "dummy0")
            return d ~= nil and d.metric == 150 and d.default_route and d.exclusive
        end)
        t:assert(snap, "dummy0: Dns.Default and Dns.Exclusive set, metric 150")
        t:log("order: " .. scope_names(snap))
        t:assert_eq(scope_names(snap), "dummy1,eth0,dummy0", "metric order again: 70, 100, 150")
        t:assert_eq(scope_of(snap, "dummy0").default_route, true, "default_route: Dns.Default, though no default route")
        t:assert_eq(scope_of(snap, "dummy0").exclusive, true, "exclusive: Dns.Exclusive")
        for _, v in ipairs({ "Dns.Default", "Dns.Exclusive", "Dns.Domains" }) do
            network.reg(sut, { "del", network.KEY .. "\\Profiles\\ptdum", v })
        end

        -- Servers and domains: the profile's, then the lease's.
        network.write(sut, "Profiles\\default", { ["Dns.Servers"] = "multi:10.77.0.9", ["Dns.Domains"] = "multi:prof.test" })
        snap = frame_until(s, function(x)
            local d = scope_of(x, "eth0")
            return d ~= nil and d.level == "routed" and #d.servers == 2 and #d.domains == 2
        end, 60)
        t:assert(snap, "eth0 rebound with the profile's DNS values")
        local sc = scope_of(snap, "eth0")
        t:log("eth0 servers " .. list(sc.servers) .. " domains " .. list(sc.domains))
        t:assert_eq(list(sc.servers), "[10.77.0.9, 10.77.0.1]", "servers: the profile's, then the lease's")
        t:assert_eq(list(sc.domains), "[prof.test, lease.test]", "domains: the profile's, then the lease's search list")
        network.reg(sut, { "del", network.KEY .. "\\Profiles\\default", "Dns.Servers" })
        network.reg(sut, { "del", network.KEY .. "\\Profiles\\default", "Dns.Domains" })
        t:assert(frame_until(s, function(x)
            local d = scope_of(x, "eth0")
            return d ~= nil and d.level == "routed" and list(d.servers) == "[10.77.0.1]"
        end, 60), "eth0 back to the lease's servers")
        close(s)
    end)

test("the ifid is the interface's stable identity and resolvd's cache key: it is netd's interface id, unchanged by a netd restart, so resolvd's answers under it survive one",
    { spec = "PSPU *nri-manager.scope-ifid-is-cache-key" }, function(t)
        local s = subscribe()
        local snap = next_frame(s, 2000)
        close(s)
        local e = network.iface(network.status(sut), "eth0")
        t:assert_eq(scope_of(snap, "eth0").ifid, e.ifid, "the scope's ifid is netd's interface id")
        sut:run("resolv flush"):assert_ok()
        local a = ask("cached.example.test")
        t:assert(a.line:find("^found  dns"), "an answer: " .. a.line)
        local n = rstatus().cache_entries
        t:assert(n >= 1, "cached")
        local since = now()
        network.restart_netd(sut)
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "netd bound again")
        s = subscribe()
        snap = next_frame(s, 2000)
        close(s)
        t:assert_eq(scope_of(snap, "eth0").ifid, e.ifid, "the same ifid from the new netd")
        wait_until(function() return #matching(rlog(since), "resolvd: info: subscribed to netd") > 0 end,
            { timeout = 15, interval = 0.25, desc = "resolvd resubscribed" })
        sut:run("sleep 0.5")
        t:assert_eq(rstatus().cache_entries, n, "resolvd's cache kept every answer")
        dns.forget(gw)
        a = ask("cached.example.test")
        t:log("after the restart: " .. a.line)
        t:assert(a.line:find("^found  cache"), "still served from the cache")
        t:assert_eq(#asked("cached.example.test"), 0, "nothing asked upstream")
    end)

test("a manager may drop a subscriber it cannot write to: netd lets go of one that has closed once there is a snapshot to send",
    { spec = "PSPU *nri-manager.manager-drops-unwritable-subscriber" }, function(t)
        -- netd's sockets, as the set of their inodes. Earlier tests' closed
        -- subscribers may still be held too, so the subscription's own
        -- socket is picked out as the one it added.
        local function netd_sockets()
            local out = {}
            for _, target in pairs(peinit.fds(sut, assert(network.netd_pid(sut)))) do
                if target:match("^socket:") then out[target] = true end
            end
            return out
        end
        local before = netd_sockets()
        local s = subscribe()
        t:assert(next_frame(s, 2000), "subscribed")
        local added = {}
        for k in pairs(netd_sockets()) do if not before[k] then added[#added + 1] = k end end
        t:log("netd's sockets added by the subscription: " .. table.concat(added, " "))
        t:assert_eq(#added, 1, "the subscription is one socket in netd")
        local mine = added[1]
        close(s)
        network.reg(sut, { "set", network.KEY .. "\\Profiles\\ptdum", "Route.Metric", "dword:60" }):assert_ok()
        local gone = pcall(wait_until, function() return not netd_sockets()[mine] end,
            { timeout = 10, interval = 0.25, desc = "the subscriber dropped" })
        t:assert(gone, "after the next snapshot netd has let it go")
    end)

test("subscribe needs the query right: refused (no NETWORK_QUERY for Everyone), resolvd connects, is refused, and reconnects about every 0.5 s, logging three lines each time; granted, it stays",
    { spec = "PSPU *nri-manager.subscribe-requires-network-query resolvd *netd-reconnect.refusal-reconnects-every-half-second" },
    function(t)
        control_security(NETWORK_CONTROL)
        -- The control object follows ControlSecurity at the next connection.
        pcall(wait_until, function()
            local f = network.call(sut, { query = "status" })   -- SYSTEM, still all access
            return f and f.ok
        end, { timeout = 5, interval = 0.2, desc = "netd answering" })
        sut:run("sleep 1")
        local since = now()
        sut:run(RESTART, { timeout = 30 }):assert_ok()
        sut:run("sleep 5")
        local lines = rlog(since)
        dump(t, lines)
        local subs = matching(lines, "resolvd: info: subscribed to netd")
        local refusals = matching(lines, "resolvd: warn: netd refused the subscription: access denied")
        local losses = matching(lines, "resolvd: warn: lost the netd channel; reconnecting")
        t:log(string.format("%d connections, %d refusals, %d losses", #subs, #refusals, #losses))
        t:assert(#subs >= 8, "about two connections a second")
        t:assert(math.abs(#refusals - #subs) <= 1 and math.abs(#losses - #subs) <= 1,
            "each connection refused and lost")
        local gaps = {}
        for i = 2, #subs do gaps[#gaps + 1] = string.format("%.2f", subs[i].ts - subs[i - 1].ts) end
        t:log("gaps: " .. table.concat(gaps, " "))
        for i = 2, #subs do
            local g = subs[i].ts - subs[i - 1].ts
            t:assert(g > 0.4 and g < 0.8, string.format("gap %d is about 0.5 s (%.3f)", i - 1, g))
        end
        -- Grant Everyone the query right (and nothing else): the next
        -- attempt is kept.
        control_security(NETWORK_QUERY)
        local st = nil
        pcall(wait_until, function()
            st = rstatus()
            return st.netd and #st.scopes > 0
        end, { timeout = 10, interval = 0.2, desc = "resolvd subscribed" })
        t:assert(st and st.netd and #st.scopes > 0, "resolvd connected and was sent a snapshot")
        local mark = now()
        sut:run("sleep 1.5")
        t:assert_eq(#matching(rlog(mark), "netd refused"), 0, "no refusal once granted")
        t:assert(rstatus().netd, "still connected")
        control_security(nil)
    end)

test("PSPU: the resolver reconnects with backoff whenever the connection is lost; a refusal is a loss, so the gaps should grow (0.5 s doubling)",
    { spec = "PSPU *nri-manager.reconnect-with-backoff", tags = { "known-bug" } }, function(t)
        -- PEI-1350: each refused connection is a successful connect, which
        -- resets the backoff, so resolvd reconnects every 0.5 s forever.
        control_security(NETWORK_CONTROL)
        sut:run("sleep 1")
        local since = now()
        sut:run(RESTART, { timeout = 30 }):assert_ok()
        sut:run("sleep 6")
        local subs = matching(rlog(since), "resolvd: info: subscribed to netd")
        control_security(nil)
        local gaps = {}
        for i = 2, #subs do gaps[#gaps + 1] = string.format("%.2f", subs[i].ts - subs[i - 1].ts) end
        t:log(#subs .. " connections in 6 s; gaps " .. table.concat(gaps, " "))
        -- 0.5, 1, 2, 4: at most five connections in six seconds.
        t:assert(#subs <= 5, "the backoff grows between refused connections")
        t:assert(#subs < 3 or (subs[3].ts - subs[2].ts) > 1.5 * (subs[2].ts - subs[1].ts),
            "the second gap is longer than the first")
        pcall(wait_until, function() return rstatus().netd end, { timeout = 15, interval = 0.25 })
    end)

test("a snapshot's hostname is the manager's: empty while unset, the name once netd sets one",
    { spec = "PSPU *nri-manager.snapshot-hostname" }, function(t)
        local s = subscribe()
        local f = next_frame(s, 2000)
        t:assert_eq(f.hostname, "", "empty while netd has set none")
        network.reg(sut, { "set", network.KEY, "Hostname", "sz:pt-mgrhost" }):assert_ok()
        local got = frame_until(s, function(x) return x.hostname == "pt-mgrhost" end, 20)
        t:assert(got, "the name netd set")
        close(s)
        local st = rstatus()
        pcall(wait_until, function() st = rstatus(); return st.hostname == "pt-mgrhost" end,
            { timeout = 10, interval = 0.2 })
        t:assert_eq(st.hostname, "pt-mgrhost", "and resolvd uses it")
    end)

test("netd gone: resolvd keeps its scopes, hostname and cache, answers synthetic, cached and new names (asking the servers it holds), reports netd false, and reconnects when netd returns",
    { spec = "resolvd *netd-reconnect.state-kept-while-disconnected PSPU *nri-manager.keeps-answering-while-disconnected" },
    function(t)
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "netd bound")
        pcall(wait_until, function() return rstatus().netd end, { timeout = 15, interval = 0.25 })
        sut:run("resolv flush"):assert_ok()
        local a = ask("www.example.test")
        t:assert(a.line:find("^found  dns via 10%.77%.0%.1 on eth0"), "www via eth0: " .. a.line)
        local before = rstatus()
        sut:run("svctl stop netd", { timeout = 30 }):assert_ok()
        local st
        pcall(wait_until, function() st = rstatus(); return st.netd == false end,
            { timeout = 10, interval = 0.2, desc = "resolvd sees netd gone" })
        t:assert_eq(st.netd, false, "status: netd not connected")
        t:assert_eq(json.encode(st.scopes), json.encode(before.scopes), "the scopes are the last snapshot's")
        t:assert_eq(st.hostname, "pt-mgrhost", "the hostname from the last snapshot is kept")
        t:assert_eq(st.cache_entries, before.cache_entries, "the cache is kept")
        t:log(string.format("disconnected: hostname %q, %d scopes, %d cached", st.hostname, #st.scopes, st.cache_entries))
        dns.forget(gw)
        a = ask("www.example.test")
        t:assert(a.line:find("^found  cache"), "a cached answer is served: " .. a.line)
        a = ask("new.example.test")
        t:log("new: " .. a.line)
        t:assert(a.line:find("^found  dns via 10%.77%.0%.1 on eth0"), "a new name goes to the scope's server")
        t:assert_eq(#asked("new.example.test"), 1, "which the gateway saw")
        a = ask("localhost")
        t:assert(a.line:find("^found  synthetic"), "localhost answered: " .. a.line)
        a = ask("pt-mgrhost")
        t:assert(a.line:find("^found  synthetic"), "and the hostname: " .. a.line)

        sut:run("svctl start netd", { timeout = 30 }):assert_ok()
        pcall(wait_until, function() return rstatus().netd end, { timeout = 20, interval = 0.25, desc = "reconnected" })
        t:assert(rstatus().netd, "resolvd reconnects once netd is back")
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "netd bound again")
    end)
