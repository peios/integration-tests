-- netd §8.3 — the resolver channel, netd's half: subscribing, when a
-- snapshot is sent and when it is not, a subscriber that cannot keep up,
-- and what a snapshot and each of its scopes carry. The DNS merge is
-- snapshot-merge.test.lua; which interfaces get a scope, and in what
-- order, is snapshot-scopes.test.lua.
--
-- Harness: the scripted gateway (helpers.gateway) and a whole Peios
-- (helpers.network). The test is its own resolver: it subscribes on the
-- control socket from the agent and reads the frames itself. resolvd is
-- subscribed too, as it always is; its handling is resolvd's testset.
--
-- Lease contents change without a profile edit (which would restart the
-- DHCP client) by re-arming the gateway's server with new options and
-- asking netd to `renew`: the ACK in RENEWING binds the new lease.
--
-- Own VMs: the tests edit the default profile, set the machine's
-- hostname (one-way: netd never unsets it) and briefly lower the kernel's
-- default socket send buffer; each puts back what it can, and the
-- hostname test runs after everything that reads `hostname`.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local unixsock = require("helpers.unixsock")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")
local msgpack = require("helpers.msgpack")
local rtnl = require("helpers.rtnl")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
local sut = network.boot({ bridges = { lan }, gateway = gw })

local function list_text(l) return "[" .. table.concat(l or {}, ", ") .. "]" end

-- ---- a subscriber ---------------------------------------------------------

--- Connect and send `subscribe`. Returns the subscription.
local function subscribe(who)
    who = who or sut
    local fd = assert(unixsock.socket(who, unixsock.AF_UNIX, unixsock.SOCK.STREAM))
    local c = unixsock.connect(who, fd, network.CONTROL)
    assert(c.ret == 0, "connect: " .. unixsock.errname(c.errno))
    local payload = msgpack.encode({ query = "subscribe" })
    ntfe.send(who, fd, string.pack("<I4", #payload) .. payload)
    return { who = who, fd = fd, buf = "" }
end

--- The next frame: its decoded reply and raw bytes, or nil and
--- "timeout" / "closed" / an errno.
local function next_frame(s, timeout_ms)
    while true do
        if #s.buf >= 4 then
            local len = string.unpack("<I4", s.buf)
            if #s.buf >= 4 + len then
                local body = s.buf:sub(5, 4 + len)
                s.buf = s.buf:sub(5 + len)
                return msgpack.decode(body), body
            end
        end
        local chunk, err = ntfe.recv(s.who, s.fd, timeout_ms or 3000, 65536)
        if not chunk then return nil, tostring(err) end
        if #chunk == 0 then return nil, "closed" end
        s.buf = s.buf .. chunk
    end
end

local function close(s) sys.close(s.who, s.fd) end

--- Pump the gateway until `s` yields a frame; returns it or nil.
local function frame_while_serving(s, timeout)
    local f
    gw:serve({ timeout = timeout or 20, until_ = function()
        f = next_frame(s, 100)
        return f ~= nil
    end })
    return f
end

local function scope_of(snap, name)
    for _, sc in ipairs(snap.scopes or {}) do if sc.name == name then return sc end end
end

--- Re-arm the gateway's DHCP server with `o` (merged over the defaults)
--- and ask netd to renew, so the client binds the new lease.
local function relese(o)
    local d = { pool = { "10.77.0.50" }, lease = 3600 }
    for k, v in pairs(o or {}) do d[k] = v end
    gw:dhcp(d)
    gw:forget()
    local r = network.call(sut, { query = "renew", interface = "eth0" })
    assert(r and r.ok, "renew: " .. tostring(r and r.error))
end

--- Pump until the gateway has ACKed a renew and the client is bound.
local function renewed()
    return gw:serve({ timeout = 15, until_ = function()
        if #gw:dhcp_messages(gateway.DHCP.REQUEST) == 0 then return false end
        local i = network.iface(network.status(sut), "eth0")
        return i and i.lease and i.lease.state == "bound"
    end })
end

-- ---------------------------------------------------------------------------

test("subscribe answers with a snapshot at once and keeps the connection; a publish that changes nothing sends nothing, one that changes the snapshot sends it",
    { spec = "netd *snapshot.subscribe netd *snapshot.sent-on-change" }, function(t)
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "netd bound")
        local s = subscribe()
        local first = next_frame(s, 3000)
        t:assert(first, "a snapshot at once")
        t:assert_eq(first.ok, true, "ok")
        t:assert_eq(first.kind, "snapshot", "kind snapshot")
        local sc = scope_of(first, "eth0")
        t:assert(sc, "eth0's scope")
        t:log("first: servers " .. list_text(sc.servers))
        local _, why = next_frame(s, 1000)
        t:assert_eq(why, "timeout", "the connection is kept open, and nothing more is sent yet")
        t:assert(network.call(sut, { query = "status" }).ok, "netd answers others meanwhile")

        -- A full pass, and a renew that brings back the same lease: each
        -- publishes, and neither changes the snapshot.
        t:assert(network.call(sut, { query = "reconcile" }).ok, "reconcile")
        relese({})
        t:assert(renewed(), "renewed with the same lease")
        gw:serve({ timeout = 1 })
        local extra
        extra, why = next_frame(s, 1500)
        t:assert(extra == nil and why == "timeout", "an equal snapshot is not sent")

        -- A different lease: one new snapshot.
        relese({ dns = { "10.77.0.1", "10.77.0.2" } })
        local f = frame_while_serving(s, 20)
        t:assert(f, "a changed snapshot is sent")
        t:log("after the change: servers " .. list_text(scope_of(f, "eth0").servers))
        t:assert_eq(list_text(scope_of(f, "eth0").servers), "[10.77.0.1, 10.77.0.2]", "carrying the new servers")
        renewed()
        extra, why = next_frame(s, 1500)
        t:assert(extra == nil and why == "timeout", "and only once")

        -- A new subscriber starts from the last snapshot published.
        local s2 = subscribe()
        local f2 = next_frame(s2, 3000)
        t:assert(f2, "the second subscriber's first snapshot")
        t:assert_eq(list_text(scope_of(f2, "eth0").servers), "[10.77.0.1, 10.77.0.2]", "is the latest")
        close(s2)
        close(s)

        relese({})
        renewed()
    end)

test("a snapshot is {ok, kind, hostname, scopes} and each scope carries the ten tabled fields; NTP servers are reported whatever Dns.Offered says",
    { spec = "netd *snapshot.contents netd *snapshot.scope-fields netd *snapshot.ntp-regardless-of-dns-offered" }, function(t)
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "netd bound")
        relese({ options = { { 42, gateway.opt.ip({ "10.77.0.123", "10.77.0.124" }) } } })
        t:assert(renewed(), "a lease with NTP servers")

        local s = subscribe()
        local snap, body = next_frame(s, 3000)
        t:assert(snap, "a snapshot")
        -- Exactly the four top-level keys.
        local keys = {}
        for k in pairs(snap) do keys[#keys + 1] = k end
        table.sort(keys)
        t:assert_eq(table.concat(keys, ","), "hostname,kind,ok,scopes", "the snapshot's fields")
        t:assert_eq(snap.hostname, "", "hostname: empty, none set")
        local st = network.status(sut)
        local e = network.iface(st, "eth0")
        local sc = scope_of(snap, "eth0")
        t:assert(sc, "eth0 has a scope")
        local skeys = {}
        for k in pairs(sc) do skeys[#skeys + 1] = k end
        table.sort(skeys)
        t:log("scope keys: " .. table.concat(skeys, ","))
        t:assert_eq(table.concat(skeys, ","),
            "addresses,default_route,domains,exclusive,ifid,level,metric,name,ntp,servers", "the ten scope fields")
        t:assert_eq(sc.ifid, e.ifid, "ifid: the interface id")
        t:assert_eq(sc.name, "eth0", "name: the kernel name")
        t:assert_eq(list_text(sc.servers), "[10.77.0.1]", "servers: the lease's")
        t:assert_eq(list_text(sc.domains), "[]", "domains: none offered")
        t:assert_eq(list_text(sc.ntp), "[10.77.0.123, 10.77.0.124]", "ntp: the lease's option 42")
        -- Every address the kernel holds on eth0, link-local included.
        local kernel = {}
        for _, a in ipairs(rtnl.addresses_of(sut, e.index)) do kernel[#kernel + 1] = a.address .. "/" .. a.prefix end
        table.sort(kernel)
        local mine = {}
        for k, v in ipairs(sc.addresses) do mine[k] = v end
        table.sort(mine)
        t:log("scope addresses " .. list_text(sc.addresses) .. "; kernel " .. list_text(kernel))
        t:assert_eq(table.concat(mine, " "), table.concat(kernel, " "), "addresses: every kernel address, address/prefix")
        local ll = false
        for _, a in ipairs(sc.addresses) do if a:match("^fe80:") then ll = true end end
        t:assert(ll, "addresses: the link-local one included")
        t:assert_eq(sc.default_route, true, "default_route: no Dns.Default, and the interface is routed")
        t:assert_eq(sc.exclusive, false, "exclusive: Dns.Exclusive unset")
        t:assert_eq(sc.metric, 100, "metric: a wired interface's default")
        t:assert_eq(sc.level, "routed", "level")

        -- The profile now says: no offered DNS, Dns.Default off, exclusive,
        -- metric 150. The edit restarts the client, so wait for the bound
        -- snapshot.
        network.write(sut, "Profiles\\default", { ["Dns.Offered"] = "dword:0", ["Dns.Default"] = "dword:0",
            ["Dns.Exclusive"] = "dword:1", ["Route.Metric"] = "dword:150" })
        local got
        gw:serve({ timeout = 40, until_ = function()
            local f = next_frame(s, 100)
            while f do
                local x = scope_of(f, "eth0")
                if x and x.metric == 150 and x.level == "routed" then got = x end
                f = next_frame(s, 10)
            end
            return got ~= nil
        end })
        t:assert(got, "a snapshot with the new profile, routed again")
        t:log(string.format("edited: servers %s ntp %s default_route %s exclusive %s metric %s",
            list_text(got.servers), list_text(got.ntp), tostring(got.default_route), tostring(got.exclusive),
            tostring(got.metric)))
        t:assert_eq(got.default_route, false, "default_route: Dns.Default when set, even while routed")
        t:assert_eq(got.exclusive, true, "exclusive: Dns.Exclusive")
        t:assert_eq(got.metric, 150, "metric: Route.Metric")
        t:assert_eq(list_text(got.servers), "[]", "servers: Dns.Offered off, so not the lease's")
        t:assert_eq(list_text(got.ntp), "[10.77.0.123, 10.77.0.124]", "ntp: reported regardless of Dns.Offered")
        t:assert_eq(list_text(network.iface(network.status(sut), "eth0").dns), "[]", "the status's dns is the same merge")
        close(s)

        for _, v in ipairs({ "Dns.Offered", "Dns.Default", "Dns.Exclusive", "Route.Metric" }) do
            network.reg(sut, { "del", network.KEY .. "\\Profiles\\default", v })
        end
        network.write(sut, "Profiles\\default", { ["Dns.Offered"] = "dword:1" })
        gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
        t:assert(network.serve_until(gw, sut, function(i)
            return network.bound(i) and #i.dns == 1
        end, { iface = "eth0", timeout = 60 }), "the default profile restored and bound")
    end)

-- The sockets netd holds open, read through /proc.
local function netd_sockets()
    local pid = assert(network.netd_pid(sut), "netd's pid")
    local n = 0
    for _, target in pairs(peinit.fds(sut, pid)) do
        if target:match("^socket:") then n = n + 1 end
    end
    return n
end

test("a subscriber that has closed, or whose socket buffer is full, is dropped; reconnecting gives a fresh snapshot",
    { spec = "netd *snapshot.slow-subscriber-dropped" }, function(t)
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "netd bound")
        local witness = subscribe()
        t:assert(next_frame(witness, 3000), "the witness subscribed")

        -- Closed: netd holds one more socket while subscribed, and lets
        -- it go at the first snapshot it cannot write.
        local n0 = netd_sockets()
        local s = subscribe()
        t:assert(next_frame(s, 3000), "subscribed")
        local n1 = netd_sockets()
        close(s)
        local turn = 0
        local function change()
            turn = turn + 1
            relese({ dns = { "10.77.0.1", string.format("10.77.1.%d", turn) } })
            local f = frame_while_serving(witness, 20)
            renewed()
            return f
        end
        t:assert(change(), "a change reached the witness")
        local n2
        pcall(wait_until, function() n2 = netd_sockets(); return n2 == n0 end,
            { timeout = 5, interval = 0.25, desc = "the closed subscriber dropped" })
        t:log(string.format("netd sockets: %d before, %d subscribed, %d after closing and a change", n0, n1, n2))
        t:assert_eq(n1, n0 + 1, "the subscription is one socket in netd")
        t:assert_eq(n2, n0, "dropped once a snapshot could not be written")

        -- Full: a subscriber that never reads. The socket's send buffer
        -- (netd's end, sized from net.core.wmem_default when the
        -- connection is made) is set small for this one connection.
        local saved = sut:read_file("/proc/sys/net/core/wmem_default"):gsub("%s+", "")
        sut:run("echo 8192 > /proc/sys/net/core/wmem_default"):assert_ok()
        local slow = subscribe()
        local first = next_frame(slow, 3000)
        sut:run("echo " .. saved .. " > /proc/sys/net/core/wmem_default"):assert_ok()
        t:assert(first, "the slow subscriber's first snapshot")
        local K = 14
        local last
        for _ = 1, K do
            last = change()
            t:assert(last, "change " .. turn .. " reached the witness")
        end
        -- Now read what the slow one was sent: a few frames, then the end.
        local frames, why = 0, nil
        while true do
            local f
            f, why = next_frame(slow, 2000)
            if not f then break end
            frames = frames + 1
        end
        t:log(string.format("slow subscriber: %d frames of %d changes, then %s", frames, K, tostring(why)))
        t:assert(why == "closed" or why == tostring(104), "netd dropped the slow subscriber (" .. tostring(why) .. ")")
        t:assert(frames < K, "it was dropped before it was sent every change")
        close(slow)

        -- The witness, which read promptly, is still subscribed.
        t:assert(change(), "the witness still receives changes")
        -- And a reconnect gets the current picture at once.
        local again = subscribe()
        local fresh = next_frame(again, 3000)
        t:assert(fresh, "a reconnect gets a snapshot")
        t:assert_eq(list_text(scope_of(fresh, "eth0").servers),
            string.format("[10.77.0.1, 10.77.1.%d]", turn), "the current one")
        close(again)
        close(witness)
        relese({})
        renewed()
    end)

test("the snapshot's hostname is the name netd last set",
    { spec = "netd *snapshot.contents" }, function(t)
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "netd bound")
        local s = subscribe()
        local f = next_frame(s, 3000)
        t:assert_eq(f.hostname, "", "none set yet")
        network.reg(sut, { "set", network.KEY, "Hostname", "sz:pt-snaphost" }):assert_ok()
        local got
        pcall(wait_until, function()
            local x = next_frame(s, 200)
            if x then got = x end
            return got ~= nil and got.hostname == "pt-snaphost"
        end, { timeout = 15, interval = 0.1, desc = "the hostname in a snapshot" })
        t:log("hostname now: " .. tostring(got and got.hostname))
        t:assert(got and got.hostname == "pt-snaphost", "the snapshot carries the name netd set")
        close(s)
    end)
