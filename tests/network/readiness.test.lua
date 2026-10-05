-- netd §8.2 — readiness: an interface's level and what counts towards it
-- (usable addresses, any default route), the machine's level over joined
-- interfaces only, and its publication on change to the log and the
-- registry. The notify-socket half of publishing is readiness-notify.
--
-- Harness: the scripted gateway (helpers.gateway) and a whole Peios
-- (helpers.network). Besides eth0, the test loads the dummy module for
-- five dummy links: dummy0..dummy3 under an IGNORE rule, and dummy4
-- joined to a bare profile with one static address.
--
-- Why IGNOREd links for the level rules: on a joined interface every
-- address is netd's, and a foreign one is removed in the very pass that
-- notices it (§4.3), so the status never shows it. An IGNOREd link is
-- never touched, and its `level` is still computed and reported (§9.2),
-- so foreign state put on it with rtnetlink shows exactly which addresses
-- and routes count. Machine level is read from the status reply, the
-- per-interface `Status Readiness` and the machine `Readiness` from the
-- registry, the publications from netd's log.
--
-- Own VMs: the rules, profile and dummy links are machine-wide. Tests run
-- in order: the first builds the links, the second moves eth0 between
-- JOIN and IGNORE and pulls its cable, the third reads what was
-- published along the way.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local rtnl = require("helpers.rtnl")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")
local sha1 = require("helpers.sha1")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
local sut = network.boot({ bridges = { lan }, gateway = gw })

local IGNORED = { "dummy0", "dummy1", "dummy2", "dummy3" }

local function list_text(l) return "[" .. table.concat(l or {}, ", ") .. "]" end

local function ifindex(name)
    return tonumber((sut:read_file("/sys/class/net/" .. name .. "/ifindex"):gsub("%s+", "")))
end

local function iface(name) return network.iface(network.status(sut), name) end

--- Wait until `name`'s reported level is `level`; returns the interface.
local function level_becomes(t, name, level, what)
    local last
    local ok = pcall(wait_until, function()
        last = iface(name)
        return last ~= nil and last.level == level
    end, { timeout = 15, interval = 0.25, desc = name .. " " .. level })
    t:log(string.format("%s: level %s, addresses %s", name, tostring(last and last.level),
        list_text(last and last.addresses)))
    t:assert(ok, what .. ": " .. name .. " is " .. level .. " (is " .. tostring(last and last.level) .. ")")
    return last
end

-- ---- rtnetlink and ioctl the helpers do not have -------------------------

local function nla(attr, payload)
    local len = 4 + #payload
    return string.pack("<I2I2", len, attr) .. payload .. string.rep("\0", (4 - len % 4) % 4)
end

--- RTM_NEWADDR for an IPv6 address with explicit lifetimes (IFA_CACHEINFO):
--- a preferred lifetime of 0 makes the kernel add it deprecated.
local function add_address6_lifetimes(index, addr, prefix, preferred, valid)
    local s = sut:syscall(ntfe.NR.socket, 16, ntfe.SOCK_RAW, 0)
    assert(s.ret >= 0, "netlink socket")
    local fd = s.ret
    local bytes = ntfe.ip6(addr)
    local body = string.pack("<I1I1I1I1i4", 10, prefix, 0, 0, index)
        .. nla(1, bytes) .. nla(6, string.pack("<I4I4I4I4", preferred, valid, 0, 0))
    -- REQUEST | ACK | EXCL | CREATE
    ntfe.send(sut, fd, string.pack("<I4I2I2I4I4", 16 + #body, 20, 0x1 | 0x4 | 0x200 | 0x400, 1, 0) .. body)
    local reply = ntfe.recv(sut, fd, 3000, 4096)
    sys.close(sut, fd)
    assert(reply and #reply >= 20, "no netlink ack")
    local err = string.unpack("<i4", reply, 17)
    return err == 0, -err
end

--- Clear IFF_NOARP on a link (a dummy is born NOARP, which skips DAD).
local function clear_noarp(name)
    local flags = assert(ntfe.if_flags(sut, name))
    local fd = sut:syscall(ntfe.NR.socket, ntfe.AF_INET, ntfe.SOCK_DGRAM, 0).ret
    local r = sut:syscall(sys.NR.ioctl, {
        args = { fd, 0x8914, 0 }, -- SIOCSIFFLAGS
        bufs = { name .. string.rep("\0", 16 - #name)
            .. string.pack("<I2", flags & ~0x80) .. string.rep("\0", 22) },
        ptrs = { 2 },
    })
    sys.close(sut, fd)
    assert(r.ret == 0, "SIOCSIFFLAGS " .. name .. ": " .. sys.errname(r.errno or 0))
end

local function rt_addr(index, addr)
    return rtnl.address(sut, index, addr)
end

-- ---------------------------------------------------------------------------

test("an interface's level is absent, link, addressed or routed from the kernel's state; 169.254, global, deprecated and tentative addresses count, link-local IPv6 and loopback do not; any default route counts",
    { spec = "netd *readiness.interface-level netd *readiness.usable-address netd *readiness.any-default-route-counts" },
    function(t)
        local s = network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 })
        t:assert(s, "netd bound")
        t:assert_eq(network.iface(s, "eth0").level, "routed", "eth0, with a lease and netd's default route, is routed")

        network.write(sut, "Profiles\\ptstatic", { ["Address.Static"] = "multi:10.99.0.1/24" })
        network.write(sut, "Rules\\Interface\\pt-ignore", {
            ["Interface.Equal"] = "multi:" .. table.concat(IGNORED, ","),
            Priority = "dword:20", Actions = "multi:IGNORE" })
        network.write(sut, "Rules\\Interface\\pt-join", {
            ["Interface.Equal"] = "multi:dummy4",
            Priority = "dword:20", Actions = "multi:JOIN(ptstatic)" })
        local taken = pcall(wait_until, function()
            return network.logged(sut, "interface layer: 3 rule tree(s), 2 profile(s)")
        end, { timeout = 15, interval = 0.3, desc = "the rules taken" })
        if not taken then
            local logs = network.logs(sut, { take = 25 })
            t:log("netd log (newest first):\n" .. table.concat(logs, "\n"))
            t:log("refusal: " .. tostring(network.status(sut).refusal))
        end
        t:assert(taken, "the rules and profile were taken")

        local mp = sut:run("modprobe dummy numdummies=5")
        t:assert_eq(mp.exit_code, 0, "dummy loads: " .. mp.stderr)
        wait_until(function()
            local st = network.status(sut)
            for _, n in ipairs(IGNORED) do
                local i = network.iface(st, n)
                if not (i and i.verdict == "IGNORE") then return false end
            end
            local j = network.iface(st, "dummy4")
            return j ~= nil and j.verdict == "JOIN"
        end, { timeout = 15, interval = 0.3, desc = "the dummies judged" })

        -- dummy0 walks the four levels.
        local i = iface("dummy0")
        t:log("dummy0 as made: up " .. tostring(i.up) .. " level " .. i.level)
        t:assert_eq(i.up, false, "dummy0 is down")
        t:assert_eq(i.level, "absent", "not up: absent")
        assert(ntfe.if_up(sut, "dummy0"))
        i = level_becomes(t, "dummy0", "link", "up with carrier, only a link-local")
        t:assert_eq(i.carrier, true, "a dummy has carrier when up")
        for _, a in ipairs(i.addresses) do
            t:assert(a:match("^fe80:") ~= nil, "dummy0's only address is the kernel's link-local: " .. a)
        end
        local i0 = ifindex("dummy0")
        t:assert(rtnl.add_address(sut, i0, "169.254.7.7", { prefix = 16 }), "add 169.254.7.7/16")
        level_becomes(t, "dummy0", "addressed", "a 169.254 address counts")
        t:assert(rtnl.add_route(sut, { dst = "0.0.0.0", prefix = 0, oif = i0, protocol = rtnl.RTPROT.STATIC }),
            "add a foreign IPv4 default route")
        local routes = rtnl.routes_of(sut, i0)
        local foreign = false
        for _, r in ipairs(routes) do
            if r.prefix == 0 and r.family == 4 and r.protocol == rtnl.RTPROT.STATIC then foreign = true end
        end
        t:assert(foreign, "the default route is not netd's (protocol static)")
        level_becomes(t, "dummy0", "routed", "any default route of the main table counts")

        -- dummy1: a global IPv6 address, then an IPv6 default route.
        assert(ntfe.if_up(sut, "dummy1"))
        level_becomes(t, "dummy1", "link", "dummy1 up")
        local i1 = ifindex("dummy1")
        t:assert(rtnl.add_address(sut, i1, "fd99::1", { prefix = 64 }), "add fd99::1/64")
        level_becomes(t, "dummy1", "addressed", "a global IPv6 address counts")
        t:assert(rtnl.add_route(sut, { dst = "::", prefix = 0, oif = i1, protocol = rtnl.RTPROT.STATIC }),
            "add a foreign IPv6 default route")
        level_becomes(t, "dummy1", "routed", "an IPv6 default route counts as well")

        -- dummy2: loopback does not count; a tentative address does. DAD
        -- is made slow (20 probes 10 s apart) so the address stays
        -- tentative for the whole check.
        clear_noarp("dummy2")
        sut:run("echo 20 > /proc/sys/net/ipv6/conf/dummy2/dad_transmits"):assert_ok()
        sut:run("echo 10000 > /proc/sys/net/ipv6/neigh/dummy2/retrans_time_ms"):assert_ok()
        sut:run("echo 1 > /proc/sys/net/ipv6/conf/dummy2/accept_dad"):assert_ok()
        assert(ntfe.if_up(sut, "dummy2"))
        t:log(string.format("dummy2 flags 0x%x; %s", ntfe.if_flags(sut, "dummy2"),
            sut:run("cd /proc/sys/net/ipv6/conf/dummy2 && grep -H . accept_dad dad_transmits disable_ipv6 optimistic_dad").stdout))
        local i2 = ifindex("dummy2")
        t:assert(rtnl.add_address(sut, i2, "127.0.0.9", { prefix = 8 }), "add 127.0.0.9/8")
        wait_until(function() return network.has_address(iface("dummy2"), "127.0.0.9") end,
            { timeout = 15, interval = 0.25, desc = "netd to see 127.0.0.9" })
        i = iface("dummy2")
        t:log("dummy2 with a loopback address: " .. i.level .. " " .. list_text(i.addresses))
        t:assert_eq(i.level, "link", "a loopback IPv4 address is not usable")
        t:assert(rtnl.add_address(sut, i2, "fd98::2", { prefix = 64 }), "add fd98::2/64")
        level_becomes(t, "dummy2", "addressed", "a tentative address counts")
        local a = rt_addr(i2, "fd98::2")
        t:log("fd98::2 flags 0x" .. string.format("%x", a and a.flags or 0))
        t:assert(a and a.tentative, "fd98::2 is still tentative (DAD running) while counted")

        -- dummy3: a deprecated address (preferred lifetime 0) counts.
        assert(ntfe.if_up(sut, "dummy3"))
        level_becomes(t, "dummy3", "link", "dummy3 up")
        local i3 = ifindex("dummy3")
        local ok, e = add_address6_lifetimes(i3, "fd97::3", 64, 0, 0xFFFFFFFF)
        t:assert(ok, "add fd97::3/64 with preferred lifetime 0: errno " .. tostring(e))
        a = rt_addr(i3, "fd97::3")
        t:assert(a and a.deprecated, "fd97::3 is deprecated")
        level_becomes(t, "dummy3", "addressed", "a deprecated address counts")

        -- None of it was undone: an IGNOREd link is not netd's.
        t:assert(rt_addr(i0, "169.254.7.7") ~= nil, "netd left dummy0's address alone")
    end)

test("the machine's level is the highest among joined interfaces, absent when none is; an IGNOREd interface contributes nothing whatever its state",
    { spec = "netd *readiness.machine-level netd *readiness.publish-on-change" }, function(t)
        local s = network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 })
        t:assert(s, "netd bound")
        local d4 = level_becomes(t, "dummy4", "addressed", "dummy4 holds its static address")
        t:assert(network.has_address(d4, "10.99.0.1"), "dummy4: 10.99.0.1")
        local function machine() return network.status(sut).level end
        local function readiness() return network.get(sut, network.KEY, "Readiness") end
        local function settle(level, what)
            local ok = pcall(wait_until, function() return machine() == level end,
                { timeout = 30, interval = 0.25, desc = what })
            local reg
            pcall(wait_until, function() reg = readiness(); return reg == level end,
                { timeout = 10, interval = 0.25, desc = "Readiness " .. level })
            t:log(string.format("%s: machine %s, Readiness %s", what, machine(), tostring(reg)))
            t:assert(ok, what .. ": machine level " .. level)
            t:assert_eq(reg, level, what .. ": Machine\\System\\Network Readiness")
        end
        settle("routed", "eth0 routed, dummy4 addressed")
        t:assert_eq(iface("dummy0").level, "routed", "IGNOREd dummy0 is routed (but not joined)")

        -- The cable: eth0 absent; the highest joined is dummy4.
        local nic = lan:nic(sut)
        nic:disconnect()
        level_becomes(t, "eth0", "absent", "cable pulled")
        settle("addressed", "eth0 absent")
        nic:reconnect()
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "bound again")
        settle("routed", "cable back")

        -- eth0 IGNOREd: its kernel state stays, and so does its own level,
        -- but it no longer counts.
        network.write(sut, "Rules\\Interface\\pt-eth0", {
            ["Interface.Equal"] = "multi:eth0", Priority = "dword:30", Actions = "multi:IGNORE" })
        wait_until(function() return iface("eth0").verdict == "IGNORE" end,
            { timeout = 15, interval = 0.25, desc = "eth0 IGNOREd" })
        settle("addressed", "eth0 IGNOREd")
        t:assert_eq(iface("eth0").level, "routed", "eth0 itself is still routed")

        -- Nothing joined: absent, whatever the IGNOREd links hold.
        network.reg(sut, { "set", network.KEY .. "\\Rules\\Interface\\pt-eth0", "Interface.Equal",
            "multi:eth0,dummy4" }):assert_ok()
        wait_until(function() return iface("dummy4").verdict == "IGNORE" end,
            { timeout = 15, interval = 0.25, desc = "dummy4 IGNOREd" })
        settle("absent", "nothing joined")
        t:assert_eq(iface("eth0").level, "routed", "eth0 is routed and counts for nothing")

        network.delete(sut, "Rules\\Interface\\pt-eth0")
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "eth0 joined and bound again")
        settle("routed", "eth0 joined again")
    end)

test("the level is published on change only: logged, written as Readiness, and each joined interface's own level as Status Readiness",
    { spec = "netd *readiness.publish-on-change" }, function(t)
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "netd bound")

        -- What the previous test's moves published, oldest first.
        local function published()
            local out = {}
            local logs = network.logs(sut, { since = "15m ago", take = 1000 })
            for k = #logs, 1, -1 do
                local lvl = logs[k]:match("machine readiness is (%a+)")
                if lvl then out[#out + 1] = lvl end
            end
            return out
        end
        local seq = published()
        t:log("published: " .. list_text(seq))
        t:assert(#seq >= 6, "every change was logged")
        for k = 2, #seq do
            t:assert(seq[k] ~= seq[k - 1], "a level is published only when it changed (" .. seq[k] .. " twice)")
        end
        -- The moves of the machine-level test, in order. Not necessarily
        -- back to back: a rule is written value by value (`reg new`, then
        -- one `reg set` each), and netd judges every intermediate state,
        -- so a half-written rule can publish a passing level in between.
        local want = { "addressed", "routed", "addressed", "absent", "routed" }
        local at = 1
        for _, lvl in ipairs(seq) do
            if lvl == want[at] then at = at + 1 end
            if at > #want then break end
        end
        t:assert(at > #want, "the log shows addressed, routed, addressed, absent, routed in that order")
        t:assert_eq(seq[#seq], "routed", "the last published is the current level")
        t:assert_eq(network.get(sut, network.KEY, "Readiness"), "routed", "Readiness is the current level")

        -- Passes that change nothing publish nothing.
        local before = #seq
        t:assert(network.call(sut, { query = "reconcile" }).ok, "a full pass")
        gw:forget()
        t:assert(network.call(sut, { query = "renew", interface = "eth0" }).ok, "a renew")
        gw:serve({ timeout = 10, until_ = function()
            return #gw:dhcp_messages(gateway.DHCP.REQUEST) > 0 and network.iface(network.status(sut), "eth0").lease.state == "bound"
        end })
        t:assert(network.call(sut, { query = "reconcile" }).ok, "another full pass")
        t:assert_eq(#published(), before, "no new 'machine readiness' line without a change")

        -- Each joined interface's own level, under its Status key.
        local st = network.status(sut)
        for _, name in ipairs({ "eth0", "dummy4", "dummy0" }) do
            local i = network.iface(st, name)
            local v = network.get(sut, "Interfaces\\" .. i.ifid .. "\\Status", "Readiness")
            t:log(string.format("%s: verdict %s level %s Status Readiness %s", name, tostring(i.verdict), i.level, tostring(v)))
            if i.verdict == "JOIN" then
                t:assert_eq(v, i.level, name .. ": Status Readiness is its level")
            else
                t:assert_eq(v, nil, name .. ": not joined, no Status Readiness")
            end
        end
    end)
