-- netd §6.1 — router discovery, the half of it about advertisements:
-- which are accepted (hop limit and source, malformed messages, each
-- option's acceptance), what an accepted one does, the M/O latch that
-- wants DHCPv6, and which router is the default. The schedule, the socket
-- and the kernel's RA switch are rdisc.test.lua.
--
-- Harness: the scripted gateway (helpers.gateway) playing a router that
-- answers every solicitation with BASE, and sending further
-- advertisements byte by byte where a test needs a bad one, a second
-- router (another link-local source), or options helpers.gateway's `ra`
-- does not build. One whole Peios machine joined by the shipped baseline.
--
-- Every refusal is proved against a MARKER: a good advertisement sent
-- after the bad ones on the same socket, whose effect (a prefix's
-- address, an RDNSS server in the status) shows netd has read past them.
-- Status `dns` lists RDNSS servers in address order and de-duplicates
-- only adjacent entries (PEI-1332), so membership is asserted, never
-- order.
--
-- Own VMs: the tests run in order on one pair. One test sets
-- `Mtu.Offered` on Profiles\default (the shipped profile has none) and
-- the next deletes it again.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local rtnl = require("helpers.rtnl")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })

local BASE = { lifetime = 1800,
    prefixes = { { prefix = "fd77::", len = 64, valid = 86400, preferred = 14400 } },
    rdnss = { lifetime = 3600, servers = { "fd77::53" } },
    dnssl = { lifetime = 3600, domains = { "lan.example" } } }
gw:router(BASE)

local sut = network.boot({ bridges = { lan }, gateway = gw })
local nic = lan:nic(sut)

local INDEX = tonumber((sut:read_file("/sys/class/net/eth0/ifindex"):match("%d+")))
local GW_LL = gateway.ip6_text(gw.ll)
local PROFILE = "Profiles\\default"

-- ---------------------------------------------------------------------------
-- Local helpers
-- ---------------------------------------------------------------------------

local function iface() return network.iface(network.status(sut), "eth0") end

--- network.serve_until, returning eth0's status (serve_until itself
--- returns the whole status reply).
local function serve_iface(pred, o)
    local s = network.serve_until(gw, sut, pred, o)
    return s and network.iface(s, "eth0")
end

local function has(list, v)
    for _, x in ipairs(list or {}) do if x == v then return true end end
    return false
end

local function trim(s) return (tostring(s or ""):gsub("%s+$", "")) end

local function in64(a, prefix)
    return gateway.ip6(a):sub(1, 8) == gateway.ip6(prefix):sub(1, 8)
end

--- Addresses in `prefix`/64: in the status and in the kernel.
local function status_in(i, prefix)
    local out = {}
    for _, a in ipairs(network.ipv6(i)) do
        local addr = a:match("^([^/]+)")
        if in64(addr, prefix) then out[#out + 1] = addr end
    end
    return out
end

local function kernel_in(prefix)
    local out = {}
    for _, a in ipairs(rtnl.addresses_of(sut, INDEX, 6)) do
        if in64(a.address, prefix) then out[#out + 1] = a.address end
    end
    return out
end

local function copy(spec, extra)
    local out = {}
    for k, v in pairs(spec) do out[k] = v end
    for k, v in pairs(extra or {}) do out[k] = v end
    return out
end

--- Send a raw advertisement body from `src` (text, default the
--- gateway's link-local) to all-nodes; the checksum is filled in.
local function send_body(body, src)
    local s = src and gateway.ip6(src) or gw.ll
    gw:send_ip6(gateway.ALL_NODES, 58, gateway.icmp6(s, gateway.ALL_NODES, body), { src = s })
end

--- A prefix information option, raw. `flags`: L 0x80, A 0x40.
local function pio(prefix, len, flags, valid, preferred)
    return string.pack(">I1I1I1I1I4I4I4", 3, 4, len, flags, valid, preferred, 0) .. gateway.ip6(prefix)
end

local function rdnss_opt(lifetime, servers)
    local body = string.pack(">I1I1I2I4", 25, 1 + 2 * #servers, 0, lifetime)
    for _, s in ipairs(servers) do body = body .. gateway.ip6(s) end
    return body
end

local function dnssl_opt(lifetime, names)
    local n = gateway.opt.names(names)
    n = n .. string.rep("\0", (8 - (#n + 8) % 8) % 8)
    return string.pack(">I1I1I2I4", 31, (8 + #n) // 8, 0, lifetime) .. n
end

--- Wait until `pred(iface_status)`, failing the test on a timeout.
local function until_status(t, pred, what, timeout)
    local s = serve_iface(pred, { iface = "eth0", timeout = timeout or 15 })
    if not s then
        local i = iface()
        t:log("status: gateway6 " .. tostring(i.gateway6) .. "; addresses " .. table.concat(i.addresses or {}, " ")
            .. "; dns " .. table.concat(i.dns or {}, " "))
        for _, r in ipairs(rtnl.routes_of(sut, INDEX)) do
            if r.family == 6 then
                t:log(string.format("route %s/%d via %s proto %d metric %d", r.dst, r.prefix,
                    tostring(r.gateway), r.protocol, r.metric))
            end
        end
        local logs = network.logs(sut, { since = "2m ago", take = 15 })
        for k = #logs, 1, -1 do t:log("log: " .. logs[k]) end
    end
    t:assert(s, what)
    return s
end

local function mtu() return tonumber(trim(sut:read_file("/sys/class/net/eth0/mtu"))) end

-- ---------------------------------------------------------------------------
-- Which advertisements count
-- ---------------------------------------------------------------------------

test("an advertisement is dropped unless it arrived with hop limit 255 from a link-local source",
    { spec = "netd *rdisc.hop-limit-and-source-checks" }, function(t)
        until_status(t, function(i)
            return network.bound(i) and i.gateway6 == GW_LL and #status_in(i, "fd77::") > 0
                and has(i.dns, "fd77::53")
        end, "netd took the router's advertisement", 60)
        -- Hop limit 254: it crossed a router.
        gw:send_ra({ lifetime = 1800, rdnss = { lifetime = 600, servers = { "fd31::53" } },
            prefixes = { { prefix = "fd31::", len = 64 } } }, { hop = 254 })
        -- A global source: not a router on this link. (fd77::1 is
        -- numerically below every fe80:: address, so it would also have
        -- become the default router.)
        gw:send_ra({ lifetime = 1800, rdnss = { lifetime = 600, servers = { "fd32::53" } },
            prefixes = { { prefix = "fd32::", len = 64 } } }, { src = gateway.ip6("fd77::1") })
        -- The marker.
        gw:send_ra({ lifetime = 1800, rdnss = { lifetime = 600, servers = { "fd33::53" } },
            prefixes = { { prefix = "fd33::", len = 64 } } })
        local s = until_status(t, function(i)
            return has(i.dns, "fd33::53") and #status_in(i, "fd33::") > 0
        end, "the marker advertisement was taken")
        for _, p in ipairs({ "fd31", "fd32" }) do
            t:assert(not has(s.dns, p .. "::53"), p .. "::53 was not taken")
            t:assert_eq(#status_in(s, p .. "::"), 0, "no " .. p .. "::/64 address in the status")
            t:assert_eq(#kernel_in(p .. "::"), 0, "no " .. p .. "::/64 address in the kernel")
        end
        t:assert_eq(s.gateway6, GW_LL, "the default router is still the gateway's link-local")
    end)

test("an advertisement shorter than 16 bytes, with a non-zero code, a zero-length option or an option past its end is refused whole",
    { spec = "netd *rdisc.malformed-advertisement-refused" }, function(t)
        local function body(code, options, lifetime)
            return string.pack(">I1I1I2I1I1I2I4I4", 134, code, 0, 64, 0, lifetime or 1800, 0, 0) .. options
        end
        -- Zero-length option after a good prefix and server.
        send_body(body(0, pio("fd41::", 64, 0xc0, 3600, 3600) .. rdnss_opt(600, { "fd41::53" })
            .. "\200\0\0\0\0\0\0\0"))
        -- An option claiming 32 bytes with 8 left.
        send_body(body(0, pio("fd42::", 64, 0xc0, 3600, 3600) .. rdnss_opt(600, { "fd42::53" })
            .. "\200\4\0\0\0\0\0\0"))
        -- Code 1.
        send_body(body(1, pio("fd43::", 64, 0xc0, 3600, 3600) .. rdnss_opt(600, { "fd43::53" })))
        -- 12 bytes from fe80::42, router lifetime 1800: had it been taken,
        -- fe80::42 (below the gateway's address) would be the default router.
        send_body(string.pack(">I1I1I2I1I1I2I4", 134, 0, 0, 64, 0, 1800, 0), "fe80::42")
        -- 17 bytes: one byte of option, no length.
        send_body(body(0, "\3"), "fe80::43")
        -- The marker.
        send_body(body(0, pio("fd44::", 64, 0xc0, 3600, 3600) .. rdnss_opt(600, { "fd44::53" })))
        local s = until_status(t, function(i)
            return has(i.dns, "fd44::53") and #status_in(i, "fd44::") > 0
        end, "the marker advertisement was taken")
        for _, p in ipairs({ "fd41", "fd42", "fd43" }) do
            t:assert(not has(s.dns, p .. "::53"), p .. "::53 was not taken")
            t:assert_eq(#kernel_in(p .. "::"), 0, "no " .. p .. "::/64 address")
        end
        t:assert_eq(s.gateway6, GW_LL, "neither fe80::42 nor fe80::43 became a router")
    end)

test("of the live routers, the numerically lowest link-local address is the default; router preference is not read",
    { spec = "netd *rdisc.default-router-is-lowest-address" }, function(t)
        local function with_prf(spec, prf)
            local b = gateway.ra(spec)
            return b:sub(1, 5) .. string.char(b:byte(6) | (prf << 3)) .. b:sub(7)
        end
        local LOW, HIGH = 3, 1
        -- fe80::1 at low preference: still the lowest address.
        send_body(with_prf({ lifetime = 1800 }, LOW), "fe80::1")
        local s = until_status(t, function(i) return i.gateway6 == "fe80::1" end,
            "fe80::1 (low preference) is the default router")
        local found = false
        for _, r in ipairs(rtnl.routes_of(sut, INDEX)) do
            if r.family == 6 and r.prefix == 0 and r.protocol == rtnl.RTPROT.NETD then
                t:assert_eq(r.gateway, "fe80::1", "netd's IPv6 default route is via fe80::1")
                found = true
            end
        end
        t:assert(found, "netd's IPv6 default route exists")
        -- fe80::ffff:1 at high preference, with a marker server.
        send_body(with_prf({ lifetime = 1800, rdnss = { lifetime = 600, servers = { "fd45::53" } } }, HIGH),
            "fe80::ffff:1")
        s = until_status(t, function(i) return has(i.dns, "fd45::53") end, "fe80::ffff:1's advertisement was taken")
        t:assert_eq(s.gateway6, "fe80::1", "a higher-preference router at a higher address does not displace it")
        -- fe80::1 withdraws: next lowest is fe80::ffff:1, below the gateway's.
        send_body(gateway.ra({ lifetime = 0 }), "fe80::1")
        s = until_status(t, function(i) return i.gateway6 ~= "fe80::1" end, "fe80::1 withdrew")
        t:assert_eq(s.gateway6, "fe80::ffff:1", "the next lowest live router takes over")
        send_body(gateway.ra({ lifetime = 0, rdnss = { lifetime = 0, servers = { "fd45::53" } } }), "fe80::ffff:1")
        s = until_status(t, function(i) return i.gateway6 == GW_LL end, "back to the gateway")
    end)

test("options: prefixes 32 bytes, length ≤ 128, not multicast or link-local, 16 per advertisement; MTU 8 bytes; RDNSS whole addresses, 16 per option, special addresses dropped; DNSSL 16 per option, lower-cased, ended by a bad name; the rest ignored",
    { spec = "netd *rdisc.acceptance netd *rdisc.option-acceptance" }, function(t)
        -- The MTU option only shows with Mtu.Offered (§4.2). Setting it is
        -- a profile edit, which restarts discovery.
        local before_mtu = mtu()
        network.write(sut, PROFILE, { ["Mtu.Offered"] = "dword:1" })
        until_status(t, function(i)
            return network.bound(i) and i.gateway6 == GW_LL and #status_in(i, "fd77::") > 0
        end, "back on the router after the profile edit", 30)
        local hop0 = trim(sut:read_file("/proc/sys/net/ipv6/conf/eth0/hop_limit"))
        local reach0 = trim(sut:read_file("/proc/sys/net/ipv6/neigh/eth0/base_reachable_time_ms"))
        local retr0 = trim(sut:read_file("/proc/sys/net/ipv6/neigh/eth0/retrans_time_ms"))

        -- A: prefixes, MTU, unknown options, header fields.
        local a = string.pack(">I1I1I2I1I1I2I4I4", 134, 0, 0, 7, 0, 1800, 12345, 777)
            .. pio("fd21::", 64, 0xc0, 3600, 3600)                         -- good
            .. string.pack(">I1I1I1I1I4I4I4", 3, 5, 64, 0xc0, 3600, 3600, 0)
                .. gateway.ip6("fd22::") .. string.rep("\0", 8)            -- 40 bytes
            .. pio("fd23::", 129, 0xc0, 3600, 3600)                        -- length 129
            .. pio("ff05::", 64, 0xc0, 3600, 3600)                         -- multicast
            .. pio("fe80::", 64, 0xc0, 3600, 3600)                         -- link-local
            .. string.pack(">I1I1I2I4I4I4", 5, 2, 0, 1300, 0, 0)          -- MTU, 16 bytes
            .. "\200\1\0\0\0\0\0\0"                                        -- unknown type 200
            .. string.pack(">I1I1I1I1I4", 24, 2, 48, 0, 3600) .. gateway.ip6("fd28::"):sub(1, 8) -- route info
        send_body(a)
        local s = until_status(t, function(i) return #status_in(i, "fd21::") > 0 end,
            "the advertisement's good prefix was taken")
        for _, p in ipairs({ "fd22::", "fd23::", "ff05::" }) do
            t:assert_eq(#kernel_in(p), 0, "no address from " .. p)
        end
        local ll_count = 0
        for _, ad in ipairs(rtnl.addresses_of(sut, INDEX, 6)) do
            if ad.address:match("^fe80:") then ll_count = ll_count + 1 end
        end
        t:assert_eq(ll_count, 1, "no address formed from a link-local prefix (only the kernel's own)")
        t:assert_eq(mtu(), before_mtu, "a 16-byte MTU option is ignored")
        for _, r in ipairs(rtnl.routes_of(sut, INDEX)) do
            t:assert(not (r.family == 6 and r.dst == "fd28::"), "the route information option made no route")
        end
        t:assert_eq(trim(sut:read_file("/proc/sys/net/ipv6/conf/eth0/hop_limit")), hop0,
            "the advertised hop limit is ignored")
        t:assert_eq(trim(sut:read_file("/proc/sys/net/ipv6/neigh/eth0/base_reachable_time_ms")), reach0,
            "the advertised reachable time is ignored")
        t:assert_eq(trim(sut:read_file("/proc/sys/net/ipv6/neigh/eth0/retrans_time_ms")), retr0,
            "the advertised retransmission timer is ignored")

        -- B: RDNSS and DNSSL.
        local seventeen, domains = {}, {}
        for k = 1, 17 do
            seventeen[k] = string.format("fd26::%x", k)
            domains[k] = string.format("d%d.example", k)
        end
        local long = string.rep("a", 63) .. "." .. string.rep("b", 63) .. "."
            .. string.rep("c", 63) .. "." .. string.rep("d", 63)
        local b = string.pack(">I1I1I2I1I1I2I4I4", 134, 0, 0, 64, 0, 1800, 0, 0)
            .. string.pack(">I1I1I2I4", 25, 4, 0, 600) .. gateway.ip6("fd25::53") .. string.rep("\0", 8)
            .. rdnss_opt(600, seventeen)
            .. rdnss_opt(600, { "::", "ff02::1", "::1", "fd27::53" })
            .. dnssl_opt(600, domains)
            .. dnssl_opt(600, { "MiXeD.Example" })
            .. dnssl_opt(600, { "ok1.example", "bad label.example", "after1.example" })
            .. dnssl_opt(600, { "ok2.example", long, "after2.example" })
        send_body(b)
        s = until_status(t, function(i) return has(i.dns, "fd27::53") end, "the RDNSS options were taken")
        t:log("dns: " .. table.concat(s.dns, " "))
        t:log("search: " .. table.concat(s.search, " "))
        t:assert(not has(s.dns, "fd25::53"), "an RDNSS of 1.5 addresses is refused")
        for k = 1, 16 do t:assert(has(s.dns, seventeen[k]), seventeen[k] .. " kept") end
        t:assert(not has(s.dns, "fd26::11"), "the 17th server of an option is not kept")
        for _, bad in ipairs({ "::", "ff02::1", "::1" }) do t:assert(not has(s.dns, bad), bad .. " dropped") end
        for k = 1, 16 do t:assert(has(s.search, domains[k]), domains[k] .. " kept") end
        t:assert(not has(s.search, "d17.example"), "the 17th domain of an option is not kept")
        t:assert(has(s.search, "mixed.example"), "domains are lower-cased")
        t:assert(not has(s.search, "MiXeD.Example"), "…and not kept as sent")
        t:assert(has(s.search, "ok1.example"), "a name before a bad label stands")
        t:assert(not has(s.search, "after1.example"), "a label with a space ends the list")
        t:assert(has(s.search, "ok2.example"), "a name before an over-long one stands")
        t:assert(not has(s.search, "after2.example"), "a name over 253 characters ends the list")
        for _, x in ipairs(s.search) do t:assert(#x <= 253, "no domain over 253 characters") end

        -- C: 17 prefixes, the first 16 taken.
        local c = string.pack(">I1I1I2I1I1I2I4I4", 134, 0, 0, 64, 0, 1800, 0, 0)
        for k = 1, 17 do c = c .. pio(string.format("fd10:0:0:%x::", k), 64, 0xc0, 20, 20) end
        send_body(c)
        s = until_status(t, function(i) return #status_in(i, "fd10:0:0:10::") > 0 end,
            "the 16th prefix was taken")
        for k = 1, 16 do
            t:assert_eq(#kernel_in(string.format("fd10:0:0:%x::", k)), 1, "prefix " .. k .. " formed an address")
        end
        t:assert_eq(#kernel_in("fd10:0:0:11::"), 0, "the 17th prefix of one advertisement is not taken")

        -- D: an 8-byte MTU option is taken.
        gw:send_ra(copy(BASE, { mtu = 1400 }))
        t:assert(wait_until(function() return mtu() == 1400 end, { timeout = 10, desc = "MTU 1400" }),
            "an 8-byte MTU option sets the link MTU (with Mtu.Offered)")
    end)

test("router lifetime 0 removes the router but not its prefixes, servers or domains; a lifetime running out is a change; the MTU is used only with Mtu.Offered and when at least 68",
    { spec = "netd *rdisc.effects" }, function(t)
        local s = until_status(t, function(i) return i.gateway6 == GW_LL end, "the gateway is the default router")
        -- The router stops answering solicitations for a moment: with no
        -- router left netd solicits again at once, and an answer would
        -- put it straight back.
        gw.handlers.router = nil
        send_body(gateway.ra({ lifetime = 0 }))
        s = until_status(t, function(i) return i.gateway6 == nil end, "router lifetime 0: no default router")
        for _, r in ipairs(rtnl.routes_of(sut, INDEX)) do
            t:assert(not (r.family == 6 and r.prefix == 0), "no IPv6 default route")
        end
        t:assert(#status_in(s, "fd77::") > 0, "its prefix's address stays")
        t:assert(has(s.dns, "fd77::53"), "its server stays")
        t:assert(has(s.search, "lan.example"), "its domain stays")
        gw:router(BASE)
        gw:send_ra(BASE)
        until_status(t, function(i) return i.gateway6 == GW_LL end, "the router is back")

        -- Time alone is a change: a second, lower router for 4 s takes
        -- over, and when its lifetime runs out (no packet) the gateway's
        -- route is back.
        local t0 = gw:now()
        send_body(gateway.ra({ lifetime = 4 }), "fe80::7")
        until_status(t, function(i) return i.gateway6 == "fe80::7" end, "fe80::7 is the default router")
        until_status(t, function(i) return i.gateway6 == GW_LL end, "fe80::7's lifetime ran out", 10)
        local back = gw:now() - t0
        t:assert(back >= 3 and back <= 6, "…4 s on, by time alone (+" .. back .. "s)")

        -- MTU below 68: not used (the link keeps 1400 from the last test).
        t:assert_eq(mtu(), 1400, "the link MTU is the advertised 1400")
        gw:send_ra(copy(BASE, { mtu = 60, rdnss = { lifetime = 600, servers = { "fd46::53" } } }))
        until_status(t, function(i) return has(i.dns, "fd46::53") end, "the MTU-60 advertisement was taken")
        t:assert_eq(mtu(), 1400, "an advertised MTU under 68 is not applied")
        gw:send_ra(copy(BASE, { mtu = 1500 }))
        t:assert(wait_until(function() return mtu() == 1500 end, { timeout = 10, desc = "MTU 1500" }),
            "an advertised 1500 is applied")

        -- Without Mtu.Offered the advertised MTU is not used.
        network.reg(sut, { "del", network.KEY .. "\\" .. PROFILE, "Mtu.Offered" }):assert_ok()
        until_status(t, function(i)
            return network.bound(i) and i.gateway6 == GW_LL and #status_in(i, "fd77::") > 0
        end, "back on the router after the profile edit", 30)
        gw:send_ra(copy(BASE, { mtu = 1400, rdnss = { lifetime = 600, servers = { "fd47::53" } } }))
        until_status(t, function(i) return has(i.dns, "fd47::53") end, "the MTU-1400 advertisement was taken")
        t:assert_eq(mtu(), 1500, "without Mtu.Offered the advertised MTU is not applied")
    end)

test("M or O wants DHCPv6, and stays wanted when later advertisements drop the flags, until discovery restarts",
    { spec = "netd *rdisc.m-or-o-latches-dhcpv6" }, function(t)
        local function irs(since)
            local out = {}
            for _, m in ipairs(gw:dhcp6_messages()) do
                if m.type == gateway.DHCP6.INFORMATION_REQUEST and m.at >= since then out[#out + 1] = m end
            end
            return out
        end
        local function await(n, since, timeout)
            gw:serve({ timeout = timeout, until_ = function() return #irs(since) >= n end })
            return irs(since)
        end
        gw:forget()
        local t0 = gw:now()
        gw:send_ra(copy(BASE, { other = true }))
        local got = await(1, t0, 10)
        t:assert(#got >= 1, "O starts DHCPv6: an INFORMATION-REQUEST")
        -- The flag dropped: the unanswered client carries on.
        local t1 = gw:now()
        gw:send_ra(BASE)
        got = await(2, t1 + 1, 15)
        t:assert(#got >= 2, "the client is still retransmitting after an advertisement without the flags (saw "
            .. #got .. ")")
        t:assert_eq(got[1].txid, irs(t0)[1].txid, "…the same exchange")

        -- Discovery restarts (carrier): the latch is cleared.
        nic:disconnect()
        t:assert(serve_iface(function(i) return i.carrier == false end,
            { iface = "eth0", timeout = 20 }), "carrier dropped")
        local before = #irs(t0)
        nic:reconnect()
        until_status(t, function(i)
            return i.carrier and i.gateway6 == GW_LL and #status_in(i, "fd77::") > 0
        end, "discovery restarted and took the router's flagless advertisement", 30)
        local t2 = gw:now()
        gw:serve({ timeout = 8 })
        for _, m in ipairs(irs(t0)) do
            t:log(string.format("request at +%ds txid %02x%02x%02x (t1 +%d, t2 +%d)", m.at - t0,
                m.txid:byte(1), m.txid:byte(2), m.txid:byte(3), t1 - t0, t2 - t0))
        end
        local logs = network.logs(sut, { since = "2m ago", take = 40 })
        for k = #logs, 1, -1 do
            if logs[k]:find("ipv6") or logs[k]:find("dhcpv6") or logs[k]:find("carrier")
                or logs[k]:find("soliciting") then
                t:log("log: " .. logs[k])
            end
        end
        -- Counted, not timed: the gateway's clock is whole seconds, and
        -- the old client's last request can share t2's second.
        t:assert(gw:now() - t1 >= 9, "waited past the old exchange's next retransmission")
        t:assert_eq(#irs(t0), before, "no DHCPv6 after a restart under advertisements without M or O")

        -- M alone also wants it.
        local t3 = gw:now()
        gw:send_ra(copy(BASE, { managed = true }))
        got = await(1, t3, 10)
        t:assert(#got >= 1, "M starts DHCPv6 as O does")
    end)
