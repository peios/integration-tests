-- netd §6.3 — DNS and DHCPv6: the lifetimes of advertised DNS servers and
-- search domains (RDNSS and DNSSL), and the stateless DHCPv6 client: when
-- it runs, the INFORMATION-REQUEST it sends, its retransmission, which
-- REPLY it accepts, and when it asks again.
--
-- Harness: the scripted gateway (helpers.gateway) playing the router
-- (`gw:router`, answering every solicitation with BASE, which carries no
-- M or O flag) and, where a test arms it, the DHCPv6 server
-- (`gw:dhcp6`). One whole Peios machine joined by the shipped baseline.
-- What netd made of it is read from its status reply (`dns`, `search`);
-- what it sent is read off the wire and decoded.
--
-- Own VMs: the whole article is one file (both prefixes). The tests run
-- in order on one pair. A cable pull (`lan:nic(sut)`) is how a test gets
-- a fresh DHCPv6 client: it stops router discovery, which discards the
-- client and clears the M/O latch (§6.1), so the next client starts only
-- when an advertisement with O is sent again.
--
-- The shipped dev baseline and DHCPv6. The gateway's REPLY goes from its
-- link-local address, port 547, unicast to the machine's link-local
-- address, port 546: conntrack sees a new inbound flow, which the
-- baseline's Flow rule `dhcpv6-client` passes. Before kernel alpha9 the
-- baseline had no such rule and the Flow backstop dropped every REPLY
-- (PEI-1366). The two tests that need an accepted reply still log the
-- firewall's drop counter (NTFE's `verdict_drop`) across the window in
-- which the gateway answered. The policy is not changed here.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local rtnl = require("helpers.rtnl")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })

--- The router's every-day advertisement: a default router and one
--- prefix, no M or O flag, no DNS.
local BASE = { lifetime = 1800,
    prefixes = { { prefix = "fd77::", len = 64, valid = 86400, preferred = 14400 } } }
gw:router(BASE)

local sut = network.boot({ bridges = { lan }, gateway = gw })
local nic = lan:nic(sut)

local INDEX = tonumber((sut:read_file("/sys/class/net/eth0/ifindex"):match("%d+")))
local MAC = gateway.mac(sut:read_file("/sys/class/net/eth0/address"))

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

local function copy(spec, extra)
    local out = {}
    for k, v in pairs(spec) do out[k] = v end
    for k, v in pairs(extra or {}) do out[k] = v end
    return out
end

--- One RDNSS option (type 25), raw: `servers` text addresses.
local function rdnss_opt(lifetime, servers)
    local body = string.pack(">I1I1I2I4", 25, 1 + 2 * #servers, 0, lifetime)
    for _, s in ipairs(servers) do body = body .. gateway.ip6(s) end
    return body
end

--- One DNSSL option (type 31), raw, padded to 8 bytes.
local function dnssl_opt(lifetime, names)
    local n = gateway.opt.names(names)
    n = n .. string.rep("\0", (8 - (#n + 8) % 8) % 8)
    return string.pack(">I1I1I2I4", 31, (8 + #n) // 8, 0, lifetime) .. n
end

--- "00:03:…" → bytes.
local function unhex(s)
    local out = {}
    for h in s:gmatch("%x%x") do out[#out + 1] = string.char(tonumber(h, 16)) end
    return table.concat(out)
end

local function hex(b)
    return (b:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

--- The machine's link-local address (text), from the kernel.
local function link_local()
    for _, a in ipairs(rtnl.addresses_of(sut, INDEX, 6)) do
        if a.address:match("^fe80:") then return a.address end
    end
end

--- Every INFORMATION-REQUEST (decoded) in the gateway's window.
local function requests()
    local out = {}
    for _, m in ipairs(gw:dhcp6_messages()) do
        if m.type == gateway.DHCP6.INFORMATION_REQUEST then out[#out + 1] = m end
    end
    return out
end

local function await_requests(n, timeout)
    gw:serve({ timeout = timeout or 30, until_ = function() return #requests() >= n end })
    return requests()
end

local function count_logged(text)
    local n = 0
    for _, l in ipairs(network.logs(sut, { since = "30m ago", take = 2000 })) do
        if l:find(text, 1, true) then n = n + 1 end
    end
    return n
end

--- Pull the cable and put it back: router discovery stops (and with it
--- the DHCPv6 client and the M/O latch) and starts again once the
--- link-local address is through DAD. Waits for the router's prefix to
--- be back.
local function cable_cycle()
    nic:disconnect()
    assert(serve_iface(function(i) return i.carrier == false end,
        { iface = "eth0", timeout = 20 }), "carrier did not drop")
    gw:forget()
    nic:reconnect()
    assert(serve_iface(function(i)
        return i.carrier and i.gateway6 ~= nil and #network.ipv6(i) > 0
    end, { iface = "eth0", timeout = 30 }), "IPv6 did not come back after the cable pull")
end

--- NTFE's verdict_drop counter on the machine, or nil and why.
local function drops()
    local fd, e = ntfe.open(sut)
    if not fd then return nil, "open: " .. sys.errname(e or 0) end
    local s, e2 = ntfe.status(sut, fd)
    sys.close(sut, fd)
    if not s then return nil, "status: " .. sys.errname(e2 or 0) end
    return s.verdict_drop
end

--- The machine's DUID, from the registry (§5.7 writes it there when the
--- DHCPv4 client first needs it).
local function duid()
    return unhex(assert(network.get(sut, network.KEY, "Duid"), "no Duid in the registry"))
end

-- ---------------------------------------------------------------------------
-- RDNSS and DNSSL
-- ---------------------------------------------------------------------------

test("RDNSS servers and DNSSL domains live for their option's lifetime from arrival; 0 removes at once, forever stays, a re-advertisement replaces the lifetime",
    { spec = "netd *v6dns.rdnss-dnssl-lifetimes" }, function(t)
        local s = serve_iface(function(i)
            return network.bound(i) and i.gateway6 ~= nil and #network.ipv6(i) > 0
        end, { iface = "eth0", timeout = 60 })
        t:assert(s, "netd bound a lease and took the router's prefix")
        t:assert(#(s.search or {}) == 0, "no search domain before any DNSSL")

        local FOREVER = 0xFFFFFFFF
        -- One advertisement, five servers and five domains:
        --   ::1 / six      6 s, left to run out
        --   ::2 / forever  0xffffffff
        --   ::3 / zero     600 s, then re-advertised with 0
        --   ::4 / grow     4 s, then re-advertised with 20
        --   ::5 / shrink   600 s, then re-advertised with 3
        local first = rdnss_opt(6, { "fd61::1" }) .. rdnss_opt(FOREVER, { "fd61::2" })
            .. rdnss_opt(600, { "fd61::3" }) .. rdnss_opt(4, { "fd61::4" })
            .. rdnss_opt(600, { "fd61::5" })
            .. dnssl_opt(6, { "six.example" }) .. dnssl_opt(FOREVER, { "forever.example" })
            .. dnssl_opt(600, { "zero.example" }) .. dnssl_opt(4, { "grow.example" })
            .. dnssl_opt(600, { "shrink.example" })
        local t0 = gw:now()
        gw:send_ra(copy(BASE, { extra = first }))
        s = serve_iface(function(i)
            for n = 1, 5 do if not has(i.dns, "fd61::" .. n) then return false end end
            for _, d in ipairs({ "six", "forever", "zero", "grow", "shrink" }) do
                if not has(i.search, d .. ".example") then return false end
            end
            return true
        end, { iface = "eth0", timeout = 10 })
        t:assert(s, "every advertised server and domain is held")
        t:log("held at +" .. (gw:now() - t0) .. "s: dns " .. table.concat(s.dns, " ")
            .. "; search " .. table.concat(s.search, " "))

        local second = rdnss_opt(0, { "fd61::3" }) .. rdnss_opt(20, { "fd61::4" })
            .. rdnss_opt(3, { "fd61::5" })
            .. dnssl_opt(0, { "zero.example" }) .. dnssl_opt(20, { "grow.example" })
            .. dnssl_opt(3, { "shrink.example" })
        local t2 = gw:now()
        gw:send_ra(copy(BASE, { extra = second }))

        -- Lifetime zero: removed at once.
        s = serve_iface(function(i)
            return not has(i.dns, "fd61::3") and not has(i.search, "zero.example")
        end, { iface = "eth0", timeout = 10 })
        t:assert(s, "a lifetime of zero removes the server and the domain")
        t:assert(gw:now() - t2 <= 2, "…at once (+" .. (gw:now() - t2) .. "s)")

        -- Re-advertised shorter: the new 3 s replaces the old 600 s.
        s = serve_iface(function(i)
            return not has(i.dns, "fd61::5") and not has(i.search, "shrink.example")
        end, { iface = "eth0", timeout = 15 })
        t:assert(s, "the shortened server and domain went")
        local shrink_at = gw:now() - t2
        t:log("shrink gone at +" .. shrink_at .. "s after the re-advertisement")
        t:assert(shrink_at >= 2 and shrink_at <= 5,
            "…about 3 s after the re-advertisement (+" .. shrink_at .. "s)")

        -- Left alone: gone 6 s after the first advertisement.
        s = serve_iface(function(i)
            return not has(i.dns, "fd61::1") and not has(i.search, "six.example")
        end, { iface = "eth0", timeout = 15 })
        t:assert(s, "the 6 s server and domain ran out")
        local six_at = gw:now() - t0
        t:log("six gone at +" .. six_at .. "s after the first advertisement")
        t:assert(six_at >= 5 and six_at <= 8, "…about 6 s after it arrived (+" .. six_at .. "s)")

        -- Past the original 4 s by a margin: grow (now 20 s) and forever stay.
        gw:serve({ timeout = math.max(0, t0 + 9 - gw:now()) })
        local i = iface()
        t:assert(gw:now() - t0 >= 8, "waited past the first lifetimes")
        t:assert(has(i.dns, "fd61::4") and has(i.search, "grow.example"),
            "a re-advertised 20 s replaces the first 4 s (still held at +" .. (gw:now() - t0) .. "s)")
        t:assert(has(i.dns, "fd61::2") and has(i.search, "forever.example"),
            "0xffffffff is forever")
        t:assert(not has(i.dns, "fd61::3") and not has(i.search, "zero.example"),
            "the zeroed server and domain did not come back")

        -- Put it back: nothing advertised stays held.
        gw:send_ra(copy(BASE, { extra = rdnss_opt(0, { "fd61::2", "fd61::4" })
            .. dnssl_opt(0, { "forever.example", "grow.example" }) }))
        s = serve_iface(function(i)
            return not has(i.dns, "fd61::2") and not has(i.dns, "fd61::4")
                and #(i.search or {}) == 0
        end, { iface = "eth0", timeout = 10 })
        t:assert(s, "cleaned up")
    end)

-- ---------------------------------------------------------------------------
-- The client: start, the request, retransmission, stop
-- ---------------------------------------------------------------------------

test("the O flag starts the client: an INFORMATION-REQUEST from the link-local address, port 546, to ff02::1:2 port 547, with the DUID, elapsed time and an option request for 23, 24 and 32, retransmitted at 1 s doubling with the same transaction; the client stops with router discovery",
    { spec = "netd *dhcp6.start-stop netd *dhcp6.information-request netd *dhcp6.retransmit-schedule" },
    function(t)
        local ll = assert(link_local(), "the machine has a link-local address")
        local DUID = duid()
        t:assert_eq(#requests(), 0, "no DHCPv6 before any advertisement asked for it")
        t:assert_eq(count_logged("dhcpv6 information request"), 0,
            "no client started under advertisements without M or O")

        gw:forget()
        local t0 = gw:now()
        gw:send_ra(copy(BASE, { other = true }))
        local irs = await_requests(5, 30)
        t:assert(#irs >= 5, "five INFORMATION-REQUESTs within 30 s (saw " .. #irs .. ")")
        t:assert(count_logged("interface eth0: dhcpv6 information request") >= 1,
            "netd logged `interface eth0: dhcpv6 information request`")

        local elapsed = {}
        for k = 1, 5 do
            local m = irs[k]
            local f = m.frame
            local what = "request " .. k
            t:log(string.format("%s at +%ds txid %s options %s", what, m.at - t0, hex(m.txid),
                (function()
                    local c = {}
                    for _, o in ipairs(m.options) do c[#c + 1] = o[1] .. "(" .. hex(o[2]) .. ")" end
                    return table.concat(c, " ")
                end)()))
            t:assert_eq(m.type, 11, what .. " is an INFORMATION-REQUEST")
            t:assert_eq(#m.txid, 3, what .. " has a 3-byte transaction id")
            t:assert_eq(m.txid, irs[1].txid, what .. " keeps the exchange's transaction id")
            t:assert_eq(f.src_ip, ll, what .. " comes from the link-local address")
            t:assert_eq(f.udp.sport, 546, what .. " from port 546")
            t:assert_eq(f.dst_ip, "ff02::1:2", what .. " to All_DHCP_Relay_Agents_and_Servers")
            t:assert_eq(f.udp.dport, 547, what .. " to port 547")
            t:assert_eq(f.dst, gateway.mcast_mac(gateway.ALL_DHCP_AGENTS), what .. " multicast MAC")
            t:assert_eq(#m.options, 3, what .. " carries exactly three options")
            t:assert_eq(m.options[1][1], 1, what .. ": client identifier first")
            t:assert_eq(m.options[1][2], DUID, what .. ": the client identifier is the machine's DUID")
            t:assert_eq(m.options[2][1], 8, what .. ": elapsed time second")
            t:assert_eq(#m.options[2][2], 2, what .. ": elapsed time is 2 bytes")
            t:assert_eq(m.options[3][1], 6, what .. ": option request third")
            t:assert_eq(m.options[3][2], string.pack(">I2I2I2", 23, 24, 32),
                what .. ": requests 23, 24 and 32")
            elapsed[k] = string.unpack(">I2", m.options[2][2])
        end
        t:assert(irs[1].at - t0 <= 2, "the first request goes when the exchange begins (+"
            .. (irs[1].at - t0) .. "s)")
        t:assert_eq(elapsed[1], 0, "the first request's elapsed time is 0")
        -- Hundredths since the exchange began: 1, 1+2, 1+2+4, 1+2+4+8
        -- seconds, each interval ±10%.
        local cum = 0
        for k = 2, 5 do
            local interval = 1 << (k - 2)
            cum = cum + interval
            local lo, hi = math.floor(90 * cum) - 5, math.ceil(110 * cum) + 5
            t:assert(elapsed[k] >= lo and elapsed[k] <= hi, string.format(
                "request %d's elapsed time %d is within [%d, %d] hundredths", k, elapsed[k], lo, hi))
            local gap = irs[k].at - irs[k - 1].at
            t:assert(gap >= math.floor(0.9 * interval) - 1 and gap <= math.ceil(1.1 * interval) + 1,
                string.format("request %d follows %d s after the last (%d s by the gateway's clock)",
                    k, interval, gap))
        end

        -- It never stops while unanswered — until router discovery does.
        -- The sixth request is due 16 s after the fifth; a cable pull
        -- before then must leave it unsent.
        local due = irs[5].at + 16
        nic:disconnect()
        t:assert(serve_iface(function(i) return i.carrier == false end,
            { iface = "eth0", timeout = 20 }), "carrier dropped")
        local cut = gw:now()
        t:assert(cut < due - 2, "the cable was pulled before the next retransmission was due")
        local before = #requests()
        nic:reconnect()
        local s = serve_iface(function(i)
            return i.carrier and i.gateway6 ~= nil and #network.ipv6(i) > 0
        end, { iface = "eth0", timeout = 30 })
        t:assert(s, "router discovery came back (an advertisement without M or O)")
        gw:serve({ timeout = math.max(0, due + 3 - gw:now()) })
        t:assert(gw:now() >= due + 2, "waited past the retransmission that was due")
        t:assert_eq(#requests(), before, "no INFORMATION-REQUEST after the client stopped with discovery")
        for _, m in ipairs(requests()) do
            if m.at > cut then t:log("unexpected request at +" .. (m.at - t0) .. "s txid " .. hex(m.txid)) end
        end
    end)

-- ---------------------------------------------------------------------------
-- The reply (needs a reply to reach netd: see the header)
-- ---------------------------------------------------------------------------

test("only a REPLY with the exchange's transaction id, the machine's DUID and a non-empty server id is accepted; option 23 gives up to 16 servers less unspecified, multicast and loopback, option 24 the domains; retransmission stops",
    { spec = "netd *dhcp6.reply-acceptance" }, function(t)
        local ll = assert(link_local(), "the machine has a link-local address")
        local srv = { 2, "\0\3\0\1" .. gw.mac }
        local function names(list) return gateway.opt.names(list) end
        local function servers(list)
            local b = {}
            for _, a in ipairs(list) do b[#b + 1] = gateway.ip6(a) end
            return table.concat(b)
        end
        -- Exchange A: five replies that must be ignored, then a good one.
        local n_req, sent = 0, 0
        gw:dhcp6({ on = function(m, _)
            n_req = n_req + 1
            local cid = { 1, m.opt[1] }
            local function bogus(k, txid, opts, kind)
                local dst = gateway.ip6(ll)
                gw:send_ip6(dst, 17, gateway.udp6(gw.ll, dst, 547, 546,
                    gateway.dhcp6_encode({ type = kind or 7, txid = txid, options = opts })),
                    { peer_mac = MAC })
                sent = sent + 1
            end
            if n_req == 1 then
                local other = string.char(m.txid:byte(1) ~ 0xff) .. m.txid:sub(2)
                bogus(1, other, { cid, srv, { 23, servers({ "fd6b::1" }) } })
                bogus(2, m.txid, { { 1, "\0\3\0\1\2\2\2\2\2\2" }, srv, { 23, servers({ "fd6b::2" }) } })
                bogus(3, m.txid, { cid, { 23, servers({ "fd6b::3" }) } })
                bogus(4, m.txid, { cid, { 2, "" }, { 23, servers({ "fd6b::4" }) } })
                bogus(5, m.txid, { cid, srv, { 23, servers({ "fd6b::5" }) } }, 2)
                return false
            end
            sent = sent + 1
            return { type = 7, txid = m.txid, options = { cid, srv,
                { 23, servers({ "fd62::1", "::", "ff02::1", "::1", "fd62::2" }) },
                { 24, names({ "v6.example", "UPPER.Example" }) } } }
        end })
        local d0, why = drops()
        t:log("NTFE verdict_drop before: " .. tostring(d0 or why))
        gw:forget()
        gw:send_ra(copy(BASE, { other = true }))
        local irs = await_requests(2, 20)
        t:assert(#irs >= 2, "the client asked twice (saw " .. #irs .. ")")
        t:assert_eq(irs[2].txid, irs[1].txid,
            "after five unacceptable datagrams the exchange retransmits unchanged")
        local s = serve_iface(function(i) return has(i.dns, "fd62::1") end,
            { iface = "eth0", timeout = 10 })
        local d1 = drops()
        t:log(string.format("replies sent %d (to %d requests); NTFE verdict_drop after: %s (delta %s); requests: %d, txids %s",
            sent, n_req, tostring(d1), (d0 and d1) and tostring(d1 - d0) or "?", #requests(),
            (function()
                local x = {}
                for _, m in ipairs(requests()) do x[#x + 1] = hex(m.txid) .. "@" .. m.at end
                return table.concat(x, " ")
            end)()))
        t:log("`dhcpv6 answered` logged " .. count_logged("dhcpv6 answered") .. " time(s)")
        -- Before alpha9 the shipped policy dropped the gateway's REPLY
        -- (fe80::gw:547 -> fe80::machine:546), so this never held (PEI-1366).
        t:assert(s, "the good REPLY was accepted (its server fd62::1 is in the status)")
        local i = iface()
        t:assert(has(i.dns, "fd62::2"), "both good servers are taken")
        for _, bad in ipairs({ "::", "ff02::1", "::1" }) do
            t:assert(not has(i.dns, bad), bad .. " is dropped")
        end
        for k = 1, 5 do
            t:assert(not has(i.dns, "fd6b::" .. k), "unacceptable datagram " .. k .. " was ignored")
        end
        t:assert(has(i.search, "v6.example") and has(i.search, "upper.example"),
            "option 24 gives the domains, lower-cased")
        t:assert(count_logged("interface eth0: dhcpv6 answered") >= 1, "netd logged `dhcpv6 answered`")
        local answered = #requests()
        gw:serve({ timeout = 6 })
        t:assert_eq(#requests(), answered, "no retransmission once a reply is accepted")

        -- Exchange B: 17 servers, the first 16 kept.
        cable_cycle()
        local seventeen = {}
        for k = 1, 17 do seventeen[k] = string.format("fd63::%x", k) end
        gw:dhcp6({ on = function(m, _)
            return { type = 7, txid = m.txid, options = { { 1, m.opt[1] }, srv,
                { 23, servers(seventeen) } } }
        end })
        gw:send_ra(copy(BASE, { other = true }))
        s = serve_iface(function(i2) return has(i2.dns, "fd63::10") end,
            { iface = "eth0", timeout = 15 })
        t:assert(s, "a reply with 17 servers was accepted")
        for k = 1, 16 do t:assert(has(s.dns, seventeen[k]), seventeen[k] .. " kept") end
        t:assert(not has(s.dns, "fd63::11"), "the 17th server is not kept")

        -- Exchange C: option 23 not a whole number of addresses.
        cable_cycle()
        gw:dhcp6({ on = function(m, _)
            return { type = 7, txid = m.txid, options = { { 1, m.opt[1] }, srv,
                { 23, servers({ "fd64::1" }) .. "\1\2\3\4" }, { 24, names({ "c.example" }) } } }
        end })
        gw:send_ra(copy(BASE, { other = true }))
        s = serve_iface(function(i2) return has(i2.search, "c.example") end,
            { iface = "eth0", timeout = 15 })
        t:assert(s, "the reply was accepted (its domain is in the status)")
        t:assert(not has(s.dns, "fd64::1"), "an option 23 of 20 bytes gives no servers")
    end)

test("after a reply the client waits for the refresh time, never less than 600 s",
    { spec = "netd *dhcp6.refresh-time" }, function(t)
        -- Only the floor's lower edge is observable in a test of this
        -- length: a refresh time of 1 s must not bring a request within
        -- 30 s. 600 s itself, the one-day default, the new transaction
        -- id and the answered/unchanged logging need a ten-minute wait
        -- (the floor is covered by `cargo +1.98.1 test -p dhcp6 -- --exact
        -- tests::a_refresh_floor_defeats_a_hostile_refresh_time`).
        cable_cycle()
        local sent = 0
        gw:dhcp6({ dns = { "fd65::1" }, refresh = 1, on = function(_, r) sent = sent + 1; return r end })
        local d0 = drops()
        gw:send_ra(copy(BASE, { other = true }))
        local s = serve_iface(function(i) return has(i.dns, "fd65::1") end,
            { iface = "eth0", timeout = 15 })
        local d1 = drops()
        t:log(string.format("replies sent %d; requests %d; NTFE verdict_drop delta %s",
            sent, #requests(), (d0 and d1) and tostring(d1 - d0) or "?"))
        -- Before alpha9 the REPLY never reached netd (see the header,
        -- PEI-1366), so nothing was accepted and there was no refresh to time.
        t:assert(s, "the REPLY with refresh time 1 was accepted")
        local n = #requests()
        local at = gw:now()
        gw:serve({ timeout = 30 })
        t:assert(gw:now() - at >= 30, "waited 30 s")
        t:assert_eq(#requests(), n, "no new exchange within 30 s of a refresh time of 1 s")
    end)
