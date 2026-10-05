-- netd §8.3 "Merging DNS facts" — the servers and search domains a scope
-- (and the status reply's `dns` and `search`) carries: the profile's own,
-- then, with Dns.Offered, the lease's, the routers' and the DHCPv6
-- reply's, link-local IPv6 servers withheld, and adjacent duplicates
-- (only adjacent ones, PEI-1332) removed.
--
-- Harness: the scripted gateway (helpers.gateway) plays all three
-- sources at once: a DHCPv4 server whose lease carries options 6, 15 and
-- 119; a router whose advertisements carry RDNSS and DNSSL and the O flag;
-- and a stateless DHCPv6 server. The profile's values are written live
-- on `Profiles\default`; each edit restarts netd's clients, so every
-- check waits for the merged list it expects.
--
-- The DHCPv6 source (step 4 of each list) cannot be shown on the shipped
-- policy: the gateway's REPLY (fe80::gw:547 → fe80::machine:546) never
-- reaches netd (PEI-1366, found by the dhcp6 testset). The
-- passing tests therefore run without a DHCPv6 server and check steps
-- 1–3; the last test asserts the TRM's step 4 and is tagged known-bug.
--
-- Own VMs: the gateway setup (router, three sources) is specific to this
-- file, and the default profile is edited throughout.

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

local function lease_with(o)
    local d = { pool = { "10.77.0.50" }, lease = 3600 }
    for k, v in pairs(o or {}) do d[k] = v end
    gw:dhcp(d)
end
local OPT119 = { 119, gateway.opt.names({ "a.example", "b.example" }) }
local OPT15 = { 15, "dn.example" }
lease_with({ dns = { "10.77.0.1" }, options = { OPT119, OPT15 } })

local RA = {
    lifetime = 1800, other = true,
    rdnss = { lifetime = 3600, servers = { "fd77::53", "fe80::53" } },
    dnssl = { lifetime = 3600, domains = { "ra.example" } },
}
gw:router(RA)

local sut = network.boot({ bridges = { lan }, gateway = gw })

local function list_text(l) return "[" .. table.concat(l or {}, ", ") .. "]" end

local function profile(values)
    for name, v in pairs(values) do
        if v == false then
            network.reg(sut, { "del", network.KEY .. "\\Profiles\\default", name })
        else
            network.reg(sut, { "set", network.KEY .. "\\Profiles\\default", name, v }):assert_ok()
        end
    end
end

--- One snapshot, read through a fresh subscription.
local function snapshot()
    local fd = assert(unixsock.socket(sut, unixsock.AF_UNIX, unixsock.SOCK.STREAM))
    assert(unixsock.connect(sut, fd, network.CONTROL).ret == 0, "connect")
    local p = msgpack.encode({ query = "subscribe" })
    ntfe.send(sut, fd, string.pack("<I4", #p) .. p)
    local buf = ""
    while #buf < 4 or #buf < 4 + string.unpack("<I4", buf) do
        local chunk = ntfe.recv(sut, fd, 3000, 65536)
        assert(chunk and #chunk > 0, "no snapshot")
        buf = buf .. chunk
    end
    sys.close(sut, fd)
    return msgpack.decode(buf:sub(5, 4 + string.unpack("<I4", buf)))
end

local function scope(name)
    for _, s in ipairs(snapshot().scopes) do if s.name == name then return s end end
end

--- Pump until eth0's status shows exactly `servers` and `domains`, and
--- check its snapshot scope says the same.
local function expect(t, servers, domains, what)
    local want_s, want_d = list_text(servers), list_text(domains)
    local last
    local ok = network.serve_until(gw, sut, function(i)
        last = i
        return network.bound(i) and list_text(i.dns) == want_s and list_text(i.search) == want_d
    end, { iface = "eth0", timeout = 60 })
    t:log(string.format("%s: status dns %s search %s", what, list_text(last and last.dns),
        list_text(last and last.search)))
    t:assert(ok, what .. ": status dns " .. want_s .. " and search " .. want_d)
    local sc = scope("eth0")
    t:log(string.format("%s: snapshot servers %s domains %s", what, list_text(sc.servers), list_text(sc.domains)))
    t:assert_eq(list_text(sc.servers), want_s, what .. ": snapshot servers")
    t:assert_eq(list_text(sc.domains), want_d, what .. ": snapshot domains")
end

test("servers: the profile's, then the lease's, then the routers' non-link-local RDNSS; domains: the profile's, then option 119 (else 15), then DNSSL; without Dns.Offered only the profile's",
    { spec = "netd *snapshot.dns-merge" }, function(t)
        profile({ ["Dns.Servers"] = "multi:10.77.0.9,fd77::9", ["Dns.Domains"] = "multi:prof.example" })
        expect(t, { "10.77.0.9", "fd77::9", "10.77.0.1", "fd77::53" },
            { "prof.example", "a.example", "b.example", "ra.example" },
            "profile, lease (119 over 15), RDNSS (fe80::53 withheld), DNSSL")

        -- A lease with no search list: its domain name instead.
        lease_with({ dns = { "10.77.0.1" }, options = { OPT15 } })
        gw:forget()
        t:assert(network.call(sut, { query = "renew", interface = "eth0" }).ok, "renew")
        expect(t, { "10.77.0.9", "fd77::9", "10.77.0.1", "fd77::53" },
            { "prof.example", "dn.example", "ra.example" }, "no option 119: option 15")

        -- Without Dns.Offered: the profile's alone.
        profile({ ["Dns.Offered"] = "dword:0" })
        expect(t, { "10.77.0.9", "fd77::9" }, { "prof.example" }, "Dns.Offered off")

        profile({ ["Dns.Offered"] = "dword:1", ["Dns.Servers"] = false, ["Dns.Domains"] = false })
        expect(t, { "10.77.0.1", "fd77::53" }, { "dn.example", "ra.example" }, "the profile's own values removed")
    end)

-- PEI-1332: de-duplication is of adjacent entries only. This is the
-- documented current behaviour; the test passes on it.
test("each list loses adjacent duplicates only: a server or domain repeated with something between keeps both (PEI-1332)",
    { spec = "netd *snapshot.adjacent-duplicates-only" }, function(t)
        lease_with({ dns = { "10.77.0.1", "10.77.0.2", "10.77.0.1" },
            options = { { 119, gateway.opt.names({ "x.example", "y.example", "x.example" }) } } })
        profile({ ["Dns.Servers"] = "multi:10.77.0.1", ["Dns.Domains"] = "multi:x.example" })
        -- profile 10.77.0.1 + lease 10.77.0.1 (adjacent: one goes),
        -- 10.77.0.2, 10.77.0.1 (not adjacent: kept), then RDNSS.
        expect(t, { "10.77.0.1", "10.77.0.2", "10.77.0.1", "fd77::53" },
            { "x.example", "y.example", "x.example", "ra.example" },
            "adjacent duplicates dropped, separated ones kept")
        profile({ ["Dns.Servers"] = false, ["Dns.Domains"] = false })
    end)

test("with Dns.Offered the DHCPv6 reply's non-link-local servers and its domains come last",
    { spec = "netd *snapshot.dns-merge", tags = { "known-bug" } }, function(t)
        lease_with({ dns = { "10.77.0.1" }, options = { OPT119 } })
        gw:dhcp6({ dns = { "fd77::54", "fe80::54" }, domains = { "v6.example" } })
        -- Restart the clients (and the O-flag DHCPv6 client with them) so
        -- the information request goes to a server that answers.
        profile({ ["Dns.Domains"] = "multi:prof.example" })
        -- PEI-1366: on the shipped policy the gateway's
        -- REPLY never reaches netd, so fd77::54 and v6.example never
        -- appear; the list stops after the routers' entries.
        local ok, err = pcall(expect, t, { "10.77.0.1", "fd77::53", "fd77::54" },
            { "prof.example", "a.example", "b.example", "ra.example", "v6.example" },
            "with a DHCPv6 reply")
        local asked = 0
        for _, m in ipairs(gw:dhcp6_messages()) do
            if m.type == gateway.DHCP6.INFORMATION_REQUEST then asked = asked + 1 end
        end
        t:log("information requests the gateway saw (its dhcp6 server replies to each): " .. asked)
        t:log("netd logged `dhcpv6 answered`: " .. tostring(network.logged(sut, "dhcpv6 answered")))
        profile({ ["Dns.Domains"] = false })
        if not ok then error(err, 0) end
    end)
