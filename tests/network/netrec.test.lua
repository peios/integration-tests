-- netd TRM §7.2 — network records: what netd writes under a record's
-- `Status`, and when; the descriptor `Status` is created with; what the
-- operator writes on the record and how often netd reads it; and that
-- records are never deleted.
--
-- Values are read with `reg get --json`, which gives each value's type
-- and its sequence number. The sequence is the instrument for "written
-- only when it differs": a value netd rewrote has a new sequence even if
-- the text is the same, so an unchanged sequence across a full pass (the
-- `reconcile` control request runs one) means netd did not write it.
--
-- The descriptor's effect is checked from a second identity: a minted
-- principal holding Administrators, which the hive root's inheritable
-- grants would let write anywhere under `Machine`. It may write the
-- record key (inherited grants reach it) and may not write `Status`
-- (protected, SYSTEM only) but may read it (Everyone may). The agent
-- itself is SYSTEM, which the descriptor admits, so it cannot show a
-- refusal.
--
-- `Server` is never seen removed: a record's key is derived from its
-- basis, and a DHCPv4 basis always has a server while an RA basis never
-- does, so no record goes from having a server to not. Removal is shown
-- on `Gateway` (a lease without option 3) and `Router` (an advertisement
-- with router lifetime 0), which do change under a fixed key.
--
-- One pair; the tests run in order.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local sha1 = require("helpers.sha1")
local token = require("helpers.token")
local lcs = require("helpers.lcs")
local sys = require("helpers.sys")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
local sut = network.boot({ bridges = { lan }, gateway = gw })

local function netid(basis) return sha1.uuid5("peios-netd-network|wired|" .. basis) end
local NETID = netid("dhcp:10.77.0.1|10.77.0.0/24")
local ID2 = netid("dhcp:10.77.0.2|10.77.0.0/24")
local GW_LL = gateway.ip6_text(gw.ll)
local STATUS_SDDL = "O:SYG:SYD:P(A;;KA;;;SY)(A;;KR;;;WD)"

local function key(id, sub)
    return network.KEY .. "\\Networks\\" .. id .. (sub and ("\\" .. sub) or "")
end

--- One value as `reg get --json` gives it ({type, data, sequence}), or nil.
local function value(k, name)
    local r = network.reg(sut, { "get", k, name, "--json" })
    if r.exit_code ~= 0 then return nil end
    return json.decode(r.stdout)
end

local function iface() return network.iface(network.status(sut), "eth0") end

local function full_pass(t)
    local r = network.call(sut, { query = "reconcile" })
    t:assert(r and r.ok, "a full pass on request")
end

local function wait_value(t, k, name, pred, what)
    local v
    local ok = wait_until(function()
        gw:serve({ timeout = 0 })
        v = value(k, name)
        return pred(v)
    end, { timeout = 15, interval = 0.25, desc = what })
    t:assert(ok, what)
    return v
end

local function sddl(k)
    local r = network.reg(sut, { "sd", k })
    r:assert_ok()
    return (r.stdout:gsub("%s+$", ""))
end

test("netd writes Kind, Server, Gateway, Router, Prefixes, DnsServers, LastSeen and LastInterface under Status, each only when it differs",
    { spec = "netd *netrec.status-values" }, function(t)
        local s = network.serve_until(gw, sut, function(i) return network.bound(i) and i.network == NETID end,
            { iface = "eth0", timeout = 60 })
        t:assert(s, "bound on network " .. NETID)
        local S = key(NETID, "Status")
        local expect = {
            Kind = { "sz", "wired" }, Server = { "sz", "10.77.0.1" }, Gateway = { "sz", "10.77.0.1" },
            LastInterface = { "sz", "eth0" },
        }
        for name, e in pairs(expect) do
            local v = value(S, name)
            t:assert(v, name .. " is written")
            t:assert_eq(v.type, e[1], name .. " is REG_SZ")
            t:assert_eq(v.data, e[2], name)
        end
        local p = value(S, "Prefixes")
        t:assert_eq(p.type, "multi", "Prefixes is REG_MULTI_SZ")
        t:assert_eq(table.concat(p.data, ","), "10.77.0.0/24", "Prefixes: the subnet, in CIDR form")
        local d = value(S, "DnsServers")
        t:assert_eq(d.type, "multi", "DnsServers is REG_MULTI_SZ")
        t:assert_eq(table.concat(d.data, ","), "10.77.0.1", "DnsServers: the lease's server")
        t:assert_eq(value(S, "Router"), nil, "no Router with no advertisement")
        local ls = value(S, "LastSeen")
        t:assert_eq(ls.type, "sz", "LastSeen is REG_SZ")
        local now = tonumber(sut:run("date +%s").stdout)
        t:assert(tonumber(ls.data) and math.abs(tonumber(ls.data) - now) <= 10,
            "LastSeen is the wall-clock time in Unix seconds (" .. ls.data .. " vs the guest's " .. now .. ")")

        -- One more full pass, a second later: LastSeen is rewritten, and
        -- nothing else is.
        local before = {}
        for _, n in ipairs({ "Kind", "Server", "Gateway", "Prefixes", "DnsServers", "LastInterface", "LastSeen" }) do
            before[n] = value(S, n).sequence
        end
        local at = os.time()
        wait_until(function() return os.time() > at + 1 end, { timeout = 5, interval = 0.2, desc = "a second to pass" })
        full_pass(t)
        local after_ls = value(S, "LastSeen")
        t:assert(after_ls.sequence ~= before.LastSeen and tonumber(after_ls.data) > tonumber(ls.data),
            "LastSeen is rewritten on the pass (" .. ls.data .. " → " .. after_ls.data .. ")")
        for _, n in ipairs({ "Kind", "Server", "Gateway", "Prefixes", "DnsServers", "LastInterface" }) do
            t:assert_eq(value(S, n).sequence, before[n], n .. " is not rewritten when it has not changed")
        end

        -- A router appears, and then withdraws (router lifetime 0).
        local ra = { lifetime = 1800, prefixes = { { prefix = "fd77::", len = 64 } } }
        gw:router(ra)
        gw:send_ra(ra)
        local r = wait_value(t, S, "Router", function(v) return v ~= nil end, "Router to be written")
        t:assert_eq(r.type, "sz", "Router is REG_SZ")
        t:assert_eq(r.data, GW_LL, "Router is the IPv6 default router")
        wait_value(t, S, "Prefixes", function(v) return v and #v.data == 2 end, "the autoconfigured prefix to join Prefixes")
        t:assert_eq(table.concat(value(S, "Prefixes").data, ","), "10.77.0.0/24,fd77::/64", "Prefixes in CIDR form")
        local gone = { lifetime = 0, prefixes = { { prefix = "fd77::", len = 64 } } }
        gw:router(gone)
        gw:send_ra(gone)
        wait_value(t, S, "Router", function(v) return v == nil end, "Router to be removed")

        -- A lease with no router option: Gateway is removed.
        gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600, router = false })
        local ok = network.call(sut, { query = "renew", interface = "eth0" })
        t:assert(ok and ok.ok, "renew accepted")
        wait_value(t, S, "Gateway", function(v) return v == nil end, "Gateway to be removed")
        gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
        ok = network.call(sut, { query = "renew", interface = "eth0" })
        t:assert(ok and ok.ok, "renew accepted")
        wait_value(t, S, "Gateway", function(v) return v and v.data == "10.77.0.1" end, "Gateway to come back")
    end)

test("Name, Trust and RequestedAddress on the record are read as strings; an empty Name or Trust is unset",
    { spec = "netd *netrec.operator-values" }, function(t)
        local R = key(NETID)
        local ra = value(R, "RequestedAddress")
        t:assert(ra, "RequestedAddress is on the record itself")
        t:assert_eq(ra.type, "sz", "as REG_SZ")
        t:assert_eq(ra.data, "10.77.0.50", "holding the lease's IPv4 address")
        t:assert_eq(value(key(NETID, "Status"), "Name"), nil, "Name is not a Status value")

        network.write(sut, "Networks\\" .. NETID, { Name = "sz:home", Trust = "sz:" })
        local s = network.serve_until(gw, sut, function(i) return i.network_name == "home" end,
            { iface = "eth0", timeout = 15 })
        t:assert(s, "Name is read as the Network.Name fact")
        t:assert_eq(network.iface(s, "eth0").network_trust, nil, "an empty Trust is unset")
        network.write(sut, "Networks\\" .. NETID, { Name = "sz:", Trust = "sz:medium" })
        s = network.serve_until(gw, sut, function(i) return i.network_trust == "medium" end,
            { iface = "eth0", timeout = 15 })
        t:assert(s, "Trust is read as the Network.Trust fact")
        t:assert_eq(network.iface(s, "eth0").network_name, nil, "an empty Name is unset")
    end)

test("Name and Trust are read at every identification, so an edit reaches the interface layer on the next pass, opaque",
    { spec = "netd *netrec.name-and-trust-are-read-each-pass" }, function(t)
        local net_before = iface().network
        -- No network event: only the registry write, whose pass picks it up.
        local name = "Büro 3 / not a word netd knows"
        network.write(sut, "Networks\\" .. NETID, { Name = "sz:" .. name, Trust = "sz:whatever-you-like" })
        local s = network.serve_until(gw, sut, function(i)
            return i.network_name == name and i.network_trust == "whatever-you-like"
        end, { iface = "eth0", timeout = 15 })
        t:assert(s, "the edit reaches the status on the following pass, exactly as written")
        t:assert_eq(network.iface(s, "eth0").network, net_before, "the network itself did not change")
        network.reg(sut, { "del", key(NETID), "Name" }):assert_ok()
        network.reg(sut, { "del", key(NETID), "Trust" }):assert_ok()
        s = network.serve_until(gw, sut, function(i) return i.network_name == nil and i.network_trust == nil end,
            { iface = "eth0", timeout = 15 })
        t:assert(s, "and deleting them unsets the facts on the following pass")
    end)

test("Status is created SYSTEM-only and protected; a Status that already exists keeps its own descriptor",
    { spec = "netd *netrec.status-descriptor" }, function(t)
        local S = key(NETID, "Status")
        t:assert_eq(sddl(S), STATUS_SDDL, "the descriptor netd gave Status")

        local ENABLED = token.GROUP.MANDATORY | token.GROUP.ENABLED_BY_DEFAULT | token.GROUP.ENABLED
        token.as_principal(t, sut, {
            user_sid = token.SID.TEST_USER,
            groups = {
                { sid = token.SID.EVERYONE, attributes = ENABLED },
                { sid = token.SID.AUTHENTICATED_USERS, attributes = ENABLED },
                { sid = token.SID.ADMINISTRATORS, attributes = ENABLED },
            },
        }, function(w)
            local rec = lcs.open_key(nil, w, -1, key(NETID), lcs.RIGHT.SET_VALUE)
            t:assert(rec.ret >= 0, "an Administrator may write the record key (inherited grants): "
                .. sys.errname(rec.errno or 0))
            if rec.ret >= 0 then sys.close(w, rec.ret) end
            local wr = lcs.open_key(nil, w, -1, S, lcs.RIGHT.SET_VALUE)
            t:assert_eq(wr.errno, sys.E.ACCES, "but not Status: the hand edit is refused")
            if wr.ret >= 0 then sys.close(w, wr.ret) end
            local rd = lcs.open_key(nil, w, -1, S, lcs.RIGHT.QUERY_VALUE)
            t:assert(rd.ret >= 0, "while anyone may read it: " .. sys.errname(rd.errno or 0))
            if rd.ret >= 0 then sys.close(w, rd.ret) end
        end)

        -- A network not seen yet, whose Status key exists already.
        network.reg(sut, { "new", key(ID2) }):assert_ok()
        network.reg(sut, { "new", key(ID2, "Status") }):assert_ok()
        local before = sddl(key(ID2, "Status"))
        t:log("pre-made Status descriptor: " .. before)
        t:assert(before ~= STATUS_SDDL, "the pre-made key has an inherited descriptor, not netd's")
        gw:dhcp({ server = "10.77.0.2", pool = { "10.77.0.50" }, lease = 3600 })
        local nic = lan:nic(sut)
        nic:disconnect()
        t:assert(network.serve_until(gw, sut, function(x) return x.carrier == false end,
            { iface = "eth0", timeout = 20 }), "carrier goes")
        nic:reconnect()
        local s = network.serve_until(gw, sut, function(i) return network.bound(i) and i.network == ID2 end,
            { iface = "eth0", timeout = 40 })
        t:assert(s, "the interface stands on network " .. ID2)
        wait_value(t, key(ID2, "Status"), "Server", function(v) return v and v.data == "10.77.0.2" end,
            "netd to fill the pre-made Status")
        t:assert_eq(sddl(key(ID2, "Status")), before, "the existing Status keeps the descriptor it had")
    end)

test("records are never deleted: not when the network changes, the carrier goes, or netd restarts",
    { spec = "netd *netrec.never-deleted" }, function(t)
        t:assert_eq(iface().network, ID2, "the interface has moved off " .. NETID)
        t:assert(value(key(NETID, "Status"), "Kind"), "the old network's record is still there")
        t:assert(value(key(NETID), "RequestedAddress"), "with the operator's side of it")

        local nic = lan:nic(sut)
        nic:disconnect()
        t:assert(network.serve_until(gw, sut, function(x) return x.carrier == false and x.network == nil end,
            { iface = "eth0", timeout = 20 }), "carrier goes and the network is forgotten")
        t:assert(value(key(ID2, "Status"), "Kind"), "the record of the network just left stays")
        network.restart_netd(sut)
        gw:serve({ timeout = 2 })
        t:assert(value(key(NETID, "Status"), "Kind"), "a new netd deletes nothing: " .. NETID)
        t:assert(value(key(ID2, "Status"), "Kind"), "nor " .. ID2)
        nic:reconnect()
        t:assert(network.serve_until(gw, sut, network.bound, { iface = "eth0", timeout = 40 }), "the machine binds again")
        t:assert(value(key(NETID, "Status"), "Kind") and value(key(ID2, "Status"), "Kind"), "both records remain")
    end)
