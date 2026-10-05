-- Cross-component: netd's network identity reaches NTFE's `Network.*`
-- facts (netd TRM §7 and §8.1; PKM §6.3 and §6.5). The ntfe testset
-- proves the kernel's half with an inventory seeded by hand into a
-- stand-in registry source (ntfe/ingest-context, ntfe/snapshot-context),
-- and the network testset proves netd's half by reading the registry.
-- Here netd writes the inventory, the real registry carries it, and the
-- kernel's Flow layer judges real TCP connections on eth0 by it.
--
-- Harness: the scripted gateway (helpers.gateway) and a whole Peios
-- (helpers.network). The gateway's own kernel is the client: it opens
-- TCP connections to listeners the agent holds on the machine (`::`,
-- ports 7001-7007), over IPv4 to the leased address and over IPv6 to
-- eth0's link-local address, which stays when the lease does not. Under
-- the shipped baseline a new inbound flow meets the Flow backstop (DROP).
-- The file writes its rules in one `reg apply` transaction:
--
--   REJECT ports, open by a Priority 1 PASS and refused at Priority 2
--   when a fact holds: 7001 `Network.Trust.Equal = pt-lab`, 7002
--   `Network.Name.Equal = pt-office`, 7003 `Network.Id.Equal = <the id>`,
--   7004 `Network.Id.Present = 0`;
--   PASS ports, shut by the backstop and opened at Priority 2 when a fact
--   holds: 7005 `Network.Id.Equal = <the id>`, 7006 `Network.Id.Present
--   = 0`, 7007 `Network.Trust.Equal = pt-lab`.
--
-- A connection is "pass" (handshake), "reject" (ECONNREFUSED: the RST)
-- or "drop" (nothing within 1.5 s). Link-local probes use the PASS
-- ports, where the outcome is the backstop's DROP or the fact's PASS and
-- no refusal is involved; the last test covers a link-local REJECT, which
-- before kernel alpha9 was never answered (PEI-1383).
--
-- The network id is computed with helpers.sha1 from netd's rule
-- (`dhcp:10.77.0.1|10.77.0.0/24`, kind wired). When a rule or a record
-- is in force is read from the engine: `net policy wait`, and the status
-- ioctl of /dev/peios-ntfe for `generation`, `contexts` and
-- `changes_noted`. The interface layer's reading of the same record is
-- netd's status (`network_trust`, and `rule` for an Interface rule
-- conditioned on the same Trust).
--
-- Own VMs: Flow and Interface rules, the network record's Name and
-- Trust, and a cable pull with the gateway silent. Tests run in order;
-- the rules stay for the whole file.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local sha1 = require("helpers.sha1")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")
local rtnl = require("helpers.rtnl")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
local DHCP = { pool = { "10.77.0.50" }, lease = 3600 }
gw:dhcp(DHCP)
local sut = network.boot({ bridges = { lan }, gateway = gw })

local KEY = network.KEY
local ADDR = "10.77.0.50"
local NETID = sha1.uuid5("peios-netd-network|wired|dhcp:10.77.0.1|10.77.0.0/24")
local PORT = { trust = 7001, name = 7002, id = 7003, none = 7004,
    open_id = 7005, open_none = 7006, open_trust = 7007 }
local ORDER = { "trust", "name", "id", "none", "open_id", "open_none", "open_trust" }

-- ---------------------------------------------------------------------------
-- Local instruments
-- ---------------------------------------------------------------------------

local function list(l) return "[" .. table.concat(l or {}, ", ") .. "]" end

local function iface() return network.iface(network.status(sut), "eth0") end

--- One registry transaction (libreg's JSON document).
local function apply(keys)
    sut:write_file("/tmp/pt-cross-ctx.json", peinit.encode_json({ keys = keys }))
    local r = network.reg(sut, { "apply", "/tmp/pt-cross-ctx.json" })
    assert(r.exit_code == 0, "reg apply: " .. r.stdout .. r.stderr)
end

local function v(name, typ, data) return { name = name, type = typ, data = data } end

local dev
local function engine()
    dev = dev or assert(ntfe.open(sut), "open /dev/peios-ntfe")
    return assert(ntfe.status(sut, dev), "the engine's status")
end

--- `net policy wait`: everything the engine has noted is walked, and
--- the walk was not refused.
local function in_force(t, what)
    local r = sut:run("net policy wait 10")
    t:assert_eq(r.exit_code, 0, what .. ": net policy wait: " .. r.stderr)
    local s = engine()
    t:log(string.format("%s: generation %d, contexts %d, noted %d, walked %d, last error %d", what,
        s.generation, s.contexts, s.changes_noted, s.changes_walked, s.last_ingest_error))
    return s
end

local listeners = {}
local function listen()
    for _, k in ipairs(ORDER) do
        listeners[PORT[k]] = listeners[PORT[k]] or assert(ntfe.tcp_listen(sut, "::", PORT[k]))
    end
end

--- A connection from the gateway to `addr`:`port` (`scope`: the
--- gateway's ifindex, for a link-local address).
local function probe(addr, port, scope)
    local fd, why = ntfe.tcp_connect(gw.vm, addr, port, 1500, scope and { scope = scope } or nil)
    if fd then
        local a = ntfe.tcp_accept(sut, listeners[port], 1000)
        if a then sys.close(sut, a) end
        sys.close(gw.vm, fd)
        return a and "pass" or "connected, never accepted"
    end
    if why == "timeout" then return "drop" end
    if why == sys.E.CONNREFUSED then return "reject" end
    return "failed: " .. sys.errname(why)
end

local COUNTERS = { "judged", "flow_judged", "verdict_pass", "verdict_drop", "verdict_reject",
    "reject_degraded", "fail_closed", "parse_errors" }

--- What the machine sent the gateway since `from` (an index into gw.seen).
local function frames_since(from)
    gw:pump(100)
    local out = {}
    for k = from + 1, #gw.seen do
        local f = gw.seen[k]
        if f.ip6 then
            out[#out + 1] = f.icmp6_body and ("icmp6/" .. f.icmp6_body:byte(1)) or ("ip6/" .. f.ip6.next)
        elseif f.ip then
            out[#out + 1] = "ip4/" .. f.ip.protocol
        else
            out[#out + 1] = string.format("eth/0x%04x", f.ethertype or 0)
        end
    end
    return list(out)
end

--- Assert each port's outcome: `want` = { trust = "reject", … }. A
--- mismatch logs the engine's verdict counters over the probe and the
--- frames the machine sent the gateway meanwhile.
local function expect(t, want, addr, scope, what)
    for _, k in ipairs(ORDER) do
        if want[k] then
            local before, mark = engine(), #gw.seen
            local got = probe(addr, PORT[k], scope)
            if got ~= want[k] then
                local after = engine()
                local d = {}
                for _, c in ipairs(COUNTERS) do d[#d + 1] = c .. " +" .. (after[c] - before[c]) end
                t:log(string.format("%s: %s (port %d) to %s: %s; engine %s; machine sent %s", what, k,
                    PORT[k], addr, got, table.concat(d, ", "), frames_since(mark)))
            end
            t:assert_eq(got, want[k], string.format("%s: %s (port %d) to %s", what, k, PORT[k], addr))
        end
    end
end

--- eth0's link-local address, once it is no longer tentative.
local function link_local(t)
    local index = assert(ntfe.if_index(sut, "eth0"))
    local found
    local ok = pcall(wait_until, function()
        for _, a in ipairs(rtnl.addresses_of(sut, index)) do
            if a.address:match("^fe80:") and not a.tentative then found = a.address; return true end
        end
        return false
    end, { timeout = 15, interval = 0.25, desc = "eth0's link-local address" })
    t:assert(ok, "eth0 has a usable link-local address")
    return found
end

local function status_value(name)
    return network.get(sut, "Interfaces\\" .. iface().ifid .. "\\Status", name)
end

--- Pump until netd's eth0 satisfies `pred`; assert it.
local function netd_shows(t, pred, what)
    local s = network.serve_until(gw, sut, pred, { iface = "eth0", timeout = 20 })
    local i = s and network.iface(s, "eth0") or iface()
    t:log(string.format("%s: network %s name %s trust %s rule %s", what, tostring(i.network),
        tostring(i.network_name), tostring(i.network_trust), tostring(i.rule)))
    t:assert(s, what)
    return i
end

local FLOW = KEY .. [[\Rules\Flow]]
local function conditioned(name, fact, typ, value, port, action)
    return { path = FLOW .. "\\" .. name, values = {
        v(fact, typ, value), v("Protocol.Equal", "sz", "tcp"), v("DstPort.Equal", "dword", port),
        v("Priority", "dword", 2), v("Actions", "multi", { action }) } }
end

local function record(values)
    apply({ { path = KEY .. [[\Networks\]] .. NETID, values = values } })
end

-- ---------------------------------------------------------------------------

test("netd identifies the gateway's network and its inventory gives eth0 a context in the kernel's table",
    { spec = "netd *netid.derivation netd *netid.when netd *inventory.value-presence " ..
             "PKM *ntfe-ingest.walk-reads-inventory-with-rules PKM *ntfe-ingest.interface-status-read " ..
             "PKM *ntfe-ingest.status-contexts-counts-interfaces" },
    function(t)
        local s = network.serve_until(gw, sut, function(i) return network.bound(i) and i.network == NETID end,
            { iface = "eth0", timeout = 60 })
        t:assert(s, "eth0 bound and stands on network " .. NETID)
        t:assert(pcall(wait_until, function() return status_value("Network") == NETID end,
            { timeout = 10, interval = 0.25, desc = "Status Network" }), "netd wrote Status Network = " .. NETID)
        t:assert_eq(status_value("Name"), "eth0", "and Status Name = eth0")
        t:assert(network.get(sut, [[Networks\]] .. NETID .. [[\Status]], "Kind"), "the network's record exists")
        local e = in_force(t, "bound")
        t:assert_eq(e.enforcing, 1, "the baseline policy is enforced")
        t:assert_eq(e.contexts, 1, "one interface, eth0, carries a context: lo has no Status")
        local r = sut:run("net policy")
        t:log("net policy:\n" .. r.stdout)
        t:assert(r.stdout:find("contexts    1", 1, true), "net policy reports it")
    end)

test("a Flow rule on Network.Id governs inbound connections on eth0; with no Name or Trust on the record only the id is a fact",
    { spec = "PKM *ntfe-snapshot.context-filled-from-active-table PKM *ntfe-snapshot.network-id-lifted-when-bit-set " ..
             "PKM *ntfe-snapshot.empty-network-name-and-trust-absent PKM *ntfe-ingest.interface-entry-joins-network-record " ..
             "PKM *ntfe-ingest.in-force-when-walked-reaches-noted" },
    function(t)
        listen()
        -- The baseline alone: a new inbound flow meets the backstop.
        t:assert_eq(probe(ADDR, PORT.id), "drop", "without the file's rules the baseline drops the connection")
        apply({
            { path = FLOW .. [[\pt-x-open]], values = {
                v("Direction.Equal", "sz", "in"), v("Protocol.Equal", "sz", "tcp"),
                v("DstPort.Equal", "multi", { "7001", "7002", "7003", "7004" }),
                v("Priority", "dword", 1), v("Actions", "multi", { "PASS" }) } },
            conditioned("pt-x-trust", "Network.Trust.Equal", "sz", "pt-lab", PORT.trust, "REJECT"),
            conditioned("pt-x-name", "Network.Name.Equal", "sz", "pt-office", PORT.name, "REJECT"),
            conditioned("pt-x-id", "Network.Id.Equal", "sz", NETID, PORT.id, "REJECT"),
            conditioned("pt-x-none", "Network.Id.Present", "dword", 0, PORT.none, "REJECT"),
            conditioned("pt-x-open-id", "Network.Id.Equal", "sz", NETID, PORT.open_id, "PASS"),
            conditioned("pt-x-open-none", "Network.Id.Present", "dword", 0, PORT.open_none, "PASS"),
            conditioned("pt-x-open-trust", "Network.Trust.Equal", "sz", "pt-lab", PORT.open_trust, "PASS"),
        })
        local e = in_force(t, "rules written")
        t:assert_eq(e.last_ingest_error, 0, "the rules are accepted")
        local i = iface()
        t:assert_eq(i.network_name, nil, "the record has no Name")
        t:assert_eq(i.network_trust, nil, "nor Trust")
        expect(t, { trust = "pass", name = "pass", id = "reject", none = "pass",
                    open_id = "pass", open_none = "drop", open_trust = "drop" }, ADDR, nil,
            "eth0 stands on " .. NETID .. ", unlabelled")
    end)

test("the operator's Name and Trust on netd's record are Network.Name and Network.Trust in both layers; changing Trust changes the outcome, a running connection included",
    { spec = "netd *netrec.operator-values netd *netrec.name-and-trust-are-read-each-pass " ..
             "PKM *ntfe-snapshot.network-facts-match-interface-layer PKM *ntfe-ingest.changed-context-table-advances-generation " ..
             "PKM *ntfe-ingest.context-change-rejudges-flows-on-next-packet PKM *ntfe-ingest.interface-entry-joins-network-record " ..
             "PKM *ntfe-seat.established-tcp-reject-tears-down-far-end" },
    function(t)
        -- The interface layer's half: a rule of netd's that speaks only
        -- while the record's Trust is pt-lab.
        apply({ { path = KEY .. [[\Rules\Interface\pt-x-trusted]], values = {
            v("Interface.Equal", "multi", { "eth0" }), v("Network.Trust.Equal", "sz", "pt-lab"),
            v("Priority", "dword", 20), v("Actions", "multi", { "JOIN(default)" }) } } })
        t:assert(network.call(sut, { query = "reconcile" }).ok, "a full pass")
        netd_shows(t, function(i) return i.rule == "wired" and network.bound(i) end, "no Trust: the baseline rule speaks")

        -- A connection opened while Trust is unset.
        local c = assert(ntfe.tcp_connect(gw.vm, ADDR, PORT.trust, 1500), "a connection to 7001 is passed")
        local a = assert(ntfe.tcp_accept(sut, listeners[PORT.trust], 1000), "and accepted")
        ntfe.send(gw.vm, c, "before")
        t:assert_eq(ntfe.recv(sut, a, 1000), "before", "and carries data")
        local g0 = engine().generation

        record({ v("Name", "sz", "pt-office"), v("Trust", "sz", "pt-lab") })
        netd_shows(t, function(i)
            return i.network_trust == "pt-lab" and i.network_name == "pt-office" and i.rule == "pt-x-trusted"
        end, "netd reads Name and Trust, and the Trust rule speaks for eth0")
        local e = in_force(t, "Trust pt-lab")
        t:assert(e.generation > g0, "the labelled record is a new generation (" .. g0 .. " -> " .. e.generation .. ")")
        t:assert_eq(e.contexts, 1, "still one context")

        -- The running connection's next packet is re-judged under the
        -- new context and refused; the refusal tears down our end.
        ntfe.send(gw.vm, c, "after")
        local got, why = ntfe.recv(sut, a, 1000)
        t:log("the running connection after the change: " .. tostring(got) .. " / " .. tostring(why))
        t:assert_eq(got, nil, "the data never arrives")
        t:assert_eq(why, sys.E.CONNRESET, "the machine's socket is reset")
        sys.close(gw.vm, c); sys.close(sut, a)
        expect(t, { trust = "reject", name = "reject", id = "reject", none = "pass",
                    open_trust = "pass" }, ADDR, nil, "Trust pt-lab, Name pt-office")

        local g1 = engine().generation
        record({ v("Trust", "sz", "pt-public") })
        netd_shows(t, function(i) return i.network_trust == "pt-public" and i.rule == "wired" end,
            "netd reads the new Trust; its rule no longer speaks")
        e = in_force(t, "Trust pt-public")
        t:assert(e.generation > g1, "the changed Trust is a new generation")
        expect(t, { trust = "pass", name = "reject", id = "reject", none = "pass",
                    open_trust = "drop" }, ADDR, nil, "Trust pt-public")
    end)

test("netd rewriting its record without changing the context costs a walk and no generation",
    { spec = "PKM *ntfe-ingest.equal-context-table-publishes-nothing PKM *ntfe-ingest.inventory-write-changes-no-generation " ..
             "PKM *ntfe-ingest.changes-noted-counts-watch-events netd *netrec.status-values" },
    function(t)
        local S = [[Networks\]] .. NETID .. [[\Status]]
        local seen = network.get(sut, S, "LastSeen")
        local before = in_force(t, "before the pass")
        -- LastSeen is in whole seconds: let one pass so the pass's write
        -- is a real change.
        local at = os.time()
        wait_until(function() return os.time() > at + 1 end, { timeout = 5, interval = 0.2, desc = "a second" })
        t:assert(network.call(sut, { query = "reconcile" }).ok, "a full pass")
        t:assert(pcall(wait_until, function() return network.get(sut, S, "LastSeen") ~= seen end,
            { timeout = 10, interval = 0.25, desc = "LastSeen rewritten" }), "netd rewrote LastSeen (" .. tostring(seen) .. ")")
        local after = in_force(t, "after the pass")
        t:assert(after.changes_noted > before.changes_noted, "the engine noted netd's write")
        t:assert_eq(after.generation, before.generation, "and published no generation: the context table is the same")
        t:assert_eq(after.contexts, 1, "eth0 keeps its context")
        expect(t, { trust = "pass", id = "reject" }, ADDR, nil, "unchanged")
    end)

test("pulling the cable makes the facts absent: Status Network goes, the kernel's table empties, and a connection on eth0 meets no network rule",
    { spec = "netd *inventory.value-presence netd *netid.sticky-while-carrier netd *netid.when " ..
             "PKM *ntfe-ingest.incomplete-status-makes-no-entry PKM *ntfe-snapshot.no-context-entry-no-network-facts " ..
             "PKM *ntfe-ingest.status-contexts-counts-interfaces PKM *ntfe-ingest.changed-context-table-advances-generation" },
    function(t)
        record({ v("Trust", "sz", "pt-lab") })
        netd_shows(t, function(i) return i.network_trust == "pt-lab" end, "Trust pt-lab again")
        in_force(t, "Trust pt-lab")
        local ll = link_local(t)
        t:log("eth0 link-local: " .. ll)
        -- The transport the unidentified case will use, identified.
        expect(t, { open_id = "pass", open_none = "drop", open_trust = "pass" }, ll, gw.ifindex,
            "identified, over link-local")

        local g0 = engine().generation
        gw:dhcp({ pool = DHCP.pool, lease = DHCP.lease, silent = true })
        local nic = lan:nic(sut)
        nic:disconnect()
        netd_shows(t, function(i) return i.carrier == false and i.network == nil end, "carrier lost, network forgotten")
        t:assert(pcall(wait_until, function() return status_value("Network") == nil end,
            { timeout = 10, interval = 0.25, desc = "Status Network removed" }), "netd removed Status Network")
        t:assert_eq(status_value("LastNetwork"), NETID, "LastNetwork still names it")
        local e = in_force(t, "cable out")
        t:assert_eq(e.contexts, 0, "no interface carries a context")
        t:assert(e.generation > g0, "the emptied table is a new generation")

        -- Carrier back, the gateway silent: up, no lease, no network.
        nic:reconnect()
        netd_shows(t, function(x) return x.carrier == true end, "carrier back")
        gw:serve({ timeout = 2 })
        local i = iface()
        t:assert_eq(i.lease, nil, "no lease: the gateway is silent")
        t:assert_eq(i.network, nil, "no network identified")
        t:assert_eq(status_value("Network"), nil, "no Status Network")
        e = in_force(t, "carrier back, unidentified")
        t:assert_eq(e.contexts, 0, "still no context")
        ll = link_local(t)
        expect(t, { open_id = "drop", open_none = "pass", open_trust = "drop" }, ll, gw.ifindex,
            "unidentified, over link-local")
        t:log("gateway DHCP seen while silent: " .. #gw:dhcp_messages() .. " message(s)")

        -- The gateway answers: identified again, and the rules apply again.
        gw:dhcp(DHCP)
        t:assert(network.serve_until(gw, sut, function(x) return network.bound(x) and x.network == NETID end,
            { iface = "eth0", timeout = 60 }), "bound and identified again")
        t:assert(pcall(wait_until, function() return status_value("Network") == NETID end,
            { timeout = 10, interval = 0.25, desc = "Status Network" }), "Status Network is back")
        e = in_force(t, "identified again")
        t:assert_eq(e.contexts, 1, "eth0 carries its context again")
        expect(t, { trust = "reject", id = "reject", none = "pass", open_id = "pass" }, ADDR, nil,
            "identified again, IPv4")
        expect(t, { open_id = "pass", open_none = "drop", open_trust = "pass" }, link_local(t), gw.ifindex,
            "identified again, link-local")
    end)

test("an inbound REJECT on eth0 answers an IPv6 peer with a reset, at a link-local address as at a global one",
    { spec = { "PKM *ntfe-seat.inbound-refusal-routed-to-peer",
               "PKM *ntfe-seat.inbound-link-local-answer-routed-on-ingress" } },
    function(t)
        -- Before kernel alpha9 an inbound TCP SYN to eth0's link-local
        -- address that a Flow rule REJECTs was judged REJECT but no reset
        -- was sent: ip6_route_me_harder() looked the answer's route up on
        -- the loopback device, found none, and the refusal degraded to
        -- DROP (reject_degraded +1 per SYN; PEI-1383).
        local spec = { lifetime = 0, prefixes = { { prefix = "fd77::", len = 64 } } }
        gw:router(spec)
        gw:send_ra(spec)
        local s = network.serve_until(gw, sut, function(i) return #network.ipv6(i) > 0 end,
            { iface = "eth0", timeout = 30 })
        t:assert(s, "eth0 has a global IPv6 address from the prefix")
        local global = network.ipv6(network.iface(s, "eth0"))[1]:match("^([^/]+)")
        local ll = link_local(t)
        t:log("eth0: global " .. global .. ", link-local " .. ll)
        t:assert(pcall(wait_until, function()
            local a = rtnl.address(sut, assert(ntfe.if_index(sut, "eth0")), global)
            return a ~= nil and not a.tentative
        end, { timeout = 15, interval = 0.25, desc = "the global address usable" }), "the global address is usable")
        expect(t, { open_id = "pass", id = "reject" }, global, nil, "IPv6, global")
        local before = engine()
        local got = probe(ll, PORT.id, gw.ifindex)
        local after = engine()
        t:log(string.format("link-local %d: %s; verdict_reject +%d, reject_degraded +%d, refusals_emitted +%d",
            PORT.id, got, after.verdict_reject - before.verdict_reject,
            after.reject_degraded - before.reject_degraded, after.refusals_emitted - before.refusals_emitted))
        t:assert_eq(got, "reject", "IPv6, link-local: the peer is refused, not left to time out")
    end)
