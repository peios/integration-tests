-- PKM §6.3 — the network context: the `Network.Id`, `Network.Name` and
-- `Network.Trust` facts, read not from the packet but from the kernel's
-- table of netd's inventory — which interface stands on which network
-- record — with the id present whenever there is an entry, the name and
-- trust only when the record has them, nothing at all without an entry,
-- and every string bounded. And, since the strings are the snapshot's
-- last fields, the proof that the Rust mirror of the struct is in step
-- with the C one.
--
-- There is no netd here: the inventory is seeded into the registry
-- source directly (`E:replace_inventory`), as netd would write it.
--
-- Own VM: the policy and the context table are machine-wide state.

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")
local H = require("helpers.ntfe_snapshot")

local vm = provium:vm("vntfesnctx", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))
local peer, net = ntfe.peer(vm)
local E = ntfe.engine(vm, H.policy())
local wire = assert(ntfe.packet_socket(peer, net.peer))

local S, L = ntfe.SEAT, ntfe.LAYER
local HOME = "6f1c2a3e-9b7d-4c1a-8e2f-0a1b2c3d4e5f"

local function publish(t, probes)
    local s = E:replace(H.policy(probes))
    t:assert_eq(s.last_ingest_error, 0, "the probe policy is accepted")
end

local function inventory(networks, interfaces)
    return E:replace_inventory(networks, interfaces)
end

-- A datagram from the peer to `port`; the events at ingress (RawPacket)
-- and LOCAL_IN (Packet).
local function inbound(port)
    local _, events = H.inject(E, peer, wire, H.udp_frame(net, 5000, port), {
        { S.INGRESS, L.RAWPACKET, { dst_port = port } }, { S.LOCAL_IN, L.PACKET, { dst_port = port } } })
    return H.attribution(events, S.INGRESS, L.RAWPACKET, { dst_port = port }),
        H.attribution(events, S.LOCAL_IN, L.PACKET, { dst_port = port }), H.describe(events)
end

local CONTEXT_PROBES = {
    full = { ["Network.Id.Present"] = 1, ["Network.Name.Present"] = 1, ["Network.Trust.Present"] = 1, Priority = 30 },
    idonly = { ["Network.Id.Present"] = 1, ["Network.Name.Present"] = 0, ["Network.Trust.Present"] = 0, Priority = 20 },
    nonet = { ["Network.Id.Present"] = 0, Priority = 10 },
}

test("the context is filled from the active table: the record the interface stands on",
    { spec = "PKM *ntfe-snapshot.context-filled-from-active-table" }, function(t)
        local s = inventory({ [HOME] = { Name = "palfrey-home", Trust = "home" } },
            { ["if-veth0"] = { Name = "veth0", Network = HOME } })
        t:assert_eq(s.contexts, 1, "one interface stands on an identified network")
        local home = { ["Network.Id.Equal"] = HOME, ["Network.Name.Equal"] = "palfrey-home",
                       ["Network.Trust.Equal"] = "home" }
        publish(t, { RawPacket = { home = home }, Packet = { home = home } })
        local raw, pkt, d = inbound(7701)
        t:assert_eq(raw, "home", "the ingress seat on veth0 reads its network: " .. d)
        t:assert_eq(pkt, "home", "and so does LOCAL_IN")

        -- The table is the kernel's reading of the inventory, so a new
        -- record is a new answer.
        inventory({ [HOME] = { Name = "palfrey-home", Trust = "public" } },
            { ["if-veth0"] = { Name = "veth0", Network = HOME } })
        local raw2, _, d2 = inbound(7702)
        t:assert_eq(raw2, "all", "once the table says otherwise, the old trust no longer holds: " .. d2)
    end)

test("the network id is given whenever the interface has an entry, record or no record",
    { spec = "PKM *ntfe-snapshot.network-id-lifted-when-bit-set" }, function(t)
        -- The interface names a network no record describes.
        local s = inventory({}, { ["if-veth0"] = { Name = "veth0", Network = HOME } })
        t:assert_eq(s.contexts, 1, "the interface still has an entry")
        local probes = { byid = { ["Network.Id.Equal"] = HOME, Priority = 40 } }
        for k, v in pairs(CONTEXT_PROBES) do probes[k] = v end
        publish(t, { RawPacket = probes, Packet = probes })
        local raw, pkt, d = inbound(7703)
        t:assert_eq(raw, "byid", "its id is a fact at ingress: " .. d)
        t:assert_eq(pkt, "byid", "and at LOCAL_IN")
    end)

test("a record the operator has not labelled gives the id and no name or trust",
    { spec = "PKM *ntfe-snapshot.empty-network-name-and-trust-absent" }, function(t)
        local s = inventory({ [HOME] = { Name = "" } },
            { ["if-veth0"] = { Name = "veth0", Network = HOME } })
        t:assert_eq(s.contexts, 1, "the interface has an entry")
        publish(t, {
            RawPacket = CONTEXT_PROBES,
            Packet = {
                emptyname = { ["Network.Name.Equal"] = "", Priority = 40 },
                emptytrust = { ["Network.Trust.Equal"] = "", Priority = 35 },
                full = CONTEXT_PROBES.full, idonly = CONTEXT_PROBES.idonly, nonet = CONTEXT_PROBES.nonet,
            },
        })
        local raw, pkt, d = inbound(7704)
        t:assert_eq(raw, "idonly", "an empty Name and a missing Trust are absent, the id present: " .. d)
        t:assert_eq(pkt, "idonly", "absent, not empty strings a condition could match")
    end)

test("an interface no network is identified on carries no context, and every condition over it is false",
    { spec = "PKM *ntfe-snapshot.no-context-entry-no-network-facts" }, function(t)
        -- veth0's Status names no network; lo has no Status at all.
        local s = inventory({ [HOME] = { Name = "palfrey-home", Trust = "home" } },
            { ["if-veth0"] = { Name = "veth0" } })
        t:assert_eq(s.contexts, 0, "no interface has an entry")
        local probes = {
            name = { ["Network.Name.Equal"] = "palfrey-home", Priority = 40 },
            trust = { ["Network.Trust.Equal"] = "home", Priority = 35 },
            emptyid = { ["Network.Id.Equal"] = "", Priority = 32 },
            full = CONTEXT_PROBES.full, idonly = CONTEXT_PROBES.idonly, nonet = CONTEXT_PROBES.nonet,
        }
        publish(t, { RawPacket = probes, Packet = probes })
        local raw, pkt, d = inbound(7705)
        t:assert_eq(raw, "nonet", "veth0 has no network facts at ingress: " .. d)
        t:assert_eq(pkt, "nonet", "nor at LOCAL_IN")

        local rx = assert(ntfe.udp_bind(vm, "127.0.0.1", 7706))
        local _, events = H.watch(E, function()
            local u = assert(ntfe.udp_connect(vm, "127.0.0.1", 7706))
            ntfe.send(vm, u, "x")
            sys.close(vm, u)
        end, { { S.LOCAL_IN, L.PACKET, { dst_port = 7706 } } })
        sys.close(vm, rx)
        t:assert_eq(H.attribution(events, S.LOCAL_IN, L.PACKET, { dst_port = 7706 }), "nonet",
            "and neither does the loopback, which the inventory never named")
    end)

test("the network strings are bounded at 40, 64 and 32 bytes",
    { spec = "PKM *ntfe-snapshot.network-strings-bounded PKM *ntfe-snapshot.long-network-value-truncated-and-logged-once" },
    function(t)
        local name = string.rep("n", 60) .. "TAIL-OF-NAME"     -- 72 bytes
        local trust = string.rep("t", 28) .. "TAIL-OF-TRUST"   -- 41 bytes
        inventory({ [HOME] = { Name = name, Trust = trust } },
            { ["if-veth0"] = { Name = "veth0", Network = HOME } })
        publish(t, {
            RawPacket = {
                whole = { ["Network.Name.Equal"] = name, Priority = 30 },
                wholetrust = { ["Network.Trust.Equal"] = trust, Priority = 25 },
                cut = { ["Network.Name.Equal"] = name:sub(1, 63), ["Network.Trust.Equal"] = trust:sub(1, 31) },
            },
        })
        local raw, _, d = inbound(7707)
        t:assert_eq(raw, "cut",
            "a longer Name keeps its first 63 bytes and a longer Trust its first 31: " .. d)

        -- Exactly at the bound, nothing is lost.
        local name63, trust31 = string.rep("m", 63), string.rep("u", 31)
        inventory({ [HOME] = { Name = name63, Trust = trust31 } },
            { ["if-veth0"] = { Name = "veth0", Network = HOME } })
        publish(t, { RawPacket = { exact = { ["Network.Name.Equal"] = name63, ["Network.Trust.Equal"] = trust31 } } })
        local raw2, _, d2 = inbound(7708)
        t:assert_eq(raw2, "exact", "a 63-byte Name and a 31-byte Trust are whole: " .. d2)
    end)

test("an interface's network id longer than the bound is truncated at ingestion",
    { spec = "PKM *ntfe-snapshot.long-network-value-truncated-and-logged-once" }, function(t)
        -- The kernel's log is not visible from the guest's agent; what is
        -- visible is the truncation itself.
        local long = HOME .. "-extended"    -- 45 bytes
        inventory({}, { ["if-veth0"] = { Name = "veth0", Network = long } })
        publish(t, {
            RawPacket = {
                whole = { ["Network.Id.Equal"] = long, Priority = 20 },
                cut = { ["Network.Id.Equal"] = long:sub(1, 39) },
            },
        })
        local raw, _, d = inbound(7709)
        t:assert_eq(raw, "cut", "the id keeps its first 39 bytes: " .. d)
    end)

test("a network record whose key name is 40 bytes or more is ignored, record and all",
    { spec = "PKM *ntfe-snapshot.overlong-network-id-name-ignored" }, function(t)
        -- veth0 names the record by the same key name each time. Its
        -- Network is truncated to 39 bytes on the way in; a record kept
        -- under a truncated id would join it and lend its Name and Trust.
        local fits, long = string.rep("f", 39), string.rep("L", 40)
        local probes = { long = { ["Network.Name.Equal"] = "long-record", Priority = 40 } }
        for k, v in pairs(CONTEXT_PROBES) do probes[k] = v end
        publish(t, { RawPacket = probes })

        inventory({ [fits] = { Name = "fitting-record", Trust = "home" } },
            { ["if-veth0"] = { Name = "veth0", Network = fits } })
        local raw, _, d = inbound(7712)
        t:assert_eq(raw, "full", "a 39-byte name is a record, joined with its Name and Trust: " .. d)

        local s = inventory({ [long] = { Name = "long-record", Trust = "home" } },
            { ["if-veth0"] = { Name = "veth0", Network = long } })
        t:assert_eq(s.last_ingest_error, 0, "a 40-byte one fails nothing")
        t:assert_eq(s.contexts, 1, "and veth0 still stands on a network")
        local raw2, _, d2 = inbound(7713)
        t:assert_eq(raw2, "idonly", "but the record is not there to join: an id, no Name, no Trust: " .. d2)
    end)

test("the packet layers read the network record's fields, the same ones the interface layer reads",
    { spec = "PKM *ntfe-snapshot.network-facts-match-interface-layer" }, function(t)
        -- The interface layer is netd's, judged in userspace, and there is
        -- no netd here; its reading of these three fields off the same
        -- record is pnp-core's (laws_network_context.rs). The kernel's
        -- half: one `Network.Trust.Equal` reads the record at every packet
        -- layer.
        inventory({ [HOME] = { Name = "palfrey-home", Trust = "home" } },
            { ["if-veth0"] = { Name = "veth0", Network = HOME } })
        local trusted = { ["Network.Trust.Equal"] = "home" }
        publish(t, { RawPacket = { trusted = trusted }, Packet = { trusted = trusted }, Flow = { trusted = trusted } })
        local rx = assert(ntfe.udp_bind(vm, net.addr, 7710))
        local _, events = H.watch(E, function()
            local u = assert(ntfe.udp_connect(peer, net.addr, 7710))
            ntfe.send(peer, u, "x")
            sys.close(peer, u)
        end, {
            { S.INGRESS, L.RAWPACKET, { dst_port = 7710 } }, { S.LOCAL_IN, L.PACKET, { dst_port = 7710 } },
            { S.LOCAL_IN, L.FLOW, { dst_port = 7710 } },
        })
        sys.close(vm, rx)
        for _, c in ipairs({ { S.INGRESS, L.RAWPACKET, "RawPacket" }, { S.LOCAL_IN, L.PACKET, "Packet" },
                             { S.LOCAL_IN, L.FLOW, "Flow" } }) do
            t:assert_eq(H.attribution(events, c[1], c[2], { dst_port = 7710 }), "trusted",
                c[3] .. " reads the record's Trust")
        end
    end)

test("the Rust mirror of the snapshot matches the C struct field for field",
    { spec = "PKM *ntfe-snapshot.rust-mirror-matches-c-struct" }, function(t)
        -- One rule over facts from the head of the struct to its tail —
        -- past the clock, the start time, the flow pointer and the two
        -- token pointers — matches only if every field lands where the
        -- core reads it.
        inventory({ [HOME] = { Name = "palfrey-home", Trust = "home" } },
            { ["if-veth0"] = { Name = "veth0", Network = HOME } })
        -- (EtherType is per packet: the Flow forest never has it.)
        local every = {
            ["Direction.Equal"] = "in", ["Interface.Equal"] = "veth0",
            ["SrcMac.Equal"] = H.mac_text(net.peer_mac), ["SrcAddr.Equal"] = net.peer_addr,
            ["DstAddr.Equal"] = net.addr, ["Protocol.Equal"] = "udp",
            ["SrcPort.Equal"] = 5000, ["DstPort.Equal"] = 7711,
            ["Time.Year.GreaterThan"] = 2000, ["Network.Id.Equal"] = HOME,
            ["Network.Name.Equal"] = "palfrey-home", ["Network.Trust.Equal"] = "home",
        }
        local packet = { ["EtherType.Equal"] = "ipv4",
                         ["DstMac.Equal"] = H.mac_text(net.mac), ["Length.Equal"] = 28,
                         ["Ttl.Equal"] = 64, ["Dscp.Equal"] = 0, ["Fragment.Equal"] = 0,
                         ["TcpFlags.Present"] = 0, ["FlowState.Equal"] = "new" }
        for k, v in pairs(every) do packet[k] = v end
        local flow = { ["Local.Equal"] = "program", ["Related.Equal"] = 0, ["Start.Year.GreaterThan"] = 2000 }
        for k, v in pairs(every) do flow[k] = v end
        publish(t, { Packet = { every = packet }, Flow = { every = flow } })
        local rx = assert(ntfe.udp_bind(vm, net.addr, 7711))
        local _, events = H.inject(E, peer, wire, H.udp_frame(net, 5000, 7711), {
            { S.LOCAL_IN, L.PACKET, { dst_port = 7711 } }, { S.LOCAL_IN, L.FLOW, { dst_port = 7711 } } })
        sys.close(vm, rx)
        t:assert_eq(H.attribution(events, S.LOCAL_IN, L.PACKET, { dst_port = 7711 }), "every",
            "the Packet forest reads every per-packet field as the C side wrote it: " .. H.describe(events))
        t:assert_eq(H.attribution(events, S.LOCAL_IN, L.FLOW, { dst_port = 7711 }), "every",
            "and the Flow forest every flow field, the identity and the network context included")
    end)
