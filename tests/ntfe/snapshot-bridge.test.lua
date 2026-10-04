-- PKM §6.3 — the ingress snapshot has no flow, so no tags exist to give
-- it. The one place the Packet layer judges an IP packet of a tracked
-- flow at ingress is a bridge-enslaved port (§6.2's fallback): the same
-- datagram is judged there, flowless, and again at the bridge's LOCAL_IN
-- with its flow and its tags.
--
-- Own VM: the policy is machine-wide state, and the peer's link here is
-- a bridge port rather than an addressed interface.

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")
local H = require("helpers.ntfe_snapshot")

local vm = provium:vm("vntfesnbridge", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))
local peer, net = ntfe.peer(vm, { unaddressed = true })
assert(ntfe.link_add(vm, "br0", "bridge"))
assert(ntfe.link_set_master(vm, net.name, "br0"))
assert(ntfe.if_addr(vm, "br0", net.addr, net.prefix))
assert(ntfe.if_addr(peer, net.peer, net.peer_addr, net.prefix))
local BRIDGE_INDEX = assert(ntfe.if_index(vm, "br0"))
local E = ntfe.engine(vm, H.policy())

local S, L = ntfe.SEAT, ntfe.LAYER

test("an ingress snapshot has no flow, so no tags exist to give it",
    { spec = "PKM *ntfe-snapshot.ingress-snapshot-has-no-tags" }, function(t)
        local s = E:replace(H.policy({
            Packet = {
                writer = { ["DstPort.Equal"] = 7801, Actions = { "TAG(seen, Set)", "PASS" }, Priority = 5 },
                reader = { ["DstPort.Equal"] = 7801, ["Tag.seen.Equal"] = 1, Priority = 20 },
                stateless = { ["DstPort.Equal"] = 7801, ["FlowState.Present"] = 0, Priority = 10 },
            },
        }))
        t:assert_eq(s.last_ingest_error, 0, "the probe policy is accepted")
        local rx = assert(ntfe.udp_bind(vm, net.addr, 7801))
        local tx = assert(ntfe.udp_connect(peer, net.addr, 7801))
        local function one(data)
            local _, events = H.watch(E, function()
                ntfe.send(peer, tx, data)
                t:assert_eq(ntfe.recv(vm, rx, 1000), data, "the datagram crosses the bridge")
            end, {
                { S.INGRESS, L.PACKET, { dst_port = 7801, ifindex = net.ifindex } },
                { S.LOCAL_IN, L.PACKET, { dst_port = 7801 } },
            })
            return events
        end
        local first = one("first")
        local port1 = H.at(first, S.INGRESS, L.PACKET, { dst_port = 7801, ifindex = net.ifindex })[1]
        t:assert(port1, "the bridge port's ingress seat judged the datagram by Packet: " .. H.describe(first))
        t:assert_eq(port1.flow_state, ntfe.FLOW_STATE.ABSENT, "with no flow")
        t:assert_eq(port1.attributed, "stateless", "no flow state at all")
        local in1 = H.at(first, S.LOCAL_IN, L.PACKET, { dst_port = 7801 })[1]
        t:assert_eq(in1.ifindex, BRIDGE_INDEX, "LOCAL_IN judged it on the bridge")
        t:assert_eq(in1.attributed, "writer", "and tagged its flow there")

        local second = one("second")
        local port2, d2 = H.attribution(second, S.INGRESS, L.PACKET, { dst_port = 7801, ifindex = net.ifindex })
        t:assert_eq(port2, "stateless", "the next datagram at the port's ingress still sees no tag: " .. d2)
        local in2, d3 = H.attribution(second, S.LOCAL_IN, L.PACKET, { dst_port = 7801 })
        t:assert_eq(in2, "reader", "while at LOCAL_IN the same datagram's flow carries it: " .. d3)
        sys.close(peer, tx); sys.close(vm, rx)
    end)
