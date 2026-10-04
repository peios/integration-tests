-- Shared shapes for the §6.4 (evaluation) tests: a policy with the rules
-- under test in one layer and pass-everything everywhere else, one
-- loopback datagram as the probe, and the network-report payload, whose
-- map16 header helpers/kmes does not decode.
--
-- A loopback datagram is judged six times (Flow at LOCAL_OUT, Packet then
-- RawPacket at EGRESS, RawPacket at INGRESS, Packet then Flow at
-- LOCAL_IN). The tests read the one evaluation they are about from its
-- own event; status deltas count every evaluation of the datagram.

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")
local kmes = require("helpers.kmes")

local M = {}

M.PASS_ALL = { all = { Actions = { "PASS" } } }

--- A whole policy: `layer` ("Packet", "Flow" or "RawPacket") holds
--- `rules`; every other layer passes everything. `values` are values of
--- the Rules key (`CurrentReportingLevel`).
function M.policy(layer, rules, values)
    local p = { RawPacket = M.PASS_ALL, Packet = M.PASS_ALL, Flow = M.PASS_ALL }
    p[layer] = rules
    p.values = values
    return p
end

--- Publish `policy` and insist it was accepted.
function M.publish(t, E, policy)
    local s = E:replace(policy)
    t:assert_eq(s.last_ingest_error, 0, "the policy is accepted")
    return s
end

--- Send `n` (default 1) datagrams from 127.0.0.1 to 127.0.0.1:`port`
--- on one connected socket — one flow — and see what happened.
---
--- Returns a table: `delta` and `events` (from `E:during`), `arrived`
--- (how many datagrams reached the receiver), and `at(seat, layer)`, the
--- events of that evaluation for this port, oldest first.
function M.probe(E, port, n)
    local vm = E.vm
    local rx = assert(ntfe.udp_bind(vm, "127.0.0.1", port))
    local tx = assert(ntfe.udp_connect(vm, "127.0.0.1", port))
    local arrived = 0
    local delta, events = E:during(function()
        for i = 1, n or 1 do
            ntfe.send(vm, tx, "probe " .. i)
            if ntfe.recv(vm, rx, 300) then arrived = arrived + 1 end
        end
    end)
    sys.close(vm, tx)
    sys.close(vm, rx)
    local r = { delta = delta, events = events, arrived = arrived }
    function r.at(seat, layer)
        return ntfe.matching(events, { seat = seat, layer = layer, dst_port = port })
    end
    --- The Packet layer's evaluation at EGRESS: the first one the
    --- datagram meets, so present whatever the verdict.
    function r.packet()
        return r.at(ntfe.SEAT.EGRESS, ntfe.LAYER.PACKET)[1]
    end
    --- The Flow layer's outbound evaluation (sentence slot 0).
    function r.flow()
        return r.at(ntfe.SEAT.LOCAL_OUT, ntfe.LAYER.FLOW)[1]
    end
    return r
end

--- The flows-dump record of the (single) flow to `port`, or nil.
function M.flow_to(E, port)
    for _, f in ipairs(assert(E:flows())) do
        if f.dst_port == port then return f end
    end
    return nil
end

--- The counters-dump cells of stream `name`.
function M.cells(E, name)
    local out = {}
    for _, c in ipairs(assert(E:counters())) do
        if c.name == name then out[#out + 1] = c end
    end
    return out
end

-- ---- the network-report payload ----

local function unpack_value(b, at)
    local tag = b:byte(at)
    if not tag then error("msgpack: ran off the end") end
    if tag < 0x80 then return tag, at + 1 end
    local function map(n, from)
        local out = {}
        for _ = 1, n do
            local k, v
            k, from = unpack_value(b, from)
            v, from = unpack_value(b, from)
            out[k] = v
        end
        return out, from
    end
    if tag >= 0x80 and tag <= 0x8f then return map(tag - 0x80, at + 1) end
    if tag == 0xde then return map(string.unpack(">I2", b, at + 1), at + 3) end
    if tag >= 0xa0 and tag <= 0xbf then
        local n = tag - 0xa0
        return b:sub(at + 1, at + n), at + 1 + n
    end
    if tag == 0xd9 then
        local n = b:byte(at + 1)
        return b:sub(at + 2, at + 1 + n), at + 2 + n
    end
    if tag == 0xda then
        local n = string.unpack(">I2", b, at + 1)
        return b:sub(at + 3, at + 2 + n), at + 3 + n
    end
    if tag == 0xcc then return string.unpack(">I1", b, at + 1), at + 2 end
    if tag == 0xcd then return string.unpack(">I2", b, at + 1), at + 3 end
    if tag == 0xce then return string.unpack(">I4", b, at + 1), at + 5 end
    if tag == 0xcf then return string.unpack(">I8", b, at + 1), at + 9 end
    if tag == 0xc0 then return nil, at + 1 end
    error(string.format("msgpack: unhandled tag 0x%02x at %d", tag, at))
end

--- Run `fn` with the KMES ring attached and return the network-report
--- events it produced, each with `payload` decoded (map16 included).
function M.reports(t, vm, fn)
    local out = {}
    for _, e in ipairs(kmes.of_type(kmes.recording(t, vm, fn), "network-report")) do
        e.payload = (unpack_value(e.raw:sub(e.header_size + 1), 1))
        out[#out + 1] = e
    end
    return out
end

-- ---- the clock ----

-- Monday 2026-09-21 00:00:00 UTC: ISO day of week 1.
M.MONDAY = 1789948800
M.HOUR, M.DAY = 3600, 86400

--- Set the guest's wall clock to `M.MONDAY + offset` seconds.
function M.clock_at(vm, offset)
    vm:clock():set(M.MONDAY + offset)
end

return M
