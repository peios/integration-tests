-- PKM §6.B — "Bounds not in the header": the 4096-rules-per-layer half
-- of the ingestion bound, driven to the bound and one past it.
--
-- Slow on purpose: the engine reads every rule back from the registry
-- source, two round trips a rule, so a walk of 4096 rules takes about
-- twenty seconds and this file about forty-five. The depth half of the
-- bound is in abi-notes-bounds.
--
-- Own VM: the policy is machine-wide state, and this file's walks would
-- hold up any other file's tests.

local ntfe = require("helpers.ntfe")
local raw = require("helpers.ntfe_abi_notes")
local sys = require("helpers.sys")

local vm = provium:vm("vntfeabirul", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))

local PASS_ALL = { all = { Actions = { "PASS" } } }
local E = ntfe.engine(vm, { RawPacket = PASS_ALL, Packet = PASS_ALL, Flow = PASS_ALL })

--- A Flow layer of 64 roots with 63 exceptions each: 4096 rules, no
--- level wider than 64 keys. `extra` adds one more root.
local function rules(extra)
    local layer = {}
    for i = 1, 64 do
        local children = {}
        for j = 1, 63 do children["c" .. j] = { Actions = { "PASS" } } end
        layer["r" .. i] = { Actions = { "PASS" }, children = children }
    end
    if extra then layer.extra = { Actions = { "PASS" } } end
    return layer
end

test("a layer holds at most 4096 rules",
    { spec = "PKM *ntfe-abi-notes.bound-rule-depth-12-rules-4096" }, function(t)
        local before = E:status().generation
        local s = raw.replace(E, { RawPacket = PASS_ALL, Packet = PASS_ALL, Flow = rules(false) }, 90000)
        t:assert_eq(s.last_ingest_error, 0, "a layer of 4096 rules is accepted")
        t:assert_eq(s.generation, before + 1, "and published")
        s = raw.replace(E, { RawPacket = PASS_ALL, Packet = PASS_ALL, Flow = rules(true) }, 90000)
        t:assert_eq(s.last_ingest_error, sys.E.BIG2, "a 4097th refuses the generation (E2BIG)")
        t:assert_eq(s.generation, before + 1, "and the previous one stands")
    end)
