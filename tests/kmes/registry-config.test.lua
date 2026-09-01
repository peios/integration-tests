-- PKM §2.6 — self-configuration, driven live against a Lua-served
-- Machine hive (helpers/registry): the empty-key bootstrap, the
-- nine-key invalid reports, rejection-not-clamping, name folding, the
-- watch's scope, and the fallback watch on a hive that grows its KMES
-- key later.
--
-- Own VMs: configuration is global state.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local kmes = require("helpers.kmes")
local registry = require("helpers.registry")

local vm = provium:vm("vcfg", "kernel-only"):boot()

-- The main source: ring attached BEFORE registration so the bootstrap's
-- own events are captured; KMES key present but empty.
local boot_ring = assert(kmes.attach(vm, 0))
local src = assert(registry.kmes_source(vm, {}))
local boot_events = kmes.drain(boot_ring)
kmes.detach(boot_ring)

local wkey = vm:spawn_worker()
local KMES_FD
do
    local o = src:pump_during(function()
        return registry.open_key_async(wkey, "Machine\\System\\KMES")
    end)
    assert(o.ret >= 0, "open KMES key: " .. sys.errname(o.errno))
    KMES_FD = o.ret
end

local function set_value(name, vtype, data)
    local r = src:pump_during(function()
        return registry.set_value_async(wkey, KMES_FD, name, vtype, data)
    end)
    return r
end

test("a present-but-empty key reports all four and retains defaults",
    { spec = "PKM *config.empty-key-emits-four" }, function(t)
        local invalid = kmes.of_type(boot_events, "KMES_SELF_CONFIG_INVALID")
        t:assert_eq(#invalid, 4, "exactly four reports, one per key")
        local names = {}
        for _, e in ipairs(invalid) do
            names[e.payload.configuration_name] = e.payload
        end
        for _, want in ipairs({ "BufferCapacity", "MaxEventSize",
                                "MaxNestingDepth", "MaxEmitRatePerProcess" }) do
            t:assert(names[want], want .. " is reported")
            t:assert_eq(names[want].received_kind, "missing", "as missing")
        end
        t:assert_eq(names.BufferCapacity.retained_value,
            kmes.DEFAULT.BUFFER_CAPACITY, "with the default retained")
        local ring = kmes.attach(vm, 0)
        t:assert_eq(ring.capacity, kmes.DEFAULT.BUFFER_CAPACITY,
            "which is also what runs")
        kmes.detach(ring)
    end)

test("an invalid-value report is a map of exactly nine keys",
    { spec = "PKM *config.invalid-event-nine-keys" }, function(t)
        local e = kmes.of_type(boot_events, "KMES_SELF_CONFIG_INVALID")[1]
        t:assert(e and e.payload, "a report with a decodable payload")
        local keys = {}
        for k in pairs(e.payload) do keys[#keys + 1] = k end
        -- msgpack nil values (received_type, received_value on a
        -- missing report) decode to Lua nil and vanish from the
        -- table; the seven non-nil keys plus those two are the nine.
        t:assert_eq(#keys, 7, "seven non-nil keys on a missing report")
        for _, want in ipairs({ "configuration_parent_path",
                "configuration_name", "expected_type", "expected_min",
                "expected_max", "received_kind", "retained_value" }) do
            t:assert(e.payload[want] ~= nil, want .. " present")
        end
        t:assert_eq(e.payload.configuration_parent_path,
            "Machine\\System\\KMES", "the parent path is the constant")
    end)

test("self-configuration reports carry origin class 1",
    { spec = "PKM *config.self-events-origin-kmes" }, function(t)
        for _, e in ipairs(kmes.of_type(boot_events,
                "KMES_SELF_CONFIG_INVALID")) do
            t:assert_eq(e.origin, kmes.ORIGIN.KMES,
                "KMES reporting on itself is origin 1")
        end
    end)

test("the full bootstrap sequence, observed end to end",
    { spec = "PKM *config.bootstrap-sequence" }, function(t)
        -- Steps 1-4 and 6 of §2.6: defaults from load (the boot ring
        -- ran at 4 MiB before any source existed); source registration
        -- made LCS usable and the enumerate-and-apply pass ran (the
        -- four reports above are its trace); the targeted watch armed
        -- — proven by a subsequent change taking effect without any
        -- re-registration.
        local r = set_value("MaxNestingDepth", registry.TYPE.DWORD,
            registry.dword(8))
        t:assert_eq(r.ret, 0, "an administrator edit lands in the registry")
        t:assert_eq(kmes.emit(vm, "PIT_BOOTSTRAP", kmes.nested(8)).ret, 0,
            "depth 8 is now the live limit")
        t:assert_eq(kmes.emit(vm, "PIT_BOOTSTRAP", kmes.nested(9)).errno,
            sys.E.INVAL, "and depth 9 is refused — the watch re-read it")
    end)

-- From here on every canonical value is kept valid, so each test's
-- re-read reports exactly its own subject: a re-read reports EVERY
-- missing or invalid value, not just the one that changed.
test("seed the remaining values", {}, function(t)
    t:assert_eq(set_value("MaxEventSize", registry.TYPE.DWORD,
        registry.dword(65536)).ret, 0, "MaxEventSize")
    t:assert_eq(set_value("MaxEmitRatePerProcess", registry.TYPE.DWORD,
        registry.dword(10000)).ret, 0, "MaxEmitRatePerProcess")
end)

test("a value change applies to the very next syscall",
    { spec = "PKM *config.capacity-change-swaps" }, function(t)
        -- The §2.6 sentence: a valid BufferCapacity different from the
        -- current one triggers the §2.5 swap.
        local before = kmes.attach(vm, 0)
        t:assert_eq(before.capacity, kmes.DEFAULT.BUFFER_CAPACITY,
            "the default capacity before")
        kmes.detach(before)
        t:assert_eq(set_value("BufferCapacity", registry.TYPE.QWORD,
            registry.qword(131072)).ret, 0, "the value is written")
        local after = kmes.attach(vm, 0)
        t:assert_eq(after.capacity, 131072, "and the rings swapped to it")
        kmes.detach(after)
    end)

test("an invalid value is rejected outright, never clamped",
    { spec = "PKM *config.invalid-rejected-not-clamped" }, function(t)
        -- 100000 is in range but not a power of two: the registry
        -- write itself succeeds and the registry keeps showing it,
        -- while KMES reports the rejection and keeps running on the
        -- previously active value.
        local ring = kmes.attach(vm, 0)
        local r = set_value("BufferCapacity", registry.TYPE.QWORD,
            registry.qword(100000))
        t:assert_eq(r.ret, 0, "the registry write succeeds")
        local stored = src.keys[src.kmes_key].values["buffercapacity"]
        t:assert_eq(string.unpack("<I8", stored.data), 100000,
            "and the registry shows what was written")
        local after = kmes.attach(vm, 0)
        t:assert_eq(after.capacity, 131072,
            "while KMES retains the last accepted capacity — not a " ..
            "clamp to a nearby power of two")
        local invalid = kmes.of_type(kmes.drain(ring),
            "KMES_SELF_CONFIG_INVALID")
        t:assert_eq(#invalid, 1, "and one report says why")
        t:assert_eq(invalid[1].payload.configuration_name, "BufferCapacity",
            "naming the value")
        t:assert_eq(invalid[1].payload.received_value, 100000,
            "carrying what was received")
        t:assert_eq(invalid[1].payload.retained_value, 131072,
            "and what stays in force")
        kmes.detach(ring); kmes.detach(after)
        -- Put a valid value back: an invalid one left in the registry
        -- is re-reported on every subsequent re-read.
        t:assert_eq(set_value("BufferCapacity", registry.TYPE.QWORD,
            registry.qword(131072)).ret, 0, "restored")
    end)

test("a right-typed value of the wrong length is a wrong-type value",
    { spec = "PKM *config.wrong-length-is-wrong-type" }, function(t)
        -- REG_QWORD with four payload bytes: not a malformed number,
        -- a wrong-type value — and reported as such, distinct from
        -- out-of-range. A wrong type tag entirely reports the same
        -- kind with the received type code.
        local ring = kmes.attach(vm, 0)
        t:assert_eq(set_value("MaxEventSize", registry.TYPE.DWORD,
            registry.qword(65536)).ret, 0,
            "a DWORD carrying eight bytes is written")
        local reports = kmes.of_type(kmes.drain(ring),
            "KMES_SELF_CONFIG_INVALID")
        t:assert_eq(#reports, 1, "one report")
        t:assert_eq(reports[1].payload.received_kind, "wrong_type",
            "classified wrong-type, not out-of-range")

        ring.cursor = nil; ring = kmes.attach(vm, 0)
        t:assert_eq(set_value("MaxEventSize", registry.TYPE.QWORD,
            registry.qword(65536)).ret, 0, "a QWORD where DWORD is expected")
        reports = kmes.of_type(kmes.drain(ring), "KMES_SELF_CONFIG_INVALID")
        t:assert_eq(#reports, 1, "one report")
        t:assert_eq(reports[1].payload.received_kind, "wrong_type",
            "same kind")
        t:assert_eq(reports[1].payload.received_type, registry.TYPE.QWORD,
            "with the actual type code")
        -- Restore a valid value.
        t:assert_eq(set_value("MaxEventSize", registry.TYPE.DWORD,
            registry.dword(65536)).ret, 0, "restored")
        kmes.detach(ring)
    end)

test("names fold; unknown names are ignored",
    { spec = "PKM *config.names-case-folded-unknown-ignored" }, function(t)
        -- "maxnestingdepth" folds to the canonical name and applies;
        -- "NotAKmesKey" folds to nothing and changes nothing — no
        -- report, no rejection, no effect.
        t:assert_eq(set_value("maxnestingdepth", registry.TYPE.DWORD,
            registry.dword(12)).ret, 0, "a lowercase name is written")
        t:assert_eq(kmes.emit(vm, "PIT_FOLD", kmes.nested(12)).ret, 0,
            "and applied — depth 12 passes")
        t:assert_eq(kmes.emit(vm, "PIT_FOLD", kmes.nested(13)).errno,
            sys.E.INVAL, "depth 13 does not")

        local ring = kmes.attach(vm, 0)
        t:assert_eq(set_value("NotAKmesKey", registry.TYPE.DWORD,
            registry.dword(7)).ret, 0, "an unknown name is written")
        t:assert_eq(#kmes.of_type(kmes.drain(ring),
            "KMES_SELF_CONFIG_INVALID"), 0,
            "and ignored without a report")
        kmes.detach(ring)
        t:assert_eq(kmes.emit(vm, "PIT_FOLD", kmes.nested(12)).ret, 0,
            "with the real configuration untouched")
    end)

test("the watch does not fire for keys below the KMES key",
    { spec = "PKM *config.watch-filtered-to-key" }, function(t)
        -- A subkey carrying a "BufferCapacity" of its own: writing it
        -- causes no re-read (no QueryValues reaches the source) and
        -- no configuration change.
        local o = src:pump_during(function()
            return registry.create_key_async(wkey,
                "Machine\\System\\KMES\\Sub")
        end)
        t:assert(o.ret >= 0, "a subkey is created: " .. sys.errname(o.errno))
        local mark = #src.log + 1
        local r = src:pump_during(function()
            return registry.set_value_async(wkey, o.ret, "BufferCapacity",
                registry.TYPE.QWORD, registry.qword(65536))
        end)
        t:assert_eq(r.ret, 0, "and a value lands on it")
        t:assert(not src:served(registry.OP.QUERY_VALUES, mark,
                src.kmes_key),
            "without triggering a configuration re-read of the KMES key")
        local ring = kmes.attach(vm, 0)
        t:assert_eq(ring.capacity, 131072,
            "and without touching the live capacity")
        kmes.detach(ring)
        sys.close(wkey, o.ret)
    end)

test("a rate change reconfigures every live bucket at once",
    { spec = "PKM *emit.rate.reconfigure-applies-immediately" }, function(t)
        -- A worker forked under the 10000 default holds a full
        -- bucket. The rate drops to 100: its bucket is clamped, so
        -- its very first 256-entry batch — which the old bucket would
        -- absorb 39 times over — fails EAGAIN.
        kacs.as_dacl_bound(t, vm, function(worker)
            local entries = {}
            for i = 1, kmes.BATCH_MAX_ENTRIES do
                entries[i] = { type = "PIT_CLAMP", payload = kmes.PAYLOAD }
            end
            t:assert_eq(kmes.emit_batch(worker, entries).ret, 0,
                "under the default rate a full batch sails through")
            t:assert_eq(set_value("MaxEmitRatePerProcess",
                registry.TYPE.DWORD, registry.dword(100)).ret, 0,
                "the rate drops to 100")
            local r = kmes.emit_batch(worker, entries)
            t:assert_eq(r.errno, sys.E.AGAIN,
                "and the live bucket was clamped below one batch: " ..
                sys.errname(r.errno))
            t:assert_eq(kmes.emit(worker, "PIT_CLAMP", kmes.PAYLOAD).ret, 0,
                "while single events still fit the small bucket")
        end, { privs = kmes.PRIV.TCB })
        t:assert_eq(set_value("MaxEmitRatePerProcess", registry.TYPE.DWORD,
            registry.dword(10000)).ret, 0, "restored")
    end)

test("a hive that grows its KMES key later is found by the fallback",
    { spec = "PKM *config.fallback-watch-on-hive-root" }, function(t)
        -- A second VM: its hive registers with no System key at all,
        -- so the bootstrap finds nothing and arms the fallback watch
        -- on the hive root. Creating Machine\System\KMES and a value
        -- afterwards re-runs the bootstrap and the value takes
        -- effect.
        local vm2 = provium:vm("vcfg2", "kernel-only"):boot()
        local src2 = registry.Source.new(vm2)
        t:assert(src2:register(), "a bare Machine hive registers")
        src2:pump()
        t:assert_eq(kmes.emit(vm2, "PIT_FB", kmes.nested(32)).ret, 0,
            "defaults run: depth 32 passes")

        local w2 = vm2:spawn_worker()
        local ok, err = pcall(function()
            local s = src2:pump_during(function()
                return registry.create_key_async(w2, "Machine\\System")
            end)
            t:assert(s.ret >= 0, "System is created: " .. sys.errname(s.errno))
            sys.close(w2, s.ret)
            local c = src2:pump_during(function()
                return registry.create_key_async(w2, "Machine\\System\\KMES")
            end)
            t:assert(c.ret >= 0, "the KMES key is created: " ..
                sys.errname(c.errno))
            local r = src2:pump_during(function()
                return registry.set_value_async(w2, c.ret, "MaxNestingDepth",
                    registry.TYPE.DWORD, registry.dword(6))
            end)
            t:assert_eq(r.ret, 0, "and a value written")
            src2:pump(400)
            t:assert_eq(kmes.emit(vm2, "PIT_FB", kmes.nested(6)).ret, 0,
                "depth 6 passes")
            t:assert_eq(kmes.emit(vm2, "PIT_FB", kmes.nested(7)).errno,
                sys.E.INVAL,
                "depth 7 is refused — the fallback re-ran the bootstrap")
        end)
        w2:kill(); w2:join()
        src2:close()
        if not ok then error(err, 0) end
    end)

test("teardown", {}, function(t)
    sys.close(wkey, KMES_FD)
    wkey:kill(); wkey:join()
    src:close()
    t:assert(true, "source torn down")
end)
