-- PKM §2.4 — kmes_emit_batch: the count bounds, the staged-prefix
-- partial-failure contract, emitted_out's two writes, and what the
-- batch shares across its events.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local kmes = require("helpers.kmes")

local vm = provium:vm("v", "kernel-only"):boot()

local function entries(n, type_name)
    local out = {}
    for i = 1, n do out[i] = { type = type_name, payload = kmes.PAYLOAD } end
    return out
end

test("a full batch emits every event and reports the count",
    { spec = "PKM *batch.partial-failure-reporting" }, function(t)
        local events = kmes.recording(t, vm, function()
            local r = kmes.emit_batch(vm, entries(5, "PIT_BATCH_OK"))
            t:assert_eq(r.ret, 0, "the batch returns 0: " .. sys.errname(r.errno))
            t:assert_eq(r.emitted, 5, "and writes count to emitted_out")
        end)
        t:assert_eq(#kmes.of_type(events, "PIT_BATCH_OK"), 5,
            "all five events are in the ring")
    end)

test("the batch shares one timestamp; each event gets its own sequence",
    { spec = "PKM *event.identity.batch-captured-once" }, function(t)
        -- §2.2: the timestamp and identity GUIDs are captured once,
        -- before the per-event loop, because the batch cannot migrate
        -- or change identity mid-write.
        local events = kmes.recording(t, vm, function()
            t:assert_eq(kmes.emit_batch(vm, entries(4, "PIT_BATCH_STAMP")).ret,
                0, "the batch is accepted")
        end)
        local mine = kmes.of_type(events, "PIT_BATCH_STAMP")
        t:assert_eq(#mine, 4, "four events")
        for i = 2, 4 do
            t:assert_eq(mine[i].timestamp, mine[1].timestamp,
                "event " .. i .. " shares the batch timestamp")
            t:assert_eq(mine[i].sequence, mine[i - 1].sequence + 1,
                "and takes the next sequence number")
            t:assert_eq(mine[i].effective_token, mine[1].effective_token,
                "and the shared identity capture")
        end
    end)

test("count is bounded to 1..256",
    { spec = "PKM *batch.count-range-einval" }, function(t)
        local r = kmes.emit_batch(vm, entries(1, "PIT_COUNT"), { count = 0 })
        t:assert_eq(r.errno, sys.E.INVAL, "zero: " .. sys.errname(r.errno))
        r = kmes.emit_batch(vm, entries(1, "PIT_COUNT"),
            { count = kmes.BATCH_MAX_ENTRIES + 1 })
        t:assert_eq(r.errno, sys.E.INVAL, "257: " .. sys.errname(r.errno))
        local full = kmes.recording(t, vm, function()
            local ok = kmes.emit_batch(vm,
                entries(kmes.BATCH_MAX_ENTRIES, "PIT_COUNT"))
            t:assert_eq(ok.ret, 0, "while 256 exactly is the largest accepted")
            t:assert_eq(ok.emitted, 256, "and all 256 emit")
        end)
        t:assert_eq(#kmes.of_type(full, "PIT_COUNT"), 256, "into the ring")
    end)

test("a failing entry stops the batch after its predecessors emitted",
    { spec = "PKM *batch.staging-stops-at-first-failure" }, function(t)
        -- Entry 3 of 5 is invalid msgpack: entries 1–2 emit, 3–5 do
        -- not, emitted_out says 2, and the errno is entry 3's.
        local batch = entries(5, "PIT_BATCH_STOP")
        batch[3].payload = "\xc1"
        local events = kmes.recording(t, vm, function()
            local r = kmes.emit_batch(vm, batch)
            t:assert_eq(r.errno, sys.E.INVAL,
                "the batch fails with the failing entry's errno: " ..
                sys.errname(r.errno))
            t:assert_eq(r.emitted, 2, "emitted_out counts the prefix")
        end)
        t:assert_eq(#kmes.of_type(events, "PIT_BATCH_STOP"), 2,
            "and exactly the prefix is in the ring")
    end)

test("failed entries consume no sequence numbers",
    { spec = "PKM *batch.no-gap-on-failure" }, function(t)
        local ring = kmes.attach(vm, 0)
        t:assert(ring, "a ring attaches")
        local bad = entries(3, "PIT_BATCH_GAP")
        bad[2].payload = "\xc1"
        t:assert_eq(kmes.emit_batch(vm, bad).errno, sys.E.INVAL,
            "a batch fails at its second entry")
        t:assert_eq(kmes.emit(vm, "PIT_BATCH_GAP", kmes.PAYLOAD).ret, 0,
            "a single emit follows")
        local events = kmes.of_type(kmes.drain(ring), "PIT_BATCH_GAP")
        kmes.detach(ring)
        t:assert_eq(#events, 2, "the ring holds the prefix and the single")
        t:assert_eq(events[2].sequence, events[1].sequence + 1,
            "abutting in sequence — the two failed entries consumed none")
    end)

test("emitted_out is zeroed before any entry is judged",
    { spec = "PKM *batch.emitted-out-zeroed-first" }, function(t)
        -- An unwritable emitted_out fails the whole call with EFAULT
        -- before any per-entry work, and nothing is emitted.
        local events = kmes.recording(t, vm, function()
            local r = kmes.emit_batch(vm, entries(3, "PIT_BATCH_OUT"),
                { emitted_ptr = 0xdead0000 })
            t:assert_eq(r.errno, sys.E.FAULT, sys.errname(r.errno))
        end)
        t:assert_eq(#kmes.of_type(events, "PIT_BATCH_OUT"), 0,
            "and nothing was emitted")
    end)

test("entry validation reuses the single-emit pipeline",
    { spec = "PKM *batch.errors" }, function(t)
        local function failing(entry, errno, why)
            local batch = { entry }
            local r = kmes.emit_batch(vm, batch)
            t:assert_eq(r.errno, errno, why .. ": " .. sys.errname(r.errno))
            t:assert_eq(r.emitted, 0, "with nothing emitted")
        end
        failing({ type = "PIT_E", payload = kmes.PAYLOAD, type_len = 0 },
            sys.E.INVAL, "a zero type length")
        failing({ type = "PIT_\xff\xfe", payload = kmes.PAYLOAD },
            sys.E.INVAL, "a non-UTF-8 type")
        failing({ type = "PIT_E" }, sys.E.INVAL, "an empty payload")
        failing({ type = "PIT_E", payload = kmes.PAYLOAD,
                  payload_len = kmes.DEFAULT.MAX_EVENT_SIZE },
            sys.E.NOSPC, "an oversize declaration")
        failing({ type = "PIT_E",
                  payload = kmes.nested(kmes.DEFAULT.MAX_NESTING_DEPTH + 1) },
            sys.E.INVAL, "nesting past MaxNestingDepth")
    end)

test("the descriptor's padding bytes are not validated",
    { spec = "PKM *batch.padding-not-validated" }, function(t)
        -- §2.A documents _pad0/_pad1 as reserved-must-be-zero, and §2.4
        -- records that nothing enforces it — a batch whose padding is
        -- garbage emits normally. The reservation is real: a future
        -- revision may give the bytes meaning, so an emitter must still
        -- zero them.
        local events = kmes.recording(t, vm, function()
            local r = kmes.emit_batch(vm, {
                { type = "PIT_PAD", payload = kmes.PAYLOAD,
                  pad0 = "\xff\xff\xff\xff\xff\xff", pad1 = "\xee\xee\xee\xee" },
            })
            t:assert_eq(r.ret, 0, "garbage padding: " .. sys.errname(r.errno))
        end)
        t:assert_eq(#kmes.of_type(events, "PIT_PAD"), 1, "and the event emits")
    end)

test("the batch takes the same privilege gate as the single emit",
    { spec = "PKM *emit.privilege-gate" }, function(t)
        kacs.as_dacl_bound(t, vm, function(worker)
            local r = kmes.emit_batch(worker, entries(2, "PIT_BATCH_PRIV"))
            t:assert_eq(r.errno, sys.E.PERM, sys.errname(r.errno))
        end, { privs = kmes.PRIV.AUDIT })
    end)
