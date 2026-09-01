-- PKM §2.4 — the per-process token bucket: exhaustion to EAGAIN,
-- atomic batch reservation, per-process scope, the fresh bucket at
-- fork, the SeTcbPrivilege exemption, and the monotonic refill.
--
-- The compiled-in rate is 10000 events per second with an equal burst
-- capacity, and refill runs while a test is still emitting — every
-- assertion here is arranged to hold with the bucket refilling under
-- it.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local kmes = require("helpers.kmes")

local vm = provium:vm("v", "kernel-only"):boot()

local function batch_entries()
    local out = {}
    for i = 1, kmes.BATCH_MAX_ENTRIES do
        out[i] = { type = "PIT_RATE", payload = kmes.PAYLOAD }
    end
    return out
end

--- Drive one process's bucket to EAGAIN with full batches. Returns
--- the failing result and how many events were accepted first.
local function exhaust(t, who)
    local entries = batch_entries()
    local accepted = 0
    for _ = 1, 300 do
        local r = kmes.emit_batch(who, entries)
        if r.ret ~= 0 then return r, accepted end
        accepted = accepted + kmes.BATCH_MAX_ENTRIES
    end
    t:assert(false, "the bucket never emptied across 300 full batches")
end

test("holders of enabled SeTcbPrivilege are not limited",
    { spec = "PKM *emit.rate.tcb-bypass" }, function(t)
        -- The agent runs as SYSTEM with SeTcbPrivilege enabled: fifty
        -- full batches — 12800 events, past any bucket — all land.
        local entries = batch_entries()
        for i = 1, 50 do
            local r = kmes.emit_batch(vm, entries)
            t:assert_eq(r.ret, 0, "batch " .. i .. ": " .. sys.errname(r.errno))
        end
    end)

test("an empty bucket refuses the reserve and consumes nothing",
    { spec = "PKM *emit.rate.empty-eagain" }, function(t)
        kacs.as_dacl_bound(t, vm, function(worker)
            local r, accepted = exhaust(t, worker)
            t:assert_eq(r.errno, sys.E.AGAIN,
                "after " .. accepted .. " events: " .. sys.errname(r.errno))
            t:assert_eq(r.emitted, 0, "and the failing call emitted none")
        end, { privs = kmes.PRIV.TCB })
    end)

test("a batch reserves its whole count or nothing",
    { spec = "PKM *batch.tokens-reserved-atomically" }, function(t)
        -- When the bucket cannot cover 256, the batch fails whole —
        -- but the tokens it could not take are still there, so a
        -- single emit right behind the EAGAIN is accepted.
        kacs.as_dacl_bound(t, vm, function(worker)
            local r = exhaust(t, worker)
            t:assert_eq(r.errno, sys.E.AGAIN, "a full batch no longer fits")
            local single = kmes.emit(worker, "PIT_RATE_ONE", kmes.PAYLOAD)
            t:assert_eq(single.ret, 0,
                "while a single event still does: the failed batch took " ..
                "nothing partial: " .. sys.errname(single.errno))
        end, { privs = kmes.PRIV.TCB })
    end)

test("one process's exhaustion is not another's",
    { spec = "PKM *emit.rate.per-process-not-per-sid" }, function(t)
        -- Both workers run under the same SID — rate state is keyed by
        -- process, so the second is untouched by the first's spree.
        kacs.as_dacl_bound(t, vm, function(worker_a)
            local r = exhaust(t, worker_a)
            t:assert_eq(r.errno, sys.E.AGAIN, "the first worker is throttled")
            kacs.as_dacl_bound(t, vm, function(worker_b)
                local fresh = kmes.emit_batch(worker_b, batch_entries())
                t:assert_eq(fresh.ret, 0,
                    "a sibling process emits freely: " .. sys.errname(fresh.errno))
            end, { privs = kmes.PRIV.TCB })
        end, { privs = kmes.PRIV.TCB })
    end)

test("a new process starts with a full bucket",
    { spec = "PKM *emit.rate.bucket-per-process-lifecycle" }, function(t)
        -- Allocated with the process's security state at fork,
        -- initialised to capacity: a burst from a brand-new worker
        -- accepts about MaxEmitRatePerProcess events before the first
        -- EAGAIN (a little more, for what refills while it runs).
        kacs.as_dacl_bound(t, vm, function(worker)
            local r, accepted = exhaust(t, worker)
            t:assert_eq(r.errno, sys.E.AGAIN, "the burst ends in EAGAIN")
            t:assert(accepted >= kmes.DEFAULT.MAX_EMIT_RATE - kmes.BATCH_MAX_ENTRIES,
                "after at least the burst capacity: " .. accepted)
            t:assert(accepted <= kmes.DEFAULT.MAX_EMIT_RATE * 2,
                "and not wildly more: " .. accepted)
        end, { privs = kmes.PRIV.TCB })
    end)

test("refill is driven by the monotonic clock",
    { spec = "PKM *emit.rate.monotonic-refill" }, function(t)
        -- On a VM of its own, because it moves the wall clock: after
        -- exhaustion, CLOCK_REALTIME jumps an hour backwards. A refill
        -- computed against the wall clock would now wait an hour;
        -- the monotonic one hands out fresh tokens within
        -- milliseconds.
        local vmc = provium:vm("vclock", "kernel-only"):boot()
        local saved = vmc:syscall(228, { -- clock_gettime(REALTIME)
            args = { 0, 0 }, bufs = { string.rep("\0", 16) }, ptrs = { 1 },
        })
        t:assert_eq(saved.ret, 0, "the clock reads")
        local sec = string.unpack("<i8", saved.out_bufs[1])

        kacs.as_dacl_bound(t, vmc, function(worker)
            local r = exhaust(t, worker)
            t:assert_eq(r.errno, sys.E.AGAIN, "the worker is throttled")
            local set = vmc:syscall(227, { -- clock_settime(REALTIME)
                args = { 0, 0 },
                bufs = { string.pack("<i8i8", sec - 3600, 0) }, ptrs = { 1 },
            })
            t:assert_eq(set.ret, 0,
                "the wall clock jumps an hour back: " .. sys.errname(set.errno))
            sys.nanosleep(vmc, 0, 100 * 1000 * 1000)
            local after = kmes.emit(worker, "PIT_MONO", kmes.PAYLOAD)
            t:assert_eq(after.ret, 0,
                "and tokens still refill on schedule: " ..
                sys.errname(after.errno))
        end, { privs = kmes.PRIV.TCB })

        vmc:syscall(227, { args = { 0, 0 },
            bufs = { string.pack("<i8i8", sec + 1, 0) }, ptrs = { 1 } })
    end)

test("throttling is temporary: tokens return at the configured rate",
    { spec = "PKM *emit.rate-limit" }, function(t)
        -- The section anchor: a bucket that refuses now accepts again
        -- a moment later, because refill is continuous at
        -- MaxEmitRatePerProcess.
        kacs.as_dacl_bound(t, vm, function(worker)
            local r = exhaust(t, worker)
            t:assert_eq(r.errno, sys.E.AGAIN, "throttled")
            sys.nanosleep(vm, 0, 100 * 1000 * 1000)
            local again = kmes.emit_batch(worker, batch_entries())
            t:assert_eq(again.ret, 0,
                "and 100ms later a full batch fits again: " ..
                sys.errname(again.errno))
        end, { privs = kmes.PRIV.TCB })
    end)

test("a failing batch charges only what it emitted",
    { spec = "PKM *batch.unused-tokens-refunded" }, function(t)
        -- 150 batches that each reserve 256 and emit nothing: without
        -- the refund they would burn 38400 tokens against a 10000
        -- bucket and refill could not keep up — some would return
        -- EAGAIN. With it, every one is EINVAL and a full valid batch
        -- still fits afterwards.
        kacs.as_dacl_bound(t, vm, function(worker)
            local bad = batch_entries()
            bad[1] = { type = "PIT_RATE", payload = "\xc1" }
            for i = 1, 150 do
                local r = kmes.emit_batch(worker, bad)
                t:assert_eq(r.errno, sys.E.INVAL,
                    "failing batch " .. i .. " is EINVAL, never EAGAIN: " ..
                    sys.errname(r.errno))
                t:assert_eq(r.emitted, 0, "and emitted nothing")
            end
            local good = kmes.emit_batch(worker, batch_entries())
            t:assert_eq(good.ret, 0,
                "a full valid batch still fits: the reservations came back")
        end, { privs = kmes.PRIV.TCB })
    end)

test("a rate change reconfigures every live bucket at once",
    { spec = "PKM *emit.rate.reconfigure-applies-immediately",
      covered_by = "kunit:pkm_kunit_kmes",
      skip = "changing MaxEmitRatePerProcess needs a registry source; " ..
             "the live-clamp runs under " ..
             "pkm_kunit_kmes_runtime_rate_change_clamps_live_bucket" },
    function(t)
    end)

test("the exemption and the refund arithmetic under refill",
    { spec = "PKM *emit.rate.reserve-then-refund",
      covered_by = "kunit:pkm_kunit_kmes",
      skip = "the reserve-refund-clamp arithmetic is not distinguishable " ..
             "from refill at syscall granularity: the compiled-in rate " ..
             "refills 10000 tokens a second, faster than failing emits can " ..
             "be issued to measure the difference; needs the rate " ..
             "configured low through a registry source, which the " ..
             "kernel-only profile does not have yet" }, function(t)
    end)
