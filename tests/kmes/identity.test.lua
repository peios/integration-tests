-- PKM §2.2 — the stamps under scrutiny: impersonation and the two
-- token GUIDs, process GUID stability, the trusted kernel origin
-- class, and what the kernel emitter does that a syscall cannot show
-- (driven through stratafs's audit events, the one kernel emitter a
-- kernel-only guest can trigger at will).

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local kmes = require("helpers.kmes")
local stratafs = require("helpers.stratafs")

local vm = provium:vm("v", "kernel-only"):boot()

local SECURITY_IMPERSONATION = 2

test("impersonation moves the effective GUID and never the true one",
    { spec = "PKM *event.identity.effective-follows-impersonation" },
    function(t)
        -- A worker duplicates its own token as an impersonation token
        -- and installs it on its thread: the effective stamp follows
        -- the impersonation (a distinct token object), the true stamp
        -- does not move, and revert restores the pair.
        local worker = vm:spawn_worker()
        local ok, err = pcall(function()
            local events = kmes.recording(t, vm, function()
                t:assert_eq(kmes.emit(worker, "PIT_IMP_BEFORE",
                    kmes.PAYLOAD).ret, 0, "a baseline emit")

                local token = worker:syscall(kacs.SYS.OPEN_SELF_TOKEN, 0,
                    kacs.TOKEN_ALL_ACCESS)
                t:assert(token.ret >= 0, "the worker opens its token")
                local dup = worker:syscall(sys.NR.ioctl, {
                    args = { token.ret, kacs.IOC.DUPLICATE, 0 },
                    bufs = { string.pack("<I4I4I4i4",
                        kacs.TOKEN_ALL_ACCESS, kacs.TOKEN_TYPE_IMPERSONATION,
                        SECURITY_IMPERSONATION, -1) },
                    ptrs = { 2 },
                })
                t:assert_eq(dup.ret, 0, "and duplicates it as an " ..
                    "impersonation token: " .. sys.errname(dup.errno))
                local imp_fd = string.unpack("<i4", dup.out_bufs[1], 13)
                t:assert(imp_fd >= 0, "which comes back as an fd")
                t:assert_eq(worker:syscall(sys.NR.ioctl, imp_fd,
                    kacs.IOC.IMPERSONATE, 0).ret, 0, "and impersonates")

                t:assert_eq(kmes.emit(worker, "PIT_IMP_DURING",
                    kmes.PAYLOAD).ret, 0, "an emit while impersonating")

                t:assert_eq(worker:syscall(kacs.SYS.REVERT, 0).ret, 0,
                    "revert")
                t:assert_eq(kmes.emit(worker, "PIT_IMP_AFTER",
                    kmes.PAYLOAD).ret, 0, "and an emit after")
            end)

            local before = kmes.of_type(events, "PIT_IMP_BEFORE")[1]
            local during = kmes.of_type(events, "PIT_IMP_DURING")[1]
            local after = kmes.of_type(events, "PIT_IMP_AFTER")[1]
            t:assert(before and during and after, "all three arrive")
            t:assert_eq(before.effective_token, before.true_token,
                "before: not impersonating, the pair agree")
            t:assert_neq(during.effective_token, during.true_token,
                "during: the effective stamp is the impersonation token's")
            t:assert_eq(during.true_token, before.true_token,
                "while the true stamp never moves")
            t:assert_eq(after.effective_token, after.true_token,
                "after revert the pair agree again")
            t:assert_eq(after.true_token, before.true_token,
                "on the same primary token throughout")
        end)
        worker:kill(); worker:join()
        if not ok then error(err, 0) end
    end)

test("the true token GUID never follows an impersonation",
    { spec = "PKM *event.identity.true-ignores-impersonation" }, function(t)
        -- The companion claim: current_real_cred() is what the true
        -- stamp reads, and impersonation leaves it untouched.
        local worker = vm:spawn_worker()
        local ok, err = pcall(function()
            local events = kmes.recording(t, vm, function()
                t:assert_eq(kmes.emit(worker, "PIT_TRUE_A", kmes.PAYLOAD).ret,
                    0, "baseline")
                local token = worker:syscall(kacs.SYS.OPEN_SELF_TOKEN, 0,
                    kacs.TOKEN_ALL_ACCESS)
                t:assert(token.ret >= 0, "token opened")
                local dup = worker:syscall(sys.NR.ioctl, {
                    args = { token.ret, kacs.IOC.DUPLICATE, 0 },
                    bufs = { string.pack("<I4I4I4i4",
                        kacs.TOKEN_ALL_ACCESS, kacs.TOKEN_TYPE_IMPERSONATION,
                        SECURITY_IMPERSONATION, -1) },
                    ptrs = { 2 },
                })
                t:assert_eq(dup.ret, 0, "duplicated for impersonation")
                t:assert_eq(worker:syscall(sys.NR.ioctl,
                    string.unpack("<i4", dup.out_bufs[1], 13),
                    kacs.IOC.IMPERSONATE, 0).ret, 0, "impersonating")
                t:assert_eq(kmes.emit(worker, "PIT_TRUE_B", kmes.PAYLOAD).ret,
                    0, "an emit while impersonating")
                worker:syscall(kacs.SYS.REVERT, 0)
            end)
            local a = kmes.of_type(events, "PIT_TRUE_A")[1]
            local b = kmes.of_type(events, "PIT_TRUE_B")[1]
            t:assert(a and b, "both arrive")
            t:assert_eq(b.true_token, a.true_token,
                "the true stamp is the primary token's GUID either way")
        end)
        worker:kill(); worker:join()
        if not ok then error(err, 0) end
    end)

test("the process GUID is one value for the process's lifetime",
    { spec = "PKM *event.identity.process-guid-stable" }, function(t)
        local worker = vm:spawn_worker()
        local ok, err = pcall(function()
            local events = kmes.recording(t, vm, function()
                for i = 1, 3 do
                    t:assert_eq(kmes.emit(worker, "PIT_PG", kmes.PAYLOAD).ret,
                        0, "emit " .. i)
                    sys.nanosleep(vm, 0, 5 * 1000 * 1000)
                end
            end)
            local mine = kmes.of_type(events, "PIT_PG")
            t:assert_eq(#mine, 3, "three events over time")
            t:assert_eq(mine[2].process_guid, mine[1].process_guid,
                "one process GUID")
            t:assert_eq(mine[3].process_guid, mine[1].process_guid,
                "across all of them")
        end)
        worker:kill(); worker:join()
        if not ok then error(err, 0) end
    end)

test("a kernel emitter's origin class is written as passed",
    { spec = "PKM *event.stamp.origin-class-trust" }, function(t)
        -- The syscall path forces 0; the kernel path writes what the
        -- subsystem passed. KACS's audit emitter passes 2, and 2 is
        -- what arrives — a value no syscall caller can produce.
        stratafs.with(vm, "kmes-origin", {
            { name = "dest", flags = { "create" } },
            { name = "src", flags = { "ro" }, entries = { f = "original" } },
        }, function(s)
            local events = kmes.recording(t, vm, function()
                t:assert_eq(kmes.emit(vm, "PIT_ORIGIN_USER", kmes.PAYLOAD).ret,
                    0, "a syscall event")
                t:assert(stratafs.try_write(vm, s:join("f"), "modified"),
                    "and a copy-up for a kernel one")
            end)
            t:assert_eq(kmes.of_type(events, "PIT_ORIGIN_USER")[1].origin,
                kmes.ORIGIN.USERSPACE, "the syscall event is 0")
            local audit = kmes.of_type(events, "STRATAFS_COPY_UP")
            t:assert_eq(#audit, 1, "the audit event arrives")
            t:assert_eq(audit[1].origin, kmes.ORIGIN.KACS,
                "carrying KACS's origin class 2, exactly as passed")
        end)
    end)

test("the observed origin classes are the assigned ones",
    { spec = "PKM *event.origin-classes-assigned" }, function(t)
        -- Between the syscall interface (0) and KACS's audit stream
        -- (2), both observable origins match the §2.1 assignment; no
        -- event in a drain ever carries an unassigned value.
        stratafs.with(vm, "kmes-origins", {
            { name = "dest", flags = { "create" } },
            { name = "src", flags = { "ro" }, entries = { g = "x" } },
        }, function(s)
            local events = kmes.recording(t, vm, function()
                t:assert_eq(kmes.emit(vm, "PIT_OC", kmes.PAYLOAD).ret, 0, "one")
                t:assert(stratafs.try_write(vm, s:join("g"), "y"), "two")
            end)
            t:assert(#events >= 2, "both arrive")
            for _, e in ipairs(events) do
                t:assert(e.origin == kmes.ORIGIN.USERSPACE or
                         e.origin == kmes.ORIGIN.KMES or
                         e.origin == kmes.ORIGIN.KACS or
                         e.origin == kmes.ORIGIN.LCS,
                    "origin " .. e.origin .. " is an assigned class")
            end
        end)
    end)

test("kernel emission neither blocks nor fails when the ring is full",
    { spec = "PKM *kernel-emit.never-blocks" }, function(t)
        -- Pack the ring to its capacity, then trigger a copy-up: the
        -- filesystem operation completes undelayed and its audit
        -- event lands, overwriting the oldest — buffer pressure is
        -- the consumer's problem, never the emitter's.
        local content = string.rep("cd", 29956)
        local payload = "\xda" .. string.pack(">I2", #content) .. content
        stratafs.with(vm, "kmes-full-ring", {
            { name = "dest", flags = { "create" } },
            { name = "src", flags = { "ro" }, entries = { f = "original" } },
        }, function(s)
            local ring = kmes.attach(vm, 0)
            t:assert(ring, "a ring attaches")
            for i = 1, 75 do
                t:assert_eq(kmes.emit(vm, "PIT_PRESSURE", payload).ret, 0,
                    "fill " .. i)
            end
            t:assert(stratafs.try_write(vm, s:join("f"), "modified"),
                "the copy-up runs against a full ring")
            local audit = kmes.of_type(kmes.drain(ring), "STRATAFS_COPY_UP")
            kmes.detach(ring)
            t:assert_eq(#audit, 1,
                "and its event is in the ring, over the oldest fill")
        end)
    end)

test("the timestamp is the wall clock in nanoseconds",
    { spec = "PKM *event.stamp.timestamp-realtime" }, function(t)
        local clk = vm:syscall(228, { -- clock_gettime(CLOCK_REALTIME)
            args = { 0, 0 }, bufs = { string.rep("\0", 16) }, ptrs = { 1 },
        })
        t:assert_eq(clk.ret, 0, "the clock reads")
        local sec = string.unpack("<i8", clk.out_bufs[1])
        local events = kmes.recording(t, vm, function()
            t:assert_eq(kmes.emit(vm, "PIT_TS", kmes.PAYLOAD).ret, 0, "emit")
        end)
        local e = kmes.of_type(events, "PIT_TS")[1]
        t:assert(e, "the event arrives")
        local delta = e.timestamp / 1e9 - sec
        t:assert(delta >= 0 and delta < 5,
            "stamped within seconds of CLOCK_REALTIME: delta " .. delta)
    end)

test("the counter increments and then its value is taken",
    { spec = "PKM *event.stamp.sequence-increment-then-read" }, function(t)
        -- Observable as: consecutive accepted events carry exactly
        -- consecutive values, with no zero and no reuse.
        local events = kmes.recording(t, vm, function()
            for i = 1, 4 do
                t:assert_eq(kmes.emit(vm, "PIT_SEQ", kmes.PAYLOAD).ret, 0,
                    "emit " .. i)
            end
        end)
        local mine = kmes.of_type(events, "PIT_SEQ")
        t:assert_eq(#mine, 4, "four events")
        for i = 2, 4 do
            t:assert_eq(mine[i].sequence, mine[i - 1].sequence + 1,
                "consecutive at " .. i)
        end
        t:assert(mine[1].sequence > 0, "and never zero")
    end)

test("the timestamp is captured before the sequence is assigned",
    { spec = "PKM *event.stamp.timestamp-before-sequence" }, function(t)
        -- Its stated consequence: two events with the same timestamp
        -- on one CPU are ordered by sequence. A batch manufactures the
        -- tie deliberately, and the ordering holds.
        local events = kmes.recording(t, vm, function()
            t:assert_eq(kmes.emit_batch(vm, {
                { type = "PIT_TIE", payload = kmes.PAYLOAD },
                { type = "PIT_TIE", payload = kmes.PAYLOAD },
                { type = "PIT_TIE", payload = kmes.PAYLOAD },
            }).ret, 0, "three events, one timestamp")
        end)
        local tie = kmes.of_type(events, "PIT_TIE")
        t:assert_eq(#tie, 3, "all arrive")
        t:assert(tie[1].timestamp == tie[2].timestamp and
                 tie[2].timestamp == tie[3].timestamp, "tied on the clock")
        t:assert(tie[1].sequence < tie[2].sequence and
                 tie[2].sequence < tie[3].sequence,
            "and totally ordered by sequence")
    end)

test("every stamp is present though the caller supplied none",
    { spec = "PKM *event.stamps-unconditional" }, function(t)
        -- The emit signature takes a type and a payload, nothing else;
        -- all four intrinsic stamps and the three identity GUIDs are
        -- populated regardless.
        local events = kmes.recording(t, vm, function()
            t:assert_eq(kmes.emit(vm, "PIT_STAMPS", kmes.PAYLOAD).ret, 0,
                "emit")
        end)
        local e = kmes.of_type(events, "PIT_STAMPS")[1]
        t:assert(e, "the event arrives")
        t:assert(e.timestamp > 0, "timestamp")
        t:assert(e.sequence > 0, "sequence")
        t:assert(e.cpu >= 0, "cpu_id")
        t:assert_eq(e.origin, 0, "origin class")
        t:assert_neq(e.effective_token, kmes.NULL_GUID, "effective token")
        t:assert_neq(e.true_token, kmes.NULL_GUID, "true token")
        t:assert_neq(e.process_guid, kmes.NULL_GUID, "process GUID")
    end)

test("drop visibility differs between the two emission paths",
    { spec = "PKM *failure.drop-visibility-differs" }, function(t)
        -- The syscall half: validation precedes the write phase, so a
        -- rejected emit consumes no sequence and the caller gets the
        -- error. (The kernel half — the gap a structural drop leaves —
        -- cannot be provoked from a guest, and runs under
        -- pkm_kunit_kmes_direct_invalid_type_drops_structurally.)
        local events = kmes.recording(t, vm, function()
            t:assert_eq(kmes.emit(vm, "PIT_VIS", kmes.PAYLOAD).ret, 0, "one")
            t:assert_eq(kmes.emit(vm, "PIT_VIS", "\xc1").errno, sys.E.INVAL,
                "a rejection, reported to the caller")
            t:assert_eq(kmes.emit(vm, "PIT_VIS", kmes.PAYLOAD).ret, 0, "two")
        end)
        local mine = kmes.of_type(events, "PIT_VIS")
        t:assert_eq(#mine, 2, "the ring holds the accepted pair")
        t:assert_eq(mine[2].sequence, mine[1].sequence + 1,
            "with no gap where the rejection was")
    end)

test("identity is null only without task context",
    { spec = "PKM *event.identity.null-without-task-context",
      covered_by = "kunit:pkm_kunit_kmes",
      skip = "interrupt-context and pre-KACS emission cannot be provoked " ..
             "from a booted guest; " ..
             "pkm_kunit_kmes_identity_stamps_match_kacs_state drives the " ..
             "accessors directly" }, function(t)
    end)

test("KMES is the sole emission path",
    { spec = "PKM *event.sole-emission-path",
      covered_by = "unreachable",
      skip = "a universal negative — that no other emission path exists " ..
             "is an architectural property with no test-shaped witness" },
    function(t)
    end)
