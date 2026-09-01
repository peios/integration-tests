-- PKM §2.6 and §2.7 — the bootstrap posture on a system where LCS
-- never becomes available. The kernel-only profile has no registry
-- source at all, which makes it exactly the "LCS unavailable" system
-- §2.7 describes: every KMES parameter is the compiled-in default,
-- and that is a valid operating mode rather than a degraded one.
--
-- The re-read, validation, rejection and self-configuration event
-- machinery (§2.6) needs a Machine-hive source to drive it; those
-- citations wait until the profile can serve one.

local sys = require("helpers.sys")
local kmes = require("helpers.kmes")

local vm = provium:vm("v", "kernel-only"):boot()

test("KMES runs whole on compiled-in defaults, indefinitely",
    { spec = "PKM *failure.lcs-never-required" }, function(t)
        -- Not one subsystem verb is missing: attach, emit, batch,
        -- drain all work on a guest where no source ever registered.
        local events = kmes.recording(t, vm, function()
            t:assert_eq(kmes.emit(vm, "PIT_NOLCS", kmes.PAYLOAD).ret, 0,
                "emit works")
            t:assert_eq(kmes.emit_batch(vm, {
                { type = "PIT_NOLCS", payload = kmes.PAYLOAD },
            }).ret, 0, "batch works")
        end)
        t:assert_eq(#kmes.of_type(events, "PIT_NOLCS"), 2,
            "and delivery works — nothing was waiting for configuration")
    end)

test("all four parameters are their §2.A defaults",
    { spec = "PKM *config.defaults-carry-until-lcs" }, function(t)
        -- Each default is observed behaviourally at its boundary; the
        -- registry shows nothing because there is no registry.
        local ring = kmes.attach(vm, 0)
        t:assert(ring, "a ring attaches")
        t:assert_eq(ring.capacity, kmes.DEFAULT.BUFFER_CAPACITY,
            "BufferCapacity: the ring is 4 MiB")
        kmes.detach(ring)

        local max = kmes.DEFAULT.MAX_EVENT_SIZE
        t:assert_eq(kmes.emit(vm, "PIT_DEF", nil,
            { payload_ptr = 0xdead0000, payload_len = max }).errno,
            sys.E.NOSPC, "MaxEventSize: 64 KiB is where ENOSPC begins")

        t:assert_eq(kmes.emit(vm, "PIT_DEF",
            kmes.nested(kmes.DEFAULT.MAX_NESTING_DEPTH)).ret, 0,
            "MaxNestingDepth: 32 is accepted")
        t:assert_eq(kmes.emit(vm, "PIT_DEF",
            kmes.nested(kmes.DEFAULT.MAX_NESTING_DEPTH + 1)).errno,
            sys.E.INVAL, "and 33 is not")
        -- MaxEmitRatePerProcess = 10000 is measured in rate.test.lua:
        -- a fresh process's burst ends within a batch of it.
        t:assert(true, "MaxEmitRatePerProcess is measured in rate.test.lua")
    end)

test("the boot-time rings are the live rings, not a bootstrap stand-in",
    { spec = "PKM *ring.boot-buffers-ordinary" }, function(t)
        -- §2.1/§2.5: buffers created at module load are ordinary in
        -- every observable way — same layout, same magic, same
        -- generation model, attachable, draining events emitted from
        -- the first instant. On this profile they are also permanent.
        local ring = kmes.attach(vm, 0)
        t:assert(ring, "the boot-time ring attaches like any other")
        t:assert_eq(ring.magic, "KMESRING", "same magic")
        t:assert_eq(ring.version, 1, "same version")
        local head = vm:read_mem(ring.addr, 40)
        t:assert_eq(string.unpack("<I8", head, 33), 1,
            "at generation 1 — never swapped since boot")
        local events = kmes.recording(t, vm, function()
            t:assert_eq(kmes.emit(vm, "PIT_BOOTRING", kmes.PAYLOAD).ret, 0,
                "an event emits into it")
        end)
        t:assert_eq(#kmes.of_type(events, "PIT_BOOTRING"), 1, "and drains")
        kmes.detach(ring)
    end)

test("the three syscalls answer at their §2.A numbers",
    { spec = "PKM *abi.syscall-numbers" }, function(t)
        -- Each number reaches KMES, not ENOSYS and not a neighbour:
        -- the errors and results are KMES's own vocabulary.
        t:assert_eq(kmes.emit(vm, "PIT_NR", kmes.PAYLOAD).ret, 0,
            "1090 emits")
        local r = vm:syscall(kmes.SYS.ATTACH, {
            args = { kmes.ATTACH_QUERY_SLOTS, 0 },
            bufs = { string.rep("\0", 8) }, ptrs = { 1 },
        })
        t:assert_eq(r.ret, 0, "1091 attaches (query form)")
        t:assert_eq(kmes.emit_batch(vm, {
            { type = "PIT_NR", payload = kmes.PAYLOAD },
        }).ret, 0, "1092 batches")
    end)

test("a batch descriptor is the 32-byte struct kmes_emit_entry",
    { spec = "PKM *abi.struct-kmes-emit-entry" }, function(t)
        -- Everything in batch.test.lua rides this layout; here it is
        -- the subject. The descriptors are packed from the measured
        -- offsets — type pointer at 0, type_len at 8, payload pointer
        -- at 16, payload_len at 24, 32-byte stride — and a two-entry
        -- batch round-trips both events intact, which no misaligned
        -- layout could.
        local events = kmes.recording(t, vm, function()
            t:assert_eq(kmes.emit_batch(vm, {
                { type = "PIT_LAYOUT_A", payload = kmes.PAYLOAD },
                { type = "PIT_LAYOUT_B", payload = "\x92\x01\x02" },
            }).ret, 0, "the batch is accepted")
        end)
        t:assert_eq(#kmes.of_type(events, "PIT_LAYOUT_A"), 1, "entry one lands")
        local b = kmes.of_type(events, "PIT_LAYOUT_B")
        t:assert_eq(#b, 1, "entry two lands from the next 32-byte stride")
        t:assert_eq(b[1].raw:sub(b[1].header_size + 1), "\x92\x01\x02",
            "with its own payload, not its neighbour's")
    end)

test("the boot-time capacity is compiled in, not configured",
    { spec = "PKM *config.boot-capacity-compiled-in" }, function(t)
        -- Nothing can deliver a value before the registry exists, so
        -- the capacity the boot rings run at is the compiled-in
        -- default — observed on a guest that has no registry, where
        -- it is also the capacity forever.
        local ring = kmes.attach(vm, 0)
        t:assert(ring, "a ring attaches")
        t:assert_eq(ring.capacity, kmes.DEFAULT.BUFFER_CAPACITY,
            "at the compiled-in default with nothing to configure it")
        t:assert_eq(string.unpack("<I8", vm:read_mem(ring.addr + 32, 8)), 1,
            "and still generation 1: it was never swapped away from")
        kmes.detach(ring)
    end)

test("emit syscalls fail closed before the subsystems exist",
    { spec = "PKM *syscalls.pre-init-fail-closed",
      covered_by = "unreachable",
      skip = "not reachable from a booted guest: the agent is PID 1 and " ..
             "starts after PKM initialises, so no syscall can be issued " ..
             "in the pre-init window this names" }, function(t)
    end)
