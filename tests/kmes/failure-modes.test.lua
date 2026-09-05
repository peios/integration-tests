-- PKM §2.7 — failure modes a guest can actually enter: a wall-clock
-- discontinuity, a CPU taken offline under a live ring, and the
-- topology fixed at initialisation.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local kmes = require("helpers.kmes")

local vm2 = provium:vm("v2", "kernel-only", { cpus = 2 }):boot()

local function pin(who, cpu)
    return who:syscall(sys.NR.sched_setaffinity, {
        args = { 0, 8, 0 },
        bufs = { string.pack("<I8", 1 << cpu) },
        ptrs = { 2 },
    }).ret == 0
end

local function pinned_emit(from_vm, cpu, type_name)
    local worker = from_vm:spawn_worker()
    local ok, err = pcall(function()
        assert(pin(worker, cpu), "pin to cpu " .. cpu)
        local r = kmes.emit(worker, type_name, kmes.PAYLOAD)
        assert(r.ret == 0, "pinned emit: " .. sys.errname(r.errno))
    end)
    worker:kill(); worker:join()
    if not ok then error(err, 0) end
end

test("a clock jump reorders timestamps and nothing else",
    { spec = "PKM *failure.clock-jump-reorders-timestamps-only" }, function(t)
        -- On its own VM because it moves CLOCK_REALTIME: after an
        -- hour's backward jump, the next event's timestamp precedes
        -- its predecessor's while its sequence number still follows
        -- it — sequence is never derived from the clock.
        local vmc = provium:vm("vclock", "kernel-only"):boot()
        local clk = vmc:syscall(228, {
            args = { 0, 0 }, bufs = { string.rep("\0", 16) }, ptrs = { 1 },
        })
        t:assert_eq(clk.ret, 0, "the clock reads")
        local sec = string.unpack("<i8", clk.out_bufs[1])

        local ring = kmes.attach(vmc, 0)
        t:assert(ring, "a ring attaches")
        t:assert_eq(kmes.emit(vmc, "PIT_JUMP", kmes.PAYLOAD).ret, 0, "before")
        t:assert_eq(vmc:syscall(227, { args = { 0, 0 },
            bufs = { string.pack("<i8i8", sec - 3600, 0) }, ptrs = { 1 },
        }).ret, 0, "the clock jumps an hour back")
        t:assert_eq(kmes.emit(vmc, "PIT_JUMP", kmes.PAYLOAD).ret, 0, "after")
        local events = kmes.of_type(kmes.drain(ring), "PIT_JUMP")
        kmes.detach(ring)
        vmc:syscall(227, { args = { 0, 0 },
            bufs = { string.pack("<i8i8", sec + 1, 0) }, ptrs = { 1 } })

        t:assert_eq(#events, 2, "both events in the ring")
        t:assert(events[2].timestamp < events[1].timestamp,
            "the second is stamped an hour before the first")
        t:assert_eq(events[2].sequence, events[1].sequence + 1,
            "while its sequence number is simply the next")
    end)

test("a CPU taken offline keeps its ring, silent",
    { spec = "PKM *failure.offline-cpu-ring-quiet" }, function(t)
        -- Offline cpu 1 through sysfs: its ring stays attached and
        -- attachable, nothing new arrives on it (the CPU executes
        -- nothing), and its events land again once the CPU returns.
        -- sysfs is UNMANAGED by KACS's own magic table; no policy to
        -- set, and the setter refuses one.
        local ok, step, errno = kacs.new_mount(vm2, "sysfs", "/sysk")
        t:assert(ok, "sysfs mounts: " .. tostring(step) .. " " ..
            sys.errname(errno or 0))
        local online = "/sysk/devices/system/cpu/cpu1/online"
        local function set_online(v)
            local fd, e = sys.open(vm2, online, sys.O.WRONLY)
            if not fd then return nil, e end
            local r = sys.write(vm2, fd, v)
            sys.close(vm2, fd)
            return r.ret == 1
        end

        local ring = kmes.attach(vm2, 1)
        t:assert(ring, "ring 1 attaches while the CPU runs")
        pinned_emit(vm2, 1, "PIT_HOTPLUG_UP")
        t:assert_eq(#kmes.of_type(kmes.drain(ring), "PIT_HOTPLUG_UP"), 1,
            "and receives a pinned event")

        t:assert(set_online("0"), "cpu 1 goes offline")
        local again = kmes.attach(vm2, 1)
        t:assert(again, "its ring still attaches — the slot is not a hole")
        kmes.detach(again)
        local before = kmes.positions(ring)
        for _ = 1, 5 do
            t:assert_eq(kmes.emit(vm2, "PIT_HOTPLUG_ELSEWHERE",
                kmes.PAYLOAD).ret, 0, "emission continues on the running CPU")
        end
        t:assert_eq(kmes.positions(ring), before,
            "while the offline CPU's ring stays exactly where it was")

        t:assert(set_online("1"), "cpu 1 returns")
        pinned_emit(vm2, 1, "PIT_HOTPLUG_BACK")
        t:assert_eq(#kmes.of_type(kmes.drain(ring), "PIT_HOTPLUG_BACK"), 1,
            "and its events land on the same ring as before")
        kmes.detach(ring)
    end)

test("the topology is fixed at initialisation",
    { spec = "PKM *failure.topology-fixed-at-init" }, function(t)
        -- Whatever hotplug did above, the slot array never moves: the
        -- query answers the boot-time count and the indexes beyond it
        -- stay EINVAL.
        local r = vm2:syscall(kmes.SYS.ATTACH, {
            args = { kmes.ATTACH_QUERY_SLOTS, 0 },
            bufs = { string.rep("\0", 8) }, ptrs = { 1 },
        })
        t:assert_eq(r.ret, 0, "the query answers")
        t:assert_eq(string.unpack("<I8", r.out_bufs[1]), 2,
            "two slots, as at boot")
        local _, errno = kmes.attach(vm2, 2)
        t:assert_eq(errno, sys.E.INVAL, "and index 2 is still EINVAL")
    end)

test("bulk losses bypass the drop counter",
    { spec = "PKM *failure.bulk-loss-outside-drop-counter",
      covered_by = "kunit:pkm_kunit_kmes",
      skip = "the drop counter is readable only through the KUnit " ..
             "interface; the shrink half runs under " ..
             "pkm_kunit_kmes_swap_downsize_preserves_newest_suffix, the " ..
             "tail-resync half under " ..
             "pkm_kunit_kmes_tail_resync_discards_window_on_corrupt_size" },
    function(t)
    end)

-- ---- a CPU offline from boot --------------------------------------

test("a CPU possible but offline at initialisation has a ring",
    { spec = "PKM *attach.offline-possible-cpus-attachable" }, function(t)
        -- Two vCPUs, booted with maxcpus=1: cpu 1 is in the possible
        -- set but never brought up. KMES created its ring at module
        -- load regardless — it is a slot, not a hole — and when the
        -- CPU comes online later its events land there.
        local vmax = provium:vm("vmax", "kernel-only", { cpus = 2 })
            :boot({ kernel_cmdline_append = "maxcpus=1" })
        local ok, step, errno = kacs.new_mount(vmax, "sysfs", "/sysk")
        t:assert(ok, "sysfs mounts: " .. tostring(step) .. " " ..
            sys.errname(errno or 0))
        local online = "/sysk/devices/system/cpu/cpu1/online"
        t:assert_eq(vmax:read_file(online):sub(1, 1), "0",
            "cpu 1 is offline from boot")

        local q = vmax:syscall(kmes.SYS.ATTACH, {
            args = { kmes.ATTACH_QUERY_SLOTS, 0 },
            bufs = { string.rep("\0", 8) }, ptrs = { 1 },
        })
        t:assert_eq(string.unpack("<I8", q.out_bufs[1]), 2,
            "the slot array still counts both CPUs")
        local ring, e = kmes.attach(vmax, 1)
        t:assert(ring, "the offline CPU's ring attaches: " ..
            sys.errname(e or 0))
        t:assert_eq(string.unpack("<I8", vmax:read_mem(ring.addr + 32, 8)), 1,
            "at generation 1, created at initialisation")
        t:assert_eq(kmes.positions(ring), 0, "and never written to")

        local fd = sys.open(vmax, online, sys.O.WRONLY)
        t:assert(fd, "the online file opens for writing")
        t:assert_eq(sys.write(vmax, fd, "1").ret, 1, "cpu 1 is brought online")
        sys.close(vmax, fd)
        pinned_emit(vmax, 1, "PIT_LATE_CPU")
        local events = kmes.of_type(kmes.drain(ring), "PIT_LATE_CPU")
        kmes.detach(ring)
        t:assert_eq(#events, 1, "and its first event lands on that ring")
        t:assert_eq(events[1].sequence, 1, "as sequence 1: the counter waited too")
    end)

-- ---- suspend to RAM -------------------------------------------------

test("suspend keeps the ring and the sequence, jumping only the clock",
    { spec = "PKM *failure.suspend-no-sequence-gap" }, function(t)
        -- The guest puts itself into S3 (a worker writes `mem` to
        -- /sys/power/state and blocks there until resume); the host
        -- wakes it with vm:wakeup(), which QEMU refuses until the
        -- guest is actually suspended — so retrying it is the wait.
        -- Ring contents survive, the sequence is contiguous across the
        -- sleep, and only the wall clock shows the gap.
        local vs3 = provium:vm("vs3", "kernel-only"):boot()
        local ok, step, errno = kacs.new_mount(vs3, "sysfs", "/sysk")
        t:assert(ok, "sysfs mounts: " .. tostring(step) .. " " ..
            sys.errname(errno or 0))
        t:assert(vs3:read_file("/sysk/power/mem_sleep"):match("deep"),
            "the guest offers suspend to RAM")
        local pre_ok = pcall(vs3.wakeup, vs3)
        t:assert(not pre_ok, "a wake before any suspend is refused")

        local ring = kmes.attach(vs3, 0)
        t:assert(ring, "a ring attaches")
        t:assert_eq(kmes.emit(vs3, "PIT_SLEEP", kmes.PAYLOAD).ret, 0,
            "an event before sleeping")

        local w = vs3:spawn_worker()
        local ok2, err = pcall(function()
            local fd, e = sys.open(w, "/sysk/power/state", sys.O.WRONLY)
            t:assert(fd, "power/state opens: " .. sys.errname(e or 0))
            local pending = w:syscall_async(sys.NR.write, {
                args = { fd, 0, 3 }, bufs = { "mem" }, ptrs = { 1 },
            })
            wait_until(function() return pcall(vs3.wakeup, vs3) end,
                { timeout = 10, interval = "200ms",
                  desc = "the guest reaching S3" })
            local r = pending:await()
            t:assert_eq(r.ret, 3, "the suspend write returns after the wake: " ..
                sys.errname(r.errno))
        end)
        w:kill(); w:join()
        if not ok2 then error(err, 0) end

        t:assert_eq(kmes.emit(vs3, "PIT_SLEEP", kmes.PAYLOAD).ret, 0,
            "an event after waking")
        local events = kmes.of_type(kmes.drain(ring), "PIT_SLEEP")
        kmes.detach(ring)
        t:assert_eq(#events, 2, "both events are in the ring — it survived")
        t:assert_eq(events[2].sequence, events[1].sequence + 1,
            "with no sequence gap")
        local gap_ms = (events[2].timestamp - events[1].timestamp) // 1000000
        t:assert(gap_ms >= 150,
            "while the wall clock jumped by the sleep: " .. gap_ms .. " ms")
    end)
