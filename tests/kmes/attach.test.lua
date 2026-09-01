-- PKM §2.4 — kmes_attach: the privilege gate, slot discovery, the
-- returned descriptor's contract, and the shared-ring semantics of
-- attaching twice.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local kmes = require("helpers.kmes")

local vm = provium:vm("v", "kernel-only"):boot()

test("attach returns a descriptor and writes back the capacity",
    { spec = "PKM *attach.capacity-and-fd-contract" }, function(t)
        local r = vm:syscall(kmes.SYS.ATTACH, {
            args = { 0, 0 },
            bufs = { string.rep("\0", 8) },
            ptrs = { 1 },
        })
        t:assert(r.ret >= 0, "an fd comes back: " .. sys.errname(r.errno))
        local capacity = string.unpack("<I8", r.out_bufs[1])
        t:assert_eq(capacity, kmes.DEFAULT.BUFFER_CAPACITY,
            "the capacity is the compiled-in default")
        -- The fd supports exactly two operations, mmap and close: the
        -- ordinary file verbs are refused.
        t:assert(vm:syscall(sys.NR.read, {
            args = { r.ret, 0, 16 },
            bufs = { string.rep("\0", 16) }, ptrs = { 1 },
        }).ret < 0, "read on it fails")
        t:assert(vm:syscall(sys.NR.write, {
            args = { r.ret, 0, 4 }, bufs = { "nope" }, ptrs = { 1 },
        }).ret < 0, "write on it fails")
        local addr = sys.mmap(vm, r.ret, 8192 + 2 * capacity,
            sys.PROT.READ | sys.PROT.WRITE, sys.MAP.SHARED)
        t:assert(addr, "while mmap of 8192 + 2 x capacity succeeds")
        sys.munmap(vm, addr, 8192 + 2 * capacity)
        t:assert_eq(sys.close(vm, r.ret).ret, 0, "as does close")
    end)

test("the mapped ring leads with the magic and version",
    { spec = "PKM *abi.ring-mapping-layout" }, function(t)
        local ring = kmes.attach(vm, 0)
        t:assert(ring, "a ring attaches")
        t:assert_eq(ring.magic, "KMESRING", "page 0 begins with KMES_RING_MAGIC")
        t:assert_eq(ring.version, 1, "then KMES_RING_VERSION")
        local head = vm:read_mem(ring.addr, 32)
        t:assert_eq(string.unpack("<I2", head, 13), 0,
            "the producer page records its cpu_id")
        t:assert_eq(string.unpack("<I8", head, 17), ring.capacity,
            "and the capacity, where the offsets table says")
        t:assert_eq(string.unpack("<I8", head, 25), 8192,
            "and the data offset: two metadata pages, then the data")
        kmes.detach(ring)
    end)

test("KMES_ATTACH_QUERY_SLOTS answers the slot count and opens nothing",
    { spec = "PKM *attach.query-slots" }, function(t)
        local r = vm:syscall(kmes.SYS.ATTACH, {
            args = { kmes.ATTACH_QUERY_SLOTS, 0 },
            bufs = { string.rep("\0", 8) },
            ptrs = { 1 },
        })
        t:assert_eq(r.ret, 0, "the query returns 0, not a descriptor: " ..
            sys.errname(r.errno))
        local slots = string.unpack("<I8", r.out_bufs[1])
        t:assert_eq(slots, 1,
            "one slot on this single-CPU VM, written through capacity")
    end)

test("an index at or beyond the slot array is EINVAL",
    { spec = "PKM *attach.slots-sized-by-nr-cpu-ids" }, function(t)
        local ring, errno = kmes.attach(vm, 1)
        t:assert(not ring, "cpu 1 on a 1-CPU VM does not attach")
        t:assert_eq(errno, sys.E.INVAL, sys.errname(errno))
        local _, errno = kmes.attach(vm, 4096)
        t:assert_eq(errno, sys.E.INVAL, "as is one far beyond it")
    end)

test("attach wants SeSecurityPrivilege, enabled",
    { spec = "PKM *attach.privilege-gate" }, function(t)
        kacs.as_dacl_bound(t, vm, function(worker)
            local r = worker:syscall(kmes.SYS.ATTACH, {
                args = { 0, 0 },
                bufs = { string.rep("\0", 8) },
                ptrs = { 1 },
            })
            t:assert_eq(r.errno, sys.E.PERM,
                "attach without it: " .. sys.errname(r.errno))
            -- The query form takes the same gate (§2.B).
            r = worker:syscall(kmes.SYS.ATTACH, {
                args = { kmes.ATTACH_QUERY_SLOTS, 0 },
                bufs = { string.rep("\0", 8) },
                ptrs = { 1 },
            })
            t:assert_eq(r.errno, sys.E.PERM,
                "and the slot query too: " .. sys.errname(r.errno))
        end, { privs = kmes.PRIV.SECURITY })
    end)

test("an unwritable capacity pointer is EFAULT",
    { spec = "PKM *attach.errors" }, function(t)
        local r = vm:syscall(kmes.SYS.ATTACH, 0, 0xdead0000)
        t:assert_eq(r.errno, sys.E.FAULT, sys.errname(r.errno))
        r = vm:syscall(kmes.SYS.ATTACH, kmes.ATTACH_QUERY_SLOTS, 0xdead0000)
        t:assert_eq(r.errno, sys.E.FAULT,
            "the query writes through the same pointer: " .. sys.errname(r.errno))
    end)

test("a faulting write-back closes the descriptor it installed",
    { spec = "PKM *attach.writeback-fault-closes-fd" }, function(t)
        -- 400 attaches whose capacity pointer faults: if each leaked
        -- its installed fd, the table would hold 400 strays and the
        -- next good attach would come back with a high number. It
        -- comes back low — the EFAULT path closed every one.
        for i = 1, 400 do
            local r = vm:syscall(kmes.SYS.ATTACH, 0, 0xdead0000)
            t:assert_eq(r.errno, sys.E.FAULT, "faulting attach " .. i)
        end
        local good = vm:syscall(kmes.SYS.ATTACH, {
            args = { 0, 0 }, bufs = { string.rep("\0", 8) }, ptrs = { 1 },
        })
        t:assert(good.ret >= 0, "a good attach still succeeds")
        t:assert(good.ret < 100,
            "with a low fd — nothing leaked: fd " .. good.ret)
        sys.close(vm, good.ret)
    end)

test("the query form's error vocabulary has no EINVAL",
    { spec = "PKM *attach.query-slots-errors" }, function(t)
        -- The sentinel is outside the index space, so the query cannot
        -- be an invalid index: it answers 0 whenever the caller is
        -- privileged and the pointer writable, and its failures are
        -- only the gate's and the pointer's.
        for _ = 1, 3 do
            local r = vm:syscall(kmes.SYS.ATTACH, {
                args = { kmes.ATTACH_QUERY_SLOTS, 0 },
                bufs = { string.rep("\0", 8) }, ptrs = { 1 },
            })
            t:assert_eq(r.ret, 0, "the query always answers")
        end
        t:assert_eq(vm:syscall(kmes.SYS.ATTACH, kmes.ATTACH_QUERY_SLOTS,
            0xdead0000).errno, sys.E.FAULT, "EFAULT for the pointer")
        kacs.as_dacl_bound(t, vm, function(worker)
            t:assert_eq(worker:syscall(kmes.SYS.ATTACH, {
                args = { kmes.ATTACH_QUERY_SLOTS, 0 },
                bufs = { string.rep("\0", 8) }, ptrs = { 1 },
            }).errno, sys.E.PERM, "EPERM for the gate — and nothing else")
        end, { privs = kmes.PRIV.SECURITY })
    end)

test("every fd for one CPU drains the same ring",
    { spec = "PKM *attach.shared-ring-many-fds" }, function(t)
        -- Repeated attaches return new fds onto one ring: both mappings
        -- see the same events, each consumer keeping its own position
        -- in its own memory (the cursor here is a Lua variable — KMES
        -- holds no per-consumer state to diverge).
        local a = kmes.attach(vm, 0)
        local b = kmes.attach(vm, 0)
        t:assert(a and b, "two attaches to cpu 0")
        t:assert(a.fd ~= b.fd, "with distinct descriptors")
        t:assert_eq(kmes.emit(vm, "PIT_SHARED", kmes.PAYLOAD).ret, 0,
            "one event emits")
        local from_a = kmes.of_type(kmes.drain(a), "PIT_SHARED")
        local from_b = kmes.of_type(kmes.drain(b), "PIT_SHARED")
        t:assert_eq(#from_a, 1, "the first consumer sees it")
        t:assert_eq(#from_b, 1, "and so does the second")
        t:assert_eq(from_a[1].sequence, from_b[1].sequence,
            "as the same event, not a copy")
        -- Closing one fd releases nothing the other needs.
        kmes.detach(a)
        t:assert_eq(kmes.emit(vm, "PIT_SHARED2", kmes.PAYLOAD).ret, 0,
            "another event after the first consumer detached")
        t:assert_eq(#kmes.of_type(kmes.drain(b), "PIT_SHARED2"), 1,
            "still reaches the survivor")
        kmes.detach(b)
    end)
