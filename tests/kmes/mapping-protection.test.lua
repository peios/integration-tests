-- PEI-241 / PEI-485 item 3: exercise the real mixed-permission VMA,
-- including write faults, GUP writes, and permission-induced VMA splits.
local sys = require("helpers.sys")
local kmes = require("helpers.kmes")
local vm = provium:vm("v", "kernel-only"):boot()
local PAGE, READ, RW = 4096, sys.PROT.READ, sys.PROT.READ | sys.PROT.WRITE
local PROCESS_VM_WRITEV = 311

local function with_ring(t, body)
    local ring, errno = kmes.attach(vm, 0)
    t:assert(ring, "attach ring: " .. sys.errname(errno or 0))
    local ok, err = pcall(body, ring)
    kmes.detach(ring)
    if not ok then error(err, 0) end
end

local function protect(addr, len, prot)
    return vm:syscall(sys.NR.mprotect, addr, len, prot)
end

local function remote_write(caller, pid, addr, bytes)
    return caller:syscall(PROCESS_VM_WRITEV, {
        args = { pid, 0, 1, 0, 1, 0 },
        bufs = { string.pack("<I8I8", 0, #bytes),
                 string.pack("<I8I8", addr, #bytes), bytes },
        ptrs = { 1, 3 },
        nested = { { parent = 1, child = 3, offset = 0 } },
    })
end

local function protected_offsets(ring)
    return { 0, 2 * PAGE, 2 * PAGE + ring.capacity }
end

test("mprotect permits only the KMES consumer page to be writable",
    { spec = "PKM *consumer.mapping-permissions" }, function(t)
        with_ring(t, function(ring)
            for _, offset in ipairs(protected_offsets(ring)) do
                t:assert_eq(protect(ring.addr + offset, PAGE, RW).errno,
                    sys.E.ACCES, "producer and both data aliases reject write permission")
            end
            t:assert_eq(protect(ring.addr, ring.length, RW).errno, sys.E.ACCES,
                "a whole-ring request cannot upgrade protected pages")
            t:assert_eq(protect(ring.addr + PAGE, 2 * PAGE, RW).errno, sys.E.ACCES,
                "consumer permission cannot spill into the first data page")
            t:assert_eq(protect(ring.addr + PAGE, PAGE, RW).ret, 0,
                "consumer page can reassert write access")
            t:assert_eq(protect(ring.addr + PAGE, PAGE, READ).ret, 0)
            t:assert_eq(protect(ring.addr + PAGE, PAGE, RW).ret, 0,
                "consumer page can regain write access after losing it")
            t:assert(kmes.poke(vm, ring.addr + PAGE, "\x00"))
        end)
    end)

test("GUP writes reach need_wake without making producer or data writable",
    { spec = "PKM *consumer.mapping-permissions" }, function(t)
        with_ring(t, function(ring)
            local pid = vm:syscall(sys.NR.getpid).ret
            -- No prior mprotect: the initially mapped consumer page must work.
            t:assert_eq(remote_write(vm, pid, ring.addr + PAGE, "\x01").ret, 1)
            t:assert_eq(vm:read_mem(ring.addr + PAGE, 1), "\x01")
            for _, offset in ipairs(protected_offsets(ring)) do
                local before = vm:read_mem(ring.addr + offset, 1)
                t:assert_eq(remote_write(vm, pid, ring.addr + offset, "\xa5").errno,
                    sys.E.FAULT, "GUP must not fault protected PTEs writable")
                t:assert(not kmes.poke(vm, ring.addr + offset, "\xa5"),
                    "ordinary copy-to-user write fault is also rejected")
                t:assert_eq(vm:read_mem(ring.addr + offset, 1), before)
            end
            t:assert_eq(remote_write(vm, pid, ring.addr + PAGE, "\x00").ret, 1)
        end)
    end)

test("KMES permission offsets survive VMA splits",
    { spec = "PKM *consumer.mapping-permissions" }, function(t)
        with_ring(t, function(ring)
            -- Splitting off the producer moves vm_start of the remainder.
            -- A check based on vm_start+PAGE would now select the first data page.
            t:assert_eq(protect(ring.addr, PAGE, READ).ret, 0)
            t:assert_eq(protect(ring.addr + 2 * PAGE, PAGE, RW).errno, sys.E.ACCES)
            t:assert_eq(protect(ring.addr + PAGE, PAGE, READ).ret, 0)
            t:assert_eq(protect(ring.addr + PAGE, PAGE, RW).ret, 0)
            -- Split both aliases as well, then retry their first and next pages.
            for _, offset in ipairs({ 2 * PAGE, 2 * PAGE + ring.capacity }) do
                t:assert_eq(protect(ring.addr + offset, PAGE, READ).ret, 0)
                t:assert_eq(protect(ring.addr + offset, PAGE, RW).errno, sys.E.ACCES)
                t:assert_eq(protect(ring.addr + offset + PAGE, PAGE, RW).errno, sys.E.ACCES)
            end
            local pid = vm:syscall(sys.NR.getpid).ret
            t:assert_eq(remote_write(vm, pid, ring.addr + PAGE, "\x00").ret, 1)
        end)
    end)

test("a supervisor can set a worker consumer's need_wake",
    { spec = "PKM *consumer.mapping-permissions" }, function(t)
        local worker = vm:spawn_worker()
        local fd, addr, length
        local ok, err = pcall(function()
            local attached = worker:syscall(kmes.SYS.ATTACH, {
                args = { 0, 0 }, bufs = { string.rep("\0", 8) }, ptrs = { 1 },
            })
            t:assert(attached.ret >= 0, "worker attaches")
            fd = attached.ret
            length = 2 * PAGE + 2 * string.unpack("<I8", attached.out_bufs[1])
            local mapped = worker:syscall(sys.NR.mmap, 0, length, RW, sys.MAP.SHARED, fd, 0)
            t:assert(mapped.ret > 0, "worker maps ring")
            addr = mapped.ret
            local pid = worker:syscall(sys.NR.getpid).ret
            t:assert_eq(remote_write(vm, pid, addr + PAGE, "\x01").ret, 1,
                "authorized supervisor writes need_wake through GUP")
            t:assert_eq(kmes.peek(worker, addr + PAGE, 1), "\x01")
            t:assert_eq(remote_write(vm, pid, addr + PAGE, "\x00").ret, 1)
        end)
        if addr then sys.munmap(worker, addr, length) end
        if fd then sys.close(worker, fd) end
        worker:close()
        if not ok then error(err, 0) end
    end)
