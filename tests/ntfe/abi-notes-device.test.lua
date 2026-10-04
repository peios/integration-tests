-- PKM §6.B — the device: what `/dev/peios-ntfe` is, who may open it, and
-- what open(), read(), poll() and each ioctl do and refuse, errno by
-- errno; the ABI version guard and what version 5 changed; sequence
-- numbers, the gaps an overwritten ring leaves, and their running total.
--
-- Every call here is issued raw (helpers/ntfe_abi_notes): the subject is
-- the return value itself. The stream has one reader at a time, and the
-- read errnos are checked after the reader claim, so each test opens and
-- closes its own files and none uses the engine handle's stream — a file
-- left holding the claim would turn every later read into EBUSY.
--
-- Own VM: the policy and the verdict ring are machine-wide state.

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")
local raw = require("helpers.ntfe_abi_notes")
local token = require("helpers.token")

local vm = provium:vm("vntfeabidev", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))

local PASS_ALL = { all = { Actions = { "PASS" } } }

-- Port 7777 is dropped by the Packet layer, which an outbound datagram
-- meets at egress after its flow's sentence: past a flow's first
-- datagram, one datagram is exactly one event. Port 7300 counts into a
-- stream a SrcAddr view reads, so the counters dump has cells.
local POLICY = {
    RawPacket = PASS_ALL,
    Packet = {
        all = { Actions = { "PASS" } },
        sink = { ["DstPort.Equal"] = 7777, Actions = { "DROP" } },
        count = { ["DstPort.Equal"] = 7300, Actions = { "COUNT(hits)", "PASS" } },
        view = { ["DstPort.Equal"] = 1, ["Counter.hits(SrcAddr).GreaterThan"] = 4000000000,
                 Actions = { "DROP" } },
    },
    Flow = PASS_ALL,
}
local E = ntfe.engine(vm, POLICY)

-- The one datagram socket every test's events come from.
local sink = assert(ntfe.udp_connect(vm, "127.0.0.1", 7777))

-- A second process, whose read can block while the agent stays free.
local W = vm:spawn_worker()

--- `n` events, each one datagram into the sink.
local function events(n) return raw.flood(vm, sink, n) end

--- Make `fd` the reader and empty the ring. The sink's flow is touched
--- first: an unreplied UDP flow lives 30 s, and a fresh one's first
--- datagram is two events (its Flow judgment too), not one.
local function quiet(who, fd)
    raw.flood(vm, sink, 1)
    raw.drain(who, fd)
end

-- ---- stability ----

test("the status carries the ABI version, in its first word",
    { spec = "PKM *ntfe-abi-notes.status-abi-carries-version" }, function(t)
        local ret, errno, buf = raw.status_raw(vm, E.dev)
        t:assert_eq(ret, 0, "the status ioctl answers: " .. sys.errname(errno))
        t:assert_eq(string.unpack("<I8", buf, 1), 5, "`abi` is PEIOS_NTFE_ABI_VERSION, 5")
        t:assert_eq(E:status().abi, ntfe.ABI, "and it is the version these decoders are written to")
    end)

test("a consumer can check the version before trusting anything else in the record",
    { spec = "PKM *ntfe-abi-notes.consumer-checks-abi-first" }, function(t)
        -- The guard works because `abi` is the one field whose place no
        -- version moves: word 0. Every other offset is what a consumer
        -- trusts only after reading it.
        local _, _, buf = raw.status_raw(vm, E.dev)
        t:assert_eq(string.unpack("<I8", buf, 1), ntfe.ABI,
            "word 0 is the version, whatever follows it")
        local ret, errno = raw.status_raw(vm, E.dev, { size = 47 * 8 })
        t:assert_eq(errno, sys.E.NOTTY,
            "a consumer built for another layout is refused the struct rather than handed one: "
            .. ret)
        t:assert_eq(E:status().enforcing, 1,
            "so a consumer that checked it reads `enforcing` where version 5 puts it")
    end)

test("version 5 renamed the device, let many files open it, and grew the status by two words",
    { spec = "PKM *ntfe-abi-notes.abi-v5-changes" }, function(t)
        t:assert(sys.stat(vm, "/dev/peios-ntfe"), "the device is /dev/peios-ntfe")
        local _, gone = sys.stat(vm, "/dev/peios-pnp")
        t:assert_eq(gone, sys.E.NOENT, "and the `pnp` name is gone")
        local a, b = raw.open(vm), raw.open(vm)
        t:assert(ntfe.status(vm, a) and ntfe.status(vm, b),
            "two files hold it open at once, and both answer")
        sys.close(vm, a); sys.close(vm, b)
        local before = E:status()
        t:assert_eq(E:poke().ret, 0, "a registry write under the Network key")
        local noted = E:status().changes_noted
        t:assert_eq(noted, before.changes_noted + 1, "is counted in the status's `changes_noted`")
        local s = E:settle()
        t:assert_eq(s.changes_walked, noted, "and `changes_walked` catches up with it")
        t:assert_eq(s.contexts, 0, "and `contexts` is there: no interface has a network context here")
        t:assert_eq(ntfe.STATUS_SIZE, 46 * 8, "the status is 46 words")
        local ret, errno = raw.status_raw(vm, E.dev, { size = 44 * 8 })
        t:assert_eq(ret, -1, "a version-4 caller's 44-word STATUS command is not this ioctl")
        t:assert_eq(errno, sys.E.NOTTY, "and is refused as unknown")
    end)

-- ---- the device node ----

test("the device is a misc device, mode 0600, owned by root",
    { spec = "PKM *ntfe-abi-notes.device-misc-0600-root-only" }, function(t)
        local st = assert(sys.stat(vm, "/dev/peios-ntfe"))
        t:assert_eq(st.mode & 0xF000, 0x2000, "a character device")
        t:assert_eq(((raw.rdev(vm, "/dev/peios-ntfe")) >> 8) & 0xFFF, 10,
            "on the misc major")
        t:assert_eq(st.perm, 0x180, "mode 0600")
        t:assert_eq(st.uid, 0, "owned by root")
        t:assert_eq(st.gid, 0, "group root")
        token.as_principal(t, vm, {}, function(w)
            local fd, errno = sys.open(w, "/dev/peios-ntfe", sys.O.RDONLY)
            t:assert(not fd, "an ordinary user cannot open it")
            t:assert_eq(errno, sys.E.ACCES, "and is refused access")
        end)
    end)

test("any number of files may hold the device open",
    { spec = "PKM *ntfe-abi-notes.open-any-number-of-openers" }, function(t)
        local fds = {}
        for i = 1, 8 do
            local fd, errno = ntfe.open(vm)
            t:assert(fd, "opener " .. i .. " is let in: " .. sys.errname(errno or 0))
            fds[#fds + 1] = fd
        end
        local w = raw.open(W)
        t:assert(ntfe.status(W, w), "another process's opener too")
        for _, fd in ipairs(fds) do
            t:assert(ntfe.status(vm, fd), "and every one of them is served")
            sys.close(vm, fd)
        end
        sys.close(W, w)
    end)

-- ---- read() ----

test("a read blocked on an empty ring is interrupted by a signal",
    { spec = "PKM *ntfe-abi-notes.read-eintr" }, function(t)
        -- The worker is provium's own agent, a Rust program: std installs
        -- a SIGBUS handler (the guard-page check) without SA_RESTART. A
        -- SIGBUS sent to the thread blocked in read() runs it, it finds no
        -- fault and returns, and the read comes back EINTR.
        local pid = W:syscall(sys.NR.getpid).ret
        local status = raw.readfile(vm, "/proc/" .. pid .. "/status")
        local caught = tonumber(status:match("SigCgt:%s*(%x+)"), 16)
        t:assert(caught & (1 << (raw.SIGBUS - 1)) ~= 0,
            "precondition: the worker catches SIGBUS")

        local fd = raw.open(W)
        quiet(W, fd)
        raw.set_nonblock(W, fd, false)
        local pending = W:syscall_async(sys.NR.read, {
            args = { fd, 0, ntfe.EVENT_SIZE },
            bufs = { string.rep("\0", ntfe.EVENT_SIZE) }, ptrs = { 1 },
        })
        local tid = raw.blocked_thread(vm, pid, sys.NR.read)
        t:assert(tid, "a read of an empty ring without O_NONBLOCK blocks")
        if tid then vm:syscall(raw.NR.tgkill, pid, tid, raw.SIGBUS) end
        local r = pending:await()
        t:assert_eq(r.ret, -1, "until a signal arrives")
        t:assert_eq(r.errno, sys.E.INTR, "and it returns EINTR")
        sys.close(W, fd)
    end)

test("a non-blocking read of an empty ring is EAGAIN",
    { spec = "PKM *ntfe-abi-notes.read-eagain-empty-nonblocking" }, function(t)
        local fd = raw.open(vm)
        quiet(vm, fd)
        local ret, errno = raw.read(vm, fd, ntfe.EVENT_SIZE)
        t:assert_eq(ret, -1, "an empty ring gives nothing")
        t:assert_eq(errno, sys.E.AGAIN, "and says try again")
        events(1)
        ret = raw.read(vm, fd, ntfe.EVENT_SIZE)
        t:assert_eq(ret, ntfe.EVENT_SIZE, "and an event later is read")
        sys.close(vm, fd)
    end)

test("a read with room for less than one record is EINVAL",
    { spec = "PKM *ntfe-abi-notes.read-einval-len-below-one-record" }, function(t)
        local fd = raw.open(vm)
        quiet(vm, fd)
        events(2)
        local ret, errno = raw.read(vm, fd, ntfe.EVENT_SIZE - 1)
        t:assert_eq(ret, -1, "one byte short of a record is refused")
        t:assert_eq(errno, sys.E.INVAL, "as invalid")
        ret, errno = raw.read(vm, fd, 0)
        t:assert_eq(errno, sys.E.INVAL, "so is a zero-length read")
        ret = raw.read(vm, fd, ntfe.EVENT_SIZE)
        t:assert_eq(ret, ntfe.EVENT_SIZE, "exactly one record's room is enough")
        t:assert_eq(#raw.drain(vm, fd), 1, "and the refused reads consumed nothing")
        sys.close(vm, fd)
    end)

test("while one file is the stream's reader, another file's read is EBUSY",
    { spec = "PKM *ntfe-abi-notes.read-ebusy-other-file-is-reader" }, function(t)
        local a, b = raw.open(vm), raw.open(vm)
        quiet(vm, a)
        events(1)
        local ret, errno = raw.read(vm, b, ntfe.EVENT_SIZE)
        t:assert_eq(ret, -1, "the second file reads nothing")
        t:assert_eq(errno, sys.E.BUSY, "it is told the stream is busy")
        local w = raw.open(W)
        ret, errno = raw.read(W, w, ntfe.EVENT_SIZE)
        t:assert_eq(errno, sys.E.BUSY, "and so is another process")
        sys.close(W, w)
        t:assert(ntfe.status(vm, b), "its ioctls still answer")
        ret = raw.read(vm, a, ntfe.EVENT_SIZE)
        t:assert_eq(ret, ntfe.EVENT_SIZE, "the reader keeps reading")
        sys.close(vm, a)
        events(1)
        ret = raw.read(vm, b, ntfe.EVENT_SIZE)
        t:assert_eq(ret, ntfe.EVENT_SIZE, "once the reader closes, another file may take over")
        sys.close(vm, b)
    end)

test("a read returns whole records only, oldest first, and consumes them",
    { spec = "PKM *ntfe-abi-notes.read-whole-records-oldest-first" }, function(t)
        local fd = raw.open(vm)
        quiet(vm, fd)
        events(5)
        local ret, _, bytes = raw.read(vm, fd, ntfe.EVENT_SIZE * 2 + ntfe.EVENT_SIZE // 2)
        t:assert_eq(ret, 2 * ntfe.EVENT_SIZE,
            "room for two and a half records reads two: never a partial one")
        local first = raw.records(bytes)
        t:assert(first[1].seq < first[2].seq, "oldest first within a read")
        local rest = raw.drain(vm, fd)
        t:assert_eq(#rest, 3, "the two are consumed; the other three remain")
        t:assert(rest[1].seq > first[2].seq, "and are newer than what came before")
        for i = 2, #rest do
            t:assert(rest[i].seq > rest[i - 1].seq, "oldest first across reads")
        end
        for _, e in ipairs(rest) do
            t:assert_eq(e.dst_port, 7777, "each record is a whole event")
        end
        sys.close(vm, fd)
    end)

test("a read into an unmapped buffer is EFAULT",
    { spec = "PKM *ntfe-abi-notes.read-efault" }, function(t)
        local fd = raw.open(vm)
        quiet(vm, fd)
        events(1)
        local ret, errno = raw.read(vm, fd, ntfe.EVENT_SIZE, { addr = raw.BAD_ADDR })
        t:assert_eq(ret, -1, "nothing is copied to a page nobody mapped")
        t:assert_eq(errno, sys.E.FAULT, "it faults")
        sys.close(vm, fd)
    end)

test("a read that cannot allocate its batch is ENOMEM",
    { spec = "PKM *ntfe-abi-notes.read-enomem", covered_by = "kunit:pkm_kunit_ntfe",
      skip = "the batch is one GFP_KERNEL allocation of at most 64 records, which " ..
             "fails only under memory exhaustion; the kernel under test has no " ..
             "fault injection (CONFIG_FAULT_INJECTION is not set), so no guest " ..
             "action makes it fail; runs under " ..
             "ntfe_kunit_device_allocation_enomem, which refuses the batch " ..
             "through a KUnit-only seam and gets -ENOMEM with the ring untouched" },
    function(t) end)

-- ---- poll() ----

test("poll() reports the device readable exactly when an event waits",
    { spec = "PKM *ntfe-abi-notes.poll-readable-when-event-waits" }, function(t)
        local fd = raw.open(vm)
        quiet(vm, fd)
        t:assert_eq(ntfe.poll(vm, fd, ntfe.POLLIN | raw.POLLRDNORM, 0), 0,
            "an empty ring is not readable")
        events(1)
        t:assert_eq(ntfe.poll(vm, fd, ntfe.POLLIN | raw.POLLRDNORM, 0),
            ntfe.POLLIN | raw.POLLRDNORM, "one waiting event raises POLLIN | POLLRDNORM")
        raw.drain(vm, fd)
        t:assert_eq(ntfe.poll(vm, fd, ntfe.POLLIN, 0), 0, "and reading it lowers it again")
        sys.close(vm, fd)
    end)

-- ---- the ioctls ----

test("the status ioctl fills the snapshot, its counters cumulative since boot",
    { spec = "PKM *ntfe-abi-notes.status-ioctl-fills-snapshot" }, function(t)
        local ret, errno, buf = raw.status_raw(vm, E.dev)
        t:assert_eq(ret, 0, "it succeeds")
        t:assert_eq(#buf, ntfe.STATUS_SIZE, "over the whole structure")
        local before = E:status()
        events(3)
        -- A changed policy: an identical one publishes nothing.
        POLICY.Packet.extra = { ["DstPort.Equal"] = 2, Actions = { "PASS" } }
        local s = E:replace(POLICY)
        t:assert_eq(s.generation, before.generation + 1, "a new generation is published")
        for _, name in ipairs({ "seen_egress", "seen_local_out", "judged",
                                "verdict_drop", "verdict_pass" }) do
            t:assert(s[name] >= before[name], name .. " is not reset by it")
        end
        t:assert(s.verdict_drop >= before.verdict_drop + 3, "and keeps counting")
        t:assert_eq(E.zero.generation, 0, "the first status this file read was from before any policy")
        t:assert(s.seen_egress > E.zero.seen_egress,
            "and the counters have grown from it, not restarted: they run since boot")
        ret, errno = raw.status_raw(vm, E.dev, { addr = raw.BAD_ADDR })
        t:assert_eq(ret, -1, "a status buffer nobody mapped is not filled")
        t:assert_eq(errno, sys.E.FAULT, "it faults")
    end)

--- Datagrams to the counting port from `n` source addresses: n cells.
local function counted_from(n)
    for i = 1, n do
        local fd = assert(ntfe.udp_connect(vm, "127.0.0.1", 7300,
            { bind = { "127.0.0." .. i, 0 } }))
        ntfe.send(vm, fd, "c")
        sys.close(vm, fd)
    end
end

test("the counters dump writes what fits and says how many cells exist",
    { spec = "PKM *ntfe-abi-notes.counters-ioctl-count-and-total" }, function(t)
        counted_from(3)
        local all = raw.dump(vm, E.dev, "counters", 64)
        t:assert_eq(all.ret, 0, "the dump succeeds")
        t:assert(all.total >= 3, "every source address has a cell: " .. tostring(all.total))
        t:assert_eq(all.count, all.total, "with room for all, all are written")
        local short = raw.dump(vm, E.dev, "counters", 1)
        t:assert_eq(short.ret, 0, "a buffer with room for one is not an error")
        t:assert_eq(short.count, 1, "one record is written")
        t:assert_eq(short.total, all.total, "and `total` still counts every cell")
        local none = raw.dump(vm, E.dev, "counters", 0)
        t:assert_eq(none.ret, 0, "nor is a buffer with no room")
        t:assert_eq(none.count, 0, "nothing is written")
        t:assert_eq(none.total, all.total, "and the cells are still counted")
    end)

test("the counters dump faults on a query or a buffer nobody mapped",
    { spec = "PKM *ntfe-abi-notes.counters-ioctl-efault" }, function(t)
        counted_from(1)
        local q = raw.dump(vm, E.dev, "counters", 1, { query_addr = raw.BAD_ADDR })
        t:assert_eq(q.errno, sys.E.FAULT, "an unmapped query is EFAULT")
        local b = raw.dump(vm, E.dev, "counters", 4, { buf_addr = raw.BAD_ADDR })
        t:assert_eq(b.ret, -1, "a record bound for an unmapped buffer is not written")
        t:assert_eq(b.errno, sys.E.FAULT, "it is EFAULT")
    end)

test("the counters dump is ENOMEM when its record cannot be allocated",
    { spec = "PKM *ntfe-abi-notes.counters-ioctl-enomem", covered_by = "kunit:pkm_kunit_ntfe",
      skip = "the dump's one record is a GFP_KERNEL allocation that fails only " ..
             "under memory exhaustion; the kernel under test has no fault " ..
             "injection (CONFIG_FAULT_INJECTION is not set); runs under " ..
             "ntfe_kunit_device_allocation_enomem, which refuses that " ..
             "allocation through a KUnit-only seam and gets -ENOMEM" },
    function(t) end)

test("the flows dump writes what fits and says how many live flows it saw",
    { spec = "PKM *ntfe-abi-notes.flows-ioctl-count-and-total" }, function(t)
        for port = 7400, 7403 do
            local fd = assert(ntfe.udp_connect(vm, "127.0.0.1", port))
            ntfe.send(vm, fd, "f")
            sys.close(vm, fd)
        end
        local all = raw.dump(vm, E.dev, "flows", 256)
        t:assert_eq(all.ret, 0, "the dump succeeds")
        t:assert(all.total >= 4, "the flows just made are live: " .. tostring(all.total))
        t:assert_eq(all.count, all.total, "with room for all, all are written")
        local short = raw.dump(vm, E.dev, "flows", 2)
        t:assert_eq(short.ret, 0, "a short buffer is not an error")
        t:assert_eq(short.count, 2, "it holds what fits")
        t:assert(short.total >= 4, "and `total` counts what the walk saw")
    end)

test("the flows dump faults on a query or a buffer nobody mapped",
    { spec = "PKM *ntfe-abi-notes.flows-ioctl-efault" }, function(t)
        events(1)
        local q = raw.dump(vm, E.dev, "flows", 1, { query_addr = raw.BAD_ADDR })
        t:assert_eq(q.errno, sys.E.FAULT, "an unmapped query is EFAULT")
        local b = raw.dump(vm, E.dev, "flows", 4, { buf_addr = raw.BAD_ADDR })
        t:assert_eq(b.ret, -1, "records bound for an unmapped buffer are not written")
        t:assert_eq(b.errno, sys.E.FAULT, "it is EFAULT")
    end)

test("the flows dump is ENOMEM when its batch cannot be allocated",
    { spec = "PKM *ntfe-abi-notes.flows-ioctl-enomem", covered_by = "kunit:pkm_kunit_ntfe",
      skip = "the batch is one GFP_KERNEL allocation of 32 records, which fails " ..
             "only under memory exhaustion; the kernel under test has no fault " ..
             "injection (CONFIG_FAULT_INJECTION is not set); runs under " ..
             "ntfe_kunit_device_allocation_enomem, which refuses that " ..
             "allocation through a KUnit-only seam and gets -ENOMEM" },
    function(t) end)

test("the listeners dump faults on a query or a buffer nobody mapped",
    { spec = "PKM *ntfe-abi-notes.listeners-ioctl-efault" }, function(t)
        local l = assert(ntfe.udp_bind(vm, "127.0.0.1", 7500))
        local q = raw.dump(vm, E.dev, "listeners", 1, { query_addr = raw.BAD_ADDR })
        t:assert_eq(q.errno, sys.E.FAULT, "an unmapped query is EFAULT")
        local b = raw.dump(vm, E.dev, "listeners", 4, { buf_addr = raw.BAD_ADDR })
        t:assert_eq(b.ret, -1, "records bound for an unmapped buffer are not written")
        t:assert_eq(b.errno, sys.E.FAULT, "it is EFAULT")
        sys.close(vm, l)
    end)

test("the listeners dump is ENOMEM when its batch cannot be allocated",
    { spec = "PKM *ntfe-abi-notes.listeners-ioctl-enomem", covered_by = "kunit:pkm_kunit_ntfe",
      skip = "the batch is one GFP_KERNEL allocation of 32 records, which fails " ..
             "only under memory exhaustion; the kernel under test has no fault " ..
             "injection (CONFIG_FAULT_INJECTION is not set); runs under " ..
             "ntfe_kunit_device_allocation_enomem, which refuses that " ..
             "allocation through a KUnit-only seam and gets -ENOMEM" },
    function(t) end)

test("any other ioctl is ENOTTY",
    { spec = "PKM *ntfe-abi-notes.unknown-ioctl-enotty" }, function(t)
        for _, cmd in ipairs({
            ntfe.ioc(3, 5, 24),   -- the next number in NTFE's type byte
            ntfe.ioc(3, 2, 32),   -- COUNTERS' number with another size
            (3 << 30) | (24 << 16) | (0x4B << 8) | 2, -- another type byte
            0,
        }) do
            local r = vm:syscall(sys.NR.ioctl, {
                args = { E.dev, cmd, 0 }, bufs = { string.rep("\0", 64) }, ptrs = { 2 },
            })
            t:assert_eq(r.ret, -1, string.format("command %#x is not answered", cmd))
            t:assert_eq(r.errno, sys.E.NOTTY, string.format("command %#x is ENOTTY", cmd))
        end
    end)

-- ---- sequence numbers ----

test("sequence numbers rise for the whole boot, across readers",
    { spec = "PKM *ntfe-abi-notes.sequence-monotonic-per-boot" }, function(t)
        local a = raw.open(vm)
        quiet(vm, a)
        events(4)
        local first = raw.drain(vm, a)
        sys.close(vm, a)
        local b = raw.open(vm)
        events(4)
        local second = raw.drain(vm, b)
        sys.close(vm, b)
        t:assert_eq(#first, 4, "the first reader reads its four")
        t:assert_eq(#second, 4, "the second reader its four")
        local all = {}
        for _, e in ipairs(first) do all[#all + 1] = e.seq end
        for _, e in ipairs(second) do all[#all + 1] = e.seq end
        for i = 2, #all do
            t:assert_eq(all[i], all[i - 1] + 1, "each record is the next number, with no restart")
        end
        t:assert(all[1] > 0, "and the count began before this test: it is per boot")
    end)

test("a gap in the sequence is exactly the number of records the ring overwrote",
    { spec = "PKM *ntfe-abi-notes.sequence-gap-equals-overwritten" }, function(t)
        local fd = raw.open(vm)
        quiet(vm, fd)
        events(1)
        local last = raw.drain(vm, fd)
        t:assert_eq(#last, 1, "one record read")
        local s0 = E:status()
        events(4096 + 100)
        local lost = E:status().events_dropped - s0.events_dropped
        t:assert(lost > 0, "the reader stayed away long enough to lose some")
        local after = raw.drain(vm, fd)
        t:assert_eq(after[1].seq - last[1].seq - 1, lost,
            "the gap to the next record read is the number overwritten")
        for i = 2, #after do
            t:assert_eq(after[i].seq, after[i - 1].seq + 1, "and there is no other gap")
        end
        sys.close(vm, fd)
    end)

test("events_dropped is the running total of overwritten records",
    { spec = "PKM *ntfe-abi-notes.events-dropped-running-total" }, function(t)
        local fd = raw.open(vm)
        quiet(vm, fd)
        local s0 = E:status()
        events(4096 + 100)
        local s1 = E:status()
        t:assert_eq(s1.events_dropped - s0.events_dropped, raw.emitted(s0, s1) - 4096,
            "what did not fit is counted")
        raw.drain(vm, fd)
        t:assert_eq(E:status().events_dropped, s1.events_dropped, "reading does not reset it")
        events(4096 + 7)
        local s2 = E:status()
        t:assert_eq(s2.events_dropped - s1.events_dropped, raw.emitted(s1, s2) - 4096,
            "and the next overwrite adds to it")
        raw.drain(vm, fd)
        sys.close(vm, fd)
    end)
