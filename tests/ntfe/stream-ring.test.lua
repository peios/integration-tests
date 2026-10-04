-- PKM §6.7 — the ring and its reader: /dev/peios-ntfe as a misc device
-- any number of files may hold open, the one drain the first reader
-- claims, whole records up to 64 per read, blocking and non-blocking
-- reads, poll, a reader that reconnects, and a full ring that loses its
-- oldest events and confesses the loss.
--
-- The reader claim is device-wide, so this file never uses the engine
-- handle's own stream: every test opens, claims and closes its files
-- itself, and closes them before the next test runs. Traffic is empty
-- UDP datagrams on loopback under a policy that passes everything —
-- each one is judged four times (egress Packet and RawPacket, ingress
-- RawPacket, LOCAL_IN Packet) once its flow has a sentence.
--
-- Own VM: the ring and its reader are machine-wide state.

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")
local stream = require("helpers.ntfe_stream")

local vm = provium:vm("vntfering", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))

local PASS_ALL = { all = { Actions = { "PASS" } } }
local E = ntfe.engine(vm, { RawPacket = PASS_ALL, Packet = PASS_ALL, Flow = PASS_ALL })

-- Readers on other processes: spawned here so their files outlive no
-- test by accident (each test closes what it opened).
local wa = vm:spawn_worker()
local wb = vm:spawn_worker()

local tx = stream.udp_pair(vm, 7100)
-- The flow's first datagram writes its sentences; every later one is
-- the steady four events.
assert(ntfe.send(vm, tx, "").ret == 0)

local NONBLOCK = sys.O.RDONLY | 0x800
local EV = ntfe.EVENT_SIZE

local function contiguous(list)
    for i = 2, #list do
        if list[i].seq ~= list[i - 1].seq + 1 then return false, i end
    end
    return true
end

-- Leave the ring empty and unclaimed for the next test.
local function settle_ring()
    local fd = assert(ntfe.open(vm, NONBLOCK))
    assert(stream.drain(vm, fd))
    sys.close(vm, fd)
end
settle_ring()

-- ---- the device -------------------------------------------------------

test("/dev/peios-ntfe is a misc character device of mode 0600",
    { spec = "PKM *ntfe-stream.device-misc-mode-0600" }, function(t)
        local r = vm:syscall(sys.NR.newfstatat, {
            args = { sys.AT_FDCWD, 0, 0, 0 },
            bufs = { sys.cstr(ntfe.DEVICE), string.rep("\0", 144) },
            ptrs = { 1, 2 },
        })
        t:assert_eq(r.ret, 0, "the node exists: " .. sys.errname(r.errno))
        local mode = string.unpack("<I4", r.out_bufs[2], 25)
        local rdev = string.unpack("<I8", r.out_bufs[2], 41)
        t:assert_eq(mode & 0xF000, sys.S_IFCHR, "it is a character device")
        t:assert_eq(mode & 0xFFF, 384, "of mode 0600")
        t:assert_eq((rdev >> 8) & 0xFFF, 10, "on the misc major")
        t:assert_contains(vm:read_file("/proc/misc"), "peios-ntfe",
            "registered with the misc driver under its name")
    end)

test("any number of files may be open while one of them holds the stream",
    { spec = "PKM *ntfe-stream.device-many-openers" }, function(t)
        local reader = assert(ntfe.open(wa, NONBLOCK))
        t:assert(ntfe.read_events(wa, reader), "a viewer on another process claims the stream")
        local tools = {}
        for i = 1, 16 do
            local fd, errno = ntfe.open(vm)
            t:assert(fd, "open number " .. i .. " is allowed: " .. sys.errname(errno or 0))
            tools[#tools + 1] = fd
        end
        local other = assert(ntfe.open(wb), "and from a third process")
        for _, fd in ipairs(tools) do
            local s = ntfe.status(vm, fd)
            t:assert(s and s.abi == ntfe.ABI, "every one of them is asked the status meanwhile")
        end
        t:assert(ntfe.status(wb, other), "including the third process's")
        t:assert(ntfe.flows(vm, tools[1]), "and the dumps")
        for _, fd in ipairs(tools) do sys.close(vm, fd) end
        sys.close(wb, other)
        sys.close(wa, reader)
    end)

test("the first file to read() claims the ring until it closes; another file's read() is EBUSY",
    { spec = "PKM *ntfe-stream.first-reader-claims-ring-others-ebusy" }, function(t)
        -- All three are open before anyone reads: opening claims nothing.
        local a = assert(ntfe.open(wa, NONBLOCK))
        local b = assert(ntfe.open(vm, NONBLOCK))
        local c = assert(ntfe.open(wb, NONBLOCK))
        assert(ntfe.send(vm, tx, "").ret == 0)
        local first = ntfe.read_events(wa, a)
        t:assert(first and #first >= 1, "the first reader drains what waits")
        local _, eb = ntfe.read_events(vm, b)
        t:assert_eq(eb, sys.E.BUSY, "a second file's read is EBUSY")
        local _, ec = ntfe.read_events(wb, c)
        t:assert_eq(ec, sys.E.BUSY, "and so is a third process's")
        t:assert(ntfe.read_events(wa, a), "an empty read keeps the claim")
        assert(ntfe.send(vm, tx, "").ret == 0)
        _, eb = ntfe.read_events(vm, b)
        t:assert_eq(eb, sys.E.BUSY, "events waiting do not loosen it")
        sys.close(wa, a)
        local taken = ntfe.read_events(vm, b)
        t:assert(taken and #taken >= 1,
            "once the reader closes, the next file to read claims the ring and finds what waited")
        _, ec = ntfe.read_events(wb, c)
        t:assert_eq(ec, sys.E.BUSY, "and holds it against everyone else in turn")
        sys.close(vm, b)
        sys.close(wb, c)
    end)

-- ---- reading ----------------------------------------------------------

test("read() returns whole records only, oldest first, at most 64 per call",
    { spec = "PKM *ntfe-stream.read-whole-records-up-to-64" }, function(t)
        local fd = assert(ntfe.open(vm, NONBLOCK))
        assert(stream.drain(vm, fd))
        t:assert_eq(stream.burst(vm, tx, 30), 30, "thirty datagrams sent")
        local all = {}
        local r = stream.read_raw(vm, fd, 65 * EV)
        t:assert_eq(r.ret, 64 * EV, "a buffer for 65 records gets 64")
        for at = 1, r.ret, EV do all[#all + 1] = ntfe.decode_event(r.out_bufs[1], at) end
        r = stream.read_raw(vm, fd, 2 * EV - 1)
        t:assert_eq(r.ret, EV, "a buffer for one and a half gets exactly one")
        all[#all + 1] = ntfe.decode_event(r.out_bufs[1], 1)
        r = stream.read_raw(vm, fd, EV - 1)
        t:assert_eq(r.errno, sys.E.INVAL, "a buffer for less than one gets none")
        local rest = assert(stream.drain(vm, fd))
        for _, e in ipairs(rest) do all[#all + 1] = e end
        t:assert_eq(#all, 120, "every event is read once: four per datagram")
        t:assert(contiguous(all), "in sequence order, the short read having consumed nothing")
        sys.close(vm, fd)
    end)

test("read() blocks on an empty ring unless the file is O_NONBLOCK",
    { spec = "PKM *ntfe-stream.read-blocks-unless-nonblock" }, function(t)
        local nb = assert(ntfe.open(vm, NONBLOCK))
        assert(stream.drain(vm, nb))
        local r = stream.read_raw(vm, nb, EV)
        t:assert_eq(r.errno, sys.E.AGAIN, "a non-blocking read of the empty ring is EAGAIN")
        sys.close(vm, nb)

        local fd = assert(ntfe.open(wa, sys.O.RDONLY))
        assert(stream.drain(wa, fd))
        local pending = wa:syscall_async(sys.NR.read, {
            args = { fd, 0, 64 * EV }, bufs = { string.rep("\0", 64 * EV) }, ptrs = { 1 },
        })
        sys.nanosleep(vm, 0, 300 * 1000 * 1000)
        local sent_at = stream.now_ns(vm)
        assert(ntfe.send(vm, tx, "").ret == 0)
        local got = pending:await()
        t:assert(got.ret > 0, "a blocking read waits for an event rather than failing: "
            .. sys.errname(got.errno or 0))
        t:assert_eq(got.ret % EV, 0, "and returns whole records")
        for at = 1, got.ret, EV do
            local e = ntfe.decode_event(got.out_bufs[1], at)
            t:assert(e.t_ns >= sent_at,
                "made of events that did not exist until 300 ms after it was issued")
        end
        sys.close(wa, fd)
    end)

test("poll() raises POLLIN when events wait, and wakes a waiting poller",
    { spec = "PKM *ntfe-stream.poll-pollin-when-events-wait" }, function(t)
        local fd = assert(ntfe.open(vm, NONBLOCK))
        assert(stream.drain(vm, fd))
        t:assert_eq(ntfe.poll(vm, fd, ntfe.POLLIN, 0), 0, "an empty ring is not readable")
        assert(ntfe.send(vm, tx, "").ret == 0)
        local revents = ntfe.poll(vm, fd, ntfe.POLLIN | stream.POLLRDNORM, 0)
        t:assert(revents & ntfe.POLLIN ~= 0, "an event waiting is POLLIN")
        t:assert(revents & stream.POLLRDNORM ~= 0, "and POLLRDNORM")
        assert(stream.drain(vm, fd))
        t:assert_eq(ntfe.poll(vm, fd, ntfe.POLLIN, 0), 0, "drained, it is not readable again")

        local wfd = assert(ntfe.open(wb, NONBLOCK))
        local pending = wb:syscall_async(sys.NR.poll, {
            args = { 0, 1, 5000 },
            bufs = { string.pack("<i4i2i2", wfd, ntfe.POLLIN, 0) }, ptrs = { 0 },
        })
        sys.nanosleep(vm, 0, 200 * 1000 * 1000)
        assert(ntfe.send(vm, tx, "").ret == 0)
        local woke = pending:await()
        t:assert_eq(woke.ret, 1, "a poller sleeping on the device is woken by the event")
        t:assert(select(3, string.unpack("<i4I2I2", woke.out_bufs[1])) & ntfe.POLLIN ~= 0,
            "with POLLIN")
        sys.close(wb, wfd)
        sys.close(vm, fd)
        settle_ring()
    end)

test("a reader that reconnects resumes from whatever the ring still holds",
    { spec = "PKM *ntfe-stream.reconnect-resumes-from-ring" }, function(t)
        local a = assert(ntfe.open(vm, NONBLOCK))
        assert(stream.drain(vm, a))
        assert(ntfe.send(vm, tx, "").ret == 0)
        local seen = assert(stream.drain(vm, a))
        t:assert(#seen >= 1, "the first connection reads an event")
        local last = seen[#seen].seq
        sys.close(vm, a)
        t:assert_eq(stream.burst(vm, tx, 3), 3, "three datagrams while nobody reads")
        local b = assert(ntfe.open(wa, NONBLOCK))
        local resumed = assert(stream.drain(wa, b))
        t:assert_eq(#resumed, 12, "a new reader on another process finds all twelve events")
        t:assert_eq(resumed[1].seq, last + 1, "starting exactly after the last one read")
        t:assert(contiguous(resumed), "with no gap: nothing was lost")
        sys.close(wa, b)
    end)

-- ---- a full ring --------------------------------------------------------

test("a full ring of 4096 overwrites its oldest events and confesses each one",
    { spec = "PKM *ntfe-stream.ring-4096-events-irqsave-lock PKM *ntfe-stream.full-ring-overwrites-oldest PKM *ntfe-stream.confess-events-dropped PKM *ntfe-stream.reconnect-resumes-from-ring" },
    function(t)
        local a = assert(ntfe.open(vm, NONBLOCK))
        assert(stream.drain(vm, a))
        assert(ntfe.send(vm, tx, "").ret == 0)
        local marker = assert(stream.drain(vm, a))
        local last = marker[#marker].seq
        sys.close(vm, a)

        local before = E:status()
        t:assert_eq(stream.burst(vm, tx, 1500), 1500, "1500 datagrams: some 6000 events")
        local after = E:status()
        local dropped = after.events_dropped - before.events_dropped
        local emitted = after.judged - before.judged
        t:assert(emitted > stream.RING, "more evaluations than the ring holds: " .. emitted)

        local b = assert(ntfe.open(vm, NONBLOCK))
        local held = assert(stream.drain(vm, b))
        sys.close(vm, b)
        t:assert_eq(#held, stream.RING, "the ring holds exactly 4096 events")
        t:assert(contiguous(held), "a contiguous run")
        t:assert_eq(held[#held].seq, last + emitted,
            "ending with the newest: nothing recent was refused")
        t:assert_eq(held[1].seq - last - 1, emitted - stream.RING,
            "and the oldest were the ones lost")
        t:assert_eq(dropped, emitted - stream.RING,
            "every overwritten event is counted in events_dropped")
        t:assert_eq(held[1].seq - last - 1, dropped,
            "and the gap a reconnecting reader sees in the sequence is exactly that count")
    end)
