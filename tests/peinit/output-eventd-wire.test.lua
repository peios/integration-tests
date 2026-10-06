-- Peinit TRM §11.4 — the eventd handoff, read off the wire — and the
-- parts of §11.1 and §11.3 that only the wire shows.
--
-- output-eventd.test.lua reads what eventd made of peinit's traffic. This
-- file reads the traffic itself. eventd is a poor witness for most of
-- §11.4: it decodes each datagram and keeps what it likes, so the framing
-- is gone by the time a query can see it; it drops any record whose origin
-- is not a bare identifier, so every hook, health-check and submitted-job
-- line is invisible through it; and its receive buffer is not something a
-- test can fill on demand, which is what a drop needs.
--
-- The lever is `Machine\System\eventd\LogSocketPath`. peinit reads it at
-- boot and again on every reload (§10.4); eventd reads it once and defers
-- any change until it restarts. So once a test binds `pt-logsink` at a
-- path of its own and points the key there, every datagram peinit would
-- have sent eventd arrives at the tool instead — the same bytes, from the
-- same socket, under the same rules — and the receiver is one the test
-- controls: it can decode every datagram, refuse to read, or be full
-- before peinit can reach it.
--
-- eventd itself stays Active throughout, which matters: peinit forwards
-- only while eventd is Active (§11.4 step 1), and nothing here wants to
-- test that rule by accident. The tests run in order on one boot, each
-- with a receiver of its own, because each points the key somewhere new.

local peinit = require("helpers.peinit")
peinit.claim(1)

-- One gigabyte and one vCPU, as every chapter 11 file: a boot is waiting
-- on I/O, not compute, and provium admits VMs by declared size.
local MEM, CPUS = "1G", 1

-- Numbered lines, so a test can say which ones arrived rather than how
-- many. The padding makes each line about a hundred bytes, which is the
-- unit the budget and capacity arithmetic below is done in.
--
--   emit.sh TAG COUNT [DELAY]
--
-- DELAY is slept before the first line, for a job whose submitter needs
-- to finish talking before the job starts.
local EMIT = [[#!/bin/sh
tag=$1
count=$2
[ -n "$3" ] && sleep "$3"
i=0
while [ $i -lt "$count" ]; do
    echo "$tag-$i-................................................................................"
    i=$((i + 1))
done
]]

-- Thirty lines of exactly ninety-nine characters and a newline: three
-- thousand bytes that `cat` writes with a single write(2). Below
-- PIPE_BUF, so the pipe takes it atomically and peinit sees all of it or
-- none of it at once.
local BURST_LINES, BURST_WIDTH = 30, 99
local burst = {}
for i = 0, BURST_LINES - 1 do
    local head = string.format("pt-burst-%02d-", i)
    burst[#burst + 1] = head .. string.rep("b", BURST_WIDTH - #head) .. "\n"
end
local BURST = table.concat(burst)

-- A health check that says something on each stream and passes.
local HEALTH = [[#!/bin/sh
echo "pt-hc-said-on-stdout"
echo "pt-hc-said-on-stderr" >&2
exit 0
]]

local vm = peinit.boot({
    memory = MEM, cpus = CPUS,
    name = "wire",
    files = peinit.merge(
        peinit.tool("pt-logsink"),
        {
            ["lcl/pt/emit.sh"] = { EMIT, exec = true },
            ["lcl/pt/burst.txt"] = BURST,
            ["lcl/pt/hc.sh"] = { HEALTH, exec = true },
        },
        peinit.seed("zz-pt-wire", {
            { path = [[Machine\System]] },
            { path = [[Machine\System\Services]] },
            {
                path = [[Machine\System\Services\pt-hc]],
                values = {
                    { name = "ImagePath", type = "sz", data = "/bin/sleep" },
                    { name = "Arguments", type = "multi", data = { "3600" } },
                    { name = "Identity", type = "sz", data = "SYSTEM" },
                    { name = "Readiness", type = "dword", data = 1 },
                    { name = "Triggers", type = "multi", data = { "boot" } },
                    { name = "HealthCheck", type = "sz", data = "/bin/sh /lcl/pt/hc.sh" },
                    { name = "HealthCheckInterval", type = "dword", data = 2 },
                    { name = "HealthCheckRetries", type = "dword", data = 3 },
                    { name = "RestartWindow", type = "dword", data = 120 },
                },
            },
        })
    ),
})

wait_until(function()
    return vm:run("svctl status eventd").stdout:find("eventd: active", 1, true)
end, { timeout = 60, interval = 1, desc = "eventd to be Active, so that peinit is forwarding" })

-- The receiver's queue, not peinit's: a Unix datagram socket takes this
-- many datagrams before its senders see EAGAIN, and the default of ten is
-- small enough that a burst arriving while the tool is writing its report
-- could be dropped. Raising it keeps the tests that want every datagram
-- from depending on the scheduler. The tests that want a full queue fill
-- whatever it is (`--fill`).
vm:run("echo 256 > /proc/sys/net/unix/max_dgram_qlen"):assert_ok()

---------------------------------------------------------------------------
-- The receiver.

--- Start a pt-logsink called `name` and wait until it is bound.
---
--- opts.fill  the queue is full before the socket is reachable
--- opts.hold  the tool reads nothing until `release` is called
local function listen(name, opts)
    opts = opts or {}
    local sink = {
        sock = "/run/pt-" .. name .. ".sock",
        log = "/run/pt-" .. name .. ".log",
        hold = "/run/pt-" .. name .. ".hold",
    }
    local flags = ""
    if opts.fill then flags = flags .. " --fill" end
    if opts.hold then
        vm:run("touch " .. sink.hold):assert_ok()
        flags = flags .. " --hold " .. sink.hold
    end
    vm:run("/usr/bin/pt-logsink listen " .. sink.sock .. " " .. sink.log .. flags ..
        " > /dev/null 2>&1 &"):assert_ok()
    sink.filled = wait_until(function()
        local ok, text = pcall(function() return vm:read_file(sink.log) end)
        return ok and tonumber(text:match("ready path=%S+ inode=%d+ filled=(%d+)")) or nil
    end, { timeout = 15, interval = 0.2, desc = "pt-logsink " .. name .. " to bind" })
    return sink
end

--- Let a held receiver read, and wait until it has read back the
--- datagrams it was filled with — until then its queue is still full, and
--- anything offered in the meantime would be refused for that reason
--- rather than for the one under test.
local function release(sink)
    vm:run("rm -f " .. sink.hold):assert_ok()
    wait_until(function()
        local ok, text = pcall(function() return vm:read_file(sink.log) end)
        if not ok then return false end
        local drained = 0
        for _ in text:gmatch("format=other head=70742d6c6f6773696e6b2d66696c6c") do
            drained = drained + 1
        end
        return drained >= sink.filled
    end, { timeout = 30, interval = 0.2, desc = "the receiver to read back its filler" })
end

--- Point peinit at `path`. The explicit reload is what makes it take
--- effect now: the registry watch would reload too, but asynchronously,
--- and a test that writes a line straight after has to know which socket
--- the line will go to.
local function point_at(path)
    vm:run([[reg set 'Machine\System\eventd' LogSocketPath sz:]] .. path):assert_ok()
    vm:run("svctl reload-config"):assert_ok()
end

--- Everything the receiver has reported, as a list of datagrams, each
--- with its records in order.
local function datagrams(sink)
    local ok, text = pcall(function() return vm:read_file(sink.log) end)
    local list, by_number = {}, {}
    if not ok then return list end
    for line in text:gmatch("[^\n]+") do
        local d = tonumber(line:match("^dgram d=(%d+)"))
        if d then
            local datagram = {
                d = d,
                line = line,
                format = line:match(" format=(%S+)"),
                bytes = tonumber(line:match(" bytes=(%d+)")),
                count = tonumber(line:match(" records=(%d+)")),
                trailing = tonumber(line:match(" trailing=(%d+)")),
                records = {},
            }
            list[#list + 1] = datagram
            by_number[d] = datagram
        elseif line:find("^rec ") then
            local owner = by_number[tonumber(line:match("^rec d=(%d+)"))]
            if owner then
                owner.records[#owner.records + 1] = {
                    d = owner.d,
                    line = line,
                    entries = tonumber(line:match(" entries=(%d+)")),
                    keys = line:match(" keys=(%S*)"),
                    types = line:match(" types=(%S*)"),
                    origin = line:match(" origin=(%S+)"),
                    is_error = line:match(" is_error=(%S+)"),
                    timestamp = tonumber(line:match(" timestamp=(%d+)")),
                    job_id = line:match(" job_id=(%S+)"),
                    message = line:match(" message=(.*)$"),
                }
            end
        end
    end
    return list
end

--- A one-line account of what a receiver got, for assertion messages.
local function summary(sink)
    local formats, origins = {}, {}
    local list = datagrams(sink)
    for _, datagram in ipairs(list) do
        formats[datagram.format or "?"] = (formats[datagram.format or "?"] or 0) + 1
        for _, record in ipairs(datagram.records) do
            origins[record.origin or "?"] = (origins[record.origin or "?"] or 0) + 1
        end
    end
    local parts = { #list .. " datagrams" }
    for k, v in pairs(formats) do parts[#parts + 1] = k .. "=" .. v end
    for k, v in pairs(origins) do parts[#parts + 1] = k .. ":" .. v end
    return table.concat(parts, " ")
end

--- Every record from `origin`, in arrival order.
local function records_from(sink, origin)
    local out = {}
    for _, datagram in ipairs(datagrams(sink)) do
        for _, record in ipairs(datagram.records) do
            if record.origin == origin then out[#out + 1] = record end
        end
    end
    return out
end

--- Records whose message starts with `prefix`, polled until `want` have
--- arrived or the wait runs out.
local function wait_for_lines(sink, prefix, want, timeout)
    local found = {}
    pcall(wait_until, function()
        found = {}
        for _, datagram in ipairs(datagrams(sink)) do
            for _, record in ipairs(datagram.records) do
                if record.message and record.message:sub(1, #prefix) == prefix then
                    found[#found + 1] = record
                end
            end
        end
        return #found >= want
    end, { timeout = timeout or 20, interval = 0.5, desc = want .. " lines of " .. prefix })
    return found
end

--- Submit a job and wait for it to end. Returns its id and its origin.
local function submit(args)
    local r = vm:run("svctl job submit --wait " .. args)
    local id = r.stdout:match("job ([%x-]+):")
    assert(id, "svctl reported no job: " .. r.stdout .. r.stderr)
    return id, "jobs/" .. id
end

--- The descriptor in PID 1's table that is connected to `sink`, and its
--- socket inode — found by asking sock_diag who is connected to the tool
--- and matching the answer against /proc/1/fd.
local function peinit_socket(sink)
    local peers = {}
    for inode in vm:run("/usr/bin/pt-logsink peers " .. sink.sock).stdout:gmatch("peer inode=(%d+)") do
        peers[inode] = true
    end
    -- PID 1's table is listed by the agent: PID 1 is TCB-signed, and PIP
    -- refuses the shell's `ls` its /proc.
    for fd, inode in peinit.fd_listing(vm, 1):gmatch("(%d+) %-> socket:%[(%d+)%]") do
        if peers[inode] then return fd, inode end
    end
end

--- Make peinit take a turn. It forwards and replays at the end of a turn,
--- and a turn needs an event; a control request is one that has no other
--- effect.
local function poke(times)
    for _ = 1, times or 1 do vm:run("svctl status eventd") end
end

local function index_of(message)
    return tonumber(message:match("^%S-%-(%d+)%-"))
end

---------------------------------------------------------------------------
-- A receiver that reads everything, for the tests that want every datagram.

local steady = listen("steady")
point_at(steady.sock)

test("every datagram is one msgpack array of one or more records, and nothing else",
    {
        spec = {
            "peinit *eventd.a-datagram-holds-a-msgpack-array-of-records",
            "peinit *eventd.the-job-id-is-omitted-when-there-is-none",
        },
    },
    function(t)
        -- Three lines in one write, so peinit reads them in one event and
        -- has three records to put in one datagram; and a line on stderr,
        -- written separately, so there is a second pipe and a second
        -- datagram.
        local id, origin = submit([[/bin/sh -c "printf 'pt-array-1\npt-array-2\npt-array-3\n'; ]] ..
            [[sleep 1; echo pt-array-err >&2"]])
        local mine = wait_for_lines(steady, "pt-array-", 4)
        t:assert_eq(#mine, 4, "all four lines reached the receiver")

        -- Every datagram the receiver got, from any producer, is a whole
        -- msgpack array: the first byte is an array header, the elements
        -- decode as records, and nothing follows the last one.
        local all = datagrams(steady)
        t:assert(#all > 0, "the receiver got datagrams")
        for _, datagram in ipairs(all) do
            t:assert_eq(datagram.format, "array",
                "datagram " .. datagram.d .. " is a msgpack array: " .. datagram.line)
            t:assert_eq(datagram.trailing, 0,
                "with nothing after the array: " .. datagram.line)
            t:assert(datagram.count >= 1, "of at least one record: " .. datagram.line)
            t:assert_eq(#datagram.records, datagram.count,
                "every element of it decoded as a record: " .. datagram.line)
        end

        -- One or more: the three lines written together went out as one
        -- array of three, not as three datagrams.
        local together = mine[1]
        t:assert_eq(together.message, "pt-array-1", "the first line came first")
        local siblings = 0
        for _, record in ipairs(mine) do
            if record.d == together.d then siblings = siblings + 1 end
        end
        t:assert_eq(siblings, 3, "and the three lines written in one write share one datagram")

        -- Each record is a map of the five fields, with the job's 16-byte
        -- identifier present because every captured line has a job behind
        -- it. (The four-entry form, for a record with no job, is the unit
        -- test this file's companion stub names.)
        for _, record in ipairs(mine) do
            t:assert_eq(record.origin, origin, "the record names the job that wrote it")
            t:assert_eq(record.entries, 5, "a record with a job is a five-entry map: " .. record.line)
            t:assert_eq(record.keys, "origin,is_error,message,timestamp,job_id",
                "keyed as §11.4 lists them")
            t:assert_eq(record.types, "str,bool,str,uint,bin",
                "with the types §11.4 gives: string, bool, string, uint, bin")
            t:assert_eq(record.job_id, (id:gsub("-", "")),
                "and the bin is the job's own 16-byte GUID")
        end
    end)

test("a record with no job identifier is a four-entry map with no job_id key",
    {
        spec = "peinit *eventd.the-job-id-is-omitted-when-there-is-none",
        covered_by = "cargo:peinit2 logging::msgpack::tests::a_record_without_a_job_id_is_a_four_entry_map",
        skip = "every record peinit forwards is read from a pipe registered for a job, and registration always " ..
            "gives the pipe that job's id (runtime/logging/service_pipes/registration.rs), so no guest action " ..
            "produces a record without one; runs under cargo test -p peinit2 --all-features --lib " ..
            "logging::msgpack::tests::a_record_without_a_job_id_is_a_four_entry_map",
    },
    function(t) end)

test("one readable event reads at most LogReadBytesPerEvent from the pipe",
    { spec = "peinit *flood.the-read-budget-bounds-one-readable-event" },
    function(t)
        -- A datagram is what one readable event produced: peinit reads the
        -- pipe, frames the lines it completed and sends them before it
        -- returns to epoll. So the datagrams a single write turns into
        -- are a direct count of the events it took to read.

        -- At the default budget, three thousand bytes written at once are
        -- read in one event.
        local _, before = submit("/bin/cat /lcl/pt/burst.txt")
        local lines = wait_for_lines(steady, "pt-burst-", BURST_LINES)
        t:assert_eq(#lines, BURST_LINES, "the whole burst arrived")
        local events = {}
        for _, record in ipairs(records_from(steady, before)) do events[record.d] = true end
        local count = 0
        for _ in pairs(events) do count = count + 1 end
        t:assert_eq(count, 1, "and at the default budget it took one readable event")

        -- At the minimum, the same write takes several, and none of them
        -- carries more than the budget plus the part-line left over from
        -- the event before.
        local BUDGET = 512
        vm:run([[reg set 'Machine\System\Init' LogReadBytesPerEvent dword:]] .. BUDGET):assert_ok()
        vm:run("svctl reload-config"):assert_ok()
        local _, after = submit("/bin/cat /lcl/pt/burst.txt")
        wait_for_lines(steady, "pt-burst-", 2 * BURST_LINES)
        vm:run([[reg set 'Machine\System\Init' LogReadBytesPerEvent dword:16384]]):assert_ok()
        vm:run("svctl reload-config"):assert_ok()

        local per_event, order = {}, {}
        local total = 0
        for _, record in ipairs(records_from(steady, after)) do
            if not per_event[record.d] then
                per_event[record.d] = 0
                order[#order + 1] = record.d
            end
            -- The line and the newline that ended it: the bytes read.
            per_event[record.d] = per_event[record.d] + #record.message + 1
            total = total + 1
        end
        t:assert_eq(total, BURST_LINES, "the whole burst arrived again")
        t:assert(#order >= math.ceil(BURST_LINES * (BURST_WIDTH + 1) / (BUDGET + BURST_WIDTH)),
            "and this time it took " .. #order .. " readable events rather than one")
        for _, d in ipairs(order) do
            t:assert(per_event[d] <= BUDGET + BURST_WIDTH,
                "no event yielded more than the budget plus one carried part-line: " ..
                per_event[d] .. " bytes in datagram " .. d)
        end
    end)

test("health check output is captured and forwarded under <service>/HealthCheck",
    { spec = "peinit *output.health-check-output-is-captured" },
    function(t)
        -- pt-hc's check runs every two seconds and writes one line to
        -- each stream. peinit captures both and forwards them like any
        -- other job's output, under the origin §11.1 gives a health check.
        --
        -- The receiver rather than eventd, because eventd discards any
        -- record whose origin is not a bare identifier — a known eventd
        -- limitation that output-wiring.test.lua's known-bug case
        -- describes — and `pt-hc/HealthCheck` is not one. What peinit
        -- does with the output is this page's claim, and that is visible
        -- on the wire.
        local said = {}
        wait_until(function()
            for _, record in ipairs(records_from(steady, "pt-hc/HealthCheck")) do
                said[record.message] = record.is_error
            end
            return said["pt-hc-said-on-stdout"] and said["pt-hc-said-on-stderr"]
        end, { timeout = 30, interval = 1, desc = "a health check's output on the wire" })
        t:assert_eq(said["pt-hc-said-on-stdout"], "false", "the check's stdout line was captured")
        t:assert_eq(said["pt-hc-said-on-stderr"], "true", "and its stderr line, marked as an error")
    end)

test("a sink that would block loses lines for the sink only, and says so once",
    { spec = "peinit *output.a-blocked-sink-write-drops-one-line-and-reports-once" },
    function(t)
        -- The sink is a FIFO whose reader opens it and then reads nothing
        -- until told to. A thousand lines of a hundred bytes is well past
        -- the sixty-four kilobytes a pipe holds, so peinit's non-blocking
        -- write to the sink starts failing with EAGAIN part-way through.
        --
        -- No `--wait`: svctl's own report goes to its standard output,
        -- which IS the sink, and would queue behind the job's lines. The
        -- job sleeps a second first, so svctl's acknowledgement is written
        -- and svctl has exited before the job says anything.
        local COUNT = 1000
        vm:run("mkfifo /run/pt-slow.fifo && touch /run/pt-slow.hold"):assert_ok()
        vm:run("sh -c 'exec 3< /run/pt-slow.fifo; " ..
            "while [ -e /run/pt-slow.hold ]; do sleep 0.1; done; " ..
            "cat <&3 > /run/pt-slow.out; echo pt-eof >> /run/pt-slow.out' > /dev/null 2>&1 &"):assert_ok()
        vm:run("svctl job submit --output /bin/sh /lcl/pt/emit.sh pt-sinkdrop " .. COUNT ..
            " 1 > /run/pt-slow.fifo"):assert_ok()

        -- The record is not the sink: every line reached the log socket,
        -- whatever happened to the copy.
        local recorded = wait_for_lines(steady, "pt-sinkdrop-", COUNT, 40)
        t:assert_eq(#recorded, COUNT, "every line of the job was recorded")
        local origin = recorded[1].origin
        local id = origin:match("^jobs/(.+)$")
        t:assert(id, "the lines came from a submitted job: " .. tostring(origin))

        -- Now let the reader drain the FIFO. The sink closes when the
        -- job's pipes do, so the reader sees end-of-file.
        vm:run("rm -f /run/pt-slow.hold"):assert_ok()
        local copy = wait_until(function()
            local ok, text = pcall(function() return vm:read_file("/run/pt-slow.out") end)
            return ok and text:find("pt-eof", 1, true) and text or nil
        end, { timeout = 30, interval = 0.5, desc = "the sink reader to reach end-of-file" })
        local copied = 0
        for _ in copy:gmatch("pt%-sinkdrop%-%d+%-") do copied = copied + 1 end
        t:assert(copied > 0, "the sink got the lines that fitted")
        t:assert(copied < COUNT,
            "and lost the rest: " .. copied .. " of " .. COUNT .. " reached the blocked sink")

        -- One event, however many lines were lost. The event names the
        -- job by `object.job.guid`, a bin.guid that evctl's JSON prints as
        -- `{"$binary": hex}` of the PCDS GUID — the first three fields of
        -- the UUID byte-reversed — so that is the form looked for.
        local function pcds_hex(uuid)
            local hex = uuid:lower():gsub("[^%x]", "")
            local out = {}
            for _, i in ipairs({ 4, 3, 2, 1, 6, 5, 8, 7, 9, 10, 11, 12, 13, 14, 15, 16 }) do
                out[#out + 1] = hex:sub(2 * i - 1, 2 * i)
            end
            return table.concat(out)
        end
        local guid = pcds_hex(id)
        local events = 0
        wait_until(function()
            events = 0
            local out = vm:run(
                "evctl 'EVENTS peinit.job.output.dropped SINCE 1h ago TAKE 200' --format jsonl").stdout
            for line in out:gmatch("[^\r\n]+") do
                if line:lower():find(guid, 1, true) then events = events + 1 end
            end
            return events > 0
        end, { timeout = 30, interval = 1, desc = "a peinit.job.output.dropped event for the job" })
        vm:run("sleep 2")
        events = 0
        for line in vm:run("evctl 'EVENTS peinit.job.output.dropped SINCE 1h ago TAKE 200' --format jsonl")
            .stdout:gmatch("[^\r\n]+") do
            if line:lower():find(guid, 1, true) then events = events + 1 end
        end
        t:assert_eq(events, 1,
            "exactly one peinit.job.output.dropped event for the job, though " .. (COUNT - copied) ..
            " lines were dropped")
    end)

test("the internal drop count rises by one per line a blocked sink loses",
    {
        spec = "peinit *output.a-blocked-sink-write-drops-one-line-and-reports-once",
        covered_by = "cargo:peinit2 runtime::logging::tests::a_sink_that_would_block_counts_each_dropped_line_and_reports_the_first",
        skip = "the per-job drop count is internal bookkeeping that no event, status field or reply exposes; " ..
            "runs under cargo test -p peinit2 --all-features --lib " ..
            "runtime::logging::tests::a_sink_that_would_block_counts_each_dropped_line_and_reports_the_first",
    },
    function(t) end)

---------------------------------------------------------------------------
-- A receiver that is full before peinit can reach it.

local full = listen("full", { fill = true, hold = true })

test("a full receiver drops datagrams without breaking the connection, and PID 1 never waits on it",
    {
        spec = {
            "peinit *eventd.a-drop-leaves-the-connection-standing",
            "peinit *eventd.peinit-never-blocks-on-a-send",
            "peinit *flood.delivery-downstream-of-the-pipe-is-loss-tolerant",
        },
    },
    function(t)
        t:assert(full.filled > 0, "the receiver's queue was filled before it was exposed")
        point_at(full.sock)

        -- A hundred kilobytes, while every datagram peinit offers is
        -- refused. More than the sixty-four kilobytes the job's own pipe
        -- holds, so the job can only finish if peinit keeps reading the
        -- pipe — which is the no-drop guarantee at the pipe — while
        -- everything it reads is lost at the socket, which is the lossy
        -- delivery the guarantee does not cover.
        local started = os.time()
        local _, flooded = submit("/bin/sh /lcl/pt/emit.sh pt-lost 1000")
        t:assert(os.time() - started < 20,
            "the job ran to completion, so peinit drained its pipe into a full receiver")

        -- PID 1 is not waiting on the socket: it answers at once, and the
        -- socket it sends on is non-blocking.
        local asked = os.time()
        vm:run("svctl status eventd"):assert_ok()
        t:assert(os.time() - asked <= 2, "peinit answered a control request promptly")

        local fd, inode = peinit_socket(full)
        t:assert(fd, "PID 1 holds a socket connected to the receiver")
        local flags = tonumber(vm:read_file("/proc/1/fdinfo/" .. fd):match("flags:%s*(%d+)"), 8)
        t:assert(flags & tonumber("04000", 8) ~= 0,
            "and it is non-blocking (flags " .. string.format("0%o", flags) .. ")")

        -- Let the receiver read. It gets the datagrams it was filled with
        -- and nothing of the job's: those were refused, and a refused
        -- datagram is gone — not buffered, not re-sent.
        release(full)
        local _, later = submit("/bin/sh /lcl/pt/emit.sh pt-after 20")
        local after = wait_for_lines(full, "pt-after-", 20)
        poke(3)
        t:assert_eq(#after, 20,
            "forwarding carried on: everything written after the drops arrived (" ..
            summary(full) .. ")")
        t:assert_eq(#records_from(full, flooded), 0,
            "and none of what was dropped came back later")
        for _, record in ipairs(after) do
            t:assert_eq(record.origin, later, "the lines that arrived are the later job's")
        end

        -- On the same connection. A transport failure would have discarded
        -- this socket and connected a new one.
        local fd_after, inode_after = peinit_socket(full)
        t:assert_eq(inode_after, inode,
            "PID 1 is still sending on the socket it had before the drops (fd " ..
            tostring(fd) .. " then " .. tostring(fd_after) .. ")")
    end)

---------------------------------------------------------------------------
-- A replay into a full receiver.

test("a replay that meets a full receiver waits for it, and loses nothing",
    {
        spec = {
            "peinit *eventd.a-drop-during-replay-waits-rather-than-loses",
            "peinit *eventd.a-failed-datagram-advances-the-replay-by-nothing",
        },
    },
    function(t)
        -- Nothing is bound at the path yet, so every send fails and peinit
        -- keeps what it reads in the pre-eventd buffer, in order.
        local path = "/run/pt-replay.sock"
        point_at(path)
        local _, origin = submit("/bin/sh /lcl/pt/emit.sh pt-replay 40")

        -- Now a receiver appears at that path, already full. peinit's
        -- next replay reaches it and has its datagram refused.
        local sink = listen("replay", { fill = true, hold = true })
        t:assert_eq(sink.sock, path, "the receiver took the path peinit is pointed at")
        poke(3)
        t:assert(peinit_socket(sink),
            "peinit connected to the full receiver, so it tried to deliver the replay there")

        -- Let it read, and give peinit a turn to try again.
        release(sink)
        poke(3)
        local replayed = wait_for_lines(sink, "pt-replay-", 40)
        t:assert_eq(#replayed, 40, "every buffered line was delivered once the receiver read")

        -- In order, from the first, and each exactly once: the refused
        -- attempt advanced the buffer by nothing, and the one that got
        -- through advanced it by everything it carried.
        for i, record in ipairs(replayed) do
            t:assert_eq(record.origin, origin, "the line is the job's")
            t:assert_eq(index_of(record.message), i - 1,
                "line " .. (i - 1) .. " arrived in its place: " .. record.message)
        end
    end)
