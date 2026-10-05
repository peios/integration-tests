-- Peinit TRM §11.1 — wiring: where a service's output goes.
--
-- peinit is not a logging system, but it holds the pipes at birth, and
-- almost every claim on this page is about descriptors. Descriptors are
-- the one thing a booted Linux shows you honestly: `/proc/<pid>/fd`
-- names what a service was handed, `/proc/1/fd` names what peinit kept,
-- and `/proc/<pid>/fdinfo/<fd>` gives the open flags on each end. So the
-- tests here read both ends of the same pipe rather than asserting that
-- a pipe "is non-blocking".
--
-- The exceptions are the tagging and the job sink, which are claims
-- about what comes out the far end: eventd's store for the record, and
-- the submitter's own descriptor for the copy.

local peinit = require("helpers.peinit")
peinit.claim(1)

-- One gigabyte rather than the helper's two. Chapter 11 boots more
-- machines than any other chapter here — a claim about output usually
-- needs a whole boot arranged around it — and provium reserves declared
-- memory for the life of a VM, so at the default these files queue
-- against the pool and each other. A booted guest uses about 300 MB
-- between its working set and the squashfs page cache, and the same
-- assertions hold at either size.
--
-- One vCPU for the same reason: provium admits VMs while the total
-- declared vCPU count fits the host's cores, so two apiece halves how
-- many of these boots can be in flight at once. Nothing here is
-- compute-bound.
local MEM, CPUS = "1G", 1

-- A service that writes one identifiable line to each stream and stays
-- resident, plus one that asks for a terminal. Both are seeded rather
-- than borrowed from the image, because the assertions below need to
-- know exactly what was written and to which stream.
local say = [[#!/bin/sh
echo "pt-wiring-stdout-marker"
echo "pt-wiring-stderr-marker" >&2
while : ; do sleep 30; done
]]

-- /dev/tty2, not /dev/console: the console is login-console's, and
-- peinit's own progress output goes there too. A spare virtual terminal
-- isolates the claim from both.
local onterminal = [[#!/bin/sh
# `tty` names fd 0 through ttyname(3), which needs FILE_READ_ATTRIBUTES
# on the handle. Without that right the call fails and this records the
# failure instead, which is exactly the distinction being tested.
tty > /run/pt-tty-name 2>&1
echo "pt-terminal-service-marker"
while : ; do sleep 30; done
]]

local vm = peinit.boot({
    memory = MEM, cpus = CPUS,
    name = "wiring",
    files = peinit.merge(
        {
            ["lcl/pt/say.sh"] = { say, exec = true },
            ["lcl/pt/onterminal.sh"] = { onterminal, exec = true },
            -- Staged without the execute bit, which under KACS is the
            -- intrinsic "this is executable" flag: a job naming it is
            -- accepted and then fails between fork and exec, so it never
            -- runs and never has pipes for the runtime to read.
            ["lcl/pt/not-executable"] = "#!/bin/sh\necho pt-never-ran\n",
        },
        peinit.seed("zz-pt-wiring", {
            { path = [[Machine\System]] },
            { path = [[Machine\System\Services]] },
            {
                path = [[Machine\System\Services\pt-say]],
                values = {
                    { name = "ImagePath", type = "sz", data = "/lcl/pt/say.sh" },
                    { name = "Identity", type = "sz", data = "SYSTEM" },
                    { name = "Readiness", type = "dword", data = 1 },
                    { name = "Triggers", type = "multi", data = { "boot" } },
                },
            },
            {
                path = [[Machine\System\Services\pt-onterminal]],
                values = {
                    { name = "ImagePath", type = "sz", data = "/lcl/pt/onterminal.sh" },
                    { name = "Identity", type = "sz", data = "SYSTEM" },
                    { name = "Readiness", type = "dword", data = 1 },
                    { name = "TTYPath", type = "sz", data = "/dev/tty2" },
                    { name = "Triggers", type = "multi", data = { "boot" } },
                },
            },
        })
    ),
})

--- Wait until eventd is serving. Nothing peinit forwards is queryable
--- before that: until eventd reaches Active the records are in the
--- pre-eventd buffer, which is §11.2's subject rather than this page's.
local function wait_for_eventd(vm)
    for _ = 1, 60 do
        if vm:run("svctl status eventd").stdout:find("eventd: active") then return true end
        vm:run("sleep 1")
    end
    return false
end

--- The log records eventd holds, newest first, as raw JSONL lines.
--- Retried, because forwarding is asynchronous: peinit reads the pipe,
--- batches, and sends on a later turn of its loop, so a query issued the
--- instant a job exits can legitimately race the record.
local function logged(vm, want, tries)
    local out
    for _ = 1, (tries or 20) do
        out = vm:run("evctl 'LOGS SINCE 1h ago TAKE 400' --format jsonl").stdout
        if not want or out:find(want, 1, true) then return out end
        vm:run("sleep 1")
    end
    return out
end

--- The pid of the first process whose comm is `name`. There is no pgrep
--- in this image — peiosutils is a coreutils fork — so /proc is walked
--- directly, which is what pgrep would have read anyway.
---
--- The /proc reads in this file are the agent's (helpers/peinit.lua): the
--- processes they look at are PID 1 and authd, both TCB-signed, and PIP
--- refuses the shell's `cat`, `ls` and `readlink` their /proc.
local function pid_of(vm, name)
    return peinit.pid_of_comm(vm, name)
end

local function link(vm, path)
    return (require("helpers.sys").readlink(vm, path) or "")
end

--- Every descriptor PID 1 holds, as target -> fd. peinit keeps the read
--- end of each service pipe, so this is how a child's pipe is found in
--- peinit's own table: by the inode both ends share.
local function peinit_fds(vm)
    local by_target = {}
    for fd, target in peinit.fd_listing(vm, 1):gmatch("(%d+) %-> (%S+)") do
        by_target[target] = fd
    end
    return by_target
end

--- The open flags on a descriptor, as a number. /proc prints them in
--- octal with a leading zero, which `tonumber` alone reads as decimal.
local function fd_flags(vm, pid, fd)
    return tonumber(vm:read_file("/proc/" .. pid .. "/fdinfo/" .. fd):match("flags:%s*(%d+)"), 8)
end

local O_NONBLOCK = tonumber("04000", 8)

wait_for_eventd(vm)

test("a service is handed two pipes and /dev/null, and peinit keeps the other ends",
    {
        spec = {
            "peinit *output.a-service-gets-a-stdout-pipe-and-a-stderr-pipe",
            "peinit *output.stdin-is-redirected-to-dev-null",
        },
    },
    function(t)
        local pid = pid_of(vm, "authd")
        t:assert(pid, "authd is running")

        -- Two pipes, not one: stdout and stderr are separate, which is
        -- what lets the tag record which stream a line came from.
        local out, err = link(vm, "/proc/" .. pid .. "/fd/1"), link(vm, "/proc/" .. pid .. "/fd/2")
        t:assert(out:match("^pipe:%[%d+%]$"), "stdout is a pipe: " .. out)
        t:assert(err:match("^pipe:%[%d+%]$"), "stderr is a pipe: " .. err)
        t:assert(out ~= err, "and they are two different pipes")

        -- stdin is not a pipe at all. peinit offers no interactive input
        -- channel, so a service that reads stdin gets end-of-file rather
        -- than a descriptor nobody is writing to.
        t:assert_eq(link(vm, "/proc/" .. pid .. "/fd/0"), "/dev/null",
            "stdin is /dev/null")

        -- The read ends are peinit's. The same pipe inode appears in
        -- PID 1's descriptor table, which is the whole of the claim that
        -- peinit "keeps the read ends".
        local held = peinit_fds(vm)
        t:assert(held[out], "peinit holds the read end of authd's stdout pipe")
        t:assert(held[err], "peinit holds the read end of authd's stderr pipe")
    end)

test("the read ends are non-blocking and the write ends are not",
    { spec = "peinit *output.the-blocking-discipline-is-asymmetric" },
    function(t)
        local pid = pid_of(vm, "authd")
        local out = link(vm, "/proc/" .. pid .. "/fd/1")
        local held = peinit_fds(vm)[out]
        t:assert(held, "the two ends of one pipe were matched by inode")

        -- The child's end keeps ordinary blocking semantics. That is
        -- what makes backpressure work: a service producing faster than
        -- peinit consumes blocks in write() rather than being handed
        -- EAGAIN it would have to cope with.
        local child = fd_flags(vm, pid, 1)
        t:assert(child, "the child's stdout flags were readable")
        t:assert(child & O_NONBLOCK == 0,
            "the service's write end blocks (flags " .. string.format("0%o", child) .. ")")

        -- peinit's end does not, because PID 1 cannot afford to block on
        -- a read.
        local parent = fd_flags(vm, 1, held)
        t:assert(parent & O_NONBLOCK ~= 0,
            "peinit's read end is non-blocking (flags " .. string.format("0%o", parent) .. ")")
    end)

test("the epoll instance is peinit's own and no service has one from it",
    { spec = "peinit *output.the-epoll-instance-is-never-inherited" },
    function(t)
        -- Created close-on-exec, so it cannot survive into a child. The
        -- observable form of that: peinit has one and the services it
        -- exec'd have none of peinit's.
        local mine = peinit.fd_listing(vm, 1)
        t:assert(mine:find("anon_inode:[eventpoll]", 1, true),
            "peinit watches its pipes with an epoll instance")

        for _, service in ipairs({ "authd", "netd", "pnpd" }) do
            local pid = pid_of(vm, service)
            if pid then
                local theirs = peinit.fd_listing(vm, pid)
                t:assert(not theirs:find("eventpoll", 1, true),
                    service .. " inherited no epoll descriptor")
            end
        end
    end)

test("each captured line records which service wrote it and which stream it came from",
    {
        spec = {
            "peinit *output.every-line-is-tagged",
            "peinit *output.the-origin-names-the-producer",
        },
    },
    function(t)
        -- pt-say writes one identifiable line to each stream, so the two
        -- records differ in exactly the field under test. The origin is
        -- the service name, because these are main-process lines.
        local out = vm:run("evctl 'LOGS FROM pt-say SINCE 1h ago' --format jsonl").stdout
        local seen = {}
        for line in out:gmatch("[^\r\n]+") do
            local message = line:match('"message":"([^"]*)"')
            if message then
                seen[message] = {
                    origin = line:match('"origin":"([^"]*)"'),
                    is_error = line:match('"is_error":(%a+)'),
                    timestamp = tonumber(line:match('"timestamp":(%d+)')),
                }
            end
        end

        local stdout_line = seen["pt-wiring-stdout-marker"]
        local stderr_line = seen["pt-wiring-stderr-marker"]
        t:assert(stdout_line, "the stdout line was captured")
        t:assert(stderr_line, "the stderr line was captured")

        t:assert_eq(stdout_line.origin, "pt-say", "the origin is the service name")
        t:assert_eq(stderr_line.origin, "pt-say", "on both streams")
        t:assert_eq(stdout_line.is_error, "false", "the stdout line is not an error")
        t:assert_eq(stderr_line.is_error, "true", "the stderr line is")
        t:assert(stdout_line.timestamp and stdout_line.timestamp > 0,
            "and each line carries a wall-clock timestamp")
    end)

test("an attached sink gets the job's lines untagged and in the order it wrote them",
    { spec = "peinit *output.the-sink-receives-untagged-lines-in-order" },
    function(t)
        -- `--output` attaches svctl's own standard output as the job's
        -- sink, so what this reads back as `stdout` IS the sink.
        local submitted = vm:run(
            [[svctl job submit --output --wait /bin/printf 'pt-sink-first\npt-sink-second\n']])
        submitted:assert_ok()

        local first = submitted.stdout:find("pt-sink-first", 1, true)
        local second = submitted.stdout:find("pt-sink-second", 1, true)
        t:assert(first and second, "both lines reached the sink")
        t:assert(first < second, "in the order the job wrote them")

        -- Untagged: the sink gets what the job wrote and nothing else,
        -- unlike the console, where everything carries the tag column.
        for line in submitted.stdout:gmatch("[^\r\n]+") do
            if line:find("pt%-sink%-") then
                t:assert(not line:find("^%["),
                    "the sink copy carries no tag column: " .. line)
            end
        end

        local job = submitted.stdout:match("job ([%x-]+):")
        t:assert(job, "svctl reported the job's identifier: " .. submitted.stdout)
    end)

--- Whether PID 1 holds a descriptor for `path`. A FIFO is named in
--- /proc/<pid>/fd by its path, so this is how a test sees whether peinit
--- still has a sink open.
local function peinit_holds(vm, path)
    return peinit.fd_listing(vm, 1):find("-> " .. path, 1, true) ~= nil
end

local function read_or_empty(vm, path)
    local ok, text = pcall(function() return vm:read_file(path) end)
    return ok and text or ""
end

--- A FIFO for a job's sink, with a reader that copies everything to a
--- file and then writes `pt-eof` — which it can only do once every writer
--- has closed the FIFO, so the marker is the moment the last holder of the
--- sink let go of it.
local function fifo_with_reader(vm, name)
    local fifo, out = "/run/pt-" .. name .. ".fifo", "/run/pt-" .. name .. ".out"
    vm:run("mkfifo " .. fifo):assert_ok()
    vm:run("sh -c 'cat " .. fifo .. " > " .. out .. "; echo pt-eof >> " .. out ..
        "' > /dev/null 2>&1 &"):assert_ok()
    return fifo, out
end

test("the sink closes after the job's last line, at once on a failed write, and unwritten for a job that never ran",
    { spec = "peinit *output.the-sink-is-closed-when-the-pipes-are" },
    function(t)
        -- Each sink here is svctl's standard output, pointed at a FIFO.
        -- svctl is run without --wait, so it prints its acknowledgement
        -- into the FIFO and exits: from then on PID 1 holds the only other
        -- write end, and the reader reaches end-of-file exactly when PID 1
        -- closes it.

        -- The ordinary case. Two lines three seconds apart: between them
        -- the job's pipes are open, and so is the sink.
        local fifo, out = fifo_with_reader(vm, "close")
        vm:run("svctl job submit --output /bin/sh -c " ..
            "'sleep 1; echo pt-close-first; sleep 3; echo pt-close-last' > " .. fifo):assert_ok()
        wait_until(function() return read_or_empty(vm, out):find("pt-close-first", 1, true) end,
            { timeout = 15, interval = 0.2, desc = "the first line through the sink" })
        t:assert(peinit_holds(vm, fifo), "between the two lines PID 1 holds the sink open")
        t:assert(not read_or_empty(vm, out):find("pt-eof", 1, true),
            "and the reader has not been given end-of-file")

        local text = wait_until(function()
            local s = read_or_empty(vm, out)
            return s:find("pt-eof", 1, true) and s or nil
        end, { timeout = 20, interval = 0.2, desc = "the sink to close" })
        local last, eof = text:find("pt-close-last", 1, true), text:find("pt-eof", 1, true)
        t:assert(last and last < eof,
            "the last line went to the sink before it was closed: " .. text)
        t:assert(not peinit_holds(vm, fifo), "and PID 1 holds it no longer")

        -- A write that fails for a reason other than blocking. The reader
        -- takes one line — svctl's acknowledgement, which names the job —
        -- and goes, so the FIFO has no reader left and peinit's next write
        -- to it fails with EPIPE. The job itself carries on for a minute.
        local wfifo = "/run/pt-wfail.fifo"
        vm:run("mkfifo " .. wfifo):assert_ok()
        vm:run("sh -c 'head -n 1 " .. wfifo .. " > /run/pt-wfail.out' > /dev/null 2>&1 &"):assert_ok()
        vm:run("svctl job submit --output /bin/sh -c " ..
            "'sleep 2; echo pt-wfail-1; echo pt-wfail-2; sleep 60' > " .. wfifo):assert_ok()
        local job = wait_until(function()
            return read_or_empty(vm, "/run/pt-wfail.out"):match("job ([%x-]+):")
        end, { timeout = 15, interval = 0.2, desc = "the reader to take svctl's acknowledgement" })
        t:assert(peinit_holds(vm, wfifo), "PID 1 holds the sink while the job has written nothing")
        wait_until(function() return not peinit_holds(vm, wfifo) end,
            { timeout = 20, interval = 0.5, desc = "PID 1 to close a sink whose reader has gone" })
        t:assert(vm:run("svctl job status " .. job).stdout:find("job " .. job .. ": running", 1, true),
            "and it closed it at once, not when the job ended — the job is still running: " ..
            vm:run("svctl job status " .. job).stdout)

        -- A job that never ran. It fails between fork and exec, so it has
        -- no pipes and writes nothing; the sink it was given is closed
        -- without a line reaching it.
        local nfifo, nout = fifo_with_reader(vm, "never")
        vm:run("svctl job submit --output /lcl/pt/not-executable > " .. nfifo)
        local never = wait_until(function()
            local s = read_or_empty(vm, nout)
            return s:find("pt-eof", 1, true) and s or nil
        end, { timeout = 20, interval = 0.2, desc = "the never-run job's sink to close" })
        local id = never:match("job ([%x-]+):")
        t:assert(id, "svctl's acknowledgement named the job: " .. never)
        t:assert(vm:run("svctl job status " .. id).stdout:find("job " .. id .. ": failed", 1, true),
            "the job failed without running: " .. vm:run("svctl job status " .. id).stdout)
        -- Everything the reader got is svctl's own acknowledgement — one
        -- `job …:` line and `field: value` lines — and then end-of-file.
        for line in never:gmatch("[^\r\n]+") do
            t:assert(line == "pt-eof" or line:find("^job ") or line:find("^[%a ]+: "),
                "nothing but svctl's acknowledgement reached the sink: " .. line)
        end
        t:assert(not never:find("pt-never-ran", 1, true), "the job wrote nothing")
        t:assert(not peinit_holds(vm, nfifo), "and PID 1 holds nothing of it")
    end)

test("a submitted job's output is recorded whether or not a sink was attached",
    { spec = "peinit *output.a-submitted-jobs-output-is-recorded-unconditionally" },
    function(t)
        -- The copy is optional; the record is not. A submitted job is
        -- launched with capture pipes on both streams, the same as a
        -- service, and PID 1 holds the read ends (the same evidence the
        -- first test in this file reads for a service) — so what it
        -- wrote is queryable afterwards with no sink involved.
        --
        -- The origin is the part worth asserting: a submitted job has no
        -- service, so it is tagged `jobs/<guid>` rather than a service
        -- name, and eventd's log ingestion accepts that two-component
        -- form (eventd TRM §4.2).
        local submitted = vm:run(
            [[svctl job submit --wait /bin/printf 'pt-record-only-marker\n']])
        submitted:assert_ok()
        local job = submitted.stdout:match("job ([%x-]+):")
        t:assert(job, "svctl reported the job's identifier")

        local records = logged(vm, "pt-record-only-marker")
        local origin
        for line in records:gmatch("[^\r\n]+") do
            if line:find("pt-record-only-marker", 1, true) then
                origin = line:match('"origin":"([^"]*)"')
            end
        end
        t:assert(origin, "the job's output was recorded even with no sink attached")
        t:assert_eq(origin, "jobs/" .. job,
            "and its origin names the job rather than a service")
    end)

test("a service that asks for a terminal gets it on all three streams and is not captured",
    { spec = "peinit *output.a-terminal-attached-service-is-not-captured" },
    function(t)
        local pid = pid_of(vm, "onterminal.sh")
        t:assert(pid, "the terminal-attached service is running")

        -- All three streams are the terminal, and neither pipe pair
        -- survives into the child: there is nothing for peinit to read.
        for _, fd in ipairs({ "0", "1", "2" }) do
            t:assert_eq(link(vm, "/proc/" .. pid .. "/fd/" .. fd), "/dev/tty2",
                "fd " .. fd .. " is the terminal")
        end

        -- The consequence the manual draws: its output is not captured
        -- at all. It wrote a marker line, and that line is nowhere in
        -- the log store, because it went to the terminal instead.
        local records = logged(vm)
        t:assert(not records:find("pt-terminal-service-marker", 1, true),
            "nothing the terminal service wrote was captured")
    end)

test("the terminal is opened with read attributes, so a session on it can name it",
    { spec = "peinit *output.the-terminal-is-opened-with-read-attributes" },
    function(t)
        -- `isatty` is an ioctl and works whatever rights the handle
        -- carries, which is why the gap this covers is easy to miss.
        -- `ttyname` is not: it stats the descriptor, and a KACS handle
        -- answers fstat only if FILE_READ_ATTRIBUTES is on it. So the
        -- service ran `tty`, and what it recorded says which happened.
        local named = vm:read_file("/run/pt-tty-name"):gsub("%s+$", "")
        t:assert_eq(named, "/dev/tty2",
            "the service could name its own terminal, so the handle answers fstat")
    end)
