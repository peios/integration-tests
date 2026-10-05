-- Peinit TRM §11.4 — the eventd handoff.
--
-- The handoff is a moment rather than a state, and it has already
-- happened by the time a test can ask anything. What it leaves behind is
-- checkable: records produced before eventd existed, carrying the
-- timestamps they were captured with rather than the ones they were
-- delivered with; a socket with an access-control list that admits only
-- peinit; and, when eventd is killed, the whole thing happening again.
--
-- As in §11.2, a seeded service is put ahead of eventd in the graph so
-- that a known set of lines is produced inside the pre-eventd window by
-- construction.

local peinit = require("helpers.peinit")
peinit.claim(2)

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

local LINES = 200

local early = [[#!/bin/sh
i=0
while [ $i -lt ]] .. LINES .. [[ ]; do
    echo "pt-handoff-$i"
    i=$((i + 1))
done
]]

-- Four hundred numbered lines of about a hundred bytes, written as fast
-- as the shell can, for the test that needs a burst to land entirely
-- inside the window in which eventd is gone.
local GAP_LINES = 400
local gap = [[#!/bin/sh
i=0
while [ $i -lt ]] .. GAP_LINES .. [[ ]; do
    echo "pt-gap-$i-..........................................................................................."
    i=$((i + 1))
done
]]

local function early_service_keys(extra)
    local keys = {
        { path = [[Machine\System]] },
        { path = [[Machine\System\Services]] },
        {
            path = [[Machine\System\Services\pt-handoff]],
            values = {
                { name = "ImagePath", type = "sz", data = "/lcl/pt/early.sh" },
                { name = "Type", type = "dword", data = 1 },
                { name = "Identity", type = "sz", data = "SYSTEM" },
                { name = "Readiness", type = "dword", data = 1 },
                { name = "Triggers", type = "multi", data = { "boot" } },
            },
        },
        {
            path = [[Machine\System\Services\eventd]],
            values = {
                { name = "Requires", type = "multi", data = { "authd", "pt-handoff" } },
                -- Eight seconds between a crash and the restart, rather than
                -- the default one, so that a test which kills eventd has a
                -- window it can put a whole burst of output into by
                -- construction instead of by racing the restart.
                { name = "RestartDelay", type = "dword", data = 8 },
            },
        },
        -- Started by hand, never at boot: the burst for the gap test. It
        -- stays Completed once it has run, so that "the burst is over" is
        -- a state a test can read rather than infer.
        {
            path = [[Machine\System\Services\pt-gap]],
            values = {
                { name = "ImagePath", type = "sz", data = "/lcl/pt/gap.sh" },
                { name = "Type", type = "dword", data = 1 },
                { name = "RemainAfterExit", type = "dword", data = 1 },
                { name = "Identity", type = "sz", data = "SYSTEM" },
                { name = "Readiness", type = "dword", data = 1 },
            },
        },
        -- A service that tries to write to eventd's log socket itself,
        -- rather than through its pipes. SYSTEM, deliberately: the user a
        -- token names is not what the socket's descriptor turns on.
        {
            path = [[Machine\System\Services\pt-broker]],
            values = {
                { name = "ImagePath", type = "sz", data = "/usr/bin/pt-notify" },
                { name = "Arguments", type = "multi", data = {
                    "--socket", "/run/eventd/log.sock", "--log", "/run/pt-broker.log",
                    "send-nocred", "pt-broker-direct", "sleep", "300",
                } },
                { name = "Identity", type = "sz", data = "SYSTEM" },
                { name = "Readiness", type = "dword", data = 1 },
            },
        },
    }
    for _, key in ipairs(extra or {}) do keys[#keys + 1] = key end
    return keys
end

local function wait_for_eventd(vm)
    for _ = 1, 60 do
        if vm:run("svctl status eventd").stdout:find("eventd: active") then return true end
        vm:run("sleep 1")
    end
    return false
end

--- Records for one origin, as a list of {message, timestamp, is_error},
--- polled until `want` of them have arrived.
local function records_from(vm, origin, want, tries)
    local records = {}
    for _ = 1, (tries or 30) do
        records = {}
        local out = vm:run(
            "evctl 'LOGS FROM " .. origin .. " SINCE 1h ago TAKE 5000' --format jsonl").stdout
        for line in out:gmatch("[^\r\n]+") do
            local message = line:match('"message":"([^"]*)"')
            if message then
                records[#records + 1] = {
                    message = message,
                    timestamp = tonumber(line:match('"timestamp":(%d+)')),
                    is_error = line:match('"is_error":(%a+)'),
                }
            end
        end
        if #records >= (want or 1) then return records end
        vm:run("sleep 1")
    end
    return records
end

--- Restart a service once it is Active.
---
--- PEI-803: a restart that reaches a service in Backoff takes PID 1 to
--- recovery (`MissingCurrentMainJob`). The restarts in this file are
--- only a way of making a service write something, and a
--- loaded host can leave one of the image's services between attempts at
--- the moment a test reaches for it. This file intermittently lost its
--- whole VM at its first restart — the connection closed mid-reply, then
--- no control socket — which is that bug's symptom exactly, though the
--- state pnpd was in at the time was not captured. So they wait for Active
--- first: the claims here are about forwarding, not about that.
local function restart_when_active(vm, service)
    wait_until(function()
        return vm:run("svctl status " .. service).stdout:find(service .. ": active", 1, true)
    end, { timeout = 60, interval = 1, desc = service .. " to be active before it is restarted" })
    return vm:run("svctl restart " .. service)
end

local vm = peinit.boot({
    memory = MEM, cpus = CPUS,
    name = "handoff",
    files = peinit.merge(
        {
            ["lcl/pt/early.sh"] = { early, exec = true },
            ["lcl/pt/gap.sh"] = { gap, exec = true },
        },
        peinit.tool("pt-notify"),
        peinit.seed("zz-pt-handoff", early_service_keys())
    ),
})
wait_for_eventd(vm)

test("eventd's log socket denies the Service group before it allows SYSTEM",
    { spec = "peinit *eventd.the-log-socket-denies-the-service-group-before-allowing-system" },
    function(t)
        -- The ordering is the mechanism, not a detail: KACS evaluates a
        -- DACL in order, so a deny ahead of the allow is what excludes
        -- every principal that carries the Service logon group while
        -- still admitting peinit, whose bootstrap token is SYSTEM
        -- without it.
        local sd = vm:run("sd show /run/eventd/log.sock")
        sd:assert_ok()

        local deny = sd.stdout:find("deny%s+Service")
        local allow = sd.stdout:find("allow%s+Local System")
        t:assert(deny, "the Service logon group is denied: " .. sd.stdout)
        t:assert(allow, "and SYSTEM is allowed")
        t:assert(deny < allow, "with the deny ahead of the allow, which is what makes it bite")

        -- 0x2 is FILE_WRITE_DATA — sending a log record — rather than a
        -- blanket denial, so a service may still stat or open the path.
        local mask = sd.stdout:match("deny%s+Service%s+%([^)]*%)%s+(%S+)")
        t:assert_eq(mask, "0x2", "and what is denied is the write, got " .. tostring(mask))
    end)

test("the log socket is a datagram socket, which is why delivery to it can be lossy",
    { spec = "peinit *eventd.the-log-socket-is-a-non-blocking-datagram-socket" },
    function(t)
        -- A datagram socket is what makes the whole lossy design
        -- possible: a full receive buffer discards the message rather
        -- than blocking the sender, so log ingestion exerts no
        -- backpressure on peinit. /proc/net/unix records the type of
        -- every Unix socket on the machine; 0002 is SOCK_DGRAM.
        local line
        for entry in vm:read_file("/proc/net/unix"):gmatch("[^\r\n]+") do
            if entry:find("/run/eventd/log.sock", 1, true) then line = entry end
        end
        t:assert(line, "the log socket is in /proc/net/unix")

        -- Columns: Num RefCount Protocol Flags Type St Inode Path.
        local socket_type = line:match("^%S+ %S+ %S+ %S+ (%S+)")
        t:assert_eq(socket_type, "0002",
            "the log socket is SOCK_DGRAM, got type " .. tostring(socket_type) .. " in: " .. line)
    end)

test("output held from before eventd is replayed with the timestamps it was captured with",
    {
        spec = {
            "peinit *eventd.forwarding-begins-when-eventd-reaches-active",
            "peinit *eventd.the-buffer-is-replayed-oldest-first",
        },
    },
    function(t)
        local records = records_from(vm, "pt-handoff", LINES)
        t:assert_eq(#records, LINES, "every buffered line was forwarded once eventd was Active")

        -- The replay preserves each line's own timestamp rather than
        -- stamping it on arrival. eventd was not yet serving when these
        -- were written, so a delivery timestamp would necessarily be
        -- later than the moment eventd started.
        local started = vm:run("svctl status eventd").stdout:match("started: (%S+)")
        t:assert(started, "svctl reports when eventd's process started")
        local year, month, day, hour, minute, second =
            started:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
        local eventd_started_ns = os.time({
            year = tonumber(year), month = tonumber(month), day = tonumber(day),
            hour = tonumber(hour), min = tonumber(minute), sec = tonumber(second),
            isdst = false,
        }) * 1000000000

        local newest = 0
        for _, record in ipairs(records) do
            if record.timestamp > newest then newest = record.timestamp end
        end
        t:assert(newest > 0, "the records carry timestamps")
        t:assert(newest < eventd_started_ns + 1000000000,
            "and they are from before eventd's process existed, not from delivery time")

        -- Oldest first, and in the order the service wrote them: the
        -- lines are numbered, so their timestamps have to rise with the
        -- numbering.
        local by_index = {}
        for _, record in ipairs(records) do
            local index = tonumber(record.message:match("^pt%-handoff%-(%d+)$"))
            if index then by_index[index] = record.timestamp end
        end
        for i = 1, LINES - 1 do
            t:assert(by_index[i] and by_index[i - 1] and by_index[i] >= by_index[i - 1],
                "line " .. i .. " is not stamped before line " .. (i - 1))
        end
    end)

test("the log socket peinit sends to is the one the registry names",
    { spec = "peinit *eventd.the-socket-path-comes-from-the-registry" },
    function(t)
        -- Not a compiled-in path: this boot moves the socket, and the
        -- records follow it. eventd binds the same key, so the two stay
        -- in step — which is the point of reading it rather than
        -- agreeing a constant.
        local moved = peinit.boot({
            memory = MEM, cpus = CPUS,
            name = "handoff-path",
            files = peinit.seed("zz-pt-path", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\eventd]] },
                {
                    path = [[Machine\System\eventd]],
                    values = {
                        { name = "LogSocketPath", type = "sz",
                          data = "/run/eventd/pt-moved-log.sock" },
                    },
                },
            }),
        })
        t:assert(wait_for_eventd(moved), "eventd came up with the moved socket")

        t:assert_eq(moved:run([[reg get 'Machine\System\eventd' LogSocketPath]])
            .stdout:gsub("%s+$", ""), "/run/eventd/pt-moved-log.sock",
            "the registry names the moved path")
        t:assert(moved:run("stat -c %F /run/eventd/pt-moved-log.sock").stdout:find("socket"),
            "and a socket is bound there")
        t:assert(not moved:run("stat -c %F /run/eventd/log.sock 2>&1").stdout:find("socket"),
            "with nothing at the default path")

        -- Records arrive, so peinit sent them somewhere, and the only
        -- socket there is to send them to is the one the registry named.
        t:assert(#records_from(moved, "registryd", 1) > 0,
            "output reached eventd through the moved socket")
    end)

test("output produced after the handoff is forwarded as it arrives",
    { spec = "peinit *eventd.new-output-is-forwarded-as-it-arrives" },
    function(t)
        -- Nothing about this line went through the buffer: eventd was
        -- already Active when the service was restarted, so peinit read
        -- the pipe and sent it on the same turn.
        local before = #records_from(vm, "pnpd", 0)
        restart_when_active(vm, "pnpd"):assert_ok()
        local after = records_from(vm, "pnpd", before + 1)
        t:assert(#after > before,
            "the restarted service's output reached eventd live, " ..
            before .. " records before and " .. #after .. " after")
    end)

test("each record carries the producer, the stream, the message and a wall-clock nanosecond timestamp",
    { spec = "peinit *eventd.the-record-fields" },
    function(t)
        local records = records_from(vm, "pt-handoff", LINES)
        local sample = records[1]
        t:assert(sample, "there is a record to look at")
        t:assert(sample.message and #sample.message > 0, "it carries the line")
        t:assert(sample.is_error == "true" or sample.is_error == "false",
            "and a boolean saying which stream it came from")

        -- The timestamp is nanoseconds on the wall clock, not a
        -- monotonic count or a millisecond one: divided by a billion it
        -- has to agree with what the guest thinks the time is.
        local now = tonumber(vm:run("date +%s").stdout:match("%d+"))
        t:assert(now, "the guest reported the time")
        local seconds = sample.timestamp / 1000000000
        t:assert(math.abs(now - seconds) < 3600,
            "the timestamp is nanoseconds since the epoch: " .. sample.timestamp ..
            " against a clock reading " .. now)
    end)

test("peinit uses one datagram socket for eventd and does not make another per batch",
    { spec = "peinit *eventd.one-socket-is-created-and-reused" },
    function(t)
        local function socket_count()
            -- Sampled until two consecutive readings agree, so a control
            -- connection that happens to be open for the svctl call that
            -- took the sample is not counted as growth.
            local previous
            for _ = 1, 20 do
                -- Listed by the agent: PID 1 is TCB-signed, and PIP
                -- refuses the shell's `ls` its /proc.
                local count = 0
                for _ in peinit.fd_listing(vm, 1):gmatch("%-> socket:") do
                    count = count + 1
                end
                if previous == count then return count end
                previous = count
                vm:run("sleep 1")
            end
            return previous
        end

        local before = socket_count()
        t:assert(before and before > 0, "peinit holds sockets")

        -- Several hundred more records through the sink. If a socket
        -- were created per record, or per batch, this would show.
        for _ = 1, 3 do
            restart_when_active(vm, "pnpd")
            restart_when_active(vm, "installerd")
        end
        vm:run("sleep 3")

        t:assert(socket_count() <= before,
            "peinit's socket count did not grow across the traffic: " ..
            before .. " before, " .. socket_count() .. " after")
    end)

test("when eventd dies the buffer takes over, and the handoff repeats when it comes back",
    {
        spec = {
            "peinit *eventd.an-eventd-exit-re-enables-the-buffer",
            "peinit *eventd.the-handoff-repeats-when-eventd-comes-back",
            "peinit *eventd.the-connection-is-discarded-when-eventd-goes-inactive",
        },
    },
    function(t)
        local pid = vm:run("svctl status eventd").stdout:match("pid: (%d+)")
        t:assert(pid, "eventd has a process to kill")

        -- SIGKILL, so this is a crash rather than a stop: peinit sees
        -- the exit through the pidfd it supervises eventd with. Sent by
        -- the agent: eventd is TCB-signed, and PIP refuses the shell's
        -- `kill`.
        peinit.signal(vm, pid, "KILL")

        -- Output produced while eventd is gone. It cannot be forwarded,
        -- so if it turns up later it was buffered in the meantime.
        restart_when_active(vm, "installerd")

        t:assert(wait_for_eventd(vm), "eventd restarted and became Active again")
        local restarted = vm:run("svctl status eventd").stdout:match("pid: (%d+)")
        t:assert(restarted ~= pid,
            "it is a new process, so it rebound the log socket at the same path")

        -- The records from the gap are there. Reaching them requires
        -- both halves: peinit had to buffer while eventd was down, and
        -- it had to discard its old connection and reconnect, because
        -- the socket the new eventd bound is a different inode at the
        -- same path.
        local records = records_from(vm, "installerd", 1)
        t:assert(#records > 0,
            "output written while eventd was down reached the restarted eventd")
    end)

test("no service can write to the log socket itself, so every record comes through peinit",
    { spec = "peinit *eventd.peinit-is-the-only-service-output-broker" },
    function(t)
        -- A service, started as SYSTEM, sends a datagram straight to the
        -- log socket instead of writing to its pipes. Its token carries the
        -- Service logon group, as every phase-2 service token does, and the
        -- socket's descriptor denies the write to that group before it
        -- allows SYSTEM — so the send is refused however the service is
        -- configured.
        vm:run("svctl start pt-broker"):assert_ok()
        local sent = wait_until(function()
            local ok, text = pcall(function() return vm:read_file("/run/pt-broker.log") end)
            return ok and text:match("step=send%-nocred [^\n]*") or nil
        end, { timeout = 20, interval = 0.5, desc = "the service's direct send to be attempted" })
        t:assert(sent:find("rc=-1 errno=13", 1, true),
            "the service's own send to the log socket was refused with EACCES: " .. sent)

        -- The same send made with peinit's bootstrap token — the one the
        -- provium agent runs on, SYSTEM without the Service group — is
        -- admitted. That is the only kind of token that has it, and peinit
        -- is the only thing that holds one while services run.
        local agent = vm:run("/usr/bin/pt-notify --socket /run/eventd/log.sock " ..
            "--log /run/pt-broker-agent.log send-nocred pt-agent-direct")
        agent:assert_ok()
        local agent_sent = vm:read_file("/run/pt-broker-agent.log")
        t:assert(agent_sent:find("step=send%-nocred rc=%d+ errno=0"),
            "the bootstrap token's send was admitted: " .. agent_sent)
    end)

test("the log gap while eventd is down is bounded by the pre-eventd buffer",
    { spec = "peinit *eventd.the-gap-is-bounded-by-the-buffer-size" },
    function(t)
        -- Sixteen kilobytes of buffer, re-read on reload (§11.2), against
        -- about forty kilobytes of output written while eventd is gone.
        local BUFFER = 16384
        vm:run([[reg set 'Machine\System\Init' PreEventdBuffer dword:]] .. BUFFER):assert_ok()
        vm:run("svctl reload-config"):assert_ok()

        local pid = vm:run("svctl status eventd").stdout:match("pid: (%d+)")
        t:assert(pid, "eventd has a process to kill")
        -- From the agent: eventd is TCB-signed, and PIP refuses the
        -- shell's `kill`.
        peinit.signal(vm, pid, "KILL")
        wait_until(function()
            return not vm:run("svctl status eventd").stdout:find("eventd: active", 1, true)
        end, { timeout = 10, interval = 0.2, desc = "peinit to see eventd go" })

        -- The whole burst inside the gap: eventd restarts eight seconds
        -- after the crash, and the burst is over well before that — which
        -- the state read straight afterwards confirms rather than assumes.
        vm:run("svctl start pt-gap"):assert_ok()
        wait_until(function()
            return vm:run("svctl status pt-gap").stdout:find("pt-gap: completed", 1, true)
        end, { timeout = 10, interval = 0.2, desc = "the burst to finish" })
        t:assert(not vm:run("svctl status eventd").stdout:find("eventd: active", 1, true),
            "and eventd was still gone when it had")

        t:assert(wait_for_eventd(vm), "eventd came back")
        local records = records_from(vm, "pt-gap", 1)
        vm:run("sleep 2")
        records = records_from(vm, "pt-gap", #records)
        vm:run([[reg set 'Machine\System\Init' PreEventdBuffer dword:1048576]])
        vm:run("svctl reload-config")

        t:assert(#records > 0, "the end of the gap reached eventd once it was back")
        t:assert(#records < GAP_LINES,
            "but not all of it: " .. #records .. " of " .. GAP_LINES .. " lines")

        -- What survives is what the buffer held: the newest lines, and no
        -- more of them than fit in its capacity by peinit's own accounting
        -- (the origin, the line, a timestamp, a job id and thirty-two bytes
        -- of overhead each). Everything older is the gap.
        local kept, bytes = {}, 0
        for _, record in ipairs(records) do
            local index = tonumber(record.message:match("^pt%-gap%-(%d+)%-"))
            if index then kept[index] = true end
            bytes = bytes + #"pt-gap" + #record.message + 8 + 16 + 32
        end
        t:assert(kept[GAP_LINES - 1], "the last line written survived the gap")
        t:assert(not kept[0], "the first did not")
        t:assert(bytes <= BUFFER,
            "and what survived fits the buffer: " .. bytes .. " of " .. BUFFER .. " bytes")
        local oldest = GAP_LINES - 1
        while kept[oldest - 1] do oldest = oldest - 1 end
        for i = oldest, GAP_LINES - 1 do
            t:assert(kept[i], "the survivors are one unbroken run up to the newest: missing " .. i)
        end
    end)

test("a pre-eventd backlog larger than one datagram is still delivered",
    {
        spec = {
            "peinit *eventd.a-batch-is-the-largest-prefix-fitting-the-portable-ceiling",
            "peinit *eventd.a-transport-failure-rebuffers-and-replays",
        },
        -- PEI-807: fixed in peinit 0a95d77, "fix(logging): size
        -- eventd batches to the socket and stop replaying
        -- oversized ones". Green since 0.0.5-4.
    },
    function(t)
        -- peinit batches up to the PSPU portable ceiling of 262144
        -- encoded bytes. A Unix datagram socket will not carry a message
        -- that size: the sender's default SO_SNDBUF is 212992, and a
        -- larger `send` fails with EMSGSIZE.
        --
        -- EMSGSIZE is not one of the three errnos §11.4 classifies as a
        -- drop, so it is handled as a transport failure — the connection
        -- is cleared and the records are kept in order for the end of
        -- the turn to replay. The replay then forms the same oversized
        -- batch and fails again, and nothing breaks the cycle. The
        -- manual says a transport failure is re-established by replaying;
        -- in fact forwarding never recovers for the rest of the boot.
        --
        -- The blast radius is the whole machine's logs, not just the
        -- noisy service's: the backlog is one buffer, so registryd's
        -- Phase 1 lines and every service's output afterwards are stuck
        -- behind the batch that cannot be sent.
        local big = "#!/bin/sh\n" ..
            "i=0\n" ..
            "while [ $i -lt 1200 ]; do\n" ..
            '    echo "pt-backlog-$i-' .. string.rep("z", 176) .. '"\n' ..
            "    i=$((i + 1))\n" ..
            "done\n"

        local other = peinit.boot({
            memory = MEM, cpus = CPUS,
            name = "handoff-backlog",
            files = peinit.merge(
                { ["lcl/pt/early.sh"] = { big, exec = true } },
                peinit.seed("zz-pt-handoff", early_service_keys())
            ),
        })
        t:assert(wait_for_eventd(other), "eventd came up")

        -- Not the flood's own output: another service's, produced after
        -- eventd was serving, which has nothing to do with the batch that
        -- failed and should not be affected by it.
        restart_when_active(other, "pnpd")
        -- Ten seconds rather than the usual wait: this case is expected to
        -- fail, and a known-bug that spends a minute failing is a minute
        -- off every run of the file.
        local records = records_from(other, "pnpd", 1, 10)
        t:assert(#records > 0,
            "a service's output still reaches eventd after a large backlog")
    end)
