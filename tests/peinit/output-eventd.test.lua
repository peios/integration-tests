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

local vm = peinit.boot({
    memory = MEM, cpus = CPUS,
    name = "handoff",
    files = peinit.merge(
        { ["lcl/pt/early.sh"] = { early, exec = true } },
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
        vm:run("svctl restart pnpd"):assert_ok()
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
                local count = 0
                for _ in vm:run("ls -l /proc/1/fd").stdout:gmatch("%-> socket:") do
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
            vm:run("svctl restart pnpd")
            vm:run("svctl restart installerd")
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
        -- the exit through the pidfd it supervises eventd with.
        vm:run("kill -9 " .. pid):assert_ok()

        -- Output produced while eventd is gone. It cannot be forwarded,
        -- so if it turns up later it was buffered in the meantime.
        vm:run("svctl restart installerd")

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

test("a pre-eventd backlog larger than one datagram is still delivered",
    {
        spec = {
            "peinit *eventd.a-batch-is-the-largest-prefix-fitting-the-portable-ceiling",
            "peinit *eventd.a-transport-failure-rebuffers-and-replays",
        },
        tags = { "known-bug" },
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
        other:run("svctl restart pnpd")
        -- Ten seconds rather than the usual wait: this case is expected to
        -- fail, and a known-bug that spends a minute failing is a minute
        -- off every run of the file.
        local records = records_from(other, "pnpd", 1, 10)
        t:assert(#records > 0,
            "a service's output still reaches eventd after a large backlog")
    end)
