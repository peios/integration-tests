-- Peinit TRM §10.7 — the jobs socket as a transport: its limits, how a
-- message that does not fit is told apart from one that is merely
-- wrong, and what a connection may do while a wait is pending on it.
--
-- `control-jobs.test.lua` covers the jobs socket through svctl, which is
-- a well-behaved client: it sends one small message per connection, never
-- attaches more than it names, and never pipelines. Every claim here is
-- about what peinit does when a client is not that, so the client is
-- `pt-jobs` (tests/tools/pt-jobs.c), which sends exactly what it is told
-- — oversize content, sixty-five descriptors, two requests back to back —
-- and reports what came back, when, and whether the connection survived.
--
-- The three connection limits are seeded down so the claims are about the
-- bounds rather than their values: a message of 4 KiB, an idle timeout of
-- four seconds, and three concurrent connections. Nothing clamps them
-- (registry/config.rs takes each value as it is), so what is seeded is
-- what peinit runs with.

local peinit = require("helpers.peinit")
peinit.claim(1)

local MAX_MESSAGE = 4096
local IDLE_TIMEOUT = 4
local MAX_CONNECTIONS = 3

-- The LocalService submitter. Its only business is to show that a
-- principal peinit grants nothing may still submit: it holds no right on
-- any service, it is not an administrator, and the control socket would
-- refuse it at connect() (security-surface.test.lua). The jobs socket's
-- own descriptor admits every authenticated principal, and that — not
-- anything peinit decides — is the whole of the permission.
local LS_SUBMIT = [[
case "$(token user)" in *S-1-5-19*) : ;; *) echo "wrong identity $(token user)" > /run/pt-lsjobs/out; exit 0 ;; esac
svctl --json job submit /bin/true > /run/pt-lsjobs/out 2>&1
]]

local vm = peinit.boot({
    name = "jobs-transport",
    files = peinit.merge(
        peinit.tool("pt-jobs"),
        peinit.seed("pt-jobs-transport", {
            { path = [[Machine\System]] },
            { path = [[Machine\System\Init]], values = {
                { name = "MaxJobMessageSize", type = "dword", data = MAX_MESSAGE },
                { name = "JobsConnectionTimeout", type = "dword", data = IDLE_TIMEOUT },
                { name = "MaxJobsConnections", type = "dword", data = MAX_CONNECTIONS },
            } },
            { path = [[Machine\System\Services]] },
            { path = [[Machine\System\Services\pt-lsjobs]], values = {
                { name = "ImagePath", type = "sz", data = "/bin/sh" },
                { name = "Arguments", type = "multi", data = { "-c", LS_SUBMIT } },
                { name = "Type", type = "dword", data = 1 },
                { name = "Identity", type = "sz", data = "LocalService" },
                { name = "Readiness", type = "dword", data = 1 },
                { name = "RemainAfterExit", type = "dword", data = 1 },
                { name = "RuntimeDirectories", type = "multi", data = { "pt-lsjobs" } },
                { name = "RestartPolicy", type = "dword", data = 0 },
                -- /run rather than the default /: the pre-exec chdir gets
                -- no traverse bypass, and / is not stamped for Everyone on
                -- every boot (security-surface.test.lua).
                { name = "WorkingDirectory", type = "sz", data = "/run" },
                { name = "Triggers", type = "multi", data = { "boot" } },
            } },
        })
    ),
})

--- Run pt-jobs with `steps` on one connection and parse its report.
---
--- Returns `{replies = {…}, closed = bool, send_failed = bool, raw = …}`,
--- each reply `{at = seconds, fds = n, ctrunc = bool, json = "…"}` in
--- arrival order. `closed` is the manager ending the connection — either
--- an end-of-file where an answer was expected, or a send refused because
--- the far end was already gone. Both are "no response on a closed
--- connection", which is the claim a limit makes.
local function pt_jobs(steps, name)
    local log = "/run/pt-jobs-" .. name .. ".log"
    local quoted = {}
    for _, step in ipairs(steps) do
        quoted[#quoted + 1] = "'" .. step .. "'"
    end
    local r = vm:run("pt-jobs --log " .. log .. " " .. table.concat(quoted, " "),
        { timeout = 60 })
    local text = tostring(vm:read_file(log))
    local out = { replies = {}, raw = text, exit_code = r.exit_code }
    local current
    for line in text:gmatch("[^\r\n]+") do
        local fds, rest = line:match("^reply rc=%d+ fds=(%d+)(.*)$")
        if fds then
            current = {
                fds = tonumber(fds),
                ctrunc = rest:find("ctruncated", 1, true) ~= nil,
                at = tonumber(rest:match("at=([%d%.]+)")),
            }
            out.replies[#out.replies + 1] = current
        end
        local json = line:match("^reply%-json (.*)$")
        if json and current then current.json = json end
        if line:match("^reply closed") then out.closed = true end
        if line:match("^send rc=%-1") then out.closed = true; out.send_failed = true end
    end
    return out
end

--- A file's contents, or "" while it does not exist yet. For polls:
--- `wait_until` re-raises a predicate's error rather than retrying, so a
--- poll on a log its writer has not created yet must not raise.
local function read_if_present(path)
    local ok, text = pcall(function() return vm:read_file(path) end)
    return ok and tostring(text) or ""
end

local function code(reply)
    return reply and reply.json and reply.json:match('"code":"([^"]+)"')
end

local function status_of(reply)
    return reply and reply.json and reply.json:match('"status":"([^"]+)"')
end

local function job_state(reply)
    return reply and reply.json and reply.json:match('"state":"([^"]+)"')
end

--- A job the tests can ask about, submitted through svctl on a
--- connection of its own and released with it.
local function background_job(seconds)
    local r = vm:run("svctl --json --no-wait job submit /bin/sleep " .. seconds,
        { timeout = 60 })
    r:assert_ok()
    local id = r.stdout:match('"id":"([^"]+)"')
    assert(id, "no job identifier in: " .. r.stdout)
    return id
end

local function status_request(id)
    return '{"command":"status","job_id":"' .. id .. '"}'
end

-- ---- message size -----------------------------------------------------

test("content past MaxJobMessageSize is REQUEST_TOO_LARGE, and the connection goes with it",
    {
        spec = {
            "peinit *jobs.max-job-message-size",
            "peinit *jobs.a-truncated-message-is-request-too-large",
        },
    },
    function(t)
        local id = background_job(60)
        -- Well-formed, and meaningful apart from its size: a status
        -- request with an unrecognised field, which §7.4 says is ignored.
        -- So the only thing wrong with it is that it does not fit.
        local big = '{"command":"status","job_id":"' .. id .. '","pad":"'
            .. string.rep("A", MAX_MESSAGE) .. '"}'
        local fits = '{"command":"status","job_id":"' .. id .. '","pad":"'
            .. string.rep("A", MAX_MESSAGE - 200) .. '"}'
        assert(#fits < MAX_MESSAGE and #big > MAX_MESSAGE)

        local under = pt_jobs({ fits }, "fits")
        t:assert_eq(status_of(under.replies[1]), "ok",
            "a message just under the bound is answered: " .. under.raw)

        local over = pt_jobs({ big, status_request(id) }, "big")
        t:assert_eq(code(over.replies[1]), "REQUEST_TOO_LARGE",
            "the same request past the bound is too large: " .. over.raw)
        t:assert(over.closed,
            "and the connection is closed behind it, since the transport lost a record: "
            .. over.raw)
        t:assert_eq(#over.replies, 1,
            "so the request after it is never answered: " .. over.raw)

        vm:run("svctl --json job stop " .. id, { timeout = 60 })
    end)

test("every other error is answered and the connection kept",
    { spec = "peinit *jobs.only-request-too-large-closes-the-connection" },
    function(t)
        local id = background_job(60)
        -- Three different refusals on one connection, then a request that
        -- should succeed. If any of them closed the connection, the ones
        -- after it would have no answer.
        local r = pt_jobs({
            '{"command":"no-such-command"}',
            '{"command":"status"}',
            '{"command":"status","job_id":"00000000-0000-7000-8000-000000000000"}',
            status_request(id),
        }, "errors")
        t:assert_eq(#r.replies, 4, "all four requests were answered: " .. r.raw)
        for k = 1, 3 do
            t:assert_eq(status_of(r.replies[k]), "error",
                "request " .. k .. " was refused: " .. tostring(r.replies[k] and r.replies[k].json))
            t:assert(code(r.replies[k]) ~= "REQUEST_TOO_LARGE",
                "and not for its size: " .. tostring(r.replies[k].json))
        end
        t:assert_eq(status_of(r.replies[4]), "ok",
            "and the connection was still there for the one that was not: " .. r.raw)
        t:assert(not r.closed, "the manager never closed it: " .. r.raw)

        vm:run("svctl --json job stop " .. id, { timeout = 60 })
    end)

-- ---- idle timeout ------------------------------------------------------

test("a connection idle past JobsConnectionTimeout is closed",
    {
        spec = {
            "peinit *jobs.jobs-connection-timeout",
            "peinit *jobs.an-idle-connection-is-closed",
        },
    },
    function(t)
        local id = background_job(60)
        -- The control: idle for well under the timeout, then answered.
        local brief = pt_jobs({ "sleep", "1", status_request(id) }, "brief")
        t:assert_eq(status_of(brief.replies[1]), "ok",
            "a connection idle for one second is still served: " .. brief.raw)

        -- The same connection idle past it. Nothing was in flight, so it
        -- was idle the whole time, and the request after the sleep finds
        -- nobody at the other end.
        local long = pt_jobs({ "sleep", tostring(IDLE_TIMEOUT + 3), status_request(id) }, "idle")
        t:assert(long.closed,
            "one idle for " .. (IDLE_TIMEOUT + 3) .. "s against a " .. IDLE_TIMEOUT
            .. "s timeout was closed: " .. long.raw)
        t:assert_eq(#long.replies, 0, "and its request went unanswered: " .. long.raw)

        vm:run("svctl --json job stop " .. id, { timeout = 60 })
    end)

-- ---- connection limit --------------------------------------------------

test("a connection past MaxJobsConnections is closed without a response",
    {
        spec = {
            "peinit *jobs.max-jobs-connections",
            "peinit *jobs.an-inadmissible-connection-is-closed-without-a-response",
        },
    },
    function(t)
        -- The limit is on connections held at once, so the first three
        -- have to stay held. A pending wait does that — a connection with
        -- one is never idle, so the four-second timeout does not free a
        -- slot underneath the test.
        --
        -- The anchor's other half, a peer whose token cannot be obtained,
        -- is not reachable from a guest process: every connecting process
        -- has one. The over-limit half is the one a client can meet.
        local id = background_job(120)
        local wait = '{"command":"wait","job_id":"' .. id .. '"}'
        for k = 1, MAX_CONNECTIONS do
            vm:run("( pt-jobs --log /run/pt-jobs-hold" .. k .. ".log '" .. wait
                .. "' ) >/dev/null 2>&1 &")
        end
        -- Each holder is connected once its log names the connect; wait for
        -- all three so the fourth is genuinely over the bound.
        wait_until(function()
            for k = 1, MAX_CONNECTIONS do
                local text = read_if_present("/run/pt-jobs-hold" .. k .. ".log")
                if not text:find("connect rc=0", 1, true) then return false end
            end
            return true
        end, { timeout = 30, desc = "the three holders to connect" })
        vm:run("sleep 1")

        local over = pt_jobs({ status_request(id) }, "over")
        t:assert(over.closed,
            "the fourth concurrent connection was closed: " .. over.raw)
        t:assert_eq(#over.replies, 0,
            "without any response, since no protocol state exists to deliver one in: "
            .. over.raw)

        -- And the bound is the bound, not a broken socket: end the job,
        -- the three waits are answered and let go, and a new connection
        -- is served again.
        vm:run("svctl --json job stop " .. id, { timeout = 60 })
        local after = wait_until(function()
            local r = pt_jobs({ status_request(id) }, "after")
            if status_of(r.replies[1]) == "ok" then return r end
        end, { timeout = 30, desc = "a slot to free" })
        t:assert_eq(status_of(after.replies[1]), "ok",
            "once the holders are released a connection is served: " .. after.raw)
    end)

-- ---- descriptors -------------------------------------------------------

--- A submit naming `n` descriptors, for a message that attaches `n`.
local function submit_naming(n)
    local names = {}
    for k = 1, n do names[k] = string.format('"d%02d"', k) end
    return '{"command":"submit","image_path":"/bin/true","descriptors":['
        .. table.concat(names, ",") .. ']}'
end

test("a message may carry sixty-four descriptors, and a sixty-fifth is invalid, not fatal",
    {
        spec = {
            "peinit *jobs.a-message-carries-one-token-and-up-to-sixty-four-descriptors",
            "peinit *jobs.truncated-ancillary-data-is-invalid-arguments",
        },
    },
    function(t)
        -- Both submits name exactly as many descriptors as they attach, so
        -- by §8.5's count rule both are well-formed. The only difference
        -- is whether the attachments fit the room peinit receives with.
        local r = pt_jobs({
            "send-fds", "64", submit_naming(64),
            "send-fds", "65", submit_naming(65),
            '{"command":"status","job_id":"00000000-0000-7000-8000-000000000000"}',
        }, "fds")
        t:assert_eq(#r.replies, 3, "every message was answered: " .. r.raw)
        t:assert_eq(status_of(r.replies[1]), "ok",
            "sixty-four descriptors fit, and the job was submitted: " .. tostring(r.replies[1].json))
        t:assert_eq(code(r.replies[2]), "INVALID_ARGUMENTS",
            "sixty-five do not, and what arrived is not acted on: "
            .. tostring(r.replies[2] and r.replies[2].json))
        -- MSG_CTRUNC, not MSG_TRUNC: the content was intact, so the
        -- connection is kept. The third request is the proof.
        t:assert_eq(code(r.replies[3]), "UNKNOWN_JOB",
            "and the connection carried on to the next request: " .. r.raw)
        t:assert(not r.closed, "it was never closed: " .. r.raw)
    end)

--- How many descriptors PID 1 holds right now. Listed by the agent: PID 1
--- is TCB-signed, and PIP refuses the shell's `ls` its /proc.
local function pid1_fds()
    local n = 0
    for _, e in ipairs(vm:listdir("/proc/1/fd")) do
        local name = type(e) == "table" and e.name or e
        if tostring(name):match("^%d+$") then n = n + 1 end
    end
    return n
end

--- Settle PID 1's descriptor count: wait until two reads a second apart
--- agree, so a connection still being torn down is not counted.
local function settled_fds()
    local last = pid1_fds()
    for _ = 1, 20 do
        vm:run("sleep 1")
        local now = pid1_fds()
        if now == last then return now end
        last = now
    end
    return last
end

test("descriptors a message carried and nothing took are closed",
    { spec = "peinit *jobs.every-unused-descriptor-is-closed" },
    function(t)
        -- Two messages whose attachments nothing is entitled to keep: a
        -- status request, which takes no descriptors at all, and a submit
        -- refused before any job exists. Eight each. If peinit held on to
        -- them, PID 1 would be sixteen descriptors heavier afterwards.
        local before = settled_fds()
        local r = pt_jobs({
            "send-fds", "8", '{"command":"status","job_id":"00000000-0000-7000-8000-000000000000"}',
            -- No image_path: refused at the first step, before identity or
            -- quota, with eight descriptors riding along.
            "send-fds", "8", '{"command":"submit","descriptors":["a","b","c","d","e","f","g","h"]}',
        }, "unused")
        t:assert_eq(#r.replies, 2, "both were answered: " .. r.raw)
        t:assert_eq(code(r.replies[2]), "INVALID_ARGUMENTS",
            "and the submit was refused: " .. tostring(r.replies[2].json))
        local after = settled_fds()
        t:assert_eq(after, before,
            "PID 1 holds as many descriptors afterwards as before (" .. before .. " -> "
            .. after .. ")")
    end)

-- ---- who may submit, and what is checked --------------------------------

test("connecting to the jobs socket is the whole of the permission to submit",
    { spec = "peinit *jobs.connecting-is-the-permission-to-submit" },
    function(t)
        local out = wait_until(function()
            local text = read_if_present("/run/pt-lsjobs/out")
            if text:find('"status"', 1, true) or text:find("wrong identity", 1, true) then
                return text
            end
        end, { timeout = 60, desc = "the LocalService probe to submit" })
        t:assert(not out:find("wrong identity", 1, true),
            "the probe ran as LocalService: " .. out)
        t:assert(out:find('"status":"ok"', 1, true),
            "and a principal holding no right peinit governs submitted a job: " .. out)
        t:assert(out:match('"submitter":"S%-1%-5%-19"'),
            "recorded as submitted by LocalService: " .. out)
    end)

test("every command but submit is checked against the job's descriptor",
    { spec = "peinit *jobs.every-command-but-submit-is-checked-against-the-jobs-descriptor" },
    function(t)
        -- A descriptor naming only a group the caller is not in. submit
        -- is not checked against anything, so it succeeds; the four
        -- commands that name the job it created are each checked against
        -- that descriptor, with this connection's token, and refused.
        local submit = '{"command":"submit","image_path":"/bin/sleep","arguments":["60"],'
            .. '"security_descriptor":"O:S-1-5-32-546G:S-1-5-32-546D:(A;;GA;;;S-1-5-32-546)"}'
        local first = pt_jobs({ submit }, "sd-submit")
        t:assert_eq(status_of(first.replies[1]), "ok",
            "the submit itself is not checked: " .. first.raw)
        local id = first.replies[1].json:match('"id":"([^"]+)"')
        t:assert(id, "and named the job it created: " .. first.raw)

        local r = pt_jobs({
            '{"command":"status","job_id":"' .. id .. '"}',
            '{"command":"wait","job_id":"' .. id .. '"}',
            '{"command":"stop","job_id":"' .. id .. '","wait":false}',
            '{"command":"signal","job_id":"' .. id .. '","signal":15}',
        }, "sd-commands")
        local names = { "status", "wait", "stop", "signal" }
        t:assert_eq(#r.replies, 4, "all four were answered: " .. r.raw)
        for k, name in ipairs(names) do
            t:assert_eq(code(r.replies[k]), "ACCESS_DENIED",
                name .. " is checked against the job's descriptor: "
                .. tostring(r.replies[k] and r.replies[k].json))
        end
        -- The job is unreachable by design and ends with its own sleep.
    end)

-- ---- the turn ----------------------------------------------------------

test("a submit is answered once the job has left created, and not before",
    { spec = "peinit *jobs.the-submit-wait" },
    function(t)
        -- The answer to a submit is never a job that is still being set
        -- up: it waits for exec confirmation or for the launch to fail.
        local ran = pt_jobs({ '{"command":"submit","image_path":"/bin/sleep","arguments":["30"]}' },
            "submit-ok")
        t:assert_eq(job_state(ran.replies[1]), "running",
            "a job that exec'd is answered Running: " .. ran.raw)
        t:assert(ran.replies[1].json:match('"pid":%d+'),
            "with the PID its exec produced: " .. ran.raw)

        local failed = pt_jobs({ '{"command":"submit","image_path":"/pt-not-a-program"}' },
            "submit-fail")
        t:assert_eq(status_of(failed.replies[1]), "ok",
            "a launch that failed is still answered: " .. failed.raw)
        t:assert_eq(job_state(failed.replies[1]), "failed",
            "with the terminal view it reached instead: " .. failed.raw)

        local id = ran.replies[1].json:match('"id":"([^"]+)"')
        if id then vm:run("svctl --json job stop " .. id, { timeout = 60 }) end
    end)

test("a request pipelined behind a wait is not read until the wait is answered",
    { spec = "peinit *jobs.pipelined-messages-serialise-behind-a-wait" },
    function(t)
        local SECONDS = 3
        local id = background_job(SECONDS)

        -- The control: the same status request on its own is answered at
        -- once, well inside a second.
        local alone = pt_jobs({ status_request(id) }, "alone")
        t:assert(alone.replies[1] and alone.replies[1].at < 1,
            "a status request on its own is answered at once: " .. alone.raw)

        -- Now behind a wait. Both go out before either is read; peinit
        -- reads nothing more from a connection while a wait is pending on
        -- it, so the status request sits in the socket until the job ends.
        local id2 = background_job(SECONDS)
        local r = pt_jobs({
            "send-only", '{"command":"wait","job_id":"' .. id2 .. '"}',
            "send-only", status_request(id2),
            "read",
            "read",
        }, "pipelined")
        t:assert_eq(#r.replies, 2, "both were answered in the end: " .. r.raw)
        -- Had the status been served while the wait was pending it would
        -- have come back first, at once, with the job still running.
        t:assert(r.replies[1].at >= SECONDS - 1,
            "nothing came back until the job ended (" .. tostring(r.replies[1].at) .. "s): " .. r.raw)
        for k = 1, 2 do
            t:assert(job_state(r.replies[k]) ~= "running",
                "and neither answer saw the job still running: " .. tostring(r.replies[k].json))
        end
        t:assert(r.replies[2].at >= r.replies[1].at,
            "the status came after the wait it was queued behind: " .. r.raw)
    end)
