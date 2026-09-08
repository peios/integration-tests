-- peinit TRM §10.7 — what the jobs socket attaches to an answer.
--
-- One sentence of that article: "A `submit` answered with a running job
-- carries a duplicate of the job's pidfd as `SCM_RIGHTS` on the response
-- record; nothing else carries ancillary data." Half of it holds and
-- half of it does not, and neither half was observable from the guest
-- until now -- `svctl` is the image's only jobs client, it asks for a
-- descriptor capacity of one (jobs/client.rs) and it never says whether
-- one arrived, so an answer that carried a process handle and one that
-- did not looked identical from a shell.
--
-- `pt-jobs` (tests/tools/pt-jobs.c) is a jobs client that reports what
-- came back on the wire: the JSON, the number of SCM_RIGHTS descriptors,
-- and what each descriptor is according to its /proc/self/fd link. The
-- socket is an ordinary SOCK_SEQPACKET Unix socket carrying ordinary
-- control messages, so plain sendmsg/recvmsg is a conforming client.

local peinit = require("helpers.peinit")
peinit.claim(1)

local vm = peinit.boot({ name = "nfjobs", files = peinit.tool("pt-jobs") })

--- Run one jobs request through pt-jobs and return its report as
--- `{fds = n, kinds = {…}, json = "…"}`.
local function ask(request, name)
    local log = "/run/" .. name .. ".log"
    local r = vm:run("pt-jobs --log " .. log .. " '" .. request .. "'",
        { timeout = 60 })
    local text = vm:read_file(log)
    local out = { raw = text, kinds = {} }
    for line in text:gmatch("[^\r\n]+") do
        local fds = line:match("^reply rc=%-?%d+ fds=(%d+)")
        if fds then out.fds = tonumber(fds) end
        local kind = line:match("^reply%-fd%d+ (.*)$")
        if kind then out.kinds[#out.kinds + 1] = kind end
        local json_line = line:match("^reply%-json (.*)$")
        if json_line then out.json = json_line end
    end
    out.exit_code = r.exit_code
    return out
end

--- Submit a long-running job through svctl and return its identifier.
---
--- Through svctl rather than pt-jobs, so that the job under test is not
--- also the answer under test: svctl's own submit answer is discarded,
--- and the connection it used is gone by the time anything below asks
--- about the job.
local function submit_via_svctl()
    local r = vm:run("svctl --json --no-wait job submit /bin/sleep 300")
    r:assert_ok()
    local id = r.stdout:match('"id":"([^"]+)"')
    assert(id, "no job identifier in: " .. r.stdout)
    return id
end

test("a submit answered with a running job carries the job's pidfd",
    { spec = "peinit *jobs.a-submit-answer-carries-the-jobs-pidfd" },
    function(t)
        -- The half of the sentence that holds. The submitter is promised
        -- a handle on the process it started, so that it can wait on the
        -- process itself rather than on a name that could be recycled.
        local answer = ask(
            '{"command":"submit","image_path":"/bin/sleep","arguments":["300"]}',
            "pt-jb-submit")

        t:assert(answer.json and answer.json:find('"status":"ok"', 1, true),
            "the submit was accepted: " .. answer.raw)
        t:assert_eq(answer.fds, 1,
            "the answer carried exactly one descriptor: " .. answer.raw)
        t:assert_eq(answer.kinds[1], "anon_inode:[pidfd]",
            "and it is a process handle, not some other descriptor: " ..
            answer.raw)
    end)

test("nothing but a submit answer carries ancillary data",
    {
        spec = "peinit *jobs.a-submit-answer-carries-the-jobs-pidfd",
        -- PEI-837. `jobs_view_frame` (supervisor/submitted/commands.rs)
        -- attaches a duplicated pidfd to *any* view of a Running job,
        -- and every one of `status`, `wait`, `stop` and `signal` reaches
        -- it through `immediate_view_response`. `status` needs only
        -- JOB_QUERY, so a caller with no right to run anything is handed
        -- a live handle on somebody else's process by asking about it.
        tags = { "known-bug" },
    },
    function(t)
        local id = submit_via_svctl()
        wait_until(function()
            local r = vm:run("svctl --json job status " .. id)
            return r:ok() and r.stdout:find('"state":"running"', 1, true) and true or nil
        end, { timeout = 60, interval = 0.3, desc = "the job to be running" })

        -- A plain `status` on a fresh connection: no submit, nothing
        -- given to this caller to own.
        local answer = ask('{"command":"status","job_id":"' .. id .. '"}',
            "pt-jb-status")
        t:assert(answer.json and answer.json:find('"status":"ok"', 1, true),
            "the status was answered: " .. answer.raw)
        t:assert_eq(answer.fds, 0,
            "and carried no ancillary data, the pidfd being the submit " ..
            "answer's alone: " .. answer.raw)
    end)
