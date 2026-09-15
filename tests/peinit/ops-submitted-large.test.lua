-- peinit TRM §8.5 and §10.7 — a submitted job as large as the jobs socket
-- accepts, under the limits the image ships with.
--
-- Its own file and its own boot. The test was a known bug that ended
-- PID 1's runtime loop (PEI-1082): beside other tests it would have
-- taken the machine down under every one after it.
--
-- The record is exactly MaxJobMessageSize, left at its default, and the
-- definition in it is a sixtieth of the 2 MiB argument bound — peinit
-- accepts it on both counts. The job's `job.ended` event then carries
-- the `arguments` array, which is the record's content plus the event's
-- own fields. With the old 64 KiB default that event was over KMES's own
-- 64 KiB MaxEventSize, the ring refused it with ENOSPC, and peinit
-- treated the refusal as fatal. Now the default is half the ring's
-- (§10.7), the event fits, and a refusal would be dropped and reported
-- rather than fatal (§8.2, §8.4).
--
-- The record is sent from a provium worker (helpers/peinit_client.lua)
-- because no command line in the guest can carry a 32 KiB argument.

local peinit = require("helpers.peinit")
local us = require("helpers.unixsock")
local client = require("helpers.peinit_client")
peinit.claim(1)

local vm = peinit.boot({ name = "submitlarge" })

-- The shipped MaxJobMessageSize (§10.7, a1).
local LIMIT = 32768

test("a job submitted in a record at MaxJobMessageSize runs to completion and peinit carries on",
    {
        spec = {
            "peinit *jobs.max-job-message-size",
            "peinit *submit.arguments-and-environment-are-bounded-at-two-mib",
        },
        -- PEI-1082: `job.ended` embeds the job's `arguments`
        -- (kmes/encode/job.rs), so a definition near the record limit
        -- makes an event over KMES's MaxEventSize; `kmes_emit` fails
        -- ENOSPC, the runtime loop ends, and PID 1 enters recovery with
        -- its sockets unlinked.
        -- PEI-1082: fixed in peinit a99db66, "fix(kmes): bound
        -- the arguments a job.ended carries and hold
        -- MaxJobMessageSize below MaxEventSize", on the
        -- containment of 210fec0 (PEI-1125). Green since
        -- 0.0.5-6.
    },
    function(t)
        local head = '{"command":"submit","image_path":"/bin/true","arguments":["'
        local tail = '"]}'
        local record = head .. string.rep("a", LIMIT - #head - #tail) .. tail
        t:assert_eq(#record, LIMIT, "the record is exactly the default MaxJobMessageSize")

        local id
        client.with_worker(vm, function(w)
            local fd = assert(us.socket(w, us.AF_UNIX, us.SOCK.SEQPACKET))
            local connected = us.connect(w, fd, client.JOBS_SOCKET)
            assert(connected.ret == 0, "connect to the jobs socket: " ..
                us.errname(connected.errno))
            local answer, why = client.jobs_request(w, fd, record)
            w:syscall(3, fd)
            assert(answer, "no answer to the submit: " .. tostring(why))
            id = answer:match('"id":"([^"]+)"')
            t:assert(id and answer:find('"status":"ok"', 1, true),
                "a record at the limit, well inside the 2 MiB bound, is accepted: " ..
                answer:sub(1, 300))
        end)

        local waited = vm:run("svctl --json job wait " .. id, { timeout = 60 })
        t:assert(waited:ok() and waited.stdout:match('"state":"([^"]+)"') == "completed",
            "the job ran to completion: " .. waited.stdout .. tostring(waited.stderr))

        -- The part that fails: the job's end has been recorded, so its
        -- event has been emitted, and peinit is still serving the socket
        -- the job came in on.
        local again = vm:run("svctl --json job submit /bin/true", { timeout = 30 })
        t:assert(again:ok(),
            "peinit still serves the jobs socket once the job has ended: " ..
            tostring(again.stderr))
        local log = vm:console():read_log()
        t:assert(not log:find("Recovery mode", 1, true),
            "and PID 1 did not go to recovery")
    end)
