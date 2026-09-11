-- peinit TRM §8.5 / §8.6 — a submitted job whose process survives SIGKILL:
-- abandonment as `process_unkillable`, the pid the abandoned view keeps,
-- and the exit fields that stay null because nothing exited.
--
-- This is the chapter-14 "keeper" trick (failure-unkillable.test.lua)
-- applied to a submitted job's own cgroup, `/sys/fs/cgroup/peinit/jobs/
-- <id>`. Nothing in a VM can put a process into uninterruptible sleep on
-- demand, but the condition peinit actually judges is narrower than the
-- story: it kills the job's cgroup, arms a post-kill deadline, and asks
-- `cgroup.events` whether the cgroup is still populated when the deadline
-- fires. That question is made honestly true two ways at once:
--
--   * the job's own main process is moved out of its cgroup before the
--     stop, so the cgroup kill cannot reach it -- exactly the position a
--     D-state process is in, SIGKILL sent and the process still there;
--   * a keeper drops a fresh live process into the job cgroup every
--     second, so it reports populated whenever the deadline lands.
--
-- `PostKillTimeout` is seeded up to twenty seconds so the keeper has a
-- wide window to win. Everything the test then reads -- the state, the
-- cause, the kept pid, the null exit fields -- is peinit's own doing on a
-- job it has given up on.

local peinit = require("helpers.peinit")
peinit.claim(1)

local ESCAPE = "/sys/fs/cgroup/pt-jobescape"

local FILES = {
    -- Ignores SIGTERM, so a stop escalates to the cgroup kill. Its own
    -- argument is where the keeper should drop replacements.
    ["pt/stuck.sh"] = { [[
trap '' TERM
while : ; do /bin/sleep 1 ; done
]], exec = true },
    -- Keeps the job cgroup populated across the post-kill deadline: each
    -- iteration forks a fresh sleep and moves it into the cgroup named by
    -- $1, so whatever the kill took, the next iteration replaces.
    ["pt/keeper.sh"] = { [[
N=0
while [ $N -lt 40 ] ; do
  /bin/sleep 300 &
  echo $! > "$1/cgroup.procs"
  N=$((N+1))
  /bin/sleep 1
done
]], exec = true },
}

local vm = peinit.boot({
    name = "opsabandon",
    files = peinit.merge(FILES, peinit.seed("pt-abandon", {
        { path = [[Machine\System]] },
        { path = [[Machine\System\Boot]], values = {
            { name = "PostKillTimeout", type = "dword", data = 20 },
        } },
    })),
})

local function status(id)
    local r = vm:run("svctl --json job status " .. id)
    return {
        raw = r.stdout,
        state = r.stdout:match('"state":"([^"]+)"'),
        cause = r.stdout:match('"cause":"([^"]+)"'),
        pid = r.stdout:match('"pid":(%d+)'),
        null_exit_code = r.stdout:find('"exit_code":null', 1, true) ~= nil,
        null_exit_signal = r.stdout:find('"exit_signal":null', 1, true) ~= nil,
    }
end

-- Submit the stubborn job. `--stop-timeout 2` makes the kill escalate
-- quickly; the job runs /pt/stuck.sh directly in its own cgroup.
local submit = vm:run(
    "svctl --json job submit --stop-timeout 2 /bin/sh /pt/stuck.sh", { timeout = 120 })
submit:assert_ok()
local id = submit.stdout:match('"id":"([^"]+)"')
assert(id, "no job id in: " .. submit.stdout)
local CGROUP = "/sys/fs/cgroup/peinit/jobs/" .. id

-- The job's main process, read from its own cgroup.
local main_pid = wait_until(function()
    local ok, procs = pcall(function() return vm:read_file(CGROUP .. "/cgroup.procs") end)
    return ok and procs:match("^(%d+)") or nil
end, { timeout = 60, interval = 0.5, desc = "the submitted job to have a process" })

-- Provoke the abandonment, once. Out of its cgroup so the kill cannot
-- reach it -- peinit tracks it by pidfd, so it is still the job's main
-- process -- and a keeper to hold the cgroup populated across the
-- post-kill deadline.
vm:run("mkdir -p " .. ESCAPE):assert_ok()
vm:run("echo " .. main_pid .. " > " .. ESCAPE .. "/cgroup.procs"):assert_ok()
vm:run("/pt/keeper.sh " .. CGROUP .. " > /dev/null 2>&1 &")

-- Stop it. The stop will not complete -- the job is heading for
-- Abandoned, not terminal -- so this does not wait for it.
vm:run("svctl --json job stop " .. id .. " --no-wait")

local abandoned = wait_until(function()
    local view = status(id)
    return view.state == "abandoned" and view or nil
end, { timeout = 60, interval = 1, desc = "the job to be abandoned" })

test("a submitted job that survives SIGKILL is abandoned as process_unkillable",
    { spec = "peinit *submit.a-process-that-survives-sigkill-is-abandoned-as-process-unkillable" },
    function(t)
        t:assert_eq(abandoned.state, "abandoned",
            "the job peinit could not empty went to Abandoned: " .. abandoned.raw)
        t:assert_eq(abandoned.cause, "process_unkillable",
            "with cause process_unkillable: " .. abandoned.raw)

        -- The condition peinit judged on is still true, which is what
        -- makes the transition the right one rather than a coincidence.
        t:assert(vm:read_file(CGROUP .. "/cgroup.procs"):match("%d"),
            "the job cgroup was still populated when the post-kill deadline fired")

        -- Supervision stopped and the cgroup is leaked, reported as a
        -- cgroup.leaked event carrying the job's tree.
        local leaked = vm:run("revstrm --snapshot --pretty --type 'cgroup.leaked'",
            { timeout = 60 })
        leaked:assert_ok()
        t:assert(leaked.stdout:find(id, 1, true) or leaked.stdout:find("jobs/" .. id, 1, true)
            or leaked.stdout:find(CGROUP, 1, true),
            "peinit recorded the job's cgroup as leaked: " .. leaked.stdout:sub(-800))
    end)

test("an abandoned job keeps its pid, and its exit fields stay null",
    {
        spec = {
            "peinit *protoview.an-abandoned-jobs-pid-is-kept",
            "peinit *job.an-abandoned-jobs-exit-fields-stay-null",
        },
    },
    function(t)
        -- The processes survived SIGKILL and are still running, so unlike
        -- every other terminal state the view keeps the pid: there is a
        -- process to name.
        t:assert(abandoned.pid, "the abandoned job's pid is kept: " .. abandoned.raw)
        t:assert_eq(tostring(abandoned.pid), tostring(main_pid),
            "and it is the process that survived the kill")
        t:assert_eq(vm:run("test -d /proc/" .. abandoned.pid).exit_code, 0,
            "which is still alive: the escaped main process the kill never reached")

        -- Nothing exited: peinit stopped supervising rather than
        -- observing an exit, so neither exit field is populated.
        t:assert(abandoned.null_exit_code,
            "exit_code stays null, because nothing exited: " .. abandoned.raw)
        t:assert(abandoned.null_exit_signal,
            "and exit_signal too: " .. abandoned.raw)
    end)
