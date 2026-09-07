-- peinit TRM §5.3 — the pre-exec sequence: everything between "peinit
-- decides to start service X" and "X's binary is running".
--
-- Almost none of this is visible from the outside once it has succeeded,
-- so the definitions staged here are built to leave evidence behind. The
-- hooks append to a file under /run as they run, which turns "in
-- sequence" into a readable order; the main process is a script that
-- looks for the process the last hook backgrounded, which is the only
-- moment at which the hooks/ kill can be observed; and the post-hook
-- asks peinit for the service's own state, which is how a claim about
-- the state a service is in *while* its post-hooks run can be checked at
-- all.
--
-- The failing definitions each pick a different point in the sequence to
-- fail at, because the chapter's claim is not that a bad start fails but
-- that the recorded cause says where it failed.

local peinit = require("helpers.peinit")
peinit.claim(1)

local FILES = {
    ["pt/pre1.sh"] = [[
echo pre1 >> /run/pt-order
cat /proc/self/cgroup > /run/pt-hook-cgroup
]],
    -- Backgrounds a long-lived process, which lands in hooks/ with the
    -- hook itself, and records its pid for the main process to look for.
    ["pt/pre2.sh"] = [[
echo pre2 >> /run/pt-order
/bin/sleep 600 &
echo $! > /run/pt-background
]],
    -- Runs as the service's main process. It answers the one question
    -- that cannot be asked afterwards -- was the hook's background
    -- process still alive when the main process started? -- and then
    -- becomes an ordinary long-running service.
    ["pt/main.sh"] = [[
bg=$(cat /run/pt-background)
state=
if [ -e "/proc/$bg/stat" ]; then
    set -- $(cat "/proc/$bg/stat")
    state=$3
fi
case "$state" in
    ""|Z) echo gone > /run/pt-background-at-main ;;
    *)    echo "alive ($state)" > /run/pt-background-at-main ;;
esac
exec /bin/sleep 3600
]],
    -- Asks peinit for its own service's state while running as that
    -- service's post-hook, which is the only vantage point from which
    -- the ordering of the transition and the post-hooks can be seen.
    ["pt/post.sh"] = [[
echo post >> /run/pt-post-order
/bin/svctl status pt-post > /run/pt-post-status 2>&1
]],
    ["pt/both.sh"] = [[
echo $1 >> /run/pt-both-order
]],
    -- Not a program, and staged without the execute bit that under KACS
    -- is the intrinsic "this is executable" flag. Naming it as an
    -- ImagePath gets a child as far as `execve` and no further.
    ["pt/not-a-binary"] = "\0\0not a program\n",
}

local SERVICES = {
    { path = [[Machine\System]] },
    { path = [[Machine\System\Services]] },
    { path = [[Machine\System\Services\pt-rundir]], values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "3600" } },
        { name = "Triggers", type = "multi", data = { "boot" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "RuntimeDirectories", type = "multi", data = { "pt-rundir" } },
    } },
    { path = [[Machine\System\Services\pt-hooks]], values = {
        { name = "ImagePath", type = "sz", data = "/bin/sh" },
        { name = "Arguments", type = "multi", data = { "/pt/main.sh" } },
        { name = "Triggers", type = "multi", data = { "boot" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "ExecStartPre", type = "multi",
          data = { "/bin/sh /pt/pre1.sh", "/bin/sh /pt/pre2.sh" } },
    } },
    -- Post-hooks, on a service with no pre-hooks. A post-hook that
    -- works, and then one that does not; the failing one is last so that
    -- its failure cannot be confused with the first one not having run.
    { path = [[Machine\System\Services\pt-post]], values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "3600" } },
        { name = "Triggers", type = "multi", data = { "boot" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "ExecStartPost", type = "multi",
          data = { "/bin/sh /pt/post.sh", "/bin/false" } },
    } },
    -- Both kinds of hook on one service, which is the combination
    -- PEI-797's chapter-5 pass found peinit gets wrong.
    { path = [[Machine\System\Services\pt-both]], values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "3600" } },
        { name = "Triggers", type = "multi", data = { "boot" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "ExecStartPre", type = "multi", data = { "/bin/sh /pt/both.sh pre" } },
        { name = "ExecStartPost", type = "multi", data = { "/bin/sh /pt/both.sh post" } },
    } },
    -- Fails in step 3, before the fork.
    { path = [[Machine\System\Services\pt-hookfail]], values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "3600" } },
        { name = "Triggers", type = "multi", data = { "boot" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "RestartPolicy", type = "dword", data = 0 },
        { name = "ExecStartPre", type = "multi", data = { "/bin/false" } },
    } },
    -- Fails after the fork, in the child, at the working-directory step.
    { path = [[Machine\System\Services\pt-badcwd]], values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "3600" } },
        { name = "Triggers", type = "multi", data = { "boot" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "RestartPolicy", type = "dword", data = 0 },
        { name = "WorkingDirectory", type = "sz", data = "/pt-not-here" },
    } },
    -- No token can be minted for this identity, so step 4 fails and no
    -- child is ever created.
    { path = [[Machine\System\Services\pt-badidentity]], values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "3600" } },
        { name = "Triggers", type = "multi", data = { "boot" } },
        { name = "Identity", type = "sz", data = "pt-no-such-principal" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "RestartPolicy", type = "dword", data = 0 },
    } },
    -- Fails at the last step of the child path rather than the seventh.
    { path = [[Machine\System\Services\pt-badexec]], values = {
        { name = "ImagePath", type = "sz", data = "/pt/not-a-binary" },
        { name = "Triggers", type = "multi", data = { "boot" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "RestartPolicy", type = "dword", data = 0 },
    } },
    -- The deadline lands during the pre-hooks.
    { path = [[Machine\System\Services\pt-slowhook]], values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "3600" } },
        { name = "Triggers", type = "multi", data = { "boot" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "RestartPolicy", type = "dword", data = 0 },
        { name = "StartTimeout", type = "dword", data = 2 },
        { name = "ExecStartPre", type = "multi", data = { "/bin/sleep 60" } },
    } },
    -- The same deadline, landing during the readiness wait instead:
    -- Readiness=Notify on a process that will never send READY=1.
    { path = [[Machine\System\Services\pt-noready]], values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "3600" } },
        { name = "Triggers", type = "multi", data = { "boot" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 0 },
        { name = "RestartPolicy", type = "dword", data = 0 },
        { name = "StartTimeout", type = "dword", data = 3 },
    } },
}

local vm = peinit.boot({
    name = "preexec",
    files = peinit.merge(FILES, peinit.seed("pt-preexec", SERVICES)),
})

--- The `state` and `cause` lines of `svctl status`, once the service has
--- stopped moving.
---
--- Several of these definitions are still starting when the boot mark
--- goes by -- a two-second hook has not expired yet, and a readiness
--- wait has three seconds to run -- so a test that reads the status the
--- moment the boot completes reads a service mid-flight.
local function settled_status(service, timeout)
    return wait_until(function()
        local out = vm:run("svctl status " .. service).stdout
        local state = out:match("^[%w%-]+: ([%w]+)")
        if state == "starting" or state == "inactive" then return nil end
        return { state = state, cause = out:match("cause: ([%w_]+)"), text = out }
    end, { timeout = timeout or 30, interval = 0.5,
           desc = service .. " to reach a settled state" })
end

test("a service's RuntimeDirectories are created under /run before the launch",
    { spec = "peinit *preexec.runtime-directories-are-created-under-run" },
    function(t)
        -- The boot mark goes by before Phase 2 has finished starting
        -- everything, so wait for this service's own start to land.
        local status = settled_status("pt-rundir")
        t:assert_eq(status.state, "active",
            "the service that declared it started: " .. status.text)

        -- It is peinit's, not the service's: /bin/sleep creates nothing,
        -- so the only thing that could have made it is step 2.
        t:assert_eq(vm:stat("/run/pt-rundir").entry_type, "directory",
            "the declared runtime directory exists under /run")
    end)

test("pre-exec hooks run in order, in the service's hooks/ cgroup",
    { spec = "peinit *preexec.pre-hooks-run-in-sequence-into-the-hooks-cgroup" },
    function(t)
        settled_status("pt-hooks")
        local order = peinit.lines(vm:read_file("/run/pt-order"))
        t:assert_eq(order[1], "pre1", "the first ExecStartPre ran first")
        t:assert_eq(order[2], "pre2", "and the second after it, in sequence")

        -- Forked into hooks/, not into main/ and not into peinit's own
        -- cgroup. `/proc/<pid>/cgroup` is relative to the cgroup2 root.
        local cgroup = vm:read_file("/run/pt-hook-cgroup"):gsub("%s+$", "")
        t:assert_eq(cgroup, "0::/peinit/pt-hooks/hooks",
            "the hook ran in the service's hooks/ sub-cgroup")
    end)

test("the hooks cgroup is killed before the main process starts",
    { spec = "peinit *preexec.the-hooks-cgroup-is-killed-before-the-main-process" },
    function(t)
        settled_status("pt-hooks")
        -- The second hook backgrounded a `sleep 600` and exited. Nothing
        -- reaped it and nothing signalled it, so the only thing that
        -- could have removed it is the hooks/ kill -- and the main
        -- process looked for it as its very first act, which is what
        -- makes this "before the main process starts" rather than
        -- "eventually". A process that has been SIGKILLed but not yet
        -- reaped still has a /proc entry, so the check reads its state
        -- rather than the directory's existence.
        t:assert_eq(vm:read_file("/run/pt-background-at-main"):gsub("%s+$", ""), "gone",
            "the process the hook backgrounded was already dead when the main process ran")

        -- And it did not become part of the service by another route.
        t:assert_eq(vm:read_file("/sys/fs/cgroup/peinit/pt-hooks/hooks/cgroup.procs"), "",
            "hooks/ is empty")
        t:assert_eq(vm:read_file("/sys/fs/cgroup/peinit/pt-hooks/main/cgroup.procs")
            :gsub("[^\r\n]+", "x"):gsub("%s", ""), "x",
            "and main/ holds the main process alone")
    end)

test("post-hooks run after the service is already Active, and a failing one does not fail it",
    {
        spec = {
            "peinit *preexec.post-hooks-run-after-readiness",
            "peinit *preexec.the-state-transition-precedes-the-post-hooks",
            "peinit *preexec.a-failed-post-hook-does-not-fail-the-service",
        },
    },
    function(t)
        -- Waiting on the post-hook's own output rather than on the
        -- service's state, because the two are not the same moment: the
        -- service reaches Active first and the post-hooks run after it,
        -- which is exactly what the second assertion below is about.
        local seen = wait_until(function()
            local ok, text = pcall(function() return vm:read_file("/run/pt-post-status") end)
            return ok and text ~= "" and text or nil
        end, { timeout = 30, interval = 0.5, desc = "pt-post's post-hook to run" })

        t:assert_eq(vm:read_file("/run/pt-post-order"):gsub("%s+$", ""), "post",
            "the post-hook ran once, after readiness")

        -- The post-hook asked peinit what state pt-post was in while it
        -- was itself running as pt-post's post-hook. The answer is the
        -- claim: the transition happens first.
        t:assert_contains(seen, "pt-post: active",
            "the service was already Active while its post-hook ran")

        -- The second post-hook is /bin/false. The service is unmoved by
        -- it -- still Active, and still with the cause it started with
        -- rather than a hook failure.
        local status = settled_status("pt-post")
        t:assert_eq(status.state, "active",
            "a post-hook exiting non-zero left the service Active: " .. status.text)
        t:assert(status.cause ~= "pre_hook_failure" and status.cause ~= "post_hook_failure",
            "and did not become the service's cause: " .. tostring(status.cause))
    end)

test("a service with both pre- and post-exec hooks still runs its post-hooks",
    {
        spec = "peinit *preexec.post-hooks-run-after-readiness",
        tags = { "known-bug" },
    },
    function(t)
        -- pt-both is pt-post's definition with one ExecStartPre added,
        -- and that is the whole difference: the pre-hook runs, the
        -- service reaches Active, and the ExecStartPost never runs at
        -- all -- no console line, no post-hook timeout when StartTimeout
        -- expires, nothing. Neither hook list is unusual on its own;
        -- only the combination is affected.
        --
        -- §5.3 says post-hooks run on readiness and says nothing about
        -- pre-hooks suppressing them, so the manual is what is being
        -- asserted here and the code is what is wrong.
        local status = settled_status("pt-both")
        t:assert_eq(status.state, "active", "the service started: " .. status.text)

        local order = wait_until(function()
            local ok, text = pcall(function() return vm:read_file("/run/pt-both-order") end)
            if not ok then return nil end
            local lines = peinit.lines(text)
            return #lines >= 2 and lines or nil
        end, { timeout = 20, interval = 0.5, desc = "pt-both's hooks to run" })

        t:assert_eq(order[1], "pre", "the pre-hook ran")
        t:assert_eq(order[2], "post", "and so did the post-hook")
    end)

test("a pre-exec hook exiting non-zero fails the service with PreHookFailure",
    { spec = "peinit *preexec.a-hook-exiting-non-zero-fails-the-service" },
    function(t)
        local status = settled_status("pt-hookfail")
        t:assert_eq(status.cause, "pre_hook_failure",
            "the recorded cause names the hook: " .. status.text)

        -- The whole tree is killed on the way out, so no process of the
        -- service survives the failed start and peinit is left holding
        -- no job for it.
        t:assert(not status.text:find("pid:"),
            "no process of the service survived the failed start: " .. status.text)
    end)

test("a token that cannot be materialised fails the start before there is a child",
    { spec = "peinit *preexec.a-token-failure-is-a-parent-setup-failure" },
    function(t)
        -- Step 4 is the last thing the parent does that can fail with no
        -- child in existence, and its failure has a classification of
        -- its own for exactly that reason: nothing was forked, so this
        -- is not a child setup failure.
        local status = settled_status("pt-badidentity")
        t:assert_eq(status.cause, "parent_setup_failure",
            "the failure is classified as the parent's: " .. status.text)
        t:assert(not status.text:find("pid:"), "and there is no process to speak of")

        t:assert(vm:console():read_log():find(
            "service pt%-badidentity failed to launch: ParentSetupFailure: token materialization failed"),
            "peinit said which parent-side step failed")
    end)

test("a child setup failure after the fork is PreExecFailure, and names the step that failed",
    {
        spec = {
            "peinit *preexec.a-child-setup-failure-is-a-pre-exec-failure",
            "peinit *preexec.the-error-pipe-carries-post-fork-failures",
        },
    },
    function(t)
        -- The working directory is set in the child, after clone3 and
        -- before execve, so this failure can only be reported back
        -- through the error pipe -- there is no other channel between
        -- the two, and the parent's own steps all succeeded.
        local status = settled_status("pt-badcwd")
        t:assert_eq(status.cause, "pre_exec_failure",
            "the cause distinguishes a child failure from a parent one: " .. status.text)

        -- The parent parsed the step and the errno out of the payload
        -- and logged both, which is the evidence that the payload
        -- arrived and was understood rather than merely that the child
        -- died.
        local log = vm:console():read_log()
        t:assert(log:find(
            "service pt%-badcwd failed to launch: PreExecFailure: set%-working%-directory failed with errno 2"),
            "peinit named the failing step and its errno on the console")

        -- A second service failing at a different point in the same
        -- child path, reported through the same pipe: pt-badexec gets
        -- all the way to `execve` and fails there. Two distinct steps
        -- named distinctly is what says the payload carries the step
        -- rather than the parent guessing.
        local exec = settled_status("pt-badexec")
        t:assert_eq(exec.cause, "pre_exec_failure",
            "the exec failure is a child failure too: " .. exec.text)
        t:assert(log:find("service pt%-badexec failed to launch: PreExecFailure: exec failed with errno"),
            "and it is reported as the exec step rather than as the working-directory one")
    end)

test("one StartTimeout bounds the hooks and the readiness wait, and the cause says which it expired in",
    {
        spec = {
            "peinit *preexec.one-deadline-covers-the-whole-sequence",
            "peinit *preexec.the-start-timeout-cause-depends-on-where-it-landed",
        },
    },
    function(t)
        -- Two services with nothing wrong with them except that they
        -- take longer than their StartTimeout, expiring at different
        -- points in the same sequence.
        local hook = settled_status("pt-slowhook")
        t:assert_eq(hook.cause, "pre_hook_failure",
            "a deadline that lands during the pre-hooks is PreHookFailure: " .. hook.text)

        local ready = settled_status("pt-noready")
        t:assert_eq(ready.cause, "readiness_timeout",
            "one that lands during the readiness wait is ReadinessTimeout: " .. ready.text)

        -- Both were aborted rather than left hanging: expiry kills the
        -- service's cgroup tree, so neither the hook that was still
        -- sleeping nor the process that never signalled is still around
        -- when the deadline has passed.
        for _, status in ipairs({ hook, ready }) do
            t:assert(not status.text:find("pid:"),
                "the aborted start left no process behind: " .. status.text)
        end
        t:assert_eq(vm:run("cat /sys/fs/cgroup/peinit/pt-noready/main/cgroup.procs 2>/dev/null")
            .stdout, "",
            "pt-noready's main process was killed with its tree")
    end)
