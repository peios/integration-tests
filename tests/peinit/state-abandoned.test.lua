-- peinit TRM §6.2 — Abandoned from the state machine's side: the two
-- routes into it, the reset out of it, and §6.1's stale-generation rule,
-- which only a service that has been Abandoned can put to the test.
--
-- The provocation is failure-unkillable.test.lua's, and its header says
-- why it is honest: peinit never sees a process's sleep state, only
-- whether a cgroup is populated when a post-kill deadline fires, so a
-- test can make that true without a D-state process. Two moves do it.
--
--   * The service's main process ignores SIGTERM and is moved out of
--     its service tree into `pt-escape`. A write to a cgroup's
--     `cgroup.kill` does not reach a process outside it, so the main
--     process survives the kill exactly as a D-state one would, and its
--     main job stays open. peinit tracks that process by pidfd, not by
--     cgroup, so it is still the service's main process.
--   * A keeper drops a fresh live process into a chosen cgroup of the
--     service's tree once a second, so whatever a kill takes, the next
--     second replaces, and the cgroup reports populated when the
--     deadline fires.
--
-- Where the keeper drops its processes is the variable the file turns
-- on. Into `main/`, a stop gives up (Abandoned). Into a sibling of
-- `main/` — `<service>/pt-outside` — the service root is populated while
-- `main/` is empty, and the two routes into Abandoned part company: an
-- explicit stop asks `main/` and completes, the shutdown wave asks the
-- root and gives up.
--
-- Every wait here is bounded, and every command runs under a timeout of
-- its own. A background process is always started with its output sent
-- to /dev/null: one that inherits the agent's pipes holds `vm:run` open
-- for as long as it lives, and the keepers' children live for minutes.
--
-- Two VMs, one after the other: the file-scope machine for the explicit
-- stop, the reset and the stale READY, and one that is shut down for the
-- wave. The claim is two because the file-scope machine is still held
-- while the second one runs.

local peinit = require("helpers.peinit")
peinit.claim(2)

local CGROUP = "/sys/fs/cgroup/peinit/"
local ESCAPE = "/sys/fs/cgroup/pt-escape"

local FILES = {
    -- Ignores SIGTERM, so a stop has to escalate to the cgroup kill. The
    -- short sleeps are forked from the shell, so once the shell is moved
    -- out of main/ its children are born outside it too.
    ["pt/stuck.sh"] = { [[
trap '' TERM
while : ; do /bin/sleep 1 ; done
]], exec = true },
    -- keeper.sh CGROUP ROUNDS: once a second, for ROUNDS seconds, fork a
    -- long sleep and move it into CGROUP. The keeper moves itself into
    -- pt-escape first, so no kill aimed at a service tree — the stop's,
    -- or the shutdown wave's — can take the keeper with it.
    ["pt/keeper.sh"] = { [[
mkdir -p ]] .. ESCAPE .. [[

echo $$ > ]] .. ESCAPE .. [[/cgroup.procs
N=0
while [ $N -lt $2 ] ; do
  /bin/sleep 300 &
  echo $! > $1/cgroup.procs
  N=$((N+1))
  /bin/sleep 1
done
]], exec = true },
}

local function stuck(name, extra)
    local values = {
        { name = "ImagePath", type = "sz", data = "/bin/sh" },
        { name = "Arguments", type = "multi", data = { "/pt/stuck.sh" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "RestartPolicy", type = "dword", data = 0 },
        { name = "StopTimeout", type = "dword", data = 2 },
    }
    for _, value in ipairs(extra or {}) do values[#values + 1] = value end
    return { path = [[Machine\System\Services\]] .. name, values = values }
end

--- A READY=1 every second for two minutes, from a process that ignores
--- SIGTERM. `trap ''` sets the disposition to SIG_IGN, which survives the
--- exec, so pt-notify — which has no handler of its own — inherits it.
--- The exec keeps the pid, so the process sending is the main job.
local function ghost_arguments()
    local script = { "trap '' TERM; exec /usr/bin/pt-notify --log /run/pt-ab-ghost.log sleep 1" }
    for _ = 1, 120 do script[#script + 1] = "send READY=1 sleep 1" end
    script[#script + 1] = "sleep 100000"
    return { "-c", table.concat(script, " ") }
end

-- The post-kill deadline, seeded up from the five-second default so a
-- keeper that ticks once a second has the cgroup populated well before
-- it is asked.
local BOOT_KEY = { path = [[Machine\System\Boot]], values = {
    { name = "PostKillTimeout", type = "dword", data = 10 },
} }

local vm = peinit.boot({
    name = "abandon",
    append = "peios.quiet=0",
    files = peinit.merge(FILES, peinit.tool("pt-notify"), peinit.seed("pt-abandon", {
        { path = [[Machine\System]] },
        BOOT_KEY,
        { path = [[Machine\System\Services]] },
        stuck("pt-ab-paths"),
        stuck("pt-ab-reset"),
        { path = [[Machine\System\Services\pt-ab-ghost]], values = {
            { name = "ImagePath", type = "sz", data = "/bin/sh" },
            { name = "Arguments", type = "multi", data = ghost_arguments() },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "Readiness", type = "dword", data = 0 },
            { name = "RestartPolicy", type = "dword", data = 0 },
            { name = "StopTimeout", type = "dword", data = 2 },
            { name = "StartTimeout", type = "dword", data = 20 },
        } },
    })),
})

--- `vm:run` with a bound. The default has none, and a command that
--- never returns would hold the whole file.
local function run(machine, command, seconds)
    return machine:run(command, { timeout = seconds or 30 })
end

local function status(machine, name)
    local out = run(machine, "svctl --json status " .. name)
    out:assert_ok()
    local view = json.decode(out.stdout)
    view.raw = out.stdout
    return view
end

local function settle(machine, name, want, seconds)
    return wait_until(function()
        local view = status(machine, name)
        return view.state == want and view or nil
    end, { timeout = seconds or 60, interval = 0.5, desc = name .. " to reach " .. want })
end

local function procs(machine, path)
    local ok, text = pcall(function() return machine:read_file(path .. "/cgroup.procs") end)
    if not ok then return nil end
    return peinit.lines(text)
end

local function exists(machine, path)
    return run(machine, "test -d " .. path).exit_code == 0
end

--- Start `name`, wait for it to be running, and move its main process
--- out of its service tree. Returns the main pid.
local function start_and_escape(machine, name)
    run(machine, "svctl --no-wait start " .. name):assert_ok()
    local view = wait_until(function()
        local current = status(machine, name)
        return current.state == "active" and current.current_job
            and current.current_job.pid and current or nil
    end, { timeout = 60, interval = 0.5, desc = name .. " to be up with a main process" })
    local pid = tostring(view.current_job.pid)
    run(machine, "mkdir -p " .. ESCAPE):assert_ok()
    run(machine, "echo " .. pid .. " > " .. ESCAPE .. "/cgroup.procs"):assert_ok()
    -- A `sleep 1` forked before the move is still in main/ for at most a
    -- second; the next one is born in pt-escape.
    wait_until(function()
        local left = procs(machine, CGROUP .. name .. "/main")
        return left and #left == 0 or nil
    end, { timeout = 10, interval = 0.3, desc = name .. "'s main/ to be empty after the move" })
    return pid
end

--- Launch a keeper against `cgroup` and return its pid.
local function keeper(machine, cgroup, rounds)
    local out = run(machine, "/pt/keeper.sh " .. cgroup .. " " .. rounds ..
        " > /dev/null 2>&1 < /dev/null & echo $!")
    out:assert_ok()
    return out.stdout:match("(%d+)")
end

--- Provoke the explicit-stop abandonment of `name`: escape its main
--- process, keep main/ populated, stop it, and wait for Abandoned.
--- Returns the main pid and the keeper pid.
local function abandon(machine, name)
    local pid = start_and_escape(machine, name)
    local keeper_pid = keeper(machine, CGROUP .. name .. "/main", 60)
    wait_until(function()
        local held = procs(machine, CGROUP .. name .. "/main")
        return held and #held > 0 or nil
    end, { timeout = 10, interval = 0.3, desc = "the keeper to populate " .. name .. "'s main/" })
    run(machine, "svctl --no-wait stop " .. name):assert_ok()
    settle(machine, name, "abandoned", 60)
    return pid, keeper_pid
end

-- Section 1: the explicit stop asks main/.

local PATHS_ROOT = CGROUP .. "pt-ab-paths"
local paths_outcome = (function()
    local pid = start_and_escape(vm, "pt-ab-paths")

    -- A live process in a sibling of main/. The service root is
    -- populated for as long as it lives; main/ holds nothing at all.
    run(vm, "mkdir -p " .. PATHS_ROOT .. "/pt-outside"):assert_ok()
    local outside = run(vm, "/bin/sleep 600 > /dev/null 2>&1 < /dev/null & echo $!")
    outside:assert_ok()
    local outside_pid = outside.stdout:match("(%d+)")
    run(vm, "echo " .. outside_pid .. " > " .. PATHS_ROOT .. "/pt-outside/cgroup.procs")
        :assert_ok()

    local ack = run(vm, "svctl --json --no-wait stop pt-ab-paths")
    ack:assert_ok()
    local operation_id = json.decode(ack.stdout).operation_id

    -- SIGTERM is ignored, the escalation comes at two seconds, and the
    -- post-kill deadline ten seconds after that. The stop ends one way
    -- or the other by then.
    local ended = wait_until(function()
        local view = status(vm, "pt-ab-paths")
        return (view.state == "inactive" or view.state == "abandoned") and view or nil
    end, { timeout = 60, interval = 0.5, desc = "the stop of pt-ab-paths to end" })
    local operation_raw = run(vm, "svctl --json op " .. operation_id).stdout
    return {
        view = ended,
        operation = json.decode(operation_raw).operation,
        operation_raw = operation_raw,
        root_events = (function()
            local ok, text = pcall(function()
                return vm:read_file(PATHS_ROOT .. "/cgroup.events")
            end)
            return ok and text or ""
        end)(),
        outside_procs = procs(vm, PATHS_ROOT .. "/pt-outside") or {},
        main_pid = pid,
        outside_pid = outside_pid,
    }
end)()

test("an explicit stop probes main/: a service root kept populated outside it does not abandon the service",
    { spec = "peinit *trans.the-two-paths-into-abandoned-probe-different-cgroups" },
    function(t)
        -- main/ was empty and the service root was not. The stop's
        -- post-kill check asked main/, found it empty, and completed.
        t:assert_eq(paths_outcome.view.state, "inactive",
            "the stop completed rather than giving up: " .. paths_outcome.view.raw)
        t:assert_eq(paths_outcome.view.cause, "explicit_stop",
            "as an ordinary explicit stop")
        t:assert_eq(paths_outcome.operation.state, "completed",
            "and the stop operation says so: " .. paths_outcome.operation_raw)

        -- The condition a root probe would have seen was true the whole
        -- time: the process in pt-outside is still there, and the kernel
        -- still counts the root populated.
        t:assert(#paths_outcome.outside_procs > 0,
            "the process outside main/ is still alive in the service root")
        t:assert(paths_outcome.root_events:find("populated 1", 1, true),
            "and the root reads populated: " .. paths_outcome.root_events)

        -- peinit did notice the root: tidying the tree after the stop,
        -- it could not remove a root with a live child, and recorded the
        -- leak. It knew the root was populated and still went Inactive,
        -- because the decision was never the root's to make.
        local leaked = {}
        for _, warning in ipairs(paths_outcome.view.warnings or {}) do
            leaked[warning.path] = warning.type
        end
        t:assert_eq(leaked[PATHS_ROOT], "service_tree",
            "the busy root is on record as a leak: " .. paths_outcome.view.raw)

        run(vm, "kill -9 " .. paths_outcome.outside_pid .. " " .. paths_outcome.main_pid)
    end)

-- Section 2: the reset of an Abandoned service whose main/ has emptied.

local RESET_ROOT = CGROUP .. "pt-ab-reset"
local reset_outcome = (function()
    local pid, keeper_pid = abandon(vm, "pt-ab-reset")

    -- The keeper stops, everything it put in main/ dies, and so does
    -- the escaped main process — the scenario's hung I/O finally
    -- completing. peinit reaps that one and records the late exit.
    run(vm, "kill " .. keeper_pid)
    run(vm, "echo 1 > " .. RESET_ROOT .. "/main/cgroup.kill")
    run(vm, "kill -9 " .. pid)
    wait_until(function()
        local left = procs(vm, RESET_ROOT .. "/main")
        local view = status(vm, "pt-ab-reset")
        return left and #left == 0 and view.current_job == nil or nil
    end, { timeout = 30, interval = 0.5,
           desc = "pt-ab-reset's main/ to empty and its main job to be reaped" })

    local before = status(vm, "pt-ab-reset")
    local tree_before = exists(vm, RESET_ROOT)
    local reset = run(vm, "svctl --json reset pt-ab-reset")
    return {
        before = before,
        tree_before = tree_before,
        reset = reset,
        after = status(vm, "pt-ab-reset"),
        tree_after = exists(vm, RESET_ROOT),
        main_after = exists(vm, RESET_ROOT .. "/main"),
    }
end)()

test("a reset of an Abandoned service whose main/ has emptied goes Inactive",
    { spec = "peinit *trans.a-reset-of-an-emptied-abandoned-service-cleans-up-and-goes-inactive" },
    function(t)
        t:assert_eq(reset_outcome.before.state, "abandoned",
            "the service was Abandoned when the reset came")
        t:assert_eq(reset_outcome.reset.exit_code, 0,
            "the reset was accepted: " .. reset_outcome.reset.stdout .. reset_outcome.reset.stderr)
        t:assert_eq(reset_outcome.after.state, "inactive", "and the service is Inactive")
        t:assert_eq(reset_outcome.after.cause, "explicit_reset", "by the reset")
        -- Nothing was left to warn about: the tree emptied.
        t:assert(not reset_outcome.reset.stdout:find("still populated after reset", 1, true),
            "no still-populated warning for a main/ that has emptied: " ..
            reset_outcome.reset.stdout)
    end)

test("a reset of an Abandoned service whose main/ has emptied reclaims the service tree",
    {
        spec = "peinit *trans.a-reset-of-an-emptied-abandoned-service-cleans-up-and-goes-inactive",
        -- PEI-817: recording the leak on the way into Abandoned advanced
        -- the service's cgroup generation, and the reset probes and
        -- cleans the tree of the generation the service has *now* —
        -- pt-ab-reset%1, which never existed — so the emptied tree the
        -- service was abandoned in is never removed.
        -- PEI-817: fixed in peinit 76783cb, "fix(lifecycle):
        -- reset an abandoned service against the tree it was
        -- abandoned in". Green since 0.0.5-4.
    },
    function(t)
        t:assert(reset_outcome.tree_before,
            "the abandoned tree was still in the hierarchy before the reset")
        -- main/, hooks/, health/, then the root: the whole tree.
        t:assert(not reset_outcome.main_after,
            "the reset removed the emptied main/ of the abandoned tree")
        t:assert(not reset_outcome.tree_after,
            "and the service root with it: " .. RESET_ROOT .. " is still there")
    end)

-- Section 3: a READY=1 from the previous incarnation.

test("a READY=1 carrying a stale generation is rejected",
    { spec = "peinit *state.a-ready-carrying-a-stale-generation-is-rejected" },
    function(t)
        -- The previous incarnation has to be alive, and still be the
        -- service's main job, after the generation has advanced. That is
        -- exactly what an Abandoned service's escaped main process is:
        -- abandoning leaves its main job open, a reset does not close
        -- it, and a start whose first job is an ExecStartPre hook enters
        -- Starting — the generation increment — without a main job of
        -- its own to displace it. pt-ab-ghost's process sends READY=1
        -- every second throughout.
        local _, keeper_pid = abandon(vm, "pt-ab-ghost")
        run(vm, "kill " .. keeper_pid)
        run(vm, "svctl reset pt-ab-ghost"):assert_ok()
        t:assert_eq(status(vm, "pt-ab-ghost").state, "inactive", "the reset cleared it")

        -- The hook outlives StartTimeout on purpose: the start ends as a
        -- hook failure rather than ever creating a main job beside the
        -- one still open.
        local batch = peinit.encode_json({ keys = { {
            path = [[Machine\System\Services\pt-ab-ghost]],
            values = { { name = "ExecStartPre", type = "multi", data = { "/bin/sleep 600" } } },
        } } })
        run(vm, "cat > /tmp/pt-ab.json <<'PT_JSON_EOF'\n" .. batch ..
            "\nPT_JSON_EOF\nreg apply /tmp/pt-ab.json"):assert_ok()
        run(vm, "svctl --json reload-config"):assert_ok()

        local before = run(vm,
            "evctl 'EVENTS notify.rejected SINCE 1h ago TAKE 2000' --format jsonl").stdout
        local seen_before = select(2, before:gsub("GenerationMismatch", ""))

        run(vm, "svctl --no-wait start pt-ab-ghost"):assert_ok()
        settle(vm, "pt-ab-ghost", "starting", 30)

        local event = wait_until(function()
            local out = run(vm,
                "evctl 'EVENTS notify.rejected SINCE 1h ago TAKE 2000' --format jsonl").stdout
            if select(2, out:gsub("GenerationMismatch", "")) <= seen_before then return nil end
            for _, line in ipairs(peinit.lines(out)) do
                if line:find("GenerationMismatch", 1, true)
                    and line:find("pt-ab-ghost", 1, true) then
                    return line
                end
            end
            return nil
        end, { timeout = 15, interval = 1,
               desc = "a READY=1 from the previous incarnation to be rejected" })

        -- Rejected for its generation, naming both: the job's, from the
        -- first start, and the service's, from this one.
        t:assert(event:find("job_generation: 1", 1, true)
            and event:find("runtime_generation: 2", 1, true),
            "the rejection names the stale generation against the current one: " .. event)

        -- And it changed nothing: the service is still Starting, not
        -- satisfied by a readiness report that was not about this start.
        local view = status(vm, "pt-ab-ghost")
        t:assert_eq(view.state, "starting",
            "the stale READY=1 did not make the new incarnation Active")
    end)

-- Section 4: the shutdown wave asks the root.

test("the shutdown wave probes the service root: main/ empty with the root populated abandons the service",
    { spec = "peinit *trans.the-two-paths-into-abandoned-probe-different-cgroups" },
    function(t)
        -- The same arrangement as the explicit stop above — main process
        -- escaped, main/ empty, a live process in pt-outside — met by the
        -- shutdown wave instead. The wave kills the whole root, so the
        -- keeper keeps replacing what it takes.
        local wave = peinit.boot({
            name = "abandonwave",
            append = "peios.quiet=0",
            files = peinit.merge(FILES, peinit.seed("pt-abandon-wave", {
                { path = [[Machine\System]] },
                BOOT_KEY,
                { path = [[Machine\System\Services]] },
                stuck("pt-ab-wave"),
            })),
        })
        local ok, err = pcall(function()
            local root = CGROUP .. "pt-ab-wave"
            start_and_escape(wave, "pt-ab-wave")
            run(wave, "mkdir -p " .. root .. "/pt-outside"):assert_ok()
            keeper(wave, root .. "/pt-outside", 90)
            wait_until(function()
                local held = procs(wave, root .. "/pt-outside")
                return held and #held > 0 or nil
            end, { timeout = 10, interval = 0.3, desc = "the keeper to populate pt-outside" })
            t:assert_eq(#(procs(wave, root .. "/main") or { "?" }), 0,
                "main/ is empty going into the shutdown")

            peinit.settle(wave)
            pcall(function() wave:run("svctl shutdown poweroff", { timeout = 20 }) end)

            -- "peinit: shutdown abandoned" is the wave's own line for a
            -- service whose cgroup it could not empty. Had the wave asked
            -- main/, it would have found it empty, reclaimed the tree and
            -- moved on without one.
            local seen = pcall(wait_until, function()
                return wave:console():read_log()
                    :find("peinit: shutdown abandoned pt-ab-wave", 1, true) and true or nil
            end, { timeout = 90, interval = 0.5,
                   desc = "the shutdown wave to give pt-ab-wave up" })
            local mentions = {}
            for _, text in ipairs(peinit.lines(wave:console():read_log())) do
                if text:find("pt-ab-wave", 1, true) then mentions[#mentions + 1] = text end
            end
            t:assert(seen,
                "the wave found the root populated and gave the service up: " ..
                table.concat(mentions, " | "))
        end)
        pcall(function() wave:shutdown() end)
        if not ok then error(err, 0) end
    end)
