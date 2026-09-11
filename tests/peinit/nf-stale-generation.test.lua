-- peinit TRM §10.5 step 5 — a notification whose activation generation is
-- not the service's current one is rejected as a previous incarnation's.
--
-- nf-notify.test.lua's header long claimed this had no route from a
-- guest, on the premise that a live previous-incarnation process cannot
-- exist -- job/store/create.rs forbids a second live main job, so the
-- previous process is always reaped before the generation advances. That
-- premise is wrong, and group E found the route (state-abandoned.test.lua):
-- an *Abandoned* service is exactly a service whose previous main process
-- is still alive and still its current main job after the generation has
-- moved on.
--
-- The provocation is failure-unkillable.test.lua's, applied to a
-- pt-notify main process:
--
--   * The process ignores SIGTERM (`trap ''` sets SIG_IGN, which survives
--     the exec into pt-notify) and is moved out of its main/ cgroup, so a
--     stop escalates to a cgroup kill the process is no longer in. A
--     keeper keeps main/ populated across the post-kill deadline, so the
--     stop gives up and abandons the service with its main job still open.
--   * A reset returns the service to Inactive without closing that job.
--   * A start whose first job is a slow ExecStartPre hook enters Starting
--     -- the generation increment -- without ever creating a main job of
--     its own, so the escaped process is still the service's current main
--     job, now at the previous generation.
--
-- The escaped pt-notify sends READY=1 every second throughout. Once the
-- generation has advanced, its datagram meets the generation check
-- (execution/notify/auth.rs) and is published as notify.rejected with the
-- job's generation against the service's.
--
-- Every wait is bounded and every background process has its stdio sent
-- to /dev/null: one that inherits the agent's pipes holds vm:run open for
-- as long as it lives, and the keeper's children live for minutes.

local peinit = require("helpers.peinit")
peinit.claim(1)

local CGROUP = "/sys/fs/cgroup/peinit/"
local ESCAPE = "/sys/fs/cgroup/pt-escape"
local NAME = "pt-sg-ghost"
local ROOT = CGROUP .. NAME

local FILES = {
    -- keeper.sh CGROUP ROUNDS: once a second, for ROUNDS seconds, fork a
    -- long sleep into CGROUP. The keeper moves itself into pt-escape first
    -- so no kill aimed at the service tree takes it.
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

--- A pt-notify that ignores SIGTERM and sends READY=1 every second for
--- two minutes. `trap ''` survives the exec, and the exec keeps the pid,
--- so the process sending is the service's main job.
local function ghost_arguments()
    local script = { "trap '' TERM; exec /usr/bin/pt-notify --log /run/pt-sg.log sleep 1" }
    for _ = 1, 120 do script[#script + 1] = "send READY=1 sleep 1" end
    script[#script + 1] = "sleep 100000"
    return { "-c", table.concat(script, " ") }
end

local vm = peinit.boot({
    name = "nfstalegen",
    append = "peios.quiet=0",
    files = peinit.merge(FILES, peinit.tool("pt-notify"), peinit.seed("pt-sg", {
        { path = [[Machine\System]] },
        -- Post-kill deadline up from the five-second default, so a keeper
        -- ticking once a second has the cgroup populated before it fires.
        { path = [[Machine\System\Boot]], values = {
            { name = "PostKillTimeout", type = "dword", data = 10 },
        } },
        { path = [[Machine\System\Services]] },
        { path = [[Machine\System\Services\]] .. NAME, values = {
            { name = "ImagePath", type = "sz", data = "/bin/sh" },
            { name = "Arguments", type = "multi", data = ghost_arguments() },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            -- Notify readiness: the service reaches Active only on a
            -- READY=1 peinit believes, which is the whole subject here.
            { name = "Readiness", type = "dword", data = 0 },
            { name = "RestartPolicy", type = "dword", data = 0 },
            { name = "StopTimeout", type = "dword", data = 2 },
            { name = "StartTimeout", type = "dword", data = 20 },
        } },
    })),
})

local function run(command, seconds)
    return vm:run(command, { timeout = seconds or 30 })
end

local function status()
    local out = run("svctl --json status " .. NAME)
    out:assert_ok()
    local view = json.decode(out.stdout)
    view.raw = out.stdout
    return view
end

local function settle(want, seconds)
    return wait_until(function()
        local view = status()
        return view.state == want and view or nil
    end, { timeout = seconds or 60, interval = 0.5, desc = NAME .. " to reach " .. want })
end

local function procs(path)
    local ok, text = pcall(function() return vm:read_file(path .. "/cgroup.procs") end)
    if not ok then return nil end
    return peinit.lines(text)
end

--- notify.rejected events still in the ring, as raw payload text.
local function rejections()
    local out = run("revstrm --snapshot --pretty --type 'notify.rejected'", 60)
    out:assert_ok()
    local events, current = {}, nil
    for line in out.stdout:gmatch("[^\r\n]+") do
        if line:match("notify%.rejected%s*$") then
            current = ""
            events[#events + 1] = { payload = current, ref = #events + 1 }
        elseif current and line:match("^%s") then
            events[#events].payload = events[#events].payload .. line .. "\n"
        end
    end
    return events
end

test("a datagram carrying a stale activation generation is rejected",
    { spec = "peinit *notify.a-stale-activation-generation-is-rejected" },
    function(t)
        -- Bring the ghost up (Notify readiness, so its own first READY=1
        -- makes it Active) and move its process out of main/.
        run("svctl --no-wait start " .. NAME):assert_ok()
        local up = wait_until(function()
            local view = status()
            return view.state == "active" and view.current_job
                and view.current_job.pid and view or nil
        end, { timeout = 60, interval = 0.5, desc = NAME .. " to be Active with a main process" })
        local pid = tostring(up.current_job.pid)
        run("mkdir -p " .. ESCAPE):assert_ok()
        run("echo " .. pid .. " > " .. ESCAPE .. "/cgroup.procs"):assert_ok()
        wait_until(function()
            local left = procs(ROOT .. "/main")
            return left and #left == 0 or nil
        end, { timeout = 10, interval = 0.3, desc = "main/ to empty after the move" })

        -- Keep main/ populated, then stop: the kill cannot reach the
        -- escaped process, the deadline finds main/ populated, and the
        -- service is abandoned with its main job left open.
        local keeper = run("/pt/keeper.sh " .. ROOT .. "/main 60 > /dev/null 2>&1 < /dev/null & echo $!")
        keeper:assert_ok()
        local keeper_pid = keeper.stdout:match("(%d+)")
        wait_until(function()
            local held = procs(ROOT .. "/main")
            return held and #held > 0 or nil
        end, { timeout = 10, interval = 0.3, desc = "the keeper to populate main/" })
        run("svctl --no-wait stop " .. NAME):assert_ok()
        settle("abandoned", 60)

        -- The keeper stops; the process it fed die off; the escaped main
        -- process stays alive and is still the service's current main job.
        run("kill " .. keeper_pid)
        run("svctl reset " .. NAME):assert_ok()
        t:assert_eq(status().state, "inactive", "the reset cleared the service")

        -- A start whose first job is a slow ExecStartPre hook: the service
        -- enters Starting -- generation 2 -- but never creates a main job
        -- of its own, so the escaped process (generation 1) is still the
        -- current main job. The hook outlives StartTimeout, so no main job
        -- is ever created beside the one still open.
        local batch = peinit.encode_json({ keys = { {
            path = [[Machine\System\Services\]] .. NAME,
            values = { { name = "ExecStartPre", type = "multi", data = { "/bin/sleep 600" } } },
        } } })
        run("cat > /tmp/pt-sg.json <<'PT_JSON_EOF'\n" .. batch ..
            "\nPT_JSON_EOF\nreg apply /tmp/pt-sg.json"):assert_ok()
        run("svctl --json reload-config"):assert_ok()

        local function mismatches()
            local out = {}
            for _, event in ipairs(rejections()) do
                if event.payload:find("GenerationMismatch", 1, true)
                    and event.payload:find(NAME, 1, true) then
                    out[#out + 1] = event.payload
                end
            end
            return out
        end
        local before = #mismatches()

        run("svctl --no-wait start " .. NAME):assert_ok()
        settle("starting", 30)

        -- The escaped process's next READY=1 now carries generation 1
        -- while the service is at generation 2, and is rejected.
        local reason = wait_until(function()
            local found = mismatches()
            return #found > before and found[#found] or nil
        end, { timeout = 20, interval = 1,
               desc = "a READY=1 from the previous incarnation to be rejected" })

        t:assert(reason:find("job_generation: 1", 1, true)
            and reason:find("runtime_generation: 2", 1, true),
            "the rejection names the stale generation against the current one: " .. reason)

        -- And it changed nothing: a READY=1 from the previous incarnation
        -- cannot mark the replacement ready. The service is still Starting.
        t:assert_eq(status().state, "starting",
            "the stale READY=1 did not make the new incarnation Active")

        run("kill -9 " .. pid)
    end)
