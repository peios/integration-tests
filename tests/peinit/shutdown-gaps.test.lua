-- peinit TRM §12.2 step 4 — the stop waves: where registryd goes in them,
-- and what a participant the service table has discarded counts as.
--
-- The console is the oracle, as in shutdown-waves.test.lua: every wave
-- decision has its own line (`shutdown stopping X`, `shutdown waiting for
-- X`, `shutdown killing X`, `shutdown service X exited`), so the plan is
-- legible from outside after the machine has gone. `peios.quiet=0` keeps
-- peinit's narrative on the console once the image's login owns it, and
-- every test settles the image's own services first (PEI-826).
--
-- Each test ends its machine, so each boots its own.

local peinit = require("helpers.peinit")
peinit.claim(1)

local function with_vm(opts, body)
    local vm = peinit.boot(opts)
    local ok, err = pcall(body, vm)
    pcall(function() vm:shutdown() end)
    if not ok then error(err, 0) end
end

local function trigger(vm, command)
    pcall(function() vm:run(command, { timeout = 30 }) end)
end

local function resident(name, extra)
    local values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "100000" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "RestartPolicy", type = "dword", data = 0 },
        { name = "Triggers", type = "multi", data = { "boot" } },
    }
    for _, value in ipairs(extra or {}) do values[#values + 1] = value end
    return { path = [[Machine\System\Services\]] .. name, values = values }
end

--- Every `peinit: shutdown …` line naming a service, in console order:
--- `{verb, service, at}` where `at` is the line's index.
local function shutdown_lines(log)
    local out = {}
    for i, line in ipairs(peinit.lines(log)) do
        local verb, name = line:match("peinit: shutdown (stopping) ([%w%-%._]+)")
        if not verb then verb, name = line:match("peinit: shutdown (waiting for) ([%w%-%._]+)") end
        if not verb then verb, name = line:match("peinit: shutdown (killing) ([%w%-%._]+)") end
        if not verb then
            name = line:match("peinit: shutdown service ([%w%-%._]+) exited")
            if name then verb = "exited" end
        end
        if verb and name ~= "job" then out[#out + 1] = { verb = verb, service = name, at = i } end
    end
    return out
end

test("registryd stops in a wave of its own, after every other participant",
    { spec = "peinit *graceful.registryd-stops-after-every-other-service" },
    function(t)
        -- Nothing declares a dependency on registryd, so the graph alone
        -- would put it in the first wave. A resident of the suite's own is
        -- here so that there is at least one service the image did not
        -- choose among those it has to outlast.
        with_vm({
            name = "shutdown-registryd",
            append = "peios.quiet=0",
            files = peinit.seed("pt-sd-registryd", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Services]] },
                resident("pt-sd-resident"),
            }),
        }, function(vm)
            peinit.settle(vm)
            trigger(vm, "svctl shutdown poweroff")
            vm:console():expect("reboot: Power down", 120)
            local lines = shutdown_lines(vm:console():read_log())

            local registryd, last_other, others = nil, 0, {}
            for _, l in ipairs(lines) do
                if l.service == "registryd" then
                    registryd = registryd or l.at
                else
                    others[l.service] = true
                    last_other = math.max(last_other, l.at)
                end
            end
            t:assert(others["pt-sd-resident"], "the suite's resident was a participant")
            t:assert(registryd, "registryd was stopped by the shutdown, on the console")
            local n = 0
            for _ in pairs(others) do n = n + 1 end
            t:assert(n >= 3, "with several other participants to order it against (" .. n .. ")")
            t:assert(registryd and registryd > last_other,
                "registryd's stop began only after every other participant's last line " ..
                "(registryd at line " .. tostring(registryd) .. ", the others end at " ..
                last_other .. ")")
        end)
    end)

test("a participant the service table has discarded counts as stopped, and its wave closes",
    { spec = "peinit *graceful.a-participant-gone-from-the-table-counts-as-stopped" },
    function(t)
        -- pt-sd-gone requires pt-sd-base, so pt-sd-base is in a wave after
        -- it. pt-sd-gone's definition is withdrawn while it runs: it stays
        -- in the table until it stops and is discarded then, while the
        -- plan fixed at step 3 still names it. Waiting for it would hold
        -- its wave open, pt-sd-base would never be signalled, and only the
        -- global timeout — set here to a minute — could move the sequence.
        with_vm({
            name = "shutdown-gone",
            append = "peios.quiet=0",
            files = peinit.seed("pt-sd-gone", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Boot]], values = {
                    { name = "ShutdownTimeout", type = "dword", data = 60 },
                } },
                { path = [[Machine\System\Services]] },
                resident("pt-sd-gone", {
                    { name = "Requires", type = "multi", data = { "pt-sd-base" } },
                }),
                resident("pt-sd-base"),
            }),
        }, function(vm)
            peinit.settle(vm)
            vm:run([[reg del 'Machine\System\Services\pt-sd-gone' --recursive]]):assert_ok()
            local view = wait_until(function()
                local v = json.decode(vm:run("svctl --json status pt-sd-gone").stdout)
                return v.definition_removed == true and v or nil
            end, { timeout = 20, interval = 0.25, desc = "the withdrawal to be seen" })
            t:assert_eq(view.state, "active", "premise: pt-sd-gone runs on, withdrawn")

            local started = os.time()
            trigger(vm, "svctl shutdown poweroff")
            vm:console():expect("reboot: Power down", 120)
            local took = os.time() - started
            local log = vm:console():read_log()

            local gone_exit, base_stop
            for _, l in ipairs(shutdown_lines(log)) do
                if l.service == "pt-sd-gone" and l.verb == "exited" then gone_exit = l.at end
                if l.service == "pt-sd-base" and l.verb == "stopping" then base_stop = l.at end
            end
            t:assert(gone_exit, "premise: the withdrawn service was a participant, and exited")
            t:assert(base_stop and base_stop > gone_exit,
                "the wave after it opened: pt-sd-base was signalled once pt-sd-gone had gone")
            t:assert(not log:find("peinit: shutdown global timeout expired", 1, true),
                "without the global timeout having to force it")
            t:assert(took < 50, "and the machine powered off well inside it (" .. took .. "s)")
        end)
    end)
