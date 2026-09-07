-- peinit TRM §6.4 — the backoff delay and the restart budget: how long a
-- pending restart waits, and what resets the counter that ends the
-- retries.
--
-- The budget counter is not on the control wire, so every claim about it
-- is asserted through the one thing it decides: whether the next failure
-- is another Backoff or a Failed carrying `restart_budget_exhausted`. A
-- definition with `RestartMaxRetries=1` turns that into a single bit --
-- a service whose counter was cleared gets one more Backoff, one whose
-- counter was preserved does not -- which is what makes the reset rules
-- testable at all.
--
-- The delay is asserted the same way round: the services stamp `/run`
-- with the wall clock on every launch, and the gaps between stamps are
-- the delays peinit actually waited. `date +%s` is whole seconds, so the
-- assertions are on bounds rather than on equality.

local peinit = require("helpers.peinit")
peinit.claim(1)

local FILES = {
    -- Stamps and crashes at once: the gaps between its stamps are
    -- backoff delays and nothing else.
    ["pt/bg-stamp.sh"] = [[
/bin/date +%s >> /run/pt-bg-stamp.log
exit 1
]],
    -- The same, for the service whose delay is asked to overflow.
    ["pt/bg-cap.sh"] = [[
/bin/date +%s >> /run/pt-bg-cap.log
exit 1
]],
    -- Stays up for four seconds and then fails. Under a window shorter
    -- than four seconds the counter resets on every life; under a longer
    -- one it never does.
    ["pt/bg-live.sh"] = [[
/bin/date +%s >> /run/pt-bg-$1.log
/bin/sleep 4
exit 1
]],
    -- Fails, then succeeds, then fails. The middle run is a clean exit
    -- to Inactive, which is one of the two events §6.4 says zeroes the
    -- counter.
    ["pt/bg-clean.sh"] = [[
n=$(cat /run/pt-bg-clean.n 2>/dev/null || echo 0)
n=$((n + 1))
echo $n > /run/pt-bg-clean.n
if [ $n -eq 2 ]; then
    /bin/sleep 2
    exit 0
fi
exit 1
]],
}

local function service(name, values)
    local base = { { name = "Identity", type = "sz", data = "SYSTEM" } }
    for _, value in ipairs(values) do base[#base + 1] = value end
    return { path = [[Machine\System\Services\]] .. name, values = base }
end

local BOOT = { name = "Triggers", type = "multi", data = { "boot" } }
local NOTIFY = { name = "Readiness", type = "dword", data = 0 }
local ALIVE = { name = "Readiness", type = "dword", data = 1 }
local ALWAYS = { name = "RestartPolicy", type = "dword", data = 2 }
local FALSE = { name = "ImagePath", type = "sz", data = "/bin/false" }

--- A service whose life is four seconds long, parameterised by the
--- window it is measured against.
local function four_second_life(name, tag, window, retries)
    return service(name, {
        BOOT, ALIVE, ALWAYS,
        { name = "ImagePath", type = "sz", data = "/bin/sh" },
        { name = "Arguments", type = "multi", data = { "/pt/bg-live.sh", tag } },
        { name = "RestartDelay", type = "dword", data = 1 },
        { name = "RestartMaxRetries", type = "dword", data = retries },
        { name = "RestartWindow", type = "dword", data = window },
    })
end

local SERVICES = {
    { path = [[Machine\System]] },
    { path = [[Machine\System\Services]] },

    -- Four restarts at a one-second base delay: 1, 2, 4, 8.
    service("pt-bg-double", {
        BOOT, NOTIFY, ALWAYS,
        { name = "ImagePath", type = "sz", data = "/bin/sh" },
        { name = "Arguments", type = "multi", data = { "/pt/bg-stamp.sh" } },
        { name = "RestartDelay", type = "dword", data = 1 },
        { name = "RestartMaxRetries", type = "dword", data = 4 },
        { name = "RestartWindow", type = "dword", data = 300 },
    }),

    -- A base delay of 2^32 - 1 seconds, which is about 136 years. The
    -- shift on the first failure is by zero, so nothing has overflowed
    -- yet and only the cap stands between this service and never being
    -- restarted at all.
    service("pt-bg-cap", {
        BOOT, NOTIFY, ALWAYS,
        { name = "ImagePath", type = "sz", data = "/bin/sh" },
        { name = "Arguments", type = "multi", data = { "/pt/bg-cap.sh" } },
        { name = "RestartDelay", type = "dword", data = 4294967295 },
        { name = "RestartMaxRetries", type = "dword", data = 3 },
        { name = "RestartWindow", type = "dword", data = 300 },
    }),

    -- Two services with identical four-second lives and identical
    -- budgets, differing only in the window they are measured against.
    four_second_life("pt-bg-window", "window", 2, 2),
    four_second_life("pt-bg-clock", "clock", 6, 2),

    -- Started by hand: a crash with a long delay, so the service parks
    -- in Backoff for as long as a test needs it to.
    service("pt-bg-preserve", {
        NOTIFY, ALWAYS, FALSE,
        { name = "RestartDelay", type = "dword", data = 25 },
        { name = "RestartMaxRetries", type = "dword", data = 1 },
        { name = "RestartWindow", type = "dword", data = 300 },
    }),
    service("pt-bg-defer", {
        NOTIFY, ALWAYS, FALSE,
        { name = "RestartDelay", type = "dword", data = 25 },
        { name = "RestartMaxRetries", type = "dword", data = 5 },
        { name = "RestartWindow", type = "dword", data = 300 },
    }),

    -- Fails, succeeds, fails. A budget of one, so the third run's
    -- outcome says whether the clean exit in the middle cleared the
    -- counter.
    service("pt-bg-clean", {
        ALIVE,
        { name = "ImagePath", type = "sz", data = "/bin/sh" },
        { name = "Arguments", type = "multi", data = { "/pt/bg-clean.sh" } },
        { name = "RestartPolicy", type = "dword", data = 1 },
        { name = "RestartDelay", type = "dword", data = 1 },
        { name = "RestartMaxRetries", type = "dword", data = 1 },
        { name = "RestartWindow", type = "dword", data = 300 },
    }),
}

local vm = peinit.boot({
    name = "budget",
    files = peinit.merge(FILES, peinit.seed("pt-budget", SERVICES)),
})

local function status(name)
    local out = vm:run("svctl --json status " .. name)
    out:assert_ok()
    return json.decode(out.stdout)
end

local function settle(name, want, desc)
    return wait_until(function()
        local view = status(name)
        return view.state == want and view or nil
    end, { timeout = 120, interval = 0.3, desc = desc or (name .. " to reach " .. want) })
end

local function stamps(path)
    local ok, text = pcall(function() return vm:read_file(path) end)
    if not ok then return {} end
    local out = {}
    for _, line in ipairs(peinit.lines(text)) do out[#out + 1] = tonumber(line) end
    return out
end

test("the backoff delay doubles on each consecutive failure",
    { spec = "peinit *restart.the-delay-doubles-and-caps-at-sixty-seconds" },
    function(t)
        -- RestartDelay is one second and the process fails instantly, so
        -- the gaps between launches are the delays: 1, 2, 4, 8.
        local launches = wait_until(function()
            local seen = stamps("/run/pt-bg-stamp.log")
            return #seen >= 5 and seen or nil
        end, { timeout = 120, interval = 0.5, desc = "five launches of pt-bg-double" })

        local gaps = {}
        for index = 2, 5 do gaps[#gaps + 1] = launches[index] - launches[index - 1] end
        t:assert(gaps[1] <= 2,
            "the first delay is about the base delay: " .. gaps[1] .. "s")
        t:assert(gaps[4] >= 7,
            "and the fourth is about eight times it: " .. gaps[4] .. "s")
        for index = 2, 4 do
            t:assert(gaps[index] >= gaps[index - 1],
                "each delay is at least the last: " ..
                table.concat(gaps, ", "))
        end
        t:assert(gaps[4] > gaps[1],
            "so the delay grew rather than staying put: " .. table.concat(gaps, ", "))
    end)

test("a stop in Backoff cancels the restart and keeps the accrued failures; a reset clears them",
    {
        spec = {
            "peinit *restart.a-stop-during-backoff-cancels-the-pending-restart",
            "peinit *restart.a-stop-in-backoff-preserves-the-accrued-failures",
            "peinit *restart.a-clean-exit-or-a-reset-also-zeroes-the-counter",
        },
    },
    function(t)
        -- One failure spends the whole budget of one, so what the next
        -- start does is a direct readout of the counter.
        vm:run("svctl --json --no-wait start pt-bg-preserve"):assert_ok()
        settle("pt-bg-preserve", "backoff", "pt-bg-preserve's first crash")

        -- The stop cancels the pending restart outright rather than
        -- waiting out the twenty-five seconds.
        vm:run("svctl stop pt-bg-preserve"):assert_ok()
        local stopped = status("pt-bg-preserve")
        t:assert_eq(stopped.state, "inactive",
            "the stop took it straight to Inactive")
        t:assert_eq(stopped.cause, "explicit_stop",
            "cancelling the pending restart")

        -- The failure it accrued survived the stop: the next crash finds
        -- the budget already spent.
        vm:run("svctl --json --no-wait start pt-bg-preserve"):assert_ok()
        local spent = settle("pt-bg-preserve", "failed",
            "pt-bg-preserve's second crash")
        t:assert_eq(spent.cause, "restart_budget_exhausted",
            "the stop preserved the accrued failure, so one more spent the budget")

        -- A reset does clear it, and the same crash is a Backoff again.
        vm:run("svctl reset pt-bg-preserve"):assert_ok()
        t:assert_eq(status("pt-bg-preserve").cause, "explicit_reset",
            "the reset cleared the Failed state")
        vm:run("svctl --json --no-wait start pt-bg-preserve"):assert_ok()
        local again = settle("pt-bg-preserve", "backoff",
            "pt-bg-preserve to be restarted after the reset")
        t:assert_eq(again.cause, "process_crash",
            "with a fresh budget, the identical crash is restart-eligible again")
    end)

test("a clean exit to Inactive also zeroes the counter",
    { spec = "peinit *restart.a-clean-exit-or-a-reset-also-zeroes-the-counter" },
    function(t)
        -- pt-bg-clean fails, is restarted, succeeds, and stops. Its
        -- budget is one, so the failure before the success spent it; if
        -- the clean exit did not clear the counter, the next failure
        -- would be terminal.
        vm:run("svctl --json --no-wait start pt-bg-clean"):assert_ok()
        settle("pt-bg-clean", "inactive", "pt-bg-clean to fail once and then succeed")
        t:assert_eq(status("pt-bg-clean").cause, "clean_exit",
            "the second run exited cleanly")
        t:assert_eq(vm:read_file("/run/pt-bg-clean.n"):match("%d+"), "2",
            "having run twice: once failing, once succeeding")

        -- The third run fails exactly as the first did. A preserved
        -- counter would make it Failed; a cleared one makes it Backoff.
        vm:run("svctl --json --no-wait start pt-bg-clean"):assert_ok()
        local view = settle("pt-bg-clean", "backoff",
            "pt-bg-clean's third run to be restart-eligible")
        t:assert_eq(view.cause, "process_crash",
            "the clean exit zeroed the counter, so the next failure was not the last")
    end)

test("an explicit start during Backoff honours the remaining delay",
    { spec = "peinit *restart.an-explicit-start-during-backoff-honours-the-remaining-delay" },
    function(t)
        vm:run("svctl --json --no-wait start pt-bg-defer"):assert_ok()
        settle("pt-bg-defer", "backoff", "pt-bg-defer to enter its twenty-five-second backoff")

        -- The start is admitted -- it produces an operation rather than
        -- an error -- and then waits.
        local ack = json.decode(vm:run("svctl --json --no-wait start pt-bg-defer").stdout)
        t:assert(ack.operation_id, "the start was admitted as an operation")
        local operation = json.decode(
            vm:run("svctl --json operation-status " .. ack.operation_id).stdout).operation
        t:assert_eq(operation.state, "pending",
            "and it is deferred rather than running: " .. tostring(operation.state))

        -- Six seconds is nowhere near the twenty-five remaining, and the
        -- service has not moved.
        vm:run("sleep 6")
        local view = status("pt-bg-defer")
        t:assert_eq(view.state, "backoff",
            "the service is still waiting out its delay: " .. view.state)
        t:assert(not view.current_job,
            "with no process, so the start did not short-circuit the delay")
    end)

test("the budget resets only after the service holds Active for RestartWindow",
    {
        spec = {
            "peinit *restart.the-budget-resets-only-after-restartwindow-active",
            "peinit *restart.a-service-healthy-for-a-window-between-crashes-never-exhausts-its-budget",
            "peinit *restart.a-crash-restarts-the-window-clock",
        },
    },
    function(t)
        -- pt-bg-window and pt-bg-clock run the same script, stay up for
        -- the same four seconds, and have the same budget of two. The
        -- only difference is the window: two seconds against six.
        --
        -- Four seconds of health clears a two-second window, so
        -- pt-bg-window starts every failure from zero and can never
        -- exhaust its budget.
        local window = wait_until(function()
            local seen = stamps("/run/pt-bg-window.log")
            return #seen >= 4 and seen or nil
        end, { timeout = 120, interval = 0.5, desc = "four lives of pt-bg-window" })
        t:assert(#window >= 4,
            "a service healthy for a window between crashes kept being restarted: " ..
            #window .. " lives")
        t:assert(status("pt-bg-window").state ~= "failed",
            "and never reached the end of a budget of two")

        -- Four seconds does not clear a six-second window, and the four
        -- seconds of the previous life do not carry over -- the crash
        -- restarted the clock -- so pt-bg-clock spends its budget on the
        -- third failure however long it has been up in total.
        local clock = settle("pt-bg-clock", "failed",
            "pt-bg-clock to exhaust a budget it is never healthy enough to reset")
        t:assert_eq(clock.cause, "restart_budget_exhausted",
            "the window was never cleared, so the failures accumulated")
        t:assert_eq(#stamps("/run/pt-bg-clock.log"), 3,
            "one life plus two restarts, after twelve seconds of cumulative health " ..
            "that never counted because each crash restarted the clock")
    end)

test("the backoff delay saturates at the cap rather than wrapping",
    {
        spec = {
            "peinit *restart.the-backoff-arithmetic-saturates-rather-than-wrapping",
            "peinit *restart.the-delay-doubles-and-caps-at-sixty-seconds",
        },
    },
    function(t)
        -- A RestartDelay of 2^32 - 1 seconds. Wrapping would produce
        -- some small delay and the service would be back in moments;
        -- honouring it literally would mean no restart this century.
        -- Saturating at the cap means one minute.
        local first = wait_until(function()
            local seen = stamps("/run/pt-bg-cap.log")
            return seen[1] and seen or nil
        end, { timeout = 60, interval = 0.5, desc = "pt-bg-cap's first launch" })
        t:assert_eq(status("pt-bg-cap").state, "backoff",
            "it is waiting rather than having given up")

        local both = wait_until(function()
            local seen = stamps("/run/pt-bg-cap.log")
            return #seen >= 2 and seen or nil
        end, { timeout = 150, interval = 1, desc = "pt-bg-cap to be restarted" })
        local delay = both[2] - both[1]
        t:assert(delay >= 55 and delay <= 70,
            "the delay saturated at the sixty-second cap rather than wrapping to " ..
            "something short or standing at 2^32 - 1: " .. delay .. "s")
        t:assert(first[1] <= both[1], "the stamps are in order")
    end)
