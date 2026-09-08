-- peinit TRM §6.6 — the two notification fields a running service uses
-- to move the deadlines it is held to.
--
-- `state-watchdog.test.lua` covers the half a definition alone decides:
-- `WatchdogTimeout` arms a timer and a service that misses a ping is
-- failed. Everything here needs a service that can actually send
-- `WATCHDOG_USEC` and `EXTEND_TIMEOUT_USEC`, which is `pt-notify`
-- (tests/tools/pt-notify.c) running as the service's own main process.
--
-- Every claim in this article is about *when* something happened, so
-- every test here is a stopwatch: a deadline is asserted by measuring
-- how long the service survived and comparing it against the deadline it
-- would have had without the message. The bounds are wide -- these are
-- real seconds on a VM sharing a host -- and they are wide on the side
-- that cannot produce a false pass. A test that says "sooner than 60
-- seconds" is bounded at 25, not at 4.
--
-- One trap is worth naming, because it cost an earlier pass an
-- afternoon. `svctl start --wait` is *not* an instrument for these:
-- control_connection/wait.rs answers a waiter OPERATION_TIMEOUT once the
-- operation's own maximum lifetime is up, and that lifetime is
-- `created_at + StartTimeout` with no extension applied to it
-- (operation_maintenance/deadlines.rs). A service that has legitimately
-- extended its readiness deadline goes on running while its waiter has
-- already been told it timed out. So every measurement below is taken
-- from the service's own state, never from a start command's answer.
--
-- One claim here has no route from the guest:
--
--   wdog.during-shutdown-the-stricter-of-the-two-caps-wins
--     Showing which cap bound needs a service that occupies Stopping for
--     longer than its own deadline *and* sends EXTEND_TIMEOUT_USEC while
--     it is there. The first half needs SIGTERM ignored and the second
--     needs the notification protocol; the image's `sh -c "trap '' TERM"`
--     does the first and pt-notify does the second, and nothing does
--     both. A `trap` step in pt-notify would close it.

local peinit = require("helpers.peinit")
peinit.claim(1)

local vm = peinit.boot({ name = "nfwdog", files = peinit.tool("pt-notify") })

local function apply(keys)
    local batch = peinit.encode_json({ keys = keys })
    vm:run("cat > /tmp/nf.json <<'PT_JSON_EOF'\n" .. batch ..
        "\nPT_JSON_EOF\nreg apply /tmp/nf.json"):assert_ok()
end

local function status(name)
    local out = vm:run("svctl --json status " .. name)
    if not out:ok() then return nil end
    if out.stdout:find("UNKNOWN_SERVICE", 1, true) then return nil end
    local ok, view = pcall(json.decode, out.stdout)
    if not ok then return nil end
    return view
end

--- Define a pt-notify service whose script is `steps`.
---
--- The opening `sleep 1` is the trap `peinit.tool` documents: peinit has
--- not processed the launch immediately after exec, so a first datagram
--- is refused as an unauthenticated sender and lost. Every measurement
--- below therefore starts about a second after the operation does, which
--- is why the bounds allow for it.
local function define(name, steps, values)
    local arguments = { "--log", "/run/" .. name .. ".log", "sleep", "1" }
    for _, step in ipairs(steps) do arguments[#arguments + 1] = step end
    arguments[#arguments + 1] = "sleep"
    arguments[#arguments + 1] = "100000"

    local base = {
        { name = "ImagePath", type = "sz", data = "/usr/bin/pt-notify" },
        { name = "Arguments", type = "multi", data = arguments },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "RestartPolicy", type = "dword", data = 0 },
    }
    for _, value in ipairs(values or {}) do
        local replaced = false
        for index, existing in ipairs(base) do
            if existing.name == value.name then
                base[index] = value
                replaced = true
            end
        end
        if not replaced then base[#base + 1] = value end
    end

    apply({ { path = [[Machine\System\Services\]] .. name, values = base } })
    wait_until(function() return status(name) ~= nil or nil end,
        { timeout = 60, interval = 0.3,
          desc = "the registry watch to deliver " .. name })
end

--- Start `name` and wait until it settles into one of `states`, timing
--- how long that took.
---
--- Returns the view and the elapsed seconds. `--no-wait` is not a
--- convenience: `svctl start` waits by default, and for a service that
--- is deliberately slow to become ready that means the command blocks
--- for the whole operation lifetime and answers OPERATION_TIMEOUT --
--- which would both distort the measurement and be the wrong instrument
--- (see the note at the top of the file).
local function time_to(name, states, timeout, desc)
    local wanted = {}
    for _, state in ipairs(states) do wanted[state] = true end
    local started = os.time()
    vm:run("svctl --json --no-wait start " .. name):assert_ok()
    local view = wait_until(function()
        local current = status(name)
        return current and wanted[current.state] and current or nil
    end, { timeout = timeout or 120, interval = 0.2,
           desc = desc or (name .. " to settle") })
    return view, os.time() - started
end

--- Watch a service for `seconds` and fail if it ever leaves `state`.
local function stays(t, name, state, seconds, why)
    local deadline = os.time() + seconds
    while os.time() < deadline do
        local view = status(name)
        t:assert(view and view.state == state,
            why .. " (after " .. (seconds - (deadline - os.time())) ..
            "s it was " .. tostring(view and view.state) .. ")")
        vm:run("sleep 2")
    end
end

test("EXTEND_TIMEOUT_USEC replaces the phase's deadline, so a small value shortens it",
    {
        spec = {
            "peinit *wdog.extend-timeout-usec-extends-the-current-phases-deadline",
            "peinit *wdog.an-extension-replaces-the-deadline-rather-than-adding-to-it",
            "peinit *wdog.a-small-extension-shortens-the-remaining-time",
            "peinit *wdog.both-fields-carry-microseconds",
        },
    },
    function(t)
        -- StartTimeout is sixty seconds and the service asks for two.
        -- Nothing about "extend" makes that a no-op or an addition: the
        -- deadline becomes two seconds from the message, and the service
        -- -- which never sends READY=1 -- is failed for readiness about
        -- a minute earlier than its definition alone would have failed
        -- it.
        --
        -- 2 000 000 read as two seconds and not as two thousand is also
        -- the microseconds claim: at milliseconds it would have been
        -- half an hour, and at seconds it would have outlived the
        -- definition's own timeout.
        define("pt-wd-short", { "send", "EXTEND_TIMEOUT_USEC=2000000" }, {
            { name = "Readiness", type = "dword", data = 0 },
            { name = "StartTimeout", type = "dword", data = 60 },
        })
        local view, elapsed = time_to("pt-wd-short", { "failed" }, 120,
            "pt-wd-short to be failed for readiness")

        t:assert_eq(view.cause, "readiness_timeout",
            "the readiness deadline is what fired")
        t:assert(elapsed < 25,
            "and it fired at the extension's two seconds rather than at " ..
            "the definition's sixty (" .. elapsed .. "s)")
    end)

test("an extension lengthens the deadline a service would otherwise miss",
    { spec = "peinit *wdog.extend-timeout-usec-extends-the-current-phases-deadline" },
    function(t)
        -- Two services with the same StartTimeout and the same late
        -- READY=1. One asks for more time and one does not, so the only
        -- difference between reaching Active and being failed is the
        -- message -- which is what makes this about the extension rather
        -- than about how long a start happens to take.
        --
        -- Twelve seconds of silence against a six-second StartTimeout,
        -- and an extension of twenty, which is inside the four-times cap
        -- of twenty-four.
        local script = { "sleep", "12", "send", "READY=1" }
        local extending = { "send", "EXTEND_TIMEOUT_USEC=20000000" }
        for _, step in ipairs(script) do extending[#extending + 1] = step end

        define("pt-wd-nolonger", script, {
            { name = "Readiness", type = "dword", data = 0 },
            { name = "StartTimeout", type = "dword", data = 6 },
        })
        define("pt-wd-longer", extending, {
            { name = "Readiness", type = "dword", data = 0 },
            { name = "StartTimeout", type = "dword", data = 6 },
        })

        local control, control_elapsed =
            time_to("pt-wd-nolonger", { "failed", "active" }, 120,
                "pt-wd-nolonger to settle")
        t:assert_eq(control.state, "failed",
            "the service that asked for nothing missed its StartTimeout")
        t:assert_eq(control.cause, "readiness_timeout",
            "for readiness")
        t:assert(control_elapsed < 12,
            "at about six seconds, before its READY= was ever sent (" ..
            control_elapsed .. "s)")

        local view, elapsed = time_to("pt-wd-longer", { "failed", "active" }, 120,
            "pt-wd-longer to settle")
        t:assert_eq(view.state, "active",
            "and the identical service that asked for twenty seconds got " ..
            "there: " .. tostring(view.cause))
        t:assert(elapsed >= 10,
            "having taken longer than the StartTimeout it was given (" ..
            elapsed .. "s)")
    end)

test("a value beyond four times the base timeout is clamped rather than refused",
    {
        spec = {
            "peinit *wdog.the-extended-deadline-is-capped-at-four-times-the-base-timeout",
            "peinit *wdog.a-value-beyond-the-cap-is-clamped-not-rejected",
        },
    },
    function(t)
        -- StartTimeout is four seconds, so the ceiling is sixteen. The
        -- service asks for six hundred and then stays silent for a
        -- minute. Both halves of the claim are in the one outcome: the
        -- message was not refused, because the service outlived its
        -- four-second base timeout; and it was clamped, because it did
        -- not outlive sixteen.
        define("pt-wd-cap", {
            "send", "EXTEND_TIMEOUT_USEC=600000000",
            "sleep", "60", "send", "READY=1",
        }, {
            { name = "Readiness", type = "dword", data = 0 },
            { name = "StartTimeout", type = "dword", data = 4 },
        })
        local view, elapsed = time_to("pt-wd-cap", { "failed", "active" }, 150,
            "pt-wd-cap to settle")

        t:assert_eq(view.state, "failed",
            "ten minutes was not granted")
        t:assert_eq(view.cause, "readiness_timeout", "the deadline fired")
        t:assert(elapsed > 5,
            "the message was accepted, not refused: the service outlived " ..
            "its four-second StartTimeout (" .. elapsed .. "s)")
        t:assert(elapsed < 45,
            "and the deadline it was given was the sixteen-second ceiling, " ..
            "not the six hundred seconds asked for (" .. elapsed .. "s)")

        -- Clamped, not rejected: a refusal would have been recorded.
        local rejected = vm:run(
            "revstrm --snapshot --pretty --type 'notify.rejected'").stdout
        t:assert(not rejected:find("pt%-wd%-cap"),
            "and nothing was recorded as rejected: " .. rejected)
    end)

test("repeated extensions cannot creep past the cap",
    { spec = "peinit *wdog.repeated-extensions-cannot-creep-past-the-cap" },
    function(t)
        -- Six extensions of twelve seconds each, three seconds apart.
        -- Each one on its own is inside the sixteen-second ceiling, so
        -- nothing here is a value that would be clamped in isolation --
        -- and if the ceiling moved with each message the last would put
        -- the deadline at about thirty, comfortably past the READY=1 at
        -- forty. It does not, because the cap is anchored to when the
        -- operation started rather than to the deadline before it.
        local steps = {}
        for _ = 1, 6 do
            steps[#steps + 1] = "send"
            steps[#steps + 1] = "EXTEND_TIMEOUT_USEC=12000000"
            steps[#steps + 1] = "sleep"
            steps[#steps + 1] = "3"
        end
        steps[#steps + 1] = "sleep"
        steps[#steps + 1] = "40"
        steps[#steps + 1] = "send"
        steps[#steps + 1] = "READY=1"

        define("pt-wd-creep", steps, {
            { name = "Readiness", type = "dword", data = 0 },
            { name = "StartTimeout", type = "dword", data = 4 },
        })
        local view, elapsed = time_to("pt-wd-creep", { "failed", "active" }, 150,
            "pt-wd-creep to settle")

        t:assert_eq(view.state, "failed",
            "the run of extensions did not carry the service to its READY=")
        t:assert_eq(view.cause, "readiness_timeout", "the deadline fired")
        t:assert(elapsed < 45,
            "at about the ceiling, rather than being pushed along by each " ..
            "new message (" .. elapsed .. "s)")
    end)

test("an extension in a non-transitional state is ignored",
    { spec = "peinit *wdog.an-extension-in-a-non-transitional-state-is-ignored" },
    function(t)
        -- Active is not a phase with a deadline, so there is nothing for
        -- a request to extend -- and nothing for a request of one
        -- millisecond to *shorten*, which is the failure this asks
        -- about. A service that treated Active as a transition would
        -- have failed within a second of the message.
        define("pt-wd-settled", { "send", "EXTEND_TIMEOUT_USEC=1000" })
        local view = time_to("pt-wd-settled", { "active" }, 90,
            "pt-wd-settled to reach Active")
        t:assert_eq(view.state, "active", "the service is Active")

        stays(t, "pt-wd-settled", "active", 15,
            "a one-millisecond extension against an Active service did nothing")
    end)

test("WATCHDOG_USEC sent while Starting is ignored and the definition applies",
    { spec = "peinit *wdog.watchdog-usec-while-starting-is-ignored" },
    function(t)
        -- The message goes out before READY=1, so the service is still
        -- Starting when it lands. It asks for ten minutes; the
        -- definition says four seconds. If the runtime value had been
        -- taken the service would still be Active a minute later.
        define("pt-wd-early", {
            "send", "WATCHDOG_USEC=600000000",
            "send", "READY=1",
        }, {
            { name = "Readiness", type = "dword", data = 0 },
            { name = "StartTimeout", type = "dword", data = 60 },
            { name = "WatchdogTimeout", type = "dword", data = 4 },
        })
        local view, elapsed = time_to("pt-wd-early", { "failed" }, 120,
            "pt-wd-early to miss a watchdog it never agreed to")

        t:assert_eq(view.cause, "watchdog_timeout",
            "the definition's watchdog is what failed it")
        t:assert(elapsed < 45,
            "at the definition's four seconds rather than the ten minutes " ..
            "it asked for while Starting (" .. elapsed .. "s)")
    end)

test("a runtime interval update re-arms immediately",
    {
        spec = {
            "peinit *wdog.a-runtime-interval-update-re-arms-immediately",
            "peinit *wdog.both-fields-carry-microseconds",
        },
    },
    function(t)
        -- The definition's interval is thirty seconds and no ping is
        -- ever sent, so the definition alone would fail this service at
        -- thirty. It sends WATCHDOG_USEC=3000000 about a second in. A
        -- timer that merely took the new interval from the next ping
        -- would never fire at all, since there is no next ping; one that
        -- waited out the old interval would fire at thirty. It fires at
        -- about four, which is three seconds from the message.
        define("pt-wd-rearm", { "send", "WATCHDOG_USEC=3000000" }, {
            { name = "WatchdogTimeout", type = "dword", data = 30 },
        })
        local view, elapsed = time_to("pt-wd-rearm", { "failed" }, 120,
            "pt-wd-rearm to miss its new interval")

        t:assert_eq(view.cause, "watchdog_timeout", "the watchdog fired")
        t:assert(elapsed < 20,
            "three seconds after the message rather than thirty after the " ..
            "start (" .. elapsed .. "s)")
    end)

test("a runtime value of zero disables the watchdog",
    { spec = "peinit *wdog.a-runtime-value-of-zero-disables-the-watchdog" },
    function(t)
        -- Two services with the same four-second WatchdogTimeout and the
        -- same silence. One sends WATCHDOG_USEC=0 and one does not.
        define("pt-wd-armed2", {}, {
            { name = "WatchdogTimeout", type = "dword", data = 4 },
        })
        define("pt-wd-zero", { "send", "WATCHDOG_USEC=0" }, {
            { name = "WatchdogTimeout", type = "dword", data = 4 },
        })

        local control = time_to("pt-wd-armed2", { "failed" }, 90,
            "pt-wd-armed2 to be failed by its definition's watchdog")
        t:assert_eq(control.cause, "watchdog_timeout",
            "the control service was failed for a missed ping")

        time_to("pt-wd-zero", { "active" }, 90, "pt-wd-zero to reach Active")
        stays(t, "pt-wd-zero", "active", 20,
            "and the one that sent zero was not, however long it stayed silent")
    end)

test("a runtime interval does not survive a restart",
    { spec = "peinit *wdog.a-runtime-interval-does-not-survive-a-restart" },
    function(t)
        -- The subject's definition says WatchdogTimeout=0 -- no watchdog
        -- at all -- and its own script sends nothing. The interval is
        -- set on it from outside, by a second service forging its pid in
        -- the credentials, so that the runtime value belongs to exactly
        -- one incarnation and the restarted process cannot set it again.
        --
        -- What must happen is that the first incarnation dies of a
        -- watchdog it was given at runtime and the second lives without
        -- one.
        define("pt-wd-revert", { "write", "/run/pt-wd-revert.up", "ok" }, {
            { name = "WatchdogTimeout", type = "dword", data = 0 },
            { name = "RestartPolicy", type = "dword", data = 2 },
            { name = "RestartDelay", type = "dword", data = 1 },
            { name = "RestartMaxRetries", type = "dword", data = 5 },
        })
        local subject = time_to("pt-wd-revert", { "active" }, 90,
            "pt-wd-revert to reach Active")
        local pid = subject.current_job.pid
        local job = subject.current_job.id

        define("pt-wd-setter", {
            "send-cred", tostring(pid), "0", "0", "WATCHDOG_USEC=3000000",
        })
        vm:run("svctl --json --no-wait start pt-wd-setter"):assert_ok()

        local failed = wait_until(function()
            local view = status("pt-wd-revert")
            return view and view.cause == "watchdog_timeout" and view or nil
        end, { timeout = 90, interval = 0.2,
               desc = "pt-wd-revert to be failed by the interval set on it" })
        t:assert_eq(failed.cause, "watchdog_timeout",
            "the runtime interval took effect on the incarnation it was sent to")

        -- RestartPolicy=Always brings it back, and the interval must not
        -- come back with it: the definition says zero, and zero is what
        -- the new incarnation gets.
        local second = wait_until(function()
            local view = status("pt-wd-revert")
            return view and view.state == "active" and view.current_job
                and view.current_job.id ~= job and view or nil
        end, { timeout = 90, interval = 0.3,
               desc = "pt-wd-revert to come back" })
        t:assert(second.current_job.pid ~= pid,
            "a new process is running it")
        stays(t, "pt-wd-revert", "active", 20,
            "and it reverted to the definition's WatchdogTimeout of zero, " ..
            "so nothing failed it for staying silent")
    end)
