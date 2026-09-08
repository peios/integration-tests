-- peinit TRM §6.5 — the two claims about reload that need a service
-- able to speak the notification protocol, and §6.1's stale-generation
-- invariant.
--
-- The signal path has no command exit to watch, so peinit infers what
-- happened from the main process's own notifications: a two-second
-- detection window, an extended wait if `RELOADING=1` lands inside it,
-- and `READY=1` at any time to confirm. Reaching any of that from the
-- suite needs a service that sends those datagrams, which is
-- `pt-notify` (tests/tools/pt-notify.c).
--
-- `ExecReload = signal:SIGWINCH` rather than the default SIGHUP,
-- because pt-notify has no signal handler and SIGHUP would kill it: a
-- reload that takes the service's main process with it is not a reload
-- anyone can then watch. SIGWINCH's default action is to ignore, so the
-- signal is delivered, the path is the signal path, and the process
-- lives to answer.
--
-- The scripts here send `RELOADING=1` on a one-second cadence rather
-- than once. A pt-notify script cannot react to a signal, so the
-- alternative is racing the test's `svctl reload` against a single
-- datagram somewhere in a two-second window. On a cadence, whenever the
-- reload begins the next `RELOADING=1` is within a second of it, and a
-- copy sent while the service is not Reloading is a documented no-op
-- (execution/notify/reload.rs: the field is recorded and ignored).
--
-- Two things have no route from the guest:
--
--   the console half of
--   reload.an-unconfirmed-reload-is-reported-on-the-console-and-audited
--     peinit pushes that line at error severity, which "does not
--     override another process owning the terminal"
--     (runtime/console/mod.rs). This image runs a console login, so
--     peinit's own console messages are gated off from Phase 2 onwards,
--     and stopping `login-console` does not bring them back. The audit
--     half is asserted below, and it carries the same sentence.
--
--   state.a-ready-carrying-a-stale-generation-is-rejected
--     A READY=1 from a previous incarnation needs that incarnation's
--     process to still be alive after the generation has advanced.
--     job/store/create.rs forbids a second live main job, so the
--     previous process is always reaped first -- and a reaped pid cannot
--     be forged into credentials either, the kernel answering ESRCH. The
--     invariant holds by construction rather than by a check the suite
--     can trip.

local peinit = require("helpers.peinit")
peinit.claim(1)

local vm = peinit.boot({ name = "nfreload", files = peinit.tool("pt-notify") })

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

--- `[send RELOADING=1, sleep 1]` repeated `count` times.
local function reloading_cadence(count)
    local steps = {}
    for _ = 1, count do
        steps[#steps + 1] = "send"
        steps[#steps + 1] = "RELOADING=1"
        steps[#steps + 1] = "sleep"
        steps[#steps + 1] = "1"
    end
    return steps
end

--- Define and start a pt-notify service on the signal reload path, and
--- wait until it is Active and has announced itself.
local function launch(name, steps, values)
    local arguments = { "--log", "/run/" .. name .. ".log", "sleep", "1",
                        "write", "/run/" .. name .. ".up", "ok" }
    for _, step in ipairs(steps) do arguments[#arguments + 1] = step end
    arguments[#arguments + 1] = "sleep"
    arguments[#arguments + 1] = "100000"

    local base = {
        { name = "ImagePath", type = "sz", data = "/usr/bin/pt-notify" },
        { name = "Arguments", type = "multi", data = arguments },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "RestartPolicy", type = "dword", data = 0 },
        -- SIGWINCH is ignored by default, so the process survives its
        -- own reload and can go on answering.
        { name = "ExecReload", type = "sz", data = "signal:SIGWINCH" },
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
    vm:run("svctl --json --no-wait start " .. name):assert_ok()
    wait_until(function()
        return vm:run("test -f /run/" .. name .. ".up"):ok() or nil
    end, { timeout = 90, interval = 0.2, desc = name .. " to come up" })
end

test("the signal path resolves on the main process's own notifications",
    { spec = "peinit *reload.the-signal-path-resolves-on-the-main-processs-notifications" },
    function(t)
        -- There is no command whose exit could say the reload finished.
        -- The service announces one with RELOADING=1 and finishes it
        -- with READY=1, and peinit's answer to the waiting administrator
        -- is built out of those two datagrams and nothing else.
        launch("pt-rl-confirm", (function()
            local steps = reloading_cadence(5)
            steps[#steps + 1] = "send"
            steps[#steps + 1] = "READY=1"
            return steps
        end)(), {
            -- The extended wait is StartTimeout, and it has to outlast
            -- the rest of the cadence.
            { name = "StartTimeout", type = "dword", data = 30 },
        })

        -- A waiting reload, so the answer is the operation's outcome
        -- rather than an acknowledgement of the request. `--wait` is
        -- explicit because `svctl reload` does not wait by default, and
        -- an ack carries no `mode`.
        local out = vm:run("svctl --json --wait reload pt-rl-confirm", { timeout = 90 })
        out:assert_ok()
        local view = json.decode(out.stdout)
        t:assert_eq(view.mode, "confirmed",
            "the reload was resolved as confirmed by the process's READY=1: "
            .. out.stdout)
        t:assert_eq(status("pt-rl-confirm").state, "active",
            "and the service is Active again")
    end)

test("a reload announced and never finished is reported on the console and audited",
    { spec = "peinit *reload.an-unconfirmed-reload-is-reported-on-the-console-and-audited" },
    function(t)
        -- This service announces a reload and then goes quiet: the
        -- extended wait expires with no READY=1, which is the case the
        -- detection protocol exists to catch. A reload issued without
        -- waiting -- the default for anything but this test's own
        -- instrument -- would otherwise resolve silently, so peinit says
        -- so on the console and audits it.
        launch("pt-rl-unconfirmed", reloading_cadence(5), {
            -- Five seconds of extended wait after the cadence stops.
            { name = "StartTimeout", type = "dword", data = 5 },
        })

        vm:run("svctl --json --no-wait reload pt-rl-unconfirmed"):assert_ok()

        -- The audit record, which is where the report is asserted.
        --
        -- The console half of this claim is not observable from this
        -- profile. peinit pushes the line at error severity, and an
        -- error "does not override another process owning the terminal"
        -- (runtime/console/mod.rs) -- and this image runs a console
        -- login, so from Phase 2 onwards peinit's own console messages
        -- are gated off. Stopping `login-console` does not bring them
        -- back either. What can be asserted is that the report was made,
        -- and it carries the same sentence the console line does.
        local record = wait_until(function()
            local out = vm:run(
                "revstrm --snapshot --pretty --type 'service.reload_unconfirmed'",
                { timeout = 60 })
            return out.stdout:find("pt%-rl%-unconfirmed") and out.stdout or nil
        end, { timeout = 90, interval = 0.5,
               desc = "a service.reload_unconfirmed event for the service" })
        t:assert(record:find(
            "service pt-rl-unconfirmed signalled RELOADING=1 but never " ..
            "completed reload", 1, true),
            "the audited record says what happened rather than only that " ..
            "something did: " .. record)

        -- A failed reload never takes a running service out of Active,
        -- and an unconfirmed one is no exception.
        t:assert_eq(status("pt-rl-unconfirmed").state, "active",
            "the service is still Active")
    end)
