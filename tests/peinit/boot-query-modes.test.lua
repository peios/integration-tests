-- peinit TRM §10.8 — the boot query across the modes a boot can end up
-- in: a Safe boot that was asked for, a Full boot that Phase 2 downgraded
-- to Safe, and a Recovery boot, which has no control socket to ask.
--
-- boot-query.test.lua covers an ordinary Full boot. Each case here needs
-- a command line or a service graph of its own, so each brings its own
-- machine and there is no file-scope VM. The threshold's other two values
-- ride along: the Safe boot turns the check off with
-- `peios.bootattempts=0`, and the downgraded boot sets nothing, so it
-- reports the default.

local peinit = require("helpers.peinit")
peinit.claim(1)

local SERVICES = [[Machine\System\Services]]
local RESIDENT = "#!/bin/sh\nwhile : ; do sleep 30; done\n"
local CRITICAL = { name = "ErrorControl", type = "dword", data = 1 }

local function boot_service(name, extra)
    local values = {
        { name = "ImagePath", type = "sz", data = "/lcl/pt/bqm-resident.sh" },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "Triggers", type = "multi", data = { "boot" } },
    }
    for _, value in ipairs(extra or {}) do values[#values + 1] = value end
    return { path = SERVICES .. [[\]] .. name, values = values }
end

--- `svctl --json boot` on `vm`, decoded, and the raw answer.
local function ask(vm)
    local r = vm:run("svctl --json boot")
    r:assert_ok()
    local ok, decoded = pcall(json.decode, r.stdout)
    assert(ok and type(decoded) == "table" and type(decoded.boot) == "table",
        "svctl --json boot did not answer with a boot object: " .. r.stdout .. r.stderr)
    return decoded.boot, r.stdout
end

local function occurrences(haystack, needle)
    local count, at = 0, 1
    while true do
        local found = haystack:find(needle, at, true)
        if not found then return count end
        count = count + 1
        at = found + 1
    end
end

test("a Safe boot asked for on the command line is reported as requested",
    {
        spec = {
            "peinit *control.boot.mode-is-the-mode-phase-2-booted-in",
            "peinit *control.boot.reason-distinguishes-normal-requested-and-downgraded",
            "peinit *control.boot.max-attempts-is-the-threshold",
            "peinit *control.boot.attempts-is-the-count-phase-1-checked",
        },
    },
    function(t)
        -- A counter of 4 is past the default threshold of 3, so this boot
        -- reaches Phase 2 only because peios.bootattempts=0 turned the
        -- check off. A long grace keeps the reset out of the way, though
        -- `attempts` would not move for it anyway.
        local vm = peinit.boot({
            name = "bq-safe",
            append = "peios.safemode=1 peios.bootattempts=0",
            files = peinit.merge(
                { [".peinit/boot-attempts"] = "4\n" },
                peinit.seed("zz-pt-bq-safe", {
                    { path = [[Machine\System]] },
                    { path = [[Machine\System\Boot]], values = {
                        { name = "BootSuccessGrace", type = "dword", data = 600 },
                    } },
                })
            ),
        })

        local boot, raw = ask(vm)
        t:assert_eq(boot.mode, "safe", "the boot is in Safe mode: " .. raw)
        t:assert_eq(boot.reason, "requested", "because peios.safemode=1 asked for it: " .. raw)
        t:assert_eq(#boot.downgrade, 0, "and nothing downgraded it: " .. raw)
        t:assert_eq(boot.max_attempts, 0,
            "max_attempts is 0, the check turned off: " .. raw)
        t:assert_eq(boot.attempts, 4,
            "and attempts is the count Phase 1 found, past what the default would allow: " .. raw)
        t:assert_eq(vm:read_file("/.peinit/boot-attempts"):match("%d+"), "5",
            "the file holds this boot's increment on top of it")
    end)

test("a Full boot downgraded to Safe is reported as a downgrade, with every finding",
    {
        spec = {
            "peinit *control.boot.mode-is-the-mode-phase-2-booted-in",
            "peinit *control.boot.reason-distinguishes-normal-requested-and-downgraded",
            "peinit *control.boot.downgrade-lists-every-finding",
            "peinit *control.boot.max-attempts-is-the-threshold",
        },
    },
    function(t)
        -- rec-modes-downgrade.test.lua's graph: a cycle with a Critical
        -- service in it, and a boot conflict with a Critical service in
        -- it. Two findings, so "all of them, not the first" can fail.
        local vm = peinit.boot({
            name = "bq-downgrade",
            files = peinit.merge(
                { ["lcl/pt/bqm-resident.sh"] = { RESIDENT, exec = true } },
                peinit.seed("zz-pt-bq-downgrade", {
                    { path = [[Machine\System]] },
                    { path = SERVICES },
                    boot_service("pt-bqm-crit", {
                        CRITICAL,
                        { name = "Requires", type = "multi", data = { "pt-bqm-norm" } },
                    }),
                    boot_service("pt-bqm-norm", {
                        { name = "Requires", type = "multi", data = { "pt-bqm-crit" } },
                    }),
                    boot_service("pt-bqm-clash", {
                        CRITICAL,
                        { name = "Conflicts", type = "multi", data = { "pt-bqm-other" } },
                    }),
                    boot_service("pt-bqm-other"),
                })
            ),
        })

        local log = vm:console():read_log()
        t:assert(log:find("Full boot", 1, true),
            "the boot began as a Full boot, so Safe mode was reached by downgrade")

        local boot, raw = ask(vm)
        t:assert_eq(boot.mode, "safe",
            "boot reports the mode after the downgrade, not the one the boot began in: " .. raw)
        t:assert_eq(boot.reason, "safe_mode_downgrade", "and why: " .. raw)

        -- Every finding, in the console line's words.
        local prefix = "peinit: boot downgraded to safe mode: "
        t:assert_eq(occurrences(log, prefix), 2, "the console carries two findings")
        t:assert_eq(#boot.downgrade, 2, "and boot carries both, not the first: " .. raw)
        local cycle, conflict = false, false
        for _, finding in ipairs(boot.downgrade) do
            t:assert(log:find(prefix .. finding, 1, true),
                "the finding is the console's words, verbatim: " .. finding)
            if finding:find("dependency cycle", 1, true) then cycle = true end
            if finding:find("pt-bqm-clash and pt-bqm-other conflict", 1, true) then
                conflict = true
            end
        end
        t:assert(cycle and conflict, "one is the cycle and one the conflict: " .. raw)

        -- And the event's: boot.safe_mode_downgrade carries the same words
        -- as its message.
        local events = wait_until(function()
            local r = vm:run(
                "evctl 'EVENTS boot.safe_mode_downgrade SINCE 1h ago TAKE 20' --format jsonl")
            if r.exit_code ~= 0 then return nil end
            for _, finding in ipairs(boot.downgrade) do
                if not r.stdout:find("boot downgraded to safe mode: " .. finding, 1, true) then
                    return nil
                end
            end
            return r.stdout
        end, { timeout = 60, interval = 0.5,
               desc = "both boot.safe_mode_downgrade events to carry boot's words" })
        t:assert(events, "the events name each finding in the same words")

        -- Nothing on the command line, so the threshold is the default.
        t:assert_eq(boot.max_attempts, 3,
            "max_attempts is 3 when the command line does not set it: " .. raw)
        t:assert_eq(boot.attempts, 0, "and an absent counter was counted as 0: " .. raw)
    end)

test("a Recovery boot serves no control socket, so boot is never answered with recovery",
    { spec = "peinit *control.boot.recovery-is-never-answered" },
    function(t)
        -- Recovery runs a shell instead of the runtime, and the runtime is
        -- what binds the control socket. The only process that can ask
        -- from inside recovery is the shell itself: /bin/recsh, staged
        -- through /lcl/bin, is the shell peinit execs, and it reports
        -- what it finds and then sleeps so the respawn loop does not push
        -- its output out of the console tail.
        local reporter = table.concat({
            "#!/bin/sh",
            "if [ -S /run/services/peinit/control.sock ]; then",
            "  echo pt-rec: socket=present",
            "else",
            "  echo pt-rec: socket=absent",
            "fi",
            "out=$(svctl --json boot 2>&1)",
            "echo pt-rec: boot-exit=$?",
            "echo \"pt-rec: boot-out=$out\"",
            "echo pt-rec: end",
            "sleep 3600",
            "",
        }, "\n")
        local console = peinit.boot_to_recovery(t, {
            name = "bq-recovery",
            agent_timeout = 20,
            append = "peios.recovery=1",
            files = { ["lcl/bin/recsh"] = { reporter, exec = true } },
        })
        t:assert(console:find("peinit: entering recovery", 1, true),
            "the boot went to recovery: " .. console:sub(-500))
        t:assert(console:find("pt-rec: end", 1, true),
            "and the reporting shell ran to its end: " .. console:sub(-500))
        t:assert(console:find("pt-rec: socket=absent", 1, true),
            "there is no control socket in recovery: " .. console:sub(-500))
        local exit = console:match("pt%-rec: boot%-exit=(%d+)")
        t:assert(exit and exit ~= "0",
            "svctl boot got no answer: exit " .. tostring(exit))
        local out = console:match("pt%-rec: boot%-out=([^\r\n]*)") or ""
        t:assert(not out:find('"status":"ok"', 1, true) and not out:find('"recovery"', 1, true),
            "and nothing answered it with a mode: " .. out)
    end)
