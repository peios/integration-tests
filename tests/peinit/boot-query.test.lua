-- peinit TRM §10.8 — the boot query: what `boot` reports about the
-- current boot, and who may ask (§10.2's `boot` row, §4.7's default).
--
-- One machine carries the ordinary Full boot from start to confirmation.
-- Three things on it are chosen rather than inherited:
--
--   * the boot attempt counter is staged at 2 and the threshold set to 5
--     on the command line, so `attempts` and `max_attempts` are values
--     this file picked and neither is a default that could be reported by
--     accident;
--   * `BootSuccessGrace` is 20 seconds: long enough to read the "holding,
--     counts at" row before it turns into the "counted" row, short enough
--     that the file does not wait half a minute for nothing;
--   * a Critical Oneshot that runs until the test creates /pt-bq-go. A
--     Oneshot is Starting until its process exits, and Starting satisfies
--     nothing, so the boot is waiting on it for exactly as long as the
--     test wants. `StartTimeout` covers a Oneshot's whole run, and a
--     Critical one that times out takes the Critical failure path, so it
--     is set far beyond anything here.
--
-- A Critical daemon sits beside it for the case that a confirmed boot
-- stays confirmed: it is killed after the confirmation, which is a real
-- failure of a Critical service, not a stop.
--
-- The tests are ordered: the report and the rights first, while the boot
-- is still waiting on the gate, then the walk through the confirmation
-- states, which releases the gate, then what happens after.
--
-- The modes other than Full, the downgrade, the threshold's default and
-- its zero, and recovery are boot-query-modes.test.lua; a reset that
-- fails is boot-query-unconfirmed.test.lua; the shutdown gate is
-- boot-query-shutdown.test.lua.

local peinit = require("helpers.peinit")
local token = require("helpers.token")
local us = require("helpers.unixsock")
local sys = require("helpers.sys")
local f = require("helpers.peinit_client")
peinit.claim(1)

local SERVICES = [[Machine\System\Services]]
local CONTROL = [[Machine\System\Init]]
local GRACE = 20
local GATE = "/pt-bq-go"

local CRITICAL = { name = "ErrorControl", type = "dword", data = 1 }
local BOOT = { name = "Triggers", type = "multi", data = { "boot" } }

local vm = peinit.boot({
    name = "boot-query",
    append = "peios.bootattempts=5",
    files = peinit.merge(
        { [".peinit/boot-attempts"] = "2\n" },
        peinit.seed("zz-pt-bq", {
            { path = [[Machine\System]] },
            { path = [[Machine\System\Boot]], values = {
                { name = "BootSuccessGrace", type = "dword", data = GRACE },
            } },
            { path = SERVICES },
            { path = SERVICES .. [[\pt-bq-gate]], values = {
                { name = "ImagePath", type = "sz", data = "/bin/sh" },
                { name = "Arguments", type = "multi",
                  data = { "-c", "while [ ! -e " .. GATE .. " ]; do sleep 1; done" } },
                { name = "Type", type = "dword", data = 1 },
                { name = "RemainAfterExit", type = "dword", data = 1 },
                { name = "StartTimeout", type = "dword", data = 600 },
                { name = "Identity", type = "sz", data = "SYSTEM" },
                CRITICAL, BOOT,
            } },
            { path = SERVICES .. [[\pt-bq-crit]], values = {
                { name = "ImagePath", type = "sz", data = "/bin/sleep" },
                { name = "Arguments", type = "multi", data = { "100000" } },
                { name = "Identity", type = "sz", data = "SYSTEM" },
                { name = "Readiness", type = "dword", data = 1 },
                -- OnFailure, the default, spelled out: the kill below is
                -- meant to be a failure the restart budget absorbs.
                { name = "RestartPolicy", type = "dword", data = 1 },
                CRITICAL, BOOT,
            } },
        })
    ),
})

local verdict = peinit.verdict

local function is_null(v) return v == nil or v == json.null end

--- `svctl --json boot`, decoded, and the raw answer for messages. A
--- null field decodes to nil.
local function ask()
    local r = vm:run("svctl --json boot")
    r:assert_ok()
    local ok, decoded = pcall(json.decode, r.stdout)
    assert(ok and type(decoded) == "table" and type(decoded.boot) == "table",
        "svctl --json boot did not answer with a boot object: " .. r.stdout .. r.stderr)
    return decoded.boot, r.stdout
end

local function counter()
    return vm:read_file("/.peinit/boot-attempts"):match("%d+")
end

local function state(service)
    return vm:run("svctl --json status " .. service).stdout:match('"state":"([^"]+)"')
end

local function pid(service)
    return vm:run("svctl --json status " .. service).stdout:match('"pid":(%d+)')
end

--- Seconds since the epoch of an RFC 3339 UTC timestamp.
local function epoch(stamp)
    local y, mo, d, h, mi, s = tostring(stamp):match("^(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
    if not y then return nil end
    y, mo, d = tonumber(y), tonumber(mo), tonumber(d)
    -- Days from the civil date (Howard Hinnant's algorithm).
    if mo <= 2 then y = y - 1 end
    local era = (y >= 0 and y or y - 399) // 400
    local yoe = y - era * 400
    local doy = (153 * (mo + (mo > 2 and -3 or 9)) + 2) // 5 + d - 1
    local doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    local days = era * 146097 + doe - 719468
    return days * 86400 + tonumber(h) * 3600 + tonumber(mi) * 60 + tonumber(s)
end

-- ---------------------------------------------------------------------------
-- A second caller. The console is SYSTEM, which every descriptor here
-- grants everything; the claim about the default is about who else it
-- admits. A provium worker mints the token and impersonates it around the
-- connect, as in dispatch-rights.test.lua.
-- ---------------------------------------------------------------------------

local USER = token.SID.TEST_USER

--- An authenticated user and nothing more: Everyone, Authenticated Users,
--- SeChangeNotifyPrivilege for the traverse to the socket's directory.
local function mint_user(w)
    local enabled = token.GROUP.MANDATORY | token.GROUP.ENABLED_BY_DEFAULT
        | token.GROUP.ENABLED
    local notify = token.bit(token.PRIV.CHANGE_NOTIFY)
    return assert(token.mint(w, {
        user_sid = USER,
        token_type = token.TYPE.IMPERSONATION,
        impersonation_level = token.LEVEL.IMPERSONATION,
        groups = {
            { sid = token.SID.EVERYONE, attributes = enabled },
            { sid = token.SID.AUTHENTICATED_USERS, attributes = enabled },
        },
        privs_present = notify,
        privs_enabled = notify,
    }))
end

local function mint_admin(w)
    return assert(f.mint_admin(w, USER))
end

--- Send one control frame as the principal `mint` makes, on a fresh
--- connection, and return the raw answer.
local function as(mint, frame)
    local answer
    f.with_worker(vm, function(w)
        local fd = assert(f.connect_as(w, f.CONTROL_SOCKET, us.SOCK.STREAM, mint(w)))
        answer = assert(f.control_request(w, fd, frame))
        sys.close(w, fd)
    end)
    return answer
end

local BOOT_FRAME = '{"command":"boot"}'
local RELOAD_FRAME = '{"command":"reload-config"}'
local SHUTDOWN_FRAME = '{"command":"shutdown","type":"poweroff"}'

local function denied(answer) return answer:find("ACCESS_DENIED", 1, true) ~= nil end
local function ok(answer) return answer:find('"status":"ok"', 1, true) ~= nil end

--- Write ControlSecurity granting SYSTEM `mask`, or delete it when `mask`
--- is nil, and wait until `landed()` says peinit has the change: it
--- arrives from a registry notification, asynchronously.
local function set_control(mask, landed, desc)
    if mask then
        vm:run("reg set '" .. CONTROL .. "' ControlSecurity hex:"
            .. peinit.system_descriptor_hex(mask)):assert_ok()
    else
        vm:run("reg del '" .. CONTROL .. "' ControlSecurity")
    end
    wait_until(function() return landed() or nil end,
        { timeout = 60, interval = 0.5, desc = desc })
end

local function boot_verdict() return verdict(vm:run("svctl boot")) end
local function reload_verdict() return verdict(vm:run("svctl reload-config")) end

-- ---------------------------------------------------------------------------

test("boot reports how the current boot went: its mode and why, the count, and where it stands",
    {
        spec = {
            "peinit *control.boot.reports-the-current-boot",
            "peinit *control.boot.mode-is-the-mode-phase-2-booted-in",
            "peinit *control.boot.reason-distinguishes-normal-requested-and-downgraded",
            "peinit *control.boot.attempts-is-the-count-phase-1-checked",
            "peinit *control.boot.max-attempts-is-the-threshold",
        },
    },
    function(t)
        local boot, raw = ask()
        -- Every field of the answer is present, null or not.
        for _, key in ipairs({ "mode", "reason", "downgrade", "attempts", "max_attempts",
            "confirmed", "grace_seconds", "waiting_on", "confirms_at", "confirm_error" }) do
            t:assert(raw:find('"' .. key .. '":', 1, true), "the answer carries " .. key .. ": " .. raw)
        end

        t:assert(vm:console():read_log():find("Full boot", 1, true),
            "Phase 1 announced a Full boot")
        t:assert_eq(boot.mode, "full", "and boot says Phase 2 booted Full: " .. raw)
        t:assert_eq(boot.reason, "normal", "for no reason but that it is a boot: " .. raw)
        t:assert_eq(#boot.downgrade, 0, "with no downgrade findings: " .. raw)

        -- The staged 2 is what the threshold was checked against; the
        -- file now holds this boot's increment on top of it.
        t:assert_eq(counter(), "3", "the counter file holds this boot's increment")
        t:assert_eq(boot.attempts, 2,
            "and attempts is the count before it, the one Phase 1 checked: " .. raw)
        t:assert_eq(boot.max_attempts, 5,
            "max_attempts is peios.bootattempts from the command line: " .. raw)
        t:assert_eq(boot.grace_seconds, GRACE, "grace_seconds is BootSuccessGrace: " .. raw)
    end)

test("under the default control descriptor every authenticated user may ask how the machine booted, and only ask",
    {
        spec = {
            "peinit *svcsd.the-control-default",
            "peinit *svcsd.the-control-default-lets-every-authenticated-user-ask-how-the-machine-booted",
        },
    },
    function(t)
        -- No ControlSecurity anywhere, so the compiled default decides:
        --   O:SY G:BA D:(A;;0x0007;;;SY)(A;;0x0007;;;BA)(A;;0x0004;;;AU)
        -- Shutdown is the one right not exercised positively, for SYSTEM
        -- and Administrators alike: granting it stops the machine.
        t:assert(vm:run("reg get '" .. CONTROL .. "' ControlSecurity").exit_code ~= 0,
            "no ControlSecurity value is present")

        t:assert_eq(boot_verdict(), "allowed", "SYSTEM may ask how the machine booted")
        t:assert_eq(reload_verdict(), "allowed", "and reload the configuration")

        local admin_boot = as(mint_admin, BOOT_FRAME)
        t:assert(ok(admin_boot) and admin_boot:find('"boot":{', 1, true),
            "an administrator may ask how the machine booted: " .. admin_boot)
        local admin_reload = as(mint_admin, RELOAD_FRAME)
        t:assert(ok(admin_reload), "and reload the configuration: " .. admin_reload)

        -- An authenticated user who is neither: the boot query, nothing else.
        local user_boot = as(mint_user, BOOT_FRAME)
        t:assert(ok(user_boot) and user_boot:find('"boot":{', 1, true),
            "an authenticated user may ask how the machine booted: " .. user_boot)
        t:assert(user_boot:find('"mode":"full"', 1, true),
            "and is told what SYSTEM is told: " .. user_boot)
        local user_reload = as(mint_user, RELOAD_FRAME)
        t:assert(denied(user_reload), "but may not reload the configuration: " .. user_reload)
        local user_shutdown = as(mint_user, SHUTDOWN_FRAME)
        t:assert(denied(user_shutdown), "nor shut the machine down: " .. user_shutdown)
    end)

test("boot is checked against the control descriptor for SYSTEM_QUERY_STATUS",
    {
        spec = {
            "peinit *dispatch.right-boot",
            "peinit *control.boot.is-checked-for-query-status",
        },
    },
    function(t)
        -- SYSTEM granted shutdown and reload but not query: boot is
        -- refused while reload-config, on the same descriptor, is not.
        set_control(0x0003, function() return boot_verdict() == "denied" end,
            "a control descriptor without SYSTEM_QUERY_STATUS to land")
        t:assert_eq(boot_verdict(), "denied",
            "without SYSTEM_QUERY_STATUS the boot query is refused")
        t:assert_eq(reload_verdict(), "allowed",
            "while reload-config, checked against the same descriptor, is answered")
        t:assert_eq(verdict(vm:run("svctl status pt-bq-crit")), "allowed",
            "and a service query, checked against the service's own, is unaffected")

        -- SYSTEM granted query alone: the other way round.
        set_control(0x0004, function() return reload_verdict() == "denied" end,
            "a control descriptor of SYSTEM_QUERY_STATUS alone to land")
        t:assert_eq(boot_verdict(), "allowed", "SYSTEM_QUERY_STATUS alone answers boot")
        t:assert_eq(reload_verdict(), "denied", "and conveys nothing else")

        -- Back to the default, which this file's later tests rely on.
        set_control(nil, function()
            return boot_verdict() == "allowed" and reload_verdict() == "allowed"
        end, "the control descriptor to be cleared")
    end)

test("boot walks a boot from waiting, to holding, to counted",
    {
        spec = {
            "peinit *control.boot.confirmation-states",
            "peinit *control.boot.confirmed-means-the-counter-was-reset",
            "peinit *control.boot.attempts-is-the-count-phase-1-checked",
        },
    },
    function(t)
        -- Waiting. The image's own Critical services may still be on
        -- their way up, so wait for the answer in which only the gate is
        -- left, and assert on that answer.
        --
        -- wait_until hands back one value, so each poll returns the pair.
        local function poll(pred, opts)
            local got = wait_until(function()
                local boot, text = ask()
                if pred(boot) then return { boot, text } end
                return nil
            end, opts)
            return got[1], got[2]
        end
        local waiting, raw = poll(function(boot)
            return #boot.waiting_on == 1 and boot.waiting_on[1] == "pt-bq-gate"
        end, { timeout = 90, interval = 0.5, desc = "boot to be waiting on pt-bq-gate alone" })
        t:assert_eq(state("pt-bq-gate"), "starting", "the gate is still running")
        t:assert_eq(waiting.confirmed, false, "a boot waiting on a service is not confirmed: " .. raw)
        t:assert(is_null(waiting.confirms_at),
            "and cannot say when it will count: " .. raw)
        t:assert(is_null(waiting.confirm_error), "and has no error: " .. raw)

        -- Holding. Release the gate; the Oneshot completes, and Completed
        -- satisfies dependents.
        vm:run("touch " .. GATE):assert_ok()
        local holding
        holding, raw = poll(function(boot) return #boot.waiting_on == 0 end,
            { timeout = 60, interval = 0.3, desc = "boot to stop waiting on anything" })
        local now = tonumber(vm:run("date -u +%s").stdout:match("%d+"))
        t:assert_eq(holding.confirmed, false,
            "a boot whose Critical services all hold is not confirmed until the grace is out: " .. raw)
        t:assert(not is_null(holding.confirms_at), "and says when it will be: " .. raw)
        local at = epoch(holding.confirms_at)
        t:assert(at, "confirms_at is an RFC 3339 time: " .. tostring(holding.confirms_at))
        t:assert(at >= now - 5 and at <= now + GRACE + 5,
            string.format("about a grace (%ds) from when the services began holding: "
                .. "confirms_at %s, guest now %d", GRACE, tostring(holding.confirms_at), now))
        t:assert(is_null(holding.confirm_error), "with no error: " .. raw)
        t:assert_eq(counter(), "3", "the counter has not been reset yet")

        -- Counted.
        local counted
        counted, raw = poll(function(boot) return boot.confirmed end,
            { timeout = GRACE + 60, interval = 0.5, desc = "boot to be confirmed" })
        t:assert_eq(#counted.waiting_on, 0, "a confirmed boot waits on nothing: " .. raw)
        t:assert(is_null(counted.confirms_at), "has no time still to come: " .. raw)
        t:assert(is_null(counted.confirm_error), "and no error: " .. raw)
        t:assert_eq(counter(), "0",
            "and confirmed means the reset was written: the counter reads 0")
        t:assert_eq(counted.attempts, 2,
            "attempts is the count at the start of this boot, so it does not drop to 0: " .. raw)
    end)

test("a confirmed boot stays confirmed when a Critical service fails afterwards",
    { spec = "peinit *control.boot.a-confirmed-boot-stays-confirmed" },
    function(t)
        local before, raw = ask()
        t:assert(before.confirmed, "the boot is confirmed to start with: " .. raw)
        t:assert_eq(state("pt-bq-crit"), "active", "and the Critical daemon is running")

        -- A real failure: the daemon is killed, and the ordinary Critical
        -- path restarts it from its budget. Through all of it the boot
        -- stays counted.
        local old = pid("pt-bq-crit")
        t:assert(old, "the daemon has a pid")
        vm:run("kill -9 " .. old):assert_ok()
        local unconfirmed
        wait_until(function()
            local boot, text = ask()
            if not (boot.confirmed and #boot.waiting_on == 0) then unconfirmed = text end
            local now = pid("pt-bq-crit")
            return (now and now ~= old and state("pt-bq-crit") == "active") or nil
        end, { timeout = 60, interval = 0.3, desc = "pt-bq-crit to be restarted after the kill" })
        t:assert(unconfirmed == nil,
            "the boot stayed confirmed while its Critical service failed and restarted: "
            .. tostring(unconfirmed))

        -- And with a Critical service down for good: still counted.
        vm:run("svctl stop pt-bq-crit"):assert_ok()
        t:assert(state("pt-bq-crit") ~= "active", "the Critical daemon is stopped")
        local after
        after, raw = ask()
        t:assert(after.confirmed, "and the boot is still confirmed: " .. raw)
        t:assert_eq(#after.waiting_on, 0, "waiting on nothing: " .. raw)
        t:assert_eq(counter(), "0", "and the counter was not put back")
    end)
