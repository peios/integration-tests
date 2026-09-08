-- peinit TRM §12.4 — finalisation: the last step, what it does not let
-- stop it, and what happens if the kernel hands control back.
--
-- This is the thinnest file in the chapter, and deliberately so. Steps 6
-- and 7 — the seed and the unmounts — write nothing to the console when
-- they succeed, and the machine they wrote it on is gone a moment later,
-- so most of what §12.4 states about them is asserted here only through
-- its one visible consequence: the machine still reaches its final
-- action. The rest is recorded in the chapter's report as unreachable
-- rather than pretended at.
--
-- One thing worth knowing before reading further. A turn's console
-- output is written after the turn's work, and the finalising turn's
-- work ends in a `reboot(2)` that does not return — so "shutdown ready
-- to finalize", "shutdown finalizing" and "shutdown completed" are never
-- printed on a shutdown that works. Their absence is the normal case,
-- and no test here waits for them.

local peinit = require("helpers.peinit")
peinit.claim(1)

local function with_vm(opts, body)
    local vm = peinit.boot(opts)
    local ok, err = pcall(body, vm)
    pcall(function() vm:shutdown() end)
    if not ok then error(err, 0) end
end

local function states(vm)
    local out, any = {}, false
    for name, state in vm:run("svctl --json list").stdout
        :gmatch('"service":"([^"]+)","state":"([^"]+)"') do
        out[name] = state
        any = true
    end
    assert(any, "svctl list answered with no services")
    return out
end

local function settle(vm)
    wait_until(function()
        for name, state in pairs(states(vm)) do
            if state == "starting" and not name:find("^pt%-") then return false end
        end
        return true
    end, { timeout = 60, interval = 0.5, desc = "the image's own services to settle" })
end

local function pause(seconds)
    pcall(wait_until, function() return false end,
        { timeout = seconds, interval = 0.25, desc = "a fixed pause" })
end

local function trigger(vm, command)
    pcall(function() vm:run(command, { timeout = 30 }) end)
end

test("a cleanup failure in steps 6 and 7 does not block the final action",
    { spec = "peinit *final.a-cleanup-failure-never-blocks-the-final-action" },
    function(t)
        -- §12.4's own note says the tail of *every* graceful shutdown on
        -- this arrangement records a cleanup failure: depth ordering
        -- unmounts /proc before /run and /sys are attempted, and the
        -- "is it really gone?" check for those two then cannot read the
        -- mountinfo it needs. So this needs no arranging — an ordinary
        -- graceful poweroff is a shutdown with retained cleanup failures
        -- in it, and the claim is that it powers off anyway.
        with_vm({ name = "cleanup", append = "peios.quiet=0" }, function(vm)
            settle(vm)
            trigger(vm, "svctl shutdown poweroff")
            vm:console():expect("peinit: shutdown Poweroff started", 30)
            vm:console():expect("reboot: Power down", 60)

            local log = vm:console():read_log()
            t:assert(not log:find("peinit: entering recovery", 1, true),
                "and none of those failures took PID 1 into recovery")
            t:assert(not log:find("peinit: shutdown final action failed", 1, true),
                "nor stopped the final action from being reached")
        end)
    end)

test("RB_HALT_SYSTEM does not return, so halting does not reach the failed-shutdown state",
    { spec = "peinit *final.rb-halt-system-does-not-return-either" },
    function(t)
        -- The failed-shutdown state exists for a `reboot(2)` that comes
        -- back, and the halt case is called out as not being one. If it
        -- were, peinit would still be alive on the other side of "System
        -- halted", printing "shutdown final action failed" and retrying
        -- once a second. It prints nothing, because it is not running.
        with_vm({ name = "halted", append = "peios.quiet=0" }, function(vm)
            settle(vm)
            trigger(vm, "svctl shutdown halt")
            vm:console():expect("peinit: shutdown Halt started", 30)
            vm:console():expect("reboot: System halted", 60)

            local at_halt = #vm:console():read_log()
            -- Several retry intervals' worth of nothing.
            pause(8)
            local log = vm:console():read_log()
            t:assert(not log:find("peinit: shutdown final action failed", 1, true),
                "the halt did not come back as a failed final action")
            t:assert_eq(#log, at_halt,
                "and nothing at all was written after the kernel halted: PID 1 " ..
                "is not on the far side of RB_HALT_SYSTEM")
        end)
    end)
