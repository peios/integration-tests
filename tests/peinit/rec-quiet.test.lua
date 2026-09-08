-- Peinit TRM §2.6 — the console quiet policy: the half of it that is about
-- who owns the terminal rather than about `peios.quiet=2`.
--
-- Level 2 is a property of the command line and modes.test.lua tests it
-- there, one VM per level. Ownership cannot be tested that way: it is not a
-- setting, it is a fact about the machine at the moment a message is
-- written, so the only way to see it is to change that fact underneath a
-- running peinit and watch the same class of message stop and start again.
--
-- That is what this file does, on one boot, at the default level. Every
-- probe is the same kind of message — the `peinit: service X started` line
-- a start produces — so the only variable between one probe and the next is
-- who holds the console. `pt-q-a` runs with the console free and is the
-- control: without it, a missing line proves nothing, because a line that
-- was never going to be written looks exactly like one the policy dropped.
--
-- The image's own `login-console` is seeded Disabled here. It holds
-- /dev/console on every ordinary boot (its seed says so, and that is
-- exactly the case the rule exists for), which would make the console
-- owned for reasons this file did not arrange and could not release. With
-- it out of the way the terminal starts free and every change of ownership
-- below is one this file made.
--
-- The two device probes need a second name for the console. /dev/console
-- is character device 5:1 and nothing else in the image points at it, so
-- the test makes its own node with `mknod` and hands it to a service as
-- `TTYPath`. A string comparison would not match it; a device comparison
-- does, and that difference is the whole of
-- `quiet.a-terminal-is-matched-by-device-not-path`.

local peinit = require("helpers.peinit")
peinit.claim(1)

-- A service that keeps a process for as long as it is left alone. Its only
-- job is to be alive while holding a terminal, since the policy asks
-- whether a live process holds the console rather than whether one ever
-- did.
local RESIDENT = "#!/bin/sh\nwhile : ; do sleep 30; done\n"

--- A demand-started service that takes `tty` as its controlling terminal.
local function holder(name, tty)
    return {
        path = [[Machine\System\Services\]] .. name,
        values = {
            { name = "ImagePath", type = "sz", data = "/lcl/pt/quiet-resident.sh" },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "Readiness", type = "dword", data = 1 },
            { name = "TTYPath", type = "sz", data = tty },
        },
    }
end

--- A demand-started service whose only purpose is the console line peinit
--- writes when it starts. Oneshot, so it is finished by the time `svctl
--- start` returns and the line has either been written or dropped.
local function probe(name)
    return {
        path = [[Machine\System\Services\]] .. name,
        values = {
            { name = "ImagePath", type = "sz", data = "/bin/true" },
            { name = "Type", type = "dword", data = 1 },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "Readiness", type = "dword", data = 1 },
        },
    }
end

local function started(name)
    return "peinit: service " .. name .. " started"
end

local vm = peinit.boot({
    name = "quiet-ownership",
    files = peinit.merge(
        { ["lcl/pt/quiet-resident.sh"] = { RESIDENT, exec = true } },
        peinit.seed("zz-pt-quiet", {
            { path = [[Machine\System]] },
            { path = [[Machine\System\Services]] },
            -- Sorts after the image's own login-console.reg, so this value
            -- is the one that lands: the console starts out unowned.
            {
                path = [[Machine\System\Services\login-console]],
                values = { { name = "Disabled", type = "dword", data = 1 } },
            },
            holder("pt-q-hold", "/dev/console"),
            holder("pt-q-alt", "/dev/pt-altcon"),
            holder("pt-q-gone", "/dev/pt-gone"),
            probe("pt-q-a"),
            probe("pt-q-b"),
            probe("pt-q-c"),
            probe("pt-q-d"),
            probe("pt-q-e"),
            probe("pt-q-f"),
            probe("pt-q-g"),
        })
    ),
})

-- The control. Nothing holds the console, so the line is written; if this
-- expect times out the rest of the file is measuring the wrong thing.
vm:run("svctl start pt-q-a"):assert_ok()
vm:console():expect(started("pt-q-a"), peinit.STAGE_TIMEOUT)

-- Someone takes the console, and the same kind of start happens behind it.
vm:run("svctl start pt-q-hold"):assert_ok()
vm:run("svctl start pt-q-b"):assert_ok()

-- ...and gives it back. pt-q-c's line arriving is what says the console was
-- working the whole time and pt-q-b's absence was the policy, not a dead
-- console — and it is also the ordering marker for the discard check: once
-- a line written after pt-q-b is on the console, pt-q-b's would be too if
-- peinit had been holding it.
vm:run("svctl stop pt-q-hold"):assert_ok()
vm:run("svctl start pt-q-c"):assert_ok()
vm:console():expect(started("pt-q-c"), peinit.STAGE_TIMEOUT)
local released_log = vm:console():read_log()

-- A second name for the same device. 5:1 is what /dev/console is, and the
-- assertions below check that rather than trusting it.
local console_dev = vm:run("stat -c '%t %T' /dev/console")
console_dev:assert_ok()
vm:run("mknod /dev/pt-altcon c 5 1"):assert_ok()
local alt_dev = vm:run("stat -c '%t %T' /dev/pt-altcon")
alt_dev:assert_ok()

vm:run("svctl start pt-q-alt"):assert_ok()
vm:run("svctl start pt-q-d"):assert_ok()
vm:run("svctl stop pt-q-alt"):assert_ok()
vm:run("svctl start pt-q-e"):assert_ok()
vm:console():expect(started("pt-q-e"), peinit.STAGE_TIMEOUT)
local alias_log = vm:console():read_log()

-- A terminal whose device cannot be determined: the node is unlinked out
-- from under a service that is still holding it, so the path is there in
-- the definition and stats to nothing.
vm:run("mknod /dev/pt-gone c 5 1"):assert_ok()
vm:run("svctl start pt-q-gone"):assert_ok()
vm:run("rm /dev/pt-gone"):assert_ok()
local gone_stat = vm:run("stat -c '%t %T' /dev/pt-gone")
vm:run("svctl start pt-q-f"):assert_ok()
vm:run("svctl stop pt-q-gone"):assert_ok()
-- A line after pt-q-f's, written with the console demonstrably free again,
-- so the log below is past the point where pt-q-f's own line would have
-- been.
vm:run("svctl start pt-q-g"):assert_ok()
vm:console():expect(started("pt-q-g"), peinit.STAGE_TIMEOUT)
local gone_log = vm:console():read_log()

test("the default level keeps peinit out of a terminal a running service holds",
    { spec = "peinit *quiet.one-is-the-default-and-respects-terminal-ownership" },
    function(t)
        -- Nothing on this boot's command line says anything about quiet, so
        -- the level under test is the default one. The rule is the level's,
        -- not the message's: all three lines below are the same kind of
        -- ordinary progress, and only the middle one was written while
        -- somebody else had the terminal.
        t:assert(released_log:find(started("pt-q-a"), 1, true),
            "with the console free, a start was announced")
        t:assert(not released_log:find(started("pt-q-b"), 1, true),
            "with a live service holding the console, the same announcement was not")
        t:assert(released_log:find(started("pt-q-c"), 1, true),
            "and once it let go, announcements resumed")
    end)

test("a message the policy suppressed is dropped rather than kept for later",
    { spec = "peinit *quiet.suppressed-messages-are-discarded" },
    function(t)
        -- pt-q-c started after pt-q-b and after the console was free again,
        -- and its line is on the console; so a peinit that had buffered
        -- pt-q-b's line would have had both the reason and the opportunity
        -- to flush it by now. It is simply gone.
        t:assert(released_log:find(started("pt-q-c"), 1, true),
            "the console was free again and being written to")
        t:assert(not released_log:find(started("pt-q-b"), 1, true),
            "and the line suppressed while it was held never arrived")
    end)

test("a terminal is recognised through a second name for the same device",
    { spec = "peinit *quiet.a-terminal-is-matched-by-device-not-path" },
    function(t)
        -- /dev/console and /dev/pt-altcon are two names for character
        -- device 5:1. A policy that compared TTYPath strings would find no
        -- holder here and write; one that compares devices finds one and
        -- stays out.
        t:assert_eq(alt_dev.stdout:match("%S+ %S+"), console_dev.stdout:match("%S+ %S+"),
            "the two nodes are the same device: " .. console_dev.stdout ..
            " vs " .. alt_dev.stdout)
        t:assert(not alias_log:find(started("pt-q-d"), 1, true),
            "a holder on the other name silenced peinit, so the match was by device")
        t:assert(alias_log:find(started("pt-q-e"), 1, true),
            "and it spoke again once that holder let go")
    end)

test("a terminal whose device cannot be determined is treated as free",
    { spec = "peinit *quiet.an-undeterminable-device-is-treated-as-free" },
    function(t)
        -- The holder is still alive and its TTYPath still names what was
        -- the console; only the node it named has gone, which is the one
        -- case where peinit cannot tell whether the terminal it is about to
        -- write to is somebody's.
        --
        -- It writes. The trade is deliberate (PEI-814): guessing wrong
        -- this way scrambles a line, and guessing wrong the other way
        -- takes the operator's console output away exactly when the
        -- machine has stopped being able to explain itself.
        t:assert(gone_stat.exit_code ~= 0,
            "the holder's terminal no longer stats: " .. tostring(gone_stat.stdout))
        t:assert(gone_log:find(started("pt-q-f"), 1, true),
            "peinit kept writing rather than assuming the terminal was held")
    end)
