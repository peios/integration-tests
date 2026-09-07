-- peinit TRM §14.4 — a full root filesystem, and the shutdown that has
-- to finish anyway.
--
-- Its own file because it ends the VM: the root is filled until nothing
-- can be written to it and then the machine is shut down, and neither is
-- something a later test could run after.
--
-- The root here is an overlay whose upper layer is a tmpfs, so `dd` into
-- a file on it is a real exhaustion of the real filesystem rather than a
-- simulated one — the same ENOSPC peinit would see on a full disk, out
-- of the same syscalls.
--
-- Of the three places §14.4 says a full root shows up, two are Phase 1
-- and belong to §2.7's counter tests, and the third is the random seed
-- at shutdown. Only half of that third is observable from here: the
-- shutdown completing is, and the recording of the failure is not,
-- because peinit's finalisation messages do not reach the serial console
-- before the machine powers off. What this file therefore proves is the
-- half that matters to the machine — a root with no space left does not
-- wedge PID 1 in its final sequence.

local peinit = require("helpers.peinit")
peinit.claim(1)

local SERVICES = {
    { path = [[Machine\System]] },
    { path = [[Machine\System\Services]] },
    { path = [[Machine\System\Services\login-console]], values = {
        { name = "Disabled", type = "dword", data = 1 },
    } },
}

local vm = peinit.boot({
    name = "exhaust-disk",
    files = peinit.seed("pt-disk", SERVICES),
})

test("a shutdown on a root with no space left still reaches poweroff",
    {
        spec =
        "peinit *exhaust.an-unsaveable-random-seed-is-recorded-and-does-not-block-the-shutdown",
    },
    function(t)
        -- Bigger than the filesystem on purpose: dd is expected to fail
        -- with ENOSPC, having first written everything that would fit.
        local fill = vm:run("dd if=/dev/zero of=/pt-fill bs=1M count=4096")
        t:assert(fill.exit_code ~= 0,
            "the fill ran out of space, which is the point: " .. fill.stderr)

        local df = vm:run("df /")
        df:assert_ok()
        t:assert(df.stdout:find("100%%"),
            "the root filesystem is full: " .. df.stdout)

        -- The seed's own directory is on this filesystem, so the write
        -- peinit is about to attempt at finalisation cannot succeed.
        local write = vm:run("dd if=/dev/zero of=/var/state/pt-probe bs=1M count=1")
        t:assert(write.exit_code ~= 0,
            "and a write under /var/state fails: " .. write.stderr)

        -- The shutdown itself. The command's own connection dies with
        -- the machine, so its result is not the oracle — the console is.
        pcall(function() vm:run("svctl shutdown poweroff") end)
        vm:console():expect("peinit: shutdown Poweroff started", peinit.STAGE_TIMEOUT)
        vm:console():expect("reboot: Power down", peinit.STAGE_TIMEOUT)
    end)
