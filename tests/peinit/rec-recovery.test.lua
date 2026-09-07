-- Peinit TRM §2.8 — the environment recovery hands the administrator.
--
-- A boot that reaches recovery starts no Phase 2 service, so it never
-- starts the provium agent either and there is no VM left to drive: the
-- console is the whole oracle, and `peinit.boot_to_recovery` returns it out
-- of the error `vm:boot` raises. Everything below is read out of that one
-- string.
--
-- The lever that makes the mode inspectable at all is `/bin/recsh`.
-- Recovery prefers it over `/bin/sh` and treats it as an opaque
-- executable, and /bin is a StrataFS view with /lcl/bin as its
-- highest-precedence stratum — so a script staged at lcl/bin/recsh is the
-- shell peinit execs, running as SYSTEM on /dev/console with everything a
-- test would like to ask about the recovery environment in reach. It
-- reports once and then sleeps rather than exiting, because the shell is
-- respawned when it exits and a chatty loop would push the earlier console
-- out of the 4 KiB tail the harness keeps.
--
-- The entry point is a boot attempt counter already at the default
-- threshold. That is the Phase 1 failure that happens LATEST while still
-- being before Phase 1's own registryd start, which is what makes it the
-- useful one here: it exercises the `RecoveryRegistryd::Start` arm (nothing
-- has tried yet, so recovery must), and it leaves the RTC clock step
-- un-run, so the Phase 1 catch-up has something left to do.

local peinit = require("helpers.peinit")
peinit.claim(1)

-- Counts, not contents: the console tail is finite, and what these claims
-- need is "exactly one of each", not the mount table itself.
local REPORTER = table.concat({
    "#!/bin/sh",
    "mounts=",
    "for want in /proc /sys /dev/shm /sys/fs/cgroup /run; do",
    "  n=0",
    "  while read -r a b c d mp rest; do",
    "    [ \"$mp\" = \"$want\" ] && n=$((n+1))",
    "  done < /proc/self/mountinfo",
    "  mounts=\"$mounts $want=$n\"",
    "done",
    "regs=0",
    "for d in /proc/[0-9]*; do",
    "  [ \"$(cat $d/comm 2>/dev/null)\" = registryd ] && regs=$((regs+1))",
    "done",
    "echo pt-rec: begin",
    "echo pt-rec: env PATH=$PATH TERM=$TERM HOME=$HOME",
    "echo pt-rec: reg=$(reg ls 'Machine\\System' --keys-only 2>&1 | tr '\\n' ',')",
    "echo pt-rec: registryd=$regs",
    "echo pt-rec: mounts=$mounts",
    "echo pt-rec: machineid=$(wc -c < /lcl/etc/machine-id)",
    "echo pt-rec: end",
    "sleep 3600",
    "",
}, "\n")

-- `boot_to_recovery` reports "this boot came up when it was not supposed
-- to" through the test context it is handed. There is no test at file
-- scope, so it gets a stand-in that raises instead: a premise that failed
-- should take the whole file down, not one test in it.
local FILE_SCOPE = {
    assert = function(_, ok, message) if not ok then error(message, 0) end end,
}

local console = peinit.boot_to_recovery(FILE_SCOPE, {
    name = "recovery-environment",
    agent_timeout = 25,
    files = peinit.merge(
        { ["lcl/bin/recsh"] = { REPORTER, exec = true } },
        { [".peinit/boot-attempts"] = "3\n" }
    ),
})

--- The value the reporter printed for `key`, or nil.
local function reported(key)
    return console:match("pt%-rec: " .. key .. "=([^\r\n]*)")
end

test("recovery reaches a shell and says what sent it there",
    { spec = "peinit *recovery.the-reason-reaches-the-console" },
    function(t)
        -- Not merely the words "Recovery mode": the reason is the whole
        -- point of the line, and an operator staring at a recovery prompt
        -- has nothing else to go on. Both the entry announcement and the
        -- recovery console's own banner carry it.
        t:assert(console:find("peinit: entering recovery: BootAttemptThresholdReached", 1, true),
            "the entry line named the reason: " .. console:sub(-600))
        t:assert(console:find("counter: 3, threshold: 3", 1, true),
            "and carried the detail that distinguishes one instance of it from another")
        t:assert(console:find("peinit entering Recovery mode:", 1, true),
            "and the recovery console repeated it as it took over")
        t:assert(console:find("pt-rec: begin", 1, true),
            "and a shell was actually delivered")
    end)

test("the recovery shell runs with the fixed environment §2.8 specifies",
    { spec = "peinit *recovery.the-shells-environment" },
    function(t)
        -- peinit builds this environment from three compiled-in strings
        -- rather than passing anything of its own on, so the assertion is
        -- for exact values rather than for the variables merely being set.
        t:assert_eq(reported("env PATH"):match("^%S+"), "/sbin:/bin",
            "PATH: " .. tostring(reported("env PATH")))
        t:assert(console:find("TERM=linux", 1, true), "TERM=linux")
        t:assert(console:find("HOME=/", 1, true), "HOME=/")
    end)

test("recovery ensures the base registry structure exists",
    { spec = "peinit *recovery.the-base-registry-structure-is-ensured" },
    function(t)
        -- So the shell sees a normal layout even on a system that has never
        -- been provisioned: Machine\System with Services and Init under it.
        local keys = reported("reg")
        t:assert(keys, "the shell could read the registry at all: " .. console:sub(-600))
        t:assert(keys:find("Services", 1, true),
            "Machine\\System\\Services exists: " .. keys)
        t:assert(keys:find("Init", 1, true),
            "Machine\\System\\Init exists: " .. keys)
    end)

test("a recovery Phase 1 never reached starts exactly one registryd",
    { spec = "peinit *recovery.recovery-starts-at-most-one-registryd" },
    function(t)
        -- This entry point is before Phase 1's own registryd start, so
        -- nothing has tried and recovery must — otherwise the operator gets
        -- a shell with no configuration store and every `reg` tool failing.
        -- One, and not two: a second daemon would bind over the first's
        -- notify socket, which succeeds rather than reporting EADDRINUSE,
        -- and would open the same hive files behind its back.
        t:assert_eq(reported("registryd"), "1",
            "exactly one registryd is running: " .. tostring(reported("registryd")))
    end)

test("recovery re-runs the Phase 1 steps, and running them twice changes nothing",
    { spec = "peinit *recovery.phase-1-steps-are-retried-idempotently" },
    function(t)
        -- The catch-up is unconditional — it runs the steps and ignores the
        -- failures — which is only safe because each step is idempotent.
        -- Phase 1 had already mounted every virtual filesystem below by the
        -- time this recovery was entered, and the catch-up mounted them
        -- again; a step that was not idempotent would show as a second
        -- mount on the same point, and the shell would be looking at a
        -- stack rather than at a filesystem.
        local mounts = reported("mounts")
        t:assert(mounts, "the shell reported the mount table: " .. console:sub(-600))
        for _, point in ipairs({ "/proc", "/sys", "/dev/shm", "/sys/fs/cgroup", "/run" }) do
            t:assert(mounts:find(point .. "=1", 1, true),
                point .. " is mounted exactly once: " .. mounts)
        end
        -- Same for the machine ID: the step ran a second time and left the
        -- one identifier Phase 1 had already established, rather than
        -- generating or appending another.
        t:assert(console:find("peinit: phase1 generated machine-id", 1, true),
            "Phase 1 established a machine ID")
        t:assert_eq(tostring(reported("machineid")):match("%d+"), "33",
            "and it is still one 32-character id and a newline, not two of them: " ..
            tostring(reported("machineid")))
    end)
