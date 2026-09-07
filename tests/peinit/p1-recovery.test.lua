-- Peinit TRM §2.3 — the Phase 1 failures that end the boot: an unusable
-- root, a filesystem that will not mount, a clock that cannot be set, a
-- registryd that never serves, and a socket that cannot be bound.
--
-- Most of these happen before anything has started the provium agent, so
-- the console is the only record and `peinit.boot_to_recovery` is how it
-- is read. The socket failures are the exception: step 9 is *after* the
-- phase-1.5 autoruns, so the agent is already running when peinit gives
-- up, and those tests boot normally, wait for the autorun mark and then
-- watch the console for the recovery line. Either way the assertions are
-- about what peinit said on its way there, which is the right level: what
-- is under test is which step failed the boot, and peinit names it.
--
-- One VM per test rather than a shared one, because a VM that reached
-- recovery is finished as far as provium is concerned.
--
-- Two of the failures are reached with `initcall_blacklist`, which stops
-- one kernel initcall from running. It is the only lever this suite has
-- on what the kernel provides, and it is what makes "the filesystem
-- cannot be mounted" and "the RTC cannot be opened" reachable at all:
-- neither is something a file staged into the root can produce.

local peinit = require("helpers.peinit")
peinit.claim(1)

test("a root that will not take the write probe sends peinit to recovery",
    { spec = "peinit *phase1.an-unwritable-root-is-recovery" },
    function(t)
        -- peinit probes rather than remounting, and the probe starts by
        -- creating `/.peinit`. A regular file staged at that path is a
        -- root that cannot hold the probe — which is what an unusable
        -- root looks like from inside the step, without needing a root
        -- that is genuinely read-only (and one that was would not get
        -- this far: the staging hook writes to it too).
        local log = peinit.boot_to_recovery(t, {
            name = "rec-root",
            files = { [".peinit"] = "not a directory\n" },
        })
        t:assert(log:find("entering recovery: RootWritable", 1, true),
            "peinit named the writability probe as the reason: " .. log:sub(-800))
        t:assert(log:find("/.peinit", 1, true),
            "and the path it could not use")
        t:assert(not log:find("peinit: phase2 boot complete", 1, true),
            "Phase 2 never ran")
    end)

test("a filesystem peinit owns that will not mount sends peinit to recovery",
    { spec = "peinit *phase1.a-failed-peinit-owned-mount-is-recovery" },
    function(t)
        -- Blacklisting devpts's initcall leaves the kernel with the
        -- filesystem unregistered, so the mount of `/dev/pts` — one of
        -- the four rows peinit owns — fails with ENODEV. The three the
        -- initramfs provides tolerate a failure; these four do not,
        -- because nothing later in the boot can do without them.
        local log = peinit.boot_to_recovery(t, {
            name = "rec-mount",
            append = "initcall_blacklist=init_devpts_fs",
        })
        t:assert(log:find("entering recovery: VirtualFilesystems", 1, true),
            "peinit named the mount step as the reason: " .. log:sub(-800))
        t:assert(log:find("mount /dev/pts as devpts failed", 1, true),
            "and the row that failed")
        -- The console provium keeps out of a failed boot is a bounded
        -- tail, so a "this line is absent" assertion is only worth
        -- something if the window reaches back past where the line would
        -- have been. The step's opening line is in it, and the missing
        -- one would have followed it.
        t:assert(log:find("peinit: phase1 mounting virtual filesystems", 1, true),
            "the tail covers the mount step")
        t:assert(not log:find("peinit: phase1 virtual filesystems mounted", 1, true),
            "the step never completed")
        t:assert(not log:find("peinit: phase1 starting registryd", 1, true),
            "and nothing after it ran")
    end)

test("no openable RTC device sends peinit to recovery",
    { spec = "peinit *phase1.any-rtc-failure-is-recovery" },
    function(t)
        -- Blacklisting the CMOS RTC driver's initcall leaves the kernel
        -- with no RTC device at all, so both `/dev/rtc` and `/dev/rtc0`
        -- are absent and the step's first action fails. Every failure in
        -- this step is fatal — an unset clock means every timestamp on
        -- the machine, including registry writes and the boot attempt
        -- counter, is meaningless.
        local log = peinit.boot_to_recovery(t, {
            name = "rec-rtc",
            append = "initcall_blacklist=cmos_init",
        })
        t:assert(log:find("entering recovery: RtcClock", 1, true),
            "peinit named the clock step as the reason: " .. log:sub(-800))
        -- The message also shows the order: the primary device first,
        -- then the fallback, which is the fallback claim seen from its
        -- failing side.
        t:assert(log:find("/dev/rtc0", 1, true),
            "having tried the fallback device as well")

        -- The step's place in the order, which is what makes this the
        -- RTC's failure and not something earlier: the mounts and the
        -- machine ID are behind it, registryd is not.
        t:assert(log:find("peinit: phase1 virtual filesystems mounted", 1, true),
            "the earlier steps had run")
        t:assert(not log:find("peinit: phase1 registryd started", 1, true),
            "and registryd was never started")
    end)

test("a registryd that cannot be exec'd sends peinit to recovery",
    { spec = "peinit *phase1.no-registryd-is-recovery" },
    function(t)
        -- `/sbin` is a StrataFS view whose create layer is `/lcl/sbin`,
        -- so a file staged there IS the binary peinit execs. Staged
        -- without the execute bit — which under KACS is the intrinsic
        -- "this is executable" flag — the exec fails with EACCES, and
        -- the failure arrives on the child's setup-status pipe rather
        -- than as a timeout.
        --
        -- This is the "fails to start" arm of the rule; the test below
        -- is the "readiness times out" arm, and p1-schema-version is the
        -- "probe fails" one.
        local log = peinit.boot_to_recovery(t, {
            name = "rec-registryd-exec",
            files = { ["lcl/sbin/registryd"] = "#!/bin/sh\nexit 0\n" },
        })
        t:assert(log:find("entering recovery: Registryd", 1, true),
            "peinit named registryd as the reason: " .. log:sub(-900))
        t:assert(not log:find("readiness timeout", 1, true),
            "and did not wait for readiness on a process that never started")
        -- The console tail is bounded, so the negative below is worth
        -- something only because the line that would have preceded it is
        -- inside the window.
        t:assert(log:find("peinit: phase1 starting registryd", 1, true),
            "the tail covers the start")
        t:assert(not log:find("peinit: phase1 registryd started", 1, true),
            "registryd never started")
        t:assert(not log:find("peinit: phase2 boot complete", 1, true),
            "and there was no Phase 2 without a registry")
    end)

test("a registryd that never becomes ready sends peinit to recovery",
    {
        spec = {
            "peinit *phase1.no-registryd-is-recovery",
            "peinit *phase1.registryd-start-has-two-thirty-second-timeouts",
        },
    },
    function(t)
        -- A regular file where registryd's hive directory belongs. The
        -- daemon execs, cannot create its storage, and exits — so peinit
        -- has a process that started and never signalled, which is the
        -- readiness timeout's case rather than the setup one's.
        --
        -- The wait is bounded, and this is the upper half of the bracket
        -- on that bound: the boot is given sixty seconds before its
        -- console is read, and the timeout has fired by then. The lower
        -- half is the next test. (Only the readiness timeout is
        -- reachable this way; nothing a test can stage makes process
        -- setup itself hang.)
        --
        -- Sixty rather than thirty-five, because the deadline is thirty
        -- seconds from the moment registryd starts and how long a loaded
        -- host takes to get there is not this test's business. A tighter
        -- upper bound would turn host load into a failure, which is the
        -- least useful kind.
        local started = os.time()
        local log = peinit.boot_to_recovery(t, {
            name = "rec-registryd",
            agent_timeout = 60,
            files = { ["var/state/loregd"] = "not a directory\n" },
        })
        t:assert(log:find("entering recovery: Registryd", 1, true),
            "peinit named registryd as the reason: " .. log:sub(-900))
        t:assert(log:find("readiness timeout expired before READY=1", 1, true),
            "and the readiness wait as what expired")
        t:assert(os.time() - started > 25,
            "which took longer than twenty-five seconds, so the wait was a real one")

        -- What registryd itself said, relayed. Phase 1 has no event loop
        -- to drain a service's pipes, so this is peinit deliberately
        -- reading them on the failure path — without it the operator has
        -- a timeout and no cause.
        t:assert(log:find("registryd failed; what it said follows", 1, true),
            "peinit relayed registryd's own words")
        t:assert(log:find("/var/state/loregd", 1, true),
            "which named the storage it could not create")
        t:assert(not log:find("peinit: phase2 boot complete", 1, true),
            "and there was no Phase 2 without a registry")
    end)

--- An autorun that puts a directory where one of peinit's sockets is
--- about to be bound. Autoruns are step 7 and the sockets are step 9, so
--- this runs in between — and a directory is a path `unlink` cannot
--- clear, which is what the bind does to a stale socket before it binds.
local function block(path)
    return {
        ["lcl/policy/autorun.d/20-pt-block.sh"] =
            { "#!/bin/sh\nmkdir -p " .. path .. "\n", exec = true },
    }
end

--- Boot expecting recovery from a step that runs *after* the agent has
--- been started, and return the console. `boot_to_recovery` is no use
--- here: the agent comes up, so the boot succeeds and only the console
--- says the system then gave up.
local function boot_to_late_recovery(name, files)
    local vm = peinit.boot({ name = name, stage = "autoruns", files = files })
    vm:console():expect("entering recovery", peinit.STAGE_TIMEOUT)
    return vm:console():read_log()
end

test("a control socket that cannot be bound sends peinit to recovery",
    { spec = "peinit *phase1.a-socket-failure-is-recovery" },
    function(t)
        -- Without the control socket there is no way to administer the
        -- system at all, so a boot that reached Phase 2 without one
        -- would be a machine nobody could stop, start or query.
        local log = boot_to_late_recovery("rec-control-sock",
            block("/run/services/peinit/control.sock"))
        t:assert(log:find("entering recovery: Infrastructure", 1, true),
            "peinit named the infrastructure step: " .. log:sub(-900))
        t:assert(log:find("bind control socket /run/services/peinit/control.sock failed", 1, true),
            "and the socket it could not bind")
        t:assert(not log:find("peinit: phase2 boot complete", 1, true),
            "Phase 2 never ran")
    end)

test("a jobs socket that cannot be bound sends peinit to recovery",
    { spec = "peinit *phase1.a-socket-failure-is-recovery" },
    function(t)
        -- The other half of the same rule, and it is not redundant: the
        -- jobs socket is bound second and its failure is a different
        -- call site. A jobs socket with the wrong descriptor is either
        -- unreachable or open to everything, so peinit refuses to boot
        -- without one rather than continue with a half-built surface.
        local log = boot_to_late_recovery("rec-jobs-sock",
            block("/run/services/peinit/jobs.sock"))
        t:assert(log:find("entering recovery: Infrastructure", 1, true),
            "peinit named the infrastructure step: " .. log:sub(-900))
        t:assert(log:find("bind jobs socket /run/services/peinit/jobs.sock failed", 1, true),
            "and the socket it could not bind")
        t:assert(not log:find("peinit: phase2 boot complete", 1, true),
            "Phase 2 never ran")
    end)

test("the readiness wait is still running twenty seconds in",
    { spec = "peinit *phase1.registryd-start-has-two-thirty-second-timeouts" },
    function(t)
        -- The lower half of the bracket: the same broken registryd, read
        -- twenty seconds in. peinit has started it and is still waiting
        -- — no recovery, and none of the failure reporting the previous
        -- test saw at sixty. Together the two put the bound between
        -- twenty and sixty seconds, which is the observable form of a
        -- thirty-second timeout: a wait that is bounded, and bounded
        -- around there rather than at one second or at five minutes.
        local log = peinit.boot_to_recovery(t, {
            name = "rec-registryd-early",
            agent_timeout = 20,
            files = { ["var/state/loregd"] = "not a directory\n" },
        })
        t:assert(log:find("peinit: phase1 starting registryd", 1, true),
            "the start was under way: " .. log:sub(-800))
        t:assert(not log:find("entering recovery", 1, true),
            "and twenty seconds was not long enough for the timeout to fire")
    end)
