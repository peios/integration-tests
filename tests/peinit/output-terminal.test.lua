-- Peinit TRM §11.6 — terminal ownership.
--
-- A queue on a device, which is what this is. Every claim on the page is
-- about which of several services ends up with a terminal and what
-- happens to the rest, so every test here seeds two or three services
-- that want the same one and reads the outcome out of the service table.
--
-- The terminals used are spare virtual consoles — /dev/tty2 upwards.
-- /dev/console is deliberately left alone: the image's own
-- login-console holds it, peinit's progress output goes there, and this
-- suite reads that output as its oracle for half the other chapters.
--
-- One arrangement is kept away from every other test in this file, on
-- its own boot: two services that want the same terminal from the boot
-- plan. That case does not skip the loser, and the machine does not
-- survive it — see the known-bug case at the end. Everywhere else the
-- contention is arranged through demand starts and handovers, which are
-- start paths §11.6 covers just as squarely and which work.

local peinit = require("helpers.peinit")

-- One gigabyte rather than the helper's two. Chapter 11 boots more
-- machines than any other chapter here — a claim about output usually
-- needs a whole boot arranged around it — and provium reserves declared
-- memory for the life of a VM, so at the default these files queue
-- against the pool and each other. A booted guest uses about 300 MB
-- between its working set and the squashfs page cache, and the same
-- assertions hold at either size.
--
-- One vCPU for the same reason: provium admits VMs while the total
-- declared vCPU count fits the host's cores, so two apiece halves how
-- many of these boots can be in flight at once. Nothing here is
-- compute-bound.
local MEM, CPUS = "1G", 1

local resident = "#!/bin/sh\nwhile : ; do sleep 30; done\n"

--- A service that wants `tty`. Everything else has a default that keeps
--- the definitions in these tests down to the fields under discussion.
---
--- Omitting `triggers` omits `Triggers` altogether rather than writing an
--- empty list: a REG_MULTI_SZ with no entries is not the same thing as an
--- absent value, and writing one costs the whole seed file.
local function on_tty(name, tty, opts)
    opts = opts or {}
    local values = {
        { name = "ImagePath", type = "sz", data = opts.image or "/lcl/pt/resident.sh" },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "TTYPath", type = "sz", data = tty },
    }
    if opts.triggers then
        values[#values + 1] = { name = "Triggers", type = "multi", data = opts.triggers }
    end
    if opts.oneshot then
        values[#values + 1] = { name = "Type", type = "dword", data = 1 }
    end
    if opts.precedence then
        values[#values + 1] = { name = "TTYPrecedence", type = "dword", data = opts.precedence }
    end
    for _, extra in ipairs(opts.extra or {}) do values[#values + 1] = extra end
    return { path = [[Machine\System\Services\]] .. name, values = values }
end

local function seed_services(name, services)
    local keys = {
        { path = [[Machine\System]] },
        { path = [[Machine\System\Services]] },
    }
    for _, service in ipairs(services) do keys[#keys + 1] = service end
    return peinit.merge(
        { ["lcl/pt/resident.sh"] = { resident, exec = true } },
        peinit.seed(name, keys)
    )
end

local function status(vm, service)
    return vm:run("svctl status " .. service).stdout
end

--- The state svctl reports for a service.
---
--- The name is matched literally rather than as a pattern: every service
--- here has a hyphen in it, and a hyphen in a Lua pattern is a lazy
--- quantifier, so `pt-tty-holder` used as a pattern matches something
--- else entirely and quietly returns nil.
local function state_of(vm, service)
    local text = status(vm, service)
    local at = text:find(service .. ": ", 1, true)
    if not at then return nil end
    return text:sub(at + #service + 2):match("^%S+")
end

local function wait_state(vm, service, want)
    for _ = 1, 30 do
        if state_of(vm, service) == want then return true end
        vm:run("sleep 1")
    end
    return false
end

-- Three independent queues, one per terminal, on a single boot. A
-- terminal is the unit of contention, so scenarios on different devices
-- do not see each other and there is no reason to spend a machine on
-- each; they are separated here only so a failure names one queue.
--
--   /dev/tty2  a holder, and two services that ask for it afterwards
--   /dev/tty3  a holder that is stopped, and two waiters behind it
--   /dev/tty4  two waiters that state no preference at all
local vm = peinit.boot({
    memory = MEM, cpus = CPUS,
    name = "terminal",
    files = seed_services("zz-pt-terminal", {
        on_tty("pt-tty-holder", "/dev/tty2", { triggers = { "boot" } }),
        -- Started by hand below, after the terminal is already somebody's,
        -- and with a precedence far above the holder's.
        on_tty("pt-tty-late", "/dev/tty2", { precedence = 200 }),
        -- Wants the same terminal AND names a condition the machine does
        -- not meet, so which cause is recorded says which check ran first.
        on_tty("pt-tty-cond", "/dev/tty2", {
            extra = { { name = "Conditions", type = "multi", data = { "path:/pt-not-here" } } },
        }),

        -- The holder carries `tty:released` and the highest precedence of
        -- the three, so the exclusion of "the one whose exit freed it" is
        -- what stops it taking its own terminal straight back.
        on_tty("pt-h-holder", "/dev/tty3", {
            triggers = { "boot", "tty:released" }, precedence = 90,
        }),
        on_tty("pt-h-wait-hi", "/dev/tty3", {
            triggers = { "tty:released" }, precedence = 5,
        }),
        on_tty("pt-h-wait-lo", "/dev/tty3", {
            triggers = { "tty:released" }, precedence = 1,
        }),

        on_tty("pt-t-holder", "/dev/tty4", { triggers = { "boot" } }),
        on_tty("pt-t-aaa", "/dev/tty4", { triggers = { "tty:released" } }),
        on_tty("pt-t-bbb", "/dev/tty4", { triggers = { "tty:released" } }),
    }),
})

test("a terminal has one owner, and a second service asking for it is skipped rather than failed",
    {
        spec = {
            "peinit *terminal.a-terminal-has-exactly-one-owner-at-a-time",
            "peinit *terminal.a-service-holds-its-terminal-while-it-may-have-a-process-on-it",
            "peinit *terminal.every-start-path-asks-first-whether-the-terminal-is-free",
            "peinit *terminal.a-held-terminal-skips-the-start-with-ttyunavailable",
        },
    },
    function(t)
        t:assert(wait_state(vm, "pt-tty-holder", "active"), "the holder took the terminal")

        -- It really is on the device: all three of its streams are the
        -- terminal, so a second writer would interleave with it, which is
        -- what the queue exists to prevent.
        local pid = status(vm, "pt-tty-holder"):match("pid: (%d+)")
        t:assert(pid, "the holder has a process")
        t:assert_eq(vm:run("readlink /proc/" .. pid .. "/fd/1").stdout:gsub("%s+$", ""),
            "/dev/tty2", "and it is attached to the terminal")

        -- The on-demand start path asks whether the terminal is free
        -- before anything else. It is not, so the start ends there.
        vm:run("svctl start pt-tty-late")
        t:assert(wait_state(vm, "pt-tty-late", "skipped"),
            "the second service was skipped, not failed: " ..
            tostring(state_of(vm, "pt-tty-late")))
        t:assert(status(vm, "pt-tty-late"):find("tty_unavailable", 1, true),
            "and the cause names the terminal: " .. status(vm, "pt-tty-late"))

        -- Skipped rather than Failed, because nothing is wrong, and the
        -- holder was left alone.
        t:assert_eq(state_of(vm, "pt-tty-holder"), "active", "the holder is still holding")
    end)

test("a service already holding a terminal is not preempted by a higher-precedence latecomer",
    { spec = "peinit *terminal.a-holder-is-never-preempted" },
    function(t)
        -- `pt-tty-late` asked for the terminal with a precedence of 200
        -- against the holder's default of 0, and was refused. Precedence
        -- is consulted among simultaneous candidates only: taking a live
        -- terminal away from a process using it would lose whatever the
        -- operator was in the middle of typing.
        t:assert_eq(state_of(vm, "pt-tty-late"), "skipped",
            "the far-higher-precedence latecomer did not get it")
        t:assert_eq(state_of(vm, "pt-tty-holder"), "active",
            "and the incumbent kept it")
    end)

test("nothing is written to the console about a service skipped for a busy terminal",
    { spec = "peinit *terminal.a-terminal-skip-is-not-announced" },
    function(t)
        -- It is the mechanism working rather than a fault, and the message
        -- would land on the very terminal whose new owner is at that
        -- moment drawing on it.
        local log = vm:console():read_log()
        t:assert(not log:find("pt-tty-late skipped", 1, true),
            "the skip was not announced")
        t:assert(not log:find("TtyUnavailable", 1, true),
            "nor was the cause")

        -- peinit did report other service outcomes on this boot, so the
        -- silence above is specific to this cause rather than to skips in
        -- general or to this console.
        t:assert(log:find("peinit: service", 1, true),
            "while other service outcomes were reported")
    end)

test("the terminal check runs ahead of the service's own conditions",
    { spec = "peinit *terminal.the-terminal-check-precedes-conditions-and-asserts" },
    function(t)
        -- `pt-tty-cond` fails on two counts: the terminal is held, and a
        -- path its Conditions require does not exist. Which cause is
        -- recorded says which check ran first — and that is why a service
        -- queued on a busy terminal never forks a check helper for the
        -- other.
        vm:run("svctl start pt-tty-cond")
        t:assert(wait_state(vm, "pt-tty-cond", "skipped"), "it was skipped")
        local reported = status(vm, "pt-tty-cond")
        t:assert(reported:find("tty_unavailable", 1, true),
            "the terminal check decided it: " .. reported)
        t:assert(not reported:find("condition_skipped", 1, true),
            "and the condition was never reached")
    end)

test("when the holder releases the terminal it goes to one waiter, the highest-precedence one",
    {
        spec = {
            "peinit *terminal.a-tty-released-waiter-is-started-when-the-terminal-comes-free",
            "peinit *terminal.every-exit-from-a-holding-state-frees-the-device",
            "peinit *terminal.higher-tty-precedence-wins",
            "peinit *terminal.one-winner-per-release",
            "peinit *terminal.the-handover-starts-the-waiter-as-an-explicit-start-would",
        },
    },
    function(t)
        t:assert(wait_state(vm, "pt-h-holder", "active"), "the tty3 holder is holding")

        -- Both waiters ask for the terminal first and are refused, so each
        -- is sitting in Skipped when its turn comes — which is the
        -- ordinary position for a waiter, and what makes the last
        -- assertion here mean something.
        vm:run("svctl start pt-h-wait-hi")
        vm:run("svctl start pt-h-wait-lo")
        t:assert(wait_state(vm, "pt-h-wait-hi", "skipped"), "the high-precedence waiter is queued")
        t:assert(wait_state(vm, "pt-h-wait-lo", "skipped"), "and so is the low-precedence one")

        -- Stopped by an administrator: one of the four ways §11.6 lists of
        -- leaving a holding state, and peinit watches the transition
        -- rather than the reason for it.
        vm:run("svctl stop pt-h-holder"):assert_ok()

        t:assert(wait_state(vm, "pt-h-wait-hi", "active"),
            "the higher-precedence waiter was given the terminal")
        t:assert(state_of(vm, "pt-h-wait-lo") ~= "active",
            "and the lower-precedence one was not, so exactly one was started")

        -- Only an explicit start takes a service out of Skipped, and the
        -- handover is that start rather than a mark that lets it drift
        -- back into the boot set.
        t:assert(vm:console():read_log():find("peinit: service pt%-h%-wait%-hi started"),
            "the winner was started rather than merely marked runnable")
    end)

test("the service whose exit freed the terminal is not the one offered it back",
    { spec = "peinit *terminal.the-service-whose-exit-freed-the-terminal-is-not-offered-it" },
    function(t)
        -- `pt-h-holder` has the highest precedence of the three and asks
        -- for `tty:released`. Without the exclusion it would win its own
        -- terminal back the moment it stopped — a restart policy with no
        -- budget, and one no waiter behind it would ever get past.
        t:assert(state_of(vm, "pt-h-holder") ~= "active",
            "the stopped holder did not take its own terminal back")

        local starts = 0
        for _ in vm:console():read_log():gmatch("peinit: service pt%-h%-holder started") do
            starts = starts + 1
        end
        t:assert_eq(starts, 1, "it was started exactly once, at boot")
    end)

test("waiters that state no preference are ranked by name, so the same machine boots the same way",
    {
        spec = {
            "peinit *terminal.equal-precedence-breaks-on-service-name",
            "peinit *terminal.the-default-precedence-is-zero",
        },
    },
    function(t)
        -- Neither waiter carries a TTYPrecedence, so both are at the
        -- default and the tie is broken on the service name rather than on
        -- whichever definition the registry happened to enumerate first.
        t:assert(wait_state(vm, "pt-t-holder", "active"), "the tty4 holder is holding")
        vm:run("svctl start pt-t-bbb")
        vm:run("svctl start pt-t-aaa")
        t:assert(wait_state(vm, "pt-t-bbb", "skipped"), "both waiters are queued")
        t:assert(wait_state(vm, "pt-t-aaa", "skipped"), "including the one asked for second")

        vm:run("svctl stop pt-t-holder"):assert_ok()
        t:assert(wait_state(vm, "pt-t-aaa", "active"),
            "the name that sorts first won the terminal")
        t:assert(state_of(vm, "pt-t-bbb") ~= "active",
            "and the other did not, though it asked first")
    end)

-- Kept off the boot above so that a `reload-config` and a `stop` cannot
-- reach the queues it reads.
local removed = peinit.boot({
    memory = MEM, cpus = CPUS,
    name = "terminal-removed",
    files = seed_services("zz-pt-removed", {
        on_tty("pt-r-holder", "/dev/tty5", { triggers = { "boot" }, precedence = 50 }),
        on_tty("pt-r-gone", "/dev/tty5", { triggers = { "tty:released" }, precedence = 99 }),
        on_tty("pt-r-wait", "/dev/tty5", { triggers = { "tty:released" }, precedence = 1 }),
    }),
})

test("a service whose definition has been removed is not offered the terminal, however high its precedence",
    {
        spec = {
            "peinit *terminal.a-service-with-a-removed-definition-is-not-offered-it",
            "peinit *terminal.the-released-terminal-is-recorded-on-the-transition",
        },
    },
    function(t)
        t:assert(wait_state(removed, "pt-r-holder", "active"), "the holder took the terminal")
        removed:run("svctl start pt-r-gone")
        removed:run("svctl start pt-r-wait")
        t:assert(wait_state(removed, "pt-r-gone", "skipped"), "both waiters queued behind it")
        t:assert(wait_state(removed, "pt-r-wait", "skipped"), "including the low-precedence one")

        -- Remove the highest-precedence waiter's definition. It keeps its
        -- table entry until it reaches a state that does not retain one,
        -- but it cannot be started, so it is not a candidate.
        removed:run([[reg del 'Machine\System\Services\pt-r-gone']]):assert_ok()
        removed:run("svctl reload-config"):assert_ok()

        -- Free the terminal. Which terminal was released is recorded on
        -- the transition itself rather than looked up afterwards, which is
        -- what makes a handover work at all when the releasing service has
        -- lost its own definition by the time anyone could ask.
        removed:run("svctl stop pt-r-holder"):assert_ok()

        t:assert(wait_state(removed, "pt-r-wait", "active"),
            "the terminal went to the waiter that could still be started")
        t:assert(state_of(removed, "pt-r-gone") ~= "active",
            "and not to the higher-precedence one whose definition had gone")
    end)

-- Two more queues, on one boot.
--
--   /dev/tty6  a holder that exits immediately and is restarted always,
--              so it spends most of its life between attempts
--   /dev/tty7  two deferred starts wanting one terminal at the same
--              moment, which is one of the two places §11.6 says has
--              genuinely simultaneous candidates
local backoff = peinit.boot({
    memory = MEM, cpus = CPUS,
    name = "terminal-backoff",
    files = seed_services("zz-pt-backoff", {
        on_tty("pt-b-holder", "/dev/tty6", {
            triggers = { "boot" }, image = "/bin/true",
            extra = { { name = "RestartPolicy", type = "dword", data = 2 },
                      { name = "RestartDelay", type = "dword", data = 5 } },
        }),
        on_tty("pt-b-wait", "/dev/tty6", { triggers = { "tty:released" }, precedence = 99 }),

        on_tty("pt-d-aaa", "/dev/tty7", { triggers = { "boot:settled" }, precedence = 1 }),
        on_tty("pt-d-zzz", "/dev/tty7", { triggers = { "boot:settled" }, precedence = 90 }),
    }),
})
local deferred = backoff

test("a service between restart attempts still holds its terminal",
    { spec = "peinit *terminal.backoff-holds" },
    function(t)
        -- Handing the terminal on during the gap would produce two owners a
        -- second later, so Backoff counts as holding even though there is
        -- no process on the device at that moment.
        t:assert(wait_state(backoff, "pt-b-holder", "backoff"),
            "the holder is between restart attempts")

        -- The waiter's precedence is 99 against the holder's default, and
        -- it asks to be woken when the terminal frees. It has not been.
        t:assert(state_of(backoff, "pt-b-wait") ~= "active",
            "the waiter was not given the terminal during the gap: " ..
            tostring(state_of(backoff, "pt-b-wait")))
        t:assert(not backoff:console():read_log():find("peinit: service pt%-b%-wait started"),
            "and was never started")
    end)

test("deferred starts are dispatched highest-precedence first, so the winner takes the device",
    { spec = "peinit *terminal.deferred-starts-are-dispatched-highest-precedence-first" },
    function(t)
        -- Note the names: `pt-d-zzz` sorts last, so a dispatch that went
        -- in table order rather than by precedence would have given the
        -- terminal to `pt-d-aaa`.
        t:assert(wait_state(deferred, "pt-d-zzz", "active"),
            "the higher-precedence deferred service took the terminal")
        t:assert(wait_state(deferred, "pt-d-aaa", "skipped"),
            "and the other was skipped: " .. tostring(state_of(deferred, "pt-d-aaa")))
    end)

test("two services wanting one terminal from the boot plan: the loser is skipped and the machine survives",
    {
        spec = {
            "peinit *terminal.a-held-terminal-skips-the-start-with-ttyunavailable",
            "peinit *terminal.the-boot-plan-orders-by-the-graph-not-precedence",
        },
        tags = { "known-bug" },
    },
    function(t)
        -- The arrangement §11.6 exists to describe, and the one start path
        -- on which it does not work. Two boot-triggered services name one
        -- terminal; both are admitted by the boot plan, so the loser is
        -- exec'd rather than skipped and dies in TIOCSCTTY with EPERM
        -- because the terminal already has a session.
        --
        -- Its default RestartPolicy is OnFailure, so it goes to Backoff,
        -- and the restart attempt does reach the terminal check — which
        -- returns Skipped with cause TtyUnavailable. `Backoff -> Skipped`
        -- is not an allowed transition, the runtime loop returns
        -- InvalidTransition, and peinit enters recovery. A machine with two
        -- definitions naming one TTYPath loses PID 1 seconds into the boot.
        local other = peinit.boot({
            memory = MEM, cpus = CPUS,
            name = "terminal-contend",
            files = seed_services("zz-pt-contend", {
                on_tty("pt-c-aaa", "/dev/tty2", { triggers = { "boot" } }),
                on_tty("pt-c-zzz", "/dev/tty2", { triggers = { "boot" }, precedence = 99 }),
            }),
        })
        -- Long enough for the restart delay to elapse and the second start
        -- attempt to be made.
        other:run("sleep 10")
        local log = other:console():read_log()

        t:assert(not log:find("entering recovery", 1, true),
            "the machine survived two services wanting one terminal: " ..
            tostring(log:match("[^\r\n]*entering recovery[^\r\n]*")))

        -- The boot plan's order is the graph's rather than precedence's,
        -- so the lower-precedence name reached first is the one that gets
        -- the device, and the other is skipped.
        t:assert_eq(state_of(other, "pt-c-aaa"), "active",
            "the service the plan reached first took the terminal")
        t:assert_eq(state_of(other, "pt-c-zzz"), "skipped",
            "and the higher-precedence one was skipped rather than launched")
    end)
