-- prelude's scheduler, as pass mechanics: what each pass runs, what
-- counts as progress, what happens when a pass achieves nothing, and what
-- prelude logs on the way through.
--
-- The scheduler makes repeated passes over the sequence, running whatever
-- is ready and leaving deferred hooks pending for a later pass. Only a
-- terminal outcome — Satisfied or Declined — is progress; a pass that
-- makes none while work remains is a dead end, and prelude ends the boot
-- there with a per-hook diagnosis rather than spinning.
--
-- The capability semantics behind readiness — settled versus achieved —
-- are in capabilities.test.lua. Every graph here that expects a handoff
-- keeps the profile's root-mounting hook, and so does every graph that
-- expects a halt: with a root mounted, a halt can only have come from the
-- scheduler and not from the root check a phase later.

local prelude = require("helpers.prelude")

-- Occurrences of a literal substring.
local function count(text, sub)
    local n, from = 0, 1
    while true do
        local i = text:find(sub, from, true)
        if not i then return n end
        n, from = n + 1, i + 1
    end
end

test("a pass walks the sequence in the order the sequence lists",
    { spec = "prelude sched.passes-in-sequence-order" },
    function(t)
        -- Deliberately reverse-alphabetical, because name order is what
        -- mkirf used when it resolved the graph and prelude must not
        -- reapply it: with no declarations to constrain anything, the
        -- listed order IS the order.
        local vm = provium:vm("sched-order", "prelude")
        vm:boot({ files = prelude.files({
            hooks = { zulu = {}, mike = {}, alpha = {} },
            order = { "zulu", "mike", "alpha" },
            keep = { "pt-mount-root.sh" },
        }) })

        local log = vm:console():read_log()
        t:assert_eq(table.concat(prelude.ran(log), ","),
            "zulu.sh,mike.sh,alpha.sh,pt-mount-root.sh",
            "the hooks ran in sequence order, not name order")
        t:assert(log:find("ran 4 hook invocation(s)", 1, true),
            "one pass, one invocation each")
    end)

test("a pass skips the hooks already satisfied or declined",
    { spec = "prelude sched.passes-in-sequence-order" },
    function(t)
        -- Both terminal outcomes are skipped, and only the pending one is
        -- tried again — so the second pass is not a replay of the first.
        local vm = provium:vm("sched-skip", "prelude")
        vm:boot({
            files = prelude.files({
                hooks = { ["sat-hook"] = {}, decliner = {}, waiting = {} },
                order = { "sat-hook", "decliner", "waiting" },
                keep = { "pt-mount-root.sh" },
            }),
            kernel_cmdline_append = "pt.decliner=decline pt.waiting=defer:2",
        })

        local log = vm:console():read_log()
        t:assert_eq(table.concat(prelude.ran(log), ","),
            "sat-hook.sh,decliner.sh,waiting.sh,pt-mount-root.sh,waiting.sh",
            "the second pass ran only the deferred hook: the satisfied and " ..
            "the declined ones were skipped")
        t:assert_eq(prelude.invocations(log, "sat-hook"), 1, "the satisfied hook ran once")
        t:assert_eq(prelude.invocations(log, "decliner"), 1, "the declined hook ran once")
        t:assert_eq(prelude.invocations(log, "waiting"), 2, "the deferred hook ran once per pass")
    end)

test("a deferral is not progress, so a pass that only defers ends the boot",
    { spec = "prelude sched.deferral-is-not-progress" },
    function(t)
        -- Pass 1 progressed because a hook declined and another satisfied:
        -- both terminal outcomes count. Pass 2 ran a hook — the deferring
        -- one — and completed nothing, and that ended the boot even though
        -- the hook was scripted to succeed on its third run. Deferral buys
        -- another pass only when something else finishes.
        local vm = provium:vm("sched-defer", "prelude")
        local err = prelude.boot_halts(t, vm, {
            files = prelude.files({
                hooks = { decliner = {}, waiting = {} },
                order = { "decliner", "waiting" },
                keep = { "pt-mount-root.sh" },
            }),
            kernel_cmdline_append = "pt.decliner=decline pt.waiting=defer:3",
        })

        t:assert(err:find("hooks cannot proceed", 1, true),
            "the boot ended in the scheduler: " .. err:sub(-500))
        t:assert_eq(prelude.invocations(err, "waiting"), 2,
            "the deferring hook was tried once on each of the two passes " ..
            "and never a third time, though its third run would have succeeded")
        t:assert(err:find("halting system", 1, true), "and the machine halted")
    end)

test("a pass that completes nothing while work remains ends the boot rather than spinning",
    { spec = "prelude sched.a-pass-with-no-progress-ends-the-boot" },
    function(t)
        -- The second pass ran no hook at all: the only one left could
        -- never become ready. prelude refuses there — before the root
        -- check, and so before noticing that a root had in fact been
        -- mounted. Outstanding work is a failure, not something to leave
        -- behind.
        local vm = provium:vm("sched-noprogress", "prelude")
        local err = prelude.boot_halts(t, vm, {
            files = prelude.files({
                hooks = {
                    blocked = { requires = { "never-achieved-cap" } },
                    decliner = { provides = { "never-achieved-cap" } },
                },
                order = { "blocked", "decliner" },
                keep = { "pt-mount-root.sh" },
            }),
            kernel_cmdline_append = "pt.decliner=decline",
        })

        t:assert(err:find("hooks cannot proceed", 1, true),
            "prelude ended the boot with the scheduler's diagnosis: " .. err:sub(-500))
        t:assert(err:find("pt|decliner|pass=1|", 1, true),
            "the console text reaches back to the first pass, so what is " ..
            "absent from it is absent because it never happened")
        t:assert_eq(prelude.invocations(err, "blocked"), 0,
            "the blocked hook was never invoked")
        t:assert(not err:find("root mounted at /mnt/rootfs", 1, true),
            "and prelude never reached the root check, though the kept hook " ..
            "had mounted one: a stuck pass ends the boot where it stands")
        t:assert(err:find("halting system", 1, true), "then halted")
    end)

test("the stuck diagnosis names every outstanding hook and why each is stuck",
    { spec = "prelude sched.stuck-diagnosis-names-each-hook" },
    function(t)
        -- One graph reaching all four of the scheduler's diagnoses at
        -- once. `decliner` provides a capability and declines it;
        -- `staller` provides another and defers for ever. Between them
        -- they strand a requirer on a fully-declined capability, a
        -- requirer on an unsettled one, and an `after` on the same
        -- unsettled one — and `staller` itself is waiting on nothing.
        local vm = provium:vm("sched-stuck", "prelude")
        local err = prelude.boot_halts(t, vm, {
            files = prelude.files({
                hooks = {
                    ["needs-declined"] = { requires = { "declined-cap" } },
                    ["decliner"]       = { provides = { "declined-cap" } },
                    ["needs-stalled"]  = { requires = { "stalled-cap" } },
                    ["after-stalled"]  = { after = { "stalled-cap" } },
                    ["staller"]        = { provides = { "stalled-cap" } },
                },
                order = { "needs-declined", "decliner", "needs-stalled",
                          "after-stalled", "staller" },
                keep = { "pt-mount-root.sh" },
            }),
            kernel_cmdline_append = "pt.decliner=decline pt.staller=defer",
        })

        t:assert(err:find("hooks cannot proceed", 1, true),
            "prelude refused the boot with a diagnosis: " .. err:sub(-600))
        local why = prelude.stuck_reasons(err)

        -- The four are distinct strings, and each lands on the hook whose
        -- declaration produced it.
        local cases = {
            { "needs-declined.sh", "declined-cap", "every provider declined it" },
            { "needs-stalled.sh",  "stalled-cap",  "not achieved" },
            { "after-stalled.sh",  "stalled-cap",  "not settled" },
            { "staller.sh",        nil,            "deferred with nothing left to wait for" },
        }
        for _, case in ipairs(cases) do
            local hook, cap, phrase = case[1], case[2], case[3]
            local line = why[hook]
            t:assert(line, hook .. " is named in the diagnosis")
            if line then
                if cap then
                    t:assert(line:find(cap, 1, true),
                        hook .. "'s diagnosis names the capability it waits on, got: " .. line)
                end
                t:assert(line:find(phrase, 1, true),
                    hook .. "'s diagnosis reads `" .. phrase .. "`, got: " .. line)
            end
        end
        t:assert(not why["decliner.sh"],
            "the hook that declined is terminal and so is not diagnosed")
    end)

test("the completion line counts invocations, so a retried hook counts twice",
    { spec = "prelude sched.invocation-count-includes-retries" },
    function(t)
        -- Three hooks, four invocations: the count is of runs, not of
        -- hooks, and a deferral is a run.
        local vm = provium:vm("sched-count", "prelude")
        vm:boot({
            files = prelude.files({
                hooks = { alpha = {}, bravo = {} },
                order = { "alpha", "bravo" },
                keep = { "pt-mount-root.sh" },
            }),
            kernel_cmdline_append = "pt.alpha=defer:2",
        })

        local log = vm:console():read_log()
        t:assert(log:find("ran 4 hook invocation(s)", 1, true),
            "prelude counted four invocations of three hooks")
        t:assert_eq(#prelude.ran(log), 4,
            "and announced a run for each of them")
        t:assert_eq(prelude.invocations(log, "alpha"), 2,
            "the deferred hook was the one counted twice")
    end)

test("repeated passes re-run only what has not settled, so invocations exceed the hook count",
    { spec = { "prelude sched.worst-case-is-quadratic",
               "prelude sched.invocation-count-includes-retries" } },
    function(t)
        -- The worst case — O(n²) invocations for n hooks — is a design
        -- property of the loop rather than something a guest can measure,
        -- but its shape is observable: each pass costs one run per hook
        -- still pending, so a staircase of deferrals produces the
        -- triangular sum rather than one run apiece.
        --
        -- Five hooks, four passes, 5 + 3 + 2 + 1 = 11 invocations: above
        -- the hook count and below the n² ceiling, which is exactly the
        -- claim.
        local vm = provium:vm("sched-passes", "prelude")
        vm:boot({
            files = prelude.files({
                hooks = { d1 = {}, d2 = {}, d3 = {}, tail = {} },
                order = { "d1", "d2", "d3", "tail" },
                keep = { "pt-mount-root.sh" },
            }),
            kernel_cmdline_append = "pt.d1=defer:4 pt.d2=defer:3 pt.d3=defer:2",
        })

        local log = vm:console():read_log()
        local ran = prelude.ran(log)
        t:assert_eq(#ran, 11,
            "each pass re-ran every hook still pending: 5 + 3 + 2 + 1 runs " ..
            "for 5 hooks, got " .. table.concat(ran, ","))
        t:assert(log:find("ran 11 hook invocation(s)", 1, true),
            "and prelude counted all eleven")
        t:assert(#ran > 5 and #ran <= 5 * 5,
            "more invocations than hooks, and inside the quadratic bound")
        t:assert_eq(prelude.invocations(log, "d1"), 4,
            "the hook that deferred longest ran on every pass")
    end)

test("prelude logs the full path of every hook before it runs it",
    { spec = "prelude hook.each-run-is-logged" },
    function(t)
        -- One line per invocation, not per hook, and the path is the one
        -- from the sequence rather than a bare name — which is what makes
        -- the log usable when two directories hold hooks of the same name.
        local vm = provium:vm("sched-log-run", "prelude")
        vm:boot({
            files = prelude.files({
                hooks = { alpha = {} },
                keep = { "pt-mount-root.sh" },
            }),
            kernel_cmdline_append = "pt.alpha=defer:2",
        })

        local log = vm:console():read_log()
        local line = "prelude: hook: " .. prelude.HOOK_DIR .. "/alpha.sh"
        t:assert_eq(count(log, line), 2,
            "the retried hook was announced on each of its two invocations")
        t:assert_eq(count(log, "prelude: hook: " .. prelude.HOOK_DIR .. "/pt-mount-root.sh"), 1,
            "and the hook that ran once was announced once")

        -- The announcement comes before the hook does anything.
        local announced = log:find(line, 1, true)
        local reported = log:find("pt|alpha|pass=1|", 1, true)
        t:assert(announced and reported and announced < reported,
            "prelude logs the hook before running it, not after")
    end)

test("a decline and a deferral are each logged, a satisfied hook is not",
    { spec = "prelude hook.decline-and-defer-are-logged" },
    function(t)
        -- The two non-terminal-looking outcomes get a line of their own,
        -- because neither is a failure and neither is silence: an operator
        -- reading the console has to be able to tell "not applicable here"
        -- from "not yet". Success needs no line — the `hook:` line already
        -- said it ran, and nothing said otherwise.
        local vm = provium:vm("sched-log-outcome", "prelude")
        vm:boot({
            files = prelude.files({
                hooks = { decliner = {}, waiting = {} },
                order = { "decliner", "waiting" },
                keep = { "pt-mount-root.sh" },
            }),
            kernel_cmdline_append = "pt.decliner=decline pt.waiting=defer:2",
        })

        local log = vm:console():read_log()
        t:assert_eq(count(log,
            "hook " .. prelude.HOOK_DIR .. "/decliner.sh: declined (not applicable here)"), 1,
            "the decline was logged, once, naming the hook")
        t:assert_eq(count(log,
            "hook " .. prelude.HOOK_DIR .. "/waiting.sh: deferred (will retry)"), 1,
            "the deferral was logged, once, on the pass it happened")
        t:assert_eq(count(log, "pt-mount-root.sh: declined"), 0,
            "and the satisfied hook got no outcome line at all")
        t:assert_eq(count(log, "pt-mount-root.sh: deferred"), 0,
            "of either kind")
    end)
