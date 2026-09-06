-- prelude's capability semantics: what makes a hook ready, and the
-- difference between a capability being *settled* and being *achieved*.
--
-- That distinction is the whole of prelude's scheduling design, and it is
-- not symmetric:
--
--   settled    every hook that supplies the capability, by `provides` or
--              by `contributes`, has reached a terminal outcome. This is
--              what `after` waits on, so a capability nothing supplies
--              settles vacuously and delays nobody.
--   achieved   settled, AND either nothing `provides` it or some provider
--              is Satisfied. This is what `requires` waits on, so a
--              capability whose every *alternative* declined is settled
--              for ever and achieved never — while a capability whose
--              every *contributor* declined is both.
--
-- The two sharp cases are the pair at the bottom of this file: the same
-- graph, the same outcomes, one key different, and the boot goes from
-- halting to handing off.
--
-- Pass mechanics — sequence order, retries, the stuck diagnosis, the
-- invocation count — are in scheduler.test.lua.

local prelude = require("helpers.prelude")

test("a hook is ready when its requires are achieved and its afters settled",
    { spec = "prelude sched.ready-is-requires-achieved-and-after-settled" },
    function(t)
        -- The consumer is FIRST in the sequence and runs LAST: readiness,
        -- not position, decides. It waits on one of each kind.
        local vm = provium:vm("cap-ready", "prelude")
        vm:boot({ files = prelude.files({
            hooks = {
                consumer = { requires = { "cap-required" }, after = { "cap-ordered" } },
                provider = { provides = { "cap-required" } },
                orderer  = { contributes = { "cap-ordered" } },
            },
            order = { "consumer", "provider", "orderer" },
            keep = { "pt-mount-root.sh" },
        }) })

        local log = vm:console():read_log()
        t:assert_eq(table.concat(prelude.ran(log), ","),
            "provider.sh,orderer.sh,pt-mount-root.sh,consumer.sh",
            "the consumer was skipped on the pass that ran its supplier " ..
            "and its orderer, and ran only once both had finished")
        t:assert(log:find("pt|consumer|pass=1|", 1, true),
            "and it ran once: waiting is not a run")
    end)

test("a capability is settled only once every supplier, by either key, is terminal",
    { spec = "prelude sched.settled-is-every-supplier-terminal" },
    function(t)
        -- Two suppliers of one capability, one by `contributes` and one by
        -- `provides`, because settling counts both keys alike. The
        -- contributor defers once, so the waiter must sit out a second
        -- pass in which the other supplier has long since finished:
        -- settled is a property of ALL suppliers, not of any.
        local vm = provium:vm("cap-settled", "prelude")
        vm:boot({
            files = prelude.files({
                hooks = {
                    waiter = { after = { "assembly" } },
                    ["part-one"] = { contributes = { "assembly" } },
                    ["part-two"] = { provides = { "assembly" } },
                },
                order = { "waiter", "part-one", "part-two" },
                keep = { "pt-mount-root.sh" },
            }),
            kernel_cmdline_append = "pt.part-one=defer:2",
        })

        local log = vm:console():read_log()
        t:assert_eq(table.concat(prelude.ran(log), ","),
            "part-one.sh,part-two.sh,pt-mount-root.sh,part-one.sh,waiter.sh",
            "the waiter ran only after the deferring contributor finished, " ..
            "though the other supplier of the same capability was done in pass 1")
    end)

test("an after on a capability nothing supplies delays nothing",
    { spec = "prelude sched.unsupplied-capability-is-settled-vacuously" },
    function(t)
        -- Settled is `all()` over the suppliers, and all() over an empty
        -- set is true. That is what lets a shared capability vocabulary
        -- name a milestone an image does not implement.
        local vm = provium:vm("cap-vacuous", "prelude")
        vm:boot({ files = prelude.files({
            hooks = { lonely = { after = { "nothing-in-this-image-supplies-this" } } },
            keep = { "pt-mount-root.sh" },
        }) })

        local log = vm:console():read_log()
        local ran = prelude.ran(log)
        t:assert_eq(ran[1], "lonely.sh",
            "the hook ran first, on the first pass: an unsupplied `after` " ..
            "is settled vacuously and holds nobody back")
        t:assert(log:find("ran 2 hook invocation(s)", 1, true),
            "and the boot completed in one pass, two invocations")
    end)

test("a requires on a capability nothing supplies is achieved vacuously too",
    { spec = { "prelude sched.unsupplied-capability-is-settled-vacuously",
               "prelude sched.achieved-needs-a-satisfied-provider" } },
    function(t)
        -- The `nothing provides it` branch of achieved, reached through an
        -- empty supplier set. mkirf refuses to BUILD an image with an
        -- unsupplied `requires`, but prelude's scheduler does not re-check
        -- it: fed such a sequence directly, it runs the hook immediately
        -- rather than refusing the boot.
        local vm = provium:vm("cap-req-vacuous", "prelude")
        vm:boot({ files = prelude.files({
            hooks = { hopeful = { requires = { "nothing-supplies-this-either" } } },
            keep = { "pt-mount-root.sh" },
        }) })

        local log = vm:console():read_log()
        local ran = prelude.ran(log)
        t:assert_eq(ran[1], "hopeful.sh",
            "prelude ran the hook rather than refusing the boot: with no " ..
            "supplier at all the capability is settled, nothing provides " ..
            "it, and so it counts as achieved")
        t:assert(log:find("pt|hopeful|outcome=satisfied", 1, true),
            "the hook ran to completion")
    end)

test("one satisfied provider achieves the capability though another alternative declined",
    { spec = "prelude sched.achieved-needs-a-satisfied-provider" },
    function(t)
        -- `provides` is alternatives: the live-boot / disk-boot shape,
        -- where one of them is the one for this machine and the other
        -- steps aside.
        local vm = provium:vm("cap-alt-one", "prelude")
        vm:boot({
            files = prelude.files({
                hooks = {
                    ["alt-one"] = { provides = { "root-source" } },
                    ["alt-two"] = { provides = { "root-source" } },
                    consumer = { requires = { "root-source" } },
                },
                order = { "alt-one", "alt-two", "consumer" },
                keep = { "pt-mount-root.sh" },
            }),
            kernel_cmdline_append = "pt.alt-one=decline",
        })

        local log = vm:console():read_log()
        t:assert(log:find("pt|alt-one|outcome=declined", 1, true),
            "the first alternative declined")
        t:assert(log:find("pt|consumer|outcome=satisfied", 1, true),
            "and the requirer still ran: one satisfied provider is enough " ..
            "to achieve a capability supplied as alternatives")
        t:assert_eq(table.concat(prelude.ran(log), ","),
            "alt-one.sh,alt-two.sh,consumer.sh,pt-mount-root.sh",
            "and it ran on the same pass, needing no second one")
    end)

test("every alternative declining leaves the capability settled but never achieved",
    { spec = { "prelude sched.all-providers-declined-is-never-achieved",
               "prelude sched.stuck-diagnosis-names-each-hook" } },
    function(t)
        -- The contrast with the next test: identical graph, identical
        -- outcomes, `provides` instead of `contributes`. Nobody was
        -- willing to be the one, so the requirer can never become ready
        -- and prelude refuses the boot — even though a root IS mounted by
        -- the kept hook, so the halt can only have come from the
        -- scheduler.
        local vm = provium:vm("cap-alt-none", "prelude")
        local err = prelude.boot_halts(t, vm, {
            files = prelude.files({
                hooks = {
                    ["alt-one"] = { provides = { "root-source" } },
                    ["alt-two"] = { provides = { "root-source" } },
                    consumer = { requires = { "root-source" } },
                },
                order = { "alt-one", "alt-two", "consumer" },
                keep = { "pt-mount-root.sh" },
            }),
            kernel_cmdline_append = "pt.alt-one=decline pt.alt-two=decline",
        })

        t:assert(err:find("hooks cannot proceed", 1, true),
            "prelude ended the boot in the scheduler: " .. err:sub(-400))
        local why = prelude.stuck_reasons(err)["consumer.sh"]
        t:assert(why, "the diagnosis names the hook that could not run")
        t:assert(why:find("root-source", 1, true),
            "naming the capability it was waiting for, got: " .. tostring(why))
        t:assert(why:find("every provider declined it", 1, true),
            "and saying every provider declined it, got: " .. tostring(why))
        t:assert(err:find("pt|alt-one|pass=1|", 1, true),
            "the console text reaches back to the first pass, so what is " ..
            "absent from it is absent because it never happened")
        t:assert(not err:find("pt|consumer|", 1, true),
            "the requirer never ran at all: settled is not achieved")
    end)

test("every contributor declining still completes the conjunction",
    { spec = "prelude sched.declining-contributor-still-completes" },
    function(t)
        -- The same graph as the test above with `contributes` in place of
        -- `provides`, and the boot succeeds. A contribution is a
        -- conjunction, so "nothing needed doing here" is a way of being
        -- done rather than an abstention.
        local vm = provium:vm("cap-contrib-none", "prelude")
        vm:boot({
            files = prelude.files({
                hooks = {
                    ["part-one"] = { contributes = { "assembly" } },
                    ["part-two"] = { contributes = { "assembly" } },
                    consumer = { requires = { "assembly" } },
                },
                order = { "part-one", "part-two", "consumer" },
                keep = { "pt-mount-root.sh" },
            }),
            kernel_cmdline_append = "pt.part-one=decline pt.part-two=decline",
        })

        local log = vm:console():read_log()
        t:assert(log:find("pt|part-one|outcome=declined", 1, true)
            and log:find("pt|part-two|outcome=declined", 1, true),
            "both contributors declined")
        t:assert(log:find("pt|consumer|outcome=satisfied", 1, true),
            "and the requirer ran anyway: a declining contributor still " ..
            "completes its part of the conjunction")
        t:assert(log:find("ran 4 hook invocation(s)", 1, true),
            "the boot ran every hook once and handed off")
    end)
