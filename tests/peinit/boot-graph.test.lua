-- peinit TRM §2.5 — building and validating the Phase 2 boot graph: what
-- gets into it, and what the two structural faults do to the services
-- that carry them.
--
-- One VM, one seed, four independent shapes in it. A boot graph is built
-- once per boot from every key under `Machine\System\Services`, so the
-- only way to test four graph shapes in four boots would be to boot four
-- times — and nothing here needs that, because the shapes cannot reach
-- each other. `pt-g-*` is a closure with no triggers below the root,
-- `pt-cyc-*` is a three-service cycle, `pt-cf-*` is a conflicting pair
-- and `pt-vw-*` is an Alive-readiness service with a dependent that
-- requires it. No name appears in two shapes, so no shape's blocking
-- propagates into another.
--
-- Two deliberate omissions in the definitions. None of these services is
-- `ErrorControl=Critical`: a cycle or a conflict involving a Critical
-- service downgrades the whole boot to Safe mode and then does NOT mark
-- the offenders Failed, which is a different claim (see boot-modes) and
-- would hide the one being tested here. And the ones that must reach a
-- terminal state are Oneshots running /bin/true, so the boot set stops
-- moving quickly and `wait_until_quiet` below is a short wait.
--
-- The oracle is `svctl status` rather than the console. Every claim here
-- is about the state a service ended in and the cause peinit recorded
-- for it, and the console says only that a service started.

local peinit = require("helpers.peinit")
peinit.claim(1)

local BOOT = { name = "Triggers", type = "multi", data = { "boot" } }

local function svc(name, image, args, extra)
    local values = {
        { name = "ImagePath", type = "sz", data = image },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
    }
    if args then values[#values + 1] = { name = "Arguments", type = "multi", data = args } end
    for _, v in ipairs(extra or {}) do values[#values + 1] = v end
    return { path = [[Machine\System\Services\]] .. name, values = values }
end

--- A service that runs, succeeds and is gone: enough to be a graph node
--- and nothing more.
local function oneshot(name, extra)
    local e = { { name = "Type", type = "dword", data = 1 } }
    for _, v in ipairs(extra or {}) do e[#e + 1] = v end
    return svc(name, "/bin/true", nil, e)
end

--- A service that stays: for the cases where the claim is about a
--- service still being there when something else is looked at.
local function daemon(name, extra)
    return svc(name, "/bin/sleep", { "3600" }, extra)
end

local function multi(name, values)
    return { name = name, type = "multi", data = values }
end

local vm = peinit.boot({
    name = "graph",
    files = peinit.seed("zz-pt-graph", {
        { path = [[Machine\System]] },
        { path = [[Machine\System\Services]] },

        -- The closure. Only the root carries a trigger; everything else
        -- is reached, or is not.
        oneshot("pt-g-root", { BOOT,
            multi("Requires", { "pt-g-req" }),
            multi("BindsTo", { "pt-g-bind" }),
            multi("Wants", { "pt-g-want", "pt-g-off" }) }),
        oneshot("pt-g-req", { multi("Requires", { "pt-g-deep" }) }),
        oneshot("pt-g-deep"),
        oneshot("pt-g-bind"),
        oneshot("pt-g-want"),
        oneshot("pt-g-off", { { name = "Disabled", type = "dword", data = 1 } }),
        oneshot("pt-g-outside"),

        -- Three services, each requiring the next.
        oneshot("pt-cyc-a", { BOOT, multi("Requires", { "pt-cyc-b" }) }),
        oneshot("pt-cyc-b", { BOOT, multi("Requires", { "pt-cyc-c" }) }),
        oneshot("pt-cyc-c", { BOOT, multi("Requires", { "pt-cyc-a" }) }),

        -- A conflict declared from one side only; it is symmetric.
        daemon("pt-cf-a", { BOOT, multi("Conflicts", { "pt-cf-b" }) }),
        daemon("pt-cf-b", { BOOT }),

        -- The validation warning: Alive readiness under a hard dependent.
        daemon("pt-vw-alive", { BOOT }),
        oneshot("pt-vw-dep", { BOOT, multi("Requires", { "pt-vw-alive" }) }),
    }),
})

local function status(service)
    return vm:run("svctl --json status " .. service).stdout
end

--- The cause peinit last recorded for a service, or nil if it has never
--- transitioned — which for a service in a settled boot means peinit
--- never started it.
local function cause(service)
    return status(service):match('"cause":"([^"]+)"')
end

local function state(service)
    return status(service):match('"state":"([^"]+)"')
end

--- Has peinit finished with this service? A recorded cause and a state
--- it will not leave on its own.
local function settled(service)
    local text = status(service)
    local at_rest = text:match('"state":"([^"]+)"')
    return text:match('"cause":"[^"]+"') ~= nil
        and at_rest ~= "starting" and at_rest ~= "backoff"
        and at_rest ~= "stopping" and at_rest ~= "reloading"
end

-- The barrier every test below depends on. `peinit.boot` returns at
-- "phase2 boot complete", which is printed when the plan has been
-- DISPATCHED — every start is still ahead of it — so a status read at
-- that mark races the boot.
--
-- Named services rather than the whole table, deliberately. Waiting for
-- `svctl list` to show nothing moving waits for the image's services
-- too, and one of those can sit in Starting for tens of seconds on a
-- loaded host, which turned this barrier into the file's flakiest line.
-- Nothing here is a claim about the image's own graph: the services
-- listed are exactly the ones this file asserts on that peinit is
-- expected to finish with. The two it must NOT touch are excluded,
-- because "has not been started yet" and "will never be started" look
-- identical, and their turn to be asserted comes once these are done.
local EXPECTED = {
    "pt-g-root", "pt-g-req", "pt-g-deep", "pt-g-bind", "pt-g-want",
    "pt-cyc-a", "pt-cyc-b", "pt-cyc-c",
    "pt-cf-a", "pt-cf-b",
    "pt-vw-alive", "pt-vw-dep",
}
local reached_rest = false
for _ = 1, 400 do
    local moving = false
    for _, service in ipairs(EXPECTED) do
        if not settled(service) then moving = true end
    end
    if not moving then
        reached_rest = true
        break
    end
    vm:clock():sleep("250ms")
end
assert(reached_rest, "the services this file plans against never came to rest")

test("the boot graph is the roots plus the transitive closure of their dependencies",
    { spec = "peinit *phase2.the-boot-graph-is-the-roots-transitive-closure" },
    function(t)
        -- `pt-g-root` is the only member of this shape carrying a boot
        -- trigger, so everything else that ran was reached through it.
        t:assert(cause("pt-g-root"), "the root ran")
        t:assert(cause("pt-g-req"), "its Requires target came in")
        t:assert(cause("pt-g-bind"), "its BindsTo target came in")
        t:assert(cause("pt-g-want"), "its existing, non-disabled Wants target came in")

        -- Transitive, not one hop: pt-g-deep is required by pt-g-req and
        -- is named nowhere else.
        t:assert(cause("pt-g-deep"),
            "and so did the service required by the service required by the root")

        -- The closure is a closure, not the whole registry. A service
        -- nothing triggers and nothing names is loaded and left alone;
        -- a Wants target that is disabled is not a member.
        t:assert(not cause("pt-g-outside"),
            "a service outside the closure was not started: " .. tostring(state("pt-g-outside")))
        t:assert(not cause("pt-g-off"),
            "and neither was the disabled service the root wanted")
    end)

test("Requires and BindsTo pull in a target that has no boot trigger of its own",
    { spec = "peinit *phase2.a-hard-dependency-pulls-in-an-untriggered-target" },
    function(t)
        -- Neither target is a root candidate: no Triggers value at all.
        -- Both ran anyway, because a hard dependency is a claim that the
        -- dependent cannot run without them.
        for _, target in ipairs({ "pt-g-req", "pt-g-bind" }) do
            local listing = vm:run([[reg get 'Machine\System\Services\]] .. target .. [[' Triggers]])
            t:assert(not listing:ok(),
                target .. " carries no Triggers value: " .. listing.stdout .. listing.stderr)
            t:assert(cause(target), target .. " was started anyway")
        end

        -- And they were started as dependencies rather than as roots,
        -- which is what makes this different from having been triggered:
        -- the untriggered target ran and the untriggered non-target did
        -- not, in the same boot.
        t:assert(not cause("pt-g-outside"),
            "while the untriggered service nothing depends on stayed put")
    end)

test("a cycle fails every service in it",
    { spec = "peinit *phase2.a-cycle-fails-every-service-in-it" },
    function(t)
        -- Every one of the three, not just the one the walk happened to
        -- close the loop on. None is Critical, so the boot stays in Full
        -- mode and the cycle members are marked rather than discarded.
        for _, service in ipairs({ "pt-cyc-a", "pt-cyc-b", "pt-cyc-c" }) do
            t:assert_eq(state(service), "failed", service .. " is Failed")
            t:assert_eq(cause(service), "cycle_detected",
                service .. " was failed for the cycle rather than for its neighbour's failure")
        end

        -- Failing the cycle is not failing the boot.
        t:assert(vm:console():read_log():find("peinit: phase2 boot complete", 1, true),
            "and the boot completed around them")
    end)

test("an unresolvable conflict fails both services",
    { spec = "peinit *phase2.a-conflict-fails-both-services" },
    function(t)
        -- The conflict is declared on pt-cf-a only. Both are boot
        -- triggered and both are in the graph, so there is no way to
        -- honour it and start either: both fail.
        for _, service in ipairs({ "pt-cf-a", "pt-cf-b" }) do
            t:assert_eq(state(service), "failed", service .. " is Failed")
            t:assert_eq(cause(service), "validation_error",
                service .. " was failed by graph validation")
        end
        t:assert(vm:console():read_log():find("peinit: phase2 boot complete", 1, true),
            "and the boot completed around them")
    end)

test("a validation warning does not prevent boot",
    { spec = "peinit *phase2.a-validation-warning-does-not-prevent-boot" },
    function(t)
        -- The warned-about shape: `pt-vw-alive` reports readiness by
        -- being alive rather than by notifying, and `pt-vw-dep` requires
        -- it — so the dependent is released on a weaker promise than it
        -- asked for. That is worth telling an operator and is not worth
        -- refusing to boot over.
        t:assert_eq(state("pt-vw-alive"), "active",
            "the Alive-readiness service is running")
        t:assert(cause("pt-vw-dep"),
            "its hard dependent was released and ran: " .. tostring(state("pt-vw-dep")))
        t:assert(vm:console():read_log():find("peinit: phase2 boot complete", 1, true),
            "and the boot completed")

        -- Neither service was failed for it, which is the whole
        -- difference between a warning and a finding: the two shapes
        -- that ARE findings, in the two tests above, both end in Failed.
        t:assert(state("pt-vw-dep") ~= "failed",
            "the dependent was not failed for depending on an Alive service")
    end)

test("a validation warning is logged",
    {
        spec = "peinit *phase2.a-validation-warning-does-not-prevent-boot",
        -- PEI-815: the sentence this anchor names says a warning is
        -- "logged and does not prevent boot". The second half holds; the
        -- first does not, because Phase 2 never runs the validator that
        -- produces warnings at all. `build_phase2_boot_graph`
        -- (src/boot/phase2/graph/build.rs) walks the closure and blocks
        -- what is unstartable; `validate_service_graph`
        -- (src/service/graph/validate.rs:24), which is what produces
        -- `AliveReadinessWithHardDependents` at validate.rs:222, has
        -- exactly one non-test caller — reload-config, at
        -- src/control/reload_config/transaction.rs:38. The audit encoder
        -- even takes a `phase` argument
        -- (src/kmes/audit/graph.rs:12) and the only value ever passed is
        -- "reload_config".
        tags = { "known-bug" },
    },
    function(t)
        -- eventd is where a boot-time finding is durable; peinit buffers
        -- what it emits before eventd exists and flushes it once it does.
        local up = false
        for _ = 1, 60 do
            if vm:run("svctl status eventd").stdout:find("eventd: active", 1, true) then
                up = true
                break
            end
            vm:clock():sleep("1s")
        end
        t:assert(up, "eventd is up to be asked")

        local events = ""
        for _ = 1, 20 do
            events = vm:run(
                "evctl 'EVENTS graph.validation_warning SINCE 1h ago TAKE 50' --format jsonl"
            ).stdout
            if events:find("pt-vw-alive", 1, true) then break end
            vm:clock():sleep("1s")
        end

        -- Either record would do: the audit trail is where reload-config
        -- puts the same warning, and the console is where peinit puts
        -- everything else it wants an operator to see at boot. The
        -- console is searched for the warning's own wording rather than
        -- for the service's name, which is on it either way in the
        -- ordinary "service pt-vw-alive started" line.
        local console = vm:console():read_log()
        t:assert(events:find("pt-vw-alive", 1, true)
            or console:find("alive_readiness", 1, true)
            or console:find("Alive readiness", 1, true),
            "the boot recorded the Alive-readiness warning somewhere: events=" .. events)
    end)
