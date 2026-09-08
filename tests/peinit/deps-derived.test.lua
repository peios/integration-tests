-- peinit TRM §7.6 — derived dependencies: Provides names a role, and
-- peinit derives the edge a service's Identity implies.
--
-- A derived edge is invisible from the outside. `svctl status` does not
-- render a service's dependencies at all, so nothing here can read one
-- off directly, and every test below reaches it through a *consequence*
-- instead. Two consequences carry the file:
--
--   * `svctl reload-config` reports an Alive-readiness warning naming
--     each service that depends *hard* on the Alive-readiness one. A
--     provider of `authn` declaring Alive readiness therefore
--     enumerates, in the reload output, exactly the set of services
--     peinit derived an edge to. That is the only enumeration of a
--     dependency set a guest can obtain.
--
--   * a start pulls its closure in. Starting a service whose only edge
--     to a provider is the derived one starts the provider, and the
--     provider going Active is the edge.
--
-- The role that carries the mechanism is `authn`, and the image's
-- authority is authd. Staging a *second* provider is what makes the
-- derivation observable: authd is already Active by the time any test
-- runs, so an edge to it would never have to do anything.

-- Every machine here is booted with 800 MiB rather than the helper's
-- default gigabyte, and the claim says so. A booted guest uses about
-- 300 MiB — the squashfs is read off the medium rather than held in RAM
-- — so the assertions are identical at either size, and a file that
-- claims 1.8 GiB instead of 2.2 GiB still fits a pool several of these
-- files are queueing against.

local peinit = require("helpers.peinit")
peinit.claim(2, { memory_mib = 800 })

local BOOT = { name = "Triggers", type = "multi", data = { "boot" } }
local LOCAL_SERVICE = { name = "Identity", type = "sz", data = "LocalService" }

local function service(name, image, args, extra)
    local values = {
        { name = "ImagePath", type = "sz", data = image },
        { name = "Readiness", type = "dword", data = 1 },
    }
    if args then values[#values + 1] = { name = "Arguments", type = "multi", data = args } end
    for _, value in ipairs(extra or {}) do values[#values + 1] = value end
    return { path = [[Machine\System\Services\]] .. name, values = values }
end

local function oneshot(name, extra)
    local values = { { name = "Type", type = "dword", data = 1 } }
    for _, value in ipairs(extra or {}) do values[#values + 1] = value end
    return service(name, "/bin/true", nil, values)
end

local function daemon(name, extra)
    return service(name, "/bin/sleep", { "3600" }, extra)
end

local function requires(...) return { name = "Requires", type = "multi", data = { ... } } end
local function provides(...) return { name = "Provides", type = "multi", data = { ... } } end

local SEED = {
    { path = [[Machine\System]] },
    { path = [[Machine\System\Services]] },

    -- A second provider of the authn role, with no boot trigger and
    -- Alive readiness. Its dependents are what the reload warning
    -- enumerates.
    daemon("pt-d-authority", { provides("authn"),
        { name = "Identity", type = "sz", data = "SYSTEM" } }),

    -- Needs the authority because its own identity is not SYSTEM.
    oneshot("pt-d-token", { LOCAL_SERVICE }),

    -- Needs it because its hooks do, even though the service itself is
    -- SYSTEM: the hook materialises a token of its own.
    oneshot("pt-d-hooked", {
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "HookIdentity", type = "sz", data = "LocalService" },
        { name = "ExecStartPre", type = "multi", data = { "/bin/true" } },
    }),

    -- Declares a hook identity and has no hooks, so it asks for
    -- nothing and must be ordered against nothing.
    oneshot("pt-d-idle", {
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "HookIdentity", type = "sz", data = "LocalService" },
    }),

    -- A dependency on the role by name, satisfied by whoever provides
    -- it. Virtual and real names share one namespace.
    oneshot("pt-d-needsauthn", {
        { name = "Identity", type = "sz", data = "SYSTEM" }, requires("authn") }),

    -- A real service whose name is also a role somebody provides. The
    -- real one wins; which of the two gets started is the evidence.
    daemon("pt-d-role", { { name = "Identity", type = "sz", data = "SYSTEM" } }),
    daemon("pt-d-provider", { provides("pt-d-role"),
        { name = "Identity", type = "sz", data = "SYSTEM" } }),
    oneshot("pt-d-namewins", {
        { name = "Identity", type = "sz", data = "SYSTEM" }, requires("pt-d-role") }),

    -- The other side of a dependency naming a role, in each of the
    -- three fields that are rewritten.
    oneshot("pt-d-wantsrole", {
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Wants", type = "multi", data = { "network:pt-nope" } } }),
    oneshot("pt-d-bindsrole", {
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "BindsTo", type = "multi", data = { "network:pt-nope" } } }),
    oneshot("pt-d-reqrole", {
        { name = "Identity", type = "sz", data = "SYSTEM" },
        requires("network:pt-nope") }),
}

local vm = peinit.boot({ memory = "800M", name = "derived",
    files = peinit.seed("zz-pt-derived", SEED) })

--- What the boot made of the staged authority, sampled once.
---
--- Sampled at file scope because the tests below start services by
--- hand: a later reading of "did the boot plan this" would be answered
--- by a start some earlier test performed. `current_operation` is the
--- indicator rather than the state, because it is set the moment the
--- Phase 2 plan is dispatched — which is the mark `peinit.boot` waits
--- for — while a service's own start completes some time after it. A
--- service the boot plan never contained has no operation at all.
local AUTHORITY_AT_BOOT = json.decode(
    vm:run("svctl --json status pt-d-authority").stdout)

local function status(machine, name)
    return json.decode(machine:run("svctl --json status " .. name).stdout)
end

--- The names peinit lists as `service`'s hard dependents, as a string.
---
--- This is the enumeration the file rests on: peinit warns that a
--- service using Alive readiness has hard dependents, and lists them
--- after the colon. Only the list is returned — the warning's own
--- preamble names the subject, and matching against the whole sentence
--- would find the subject in its own dependent list.
local function hard_dependents_of(machine, name)
    local reload = machine:run("svctl --json reload-config")
    reload:assert_ok()
    local out = json.decode(reload.stdout)
    local prefix = "service " .. name .. " uses Alive readiness while hard dependents " ..
        "require readiness: "
    for _, warning in ipairs(out.warnings or {}) do
        if warning:sub(1, #prefix) == prefix then
            return warning:sub(#prefix + 1)
        end
    end
    return nil, reload.stdout
end

test("a service that needs the authority gains a Requires on each provider of authn",
    {
        spec = {
            "peinit *derived.a-service-needing-the-authority-gains-a-requires-on-each-authn-provider",
            "peinit *derived.hooks-running-as-a-non-system-identity-also-need-the-edge",
            "peinit *derived.a-provider-never-gains-a-dependency-on-its-own-role",
        },
    },
    function(t)
        local dependents, raw = hard_dependents_of(vm, "pt-d-authority")
        t:assert(dependents,
            "peinit knows something depends hard on the staged authority: " .. tostring(raw))
        local warning = dependents

        -- Identity, not declaration: nothing in the seed names
        -- pt-d-authority. The edge exists because these services cannot
        -- launch without an authority.
        t:assert(warning:find("pt-d-token", 1, true),
            "a non-SYSTEM identity gained the edge: " .. warning)
        t:assert(warning:find("pt-d-hooked", 1, true),
            "and so did a SYSTEM service whose hooks run as something else: " .. warning)
        -- The image's own LocalService definitions declare no such
        -- ordering either, and gained it the same way.
        t:assert(warning:find("timed", 1, true) or warning:find("resolvd", 1, true),
            "as did the shipped definitions that started this: " .. warning)

        -- A hook identity with no hooks asks for nothing.
        t:assert(not warning:find("pt-d-idle", 1, true),
            "a HookIdentity with no hooks gained nothing: " .. warning)
        -- And a provider does not require itself: a service that
        -- requires itself never starts.
        t:assert(not warning:find("pt-d-authority", 1, true),
            "the provider is not among its own dependents: " .. warning)
    end)

test("every provider of the role becomes its own Requires, so a start is ordered after all of them",
    { spec = "peinit *derived.every-provider-of-the-role-becomes-its-own-requires" },
    function(t)
        -- pt-d-authority has no trigger and nothing declares an edge to
        -- it. Starting a service whose Identity needs an authority has
        -- to pull it in, alongside authd, because each provider becomes
        -- its own edge.
        t:assert_eq(status(vm, "pt-d-authority").state, "inactive",
            "the staged provider is not running yet")
        vm:run("svctl start pt-d-token"):assert_ok()

        wait_until(function()
            return status(vm, "pt-d-authority").state == "active"
        end, { timeout = 60, interval = 0.5,
               desc = "the second authn provider to be started as a dependency" })
        t:assert_eq(status(vm, "pt-d-authority").cause, "dependency_start",
            "and it was started because something depended on it")
    end)

test("a dependency naming a role is satisfied by whoever provides it",
    { spec = "peinit *derived.a-real-service-name-and-a-role-share-one-namespace" },
    function(t)
        -- No service is called `authn`. authd declares it, and that is
        -- what makes the dependency resolvable at all: if virtual and
        -- real names did not share a namespace this would be a missing
        -- hard dependency.
        t:assert(vm:run([[reg get 'Machine\System\Services\authn' ImagePath]]).exit_code ~= 0,
            "there is no service literally called authn")
        vm:run("svctl start pt-d-needsauthn"):assert_ok()
        t:assert_eq(status(vm, "pt-d-needsauthn").cause, "clean_exit",
            "the dependency on the role resolved and the service ran")
    end)

test("a real service name wins over a role of the same name",
    { spec = "peinit *derived.a-real-service-name-wins-over-a-role-of-the-same-name" },
    function(t)
        -- pt-d-role is a service. pt-d-provider declares
        -- `Provides = ["pt-d-role"]`. A dependent naming pt-d-role must
        -- get the service, so starting it starts pt-d-role and leaves
        -- pt-d-provider alone.
        vm:run("svctl start pt-d-namewins"):assert_ok()
        wait_until(function()
            return status(vm, "pt-d-role").state == "active"
        end, { timeout = 60, interval = 0.5, desc = "the real service to be started" })
        t:assert_eq(status(vm, "pt-d-provider").state, "inactive",
            "the service merely providing that name was not started")
    end)

test("Requires, Wants and BindsTo all resolve a role on the other side of the dependency",
    {
        spec = {
            "peinit *derived.requires-wants-and-bindsto-are-all-rewritten",
            "peinit *derived.a-declared-role-reference-is-rewritten-at-boot-and-on-every-reload",
        },
    },
    function(t)
        -- Each of the three names `network:pt-nope`, which netd fills.
        -- Rewritten, all three become a level dependency on netd and
        -- are held, because netd never publishes that level. Left as
        -- written, the three would behave differently from each other
        -- and none of them would wait: a missing Wants target is
        -- dropped and the service starts, and a missing Requires or
        -- BindsTo target fails it.
        for _, name in ipairs({ "pt-d-reqrole", "pt-d-wantsrole", "pt-d-bindsrole" }) do
            vm:run("svctl start " .. name .. " --no-wait"):assert_ok()
        end
        vm:run("sleep 4")
        for _, name in ipairs({ "pt-d-reqrole", "pt-d-wantsrole", "pt-d-bindsrole" }) do
            local entry = status(vm, name)
            t:assert_eq(entry.state, "inactive",
                name .. " is held rather than started or failed")
            t:assert(entry.current_operation,
                name .. "'s start operation is still open: " ..
                vm:run("svctl --json status " .. name).stdout)
            t:assert(entry.cause ~= "dependency_failure",
                name .. " was not blocked on a missing service called `network`")
        end
    end)

test("a level on a Provides entry is rejected rather than ignored",
    { spec = "peinit *derived.a-level-on-a-provides-entry-is-rejected" },
    function(t)
        -- A role is not a service, so there would be nothing for the
        -- level to qualify. `Provides` takes the service-name grammar,
        -- and a colon is not in it.
        vm:run([[reg set 'Machine\System\Services\pt-d-idle' Provides 'multi:pt-d-thing:ready']])
            :assert_ok()
        local reload = vm:run("svctl --json reload-config")
        t:assert(reload.exit_code ~= 0 or reload.stdout:find("error", 1, true),
            "the definition was rejected: rc=" .. reload.exit_code ..
            " out=" .. reload.stdout .. " err=" .. reload.stderr)
        vm:run([[reg set 'Machine\System\Services\pt-d-idle' Provides 'multi:']])
        vm:run([[reg del 'Machine\System\Services\pt-d-idle' Provides]])
    end)

test("the derived edge is an ordinary Requires everywhere the graph is built",
    {
        spec = "peinit *derived.the-derived-edge-behaves-exactly-like-a-declared-requires",
        -- PEI-829: run_phase2_boot_with_retained (peinit/src/boot/
        -- phase2/coordinator.rs:104) builds the boot plan from the raw
        -- registry definitions, and only afterwards builds the service
        -- table from role-synthesised ones. The derived edge therefore
        -- exists everywhere except in the boot plan, so a provider that
        -- is not itself boot-triggered is never pulled into the boot
        -- graph by the services that need it.
        tags = { "known-bug" },
    },
    function(t)
        -- A declared `Requires` on a triggerless service pulls it into
        -- the boot closure and starts it. The image's own timed,
        -- resolvd and trustd are boot-triggered and non-SYSTEM, so the
        -- derived edge to pt-d-authority should have done the same.
        --
        -- This test reads the boot's own record, so it is unaffected by
        -- the on-demand start an earlier test did.
        t:assert(AUTHORITY_AT_BOOT.current_operation or AUTHORITY_AT_BOOT.cause,
            "the provider was pulled into the boot graph by the services that need it, " ..
            "and so has a boot operation of its own: " ..
            (AUTHORITY_AT_BOOT.current_operation and "yes" or "none"))
    end)

test("nothing is derived when no service fills the role, and the reload still succeeds",
    {
        spec = {
            "peinit *derived.nothing-is-derived-when-no-service-fills-the-role",
            "peinit *derived.an-unfilled-role-is-a-warning-and-the-reload-still-succeeds",
            "peinit *derived.the-launch-that-cannot-get-a-token-is-what-fails",
        },
    },
    function(t)
        -- Its own machine, because it takes the authority away.
        local other = peinit.boot({
            memory = "800M",
            name = "noauthority",
            files = peinit.seed("zz-pt-noauth", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Services]] },
                oneshot("pt-d-orphan", { LOCAL_SERVICE }),
            }),
        })

        -- Take the role away rather than the service: the image's
        -- eventd and lpsd *declare* `Requires = ["authd"]`, so deleting
        -- authd's key would be a missing hard dependency for reasons
        -- that have nothing to do with roles. Dropping only `Provides`
        -- leaves every declared edge intact and leaves `authn` filled
        -- by nobody, which is the case under test.
        other:run([[reg del 'Machine\System\Services\authd' Provides]]):assert_ok()
        local reload = other:run("svctl --json reload-config")
        reload:assert_ok()
        local out = json.decode(reload.stdout)
        t:assert_eq(out.status, "ok",
            "the reload succeeded: " .. reload.stdout)

        -- A warning naming the services that cannot start, rather than
        -- an invented edge to a name nothing answers to. An edge would
        -- have been a missing hard dependency, and that rejects the
        -- whole transaction.
        local unfilled
        for _, warning in ipairs(out.warnings or {}) do
            if warning:find("authn", 1, true) then unfilled = warning end
        end
        t:assert(unfilled, "the unfilled role was warned about: " .. reload.stdout)
        t:assert(unfilled:find("pt-d-orphan", 1, true),
            "naming a service that cannot start: " .. unfilled)

        -- And the failure lands where the fault actually is: at the
        -- launch that asked for a token and could not have one.
        other:run("svctl stop authd")
        local start = other:run("svctl start pt-d-orphan")
        t:assert(start.exit_code ~= 0
            or status(other, "pt-d-orphan").state == "failed"
            or status(other, "pt-d-orphan").state == "backoff",
            "the launch failed rather than the graph: rc=" .. start.exit_code ..
            " out=" .. start.stdout .. " status=" ..
            other:run("svctl --json status pt-d-orphan").stdout)
    end)
