-- peinit TRM §2.5 — the deadline half of deferred starts: what bounds the
-- wait, what an unusable `SettleTimeout` does, and what a deferred
-- service is NOT.
--
-- Three boots, one per test, because each needs a different
-- `Machine\System\Boot` and that key is read once at the top of Phase 2.
-- They run one at a time — the file claims a single VM and each test
-- scope is torn down at the end of the test — so the file's peak is one.
--
-- `login-console` is disabled in the two boots that reach a Phase 2. It
-- is the image's own `boot:settled` service, it takes /dev/console when
-- it starts, and peinit's console messages stop appearing there once it
-- has — including the deadline message the first test asserts on.
--
-- The settling half, where the plan comes to rest and the clock never
-- matters, is boot-settle.test.lua.

local peinit = require("helpers.peinit")
peinit.claim(1)

local BOOT = { name = "Triggers", type = "multi", data = { "boot" } }
local SETTLED = { name = "Triggers", type = "multi", data = { "boot:settled" } }
local ONESHOT = { name = "Type", type = "dword", data = 1 }
local DISABLE_LOGIN = {
    path = [[Machine\System\Services\login-console]],
    values = { { name = "Disabled", type = "dword", data = 1 } },
}

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

local function oneshot(name, extra)
    local e = { ONESHOT }
    for _, v in ipairs(extra or {}) do e[#e + 1] = v end
    return svc(name, "/bin/true", nil, e)
end

local function status(vm, service)
    return vm:run("svctl --json status " .. service).stdout
end

local function state(vm, service)
    return status(vm, service):match('"state":"([^"]+)"')
end

local function cause(vm, service)
    return status(vm, service):match('"cause":"([^"]+)"')
end

--- Poll until `service` has a recorded cause, meaning peinit started it.
local function wait_started(vm, service, ticks)
    for _ = 1, ticks or 200 do
        if cause(vm, service) then return true end
        vm:clock():sleep("250ms")
    end
    return false
end

--- Poll until `service` has been started AND has come to rest.
---
--- Not the same wait as `wait_started`: a service acquires its cause on
--- entering Starting, so a status read taken the moment a cause appears
--- can still catch it mid-start. Anything asserting the state a service
--- ENDED in has to wait for the state to stop being one the service
--- leaves on its own.
local function wait_settled(vm, service, ticks)
    for _ = 1, ticks or 200 do
        local at_rest = state(vm, service)
        if cause(vm, service) and at_rest ~= "starting" and at_rest ~= "backoff"
            and at_rest ~= "stopping" and at_rest ~= "reloading" then
            return true
        end
        vm:clock():sleep("250ms")
    end
    return false
end

test("a service in Backoff is not settled, and the deadline bounds the wait anyway",
    {
        spec = {
            "peinit *settle.backoff-is-not-settled",
            "peinit *settle.settletimeout-bounds-the-wait",
            "peinit *settle.the-dispatch-says-whether-the-deadline-expired",
        },
    },
    function(t)
        -- `pt-b-flap` exits non-zero immediately and is asked to restart
        -- always, with two minutes between attempts. So it sits in
        -- Backoff for the whole test: a state it WILL leave on its own,
        -- which is exactly why it does not count as settled.
        local vm = peinit.boot({
            name = "backoff",
            files = peinit.seed("zz-pt-backoff", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Boot]], values = {
                    { name = "SettleTimeout", type = "dword", data = 6 },
                } },
                { path = [[Machine\System\Services]] },
                DISABLE_LOGIN,
                svc("pt-b-flap", "/bin/false", nil, { BOOT,
                    { name = "RestartPolicy", type = "dword", data = 2 },
                    { name = "RestartDelay", type = "dword", data = 120 } }),
                oneshot("pt-b-defer", { SETTLED }),
            }),
        })

        local backoff = false
        for _ = 1, 80 do
            if state(vm, "pt-b-flap") == "backoff" then
                backoff = true
                break
            end
            vm:clock():sleep("250ms")
        end
        t:assert(backoff, "the flapping service reached Backoff: " .. status(vm, "pt-b-flap"))

        -- The deadline is what ends the wait, and peinit says so. That
        -- flag is the whole point: a prompt started on a timeout may
        -- still be written over by whatever is still moving.
        t:assert(wait_started(vm, "pt-b-defer"),
            "the deferred service started anyway: " .. status(vm, "pt-b-defer"))
        t:assert(vm:console():read_log():find("boot did not settle in time", 1, true),
            "and the dispatch reported that the deadline expired rather than the set settling: "
            .. vm:console():read_log():sub(-800))

        -- Still in Backoff after the deferred start, so the wait cannot
        -- have ended by the set settling: it was bounded by the clock.
        t:assert_eq(state(vm, "pt-b-flap"), "backoff",
            "the boot set was still moving when the deferred service was started")
    end)

test("a SettleTimeout that cannot be decoded sends the boot to recovery",
    { spec = "peinit *settle.an-invalid-settletimeout-is-recovery" },
    function(t)
        -- A string where a dword belongs. The chapter names a type
        -- mismatch and a bad length; both arrive at the same decoder, and
        -- a type mismatch is the one a seed file can express.
        local vm = peinit.boot({
            name = "bad-settle",
            stage = false,
            files = peinit.seed("zz-pt-badsettle", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Boot]], values = {
                    { name = "SettleTimeout", type = "sz", data = "soon" },
                } },
            }),
        })
        vm:console():expect("peinit entering Recovery mode", peinit.STAGE_TIMEOUT)

        local log = vm:console():read_log()
        t:assert(log:find("SettleTimeout", 1, true),
            "peinit named the key it could not read: " .. log:sub(-800))
        t:assert(not log:find("peinit: phase2 boot complete", 1, true),
            "and Phase 2 never completed")
    end)

test("a SettleTimeout of zero is legal, and a deferred service is outside the boot plan",
    {
        spec = {
            "peinit *settle.a-settletimeout-of-zero-is-legal",
            "peinit *settle.a-deferred-service-is-outside-the-boot-plan",
        },
    },
    function(t)
        -- Zero means "start on the next turn, settled or not" — a legal
        -- setting rather than the invalid-configuration case above.
        --
        -- The deferred service is `ErrorControl=Critical` and is a
        -- Oneshot with no `RemainAfterExit`, so it ends Inactive, which
        -- does NOT satisfy dependents. A Critical service in the boot
        -- plan that never holds a satisfying state means the boot is
        -- never declared successful. This one is not in the plan, so the
        -- boot succeeds anyway — and the attempt counter, staged at 2,
        -- goes back to zero.
        local vm = peinit.boot({
            name = "zero-settle",
            files = peinit.merge(
                { [".peinit/boot-attempts"] = "2\n" },
                peinit.seed("zz-pt-zerosettle", {
                    { path = [[Machine\System]] },
                    { path = [[Machine\System\Boot]], values = {
                        { name = "SettleTimeout", type = "dword", data = 0 },
                        { name = "BootSuccessGrace", type = "dword", data = 3 },
                    } },
                    { path = [[Machine\System\Services]] },
                    DISABLE_LOGIN,
                    oneshot("pt-z-plan", { BOOT }),
                    oneshot("pt-z-defer", { SETTLED,
                        { name = "ErrorControl", type = "dword", data = 1 } }),
                })
            ),
        })

        -- Settled rather than merely started: the assertion below is
        -- about the state this service ENDS in, and a cause appears as
        -- soon as it enters Starting.
        t:assert(wait_settled(vm, "pt-z-defer"),
            "a timeout of zero still starts the deferred service, and it ran to rest: "
            .. status(vm, "pt-z-defer"))
        t:assert_eq(state(vm, "pt-z-defer"), "inactive",
            "which ran and ended in a state that does not satisfy dependents")

        local log = vm:console():read_log()
        t:assert(log:find("peinit: phase2 boot complete", 1, true),
            "zero is a legal setting, not invalid boot configuration")
        t:assert(not log:find("entering Recovery mode", 1, true),
            "so the boot did not go to recovery: " .. log:sub(-800))

        -- Not part of the plan: it was not started with it, and it is not
        -- counted towards boot success.
        local complete = log:find("peinit: phase2 boot complete", 1, true)
        local deferred = log:find("peinit: service pt-z-defer started", 1, true)
        t:assert(deferred and complete < deferred,
            "the deferred service was started after the plan, not as part of it")

        local counter
        for _ = 1, 80 do
            counter = vm:read_file("/.peinit/boot-attempts"):match("%d+")
            if counter == "0" then break end
            vm:clock():sleep("500ms")
        end
        t:assert_eq(counter, "0",
            "and the boot was declared successful despite a Critical deferred service "
            .. "sitting in a state that would have prevented it from inside the plan")
    end)
