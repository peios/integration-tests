-- Peinit TRM §4.6 — the ServiceSecurity descriptor: who may perform
-- runtime operations on a service through the control interface.
--
-- Everything here is checked from the caller's side, which is the only
-- side that exists: peinit evaluates the descriptor and answers, and the
-- answer is what `svctl` prints. The lever is that the descriptor lives
-- in the registry and is re-read on every change, so one booted machine
-- can be walked through every right in the table by writing a value and
-- issuing the six commands against it.
--
-- The agent runs as SYSTEM, so a descriptor naming SYSTEM is a descriptor
-- about this caller. Each test puts the value back when it is done,
-- because the tests share a machine.

local peinit = require("helpers.peinit")
peinit.claim(1)

-- A self-relative security descriptor, hex-encoded for `reg set`.
--
-- Built here rather than read from anywhere: `ServiceSecurity` is a
-- REG_BINARY value and there is no SDDL form of it in the registry, so a
-- test that wants to say "SYSTEM may only query" has to say it in bytes.
-- The layout is MS-DTYP's, which KACS uses verbatim (pkm/sd.h): a
-- twenty-byte header of revision, control and four offsets, then the
-- owner and group SIDs, then an ACL of allow-ACEs.
local function sid_bytes(authority, subs)
    local out = string.pack("BB", 1, #subs) .. string.pack(">I2>I4", 0, authority)
    for _, sub in ipairs(subs) do out = out .. string.pack("<I4", sub) end
    return out
end

local SYSTEM_SID = sid_bytes(5, { 18 })

local function descriptor_hex(mask)
    local ace = string.pack("<BBI2I4", 0, 0, 8 + #SYSTEM_SID, mask) .. SYSTEM_SID
    local acl = string.pack("<BBI2I2I2", 2, 0, 8 + #ace, 1, 0) .. ace
    -- DACL_PRESENT | SELF_RELATIVE.
    local header = string.pack("<BBI2I4I4I4I4", 1, 0, 0x8004,
        20, 20 + #SYSTEM_SID, 0, 20 + 2 * #SYSTEM_SID)
    return ((header .. SYSTEM_SID .. SYSTEM_SID .. acl):gsub(".",
        function(byte) return string.format("%02x", byte:byte()) end))
end

local TARGET = [[Machine\System\Services\pt-svcsd]]
local SERVICES = [[Machine\System\Services]]

local vm = peinit.boot({
    name = "identity-service-descriptors",
    files = peinit.seed("pt-svcsd", {
        { path = [[Machine\System]] },
        { path = SERVICES },
        -- Demand-only and Oneshot: a command against it can be issued at
        -- any moment without waiting for or disturbing a resident
        -- process, and `start` is a real operation rather than a no-op.
        { path = TARGET, values = {
            { name = "ImagePath", type = "sz", data = "/bin/true" },
            { name = "Type", type = "dword", data = 1 },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "Readiness", type = "dword", data = 1 },
        } },
    }),
})

-- ACCESS_DENIED is peinit's answer to a failed check; anything else is
-- the command running and succeeding or failing on its own merits. The
-- distinction matters: `reload` on an inactive Oneshot fails for a
-- reason that has nothing to do with the descriptor, and a test that
-- only looked at the exit code could not tell the two apart.
local function verdict(result)
    if (result.stdout .. result.stderr):find("ACCESS_DENIED", 1, true) then
        return "denied"
    end
    return "allowed"
end

local function run(command, service)
    return verdict(vm:run("svctl " .. command .. " " .. (service or "pt-svcsd")))
end

-- A descriptor change takes effect on the next control request, but the
-- registry notification that carries it to peinit is asynchronous. Poll
-- until the answer has moved rather than sleeping a fixed time.
local function set_descriptor(key, mask, expect_status)
    vm:run("reg set '" .. key .. "' ServiceSecurity hex:" .. descriptor_hex(mask)):assert_ok()
    for _ = 1, 40 do
        if run("status") == expect_status then return end
        vm:run("sleep 1")
    end
    error(string.format("the reload of %s never landed for mask %#x", key, mask))
end

-- Back to the built-in default: neither the definition nor the Services
-- key carries a value, which is the state a stock boot is in. Every test
-- that writes one ends by calling this, because they share a machine.
local function clear_descriptors()
    vm:run("reg del '" .. TARGET .. "' ServiceSecurity")
    vm:run("reg del '" .. SERVICES .. "' ServiceSecurity")
    for _ = 1, 40 do
        if run("status") == "allowed" and run("stop") == "allowed" then return end
        vm:run("sleep 1")
    end
    error("the descriptors were not cleared")
end

test("the descriptor is what the control interface enforces, and the caller's rights come from it",
    { spec = "peinit *svcsd.servicesecurity-governs-runtime-operations" },
    function(t)
        -- Two descriptors on the same definition, one after the other,
        -- with nothing else changed: the runtime answer follows the
        -- value. Nothing about the service, its definition, or who is
        -- asking has moved.
        set_descriptor(TARGET, 0x0001, "allowed")
        t:assert_eq(run("stop"), "denied", "stopping is refused under a query-only descriptor")

        set_descriptor(TARGET, 0x0004, "denied")
        t:assert_eq(run("stop"), "allowed", "and permitted under one that grants stop")

        clear_descriptors()
    end)

test("each named right grants exactly the command it names",
    {
        spec = {
            "peinit *svcsd.query-status-grants-status",
            "peinit *svcsd.start-grants-start",
            "peinit *svcsd.stop-grants-stop",
            "peinit *svcsd.interrogate-grants-reload",
        },
    },
    function(t)
        local cases = {
            { mask = 0x0001, right = "SERVICE_QUERY_STATUS", allows = "status" },
            { mask = 0x0002, right = "SERVICE_START", allows = "start" },
            { mask = 0x0004, right = "SERVICE_STOP", allows = "stop" },
            { mask = 0x0008, right = "SERVICE_INTERROGATE", allows = "reload" },
        }
        for _, case in ipairs(cases) do
            set_descriptor(TARGET, case.mask,
                case.allows == "status" and "allowed" or "denied")
            for _, command in ipairs({ "status", "start", "stop", "reload" }) do
                local got = run(command)
                if command == case.allows then
                    t:assert_eq(got, "allowed",
                        case.right .. " grants " .. command)
                else
                    t:assert_eq(got, "denied",
                        case.right .. " does not grant " .. command)
                end
            end
        end
        clear_descriptors()
    end)

test("restart needs start and stop together, and reset needs stop",
    {
        spec = {
            "peinit *svcsd.restart-requires-start-and-stop",
            "peinit *svcsd.reset-requires-stop",
        },
    },
    function(t)
        -- Neither command has a right of its own; each is checked against
        -- the rights the work it does would need.
        set_descriptor(TARGET, 0x0002, "denied")
        t:assert_eq(run("restart"), "denied", "start alone does not authorise a restart")
        t:assert_eq(run("reset"), "denied", "nor a reset")

        set_descriptor(TARGET, 0x0004, "denied")
        t:assert_eq(run("restart"), "denied", "stop alone does not authorise a restart")
        -- Clearing a Failed or Abandoned state is the tail of stopping
        -- something rather than the head of starting it, so stop is the
        -- right it asks for.
        t:assert_eq(run("reset"), "allowed", "but it does authorise a reset")

        set_descriptor(TARGET, 0x0006, "denied")
        t:assert_eq(run("restart"), "allowed", "the two together authorise a restart")

        clear_descriptors()
    end)

test("the generic rights map to the specific ones peinit passes AccessCheck",
    {
        spec = {
            "peinit *svcsd.generic-read-is-query-status",
            "peinit *svcsd.generic-write-is-start-stop-interrogate",
            "peinit *svcsd.generic-execute-is-start-stop-interrogate",
            "peinit *svcsd.generic-all-is-service-all-access",
        },
    },
    function(t)
        -- A descriptor may be written with generic rights, and what they
        -- mean for a service object is the mapping peinit hands the
        -- check. Each generic bit is asserted by the set of commands it
        -- opens, which is what the mapping says it should be.
        local function expect(mask, label, allowed)
            set_descriptor(TARGET, mask, allowed.status and "allowed" or "denied")
            for _, command in ipairs({ "status", "start", "stop", "reload" }) do
                t:assert_eq(run(command), allowed[command] and "allowed" or "denied",
                    label .. (allowed[command] and " grants " or " does not grant ") .. command)
            end
        end

        expect(0x80000000, "GENERIC_READ", { status = true })
        expect(0x40000000, "GENERIC_WRITE", { start = true, stop = true, reload = true })
        expect(0x20000000, "GENERIC_EXECUTE", { start = true, stop = true, reload = true })
        expect(0x10000000, "GENERIC_ALL",
            { status = true, start = true, stop = true, reload = true })

        clear_descriptors()
    end)

test("a definition with no value of its own takes the one on the Services key",
    { spec = "peinit *svcsd.a-definition-with-no-value-takes-the-services-keys" },
    function(t)
        -- pt-svcsd carries no `ServiceSecurity` value at this point, and
        -- the descriptor that decides its answers is the one a single
        -- step up, on `Machine\System\Services` itself.
        vm:run("reg set '" .. SERVICES .. "' ServiceSecurity hex:" .. descriptor_hex(0x0004))
            :assert_ok()
        local landed = false
        for _ = 1, 40 do
            if run("status") == "denied" then landed = true break end
            vm:run("sleep 1")
        end
        t:assert(landed, "the parent key's descriptor reached a definition that carries none")
        t:assert_eq(run("stop"), "allowed", "and it is that descriptor's rights that apply")

        -- A value on the definition itself wins over the inherited one,
        -- which is the other half of the lookup.
        set_descriptor(TARGET, 0x0001, "allowed")
        t:assert_eq(run("stop"), "denied", "the definition's own value takes precedence")

        clear_descriptors()
    end)

test("with no value anywhere, SYSTEM may do everything to a service",
    { spec = "peinit *svcsd.the-built-in-default-grants-system-and-administrators-everything" },
    function(t)
        -- Neither the definition nor the Services key carries a value on
        -- a stock boot, so what is being exercised here is the built-in
        -- default: SERVICE_ALL_ACCESS for SYSTEM and Administrators.
        t:assert(vm:run("reg get '" .. TARGET .. "' ServiceSecurity").exit_code ~= 0,
            "the definition carries no ServiceSecurity value")
        t:assert(vm:run("reg get '" .. SERVICES .. "' ServiceSecurity").exit_code ~= 0,
            "and neither does the Services key")

        for _, command in ipairs({ "status", "start", "stop", "restart", "reset" }) do
            t:assert_eq(run(command), "allowed",
                "SYSTEM may " .. command .. " under the default")
        end
    end)

test("a command naming no service is refused as unknown rather than as denied",
    { spec = "peinit *svcsd.an-unknown-service-is-not-access-checked" },
    function(t)
        -- peinit does not invent a descriptor to check against, so the
        -- answer says the service is unknown. Answering ACCESS_DENIED
        -- instead would be the wrong answer twice over — no check ran,
        -- and it would hide the typo.
        local result = vm:run("svctl status pt-svcsd-does-not-exist")
        local output = result.stdout .. result.stderr
        t:assert(output:find("UNKNOWN_SERVICE", 1, true),
            "the answer names the service as unknown: " .. output)
        t:assert(not output:find("ACCESS_DENIED", 1, true),
            "and does not report a denial: " .. output)
    end)

test("a denial is recorded as an access.denied event carrying the whole attempt",
    { spec = "peinit *svcsd.a-denial-is-recorded-as-an-access-denied-event" },
    function(t)
        set_descriptor(TARGET, 0x0001, "allowed")
        t:assert_eq(run("start"), "denied", "the attempt was refused")

        -- The event is peinit's own audit record of the refusal, so it
        -- carries what an auditor would need: who asked, for what, and
        -- what they were given instead.
        -- Several denials against this target have been recorded by now,
        -- so pick out the one this test caused: a refused SERVICE_START.
        local found
        for _ = 1, 20 do
            local query = vm:run([[evctl 'EVENTS access.denied SINCE 1h ago TAKE 50']])
            for _, line in ipairs(peinit.lines(query.stdout)) do
                if line:find('target="pt-svcsd"', 1, true)
                    and line:find('requested_right="SERVICE_START"', 1, true) then
                    found = line
                end
            end
            if found then break end
            vm:run("sleep 1")
        end
        t:assert(found, "the denial reached the event store, named by the right it asked for")
        t:assert(found:find('caller_sid="S-1-5-18"', 1, true),
            "it names the caller's SID: " .. found)
        t:assert(found:find('target_type="service"', 1, true),
            "and the kind of target: " .. found)
        t:assert(found:find("requested_access_bits=2", 1, true),
            "and the bits that were asked for: " .. found)
        t:assert(found:find("granted_access_bits=", 1, true),
            "and the bits that were granted: " .. found)

        clear_descriptors()
    end)

test("a descriptor change takes effect on the next request, with no restart",
    { spec = "peinit *svcsd.a-descriptor-change-needs-no-restart" },
    function(t)
        -- There is no cached decision to invalidate: the check runs
        -- against the current descriptor every time. Nothing here stops,
        -- starts or reloads peinit, and the answers still change.
        local before = vm:read_file("/proc/1/stat"):match("^%d+ %S+ %a+ (%d+)")
        set_descriptor(TARGET, 0x0001, "allowed")
        t:assert_eq(run("stop"), "denied", "the new descriptor is in force")
        clear_descriptors()
        t:assert_eq(run("stop"), "allowed", "and so is its removal")
        t:assert_eq(vm:read_file("/proc/1/stat"):match("^%d+ %S+ %a+ (%d+)"), before,
            "peinit was never restarted: it is the same PID 1 it was")
    end)

test("list omits what the caller cannot query and still succeeds",
    { spec = "peinit *svcsd.list-omits-rather-than-denies" },
    function(t)
        -- Reporting the denials would answer the question the filtering
        -- exists to avoid answering, so the response is a short list and
        -- a success rather than a refusal.
        vm:run("reg set '" .. SERVICES .. "' ServiceSecurity hex:" .. descriptor_hex(0x000E))
            :assert_ok()
        local landed = false
        for _ = 1, 40 do
            if run("status") == "denied" then landed = true break end
            vm:run("sleep 1")
        end
        t:assert(landed, "a descriptor granting everything but query is in force")

        local listing = vm:run("svctl list")
        listing:assert_ok()
        t:assert(not listing.stdout:find("pt%-svcsd"),
            "the service the caller cannot query is absent from the list")
        -- Absent rather than refused: the command answered normally, and
        -- with rather less in it than a moment ago.
        t:assert(not (listing.stdout .. listing.stderr):find("ACCESS_DENIED", 1, true),
            "and nothing about the omission was reported as a denial")

        vm:run("reg del '" .. SERVICES .. "' ServiceSecurity")
        for _ = 1, 40 do
            if run("status") == "allowed" then break end
            vm:run("sleep 1")
        end
        t:assert(vm:run("svctl list").stdout:find("pt%-svcsd"),
            "and it is listed again once the caller may query it")
    end)
