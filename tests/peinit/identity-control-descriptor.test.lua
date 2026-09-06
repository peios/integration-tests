-- Peinit TRM §4.7 — the control descriptor: the two operations that are
-- not about any one service, checked against peinit's own descriptor.
--
-- `reload-config` is the whole test surface here, and deliberately so.
-- Both rights can be exercised through it: a caller granted
-- SYSTEM_RELOAD_CONFIG is answered, and a caller granted anything else —
-- including SYSTEM_SHUTDOWN — is refused, so the pairs of results below
-- pin down which bit each descriptor conveys without the test ever
-- having to turn the machine off underneath itself. The one case that
-- cannot be reached that way, GENERIC_EXECUTE actually granting a
-- shutdown, is noted where it arises.

local peinit = require("helpers.peinit")

-- Nothing here varies the boot, so the stock image is what is wanted:
-- staging files perturbs the root's descriptor (see
-- identity-materialisation.test.lua) and nothing below needs a seed.
local vm = peinit.boot({ name = "identity-control-descriptor" })

local CONTROL = [[Machine\System\Init]]

-- A self-relative security descriptor granting SYSTEM one mask, hex
-- encoded for `reg set`. `ControlSecurity` is a REG_BINARY value with no
-- SDDL form in the registry, so a test that wants to say "SYSTEM may
-- only reload" has to say it in bytes. MS-DTYP's layout, which KACS uses
-- verbatim (pkm/sd.h).
local SYSTEM_SID = string.pack("BB", 1, 1) .. string.pack(">I2>I4", 0, 5)
    .. string.pack("<I4", 18)

local function descriptor_hex(mask)
    local ace = string.pack("<BBI2I4", 0, 0, 8 + #SYSTEM_SID, mask) .. SYSTEM_SID
    local acl = string.pack("<BBI2I2I2", 2, 0, 8 + #ace, 1, 0) .. ace
    -- DACL_PRESENT | SELF_RELATIVE.
    local header = string.pack("<BBI2I4I4I4I4", 1, 0, 0x8004,
        20, 20 + #SYSTEM_SID, 0, 20 + 2 * #SYSTEM_SID)
    return ((header .. SYSTEM_SID .. SYSTEM_SID .. acl):gsub(".",
        function(byte) return string.format("%02x", byte:byte()) end))
end

local function verdict(result)
    if (result.stdout .. result.stderr):find("ACCESS_DENIED", 1, true) then
        return "denied"
    end
    return "allowed"
end

local function reload_config()
    return verdict(vm:run("svctl reload-config"))
end

-- The descriptor is hot-reloaded from a registry change notification,
-- which arrives asynchronously, so wait for the answer to move rather
-- than for a fixed time.
local function set_control(mask, expect)
    vm:run("reg set '" .. CONTROL .. "' ControlSecurity hex:" .. descriptor_hex(mask))
        :assert_ok()
    for _ = 1, 40 do
        if reload_config() == expect then return end
        vm:run("sleep 1")
    end
    error(string.format("the control descriptor never took effect for mask %#x", mask))
end

local function clear_control()
    vm:run("reg del '" .. CONTROL .. "' ControlSecurity")
    for _ = 1, 40 do
        if reload_config() == "allowed" then return end
        vm:run("sleep 1")
    end
    error("the control descriptor was not cleared")
end

test("shutdown and reload-config are checked against peinit's own descriptor",
    { spec = "peinit *svcsd.control-operations-use-peinits-own-descriptor" },
    function(t)
        -- Neither operation is about a service, and neither consults a
        -- service's descriptor: what decides them is the value at
        -- Machine\System\Init\ControlSecurity. Writing one there changes
        -- the answer, while every service on the machine keeps its own.
        set_control(0x0000, "denied")
        t:assert_eq(reload_config(), "denied",
            "a control descriptor granting nothing refuses a control operation")
        t:assert_eq(verdict(vm:run("svctl status registryd")), "allowed",
            "while a service command, checked against the service's descriptor, is unaffected")
        clear_control()
    end)

test("the two control rights are separate grants",
    {
        spec = {
            "peinit *svcsd.control-shutdown-grants-poweroff-reboot-halt",
            "peinit *svcsd.control-reload-config-grants-a-definition-reread",
        },
    },
    function(t)
        -- SYSTEM_SHUTDOWN, and only that. The three shutdown forms are
        -- not issued under this descriptor: it is the one that permits
        -- them, and permitting them stops the machine.
        set_control(0x0001, "denied")
        t:assert_eq(reload_config(), "denied",
            "the right to shut the machine down does not carry the right to reload")

        -- SYSTEM_RELOAD_CONFIG, and only that. Here the three forms can
        -- be issued safely, because each of them is refused — which is
        -- what says SYSTEM_SHUTDOWN, and not this right, is what
        -- poweroff, reboot and halt are checked against.
        set_control(0x0002, "allowed")
        local reloaded = vm:run("svctl reload-config")
        reloaded:assert_ok()
        t:assert(reloaded.stdout:find("configuration reloaded", 1, true),
            "the definitions were re-read from the registry: " .. reloaded.stdout)
        for _, kind in ipairs({ "poweroff", "reboot", "halt" }) do
            t:assert_eq(verdict(vm:run("svctl shutdown " .. kind)), "denied",
                kind .. " needs SYSTEM_SHUTDOWN, which this descriptor does not grant")
        end

        clear_control()
    end)

test("the generic rights map onto the two control rights",
    {
        spec = {
            "peinit *svcsd.control-generic-read-conveys-nothing",
            "peinit *svcsd.control-generic-write-is-reload-config",
            "peinit *svcsd.control-generic-execute-is-shutdown",
            "peinit *svcsd.control-generic-all-is-both",
        },
    },
    function(t)
        -- GENERIC_READ conveys no access at all: the control descriptor
        -- governs two actions and no queries, so there is nothing for a
        -- read grant to convey. Not an error — just nothing.
        set_control(0x80000000, "denied")
        t:assert_eq(reload_config(), "denied", "GENERIC_READ does not convey reload-config")
        t:assert_eq(verdict(vm:run("svctl shutdown poweroff")), "denied",
            "and it does not convey shutdown either, so it conveys nothing")

        -- GENERIC_WRITE is SYSTEM_RELOAD_CONFIG, and that alone.
        set_control(0x40000000, "allowed")
        t:assert_eq(reload_config(), "allowed", "GENERIC_WRITE conveys reload-config")
        t:assert_eq(verdict(vm:run("svctl shutdown poweroff")), "denied",
            "and not shutdown")

        -- GENERIC_EXECUTE is SYSTEM_SHUTDOWN, and that alone. Only the
        -- negative half is asserted: the positive half is a machine that
        -- powers off, which would take the rest of this file with it.
        set_control(0x20000000, "denied")
        t:assert_eq(reload_config(), "denied",
            "GENERIC_EXECUTE does not convey reload-config")

        -- GENERIC_ALL is both, which is visible in the one of the two
        -- that can be asked for without consequence.
        set_control(0x10000000, "allowed")
        t:assert_eq(reload_config(), "allowed", "GENERIC_ALL conveys reload-config")

        clear_control()
    end)

test("with no value in the registry, SYSTEM gets both rights",
    { spec = "peinit *svcsd.the-control-default-grants-system-and-administrators-both" },
    function(t)
        -- The image ships no ControlSecurity value, so this is the
        -- built-in default and not a policy decision anybody made.
        t:assert(vm:run("reg get '" .. CONTROL .. "' ControlSecurity").exit_code ~= 0,
            "no ControlSecurity value is present")
        t:assert_eq(reload_config(), "allowed",
            "and SYSTEM may reload the configuration anyway")
        -- The shutdown half of the default is not exercised for the same
        -- reason as above: exercising it stops the machine.
    end)

test("the descriptor is loaded during the boot and re-read on every change",
    { spec = "peinit *svcsd.controlsecurity-is-loaded-at-phase-2-and-hot-reloaded" },
    function(t)
        -- Loaded during Phase 2: the boot completed long before this test
        -- ran and the default has been in force since, which is why the
        -- control socket has been answering.
        t:assert(vm:console():read_log():find("peinit: phase2 boot complete", 1, true),
            "the boot that loaded it finished")

        -- Hot-reloaded on notification: writing the value changes the
        -- answer, and deleting it changes it back, with no restart in
        -- between. peinit is the same process throughout — a restarted
        -- PID 1 would have a different start time in /proc/1/stat.
        local before = vm:read_file("/proc/1/stat"):match("^%d+ %S+ %a+ (%d+)")
        set_control(0x0001, "denied")
        clear_control()
        t:assert_eq(vm:read_file("/proc/1/stat"):match("^%d+ %S+ %a+ (%d+)"), before,
            "the descriptor was re-read by the peinit that was already running")
    end)
