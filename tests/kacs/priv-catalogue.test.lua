-- PKM §3.4.2 — the catalogue's *shape*: which bit each privilege
-- occupies, which bits are allocated at all, and what the kernel does
-- with the ones that are not. The per-privilege enforcement points are
-- in priv-gates.test.lua.
--
-- Nothing validates a privilege mask against the allocated set, so most
-- of what is testable here is the difference between a bit that opens a
-- gate and a bit that is merely carried.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local token = require("helpers.token")
local unixsock = require("helpers.unixsock")

local vm = provium:vm("v", "kernel-only"):boot()

local P = token.PRIV
local NR = { reboot = 169, settimeofday = 164, open_by_handle_at = 304, mlock = 149,
             setrlimit = 160 }
local REBOOT_MAGIC1, REBOOT_MAGIC2, CAD_OFF = 0xfee1dead, 672274793, 0

-- The two custom-allocation bits, counted down from 63: bit 63 is the
-- retired SeBindPrivilegedPortPrivilege and bit 62 is SeCreateJobPrivilege.
local BIT_CREATE_JOB, BIT_RETIRED_PORT = 62, 63
-- The reserved privileges of §3.4.2, allocated for format compatibility.
local RESERVED = { 15, 16, 22, 25, 30, 31, 33, 34 }
-- The application-level privileges: SeMachineAccount, SeSyncAgent,
-- SeEnableDelegation.
local APPLICATION_LEVEL = { 6, 26, 27 }

local function mask(bits)
    local m = 0
    for _, b in ipairs(bits) do m = m | token.bit(b) end
    return m
end

local function as(t, bits, fn, spec)
    local s = { privs_present = mask(bits), privs_enabled = mask(bits) }
    for k, v in pairs(spec or {}) do s[k] = v end
    token.as_principal(t, vm, s, fn)
end

local function words(w)
    local fd = assert(token.open_self(w, token.RIGHT.QUERY))
    local p = assert(token.privileges(w, fd))
    sys.close(w, fd)
    return p
end

local function hex(v) return ("0x%016X"):format(v) end

-- Most principals here are minted with no privileges at all, and
-- without SeChangeNotifyPrivilege reaching any path costs FILE_TRAVERSE
-- on every directory above it. Opening the guest root keeps a case's
-- refusal about its own gate rather than about the walk that got there;
-- every case that is about a descriptor sets one on its own object.
sys.mkdir_p(vm, "/priv-cat")
kacs.set_sd(vm, "/priv-cat", kacs.grant(kacs.ALL_RIGHTS))
kacs.set_sd(vm, "/", kacs.grant(kacs.ALL_RIGHTS))

-- Bit positions ------------------------------------------------------------

test("format-compatible privileges occupy bits 2-35 and custom ones are allocated downward from 63",
    { spec = "PKM *priv.bits.luid-positions-and-downward-allocation" }, function(t)
        -- The boot SYSTEM token carries the whole allocated set (§3.4.2),
        -- which is exactly the two regions and nothing between them.
        local fd = assert(token.open_self(vm, token.RIGHT.QUERY))
        local present = assert(token.privileges(vm, fd)).present
        sys.close(vm, fd)
        local luid_region = 0
        for b = 2, 35 do luid_region = luid_region | token.bit(b) end
        local custom_region = token.bit(BIT_CREATE_JOB) | token.bit(BIT_RETIRED_PORT)
        t:assert_eq(present, luid_region | custom_region,
            "the allocated set is bits 2-35 plus 62 and 63: " .. hex(present))
        t:assert_eq(present & 0x3, 0, "nothing below bit 2")
        local between = 0
        for b = 36, 61 do between = between | token.bit(b) end
        t:assert_eq(present & between, 0, "and nothing in bits 36-61")

        -- And the catalogue's numbering is the enforcement point's: a
        -- token whose present set is one bit opens exactly that gate.
        local function only(bit, drive)
            local passed
            as(t, { bit }, function(w)
                t:assert_eq(words(w).present, token.bit(bit),
                    "a token carrying only bit " .. bit)
                passed = drive(w)
            end)
            return passed
        end
        t:assert(only(19, function(w)
            return w:syscall(NR.reboot, REBOOT_MAGIC1, REBOOT_MAGIC2, CAD_OFF, 0).ret == 0
        end), "bit 19 is SeShutdownPrivilege")
        t:assert(only(12, function(w)
            return w:syscall(NR.settimeofday, { args = { 0, 0 },
                bufs = { string.pack("<i8i8", 1800000000, 0) }, ptrs = { 0 } }).ret == 0
        end), "bit 12 is SeSystemtimePrivilege")
        t:assert(only(35, function(w)
            return sys.symlink(w, "t", "/priv-cat/bit35").ret == 0
        end), "bit 35 is SeCreateSymbolicLinkPrivilege")
        t:assert(only(23, function(w)
            -- Past the gate the handle itself is what fails.
            return w:syscall(NR.open_by_handle_at, { args = { sys.AT_FDCWD, 0, 0 },
                bufs = { string.pack("<I4i4", 8, 1) .. string.rep("\0", 8) }, ptrs = { 1 } }).errno
                == sys.E.STALE
        end), "bit 23 is SeChangeNotifyPrivilege")
    end)

test("the SYSTEM token holds bit 62 present and enabled with no name and no gate behind it",
    { spec = "PKM *priv.create-job.present-in-system-token" }, function(t)
        local fd = assert(token.open_self(vm, token.RIGHT.QUERY))
        local p = assert(token.privileges(vm, fd))
        sys.close(vm, fd)
        local bit62 = token.bit(BIT_CREATE_JOB)
        t:assert_eq(p.present & bit62, bit62, "bit 62 is present in the boot SYSTEM token")
        t:assert_eq(p.enabled & bit62, bit62, "and enabled")
        t:assert_eq(p.default & bit62, bit62, "and enabled by default")
        t:assert_eq(p.used & bit62, 0,
            "and nothing the agent has done has ever consulted it")
    end)

test("SeCreateJobPrivilege at bit 62 has no kernel definition and nothing consults it",
    { spec = "PKM *priv.create-job.bit-62-unused" }, function(t)
        as(t, { BIT_CREATE_JOB }, function(w)
            t:assert_eq(words(w).present, token.bit(BIT_CREATE_JOB), "the bit is carried")
            -- Nothing a principal can do turns it into a grant.
            t:assert_eq(w:syscall(NR.reboot, REBOOT_MAGIC1, REBOOT_MAGIC2, CAD_OFF, 0).errno,
                sys.E.PERM, "it opens no shutdown gate")
            t:assert(not token.create_logon_session(w, {}), "no TCB operation")
            t:assert_eq(sys.symlink(w, "t", "/priv-cat/job62").errno, sys.E.PERM,
                "and no symlink")
            t:assert_eq(words(w).used, 0, "and it is never recorded as used")
        end)
    end)

test("bits the catalogue does not allocate are accepted at creation and are inert",
    { spec = "PKM *priv.bits.unallocated-accepted-and-inert" }, function(t)
        local UNALLOCATED = { 0, 1, 36, 45, 61 }
        local m = mask(UNALLOCATED)
        local fd, errno = token.mint(vm, { privs_present = m, privs_enabled = m })
        t:assert(fd, "a token carrying only unallocated bits mints: " .. sys.errname(errno or 0))
        local p = assert(token.privileges(vm, fd))
        t:assert_eq(p.present, m, "the present set is exactly what was asked for: " .. hex(p.present))
        t:assert_eq(p.enabled, m, "and so is the enabled set")
        local handle = assert(token.duplicate(vm, fd, { access = token.RIGHT.ALL_ACCESS }))
        for _, bit in ipairs(UNALLOCATED) do
            t:assert_eq(token.disable_priv(vm, handle, bit).ret, 0, "bit " .. bit .. " disables")
            t:assert_eq(token.remove_priv(vm, handle, bit).ret, 0, "and removes")
        end
        t:assert_eq(assert(token.privileges(vm, handle)).present, 0, "leaving nothing present")
        -- Adjustment accepts any index from 0 to 63 and nothing beyond.
        t:assert_eq(token.adjust_privs(vm, handle, { { 63, 0 } }).ret, 0, "index 63 is accepted")
        local past = token.adjust_privs(vm, handle, { { 64, 0 } })
        t:assert(past.ret ~= 0, "index 64 is not: " .. sys.errname(past.errno))
        t:assert_eq(past.errno, sys.E.INVAL, "EINVAL")
        sys.close(vm, handle); sys.close(vm, fd)
        -- Inert: a principal carrying them is refused everything.
        as(t, UNALLOCATED, function(w)
            t:assert_eq(w:syscall(NR.reboot, REBOOT_MAGIC1, REBOOT_MAGIC2, CAD_OFF, 0).errno,
                sys.E.PERM, "they open no gate")
            t:assert_eq(words(w).used, 0, "and are never marked used")
        end)
    end)

-- Enforcement classes with no kernel enforcement point -----------------------

test("the reserved privileges are carried without loss and have no enforcement point",
    { spec = "PKM *priv.reserved.no-enforcement-point" }, function(t)
        local m = mask(RESERVED)
        local fd, errno = token.mint(vm, { privs_present = m, privs_enabled = m })
        t:assert(fd, "a token from an AD environment carries them: " .. sys.errname(errno or 0))
        local p = assert(token.privileges(vm, fd))
        t:assert_eq(p.present, m, "every reserved bit survives creation: " .. hex(p.present))
        t:assert_eq(p.enabled, m, "enabled as supplied")
        sys.close(vm, fd)
        as(t, RESERVED, function(w)
            local clock = string.pack("<i8i8", 1800000000, 0)
            t:assert_eq(w:syscall(NR.reboot, REBOOT_MAGIC1, REBOOT_MAGIC2, CAD_OFF, 0).errno,
                sys.E.PERM, "no shutdown")
            t:assert_eq(w:syscall(NR.settimeofday, { args = { 0, 0 }, bufs = { clock },
                ptrs = { 0 } }).errno, sys.E.PERM, "no clock")
            t:assert(not token.create_logon_session(w, {}), "no TCB operation")
            t:assert_eq(sys.symlink(w, "t", "/priv-cat/reserved").errno, sys.E.PERM, "no symlink")
            local mounted = sys.mount(w, { source = "none", target = "/priv-cat",
                fstype = "tmpfs" })
            t:assert(mounted.ret ~= 0, "no mount: " .. sys.errname(mounted.errno))
            t:assert_eq(words(w).used, 0, "and not one of them is ever recorded as used")
        end)
    end)

test("the application-level privileges are enforced nowhere",
    { spec = "PKM *priv.application-level.none-enforced-anywhere" }, function(t)
        local m = mask(APPLICATION_LEVEL)
        local fd = assert(token.mint(vm, { privs_present = m, privs_enabled = m }))
        t:assert_eq(assert(token.privileges(vm, fd)).present, m,
            "SeMachineAccount, SeSyncAgent and SeEnableDelegation are carried")
        sys.close(vm, fd)
        as(t, APPLICATION_LEVEL, function(w)
            -- The directory-wide read SeSyncAgentPrivilege is supposed to
            -- confer reaches no kernel object either.
            local denied = "/priv-cat/closed"
            vm:write_file(denied, "secret")
            kacs.set_sd(vm, denied, kacs.deny_all())
            local got, errno = sys.open(w, denied, sys.O.RDONLY)
            t:assert(not got, "no object opens for them: " .. sys.errname(errno or 0))
            t:assert_eq(w:syscall(NR.reboot, REBOOT_MAGIC1, REBOOT_MAGIC2, CAD_OFF, 0).errno,
                sys.E.PERM, "and no system operation")
            t:assert_eq(words(w).used, 0,
                "nothing in the kernel ever records one of them as used")
        end)
    end)

test("binding a port is an access check against the reservation, not a privilege test",
    { spec = "PKM *priv.network.no-port-privilege" }, function(t)
        -- The retired SeBindPrivilegedPortPrivilege bit changes nothing:
        -- with it and without it, the same bind reaches the same verdict.
        local function bind_low(w)
            local fd, errno = unixsock.socket(w, unixsock.AF_INET, unixsock.SOCK.STREAM)
            assert(fd, "socket: " .. unixsock.errname(errno or 0))
            -- struct sockaddr_in: family, port (big-endian), addr, pad.
            local addr = string.pack("<I2", unixsock.AF_INET) .. string.pack(">I2", 80)
                .. string.pack("<I4", 0) .. string.rep("\0", 8)
            local r = w:syscall(unixsock.NR.bind,
                { args = { fd, 0, 16 }, bufs = { addr }, ptrs = { 1 } })
            sys.close(w, fd)
            return r
        end
        local plain, retired
        as(t, {}, function(w) plain = bind_low(w) end)
        as(t, { BIT_RETIRED_PORT }, function(w)
            retired = bind_low(w)
            t:assert_eq(words(w).present, token.bit(BIT_RETIRED_PORT), "bit 63 is carried")
            t:assert_eq(words(w).used, 0, "and no bind consults it")
        end)
        t:assert_eq(retired.ret, plain.ret,
            "the retired bit changes nothing about a privileged-port bind ("
            .. sys.errname(plain.errno) .. " either way)")
        -- Whatever the reservation decides, it is not a privilege verdict:
        -- a principal holding every privilege in the catalogue gets the
        -- same answer.
        local everything
        local all = 0
        for b = 2, 35 do all = all | token.bit(b) end
        token.as_principal(t, vm, { privs_present = all, privs_enabled = all }, function(w)
            everything = bind_low(w)
        end)
        t:assert_eq(everything.ret, plain.ret,
            "and so does one holding every privilege there is")
    end)

-- Default grants ---------------------------------------------------------------

test("SeChangeNotifyPrivilege is in authd's issuer floor for Everyone",
    { spec = "PKM *priv.default.change-notify-to-everyone",
      covered_by = "authd:policy::principal::tests",
      skip = "the issuer floor is authd policy, and the kernel-only profile has " ..
             "no authd — the kernel neither applies nor records a default grant; " ..
             "runs under authd's the_floor_keeps_an_unseeded_machine_usable, " ..
             "which resolves an unconfigured machine's floor to exactly " ..
             "SeChangeNotifyPrivilege for a principal known only as Everyone" },
    function(t) end)

test("SeCreateSymbolicLinkPrivilege is deliberately left out of the floor",
    { spec = "PKM *priv.default.symlink-not-granted",
      covered_by = "authd:policy::principal::tests",
      skip = "the same authd issuer floor, plus the shipped seeds, neither of " ..
             "which exists in a kernel-only guest; runs under authd's " ..
             "the_floor_grants_no_administrative_privilege (the floor grants " ..
             "nothing beyond ChangeNotify) and " ..
             "the_seed_does_not_grant_the_privileges_reserved_to_the_tcb" },
    function(t) end)
