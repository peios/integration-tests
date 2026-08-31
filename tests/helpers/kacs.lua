-- Security descriptors and tokens, for the cases whose subject is a
-- refusal.
--
-- Most stratafs cases run as the agent, which is SYSTEM and is granted
-- everything. A case that says "this operation requires FILE_TRAVERSE"
-- is only really tested by a caller who has been given every other
-- right and not that one — so this module does two things: it authors a
-- descriptor granting exactly the rights a case wants to allow, and it
-- produces a caller that will be judged on it.
--
-- Producing the caller is less obvious than it looks. Dropping the
-- token's privileges is the load-bearing half: SYSTEM otherwise
-- bypasses the DACL entirely, and a directory whose DACL grants nothing
-- still stats perfectly well. And the token has to be *installed*
-- rather than impersonated, because impersonation is per-thread while
-- provium's agent spreads a test's syscalls across threads — the ioctl
-- succeeds and the next syscall lands on a thread that never
-- impersonated. KACS_IOC_INSTALL replaces the primary token for the
-- whole thread group (PKM §3.2.3), so it survives the trip.
--
-- Every number here is from PKM §3.A, which is generated from the uapi
-- headers. Nothing in this file is guessed.

local sys = require("helpers.sys")

local M = {}

M.SYS = {
    OPEN_SELF_TOKEN = 1000,
    OPEN_PROCESS_TOKEN = 1001,
    CREATE_TOKEN = 1003,
    REVERT = 1012,
    GET_SD = 1021,
    SET_SD = 1022,
}

M.IOC = {
    QUERY = 0xC0104B00,
    ADJUST_PRIVS = 0x40184B01,
    DUPLICATE = 0xC0104B02,
    INSTALL = 0x00004B03,
    RESTRICT = 0xC0284B04,
    IMPERSONATE = 0x00004B08,
}

M.TOKEN_ALL_ACCESS = 0x000F01FF
M.TOKEN_TYPE_PRIMARY, M.TOKEN_TYPE_IMPERSONATION = 1, 2

-- security_information bits for get_sd / set_sd.
M.SI = { OWNER = 1, GROUP = 2, DACL = 4, SACL = 8 }

-- Access rights. The directory names alias the file ones: LIST_DIRECTORY
-- is READ_DATA, TRAVERSE is EXECUTE, ADD_FILE is WRITE_DATA.
M.RIGHT = {
    READ_DATA = 0x00000001, WRITE_DATA = 0x00000002,
    APPEND_DATA = 0x00000004, READ_EA = 0x00000008,
    WRITE_EA = 0x00000010, EXECUTE = 0x00000020,
    DELETE_CHILD = 0x00000040, READ_ATTRIBUTES = 0x00000080,
    WRITE_ATTRIBUTES = 0x00000100,
    LIST_DIRECTORY = 0x00000001, TRAVERSE = 0x00000020,
    ADD_FILE = 0x00000002, ADD_SUBDIRECTORY = 0x00000004,

    DELETE = 0x00010000, READ_CONTROL = 0x00020000,
    WRITE_DAC = 0x00040000, WRITE_OWNER = 0x00080000,
    SYNCHRONIZE = 0x00100000,
    GENERIC_ALL = 0x10000000,
}

--- Every right a file or directory object defines, for "grant all but".
M.ALL_RIGHTS = 0x001F01FF

M.ACE_ALLOWED, M.ACE_DENIED = 0x00, 0x01

-- Privileges. Only the ones that let a holder past an access check
-- matter here; the rest are named in PKM §3.A.
M.PRIV = {
    SECURITY = 0x100, TAKE_OWNERSHIP = 0x200,
    BACKUP = 0x20000, RESTORE = 0x40000,
    CHANGE_NOTIFY = 0x800000, MANAGE_VOLUME = 0x10000000,
}

--- The privileges that let their holder past a DACL.
---
--- Backup and Restore stand in for read and write access, Change Notify
--- bypasses traverse checking, and Take Ownership and Security reach a
--- descriptor regardless of what it says. Deleting exactly these leaves
--- a caller that can still do its job — mount, open, walk — but is
--- judged on the descriptor when it gets there.
---
--- Deleting *every* privilege instead would be simpler and is wrong: a
--- token with none cannot mount at all, and a case about a stratum path
--- would fail with EPERM before reaching the question it is asking.
M.BYPASS_PRIVILEGES = M.PRIV.SECURITY | M.PRIV.TAKE_OWNERSHIP
    | M.PRIV.BACKUP | M.PRIV.RESTORE | M.PRIV.CHANGE_NOTIFY

-- Well-known SIDs, as MS-DTYP binary: revision, sub-authority count,
-- a six-byte big-endian identifier authority, then little-endian
-- sub-authorities.
local function sid(authority, ...)
    local subs = { ... }
    local out = string.pack("<I1I1", 1, #subs) ..
        string.pack(">I2I4", 0, authority)
    for _, s in ipairs(subs) do out = out .. string.pack("<I4", s) end
    return out
end

M.SID = {
    EVERYONE = sid(1, 0),              -- S-1-1-0
    LOCAL_SYSTEM = sid(5, 18),         -- S-1-5-18
    AUTHENTICATED_USERS = sid(5, 11),  -- S-1-5-11
    ADMINISTRATORS = sid(5, 32, 544),  -- S-1-5-32-544
}

--- One ACE: a type, an access mask and a trustee SID.
---
--- `flags` carries the inheritance bits; a stratafs case wanting a whole
--- subtree covered passes CONTAINER_INHERIT | OBJECT_INHERIT (3).
function M.ace(ace_type, mask, trustee, flags)
    local size = 8 + #trustee
    return string.pack("<I1I1I2I4", ace_type, flags or 0, size, mask) .. trustee
end

--- An ACL holding the given ACEs, in order.
---
--- Order is the caller's, and it matters: KACS evaluates ACEs in
--- sequence, so a denying ACE only wins where it precedes the granting
--- one. An ACL with no ACEs is present and grants nothing, which denies
--- everyone — distinct from having no DACL at all, which grants
--- everyone.
function M.acl(aces)
    local body = table.concat(aces or {})
    return string.pack("<I1I1I2I2I2", 2, 0, 8 + #body, #(aces or {}), 0) .. body
end

-- Descriptor control bits (MS-DTYP 2.4.6).
local SE_DACL_PRESENT, SE_SELF_RELATIVE = 0x0004, 0x8000

--- A self-relative security descriptor carrying a DACL.
---
--- Only the DACL is emitted, which is all `set_sd` is asked to replace
--- here; owner and group are left as they are on the object.
function M.descriptor(acl)
    local header_len = 20
    return string.pack("<I1I1I2I4I4I4I4",
        1, 0, SE_DACL_PRESENT | SE_SELF_RELATIVE, 0, 0, 0, header_len) .. acl
end

--- The descriptor that denies everyone: a DACL that is present and empty.
function M.deny_all() return M.descriptor(M.acl({})) end

--- A descriptor granting `mask` to Everyone, and nothing else to anyone.
---
--- Inherited by everything below, so a whole test tree can be placed
--- under one call.
function M.grant(mask)
    return M.descriptor(M.acl({ M.ace(M.ACE_ALLOWED, mask, M.SID.EVERYONE, 3) }))
end

--- Every right except those in `mask` — the shape a rights case wants.
function M.grant_all_but(mask) return M.grant(M.ALL_RIGHTS & ~mask) end

--- Write a descriptor's DACL onto a path. Returns the raw syscall result.
function M.set_sd(who, path, descriptor, info)
    return who:syscall(M.SYS.SET_SD, {
        args = { sys.AT_FDCWD, 0, info or M.SI.DACL, 0, #descriptor, 0 },
        bufs = { sys.cstr(path), descriptor },
        ptrs = { 1, 3 },
    })
end

--- Read a path's descriptor back. Returns the bytes, or `nil, errno`.
function M.get_sd(who, path, info)
    local r = who:syscall(M.SYS.GET_SD, {
        args = { sys.AT_FDCWD, 0, info or M.SI.DACL, 0, 4096, 0 },
        bufs = { sys.cstr(path), string.rep("\0", 4096) },
        ptrs = { 1, 3 },
    })
    if r.ret < 0 then return nil, r.errno end
    return r.out_bufs[2]:sub(1, r.ret)
end

--- Run `fn` in a worker process bound by the descriptors it meets.
---
--- The worker is the same principal as the agent, minus the privileges
--- that let a holder past an access check — so what it can reach is
--- decided by the DACL alone, which is what makes a `security.rights`
--- case mean anything.
---
--- It is killed afterwards whether the body passed or raised: a worker
--- left running holds a mount namespace of its own and pins superblocks
--- the file is trying to tear down.
---
--- `opts.privs` overrides which privileges are deleted.
function M.as_dacl_bound(t, vm, fn, opts)
    opts = opts or {}
    local worker = vm:spawn_worker()
    local ok, err = pcall(function()
        local token = worker:syscall(M.SYS.OPEN_SELF_TOKEN, 0, M.TOKEN_ALL_ACCESS)
        assert(token.ret >= 0,
            "open_self_token: " .. sys.errname(token.errno))

        -- FilterToken. struct kacs_restrict_args, 40 bytes: the
        -- privileges to delete, then counts and a data pointer for the
        -- deny-only and restricted SIDs this does not use, then the fd
        -- the new token comes back in.
        local restrict = worker:syscall(sys.NR.ioctl, {
            args = { token.ret, M.IOC.RESTRICT, 0 },
            bufs = { string.pack("<I8I4I4I4I4I8i4I4",
                opts.privs or M.BYPASS_PRIVILEGES, 0, 0, 0, 0, 0, -1, 0) },
            ptrs = { 2 },
        })
        assert(restrict.ret == 0,
            "KACS_IOC_RESTRICT: " .. sys.errname(restrict.errno))
        local filtered = string.unpack("<i4", restrict.out_bufs[1], 33)
        assert(filtered >= 0, "RESTRICT returned no token")

        local install = worker:syscall(sys.NR.ioctl, filtered, M.IOC.INSTALL, 0)
        assert(install.ret == 0,
            "KACS_IOC_INSTALL: " .. sys.errname(install.errno))

        fn(worker)
    end)
    worker:kill()
    worker:join()
    if not ok then error(err, 0) end
end

return M
