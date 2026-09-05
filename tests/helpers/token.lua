-- Tokens, LogonSessions and the token-handle ioctls, for the chapter 3
-- cases whose subject is the token itself.
--
-- helpers/kacs is about descriptors and the file path; this module is
-- about the identity object — minting one from a spec, deriving one from
-- another, reading it back class by class, and moving it between
-- credentials. Every number is from PKM §3.A, which is generated from
-- the uapi headers.
--
-- Wire buffers cross the agent as `bufs`, and a struct that carries a
-- pointer to another buffer names it through `nested`: the agent fills
-- the pointer field with the child buffer's guest address before the
-- syscall runs.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")

local M = {}

M.SYS = {
    OPEN_SELF_TOKEN = 1000, OPEN_PROCESS_TOKEN = 1001,
    OPEN_THREAD_TOKEN = 1002, CREATE_TOKEN = 1003,
    CREATE_LOGON_SESSION = 1004, SET_PSB = 1005,
    DESTROY_EMPTY_LOGON_SESSION = 1006, REVERT = 1012,
}

M.OPEN_REAL = 0x01

M.IOC = {
    QUERY = 0xC0104B00,
    ADJUST_PRIVS = 0x40184B01,
    DUPLICATE = 0xC0104B02,
    INSTALL = 0x00004B03,
    RESTRICT = 0xC0284B04,
    LINK_TOKENS = 0x40104B05,
    GET_LINKED_TOKEN = 0xC0044B06,
    ADJUST_GROUPS = 0x40904B07,
    IMPERSONATE = 0x00004B08,
    ADJUST_DEFAULT = 0x40104B09,
    ADJUST_INTERACTIVITY_SCOPE = 0x40044B0A,
}

M.RIGHT = {
    ASSIGN_PRIMARY = 0x0001, DUPLICATE = 0x0002, IMPERSONATE = 0x0004,
    QUERY = 0x0008, QUERY_SOURCE = 0x0010, ADJUST_PRIVS = 0x0020,
    ADJUST_GROUPS = 0x0040, ADJUST_DEFAULT = 0x0080,
    ADJUST_INTERACTIVITY_SCOPE = 0x0100,
    DELETE = 0x00010000, READ_CONTROL = 0x00020000,
    WRITE_DAC = 0x00040000, WRITE_OWNER = 0x00080000,
    ALL_ACCESS = 0x000F01FF,
    GENERIC_READ = 0x80000000, GENERIC_WRITE = 0x40000000,
    GENERIC_EXECUTE = 0x20000000, GENERIC_ALL = 0x10000000,
    MAXIMUM_ALLOWED = 0x02000000,
}

M.TYPE = { PRIMARY = 1, IMPERSONATION = 2 }
M.LEVEL = { ANONYMOUS = 0, IDENTIFICATION = 1, IMPERSONATION = 2, DELEGATION = 3 }
M.ELEVATION = { DEFAULT = 1, FULL = 2, LIMITED = 3 }
M.MANDATORY = { NO_WRITE_UP = 0x1, NEW_PROCESS_MIN = 0x2 }
M.AUDIT = {
    OBJECT_ACCESS_SUCCESS = 0x1, OBJECT_ACCESS_FAILURE = 0x2,
    PRIVILEGE_USE_SUCCESS = 0x4, PRIVILEGE_USE_FAILURE = 0x8,
}
M.LOGON_TYPE = {
    INTERACTIVE = 2, NETWORK = 3, BATCH = 4, SERVICE = 5,
    NETWORK_CLEARTEXT = 8, NEW_CREDENTIALS = 9,
}
M.INTEGRITY = { UNTRUSTED = 0, LOW = 4096, MEDIUM = 8192, HIGH = 12288, SYSTEM = 16384 }

M.PRIV_ATTR = { ENABLED = 0x2, REMOVED = 0x4, RESET_ALL_DEFAULTS = 0x80000000 }
M.RESTRICT_WRITE_RESTRICTED = 0x1

M.GROUP = {
    MANDATORY = 0x01, ENABLED_BY_DEFAULT = 0x02, ENABLED = 0x04,
    OWNER = 0x08, USE_FOR_DENY_ONLY = 0x10, INTEGRITY = 0x20,
    INTEGRITY_ENABLED = 0x40, RESOURCE = 0x20000000, LOGON_ID = 0xC0000000,
}

M.CLASS = {
    USER = 0x01, GROUPS = 0x02, PRIVILEGES = 0x03, TYPE = 0x04,
    INTEGRITY_LEVEL = 0x05, OWNER = 0x06, PRIMARY_GROUP = 0x07,
    INTERACTIVITY_SCOPE = 0x08, RESTRICTED_SIDS = 0x09, SOURCE = 0x0A,
    STATISTICS = 0x0B, ORIGIN = 0x0C, ELEVATION_TYPE = 0x0D,
    DEVICE_GROUPS = 0x0E, APPCONTAINER_SID = 0x0F, CAPABILITIES = 0x10,
    MANDATORY_POLICY = 0x11, LOGON_TYPE = 0x12, LOGON_SID = 0x13,
    DEFAULT_DACL = 0x14, IMPERSONATION_LEVEL = 0x15, USER_CLAIMS = 0x16,
    DEVICE_CLAIMS = 0x17, PROJECTED_SUPPLEMENTARY_GIDS = 0x18,
}

-- Privilege bit indices (the LUID is the bit index).
M.PRIV = {
    CREATE_TOKEN = 2, ASSIGN_PRIMARY_TOKEN = 3, LOCK_MEMORY = 4,
    INCREASE_QUOTA = 5, TCB = 7, SECURITY = 8, TAKE_OWNERSHIP = 9,
    LOAD_DRIVER = 10, SYSTEM_PROFILE = 11, SYSTEMTIME = 12,
    PROFILE_SINGLE_PROCESS = 13, INCREASE_BASE_PRIORITY = 14,
    BACKUP = 17, RESTORE = 18, SHUTDOWN = 19, DEBUG = 20, AUDIT = 21,
    CHANGE_NOTIFY = 23, REMOTE_SHUTDOWN = 24, MANAGE_VOLUME = 28,
    IMPERSONATE = 29, RELABEL = 32, CREATE_SYMBOLIC_LINK = 35,
}
function M.bit(index) return 1 << index end

M.SYSTEM_LUID, M.ANONYMOUS_LOGON_LUID = 999, 998

-- SIDs -------------------------------------------------------------------

--- Binary SID from an authority and sub-authorities.
function M.sid(authority, ...)
    local subs = { ... }
    local out = string.pack("<I1I1", 1, #subs) .. string.pack(">I2I4", 0, authority)
    for _, s in ipairs(subs) do out = out .. string.pack("<I4", s) end
    return out
end

--- Parse a SID from `buf` at `pos` (1-based). Returns table, next pos.
function M.parse_sid(buf, pos)
    pos = pos or 1
    local rev, count = string.unpack("<I1I1", buf, pos)
    local hi, lo = string.unpack(">I2I4", buf, pos + 2)
    local subs = {}
    for i = 1, count do
        subs[i] = string.unpack("<I4", buf, pos + 8 + 4 * (i - 1))
    end
    return { revision = rev, authority = (hi << 32) | lo, subs = subs },
        pos + 8 + 4 * count
end

--- "S-1-5-18" from a binary SID.
function M.sid_string(bin)
    local s = M.parse_sid(bin)
    local out = "S-" .. s.revision .. "-" .. s.authority
    for _, sub in ipairs(s.subs) do out = out .. "-" .. sub end
    return out
end

M.SID = {
    EVERYONE = M.sid(1, 0),
    ANONYMOUS = M.sid(5, 7),
    AUTHENTICATED_USERS = M.sid(5, 11),
    LOCAL_SYSTEM = M.sid(5, 18),
    ADMINISTRATORS = M.sid(5, 32, 544),
    USERS = M.sid(5, 32, 545),
    OWNER_RIGHTS = M.sid(3, 4),
    -- A local account for tests to mint: S-1-5-21-<domain>-<rid>.
    TEST_USER = M.sid(5, 21, 1000, 2000, 3000, 1101),
    TEST_USER_2 = M.sid(5, 21, 1000, 2000, 3000, 1102),
    TEST_GROUP = M.sid(5, 21, 1000, 2000, 3000, 5001),
    TEST_GROUP_2 = M.sid(5, 21, 1000, 2000, 3000, 5002),
}
function M.label_sid(level) return M.sid(16, level) end

--- Logon SID for a session id: S-1-5-5-{hi}-{lo}.
function M.logon_sid(session_id)
    return M.sid(5, 5, session_id >> 32, session_id & 0xFFFFFFFF)
end

-- Handles ------------------------------------------------------------------

--- Open the caller's own token. `flags` may carry M.OPEN_REAL.
--- Returns fd, or nil, errno.
function M.open_self(who, access, flags)
    local r = who:syscall(M.SYS.OPEN_SELF_TOKEN, flags or 0,
        access or M.RIGHT.ALL_ACCESS)
    if r.ret < 0 then return nil, r.errno end
    return r.ret
end

function M.open_process(who, pidfd, access)
    local r = who:syscall(M.SYS.OPEN_PROCESS_TOKEN, pidfd,
        access or M.RIGHT.ALL_ACCESS)
    if r.ret < 0 then return nil, r.errno end
    return r.ret
end

function M.open_thread(who, pidfd, tid, access)
    local r = who:syscall(M.SYS.OPEN_THREAD_TOKEN, pidfd, tid,
        access or M.RIGHT.ALL_ACCESS)
    if r.ret < 0 then return nil, r.errno end
    return r.ret
end

--- pidfd_open(2) on a pid. Returns fd, or nil, errno.
function M.pidfd_open(who, pid)
    local r = who:syscall(434, pid, 0)
    if r.ret < 0 then return nil, r.errno end
    return r.ret
end

-- Query ---------------------------------------------------------------------

--- Query one information class. Returns the payload bytes (possibly
--- empty), or nil, errno. Two calls: a probe for the size, then the
--- read, exactly as a userspace client does.
function M.query(who, fd, class)
    local probe = who:syscall(sys.NR.ioctl, {
        args = { fd, M.IOC.QUERY, 0 },
        bufs = { string.pack("<I4I4I8", class, 0, 0) },
        ptrs = { 2 },
    })
    if probe.ret ~= 0 then return nil, probe.errno end
    local _, need = string.unpack("<I4I4", probe.out_bufs[1])
    if need == 0 then return "" end
    local r = who:syscall(sys.NR.ioctl, {
        args = { fd, M.IOC.QUERY, 0 },
        bufs = { string.pack("<I4I4I8", class, need, 0), string.rep("\0", need) },
        ptrs = { 2 },
        nested = { { parent = 1, child = 2, offset = 8 } },
    })
    if r.ret ~= 0 then return nil, r.errno end
    return r.out_bufs[2]:sub(1, need)
end

--- Raw query with a caller-chosen buffer length, for the size-contract
--- cases. Returns the raw syscall result plus the reported length.
function M.query_raw(who, fd, class, buf_len)
    local bufs = { string.pack("<I4I4I8", class, buf_len, 0) }
    local nested
    if buf_len > 0 then
        bufs[2] = string.rep("\0", buf_len)
        nested = { { parent = 1, child = 2, offset = 8 } }
    end
    local r = who:syscall(sys.NR.ioctl, {
        args = { fd, M.IOC.QUERY, 0 }, bufs = bufs, ptrs = { 2 }, nested = nested,
    })
    local _, reported = string.unpack("<I4I4", r.out_bufs[1])
    return r, reported
end

function M.query_u32(who, fd, class)
    local p, e = M.query(who, fd, class)
    if not p then return nil, e end
    return (string.unpack("<I4", p))
end

function M.query_u64(who, fd, class)
    local p, e = M.query(who, fd, class)
    if not p then return nil, e end
    return (string.unpack("<I8", p))
end

--- Parse a SID array payload into { {sid=bin, attributes=n}, ... }.
function M.parse_sid_array(payload)
    local count, pos = string.unpack("<I4", payload)
    local out = {}
    for i = 1, count do
        local len; len, pos = string.unpack("<I4", payload, pos)
        local sid = payload:sub(pos, pos + len - 1); pos = pos + len
        local attrs; attrs, pos = string.unpack("<I4", payload, pos)
        out[i] = { sid = sid, attributes = attrs }
    end
    return out
end

function M.groups(who, fd)
    local p, e = M.query(who, fd, M.CLASS.GROUPS)
    if not p then return nil, e end
    return M.parse_sid_array(p)
end

--- Find a group entry by binary SID.
function M.find_group(groups, sid)
    for i, g in ipairs(groups) do if g.sid == sid then return g, i end end
    return nil
end

--- The four privilege words: present, enabled, enabled_by_default, used.
function M.privileges(who, fd)
    local p, e = M.query(who, fd, M.CLASS.PRIVILEGES)
    if not p then return nil, e end
    local present, enabled, default, used = string.unpack("<I8I8I8I8", p)
    return { present = present, enabled = enabled, default = default, used = used }
end

function M.statistics(who, fd)
    local p, e = M.query(who, fd, M.CLASS.STATISTICS)
    if not p then return nil, e end
    local token_id, auth_id, modified_id, ttype, reserved, expiration =
        string.unpack("<I8I8I8I4I4I8", p)
    return { token_id = token_id, auth_id = auth_id, modified_id = modified_id,
        token_type = ttype, reserved = reserved, expiration = expiration }
end

function M.source(who, fd)
    local p, e = M.query(who, fd, M.CLASS.SOURCE)
    if not p then return nil, e end
    return { name = p:sub(1, 8), luid = (string.unpack("<I8", p, 9)) }
end

--- Integrity level as a number (the label SID's single sub-authority).
function M.integrity(who, fd)
    local p, e = M.query(who, fd, M.CLASS.INTEGRITY_LEVEL)
    if not p then return nil, e end
    return M.parse_sid(p).subs[1]
end

-- LogonSessions -----------------------------------------------------------------

--- kacs_create_logon_session. Returns the session id, or nil, errno.
function M.create_logon_session(who, spec)
    spec = spec or {}
    local pkg = spec.auth_package or "Negotiate"
    local user = spec.user_sid or M.SID.TEST_USER
    local buf = string.pack("<I1I2", spec.logon_type or M.LOGON_TYPE.INTERACTIVE, #pkg)
        .. pkg .. string.pack("<I4", #user) .. user
    local r = who:syscall(M.SYS.CREATE_LOGON_SESSION, {
        args = { 0, #buf }, bufs = { buf }, ptrs = { 0 },
    })
    if r.ret < 0 then return nil, r.errno end
    return r.ret
end

function M.destroy_empty_logon_session(who, id)
    return who:syscall(M.SYS.DESTROY_EMPTY_LOGON_SESSION, id)
end

-- CreateToken -------------------------------------------------------------------

--- Pack a SID_AND_ATTRIBUTES array section.
local function pack_sid_entries(entries)
    local out = {}
    for _, e in ipairs(entries or {}) do
        out[#out + 1] = string.pack("<I4", #e.sid) .. e.sid .. string.pack("<I4", e.attributes or 0)
    end
    return table.concat(out)
end

M.SPEC_HEADER_BYTES = 192
M.SPEC_VERSION = 2

--- Build a kacs_create_token spec. Every field has a workable default so a
--- case names only what it is about; the defaults mint an ordinary
--- interactive user: TEST_USER in Everyone + Authenticated Users +
--- TEST_GROUP, Medium integrity, NO_WRITE_UP, Primary at Delegation.
---
--- `spec.auth_id` is required — a LogonSession id from
--- create_logon_session. `spec.groups` is a list of { sid, attributes };
--- `spec.raw` lets a case overwrite header bytes after packing:
--- { { offset, bytes }, ... }.
function M.build_spec(spec)
    local ENABLED = M.GROUP.MANDATORY | M.GROUP.ENABLED_BY_DEFAULT | M.GROUP.ENABLED
    local user = spec.user_sid or M.SID.TEST_USER
    local groups = spec.groups or {
        { sid = M.SID.EVERYONE, attributes = ENABLED },
        { sid = M.SID.AUTHENTICATED_USERS, attributes = ENABLED },
        { sid = M.SID.TEST_GROUP, attributes = M.GROUP.ENABLED_BY_DEFAULT | M.GROUP.ENABLED },
    }
    local sections = {}
    local cursor = M.SPEC_HEADER_BYTES
    local function section(bytes)
        if not bytes or #bytes == 0 then return 0 end
        local off = cursor
        sections[#sections + 1] = bytes
        cursor = cursor + #bytes
        return off
    end
    local user_off = section(user)
    local groups_bytes = pack_sid_entries(groups)
    local groups_off = section(groups_bytes)
    local dacl_off = section(spec.default_dacl)
    local uclaims_off = section(spec.user_claims)
    local dclaims_off = section(spec.device_claims)
    local dgroups_bytes = pack_sid_entries(spec.device_groups)
    local dgroups_off = section(dgroups_bytes)
    local rsids_bytes = pack_sid_entries(spec.restricted_sids)
    local rsids_off = section(rsids_bytes)
    local csid_off = section(spec.confinement_sid)
    local ccaps_bytes = pack_sid_entries(spec.confinement_capabilities)
    local ccaps_off = section(ccaps_bytes)
    local supp = {}
    for _, g in ipairs(spec.supplementary_gids or {}) do supp[#supp + 1] = string.pack("<I4", g) end
    local supp_off = section(table.concat(supp))
    local rdg_bytes = pack_sid_entries(spec.restricted_device_groups)
    local rdg_off = section(rdg_bytes)
    local lcs_off = section(spec.lcs_credentials)

    local name = spec.source_name or "PITTest\0"
    name = (name .. string.rep("\0", 8)):sub(1, 8)

    local header = string.pack(
        "<I4" .. "I1I1I2" .. "I4I4" .. "I8I8" .. "I4I4I4I4" .. "I8I8" .. "I4I4" .. "c8I8"
        .. "I4I4I4" .. "I4I4" .. "I4I4" .. "I4I4" .. "I4I4" .. "I4I4" .. "I4I4" .. "I4I4"
        .. "I1I1I1I1" .. "I4I4" .. "I4I4" .. "I8" .. "I4" .. "I4",
        spec.version or M.SPEC_VERSION,
        spec.token_type or M.TYPE.PRIMARY,
        spec.impersonation_level or M.LEVEL.DELEGATION,
        spec.reserved0 or 0,
        spec.integrity_level or M.INTEGRITY.MEDIUM,
        spec.mandatory_policy or M.MANDATORY.NO_WRITE_UP,
        spec.privs_present or 0,
        spec.privs_enabled or 0,
        spec.reserved1 or 0,
        spec.projected_uid or 1101,
        spec.projected_gid or 1101,
        spec.audit_policy or 0,
        spec.expiration or 0,
        spec.auth_id,
        spec.owner_sid_index or 0,
        spec.primary_group_index or 0,
        name,
        spec.source_id or 0x5049545F54455354,
        user_off, groups_off, #groups,
        dacl_off, spec.default_dacl and #spec.default_dacl or 0,
        uclaims_off, spec.user_claims and #spec.user_claims or 0,
        dclaims_off, spec.device_claims and #spec.device_claims or 0,
        dgroups_off, #(spec.device_groups or {}),
        rsids_off, #(spec.restricted_sids or {}),
        csid_off, spec.confinement_sid and #spec.confinement_sid or 0,
        ccaps_off, #(spec.confinement_capabilities or {}),
        spec.confinement_exempt and 1 or 0,
        spec.write_restricted and 1 or 0,
        spec.user_deny_only and 1 or 0,
        spec.isolation_boundary and 1 or 0,
        supp_off, #(spec.supplementary_gids or {}),
        rdg_off, #(spec.restricted_device_groups or {}),
        spec.origin or 0,
        spec.interactivity_scope or 1,
        lcs_off)
    assert(#header == M.SPEC_HEADER_BYTES, "spec header is " .. #header)
    local blob = header .. table.concat(sections)
    for _, patch in ipairs(spec.raw or {}) do
        local off, bytes = patch[1], patch[2]
        blob = blob:sub(1, off) .. bytes .. blob:sub(off + #bytes + 1)
    end
    return blob
end

--- kacs_create_token from a spec table (see build_spec) or a prebuilt
--- blob. Returns fd, or nil, errno.
function M.create(who, spec)
    local blob = type(spec) == "string" and spec or M.build_spec(spec)
    local r = who:syscall(M.SYS.CREATE_TOKEN, {
        args = { 0, #blob }, bufs = { blob }, ptrs = { 0 },
    })
    if r.ret < 0 then return nil, r.errno end
    return r.ret
end

--- A fresh LogonSession plus a token in it. Returns fd, session id.
function M.mint(who, spec)
    spec = spec or {}
    local sid, e = M.create_logon_session(who, {
        logon_type = spec.logon_type, user_sid = spec.user_sid,
        auth_package = spec.auth_package,
    })
    if not sid then return nil, e end
    spec.auth_id = spec.auth_id or sid
    local fd, e2 = M.create(who, spec)
    if not fd then return nil, e2 end
    return fd, sid
end

-- Derivation -------------------------------------------------------------------

--- KACS_IOC_DUPLICATE. Returns fd, or nil, errno.
function M.duplicate(who, fd, how)
    how = how or {}
    local r = who:syscall(sys.NR.ioctl, {
        args = { fd, M.IOC.DUPLICATE, 0 },
        bufs = { string.pack("<I4I4I4i4", how.access or M.RIGHT.ALL_ACCESS,
            how.token_type or M.TYPE.PRIMARY,
            how.impersonation_level or M.LEVEL.DELEGATION, -1) },
        ptrs = { 2 },
    })
    if r.ret ~= 0 then return nil, r.errno end
    return (string.unpack("<i4", r.out_bufs[1], 13))
end

--- KACS_IOC_RESTRICT (FilterToken). `how`: privs (u64 mask to delete),
--- deny_indices (list of group indices), restrict_sids (list of binary
--- SIDs), flags. Returns fd, or nil, errno.
function M.restrict(who, fd, how)
    how = how or {}
    local data = {}
    for _, i in ipairs(how.deny_indices or {}) do data[#data + 1] = string.pack("<I4", i) end
    for _, s in ipairs(how.restrict_sids or {}) do data[#data + 1] = s end
    if how.raw_data then data = { how.raw_data } end
    local blob = table.concat(data)
    local bufs = { string.pack("<I8I4I4I4I4I8i4I4",
        how.privs or 0, #(how.deny_indices or {}), #(how.restrict_sids or {}),
        how.data_len or #blob, how.flags or 0, 0, -1, 0) }
    local nested
    if #blob > 0 then
        bufs[2] = blob
        nested = { { parent = 1, child = 2, offset = 24 } }
    end
    local r = who:syscall(sys.NR.ioctl, {
        args = { fd, M.IOC.RESTRICT, 0 }, bufs = bufs, ptrs = { 2 }, nested = nested,
    })
    if r.ret ~= 0 then return nil, r.errno end
    return (string.unpack("<i4", r.out_bufs[1], 33))
end

function M.install(who, fd) return who:syscall(sys.NR.ioctl, fd, M.IOC.INSTALL, 0) end
function M.impersonate(who, fd) return who:syscall(sys.NR.ioctl, fd, M.IOC.IMPERSONATE, 0) end
function M.revert(who) return who:syscall(M.SYS.REVERT) end

-- Adjustment --------------------------------------------------------------------

--- KACS_IOC_ADJUST_PRIVS with a list of { luid, attributes }. Returns the
--- raw result and the previous_enabled word.
function M.adjust_privs(who, fd, entries)
    local data = {}
    for _, e in ipairs(entries) do data[#data + 1] = string.pack("<I4I4", e[1], e[2]) end
    local blob = table.concat(data)
    local r = who:syscall(sys.NR.ioctl, {
        args = { fd, M.IOC.ADJUST_PRIVS, 0 },
        bufs = { string.pack("<I4I4I8I8", #entries, 0, 0, 0), blob },
        ptrs = { 2 },
        nested = { { parent = 1, child = 2, offset = 8 } },
    })
    local previous = string.unpack("<I8", r.out_bufs[1], 17)
    return r, previous
end

function M.enable_priv(who, fd, luid) return M.adjust_privs(who, fd, { { luid, M.PRIV_ATTR.ENABLED } }) end
function M.disable_priv(who, fd, luid) return M.adjust_privs(who, fd, { { luid, 0 } }) end
function M.remove_priv(who, fd, luid) return M.adjust_privs(who, fd, { { luid, M.PRIV_ATTR.REMOVED } }) end
function M.reset_privs(who, fd) return M.adjust_privs(who, fd, { { 0, M.PRIV_ATTR.RESET_ALL_DEFAULTS } }) end

--- KACS_IOC_ADJUST_GROUPS with { index, enable } entries. Returns the raw
--- result and the previous-state mask as sixteen u64 words.
function M.adjust_groups(who, fd, entries, count_override)
    local data = {}
    for _, e in ipairs(entries) do data[#data + 1] = string.pack("<I4I4", e[1], e[2]) end
    local blob = table.concat(data)
    local bufs = { string.pack("<I4I4I8", count_override or #entries, 0, 0) .. string.rep("\0", 128) }
    local nested
    if #blob > 0 then
        bufs[2] = blob
        nested = { { parent = 1, child = 2, offset = 8 } }
    end
    local r = who:syscall(sys.NR.ioctl, {
        args = { fd, M.IOC.ADJUST_GROUPS, 0 }, bufs = bufs, ptrs = { 2 }, nested = nested,
    })
    local words = {}
    for i = 1, 16 do words[i] = string.unpack("<I8", r.out_bufs[1], 17 + 8 * (i - 1)) end
    return r, words
end
M.GROUP_RESET_INDEX = 0xFFFFFFFF

--- KACS_IOC_ADJUST_DEFAULT. `how`: dacl (binary ACL or nil to clear),
--- owner_index, group_index.
function M.adjust_default(who, fd, how)
    local bufs = { string.pack("<I8I4I2I2", 0, how.dacl and #how.dacl or 0,
        how.owner_index or 0, how.group_index or 0) }
    local nested
    if how.dacl then
        bufs[2] = how.dacl
        nested = { { parent = 1, child = 2, offset = 0 } }
    end
    return who:syscall(sys.NR.ioctl, {
        args = { fd, M.IOC.ADJUST_DEFAULT, 0 }, bufs = bufs, ptrs = { 2 }, nested = nested,
    })
end

function M.adjust_interactivity_scope(who, fd, scope)
    return who:syscall(sys.NR.ioctl, {
        args = { fd, M.IOC.ADJUST_INTERACTIVITY_SCOPE, 0 },
        bufs = { string.pack("<I4", scope) }, ptrs = { 2 },
    })
end

-- Linked pairs ------------------------------------------------------------------

function M.link(who, any_fd, elevated_fd, filtered_fd, session_id)
    return who:syscall(sys.NR.ioctl, {
        args = { any_fd, M.IOC.LINK_TOKENS, 0 },
        bufs = { string.pack("<i4i4I8", elevated_fd, filtered_fd, session_id) },
        ptrs = { 2 },
    })
end

--- Returns fd, or nil, errno.
function M.get_linked(who, fd)
    local r = who:syscall(sys.NR.ioctl, {
        args = { fd, M.IOC.GET_LINKED_TOKEN, 0 },
        bufs = { string.pack("<i4", -1) }, ptrs = { 2 },
    })
    if r.ret ~= 0 then return nil, r.errno end
    return (string.unpack("<i4", r.out_bufs[1]))
end

-- Token descriptors ---------------------------------------------------------------

--- The token's own descriptor through the fd (AT_EMPTY_PATH form of
--- kacs_get_sd). Returns bytes, or nil, errno.
function M.get_sd(who, fd, info)
    local r = who:syscall(kacs.SYS.GET_SD, {
        args = { fd, 0, info or (kacs.SI.OWNER | kacs.SI.GROUP | kacs.SI.DACL), 0, 4096, sys.AT_EMPTY_PATH },
        bufs = { sys.cstr(""), string.rep("\0", 4096) },
        ptrs = { 1, 3 },
    })
    if r.ret < 0 then return nil, r.errno end
    return r.out_bufs[2]:sub(1, r.ret)
end

function M.set_sd(who, fd, descriptor, info)
    return who:syscall(kacs.SYS.SET_SD, {
        args = { fd, 0, info or kacs.SI.DACL, 0, #descriptor, sys.AT_EMPTY_PATH },
        bufs = { sys.cstr(""), descriptor },
        ptrs = { 1, 3 },
    })
end

--- Parse a self-relative descriptor: owner, group (binary SIDs or nil),
--- dacl = list of { type, flags, mask, sid } or nil when absent, control.
function M.parse_sd(bytes)
    local rev, sbz, control, owner_off, group_off, sacl_off, dacl_off =
        string.unpack("<I1I1I2I4I4I4I4", bytes)
    local out = { control = control }
    if owner_off ~= 0 then out.owner = (function() local s, n = M.parse_sid(bytes, owner_off + 1); return bytes:sub(owner_off + 1, n - 1) end)() end
    if group_off ~= 0 then out.group = (function() local s, n = M.parse_sid(bytes, group_off + 1); return bytes:sub(group_off + 1, n - 1) end)() end
    local function parse_acl(off)
        local acl = {}
        local _, _, size, count = string.unpack("<I1I1I2I2", bytes, off + 1)
        local pos = off + 9
        for _ = 1, count do
            local atype, aflags, asize = string.unpack("<I1I1I2", bytes, pos)
            local ace = { type = atype, flags = aflags, size = asize }
            if atype <= 0x03 or atype == 0x11 or atype == 0x13 or atype == 0x14 then
                ace.mask = string.unpack("<I4", bytes, pos + 4)
                local _, n = M.parse_sid(bytes, pos + 8)
                ace.sid = bytes:sub(pos + 8, n - 1)
            end
            acl[#acl + 1] = ace
            pos = pos + asize
        end
        return acl
    end
    if dacl_off ~= 0 then out.dacl = parse_acl(dacl_off) end
    if sacl_off ~= 0 then out.sacl = parse_acl(sacl_off) end
    return out
end

--- Find the first ACE in `acl` for `sid` (binary), or nil.
function M.find_ace(acl, sid, ace_type)
    for _, a in ipairs(acl or {}) do
        if a.sid == sid and (ace_type == nil or a.type == ace_type) then return a end
    end
    return nil
end

-- Workers ----------------------------------------------------------------------

--- Run `fn(worker)` in a worker whose primary token is `fd`'s token,
--- installed there: the worker opens nothing — the fd is inherited only
--- if the caller made it so — so callers pass a spec and the worker
--- mints and installs in its own context. Returns nothing; raises on
--- failure inside `fn`.
---
--- `spec` is a build_spec table (auth_id optional: a fresh session is
--- created). `opts.keep_privs` leaves the agent's privileges on the
--- minted token — default is a token with exactly the privileges the
--- spec names.
function M.as_principal(t, vm, spec, fn)
    local worker = vm:spawn_worker()
    local ok, err = pcall(function()
        local fd, sid = M.mint(worker, spec)
        assert(fd, "mint: " .. sys.errname(sid or 0))
        local r = M.install(worker, fd)
        assert(r.ret == 0, "KACS_IOC_INSTALL: " .. sys.errname(r.errno))
        sys.close(worker, fd)
        fn(worker, sid)
    end)
    worker:kill(); worker:join()
    if not ok then error(err, 0) end
end

--- A handle on `worker`'s current *effective* token, opened by `vm`.
---
--- A thread that has impersonated cannot always read its own effective
--- token back: the impersonation gate may have capped the level to
--- Identification, and an Identification-level token is barred from
--- AccessCheck (§3.5.1) — including the check on the token's own
--- descriptor. The agent is SYSTEM and can open any thread's token, so
--- the impersonation cases read the result from outside instead.
---
--- A worker issues every syscall on one thread, so its tid is its pid.
--- Returns fd, or nil, errno.
function M.effective_token(vm, worker, access)
    local pid = worker:syscall(sys.NR.getpid).ret
    local pidfd, e = M.pidfd_open(vm, pid)
    if not pidfd then return nil, e end
    local fd, e2 = M.open_thread(vm, pidfd, pid, access or M.RIGHT.ALL_ACCESS)
    sys.close(vm, pidfd)
    if not fd then return nil, e2 end
    return fd
end

--- What `worker`'s thread is currently acting as: `level`, `type`,
--- `user` (binary SID) and `integrity`. Returns nil, errno on failure.
function M.effective(vm, worker)
    local fd, e = M.effective_token(vm, worker, M.RIGHT.QUERY)
    if not fd then return nil, e end
    local out = {
        level = M.query_u32(vm, fd, M.CLASS.IMPERSONATION_LEVEL),
        type = M.query_u32(vm, fd, M.CLASS.TYPE),
        user = M.query(vm, fd, M.CLASS.USER),
        integrity = M.integrity(vm, fd),
    }
    sys.close(vm, fd)
    return out
end

return M
