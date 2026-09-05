-- AccessCheck from userspace: kacs_access_check, kacs_access_check_list,
-- and a full security-descriptor builder (owner, group, DACL, SACL —
-- helpers/kacs.descriptor emits a DACL only).
--
-- Every number is from PKM §3.A. The request struct carries eight
-- pointers, so a call is one parent buffer plus a child buffer per
-- present pointer, wired with `nested`.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local token = require("helpers.token")

local M = {}

M.SYS = { ACCESS_CHECK = 1023, ACCESS_CHECK_LIST = 1024, SET_CAAP = 1025 }
M.ARGS_SIZE, M.ARGS_V1_SIZE = 136, 40

M.ACE = {
    ALLOWED = 0x00, DENIED = 0x01, AUDIT = 0x02, ALARM = 0x03,
    ALLOWED_OBJECT = 0x05, DENIED_OBJECT = 0x06, AUDIT_OBJECT = 0x07, ALARM_OBJECT = 0x08,
    ALLOWED_CALLBACK = 0x09, DENIED_CALLBACK = 0x0A,
    MANDATORY_LABEL = 0x11, RESOURCE_ATTRIBUTE = 0x12, SCOPED_POLICY_ID = 0x13,
    PROCESS_TRUST_LABEL = 0x14, ACCESS_FILTER = 0x15,
}
M.ACE_FLAG = {
    OBJECT_INHERIT = 0x01, CONTAINER_INHERIT = 0x02, NO_PROPAGATE = 0x04,
    INHERIT_ONLY = 0x08, INHERITED = 0x10, SUCCESSFUL_ACCESS = 0x40, FAILED_ACCESS = 0x80,
}
M.LABEL = { NO_READ_UP = 0x1, NO_WRITE_UP = 0x2, NO_EXECUTE_UP = 0x4 }
M.CONTROL = {
    DACL_PRESENT = 0x0004, SACL_PRESENT = 0x0010, DACL_PROTECTED = 0x1000,
    SACL_PROTECTED = 0x2000, SELF_RELATIVE = 0x8000,
}
M.INTENT = { BACKUP = 0x1, RESTORE = 0x2 }

-- Standard and generic bits.
M.STD = {
    DELETE = 0x00010000, READ_CONTROL = 0x00020000, WRITE_DAC = 0x00040000,
    WRITE_OWNER = 0x00080000, SYNCHRONIZE = 0x00100000,
    ACCESS_SYSTEM_SECURITY = 0x01000000, MAXIMUM_ALLOWED = 0x02000000,
    GENERIC_ALL = 0x10000000, GENERIC_EXECUTE = 0x20000000,
    GENERIC_WRITE = 0x40000000, GENERIC_READ = 0x80000000,
}

--- The file object's generic mapping (the Windows FILE_GENERIC_* values,
--- which libp builds from <pkm/file.h>).
M.FILE_MAPPING = { read = 0x00120089, write = 0x00120116, execute = 0x001200A0, all = 0x001F01FF }
--- The token object's mapping (§3.2.8).
M.TOKEN_MAPPING = {
    read = token.RIGHT.QUERY | M.STD.READ_CONTROL,
    write = token.RIGHT.ADJUST_PRIVS | token.RIGHT.ADJUST_GROUPS | token.RIGHT.ADJUST_DEFAULT | M.STD.WRITE_DAC,
    execute = token.RIGHT.IMPERSONATE,
    all = token.RIGHT.ALL_ACCESS,
}

-- Descriptors ----------------------------------------------------------------------

--- One ACE. `ace_type`, `mask`, `sid` (binary), optional `flags`.
--- Object ACEs (0x05–0x08) take `object_type` / `inherited_object_type`
--- as 16-byte GUIDs; callback ACEs take `condition` bytes appended.
function M.ace(ace_type, mask, sid, flags, extra)
    extra = extra or {}
    local body
    if ace_type >= 0x05 and ace_type <= 0x08 then
        local oflags, guids = 0, ""
        if extra.object_type then oflags = oflags | 1; guids = guids .. extra.object_type end
        if extra.inherited_object_type then oflags = oflags | 2; guids = guids .. extra.inherited_object_type end
        body = string.pack("<I4I4", mask, oflags) .. guids .. sid
    else
        body = string.pack("<I4", mask) .. sid
    end
    body = body .. (extra.condition or "")
    return string.pack("<I1I1I2", ace_type, flags or 0, 4 + #body) .. body
end

--- An ACL (revision 2, or 4 when any ACE is an object ACE) from ACEs.
function M.acl(aces, revision)
    local body = table.concat(aces or {})
    if not revision then
        revision = 2
        for _, a in ipairs(aces or {}) do
            local t = a:byte(1)
            if t >= 0x05 and t <= 0x08 then revision = 4 end
        end
    end
    return string.pack("<I1I1I2I2I2", revision, 0, 8 + #body, #(aces or {}), 0) .. body
end

--- A self-relative descriptor. `d`: owner, group (binary SIDs or nil),
--- dacl (ACL bytes; nil = no DACL, "" impossible — use M.acl({}) for an
--- empty one), sacl, control (extra bits OR'd in).
function M.sd(d)
    local control = M.CONTROL.SELF_RELATIVE | (d.control or 0)
    local pos, parts = 20, {}
    local function place(bytes)
        if not bytes then return 0 end
        local off = pos; parts[#parts + 1] = bytes; pos = pos + #bytes
        return off
    end
    local owner_off, group_off = place(d.owner), place(d.group)
    local sacl_off, dacl_off = 0, 0
    if d.sacl then control = control | M.CONTROL.SACL_PRESENT; sacl_off = place(d.sacl) end
    if d.dacl then control = control | M.CONTROL.DACL_PRESENT; dacl_off = place(d.dacl) end
    return string.pack("<I1I1I2I4I4I4I4", 1, 0, control, owner_off, group_off, sacl_off, dacl_off)
        .. table.concat(parts)
end

--- Mandatory label ACE: S-1-16-<level> with a policy mask.
function M.label_ace(level, policy, flags)
    return M.ace(M.ACE.MANDATORY_LABEL, policy or M.LABEL.NO_WRITE_UP, token.label_sid(level), flags)
end

--- Process trust label ACE: S-1-19-<type>-<trust> with the mask a
--- non-dominant caller is limited to.
function M.trust_label_ace(pip_type, pip_trust, mask, flags)
    return M.ace(M.ACE.PROCESS_TRUST_LABEL, mask, token.sid(19, pip_type, pip_trust), flags)
end

--- A plain descriptor: SYSTEM-owned, DACL from `aces`, optional sacl.
function M.simple(aces, opts)
    opts = opts or {}
    return M.sd({
        owner = opts.owner or token.SID.LOCAL_SYSTEM,
        group = opts.group or token.SID.LOCAL_SYSTEM,
        dacl = aces and M.acl(aces) or nil,
        sacl = opts.sacl,
    })
end

-- The check ---------------------------------------------------------------------------

--- kacs_access_check. `req`:
---   token_fd (default -1: the caller's effective token), sd (bytes),
---   desired, mapping ({read,write,execute,all}, default FILE_MAPPING),
---   self_sid, intent, tree (list of {level, guid}), claims (bytes),
---   pip_type, pip_trust, audit_context (bytes), caller_size.
--- Returns a table: ret, errno, granted, continuous_audit,
--- staging_mismatch (numbers). On success the syscall returns the
--- granted mask itself (non-negative; granted_out is written too); a
--- denial verdict is -1/EACCES; other negative returns are errors.
--- `ok` is ret >= 0; `denied` is a -1/EACCES verdict.
function M.check(who, req)
    local mapping = req.mapping or M.FILE_MAPPING
    local bufs, nested = {}, {}
    local function child(bytes, offset)
        if not bytes then return 0 end
        bufs[#bufs + 1] = bytes
        nested[#nested + 1] = { parent = 1, child = #bufs, offset = offset }
        return #bytes
    end
    local tree
    if req.tree then
        local parts = {}
        for _, n in ipairs(req.tree) do
            parts[#parts + 1] = string.pack("<I2I2", n.level, 0) .. (n.guid or string.rep("\0", 16))
        end
        tree = table.concat(parts)
    end
    -- Parent first so nested children index from 2.
    bufs[1] = ""
    local sd_len = child(req.sd, 8)
    local self_len = child(req.self_sid, 40)
    child(tree, 56)
    local claims_len = child(req.claims, 72)
    child(string.rep("\0", 4), 88)              -- granted_out
    local audit_len = child(req.audit_context, 104)
    child(string.rep("\0", 4), 120)             -- continuous_audit_out
    child(string.rep("\0", 4), 128)             -- staging_mismatch_out
    bufs[1] = string.pack("<I4i4I8I4I4I4I4I4I4I8I4I4I8I4I4I8I4I4I8I4I4I8I4I4I8I8",
        req.caller_size or M.ARGS_SIZE, req.token_fd or -1,
        0, sd_len, req.desired or 0,
        mapping.read, mapping.write, mapping.execute, mapping.all,
        0, self_len, req.intent or 0,
        0, req.tree and #req.tree or 0, 0,
        0, claims_len, 0,
        0, req.pip_type or 0, req.pip_trust or 0,
        0, audit_len, 0,
        0, 0)
    assert(#bufs[1] == M.ARGS_SIZE, "args are " .. #bufs[1])
    local r = who:syscall(M.SYS.ACCESS_CHECK, {
        args = { 0 }, bufs = bufs, ptrs = { 0 }, nested = nested,
    })
    -- Locate the three output children by their offsets.
    local out = { ret = r.ret, errno = r.errno, ok = r.ret >= 0, denied = (r.ret == -1 and r.errno == 13) }
    for _, n in ipairs(nested) do
        local b = r.out_bufs[n.child]
        if n.offset == 88 then out.granted = string.unpack("<I4", b)
        elseif n.offset == 120 then out.continuous_audit = string.unpack("<I4", b)
        elseif n.offset == 128 then out.staging_mismatch = string.unpack("<I4", b) end
    end
    return out
end

--- kacs_access_check_list: as check(), with `req.tree` required; returns
--- the same table plus `nodes` = list of { granted, status }.
function M.check_list(who, req)
    local mapping = req.mapping or M.FILE_MAPPING
    -- bufs[1] is the args block (arg slot 0), bufs[2] the results array
    -- (arg slot 1); nested children follow from index 3.
    local bufs, nested = { "", string.rep("\0", 8 * #req.tree) }, {}
    local function child(bytes, offset)
        if not bytes then return 0 end
        bufs[#bufs + 1] = bytes
        nested[#nested + 1] = { parent = 1, child = #bufs, offset = offset }
        return #bytes
    end
    local parts = {}
    for _, n in ipairs(req.tree) do
        parts[#parts + 1] = string.pack("<I2I2", n.level, 0) .. (n.guid or string.rep("\0", 16))
    end
    local sd_len = child(req.sd, 8)
    local self_len = child(req.self_sid, 40)
    child(table.concat(parts), 56)
    local claims_len = child(req.claims, 72)
    child(string.rep("\0", 4), 88)
    local audit_len = child(req.audit_context, 104)
    child(string.rep("\0", 4), 120)
    child(string.rep("\0", 4), 128)
    bufs[1] = string.pack("<I4i4I8I4I4I4I4I4I4I8I4I4I8I4I4I8I4I4I8I4I4I8I4I4I8I8",
        req.caller_size or M.ARGS_SIZE, req.token_fd or -1,
        0, sd_len, req.desired or 0,
        mapping.read, mapping.write, mapping.execute, mapping.all,
        0, self_len, req.intent or 0,
        0, #req.tree, 0,
        0, claims_len, 0,
        0, req.pip_type or 0, req.pip_trust or 0,
        0, audit_len, 0,
        0, 0)
    local r = who:syscall(M.SYS.ACCESS_CHECK_LIST, {
        args = { 0, 0, #req.tree }, bufs = bufs, ptrs = { 0, 1 }, nested = nested,
    })
    local out = { ret = r.ret, errno = r.errno, ok = r.ret >= 0, denied = (r.ret == -1 and r.errno == 13), nodes = {} }
    for _, n in ipairs(nested) do
        local b = r.out_bufs[n.child]
        if n.offset == 88 then out.granted = string.unpack("<I4", b)
        elseif n.offset == 120 then out.continuous_audit = string.unpack("<I4", b)
        elseif n.offset == 128 then out.staging_mismatch = string.unpack("<I4", b) end
    end
    local rb = r.out_bufs[2]
    for i = 1, #req.tree do
        local g, st = string.unpack("<I4i4", rb, 1 + 8 * (i - 1))
        out.nodes[i] = { granted = g, status = st }
    end
    return out
end

--- kacs_set_caap. `spec` bytes or nil to remove. Returns the raw result.
function M.set_caap(who, policy_sid, spec)
    local bufs, ptrs = { policy_sid }, { 0 }
    if spec then bufs[2] = spec; ptrs[2] = 2 end
    return who:syscall(M.SYS.SET_CAAP, {
        args = { 0, #policy_sid, 0, spec and #spec or 0 }, bufs = bufs, ptrs = ptrs,
    })
end

--- Build a CAAP spec from rules: each { applies_to=bytes|nil,
--- effective_dacl=bytes, effective_sacl=, staged_dacl=, staged_sacl= }.
function M.caap_spec(rules)
    local out = { string.pack("<I1I4", 1, #rules) }
    for _, r in ipairs(rules) do
        for _, k in ipairs({ "applies_to", "effective_dacl", "effective_sacl", "staged_dacl", "staged_sacl" }) do
            local v = r[k] or ""
            out[#out + 1] = string.pack("<I4", #v) .. v
        end
    end
    return table.concat(out)
end

return M
