-- LABEL is a projection/merge of mandatory-label ACEs, using the same
-- access and integrity-assignment rules as file security descriptors.
local sys = require("helpers.sys")
local lcs = require("helpers.lcs")
local token = require("helpers.token")
local access = require("helpers.access")

local vm = provium:vm("v", "kernel-only"):boot()
local R, SI = lcs.RIGHT, lcs.SI
local C, AF = access.CONTROL, access.ACE_FLAG
local LOW, MEDIUM, HIGH = token.INTEGRITY.LOW, token.INTEGRITY.MEDIUM, token.INTEGRITY.HIGH
local AUDIT = access.ace(access.ACE.AUDIT, R.QUERY_VALUE, token.SID.EVERYONE,
    AF.SUCCESSFUL_ACCESS)
local DACL = access.acl({ access.ace(access.ACE.ALLOWED, lcs.KEY_ALL_ACCESS,
    token.SID.EVERYONE) })
local FLAGS = C.DACL_PROTECTED | C.SACL_PROTECTED
local function label(level)
    return access.sd({ sacl = access.acl({ access.label_ace(level) }) })
end
local initial = access.sd({ owner = token.SID.LOCAL_SYSTEM, group = token.SID.EVERYONE,
    dacl = DACL, control = FLAGS,
    sacl = access.acl({ AUDIT, access.label_ace(MEDIUM) }) })
local src = lcs.source(vm, { hives = { { name = "Machine", sd = lcs.machine_root_sd() } } })
for _, name in ipairs({ "Read", "Merge", "Clear", "Last", "Rights", "Invalid",
    "Levels", "Privileged", "Disabled", "SaclDenied", "SaclAllowed" }) do
    local sd = initial
    if name == "Last" then
        sd = access.sd({ owner = token.SID.LOCAL_SYSTEM, dacl = DACL,
            control = FLAGS, sacl = access.acl({ access.label_ace(MEDIUM) }) })
    end
    src:key("Machine\\Labels\\" .. name, { sd = sd })
end
assert(src:register())
src:pump()
local system = vm:spawn_worker()

local function open(t, w, name, rights)
    local r = lcs.open_key(src, w, -1, "Machine\\Labels\\" .. name, rights)
    t:assert(r.ret >= 0, "open " .. name .. ": " .. sys.errname(r.errno or 0))
    return r.ret
end

local ENABLED = token.GROUP.MANDATORY | token.GROUP.ENABLED_BY_DEFAULT | token.GROUP.ENABLED
local function as_user(t, privileges, fn, enabled)
    token.as_principal(t, vm, {
        integrity_level = MEDIUM, privs_present = privileges,
        privs_enabled = enabled == nil and privileges or enabled,
        groups = {
            { sid = token.SID.EVERYONE, attributes = ENABLED },
            { sid = token.SID.AUTHENTICATED_USERS, attributes = ENABLED },
            -- Base-key writes require this group independently of label access.
            { sid = token.SID.ADMINISTRATORS, attributes = ENABLED },
        },
    }, fn)
end

local function get(t, w, fd, selector)
    local r = lcs.get_security(src, w, fd, selector)
    t:assert_eq(r.ret, 0, "get security: " .. sys.errname(r.errno or 0))
    return access.parse_sd(r.sd), r.sd
end

local function full(t, name)
    local fd = open(t, system, name, R.READ_CONTROL | R.ACCESS_SYSTEM_SECURITY)
    local sd = get(t, system, fd, SI.ALL)
    sys.close(system, fd)
    return sd
end

local function denied(t, r, errno)
    t:assert_eq(r.ret, -1, "operation refused")
    t:assert_eq(r.errno, errno, sys.errname(errno))
end

test("LABEL query needs only READ_CONTROL and does not expose audit ACEs",
    { spec = "PKM *inherit.label-access-and-projection" }, function(t)
        as_user(t, 0, function(w)
            local fd = open(t, w, "Read", R.READ_CONTROL)
            local sd = get(t, w, fd, SI.LABEL)
            t:assert_eq(sd.owner, nil, "owner was not selected")
            t:assert_eq(sd.group, nil, "group was not selected")
            t:assert_eq(sd.dacl, nil, "DACL was not selected")
            t:assert_eq(#sd.sacl.aces, 1, "only the mandatory label is exposed")
            t:assert_eq(sd.sacl.aces[1].type, access.ACE.MANDATORY_LABEL)
            t:assert_eq(sd.sacl.aces[1].sid, token.label_sid(MEDIUM))
            denied(t, lcs.get_security(src, w, fd, SI.SACL), sys.E.ACCES)
            sys.close(w, fd)
        end)
    end)

test("LABEL set uses WRITE_OWNER and preserves the other descriptor components",
    { spec = "PKM *inherit.label-merge-preserves-other-security" }, function(t)
        as_user(t, 0, function(w)
            local fd = open(t, w, "Merge", R.WRITE_OWNER)
            t:assert_eq(lcs.set_security(src, w, fd, SI.LABEL, label(LOW)).ret, 0)
            sys.close(w, fd)
        end)
        local sd = full(t, "Merge")
        t:assert_eq(sd.owner, token.SID.LOCAL_SYSTEM)
        t:assert_eq(sd.group, token.SID.EVERYONE)
        t:assert_eq(sd.control & FLAGS, FLAGS, "ACL protection flags survive")
        t:assert_eq(#sd.dacl.aces, 1)
        t:assert_eq(sd.dacl.aces[1].mask, lcs.KEY_ALL_ACCESS)
        t:assert_eq(sd.dacl.aces[1].sid, token.SID.EVERYONE)
        t:assert_eq(#sd.sacl.aces, 2, "label and audit ACE survive")
        t:assert_eq(sd.sacl.aces[1].sid, token.label_sid(LOW))
        t:assert_eq(sd.sacl.aces[2].type, access.ACE.AUDIT)
        t:assert_eq(sd.sacl.aces[2].mask, R.QUERY_VALUE)
        t:assert_eq(sd.sacl.aces[2].flags, AF.SUCCESSFUL_ACCESS)
        t:assert_eq(sd.sacl.aces[2].sid, token.SID.EVERYONE)
    end)

test("an absent input SACL clears only the mandatory label",
    { spec = "PKM *inherit.label-merge-preserves-other-security" }, function(t)
        as_user(t, 0, function(w)
            local fd = open(t, w, "Clear", R.WRITE_OWNER | R.READ_CONTROL)
            t:assert_eq(lcs.set_security(src, w, fd, SI.LABEL, access.sd({})).ret, 0)
            t:assert_eq(get(t, w, fd, SI.LABEL).sacl, nil, "no explicit label remains")
            sys.close(w, fd)
        end)
        local sd = full(t, "Clear")
        t:assert_eq(#sd.sacl.aces, 1)
        t:assert_eq(sd.sacl.aces[1].type, access.ACE.AUDIT)
        t:assert_eq(sd.control & FLAGS, FLAGS)
    end)

test("clearing the last label preserves SACL protection even without a remaining ACL",
    { spec = "PKM *inherit.label-merge-preserves-other-security" }, function(t)
        local fd = open(t, system, "Last", R.WRITE_OWNER | R.READ_CONTROL)
        t:assert_eq(lcs.set_security(src, system, fd, SI.LABEL, access.sd({})).ret, 0)
        local sd = get(t, system, fd, SI.LABEL)
        t:assert_eq(sd.sacl, nil)
        t:assert_eq(sd.control & C.SACL_PRESENT, 0)
        t:assert_eq(sd.control & C.SACL_PROTECTED, C.SACL_PROTECTED)
        sys.close(system, fd)
    end)

test("cached rights for another component do not grant LABEL read or write",
    { spec = "PKM *inherit.label-access-and-projection" }, function(t)
        as_user(t, 0, function(w)
            local read = open(t, w, "Rights", R.QUERY_VALUE)
            local write = open(t, w, "Rights", R.WRITE_DAC)
            local mark = src:mark()
            denied(t, lcs.get_security(src, w, read, SI.LABEL), sys.E.ACCES)
            denied(t, lcs.set_security(src, w, write, SI.LABEL, label(LOW)), sys.E.ACCES)
            t:assert_eq(#src:served(lcs.OP.READ_KEY, mark), 0)
            t:assert_eq(#src:served(lcs.OP.WRITE_KEY, mark), 0)
            sys.close(w, read); sys.close(w, write)
        end)
    end)

test("LABEL rejects a combined SACL selector and malformed subsets before source contact",
    { spec = "PKM *inherit.label-input-validation" }, function(t)
        local fd = open(t, system, "Invalid", R.READ_CONTROL | R.WRITE_OWNER | R.ACCESS_SYSTEM_SECURITY)
        local mark = src:mark()
        denied(t, lcs.get_security(src, system, fd, SI.SACL | SI.LABEL), sys.E.INVAL)
        denied(t, lcs.set_security(src, system, fd, SI.SACL | SI.LABEL, label(LOW)), sys.E.INVAL)
        for _, acl in ipairs({ access.acl({}), access.acl({ AUDIT }),
            access.acl({ access.label_ace(LOW, nil, AF.INHERIT_ONLY) }),
            access.acl({ access.label_ace(LOW), access.label_ace(MEDIUM) }) }) do
            denied(t, lcs.set_security(src, system, fd, SI.LABEL, access.sd({ sacl = acl })), sys.E.INVAL)
        end
        t:assert_eq(#src:served(lcs.OP.READ_KEY, mark), 0)
        t:assert_eq(#src:served(lcs.OP.WRITE_KEY, mark), 0)
        sys.close(system, fd)
    end)

test("a caller without SeRelabel may set Low or Medium but cannot assign High",
    { spec = "PKM *inherit.label-level-constraint" }, function(t)
        as_user(t, 0, function(w)
            local fd = open(t, w, "Levels", R.WRITE_OWNER)
            t:assert_eq(lcs.set_security(src, w, fd, SI.LABEL, label(LOW)).ret, 0)
            t:assert_eq(lcs.set_security(src, w, fd, SI.LABEL, label(MEDIUM)).ret, 0)
            local mark = src:mark()
            denied(t, lcs.set_security(src, w, fd, SI.LABEL, label(HIGH)), sys.E.ACCES)
            t:assert_eq(#src:served(lcs.OP.READ_KEY, mark), 0)
            t:assert_eq(#src:served(lcs.OP.WRITE_KEY, mark), 0)
            sys.close(w, fd)
        end)
        t:assert_eq(full(t, "Levels").sacl.aces[1].sid, token.label_sid(MEDIUM))
    end)

test("enabled SeRelabel permits High without SeSecurity",
    { spec = "PKM *inherit.label-level-constraint" }, function(t)
        as_user(t, token.bit(token.PRIV.RELABEL), function(w)
            local fd = open(t, w, "Privileged", R.WRITE_OWNER)
            t:assert_eq(lcs.set_security(src, w, fd, SI.LABEL, label(HIGH)).ret, 0)
            sys.close(w, fd)
        end)
        t:assert_eq(full(t, "Privileged").sacl.aces[1].sid, token.label_sid(HIGH))
    end)

test("a present but disabled SeRelabel privilege cannot raise the label",
    { spec = "PKM *inherit.label-level-constraint" }, function(t)
        as_user(t, token.bit(token.PRIV.RELABEL), function(w)
            local fd = open(t, w, "Disabled", R.WRITE_OWNER)
            denied(t, lcs.set_security(src, w, fd, SI.LABEL, label(HIGH)), sys.E.ACCES)
            sys.close(w, fd)
        end, 0)
    end)

test("SeSecurity alone cannot bypass the label rule through a whole-SACL write",
    { spec = "PKM *inherit.label-level-constraint" }, function(t)
        as_user(t, token.bit(token.PRIV.SECURITY), function(w)
            local fd = open(t, w, "SaclDenied", R.ACCESS_SYSTEM_SECURITY)
            local mark = src:mark()
            denied(t, lcs.set_security(src, w, fd, SI.SACL, label(HIGH)), sys.E.ACCES)
            t:assert_eq(#src:served(lcs.OP.READ_KEY, mark), 0)
            t:assert_eq(#src:served(lcs.OP.WRITE_KEY, mark), 0)
            sys.close(w, fd)
        end)
    end)

test("SeSecurity and enabled SeRelabel permit a whole-SACL write raising integrity",
    { spec = "PKM *inherit.label-level-constraint" }, function(t)
        as_user(t, token.bit(token.PRIV.SECURITY) | token.bit(token.PRIV.RELABEL), function(w)
            local fd = open(t, w, "SaclAllowed", R.ACCESS_SYSTEM_SECURITY)
            t:assert_eq(lcs.set_security(src, w, fd, SI.SACL, label(HIGH)).ret, 0)
            sys.close(w, fd)
        end)
        t:assert_eq(full(t, "SaclAllowed").sacl.aces[1].sid, token.label_sid(HIGH))
    end)

