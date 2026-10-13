-- Component selection includes control bits even when an ACL has no bytes.
local sys = require("helpers.sys")
local lcs = require("helpers.lcs")
local token = require("helpers.token")
local access = require("helpers.access")
local vm = provium:vm("v", "kernel-only"):boot()
local SI, R, C = lcs.SI, lcs.RIGHT, access.CONTROL
-- DEFAULTED | AUTO_INHERIT_REQ | AUTO_INHERITED | PROTECTED, per PCDS.
local DFLAGS, SFLAGS = 0x1508, 0x2a20
local OWNER = token.SID.LOCAL_SYSTEM
local grant = access.acl({ access.ace(access.ACE.ALLOWED, lcs.KEY_ALL_ACCESS,
    token.SID.EVERYONE) })
local empty = access.acl({})
local null = access.sd({ owner = OWNER, control = DFLAGS | SFLAGS })
local present = access.sd({ owner = OWNER, dacl = grant, sacl = empty,
    control = DFLAGS | SFLAGS })
local src = lcs.source(vm, { hives = { { name = "Machine", sd = lcs.machine_root_sd() } } })
for _, name in ipairs({ "Query", "Owner", "Group", "Empty", "Label" }) do
    src:key("Machine\\NullAcl\\" .. name, { sd = null })
end
for _, name in ipairs({ "DaclReplace", "SaclReplace" }) do
    src:key("Machine\\NullAcl\\" .. name, { sd = present })
end
src:key("Machine\\NullAcl\\NullGroup", {
    sd = access.sd({ owner = OWNER, control = DFLAGS | 0x2 }),
})
assert(src:register())
src:pump()
local w = vm:spawn_worker()

local function open(t, name)
    local r = lcs.open_key(src, w, -1, "Machine\\NullAcl\\" .. name,
        R.READ_CONTROL | R.WRITE_OWNER | R.WRITE_DAC | R.ACCESS_SYSTEM_SECURITY)
    t:assert(r.ret >= 0, "open " .. name .. ": " .. sys.errname(r.errno or 0))
    return r.ret
end
local function query(t, fd, info)
    local r = lcs.get_security(src, w, fd, info or SI.ALL)
    t:assert_eq(r.ret, 0, "get security: " .. sys.errname(r.errno or 0))
    return access.parse_sd(r.sd)
end
local function set(t, fd, info, sd)
    local r = lcs.set_security(src, w, fd, info, sd)
    t:assert_eq(r.ret, 0, "set security: " .. sys.errname(r.errno or 0))
end

test("NULL ACL queries retain the selected ACL flags without setting PRESENT",
    { spec = "PKM *inherit.null-acl-control-flags" }, function(t)
        local fd = open(t, "Query")
        for _, case in ipairs({ { SI.DACL, DFLAGS }, { SI.SACL, SFLAGS },
            { SI.DACL | SI.SACL, DFLAGS | SFLAGS } }) do
            local sd = query(t, fd, case[1])
            t:assert_eq(sd.control, C.SELF_RELATIVE | case[2])
            t:assert_eq(sd.dacl, nil)
            t:assert_eq(sd.sacl, nil)
        end
        sys.close(w, fd)
    end)

test("owner and group updates preserve flags on both unselected NULL ACLs",
    { spec = "PKM *inherit.null-acl-control-flags" }, function(t)
        for _, case in ipairs({ { "Owner", SI.OWNER }, { "Group", SI.GROUP } }) do
            local fd = open(t, case[1])
            set(t, fd, case[2], access.sd({ owner = OWNER, group = token.SID.EVERYONE }))
            local sd = query(t, fd)
            t:assert_eq(sd.control, C.SELF_RELATIVE | DFLAGS | SFLAGS)
            t:assert_eq(sd.owner, OWNER)
            t:assert_eq(sd.dacl, nil)
            t:assert_eq(sd.sacl, nil)
            if case[2] == SI.GROUP then t:assert_eq(sd.group, token.SID.EVERYONE) end
            sys.close(w, fd)
        end
    end)

test("a selected NULL ACL takes its supplied flags and preserves the other ACL",
    { spec = "PKM *inherit.null-acl-control-flags" }, function(t)
        for _, case in ipairs({
            { "DaclReplace", SI.DACL, C.DACL_PROTECTED, SFLAGS | C.SACL_PRESENT },
            { "SaclReplace", SI.SACL, C.SACL_PROTECTED, DFLAGS | C.DACL_PRESENT },
        }) do
            local fd = open(t, case[1])
            set(t, fd, case[2], access.sd({ control = case[3] }))
            local sd = query(t, fd)
            t:assert_eq(sd.control, C.SELF_RELATIVE | case[3] | case[4])
            if case[2] == SI.DACL then
                t:assert_eq(sd.dacl, nil)
                t:assert_eq(#sd.sacl.aces, 0, "unselected empty SACL stays present")
            else
                t:assert_eq(sd.sacl, nil)
                t:assert_eq(#sd.dacl.aces, 1)
                t:assert_eq(sd.dacl.aces[1].sid, token.SID.EVERYONE)
            end
            sys.close(w, fd)
        end
    end)

test("empty ACL replacements remain distinct from NULL ACLs",
    { spec = "PKM *inherit.null-acl-control-flags" }, function(t)
        local fd = open(t, "Empty")
        set(t, fd, SI.DACL | SI.SACL, access.sd({ dacl = empty, sacl = empty,
            control = DFLAGS | SFLAGS }))
        local sd = query(t, fd)
        t:assert_eq(sd.control, C.SELF_RELATIVE | C.DACL_PRESENT | C.SACL_PRESENT | DFLAGS | SFLAGS)
        t:assert_eq(#sd.dacl.aces, 0)
        t:assert_eq(#sd.sacl.aces, 0)
        sys.close(w, fd)
    end)

test("LABEL plus DACL selection takes NULL DACL flags without changing SACL flags",
    { spec = "PKM *inherit.null-acl-control-flags" }, function(t)
        local fd = open(t, "Label")
        set(t, fd, SI.LABEL | SI.DACL, access.sd({ control = C.DACL_PROTECTED,
            sacl = access.acl({ access.label_ace(token.INTEGRITY.MEDIUM) }) }))
        local sd = query(t, fd)
        t:assert_eq(sd.control, C.SELF_RELATIVE | C.SACL_PRESENT | C.DACL_PROTECTED | SFLAGS)
        t:assert_eq(sd.dacl, nil)
        t:assert_eq(sd.sacl.aces[1].sid, token.label_sid(token.INTEGRITY.MEDIUM))
        sys.close(w, fd)
    end)

test("unselected defaulted NULL group state also survives a merge",
    { spec = "PKM *inherit.null-acl-control-flags" }, function(t)
        local fd = open(t, "NullGroup")
        set(t, fd, SI.OWNER, access.sd({ owner = OWNER }))
        local sd = query(t, fd)
        t:assert_eq(sd.group, nil)
        t:assert_eq(sd.control, C.SELF_RELATIVE | 0x2 | DFLAGS)
        sys.close(w, fd)
    end)
