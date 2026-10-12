-- PEI-1397: creation must preserve unresolved rules for the next creator.
local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local facs = require("helpers.facs")
local access = require("helpers.access")
local token = require("helpers.token")
local lcs = require("helpers.lcs")

local vm = provium:vm("v", "kernel-only"):boot()
local F = access.ACE_FLAG
local CI, OI, IO, ID, NP = F.CONTAINER_INHERIT, F.OBJECT_INHERIT,
    F.INHERIT_ONLY, F.INHERITED, F.NO_PROPAGATE
local GR = access.STD.GENERIC_READ
local CO, CG = token.sid(3, 0), token.sid(3, 1)
local AU = token.SID.AUTHENTICATED_USERS
local TRAVERSE = token.bit(token.PRIV.CHANGE_NOTIFY)
local INFO = kacs.SI.OWNER | kacs.SI.GROUP | kacs.SI.DACL
local base = facs.workspace(vm, "inherit-generations")

local function matching(sd, sid, mask, flags)
    for _, ace in ipairs(sd.dacl or {}) do
        if ace.sid == sid and ace.mask == mask and ace.flags == flags then return true end
    end
    return false
end

local function check_split(t, sd, read, inherit_flags)
    t:assert(matching(sd, sd.owner, read, ID), "creator owner resolved for this child")
    t:assert(matching(sd, sd.group, read, ID), "creator group resolved for this child")
    t:assert(matching(sd, AU, read, ID), "ordinary SID's generic rights mapped for this child")
    for _, sid in ipairs({ CO, CG, AU }) do
        t:assert(matching(sd, sid, GR, inherit_flags | IO | ID),
            "unresolved SID and generic mask retained in the inherit-only copy")
    end
end

local function marker_aces(all, flags)
    local aces = { access.ace(access.ACE.ALLOWED, all, token.SID.EVERYONE, flags) }
    for _, sid in ipairs({ CO, CG, AU }) do
        aces[#aces + 1] = access.ace(access.ACE.ALLOWED, GR, sid, flags)
    end
    return aces
end

test("file creation resolves each generation and leaves files without propagation flags", function(t)
    local parent = base .. "/parent"
    t:assert_eq(sys.mkdir(vm, parent).ret, 0)
    local sd = access.sd({ owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM,
        dacl = access.acl(marker_aces(kacs.ALL_RIGHTS, OI | CI)) })
    t:assert_eq(kacs.set_sd(vm, parent, sd, INFO).ret, 0)
    local child, grandchild = parent .. "/child", parent .. "/child/grandchild"
    token.as_principal(t, vm, { user_sid = token.SID.TEST_USER, privs_present = TRAVERSE, privs_enabled = TRAVERSE }, function(w)
        local r = sys.mkdir(w, child)
        t:assert_eq(r.ret, 0, "first principal creates directory: " .. sys.errname(r.errno or 0))
    end)
    token.as_principal(t, vm, { user_sid = token.SID.TEST_USER_2, privs_present = TRAVERSE, privs_enabled = TRAVERSE }, function(w)
        t:assert_eq(sys.mkdir(w, grandchild).ret, 0, "second principal creates grandchild")
    end)
    local child_sd = token.parse_sd(assert(kacs.get_sd(vm, child, INFO)))
    local grandchild_sd = token.parse_sd(assert(kacs.get_sd(vm, grandchild, INFO)))
    t:assert(child_sd.owner ~= grandchild_sd.owner, "the generations have different owners")
    check_split(t, child_sd, access.FILE_MAPPING.read, OI | CI)
    check_split(t, grandchild_sd, access.FILE_MAPPING.read, OI | CI)
    local fd, errno = sys.open(vm, grandchild .. "/file", sys.O.CREAT | sys.O.RDWR, 0x180)
    t:assert(fd, "file create: " .. sys.errname(errno or 0))
    sys.close(vm, fd)
    local file_sd = token.parse_sd(assert(kacs.get_sd(vm, grandchild .. "/file", INFO)))
    for _, ace in ipairs(file_sd.dacl) do
        t:assert_eq(ace.flags & (OI | CI | IO | NP), 0, "non-container has no propagation flags")
    end
end)

test("NO_PROPAGATE clears itself and cannot carry an object-only rule through a directory", function(t)
    local parent = base .. "/no-propagate"
    t:assert_eq(sys.mkdir(vm, parent).ret, 0)
    local sd = access.sd({ owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM,
        dacl = access.acl({
            access.ace(access.ACE.ALLOWED, kacs.ALL_RIGHTS, token.SID.EVERYONE, OI | CI),
            access.ace(access.ACE.ALLOWED, access.FILE_MAPPING.read, token.SID.TEST_USER, OI | CI | NP),
            access.ace(access.ACE.ALLOWED, access.FILE_MAPPING.read, token.SID.TEST_USER_2, OI | NP),
        }) })
    t:assert_eq(kacs.set_sd(vm, parent, sd, INFO).ret, 0)
    t:assert_eq(sys.mkdir(vm, parent .. "/child").ret, 0)
    local child = token.parse_sd(assert(kacs.get_sd(vm, parent .. "/child", INFO)))
    t:assert(matching(child, token.SID.TEST_USER, access.FILE_MAPPING.read, ID),
        "NP rule applies once with all propagation flags cleared")
    for _, ace in ipairs(child.dacl) do
        t:assert(ace.sid ~= token.SID.TEST_USER_2, "OI-only NP rule does not apply to a directory")
    end
end)

local src = lcs.source(vm, { hives = { { name = "Machine", sd = lcs.machine_root_sd() } } })
src:key("Machine\\Generations", { sd = lcs.sd(marker_aces(lcs.KEY_ALL_ACCESS, CI)) })
assert(src:register())
src:pump()

test("registry creator and generic rules reach grandchildren with a different owner", function(t)
    local enabled = token.GROUP.MANDATORY | token.GROUP.ENABLED_BY_DEFAULT | token.GROUP.ENABLED
    local paths = { "Machine\\Generations\\Child", "Machine\\Generations\\Child\\Grandchild" }
    local owners = { token.SID.TEST_USER, token.SID.TEST_USER_2 }
    for i, path in ipairs(paths) do
        token.as_principal(t, vm, { user_sid = owners[i], groups = {
            { sid = token.SID.EVERYONE, attributes = enabled },
            { sid = AU, attributes = enabled },
            { sid = token.SID.ADMINISTRATORS, attributes = enabled },
        } }, function(w)
            local made = lcs.create_key(src, w, { path = path })
            t:assert(made.ret >= 0, "create " .. path .. ": " .. sys.errname(made.errno or 0))
            sys.close(w, made.ret)
        end)
        local w = vm:spawn_worker()
        local opened = lcs.open_key(src, w, -1, path, lcs.RIGHT.READ_CONTROL)
        t:assert(opened.ret >= 0, "read child descriptor")
        local result = lcs.get_security(src, w, opened.ret, lcs.SI.OWNER | lcs.SI.GROUP | lcs.SI.DACL)
        t:assert_eq(result.ret, 0)
        local parsed = token.parse_sd(result.sd)
        t:assert_eq(parsed.owner, owners[i], "owner is the creating principal")
        check_split(t, parsed, lcs.RIGHT.KEY_READ, CI)
        sys.close(w, opened.ret)
        w:kill(); w:join()
    end
end)
