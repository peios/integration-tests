-- PKM §3.A — the generated ABI appendix, structure half: the syscall
-- numbers and every `struct kacs_*` layout, each measured against live
-- behaviour rather than against the header it was generated from.
--
-- A published number is testable because getting it wrong is visible: a
-- syscall number that is not registered is ENOSYS, an ioctl whose
-- encoded argument size is wrong is ENOTTY, and a field read at the
-- wrong offset carries the neighbouring field's value. So each case
-- drives the real call with the documented layout, then perturbs
-- exactly the number under test and shows the kernel notice.
--
-- The constant tables of the same appendix are in abi-tables.test.lua
-- and abi-constants.test.lua; the tracepoint vocabularies in
-- abi-tracepoints.test.lua.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local token = require("helpers.token")
local access = require("helpers.access")
local facs = require("helpers.facs")

local vm = provium:vm("v", "kernel-only"):boot()

local B = facs.workspace(vm, "abistructs")

--- An ioctl command word, from the four fields the kernel's _IOC packs.
--- Every token ioctl is type 0x4B (§3.A), and its `size` field is the
--- byte size of the struct it carries — which is what makes a wrong
--- size an ENOTTY rather than a misread.
local function ioc(dir, size, nr)
    return (dir << 30) | (size << 16) | (0x4B << 8) | nr
end
local IOC_READ_WRITE, IOC_WRITE = 3, 1

--- A token to drive the handle ioctls against, plus its session.
local function fresh(spec)
    local fd, e = token.mint(vm, spec or {})
    assert(fd, "mint: " .. sys.errname(e or 0))
    return fd
end

test("the appendix is generated from uapi/pkm/, not written by hand",
    { spec = "PKM *kacs-abi.generated-from-source",
      covered_by = "ci:regenerate-and-diff",
      skip = "a CI property: pkm/tools/gen-kacs-abi.py rewrites §3.A " ..
             "wholesale from pkm/uapi/pkm/ and the check run fails when " ..
             "the committed appendix differs; nothing in a VM can " ..
             "observe how a document was produced" }, function(t)
    end)

test("every published syscall number is registered, and the holes are not",
    { spec = "PKM *kacs-abi.syscall-numbers" }, function(t)
        -- A registered number answers its own call; an unregistered one
        -- is ENOSYS whatever it is handed. Each call below is given
        -- arguments that make it fail early, so the only thing under
        -- test is that the number reaches KACS at all.
        local calls = {
            { 1000, "open_self_token", { 0xF000, 0 } },
            { 1001, "open_process_token", { -1, 0 } },
            { 1002, "open_thread_token", { -1, 0, 0 } },
            { 1003, "create_token", { 0, 0 } },
            { 1004, "create_logon_session", { 0, 0 } },
            { 1005, "set_psb", { -1, 0 } },
            { 1006, "destroy_empty_logon_session", { 0 } },
            { 1012, "revert", {} },
            { 1023, "access_check", { 0 } },
            { 1024, "access_check_list", { 0, 0, 0 } },
            { 1025, "set_caap", { 0, 0, 0, 0 } },
            { 1026, "get_mount_policy", { -1, 0, 0 } },
            { 1027, "set_mount_policy", { -1, 0, 0 } },
        }
        for _, c in ipairs(calls) do
            local r = vm:syscall(c[1], table.unpack(c[3]))
            t:assert_neq(r.errno, sys.E.NOSYS,
                c[1] .. " is " .. c[2] .. ", not a hole: " ..
                sys.errname(r.errno))
        end
        -- The three path-taking numbers, given a real path so they
        -- answer as themselves rather than EFAULT.
        local p = facs.file(vm, B .. "/syscalls", "n")
        local fd = kacs.open(vm, p, { access = kacs.RIGHT.READ_DATA })
        t:assert(fd, "1020 is kacs_open")
        sys.close(vm, fd)
        t:assert(kacs.get_sd(vm, p), "1021 is kacs_get_sd")
        t:assert_eq(kacs.set_sd(vm, p, kacs.grant(kacs.ALL_RIGHTS)).ret, 0,
            "1022 is kacs_set_sd")
        for _, hole in ipairs({ 1007, 1008, 1009, 1014, 1019, 1028, 1030 }) do
            t:assert_eq(vm:syscall(hole, 0, 0, 0).errno, sys.E.NOSYS,
                hole .. " is not registered")
        end
    end)

test("the sibling KMES and LCS numbers occupy 1090-1102 and nothing beyond",
    { spec = "PKM *kacs-abi.sibling-syscall-range" }, function(t)
        for _, nr in ipairs({ 1090, 1091, 1092, 1100, 1101, 1102 }) do
            t:assert_neq(vm:syscall(nr, 0, 0, 0, 0).errno, sys.E.NOSYS,
                nr .. " answers")
        end
        for _, nr in ipairs({ 1089, 1093, 1099, 1103 }) do
            t:assert_eq(vm:syscall(nr, 0, 0, 0, 0).errno, sys.E.NOSYS,
                nr .. " is outside the registered range")
        end
    end)

test("struct kacs_query_args is 16 bytes: class at 0, buf_len at 4, buf_ptr at 8",
    { spec = "PKM *kacs-abi.struct-kacs-query-args" }, function(t)
        local fd = fresh()
        -- The documented layout, used as documented: the probe form
        -- writes the needed length back into the field at 4.
        local probe = vm:syscall(sys.NR.ioctl, {
            args = { fd, token.IOC.QUERY, 0 },
            bufs = { string.pack("<I4I4I8", token.CLASS.TYPE, 0, 0) },
            ptrs = { 2 },
        })
        t:assert_eq(probe.ret, 0, "a probe with the class at 0 succeeds")
        t:assert_eq(string.unpack("<I4", probe.out_bufs[1], 5), 4,
            "and the length comes back at offset 4")
        -- The same bytes shifted one field along: the class the kernel
        -- now reads at 0 is zero, which is not a class.
        local shifted = vm:syscall(sys.NR.ioctl, {
            args = { fd, token.IOC.QUERY, 0 },
            bufs = { string.pack("<I4I4I8", 0, token.CLASS.TYPE, 0) },
            ptrs = { 2 },
        })
        t:assert_eq(shifted.errno, sys.E.INVAL,
            "the class is read at 0 and nowhere else: " ..
            sys.errname(shifted.errno))
        -- buf_ptr at 8 carries the payload out.
        t:assert_eq(token.query(vm, fd, token.CLASS.TYPE),
            string.pack("<I4", token.TYPE.PRIMARY),
            "and the payload arrives through the pointer at 8")
        t:assert_eq(vm:syscall(sys.NR.ioctl, {
            args = { fd, ioc(IOC_READ_WRITE, 24, 0x00), 0 },
            bufs = { string.rep("\0", 24) }, ptrs = { 2 },
        }).errno, sys.E.NOTTY,
            "an argument size other than 16 is not KACS_IOC_QUERY")
        sys.close(vm, fd)
    end)

test("struct kacs_adjust_privs_args is 24 bytes with previous_enabled at 16",
    { spec = "PKM *kacs-abi.struct-kacs-adjust-privs-args" }, function(t)
        local BACKUP = token.bit(token.PRIV.BACKUP)
        local fd = fresh({ privs_present = BACKUP, privs_enabled = BACKUP })
        -- count at 0, data_ptr at 8, previous_enabled written at 16.
        local r, previous = token.disable_priv(vm, fd, token.PRIV.BACKUP)
        t:assert_eq(r.ret, 0, "the adjustment lands")
        t:assert_eq(previous, BACKUP,
            "previous_enabled at 16 is the mask as it was")
        local _, after = token.enable_priv(vm, fd, token.PRIV.BACKUP)
        t:assert_eq(after, 0, "and the next call reports the disabled state")
        t:assert_eq(vm:syscall(sys.NR.ioctl, {
            args = { fd, ioc(IOC_WRITE, 16, 0x01), 0 },
            bufs = { string.rep("\0", 16) }, ptrs = { 2 },
        }).errno, sys.E.NOTTY, "a 16-byte argument is not this ioctl")
        sys.close(vm, fd)
    end)

test("struct kacs_priv_entry is 8 bytes: luid at 0, attributes at 4",
    { spec = "PKM *kacs-abi.struct-kacs-priv-entry" }, function(t)
        local BACKUP, RESTORE =
            token.bit(token.PRIV.BACKUP), token.bit(token.PRIV.RESTORE)
        local fd = fresh({ privs_present = BACKUP | RESTORE, privs_enabled = 0 })
        -- Two entries at stride 8: if the stride were anything else the
        -- second entry would be read from the middle of the first.
        local r = token.adjust_privs(vm, fd, {
            { token.PRIV.BACKUP, token.PRIV_ATTR.ENABLED },
            { token.PRIV.RESTORE, token.PRIV_ATTR.ENABLED },
        })
        t:assert_eq(r.ret, 0, "two entries are accepted")
        local privs = assert(token.privileges(vm, fd))
        t:assert_eq(privs.enabled, BACKUP | RESTORE,
            "both entries were read, so each is 8 bytes wide")
        -- attributes lives at 4: the same luid with a zero attributes
        -- word disables rather than enables.
        token.adjust_privs(vm, fd, { { token.PRIV.BACKUP, 0 } })
        t:assert_eq(assert(token.privileges(vm, fd)).enabled, RESTORE,
            "and the word at 4 is the attributes")
        sys.close(vm, fd)
    end)

test("struct kacs_adjust_groups_args is 144 bytes with previous_state at 16",
    { spec = "PKM *kacs-abi.struct-kacs-adjust-groups-args" }, function(t)
        local ENABLED = token.GROUP.MANDATORY | token.GROUP.ENABLED_BY_DEFAULT
            | token.GROUP.ENABLED
        local fd = fresh({ groups = {
            { sid = token.SID.EVERYONE, attributes = ENABLED },
            { sid = token.SID.TEST_GROUP,
              attributes = token.GROUP.ENABLED_BY_DEFAULT | token.GROUP.ENABLED },
            { sid = token.SID.USERS, attributes = 0 },
        } })
        local r, words = token.adjust_groups(vm, fd, { { 1, 0 }, { 2, 1 } })
        t:assert_eq(r.ret, 0, "the adjustment lands")
        t:assert_eq(#words, 16, "sixteen u64 words are readable from 16")
        t:assert(words[1] & (1 << 1) ~= 0,
            "group 1 was enabled before the call")
        t:assert_eq(words[1] & (1 << 2), 0, "and group 2 was not")
        t:assert_eq(vm:syscall(sys.NR.ioctl, {
            args = { fd, ioc(IOC_WRITE, 24, 0x07), 0 },
            bufs = { string.rep("\0", 24) }, ptrs = { 2 },
        }).errno, sys.E.NOTTY,
            "only the 144-byte form is KACS_IOC_ADJUST_GROUPS")
        sys.close(vm, fd)
    end)

test("struct kacs_group_entry is 8 bytes: index at 0, enable at 4",
    { spec = "PKM *kacs-abi.struct-kacs-group-entry" }, function(t)
        local ENABLED = token.GROUP.MANDATORY | token.GROUP.ENABLED_BY_DEFAULT
            | token.GROUP.ENABLED
        local fd = fresh({ groups = {
            { sid = token.SID.EVERYONE, attributes = ENABLED },
            { sid = token.SID.TEST_GROUP, attributes = token.GROUP.ENABLED },
            { sid = token.SID.USERS, attributes = 0 },
        } })
        -- An index beyond the array is rejected, which is only true if
        -- the index is the word at 0.
        t:assert_eq(token.adjust_groups(vm, fd, { { 99, 1 } }).errno,
            sys.E.INVAL, "the word at 0 is the group index")
        t:assert_eq(token.adjust_groups(vm, fd, { { 2, 1 } }).ret, 0,
            "an in-range index is accepted")
        local groups = assert(token.groups(vm, fd))
        t:assert(groups[3].attributes & token.GROUP.ENABLED ~= 0,
            "and the word at 4 said enable")
        t:assert_eq(token.adjust_groups(vm, fd, { { 2, 0 } }).ret, 0, "disable")
        t:assert_eq(assert(token.groups(vm, fd))[3].attributes
            & token.GROUP.ENABLED, 0, "the same word said disable")
        sys.close(vm, fd)
    end)

test("struct kacs_duplicate_args is 16 bytes with result_fd at 12",
    { spec = "PKM *kacs-abi.struct-kacs-duplicate-args" }, function(t)
        local fd = fresh()
        local r = vm:syscall(sys.NR.ioctl, {
            args = { fd, token.IOC.DUPLICATE, 0 },
            bufs = { string.pack("<I4I4I4i4", token.RIGHT.QUERY,
                token.TYPE.IMPERSONATION, token.LEVEL.IDENTIFICATION, -1) },
            ptrs = { 2 },
        })
        t:assert_eq(r.ret, 0, "a duplicate with the documented layout")
        local new_fd = string.unpack("<i4", r.out_bufs[1], 13)
        t:assert(new_fd >= 0, "result_fd comes back at offset 12")
        t:assert_eq(token.query_u32(vm, new_fd, token.CLASS.TYPE),
            token.TYPE.IMPERSONATION, "token_type was read at 4")
        t:assert_eq(token.query_u32(vm, new_fd, token.CLASS.IMPERSONATION_LEVEL),
            token.LEVEL.IDENTIFICATION, "impersonation_level at 8")
        -- access_mask at 0: QUERY only, so an adjustment is refused.
        t:assert_eq(token.enable_priv(vm, new_fd, token.PRIV.BACKUP).errno,
            sys.E.ACCES, "and the access mask at 0 bound the new handle")
        sys.close(vm, new_fd); sys.close(vm, fd)
    end)

test("struct kacs_adjust_default_args is 16 bytes: dacl_ptr 0, len 8, indices 12 and 14",
    { spec = "PKM *kacs-abi.struct-kacs-adjust-default-args" }, function(t)
        local ENABLED = token.GROUP.MANDATORY | token.GROUP.ENABLED_BY_DEFAULT
            | token.GROUP.ENABLED
        local fd = fresh({ groups = {
            -- An owner index may only name a group carrying the OWNER
            -- attribute, so the first group is authored to carry it.
            { sid = token.SID.EVERYONE, attributes = ENABLED | token.GROUP.OWNER },
            { sid = token.SID.TEST_GROUP, attributes = ENABLED },
        } })
        local dacl = access.acl({ access.ace(access.ACE.ALLOWED,
            token.RIGHT.QUERY, token.SID.EVERYONE) })
        -- owner_index is a u16 at 12 and group_index a u16 at 14: two
        -- distinct values in adjacent halves of one word.
        t:assert_eq(token.adjust_default(vm, fd,
            { dacl = dacl, owner_index = 1, group_index = 2 }).ret, 0,
            "the adjustment lands")
        t:assert_eq(token.query(vm, fd, token.CLASS.OWNER), token.SID.EVERYONE,
            "owner_index 1 resolved to groups[0] — the u16 at 12")
        t:assert_eq(token.query(vm, fd, token.CLASS.PRIMARY_GROUP),
            token.SID.TEST_GROUP,
            "group_index 2 resolved to groups[1] — the u16 at 14")
        t:assert_eq(token.query(vm, fd, token.CLASS.DEFAULT_DACL), dacl,
            "and dacl_ptr at 0 with dacl_len at 8 carried the ACL")
        sys.close(vm, fd)
    end)

test("struct kacs_restrict_args is 40 bytes with result_fd at 32",
    { spec = "PKM *kacs-abi.struct-kacs-restrict-args" }, function(t)
        local BACKUP = token.bit(token.PRIV.BACKUP)
        local fd = fresh({ privs_present = BACKUP, privs_enabled = BACKUP })
        local r = vm:syscall(sys.NR.ioctl, {
            args = { fd, token.IOC.RESTRICT, 0 },
            bufs = { string.pack("<I8I4I4I4I4I8i4I4",
                BACKUP, 0, 0, 0, token.RESTRICT_WRITE_RESTRICTED, 0, -1, 0) },
            ptrs = { 2 },
        })
        t:assert_eq(r.ret, 0, "a filter with the documented layout")
        local filtered = string.unpack("<i4", r.out_bufs[1], 33)
        t:assert(filtered >= 0, "result_fd comes back at offset 32")
        t:assert_eq(assert(token.privileges(vm, filtered)).present, 0,
            "privs_to_delete at 0 removed the privilege")
        t:assert_eq(vm:syscall(sys.NR.ioctl, {
            args = { fd, ioc(IOC_READ_WRITE, 32, 0x04), 0 },
            bufs = { string.rep("\0", 32) }, ptrs = { 2 },
        }).errno, sys.E.NOTTY, "only the 40-byte form is KACS_IOC_RESTRICT")
        sys.close(vm, filtered); sys.close(vm, fd)
    end)

test("struct kacs_link_tokens_args is 16 bytes: two fds then the session id",
    { spec = "PKM *kacs-abi.struct-kacs-link-tokens-args" }, function(t)
        local TCB = token.bit(token.PRIV.TCB)
        local elevated, sid = token.mint(vm,
            { privs_present = TCB, privs_enabled = TCB })
        t:assert(elevated, "an elevated token: " .. sys.errname(sid or 0))
        local filtered = assert(token.create(vm, { auth_id = sid }))
        local r = vm:syscall(sys.NR.ioctl, {
            args = { elevated, token.IOC.LINK_TOKENS, 0 },
            bufs = { string.pack("<i4i4I8", elevated, filtered, sid) },
            ptrs = { 2 },
        })
        t:assert_eq(r.ret, 0, "elevated_fd at 0, filtered_fd at 4, id at 8: " ..
            sys.errname(r.errno))
        t:assert_eq(token.query_u32(vm, elevated, token.CLASS.ELEVATION_TYPE),
            token.ELEVATION.FULL, "the fd named at 0 became the full token")
        t:assert_eq(token.query_u32(vm, filtered, token.CLASS.ELEVATION_TYPE),
            token.ELEVATION.LIMITED, "and the one at 4 the limited token")
        sys.close(vm, elevated); sys.close(vm, filtered)
    end)

test("struct kacs_get_linked_token_args is 4 bytes: result_fd alone",
    { spec = "PKM *kacs-abi.struct-kacs-get-linked-token-args" }, function(t)
        local TCB = token.bit(token.PRIV.TCB)
        local elevated, sid = token.mint(vm,
            { privs_present = TCB, privs_enabled = TCB })
        t:assert(elevated, "an elevated token")
        local filtered = assert(token.create(vm, { auth_id = sid }))
        t:assert_eq(token.link(vm, elevated, elevated, filtered, sid).ret, 0,
            "the pair is linked")
        local r = vm:syscall(sys.NR.ioctl, {
            args = { elevated, token.IOC.GET_LINKED_TOKEN, 0 },
            bufs = { string.pack("<i4", -1) }, ptrs = { 2 },
        })
        t:assert_eq(r.ret, 0, "the whole argument is one 4-byte field")
        t:assert(string.unpack("<i4", r.out_bufs[1]) >= 0,
            "result_fd is written at offset 0")
        t:assert_eq(vm:syscall(sys.NR.ioctl, {
            args = { elevated, ioc(IOC_READ_WRITE, 8, 0x06), 0 },
            bufs = { string.rep("\0", 8) }, ptrs = { 2 },
        }).errno, sys.E.NOTTY, "an 8-byte form is not this ioctl")
        sys.close(vm, elevated); sys.close(vm, filtered)
    end)

test("struct kacs_access_check_args is 136 bytes with the fields at their offsets",
    { spec = "PKM *kacs-abi.struct-kacs-access-check-args" }, function(t)
        -- helpers/access packs exactly the published layout; a check
        -- that grants through the descriptor at sd_ptr (8), for the
        -- mask at desired_access (20), reporting through granted_out_ptr
        -- (88), exercises the offsets as a set.
        local fd = fresh()
        local sd = access.simple({ access.ace(access.ACE.ALLOWED, 0x1,
            token.SID.TEST_USER) })
        local r = access.check(vm, { token_fd = fd, sd = sd, desired = 0x1 })
        t:assert(r.ok, "the check is answered: " .. sys.errname(r.errno))
        t:assert_eq(r.granted, 0x1, "granted_out_ptr at 88 carried the mask")
        -- token_fd is the s32 at 4: -2 is neither -1 nor a descriptor.
        t:assert_eq(access.check(vm, { token_fd = -2, sd = sd, desired = 0x1 }).errno,
            sys.E.INVAL, "token_fd is the signed word at 4")
        -- caller_size is the u32 at 0.
        t:assert_eq(access.check(vm, { token_fd = fd, sd = sd, desired = 0x1,
            caller_size = 39 }).errno, sys.E.INVAL,
            "caller_size at 0 below the v1 size is refused")
        sys.close(vm, fd)
    end)

test("struct kacs_object_type_entry is 20 bytes: level at 0, guid at 4",
    { spec = "PKM *kacs-abi.struct-kacs-object-type-entry" }, function(t)
        local fd = fresh()
        local root, child = string.rep("\1", 16), string.rep("\2", 16)
        -- An object ACE scoped to the child GUID: it can only match if
        -- each entry's GUID is read from offset 4 of a 20-byte slot.
        local sd = access.sd({
            owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM,
            dacl = access.acl({ access.ace(access.ACE.ALLOWED_OBJECT, 0x1,
                token.SID.TEST_USER, 0, { object_type = child }) }),
        })
        local r = access.check_list(vm, { token_fd = fd, sd = sd, desired = 0x1,
            tree = { { level = 0, guid = root }, { level = 1, guid = child } } })
        t:assert(r.ok, "a two-node tree is accepted: " .. sys.errname(r.errno))
        t:assert_eq(#r.nodes, 2, "and answered node by node — stride 20")
        t:assert_eq(r.nodes[2].granted, 0x1,
            "the second entry's GUID at offset 4 matched the object ACE")
        -- level is the u16 at 0: a gap in the sequence is refused
        -- (§3.8.5), which only holds if the level is read there.
        local gap = access.check_list(vm, { token_fd = fd, sd = sd, desired = 0x1,
            tree = { { level = 0, guid = root }, { level = 2, guid = child } } })
        t:assert_eq(gap.errno, sys.E.INVAL,
            "a level gap is refused, so level is the u16 at 0: " ..
            sys.errname(gap.errno))
        sys.close(vm, fd)
    end)

test("struct kacs_node_result is 8 bytes: granted at 0, status at 4",
    { spec = "PKM *kacs-abi.struct-kacs-node-result" }, function(t)
        local fd = fresh()
        local root = string.rep("\3", 16)
        local left, right = string.rep("\4", 16), string.rep("\5", 16)
        -- An object ACE scoped to the right-hand sibling: three nodes,
        -- two outcomes, so each result must land in its own 8-byte slot.
        local sd = access.sd({
            owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM,
            dacl = access.acl({
                access.ace(access.ACE.ALLOWED_OBJECT, 0x1, token.SID.TEST_USER,
                    0, { object_type = right }),
            }),
        })
        local r = access.check_list(vm, { token_fd = fd, sd = sd, desired = 0x1,
            tree = { { level = 0, guid = root }, { level = 1, guid = left },
                     { level = 1, guid = right } } })
        t:assert_eq(#r.nodes, 3, "three results, 8 bytes apart")
        t:assert_eq(r.nodes[3].granted, 0x1,
            "the scoped node's granted mask is the u32 at 0")
        t:assert_eq(r.nodes[3].status, 0, "and its status the s32 at 4")
        t:assert_eq(r.nodes[2].granted, 0, "its sibling was granted nothing")
        t:assert_eq(r.nodes[2].status, -13,
            "carrying -EACCES in the signed word at 4")
        sys.close(vm, fd)
    end)

test("struct kacs_open_how is 32 bytes with the fields at their offsets",
    { spec = "PKM *kacs-abi.struct-kacs-open-how" }, function(t)
        local p = B .. "/openhow"
        -- desired_access at 0, create_disposition at 4, create_options at
        -- 8, flags at 12, sd_ptr at 16 and sd_len at 24: a create with a
        -- caller-supplied descriptor uses every one of them.
        local sd = kacs.grant(kacs.ALL_RIGHTS)
        local fd, status = facs.open(vm, p, {
            access = kacs.RIGHT.READ_DATA | kacs.RIGHT.WRITE_DATA,
            disposition = kacs.DISPOSITION.CREATE, sd = sd,
        })
        t:assert(fd, "a create with a descriptor: " .. sys.errname(status or 0))
        t:assert_eq(status, facs.STATUS.CREATED,
            "create_disposition was read at 4")
        sys.close(vm, fd)
        local stored = assert(kacs.get_sd(vm, p))
        t:assert(#stored > 0, "and sd_ptr at 16 with sd_len at 24 was stored")
        -- The u32 at 28 is padding the kernel requires to be zero.
        local _, e = facs.open(vm, p, { access = kacs.RIGHT.READ_DATA,
            disposition = kacs.DISPOSITION.OPEN, pad = 1 })
        t:assert_eq(e, sys.E.INVAL,
            "the pad word at 28 must be zero: " .. sys.errname(e or 0))
        -- create_options at 8: DIRECTORY on a regular file is refused.
        local _, e2 = facs.open(vm, p, { access = kacs.RIGHT.READ_DATA,
            options = kacs.CREATE_OPT.DIRECTORY })
        t:assert(e2, "create_options is read at 8: " .. sys.errname(e2 or 0))
    end)

test("struct kacs_mount_policy_args is 32 bytes: policy 0, flags 4, generation 8",
    { spec = "PKM *kacs-abi.struct-kacs-mount-policy-args" }, function(t)
        local fd = assert(sys.open(vm, "/", sys.O.RDONLY | sys.O.DIRECTORY))
        local r = vm:syscall(kacs.SYS.GET_MOUNT_POLICY, {
            args = { fd, 0, 32 }, bufs = { string.rep("\0", 32) }, ptrs = { 1 },
        })
        t:assert_eq(r.ret, 0, "the snapshot is returned")
        local policy, flags, generation = string.unpack("<I4I4I4", r.out_bufs[1])
        t:assert(policy >= 1 and policy <= 4,
            "policy at 0 is a mount-policy value: " .. policy)
        t:assert_eq(flags, 0, "flags at 4")
        t:assert(generation >= 0, "generation at 8: " .. generation)
        -- template_sd_ptr at 16 with template_sd_len at 24: a length
        -- naming bytes that are not a descriptor is rejected there.
        local bad = vm:syscall(kacs.SYS.SET_MOUNT_POLICY, {
            args = { fd, 0, 32 },
            bufs = { string.pack("<I4I4I4I4I8I4I4",
                kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL, 0, 0, 0, 0, 8, 0),
                "notansd!" },
            ptrs = { 1 },
            nested = { { parent = 1, child = 2, offset = 16 } },
        })
        t:assert_neq(bad.ret, 0,
            "an eight-byte template SD is refused: " .. sys.errname(bad.errno))
        sys.close(vm, fd)
    end)

test("struct kacs_generic_mapping is 16 bytes: read, write, execute, all",
    { spec = "PKM *kacs-abi.struct-kacs-generic-mapping" }, function(t)
        -- The four words in that order, inline in the AccessCheck args
        -- at 24..36. Each generic bit folds to its own word, so a
        -- mapping whose four entries are four distinct bits shows which
        -- word each generic right consulted.
        local fd = fresh()
        local MAP = { read = 0x1, write = 0x2, execute = 0x4,
                      all = 0x1 | 0x2 | 0x4 | 0x8 }
        local sd = access.simple({ access.ace(access.ACE.ALLOWED,
            MAP.all, token.SID.TEST_USER) })
        local function granted(generic)
            return access.check(vm, { token_fd = fd, sd = sd,
                desired = generic, mapping = MAP }).granted
        end
        t:assert_eq(granted(access.STD.GENERIC_READ), 0x1, "read is the word at 0")
        t:assert_eq(granted(access.STD.GENERIC_WRITE), 0x2, "write at 4")
        t:assert_eq(granted(access.STD.GENERIC_EXECUTE), 0x4, "execute at 8")
        t:assert_eq(granted(access.STD.GENERIC_ALL), MAP.all, "all at 12")
        sys.close(vm, fd)
    end)

test("each argument block declares a minimum size the kernel enforces",
    { spec = "PKM *kacs-abi.arg-block-min-sizes" }, function(t)
        local p = facs.file(vm, B .. "/minsize", "m")
        -- KACS_OPEN_HOW_MIN_SIZE is 16.
        local _, short = facs.open(vm, p,
            { access = kacs.RIGHT.READ_DATA, howsize = 15 })
        t:assert_eq(short, sys.E.INVAL,
            "howsize 15 is refused: " .. sys.errname(short or 0))
        local fd = facs.open(vm, p,
            { access = kacs.RIGHT.READ_DATA, howsize = 16 })
        t:assert(fd, "howsize 16 is the smallest accepted")
        sys.close(vm, fd)
        -- KACS_MOUNT_POLICY_ARGS_MIN_SIZE is 16.
        local dirfd = assert(sys.open(vm, "/", sys.O.RDONLY | sys.O.DIRECTORY))
        t:assert_eq(vm:syscall(kacs.SYS.GET_MOUNT_POLICY, {
            args = { dirfd, 0, 15 }, bufs = { string.rep("\0", 32) },
            ptrs = { 1 },
        }).errno, sys.E.INVAL, "argsize 15 is refused")
        t:assert_eq(vm:syscall(kacs.SYS.GET_MOUNT_POLICY, {
            args = { dirfd, 0, 16 }, bufs = { string.rep("\0", 32) },
            ptrs = { 1 },
        }).ret, 0, "argsize 16 is accepted")
        sys.close(vm, dirfd)
    end)
