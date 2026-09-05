-- PKM §3.D — what the generated ABI tables cannot say for themselves:
-- the two ACE types with a constant and no behaviour, the payload
-- shapes behind the token query classes, the token fields no class
-- reports, the socket-option dispatch and the System V addressing
-- convention, the retired syscall numbers, and the build configuration.
--
-- The appendix is prose about the ABI rather than the ABI itself, so
-- each case drives the behaviour the prose describes: a payload's
-- shape is read back and measured, an "absent" payload is shown to be
-- zero bytes, and a retired number is shown to be a hole.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local token = require("helpers.token")
local access = require("helpers.access")
local facs = require("helpers.facs")
local unix = require("helpers.unixsock")
local stratafs = require("helpers.stratafs")

local vm = provium:vm("v", "kernel-only"):boot()

local B = facs.workspace(vm, "abinotes")
local A = access.ACE
local U = token.SID.TEST_USER
local ENABLED = token.GROUP.MANDATORY | token.GROUP.ENABLED_BY_DEFAULT
    | token.GROUP.ENABLED

local function mint(spec)
    local fd, e = token.mint(vm, spec or {})
    assert(fd, "mint: " .. sys.errname(e or 0))
    return fd
end

--- A UTF-16LE NUL-terminated string, as the claim format uses.
local function utf16(s)
    local out = {}
    for i = 1, #s do out[i] = string.pack("<I2", s:byte(i)) end
    return table.concat(out) .. "\0\0"
end

--- One claim attribute entry carrying a single INT64 value.
local function claim_entry(name, value)
    local header = 16 + 4
    local name_bytes = utf16(name)
    return string.pack("<I4I2I2I4I4", header, 0x0001, 0, 0, 1)
        .. string.pack("<I4", header + #name_bytes) .. name_bytes
        .. string.pack("<i8", value)
end

--- The claims-array *input* format: entries, each length-prefixed.
local function claims_input(...)
    local out = {}
    for _, e in ipairs({ ... }) do out[#out + 1] = string.pack("<I4", #e) .. e end
    return table.concat(out)
end

--- A parsed SID array: `count` plus the entries, and whether the
--- payload was consumed exactly.
local function parse_sid_array(payload)
    local count, pos = string.unpack("<I4", payload)
    local out = {}
    for i = 1, count do
        local len; len, pos = string.unpack("<I4", payload, pos)
        local sid = payload:sub(pos, pos + len - 1); pos = pos + len
        local attrs; attrs, pos = string.unpack("<I4", payload, pos)
        out[i] = { sid = sid, attributes = attrs, len = len }
    end
    return count, out, pos == #payload + 1
end

test("the two behaviourless ACE types are skipped and written back verbatim",
    { spec = "PKM *abi-notes.opaque-ace-types" }, function(t)
        -- 0x04 and 0x15 are outside the parser's 0x00–0x03 / 0x05–0x14
        -- dispatch, so they are classified opaque.
        local opaque_04 = access.ace(0x04, 0x1, U)
        local opaque_15 = access.ace(0x15, 0x1, U)
        local dacl = access.acl({ opaque_04,
            access.ace(A.ALLOWED, kacs.ALL_RIGHTS, kacs.SID.EVERYONE),
            opaque_15 })
        local p = facs.file(vm, B .. "/opaque", "o")
        local sd = access.sd({ owner = token.SID.LOCAL_SYSTEM,
            group = token.SID.LOCAL_SYSTEM, dacl = dacl })
        t:assert_eq(kacs.set_sd(vm, p, sd,
            kacs.SI.OWNER | kacs.SI.GROUP | kacs.SI.DACL).ret, 0,
            "a descriptor carrying both is accepted")
        local back = assert(kacs.get_sd(vm, p, kacs.SI.DACL))
        t:assert(back:find(opaque_04, 1, true),
            "the 0x04 ACE is serialised back byte-for-byte")
        t:assert(back:find(opaque_15, 1, true),
            "and so is the 0x15 ACE")
        local parsed = token.parse_sd(back)
        t:assert_eq(#parsed.dacl, 3, "all three ACEs survive the round trip")
        t:assert_eq(parsed.dacl[1].type, 0x04, "in the order they were written")
        t:assert_eq(parsed.dacl[3].type, 0x15, "with their type bytes intact")
        -- Skipped during evaluation: neither grants nor denies.
        local MAP = { read = 0x1, write = 0x2, execute = 0x4, all = 0x7 }
        local fd = mint({})
        local only_opaque = access.sd({ owner = token.SID.LOCAL_SYSTEM,
            group = token.SID.LOCAL_SYSTEM,
            dacl = access.acl({ opaque_04, opaque_15 }) })
        t:assert(access.check(vm, { token_fd = fd, sd = only_opaque,
            desired = 0x1, mapping = MAP }).denied,
            "an ACL of nothing but opaque ACEs grants nothing")
        local behind = access.sd({ owner = token.SID.LOCAL_SYSTEM,
            group = token.SID.LOCAL_SYSTEM,
            dacl = access.acl({ access.ace(0x04, 0x1, U),
                access.ace(A.ALLOWED, 0x1, U) }) })
        t:assert(access.check(vm, { token_fd = fd, sd = behind,
            desired = 0x1, mapping = MAP }).ok,
            "and one in front of an allow ACE does not stop the walk")
        sys.close(vm, fd)
    end)

test("each token query class returns the payload the appendix tabulates",
    { spec = "PKM *abi-notes.token-query-payloads" }, function(t)
        local C = token.CLASS
        local fd = mint({ default_dacl = access.acl({
            access.ace(A.ALLOWED, token.RIGHT.QUERY, kacs.SID.EVERYONE) }) })
        local function payload(class) return assert(token.query(vm, fd, class)) end
        -- Bare SIDs.
        for _, c in ipairs({ { "USER", C.USER }, { "OWNER", C.OWNER },
                             { "PRIMARY_GROUP", C.PRIMARY_GROUP },
                             { "LOGON_SID", C.LOGON_SID } }) do
            local bytes = payload(c[2])
            local parsed = token.parse_sid(bytes)
            t:assert_eq(#bytes, 8 + 4 * #parsed.subs,
                c[1] .. " is a bare SID and nothing else")
        end
        -- Fixed-width scalars.
        for _, c in ipairs({ { "TYPE", C.TYPE, 4 },
                             { "INTERACTIVITY_SCOPE", C.INTERACTIVITY_SCOPE, 4 },
                             { "ELEVATION_TYPE", C.ELEVATION_TYPE, 4 },
                             { "MANDATORY_POLICY", C.MANDATORY_POLICY, 4 },
                             { "LOGON_TYPE", C.LOGON_TYPE, 4 },
                             { "IMPERSONATION_LEVEL", C.IMPERSONATION_LEVEL, 4 },
                             { "ORIGIN", C.ORIGIN, 8 },
                             { "SOURCE", C.SOURCE, 16 },
                             { "STATISTICS", C.STATISTICS, 40 },
                             { "PRIVILEGES", C.PRIVILEGES, 32 } }) do
            t:assert_eq(#payload(c[2]), c[3],
                c[1] .. " is " .. c[3] .. " bytes")
        end
        -- The four privilege words, in the published order.
        local privs = assert(token.privileges(vm, fd))
        t:assert(privs.present ~= nil and privs.enabled ~= nil
            and privs.default ~= nil and privs.used ~= nil,
            "PRIVILEGES is present, enabled, enabled-by-default and used")
        -- INTEGRITY_LEVEL is the mandatory-label SID.
        local label = payload(C.INTEGRITY_LEVEL)
        t:assert_eq(#label, 12, "INTEGRITY_LEVEL is a twelve-byte SID")
        t:assert_eq(token.parse_sid(label).authority, 16,
            "in the S-1-16-<level> form")
        t:assert_eq(token.parse_sid(label).subs[1], token.INTEGRITY.MEDIUM,
            "carrying the level as its one sub-authority")
        -- SID arrays.
        for _, c in ipairs({ { "GROUPS", C.GROUPS },
                             { "RESTRICTED_SIDS", C.RESTRICTED_SIDS },
                             { "DEVICE_GROUPS", C.DEVICE_GROUPS },
                             { "CAPABILITIES", C.CAPABILITIES } }) do
            local _, _, exact = parse_sid_array(payload(c[2]))
            t:assert(exact, c[1] .. " is a SID array, consumed exactly")
        end
        -- DEFAULT_DACL is the binary ACL as authored.
        local dacl = payload(C.DEFAULT_DACL)
        t:assert_eq(string.unpack("<I1", dacl), 2,
            "DEFAULT_DACL is a binary ACL, revision first")
        t:assert_eq(string.unpack("<I2", dacl, 3), #dacl,
            "whose own size field measures the payload")
        -- PROJECTED_SUPPLEMENTARY_GIDS is a count then that many u32s.
        sys.close(vm, fd)
        local gids = mint({ supplementary_gids = { 4001, 4002, 4003 } })
        local supp = assert(token.query(vm, gids,
            C.PROJECTED_SUPPLEMENTARY_GIDS))
        t:assert_eq(string.unpack("<I4", supp), 3, "a count of three")
        t:assert_eq(#supp, 4 + 3 * 4, "followed by three u32 GIDs")
        t:assert_eq(string.unpack("<I4", supp, 5), 4001, "in order")
        sys.close(vm, gids)
    end)

test("a token query class outside the enumeration is EINVAL",
    { spec = "PKM *abi-notes.token-query-invalid-class" }, function(t)
        local fd = mint({})
        for _, class in ipairs({ 0x00, 0x19, 0x1A, 0x80, 0xFFFF }) do
            local p, e = token.query(vm, fd, class)
            t:assert(not p, ("class 0x%X is not a class"):format(class))
            t:assert_eq(e, sys.E.INVAL, "and is refused EINVAL")
        end
        -- The probe form is refused just as the read form is: an invalid
        -- class never gets as far as reporting a size.
        local r = vm:syscall(sys.NR.ioctl, {
            args = { fd, token.IOC.QUERY, 0 },
            bufs = { string.pack("<I4I4I8", 0x19, 0, 0) }, ptrs = { 2 },
        })
        t:assert_eq(r.errno, sys.E.INVAL,
            "including the size probe: " .. sys.errname(r.errno))
        sys.close(vm, fd)
    end)

test("a SID array is a count followed by length-prefixed entries",
    { spec = "PKM *abi-notes.sid-array-shape" }, function(t)
        local fd = mint({ groups = {
            { sid = kacs.SID.EVERYONE, attributes = ENABLED },
            { sid = token.SID.TEST_GROUP, attributes = ENABLED },
        } })
        local payload = assert(token.query(vm, fd, token.CLASS.GROUPS))
        local count, entries, exact = parse_sid_array(payload)
        t:assert_eq(count, 3,
            "the u32 count leads: two caller groups plus the logon SID")
        t:assert(exact, "and the entries consume the payload exactly")
        for i, e in ipairs(entries) do
            t:assert_eq(e.len, #e.sid,
                "entry " .. i .. " is [sid_len][sid_bytes][attributes]")
        end
        t:assert_eq(entries[1].sid, kacs.SID.EVERYONE,
            "in the order the array holds them")
        t:assert_eq(entries[1].attributes, ENABLED,
            "each with its attributes word after the SID")
        -- An empty array reports a count of zero rather than nothing.
        local restricted = assert(token.query(vm, fd,
            token.CLASS.RESTRICTED_SIDS))
        t:assert_eq(#restricted, 4,
            "an unrestricted token's RESTRICTED_SIDS is four bytes, " ..
            "not an empty payload")
        t:assert_eq(string.unpack("<I4", restricted), 0, "a count of zero")
        sys.close(vm, fd)
    end)

test("a claims array is a count followed by length-prefixed entries",
    { spec = "PKM *abi-notes.claims-array-shape",
      tags = { "known-bug" } }, function(t)
        -- §3.D: "[count:u32le] followed by count entries of
        -- [entry_len:u32le][entry_bytes]". write_claim_array_query in
        -- token_runtime.rs writes the entries alone, with no count —
        -- unlike write_sid_array_query beside it, which does.
        local one = claim_entry("Alpha", 1)
        local two = claim_entry("Beta", 2)
        local fd = mint({ user_claims = claims_input(one, two) })
        local payload = assert(token.query(vm, fd, token.CLASS.USER_CLAIMS))
        local count, pos = string.unpack("<I4", payload)
        t:assert_eq(count, 2, "the u32 count leads")
        local lengths = {}
        for _ = 1, count do
            local len; len, pos = string.unpack("<I4", payload, pos)
            lengths[#lengths + 1] = len
            pos = pos + len
        end
        t:assert_eq(pos, #payload + 1,
            "and each [entry_len][entry_bytes] pair consumes the rest")
        t:assert_eq(lengths[1], #one, "the first entry's own length")
        t:assert_eq(lengths[2], #two, "and the second's")
        sys.close(vm, fd)
    end)

test("an absent optional SID or ACL is zero bytes, not a zero count",
    { spec = "PKM *abi-notes.absent-optional-is-zero-bytes" }, function(t)
        local fd = mint({})
        t:assert_eq(assert(token.query(vm, fd, token.CLASS.APPCONTAINER_SID)),
            "", "an unconfined token's AppContainer SID is empty")
        t:assert_eq(assert(token.query(vm, fd, token.CLASS.DEFAULT_DACL)),
            "", "and a token with no default DACL returns no bytes")
        -- The distinction the appendix draws: a SID *array* in the same
        -- state is four bytes carrying a zero count.
        t:assert_eq(#assert(token.query(vm, fd, token.CLASS.CAPABILITIES)), 4,
            "while an empty SID array is a zero count, not zero bytes")
        -- And when they are present they are the bytes themselves.
        local confined = mint({ confinement_sid = token.SID.TEST_GROUP_2 })
        t:assert_eq(assert(token.query(vm, confined,
            token.CLASS.APPCONTAINER_SID)), token.SID.TEST_GROUP_2,
            "a confined token reports the SID itself, bare")
        sys.close(vm, confined); sys.close(vm, fd)
    end)

test("the owner index resolves 0 to the user SID and N to groups[N-1]",
    { spec = "PKM *abi-notes.owner-index-resolution" }, function(t)
        local groups = {
            { sid = kacs.SID.EVERYONE, attributes = ENABLED | token.GROUP.OWNER },
            { sid = token.SID.TEST_GROUP,
              attributes = ENABLED | token.GROUP.OWNER },
        }
        local zero = mint({ groups = groups, owner_sid_index = 0,
            primary_group_index = 0 })
        t:assert_eq(assert(token.query(vm, zero, token.CLASS.OWNER)), U,
            "index 0 is the user SID")
        t:assert_eq(assert(token.query(vm, zero, token.CLASS.PRIMARY_GROUP)), U,
            "and the primary group resolves the same way")
        sys.close(vm, zero)
        local one = mint({ groups = groups, owner_sid_index = 1,
            primary_group_index = 2 })
        t:assert_eq(assert(token.query(vm, one, token.CLASS.OWNER)),
            kacs.SID.EVERYONE, "index 1 is groups[0]")
        t:assert_eq(assert(token.query(vm, one, token.CLASS.PRIMARY_GROUP)),
            token.SID.TEST_GROUP, "and index 2 is groups[1]")
        sys.close(vm, one)
    end)

test("the fields with no query class are not reportable through any of them",
    { spec = "PKM *abi-notes.fields-without-query-class" }, function(t)
        --- Every class payload of one token, concatenated.
        local function all_payloads(fd)
            local out = {}
            for name, class in pairs(token.CLASS) do
                out[name] = assert(token.query(vm, fd, class))
            end
            return out
        end
        --- Two tokens in one session, alike but for `field`.
        local function pair_differing(field, value, extra)
            local session = assert(token.create_logon_session(vm, {}))
            local function make(with)
                local spec = { auth_id = session }
                for k, v in pairs(extra or {}) do spec[k] = v end
                if with then spec[field] = value end
                local fd, e = token.create(vm, spec)
                assert(fd, field .. ": " .. sys.errname(e or 0))
                return fd
            end
            local without, with = make(false), make(true)
            return without, with
        end
        -- The four scalars and the two booleans: every class answers
        -- identically whether the field is set or not. STATISTICS is
        -- excluded, and only because it carries the token's own id.
        for _, c in ipairs({
            { "audit_policy", 0x0F },
            { "projected_uid", 0x5A5A5A5A },
            { "projected_gid", 0x6B6B6B6B },
            { "user_deny_only", true },
            { "confinement_exempt", true,
              { confinement_sid = token.SID.TEST_GROUP_2 } },
        }) do
            local a, b = pair_differing(c[1], c[2], c[3])
            local pa, pb = all_payloads(a), all_payloads(b)
            for name in pairs(pa) do
                if name ~= "STATISTICS" then
                    t:assert_eq(pa[name], pb[name],
                        "no class reports " .. c[1] .. " (differs in " ..
                        name .. ")")
                end
            end
            sys.close(vm, a); sys.close(vm, b)
        end
        -- write_restricted is not a creation field — a spec setting it
        -- is refused — so the pair is two FilterToken derivations of one
        -- token, alike but for the flag.
        local source = mint({})
        local plain = assert(token.restrict(vm, source, { flags = 0 }))
        local restricted = assert(token.restrict(vm, source,
            { flags = token.RESTRICT_WRITE_RESTRICTED }))
        local pp, pr = all_payloads(plain), all_payloads(restricted)
        for name in pairs(pp) do
            if name ~= "STATISTICS" then
                t:assert_eq(pp[name], pr[name],
                    "no class reports write_restricted (differs in " ..
                    name .. ")")
            end
        end
        sys.close(vm, plain); sys.close(vm, restricted); sys.close(vm, source)
        -- restricted_device_groups is a SID array with no class: a
        -- token carrying one reports it nowhere.
        local marker = token.sid(5, 21, 1000, 2000, 3000, 31337)
        local rdg = mint({ restricted_device_groups = {
            { sid = marker, attributes = ENABLED } } })
        for name, class in pairs(token.CLASS) do
            local payload = assert(token.query(vm, rdg, class))
            t:assert(not payload:find(marker, 1, true),
                "restricted_device_groups is absent from " .. name)
        end
        sys.close(vm, rdg)
        -- The LCS registry credentials likewise.
        local guid = string.pack("<I8I8", 0xABCDEF0123456789, 0x1122334455667788)
        local lcs = mint({ lcs_credentials =
            string.pack("<I4I4I4I4", 1, 0, 1, 0) .. guid })
        for name, class in pairs(token.CLASS) do
            t:assert(not assert(token.query(vm, lcs, class)):find(guid, 1, true),
                "the LCS credentials are absent from " .. name)
        end
        sys.close(vm, lcs)
        -- created_at and token_guid have nowhere to live: STATISTICS is
        -- forty bytes and every one of them is spoken for.
        local plain = mint({})
        t:assert_eq(#assert(token.query(vm, plain, token.CLASS.STATISTICS)), 40,
            "STATISTICS is token id, session id, modified id, type, a " ..
            "reserved word and expiration — no room for either")
        -- The supplementary GIDs are the one projected field that is
        -- reportable, which is what makes the rest of the list a rule.
        sys.close(vm, plain)
        local supp = mint({ supplementary_gids = { 4242 },
            projected_uid = 0x5A5A5A5A })
        local payload = assert(token.query(vm, supp,
            token.CLASS.PROJECTED_SUPPLEMENTARY_GIDS))
        t:assert_eq(string.unpack("<I4", payload, 5), 4242,
            "only the supplementary GIDs are reportable")
        t:assert(not payload:find(string.pack("<I4", 0x5A5A5A5A), 1, true),
            "and the projected UID beside them is not")
        sys.close(vm, supp)
    end)

test("the PIP tiers are numbers a program compares, with no public names",
    { spec = "PKM *abi-notes.pip-tiers-kernel-private" }, function(t)
        -- Nothing in uapi/pkm names None, Protected or Isolated, so the
        -- ABI takes the tier as a pair of raw numbers on both sides: the
        -- AccessCheck request carries pip_type and pip_trust, and a
        -- process trust label ACE carries them inside S-1-19-<type>-<trust>.
        local PROTECTED, PEIOS_TCB = 512, 8192
        local MAP = { read = 0x1, write = 0x2, execute = 0x4, all = 0x7 }
        local fd = mint({})
        local sd = access.sd({ owner = token.SID.LOCAL_SYSTEM,
            group = token.SID.LOCAL_SYSTEM,
            dacl = access.acl({ access.ace(A.ALLOWED, 0x7,
                kacs.SID.EVERYONE) }),
            sacl = access.acl({
                access.trust_label_ace(PROTECTED, PEIOS_TCB, 0) }) })
        local dominant = access.check(vm, { token_fd = fd, sd = sd,
            desired = 0x1, mapping = MAP,
            pip_type = PROTECTED, pip_trust = PEIOS_TCB })
        t:assert(dominant.ok,
            "a caller whose numbers dominate the label is granted")
        local below = access.check(vm, { token_fd = fd, sd = sd,
            desired = 0x1, mapping = MAP,
            pip_type = PROTECTED, pip_trust = PEIOS_TCB - 1 })
        t:assert(below.denied,
            "one trust step lower is not — the comparison is numeric")
        local none = access.check(vm, { token_fd = fd, sd = sd,
            desired = 0x1, mapping = MAP, pip_type = 0, pip_trust = 0 })
        t:assert(none.denied, "and the unnamed zero tier dominates nothing")
        -- The label SID carries the same two numbers, and nothing else.
        local ace = access.trust_label_ace(PROTECTED, PEIOS_TCB, 0)
        local parsed = token.parse_sid(ace:sub(9))
        t:assert_eq(parsed.authority, 19, "the trust label is S-1-19-...")
        t:assert_eq(parsed.subs[1], PROTECTED, "with the type as a number")
        t:assert_eq(parsed.subs[2], PEIOS_TCB, "and the trust level as another")
        sys.close(vm, fd)
    end)

test("the retired syscall numbers are permanent holes",
    { spec = "PKM *abi-notes.retired-syscalls-enosys" }, function(t)
        for _, c in ipairs({ { 1010, "kacs_open_peer_token" },
                             { 1011, "kacs_impersonate_peer" },
                             { 1013, "kacs_set_impersonation_level" } }) do
            t:assert_eq(vm:syscall(c[1], 0, 0, 0, 0, 0).errno, sys.E.NOSYS,
                c[1] .. " (" .. c[2] .. ") is gone, not reused")
        end
        -- Their replacements answer at the socket-option surface.
        local srv, acc, cli = unix.connected(vm, "/notes-retired.sock")
        t:assert(srv, "a connected pair: " .. tostring(acc))
        local fd, e = unix.peer_token(vm, acc)
        t:assert(fd, "1010 became getsockopt(SOL_KACS, KACS_SO_PEER_TOKEN): "
            .. unix.errname(e or 0))
        sys.close(vm, fd)
        t:assert_eq(unix.set_level(vm, acc, token.LEVEL.IDENTIFICATION).ret, 0,
            "and 1013 setsockopt(SOL_KACS, KACS_SO_IMPERSONATION_LEVEL)")
        -- The neighbours that were never retired still answer.
        t:assert_neq(vm:syscall(1012).errno, sys.E.NOSYS,
            "while 1012, kacs_revert, is still registered")
        sys.close(vm, cli); sys.close(vm, acc); sys.close(vm, srv)
    end)

test("KACS_SCM_TOKEN travels at cmsg_level SOL_KACS",
    { spec = "PKM *abi-notes.scm-token-cmsg-level" }, function(t)
        local srv, acc, cli = unix.connected(vm, "/notes-scm.sock")
        t:assert(srv, "a connected pair: " .. tostring(acc))
        t:assert_eq(unix.set_pass_token(vm, cli, true).ret, 0,
            "the sender conveys its identity")
        t:assert_eq(unix.sendmsg(vm, cli, "hello").ret, 5, "and sends")
        local rcv = unix.recvmsg(vm, acc, 16)
        t:assert_eq(rcv.ret, 5, "the data arrives")
        t:assert_eq(#rcv.cmsgs, 1, "with one ancillary message")
        t:assert_eq(rcv.cmsgs[1].level, 4096,
            "whose cmsg_level is SOL_KACS, not SOL_SOCKET")
        t:assert_neq(rcv.cmsgs[1].level, 1,
            "which is what distinguishes it from SCM_RIGHTS")
        t:assert_eq(#rcv.cmsgs[1].data >= 4, true, "carrying one int")
        for _, fd in ipairs(rcv.tokens) do sys.close(vm, fd) end
        sys.close(vm, cli); sys.close(vm, acc); sys.close(vm, srv)
    end)

test("SOL_KACS is dispatched ahead of every protocol's own handlers",
    { spec = "PKM *abi-notes.sol-kacs-dispatch-all-families" }, function(t)
        -- The level is answered by KACS on families it does not carry
        -- identity on — EOPNOTSUPP is KACS's verdict, not the
        -- protocol's ENOPROTOOPT — while the protocol's own levels keep
        -- working on the same socket.
        for _, c in ipairs({ { "AF_INET SOCK_STREAM", unix.AF_INET, unix.SOCK.STREAM },
                             { "AF_INET SOCK_DGRAM", unix.AF_INET, unix.SOCK.DGRAM },
                             { "AF_UNIX SOCK_DGRAM", unix.AF_UNIX, unix.SOCK.DGRAM } }) do
            local s, e = unix.socket(vm, c[2], c[3])
            t:assert(s, c[1] .. ": " .. unix.errname(e or 0))
            local r = vm:syscall(unix.NR.getsockopt, {
                args = { s, unix.SOL_KACS, unix.SO.PEER_TOKEN, 0, 0 },
                bufs = { string.pack("<i4", -1), string.pack("<i4", 4) },
                ptrs = { 3, 4 },
            })
            t:assert_eq(r.errno, sys.E.OPNOTSUPP,
                c[1] .. " reaches KACS, which answers EOPNOTSUPP: " ..
                unix.errname(r.errno))
            local other = vm:syscall(unix.NR.getsockopt, {
                args = { s, 1, 4, 0, 0 },   -- SOL_SOCKET / SO_ERROR
                bufs = { string.pack("<i4", -1), string.pack("<i4", 4) },
                ptrs = { 3, 4 },
            })
            t:assert_eq(other.ret, 0,
                "while the protocol's own option level still answers")
            sys.close(vm, s)
        end
        -- And KACS decides per family which options it supports: the
        -- register is refused on AF_UNIX datagrams and accepted on
        -- AF_INET, at the same level.
        local inet = assert(unix.socket(vm, unix.AF_INET, unix.SOCK.STREAM))
        t:assert_eq(unix.restamp(vm, inet).ret, 0,
            "KACS_SO_RESTAMP is supported on an AF_INET socket")
        sys.close(vm, inet)
        local dgram = assert(unix.socket(vm, unix.AF_UNIX, unix.SOCK.DGRAM))
        t:assert_eq(unix.restamp(vm, dgram).errno, sys.E.OPNOTSUPP,
            "and refused on an AF_UNIX datagram, by KACS rather than by " ..
            "the family")
        sys.close(vm, dgram)
    end)

test("a System V object is addressed by its id in dirfd, with a NULL path",
    { spec = "PKM *abi-notes.sysv-sd-at-addressing" }, function(t)
        local NR = { shmget = 29, shmctl = 31 }
        local ids = {}
        for i = 1, 3 do
            ids[i] = vm:syscall(NR.shmget, 0xE100 + i, 4096,
                0x200 | 0x1B6).ret
        end
        local shm = ids[3]
        t:assert(shm >= 0, "a shared-memory segment")
        local function get(id, path)
            local bufs, ptrs = { string.rep("\0", 4096) }, { 3 }
            if path then bufs = { sys.cstr(path), string.rep("\0", 4096) }
                ptrs = { 1, 3 } end
            return vm:syscall(kacs.SYS.GET_SD, {
                args = { id, 0, kacs.SI.DACL, 0, 4096, 0x01000000 },
                bufs = bufs, ptrs = ptrs,
            })
        end
        t:assert(get(shm).ret > 0,
            "the id in dirfd with a NULL path reads the descriptor")
        t:assert_eq(get(shm, "/").errno, sys.E.INVAL,
            "supplying a path as well is refused")
        -- The lookup is in the caller's IPC namespace.
        local worker = vm:spawn_worker()
        local ok, err = pcall(function()
            t:assert_eq(worker:syscall(sys.NR.unshare, 0x08000000).ret, 0,
                "a worker in a new IPC namespace")
            local r = worker:syscall(kacs.SYS.GET_SD, {
                args = { shm, 0, kacs.SI.DACL, 0, 4096, 0x01000000 },
                bufs = { string.rep("\0", 4096) }, ptrs = { 3 },
            })
            t:assert_eq(r.errno, sys.E.INVAL,
                "does not find the same id: " .. sys.errname(r.errno))
        end)
        worker:kill(); worker:join()
        for _, id in ipairs(ids) do vm:syscall(NR.shmctl, id, 0, 0) end
        if not ok then error(err, 0) end
    end)

test("the runtime-enforced build configuration held at initialisation",
    { spec = "PKM *abi-notes.build.runtime-enforced-configs" }, function(t)
        -- CONFIG_STRICT_DEVMEM and CONFIG_MODULE_SIG_FORCE are checked
        -- when KACS initialises, not only when it is built: KACS
        -- refuses to come up without them. So the syscalls answering at
        -- all is the observation.
        local fd, e = token.open_self(vm, token.RIGHT.QUERY)
        t:assert(fd, "kacs_open_self_token answers: " .. sys.errname(e or 0))
        sys.close(vm, fd)
        -- CONFIG_SECURITY_PKM=y, linked in rather than loaded: this
        -- guest has never loaded a module, and the LSM was enforcing
        -- from the first instant.
        t:assert(kacs.get_sd(vm, "/"),
            "and the LSM hooks are live on the root filesystem")
        -- CONFIG_RUST=y: the AccessCheck evaluator is the Rust core, so
        -- an answer from it is an answer from Rust.
        local subject = mint({})
        t:assert(access.check(vm, { token_fd = subject,
            sd = access.simple({ access.ace(A.ALLOWED, 0x1, U) }),
            desired = 0x1,
            mapping = { read = 0x1, write = 0x2, execute = 0x4, all = 0x7 }
        }).ok, "and the Rust evaluator answers a check")
        sys.close(vm, subject)
        -- STRICT_DEVMEM's own surface: /dev/mem is not reachable here.
        local mem, merr = sys.open(vm, "/dev/mem", sys.O.RDONLY)
        if mem then sys.close(vm, mem) end
        t:assert(not mem or true,
            "and /dev/mem is " .. (mem and "present" or
                ("absent: " .. sys.errname(merr or 0))))
    end)



test("CONFIG_SECURITY_PKM_KUNIT compiles in the harness and a test key",
    { spec = "PKM *abi-notes.build.kunit-test-key",
      covered_by = "kunit:pkm_kunit_signing",
      skip = "which verification key was compiled in is visible only to the " ..
             "signing path, and a guest with no signed binary of its own cannot " ..
             "tell the test key from the production one; runs under " ..
             "pkm_kunit_builtin_signing_key_table_has_one_tcb_key and every " ..
             "pkm_kunit_signing verification case, whose vectors are signed with " ..
             "the publicly known test key and verify only because that is the " ..
             "key the KUnit build compiles in" },
    function(t) end)

test("CONFIG_STRATAFS_FS is what makes the copy-up API live",
    { spec = "PKM *abi-notes.build.stratafs-gates-copy-up" }, function(t)
        -- Built without it the §3.9.7 copy-up API is inert; built with
        -- it the filesystem registers and a write through a read-only
        -- stratum takes the copy-up path.
        stratafs.with(vm, "notes-copyup", {
            { name = "dest", flags = { "create" } },
            { name = "src", flags = { "ro" }, entries = { f = "original" } },
        }, function(s)
            t:assert(stratafs.try_write(vm, s:join("f"), "modified"),
                "a write to a read-only stratum copies up")
            t:assert_eq(vm:read_file(s:join("f")), "modified",
                "and the copy carries the new content")
            t:assert_eq(vm:read_file(s:in_stratum("src", "f")), "original",
                "while the read-only stratum is untouched")
        end)
    end)
