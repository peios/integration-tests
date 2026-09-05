-- PKM §3.B — where KACS departs from MS-DTYP.
--
-- Each row of the departures table is a behaviour, so each case here
-- drives the behaviour rather than the constant: the same token,
-- descriptor and desired mask that MS-DTYP describes, and the answer
-- KACS gives instead.
--
-- The agent is SYSTEM and passes everything, so every evaluator case
-- mints its own subject and hands it to kacs_access_check as
-- `token_fd`; the impersonation cases run in a worker, because
-- impersonation is per-thread and the agent spreads its syscalls
-- across threads.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local token = require("helpers.token")
local access = require("helpers.access")
local facs = require("helpers.facs")

local vm = provium:vm("v", "kernel-only"):boot()

local B = facs.workspace(vm, "dtyp")
local A, STD, L = access.ACE, access.STD, token.LEVEL
local U, U2 = token.SID.TEST_USER, token.SID.TEST_USER_2
local G2 = token.SID.TEST_GROUP_2
local ENABLED = token.GROUP.MANDATORY | token.GROUP.ENABLED_BY_DEFAULT
    | token.GROUP.ENABLED

--- A synthetic object class whose three generic groups are three
--- disjoint bits, so a case can tell which class a granted bit came
--- from.
local READ, WRITE, EXEC = 0x1, 0x2, 0x4
local MAP = { read = READ, write = WRITE, execute = EXEC,
    all = 0x7 | STD.DELETE | STD.READ_CONTROL | STD.WRITE_DAC
        | STD.WRITE_OWNER | STD.SYNCHRONIZE }

--- A minted subject. The spec is copied because `token.mint` stamps the
--- session it creates into it.
local function subject(spec)
    local fresh = {}
    for k, v in pairs(spec or {}) do fresh[k] = v end
    local fd, e = token.mint(vm, fresh)
    assert(fd, "mint: " .. sys.errname(e or 0))
    return fd
end

local function check(fd, sd, desired, opts)
    opts = opts or {}
    return access.check(vm, { token_fd = fd, sd = sd, desired = desired,
        mapping = MAP, claims = opts.claims, tree = opts.tree })
end

-- Conditional-expression bytecode ---------------------------------------------

--- Pad an expression so the ACE containing it keeps a size that is a
--- multiple of four.
local function pad(expr) return expr .. string.rep("\0", (-#expr) % 4) end
local function int_lit(v) return string.pack("<I1i8I1I1", 0x04, v, 0x01, 0x02) end
local function sid_lit(sid) return string.pack("<I1I4", 0x51, #sid) .. sid end
local function composite(...)
    local body = table.concat({ ... })
    return string.pack("<I1I4", 0x50, #body) .. body
end

--- A UTF-16LE string, NUL-terminated unless `bare`.
local function utf16(s, bare)
    local out = {}
    for i = 1, #s do out[i] = string.pack("<I2", s:byte(i)) end
    return table.concat(out) .. (bare and "" or "\0\0")
end

--- An attribute reference: 0xf8 @Local, 0xf9 @User, 0xfa @Resource,
--- 0xfb @Device.
local NS = { LOCAL = 0xf8, USER = 0xf9, RESOURCE = 0xfa, DEVICE = 0xfb }
local function attr(namespace, name)
    local n = utf16(name, true)
    return string.pack("<I1I4", namespace, #n) .. n
end

local OP = { EQ = 0x80, NE = 0x81, LT = 0x82, GT = 0x84, EXISTS = 0x87,
             MEMBER_OF = 0x89 }

--- One claim attribute entry: name at `name_offset`, value type, flags,
--- one value. Fixed-width values sit at their offset; the rest carry an
--- in-entry offset to their payload.
local function claim_entry(name, value_type, flags, value_bytes)
    local header = 16 + 4
    local name_bytes = utf16(name)
    local value_off = header + #name_bytes
    return string.pack("<I4I2I2I4I4", header, value_type, 0, flags or 0, 1)
        .. string.pack("<I4", value_off) .. name_bytes .. value_bytes
end

--- A packed claims array: each entry length-prefixed.
local function claims(...)
    local out = {}
    for _, entry in ipairs({ ... }) do
        out[#out + 1] = string.pack("<I4", #entry) .. entry
    end
    return table.concat(out)
end

local CLAIM = { INT64 = 0x0001, UINT64 = 0x0002, STRING = 0x0003,
                SID = 0x0005, BOOLEAN = 0x0006, OCTET = 0x0010 }

--- A SYSTEM_RESOURCE_ATTRIBUTE ACE: the trustee must be Everyone and
--- the body carries one claim entry, padded so the ACE keeps a size
--- that is a multiple of four.
local function resource_ace(entry)
    return access.ace(A.RESOURCE_ATTRIBUTE, 0, token.SID.EVERYONE, 0,
        { condition = entry .. string.rep("\0", (-#entry) % 4) })
end

--- An allow-callback ACE for `sid` gated on `expr`.
local function callback(sid, expr, mask)
    return access.ace(A.ALLOWED_CALLBACK, mask or READ, sid, 0,
        { condition = pad(expr) })
end

local function owned(owner, dacl, sacl)
    return access.sd({ owner = owner, group = owner, dacl = dacl, sacl = sacl })
end

-- The departures ---------------------------------------------------------------

test("a descriptor in MS-DTYP binary form is stored and evaluated untranslated",
    { spec = "PKM *dtyp.binary-formats-untranslated" }, function(t)
        -- The bytes a Windows domain controller would author: a
        -- self-relative descriptor with an owner, a group and a DACL
        -- whose ACE headers are MS-DTYP's own layout.
        local dacl = access.acl({
            access.ace(A.DENIED, kacs.RIGHT.WRITE_DATA, U2, 0x03),
            access.ace(A.ALLOWED, kacs.ALL_RIGHTS, kacs.SID.EVERYONE, 0x03),
        })
        local sd = access.sd({ owner = U, group = G2, dacl = dacl })
        local p = facs.file(vm, B .. "/wire", "w")
        t:assert_eq(kacs.set_sd(vm, p, sd,
            kacs.SI.OWNER | kacs.SI.GROUP | kacs.SI.DACL).ret, 0,
            "the descriptor is accepted as authored")
        local back = assert(kacs.get_sd(vm, p,
            kacs.SI.OWNER | kacs.SI.GROUP | kacs.SI.DACL))
        local parsed = token.parse_sd(back)
        t:assert_eq(parsed.owner, U, "the owner SID comes back byte-for-byte")
        t:assert_eq(parsed.group, G2, "and the group SID")
        t:assert_eq(#parsed.dacl, 2, "with both ACEs, in the authored order")
        t:assert_eq(parsed.dacl[1].type, A.DENIED, "the deny ACE first")
        t:assert_eq(parsed.dacl[1].sid, U2, "naming the trustee it named")
        t:assert_eq(parsed.dacl[1].flags, 0x03,
            "with its inheritance byte intact")
        t:assert_eq(parsed.dacl[2].mask, kacs.ALL_RIGHTS,
            "and the allow ACE's mask unaltered")
        -- The same bytes, handed straight to the evaluator.
        local fd = subject({})
        t:assert(check(fd, sd, READ).ok,
            "and the evaluator reads the same buffer without translation")
        sys.close(vm, fd)
    end)

test("@Local resolves from the AccessCheck parameter, not from the token",
    { spec = "PKM *dtyp.local-from-accesscheck-parameter" }, function(t)
        local sd = owned(U, access.acl({
            callback(U, "artx" .. attr(NS.LOCAL, "Level") .. int_lit(5)
                .. string.pack("<I1", OP.EQ)) }))
        local fd = subject({})
        local present = claims(claim_entry("Level", CLAIM.INT64, 0,
            string.pack("<i8", 5)))
        t:assert(check(fd, sd, READ, { claims = present }).ok,
            "the attribute the call supplies satisfies the condition")
        t:assert(check(fd, sd, READ).denied,
            "the same token without it satisfies nothing — the context is " ..
            "per-call")
        local other = claims(claim_entry("Level", CLAIM.INT64, 0,
            string.pack("<i8", 6)))
        t:assert(check(fd, sd, READ, { claims = other }).denied,
            "and a different value from the same token is a different answer")
        sys.close(vm, fd)
    end)

test("Member_of({S-1-3-4}) is true for the descriptor's owner",
    { spec = "PKM *dtyp.member-of-owner-virtual-group" }, function(t)
        local expr = "artx" .. sid_lit(token.SID.OWNER_RIGHTS)
            .. string.pack("<I1", OP.MEMBER_OF)
        local dacl = access.acl({ callback(kacs.SID.EVERYONE, expr) })
        local fd = subject({})
        t:assert(check(fd, owned(U, dacl), READ).ok,
            "the owner satisfies the virtual OWNER RIGHTS group")
        t:assert(check(fd, owned(U2, dacl), READ).denied,
            "and a subject who is not the owner does not")
        sys.close(vm, fd)
    end)

test("relational operators promote between INT64 and UINT64",
    { spec = "PKM *dtyp.int64-uint64-promotion" }, function(t)
        local fd = subject({})
        local sd = owned(U, access.acl({
            callback(U, "artx" .. attr(NS.LOCAL, "N") .. int_lit(10)
                .. string.pack("<I1", OP.LT)) }))
        local as_uint = claims(claim_entry("N", CLAIM.UINT64, 0,
            string.pack("<I8", 5)))
        t:assert(check(fd, sd, READ, { claims = as_uint }).ok,
            "a UINT64 claim compares against an INT64 literal")
        local as_int = claims(claim_entry("N", CLAIM.INT64, 0,
            string.pack("<i8", 5)))
        t:assert(check(fd, sd, READ, { claims = as_int }).ok,
            "as does an INT64 one — the two promote to a common type")
        local bigger = claims(claim_entry("N", CLAIM.UINT64, 0,
            string.pack("<I8", 20)))
        t:assert(check(fd, sd, READ, { claims = bigger }).denied,
            "and the comparison is a real ordering, not an always-true")
        sys.close(vm, fd)
    end)

test("Member_of is filtered by ACE polarity: a deny-only group satisfies no allow",
    { spec = "PKM *dtyp.member-of-ace-polarity" }, function(t)
        -- The subject carries G2 as a deny-only group.
        local fd = subject({ groups = {
            { sid = kacs.SID.EVERYONE, attributes = ENABLED },
            { sid = G2, attributes = token.GROUP.USE_FOR_DENY_ONLY },
        } })
        local expr = "artx" .. sid_lit(G2) .. string.pack("<I1", OP.MEMBER_OF)
        local allow = owned(U, access.acl({
            callback(kacs.SID.EVERYONE, expr) }))
        t:assert(check(fd, allow, READ).denied,
            "an allow ACE conditioned on the deny-only group grants nothing")
        local deny = owned(U, access.acl({
            access.ace(A.DENIED_CALLBACK, READ, kacs.SID.EVERYONE, 0,
                { condition = pad(expr) }),
            access.ace(A.ALLOWED, READ, kacs.SID.EVERYONE),
        }))
        t:assert(check(fd, deny, READ).denied,
            "while a deny ACE conditioned on it still applies")
        -- A group the subject holds properly satisfies both polarities.
        local ok_fd = subject({ groups = {
            { sid = kacs.SID.EVERYONE, attributes = ENABLED },
            { sid = G2, attributes = ENABLED },
        } })
        t:assert(check(ok_fd, allow, READ).ok,
            "and an ordinary membership satisfies the allow ACE")
        sys.close(vm, ok_fd); sys.close(vm, fd)
    end)

test("Exists answers over all four attribute namespaces",
    { spec = "PKM *dtyp.exists-all-namespaces" }, function(t)
        local present = claim_entry("Tag", CLAIM.INT64, 0, string.pack("<i8", 1))
        local fd = subject({
            user_claims = claims(present),
            device_claims = claims(claim_entry("DevTag", CLAIM.INT64, 0,
                string.pack("<i8", 1))),
        })
        local function exists(namespace, name, sacl)
            local sd = owned(U, access.acl({ callback(kacs.SID.EVERYONE,
                "artx" .. attr(namespace, name)
                    .. string.pack("<I1", OP.EXISTS)) }), sacl)
            return check(fd, sd, READ, {
                claims = claims(claim_entry("LocalTag", CLAIM.INT64, 0,
                    string.pack("<i8", 1))) })
        end
        t:assert(exists(NS.LOCAL, "LocalTag").ok, "@Local answers Exists")
        t:assert(exists(NS.USER, "Tag").ok, "@User answers Exists")
        t:assert(exists(NS.DEVICE, "DevTag").ok, "@Device answers Exists")
        local resource_sacl = access.acl({ resource_ace(
            claim_entry("ResTag", CLAIM.INT64, 0, string.pack("<i8", 1))) })
        t:assert(exists(NS.RESOURCE, "ResTag", resource_sacl).ok,
            "and @Resource answers Exists")
        t:assert(exists(NS.USER, "Absent").denied,
            "an attribute that is not there answers no")
        sys.close(vm, fd)
    end)

test("an ACE mask is mapped through the GenericMapping at evaluation time",
    { spec = "PKM *dtyp.ace-mask-generic-mapping" }, function(t)
        local fd = subject({})
        -- The ACE grants GENERIC_ALL; the request is a concrete right.
        local sd = owned(U, access.acl({
            access.ace(A.ALLOWED, STD.GENERIC_ALL, kacs.SID.EVERYONE) }))
        local r = check(fd, sd, READ)
        t:assert(r.ok, "GENERIC_ALL in an ACE grants the mapped rights")
        t:assert_eq(check(fd, sd, WRITE).ok, true, "in every class")
        -- One generic class alone maps to that class alone.
        local read_only = owned(U, access.acl({
            access.ace(A.ALLOWED, STD.GENERIC_READ, kacs.SID.EVERYONE) }))
        t:assert(check(fd, read_only, READ).ok,
            "GENERIC_READ maps to the read word")
        t:assert(check(fd, read_only, WRITE).denied,
            "and to nothing else")
        sys.close(vm, fd)
    end)

test("MAXIMUM_ALLOWED is first-writer-wins, exactly as a targeted request is",
    { spec = "PKM *dtyp.maximum-allowed-first-writer-wins" }, function(t)
        local fd = subject({})
        -- Non-canonical: an allow ACE ahead of a deny ACE for the same
        -- bit. MS-DTYP's maximum-allowed walk would let the later deny
        -- remove it; here the first writer fixes the outcome.
        local allow_first = owned(U, access.acl({
            access.ace(A.ALLOWED, READ, kacs.SID.EVERYONE),
            access.ace(A.DENIED, READ, kacs.SID.EVERYONE),
        }))
        t:assert(check(fd, allow_first, READ).ok,
            "a targeted request is granted by the first ACE to decide")
        local maximal = check(fd, allow_first, STD.MAXIMUM_ALLOWED)
        t:assert(maximal.ok, "and MAXIMUM_ALLOWED answers")
        t:assert_eq(maximal.granted & READ, READ,
            "with the same bit — the two questions cannot disagree")
        -- Reversed, both answers change together.
        local deny_first = owned(U, access.acl({
            access.ace(A.DENIED, READ, kacs.SID.EVERYONE),
            access.ace(A.ALLOWED, READ, kacs.SID.EVERYONE),
        }))
        t:assert(check(fd, deny_first, READ).denied,
            "a deny that comes first denies the targeted request")
        t:assert_eq(check(fd, deny_first, STD.MAXIMUM_ALLOWED).granted & READ, 0,
            "and is absent from the maximum")
        sys.close(vm, fd)
    end)

test("a zero desired mask succeeds rather than returning access denied",
    { spec = "PKM *dtyp.zero-desired-mask-succeeds" }, function(t)
        local fd = subject({})
        local closed = owned(U2, access.acl({}))
        t:assert(check(fd, closed, 0).ok,
            "asking for nothing against a DACL that grants nothing succeeds")
        t:assert_eq(check(fd, closed, 0).granted, 0, "and nothing is granted")
        t:assert(check(fd, closed, READ).denied,
            "while asking for something is still denied")
        sys.close(vm, fd)
    end)

test("an alarm ACE drives continuous per-operation auditing",
    { spec = "PKM *dtyp.alarm-ace-continuous-audit" }, function(t)
        local fd = subject({})
        local sacl = access.acl({
            access.ace(A.ALARM, READ | WRITE, kacs.SID.EVERYONE,
                access.ACE_FLAG.SUCCESSFUL_ACCESS) })
        local sd = owned(U, access.acl({
            access.ace(A.ALLOWED, MAP.all, kacs.SID.EVERYONE) }), sacl)
        local r = check(fd, sd, READ)
        t:assert(r.ok, "the check is answered")
        t:assert(r.continuous_audit ~= 0,
            "and the alarm ACE reports a continuous-audit mask, which " ..
            "MS-DTYP reserves and never implements")
        t:assert_eq(r.continuous_audit & READ, READ,
            "carrying the rights the ACE named")
        local plain = owned(U, access.acl({
            access.ace(A.ALLOWED, MAP.all, kacs.SID.EVERYONE) }))
        t:assert_eq(check(fd, plain, READ).continuous_audit, 0,
            "a descriptor with no alarm ACE reports none")
        sys.close(vm, fd)
    end)

test("several scoped-policy ACEs are permitted in one SACL, and AND together",
    { spec = "PKM *dtyp.multiple-scoped-policy-aces" }, function(t)
        local p1 = token.sid(5, 21, 1000, 2000, 3000, 8001)
        local p2 = token.sid(5, 21, 1000, 2000, 3000, 8002)
        local function policy(sid, mask)
            local dacl = access.acl({ access.ace(A.ALLOWED, mask, U) })
            return access.set_caap(vm, sid,
                access.caap_spec({ { effective_dacl = dacl } }))
        end
        local fd = subject({})
        local sd = owned(U, access.acl({
            access.ace(A.ALLOWED, MAP.all, kacs.SID.EVERYONE) }),
            access.acl({
                access.ace(A.SCOPED_POLICY_ID, 0, p1),
                access.ace(A.SCOPED_POLICY_ID, 0, p2),
            }))
        t:assert_eq(policy(p1, READ | WRITE).ret, 0, "the first policy is set")
        t:assert_eq(policy(p2, READ).ret, 0, "and the second")
        t:assert(check(fd, sd, READ).ok,
            "a right both policies grant survives two scoped-policy ACEs")
        t:assert(check(fd, sd, WRITE).denied,
            "and a right only one of them grants does not — the semantics " ..
            "are AND")
        access.set_caap(vm, p1, nil); access.set_caap(vm, p2, nil)
        sys.close(vm, fd)
    end)

test("mandatory_policy is fixed at creation and immutable thereafter",
    { spec = "PKM *dtyp.mandatory-policy-immutable" }, function(t)
        local fd = subject({ mandatory_policy = token.MANDATORY.NO_WRITE_UP })
        t:assert_eq(token.query_u32(vm, fd, token.CLASS.MANDATORY_POLICY),
            token.MANDATORY.NO_WRITE_UP, "the token carries what it was minted with")
        -- None of the eleven adjustment verbs reaches it, and there is
        -- no twelfth.
        t:assert_eq(token.adjust_privs(vm, fd,
            { { token.PRIV.BACKUP, 0 } }).ret, 0, "privileges are adjustable")
        t:assert_eq(token.adjust_interactivity_scope(vm, fd, 3).ret, 0,
            "so is the interactivity scope")
        t:assert_eq(token.query_u32(vm, fd, token.CLASS.MANDATORY_POLICY),
            token.MANDATORY.NO_WRITE_UP,
            "and the mandatory policy is unchanged by either")
        for nr = 0x0B, 0x1F do
            t:assert_eq(vm:syscall(sys.NR.ioctl, {
                args = { fd, 0x40044B00 | nr, 0 },
                bufs = { string.pack("<I4", 0) }, ptrs = { 2 },
            }).errno, sys.E.NOTTY,
                ("no ioctl 0x%02X exists to change it"):format(nr))
        end
        -- A duplicate carries it onward unchanged: it is not a
        -- derivation parameter either.
        local copy = assert(token.duplicate(vm, fd, {}))
        t:assert_eq(token.query_u32(vm, copy, token.CLASS.MANDATORY_POLICY),
            token.MANDATORY.NO_WRITE_UP,
            "and a duplicate inherits it rather than resetting it")
        sys.close(vm, copy); sys.close(vm, fd)
    end)

test("the impersonation integrity ceiling holds whatever privileges are held",
    { spec = "PKM *dtyp.impersonation-ceiling-unconditional" }, function(t)
        local MINTER = token.bit(token.PRIV.TCB)
            | token.bit(token.PRIV.CREATE_TOKEN)
        local IMPERSONATE = token.bit(token.PRIV.IMPERSONATE)
        token.as_principal(t, vm, {
            privs_present = MINTER | IMPERSONATE,
            privs_enabled = MINTER | IMPERSONATE,
            integrity_level = token.INTEGRITY.MEDIUM }, function(w)
            -- Same user, so the identity gate is satisfied outright; the
            -- only thing left to decide is the ceiling.
            local high = assert(token.mint(w, { user_sid = U,
                token_type = token.TYPE.IMPERSONATION,
                impersonation_level = L.IMPERSONATION,
                integrity_level = token.INTEGRITY.HIGH }))
            t:assert_eq(token.impersonate(w, high).ret, 0,
                "the impersonation is accepted")
            local eff = assert(token.effective(vm, w))
            t:assert_eq(eff.level, L.IDENTIFICATION,
                "and SeImpersonatePrivilege does not lift the ceiling")
            t:assert_eq(eff.integrity, token.INTEGRITY.HIGH,
                "the client's own label is kept, so nothing is forged")
            token.revert(w)
            sys.close(w, high)
        end)
    end)

test("there is no impersonation origin check: an unrelated token impersonates",
    { spec = "PKM *dtyp.impersonation-origin-check-dropped" }, function(t)
        local MINTER = token.bit(token.PRIV.TCB)
            | token.bit(token.PRIV.CREATE_TOKEN)
        token.as_principal(t, vm, {
            privs_present = MINTER, privs_enabled = MINTER,
            user_sid = U, integrity_level = token.INTEGRITY.MEDIUM },
            function(w)
                -- A client token in a LogonSession of its own: it did
                -- not come from the server's logon, nor from a network
                -- or RPC path. Windows would want an origin; here the
                -- identity gate and the ceiling are the whole test.
                local client = assert(token.mint(w, { user_sid = U,
                    token_type = token.TYPE.IMPERSONATION,
                    impersonation_level = L.IMPERSONATION,
                    integrity_level = token.INTEGRITY.MEDIUM }))
                t:assert_eq(token.impersonate(w, client).ret, 0,
                    "an unrelated session's token impersonates")
                local eff = assert(token.effective(vm, w))
                t:assert_eq(eff.level, L.IMPERSONATION,
                    "at full Impersonation level, with no origin consulted")
                token.revert(w)
                sys.close(w, client)
            end)
    end)

test("impersonation level is meaningful and queryable on a primary token",
    { spec = "PKM *dtyp.impersonation-level-on-primaries" }, function(t)
        -- Windows rejects TokenImpersonationLevel on a primary; here
        -- every token carries one, it is queryable, and it is a ratchet
        -- bounding everything derived from the token.
        for _, level in ipairs({ L.IMPERSONATION, L.DELEGATION }) do
            local fd = subject({ token_type = token.TYPE.PRIMARY,
                impersonation_level = level })
            t:assert_eq(token.query_u32(vm, fd, token.CLASS.TYPE),
                token.TYPE.PRIMARY, "the token is a primary")
            t:assert_eq(token.query_u32(vm, fd,
                token.CLASS.IMPERSONATION_LEVEL), level,
                "and its level is queryable through TokenImpersonationLevel: "
                    .. level)
            sys.close(vm, fd)
        end
        -- The ratchet: a primary at Impersonation cannot yield a
        -- Delegation-level derivation.
        local capped = subject({ token_type = token.TYPE.PRIMARY,
            impersonation_level = L.IMPERSONATION })
        local up, e = token.duplicate(vm, capped, {
            token_type = token.TYPE.IMPERSONATION,
            impersonation_level = L.DELEGATION })
        if up then
            t:assert_eq(token.query_u32(vm, up,
                token.CLASS.IMPERSONATION_LEVEL), L.IMPERSONATION,
                "a duplicate is bounded by the primary's own level")
            sys.close(vm, up)
        else
            t:assert_eq(e, sys.E.INVAL,
                "or the derivation is refused outright: " ..
                sys.errname(e or 0))
        end
        local same = assert(token.duplicate(vm, capped, {
            token_type = token.TYPE.IMPERSONATION,
            impersonation_level = L.IDENTIFICATION }))
        t:assert_eq(token.query_u32(vm, same,
            token.CLASS.IMPERSONATION_LEVEL), L.IDENTIFICATION,
            "while deriving at or below it is fine")
        sys.close(vm, same)
        -- A primary below Impersonation cannot exist at all: the level
        -- is a real property of the credential, not an ignored field.
        for _, level in ipairs({ L.ANONYMOUS, L.IDENTIFICATION }) do
            local fd, err = token.mint(vm, { token_type = token.TYPE.PRIMARY,
                impersonation_level = level })
            t:assert(not fd, "a primary at level " .. level ..
                " is refused: " .. sys.errname(err or 0))
        end
        sys.close(vm, capped)
    end)

test("a process's PIP is the kernel's alone, taken from the binary signature",
    { spec = "PKM *dtyp.pip-kernel-only-determination",
      covered_by = "kunit:pkm_kunit_signing",
      skip = "no syscall accepts a PIP for a process, so a guest can " ..
             "observe the absence of parent input but not the " ..
             "determination itself: the signature-to-tier mapping and " ..
             "the exec-time assignment run in kernel context under " ..
             "pkm_kunit_signing (verify/probe) and pkm_kunit_process " ..
             "(exec PIP staging and commit)" }, function(t)
    end)

test("an object-type list with duplicate GUIDs or a level gap is refused",
    { spec = "PKM *dtyp.object-type-list-validation" }, function(t)
        local fd = subject({})
        local root = string.rep("\1", 16)
        local child = string.rep("\2", 16)
        local sd = owned(U, access.acl({
            access.ace(A.ALLOWED, MAP.all, kacs.SID.EVERYONE) }))
        t:assert(check(fd, sd, READ,
            { tree = { { level = 0, guid = root },
                       { level = 1, guid = child } } }).ok,
            "a well-formed two-level tree is evaluated")
        local dup = check(fd, sd, READ,
            { tree = { { level = 0, guid = root },
                       { level = 1, guid = root } } })
        t:assert_eq(dup.errno, sys.E.INVAL,
            "a duplicate GUID is refused: " .. sys.errname(dup.errno))
        local gap = check(fd, sd, READ,
            { tree = { { level = 0, guid = root },
                       { level = 2, guid = child } } })
        t:assert_eq(gap.errno, sys.E.INVAL,
            "and so is a level gap: " .. sys.errname(gap.errno))
        local no_root = check(fd, sd, READ,
            { tree = { { level = 1, guid = root } } })
        t:assert_eq(no_root.errno, sys.E.INVAL,
            "a tree that does not start at level 0 is refused too")
        sys.close(vm, fd)
    end)

