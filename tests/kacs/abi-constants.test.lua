-- PKM §3.A — the generated ABI appendix: the AccessCheck bounds and
-- claim formats, the file / open / mount constants, the process
-- mitigation and access-right bits, and the security-descriptor and SID
-- tables.
--
-- Each case drives the syscall the constant governs with the published
-- value and, where the kernel can tell, shows a value outside the table
-- refused. The struct layouts are in abi-structs.test.lua, the token
-- and socket constants in abi-tables.test.lua, the tracepoint
-- vocabularies in abi-tracepoints.test.lua.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local token = require("helpers.token")
local access = require("helpers.access")
local facs = require("helpers.facs")
local psb = require("helpers.psb")
local kmes = require("helpers.kmes")

local vm = provium:vm("v", "kernel-only"):boot()

local B = facs.workspace(vm, "abiconst")
local R, STD = kacs.RIGHT, access.STD
local ENABLED = token.GROUP.MANDATORY | token.GROUP.ENABLED_BY_DEFAULT
    | token.GROUP.ENABLED

local function fresh(spec)
    local fd, e = token.mint(vm, spec or {})
    assert(fd, "mint: " .. sys.errname(e or 0))
    return fd
end

--- kacs_access_check with the argument block written field by field, so
--- a case can declare a length or a count the buffer does not have —
--- which is the only way to reach the bounds the appendix publishes.
---
--- `opts.fields` is a list of `{ offset, format, value }` applied after
--- the defaults; `opts.children` a list of `{ bytes = , at = }` whose
--- guest addresses are written into the block at `at`.
local function raw_check(who, opts)
    local blob = string.rep("\0", access.ARGS_SIZE)
    local function put(off, fmt, v)
        local p = string.pack(fmt, v)
        blob = blob:sub(1, off) .. p .. blob:sub(off + #p + 1)
    end
    local m = opts.mapping or access.FILE_MAPPING
    put(0, "<I4", opts.caller_size or access.ARGS_SIZE)
    put(4, "<i4", opts.token_fd or -1)
    put(20, "<I4", opts.desired or 0)
    put(24, "<I4", m.read); put(28, "<I4", m.write)
    put(32, "<I4", m.execute); put(36, "<I4", m.all)
    for _, f in ipairs(opts.fields or {}) do put(f[1], f[2], f[3]) end
    local bufs, nested = { "" }, {}
    for _, c in ipairs(opts.children or {}) do
        bufs[#bufs + 1] = c.bytes
        nested[#nested + 1] = { parent = 1, child = #bufs, offset = c.at }
    end
    bufs[1] = blob
    local r = who:syscall(access.SYS.ACCESS_CHECK, {
        args = { 0 }, bufs = bufs, ptrs = { 0 }, nested = nested,
    })
    r.granted_out = nil
    for i, c in ipairs(opts.children or {}) do
        if c.at == 88 then r.granted_out = string.unpack("<I4", r.out_bufs[i + 1]) end
    end
    return r
end

--- One object-type tree entry: level, the must-be-zero u16, the GUID.
local function tree_entry(level, guid)
    return string.pack("<I2I2", level, 0) .. guid
end

--- A UTF-16LE NUL-terminated string, as the claim format uses.
local function utf16(s)
    local out = {}
    for i = 1, #s do out[i] = string.pack("<I2", s:byte(i)) end
    return table.concat(out) .. "\0\0"
end

--- One @Local claim entry: a name, a value type, flags, and one value.
--- Layout from the appendix's claim tables: name_offset at 0, the value
--- type at 4, flags at 8, the value count at 12, then the offsets.
local function claim(name, value_type, flags, value_bytes)
    local header_len = 16 + 4              -- header plus one value offset
    local name_off = header_len
    local name_bytes = utf16(name)
    local value_off = name_off + #name_bytes
    local entry = string.pack("<I4I2I2I4I4", name_off, value_type, 0,
        flags or 0, 1) .. string.pack("<I4", value_off)
        .. name_bytes .. value_bytes
    return string.pack("<I4", #entry) .. entry
end

--- An int64 literal token in a conditional expression.
local function int_lit(v) return string.pack("<I1i8I1I1", 0x04, v, 0x01, 0x02) end

--- `@Local.<name> == <value>` as conditional-ACE bytecode, padded so
--- the containing ACE keeps a size that is a multiple of four.
local function local_eq(name, value)
    local n = utf16(name):sub(1, -3)        -- the reference is not terminated
    local expr = "artx" .. string.pack("<I1I4", 0xf8, #n) .. n
        .. int_lit(value) .. string.pack("<I1", 0x80)
    return expr .. string.rep("\0", (-#expr) % 4)
end

-- AccessCheck bounds ---------------------------------------------------------

test("KACS_ACCESS_CHECK_ARGS_SIZE is 136 — the whole block the kernel copies",
    { spec = "PKM *kacs-abi.access-check-args-size" }, function(t)
        local fd = fresh()
        local sd = access.simple({ access.ace(access.ACE.ALLOWED, 0x1,
            token.SID.TEST_USER) })
        local out = string.rep("\0", 4)
        local base = { token_fd = fd, desired = 0x1,
            fields = { { 16, "<I4", #sd } },
            children = { { bytes = sd, at = 8 }, { bytes = out, at = 88 } } }
        base.caller_size = access.ARGS_SIZE
        local full = raw_check(vm, base)
        t:assert(full.ret >= 0, "the full 136-byte block is accepted")
        t:assert_eq(full.granted_out, 0x1,
            "and granted_out_ptr, at 88, is within it")
        -- A caller_size that stops before the pointer field leaves it
        -- zero, so nothing is written back.
        base.caller_size = 88
        local shortened = raw_check(vm, base)
        t:assert(shortened.ret >= 0, "a shorter block still answers")
        t:assert_eq(shortened.granted_out, 0,
            "but a size of 88 does not reach the field that begins there")
        -- Anything past 136 is clamped rather than refused.
        base.caller_size = 4096
        t:assert(raw_check(vm, base).ret >= 0,
            "a size past 136 is clamped to it, not rejected")
        sys.close(vm, fd)
    end)

test("KACS_ACCESS_CHECK_ARGS_V1_SIZE is 40 — the smallest block accepted",
    { spec = "PKM *kacs-abi.access-check-args-v1-size" }, function(t)
        local fd = fresh()
        local sd = access.simple({ access.ace(access.ACE.ALLOWED, 0x1,
            token.SID.TEST_USER) })
        local function at(size)
            return raw_check(vm, { token_fd = fd, desired = 0x1,
                caller_size = size, fields = { { 16, "<I4", #sd } },
                children = { { bytes = sd, at = 8 } } })
        end
        t:assert_eq(at(39).errno, sys.E.INVAL,
            "39 is below the v1 layout: " .. sys.errname(at(39).errno))
        local v1 = at(40)
        t:assert(v1.ret >= 0, "40 is accepted: " .. sys.errname(v1.errno))
        t:assert_eq(v1.ret, 0x1,
            "and everything it covers — sd, mask, mapping — was read")
        sys.close(vm, fd)
    end)

test("KACS_OBJECT_TYPE_ENTRY_SIZE is 20 — the tree array's stride",
    { spec = "PKM *kacs-abi.object-type-entry-size" }, function(t)
        local fd = fresh()
        local root, child = string.rep("\1", 16), string.rep("\2", 16)
        local tree = tree_entry(0, root) .. tree_entry(1, child)
        t:assert_eq(#tree, 40, "two entries are forty bytes")
        local sd = access.sd({
            owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM,
            dacl = access.acl({ access.ace(access.ACE.ALLOWED_OBJECT, 0x1,
                token.SID.TEST_USER, 0, { object_type = child }) }) })
        local function with_count(n)
            return raw_check(vm, { token_fd = fd, desired = 0x1,
                fields = { { 16, "<I4", #sd }, { 64, "<I4", n } },
                children = { { bytes = sd, at = 8 }, { bytes = tree, at = 56 } } })
        end
        t:assert(with_count(2).ret >= 0,
            "a count of 2 reaches the second entry, which the ACE names")
        local one = with_count(1)
        t:assert_eq(one.ret, -1,
            "a count of 1 stops after twenty bytes and never sees it")
        t:assert_eq(one.errno, sys.E.ACCES, "so the check is denied")
        sys.close(vm, fd)
    end)

test("KACS_ACCESS_CHECK_MAX_AUDIT_CONTEXT_LEN is 4096",
    { spec = "PKM *kacs-abi.max-audit-context-len" }, function(t)
        local fd = fresh()
        local sd = access.simple({ access.ace(access.ACE.ALLOWED, 0x1,
            token.SID.TEST_USER) })
        local ctx = string.rep("c", 4096)
        local function with_len(n)
            return raw_check(vm, { token_fd = fd, desired = 0x1,
                fields = { { 16, "<I4", #sd }, { 112, "<I4", n } },
                children = { { bytes = sd, at = 8 }, { bytes = ctx, at = 104 } } })
        end
        t:assert(with_len(4096).ret >= 0,
            "a 4096-byte audit context is accepted: " ..
            sys.errname(with_len(4096).errno))
        t:assert_eq(with_len(4097).errno, sys.E.INVAL,
            "and 4097 is refused before the buffer is even read")
        sys.close(vm, fd)
    end)

test("KACS_ACCESS_CHECK_MAX_LOCAL_CLAIMS_LEN is 65536",
    { spec = "PKM *kacs-abi.max-local-claims-len" }, function(t)
        local fd = fresh()
        local sd = access.simple({ access.ace(access.ACE.ALLOWED, 0x1,
            token.SID.TEST_USER) })
        local claims = claim("Small", 1, 0, string.pack("<i8", 1))
        local function with_len(n)
            return raw_check(vm, { token_fd = fd, desired = 0x1,
                fields = { { 16, "<I4", #sd }, { 80, "<I4", n } },
                children = { { bytes = sd, at = 8 },
                             { bytes = claims, at = 72 } } })
        end
        t:assert(with_len(#claims).ret >= 0,
            "a claims blob inside the bound is parsed: " ..
            sys.errname(with_len(#claims).errno))
        t:assert_eq(with_len(65537).errno, sys.E.INVAL,
            "65537 bytes is past the maximum and refused before the read")
        sys.close(vm, fd)
    end)

test("KACS_ACCESS_CHECK_MAX_OBJECT_TYPE_COUNT is 1024",
    { spec = "PKM *kacs-abi.max-object-type-count" }, function(t)
        local fd = fresh()
        local sd = access.simple({ access.ace(access.ACE.ALLOWED, 0x1,
            token.SID.TEST_USER) })
        local entries = { tree_entry(0, string.rep("\1", 16)) }
        for i = 2, 1024 do
            entries[i] = tree_entry(1, string.pack("<I8I8", i, 0x5555))
        end
        local tree = table.concat(entries)
        local function with_count(n, bytes)
            return raw_check(vm, { token_fd = fd, desired = 0x1,
                fields = { { 16, "<I4", #sd }, { 64, "<I4", n } },
                children = { { bytes = sd, at = 8 },
                             { bytes = bytes or tree, at = 56 } } })
        end
        t:assert(with_count(1024).ret >= 0,
            "1024 entries are accepted: " .. sys.errname(with_count(1024).errno))
        t:assert_eq(with_count(1025).errno, sys.E.INVAL,
            "1025 is past the maximum, and refused before the array is read")
        sys.close(vm, fd)
    end)

test("the six claim value types are the discriminants the kernel parses",
    { spec = "PKM *kacs-abi.claim-value-types" }, function(t)
        local fd = fresh()
        local sd = access.simple({ access.ace(access.ACE.ALLOWED, 0x1,
            token.SID.TEST_USER) })
        -- A value's encoding follows from its type: the fixed-width
        -- kinds carry a u64, the rest an offset to their payload.
        local sid_at = 8
        local cases = {
            { "KACS_CLAIM_TYPE_INT64", 0x0001, string.pack("<i8", -7) },
            { "KACS_CLAIM_TYPE_UINT64", 0x0002, string.pack("<I8", 9) },
            { "KACS_CLAIM_TYPE_BOOLEAN", 0x0006, string.pack("<I8", 1) },
        }
        for _, c in ipairs(cases) do
            local blob = claim("Attr", c[2], 0, c[3])
            local r = raw_check(vm, { token_fd = fd, desired = 0x1,
                fields = { { 16, "<I4", #sd }, { 80, "<I4", #blob } },
                children = { { bytes = sd, at = 8 }, { bytes = blob, at = 72 } } })
            t:assert(r.ret >= 0, c[1] .. " (0x" .. string.format("%04X", c[2]) ..
                ") parses: " .. sys.errname(r.errno))
        end
        -- STRING (3), SID (5) and OCTET (0x10) carry an in-entry offset
        -- to their payload.
        local function offset_claim(value_type, payload)
            local header_len = 16 + 4
            local name = utf16("Attr")
            local value_off = header_len + #name
            local payload_off = value_off + 4
            local entry = string.pack("<I4I2I2I4I4", header_len, value_type, 0,
                0, 1) .. string.pack("<I4", value_off) .. name
                .. string.pack("<I4", payload_off) .. payload
            return string.pack("<I4", #entry) .. entry
        end
        local offset_cases = {
            { "KACS_CLAIM_TYPE_STRING", 0x0003, utf16("hello") },
            { "KACS_CLAIM_TYPE_SID", 0x0005, token.SID.TEST_USER },
            { "KACS_CLAIM_TYPE_OCTET", 0x0010,
              string.pack("<I4", 3) .. "abc" },
        }
        for _, c in ipairs(offset_cases) do
            local blob = offset_claim(c[2], c[3])
            local r = raw_check(vm, { token_fd = fd, desired = 0x1,
                fields = { { 16, "<I4", #sd }, { 80, "<I4", #blob } },
                children = { { bytes = sd, at = 8 }, { bytes = blob, at = 72 } } })
            t:assert(r.ret >= 0, c[1] .. " (0x" .. string.format("%04X", c[2]) ..
                ") parses: " .. sys.errname(r.errno))
        end
        -- 0x0004 is a hole in the enumeration.
        local bad = claim("Attr", 0x0004, 0, string.pack("<I8", 1))
        local r = raw_check(vm, { token_fd = fd, desired = 0x1,
            fields = { { 16, "<I4", #sd }, { 80, "<I4", #bad } },
            children = { { bytes = sd, at = 8 }, { bytes = bad, at = 72 } } })
        t:assert_eq(r.errno, sys.E.INVAL,
            "0x0004 is not a claim value type: " .. sys.errname(r.errno))
        t:assert_eq(sid_at, 8, "the descriptor pointer stays at 8 throughout")
        sys.close(vm, fd)
    end)

test("the claim attribute flags decide whether an attribute answers at all",
    { spec = "PKM *kacs-abi.claim-attribute-flags" }, function(t)
        local fd = fresh()
        -- A callback ACE conditioned on `@Local.Level == 5`: whether the
        -- attribute is visible to the expression is exactly what the
        -- flags decide.
        local function check(flags)
            local blob = claim("Level", 0x0001, flags, string.pack("<i8", 5))
            local sd = access.sd({
                owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM,
                dacl = access.acl({ access.ace(access.ACE.ALLOWED_CALLBACK,
                    0x1, token.SID.TEST_USER, 0,
                    { condition = local_eq("Level", 5) }) }) })
            return raw_check(vm, { token_fd = fd, desired = 0x1,
                fields = { { 16, "<I4", #sd }, { 80, "<I4", #blob } },
                children = { { bytes = sd, at = 8 }, { bytes = blob, at = 72 } } })
        end
        t:assert(check(0).ret >= 0,
            "an unflagged attribute satisfies the condition: " ..
            sys.errname(check(0).errno))
        t:assert_eq(check(0x0010).errno, sys.E.ACCES,
            "KACS_CLAIM_ATTR_DISABLED (0x10) makes it answer nothing")
        t:assert_eq(check(0x0004).errno, sys.E.ACCES,
            "KACS_CLAIM_ATTR_USE_FOR_DENY_ONLY (0x04) hides it from an allow ACE")
        t:assert(check(0x0002).ret >= 0,
            "KACS_CLAIM_ATTR_CASE_SENSITIVE (0x02) is a comparison flag, " ..
            "not a visibility one")
        sys.close(vm, fd)
    end)

test("the CAAP spec is a versioned prefix followed by exactly rule_count rules",
    { spec = "PKM *kacs-abi.caap-spec-wire-format" }, function(t)
        local policy = token.sid(5, 21, 1000, 2000, 3000, 7001)
        local dacl = access.acl({ access.ace(access.ACE.ALLOWED, 0x1,
            token.SID.TEST_USER) })
        local good = access.caap_spec({ { effective_dacl = dacl } })
        t:assert_eq(access.set_caap(vm, policy, good).ret, 0,
            "version 1 with one rule is accepted")
        -- effective_dacl_len MUST be nonzero.
        local empty = access.caap_spec({ { effective_dacl = "" } })
        t:assert_eq(access.set_caap(vm, policy, empty).errno, sys.E.INVAL,
            "a rule with no effective DACL is refused")
        -- Consumed exactly.
        t:assert_eq(access.set_caap(vm, policy, good .. "\0").errno,
            sys.E.INVAL, "a trailing byte is refused")
        -- KACS_CAAP_MAX_RULE_COUNT is 256.
        local rules = {}
        for i = 1, 256 do rules[i] = { effective_dacl = dacl } end
        t:assert_eq(access.set_caap(vm, policy,
            access.caap_spec(rules)).ret, 0, "256 rules are accepted")
        rules[257] = { effective_dacl = dacl }
        t:assert_eq(access.set_caap(vm, policy,
            access.caap_spec(rules)).errno, sys.E.INVAL,
            "257 is past KACS_CAAP_MAX_RULE_COUNT")
        -- KACS_CAAP_MAX_FIELD_BYTES is 65536.
        local over_field = access.caap_spec({ { effective_dacl = dacl,
            applies_to = string.rep("\0", 65537) } })
        t:assert_eq(access.set_caap(vm, policy, over_field).errno, sys.E.INVAL,
            "a field of 65537 bytes is past KACS_CAAP_MAX_FIELD_BYTES")
        -- KACS_CAAP_MAX_SPEC_BYTES is 262144.
        local huge = {}
        for i = 1, 5 do
            huge[i] = { effective_dacl = dacl,
                applies_to = string.rep("\0", 65536) }
        end
        t:assert_eq(access.set_caap(vm, policy,
            access.caap_spec(huge)).errno, sys.E.INVAL,
            "and a whole spec past 262144 bytes is refused")
        access.set_caap(vm, policy, nil)
    end)

test("the CAAP prefix carries the version at 0 and the rule count at 1",
    { spec = "PKM *kacs-abi.caap-spec-offsets" }, function(t)
        local policy = token.sid(5, 21, 1000, 2000, 3000, 7002)
        local dacl = access.acl({ access.ace(access.ACE.ALLOWED, 0x1,
            token.SID.TEST_USER) })
        local body = string.pack("<I4", 0) .. string.pack("<I4", #dacl) .. dacl
            .. string.pack("<I4", 0) .. string.pack("<I4", 0)
            .. string.pack("<I4", 0)
        local function spec(version, rule_count)
            return string.pack("<I1I4", version, rule_count) .. body
        end
        t:assert_eq(access.set_caap(vm, policy, spec(1, 1)).ret, 0,
            "the byte at 0 is the version and the __le32 at 1 the rule count")
        t:assert_eq(access.set_caap(vm, policy, spec(2, 1)).errno, sys.E.INVAL,
            "version 2 at offset 0 is refused")
        t:assert_eq(access.set_caap(vm, policy, spec(1, 2)).errno, sys.E.INVAL,
            "a rule count at 1 that overruns the buffer is refused")
        t:assert_eq(access.set_caap(vm, policy, spec(1, 0)).errno, sys.E.INVAL,
            "and a count of 0 leaves the rule bytes unconsumed")
        access.set_caap(vm, policy, nil)
    end)

test("KACS_CAAP_SPEC_PREFIX_BYTES is 5 — a shorter spec cannot be read",
    { spec = "PKM *kacs-abi.caap-spec-prefix-bytes" }, function(t)
        local policy = token.sid(5, 21, 1000, 2000, 3000, 7003)
        for _, len in ipairs({ 1, 2, 3, 4 }) do
            local short = string.pack("<I1I4", 1, 0):sub(1, len)
            t:assert_eq(access.set_caap(vm, policy, short).errno, sys.E.INVAL,
                len .. " bytes cannot hold the version and rule count")
        end
        -- Exactly the prefix, with a rule count of zero, is a
        -- well-formed spec that carries no rules.
        local prefix_only = string.pack("<I1I4", 1, 0)
        t:assert_eq(#prefix_only, 5, "the prefix is five bytes")
        local r = access.set_caap(vm, policy, prefix_only)
        t:assert_eq(r.ret, 0, "and is consumed exactly: " ..
            sys.errname(r.errno))
        access.set_caap(vm, policy, nil)
    end)

-- File and open constants ----------------------------------------------------

test("the six create dispositions are 0 through 5 in the published order",
    { spec = "PKM *kacs-abi.create-dispositions" }, function(t)
        local D, S = kacs.DISPOSITION, facs.STATUS
        local mask = R.READ_DATA | R.WRITE_DATA | R.READ_ATTRIBUTES
        local function open(name, disposition)
            return facs.open(vm, B .. "/" .. name,
                { access = mask, disposition = disposition })
        end
        -- CREATE (2) makes a new file and refuses an existing one.
        local fd, status = open("disp", D.CREATE)
        t:assert(fd, "KACS_DISPOSITION_CREATE creates: " ..
            sys.errname(status or 0))
        t:assert_eq(status, S.CREATED, "reporting CREATED")
        sys.close(vm, fd)
        local _, e = open("disp", D.CREATE)
        t:assert_eq(e, sys.E.EXIST, "and refuses an existing name")
        -- OPEN (1) is the other way round.
        fd, status = open("disp", D.OPEN)
        t:assert(fd, "KACS_DISPOSITION_OPEN opens an existing file")
        t:assert_eq(status, S.OPENED, "reporting OPENED")
        sys.close(vm, fd)
        local _, e2 = open("disp-absent", D.OPEN)
        t:assert_eq(e2, sys.E.NOENT, "and refuses an absent one")
        -- OPEN_IF (3) does either.
        fd = open("disp-if", D.OPEN_IF)
        t:assert(fd, "KACS_DISPOSITION_OPEN_IF creates when absent")
        sys.close(vm, fd)
        fd, status = open("disp-if", D.OPEN_IF)
        t:assert_eq(status, S.OPENED, "and opens when present")
        sys.close(vm, fd)
        -- OVERWRITE (4) and OVERWRITE_IF (5).
        fd, status = open("disp", D.OVERWRITE)
        t:assert_eq(status, S.OVERWRITTEN,
            "KACS_DISPOSITION_OVERWRITE reports OVERWRITTEN")
        sys.close(vm, fd)
        local _, e3 = open("disp-absent", D.OVERWRITE)
        t:assert_eq(e3, sys.E.NOENT, "and needs the file to exist")
        fd, status = open("disp-ovw", D.OVERWRITE_IF)
        t:assert(fd, "KACS_DISPOSITION_OVERWRITE_IF creates when absent")
        sys.close(vm, fd)
        -- SUPERSEDE (0).
        fd, status = open("disp", D.SUPERSEDE)
        t:assert_eq(status, S.SUPERSEDED,
            "KACS_DISPOSITION_SUPERSEDE reports SUPERSEDED")
        sys.close(vm, fd)
        -- Six values, and nothing past them.
        local _, e4 = open("disp", 6)
        t:assert_eq(e4, sys.E.INVAL, "6 is not a disposition")
    end)

test("the create options are DIRECTORY 1 and DELETE_ON_CLOSE 2",
    { spec = "PKM *kacs-abi.create-options" }, function(t)
        local O, D = kacs.CREATE_OPT, kacs.DISPOSITION
        local mask = R.READ_DATA | R.READ_ATTRIBUTES
        -- KACS_CREATE_OPT_DIRECTORY creates a directory.
        local dir = B .. "/optdir"
        local fd, status = facs.open(vm, dir, { access = mask,
            disposition = D.CREATE, options = O.DIRECTORY })
        t:assert(fd, "0x1 creates a directory: " .. sys.errname(status or 0))
        sys.close(vm, fd)
        t:assert(assert(sys.stat(vm, dir)).is_dir, "and it is one")
        -- KACS_CREATE_OPT_DELETE_ON_CLOSE removes the file at close.
        local doomed = B .. "/optdoc"
        fd = facs.open(vm, doomed, { access = mask | R.DELETE,
            disposition = D.CREATE, options = O.DELETE_ON_CLOSE })
        t:assert(fd, "0x2 opens with delete-on-close armed")
        t:assert(sys.stat(vm, doomed), "the file exists while the handle does")
        sys.close(vm, fd)
        t:assert(not sys.stat(vm, doomed), "and is gone once it is closed")
        -- Only those two bits are options.
        local _, e = facs.open(vm, B .. "/optbad", { access = mask,
            disposition = D.CREATE, options = 0x4 })
        t:assert_eq(e, sys.E.INVAL, "0x4 is not a create option")
    end)

test("KACS_BACKUP_INTENT and KACS_RESTORE_INTENT are the kacs_open_how flags",
    { spec = "PKM *kacs-abi.open-how-flags", tags = { "known-bug" } },
    function(t)
        -- §3.A publishes both as `kacs_open_how.flags` bits, so both
        -- must be accepted values of the field. The kernel refuses them
        -- outright (PEI-687): the flags validator admits only zero.
        local p = facs.file(vm, B .. "/intents", "i")
        local mask = R.READ_DATA | R.READ_ATTRIBUTES
        local fd, e = facs.open(vm, p, { access = mask, flags = 0x1 })
        t:assert(fd, "KACS_BACKUP_INTENT (0x1) is a defined flag: " ..
            sys.errname(e or 0))
        if fd then sys.close(vm, fd) end
        local fd2, e2 = facs.open(vm, p, { access = mask, flags = 0x2 })
        t:assert(fd2, "KACS_RESTORE_INTENT (0x2) likewise: " ..
            sys.errname(e2 or 0))
        if fd2 then sys.close(vm, fd2) end
        local _, e3 = facs.open(vm, p, { access = mask, flags = 0x4 })
        t:assert_eq(e3, sys.E.INVAL, "while 0x4 is not a flag at all")
    end)

test("each file object-specific right gates its own access",
    { spec = "PKM *kacs-abi.file-access-rights" }, function(t)
        local p = facs.file(vm, B .. "/rights", "r")
        local rights = {
            { "KACS_FILE_READ_DATA", R.READ_DATA },
            { "KACS_FILE_WRITE_DATA", R.WRITE_DATA },
            { "KACS_FILE_APPEND_DATA", R.APPEND_DATA },
            { "KACS_FILE_READ_EA", R.READ_EA },
            { "KACS_FILE_WRITE_EA", R.WRITE_EA },
            { "KACS_FILE_EXECUTE", R.EXECUTE },
            { "KACS_FILE_READ_ATTRIBUTES", R.READ_ATTRIBUTES },
            { "KACS_FILE_WRITE_ATTRIBUTES", R.WRITE_ATTRIBUTES },
        }
        -- A native open needs a data right in the mask, so each case
        -- rides on one the DACL still grants and adds the bit under
        -- test to it.
        for _, right in ipairs(rights) do
            local base = right[2] == R.READ_DATA and R.WRITE_DATA or R.READ_DATA
            t:assert_eq(kacs.set_sd(vm, p,
                kacs.grant_all_but(right[2])).ret, 0,
                "the DACL withholds " .. right[1])
            kacs.as_dacl_bound(t, vm, function(w)
                local fd, e = facs.open(w, p, { access = base | right[2] })
                t:assert(not fd, right[1] ..
                    " is needed for its own bit: " .. sys.errname(e or 0))
                t:assert_eq(e, sys.E.ACCES, "and the open is EACCES")
                local ok, e2 = facs.open(w, p, { access = base })
                t:assert(ok, "while a mask without it opens: " ..
                    sys.errname(e2 or 0))
                if ok then sys.close(w, ok) end
            end)
        end
        -- KACS_FILE_DELETE_CHILD (0x40) is a parent-directory right, so
        -- it is not something a handle on the child asks for: it is what
        -- lets a caller unlink a child it has no DELETE on.
        local dir = B .. "/rightsdir"
        vm:mkdir(dir, { parents = true })
        local function child()
            local at = dir .. "/victim"
            vm:write_file(at, "v")
            kacs.set_sd(vm, at, kacs.grant_all_but(R.DELETE))
            return at
        end
        t:assert_eq(kacs.set_sd(vm, dir, kacs.grant(kacs.ALL_RIGHTS)).ret, 0,
            "the directory grants every right, KACS_FILE_DELETE_CHILD among them")
        local victim = child()
        kacs.as_dacl_bound(t, vm, function(w)
            t:assert_eq(sys.unlink(w, victim).ret, 0,
                "the parent's DELETE_CHILD carries the unlink")
        end)
        t:assert_eq(kacs.set_sd(vm, dir,
            kacs.grant_all_but(R.DELETE_CHILD)).ret, 0,
            "withholding only KACS_FILE_DELETE_CHILD")
        victim = child()
        kacs.as_dacl_bound(t, vm, function(w)
            t:assert_eq(sys.unlink(w, victim).errno, sys.E.ACCES,
                "and the same unlink is refused")
        end)
        -- The directory aliases are the same bits under other names.
        t:assert_eq(R.LIST_DIRECTORY, R.READ_DATA,
            "KACS_FILE_LIST_DIRECTORY is KACS_FILE_READ_DATA")
        t:assert_eq(R.TRAVERSE, R.EXECUTE,
            "KACS_FILE_TRAVERSE is KACS_FILE_EXECUTE")
        t:assert_eq(R.ADD_FILE, R.WRITE_DATA,
            "KACS_FILE_ADD_FILE is KACS_FILE_WRITE_DATA")
        t:assert_eq(R.ADD_SUBDIRECTORY, R.APPEND_DATA,
            "and KACS_FILE_ADD_SUBDIRECTORY is KACS_FILE_APPEND_DATA")
        t:assert_eq(kacs.set_sd(vm, dir,
            kacs.grant_all_but(R.LIST_DIRECTORY)).ret, 0,
            "a directory that withholds LIST_DIRECTORY")
        kacs.as_dacl_bound(t, vm, function(w)
            local fd, e = facs.open(w, dir,
                { access = R.LIST_DIRECTORY, options = kacs.CREATE_OPT.DIRECTORY })
            t:assert(not fd, "cannot be opened for listing: " ..
                sys.errname(e or 0))
        end)
        kacs.set_sd(vm, p, kacs.grant(kacs.ALL_RIGHTS))
        kacs.set_sd(vm, dir, kacs.grant(kacs.ALL_RIGHTS))
    end)

test("the four mount-policy classes are 1 through 4",
    { spec = "PKM *kacs-abi.mount-policy-values" }, function(t)
        local P = kacs.MOUNT_POLICY
        local root = assert(sys.open(vm, "/", sys.O.RDONLY | sys.O.DIRECTORY))
        local live = assert(kacs.get_mount_policy(vm, root))
        t:assert(live >= P.UNMANAGED and live <= P.SYNTHESIZE_PERSISTENT,
            "a live mount reports a value in 1..4: " .. live)
        -- A filesystem attached with each synthesising class reports it.
        for _, class in ipairs({ P.SYNTHESIZE_EPHEMERAL,
                                 P.SYNTHESIZE_PERSISTENT }) do
            local at = "/mp-" .. class
            local ok, step, errno = kacs.new_mount(vm, "tmpfs", at, class)
            t:assert(ok, "a tmpfs at class " .. class .. ": " ..
                tostring(step) .. " " .. sys.errname(errno or 0))
            local fd = assert(sys.open(vm, at, sys.O.RDONLY | sys.O.DIRECTORY))
            t:assert_eq(kacs.get_mount_policy(vm, fd), class,
                "and reads its class back")
            -- DENY_MISSING is settable on a live mount.
            t:assert_eq(kacs.set_mount_policy(vm, fd, P.DENY_MISSING).ret, 0,
                "KACS_MOUNT_POLICY_DENY_MISSING (2) is settable")
            t:assert_eq(kacs.get_mount_policy(vm, fd), P.DENY_MISSING,
                "and takes effect")
            -- UNMANAGED is assigned by the resolver, never set.
            t:assert_eq(kacs.set_mount_policy(vm, fd, P.UNMANAGED).errno,
                sys.E.INVAL, "KACS_MOUNT_POLICY_UNMANAGED (1) is not settable")
            for _, bad in ipairs({ 0, 5, 255 }) do
                t:assert_eq(kacs.set_mount_policy(vm, fd, bad).errno,
                    sys.E.INVAL, bad .. " is not a policy class")
            end
            sys.close(vm, fd)
        end
        sys.close(vm, root)
    end)

test("the four open status values report what happened to the file",
    { spec = "PKM *kacs-abi.open-status-values" }, function(t)
        local D = kacs.DISPOSITION
        local mask = R.READ_DATA | R.WRITE_DATA | R.READ_ATTRIBUTES
        local p = B .. "/status"
        local function status_of(disposition)
            local fd, status = facs.open(vm, p,
                { access = mask, disposition = disposition })
            assert(fd, "open: " .. sys.errname(status or 0))
            sys.close(vm, fd)
            return status
        end
        t:assert_eq(status_of(D.CREATE), 2, "KACS_STATUS_CREATED is 2")
        t:assert_eq(status_of(D.OPEN), 1, "KACS_STATUS_OPENED is 1")
        t:assert_eq(status_of(D.OVERWRITE), 3, "KACS_STATUS_OVERWRITTEN is 3")
        t:assert_eq(status_of(D.SUPERSEDE), 4, "KACS_STATUS_SUPERSEDED is 4")
    end)

-- Process constants ----------------------------------------------------------

test("the process object-specific rights gate their own operations",
    { spec = "PKM *kacs-abi.process-access-rights" }, function(t)
        -- The three ptrace-mode rights (VM_READ, VM_WRITE, DUP_HANDLE)
        -- are exercised in psb-rights.test.lua, where they are tagged
        -- known-bug; the six that hold from the guest are here.
        local PR = psb.RIGHT
        local function without(mask, fn) psb.against(t, vm, psb.ALL_RIGHTS & ~mask, fn) end
        local function only(mask, fn) psb.against(t, vm, mask, fn) end
        only(PR.TERMINATE, function(w, pid)
            t:assert_eq(w:syscall(psb.NR.kill, pid, 15).ret, 0,
                "KACS_PROCESS_TERMINATE (0x1) carries SIGTERM")
        end)
        without(PR.TERMINATE, function(w, pid)
            t:assert_eq(w:syscall(psb.NR.kill, pid, 15).errno, sys.E.ACCES,
                "and withholding it refuses SIGTERM")
        end)
        only(PR.SIGNAL, function(w, pid)
            t:assert_eq(w:syscall(psb.NR.kill, pid, 28).ret, 0,
                "KACS_PROCESS_SIGNAL (0x2) carries an informational signal")
        end)
        without(PR.SIGNAL, function(w, pid)
            t:assert_eq(w:syscall(psb.NR.kill, pid, 28).errno, sys.E.ACCES,
                "and withholding it refuses one")
        end)
        without(PR.SET_INFORMATION, function(w, pid)
            t:assert_eq(w:syscall(psb.NR.setpriority, 0, pid, 5).errno,
                sys.E.ACCES,
                "KACS_PROCESS_SET_INFORMATION (0x200) gates setpriority")
        end)
        without(PR.QUERY_INFORMATION, function(w, pid)
            t:assert_eq(w:syscall(psb.NR.sched_getscheduler, pid).errno,
                sys.E.ACCES,
                "KACS_PROCESS_QUERY_INFORMATION (0x400) gates the detailed query")
        end)
        without(PR.SUSPEND_RESUME, function(w, pid)
            t:assert_eq(w:syscall(psb.NR.kill, pid, 19).errno, sys.E.ACCES,
                "KACS_PROCESS_SUSPEND_RESUME (0x800) gates SIGSTOP")
        end)
        without(PR.QUERY_LIMITED, function(w, pid)
            t:assert_eq(w:syscall(psb.NR.kill, pid, 0).errno, sys.E.ACCES,
                "KACS_PROCESS_QUERY_LIMITED (0x1000) gates the existence probe")
        end)
    end)

test("the process mitigation bits are the ten the table names",
    { spec = "PKM *kacs-abi.mitigation-bits" }, function(t)
        local M = psb.MIT
        local names = { "WXP", "TLP", "LSV", "UI_ACCESS", "NO_CHILD",
                        "CFIF", "CFIB", "PIE", "SML" }
        for _, name in ipairs(names) do
            local bit = M[name]
            t:assert(bit, "KACS_MIT_" .. name .. " is defined")
            local worker = vm:spawn_worker()
            local ok, err = pcall(function()
                local pidfd = assert(token.pidfd_open(vm, psb.pid(worker)))
                local r = psb.set_psb(vm, bit, pidfd)
                t:assert_neq(r.errno, sys.E.INVAL,
                    ("KACS_MIT_%s (0x%03X) is an accepted request bit: %s")
                        :format(name, bit, sys.errname(r.errno)))
                sys.close(vm, pidfd)
            end)
            worker:kill(); worker:join()
            if not ok then error(err, 0) end
        end
        -- KACS_MIT_CFI (0x008) is the legacy alias for CFIF | CFIB.
        local worker = vm:spawn_worker()
        local ok, err = pcall(function()
            local pidfd = assert(token.pidfd_open(vm, psb.pid(worker)))
            t:assert_neq(psb.set_psb(vm, M.CFI, pidfd).errno, sys.E.INVAL,
                "KACS_MIT_CFI (0x008) is accepted as a request")
            sys.close(vm, pidfd)
        end)
        worker:kill(); worker:join()
        if not ok then error(err, 0) end
    end)

test("KACS_MIT_ALL is 0x3FF — the accepted-request mask",
    { spec = "PKM *kacs-abi.mitigation-all-mask" }, function(t)
        local worker = vm:spawn_worker()
        local ok, err = pcall(function()
            local pidfd = assert(token.pidfd_open(vm, psb.pid(worker)))
            t:assert_eq(psb.MIT_ALL, 0x3FF, "the mask is ten bits wide")
            for _, bad in ipairs({ 0x400, 0x800, 0x80000000 }) do
                t:assert_eq(psb.set_psb(vm, bad, pidfd).errno, sys.E.INVAL,
                    ("0x%X is outside KACS_MIT_ALL and rejected")
                        :format(bad))
            end
            t:assert_eq(psb.set_psb(vm, 0x3FF | 0x400, pidfd).errno,
                sys.E.INVAL,
                "one stray bit rejects the whole request")
            sys.close(vm, pidfd)
        end)
        worker:kill(); worker:join()
        if not ok then error(err, 0) end
    end)

-- Security descriptor constants ----------------------------------------------

test("KACS_SD_HEADER_BYTES is 20 — nothing shorter is a descriptor",
    { spec = "PKM *kacs-abi.sd-header-bytes" }, function(t)
        local p = facs.file(vm, B .. "/sdheader", "h")
        local full = assert(kacs.get_sd(vm, p, kacs.SI.OWNER | kacs.SI.GROUP
            | kacs.SI.DACL))
        t:assert(#full >= 20, "a returned descriptor is at least the header")
        -- The five header fields: revision, sbz, control, and four
        -- offsets — twenty bytes before any body.
        local _, _, _, owner_off, group_off, sacl_off, dacl_off =
            string.unpack("<I1I1I2I4I4I4I4", full)
        for _, off in ipairs({ owner_off, group_off, sacl_off, dacl_off }) do
            t:assert(off == 0 or off >= 20,
                "every body offset is at or past 20: " .. off)
        end
        local descriptor = kacs.grant(kacs.ALL_RIGHTS)
        for _, len in ipairs({ 4, 12, 19 }) do
            t:assert_eq(vm:syscall(kacs.SYS.SET_SD, {
                args = { sys.AT_FDCWD, 0, kacs.SI.DACL, 0, len, 0 },
                bufs = { sys.cstr(p), descriptor }, ptrs = { 1, 3 },
            }).errno, sys.E.INVAL, len .. " bytes cannot be a descriptor")
        end
    end)

test("the SECURITY_INFORMATION bits select the components independently",
    { spec = "PKM *kacs-abi.security-information-bits" }, function(t)
        local p = facs.file(vm, B .. "/secinfo", "s")
        local SI = kacs.SI
        local function control_of(info)
            local bytes = kacs.get_sd(vm, p, info)
            if not bytes then return nil end
            local parsed = token.parse_sd(bytes)
            return parsed, bytes
        end
        local owner_only = assert(control_of(SI.OWNER))
        t:assert(owner_only.owner, "0x1 returns the owner")
        t:assert(not owner_only.dacl, "and not the DACL")
        local dacl_only = assert(control_of(SI.DACL))
        t:assert(dacl_only.dacl, "0x4 returns the DACL")
        t:assert(not dacl_only.owner, "and not the owner")
        local group_only = assert(control_of(SI.GROUP))
        t:assert(group_only.group, "0x2 returns the group")
        -- KACS_SECINFO_SACL is 0x8 and needs SeSecurityPrivilege, which
        -- the agent holds.
        t:assert(kacs.get_sd(vm, p, SI.SACL), "0x8 reads the SACL")
        -- KACS_SECINFO_LABEL is 0x10, the mandatory label alone.
        t:assert(kacs.get_sd(vm, p, 0x10), "0x10 reads the label")
        -- Nothing outside the five bits.
        local _, e = kacs.get_sd(vm, p, 0x20)
        t:assert_eq(e, sys.E.INVAL, "0x20 is not a selector: " ..
            sys.errname(e or 0))
        local _, e2 = kacs.get_sd(vm, p, 0)
        t:assert_eq(e2, sys.E.INVAL, "and neither is an empty selector")
    end)

test("the descriptor control bits are the header's u16 flags",
    { spec = "PKM *kacs-abi.sd-control-bits" }, function(t)
        local p = facs.file(vm, B .. "/sdcontrol", "c")
        local stored = assert(kacs.get_sd(vm, p, kacs.SI.OWNER | kacs.SI.DACL))
        local control = string.unpack("<I2", stored, 3)
        t:assert(control & 0x8000 ~= 0,
            "KACS_SD_SELF_RELATIVE (0x8000) is set on every stored descriptor")
        t:assert(control & 0x0004 ~= 0,
            "as is KACS_SD_DACL_PRESENT (0x0004) where a DACL exists")
        -- KACS_SD_DACL_PROTECTED (0x1000) survives a write and read.
        local protected = access.sd({
            owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM,
            dacl = access.acl({ access.ace(access.ACE.ALLOWED,
                kacs.ALL_RIGHTS, kacs.SID.EVERYONE) }),
            control = access.CONTROL.DACL_PROTECTED })
        t:assert_eq(kacs.set_sd(vm, p, protected,
            kacs.SI.OWNER | kacs.SI.GROUP | kacs.SI.DACL).ret, 0,
            "a protected DACL is written")
        local back = assert(kacs.get_sd(vm, p, kacs.SI.DACL))
        t:assert(string.unpack("<I2", back, 3) & 0x1000 ~= 0,
            "and KACS_SD_DACL_PROTECTED reads back")
        -- A descriptor that is not self-relative is not a wire
        -- descriptor at all.
        local absolute = protected:sub(1, 2)
            .. string.pack("<I2", 0x0004) .. protected:sub(5)
        t:assert_neq(kacs.set_sd(vm, p, absolute,
            kacs.SI.OWNER | kacs.SI.GROUP | kacs.SI.DACL).ret, 0,
            "clearing KACS_SD_SELF_RELATIVE makes it unreadable")
    end)

test("the standard and generic access bits sit where the table puts them",
    { spec = "PKM *kacs-abi.standard-and-generic-rights" }, function(t)
        local fd = fresh()
        local MAP = { read = 0x1, write = 0x2, execute = 0x4,
                      all = 0x7 | STD.DELETE | STD.READ_CONTROL
                          | STD.WRITE_DAC | STD.WRITE_OWNER | STD.SYNCHRONIZE }
        local function granted(desired, mask)
            local sd = access.sd({
                owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM,
                dacl = access.acl({ access.ace(access.ACE.ALLOWED,
                    mask or MAP.all, token.SID.TEST_USER) }) })
            return access.check(vm, { token_fd = fd, sd = sd,
                desired = desired, mapping = MAP })
        end
        for _, c in ipairs({
            { "KACS_ACCESS_DELETE", STD.DELETE },
            { "KACS_ACCESS_READ_CONTROL", STD.READ_CONTROL },
            { "KACS_ACCESS_WRITE_DAC", STD.WRITE_DAC },
            { "KACS_ACCESS_WRITE_OWNER", STD.WRITE_OWNER },
            { "KACS_ACCESS_SYNCHRONIZE", STD.SYNCHRONIZE },
        }) do
            t:assert(granted(c[2]).ok, c[1] .. " is granted by a DACL that names it")
            t:assert(granted(c[2], MAP.all & ~c[2]).denied,
                "and denied by one that does not")
        end
        -- The generic bits fold through the mapping rather than being
        -- granted as themselves.
        t:assert_eq(granted(STD.GENERIC_READ).granted, MAP.read,
            "KACS_ACCESS_GENERIC_READ (0x80000000) folds to the read word")
        t:assert_eq(granted(STD.GENERIC_WRITE).granted, MAP.write,
            "GENERIC_WRITE (0x40000000) to the write word")
        t:assert_eq(granted(STD.GENERIC_EXECUTE).granted, MAP.execute,
            "GENERIC_EXECUTE (0x20000000) to the execute word")
        t:assert_eq(granted(STD.GENERIC_ALL).granted, MAP.all,
            "and GENERIC_ALL (0x10000000) to the whole mapping")
        -- MAXIMUM_ALLOWED asks for the computed maximum.
        local maximal = granted(STD.MAXIMUM_ALLOWED, MAP.read | MAP.write)
        t:assert(maximal.ok, "KACS_ACCESS_MAXIMUM_ALLOWED (0x02000000) answers")
        t:assert_eq(maximal.granted & (MAP.read | MAP.write),
            MAP.read | MAP.write, "with everything the DACL grants")
        -- ACCESS_SYSTEM_SECURITY is the privilege-backed SACL right.
        local without_priv = granted(STD.ACCESS_SYSTEM_SECURITY)
        t:assert(without_priv.denied,
            "KACS_ACCESS_ACCESS_SYSTEM_SECURITY (0x01000000) is not in a DACL")
        local sec = token.bit(token.PRIV.SECURITY)
        local privileged = fresh({ privs_present = sec, privs_enabled = sec })
        local sd = access.simple({})
        t:assert(access.check(vm, { token_fd = privileged, sd = sd,
            desired = STD.ACCESS_SYSTEM_SECURITY, mapping = MAP }).ok,
            "SeSecurityPrivilege grants it instead")
        sys.close(vm, privileged); sys.close(vm, fd)
    end)

test("the ACE type byte selects which evaluator an ACE reaches",
    { spec = "PKM *kacs-abi.ace-types" }, function(t)
        local A = access.ACE
        local MAP = { read = 0x1, write = 0x2, execute = 0x4, all = 0x7 }
        local fd = fresh({ integrity_level = token.INTEGRITY.LOW })
        local function check(dacl, sacl, desired, tree)
            return access.check(vm, { token_fd = fd, mapping = MAP,
                desired = desired or 0x1, tree = tree,
                sd = access.sd({ owner = token.SID.LOCAL_SYSTEM,
                    group = token.SID.LOCAL_SYSTEM, dacl = dacl, sacl = sacl }) })
        end
        local U = token.SID.TEST_USER
        t:assert(check(access.acl({ access.ace(A.ALLOWED, 0x1, U) })).ok,
            "0x00 KACS_ACE_TYPE_ACCESS_ALLOWED grants")
        t:assert(check(access.acl({ access.ace(A.DENIED, 0x1, U),
            access.ace(A.ALLOWED, 0x1, U) })).denied,
            "0x01 KACS_ACE_TYPE_ACCESS_DENIED denies")
        -- 0x02 / 0x03 live in the SACL and do not decide access.
        t:assert(check(access.acl({ access.ace(A.ALLOWED, 0x1, U) }),
            access.acl({ access.ace(A.AUDIT, 0x1, U,
                access.ACE_FLAG.SUCCESSFUL_ACCESS) })).ok,
            "0x02 KACS_ACE_TYPE_SYSTEM_AUDIT does not change the verdict")
        t:assert(check(access.acl({ access.ace(A.ALLOWED, 0x1, U) }),
            access.acl({ access.ace(A.ALARM, 0x1, U) })).ok,
            "and neither does 0x03 KACS_ACE_TYPE_SYSTEM_ALARM")
        -- 0x05 / 0x06 are the object forms.
        local g, elsewhere = string.rep("\7", 16), string.rep("\8", 16)
        t:assert(check(access.acl({ access.ace(A.ALLOWED_OBJECT, 0x1, U, 0,
            { object_type = g }) }), nil, 0x1,
            { { level = 0, guid = g } }).ok,
            "0x05 KACS_ACE_TYPE_ACCESS_ALLOWED_OBJECT grants at its GUID")
        t:assert(check(access.acl({ access.ace(A.ALLOWED_OBJECT, 0x1, U, 0,
            { object_type = g }) }), nil, 0x1,
            { { level = 0, guid = elsewhere } }).denied,
            "and nowhere else")
        -- 0x09 is the callback form, evaluated against its condition.
        -- The bytecode is padded so the containing ACE keeps a size that
        -- is a multiple of four.
        local function pad(expr) return expr .. string.rep("\0", (-#expr) % 4) end
        local TRUE = pad("artx" .. int_lit(1) .. int_lit(1)
            .. string.pack("<I1", 0x80))
        local FALSE = pad("artx" .. int_lit(1) .. int_lit(2)
            .. string.pack("<I1", 0x80))
        t:assert(check(access.acl({ access.ace(A.ALLOWED_CALLBACK, 0x1, U, 0,
            { condition = TRUE }) })).ok,
            "0x09 KACS_ACE_TYPE_ACCESS_ALLOWED_CALLBACK grants when true")
        t:assert(check(access.acl({ access.ace(A.ALLOWED_CALLBACK, 0x1, U, 0,
            { condition = FALSE }) })).denied, "and not when false")
        t:assert(check(access.acl({ access.ace(A.DENIED_CALLBACK, 0x1, U, 0,
            { condition = TRUE }),
            access.ace(A.ALLOWED, 0x1, U) })).denied,
            "0x0A KACS_ACE_TYPE_ACCESS_DENIED_CALLBACK denies when true")
        -- 0x11 is the mandatory label, in the SACL.
        t:assert(check(access.acl({ access.ace(A.ALLOWED, 0x2, U) }),
            access.acl({ access.label_ace and
                access.label_ace(token.INTEGRITY.MEDIUM, access.LABEL.NO_WRITE_UP)
                or access.ace(A.MANDATORY_LABEL, access.LABEL.NO_WRITE_UP,
                    token.label_sid(token.INTEGRITY.MEDIUM)) }), 0x2).denied,
            "0x11 KACS_ACE_TYPE_SYSTEM_MANDATORY_LABEL bars a write-up")
        -- 0x14 is the process trust label.
        t:assert(check(access.acl({ access.ace(A.ALLOWED, 0x1, U) }),
            access.acl({ access.trust_label_ace(512, 8192, 0) })).denied,
            "0x14 KACS_ACE_TYPE_SYSTEM_PROCESS_TRUST_LABEL bounds a " ..
            "non-dominant caller")
        -- 0x04 and 0x15 have a constant and no evaluator (§3.D): an ACE
        -- of either type is skipped, not an error.
        t:assert(check(access.acl({ access.ace(0x04, 0x1, U),
            access.ace(A.ALLOWED, 0x1, U) })).ok,
            "0x04 KACS_ACE_TYPE_ACCESS_ALLOWED_COMPOUND is skipped")
        t:assert(check(access.acl({ access.ace(0x15, 0x1, U),
            access.ace(A.ALLOWED, 0x1, U) })).ok,
            "and so is 0x15 KACS_ACE_TYPE_SYSTEM_ACCESS_FILTER")
        sys.close(vm, fd)
    end)

test("the ACE flag byte carries inheritance and audit control",
    { spec = "PKM *kacs-abi.ace-flags" }, function(t)
        local A, F = access.ACE, access.ACE_FLAG
        local MAP = { read = 0x1, write = 0x2, execute = 0x4, all = 0x7 }
        local U = token.SID.TEST_USER
        local fd = fresh()
        local function check(dacl, sacl)
            return access.check(vm, { token_fd = fd, mapping = MAP, desired = 0x1,
                sd = access.sd({ owner = token.SID.LOCAL_SYSTEM,
                    group = token.SID.LOCAL_SYSTEM, dacl = dacl, sacl = sacl }) })
        end
        -- KACS_ACE_FLAG_INHERIT_ONLY (0x08): the ACE does not apply here.
        t:assert(check(access.acl({ access.ace(A.ALLOWED, 0x1, U,
            F.INHERIT_ONLY | F.OBJECT_INHERIT) })).denied,
            "0x08 INHERIT_ONLY keeps the ACE off the object itself")
        t:assert(check(access.acl({ access.ace(A.ALLOWED, 0x1, U,
            F.OBJECT_INHERIT) })).ok,
            "while 0x01 OBJECT_INHERIT alone still applies here")
        t:assert(check(access.acl({ access.ace(A.ALLOWED, 0x1, U,
            F.CONTAINER_INHERIT | F.NO_PROPAGATE | F.INHERITED) })).ok,
            "0x02, 0x04 and 0x10 are inheritance bookkeeping, not gates")
        -- 0x40 and 0x80 pick which outcome a SACL audit ACE reports.
        local ring = assert(kmes.attach(vm, 0))
        local function audits(flags, dacl)
            kmes.drain(ring)
            check(dacl, access.acl({ access.ace(A.AUDIT, 0x1, U, flags) }))
            return #kmes.of_type(kmes.drain(ring), "access-audit")
        end
        local grants = access.acl({ access.ace(A.ALLOWED, 0x1, U) })
        local refuses = access.acl({})
        t:assert_eq(audits(F.SUCCESSFUL_ACCESS, grants), 1,
            "0x40 SUCCESSFUL_ACCESS audits a grant")
        t:assert_eq(audits(F.SUCCESSFUL_ACCESS, refuses), 0, "and only a grant")
        t:assert_eq(audits(F.FAILED_ACCESS, refuses), 1,
            "0x80 FAILED_ACCESS audits a denial")
        t:assert_eq(audits(F.FAILED_ACCESS, grants), 0, "and only a denial")
        kmes.detach(ring)
        -- Inheritance itself: an ACE marked for object inheritance
        -- reaches a file created under the directory carrying it.
        local dir = B .. "/inherit"
        vm:mkdir(dir, { parents = true })
        t:assert_eq(kacs.set_sd(vm, dir, kacs.descriptor(kacs.acl({
            kacs.ace(kacs.ACE_ALLOWED, kacs.ALL_RIGHTS, kacs.SID.EVERYONE,
                F.OBJECT_INHERIT | F.CONTAINER_INHERIT) }))).ret, 0,
            "the directory's ACE is marked for inheritance")
        vm:write_file(dir .. "/child", "x")
        local child = assert(kacs.get_sd(vm, dir .. "/child"))
        local parsed = token.parse_sd(child)
        t:assert(parsed.dacl and #parsed.dacl > 0,
            "and the created file inherits a DACL from it")
        t:assert(parsed.dacl[1].flags & F.INHERITED ~= 0,
            "marked KACS_ACE_FLAG_INHERITED (0x10)")
        sys.close(vm, fd)
    end)

test("the mandatory-label policy bits suppress the three generic classes",
    { spec = "PKM *kacs-abi.mandatory-label-policy-bits" }, function(t)
        local MAP = { read = 0x1, write = 0x2, execute = 0x4, all = 0x7 }
        local U = token.SID.TEST_USER
        local fd = fresh({ integrity_level = token.INTEGRITY.LOW })
        local function granted(policy, desired)
            local sd = access.sd({
                owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM,
                dacl = access.acl({ access.ace(access.ACE.ALLOWED, 0x7, U) }),
                sacl = access.acl({
                    access.label_ace(token.INTEGRITY.MEDIUM, policy) }) })
            return access.check(vm, { token_fd = fd, sd = sd,
                desired = desired, mapping = MAP })
        end
        t:assert(granted(access.LABEL.NO_WRITE_UP, 0x2).denied,
            "0x2 NO_WRITE_UP bars the write class")
        t:assert(granted(access.LABEL.NO_WRITE_UP, 0x1).ok,
            "and leaves read alone")
        t:assert(granted(access.LABEL.NO_READ_UP, 0x1).denied,
            "0x1 NO_READ_UP bars the read class")
        t:assert(granted(access.LABEL.NO_READ_UP, 0x4).ok,
            "and leaves execute alone")
        t:assert(granted(access.LABEL.NO_EXECUTE_UP, 0x4).denied,
            "0x4 NO_EXECUTE_UP bars the execute class")
        t:assert(granted(access.LABEL.NO_EXECUTE_UP, 0x1).ok,
            "and leaves read alone")
        -- Unknown bits must be ignored, not rejected.
        t:assert(granted(access.LABEL.NO_WRITE_UP | 0x8, 0x1).ok,
            "an unknown policy bit is ignored")
        t:assert(granted(access.LABEL.NO_WRITE_UP | 0x8, 0x2).denied,
            "while the known one still applies")
        sys.close(vm, fd)
    end)

test("the object-ACE body Flags word says which GUIDs the ACE carries",
    { spec = "PKM *kacs-abi.object-ace-flags" }, function(t)
        local MAP = { read = 0x1, write = 0x2, execute = 0x4, all = 0x7 }
        local U = token.SID.TEST_USER
        local fd = fresh()
        local scope, other = string.rep("\3", 16), string.rep("\4", 16)
        local function check(ace, tree)
            return access.check(vm, { token_fd = fd, mapping = MAP,
                desired = 0x1, tree = tree,
                sd = access.sd({ owner = token.SID.LOCAL_SYSTEM,
                    group = token.SID.LOCAL_SYSTEM,
                    dacl = access.acl({ ace }) }) })
        end
        -- KACS_ACE_OBJECT_TYPE_PRESENT (0x1): the body carries an
        -- ObjectType, and the ACE applies only where the tree names it.
        local scoped = access.ace(access.ACE.ALLOWED_OBJECT, 0x1, U, 0,
            { object_type = scope })
        t:assert_eq(string.unpack("<I4", scoped, 9), 0x1,
            "the __le32 at body offset 8 reads 1 for one GUID")
        t:assert(check(scoped, { { level = 0, guid = scope } }).ok,
            "and the ACE matches the node it names")
        t:assert(check(scoped, { { level = 0, guid = other } }).denied,
            "but not another")
        -- With no GUIDs the flags word is zero and the ACE applies to
        -- the object as a whole.
        local unscoped = access.ace(access.ACE.ALLOWED_OBJECT, 0x1, U, 0, {})
        t:assert_eq(string.unpack("<I4", unscoped, 9), 0,
            "an object ACE with no GUIDs reads 0 there")
        t:assert(check(unscoped, { { level = 0, guid = other } }).ok,
            "and applies whatever the tree says")
        -- KACS_ACE_INHERITED_OBJECT_TYPE_PRESENT (0x2) is the second
        -- GUID's flag; with both set the body carries two GUIDs.
        local both = access.ace(access.ACE.ALLOWED_OBJECT, 0x1, U, 0,
            { object_type = scope, inherited_object_type = other })
        t:assert_eq(string.unpack("<I4", both, 9), 0x3,
            "both bits set means both GUIDs are present")
        t:assert_eq(#both, #scoped + 16, "and the body is sixteen bytes longer")
        t:assert(check(both, { { level = 0, guid = scope } }).ok,
            "the ObjectType still selects the node")
        sys.close(vm, fd)
    end)

-- SID constants --------------------------------------------------------------

test("KACS_SID_MAX_SUB_AUTHORITIES is 15",
    { spec = "PKM *kacs-abi.sid-max-sub-authorities" }, function(t)
        local function sid_with(n)
            local subs = {}
            for i = 1, n do subs[i] = 1000 + i end
            return token.sid(5, table.unpack(subs))
        end
        local fd, e = token.mint(vm, { user_sid = sid_with(15) })
        t:assert(fd, "a SID with fifteen sub-authorities mints: " ..
            sys.errname(e or 0))
        t:assert_eq(#token.parse_sid(assert(
            token.query(vm, fd, token.CLASS.USER))).subs, 15,
            "and reads back with all fifteen")
        sys.close(vm, fd)
        local bad, e2 = token.mint(vm, { user_sid = sid_with(16) })
        t:assert(not bad, "sixteen is past the maximum: " ..
            sys.errname(e2 or 0))
        t:assert_eq(e2, sys.E.INVAL, "and is refused EINVAL")
    end)

test("KACS_SID_BYTE_LEN(count) is 8 + 4 * count",
    { spec = "PKM *kacs-abi.sid-byte-len" }, function(t)
        for _, n in ipairs({ 0, 1, 5, 15 }) do
            local subs = {}
            for i = 1, n do subs[i] = 2000 + i end
            local sid = token.sid(5, table.unpack(subs))
            t:assert_eq(#sid, 8 + 4 * n,
                n .. " sub-authorities encode as " .. (8 + 4 * n) .. " bytes")
        end
        -- A declared count that disagrees with the byte length is not a
        -- SID: the encoded length is a function of the count alone.
        local five = token.sid(5, 1, 2, 3, 4, 5)
        local truncated = five:sub(1, #five - 4)   -- says 5, carries 4
        local bad, e = token.mint(vm, { user_sid = truncated })
        t:assert(not bad, "a SID four bytes short of its count is refused: " ..
            sys.errname(e or 0))
        local padded = five .. string.rep("\0", 4)  -- says 5, carries 6
        local bad2, e2 = token.mint(vm, { user_sid = padded })
        t:assert(not bad2, "and one four bytes long: " .. sys.errname(e2 or 0))
        local good = assert(token.mint(vm, { user_sid = five }))
        t:assert_eq(#assert(token.query(vm, good, token.CLASS.USER)), 28,
            "while the exact length round-trips")
        sys.close(vm, good)
    end)

test("the SID_AND_ATTRIBUTES bits describe how an entry participates",
    { spec = "PKM *kacs-abi.sid-attribute-bits" }, function(t)
        local G = token.GROUP
        local MAP = { read = 0x1, write = 0x2, execute = 0x4, all = 0x7 }
        local fd, sid = token.mint(vm, { groups = {
            { sid = token.SID.TEST_GROUP, attributes = G.MANDATORY
                | G.ENABLED_BY_DEFAULT | G.ENABLED },
            { sid = token.SID.TEST_GROUP_2, attributes = G.USE_FOR_DENY_ONLY },
            { sid = token.SID.USERS, attributes = 0 },
            { sid = token.SID.ADMINISTRATORS,
                attributes = G.ENABLED_BY_DEFAULT | G.ENABLED | G.OWNER },
        } })
        t:assert(fd, "a token with one group of each kind: " ..
            sys.errname(sid or 0))
        local groups = assert(token.groups(vm, fd))
        t:assert_eq(groups[1].attributes & G.MANDATORY, G.MANDATORY,
            "0x01 KACS_SID_GROUP_MANDATORY round-trips")
        t:assert_eq(groups[1].attributes & G.ENABLED_BY_DEFAULT,
            G.ENABLED_BY_DEFAULT, "as does 0x02 ENABLED_BY_DEFAULT")
        t:assert_eq(groups[1].attributes & G.ENABLED, G.ENABLED,
            "and 0x04 ENABLED")
        t:assert_eq(groups[4].attributes & G.OWNER, G.OWNER,
            "0x08 OWNER marks a group an owner index may name")
        t:assert_eq(groups[2].attributes & G.USE_FOR_DENY_ONLY,
            G.USE_FOR_DENY_ONLY, "and 0x10 USE_FOR_DENY_ONLY survives")
        -- 0x01 MANDATORY is what stops an adjustment.
        t:assert_eq(token.adjust_groups(vm, fd, { { 0, 0 } }).errno,
            sys.E.INVAL, "a mandatory group cannot be disabled")
        t:assert_eq(token.adjust_groups(vm, fd, { { 2, 1 } }).ret, 0,
            "while an ordinary one can be enabled")
        -- 0x10 makes the SID match deny ACEs and no allow ACE.
        local function check(ace)
            return access.check(vm, { token_fd = fd, mapping = MAP,
                desired = 0x1, sd = access.sd({
                    owner = token.SID.LOCAL_SYSTEM,
                    group = token.SID.LOCAL_SYSTEM,
                    dacl = access.acl(ace) }) })
        end
        t:assert(check({ access.ace(access.ACE.ALLOWED, 0x1,
            token.SID.TEST_GROUP_2) }).denied,
            "a deny-only SID satisfies no allow ACE")
        t:assert(check({ access.ace(access.ACE.DENIED, 0x1,
            token.SID.TEST_GROUP_2),
            access.ace(access.ACE.ALLOWED, 0x1, token.SID.TEST_USER) }).denied,
            "but it does satisfy a deny ACE")
        -- 0x20 / 0x40 are the integrity pair, and 0xC0000000 the logon
        -- id: the kernel stamps the injected logon SID with it.
        local logon = token.find_group(groups, token.logon_sid(sid))
        t:assert(logon, "the injected logon SID is in the array")
        t:assert_eq(logon.attributes & G.LOGON_ID, G.LOGON_ID,
            "carrying 0xC0000000 KACS_SID_GROUP_LOGON_ID")
        local label = fresh({ integrity_level = token.INTEGRITY.LOW })
        t:assert_eq(token.integrity(vm, label), token.INTEGRITY.LOW,
            "and the integrity SID (0x20 / 0x40) is carried apart, " ..
            "as the label class")
        sys.close(vm, label); sys.close(vm, fd)
    end)
