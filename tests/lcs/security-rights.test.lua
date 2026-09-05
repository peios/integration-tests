-- PKM §5.4.2 — Access rights: the Windows bit positions, the
-- convenience masks, the generic mapping, what a caller may ask for and
-- what a source may return, the right each operation needs, and the two
-- places where structure is deliberately more visible than content.
--
-- A key whose DACL names only what a case is about needs a caller the
-- descriptor does not otherwise favour: the agent is SYSTEM, so the bit
-- cases run under a minted TEST_USER.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")
local kacs = require("helpers.kacs")
local token = require("helpers.token")
local access = require("helpers.access")

local vm = provium:vm("v", "kernel-only"):boot()

local CI = access.ACE_FLAG.CONTAINER_INHERIT
local R = lcs.RIGHT

--- A descriptor granting Everyone exactly `mask` and nobody anything else.
local function only(mask)
    return lcs.sd({ access.ace(access.ACE.ALLOWED, mask, kacs.SID.EVERYONE, CI) })
end
local SYSTEM_ONLY = lcs.sd({
    access.ace(access.ACE.ALLOWED, lcs.KEY_ALL_ACCESS, kacs.SID.LOCAL_SYSTEM, CI),
})

-- The ten rights of §5.A at the numeric positions Windows gives them.
local RIGHT_BITS = {
    { 0x00000001, "KEY_QUERY_VALUE", R.QUERY_VALUE },
    { 0x00000002, "KEY_SET_VALUE", R.SET_VALUE },
    { 0x00000004, "KEY_CREATE_SUB_KEY", R.CREATE_SUB_KEY },
    { 0x00000008, "KEY_ENUMERATE_SUB_KEYS", R.ENUMERATE_SUB_KEYS },
    { 0x00000010, "KEY_NOTIFY", R.NOTIFY },
    { 0x00000020, "KEY_CREATE_LINK", R.CREATE_LINK },
    { 0x00010000, "DELETE", R.DELETE },
    { 0x00020000, "READ_CONTROL", R.READ_CONTROL },
    { 0x00040000, "WRITE_DAC", R.WRITE_DAC },
    { 0x00080000, "WRITE_OWNER", R.WRITE_OWNER },
}

local src = lcs.source(vm)
local TEST = src:key("Machine\\Software\\Test")
src:value(TEST, "Seeded", lcs.TYPE.DWORD, lcs.dword(1))
for i, e in ipairs(RIGHT_BITS) do
    src:key("Machine\\Bits\\B" .. i, { sd = only(e[1]) })
end
src:key("Machine\\Reader", { sd = only(0x00020019) })  -- KEY_READ, spelled numerically
src:key("Machine\\Writer", { sd = only(0x00020006) })  -- KEY_WRITE, spelled numerically
src:key("Machine\\GenericAce", { sd = only(R.GENERIC_READ) })
src:key("Machine\\Everything")
src:key("Machine\\NoCreate", { sd = only(R.KEY_READ) })
-- Two descriptors a source may not return.
src:key("Machine\\AceMaxAllowed", { sd = only(R.KEY_READ | R.MAXIMUM_ALLOWED) })
src:key("Machine\\AceSynchronize", { sd = only(R.KEY_READ | 0x00100000) })
-- Structure is more visible than content.
src:key("Machine\\Enumerable")
src:key("Machine\\Enumerable\\Plain")
src:key("Machine\\Enumerable\\Secret", { sd = SYSTEM_ONLY })
src:key("Machine\\Watched")
src:key("Machine\\Watched\\Locked", { sd = SYSTEM_ONLY })
-- Keys the per-operation cases consume.
for i = 1, 8 do src:key("Machine\\Software\\Test\\Doomed" .. i) end
src:key("Machine\\Software\\Test\\Children\\One")
assert(src:register())
src:pump()

local w = vm:spawn_worker()

local function open_as(t, who, path, desired)
    return lcs.open_key(src, who, -1, path, desired)
end

--- Open `path` as SYSTEM with every right but `right`.
local function without(t, path, right)
    local r = open_as(t, w, path, lcs.KEY_ALL_ACCESS & ~right)
    t:assert(r.ret >= 0, "open " .. path .. " without the right: " ..
        sys.errname(r.errno or 0))
    return r.ret
end

--- Open `path` as SYSTEM with exactly `right`.
local function holding(t, path, right)
    local r = open_as(t, w, path, right)
    t:assert(r.ret >= 0, "open " .. path .. " holding the right: " ..
        sys.errname(r.errno or 0))
    return r.ret
end

--- Assert an operation is refused for want of a right, and that the
--- refusal cost the source nothing (§5.4.1).
local function refused(t, what, fn)
    local mark = src:mark()
    local r = fn()
    t:assert_eq(r.errno, sys.E.ACCES, what .. " without its right is EACCES")
    t:assert_eq(#src.log, mark - 1, "and the source was never contacted")
end

-- Bit positions, convenience masks, generic mapping ---------------------

test("registry rights occupy the Windows bit positions",
    { spec = "PKM *right.windows-bit-positions" }, function(t)
        token.as_principal(t, vm, { user_sid = token.SID.TEST_USER }, function(w2)
            for i, e in ipairs(RIGHT_BITS) do
                local path = "Machine\\Bits\\B" .. i
                local mine = open_as(t, w2, path, e[3])
                t:assert(mine.ret >= 0, e[2] .. " is bit value " ..
                    string.format("0x%08X", e[1]) .. ": " .. sys.errname(mine.errno or 0))
                if mine.ret >= 0 then sys.close(w2, mine.ret) end
                local other = RIGHT_BITS[(i % #RIGHT_BITS) + 1]
                local wrong = open_as(t, w2, path, other[3])
                t:assert_eq(wrong.errno, sys.E.ACCES,
                    "and grants nothing at " .. other[2] .. "'s position")
            end
        end)
    end)

test("there is no execute right on a key",
    { spec = "PKM *right.no-execute-right" }, function(t)
        local next_bit = lcs.open_key(src, w, -1, "Machine\\Everything", 0x00000040)
        t:assert_eq(next_bit.errno, sys.E.INVAL,
            "the bit after KEY_CREATE_LINK names no right, so it is an unknown bit")
        token.as_principal(t, vm, { user_sid = token.SID.TEST_USER }, function(w2)
            local exec = open_as(t, w2, "Machine\\Reader", R.GENERIC_READ | R.GENERIC_EXECUTE)
            t:assert(exec.ret >= 0,
                "GENERIC_EXECUTE alongside GENERIC_READ asks for nothing extra: " ..
                sys.errname(exec.errno or 0))
            if exec.ret >= 0 then sys.close(w2, exec.ret) end
        end)
    end)

test("KEY_READ, KEY_WRITE and KEY_ALL_ACCESS are concrete masks, usable directly",
    { spec = "PKM *right.convenience-masks-are-concrete" }, function(t)
        token.as_principal(t, vm, { user_sid = token.SID.TEST_USER }, function(w2)
            -- The descriptors spell the masks numerically; the opens use
            -- the named constants.
            local r = open_as(t, w2, "Machine\\Reader", R.KEY_READ)
            t:assert(r.ret >= 0, "KEY_READ is 0x00020019: " .. sys.errname(r.errno or 0))
            if r.ret >= 0 then sys.close(w2, r.ret) end
            local union = open_as(t, w2, "Machine\\Reader",
                R.QUERY_VALUE | R.ENUMERATE_SUB_KEYS | R.NOTIFY | R.READ_CONTROL)
            t:assert(union.ret >= 0, "and is exactly that union of the rights above")
            if union.ret >= 0 then sys.close(w2, union.ret) end
            local more = open_as(t, w2, "Machine\\Reader", R.KEY_READ | R.SET_VALUE)
            t:assert_eq(more.errno, sys.E.ACCES, "and no more than it")

            local wr = open_as(t, w2, "Machine\\Writer", R.KEY_WRITE)
            t:assert(wr.ret >= 0, "KEY_WRITE is 0x00020006: " .. sys.errname(wr.errno or 0))
            if wr.ret >= 0 then sys.close(w2, wr.ret) end

            local all = open_as(t, w2, "Machine\\Everything", R.KEY_ALL_ACCESS)
            t:assert(all.ret >= 0, "and KEY_ALL_ACCESS is a mask a caller may name outright: " ..
                sys.errname(all.errno or 0))
            if all.ret >= 0 then sys.close(w2, all.ret) end
        end)
    end)

test("raw generic bits are accepted in desired_access and in an ACE mask, and mapped first",
    { spec = "PKM *right.generic-bits-accepted-and-mapped" }, function(t)
        token.as_principal(t, vm, { user_sid = token.SID.TEST_USER }, function(w2)
            local asked = open_as(t, w2, "Machine\\Reader", R.GENERIC_READ)
            t:assert(asked.ret >= 0, "GENERIC_READ in desired_access is mapped and granted: " ..
                sys.errname(asked.errno or 0))
            if asked.ret >= 0 then sys.close(w2, asked.ret) end
            -- The descriptor's own ACE names GENERIC_READ, and a caller
            -- asking for the concrete rights it maps to is granted them.
            local in_ace = open_as(t, w2, "Machine\\GenericAce", R.KEY_READ)
            t:assert(in_ace.ret >= 0,
                "a GENERIC_READ ACE mask grants KEY_READ once mapped: " ..
                sys.errname(in_ace.errno or 0))
            if in_ace.ret >= 0 then sys.close(w2, in_ace.ret) end
            local beyond = open_as(t, w2, "Machine\\GenericAce", R.SET_VALUE)
            t:assert_eq(beyond.errno, sys.E.ACCES, "and nothing outside KEY_READ")
        end)
    end)

test("GENERIC_READ is KEY_READ, GENERIC_WRITE is KEY_WRITE, GENERIC_ALL is KEY_ALL_ACCESS",
    { spec = "PKM *right.generic-mapping" }, function(t)
        token.as_principal(t, vm, { user_sid = token.SID.TEST_USER }, function(w2)
            local cases = {
                { "Machine\\Reader", R.GENERIC_READ, true, "GENERIC_READ maps to KEY_READ" },
                { "Machine\\Reader", R.GENERIC_WRITE, false, "GENERIC_WRITE does not" },
                { "Machine\\Reader", R.GENERIC_ALL, false, "and neither does GENERIC_ALL" },
                { "Machine\\Writer", R.GENERIC_WRITE, true, "GENERIC_WRITE maps to KEY_WRITE" },
                { "Machine\\Writer", R.GENERIC_READ, false, "GENERIC_READ does not" },
                { "Machine\\Everything", R.GENERIC_ALL, true,
                  "GENERIC_ALL maps to KEY_ALL_ACCESS" },
            }
            for _, c in ipairs(cases) do
                local r = open_as(t, w2, c[1], c[2])
                if c[3] then
                    t:assert(r.ret >= 0, c[4] .. ": " .. sys.errname(r.errno or 0))
                    sys.close(w2, r.ret)
                else
                    t:assert_eq(r.errno, sys.E.ACCES, c[4])
                end
            end
        end)
    end)

-- Validating what a caller asks for -------------------------------------

test("desired_access is validated before path resolution or AccessCheck",
    { spec = "PKM *right.desired-access-validated-first" }, function(t)
        local mark = src:mark()
        local r = lcs.open_key(nil, w, -1, "Machine\\NoSuchKeyAnywhere", 0)
        t:assert_eq(r.errno, sys.E.INVAL,
            "a zero mask on a path that does not exist is EINVAL, not ENOENT")
        t:assert_eq(#src.log, mark - 1, "and the path was never resolved")
    end)

test("a zero desired_access is EINVAL: a caller must ask for something",
    { spec = "PKM *right.zero-desired-access-is-einval" }, function(t)
        local o = lcs.open_key(nil, w, -1, "Machine\\Everything", 0)
        t:assert_eq(o.errno, sys.E.INVAL, "reg_open_key with a zero mask is EINVAL")
        local c = lcs.create_key(nil, w, { path = "Machine\\Everything", access = 0 })
        t:assert_eq(c.errno, sys.E.INVAL, "and so is reg_create_key")
    end)

test("any bit outside the valid caller mask is EINVAL",
    { spec = "PKM *right.unknown-desired-access-bit-is-einval" }, function(t)
        for _, bit in ipairs({ 0x00000040, 0x00000800, 0x00200000, 0x00800000, 0x08000000 }) do
            local r = lcs.open_key(nil, w, -1, "Machine\\Everything", R.KEY_READ | bit)
            t:assert_eq(r.errno, sys.E.INVAL,
                string.format("0x%08X is outside REG_VALID_DESIRED_ACCESS_MASK", bit))
        end
    end)

test("SYNCHRONIZE is not a registry right, so it is an unknown bit",
    { spec = "PKM *right.synchronize-is-not-a-registry-right" }, function(t)
        local r = lcs.open_key(nil, w, -1, "Machine\\Everything", R.KEY_READ | 0x00100000)
        t:assert_eq(r.errno, sys.E.INVAL, "SYNCHRONIZE (0x00100000) fails EINVAL")
    end)

test("MAXIMUM_ALLOWED may appear alone or combined with anything else",
    { spec = "PKM *right.maximum-allowed-may-combine" }, function(t)
        local alone = lcs.open_key(src, w, -1, "Machine\\Everything", R.MAXIMUM_ALLOWED)
        t:assert(alone.ret >= 0, "alone: " .. sys.errname(alone.errno or 0))
        sys.close(w, alone.ret)
        local with_read = lcs.open_key(src, w, -1, "Machine\\Everything",
            R.MAXIMUM_ALLOWED | R.KEY_READ)
        t:assert(with_read.ret >= 0, "combined with KEY_READ: " ..
            sys.errname(with_read.errno or 0))
        sys.close(w, with_read.ret)
        local with_generic = lcs.open_key(src, w, -1, "Machine\\Everything",
            R.MAXIMUM_ALLOWED | R.GENERIC_ALL)
        t:assert(with_generic.ret >= 0, "and combined with a generic bit: " ..
            sys.errname(with_generic.errno or 0))
        sys.close(w, with_generic.ret)
    end)

test("REG_VALID_DESIRED_ACCESS_MASK is the whole of what a caller may name",
    { spec = "PKM *right.valid-desired-access-mask-contents" }, function(t)
        -- Every bit, probed alongside KEY_QUERY_VALUE so the mask is
        -- never empty: in the constant means "not EINVAL", outside it
        -- means EINVAL.
        for bit = 0, 31 do
            local value = 1 << bit
            if value ~= R.QUERY_VALUE then
                local expected_valid = (value & R.VALID_DESIRED) ~= 0
                local r = lcs.open_key(src, w, -1, "Machine\\Everything",
                    R.QUERY_VALUE | value)
                local got_einval = r.errno == sys.E.INVAL
                t:assert_eq(got_einval, not expected_valid,
                    string.format("bit 0x%08X is %s REG_VALID_DESIRED_ACCESS_MASK (0x%08X)",
                        value, expected_valid and "inside" or "outside", R.VALID_DESIRED))
                if r.ret >= 0 then sys.close(w, r.ret) end
            end
        end
        t:assert_eq(R.VALID_DESIRED, 0xF30F003F,
            "the six specific rights, four standard rights, ACCESS_SYSTEM_SECURITY, " ..
            "MAXIMUM_ALLOWED and the four generic bits")
    end)

-- Validating what a source returns --------------------------------------

test("an ACE mask may not contain MAXIMUM_ALLOWED",
    { spec = "PKM *right.ace-mask-rejects-maximum-allowed" }, function(t)
        local r = lcs.open_key(src, w, -1, "Machine\\AceMaxAllowed", R.KEY_READ)
        t:assert_eq(r.errno, sys.E.IO,
            "MAXIMUM_ALLOWED is a request, not a grant, and is meaningless in an ACE")
    end)

test("after generic mapping an ACE mask must be a subset of the concrete registry rights",
    { spec = "PKM *right.ace-mask-subset-after-mapping" }, function(t)
        local r = lcs.open_key(src, w, -1, "Machine\\AceSynchronize", R.KEY_READ)
        t:assert_eq(r.errno, sys.E.IO,
            "SYNCHRONIZE survives mapping and is outside REG_VALID_ACE_ACCESS_MASK")
        t:assert_eq(R.VALID_ACE, 0xF10F003F, "which is the bound REG_VALID_ACE_ACCESS_MASK names")
    end)

test("a descriptor breaking either rule is malformed source data and fails closed with EIO",
    { spec = "PKM *right.malformed-descriptor-is-eio" }, function(t)
        for _, path in ipairs({ "Machine\\AceMaxAllowed", "Machine\\AceSynchronize" }) do
            local r = lcs.open_key(src, w, -1, path, R.KEY_READ)
            t:assert_eq(r.errno, sys.E.IO, path .. " fails closed with EIO")
            t:assert_eq(r.ret, -1, "and publishes no fd")
        end
    end)

-- Which right each operation needs ---------------------------------------

test("REG_IOC_QUERY_VALUE, QUERY_VALUES_BATCH and ENUM_VALUES need KEY_QUERY_VALUE",
    { spec = "PKM *right.query-value" }, function(t)
        local no = without(t, "Machine\\Software\\Test", R.QUERY_VALUE)
        refused(t, "REG_IOC_QUERY_VALUE", function()
            return lcs.query_value(nil, w, no, "Seeded") end)
        refused(t, "REG_IOC_QUERY_VALUES_BATCH", function()
            return lcs.query_values_batch(nil, w, no) end)
        refused(t, "REG_IOC_ENUM_VALUES", function()
            return lcs.enum_values(nil, w, no, 0) end)
        sys.close(w, no)

        local yes = holding(t, "Machine\\Software\\Test", R.QUERY_VALUE)
        t:assert_eq(lcs.query_value(src, w, yes, "Seeded").ret, 0, "with the right, the read runs")
        t:assert_eq(lcs.query_values_batch(src, w, yes).ret, 0, "and so does the batch")
        t:assert_eq(lcs.enum_values(src, w, yes, 0).ret, 0, "and the enumeration")
        sys.close(w, yes)
    end)

test("REG_IOC_SET_VALUE, DELETE_VALUE, BLANKET_TOMBSTONE and FLUSH need KEY_SET_VALUE",
    { spec = "PKM *right.set-value" }, function(t)
        local no = without(t, "Machine\\Software\\Test", R.SET_VALUE)
        refused(t, "REG_IOC_SET_VALUE", function()
            return lcs.set_value(nil, w, no, "X", lcs.TYPE.DWORD, lcs.dword(1)) end)
        refused(t, "REG_IOC_DELETE_VALUE", function()
            return lcs.delete_value(nil, w, no, "X") end)
        refused(t, "REG_IOC_BLANKET_TOMBSTONE", function()
            return lcs.blanket_tombstone(nil, w, no, nil, true) end)
        refused(t, "REG_IOC_FLUSH", function() return lcs.flush(nil, w, no) end)
        sys.close(w, no)

        local yes = holding(t, "Machine\\Software\\Test", R.SET_VALUE)
        t:assert_eq(lcs.set_value(src, w, yes, "Written", lcs.TYPE.DWORD, lcs.dword(1)).ret, 0,
            "with the right, the write runs")
        t:assert_eq(lcs.flush(src, w, yes).ret, 0,
            "and so does the flush a writer wants for durability")
        sys.close(w, yes)
    end)

test("REG_IOC_ENUM_SUBKEYS needs KEY_ENUMERATE_SUB_KEYS",
    { spec = "PKM *right.enum-subkeys" }, function(t)
        local no = without(t, "Machine\\Enumerable", R.ENUMERATE_SUB_KEYS)
        refused(t, "REG_IOC_ENUM_SUBKEYS", function()
            return lcs.enum_subkeys(nil, w, no, 0) end)
        sys.close(w, no)
        local yes = holding(t, "Machine\\Enumerable", R.ENUMERATE_SUB_KEYS)
        t:assert_eq(lcs.enum_subkeys(src, w, yes, 0).ret, 0, "with the right, it enumerates")
        sys.close(w, yes)
    end)

test("REG_IOC_QUERY_KEY_INFO needs READ_CONTROL",
    { spec = "PKM *right.query-key-info" }, function(t)
        local no = without(t, "Machine\\Software\\Test", R.READ_CONTROL)
        refused(t, "REG_IOC_QUERY_KEY_INFO", function()
            return lcs.query_key_info(nil, w, no) end)
        sys.close(w, no)
        local yes = holding(t, "Machine\\Software\\Test", R.READ_CONTROL)
        t:assert_eq(lcs.query_key_info(src, w, yes).ret, 0, "READ_CONTROL is what it wants")
        sys.close(w, yes)
    end)

test("REG_IOC_DELETE_KEY and REG_IOC_HIDE_KEY need DELETE",
    { spec = "PKM *right.delete-key" }, function(t)
        local no = without(t, "Machine\\Software\\Test\\Doomed1", R.DELETE)
        refused(t, "REG_IOC_DELETE_KEY", function() return lcs.delete_key(nil, w, no) end)
        refused(t, "REG_IOC_HIDE_KEY", function() return lcs.hide_key(nil, w, no) end)
        sys.close(w, no)

        local del = holding(t, "Machine\\Software\\Test\\Doomed1", R.DELETE)
        t:assert_eq(lcs.delete_key(src, w, del).ret, 0, "with DELETE, the key goes")
        sys.close(w, del)
        local hide = holding(t, "Machine\\Software\\Test\\Doomed2", R.DELETE)
        t:assert_eq(lcs.hide_key(src, w, hide).ret, 0, "and so does a hide")
        sys.close(w, hide)
    end)

test("REG_IOC_NOTIFY needs KEY_NOTIFY",
    { spec = "PKM *right.notify" }, function(t)
        local no = without(t, "Machine\\Software\\Test", R.NOTIFY)
        refused(t, "REG_IOC_NOTIFY", function()
            return lcs.notify(nil, w, no, lcs.NOTIFY.ALL, false) end)
        sys.close(w, no)
        local yes = holding(t, "Machine\\Software\\Test", R.NOTIFY)
        t:assert_eq(lcs.notify(nil, w, yes, lcs.NOTIFY.ALL, false).ret, 0,
            "KEY_NOTIFY is what arms a watch")
        sys.close(w, yes)
    end)

test("REG_IOC_GET_SECURITY needs READ_CONTROL for owner, group and DACL",
    { spec = "PKM *right.get-security" }, function(t)
        local no = without(t, "Machine\\Software\\Test", R.READ_CONTROL)
        refused(t, "REG_IOC_GET_SECURITY", function()
            return lcs.get_security(nil, w, no, lcs.SI.OWNER | lcs.SI.GROUP | lcs.SI.DACL) end)
        sys.close(w, no)
        local yes = holding(t, "Machine\\Software\\Test", R.READ_CONTROL)
        local g = lcs.get_security(src, w, yes, lcs.SI.OWNER | lcs.SI.GROUP | lcs.SI.DACL)
        t:assert_eq(g.ret, 0, "with READ_CONTROL the three come back: " ..
            sys.errname(g.errno or 0))
        local sacl = lcs.get_security(nil, w, yes, lcs.SI.SACL)
        t:assert_eq(sacl.errno, sys.E.ACCES,
            "but the SACL needs ACCESS_SYSTEM_SECURITY, which READ_CONTROL is not")
        sys.close(w, yes)
    end)

test("REG_IOC_SET_SECURITY needs WRITE_OWNER for owner or group and WRITE_DAC for the DACL",
    { spec = "PKM *right.set-security" }, function(t)
        local sd = lcs.permissive_sd()
        local no_dac = without(t, "Machine\\Software\\Test\\Doomed3", R.WRITE_DAC)
        refused(t, "REG_IOC_SET_SECURITY of the DACL", function()
            return lcs.set_security(nil, w, no_dac, lcs.SI.DACL, sd) end)
        sys.close(w, no_dac)

        local no_owner = without(t, "Machine\\Software\\Test\\Doomed3", R.WRITE_OWNER)
        refused(t, "REG_IOC_SET_SECURITY of the owner", function()
            return lcs.set_security(nil, w, no_owner, lcs.SI.OWNER, sd) end)
        refused(t, "REG_IOC_SET_SECURITY of the group", function()
            return lcs.set_security(nil, w, no_owner, lcs.SI.GROUP, sd) end)
        sys.close(w, no_owner)

        local dac = holding(t, "Machine\\Software\\Test\\Doomed3", R.WRITE_DAC)
        t:assert_eq(lcs.set_security(src, w, dac, lcs.SI.DACL, sd).ret, 0,
            "WRITE_DAC is what writes a DACL")
        sys.close(w, dac)
        local owner = holding(t, "Machine\\Software\\Test\\Doomed3", R.WRITE_OWNER)
        t:assert_eq(lcs.set_security(src, w, owner, lcs.SI.OWNER, sd).ret, 0,
            "and WRITE_OWNER is what writes an owner")
        sys.close(w, owner)
    end)

test("creating a key needs KEY_CREATE_SUB_KEY on the parent",
    { spec = "PKM *right.create-key" }, function(t)
        -- reg_create_key AccessChecks the parent key's own descriptor
        -- (§5.5.2 step 2), so the case that shows the requirement is a
        -- parent whose descriptor withholds the right.
        token.as_principal(t, vm, { user_sid = token.SID.TEST_USER }, function(w2)
            local open = open_as(t, w2, "Machine\\NoCreate", R.KEY_READ)
            t:assert(open.ret >= 0, "the parent grants KEY_READ and no more: " ..
                sys.errname(open.errno or 0))
            sys.close(w2, open.ret)
            local r = lcs.create_key(src, w2, { path = "Machine\\NoCreate\\Denied",
                access = R.KEY_READ })
            t:assert_eq(r.errno, sys.E.ACCES, "so creating under it is EACCES")
        end)

        local yes = holding(t, "Machine\\Everything", R.CREATE_SUB_KEY)
        local made = lcs.create_key(src, w, { parent_fd = yes, path = "Allowed" })
        t:assert(made.ret >= 0, "where the parent grants it, the child is created: " ..
            sys.errname(made.errno or 0))
        t:assert_eq(made.disposition, lcs.CREATED_NEW, "and reports REG_CREATED_NEW")
        sys.close(w, made.ret)
        sys.close(w, yes)
    end)

test("a security_info naming several components needs every right they imply",
    { spec = "PKM *right.security-info-needs-every-implied-right" }, function(t)
        local fd = holding(t, "Machine\\Software\\Test", R.READ_CONTROL)
        local mark = src:mark()
        local r = lcs.get_security(nil, w, fd, lcs.SI.OWNER | lcs.SI.SACL)
        t:assert_eq(r.errno, sys.E.ACCES,
            "READ_CONTROL covers the owner but not the SACL, so the whole request is refused")
        t:assert_eq(#src.log, mark - 1, "before the source is contacted")
        sys.close(w, fd)

        local dac = holding(t, "Machine\\Software\\Test\\Doomed4", R.WRITE_DAC)
        local mark2 = src:mark()
        local s = lcs.set_security(nil, w, dac, lcs.SI.DACL | lcs.SI.OWNER, lcs.permissive_sd())
        t:assert_eq(s.errno, sys.E.ACCES,
            "and WRITE_DAC alone cannot serve a request that also names the owner")
        t:assert_eq(#src.log, mark2 - 1, "before the source is contacted")
        sys.close(w, dac)
    end)

-- Structure is more visible than content ---------------------------------

test("REG_IOC_ENUM_SUBKEYS performs no per-child access check",
    { spec = "PKM *right.enum-subkeys-no-per-child-check" }, function(t)
        token.as_principal(t, vm, { user_sid = token.SID.TEST_USER }, function(w2)
            local fd = open_as(t, w2, "Machine\\Enumerable", R.ENUMERATE_SUB_KEYS)
            t:assert(fd.ret >= 0, "the parent grants enumeration: " ..
                sys.errname(fd.errno or 0))
            local seen = {}
            for i = 0, 1 do
                local e = lcs.enum_subkeys(src, w2, fd.ret, i)
                t:assert_eq(e.ret, 0, "child " .. i .. ": " .. sys.errname(e.errno or 0))
                seen[e.name] = true
            end
            t:assert(seen["Secret"], "a child whose descriptor denies the caller is still named")
            t:assert(seen["Plain"], "alongside the one it may open")
            local locked = open_as(t, w2, "Machine\\Enumerable\\Secret", R.KEY_READ)
            t:assert_eq(locked.errno, sys.E.ACCES,
                "the caller learns the name and must open it separately, with a real AccessCheck")
            sys.close(w2, fd.ret)
        end)
    end)

test("a subtree watch reports a descendant without a check on that descendant",
    { spec = "PKM *right.subtree-watch-no-per-descendant-check" }, function(t)
        token.as_principal(t, vm, { user_sid = token.SID.TEST_USER }, function(w2)
            local fd = open_as(t, w2, "Machine\\Watched", R.NOTIFY)
            t:assert(fd.ret >= 0, "the watcher holds KEY_NOTIFY on the root: " ..
                sys.errname(fd.errno or 0))
            t:assert_eq(lcs.notify(nil, w2, fd.ret, lcs.NOTIFY.SUBKEY, true).ret, 0,
                "and arms a subtree watch")

            -- SYSTEM creates a key under a subtree the watcher cannot
            -- reach; the child inherits the container-inheritable
            -- SYSTEM-only descriptor.
            local made = lcs.create_key(src, w, { path = "Machine\\Watched\\Locked\\Fresh" })
            t:assert(made.ret >= 0, "SYSTEM creates it: " .. sys.errname(made.errno or 0))
            sys.close(w, made.ret)

            local ev = lcs.read_events(nil, w2, fd.ret)
            t:assert(ev.ret > 0, "the watcher is told: " .. sys.errname(ev.errno or 0))
            t:assert_eq(ev.events[1].type, lcs.WATCH.SUBKEY_CREATED, "SUBKEY_CREATED")

            local nope = open_as(t, w2, "Machine\\Watched\\Locked\\Fresh", R.KEY_READ)
            t:assert_eq(nope.errno, sys.E.ACCES,
                "for a descendant it could not have opened: structure visibility is " ..
                "deliberately weaker than content visibility")
            sys.close(w2, fd.ret)
        end)
    end)
