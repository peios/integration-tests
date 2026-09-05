-- PKM §5.2.6 Values and §5.2.7 Tombstones — a named typed datum with
-- one entry per writing layer, the full Windows type set, REG_TOMBSTONE,
-- value naming, and the two kinds of tombstone that express absence.
--
-- MaxValueSize is configured down to its minimum (4 KB) so the size
-- bound can be exercised without pushing a megabyte through the RSI.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")

local vm = provium:vm("v", "kernel-only"):boot()

local TEST = "Machine\\Software\\Test"
local MAX_VALUE_SIZE = 4096

local src, scratch, tomb_key, blanket_key, same_layer_key, tie_key, typed_key
local function fixture()
    if src then return src end
    local s = lcs.source(vm)
    s:key(lcs.LAYERS_PATH .. "\\base", { sd = lcs.permissive_sd() })
    s:seed_param("MaxValueSize", MAX_VALUE_SIZE)
    s:seed_layer("Policy", { precedence = 10, enabled = true })
    s:seed_layer("Blank", { precedence = 20, enabled = true })
    s:seed_layer("TieA", { precedence = 30, enabled = true })
    s:seed_layer("TieB", { precedence = 30, enabled = true })
    -- A layer of its own for the blanket-shape case, which runs after
    -- the tombstone-revert case has deleted `Policy`.
    s:seed_layer("Flag", { precedence = 40, enabled = true })
    s:key(TEST)

    scratch = s:key(TEST .. "\\Scratch")

    -- Every type tag, seeded rather than written: §5.2.4's write-time
    -- gate refuses REG_LINK, which has its own known-bug case below.
    typed_key = s:key(TEST .. "\\Typed")
    for code = 0, 11 do
        s:value(typed_key, "T" .. code, code, string.char(code, 0xEE, 0xBB) .. "payload")
    end

    -- A value tombstoned by a higher-precedence layer.
    tomb_key = s:key(TEST .. "\\Tomb")
    s:value(tomb_key, "V", lcs.TYPE.SZ, lcs.sz("base"))
    s:value(tomb_key, "Untouched", lcs.TYPE.SZ, lcs.sz("base"))
    s:tombstone(tomb_key, "V", "Policy")

    -- A key whose base values a blanket in `Blank` masks.
    blanket_key = s:key(TEST .. "\\Blanketed")
    for _, n in ipairs({ "A", "B", "C" }) do
        s:value(blanket_key, n, lcs.TYPE.SZ, lcs.sz("base " .. n))
    end
    s:blanket(blanket_key, "Blank")

    -- A blanket and, in the same layer afterwards, a value of its own.
    same_layer_key = s:key(TEST .. "\\SameLayer")
    s:value(same_layer_key, "Old", lcs.TYPE.SZ, lcs.sz("base"))
    s:value(same_layer_key, "New", lcs.TYPE.SZ, lcs.sz("base"))
    s:blanket(same_layer_key, "Blank")
    s:value(same_layer_key, "New", lcs.TYPE.SZ, lcs.sz("blank"), { layer = "Blank" })

    -- One precedence, two layers: the blanket in TieA, and values in
    -- TieB written before and after it.
    tie_key = s:key(TEST .. "\\Tie")
    s:value(tie_key, "Earlier", lcs.TYPE.SZ, lcs.sz("tieb"), { layer = "TieB" })
    s:value(tie_key, "Loser", lcs.TYPE.SZ, lcs.sz("base"))
    s:blanket(tie_key, "TieA")
    s:value(tie_key, "Later", lcs.TYPE.SZ, lcs.sz("tieb"), { layer = "TieB" })

    assert(s:register())
    s:pump()
    src = s
    return s
end

local function worker() return vm:spawn_worker() end
local function done(w) w:kill(); w:join() end

local function open(t, w, path, mask)
    local r = lcs.open_key(src, w, -1, path, mask or lcs.KEY_ALL_ACCESS)
    t:assert(r.ret >= 0, "open " .. path .. ": " .. sys.errname(r.errno or 0))
    return r.ret
end

--- The effective value names on a key, from REG_IOC_QUERY_VALUES_BATCH.
local function effective_names(s, w, fd)
    local b = lcs.query_values_batch(s, w, fd)
    local out = {}
    for _, v in ipairs(b.values or {}) do out[v.name] = v end
    return out, b
end

--- The names REG_IOC_ENUM_VALUES walks, in order.
local function enumerated(s, w, fd)
    local out = {}
    for i = 0, 63 do
        local e = lcs.enum_values(s, w, fd, i)
        if e.ret ~= 0 then break end
        out[#out + 1] = e.name
    end
    table.sort(out)
    return out
end

--- An RSI_QUERY_VALUES response body from a row list.
local function values_body(rows)
    local out = { string.pack("<I4", #rows) }
    for _, v in ipairs(rows) do
        out[#out + 1] = string.pack("<s4", v.name) .. string.pack("<s4", v.layer)
            .. string.pack("<I4", v.type) .. string.pack("<s4", v.data)
            .. string.pack("<I8", v.seq)
    end
    out[#out + 1] = string.pack("<I4", 0)
    return table.concat(out)
end

--- Answer a query for `asked` with the entry stored under `stored`, as a
--- source whose folding is Unicode-aware would. The Lua source folds
--- ASCII only, so a case about folding beyond ASCII has to hand LCS the
--- row and let LCS decide whether the two names are one.
local function answer_folded(s, asked, row)
    s:intercept(lcs.OP.QUERY_VALUES, row and function(self, req)
        local name = string.unpack("<s4", req.payload, 17)
        if name == asked then return lcs.STATUS.OK, values_body({ row }) end
        return nil
    end or nil)
end

-- Fields ------------------------------------------------------------------

test("the empty string is the default value",
    { spec = "PKM *value.field.empty-name-is-the-default-value" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\Scratch")
        local sv = lcs.set_value(s, w, fd, "", lcs.TYPE.SZ, lcs.sz("default"))
        t:assert_eq(sv.ret, 0, "the empty name is accepted: " .. sys.errname(sv.errno or 0))
        local q = lcs.query_value(s, w, fd, "")
        t:assert_eq(q.ret, 0, "and reads back: " .. sys.errname(q.errno or 0))
        t:assert_eq(q.data, lcs.sz("default"), "as the key's default value")
        lcs.delete_value(s, w, fd, "")
        sys.close(w, fd)
        done(w)
    end)

test("value data is bounded by MaxValueSize",
    { spec = "PKM *value.field.data-bounded-by-max-value-size" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\Scratch")
        local at_limit = lcs.set_value(s, w, fd, "AtLimit", lcs.TYPE.BINARY,
            string.rep("x", MAX_VALUE_SIZE))
        t:assert_eq(at_limit.ret, 0,
            "MaxValueSize bytes is accepted: " .. sys.errname(at_limit.errno or 0))
        local mark = s:mark()
        local over = lcs.set_value(nil, w, fd, "Over", lcs.TYPE.BINARY,
            string.rep("x", MAX_VALUE_SIZE + 1))
        t:assert(over.ret < 0, "one byte more is refused")
        t:assert_eq(over.errno, sys.E.NOSPC,
            "value data exceeding MaxValueSize is ENOSPC: " .. sys.errname(over.errno or 0))
        t:assert_eq(#s:served(lcs.OP.SET_VALUE, mark), 0, "and nothing was dispatched")
        lcs.delete_value(s, w, fd, "AtLimit")
        sys.close(w, fd)
        done(w)
    end)

test("every write is tagged with a layer",
    { spec = "PKM *value.field.every-write-is-layer-tagged" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\Scratch")
        local mark = s:mark()
        t:assert_eq(lcs.set_value(s, w, fd, "Tagged", lcs.TYPE.DWORD, lcs.dword(1)).ret, 0,
            "a write with no layer named")
        t:assert_eq(lcs.set_value(s, w, fd, "Tagged", lcs.TYPE.DWORD, lcs.dword(2),
            { layer = "Policy" }).ret, 0, "and one into a named layer")
        local writes = s:served(lcs.OP.SET_VALUE, mark, scratch)
        t:assert_eq(#writes, 2, "two RSI_SET_VALUE requests")
        local layers = {}
        for i, req in ipairs(writes) do
            local _, at = string.unpack("<s4", req.payload, 17)
            layers[i] = string.unpack("<s4", req.payload, at)
        end
        t:assert_eq(layers[1], "base", "an unqualified write is tagged with the base layer")
        t:assert_eq(layers[2], "Policy", "and a qualified one with the layer named")
        local q = lcs.query_value(s, w, fd, "Tagged")
        t:assert_eq(q.layer, "Policy", "the read reports which layer won")
        lcs.delete_value(s, w, fd, "Tagged")
        lcs.delete_value(s, w, fd, "Tagged", { layer = "Policy" })
        sys.close(w, fd)
        done(w)
    end)

test("a key holds at most one unnamed value",
    { spec = "PKM *value.at-most-one-unnamed-value-per-key" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\Scratch")
        t:assert_eq(lcs.set_value(s, w, fd, "", lcs.TYPE.SZ, lcs.sz("first")).ret, 0, "first")
        t:assert_eq(lcs.set_value(s, w, fd, "", lcs.TYPE.SZ, lcs.sz("second")).ret, 0, "second")
        local q = lcs.query_value(s, w, fd, "")
        t:assert_eq(q.data, lcs.sz("second"), "the second write replaced the first")
        local names = enumerated(s, w, fd)
        local unnamed = 0
        for _, n in ipairs(names) do if n == "" then unnamed = unnamed + 1 end end
        t:assert_eq(unnamed, 1, "and exactly one unnamed value is enumerated")
        lcs.delete_value(s, w, fd, "")
        sys.close(w, fd)
        done(w)
    end)

test("one name may have one entry per writing layer, and the source returns them all",
    { spec = "PKM *value.one-name-many-entries.one-entry-per-writing-layer" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\Scratch")
        t:assert_eq(lcs.set_value(s, w, fd, "Many", lcs.TYPE.SZ, lcs.sz("base")).ret, 0, "base")
        t:assert_eq(lcs.set_value(s, w, fd, "Many", lcs.TYPE.SZ, lcs.sz("policy"),
            { layer = "Policy" }).ret, 0, "policy")
        local slot = s.store.values[scratch][lcs.fold("Many")]
        local count = 0
        for _ in pairs(slot.by_layer) do count = count + 1 end
        t:assert_eq(count, 2, "the source holds one entry per layer that has written")
        lcs.delete_value(s, w, fd, "Many")
        lcs.delete_value(s, w, fd, "Many", { layer = "Policy" })
        sys.close(w, fd)
        done(w)
    end)

test("the source returns every entry and LCS resolves the effective one",
    { spec = "PKM *value.one-name-many-entries.source-returns-every-entry" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\Scratch")
        lcs.set_value(s, w, fd, "Both", lcs.TYPE.SZ, lcs.sz("base"))
        lcs.set_value(s, w, fd, "Both", lcs.TYPE.SZ, lcs.sz("policy"), { layer = "Policy" })
        local mark = s:mark()
        local q = lcs.query_value(s, w, fd, "Both")
        t:assert_eq(q.ret, 0, "query: " .. sys.errname(q.errno or 0))
        local served = s:served(lcs.OP.QUERY_VALUES, mark, scratch)
        t:assert(#served >= 1, "the source was asked once for the name")
        local slot = s.store.values[scratch][lcs.fold("Both")]
        local held = 0
        for _ in pairs(slot.by_layer) do held = held + 1 end
        t:assert_eq(held, 2, "the source holds both entries and returned both")
        t:assert_eq(q.data, lcs.sz("policy"), "the higher-precedence entry is effective")
        t:assert_eq(q.layer, "Policy", "and the read names the layer it came from")
        lcs.delete_value(s, w, fd, "Both")
        lcs.delete_value(s, w, fd, "Both", { layer = "Policy" })
        sys.close(w, fd)
        done(w)
    end)

-- Types ---------------------------------------------------------------------

test("the full Windows type set, numbered 0 to 11, is supported",
    { spec = "PKM *value.types.full-windows-set-numbered-0-to-11" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\Typed", lcs.RIGHT.KEY_READ)
        for code = 0, 11 do
            local q = lcs.query_value(s, w, fd, "T" .. code)
            t:assert_eq(q.ret, 0, "type " .. code .. " reads back: "
                .. sys.errname(q.errno or 0))
            t:assert_eq(q.type, code, "with its tag intact")
            t:assert_eq(q.data, string.char(code, 0xEE, 0xBB) .. "payload",
                "and its data unchanged")
        end
        sys.close(w, fd)
        done(w)
    end)

test("LCS stores the type tag and returns it without interpreting the data",
    { spec = "PKM *value.types.tag-stored-and-returned-uninterpreted" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\Scratch")
        -- A REG_SZ that is not a string, a REG_DWORD that is not four
        -- bytes: the tag is carried, the data is not read.
        local cases = {
            { lcs.TYPE.SZ, "\xff\xfe not a string at all" },
            { lcs.TYPE.DWORD, "seven!!" },
            { lcs.TYPE.MULTI_SZ, "no terminators here" },
            { lcs.TYPE.QWORD, "" },
        }
        for i, c in ipairs(cases) do
            local name = "Uninterpreted" .. i
            local sv = lcs.set_value(s, w, fd, name, c[1], c[2])
            t:assert_eq(sv.ret, 0, "the write is accepted: " .. sys.errname(sv.errno or 0))
            local q = lcs.query_value(s, w, fd, name)
            t:assert_eq(q.type, c[1], "the tag comes back")
            t:assert_eq(q.data, c[2], "and the bytes come back unchanged")
            lcs.delete_value(s, w, fd, name)
        end
        sys.close(w, fd)
        done(w)
    end)

-- KNOWN BUG. §5.2.6: LCS "does not interpret the data. The single
-- exception is REG_LINK read as a symlink key's default value".
-- pkm_lcs_key_fd_set_value_symlink_target_gate (lcs/key_fd.c) fires on
-- *every* REG_LINK write, named values on ordinary keys included, and
-- hands the length-delimited value data to
-- validate_syscall_path_c_string, which requires a NUL terminator. So no
-- REG_LINK value can be written at all: the write is EINVAL, and the
-- only payload it accepts (one with a trailing NUL) is a target
-- §5.2.4 says resolution must reject.
test("a named REG_LINK value is stored and returned uninterpreted",
    { spec = "PKM *value.types.tag-stored-and-returned-uninterpreted",
      tags = { "known-bug" } }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\Scratch")
        local sv = lcs.set_value(s, w, fd, "NamedLink", lcs.TYPE.LINK, "Machine\\Software")
        t:assert_eq(sv.ret, 0,
            "a REG_LINK value that is not a symlink target is ordinary data: "
            .. sys.errname(sv.errno or 0))
        local q = lcs.query_value(s, w, fd, "NamedLink")
        t:assert_eq(q.type, lcs.TYPE.LINK, "the tag comes back")
        t:assert_eq(q.data, "Machine\\Software", "and the bytes unchanged")
        sys.close(w, fd)
        done(w)
    end)

test("the three hardware-resource types behave exactly as REG_BINARY",
    { spec = "PKM *value.types.hardware-resource-types-behave-as-reg-binary" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\Scratch")
        local payload = "\x00\x01\xff\xfe arbitrary resource bytes"
        local binary = lcs.set_value(s, w, fd, "Ref", lcs.TYPE.BINARY, payload)
        t:assert_eq(binary.ret, 0, "REG_BINARY: " .. sys.errname(binary.errno or 0))
        for _, code in ipairs({ lcs.TYPE.RESOURCE_LIST,
                                lcs.TYPE.FULL_RESOURCE_DESCRIPTOR,
                                lcs.TYPE.RESOURCE_REQUIREMENTS_LIST }) do
            local name = "Res" .. code
            local sv = lcs.set_value(s, w, fd, name, code, payload)
            t:assert_eq(sv.ret, 0, "type " .. code .. " writes: " .. sys.errname(sv.errno or 0))
            local q = lcs.query_value(s, w, fd, name)
            t:assert_eq(q.type, code, "and round-trips with its tag intact")
            t:assert_eq(q.data, payload, "and the same bytes REG_BINARY carried")
            local names = effective_names(s, w, fd)
            t:assert(names[name] ~= nil, "it enumerates like any other value")
            t:assert_eq(names[name].type, code, "with its own tag")
            lcs.delete_value(s, w, fd, name)
        end
        lcs.delete_value(s, w, fd, "Ref")
        sys.close(w, fd)
        done(w)
    end)

test("an unknown type code is EINVAL, before any dispatch",
    { spec = "PKM *value.types.unknown-type-code-is-einval" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\Scratch")
        for _, code in ipairs({ 12, 13, 0xFFFE, 0x7FFFFFFF }) do
            local mark = s:mark()
            local r = lcs.set_value(nil, w, fd, "Bad", code, "x")
            t:assert_eq(r.errno, sys.E.INVAL,
                "type " .. code .. " is invalid: " .. sys.errname(r.errno or 0))
            t:assert_eq(#s:served(lcs.OP.SET_VALUE, mark), 0,
                "and is refused before the source is dispatched to")
        end
        sys.close(w, fd)
        done(w)
    end)

-- REG_TOMBSTONE -------------------------------------------------------------

test("writing type REG_TOMBSTONE is the explicit tombstone operation",
    { spec = "PKM *value.reg-tombstone.written-by-setting-the-type" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\Scratch")
        lcs.set_value(s, w, fd, "Doomed", lcs.TYPE.SZ, lcs.sz("here"))
        t:assert_eq(lcs.query_value(s, w, fd, "Doomed").ret, 0, "the value is there")
        local sv = lcs.set_value(s, w, fd, "Doomed", lcs.TYPE.TOMBSTONE, "",
            { layer = "Policy" })
        t:assert_eq(sv.ret, 0, "writing REG_TOMBSTONE: " .. sys.errname(sv.errno or 0))
        local stored = s.store.values[scratch][lcs.fold("Doomed")].by_layer[lcs.fold("Policy")]
        t:assert_eq(stored.type, lcs.TYPE.TOMBSTONE,
            "the source stores an entry of type REG_TOMBSTONE")
        t:assert_eq(stored.data, "", "with no data")
        lcs.delete_value(s, w, fd, "Doomed", { layer = "Policy" })
        lcs.delete_value(s, w, fd, "Doomed")
        sys.close(w, fd)
        done(w)
    end)

test("a tombstone is never returned to a caller",
    { spec = "PKM *value.reg-tombstone.never-returned-to-a-caller" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\Tomb", lcs.RIGHT.KEY_READ)
        local q = lcs.query_value(s, w, fd, "V")
        t:assert_eq(q.errno, sys.E.NOENT,
            "a caller whose effective entry is a tombstone gets ENOENT: "
            .. sys.errname(q.errno or 0))
        local names = effective_names(s, w, fd)
        t:assert(names["V"] == nil, "the batch does not carry it")
        for _, v in pairs(names) do
            t:assert(v.type ~= lcs.TYPE.TOMBSTONE, "and no read ever returns the type")
        end
        t:assert(names["Untouched"] ~= nil, "while its neighbour is unaffected")
        for _, n in ipairs(enumerated(s, w, fd)) do
            t:assert(n ~= "V", "and enumeration skips it")
        end
        sys.close(w, fd)
        done(w)
    end)

test("a tombstone with non-empty data is EINVAL, before any dispatch",
    { spec = "PKM *value.reg-tombstone.non-empty-data-is-einval" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\Scratch")
        local mark = s:mark()
        local r = lcs.set_value(nil, w, fd, "BadTomb", lcs.TYPE.TOMBSTONE, "x")
        t:assert_eq(r.errno, sys.E.INVAL,
            "non-empty tombstone data is invalid: " .. sys.errname(r.errno or 0))
        t:assert_eq(#s:served(lcs.OP.SET_VALUE, mark), 0,
            "refused before sequence allocation, enlistment or dispatch")
        sys.close(w, fd)
        done(w)
    end)

-- Naming ---------------------------------------------------------------------

test("value names use the same case rules as key names",
    { spec = "PKM *value.name.same-case-rules-as-key-names" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\Scratch")
        lcs.set_value(s, w, fd, "MixedCase", lcs.TYPE.SZ, lcs.sz("stored"))
        local q = lcs.query_value(s, w, fd, "MIXEDCASE")
        t:assert_eq(q.ret, 0, "a different spelling finds it: " .. sys.errname(q.errno or 0))
        t:assert_eq(q.data, lcs.sz("stored"), "the same value")
        local names = effective_names(s, w, fd)
        t:assert(names["MixedCase"] ~= nil, "and storage preserved the spelling written")

        -- Beyond ASCII: Simple Case Folding maps capital sigma and final
        -- sigma onto the same codepoint, so all three spellings are one
        -- name. The Lua source folds ASCII only, so it is made to answer
        -- with every entry and let LCS do the matching.
        lcs.set_value(s, w, fd, "\u{03A3}igma", lcs.TYPE.SZ, lcs.sz("greek"))
        local stored = s.store.values[scratch][lcs.fold("\u{03A3}igma")]
        answer_folded(s, "\u{03C3}igma", stored.by_layer[lcs.fold("base")])
        local folded = lcs.query_value(s, w, fd, "\u{03C3}igma")
        answer_folded(s, nil, nil)
        t:assert_eq(folded.ret, 0,
            "U+03C3 finds the value written as U+03A3: " .. sys.errname(folded.errno or 0))
        t:assert_eq(folded.data, lcs.sz("greek"), "the same value")
        lcs.delete_value(s, w, fd, "MixedCase")
        lcs.delete_value(s, w, fd, "\u{03A3}igma")
        sys.close(w, fd)
        done(w)
    end)

test("backslash and forward slash are permitted in a value name",
    { spec = "PKM *value.name.separators-are-permitted" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\Scratch")
        local name = "a\\b/c\\"
        local sv = lcs.set_value(s, w, fd, name, lcs.TYPE.SZ, lcs.sz("sep"))
        t:assert_eq(sv.ret, 0, "a value name may hold separators: " .. sys.errname(sv.errno or 0))
        local q = lcs.query_value(s, w, fd, name)
        t:assert_eq(q.ret, 0, "and reads back by that name: " .. sys.errname(q.errno or 0))
        local names = effective_names(s, w, fd)
        t:assert(names[name] ~= nil, "and enumerates under it whole")
        lcs.delete_value(s, w, fd, name)
        sys.close(w, fd)
        done(w)
    end)

test("only the null byte is forbidden in a value name",
    { spec = "PKM *value.name.only-the-null-byte-is-forbidden" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\Scratch")
        local nul = lcs.set_value(nil, w, fd, "has\0null", lcs.TYPE.SZ, lcs.sz("x"))
        t:assert_eq(nul.errno, sys.E.INVAL,
            "a null byte in a value name is invalid: " .. sys.errname(nul.errno or 0))
        local bad_utf8 = lcs.set_value(nil, w, fd, "bad\xffutf8", lcs.TYPE.SZ, lcs.sz("x"))
        t:assert_eq(bad_utf8.errno, sys.E.INVAL,
            "and invalid UTF-8 is rejected: " .. sys.errname(bad_utf8.errno or 0))
        local ok = lcs.set_value(s, w, fd, "spaces and Ünïcödé 🙂", lcs.TYPE.SZ, lcs.sz("x"))
        t:assert_eq(ok.ret, 0, "everything else is permitted: " .. sys.errname(ok.errno or 0))
        lcs.delete_value(s, w, fd, "spaces and Ünïcödé 🙂")
        sys.close(w, fd)
        done(w)
    end)

test("value data is opaque bytes and is not UTF-8 validated",
    { spec = "PKM *value.data.opaque-and-not-utf8-validated" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\Scratch")
        local payload = "\xff\xfe\x00\x80\xc0 not UTF-8 \x00 and with nulls"
        local sv = lcs.set_value(s, w, fd, "Opaque", lcs.TYPE.BINARY, payload)
        t:assert_eq(sv.ret, 0, "invalid UTF-8 in the data is accepted: "
            .. sys.errname(sv.errno or 0))
        local q = lcs.query_value(s, w, fd, "Opaque")
        t:assert_eq(q.data, payload, "and comes back byte for byte, nulls included")
        lcs.delete_value(s, w, fd, "Opaque")
        sys.close(w, fd)
        done(w)
    end)

-- §5.2.7 value tombstones -------------------------------------------------

test("a value tombstone masks lower-precedence layers",
    { spec = "PKM *tombstone.value.masks-lower-precedence-layers" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\Tomb", lcs.RIGHT.KEY_READ)
        t:assert(s.store.values[tomb_key][lcs.fold("V")].by_layer[lcs.fold("base")] ~= nil,
            "the base layer still holds the value")
        local q = lcs.query_value(s, w, fd, "V")
        t:assert_eq(q.errno, sys.E.NOENT,
            "the Policy tombstone masks it: " .. sys.errname(q.errno or 0))
        sys.close(w, fd)
        done(w)
    end)

test("a winning tombstone does not fall through to the next layer",
    { spec = "PKM *tombstone.value.winning-tombstone-does-not-fall-through" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\Tomb", lcs.RIGHT.KEY_READ)
        local q = lcs.query_value(s, w, fd, "V")
        t:assert_eq(q.errno, sys.E.NOENT, "resolution stops at the tombstone")
        t:assert(q.data == nil or q.data == "",
            "the lower-precedence value is not returned instead")
        local names = effective_names(s, w, fd)
        t:assert(names["V"] == nil, "and the batch does not fall through either")
        sys.close(w, fd)
        done(w)
    end)

test("both kinds of tombstone are per-layer and vanish with their layer",
    { spec = "PKM *tombstone.per-layer-and-vanish-with-the-layer" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\Tomb", lcs.RIGHT.KEY_READ)
        t:assert_eq(lcs.query_value(s, w, fd, "V").errno, sys.E.NOENT, "masked to begin with")
        local layer_fd = open(t, w, lcs.LAYERS_PATH .. "\\Policy")
        t:assert_eq(lcs.delete_key(s, w, layer_fd).ret, 0, "delete the tombstone's layer")
        sys.close(w, layer_fd)
        local q = lcs.query_value(s, w, fd, "V")
        t:assert_eq(q.ret, 0, "the masked value is restored: " .. sys.errname(q.errno or 0))
        t:assert_eq(q.data, lcs.sz("base"), "to what it was masking")
        sys.close(w, fd)
        done(w)
    end)

-- §5.2.7 blanket tombstones -------------------------------------------------

test("a blanket tombstone masks every value name from lower layers",
    { spec = "PKM *tombstone.blanket.masks-every-value-name" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\Blanketed", lcs.RIGHT.KEY_READ)
        for _, n in ipairs({ "A", "B", "C" }) do
            local q = lcs.query_value(s, w, fd, n)
            t:assert_eq(q.errno, sys.E.NOENT,
                n .. " is masked whatever its name: " .. sys.errname(q.errno or 0))
        end
        sys.close(w, fd)
        done(w)
    end)

test("a blanket covers names that were not known when it was written",
    { spec = "PKM *tombstone.blanket.covers-names-unknown-when-written" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\Blanketed")
        -- A name the blanket's author never saw, written into a lower
        -- layer afterwards, is masked all the same.
        local sv = lcs.set_value(s, w, fd, "LaterName", lcs.TYPE.SZ, lcs.sz("base"))
        t:assert_eq(sv.ret, 0, "write: " .. sys.errname(sv.errno or 0))
        local q = lcs.query_value(s, w, fd, "LaterName")
        t:assert_eq(q.errno, sys.E.NOENT,
            "the blanket names none and covers all: " .. sys.errname(q.errno or 0))
        lcs.delete_value(s, w, fd, "LaterName")
        sys.close(w, fd)
        done(w)
    end)

test("a blanket is a flag on (key GUID, layer) with its own sequence number",
    { spec = "PKM *tombstone.blanket.stored-as-a-flag-with-its-own-sequence" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\Scratch")
        local mark = s:mark()
        local b = lcs.blanket_tombstone(s, w, fd, "Flag", true)
        t:assert_eq(b.ret, 0, "set a blanket: " .. sys.errname(b.errno or 0))
        local reqs = s:served(lcs.OP.BLANKET_TOMBSTONE, mark, scratch)
        t:assert_eq(#reqs, 1, "one RSI_BLANKET_TOMBSTONE")
        local layer, at = string.unpack("<s4", reqs[1].payload, 17)
        t:assert_eq(layer, "Flag", "naming the layer")
        t:assert_eq(reqs[1].payload:byte(at), 1, "and setting the flag")
        local seq = string.unpack("<I8", reqs[1].payload, at + 1)
        t:assert(seq > 0, "with a sequence number of its own")
        local stored = s.store.blankets[scratch][lcs.fold("Flag")]
        t:assert_eq(stored.seq, seq, "which the source records against (key, layer)")
        -- And no per-name entry was created for it.
        for name, slot in pairs(s.store.values[scratch] or {}) do
            for _, e in pairs(slot.by_layer) do
                t:assert(not (e.layer == "Flag" and e.type == lcs.TYPE.TOMBSTONE),
                    "it occupies no per-name entry (" .. name .. ")")
            end
        end
        lcs.blanket_tombstone(s, w, fd, "Flag", false)
        sys.close(w, fd)
        done(w)
    end)

test("a per-value entry wins or loses against the blanket on the (precedence, sequence) tuple",
    { spec = "PKM *tombstone.blanket.per-value-entry-wins-or-loses-on-the-tuple" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\Blanketed")
        -- A value written into the blanket's own layer afterwards wins:
        -- same precedence, higher sequence.
        local sv = lcs.set_value(s, w, fd, "A", lcs.TYPE.SZ, lcs.sz("blank"),
            { layer = "Blank" })
        t:assert_eq(sv.ret, 0, "write into the blanket's layer: " .. sys.errname(sv.errno or 0))
        local q = lcs.query_value(s, w, fd, "A")
        t:assert_eq(q.ret, 0, "it beats the blanket: " .. sys.errname(q.errno or 0))
        t:assert_eq(q.data, lcs.sz("blank"), "and is the effective value")
        -- While a base entry, lower on precedence, still loses.
        local loser = lcs.query_value(s, w, fd, "B")
        t:assert_eq(loser.errno, sys.E.NOENT, "one that loses on the tuple stays masked")
        lcs.delete_value(s, w, fd, "A", { layer = "Blank" })
        sys.close(w, fd)
        done(w)
    end)

test("the blanket enters the candidate pool for every value name",
    { spec = "PKM *tombstone.blanket.enters-the-candidate-pool-for-every-name" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\SameLayer", lcs.RIGHT.KEY_READ)
        -- `Old` and `New` are both base values under one blanket. The
        -- blanket is a candidate for each name separately, so the
        -- ordinary rule can pick a different winner per name rather than
        -- short-circuiting the key.
        t:assert_eq(lcs.query_value(s, w, fd, "Old").errno, sys.E.NOENT,
            "the blanket wins for a name nothing else claims")
        local won = lcs.query_value(s, w, fd, "New")
        t:assert_eq(won.ret, 0, "and loses for one that does: " .. sys.errname(won.errno or 0))
        t:assert_eq(won.data, lcs.sz("blank"), "per name, not per key")
        sys.close(w, fd)
        done(w)
    end)

test("writes made after a blanket in the same layer stay visible",
    { spec = "PKM *tombstone.blanket.same-layer-writes-after-a-blanket-stay-visible" },
    function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\SameLayer", lcs.RIGHT.KEY_READ)
        local blanket = s.store.blankets[same_layer_key][lcs.fold("Blank")]
        local after = s.store.values[same_layer_key][lcs.fold("New")].by_layer[lcs.fold("Blank")]
        t:assert(after.seq > blanket.seq, "the value was written after the blanket")
        local q = lcs.query_value(s, w, fd, "New")
        t:assert_eq(q.ret, 0, "so it is visible: " .. sys.errname(q.errno or 0))
        t:assert_eq(q.data, lcs.sz("blank"), "with the layer's own data")
        t:assert_eq(lcs.query_value(s, w, fd, "Old").errno, sys.E.NOENT,
            "and everything else from below is masked")
        sys.close(w, fd)
        done(w)
    end)

test("enumeration applies the per-name rule to a blanketed key",
    { spec = "PKM *tombstone.blanket.enumeration-applies-the-per-name-rule" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\SameLayer", lcs.RIGHT.KEY_READ)
        local names = enumerated(s, w, fd)
        t:assert_eq(table.concat(names, ","), "New",
            "a caller sees the names whose winning candidate is not the blanket")
        local batch = effective_names(s, w, fd)
        t:assert(batch["New"] ~= nil and batch["Old"] == nil,
            "and the batch agrees with the enumeration")
        sys.close(w, fd)
        done(w)
    end)

test("enumeration surfaces a higher sequence at the same precedence",
    { spec = "PKM *tombstone.blanket.enumeration-surfaces-higher-sequence-at-same-precedence" },
    function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\Tie", lcs.RIGHT.KEY_READ)
        local blanket = s.store.blankets[tie_key][lcs.fold("TieA")]
        local earlier = s.store.values[tie_key][lcs.fold("Earlier")].by_layer[lcs.fold("TieB")]
        local later = s.store.values[tie_key][lcs.fold("Later")].by_layer[lcs.fold("TieB")]
        t:assert(earlier.seq < blanket.seq and later.seq > blanket.seq,
            "TieB wrote one value before the TieA blanket and one after")
        local names = enumerated(s, w, fd)
        t:assert_eq(table.concat(names, ","), "Later",
            "it is not simply the blanket's layer and above: the same-precedence "
            .. "entry with the higher sequence surfaces and the lower one does not")
        sys.close(w, fd)
        done(w)
    end)

test("removing a blanket unmasks everything it was hiding",
    { spec = "PKM *tombstone.blanket.removal-unmasks-everything-it-hid" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\Blanketed")
        t:assert_eq(lcs.query_value(s, w, fd, "B").errno, sys.E.NOENT, "masked to begin with")
        local b = lcs.blanket_tombstone(s, w, fd, "Blank", false)
        t:assert_eq(b.ret, 0, "clear the blanket: " .. sys.errname(b.errno or 0))
        for _, n in ipairs({ "B", "C" }) do
            local q = lcs.query_value(s, w, fd, n)
            t:assert_eq(q.ret, 0, n .. " is unmasked: " .. sys.errname(q.errno or 0))
            t:assert_eq(q.data, lcs.sz("base " .. n), "with what it was hiding")
        end
        sys.close(w, fd)
        done(w)
    end)
