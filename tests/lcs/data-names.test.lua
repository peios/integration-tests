-- PKM §5.2.8 Names and Case — every string is UTF-8, every length is a
-- byte count, backslash and forward slash are both separators, and
-- comparison is Unicode Simple Case Folding pinned to one version.
--
-- Folding is LCS's own work only where LCS compares names itself: hive
-- routing and layer identity. A key name reaches the source as a
-- (parent, name) lookup, so most of the folding cases here are about
-- hives.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")
local token = require("helpers.token")

local vm = provium:vm("v", "kernel-only"):boot()

local TEST = "Machine\\Software\\Test"
local SIGMA_UPPER, SIGMA_LOWER = "\u{03A3}igma", "\u{03C3}igma"
local CAFE_NFC, CAFE_NFD = "Caf\u{00E9}", "Cafe\u{0301}"
local SHARP_CAPITAL, SHARP_SMALL = "\u{1E9E}sharp", "\u{00DF}sharp"
local DOTTED_I = "\u{0130}dot"
-- Garay, added in Unicode 16.0: U+10D50..U+10D65 fold to U+10D70..
local GARAY_UPPER, GARAY_LOWER = "\u{10D50}garay", "\u{10D70}garay"

local src, test_key
local function fixture()
    if src then return src end
    local s = lcs.source(vm, { hives = {
        { name = "Machine" },
        { name = SIGMA_UPPER },
        { name = CAFE_NFC }, { name = CAFE_NFD },
        { name = "stra\u{00DF}e" }, { name = "strasse" },
        { name = SHARP_CAPITAL },
        { name = DOTTED_I },
        { name = GARAY_UPPER },
    } })
    s:key(lcs.LAYERS_PATH .. "\\base", { sd = lcs.permissive_sd() })
    test_key = s:key(TEST)
    s:key(TEST .. "\\MixedCase")
    for i = 2, #s.hives do
        s:key(s.hives[i].name .. "\\Marker", { root = s.hives[i].root })
        -- A value naming the hive, so a routed open can say which one it
        -- reached.
        local guid = s:lookup(s.hives[i].name .. "\\Marker")
            or s:key(s.hives[i].name .. "\\Marker", { root = s.hives[i].root })
        s:value(guid, "Which", lcs.TYPE.SZ, lcs.sz(s.hives[i].name))
    end
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

--- Which hive `path` routed into, by the marker value it carries.
local function which_hive(t, s, w, name)
    local r = lcs.open_key(s, w, -1, name .. "\\Marker", lcs.RIGHT.KEY_READ)
    if r.ret < 0 then return nil, r.errno end
    local q = lcs.query_value(s, w, r.ret, "Which")
    sys.close(w, r.ret)
    return q.data
end

--- A path of exactly `total` bytes under `prefix`, built from
--- components no longer than MaxPathComponentLength.
local function path_of_length(prefix, total)
    local parts, len = { prefix }, #prefix
    while len + 1 + 255 <= total do
        parts[#parts + 1] = string.rep("x", 255)
        len = len + 256
    end
    if len < total then parts[#parts + 1] = string.rep("y", total - len - 1) end
    return table.concat(parts, "\\")
end

-- UTF-8 -----------------------------------------------------------------

test("invalid UTF-8 is EINVAL before parsing, routing or dispatch",
    { spec = "PKM *name.utf8.invalid-utf8-is-einval-before-any-other-work" }, function(t)
        local s = fixture()
        local w = worker()
        local mark = s:mark()
        -- In a later component, where a source would otherwise be asked.
        local mid = lcs.open_key(nil, w, -1, "Machine\\Software\\bad\xffname",
            lcs.RIGHT.KEY_READ)
        t:assert_eq(mid.errno, sys.E.INVAL, "invalid UTF-8 in a component: "
            .. sys.errname(mid.errno or 0))
        -- And in the hive name, where routing would otherwise happen.
        local hive = lcs.open_key(nil, w, -1, "\xffMachine\\Software", lcs.RIGHT.KEY_READ)
        t:assert_eq(hive.errno, sys.E.INVAL, "and in the hive name: "
            .. sys.errname(hive.errno or 0))
        t:assert_eq(#s.log - mark + 1, 0, "neither reached a source")
        done(w)
    end)

test("null bytes are rejected in every string",
    { spec = "PKM *name.utf8.null-bytes-rejected-in-every-string" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST)
        -- Length-delimited strings can carry one, and are refused.
        local vname = lcs.set_value(nil, w, fd, "has\0null", lcs.TYPE.DWORD, lcs.dword(1))
        t:assert_eq(vname.errno, sys.E.INVAL, "a value name: " .. sys.errname(vname.errno or 0))
        local lname = lcs.set_value(nil, w, fd, "Ok", lcs.TYPE.DWORD, lcs.dword(1),
            { layer = "bad\0layer" })
        t:assert_eq(lname.errno, sys.E.INVAL, "a layer name: " .. sys.errname(lname.errno or 0))
        sys.close(w, fd)
        done(w)
    end)

-- KNOWN BUG. §5.2.8: "Null bytes are rejected in all of them", and
-- §5.5.5 makes an invalid string EINVAL. REG_IOC_SET_VALUE does reject
-- a layer name containing a null byte that way, but reg_create_key does
-- not: it carries the bytes through to layer resolution and answers
-- ENOENT, the errno for a layer that is not in the table — so a null
-- byte reaches layer lookup instead of being refused as an invalid
-- string.
test("a null byte in reg_create_key's layer name is rejected as an invalid string",
    { spec = "PKM *name.utf8.null-bytes-rejected-in-every-string",
      tags = { "known-bug" } }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST)
        local cname = lcs.create_key(s, w, {
            parent_fd = fd, path = "NulLayerChild", layer = "bad\0layer",
        })
        t:assert_eq(cname.errno, sys.E.INVAL,
            "a layer name carrying a null byte is invalid: "
            .. sys.errname(cname.errno or 0))
        sys.close(w, fd)
        done(w)
    end)

-- Lengths ---------------------------------------------------------------

test("lengths are counted in UTF-8 bytes, not characters",
    { spec = "PKM *name.length.measured-in-utf8-bytes" }, function(t)
        local s = fixture()
        local w = worker()
        -- 128 two-byte codepoints: 128 characters, 256 bytes.
        local too_long = string.rep("\u{00E9}", 128)
        t:assert_eq(#too_long, 256, "256 bytes")
        local r = lcs.open_key(nil, w, -1, "Machine\\" .. too_long, lcs.RIGHT.KEY_READ)
        t:assert_eq(r.errno, sys.E.NAMETOOLONG,
            "128 characters is over the limit because it is 256 bytes: "
            .. sys.errname(r.errno or 0))
        -- 127 of them plus one ASCII byte: 128 characters, 255 bytes.
        local ok_name = string.rep("\u{00E9}", 127) .. "z"
        t:assert_eq(#ok_name, 255, "255 bytes")
        local ok = lcs.open_key(s, w, -1, "Machine\\" .. ok_name, lcs.RIGHT.KEY_READ)
        t:assert_eq(ok.errno, sys.E.NOENT,
            "while the same character count in 255 bytes is merely absent: "
            .. sys.errname(ok.errno or 0))
        done(w)
    end)

test("MaxPathComponentLength bounds one component, one value name and one layer name",
    { spec = "PKM *name.length.max-path-component-length-bounds-a-component" }, function(t)
        local s = fixture()
        local w = worker()
        local at_limit, over = string.rep("c", 255), string.rep("c", 256)
        local ok = lcs.open_key(s, w, -1, "Machine\\" .. at_limit, lcs.RIGHT.KEY_READ)
        t:assert_eq(ok.errno, sys.E.NOENT, "255 bytes is a legal component")
        local bad = lcs.open_key(nil, w, -1, "Machine\\" .. over, lcs.RIGHT.KEY_READ)
        t:assert_eq(bad.errno, sys.E.NAMETOOLONG, "256 is not: " .. sys.errname(bad.errno or 0))

        local fd = open(t, w, TEST)
        t:assert_eq(lcs.set_value(s, w, fd, at_limit, lcs.TYPE.DWORD, lcs.dword(1)).ret, 0,
            "a 255-byte value name is legal")
        local vbad = lcs.set_value(nil, w, fd, over, lcs.TYPE.DWORD, lcs.dword(1))
        t:assert_eq(vbad.errno, sys.E.NAMETOOLONG,
            "a 256-byte one is not: " .. sys.errname(vbad.errno or 0))
        local lbad = lcs.set_value(nil, w, fd, "Ok", lcs.TYPE.DWORD, lcs.dword(1),
            { layer = over })
        t:assert(lbad.ret < 0, "and neither is a 256-byte layer name")
        lcs.delete_value(s, w, fd, at_limit)
        sys.close(w, fd)
        done(w)
    end)

test("MaxTotalPathLength bounds a whole path",
    { spec = "PKM *name.length.max-total-path-length-bounds-a-path" }, function(t)
        local s = fixture()
        local w = worker()
        local at_limit = path_of_length("Machine", 16383)
        local over = path_of_length("Machine", 16384)
        t:assert_eq(#at_limit, 16383, "exactly the limit")
        t:assert_eq(#over, 16384, "one byte over")
        local ok = lcs.open_key(s, w, -1, at_limit, lcs.RIGHT.KEY_READ)
        t:assert_eq(ok.errno, sys.E.NOENT,
            "a path of exactly MaxTotalPathLength is accepted and merely absent: "
            .. sys.errname(ok.errno or 0))
        local bad = lcs.open_key(nil, w, -1, over, lcs.RIGHT.KEY_READ)
        t:assert_eq(bad.errno, sys.E.NAMETOOLONG,
            "one byte more is ENAMETOOLONG: " .. sys.errname(bad.errno or 0))
        done(w)
    end)

test("MaxKeyDepth bounds nesting",
    { spec = "PKM *name.length.max-key-depth-bounds-nesting" }, function(t)
        local s = fixture()
        local w = worker()
        local function nested(n)
            local parts = { "Machine" }
            for i = 1, n do parts[#parts + 1] = "d" end
            return table.concat(parts, "\\")
        end
        local shallow = lcs.open_key(s, w, -1, nested(400), lcs.RIGHT.KEY_READ)
        t:assert_eq(shallow.errno, sys.E.NOENT,
            "400 components are within MaxKeyDepth and merely absent: "
            .. sys.errname(shallow.errno or 0))
        local deep = lcs.open_key(nil, w, -1, nested(600), lcs.RIGHT.KEY_READ)
        t:assert_eq(deep.errno, sys.E.INVAL,
            "600 exceed the default of 512: " .. sys.errname(deep.errno or 0))
        done(w)
    end)

test("a syscall path's terminator is not part of its length",
    { spec = "PKM *name.length.syscall-path-terminator-is-not-counted" }, function(t)
        local s = fixture()
        local w = worker()
        -- The path handed to the syscall is 16384 bytes on the wire —
        -- MaxTotalPathLength plus its NUL — and is accepted.
        local at_limit = path_of_length("Machine", 16383)
        t:assert_eq(#sys.cstr(at_limit), 16384, "16384 bytes reach the kernel")
        local ok = lcs.open_key(s, w, -1, at_limit, lcs.RIGHT.KEY_READ)
        t:assert_eq(ok.errno, sys.E.NOENT,
            "the terminator is stripped before anything is measured: "
            .. sys.errname(ok.errno or 0))
        -- And a shorter path is not shortened further by it.
        local short = lcs.open_key(s, w, -1, "Machine\\" .. string.rep("c", 255),
            lcs.RIGHT.KEY_READ)
        t:assert_eq(short.errno, sys.E.NOENT,
            "a 255-byte final component is legal with its terminator: "
            .. sys.errname(short.errno or 0))
        done(w)
    end)

test("ioctl and RSI strings are length-delimited and need no terminator",
    { spec = "PKM *name.length.ioctl-and-rsi-strings-are-length-delimited" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST)
        local name = string.rep("n", 255)
        local sv = lcs.set_value(s, w, fd, name, lcs.TYPE.DWORD, lcs.dword(1))
        t:assert_eq(sv.ret, 0,
            "255 bytes with no terminator is a complete value name: "
            .. sys.errname(sv.errno or 0))
        local q = lcs.query_value(s, w, fd, name)
        t:assert_eq(q.ret, 0, "and reads back by the same 255 bytes")
        -- A terminator inside the length is a null byte, and invalid.
        local terminated = lcs.set_value(nil, w, fd, "Name\0", lcs.TYPE.DWORD, lcs.dword(1))
        t:assert_eq(terminated.errno, sys.E.INVAL,
            "a terminator byte counted in the length is a null byte: "
            .. sys.errname(terminated.errno or 0))
        lcs.delete_value(s, w, fd, name)
        sys.close(w, fd)
        done(w)
    end)

-- Separators --------------------------------------------------------------

test("forward slash is a separator wherever a separator is recognised",
    { spec = "PKM *name.separator.forward-slash-is-a-separator" }, function(t)
        local s = fixture()
        local w = worker()
        for _, path in ipairs({ "Machine/Software/Test",
                                "Machine/Software\\Test",
                                "Machine\\Software/Test" }) do
            local r = lcs.open_key(s, w, -1, path, lcs.RIGHT.KEY_READ)
            t:assert(r.ret >= 0, path .. " reaches the same key: "
                .. sys.errname(r.errno or 0))
            if r.ret >= 0 then
                local info = lcs.query_key_info(s, w, r.ret)
                t:assert_eq(info.name, "Test", "and it is that key")
                sys.close(w, r.ret)
            end
        end
        done(w)
    end)

test("there is no string-rewriting step: normalisation is how paths are split",
    { spec = "PKM *name.separator.no-string-rewriting-step" }, function(t)
        local s = fixture()
        local w = worker()
        local function components(path)
            local mark = s:mark()
            local r = lcs.open_key(s, w, -1, path, lcs.RIGHT.KEY_READ)
            local names = {}
            for _, req in ipairs(s:served(lcs.OP.LOOKUP, mark)) do
                names[#names + 1] = string.unpack("<s4", req.payload, 17)
            end
            if r.ret >= 0 then sys.close(w, r.ret) end
            return table.concat(names, "|")
        end
        local back = components("Machine\\Software\\Test")
        local fwd = components("Machine/Software/Test")
        t:assert_eq(fwd, back, "both spellings produce the same component sequence")
        t:assert_eq(back, "Software|Test", "each looked up as one component")
        for _, name in ipairs({ "Software", "Test" }) do
            t:assert(not name:find("[\\/]"), "no materialised component holds a separator")
        end
        done(w)
    end)

-- Case folding ---------------------------------------------------------------

test("comparison is case-insensitive and storage is case-preserving",
    { spec = "PKM *name.case.insensitive-comparison-preserving-storage" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\MIXEDCASE", lcs.RIGHT.KEY_READ)
        t:assert(fd >= 0, "a different spelling finds the key")
        sys.close(w, fd)
        local lower = open(t, w, TEST .. "\\mixedcase", lcs.RIGHT.KEY_READ)
        t:assert(lower >= 0, "and so does another")
        sys.close(w, lower)
        local parent = open(t, w, TEST, lcs.RIGHT.KEY_READ)
        local found
        for i = 0, 31 do
            local e = lcs.enum_subkeys(s, w, parent, i)
            if e.ret ~= 0 then break end
            if e.name == "MixedCase" then found = true end
        end
        t:assert(found, "and enumeration reports it as it was written")
        sys.close(w, parent)
        done(w)
    end)

test("folding is applied to codepoints, never to raw bytes",
    { spec = "PKM *name.case.folding-applied-to-codepoints-not-bytes" }, function(t)
        local s = fixture()
        local w = worker()
        -- U+03A3 and U+03C3 differ in both UTF-8 bytes; no byte-wise
        -- ASCII lowering relates them.
        t:assert(SIGMA_UPPER:byte(1) > 0x7F and SIGMA_LOWER:byte(1) > 0x7F,
            "both spellings are multi-byte")
        t:assert(SIGMA_UPPER:lower() == SIGMA_UPPER and SIGMA_UPPER ~= SIGMA_LOWER,
            "and byte-wise ASCII lowering does not relate them")
        local which = which_hive(t, s, w, SIGMA_LOWER)
        t:assert_eq(which, lcs.sz(SIGMA_UPPER),
            "the lowercase spelling routes to the hive registered uppercase")
        done(w)
    end)

test("Simple Case Folding: the C and S entries only",
    { spec = "PKM *name.case.simple-case-folding-c-and-s-entries-only" }, function(t)
        local s = fixture()
        local w = worker()
        -- A C entry: U+1E9E folds to U+00DF.
        t:assert_eq(which_hive(t, s, w, SHARP_SMALL), lcs.sz(SHARP_CAPITAL),
            "a C mapping folds")
        -- An F entry, excluded: U+00DF does not become `ss`, so `straße`
        -- and `strasse` are two names — and both registered.
        t:assert_eq(which_hive(t, s, w, "stra\u{00DF}e"), lcs.sz("stra\u{00DF}e"),
            "the full mapping is excluded: straße is its own name")
        t:assert_eq(which_hive(t, s, w, "strasse"), lcs.sz("strasse"),
            "and strasse is another")
        -- A T entry, excluded: U+0130 does not fold to `i`.
        local _, errno = which_hive(t, s, w, "idot")
        t:assert_eq(errno, sys.E.NOENT,
            "the Turkic mapping is excluded, so İdot is not idot: "
            .. sys.errname(errno or 0))
        t:assert_eq(which_hive(t, s, w, DOTTED_I), lcs.sz(DOTTED_I),
            "while its own spelling routes")
        done(w)
    end)

test("Unicode normalisation is not performed",
    { spec = "PKM *name.case.no-unicode-normalisation" }, function(t)
        local s = fixture()
        local w = worker()
        -- The NFC and NFD forms of the same visual character are two
        -- names: both registered, and each routes to its own hive.
        t:assert(CAFE_NFC ~= CAFE_NFD, "the two forms differ byte for byte")
        t:assert_eq(which_hive(t, s, w, CAFE_NFC), lcs.sz(CAFE_NFC), "NFC routes to its own")
        t:assert_eq(which_hive(t, s, w, CAFE_NFD), lcs.sz(CAFE_NFD), "NFD to its own")
        done(w)
    end)

test("the Unicode version is pinned at 16.0",
    { spec = "PKM *name.case.unicode-version-pinned-at-16-0" }, function(t)
        local s = fixture()
        local w = worker()
        -- Garay (U+10D50..U+10D65 → U+10D70..) was added to
        -- CaseFolding.txt in Unicode 16.0. A table built from an earlier
        -- version has no mapping for it, and the two spellings would be
        -- two names.
        t:assert_eq(which_hive(t, s, w, GARAY_LOWER), lcs.sz(GARAY_UPPER),
            "a mapping that exists only from Unicode 16.0 folds")
        done(w)
    end)

test("identity is the folded name: a duplicate is a folded-equal duplicate",
    { spec = "PKM *name.case.identity-is-the-folded-name" }, function(t)
        local s = fixture()
        local w = worker()
        -- A hive route's identity includes its folded name, so a second
        -- source cannot take the same name spelled differently.
        local rival = lcs.source(vm, { hives = { { name = SIGMA_LOWER } } })
        t:assert(not rival:register(),
            "σigma and Σigma are one route, not two")
        t:assert_eq(rival.errno, sys.E.EXIST, "the collision is EEXIST: "
            .. sys.errname(rival.errno or 0))
        rival:close()

        -- And a layer's identity is its folded name: RoleA and rolea are
        -- one layer.
        local layer_fd = assert(lcs.create_layer(s, w, "RoleA", { precedence = 5 }))
        sys.close(w, layer_fd)
        local fd = open(t, w, TEST)
        t:assert_eq(lcs.set_value(s, w, fd, "Role", lcs.TYPE.SZ, lcs.sz("via rolea"),
            { layer = "rolea" }).ret, 0, "a write naming `rolea` resolves the layer")
        local q = lcs.query_value(s, w, fd, "Role")
        t:assert_eq(q.ret, 0, "and reads back: " .. sys.errname(q.errno or 0))
        t:assert_eq(q.layer, "RoleA",
            "reported under the spelling the layer was created with")
        lcs.delete_value(s, w, fd, "Role", { layer = "RoleA" })
        sys.close(w, fd)
        done(w)
    end)

test("two comparisons in the kernel are ASCII-only rather than folded",
    { spec = "PKM *name.case.two-comparisons-are-ascii-only" }, function(t)
        local w = worker()
        -- KACS's duplicate check when parsing private layer names into a
        -- token compares ASCII case only. Two names that differ only in
        -- ASCII case are caught ...
        local ascii, ascii_errno = token.mint(w, {
            lcs_credentials = lcs.lcs_credentials({}, { "RoleA", "rolea" }),
        })
        t:assert(ascii == nil, "an ASCII-case duplicate is rejected")
        t:assert_eq(ascii_errno, sys.E.INVAL, "with EINVAL: " .. sys.errname(ascii_errno or 0))

        -- ... while two that are folded-equal beyond ASCII are not, so
        -- the token carries one layer under two names.
        local folded = token.mint(w, {
            lcs_credentials = lcs.lcs_credentials({}, { "\u{03A3}", "\u{03C3}" }),
        })
        t:assert(folded ~= nil,
            "a folded-equal duplicate outside ASCII is not caught by that check")
        if folded then sys.close(w, folded) end
        done(w)
    end)
