-- PKM §5.2.3 Keys — what a key carries, what identifies it, the
-- volatile containment rule, and how a name component may be spelled.
--
-- Identity is the interesting half: a GUID is never visible to a
-- caller, so every claim about one is observed on the RSI wire, where
-- LCS pushes the GUID it minted to the source.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")
local access = require("helpers.access")
local kacs = require("helpers.kacs")

local vm = provium:vm("v", "kernel-only"):boot()

local TEST = "Machine\\Software\\Test"
local INHERIT_SID = kacs.SID.AUTHENTICATED_USERS

local src, test_key, layer_dual_base, layer_dual_policy, wrong_name_key
local function fixture()
    if src then return src end
    local s = lcs.source(vm)
    s:seed_layer("Policy", { precedence = 10 })
    test_key = s:key(TEST)

    -- A parent whose descriptor carries a container-inheritable ACE for
    -- a distinctive SID, so a child created under it can be seen to
    -- have had its descriptor computed rather than defaulted.
    s:key(TEST .. "\\Inheriting", { sd = lcs.permissive_sd({
        access.ace(access.ACE.ALLOWED, lcs.RIGHT.KEY_READ, INHERIT_SID,
            access.ACE_FLAG.CONTAINER_INHERIT),
    }) })

    -- A key whose *record* name disagrees with the path entry naming it.
    wrong_name_key = s:key(TEST .. "\\Authoritative")
    s.store.keys[wrong_name_key].name = "NotTheName"

    -- The same path in two layers: two key objects, each with its own
    -- properties. The Policy layer's is volatile; the base one is not.
    layer_dual_base = s:key(TEST .. "\\Dual")
    layer_dual_policy = lcs.seed_key_in_layer(s, test_key, "Dual", "Policy",
        { volatile = true })

    -- A volatile parent, for the containment rule.
    s:key(TEST .. "\\Vol", { volatile = true })

    assert(s:register())
    s:pump()
    src = s
    return s
end

local function worker() return vm:spawn_worker() end
local function done(w) w:kill(); w:join() end

--- Open `path` for KEY_ALL_ACCESS, asserting it worked.
local function open(t, w, path, access_mask)
    local r = lcs.open_key(src, w, -1, path, access_mask or lcs.KEY_ALL_ACCESS)
    t:assert(r.ret >= 0, "open " .. path .. ": " .. sys.errname(r.errno or 0))
    return r.ret
end

-- Fields --------------------------------------------------------------

test("a key record's own name is informational; the path entry is authoritative",
    { spec = "PKM *key.field.name-is-informational" }, function(t)
        local s = fixture()
        local w = worker()
        -- The source's key record says `NotTheName`; the path entry that
        -- reaches it says `Authoritative`.
        t:assert_eq(s.store.keys[wrong_name_key].name, "NotTheName",
            "the source's key record carries a different name")
        local fd = open(t, w, TEST .. "\\Authoritative")
        local info = lcs.query_key_info(s, w, fd)
        t:assert_eq(info.ret, 0, "key info: " .. sys.errname(info.errno or 0))
        t:assert_eq(info.name, "Authoritative",
            "the name a caller sees is the path entry's, not the key record's")
        sys.close(w, fd)
        done(w)
    end)

test("a hive root has a nil parent GUID; every other key names its parent",
    { spec = "PKM *key.field.parent-guid-nil-for-hive-root" }, function(t)
        local s = fixture()
        local root = s.hives[1].root
        t:assert_eq(s.store.keys[root].parent, lcs.NULL_GUID,
            "the hive root's key record carries a nil parent GUID")
        local w = worker()
        -- LCS serves the root as an ordinary key on that basis.
        local fd = open(t, w, "Machine", lcs.RIGHT.KEY_READ)
        local info = lcs.query_key_info(s, w, fd)
        t:assert_eq(info.ret, 0, "the root answers key info: " .. sys.errname(info.errno or 0))
        sys.close(w, fd)

        -- A key created under it is pushed with that root as its parent.
        local parent = open(t, w, "Machine\\Software")
        local mark = s:mark()
        local c = lcs.create_key(s, w, { parent_fd = parent, path = "ParentedChild" })
        t:assert(c.ret >= 0, "create: " .. sys.errname(c.errno or 0))
        local created = s:served(lcs.OP.CREATE_KEY, mark)
        t:assert_eq(#created, 1, "one RSI_CREATE_KEY")
        local at = 17
        local _, next_at = string.unpack("<s4", created[1].payload, at)
        t:assert_eq(created[1].payload:sub(next_at, next_at + 15), s:lookup("Machine\\Software"),
            "a non-root key record carries its parent's GUID, not nil")
        sys.close(w, c.ret); sys.close(w, parent)
        done(w)
    end)

test("a new key's Security Descriptor is computed from its parent's",
    { spec = "PKM *key.field.security-descriptor-computed-from-parent" }, function(t)
        local s = fixture()
        local w = worker()
        local parent = open(t, w, TEST .. "\\Inheriting")
        local c = lcs.create_key(s, w, { parent_fd = parent, path = "Inherited" })
        t:assert(c.ret >= 0, "create: " .. sys.errname(c.errno or 0))
        local g = lcs.get_security(s, w, c.ret, lcs.SI.OWNER | lcs.SI.GROUP | lcs.SI.DACL)
        t:assert_eq(g.ret, 0, "get security: " .. sys.errname(g.errno or 0))
        local sd = access.parse_sd(g.sd)
        local found = false
        for _, ace in ipairs(sd.dacl and sd.dacl.aces or {}) do
            if ace.sid == INHERIT_SID then found = true end
        end
        t:assert(found,
            "the parent's container-inheritable ACE reached the child's descriptor")
        sys.close(w, c.ret); sys.close(w, parent)
        done(w)
    end)

test("the last write time updates when a value is written and when the descriptor changes",
    { spec = "PKM *key.field.last-write-time-updates" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\Inheriting")
        local before = lcs.query_key_info(s, w, fd)
        t:assert_eq(before.ret, 0, "key info: " .. sys.errname(before.errno or 0))

        local sv = lcs.set_value(s, w, fd, "Stamp", lcs.TYPE.DWORD, lcs.dword(1))
        t:assert_eq(sv.ret, 0, "set value: " .. sys.errname(sv.errno or 0))
        local after_write = lcs.query_key_info(s, w, fd)
        t:assert(after_write.last_write_time > before.last_write_time,
            "writing a value updated the last write time")

        local dv = lcs.delete_value(s, w, fd, "Stamp")
        t:assert_eq(dv.ret, 0, "delete value: " .. sys.errname(dv.errno or 0))
        local after_delete = lcs.query_key_info(s, w, fd)
        t:assert(after_delete.last_write_time >= after_write.last_write_time,
            "and so did deleting one")

        local ss = lcs.set_security(s, w, fd, lcs.SI.DACL, lcs.permissive_sd())
        t:assert_eq(ss.ret, 0, "set security: " .. sys.errname(ss.errno or 0))
        local after_sd = lcs.query_key_info(s, w, fd)
        t:assert(after_sd.last_write_time >= after_delete.last_write_time,
            "and so did changing the descriptor")
        sys.close(w, fd)
        done(w)
    end)

test("no key property is layer-qualified: a layer gets its own key object",
    { spec = "PKM *key.no-property-is-layer-qualified" }, function(t)
        local s = fixture()
        t:assert(layer_dual_base ~= layer_dual_policy,
            "the two layers name two distinct key objects at one path")
        t:assert_eq(s.store.keys[layer_dual_base].volatile, false,
            "the base layer's object is not volatile")
        t:assert_eq(s.store.keys[layer_dual_policy].volatile, true,
            "the Policy layer's object is")
        local w = worker()
        local fd = open(t, w, TEST .. "\\Dual")
        local info = lcs.query_key_info(s, w, fd)
        t:assert_eq(info.ret, 0, "key info: " .. sys.errname(info.errno or 0))
        t:assert_eq(info.volatile, true,
            "the winning layer's key object supplies the property whole — "
            .. "the flag was never qualified by a layer")
        sys.close(w, fd)
        done(w)
    end)

-- Identity ------------------------------------------------------------

test("identity is the GUID, not the path: two keys at one path over time differ",
    { spec = "PKM *key.identity.is-guid-not-path" }, function(t)
        local s = fixture()
        local w = worker()
        local parent = open(t, w, TEST)
        local m1 = s:mark()
        local a = lcs.create_key(s, w, { parent_fd = parent, path = "Reborn" })
        t:assert_eq(a.disposition, lcs.CREATED_NEW, "created new")
        local first = lcs.created_guid(s, m1)
        local d = lcs.delete_key(s, w, a.ret)
        t:assert_eq(d.ret, 0, "delete: " .. sys.errname(d.errno or 0))
        sys.close(w, a.ret)

        local m2 = s:mark()
        local b = lcs.create_key(s, w, { parent_fd = parent, path = "Reborn" })
        t:assert_eq(b.disposition, lcs.CREATED_NEW, "created new again")
        local second = lcs.created_guid(s, m2)
        t:assert(first and second, "both creations pushed a GUID to the source")
        t:assert(first ~= second,
            "the same path at two times is two objects with different GUIDs")
        sys.close(w, b.ret); sys.close(w, parent)
        done(w)
    end)

test("GUIDs are assigned by LCS and pushed to the source, never chosen by it",
    { spec = "PKM *key.identity.guid-assigned-by-lcs-not-source" }, function(t)
        local s = fixture()
        local w = worker()
        local parent = open(t, w, TEST)
        local mark = s:mark()
        local c = lcs.create_key(s, w, { parent_fd = parent, path = "Minted" })
        t:assert(c.ret >= 0, "create: " .. sys.errname(c.errno or 0))
        local entries = s:served(lcs.OP.CREATE_ENTRY, mark)
        local keys = s:served(lcs.OP.CREATE_KEY, mark)
        t:assert_eq(#entries, 1, "one RSI_CREATE_ENTRY")
        t:assert_eq(#keys, 1, "one RSI_CREATE_KEY")
        local guid = keys[1].payload:sub(1, 16)
        -- The same GUID arrives on both requests: the source was told,
        -- not asked. It never returned a GUID for this key.
        local at = 17
        local _, a2 = string.unpack("<s4", entries[1].payload, at)
        local _, a3 = string.unpack("<s4", entries[1].payload, a2)
        t:assert_eq(entries[1].payload:sub(a3, a3 + 15), guid,
            "the entry and the key record carry the GUID LCS minted")
        sys.close(w, c.ret); sys.close(w, parent)
        done(w)
    end)

test("the generator is the kernel's UUIDv4",
    { spec = "PKM *key.identity.guid-generator-is-uuidv4" }, function(t)
        local s = fixture()
        local w = worker()
        local parent = open(t, w, TEST)
        local seen = {}
        for i = 1, 4 do
            local mark = s:mark()
            local c = lcs.create_key(s, w, { parent_fd = parent, path = "Uuid" .. i })
            t:assert(c.ret >= 0, "create: " .. sys.errname(c.errno or 0))
            local guid = assert(lcs.created_guid(s, mark))
            t:assert_eq(guid:byte(7) >> 4, 4,
                "RFC 4122 version 4 in the version nibble")
            t:assert_eq(guid:byte(9) >> 6, 2,
                "RFC 4122 variant bits (10x) in the variant octet")
            t:assert(not seen[guid], "and random bytes elsewhere: no repeats")
            seen[guid] = true
            sys.close(w, c.ret)
        end
        sys.close(w, parent)
        done(w)
    end)

test("after the open the RSI uses the GUID directly",
    { spec = "PKM *key.identity.rsi-uses-guid-after-open" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST)
        local mark = s:mark()
        local sv = lcs.set_value(s, w, fd, "ByGuid", lcs.TYPE.DWORD, lcs.dword(7))
        t:assert_eq(sv.ret, 0, "set value: " .. sys.errname(sv.errno or 0))
        t:assert_eq(#s:served(lcs.OP.LOOKUP, mark), 0,
            "no path lookup after the open: the path was resolved once")
        t:assert_eq(#s:served(lcs.OP.SET_VALUE, mark, test_key), 1,
            "the write named the key by GUID")
        lcs.delete_value(s, w, fd, "ByGuid")
        sys.close(w, fd)
        done(w)
    end)

test("RSI_ALREADY_EXISTS on a freshly minted GUID is source inconsistency, not a race",
    { spec = "PKM *key.identity.create-key-already-exists-is-eio" }, function(t)
        local s = fixture()
        local w = worker()
        local parent = open(t, w, TEST)
        s:intercept(lcs.OP.CREATE_KEY, function() return lcs.STATUS.ALREADY_EXISTS, "" end)
        local c = lcs.create_key(s, w, { parent_fd = parent, path = "Inconsistent" })
        s:intercept(lcs.OP.CREATE_KEY, nil)
        t:assert(c.ret < 0, "the create fails")
        t:assert_eq(c.errno, sys.E.IO,
            "failing closed with EIO rather than retrying: " .. sys.errname(c.errno or 0))
        sys.close(w, parent)
        done(w)
    end)

test("EEXIST never reaches userspace from reg_create_key",
    { spec = "PKM *key.identity.no-eexist-from-reg-create-key" }, function(t)
        local s = fixture()
        local w = worker()
        local parent = open(t, w, TEST)
        -- A key that already exists is opened, not refused.
        local first = lcs.create_key(s, w, { parent_fd = parent, path = "Twice" })
        t:assert_eq(first.disposition, lcs.CREATED_NEW, "created new")
        local second = lcs.create_key(s, w, { parent_fd = parent, path = "Twice" })
        t:assert(second.ret >= 0, "the second create succeeds: " .. sys.errname(second.errno or 0))
        t:assert_eq(second.disposition, lcs.OPENED_EXISTING, "reporting REG_OPENED_EXISTING")

        -- And the one case that does fail — a source answering
        -- RSI_ALREADY_EXISTS for a GUID LCS just minted — is not retried
        -- as an open and does not surface EEXIST either.
        s:intercept(lcs.OP.CREATE_KEY, function() return lcs.STATUS.ALREADY_EXISTS, "" end)
        local third = lcs.create_key(s, w, { parent_fd = parent, path = "NeverEexist" })
        s:intercept(lcs.OP.CREATE_KEY, nil)
        t:assert(third.ret < 0, "it is never retried as an open")
        t:assert(third.errno ~= sys.E.EXIST,
            "and EEXIST never comes out of reg_create_key: " .. sys.errname(third.errno or 0))
        t:assert_eq(third.errno, sys.E.IO, "it is EIO: " .. sys.errname(third.errno or 0))
        sys.close(w, first.ret); sys.close(w, second.ret); sys.close(w, parent)
        done(w)
    end)

test("GUID freshness is checked against the keys LCS currently tracks, with a bounded retry",
    { spec = "PKM *key.identity.freshness-checked-against-tracked-keys",
      covered_by = "kunit:pkm_lcs_kunit_key",
      skip = "no guest can steer the kernel CSPRNG into producing a candidate that "
          .. "collides with a tracked key, and the retry is invisible once it "
          .. "succeeds; runs under pkm_lcs_kunit_key_guid_assignment_retries_bad_candidates "
          .. "and pkm_lcs_kunit_key_guid_assignment_exhaustion_fails_closed" },
    function(t) end)

test("there is no persistent retired-GUID catalogue",
    { spec = "PKM *key.identity.no-retired-guid-catalogue",
      covered_by = "kunit:pkm_lcs_kunit_key",
      skip = "the absence of a catalogue is a property of the code rather than an "
          .. "observable behaviour: a guest cannot ask whether a dropped GUID is "
          .. "remembered without steering the generator. The nearest evidence is "
          .. "that the freshness set passed to the allocator is the currently "
          .. "active key set, under pkm_lcs_kunit_key_guid_assignment_retries_bad_candidates" },
    function(t) end)

-- Volatile ------------------------------------------------------------

test("a non-volatile key may not be created under a volatile parent",
    { spec = "PKM *key.volatile.non-volatile-under-volatile-parent-is-einval" }, function(t)
        local s = fixture()
        local w = worker()
        local parent = open(t, w, TEST .. "\\Vol")
        local c = lcs.create_key(s, w, { parent_fd = parent, path = "Persistent" })
        t:assert(c.ret < 0, "a persistent child of a volatile parent is refused")
        t:assert_eq(c.errno, sys.E.INVAL, "with EINVAL: " .. sys.errname(c.errno or 0))
        sys.close(w, parent)
        done(w)
    end)

test("a volatile key under a persistent parent is ordinary",
    { spec = "PKM *key.volatile.volatile-under-persistent-parent-allowed" }, function(t)
        local s = fixture()
        local w = worker()
        local parent = open(t, w, TEST)
        local c = lcs.create_key(s, w, {
            parent_fd = parent, path = "Ephemeral", flags = lcs.OPTION_VOLATILE,
        })
        t:assert(c.ret >= 0, "the converse is allowed: " .. sys.errname(c.errno or 0))
        local info = lcs.query_key_info(s, w, c.ret)
        t:assert_eq(info.volatile, true, "and the key is volatile")
        -- A volatile child of a volatile key is allowed too.
        local nested = lcs.create_key(s, w, {
            parent_fd = c.ret, path = "AlsoEphemeral", flags = lcs.OPTION_VOLATILE,
        })
        t:assert(nested.ret >= 0, "as is a volatile child of a volatile parent: "
            .. sys.errname(nested.errno or 0))
        if nested.ret >= 0 then sys.close(w, nested.ret) end
        sys.close(w, c.ret); sys.close(w, parent)
        done(w)
    end)

test("volatile storage is the source's obligation; the kernel only forwards the flag",
    { spec = "PKM *key.volatile.storage-is-the-source-obligation" }, function(t)
        local s = fixture()
        local w = worker()
        local parent = open(t, w, TEST)
        local mark = s:mark()
        local c = lcs.create_key(s, w, {
            parent_fd = parent, path = "Forwarded", flags = lcs.OPTION_VOLATILE,
        })
        t:assert(c.ret >= 0, "create: " .. sys.errname(c.errno or 0))
        local keys = s:served(lcs.OP.CREATE_KEY, mark)
        t:assert_eq(#keys, 1, "one RSI_CREATE_KEY")
        -- guid, name, parent guid, sd, then the volatile byte.
        local at = 17
        local _, a2 = string.unpack("<s4", keys[1].payload, at)
        local a3 = a2 + 16
        local _, a4 = string.unpack("<s4", keys[1].payload, a3)
        t:assert_eq(keys[1].payload:byte(a4), 1,
            "the flag is forwarded to the source verbatim")
        -- This source has no non-persistent storage at all; it keeps the
        -- key in the same table as every other, and nothing complains.
        local info = lcs.query_key_info(s, w, c.ret)
        t:assert_eq(info.ret, 0, "the key works: " .. sys.errname(info.errno or 0))
        t:assert_eq(info.volatile, true, "and still reports volatile")
        sys.close(w, c.ret); sys.close(w, parent)
        done(w)
    end)

-- Naming --------------------------------------------------------------

test("three bytes are forbidden in a key name component",
    { spec = "PKM *key.name.three-forbidden-bytes" }, function(t)
        -- A component containing a separator cannot be spelled in a
        -- path, so the rule is observed where such a name can appear at
        -- all: on the wire, in what a source reports as a child name.
        for _, bad in ipairs({ "Ch\\ild", "Ch/ild", "Ch\0ild" }) do
            local s = lcs.source(vm, { hives = { { name = "Bad" .. #bad .. bad:byte(3) } } })
            local parent = s:key(s.hives[1].name .. "\\Parent")
            lcs.seed_key_in_layer(s, parent, bad, "base")
            assert(s:register())
            s:pump()
            local w = worker()
            local r = lcs.open_key(s, w, -1, s.hives[1].name .. "\\Parent", lcs.KEY_ALL_ACCESS)
            t:assert(r.ret >= 0, "the parent opens: " .. sys.errname(r.errno or 0))
            local e = lcs.enum_subkeys(s, w, r.ret, 0)
            t:assert(e.ret < 0, "a child name containing a forbidden byte is malformed")
            t:assert_eq(e.errno, sys.E.IO,
                "and the source is refused with EIO: " .. sys.errname(e.errno or 0))
            sys.close(w, r.ret)
            done(w)
            s:close()
        end
    end)

test("every other valid UTF-8 sequence is permitted in a key name",
    { spec = "PKM *key.name.any-other-utf8-permitted" }, function(t)
        local s = fixture()
        local w = worker()
        local parent = open(t, w, TEST)
        local name = "Ünïcödé 🙂 with spaces"
        local c = lcs.create_key(s, w, { parent_fd = parent, path = name })
        t:assert(c.ret >= 0, "spaces and arbitrary Unicode are permitted: "
            .. sys.errname(c.errno or 0))
        local info = lcs.query_key_info(s, w, c.ret)
        t:assert_eq(info.name, name, "and the name is preserved byte for byte")
        local again = lcs.open_key(s, w, -1, TEST .. "\\" .. name, lcs.RIGHT.KEY_READ)
        t:assert(again.ret >= 0, "and it opens by that name: " .. sys.errname(again.errno or 0))
        if again.ret >= 0 then sys.close(w, again.ret) end
        sys.close(w, c.ret); sys.close(w, parent)
        done(w)
    end)

test("empty components are forbidden",
    { spec = "PKM *key.name.empty-components-forbidden" }, function(t)
        local w = worker()
        for _, path in ipairs({ "Machine\\\\Software", "\\Machine\\Software",
                                "Machine//Software", "/Machine" }) do
            local r = lcs.open_key(nil, w, -1, path, lcs.RIGHT.KEY_READ)
            t:assert_eq(r.errno, sys.E.INVAL,
                "`" .. path .. "` has an empty component: " .. sys.errname(r.errno or 0))
        end
        done(w)
    end)

test("a trailing separator is invalid",
    { spec = "PKM *key.name.trailing-separator-invalid" }, function(t)
        local w = worker()
        for _, path in ipairs({ "Machine\\Software\\", "Machine/Software/", "Machine\\" }) do
            local r = lcs.open_key(nil, w, -1, path, lcs.RIGHT.KEY_READ)
            t:assert_eq(r.errno, sys.E.INVAL,
                "`" .. path .. "` ends in a separator: " .. sys.errname(r.errno or 0))
        end
        done(w)
    end)
