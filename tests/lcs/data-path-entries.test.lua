-- PKM §5.2.5 Path Entries — naming is per-layer while identity is not:
-- the two records a create produces, the order they go out in, hiding,
-- hide-and-replace, and the hive root that has no entry at all.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")

local vm = provium:vm("v", "kernel-only"):boot()

local TEST = "Machine\\Software\\Test"

local src, test_key, base_masked, policy_masked, tie_parent
local function fixture()
    if src then return src end
    local s = lcs.source(vm)
    s:key(lcs.LAYERS_PATH .. "\\base", { sd = lcs.permissive_sd() })
    s:seed_layer("Policy", { precedence = 10, enabled = true })
    s:seed_layer("Hider", { precedence = 20, enabled = true })
    -- Two layers at one precedence, so a tie is broken by sequence.
    s:seed_layer("TieLow", { precedence = 30, enabled = true })
    s:seed_layer("TieHigh", { precedence = 30, enabled = true })
    test_key = s:key(TEST)

    -- Hide-and-replace: the base key carries a value only it has, and
    -- the Policy layer puts its own key at the same path.
    base_masked = s:key(TEST .. "\\Masked")
    s:value(base_masked, "Whose", lcs.TYPE.SZ, lcs.sz("base"))
    policy_masked = lcs.seed_key_in_layer(s, test_key, "Masked", "Policy")
    s:value(policy_masked, "Whose", lcs.TYPE.SZ, lcs.sz("policy"), { layer = "Policy" })

    -- A key the Hider layer hides outright.
    s:key(TEST .. "\\Hidden")
    s:hide(test_key, "Hidden", "Hider")

    -- The sequence tiebreak: a GUID entry and a HIDDEN entry at one
    -- precedence. `Sequenced` is hidden by the later entry; `Surviving`
    -- is hidden first and then re-named, so the name wins.
    tie_parent = s:key(TEST .. "\\Tie")
    lcs.seed_key_in_layer(s, tie_parent, "Sequenced", "TieLow")
    s:hide(tie_parent, "Sequenced", "TieHigh")
    s:hide(tie_parent, "Surviving", "TieLow")
    lcs.seed_key_in_layer(s, tie_parent, "Surviving", "TieHigh")

    -- A GUID reachable through two parents, which no source may report.
    s:key(TEST .. "\\CanonA\\Real")
    s:key(TEST .. "\\CanonB")

    assert(s:register())
    s:pump()
    src = s
    return s
end

local function worker() return vm:spawn_worker() end
local function done(w) w:kill(); w:join() end

local function open(t, w, path, mask, flags)
    local r = lcs.open_key(src, w, -1, path, mask or lcs.KEY_ALL_ACCESS, flags)
    t:assert(r.ret >= 0, "open " .. path .. ": " .. sys.errname(r.errno or 0))
    return r.ret
end

--- The (name, layer, guid, seq) an RSI_CREATE_ENTRY or RSI_HIDE_ENTRY
--- request carries: parent GUID, child name, layer, then the GUID (on a
--- create) and the sequence.
local function entry_request(req, with_guid)
    local parent = req.payload:sub(1, 16)
    local name, at = string.unpack("<s4", req.payload, 17)
    local layer; layer, at = string.unpack("<s4", req.payload, at)
    local guid
    if with_guid then guid = req.payload:sub(at, at + 15); at = at + 16 end
    return { parent = parent, name = name, layer = layer, guid = guid,
             seq = string.unpack("<I8", req.payload, at) }
end

--- An RSI_LOOKUP response body carrying one entry verbatim, so a case
--- can hand LCS an entry no honest source would produce.
local function lookup_body(layer, hidden, guid, seq)
    return string.pack("<I4", 1) .. string.pack("<s4", layer)
        .. string.pack("<I1", hidden and 1 or 0) .. guid
        .. string.pack("<I8", seq) .. string.pack("<I4", 0)
end

-- The model ------------------------------------------------------------

test("existence and naming are layer-qualified while identity is not",
    { spec = "PKM *path-entry.existence-and-naming-are-layer-qualified" }, function(t)
        local s = fixture()
        local w = worker()
        -- One path, two layers, two path entries, two key objects: the
        -- directory entry is per-layer and the inode is not shared.
        t:assert(base_masked ~= policy_masked, "two distinct key objects at one path")
        t:assert(lcs.entry(s, test_key, "Masked", "base").guid, "a base entry names one")
        t:assert(lcs.entry(s, test_key, "Masked", "Policy").guid, "a Policy entry names the other")
        t:assert(lcs.entry(s, test_key, "Masked", "base").guid
            ~= lcs.entry(s, test_key, "Masked", "Policy").guid,
            "and the two entries at one (parent, name) name different identities")

        local fd = open(t, w, TEST .. "\\Masked", lcs.RIGHT.KEY_READ)
        local q = lcs.query_value(s, w, fd, "Whose")
        t:assert_eq(q.ret, 0, "query: " .. sys.errname(q.errno or 0))
        t:assert_eq(q.data, lcs.sz("policy"),
            "the higher-precedence layer's entry names the visible key")
        sys.close(w, fd)
        done(w)
    end)

test("the child name is one component, never a path",
    { spec = "PKM *path-entry.field.child-name-is-one-component" }, function(t)
        local s = fixture()
        local w = worker()
        local parent = open(t, w, TEST)
        local outer = lcs.create_key(s, w, { parent_fd = parent, path = "Two" })
        t:assert(outer.ret >= 0, "create parent: " .. sys.errname(outer.errno or 0))
        local mark = s:mark()
        local c = lcs.create_key(s, w, { parent_fd = parent, path = "Two\\Deep" })
        t:assert(c.ret >= 0, "create: " .. sys.errname(c.errno or 0))
        local entries = s:served(lcs.OP.CREATE_ENTRY, mark)
        t:assert_eq(#entries, 1, "only the missing component produced an entry")
        local e = entry_request(entries[1], true)
        t:assert_eq(e.name, "Deep",
            "the entry's child name is the last component alone, not the path")
        t:assert(not e.name:find("[\\/]"), "and carries no separator")
        t:assert_eq(e.parent, s:lookup(TEST .. "\\Two"),
            "with the parent named by GUID rather than by path")
        sys.close(w, c.ret); sys.close(w, outer.ret); sys.close(w, parent)
        done(w)
    end)

test("an entry's target is a GUID or HIDDEN",
    { spec = "PKM *path-entry.field.target-is-a-guid-or-hidden" }, function(t)
        local s = fixture()
        local w = worker()
        local parent = open(t, w, TEST)
        local mark = s:mark()
        local c = lcs.create_key(s, w, { parent_fd = parent, path = "Targeted" })
        t:assert(c.ret >= 0, "create: " .. sys.errname(c.errno or 0))
        local created = entry_request(s:served(lcs.OP.CREATE_ENTRY, mark)[1], true)
        t:assert(created.guid ~= lcs.NULL_GUID, "a create names a GUID")

        local hide_mark = s:mark()
        local h = lcs.hide_key(s, w, c.ret, { layer = "Hider" })
        t:assert_eq(h.ret, 0, "hide: " .. sys.errname(h.errno or 0))
        local hidden = s:served(lcs.OP.HIDE_ENTRY, hide_mark)
        t:assert_eq(#hidden, 1, "one RSI_HIDE_ENTRY")
        local he = entry_request(hidden[1], false)
        t:assert_eq(he.name, "Targeted", "for the same (parent, name)")
        t:assert_eq(he.layer, "Hider", "in the hiding layer")
        -- The HIDDEN entry carries no GUID at all: the request has none.
        t:assert_eq(lcs.entry(s, test_key, "Targeted", "Hider").guid, lcs.NULL_GUID,
            "and the stored entry's target is HIDDEN rather than a GUID")
        sys.close(w, c.ret); sys.close(w, parent)
        done(w)
    end)

test("a HIDDEN entry is a target type of 1 with an all-zero GUID",
    { spec = "PKM *path-entry.hidden.wire-form-is-type-1-and-zero-guid" }, function(t)
        local s = fixture()
        local w = worker()
        -- The fixture's `Hidden` entry is exactly that on the wire, and
        -- LCS reads it as hiding the key.
        local e = lcs.entry(s, test_key, "Hidden", "Hider")
        t:assert(e and e.hidden, "the source holds a hidden entry")
        t:assert_eq(e.guid, lcs.NULL_GUID, "with an all-zero GUID")
        local r = lcs.open_key(s, w, -1, TEST .. "\\Hidden", lcs.RIGHT.KEY_READ)
        t:assert_eq(r.errno, sys.E.NOENT,
            "and LCS reads the wire form as HIDDEN: " .. sys.errname(r.errno or 0))
        done(w)
    end)

test("a HIDDEN entry with a non-zero GUID is malformed source data",
    { spec = "PKM *path-entry.hidden.non-zero-guid-is-malformed" }, function(t)
        local s = fixture()
        local w = worker()
        local bogus = lcs.guid()
        s:intercept(lcs.OP.LOOKUP, function(self, req)
            local name = string.unpack("<s4", req.payload, 17)
            if name == "Malformed" then
                return lcs.STATUS.OK, lookup_body("base", true, bogus, 1)
            end
            return nil
        end)
        local r = lcs.open_key(s, w, -1, TEST .. "\\Malformed", lcs.RIGHT.KEY_READ)
        s:intercept(lcs.OP.LOOKUP, nil)
        t:assert(r.ret < 0, "a hidden entry carrying a GUID is refused")
        t:assert_eq(r.errno, sys.E.IO,
            "as malformed source data: " .. sys.errname(r.errno or 0))
        done(w)
    end)

-- Creating a key --------------------------------------------------------

test("creating a key produces a fresh GUID and two records",
    { spec = "PKM *path-entry.create.fresh-guid-and-two-records" }, function(t)
        local s = fixture()
        local w = worker()
        local parent = open(t, w, TEST)
        local mark = s:mark()
        local c = lcs.create_key(s, w, { parent_fd = parent, path = "TwoRecords" })
        t:assert(c.ret >= 0, "create: " .. sys.errname(c.errno or 0))
        local entries = s:served(lcs.OP.CREATE_ENTRY, mark)
        local keys = s:served(lcs.OP.CREATE_KEY, mark)
        t:assert_eq(#entries, 1, "one path entry")
        t:assert_eq(#keys, 1, "one key record")
        local e = entry_request(entries[1], true)
        t:assert_eq(e.parent, test_key, "the entry is (parent, name, layer)")
        t:assert_eq(e.name, "TwoRecords", "with the child name")
        t:assert_eq(e.layer, "base", "in the layer being written")
        t:assert_eq(e.guid, keys[1].payload:sub(1, 16),
            "and it points at the key record's GUID")
        t:assert(e.seq > 0, "with a new sequence number")
        sys.close(w, c.ret); sys.close(w, parent)
        done(w)
    end)

test("RSI_CREATE_ENTRY is sent first and RSI_CREATE_KEY second",
    { spec = "PKM *path-entry.create.entry-before-key" }, function(t)
        local s = fixture()
        local w = worker()
        local parent = open(t, w, TEST)
        local mark = s:mark()
        local c = lcs.create_key(s, w, { parent_fd = parent, path = "Ordered" })
        t:assert(c.ret >= 0, "create: " .. sys.errname(c.errno or 0))
        local entry_at, key_at
        for i = mark, #s.log do
            if s.log[i].op == lcs.OP.CREATE_ENTRY and not entry_at then entry_at = i end
            if s.log[i].op == lcs.OP.CREATE_KEY and not key_at then key_at = i end
        end
        t:assert(entry_at and key_at, "both requests were sent")
        t:assert(entry_at < key_at, "the entry goes out before the key record")
        sys.close(w, c.ret); sys.close(w, parent)
        done(w)
    end)

test("an entry that already exists is retried as an open",
    { spec = "PKM *path-entry.create.entry-already-exists-retries-as-open" }, function(t)
        local s = fixture()
        local w = worker()
        local parent = open(t, w, TEST)
        local first = lcs.create_key(s, w, { parent_fd = parent, path = "Raced" })
        t:assert_eq(first.disposition, lcs.CREATED_NEW, "the name exists after the first create")
        sys.close(w, first.ret)

        -- Another caller got there between the lookup and the create:
        -- the lookup answers "absent" once, and the entry creation then
        -- honestly reports RSI_ALREADY_EXISTS.
        local lied = false
        s:intercept(lcs.OP.LOOKUP, function(self, req)
            local name = string.unpack("<s4", req.payload, 17)
            if name == "Raced" and not lied then
                lied = true
                return lcs.STATUS.OK, string.pack("<I4I4", 0, 0)
            end
            return nil
        end)
        local second = lcs.create_key(s, w, { parent_fd = parent, path = "Raced" })
        s:intercept(lcs.OP.LOOKUP, nil)
        t:assert(lied, "the race was simulated")
        t:assert(second.ret >= 0, "the create succeeds: " .. sys.errname(second.errno or 0))
        t:assert_eq(second.disposition, lcs.OPENED_EXISTING,
            "reported as REG_OPENED_EXISTING rather than failing")
        sys.close(w, second.ret); sys.close(w, parent)
        done(w)
    end)

-- KNOWN BUG. §5.2.5: "If a different layer already has a key at that
-- path, the new layer gets its own distinct GUID. Each layer has its own
-- key object." reg_create_key resolves the path first (across every
-- enabled layer, via pkm_lcs_create_existing_*_for_token in
-- lcs/source_create.c) and returns REG_OPENED_EXISTING on the *other*
-- layer's key, so a layer can never author its own entry at a path some
-- lower layer already names — which is also what §5.2.5's hide-and-
-- replace pattern needs.
test("a different layer gets its own distinct GUID at the same path",
    { spec = "PKM *path-entry.create.other-layer-gets-a-distinct-guid",
      tags = { "known-bug" } }, function(t)
        local s = fixture()
        local w = worker()
        local parent = open(t, w, TEST)
        local m1 = s:mark()
        local a = lcs.create_key(s, w, { parent_fd = parent, path = "PerLayer" })
        t:assert(a.ret >= 0, "base create: " .. sys.errname(a.errno or 0))
        local base_guid = assert(lcs.created_guid(s, m1))
        sys.close(w, a.ret)

        local m2 = s:mark()
        local b = lcs.create_key(s, w, {
            parent_fd = parent, path = "PerLayer", layer = "Hider",
        })
        t:assert(b.ret >= 0, "layer create: " .. sys.errname(b.errno or 0))
        t:assert_eq(b.disposition, lcs.CREATED_NEW,
            "the layer creates rather than opening the base key")
        local layer_guid = assert(lcs.created_guid(s, m2))
        t:assert(layer_guid ~= base_guid, "each layer has its own key object")
        t:assert_eq(lcs.entry(s, test_key, "PerLayer", "base").guid, base_guid,
            "the base entry still points at the base GUID")
        t:assert_eq(lcs.entry(s, test_key, "PerLayer", "Hider").guid, layer_guid,
            "and the layer's entry at its own")
        sys.close(w, b.ret); sys.close(w, parent)
        done(w)
    end)

test("no operation creates a path entry pointing at an existing GUID",
    { spec = "PKM *path-entry.create.never-points-at-an-existing-guid" }, function(t)
        local s = fixture()
        local w = worker()
        local parent = open(t, w, TEST)
        local mark = s:mark()
        for i = 1, 3 do
            local c = lcs.create_key(s, w, { parent_fd = parent, path = "Fresh" .. i })
            t:assert(c.ret >= 0, "create: " .. sys.errname(c.errno or 0))
            sys.close(w, c.ret)
        end
        -- And re-creating an existing name opens rather than making a
        -- second entry for the same GUID.
        local reopen = lcs.create_key(s, w, { parent_fd = parent, path = "Fresh1" })
        t:assert_eq(reopen.disposition, lcs.OPENED_EXISTING, "the fourth create opens")
        sys.close(w, reopen.ret)

        local seen = {}
        for _, req in ipairs(s:served(lcs.OP.CREATE_ENTRY, mark)) do
            local e = entry_request(req, true)
            t:assert(not seen[e.guid],
                "every entry created names a GUID no earlier entry named")
            seen[e.guid] = true
        end
        sys.close(w, parent)
        done(w)
    end)

test("no API exposes GUID sharing: the namespace is a tree, not a graph",
    { spec = "PKM *path-entry.no-hard-links.no-api-exposes-guid-sharing" }, function(t)
        local s = fixture()
        local w = worker()
        local parent = open(t, w, TEST)
        local a = lcs.create_key(s, w, { parent_fd = parent, path = "TreeA" })
        local b = lcs.create_key(s, w, { parent_fd = parent, path = "TreeB" })
        t:assert(a.ret >= 0 and b.ret >= 0, "two keys")
        -- Every non-hidden entry the source holds names a GUID no other
        -- entry names: nothing in the interface can produce a second one.
        local owners = {}
        for parent_guid, per in pairs(s.store.entries) do
            for name, slot in pairs(per) do
                for _, e in pairs(slot.by_layer) do
                    if not e.hidden then
                        local key = e.guid
                        t:assert(owners[key] == nil,
                            "GUID named twice: " .. tostring(owners[key]) .. " and "
                            .. slot.name)
                        owners[key] = slot.name
                    end
                end
            end
        end
        sys.close(w, a.ret); sys.close(w, b.ret); sys.close(w, parent)
        done(w)
    end)

-- KNOWN BUG. §5.2.5: "Every key has exactly one canonical parent and
-- name, and LCS validates that a source is not reporting otherwise."
-- lcs-core has the validator — validate_key_canonical_path_locations in
-- crates/lcs-core/src/key.rs — but nothing in pkm/lcs calls it, so a
-- source that names one GUID under two parents is served: both paths
-- open, and REG_IOC_QUERY_KEY_INFO answers on both.
test("LCS validates that a source reports one canonical parent and name",
    { spec = "PKM *path-entry.no-hard-links.one-canonical-parent-and-name",
      tags = { "known-bug" } }, function(t)
        local s = fixture()
        local w = worker()
        -- `CanonB\Real` is made to point at the key whose record says its
        -- parent is `CanonA`: one GUID, two canonical locations.
        local real = s:lookup(TEST .. "\\CanonA\\Real")
        local canon_b = s:lookup(TEST .. "\\CanonB")
        s:intercept(lcs.OP.LOOKUP, function(self, req)
            local parent = req.payload:sub(1, 16)
            local name = string.unpack("<s4", req.payload, 17)
            if parent == canon_b and name == "Real" then
                return lcs.STATUS.OK,
                    lookup_body("base", false, real, 1)
                    :sub(1, -5) .. string.pack("<I4", 1)
                    .. real .. string.pack("<s4", s.store.keys[real].sd)
                    .. string.pack("<I1I1I8", 0, 0, 0)
            end
            return nil
        end)
        local r = lcs.open_key(s, w, -1, TEST .. "\\CanonB\\Real", lcs.RIGHT.KEY_READ)
        local info
        if r.ret >= 0 then info = lcs.query_key_info(s, w, r.ret) end
        s:intercept(lcs.OP.LOOKUP, nil)
        t:assert(r.ret < 0 or (info and info.ret < 0),
            "a GUID reported at a second canonical location is refused")
        t:assert_eq(r.ret < 0 and r.errno or info.errno, sys.E.IO,
            "as malformed source data: "
            .. sys.errname((r.ret < 0 and r.errno or info.errno) or 0))
        if r.ret >= 0 then sys.close(w, r.ret) end
        done(w)
    end)

-- Hiding ------------------------------------------------------------------

test("a HIDDEN entry makes a key invisible regardless of lower layers",
    { spec = "PKM *path-entry.hiding.hidden-entry-makes-a-key-invisible" }, function(t)
        local s = fixture()
        local w = worker()
        local parent = open(t, w, TEST)
        local c = lcs.create_key(s, w, { parent_fd = parent, path = "ToHide" })
        t:assert(c.ret >= 0, "create: " .. sys.errname(c.errno or 0))
        local before = lcs.open_key(s, w, -1, TEST .. "\\ToHide", lcs.RIGHT.KEY_READ)
        t:assert(before.ret >= 0, "visible to begin with")
        sys.close(w, before.ret)

        local h = lcs.hide_key(s, w, c.ret, { layer = "Hider" })
        t:assert_eq(h.ret, 0, "hide: " .. sys.errname(h.errno or 0))
        local after = lcs.open_key(s, w, -1, TEST .. "\\ToHide", lcs.RIGHT.KEY_READ)
        t:assert_eq(after.errno, sys.E.NOENT,
            "the higher-precedence HIDDEN entry hides the base key: "
            .. sys.errname(after.errno or 0))
        -- And it is gone from enumeration too.
        local names = {}
        for i = 0, 63 do
            local e = lcs.enum_subkeys(s, w, parent, i)
            if e.ret ~= 0 then break end
            names[e.name] = true
        end
        t:assert(not names["ToHide"], "and it is not enumerated")
        sys.close(w, c.ret); sys.close(w, parent)
        done(w)
    end)

test("removing the hiding layer restores the lower key",
    { spec = "PKM *path-entry.hiding.removing-the-layer-restores-the-lower-key" }, function(t)
        local s = fixture()
        local w = worker()
        local gone = lcs.open_key(s, w, -1, TEST .. "\\Hidden", lcs.RIGHT.KEY_READ)
        t:assert_eq(gone.errno, sys.E.NOENT, "hidden by the Hider layer")
        local layer_fd = open(t, w, lcs.LAYERS_PATH .. "\\Hider")
        t:assert_eq(lcs.delete_key(s, w, layer_fd).ret, 0, "delete the Hider layer")
        sys.close(w, layer_fd)
        local back = lcs.open_key(s, w, -1, TEST .. "\\Hidden", lcs.RIGHT.KEY_READ)
        t:assert(back.ret >= 0, "the lower key reappears: " .. sys.errname(back.errno or 0))
        sys.close(w, back.ret)
        done(w)
    end)

test("a HIDDEN entry carries a sequence number, so a tie resolves deterministically",
    { spec = "PKM *path-entry.hiding.hidden-entry-carries-a-sequence-number" }, function(t)
        local s = fixture()
        local w = worker()
        -- TieLow and TieHigh share a precedence; only the sequence
        -- separates them, and it was fixed when each entry was written.
        local named = lcs.entry(s, tie_parent, "Sequenced", "TieLow")
        local hidden = lcs.entry(s, tie_parent, "Sequenced", "TieHigh")
        t:assert(hidden.seq > named.seq, "the HIDDEN entry was written second")
        local r = lcs.open_key(s, w, -1, TEST .. "\\Tie\\Sequenced", lcs.RIGHT.KEY_READ)
        t:assert_eq(r.errno, sys.E.NOENT,
            "the higher sequence wins and the key is hidden: " .. sys.errname(r.errno or 0))

        local hidden_first = lcs.entry(s, tie_parent, "Surviving", "TieLow")
        local named_second = lcs.entry(s, tie_parent, "Surviving", "TieHigh")
        t:assert(named_second.seq > hidden_first.seq, "here the naming entry was written second")
        local ok = lcs.open_key(s, w, -1, TEST .. "\\Tie\\Surviving", lcs.RIGHT.KEY_READ)
        t:assert(ok.ret >= 0,
            "so it wins the tie and the key is visible: " .. sys.errname(ok.errno or 0))
        if ok.ret >= 0 then sys.close(w, ok.ret) end
        done(w)
    end)

-- Hide and replace ---------------------------------------------------------

test("a layer's own entry masks lower entries at the same path",
    { spec = "PKM *path-entry.hide-and-replace.layer-entry-masks-lower-entries" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\Masked", lcs.RIGHT.KEY_READ)
        local q = lcs.query_value(s, w, fd, "Whose")
        t:assert_eq(q.ret, 0, "query: " .. sys.errname(q.errno or 0))
        t:assert_eq(q.data, lcs.sz("policy"),
            "the layer's key is the visible one; no hiding entry was needed")
        t:assert(lcs.entry(s, test_key, "Masked", "base") ~= nil,
            "the base entry is still there, merely masked")
        sys.close(w, fd)
        done(w)
    end)

test("removing the replacing layer brings the lower key back",
    { spec = "PKM *path-entry.hide-and-replace.removing-the-layer-restores-the-lower-key" },
    function(t)
        local s = fixture()
        local w = worker()
        local layer_fd = open(t, w, lcs.LAYERS_PATH .. "\\Policy")
        t:assert_eq(lcs.delete_key(s, w, layer_fd).ret, 0, "delete the Policy layer")
        sys.close(w, layer_fd)
        t:assert(lcs.entry(s, test_key, "Masked", "Policy") == nil,
            "the layer's entry went with it")
        local fd = open(t, w, TEST .. "\\Masked", lcs.RIGHT.KEY_READ)
        local q = lcs.query_value(s, w, fd, "Whose")
        t:assert_eq(q.data, lcs.sz("base"), "and the lower key is visible again")
        sys.close(w, fd)
        done(w)
    end)

-- Hive roots ----------------------------------------------------------------

test("a hive root has no parent GUID and no child name",
    { spec = "PKM *path-entry.hive-root.has-no-parent-or-child-name" }, function(t)
        local s = fixture()
        local root = s.hives[1].root
        for parent, per in pairs(s.store.entries) do
            for _, slot in pairs(per) do
                for _, e in pairs(slot.by_layer) do
                    t:assert(e.hidden or e.guid ~= root,
                        "no (parent, name, layer) tuple anywhere names the hive root")
                end
            end
        end
        t:assert_eq(s.store.keys[root].parent, lcs.NULL_GUID, "and it has no parent GUID")
        local w = worker()
        local fd = open(t, w, "Machine", lcs.RIGHT.KEY_READ)
        t:assert(fd >= 0, "yet it opens as a key")
        sys.close(w, fd)
        done(w)
    end)

test("deleting or hiding a hive root is EINVAL, rejected before any dispatch",
    { spec = "PKM *path-entry.hive-root.delete-or-hide-is-einval" }, function(t)
        local s = fixture()
        local w = worker()
        local root = open(t, w, "Machine")
        local n = lcs.notify(nil, w, root, lcs.NOTIFY.ALL, false)
        t:assert_eq(n.ret, 0, "a watch is armed on the root: " .. sys.errname(n.errno or 0))

        local mark = s:mark()
        local d = lcs.delete_key(nil, w, root)
        t:assert_eq(d.errno, sys.E.INVAL, "delete: " .. sys.errname(d.errno or 0))
        local h = lcs.hide_key(nil, w, root, { layer = "Hider" })
        t:assert_eq(h.errno, sys.E.INVAL, "hide: " .. sys.errname(h.errno or 0))

        t:assert_eq(#s.log - mark + 1, 0,
            "neither reached the source: the rejection is before dispatch")
        -- A read on a key fd blocks until an event arrives, so the
        -- absence of one is observed by polling.
        local revents = lcs.poll_revents(w, root, 50)
        t:assert_eq(revents, 0, "and before any watch event was generated")
        sys.close(w, root)
        done(w)
    end)
