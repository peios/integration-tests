-- PKM §5.5.2 — reg_create_key: what "exists" means depends on the layer
-- named. For the base layer (a null layer_ptr) it is the path resolving
-- through any enabled layer; for a named layer it is that layer holding
-- an entry at the path, so another layer's key does not count and the
-- create makes the named layer's own entry — hide-and-replace.
--
-- What the source was asked to store is the witness: every CREATE_ENTRY
-- carries the layer it is for, and `lcs.entry` reads back what the
-- source holds per (parent, name, layer).
--
-- Belongs in iface-syscalls.test.lua after "an existing key is opened
-- and no path entry created". data-path-entries' "a different layer
-- gets its own distinct GUID at the same path" proves the GUID half
-- under the §5.2.5 anchor.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")
local kacs = require("helpers.kacs")
local token = require("helpers.token")
local access = require("helpers.access")

local vm = provium:vm("v", "kernel-only"):boot()

local TEST = "Machine\\Software\\Test"
local R = lcs.RIGHT
local CI = access.ACE_FLAG.CONTAINER_INHERIT

local src = lcs.source(vm)
src:key(lcs.LAYERS_PATH .. "\\base", { sd = lcs.permissive_sd() })
-- Two layers above base, seeded so no SeTcbPrivilege is needed to have
-- them; Overlay wins over Other.
src:seed_layer("Overlay", { precedence = 10 })
src:seed_layer("Other", { precedence = 5 })
local TEST_KEY = src:key(TEST)
-- A key base holds, with a value saying so.
local BASE_P = src:key(TEST .. "\\P")
src:value(BASE_P, "Who", lcs.TYPE.SZ, lcs.sz("base"))
-- A key only Overlay holds: its parent is base's Test.
local OVERLAY_ONLY = lcs.seed_key_in_layer(src, TEST_KEY, "OnlyOverlay", "Overlay")
-- A parent nobody but SYSTEM may create under, with a child that both
-- base and Overlay hold.
local NO_CREATE = src:key(TEST .. "\\NoCreate", { sd = lcs.sd({
    access.ace(access.ACE.ALLOWED, lcs.KEY_ALL_ACCESS, kacs.SID.LOCAL_SYSTEM, CI),
    access.ace(access.ACE.ALLOWED, lcs.KEY_ALL_ACCESS & ~R.CREATE_SUB_KEY,
        kacs.SID.EVERYONE, CI),
}) })
src:key(TEST .. "\\NoCreate\\Kid")
lcs.seed_key_in_layer(src, NO_CREATE, "Kid", "Overlay")
assert(src:register())
src:pump()

local w = vm:spawn_worker()

--- The layers of every CREATE_ENTRY served since `mark`.
local function entry_layers(mark)
    local out = {}
    for _, req in ipairs(src:served(lcs.OP.CREATE_ENTRY, mark)) do
        local _, at = string.unpack("<s4", req.payload, 17)
        out[#out + 1] = string.unpack("<s4", req.payload, at)
    end
    return out
end

test("a named layer with no entry of its own at an occupied path creates one",
    { spec = "PKM *reg-syscall.create-key.named-layer-creates-its-own-entry" }, function(t)
        local mark = src:mark()
        local made = lcs.create_key(src, w, { path = TEST .. "\\P", layer = "Overlay" })
        t:assert(made.ret >= 0, "the create succeeds: " .. sys.errname(made.errno or 0))
        t:assert_eq(made.disposition, lcs.CREATED_NEW,
            "base's key at the path does not count as existing for Overlay")
        local layers = entry_layers(mark)
        t:assert_eq(table.concat(layers, ","), "Overlay",
            "one path entry was created, in the named layer")
        local guid = lcs.created_guid(src, mark)
        t:assert(guid, "and a key record was minted for it")
        t:assert(guid ~= BASE_P, "with its own GUID, not base's")
        local e = lcs.entry(src, TEST_KEY, "P", "Overlay")
        t:assert(e and e.guid == guid, "the source holds Overlay's entry at the path")
        t:assert_eq(lcs.entry(src, TEST_KEY, "P", "base").guid, BASE_P,
            "and base's entry is untouched")

        -- Hide-and-replace: Overlay outranks base, so the path now
        -- resolves to Overlay's key object, not base's.
        local sv = lcs.set_value(src, w, made.ret, "Who", lcs.TYPE.SZ, lcs.sz("overlay"))
        t:assert_eq(sv.ret, 0, "a value on the new key: " .. sys.errname(sv.errno or 0))
        sys.close(w, made.ret)
        local plain = lcs.open_key(src, w, -1, TEST .. "\\P", R.KEY_READ)
        t:assert(plain.ret >= 0, "the path opens: " .. sys.errname(plain.errno or 0))
        if plain.ret >= 0 then
            t:assert_eq(lcs.query_value(src, w, plain.ret, "Who").data, lcs.sz("overlay"),
                "and reaches Overlay's key object — base's is replaced at the path")
            sys.close(w, plain.ret)
        end

        -- Now Overlay holds an entry there, so a second create opens it.
        local m2 = src:mark()
        local again = lcs.create_key(src, w, { path = TEST .. "\\P", layer = "Overlay" })
        t:assert(again.ret >= 0, "a second create: " .. sys.errname(again.errno or 0))
        t:assert_eq(again.disposition, lcs.OPENED_EXISTING,
            "finds the layer's own entry and opens it")
        -- What must not happen is a second key object for the layer.
        -- That the source is asked for no entry either is the known-bug
        -- case below.
        t:assert_eq(#src:served(lcs.OP.CREATE_KEY, m2), 0, "no key record was minted")
        t:assert_eq(lcs.entry(src, TEST_KEY, "P", "Overlay").guid, guid,
            "and Overlay's entry still names the key it created")
        if again.ret >= 0 then sys.close(w, again.ret) end
    end)

test("another named layer's key does not count either",
    { spec = "PKM *reg-syscall.create-key.named-layer-creates-its-own-entry" }, function(t)
        -- `OnlyOverlay` exists — it resolves, through Overlay — but Other
        -- holds nothing there.
        local mark = src:mark()
        local made = lcs.create_key(src, w, { path = TEST .. "\\OnlyOverlay", layer = "Other" })
        t:assert(made.ret >= 0, "the create succeeds: " .. sys.errname(made.errno or 0))
        t:assert_eq(made.disposition, lcs.CREATED_NEW, "Other creates its own entry")
        t:assert_eq(table.concat(entry_layers(mark), ","), "Other", "in Other")
        t:assert(lcs.created_guid(src, mark) ~= OVERLAY_ONLY, "with its own GUID")
        if made.ret >= 0 then sys.close(w, made.ret) end
    end)

test("for the base layer, a key any enabled layer holds exists",
    { spec = "PKM *reg-syscall.create-key.named-layer-creates-its-own-entry" }, function(t)
        -- The other half of the rule: a null layer_ptr asks whether the
        -- path resolves, and a path only Overlay holds does.
        local mark = src:mark()
        local r = lcs.create_key(src, w, { path = TEST .. "\\OnlyOverlay" })
        t:assert(r.ret >= 0, "the create succeeds: " .. sys.errname(r.errno or 0))
        t:assert_eq(r.disposition, lcs.OPENED_EXISTING,
            "and opens Overlay's key rather than creating a base one")
        t:assert_eq(#src:served(lcs.OP.CREATE_ENTRY, mark), 0, "no path entry was created")
        t:assert_eq(lcs.entry(src, TEST_KEY, "OnlyOverlay", "base"), nil,
            "base holds no entry there afterwards")
        if r.ret >= 0 then sys.close(w, r.ret) end
    end)

-- KNOWN BUG (kernel 0.21.0-alpha8, PEI-1375). For a named layer the kernel skips
-- the existing-path finisher altogether and runs the missing-key flow,
-- counting on the source's ALREADY_EXISTS to turn it back into an open
-- (source_create.c, pkm_lcs_reg_create_key_layer_owns_entry). The
-- missing-key flow checks KEY_CREATE_SUB_KEY on the parent first, so a
-- caller who may open the layer's key but not create beside it is
-- refused EACCES for a key that, by §5.5.2's own definition, exists.
test("a named layer's existing entry is opened as reg_open_key would open it",
    { spec = "PKM *reg-syscall.create-key.named-layer-creates-its-own-entry",
      tags = { "known-bug" } }, function(t)
        -- Overlay holds `Kid`, so for Overlay the key exists and the
        -- create "behaves as reg_open_key": what it needs is what an open
        -- needs, not KEY_CREATE_SUB_KEY on a parent it is not creating
        -- under. The caller here may open anything under NoCreate but
        -- create nothing there.
        token.as_principal(t, vm, {}, function(w2)
            local plain = lcs.create_key(src, w2, { path = TEST .. "\\NoCreate\\Kid" })
            t:assert(plain.ret >= 0, "the base-layer create of an existing key opens it: "
                .. sys.errname(plain.errno or 0))
            t:assert_eq(plain.disposition, lcs.OPENED_EXISTING, "REG_OPENED_EXISTING")
            if plain.ret >= 0 then
                -- And layer write authorization for Overlay is not what
                -- stands in the way: this caller may write into it.
                local sv = lcs.set_value(src, w2, plain.ret, "InOverlay", lcs.TYPE.DWORD,
                    lcs.dword(1), { layer = "Overlay" })
                t:assert_eq(sv.ret, 0, "the caller may write into Overlay: "
                    .. sys.errname(sv.errno or 0))
                sys.close(w2, plain.ret)
            end

            local named = lcs.create_key(src, w2, {
                path = TEST .. "\\NoCreate\\Kid", layer = "Overlay",
            })
            t:assert(named.ret >= 0,
                "and so does a create naming the layer that holds it: "
                .. sys.errname(named.errno or 0))
            t:assert_eq(named.disposition, lcs.OPENED_EXISTING, "REG_OPENED_EXISTING")
            if named.ret >= 0 then sys.close(w2, named.ret) end
        end)
    end)

-- KNOWN BUG (kernel 0.21.0-alpha8, PEI-1375), the same cause as the case above.
-- With no race, an open asks the source to create nothing; §5.5.2's
-- Races paragraph covers a concurrent creator, not this.
test("a create naming the layer that holds the entry asks the source to create nothing",
    { spec = "PKM *reg-syscall.create-key.named-layer-creates-its-own-entry",
      tags = { "known-bug" } }, function(t)
        local first = lcs.create_key(src, w, { path = TEST .. "\\Twice", layer = "Overlay" })
        t:assert(first.ret >= 0, "Overlay's entry is created: " .. sys.errname(first.errno or 0))
        if first.ret >= 0 then sys.close(w, first.ret) end

        local mark = src:mark()
        local again = lcs.create_key(src, w, { path = TEST .. "\\Twice", layer = "Overlay" })
        t:assert(again.ret >= 0, "the second create opens it: " .. sys.errname(again.errno or 0))
        t:assert_eq(again.disposition, lcs.OPENED_EXISTING, "REG_OPENED_EXISTING")
        if again.ret >= 0 then sys.close(w, again.ret) end
        t:assert_eq(#src:served(lcs.OP.CREATE_ENTRY, mark), 0,
            "behaving as reg_open_key, it sends the source no CREATE_ENTRY")
    end)
