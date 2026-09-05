-- PKM §5.3.1–§5.3.2 — The layer model and the base layer: what a layer
-- is, the caps that bound the table and the number of layers on one
-- value, the fact that the table is global while entries are per-source,
-- and the kernel-reserved `base` layer that exists whatever storage says.
--
-- The three MaxTotalLayers cases are last in the file on purpose: they
-- reconfigure the layer table cap and then fill it.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")
local token = require("helpers.token")
local kacs = require("helpers.kacs")
local access = require("helpers.access")
local kmes = require("helpers.kmes")

local vm = provium:vm("v", "kernel-only"):boot()

local CI = access.ACE_FLAG.CONTAINER_INHERIT
local R = lcs.RIGHT
local TEST_PATH = "Machine\\Software\\Test"
local function layer_path(name) return lcs.LAYERS_PATH .. "\\" .. name end
local LONG_S = "\u{017F}"

local src = lcs.source(vm)
local TEST_KEY = src:key(TEST_PATH)
src:key(lcs.PARAMS_PATH)
-- `base` is decorated with a Precedence and an Enabled that must both
-- be ignored (§5.3.2).
src:seed_layer("base", { precedence = 9, enabled = false })
src:seed_layer("tier1", { precedence = 1 })
src:seed_layer("sentinel")
src:key(layer_path("locked-owner"), { sd = lcs.sd({
    access.ace(access.ACE.ALLOWED, R.KEY_ALL_ACCESS, kacs.SID.LOCAL_SYSTEM, CI),
    access.ace(access.ACE.ALLOWED, R.KEY_READ, kacs.SID.EVERYONE, CI),
}) })
src:seed_layer("locked-owner", { owner = token.SID.TEST_USER })

-- One value carrying 127 entries in 127 layers that are not in the
-- table. MaxLayersPerValue counts what the source returns for the
-- (key GUID, value name) pair, so latent entries are the cheap way to
-- stand a value up against the default cap of 128.
local CAP_KEY = src:key(TEST_PATH .. "\\Cap")
for i = 1, 127 do
    src:value(CAP_KEY, "V", lcs.TYPE.DWORD, lcs.dword(i), { layer = string.format("lat%03d", i) })
end
local NEAR_KEY = src:key(TEST_PATH .. "\\Near")
for i = 1, 126 do
    src:value(NEAR_KEY, "V", lcs.TYPE.DWORD, lcs.dword(i), { layer = string.format("lat%03d", i) })
end
assert(src:register())
src:pump()

local w = vm:spawn_worker()

local function open(t, path, mask, who)
    local r = lcs.open_key(src, who or w, -1, path, mask or lcs.KEY_ALL_ACCESS)
    t:assert(r.ret >= 0, "open " .. path .. ": " .. sys.errname(r.errno or 0))
    return r.ret
end

local function subkey(t, name, who)
    local root = open(t, TEST_PATH, lcs.KEY_ALL_ACCESS, who)
    local c = lcs.create_key(src, who or w, { parent_fd = root, path = name })
    t:assert(c.ret >= 0, "a fresh subkey: " .. sys.errname(c.errno or 0))
    sys.close(who or w, root)
    return c.ret
end

-- ---- §5.3.1 the layer model ----------------------------------------

-- The two MaxTotalLayers cases that read self-configuration audits come
-- first: they must see a boot whose configuration nothing has touched.

--- The parameter names an LCS_SELF_CONFIG_INVALID audit reported while
--- `fn` ran, mapped to the payload that reported them. Every refresh
--- audits each parameter it could not take, so an empty result means
--- the refresh did not run rather than that everything validated.
local function self_config_rejections(t, fn)
    local events = kmes.recording(t, vm, fn)
    local records = kmes.of_type(events, "LCS_SELF_CONFIG_INVALID")
    t:assert(#records >= 1, "the self-configuration refresh ran and audited what it read")
    local out = {}
    for _, e in ipairs(records) do
        if e.payload and e.payload.configuration_name then
            out[e.payload.configuration_name] = e.payload
        end
    end
    return out
end

test("MaxTotalLayers defaults to 1024",
    { spec = "PKM *layer.model.max-total-layers-default-1024" },
    function(t)
        -- Nothing has configured it in this boot, so the value LCS
        -- retains when it refuses an out-of-range one is the default.
        local pfd = open(t, lcs.PARAMS_PATH, lcs.KEY_ALL_ACCESS)
        local rejected = self_config_rejections(t, function()
            local s = lcs.set_value(src, w, pfd, "MaxTotalLayers", lcs.TYPE.DWORD, lcs.dword(8))
            t:assert_eq(s.ret, 0, "8 is written: " .. sys.errname(s.errno or 0))
        end)
        local record = rejected["MaxTotalLayers"]
        t:assert(record, "8 is below the configurable minimum and is refused")
        t:assert_eq(record.retained_value, 1024,
            "and the value LCS keeps bounding the in-memory layer table is the default")
        t:assert_eq(record.expected_max, 65536, "which is configurable up to 65536")
        sys.close(w, pfd)
    end)

test("MaxTotalLayers is configurable up to 65536, and a value above 1024 validates and publishes",
    { spec = "PKM *layer.model.max-total-layers-above-1024-not-honoured" },
    function(t)
        -- The other half of this claim — that the table still runs out
        -- at 1023 dynamic entries whatever the configured value says —
        -- needs 1024 layers and is out of a guest test's reach; the
        -- fixed array has a stub of its own below.
        local pfd = open(t, lcs.PARAMS_PATH, lcs.KEY_ALL_ACCESS)
        local rejected = self_config_rejections(t, function()
            local s = lcs.set_value(src, w, pfd, "MaxTotalLayers", lcs.TYPE.DWORD, lcs.dword(2048))
            t:assert_eq(s.ret, 0, "2048 is written: " .. sys.errname(s.errno or 0))
        end)
        t:assert(not rejected["MaxTotalLayers"],
            "a value above 1024 and within the configurable range validates and publishes, " ..
            "unlike one outside it")
        sys.close(w, pfd)
    end)

test("the layer's name is its identity, case-preserving and compared by folding",
    { spec = "PKM *layer.model.name-is-the-identity" },
    function(t)
        local lfd, e = lcs.create_layer(src, w, "MixedCase")
        t:assert(lfd, "a layer with a mixed-case name: " .. sys.errname(e or 0))
        sys.close(w, lfd)
        local fd = subkey(t, "Identity")
        local s = lcs.set_value(src, w, fd, "V", lcs.TYPE.DWORD, lcs.dword(1),
            { layer = "mixedcase" })
        t:assert_eq(s.ret, 0, "another spelling names the same layer: " ..
            sys.errname(s.errno or 0))
        local q = lcs.query_value(src, w, fd, "V")
        t:assert_eq(q.layer, "MixedCase",
            "and the name is preserved as it was created, not as it was written")
        local unicode = lcs.set_value(src, w, fd, "V2", lcs.TYPE.DWORD, lcs.dword(1),
            { layer = "mixedcaſe" })
        t:assert_eq(unicode.ret, 0,
            "matching is Unicode Simple Case Folding, so U+017F names it too: " ..
            sys.errname(unicode.errno or 0))
        -- Bounded by MaxPathComponentLength, which defaults to 255.
        local too_long = lcs.create_key(src, w, { path = layer_path(string.rep("x", 256)) })
        t:assert(too_long.ret < 0, "a name longer than MaxPathComponentLength is refused")
        sys.close(w, fd)
    end)

test("Owner is never used for an access check",
    { spec = "PKM *layer.model.owner-never-used-for-an-access-check" },
    function(t)
        -- `locked-owner` records TEST_USER as its Owner and its metadata
        -- key grants only SYSTEM KEY_SET_VALUE.
        token.as_principal(t, vm, { privs_present = 0, privs_enabled = 0 }, function(w2)
            local fd = open(t, TEST_PATH, lcs.KEY_ALL_ACCESS, w2)
            local s = lcs.set_value(src, w2, fd, "V", lcs.TYPE.DWORD, lcs.dword(1),
                { layer = "locked-owner" })
            t:assert_eq(s.errno, sys.E.ACCES,
                "the principal the Owner value names is refused all the same: " ..
                "authorisation is the descriptor on the metadata key")
            sys.close(w2, fd)
        end, { user_sid = token.SID.TEST_USER })
    end)

test("a refresh re-reads the Owner value and re-selects it",
    { spec = "PKM *layer.model.owner-re-selected-by-refresh" },
    function(t)
        local lfd, e = lcs.create_layer(src, w, "owner-refresh",
            { owner = token.SID.TEST_USER })
        t:assert(lfd, "a layer with an Owner: " .. sys.errname(e or 0))
        local rewrite = lcs.set_value(src, w, lfd, "Owner", lcs.TYPE.BINARY, token.SID.TEST_USER_2)
        t:assert_eq(rewrite.ret, 0, "rewriting the value is accepted: " ..
            sys.errname(rewrite.errno or 0))
        -- The refresh really did re-read it: a value it cannot select
        -- fails the refresh rather than being left as it was.
        local broken = lcs.set_value(src, w, lfd, "Owner", lcs.TYPE.SZ, lcs.sz("nobody"))
        t:assert_eq(broken.errno, sys.E.IO,
            "so an Owner the refresh cannot parse fails the refresh")
        sys.close(w, lfd)
    end)

test("MaxLayersPerValue defaults to 128 and exceeding it is ENOSPC",
    { spec = "PKM *layer.model.max-layers-per-value-default-128" },
    function(t)
        local fd = open(t, TEST_PATH .. "\\Near", lcs.KEY_ALL_ACCESS)
        -- 126 entries in storage: the base layer makes 127.
        local ok = lcs.set_value(src, w, fd, "V", lcs.TYPE.DWORD, lcs.dword(1))
        t:assert_eq(ok.ret, 0, "the 127th layer on one value is admitted: " ..
            sys.errname(ok.errno or 0))
        sys.close(w, fd)
        local full = open(t, TEST_PATH .. "\\Cap", lcs.KEY_ALL_ACCESS)
        -- 127 entries in storage: the base layer makes 128, the cap.
        local last = lcs.set_value(src, w, full, "V", lcs.TYPE.DWORD, lcs.dword(1))
        t:assert_eq(last.ret, 0, "and so is the 128th: " .. sys.errname(last.errno or 0))
        sys.close(w, full)
    end)

test("exceeding MaxLayersPerValue is ENOSPC",
    { spec = "PKM *layer.model.max-layers-per-value-exceeded-is-enospc" },
    function(t)
        local lfd = lcs.create_layer(src, w, "over-the-cap")
        t:assert(lfd, "a layer to write from")
        sys.close(w, lfd)
        local fd = open(t, TEST_PATH .. "\\Cap", lcs.KEY_ALL_ACCESS)
        local s = lcs.set_value(src, w, fd, "V", lcs.TYPE.DWORD, lcs.dword(9),
            { layer = "over-the-cap" })
        t:assert_eq(s.errno, sys.E.NOSPC,
            "the 129th layer on one (key GUID, value name) pair is refused")
        sys.close(w, fd)
    end)

test("the cap is enforced at REG_IOC_SET_VALUE, before the source is contacted, by querying it",
    { spec = "PKM *layer.model.max-layers-per-value-checked-at-set-value" },
    function(t)
        local lfd = lcs.create_layer(src, w, "checked-at-set")
        t:assert(lfd, "a layer to write from")
        sys.close(w, lfd)
        local fd = open(t, TEST_PATH .. "\\Cap", lcs.KEY_ALL_ACCESS)
        local mark = src:mark()
        local s = lcs.set_value(src, w, fd, "V", lcs.TYPE.DWORD, lcs.dword(9),
            { layer = "checked-at-set" })
        t:assert_eq(s.errno, sys.E.NOSPC, "the write is refused")
        t:assert(#src:served(lcs.OP.QUERY_VALUES, mark, CAP_KEY) >= 1,
            "after LCS asked the source for the current entry count")
        t:assert_eq(#src:served(lcs.OP.SET_VALUE, mark, CAP_KEY), 0,
            "and before the write itself was dispatched")
        sys.close(w, fd)
    end)

test("a write that replaces an existing entry in the same layer is exempt",
    { spec = "PKM *layer.model.max-layers-per-value-same-layer-replace-exempt" },
    function(t)
        local fd = open(t, TEST_PATH .. "\\Cap", lcs.KEY_ALL_ACCESS)
        local s = lcs.set_value(src, w, fd, "V", lcs.TYPE.DWORD, lcs.dword(77))
        t:assert_eq(s.ret, 0,
            "at the cap, rewriting the base-layer entry does not increase the count: " ..
            sys.errname(s.errno or 0))
        local q = lcs.query_value(src, w, fd, "V")
        t:assert_eq(q.data, lcs.dword(77), "and the replacement lands")
        sys.close(w, fd)
    end)

test("once LCS observes a count at or above the cap, further new-layer writes are refused",
    { spec = "PKM *layer.model.max-layers-per-value-refuses-once-observed-full" },
    function(t)
        for _, name in ipairs({ "refused-a", "refused-b" }) do
            local lfd = lcs.create_layer(src, w, name)
            t:assert(lfd, "a layer named " .. name)
            sys.close(w, lfd)
        end
        local fd = open(t, TEST_PATH .. "\\Cap", lcs.KEY_ALL_ACCESS)
        for _, name in ipairs({ "refused-a", "refused-b" }) do
            local s = lcs.set_value(src, w, fd, "V", lcs.TYPE.DWORD, lcs.dword(1),
                { layer = name })
            t:assert_eq(s.errno, sys.E.NOSPC, "a new-layer write from " .. name .. " is refused")
        end
        sys.close(w, fd)
    end)

test("blanket tombstones and value deletions are not subject to the cap",
    { spec = "PKM *layer.model.max-layers-per-value-exempts-blankets-and-deletions" },
    function(t)
        local lfd = lcs.create_layer(src, w, "exempt-layer")
        t:assert(lfd, "a layer that holds no entry on the capped value")
        sys.close(w, lfd)
        local fd = open(t, TEST_PATH .. "\\Cap", lcs.KEY_ALL_ACCESS)
        local d = lcs.delete_value(src, w, fd, "V", { layer = "exempt-layer" })
        t:assert_eq(d.ret, 0, "a value deletion in a new layer is allowed at the cap: " ..
            sys.errname(d.errno or 0))
        local b = lcs.blanket_tombstone(src, w, fd, "exempt-layer", true)
        t:assert_eq(b.ret, 0, "and so is a blanket tombstone: " .. sys.errname(b.errno or 0))
        lcs.blanket_tombstone(src, w, fd, "exempt-layer", false)
        sys.close(w, fd)
    end)

test("the cap is best-effort admission control, not a storage invariant",
    { spec = "PKM *layer.model.max-layers-per-value-is-best-effort" },
    function(t)
        local lfd = lcs.create_layer(src, w, "best-effort")
        t:assert(lfd, "a layer to write from")
        sys.close(w, lfd)
        local fd = open(t, TEST_PATH .. "\\Cap", lcs.KEY_ALL_ACCESS)
        -- LCS queries and then dispatches, holding nothing: the count it
        -- admits against is whatever the source said a moment ago, and
        -- sources are not required to enforce the cap atomically.
        src:intercept(lcs.OP.QUERY_VALUES, function(self, req)
            if req.payload:sub(1, 16) == CAP_KEY then
                return lcs.STATUS.OK, string.pack("<I4I4", 0, 0) -- no entries, no blankets
            end
            return nil
        end)
        local s = lcs.set_value(src, w, fd, "V", lcs.TYPE.DWORD, lcs.dword(1),
            { layer = "best-effort" })
        src:intercept(lcs.OP.QUERY_VALUES, nil)
        t:assert_eq(s.ret, 0,
            "a source that reports room admits the write, whatever storage actually holds: " ..
            sys.errname(s.errno or 0))
        local held = 0
        for _, e in pairs(src.store.values[CAP_KEY]["v"].by_layer) do held = held + 1 end
        t:assert(held > 128,
            "so storage now holds more entries than the cap — it is admission control, " ..
            "not an invariant (" .. held .. " entries)")
        sys.close(w, fd)
    end)

test("there is one global layer table and each source stores only its own entries",
    { spec = "PKM *layer.model.table-is-global-entries-are-per-source" },
    function(t)
        local other = lcs.source(vm, { hives = { { name = "Other" } } })
        local okey = other:key("Other\\K")
        t:assert(other:register(), "a second source registers a hive of its own")
        other:pump()
        -- A layer created through the Machine hive is immediately a
        -- write target in the other source's hive: the table is global.
        local lfd = lcs.create_layer(src, w, "global-layer")
        t:assert(lfd, "a layer created through the Machine hive")
        sys.close(w, lfd)
        local ofd = lcs.open_key(other, w, -1, "Other\\K", lcs.KEY_ALL_ACCESS)
        t:assert(ofd.ret >= 0, "the other hive opens: " .. sys.errname(ofd.errno or 0))
        local s = lcs.set_value(other, w, ofd.ret, "V", lcs.TYPE.SZ, lcs.sz("other"),
            { layer = "global-layer" })
        t:assert_eq(s.ret, 0, "and takes writes tagged with it: " .. sys.errname(s.errno or 0))
        -- The entry, though, is the other source's alone.
        t:assert(other.store.values[okey] and other.store.values[okey]["v"],
            "the entry is stored by the source whose hive it is in")
        local mfd = subkey(t, "PerSource")
        local q = lcs.query_value(src, w, mfd, "V")
        t:assert_eq(q.errno, sys.E.NOENT, "and is not visible in another source's hive")
        sys.close(w, mfd)
        sys.close(w, ofd.ret)
        other:close()
    end)

test("no RSI operation hands a source the layer list",
    { spec = "PKM *layer.model.no-rsi-operation-sends-the-layer-list" },
    function(t)
        -- `sentinel` is a published layer that nothing in this case
        -- targets. If any request carried the layer list, its name would
        -- be in one of them.
        local fd = subkey(t, "NoLayerList")
        local mark = src:mark()
        lcs.set_value(src, w, fd, "V", lcs.TYPE.DWORD, lcs.dword(1))
        lcs.set_value(src, w, fd, "V", lcs.TYPE.DWORD, lcs.dword(2), { layer = "tier1" })
        lcs.query_value(src, w, fd, "V")
        lcs.query_values_batch(src, w, fd)
        lcs.enum_values(src, w, fd, 0)
        lcs.query_key_info(src, w, fd)
        local seen = 0
        for i = mark, #src.log do
            if src.log[i].raw:find("sentinel", 1, true) then seen = seen + 1 end
        end
        t:assert(#src.log > mark, "the operations reached the source")
        t:assert_eq(seen, 0,
            "and none of them carried the name of a layer they did not target: " ..
            "resolution happens entirely in the kernel and the snapshot is never pushed")
        sys.close(w, fd)
    end)

-- ---- §5.3.2 the base layer -----------------------------------------

test("the base layer exists unconditionally, whatever a source's database holds",
    { spec = "PKM *layer.base.exists-unconditionally" },
    function(t)
        -- A source whose database has no layer metadata at all — no
        -- Layers key, no `base` key, nothing.
        local bare = lcs.source(vm, { hives = { { name = "Bare" } } })
        bare:key("Bare\\K")
        t:assert(bare:register(), "a source with no layer metadata registers")
        bare:pump()
        local fd = lcs.open_key(bare, w, -1, "Bare\\K", lcs.KEY_ALL_ACCESS)
        t:assert(fd.ret >= 0, "its hive routes: " .. sys.errname(fd.errno or 0))
        local s = lcs.set_value(bare, w, fd.ret, "V", lcs.TYPE.DWORD, lcs.dword(1))
        t:assert_eq(s.ret, 0, "and the base layer is there to write into: " ..
            sys.errname(s.errno or 0))
        local q = lcs.query_value(bare, w, fd.ret, "V")
        t:assert_eq(q.layer, "base", "spelled `base`")
        sys.close(w, fd.ret)
        bare:close()
    end)

test("the base layer is a static constant: precedence 0 and enabled",
    { spec = "PKM *layer.base.is-precedence-zero-and-enabled" },
    function(t)
        local fd = subkey(t, "BaseConstant")
        local a = lcs.set_value(src, w, fd, "V", lcs.TYPE.SZ, lcs.sz("base"))
        t:assert_eq(a.ret, 0, "a base write: " .. sys.errname(a.errno or 0))
        local q = lcs.query_value(src, w, fd, "V")
        t:assert_eq(q.layer, "base",
            "it resolves for a thread naming no private layer, so it is enabled")
        local b = lcs.set_value(src, w, fd, "V", lcs.TYPE.SZ, lcs.sz("tier1"), { layer = "tier1" })
        t:assert_eq(b.ret, 0, "a precedence-1 write: " .. sys.errname(b.errno or 0))
        t:assert_eq(lcs.query_value(src, w, fd, "V").layer, "tier1",
            "and a precedence-1 layer beats it, so it is at precedence 0")
        sys.close(w, fd)
    end)

test("the base layer is never stored in the dynamic layer table",
    { spec = "PKM *layer.base.not-in-the-dynamic-layer-table" },
    function(t)
        -- Its metadata key can be deleted, and the layer is still there:
        -- nothing in the dynamic table is what makes it exist.
        local before = subkey(t, "NotDynamic")
        local dfd = open(t, layer_path("base"), R.DELETE)
        local d = lcs.delete_key(src, w, dfd)
        t:assert_eq(d.ret, 0, "the metadata key is deleted: " .. sys.errname(d.errno or 0))
        sys.close(w, dfd)
        local s = lcs.set_value(src, w, before, "V", lcs.TYPE.DWORD, lcs.dword(1))
        t:assert_eq(s.ret, 0, "and base-layer writes still work: " .. sys.errname(s.errno or 0))
        t:assert_eq(lcs.query_value(src, w, before, "V").layer, "base",
            "resolving from a layer that no table row describes")
        sys.close(w, before)
    end)

test("the base layer is emitted first in every snapshot, even when the dynamic table is empty",
    { spec = "PKM *layer.base.emitted-first-in-every-snapshot" },
    function(t)
        -- The consequence the manual draws: a source that registers with
        -- a completely empty database is immediately usable, because the
        -- one layer writes need is not in the database.
        local empty = lcs.source(vm, { hives = { { name = "Empty" } } })
        empty:key("Empty\\Root")
        t:assert(empty:register(), "a source with a completely empty database registers")
        empty:pump()
        local fd = lcs.open_key(empty, w, -1, "Empty\\Root", lcs.KEY_ALL_ACCESS)
        t:assert(fd.ret >= 0, "its root opens: " .. sys.errname(fd.errno or 0))
        local c = lcs.create_key(empty, w, { parent_fd = fd.ret, path = "Made" })
        t:assert(c.ret >= 0, "a key can be created in it straight away: " ..
            sys.errname(c.errno or 0))
        local s = lcs.set_value(empty, w, c.ret, "V", lcs.TYPE.DWORD, lcs.dword(1))
        t:assert_eq(s.ret, 0, "and written to: " .. sys.errname(s.errno or 0))
        sys.close(w, c.ret)
        sys.close(w, fd.ret)
        empty:close()
    end)

test("the base layer cannot be deleted",
    { spec = "PKM *layer.base.cannot-be-deleted" },
    function(t)
        local fd = subkey(t, "CannotDelete")
        -- Its metadata key may or may not exist by now; either way the
        -- layer survives every attempt to remove it.
        local made = lcs.create_key(src, w, { path = layer_path("base") })
        t:assert(made.ret >= 0, "the metadata key: " .. sys.errname(made.errno or 0))
        sys.close(w, made.ret)
        local dfd = open(t, layer_path("base"), R.DELETE)
        local d = lcs.delete_key(src, w, dfd)
        t:assert_eq(d.ret, 0, "deleting the metadata key is allowed: " ..
            sys.errname(d.errno or 0))
        sys.close(w, dfd)
        local s = lcs.set_value(src, w, fd, "V", lcs.TYPE.DWORD, lcs.dword(1))
        t:assert_eq(s.ret, 0, "but the layer is still there: " .. sys.errname(s.errno or 0))
        t:assert_eq(lcs.query_value(src, w, fd, "V").layer, "base", "and still named base")
        sys.close(w, fd)
    end)

test("a SUBKEY_DELETED for base is ignored by the internal self-watch",
    { spec = "PKM *layer.base.subkey-deleted-is-ignored" },
    function(t)
        local made = lcs.create_key(src, w, { path = layer_path("base") })
        t:assert(made.ret >= 0, "the metadata key exists: " .. sys.errname(made.errno or 0))
        sys.close(w, made.ret)
        local fd = subkey(t, "SubkeyDeleted")
        local seed = lcs.set_value(src, w, fd, "V", lcs.TYPE.DWORD, lcs.dword(1))
        t:assert_eq(seed.ret, 0, "with a base-layer entry: " .. sys.errname(seed.errno or 0))
        local mark = src:mark()
        local dfd = open(t, layer_path("base"), R.DELETE)
        lcs.delete_key(src, w, dfd)
        sys.close(w, dfd)
        for _, req in ipairs(src:served(lcs.OP.DELETE_LAYER, mark)) do
            local name = string.unpack("<s4", req.payload, 1)
            t:assert(lcs.fold(name) ~= "base",
                "it is not processed as a layer deletion, so no RSI_DELETE_LAYER names base")
        end
        local q = lcs.query_value(src, w, fd, "V")
        t:assert_eq(q.ret, 0, "and no entry was purged: " .. sys.errname(q.errno or 0))
        t:assert_eq(q.layer, "base", "the base layer's existence is hardcoded")
        sys.close(w, fd)
    end)

test("the base layer cannot be disabled",
    { spec = "PKM *layer.base.cannot-be-disabled" },
    function(t)
        local made = lcs.create_key(src, w, { path = layer_path("base") })
        t:assert(made.ret >= 0, "the metadata key: " .. sys.errname(made.errno or 0))
        local s = lcs.set_value(src, w, made.ret, "Enabled", lcs.TYPE.DWORD, lcs.dword(0))
        t:assert_eq(s.ret, 0, "writing Enabled = 0 is accepted: " .. sys.errname(s.errno or 0))
        sys.close(w, made.ret)
        local fd = subkey(t, "CannotDisable")
        local wv = lcs.set_value(src, w, fd, "V", lcs.TYPE.DWORD, lcs.dword(1))
        t:assert_eq(wv.ret, 0, "a base write: " .. sys.errname(wv.errno or 0))
        local q = lcs.query_value(src, w, fd, "V")
        t:assert_eq(q.ret, 0, "and it still resolves for a thread naming no private layer")
        t:assert_eq(q.layer, "base", "so the base layer is still enabled")
        sys.close(w, fd)
    end)

test("the base layer's precedence cannot be changed, and no table row for it is ever published",
    { spec = "PKM *layer.base.precedence-cannot-be-changed" },
    function(t)
        local made = lcs.create_key(src, w, { path = layer_path("base") })
        t:assert(made.ret >= 0, "the metadata key: " .. sys.errname(made.errno or 0))
        local s = lcs.set_value(src, w, made.ret, "Precedence", lcs.TYPE.DWORD, lcs.dword(9))
        t:assert_eq(s.ret, 0, "writing Precedence = 9 is accepted: " .. sys.errname(s.errno or 0))
        sys.close(w, made.ret)
        local fd = subkey(t, "PrecedenceFixed")
        lcs.set_value(src, w, fd, "V", lcs.TYPE.SZ, lcs.sz("base"))
        lcs.set_value(src, w, fd, "V", lcs.TYPE.SZ, lcs.sz("tier1"), { layer = "tier1" })
        t:assert_eq(lcs.query_value(src, w, fd, "V").layer, "tier1",
            "and a precedence-1 layer still beats it: the base layer is still at 0")
        sys.close(w, fd)
    end)

test("a layer table row for base cannot be published at all",
    { spec = "PKM *layer.base.row-cannot-be-published" },
    function(t)
        -- The refresh short-circuits for `base` before it would read
        -- Precedence or Enabled, so no row describing it ever reaches
        -- the table: a metadata key holding values that would be
        -- malformed for any other layer publishes nothing and fails
        -- nothing.
        local made = lcs.create_key(src, w, { path = layer_path("base") })
        t:assert(made.ret >= 0, "the metadata key: " .. sys.errname(made.errno or 0))
        local s = lcs.set_value(src, w, made.ret, "Enabled", lcs.TYPE.DWORD, lcs.dword(7))
        t:assert_eq(s.ret, 0,
            "an Enabled of 7 — malformed metadata for any other layer — is accepted, " ..
            "because nothing tries to publish a row from it: " .. sys.errname(s.errno or 0))
        sys.close(w, made.ret)
        local fd = subkey(t, "NoRow")
        local wv = lcs.set_value(src, w, fd, "V", lcs.TYPE.DWORD, lcs.dword(1))
        t:assert_eq(wv.ret, 0, "and the base layer is unaffected: " .. sys.errname(wv.errno or 0))
        t:assert_eq(lcs.query_value(src, w, fd, "V").layer, "base", "still precedence 0, enabled")
        sys.close(w, fd)
    end)

test("the metadata key supplies the base layer's GUID and its cached descriptor",
    { spec = "PKM *layer.base.metadata-key-supplies-guid-and-descriptor" },
    function(t)
        local made = lcs.create_key(src, w, { path = layer_path("base") })
        t:assert(made.ret >= 0, "the metadata key: " .. sys.errname(made.errno or 0))
        local g = lcs.get_security(src, w, made.ret, lcs.SI.OWNER | lcs.SI.GROUP | lcs.SI.DACL)
        t:assert_eq(g.ret, 0, "carries a descriptor: " .. sys.errname(g.errno or 0))
        -- What LCS takes from the key is who may write into the base
        -- layer: replacing the descriptor changes exactly that.
        local locked = lcs.sd({
            access.ace(access.ACE.ALLOWED, R.KEY_ALL_ACCESS, kacs.SID.LOCAL_SYSTEM, CI),
            access.ace(access.ACE.ALLOWED, R.KEY_READ, kacs.SID.EVERYONE, CI),
        })
        local ss = lcs.set_security(src, w, made.ret,
            lcs.SI.OWNER | lcs.SI.GROUP | lcs.SI.DACL, locked)
        t:assert_eq(ss.ret, 0, "replacing it: " .. sys.errname(ss.errno or 0))
        sys.close(w, made.ret)
        token.as_principal(t, vm, { privs_present = 0, privs_enabled = 0 }, function(w2)
            local fd = open(t, TEST_PATH, lcs.KEY_ALL_ACCESS, w2)
            local s = lcs.set_value(src, w2, fd, "V", lcs.TYPE.DWORD, lcs.dword(1))
            t:assert_eq(s.errno, sys.E.ACCES,
                "changes who may write into the base layer")
            sys.close(w2, fd)
        end)
        -- Put it back, so later cases still have a writable base layer.
        local again = open(t, layer_path("base"), lcs.KEY_ALL_ACCESS)
        lcs.set_security(src, w, again, lcs.SI.OWNER | lcs.SI.GROUP | lcs.SI.DACL,
            lcs.permissive_sd())
        sys.close(w, again)
    end)

test("the base layer's persisted Precedence and Enabled are ignored",
    { spec = "PKM *layer.base.persisted-precedence-and-enabled-ignored" },
    function(t)
        -- This source persisted Precedence 9 and Enabled 0 for `base`
        -- before it ever registered. Neither was consulted.
        local fd = subkey(t, "PersistedIgnored")
        local a = lcs.set_value(src, w, fd, "V", lcs.TYPE.SZ, lcs.sz("base"))
        t:assert_eq(a.ret, 0, "a base write: " .. sys.errname(a.errno or 0))
        t:assert_eq(lcs.query_value(src, w, fd, "V").layer, "base",
            "the persisted Enabled 0 did not disable it")
        local b = lcs.set_value(src, w, fd, "V", lcs.TYPE.SZ, lcs.sz("tier1"), { layer = "tier1" })
        t:assert_eq(b.ret, 0, "a precedence-1 write: " .. sys.errname(b.errno or 0))
        t:assert_eq(lcs.query_value(src, w, fd, "V").layer, "tier1",
            "and the persisted Precedence 9 did not raise it")
        sys.close(w, fd)
    end)

test("a write that names no layer targets the base layer",
    { spec = "PKM *layer.base.is-the-default-write-target" },
    function(t)
        local fd = subkey(t, "DefaultTarget")
        local s = lcs.set_value(src, w, fd, "V", lcs.TYPE.DWORD, lcs.dword(1))
        t:assert_eq(s.ret, 0, "a write naming no layer: " .. sys.errname(s.errno or 0))
        t:assert_eq(lcs.query_value(src, w, fd, "V").layer, "base", "lands in the base layer")
        local c = lcs.create_key(src, w, { parent_fd = fd, path = "Child" })
        t:assert(c.ret >= 0, "and so does key creation: " .. sys.errname(c.errno or 0))
        sys.close(w, c.ret)
        sys.close(w, fd)
    end)

test("the reserved name base is matched like every other layer name",
    { spec = "PKM *layer.base.name-matched-by-case-folding" },
    function(t)
        local fd = subkey(t, "BaseFolded")
        for i, spelling in ipairs({ "base", "BASE", "Base", "bAsE" }) do
            local s = lcs.set_value(src, w, fd, "V" .. i, lcs.TYPE.DWORD, lcs.dword(1),
                { layer = spelling })
            t:assert_eq(s.ret, 0, "`" .. spelling .. "` names the base layer: " ..
                sys.errname(s.errno or 0))
            local q = lcs.query_value(src, w, fd, "V" .. i)
            t:assert_eq(q.layer, "base", "and resolves as the canonical `base`")
        end
        sys.close(w, fd)
    end)

test("the reserved name base is recognised with Unicode Simple Case Folding, the same table as every other layer name",
    { spec = "PKM *layer.base.name-matched-by-case-folding",
      tags = { "known-bug" } },
    function(t)
        -- §5.3.2 says the second, ASCII-only comparator beside the
        -- folding one is gone, and that the length pre-check which made
        -- a non-ASCII case pair fail before folding could matter went
        -- with it.
        --
        -- KERNEL: `ba<U+017F>e` folds to `base` — U+017F LATIN SMALL
        -- LETTER LONG S folds to `s` — and is still not recognised as
        -- the reserved name. It is not treated as an absent layer
        -- either: the write fails EIO rather than ENOENT.
        local fd = subkey(t, "BaseFoldedUnicode")
        local s = lcs.set_value(src, w, fd, "V", lcs.TYPE.DWORD, lcs.dword(1),
            { layer = "ba" .. LONG_S .. "e" })
        t:assert_eq(s.ret, 0,
            "`ba" .. LONG_S .. "e` folds to `base` and names the base layer: " ..
            sys.errname(s.errno or 0))
        local q = lcs.query_value(src, w, fd, "V")
        t:assert_eq(q.layer, "base", "and resolves as the canonical `base`")
        sys.close(w, fd)
    end)

-- ---- MaxTotalLayers: last, because these reconfigure and fill the table

--- Where the fill loop stopped, and why. Set by the `binds` case and
--- read by the `ENOSPC` case, which is the same fill.
local fill_stop, fill_errno

test("the table is a fixed array sized for 1023 dynamic layers plus the base layer",
    { spec = "PKM *layer.model.table-is-fixed-at-1023-dynamic-plus-base",
      covered_by = "kunit:pkm_lcs_kunit_layer",
      skip = "the compile-time size of pkm_lcs_layer_table is only visible once 1023 " ..
             "dynamic layers exist, which a guest cannot reach in a test's budget; " ..
             "runs under pkm_lcs_kunit_layer_table_publish_snapshot_remove" },
    function(t) end)

test("a MaxTotalLayers below 1024 binds",
    { spec = "PKM *layer.model.max-total-layers-below-1024-binds" },
    function(t)
        local pfd = open(t, lcs.PARAMS_PATH, lcs.KEY_ALL_ACCESS)
        local s = lcs.set_value(src, w, pfd, "MaxTotalLayers", lcs.TYPE.DWORD, lcs.dword(24))
        t:assert_eq(s.ret, 0, "MaxTotalLayers is set to 24: " .. sys.errname(s.errno or 0))
        sys.close(w, pfd)
        for i = 1, 60 do
            local fd, e = lcs.create_layer(src, w, string.format("fill%03d", i))
            if not fd then fill_stop, fill_errno = i, e; break end
            sys.close(w, fd)
        end
        t:assert(fill_stop,
            "layer creation stops: a configured value below 1024 binds, and this one " ..
            "bound far below the default")
        t:assert(fill_stop <= 24,
            "at the configured 24, not at the 1024 that was in force before it")
    end)

test("creating a layer when the table is full returns ENOSPC",
    { spec = "PKM *layer.model.layer-table-full-is-enospc",
      tags = { "known-bug" } },
    function(t)
        -- KERNEL: MaxTotalLayers is meant to bound the whole table —
        -- 1023 dynamic entries plus the base layer for the default 1024
        -- (§5.3.1). The admission check counts only the dynamic entries,
        -- so with the cap at N a further dynamic layer is admitted past
        -- the point where base needs its slot; the snapshot the next
        -- operation asks for then needs N+1 slots in buffers sized for
        -- N, and from there every registry operation on every hive fails
        -- EINVAL rather than the creation failing ENOSPC. This case is
        -- last in the file because the fill leaves the registry so.
        t:assert(fill_stop, "the fill in the preceding case reached the cap")
        t:assert_eq(fill_errno, sys.E.NOSPC,
            "the creation that would exceed the table is refused with ENOSPC, not " ..
            sys.errname(fill_errno or 0))
        local probe = lcs.open_key(src, w, -1, TEST_PATH, R.KEY_READ)
        t:assert(probe.ret >= 0,
            "and the rest of the registry keeps working: " .. sys.errname(probe.errno or 0))
        if probe.ret >= 0 then sys.close(w, probe.ret) end
    end)
