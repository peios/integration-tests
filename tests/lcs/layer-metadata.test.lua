-- PKM §5.3.3 — Layer metadata: the three values under
-- `Machine\System\Registry\Layers\<LayerName>\`, what makes them
-- malformed, the circularity of storing them in the registry they
-- configure, the atomicity of publication, and when the refresh runs.

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

local src = lcs.source(vm)
local TEST_KEY = src:key(TEST_PATH)
src:seed_layer("base")
-- Well-formed layers. Each malformed-metadata case gets one of its own,
-- because a metadata value that fails validation stays in storage and
-- every later refresh of that layer fails on it too.
src:seed_layer("keeper")
src:seed_layer("wrongtype")
src:seed_layer("shortdword")
src:seed_layer("longdword")
src:seed_layer("enabled2")
src:seed_layer("ownerbad")
src:seed_layer("target")
src:seed_layer("over", { precedence = 6 })
src:seed_layer("tier1", { precedence = 1 })
src:seed_layer("cached")
-- Defaults: a metadata key holding none of the three values at all.
src:seed_layer("bare")
-- An explicit, well-formed Owner.
src:seed_layer("ownersid", { owner = token.SID.TEST_USER })
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

--- Which of two layers wins for one value on a fresh key.
local function winner(t, name, first, second)
    local fd = subkey(t, name)
    local a = lcs.set_value(src, w, fd, "V", lcs.TYPE.SZ, lcs.sz(first), { layer = first })
    t:assert_eq(a.ret, 0, "write in " .. first .. ": " .. sys.errname(a.errno or 0))
    local b = lcs.set_value(src, w, fd, "V", lcs.TYPE.SZ, lcs.sz(second), { layer = second })
    t:assert_eq(b.ret, 0, "write in " .. second .. ": " .. sys.errname(b.errno or 0))
    local q = lcs.query_value(src, w, fd, "V")
    t:assert_eq(q.ret, 0, "query: " .. sys.errname(q.errno or 0))
    sys.close(w, fd)
    return q.layer
end

--- Can this layer be written into at all?
local function usable(name, fd)
    local s = lcs.set_value(src, w, fd, "Probe_" .. name, lcs.TYPE.DWORD, lcs.dword(1),
        { layer = name })
    return s.ret == 0, s.errno
end

test("layer metadata lives under Machine\\System\\Registry\\Layers",
    { spec = "PKM *layer.metadata.lives-under-the-layers-key" },
    function(t)
        local fd = subkey(t, "LivesUnder")
        local before = lcs.set_value(src, w, fd, "V", lcs.TYPE.DWORD, lcs.dword(1),
            { layer = "Elsewhere" })
        t:assert_eq(before.errno, sys.E.NOENT, "the name is not a layer yet")
        -- A key of that name anywhere else is not a layer.
        local other = lcs.create_key(src, w, { path = TEST_PATH .. "\\Elsewhere" })
        t:assert(other.ret >= 0, "a key of the same name elsewhere: " ..
            sys.errname(other.errno or 0))
        sys.close(w, other.ret)
        local still = lcs.set_value(src, w, fd, "V", lcs.TYPE.DWORD, lcs.dword(1),
            { layer = "Elsewhere" })
        t:assert_eq(still.errno, sys.E.NOENT, "and does not create one")
        -- Under Layers\ it does.
        local made = lcs.create_key(src, w, { path = layer_path("Elsewhere") })
        t:assert(made.ret >= 0, "under Layers\\ it does: " .. sys.errname(made.errno or 0))
        sys.close(w, made.ret)
        local now = lcs.set_value(src, w, fd, "V", lcs.TYPE.DWORD, lcs.dword(1),
            { layer = "Elsewhere" })
        t:assert_eq(now.ret, 0, "and the layer is a usable write target: " ..
            sys.errname(now.errno or 0))
        sys.close(w, fd)
    end)

test("Precedence is a REG_DWORD and defaults to 0 when the value is missing",
    { spec = "PKM *layer.metadata.precedence-is-dword-default-0" },
    function(t)
        t:assert_eq(winner(t, "PrecedenceDefault", "bare", "tier1"), "tier1",
            "a metadata key with no Precedence value is at precedence 0, so a " ..
            "precedence-1 layer beats it whatever the sequence numbers say")
    end)

test("Enabled is a REG_DWORD 0 or 1 and defaults to true when the value is missing",
    { spec = "PKM *layer.metadata.enabled-is-dword-default-true" },
    function(t)
        local fd = subkey(t, "EnabledDefault")
        local s = lcs.set_value(src, w, fd, "V", lcs.TYPE.SZ, lcs.sz("bare"), { layer = "bare" })
        t:assert_eq(s.ret, 0, "a write into it: " .. sys.errname(s.errno or 0))
        local q = lcs.query_value(src, w, fd, "V")
        t:assert_eq(q.ret, 0, "resolves for a thread that names no private layer: " ..
            sys.errname(q.errno or 0))
        t:assert_eq(q.layer, "bare", "so the layer is enabled by default")
        sys.close(w, fd)
    end)

test("Owner is a REG_BINARY SID",
    { spec = "PKM *layer.metadata.owner-is-binary-sid" },
    function(t)
        local fd = subkey(t, "OwnerBinary")
        local ok = usable("ownersid", fd)
        t:assert(ok, "a layer whose Owner is a REG_BINARY SID publishes and is usable")
        local mfd = open(t, layer_path("ownerbad"), lcs.KEY_ALL_ACCESS)
        local bad = lcs.set_value(src, w, mfd, "Owner", lcs.TYPE.DWORD, lcs.dword(1))
        t:assert_eq(bad.errno, sys.E.IO, "an Owner that is not REG_BINARY is malformed")
        sys.close(w, mfd)
        sys.close(w, fd)
    end)

test("a metadata value of the wrong type is rejected rather than coerced",
    { spec = "PKM *layer.metadata.wrong-type-is-malformed" },
    function(t)
        local mfd = open(t, layer_path("wrongtype"), lcs.KEY_ALL_ACCESS)
        local s = lcs.set_value(src, w, mfd, "Enabled", lcs.TYPE.SZ, lcs.sz("1"))
        t:assert_eq(s.errno, sys.E.IO,
            "an Enabled that is REG_SZ is not read as the number one, it is malformed")
        sys.close(w, mfd)
    end)

test("a REG_DWORD metadata value that is not exactly four bytes is malformed",
    { spec = "PKM *layer.metadata.dword-must-be-exactly-four-bytes" },
    function(t)
        local short_fd = open(t, layer_path("shortdword"), lcs.KEY_ALL_ACCESS)
        local a = lcs.set_value(src, w, short_fd, "Precedence", lcs.TYPE.DWORD, "abc")
        t:assert_eq(a.errno, sys.E.IO, "three bytes is malformed")
        sys.close(w, short_fd)
        local long_fd = open(t, layer_path("longdword"), lcs.KEY_ALL_ACCESS)
        local b = lcs.set_value(src, w, long_fd, "Precedence", lcs.TYPE.DWORD, lcs.qword(1))
        t:assert_eq(b.errno, sys.E.IO, "and so is eight")
        sys.close(w, long_fd)
    end)

test("an Enabled greater than 1 is malformed",
    { spec = "PKM *layer.metadata.enabled-above-one-is-malformed" },
    function(t)
        local mfd = open(t, layer_path("enabled2"), lcs.KEY_ALL_ACCESS)
        local s = lcs.set_value(src, w, mfd, "Enabled", lcs.TYPE.DWORD, lcs.dword(2))
        t:assert_eq(s.errno, sys.E.IO, "Enabled is 0 or 1, and 2 is not coerced to true")
        sys.close(w, mfd)
    end)

test("the Owner selection falls back when the metadata value is absent",
    { spec = "PKM *layer.metadata.owner-fallback-chain" },
    function(t)
        local fd = subkey(t, "OwnerFallback")
        t:assert(usable("bare", fd),
            "a seeded layer with no Owner value still publishes and is usable")
        -- A newly created layer with no Owner value falls back to the
        -- creating token's SID and publishes on the spot.
        local lfd, e = lcs.create_layer(src, w, "fresh-owner")
        t:assert(lfd, "a layer created without an Owner value publishes: " ..
            sys.errname(e or 0))
        t:assert(usable("fresh-owner", fd), "and is immediately usable")
        if lfd then sys.close(w, lfd) end
        t:assert(usable("ownersid", fd), "as does one whose Owner value is present")
        sys.close(w, fd)
    end)

test("a layer whose owner cannot be resolved at all cannot be published",
    { spec = "PKM *layer.metadata.unresolvable-owner-blocks-publication",
      covered_by = "kunit:",
      skip = "the fallback chain ends at the metadata key's own descriptor owner, and " ..
             "LCS validates a source's key descriptors as complete, so no guest can " ..
             "present a metadata key with no owner anywhere in the chain; no KUnit " ..
             "case found — candidate for a new one" },
    function(t) end)

test("creating a key under Layers creates a layer and deleting it deletes one",
    { spec = "PKM *layer.metadata.key-creation-and-deletion-are-the-lifecycle" },
    function(t)
        local fd = subkey(t, "Lifecycle")
        local made = lcs.create_key(src, w, { path = layer_path("lifecycle") })
        t:assert(made.ret >= 0, "the key creates the layer: " .. sys.errname(made.errno or 0))
        sys.close(w, made.ret)
        t:assert(usable("lifecycle", fd), "which is a usable write target")
        local dfd = open(t, layer_path("lifecycle"), R.DELETE)
        local d = lcs.delete_key(src, w, dfd)
        t:assert_eq(d.ret, 0, "deleting the key deletes the layer: " .. sys.errname(d.errno or 0))
        sys.close(w, dfd)
        local ok, errno = usable("lifecycle", fd)
        t:assert(not ok, "and the layer is gone")
        t:assert_eq(errno, sys.E.NOENT, "there is no create-layer or delete-layer call besides these")
        sys.close(w, fd)
    end)

test("layer metadata is itself resolved with the currently published layer table",
    { spec = "PKM *layer.metadata.resolved-with-the-published-table" },
    function(t)
        local fd = subkey(t, "PublishedTable")
        t:assert_eq(winner(t, "PublishedTableBefore", "target", "tier1"), "tier1",
            "the target layer starts at precedence 0")
        -- A higher-precedence layer overrides another layer's Precedence
        -- value. Reading the metadata uses the published table, so the
        -- entry in `over` (precedence 6) is what the refresh sees.
        local mfd = open(t, layer_path("target"), lcs.KEY_ALL_ACCESS)
        local s = lcs.set_value(src, w, mfd, "Precedence", lcs.TYPE.DWORD, lcs.dword(9),
            { layer = "over" })
        t:assert_eq(s.ret, 0, "an override written into a high-precedence layer: " ..
            sys.errname(s.errno or 0))
        sys.close(w, mfd)
        t:assert_eq(winner(t, "PublishedTableAfter", "target", "tier1"), "target",
            "and it is what the refresh read, so the target layer is now at precedence 9")
        sys.close(w, fd)
    end)

test("the table is never re-resolved mid-operation: one snapshot per operation",
    { spec = "PKM *layer.metadata.one-snapshot-per-operation" },
    function(t)
        -- Resolving a value that lives on a layer metadata key is the
        -- circular case. The operation takes one snapshot of the table
        -- and uses it throughout; it does not re-enter resolution to
        -- re-read the table it is already resolving with.
        local guid = src:lookup(layer_path("tier1"))
        local mfd = open(t, layer_path("tier1"), lcs.KEY_ALL_ACCESS)
        local mark = src:mark()
        local q = lcs.query_value(src, w, mfd, "Precedence")
        t:assert_eq(q.ret, 0, "the metadata value resolves: " .. sys.errname(q.errno or 0))
        t:assert_eq(q.data, lcs.dword(1), "to what the metadata key holds")
        t:assert_eq(#src:served(lcs.OP.QUERY_VALUES, mark, guid), 1,
            "in one resolution of that key, not one per layer in the table")
        sys.close(w, mfd)
    end)

test("a high-precedence override of another layer's metadata takes effect at the next publication",
    { spec = "PKM *layer.metadata.override-takes-effect-at-next-publication" },
    function(t)
        local lfd = lcs.create_layer(src, w, "overridden")
        t:assert(lfd, "a layer at precedence 0")
        t:assert_eq(winner(t, "OverrideBefore", "overridden", "tier1"), "tier1",
            "which loses to precedence 1")
        local s = lcs.set_value(src, w, lfd, "Precedence", lcs.TYPE.DWORD, lcs.dword(8),
            { layer = "over" })
        t:assert_eq(s.ret, 0, "the override: " .. sys.errname(s.errno or 0))
        t:assert_eq(winner(t, "OverrideAfter", "overridden", "tier1"), "overridden",
            "takes effect at the publication that follows the write, not recursively " ..
            "during it")
        sys.close(w, lfd)
    end)

test("the published unit is the table entry, the metadata key's GUID and its cached descriptor",
    { spec = "PKM *layer.metadata.published-unit-is-three-things" },
    function(t)
        local fd = subkey(t, "PublishedUnit")
        t:assert(usable("cached", fd), "the layer is usable to begin with")
        local mfd = open(t, layer_path("cached"), lcs.KEY_ALL_ACCESS)
        -- Republishing the descriptor alone changes who may write into
        -- the layer, so the descriptor travels with the row.
        local locked = lcs.sd({
            access.ace(access.ACE.ALLOWED, R.KEY_ALL_ACCESS, kacs.SID.LOCAL_SYSTEM, CI),
            access.ace(access.ACE.ALLOWED, R.KEY_READ, kacs.SID.EVERYONE, CI),
        })
        local ss = lcs.set_security(src, w, mfd, lcs.SI.OWNER | lcs.SI.GROUP | lcs.SI.DACL, locked)
        t:assert_eq(ss.ret, 0, "the metadata descriptor is replaced: " .. sys.errname(ss.errno or 0))
        sys.close(w, mfd)
        token.as_principal(t, vm, { privs_present = 0, privs_enabled = 0 }, function(w2)
            local kfd = open(t, TEST_PATH, lcs.KEY_ALL_ACCESS, w2)
            local s = lcs.set_value(src, w2, kfd, "V", lcs.TYPE.DWORD, lcs.dword(1),
                { layer = "cached" })
            t:assert_eq(s.errno, sys.E.ACCES,
                "the cached descriptor was republished with the row")
            sys.close(w2, kfd)
        end)
        t:assert(usable("cached", fd),
            "while the row and the metadata key GUID are still there for a caller it grants")
        sys.close(w, fd)
    end)

test("a snapshot reader that finds a published layer incomplete returns EIO",
    { spec = "PKM *layer.metadata.incomplete-publication-is-eio",
      covered_by = "kunit:",
      skip = "all three parts are written under one lock, so no guest can observe the " ..
             "half-populated window the check exists for (layer_table.c, the -EIO on " ..
             "an occupied entry with no metadata_sd or owner_sid); no KUnit case found " ..
             "— candidate for a new one" },
    function(t) end)

test("a layer with no metadata key GUID and no authorisation descriptor is not in the table",
    { spec = "PKM *layer.metadata.layer-without-guid-or-descriptor-is-invisible" },
    function(t)
        -- The refresh that would publish this layer cannot read a
        -- descriptor for its metadata key, so no entry is published and
        -- there is no window in which the layer exists unauthorisable.
        local poisoned
        src:intercept(lcs.OP.CREATE_KEY, function(self, req)
            local name = string.unpack("<s4", req.payload, 17)
            if name == "Invisible" then poisoned = req.payload:sub(1, 16) end
            return nil
        end)
        src:intercept(lcs.OP.READ_KEY, function(self, req)
            if poisoned and req.payload:sub(1, 16) == poisoned then
                local k = self.store.keys[poisoned]
                if k then
                    return lcs.STATUS.OK, string.pack("<s4", k.name) .. k.parent ..
                        string.pack("<s4", "not a descriptor") ..
                        string.pack("<I1I1i8", 0, 0, 0)
                end
            end
            return nil
        end)
        local made = lcs.create_key(src, w, { path = layer_path("Invisible") })
        src:intercept(lcs.OP.CREATE_KEY, nil)
        src:intercept(lcs.OP.READ_KEY, nil)
        t:assert(made.ret < 0, "the operation that would have exposed the layer fails")
        local fd = subkey(t, "Invisible")
        local ok, errno = usable("Invisible", fd)
        t:assert(not ok, "and the layer is not visible in the table at all")
        t:assert_eq(errno, sys.E.NOENT, "so naming it is ENOENT, not a half-published layer")
        sys.close(w, fd)
    end)

test("the metadata key's descriptor is computed by inheritance before the source persists it",
    { spec = "PKM *layer.metadata.descriptor-computed-by-inheritance-before-persist" },
    function(t)
        local mark = src:mark()
        local made = lcs.create_key(src, w, { path = layer_path("Inherited") })
        t:assert(made.ret >= 0, "the metadata key is created: " .. sys.errname(made.errno or 0))
        local creates = src:served(lcs.OP.CREATE_KEY, mark)
        local persisted
        for _, req in ipairs(creates) do
            local name, at = string.unpack("<s4", req.payload, 17)
            if name == "Inherited" then
                persisted = string.unpack("<s4", req.payload, at + 16)
            end
        end
        t:assert(persisted and #persisted > 0,
            "and the descriptor LCS computed reaches the source in RSI_CREATE_KEY")
        local g = lcs.get_security(src, w, made.ret, lcs.SI.OWNER | lcs.SI.GROUP | lcs.SI.DACL)
        t:assert_eq(g.ret, 0, "get_security: " .. sys.errname(g.errno or 0))
        t:assert_eq(g.sd, persisted,
            "so the key has its descriptor before the layer can be published")
        sys.close(w, made.ret)
    end)

test("the refresh runs after the mutation commits and before the syscall returns",
    { spec = "PKM *layer.metadata.refresh-runs-before-the-syscall-returns" },
    function(t)
        local lfd = lcs.create_layer(src, w, "refresh-timing")
        t:assert(lfd, "a layer at precedence 0")
        t:assert_eq(winner(t, "RefreshBefore", "refresh-timing", "tier1"), "tier1",
            "which loses to precedence 1")
        local guid = src:lookup(layer_path("refresh-timing"))
        local mark = src:mark()
        local s = lcs.set_value(src, w, lfd, "Precedence", lcs.TYPE.DWORD, lcs.dword(4))
        t:assert_eq(s.ret, 0, "raising its precedence: " .. sys.errname(s.errno or 0))
        t:assert(#src:served(lcs.OP.QUERY_VALUES, mark, guid) >= 1,
            "the refresh read the committed metadata key inside the syscall")
        t:assert_eq(winner(t, "RefreshAfter", "refresh-timing", "tier1"), "refresh-timing",
            "and the new entry is published by the time the syscall returns — nothing " ..
            "has to be waited for")
        sys.close(w, lfd)
    end)

test("for a transaction the refresh runs once, after the source commit and before REG_IOC_COMMIT returns",
    { spec = "PKM *layer.metadata.transaction-refresh-runs-once-before-commit-returns" },
    function(t)
        local fd = subkey(t, "TxnRefresh")

        --- Create a layer in one transaction, writing `values` metadata
        --- values into it. Returns how many times the refresh read the
        --- metadata key after the commit began.
        local function create_in_transaction(name, values)
            local txn = assert(lcs.begin_transaction(w))
            local c = lcs.create_key(src, w, { path = layer_path(name), txn_fd = txn })
            t:assert(c.ret >= 0, "the metadata key is created in the transaction: " ..
                sys.errname(c.errno or 0))
            for _, v in ipairs(values) do
                local s = lcs.set_value(src, w, c.ret, v[1], v[2], v[3], { txn_fd = txn })
                t:assert_eq(s.ret, 0, "with " .. v[1] .. ": " .. sys.errname(s.errno or 0))
            end
            t:assert(not usable(name, fd),
                "nothing is published while the transaction is uncommitted")
            local mark = src:mark()
            local cm = lcs.commit(src, w, txn)
            t:assert_eq(cm.ret, 0, "commit: " .. sys.errname(cm.errno or 0))
            sys.close(w, txn)
            sys.close(w, c.ret)
            t:assert(usable(name, fd),
                "and the layer is published by the time REG_IOC_COMMIT returns")
            return #src:served(lcs.OP.QUERY_VALUES, mark, src:lookup(layer_path(name)))
        end

        local few = create_in_transaction("txn-refresh-few", {
            { "Precedence", lcs.TYPE.DWORD, lcs.dword(0) },
            { "Enabled", lcs.TYPE.DWORD, lcs.dword(1) },
        })
        local many = create_in_transaction("txn-refresh-many", {
            { "Precedence", lcs.TYPE.DWORD, lcs.dword(0) },
            { "Enabled", lcs.TYPE.DWORD, lcs.dword(1) },
            { "Owner", lcs.TYPE.BINARY, token.SID.TEST_USER },
            { "Enabled", lcs.TYPE.DWORD, lcs.dword(1) },
            { "Precedence", lcs.TYPE.DWORD, lcs.dword(0) },
        })
        t:assert(few > 0, "the refresh reads the committed metadata key")
        t:assert_eq(many, few,
            "once for the transaction, not once per operation its mutation log holds")
        sys.close(w, fd)
    end)

test("LCS performs no source round trips while holding the watch-map or layer-table publication locks",
    { spec = "PKM *layer.metadata.no-source-round-trips-under-publication-locks",
      covered_by = "kunit:pkm_lcs_kunit_misc",
      skip = "a lock discipline has no guest-visible signature — the same requests are " ..
             "issued either way; runs under " ..
             "pkm_lcs_kunit_internal_layer_watch_value_event_refreshes_metadata" },
    function(t) end)

test("an unparseable metadata descriptor keeps the previous entry and fails the operation with EIO",
    { spec = "PKM *layer.metadata.unparseable-descriptor-keeps-previous-entry" },
    function(t)
        local fd = subkey(t, "Unparseable")
        t:assert(usable("keeper", fd), "the layer is published and usable")
        local guid = src:lookup(layer_path("keeper"))
        src:intercept(lcs.OP.READ_KEY, function(self, req)
            if req.payload:sub(1, 16) == guid then
                local k = self.store.keys[guid]
                return lcs.STATUS.OK, string.pack("<s4", k.name) .. k.parent ..
                    string.pack("<s4", "not a descriptor") ..
                    string.pack("<I1I1i8", 0, 0, 0)
            end
            return nil
        end)
        local mfd = open(t, layer_path("keeper"), lcs.KEY_ALL_ACCESS)
        local s
        local events = kmes.recording(t, vm, function()
            s = lcs.set_value(src, w, mfd, "Enabled", lcs.TYPE.DWORD, lcs.dword(1))
        end)
        src:intercept(lcs.OP.READ_KEY, nil)
        sys.close(w, mfd)
        t:assert_eq(s.errno, sys.E.IO,
            "the refresh was required to complete the operation, so the syscall fails")
        t:assert(#kmes.of_type(events, "LCS_SOURCE_VALIDATION_FAILURE") >= 1,
            "LCS emits an audit event for the malformed source data")
        t:assert(usable("keeper", fd),
            "and keeps the previous known-good entry rather than dropping the layer")
        sys.close(w, fd)
    end)

test("a refresh failure that the operation in hand needed is EIO",
    { spec = "PKM *layer.metadata.required-refresh-failure-is-eio" },
    function(t)
        -- Creating a layer needs the refresh to complete; a metadata
        -- value that will not validate makes it fail, and the syscall
        -- reports EIO rather than leaving a half-made layer behind.
        local mfd = open(t, layer_path("keeper"), lcs.KEY_ALL_ACCESS)
        local s = lcs.set_value(src, w, mfd, "Enabled", lcs.TYPE.SZ, lcs.sz("yes"))
        t:assert_eq(s.errno, sys.E.IO, "EIO, not EINVAL: the source's data is what is wrong")
        sys.close(w, mfd)
    end)
