-- PKM §5.3.4 — Writing into a layer: layer write authorization, the
-- base layer before its metadata key exists, the precedence gate, and
-- what deleting a layer's metadata key does.
--
-- Order matters at the top of this file: the two cases about the base
-- layer *before* `Layers\base` exists must run before the case that
-- creates it. Everything after that is order-independent.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")
local token = require("helpers.token")
local kacs = require("helpers.kacs")
local access = require("helpers.access")

local vm = provium:vm("v", "kernel-only"):boot()

local CI = access.ACE_FLAG.CONTAINER_INHERIT
local R = lcs.RIGHT
local TEST_PATH = "Machine\\Software\\Test"
local BASE_KEY_PATH = lcs.LAYERS_PATH .. "\\base"

-- The Machine hive root, and every component down to `Layers`, carry
-- one descriptor, so what a live-created layer metadata key inherits is
-- unambiguously the Machine hive root's. TEST_USER_2 is denied; Everyone
-- gets everything except the right to create a subkey, which only
-- TEST_USER and SYSTEM hold.
local OTHER_USER = token.sid(5, 21, 1000, 2000, 3000, 1103)
local EVERYONE_MASK = R.KEY_ALL_ACCESS & ~R.CREATE_SUB_KEY
local ROOT_SD = lcs.sd({
    access.ace(access.ACE.DENIED, R.KEY_ALL_ACCESS, token.SID.TEST_USER_2, CI),
    access.ace(access.ACE.ALLOWED, R.KEY_ALL_ACCESS, kacs.SID.LOCAL_SYSTEM, CI),
    access.ace(access.ACE.ALLOWED, R.KEY_ALL_ACCESS, token.SID.TEST_USER, CI),
    access.ace(access.ACE.ALLOWED, EVERYONE_MASK, kacs.SID.EVERYONE, CI),
})

local src = lcs.source(vm, { hives = { { name = "Machine", sd = ROOT_SD } } })
local TEST_KEY = src:key(TEST_PATH)                       -- permissive: Everyone all rights
src:key("Machine\\System", { sd = ROOT_SD })
src:key("Machine\\System\\Registry", { sd = ROOT_SD })
src:key(lcs.LAYERS_PATH, { sd = ROOT_SD })
-- A layer whose metadata key nobody but SYSTEM may write into, and one
-- open to everybody. Both at precedence 0.
local LOCKED_SD = lcs.sd({
    access.ace(access.ACE.ALLOWED, R.KEY_ALL_ACCESS, kacs.SID.LOCAL_SYSTEM, CI),
    access.ace(access.ACE.ALLOWED, R.KEY_READ, kacs.SID.EVERYONE, CI),
})
src:key(lcs.LAYERS_PATH .. "\\locked", { sd = LOCKED_SD })
src:seed_layer("locked")
src:seed_layer("open")
src:seed_layer("tier2", { precedence = 2 })
src:seed_layer("slippery")
src:value(TEST_KEY, "Locked", lcs.TYPE.SZ, lcs.sz("locked"), { layer = "locked" })
assert(src:register())
src:pump()

local w = vm:spawn_worker()

local function open(t, path, access_mask, who)
    local r = lcs.open_key(src, who or w, -1, path, access_mask or lcs.KEY_ALL_ACCESS)
    t:assert(r.ret >= 0, "open " .. path .. ": " .. sys.errname(r.errno or 0))
    return r.ret
end

--- A fresh subkey of the test key, so cases do not share a value set.
local function subkey(t, name, who)
    local root = open(t, TEST_PATH, lcs.KEY_ALL_ACCESS, who)
    local c = lcs.create_key(src, who or w, { parent_fd = root, path = name })
    t:assert(c.ret >= 0, "a fresh subkey: " .. sys.errname(c.errno or 0))
    sys.close(who or w, root)
    return c.ret
end

--- Run `fn(w2)` as an unprivileged principal — no privileges at all,
--- so nothing it does can be explained by SeTcbPrivilege.
local function unprivileged(t, fn, spec)
    spec = spec or {}
    spec.privs_present, spec.privs_enabled = 0, 0
    token.as_principal(t, vm, spec, fn)
end

test("before Layers\\base exists, base-layer writes fall back to a compiled-in descriptor",
    { spec = "PKM *layer.authz.base-falls-back-to-a-compiled-in-descriptor" },
    function(t)
        local probe = lcs.open_key(src, w, -1, BASE_KEY_PATH, R.KEY_READ)
        t:assert_eq(probe.errno, sys.E.NOENT,
            "this case must run before the one that creates Layers\\base")
        -- SYSTEM writes into the base layer from the very beginning.
        local fd = subkey(t, "Fallback")
        local s = lcs.set_value(src, w, fd, "V", lcs.TYPE.DWORD, lcs.dword(1))
        t:assert_eq(s.ret, 0,
            "the compiled-in default grants SYSTEM KEY_ALL_ACCESS: " .. sys.errname(s.errno or 0))
        sys.close(w, fd)
        -- An ordinary user is not SYSTEM and not an Administrator, and
        -- its fd mask on the target key is complete, so the only thing
        -- that can refuse it is the base layer's descriptor.
        unprivileged(t, function(w2)
            local kfd = open(t, TEST_PATH, lcs.KEY_ALL_ACCESS, w2)
            local d = lcs.set_value(src, w2, kfd, "Denied", lcs.TYPE.DWORD, lcs.dword(1))
            t:assert_eq(d.errno, sys.E.ACCES,
                "and grants nothing to anyone else, even with a full mask on the target key")
            sys.close(w2, kfd)
        end)
    end)

test("the compiled-in fallback is replaced the moment the metadata key is created",
    { spec = "PKM *layer.authz.base-fallback-replaced-at-seed-restore" },
    function(t)
        -- Seed restore creates `Layers\base` by ordinary key creation;
        -- a kernel-only guest has no seed restore, so this creates it
        -- the same way a restore would.
        local created = lcs.create_key(src, w, { path = BASE_KEY_PATH })
        t:assert(created.ret >= 0, "Layers\\base is created: " .. sys.errname(created.errno or 0))
        t:assert_eq(created.disposition, lcs.CREATED_NEW, "for the first time")
        sys.close(w, created.ret)
        unprivileged(t, function(w2)
            local kfd = open(t, TEST_PATH, lcs.KEY_ALL_ACCESS, w2)
            local s = lcs.set_value(src, w2, kfd, "NowAllowed", lcs.TYPE.DWORD, lcs.dword(1))
            t:assert_eq(s.ret, 0,
                "the persisted descriptor has replaced the compiled-in default: " ..
                sys.errname(s.errno or 0))
            sys.close(w2, kfd)
        end)
    end)

test("the base layer's descriptor is the one inheritance computes from the Machine hive root",
    { spec = "PKM *layer.authz.base-descriptor-inherits-from-the-machine-root" },
    function(t)
        local bfd = open(t, BASE_KEY_PATH, R.READ_CONTROL)
        local g = lcs.get_security(src, w, bfd, lcs.SI.OWNER | lcs.SI.GROUP | lcs.SI.DACL)
        t:assert_eq(g.ret, 0, "the metadata key carries a descriptor: " .. sys.errname(g.errno or 0))
        sys.close(w, bfd)
        -- The Machine root's inheritable ACEs are the only source of
        -- what `Layers\base` grants: the principal the root denies is
        -- refused a base-layer write, and the one it allows is not.
        unprivileged(t, function(w2)
            local kfd = open(t, TEST_PATH, lcs.KEY_ALL_ACCESS, w2)
            local s = lcs.set_value(src, w2, kfd, "FromRoot", lcs.TYPE.DWORD, lcs.dword(1))
            t:assert_eq(s.ret, 0, "the root's inheritable allow reaches the base layer: " ..
                sys.errname(s.errno or 0))
            sys.close(w2, kfd)
        end)
        unprivileged(t, function(w2)
            local kfd = open(t, TEST_PATH, lcs.KEY_ALL_ACCESS, w2)
            local s = lcs.set_value(src, w2, kfd, "DeniedByRoot", lcs.TYPE.DWORD, lcs.dword(1))
            t:assert_eq(s.errno, sys.E.ACCES, "and so does its inheritable deny")
            sys.close(w2, kfd)
        end, { user_sid = token.SID.TEST_USER_2 })
    end)

test("every mutation targeting a layer requires KEY_SET_VALUE on the layer's metadata key",
    { spec = "PKM *layer.authz.write-requires-key-set-value-on-metadata-key" },
    function(t)
        unprivileged(t, function(w2)
            local fd = subkey(t, "LayerWrite", w2)
            local denied = {
                { "a value write", function()
                    return lcs.set_value(src, w2, fd, "V", lcs.TYPE.DWORD, lcs.dword(1),
                        { layer = "locked" }) end },
                { "a value deletion", function()
                    return lcs.delete_value(src, w2, fd, "Locked", { layer = "locked" }) end },
                { "a blanket tombstone", function()
                    return lcs.blanket_tombstone(src, w2, fd, "locked", true) end },
                { "a key hide", function()
                    return lcs.hide_key(src, w2, fd, { layer = "locked" }) end },
            }
            for _, case in ipairs(denied) do
                local r = case[2]()
                t:assert_eq(r.errno, sys.E.ACCES,
                    case[1] .. " into a layer whose metadata key denies KEY_SET_VALUE")
            end
            local created = lcs.create_key(src, w2,
                { parent_fd = fd, path = "Child", layer = "locked" })
            t:assert_eq(created.errno, sys.E.ACCES, "and so does key creation")
            -- The same operations into a layer that grants it succeed.
            local ok = lcs.set_value(src, w2, fd, "V", lcs.TYPE.DWORD, lcs.dword(1),
                { layer = "open" })
            t:assert_eq(ok.ret, 0, "a layer whose metadata key grants KEY_SET_VALUE allows it: " ..
                sys.errname(ok.errno or 0))
            sys.close(w2, fd)
        end)
    end)

test("layer write authorization is a second check, in addition to the fd's granted mask",
    { spec = "PKM *layer.authz.is-a-second-check-additional-to-the-fd-mask" },
    function(t)
        unprivileged(t, function(w2)
            -- A complete mask on the target key, refused by the layer.
            local full = subkey(t, "SecondCheck", w2)
            local a = lcs.set_value(src, w2, full, "V", lcs.TYPE.DWORD, lcs.dword(1),
                { layer = "locked" })
            t:assert_eq(a.errno, sys.E.ACCES,
                "the fd's mask is complete and the write is still refused, by the layer")
            sys.close(w2, full)
            -- A layer that grants everybody, refused by the fd's mask.
            local ro = lcs.open_key(src, w2, -1, TEST_PATH, R.KEY_READ)
            t:assert(ro.ret >= 0, "a read-only handle: " .. sys.errname(ro.errno or 0))
            local b = lcs.set_value(src, w2, ro.ret, "V", lcs.TYPE.DWORD, lcs.dword(1),
                { layer = "open" })
            t:assert_eq(b.errno, sys.E.ACCES,
                "the layer grants it and the write is still refused, by the fd's mask")
            sys.close(w2, ro.ret)
        end)
    end)

test("a layer that is not in the table is ENOENT for any operation naming it",
    { spec = "PKM *layer.authz.unknown-layer-is-enoent" },
    function(t)
        local fd = subkey(t, "UnknownLayer")
        local s = lcs.set_value(src, w, fd, "V", lcs.TYPE.DWORD, lcs.dword(1),
            { layer = "no-such-layer" })
        t:assert_eq(s.errno, sys.E.NOENT, "a value write naming it")
        local b = lcs.blanket_tombstone(src, w, fd, "no-such-layer", true)
        t:assert_eq(b.errno, sys.E.NOENT, "a blanket tombstone naming it")
        local h = lcs.hide_key(src, w, fd, { layer = "no-such-layer" })
        t:assert_eq(h.errno, sys.E.NOENT, "a key hide naming it")
        sys.close(w, fd)
    end)

test("creating a layer requires KEY_CREATE_SUB_KEY on the Layers key",
    { spec = "PKM *layer.authz.create-requires-create-sub-key" },
    function(t)
        unprivileged(t, function(w2)
            local fd, e = lcs.create_layer(src, w2, "unprivileged-cannot")
            t:assert(not fd, "a principal the Layers descriptor denies that right cannot")
            t:assert_eq(e, sys.E.ACCES, "the creation is refused")
        end, { user_sid = OTHER_USER })
        unprivileged(t, function(w2)
            local fd, e = lcs.create_layer(src, w2, "user-can")
            t:assert(fd, "and one it grants can, with no privilege at all: " ..
                sys.errname(e or 0))
            if fd then sys.close(w2, fd) end
        end, { user_sid = token.SID.TEST_USER })
    end)

test("modifying layer metadata requires KEY_SET_VALUE on the metadata key",
    { spec = "PKM *layer.authz.modify-metadata-requires-key-set-value" },
    function(t)
        unprivileged(t, function(w2)
            local read_only = lcs.open_key(src, w2, -1, lcs.LAYERS_PATH .. "\\locked", R.KEY_READ)
            t:assert(read_only.ret >= 0,
                "the locked layer's metadata key is readable: " .. sys.errname(read_only.errno or 0))
            sys.close(w2, read_only.ret)
            local want_write = lcs.open_key(src, w2, -1, lcs.LAYERS_PATH .. "\\locked",
                R.KEY_READ | R.SET_VALUE)
            t:assert_eq(want_write.errno, sys.E.ACCES,
                "but its descriptor does not grant KEY_SET_VALUE, so metadata cannot be modified")
            local open_fd = open(t, lcs.LAYERS_PATH .. "\\open", R.KEY_READ | R.SET_VALUE, w2)
            local s2 = lcs.set_value(src, w2, open_fd, "Enabled", lcs.TYPE.DWORD, lcs.dword(1))
            t:assert_eq(s2.ret, 0, "and a metadata key that grants it accepts the write: " ..
                sys.errname(s2.errno or 0))
            sys.close(w2, open_fd)
        end, { user_sid = OTHER_USER })
    end)

test("deleting a layer requires DELETE on the metadata key's fd",
    { spec = "PKM *layer.authz.delete-requires-delete-on-the-metadata-fd" },
    function(t)
        local fd = lcs.create_layer(src, w, "delete-rights")
        t:assert(fd, "a layer to delete")
        sys.close(w, fd)
        local no_delete = open(t, lcs.LAYERS_PATH .. "\\delete-rights", R.KEY_READ)
        local a = lcs.delete_key(src, w, no_delete)
        t:assert_eq(a.errno, sys.E.ACCES, "a handle without DELETE cannot delete it")
        sys.close(w, no_delete)
        local with_delete = open(t, lcs.LAYERS_PATH .. "\\delete-rights", R.DELETE)
        local b = lcs.delete_key(src, w, with_delete)
        t:assert_eq(b.ret, 0, "a handle with DELETE can: " .. sys.errname(b.errno or 0))
        sys.close(w, with_delete)
    end)

test("everything except the precedence rule is controlled purely by the metadata descriptor",
    { spec = "PKM *layer.authz.only-precedence-needs-a-privilege" },
    function(t)
        unprivileged(t, function(w2)
            local fd, e = lcs.create_layer(src, w2, "no-privilege-needed")
            t:assert(fd, "an unprivileged principal creates a layer: " .. sys.errname(e or 0))
            local s = lcs.set_value(src, w2, fd, "Enabled", lcs.TYPE.DWORD, lcs.dword(1))
            t:assert_eq(s.ret, 0, "modifies its metadata: " .. sys.errname(s.errno or 0))
            local kfd = subkey(t, "NoPrivilege", w2)
            local wv = lcs.set_value(src, w2, kfd, "V", lcs.TYPE.DWORD, lcs.dword(1),
                { layer = "no-privilege-needed" })
            t:assert_eq(wv.ret, 0, "writes into it: " .. sys.errname(wv.errno or 0))
            sys.close(w2, kfd)
            sys.close(w2, fd)
            local dfd = open(t, lcs.LAYERS_PATH .. "\\no-privilege-needed", R.DELETE, w2)
            local d = lcs.delete_key(src, w2, dfd)
            t:assert_eq(d.ret, 0, "and deletes it: " .. sys.errname(d.errno or 0))
            sys.close(w2, dfd)
        end, { user_sid = token.SID.TEST_USER })
    end)

test("raising a layer's precedence above 0 requires SeTcbPrivilege, and the denial is EPERM",
    { spec = "PKM *layer.authz.precedence-above-zero-requires-setcbprivilege" },
    function(t)
        local fd = lcs.create_layer(src, w, "raise-me")
        t:assert(fd, "a layer at precedence 0")
        sys.close(w, fd)
        unprivileged(t, function(w2)
            local mfd = open(t, lcs.LAYERS_PATH .. "\\raise-me", lcs.KEY_ALL_ACCESS, w2)
            local s = lcs.set_value(src, w2, mfd, "Precedence", lcs.TYPE.DWORD, lcs.dword(5))
            t:assert_eq(s.errno, sys.E.PERM,
                "compromising the descriptor on Layers is not enough to reach the " ..
                "Group Policy tier")
            sys.close(w2, mfd)
        end, { user_sid = token.SID.TEST_USER })
        local mfd = open(t, lcs.LAYERS_PATH .. "\\raise-me", lcs.KEY_ALL_ACCESS)
        local s = lcs.set_value(src, w, mfd, "Precedence", lcs.TYPE.DWORD, lcs.dword(5))
        t:assert_eq(s.ret, 0, "a caller holding SeTcbPrivilege may: " .. sys.errname(s.errno or 0))
        sys.close(w, mfd)
    end)

test("establishing a layer above precedence 0 requires SeTcbPrivilege",
    { spec = "PKM *layer.authz.precedence-above-zero-requires-setcbprivilege",
      tags = { "known-bug" } },
    function(t)
        -- KERNEL: the gate fires only when the target key GUID is
        -- already in the set of known layer metadata keys (§5.3.4). A
        -- layer created the way §5.3.3 prescribes — the metadata key and
        -- its three values in one transaction — writes `Precedence`
        -- before the key has ever been published, so the GUID is not in
        -- that set, the gate never runs, and the refresh at commit
        -- publishes the layer at precedence 5. An unprivileged principal
        -- reaches the Group Policy tier in one transaction.
        local note = ""
        unprivileged(t, function(w2)
            local fd, e = lcs.create_layer(src, w2, "escalated", { precedence = 5 })
            if fd then
                -- Confirm the layer really is above the tier boundary.
                local kfd = subkey(t, "Escalated", w2)
                lcs.set_value(src, w2, kfd, "V", lcs.TYPE.SZ, lcs.sz("tier2"), { layer = "tier2" })
                lcs.set_value(src, w2, kfd, "V", lcs.TYPE.SZ, lcs.sz("escalated"),
                    { layer = "escalated" })
                note = " and it resolves above precedence 2 as `" ..
                    lcs.query_value(src, w2, kfd, "V").layer .. "`"
                sys.close(w2, kfd)
                sys.close(w2, fd)
            end
            t:assert(not fd,
                "a principal without SeTcbPrivilege cannot establish a layer above " ..
                "precedence 0: " .. (fd and ("it created one" .. note) or sys.errname(e or 0)))
        end, { user_sid = token.SID.TEST_USER })
    end)

test("the precedence gate runs before sequence allocation and before the source is contacted",
    { spec = "PKM *layer.authz.precedence-gate-runs-before-sequence-and-dispatch" },
    function(t)
        local fd = lcs.create_layer(src, w, "gate-timing")
        t:assert(fd, "a layer at precedence 0")
        sys.close(w, fd)
        local kfd = subkey(t, "GateTiming")
        local before = lcs.set_value(src, w, kfd, "Probe", lcs.TYPE.DWORD, lcs.dword(1))
        t:assert_eq(before.ret, 0, "a write to bracket the gate: " .. sys.errname(before.errno or 0))
        local first = lcs.query_value(src, w, kfd, "Probe").sequence
        local mark = src:mark()
        unprivileged(t, function(w2)
            local mfd = open(t, lcs.LAYERS_PATH .. "\\gate-timing", lcs.KEY_ALL_ACCESS, w2)
            local s = lcs.set_value(src, w2, mfd, "Precedence", lcs.TYPE.DWORD, lcs.dword(7))
            t:assert_eq(s.errno, sys.E.PERM, "the refused write")
            sys.close(w2, mfd)
        end, { user_sid = token.SID.TEST_USER })
        t:assert_eq(#src:served(lcs.OP.SET_VALUE, mark), 0,
            "never reached the source")
        local after = lcs.set_value(src, w, kfd, "Probe2", lcs.TYPE.DWORD, lcs.dword(1))
        t:assert_eq(after.ret, 0, "set: " .. sys.errname(after.errno or 0))
        t:assert_eq(lcs.query_value(src, w, kfd, "Probe2").sequence, first + 1,
            "and took no sequence number: the gate is inline and early")
        sys.close(w, kfd)
    end)

test("the precedence gate runs on exactly three conditions",
    { spec = "PKM *layer.authz.precedence-gate-trigger-conditions" },
    function(t)
        local fd = lcs.create_layer(src, w, "trigger")
        t:assert(fd, "a layer to write metadata on")
        sys.close(w, fd)
        unprivileged(t, function(w2)
            local mfd = open(t, lcs.LAYERS_PATH .. "\\trigger", lcs.KEY_ALL_ACCESS, w2)
            -- The value name folds equal to `Precedence`.
            local folded = lcs.set_value(src, w2, mfd, "pReCeDeNcE", lcs.TYPE.DWORD, lcs.dword(4))
            t:assert_eq(folded.errno, sys.E.PERM,
                "the name is folded like every other value name, so a case variant fires it")
            local other = lcs.set_value(src, w2, mfd, "Precedency", lcs.TYPE.DWORD, lcs.dword(4))
            t:assert_eq(other.ret, 0, "a different name does not: " .. sys.errname(other.errno or 0))
            -- The data is a *positive* REG_DWORD.
            local zero = lcs.set_value(src, w2, mfd, "Precedence", lcs.TYPE.DWORD, lcs.dword(0))
            t:assert_eq(zero.ret, 0, "precedence 0 does not fire it: " .. sys.errname(zero.errno or 0))
            sys.close(w2, mfd)
            -- The target key GUID is in the set of known layer metadata keys.
            local kfd = subkey(t, "NotALayerKey", w2)
            local plain = lcs.set_value(src, w2, kfd, "Precedence", lcs.TYPE.DWORD, lcs.dword(9))
            t:assert_eq(plain.ret, 0,
                "and a `Precedence` value on a key that is not layer metadata is an " ..
                "ordinary write: " .. sys.errname(plain.errno or 0))
            sys.close(w2, kfd)
        end, { user_sid = token.SID.TEST_USER })
    end)

test("failing the precedence privilege check is EPERM",
    { spec = "PKM *layer.authz.precedence-gate-denial-is-eperm" },
    function(t)
        local fd = lcs.create_layer(src, w, "eperm")
        t:assert(fd, "a layer at precedence 0")
        sys.close(w, fd)
        unprivileged(t, function(w2)
            local mfd = open(t, lcs.LAYERS_PATH .. "\\eperm", lcs.KEY_ALL_ACCESS, w2)
            local s = lcs.set_value(src, w2, mfd, "Precedence", lcs.TYPE.DWORD, lcs.dword(3))
            t:assert_eq(s.errno, sys.E.PERM,
                "a privilege failure, not an access-control denial")
            t:assert(s.errno ~= sys.E.ACCES, "so it is not EACCES")
            sys.close(w2, mfd)
        end, { user_sid = token.SID.TEST_USER })
    end)

test("a Precedence written with some other type slips the gate and fails at the refresh",
    { spec = "PKM *layer.authz.non-dword-precedence-slips-the-gate-and-fails-at-refresh" },
    function(t)
        -- `slippery` is at precedence 0 and `tier2` at precedence 2, so
        -- a rise to 9 would be visible immediately.
        local kfd = subkey(t, "Slippery")
        local a = lcs.set_value(src, w, kfd, "V", lcs.TYPE.SZ, lcs.sz("slippery"),
            { layer = "slippery" })
        t:assert_eq(a.ret, 0, "a value in the layer: " .. sys.errname(a.errno or 0))
        local b = lcs.set_value(src, w, kfd, "V", lcs.TYPE.SZ, lcs.sz("tier2"), { layer = "tier2" })
        t:assert_eq(b.ret, 0, "and one in a higher tier: " .. sys.errname(b.errno or 0))
        t:assert_eq(lcs.query_value(src, w, kfd, "V").layer, "tier2", "which wins")
        unprivileged(t, function(w2)
            local mfd = open(t, lcs.LAYERS_PATH .. "\\slippery", lcs.KEY_ALL_ACCESS, w2)
            local s = lcs.set_value(src, w2, mfd, "Precedence", lcs.TYPE.SZ, lcs.sz("9"))
            t:assert(s.errno ~= sys.E.PERM,
                "the gate tests for a four-byte REG_DWORD, so this slips past it")
            t:assert_eq(s.errno, sys.E.IO,
                "and fails at the refresh, which rejects a non-REG_DWORD Precedence as " ..
                "malformed metadata")
            sys.close(w2, mfd)
        end, { user_sid = token.SID.TEST_USER })
        t:assert_eq(lcs.query_value(src, w, kfd, "V").layer, "tier2",
            "the precedence never actually rises")
        sys.close(w, kfd)
    end)

test("deleting the metadata key removes the layer from the table and broadcasts RSI_DELETE_LAYER",
    { spec = "PKM *layer.authz.deleting-the-metadata-key-removes-the-layer-from-the-table" },
    function(t)
        local lfd = lcs.create_layer(src, w, "doomed")
        t:assert(lfd, "a layer")
        sys.close(w, lfd)
        local kfd = subkey(t, "Doomed")
        local s = lcs.set_value(src, w, kfd, "V", lcs.TYPE.SZ, lcs.sz("doomed"),
            { layer = "doomed" })
        t:assert_eq(s.ret, 0, "with an entry in it: " .. sys.errname(s.errno or 0))
        t:assert_eq(lcs.query_value(src, w, kfd, "V").layer, "doomed", "which resolves")
        local mark = src:mark()
        local mfd = open(t, lcs.LAYERS_PATH .. "\\doomed", R.DELETE)
        local d = lcs.delete_key(src, w, mfd)
        t:assert_eq(d.ret, 0, "deleting the metadata key: " .. sys.errname(d.errno or 0))
        sys.close(w, mfd)
        t:assert(#src:served(lcs.OP.DELETE_LAYER, mark) >= 1,
            "broadcasts RSI_DELETE_LAYER to every registered source")
        local gone = lcs.set_value(src, w, kfd, "V2", lcs.TYPE.DWORD, lcs.dword(1),
            { layer = "doomed" })
        t:assert_eq(gone.errno, sys.E.NOENT, "and the layer is out of the table")
        local purged = lcs.query_value(src, w, kfd, "V")
        t:assert_eq(purged.errno, sys.E.NOENT,
            "each source having purged every entry tagged with that name")
        sys.close(w, kfd)
    end)
