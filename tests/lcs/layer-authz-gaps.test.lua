-- PKM §5.3.4 — the precedence gate keys on the path. A key is a layer
-- metadata key by being a direct child of Machine\System\Registry\Layers
-- or by already being published as one, and the path test is what
-- covers the recommended creation flow (§5.3.3): `Precedence` written
-- inside the transaction that creates the metadata key, before the
-- layer has been published at all.
--
-- The discriminating case is the gate firing on a key nothing has
-- published: inside an uncommitted transaction there is no layer, no
-- table entry and no watch event, so a refusal there can only have come
-- from the path. The other side of "direct child" is a deeper key under
-- Layers, where `Precedence` is an ordinary value.
--
-- Belongs in layer-authz.test.lua after "the precedence gate runs on
-- exactly three conditions". That file's "establishing a layer above
-- precedence 0 requires SeTcbPrivilege" drives the same flow through
-- lcs.create_layer.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")
local token = require("helpers.token")

local vm = provium:vm("v", "kernel-only"):boot()

local TEST = "Machine\\Software\\Test"

local src = lcs.source(vm)
src:key(lcs.LAYERS_PATH .. "\\base", { sd = lcs.permissive_sd() })
src:key(TEST)
-- A published layer with a key beneath its metadata key.
src:seed_layer("seeded")
src:key(lcs.LAYERS_PATH .. "\\seeded\\Sub")
assert(src:register())
src:pump()

local w = vm:spawn_worker()

--- Run `fn(w2)` as TEST_USER with no privileges at all, so nothing it
--- does can be explained by SeTcbPrivilege.
local function unprivileged(t, fn)
    token.as_principal(t, vm, {
        user_sid = token.SID.TEST_USER, privs_present = 0, privs_enabled = 0,
    }, fn)
end

test("the gate fires on a direct child of Layers that has not been published",
    { spec = "PKM *layer.authz.precedence-gate-keys-on-the-path" }, function(t)
        local NAME = "pathgated"
        unprivileged(t, function(w2)
            local txn = assert(lcs.begin_transaction(w2))
            local made = lcs.create_key(src, w2, {
                path = lcs.LAYERS_PATH .. "\\" .. NAME, txn_fd = txn,
            })
            t:assert(made.ret >= 0, "the metadata key is created in the transaction: "
                .. sys.errname(made.errno or 0))
            -- Nothing has published it: the key exists only inside an
            -- uncommitted transaction.
            local mark = src:mark()
            local sv = lcs.set_value(src, w2, made.ret, "Precedence", lcs.TYPE.DWORD,
                lcs.dword(5), { txn_fd = txn })
            t:assert(sv.ret ~= 0, "Precedence 5 on it is refused")
            t:assert_eq(sv.errno, sys.E.PERM,
                "with the gate's EPERM: " .. sys.errname(sv.errno or 0))
            t:assert_eq(#src:served(lcs.OP.SET_VALUE, mark), 0,
                "and the source never saw the write")
            -- Abandon the transaction.
            sys.close(w2, made.ret)
            sys.close(w2, txn)
        end)
        local gone = lcs.open_key(src, w, -1, lcs.LAYERS_PATH .. "\\" .. NAME, lcs.RIGHT.KEY_READ)
        t:assert_eq(gone.errno, sys.E.NOENT,
            "the transaction never committed, so no such key was ever outside it: "
            .. sys.errname(gone.errno or 0))
        local test_fd = lcs.open_key(src, w, -1, TEST, lcs.KEY_ALL_ACCESS)
        t:assert(test_fd.ret >= 0, "open the test key")
        local into = lcs.set_value(src, w, test_fd.ret, "V", lcs.TYPE.DWORD, lcs.dword(1),
            { layer = NAME })
        t:assert_eq(into.errno, sys.E.NOENT,
            "and no layer of that name was ever published: " .. sys.errname(into.errno or 0))
        sys.close(w, test_fd.ret)
    end)

test("the same flow at precedence 0, or with SeTcbPrivilege, is not refused",
    { spec = "PKM *layer.authz.precedence-gate-keys-on-the-path" }, function(t)
        -- The controls: the EPERM above is the precedence gate, not the
        -- create or the transaction.
        unprivileged(t, function(w2)
            local fd, e = lcs.create_layer(src, w2, "pathzero", { precedence = 0 })
            t:assert(fd, "an unprivileged caller creates a layer at precedence 0: "
                .. sys.errname(e or 0))
            if fd then sys.close(w2, fd) end
        end)
        local fd, e = lcs.create_layer(src, w, "pathtcb", { precedence = 5 })
        t:assert(fd, "SYSTEM, holding SeTcbPrivilege, creates one at precedence 5: "
            .. sys.errname(e or 0))
        if fd then sys.close(w, fd) end
    end)

test("a key deeper than a direct child of Layers is not layer metadata",
    { spec = "PKM *layer.authz.precedence-gate-keys-on-the-path" }, function(t)
        unprivileged(t, function(w2)
            local sub = lcs.open_key(src, w2, -1, lcs.LAYERS_PATH .. "\\seeded\\Sub",
                lcs.KEY_ALL_ACCESS)
            t:assert(sub.ret >= 0, "open a grandchild of Layers: " .. sys.errname(sub.errno or 0))
            local sv = lcs.set_value(src, w2, sub.ret, "Precedence", lcs.TYPE.DWORD, lcs.dword(9))
            t:assert_eq(sv.ret, 0,
                "Precedence 9 there is an ordinary value, not a gated one: "
                .. sys.errname(sv.errno or 0))
            sys.close(w2, sub.ret)

            -- The same, created inside a transaction alongside its parent.
            local txn = assert(lcs.begin_transaction(w2))
            local parent = lcs.create_key(src, w2, {
                path = lcs.LAYERS_PATH .. "\\deeptxn", txn_fd = txn,
            })
            t:assert(parent.ret >= 0, "a metadata key in a transaction: "
                .. sys.errname(parent.errno or 0))
            local child = lcs.create_key(src, w2, {
                parent_fd = parent.ret, path = "Below", txn_fd = txn,
            })
            t:assert(child.ret >= 0, "and a key beneath it: " .. sys.errname(child.errno or 0))
            local deep = lcs.set_value(src, w2, child.ret, "Precedence", lcs.TYPE.DWORD,
                lcs.dword(9), { txn_fd = txn })
            t:assert_eq(deep.ret, 0, "Precedence there is not gated either: "
                .. sys.errname(deep.errno or 0))
            sys.close(w2, child.ret); sys.close(w2, parent.ret); sys.close(w2, txn)
        end)
    end)
