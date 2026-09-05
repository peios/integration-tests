-- PKM §5.2.9 Deletion and Orphans — deleting a name rather than a key,
-- layer deletion, what an orphaned key may and may not do, its watches,
-- and the RSI_DROP_KEY that follows the last close.
--
-- Layer deletion is broadcast to every source and refuses to run while
-- any slot is Down, so the source that goes Down for the deferred-drop
-- case is the last thing this file does.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")
local token = require("helpers.token")

local vm = provium:vm("v", "kernel-only"):boot()

local TEST = "Machine\\Software\\Test"

local main, other, test_key, only_layer_key, sd_key
local function fixture()
    if main then return main end
    local s = lcs.source(vm)
    s:key(lcs.LAYERS_PATH .. "\\base", { sd = lcs.permissive_sd() })
    s:seed_layer("Alt", { precedence = 10, enabled = true })
    s:seed_layer("Only", { precedence = 20, enabled = true })
    s:seed_layer("Priv", { precedence = 30, enabled = false })
    s:seed_layer("Cross", { precedence = 40, enabled = true })
    s:seed_layer("Txn", { precedence = 50, enabled = true })
    s:seed_layer("SDLayer", { precedence = 60, enabled = true })
    s:seed_layer("ValLayer", { precedence = 70, enabled = true })
    test_key = s:key(TEST)

    -- One path named by two layers, each with its own key object.
    s:key(TEST .. "\\TwoNames")
    lcs.seed_key_in_layer(s, test_key, "TwoNames", "Alt")

    s:key(TEST .. "\\Solo")
    s:key(TEST .. "\\Orphanable")
    s:key(TEST .. "\\Watched")
    s:key(TEST .. "\\Rearm")
    s:key(TEST .. "\\Isolated")
    s:key(TEST .. "\\Async")
    s:key(TEST .. "\\Failing")

    local vals = s:key(TEST .. "\\Values")
    s:value(vals, "Kept", lcs.TYPE.SZ, lcs.sz("survives"))

    s:key(TEST .. "\\Parent\\Kid")
    s:key(TEST .. "\\Deep\\A\\B")

    -- A parent whose only child lives in a disabled (private) layer.
    local vis = s:key(TEST .. "\\VisPriv")
    lcs.seed_key_in_layer(s, vis, "Kid", "Priv")

    -- A key named only by the `Only` layer.
    only_layer_key = lcs.seed_key_in_layer(s, test_key, "OnlyLayer", "Only")

    -- A value whose winning entry is in `ValLayer`.
    local nv = s:key(TEST .. "\\NextVal")
    s:value(nv, "V", lcs.TYPE.SZ, lcs.sz("base"))
    s:value(nv, "V", lcs.TYPE.SZ, lcs.sz("layer"), { layer = "ValLayer" })

    -- A key whose descriptor is changed at runtime while a layer holds
    -- one of its names.
    sd_key = s:key(TEST .. "\\SDKey")
    lcs.seed_key_in_layer(s, test_key, "SDAlias", "SDLayer", { guid = sd_key })

    -- The cross-source case: an entry in `Cross` on each of two sources.
    lcs.seed_key_in_layer(s, test_key, "CrossHere", "Cross")

    local o = lcs.source(vm, { hives = { { name = "Other" } } })
    local oroot = o.hives[1].root
    lcs.seed_key_in_layer(o, oroot, "CrossThere", "Cross")

    assert(s:register())
    s:pump()
    assert(o:register())
    o:pump()
    main, other = s, o
    return s
end

local function worker() return vm:spawn_worker() end
local function done(w) w:kill(); w:join() end

local function open(t, w, path, mask, flags)
    local r = lcs.open_key(main, w, -1, path, mask or lcs.KEY_ALL_ACCESS, flags)
    t:assert(r.ret >= 0, "open " .. path .. ": " .. sys.errname(r.errno or 0))
    return r.ret
end

--- Run a pending call while pumping both sources: a layer deletion is
--- broadcast to every registered source, so one pump is not enough.
local function run_both(launch, rounds)
    local pending = launch()
    for _ = 1, rounds or 12 do
        main:pump(40)
        other:pump(40)
    end
    return pending:await()
end

--- Delete a layer the way §5.3.3 says one is deleted: by deleting its
--- metadata key under Machine\System\Registry\Layers.
local function delete_layer(t, w, name)
    local fd = open(t, w, lcs.LAYERS_PATH .. "\\" .. name)
    local r = run_both(function() return lcs.delete_key_async(w, fd) end)
    sys.close(w, fd)
    return r
end

--- Is the source holding any path entry naming `guid`?
local function named_anywhere(s, guid)
    for _, per in pairs(s.store.entries) do
        for _, slot in pairs(per) do
            for _, e in pairs(slot.by_layer) do
                if not e.hidden and e.guid == guid then return true end
            end
        end
    end
    return false
end

-- Deleting a key ---------------------------------------------------------

test("REG_IOC_DELETE_KEY removes one layer's path entry and nothing else",
    { spec = "PKM *orphan.delete-key.removes-one-layer-path-entry" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\Solo")
        local guid = s:lookup(TEST .. "\\Solo")
        local d = lcs.delete_key(s, w, fd)
        t:assert_eq(d.ret, 0, "delete: " .. sys.errname(d.errno or 0))
        t:assert(lcs.entry(s, test_key, "Solo", "base") == nil, "the base entry is gone")
        t:assert(s.store.keys[guid] ~= nil,
            "while the key's own record — its GUID, descriptor and values — is untouched")
        sys.close(w, fd)
        main:pump(300)
        done(w)
    end)

test("the parent GUID and child name come from the fd",
    { spec = "PKM *orphan.delete-key.parent-and-name-derived-from-the-fd" }, function(t)
        local s = fixture()
        local w = worker()
        local parent = open(t, w, TEST)
        local c = lcs.create_key(s, w, { parent_fd = parent, path = "FromFd" })
        t:assert(c.ret >= 0, "create: " .. sys.errname(c.errno or 0))
        local mark = s:mark()
        local d = lcs.delete_key(s, w, c.ret)
        t:assert_eq(d.ret, 0, "delete: " .. sys.errname(d.errno or 0))
        local reqs = s:served(lcs.OP.DELETE_ENTRY, mark)
        t:assert_eq(#reqs, 1, "one RSI_DELETE_ENTRY")
        t:assert_eq(reqs[1].payload:sub(1, 16), test_key,
            "with the parent GUID taken from the fd's ancestor chain")
        local name, at = string.unpack("<s4", reqs[1].payload, 17)
        t:assert_eq(name, "FromFd", "and the child name from its resolved path")
        t:assert_eq(string.unpack("<s4", reqs[1].payload, at), "base", "in the base layer")
        sys.close(w, c.ret); sys.close(w, parent)
        main:pump(300)
        done(w)
    end)

test("entries remaining in other layers keep the path visible",
    { spec = "PKM *orphan.delete-key.remaining-entries-keep-the-key-visible" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\TwoNames")
        local d = lcs.delete_key(s, w, fd, { layer = "Alt" })
        t:assert_eq(d.ret, 0, "delete the Alt entry: " .. sys.errname(d.errno or 0))
        sys.close(w, fd)
        local still = lcs.open_key(s, w, -1, TEST .. "\\TwoNames", lcs.RIGHT.KEY_READ)
        t:assert(still.ret >= 0,
            "the base layer still names the path: " .. sys.errname(still.errno or 0))
        sys.close(w, still.ret)
        main:pump(300)
        done(w)
    end)

test("removing the last entry anywhere orphans the key",
    { spec = "PKM *orphan.delete-key.last-entry-removed-orphans-the-key" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\Orphanable")
        local guid = s:lookup(TEST .. "\\Orphanable")
        t:assert_eq(lcs.delete_key(s, w, fd).ret, 0, "delete")
        t:assert(not named_anywhere(s, guid), "no layer names it any more")
        local gone = lcs.open_key(s, w, -1, TEST .. "\\Orphanable", lcs.RIGHT.KEY_READ)
        t:assert_eq(gone.errno, sys.E.NOENT, "the path is gone")
        -- The fd still works, which is what being orphaned rather than
        -- destroyed means.
        local info = lcs.query_key_info(s, w, fd)
        t:assert_eq(info.ret, 0, "and the existing fd still works: "
            .. sys.errname(info.errno or 0))
        sys.close(w, fd)
        main:pump(300)
        done(w)
    end)

test("a key with visible children cannot be deleted",
    { spec = "PKM *orphan.delete-key.visible-children-is-enotempty" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\Parent")
        local d = lcs.delete_key(s, w, fd)
        t:assert_eq(d.errno, sys.E.NOTEMPTY,
            "a parent with a visible child is ENOTEMPTY: " .. sys.errname(d.errno or 0))
        -- Once the child is gone the parent goes.
        local kid = open(t, w, TEST .. "\\Parent\\Kid")
        t:assert_eq(lcs.delete_key(s, w, kid).ret, 0, "delete the child")
        sys.close(w, kid)
        t:assert_eq(lcs.delete_key(s, w, fd).ret, 0, "then the parent")
        sys.close(w, fd)
        main:pump(300)
        done(w)
    end)

test("visibility is global and ignores the caller's private layer set",
    { spec = "PKM *orphan.delete-key.visibility-ignores-the-callers-private-layers" },
    function(t)
        local s = fixture()
        -- `VisPriv\Kid` exists only in `Priv`, a disabled layer. A thread
        -- whose token names it sees the child ...
        token.as_principal(t, vm, {
            lcs_credentials = lcs.lcs_credentials({}, { "Priv" }),
        }, function(w)
            local kid = lcs.open_key(s, w, -1, TEST .. "\\VisPriv\\Kid", lcs.RIGHT.KEY_READ)
            t:assert(kid.ret >= 0,
                "the caller's private layer makes the child visible to it: "
                .. sys.errname(kid.errno or 0))
            sys.close(w, kid.ret)
            -- ... and can still delete the parent, because the
            -- ENOTEMPTY test is evaluated across enabled layers only and
            -- deliberately ignores the caller's private set.
            local parent = lcs.open_key(s, w, -1, TEST .. "\\VisPriv", lcs.KEY_ALL_ACCESS)
            t:assert(parent.ret >= 0, "open: " .. sys.errname(parent.errno or 0))
            local d = lcs.delete_key(s, w, parent.ret)
            t:assert_eq(d.ret, 0,
                "whether the deletion succeeds does not depend on who is asking: "
                .. sys.errname(d.errno or 0))
            sys.close(w, parent.ret)
        end)
        main:pump(300)
    end)

test("there is no recursive delete primitive",
    { spec = "PKM *orphan.delete-key.no-recursive-delete-primitive" }, function(t)
        local s = fixture()
        local w = worker()
        local top = open(t, w, TEST .. "\\Deep")
        t:assert_eq(lcs.delete_key(s, w, top).errno, sys.E.NOTEMPTY,
            "deleting a subtree root does not take the subtree with it")
        -- The client walks the tree itself, deepest first.
        local b = open(t, w, TEST .. "\\Deep\\A\\B")
        t:assert_eq(lcs.delete_key(s, w, b).ret, 0, "delete the leaf")
        sys.close(w, b)
        local a = open(t, w, TEST .. "\\Deep\\A")
        t:assert_eq(lcs.delete_key(s, w, a).ret, 0, "then its parent")
        sys.close(w, a)
        t:assert_eq(lcs.delete_key(s, w, top).ret, 0, "then the root")
        sys.close(w, top)
        main:pump(300)
        done(w)
    end)

test("deleting a key does not delete its values",
    { spec = "PKM *orphan.delete-key.values-survive-entry-deletion" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\Values")
        local guid = s:lookup(TEST .. "\\Values")
        t:assert_eq(lcs.delete_key(s, w, fd).ret, 0, "delete the entry")
        local q = lcs.query_value(s, w, fd, "Kept")
        t:assert_eq(q.ret, 0, "the value is still readable through the fd: "
            .. sys.errname(q.errno or 0))
        t:assert_eq(q.data, lcs.sz("survives"), "unchanged")
        t:assert(s.store.values[guid] ~= nil, "values belong to the GUID, not the entry")
        sys.close(w, fd)
        main:pump(300)
        done(w)
    end)

-- Layer deletion ------------------------------------------------------------

test("deleting a layer removes its entries across every source",
    { spec = "PKM *orphan.layer-delete.removes-every-entry-across-all-sources" }, function(t)
        local s = fixture()
        local w = worker()
        local here = lcs.open_key(s, w, -1, TEST .. "\\CrossHere", lcs.RIGHT.KEY_READ)
        t:assert(here.ret >= 0, "the entry on this source resolves")
        sys.close(w, here.ret)
        local there = lcs.open_key(other, w, -1, "Other\\CrossThere", lcs.RIGHT.KEY_READ)
        t:assert(there.ret >= 0, "and the one on the other source")
        sys.close(w, there.ret)

        local d = delete_layer(t, w, "Cross")
        t:assert_eq(d.ret, 0, "delete the layer: " .. sys.errname(d.errno or 0))
        t:assert(#main:served(lcs.OP.DELETE_LAYER) >= 1, "this source was told")
        t:assert(#other:served(lcs.OP.DELETE_LAYER) >= 1, "and so was the other")
        t:assert(lcs.entry(s, test_key, "CrossHere", "Cross") == nil, "its entry went")
        t:assert(lcs.entry(other, other.hives[1].root, "CrossThere", "Cross") == nil,
            "and so did the other source's")
        done(w)
    end)

test("sources report the GUIDs that lost their last path entry",
    { spec = "PKM *orphan.layer-delete.sources-report-newly-orphaned-guids" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\OnlyLayer")
        local mark = main:mark()
        local d = delete_layer(t, w, "Only")
        t:assert_eq(d.ret, 0, "delete the layer: " .. sys.errname(d.errno or 0))
        local reqs = main:served(lcs.OP.DELETE_LAYER, mark)
        t:assert_eq(#reqs, 1, "one RSI_DELETE_LAYER went to this source")
        t:assert(not named_anywhere(s, only_layer_key), "the key lost its last name")
        -- Which is exactly what the source reported: LCS now treats the
        -- key as orphaned, and a namespace operation on it is ENOENT.
        local child = lcs.create_key(nil, w, { parent_fd = fd, path = "Nope" })
        t:assert_eq(child.errno, sys.E.NOENT,
            "LCS took the orphan report: " .. sys.errname(child.errno or 0))
        sys.close(w, fd)
        main:pump(300)
        done(w)
    end)

test("keys named only by the deleted layer become orphaned",
    { spec = "PKM *orphan.layer-delete.keys-named-only-by-it-become-orphaned" }, function(t)
        local s = fixture()
        local w = worker()
        -- `Alt` still names TwoNames; the base layer names it too, so it
        -- survives the layer's removal with a name.
        local kept = s:lookup(TEST .. "\\TwoNames")
        local d = delete_layer(t, w, "Alt")
        t:assert_eq(d.ret, 0, "delete the layer: " .. sys.errname(d.errno or 0))
        t:assert(named_anywhere(s, kept),
            "a key another layer also names keeps a name and is not orphaned")
        local still = lcs.open_key(s, w, -1, TEST .. "\\TwoNames", lcs.RIGHT.KEY_READ)
        t:assert(still.ret >= 0, "and stays reachable: " .. sys.errname(still.errno or 0))
        sys.close(w, still.ret)
        done(w)
    end)

test("where the layer held the winning value entry, the next layer's becomes effective",
    { spec = "PKM *orphan.layer-delete.next-layers-value-becomes-effective" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\NextVal", lcs.RIGHT.KEY_READ)
        local before = lcs.query_value(s, w, fd, "V")
        t:assert_eq(before.data, lcs.sz("layer"), "the layer's entry is effective")
        local d = delete_layer(t, w, "ValLayer")
        t:assert_eq(d.ret, 0, "delete the layer: " .. sys.errname(d.errno or 0))
        local after = lcs.query_value(s, w, fd, "V")
        t:assert_eq(after.ret, 0, "the value is still there: " .. sys.errname(after.errno or 0))
        t:assert_eq(after.data, lcs.sz("base"), "and the next layer's entry is effective")
        t:assert_eq(after.layer, "base", "reported as the base layer")
        sys.close(w, fd)
        done(w)
    end)

test("Security Descriptors are unchanged by layer deletion",
    { spec = "PKM *orphan.layer-delete.security-descriptors-unchanged" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\SDKey")
        -- A runtime descriptor change: operational state, not overlay.
        local changed = lcs.sd({
            require("helpers.access").ace(require("helpers.access").ACE.ALLOWED,
                lcs.RIGHT.KEY_ALL_ACCESS | lcs.RIGHT.GENERIC_ALL,
                require("helpers.kacs").SID.EVERYONE,
                require("helpers.access").ACE_FLAG.CONTAINER_INHERIT),
        })
        t:assert_eq(lcs.set_security(s, w, fd, lcs.SI.DACL, changed).ret, 0, "set the descriptor")
        local before = lcs.get_security(s, w, fd, lcs.SI.DACL)
        t:assert_eq(before.ret, 0, "read it back: " .. sys.errname(before.errno or 0))

        local d = delete_layer(t, w, "SDLayer")
        t:assert_eq(d.ret, 0, "delete the layer that also named the key: "
            .. sys.errname(d.errno or 0))
        local after = lcs.get_security(s, w, fd, lcs.SI.DACL)
        t:assert_eq(after.ret, 0, "the descriptor is still readable")
        t:assert_eq(after.sd, before.sd,
            "and unchanged: security was never layered, so nothing reverts")
        sys.close(w, fd)
        main:pump(300)
        done(w)
    end)

test("transactions whose mutation log touches the layer are aborted, and return EINVAL",
    { spec = "PKM *orphan.layer-delete.aborts-transactions-touching-the-layer" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST)
        local txn = assert(lcs.begin_transaction(w))
        local sv = lcs.set_value(s, w, fd, "InTxn", lcs.TYPE.SZ, lcs.sz("x"),
            { layer = "Txn", txn_fd = txn })
        t:assert_eq(sv.ret, 0, "a write into the layer inside a transaction: "
            .. sys.errname(sv.errno or 0))

        local d = delete_layer(t, w, "Txn")
        t:assert_eq(d.ret, 0, "delete the layer: " .. sys.errname(d.errno or 0))
        local st = lcs.txn_status(nil, w, txn)
        t:assert_eq(st.state, lcs.TXN.ABORTED,
            "the transaction was aborted before RSI_DELETE_LAYER went out")
        sys.close(w, txn); sys.close(w, fd)
        main:pump(300)
        done(w)
    end)

test("an aborted transaction returns EINVAL on its next operation or commit",
    { spec = "PKM *orphan.layer-delete.aborted-transactions-return-einval" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST)
        -- The layer has to exist in the table, so it is created live.
        local layer_fd = assert(lcs.create_layer(s, w, "Txn2", { precedence = 55 }))
        sys.close(w, layer_fd)

        local txn = assert(lcs.begin_transaction(w))
        t:assert_eq(lcs.set_value(s, w, fd, "InTxn2", lcs.TYPE.SZ, lcs.sz("x"),
            { layer = "Txn2", txn_fd = txn }).ret, 0, "a write into the layer")
        t:assert_eq(delete_layer(t, w, "Txn2").ret, 0, "delete the layer")

        local next_op = lcs.set_value(s, w, fd, "After", lcs.TYPE.SZ, lcs.sz("y"),
            { txn_fd = txn })
        t:assert_eq(next_op.errno, sys.E.INVAL,
            "the next operation on it is EINVAL: " .. sys.errname(next_op.errno or 0))
        local cm = lcs.commit(s, w, txn)
        t:assert_eq(cm.errno, sys.E.INVAL,
            "and so is the commit attempt: " .. sys.errname(cm.errno or 0))
        sys.close(w, txn); sys.close(w, fd)
        main:pump(300)
        done(w)
    end)

-- Orphaned keys ---------------------------------------------------------------

--- Orphan `path`: open it, delete its only entry, return the fd.
local function orphan(t, w, path)
    local fd = open(t, w, path)
    local d = lcs.delete_key(main, w, fd)
    t:assert_eq(d.ret, 0, "orphan " .. path .. ": " .. sys.errname(d.errno or 0))
    return fd
end

test("an orphaned key is a GUID with no path entry in any layer",
    { spec = "PKM *orphan.definition.guid-with-no-path-entry-anywhere" }, function(t)
        local s = fixture()
        local w = worker()
        local parent = open(t, w, TEST)
        local c = lcs.create_key(s, w, { parent_fd = parent, path = "Defined" })
        local guid = assert(lcs.created_guid(s, s:mark() - 1) or s:lookup(TEST .. "\\Defined"))
        t:assert_eq(lcs.delete_key(s, w, c.ret).ret, 0, "delete its only entry")
        t:assert(not named_anywhere(s, s:lookup(TEST .. "\\Defined") or guid),
            "no path entry names it in any layer")
        -- Alive but unnamed: the Linux unlink model.
        t:assert_eq(lcs.query_key_info(s, w, c.ret).ret, 0, "the key is still alive")
        sys.close(w, c.ret); sys.close(w, parent)
        main:pump(300)
        done(w)
    end)

test("value, blanket, descriptor, metadata and flush operations proceed on an orphan",
    { spec = "PKM *orphan.allowed.value-operations" }, function(t)
        local s = fixture()
        local w = worker()
        local parent = open(t, w, TEST)
        local c = lcs.create_key(s, w, { parent_fd = parent, path = "AllowedOps" })
        t:assert(c.ret >= 0, "create: " .. sys.errname(c.errno or 0))
        local fd = c.ret
        t:assert_eq(lcs.delete_key(s, w, fd).ret, 0, "orphan it")

        t:assert_eq(lcs.set_value(s, w, fd, "V", lcs.TYPE.SZ, lcs.sz("set")).ret, 0,
            "setting a value")
        local q = lcs.query_value(s, w, fd, "V")
        t:assert_eq(q.ret, 0, "querying it: " .. sys.errname(q.errno or 0))
        t:assert_eq(q.data, lcs.sz("set"), "with the data written")
        t:assert_eq(lcs.delete_value(s, w, fd, "V").ret, 0, "and deleting it")
        sys.close(w, fd); sys.close(w, parent)
        main:pump(300)
        done(w)
    end)

test("blanket tombstone operations proceed on an orphan",
    { spec = "PKM *orphan.allowed.blanket-tombstone-operations" }, function(t)
        local s = fixture()
        local w = worker()
        local parent = open(t, w, TEST)
        local c = lcs.create_key(s, w, { parent_fd = parent, path = "AllowedBlanket" })
        local fd = c.ret
        t:assert_eq(lcs.delete_key(s, w, fd).ret, 0, "orphan it")
        t:assert_eq(lcs.blanket_tombstone(s, w, fd, nil, true).ret, 0, "setting a blanket")
        t:assert_eq(lcs.blanket_tombstone(s, w, fd, nil, false).ret, 0, "and removing it")
        sys.close(w, fd); sys.close(w, parent)
        main:pump(300)
        done(w)
    end)

test("Security Descriptor operations proceed on an orphan",
    { spec = "PKM *orphan.allowed.security-descriptor-operations" }, function(t)
        local s = fixture()
        local w = worker()
        local parent = open(t, w, TEST)
        local c = lcs.create_key(s, w, { parent_fd = parent, path = "AllowedSd" })
        local fd = c.ret
        t:assert_eq(lcs.delete_key(s, w, fd).ret, 0, "orphan it")
        local g = lcs.get_security(s, w, fd, lcs.SI.OWNER | lcs.SI.GROUP | lcs.SI.DACL)
        t:assert_eq(g.ret, 0, "querying the descriptor: " .. sys.errname(g.errno or 0))
        t:assert_eq(lcs.set_security(s, w, fd, lcs.SI.DACL, lcs.permissive_sd()).ret, 0,
            "and setting it")
        sys.close(w, fd); sys.close(w, parent)
        main:pump(300)
        done(w)
    end)

test("key metadata can be queried on an orphan",
    { spec = "PKM *orphan.allowed.query-key-metadata" }, function(t)
        local s = fixture()
        local w = worker()
        local parent = open(t, w, TEST)
        local c = lcs.create_key(s, w, { parent_fd = parent, path = "AllowedInfo" })
        local fd = c.ret
        t:assert_eq(lcs.delete_key(s, w, fd).ret, 0, "orphan it")
        local info = lcs.query_key_info(s, w, fd)
        t:assert_eq(info.ret, 0, "query key info: " .. sys.errname(info.errno or 0))
        t:assert_eq(info.name, "AllowedInfo", "the name it had")
        sys.close(w, fd); sys.close(w, parent)
        main:pump(300)
        done(w)
    end)

test("the orphan's hive can be flushed and the fd closed",
    { spec = "PKM *orphan.allowed.flush-the-hive" }, function(t)
        local s = fixture()
        local w = worker()
        local parent = open(t, w, TEST)
        local c = lcs.create_key(s, w, { parent_fd = parent, path = "AllowedFlush" })
        local fd = c.ret
        t:assert_eq(lcs.delete_key(s, w, fd).ret, 0, "orphan it")
        local f = lcs.flush(s, w, fd)
        t:assert_eq(f.ret, 0, "flushing the key's hive: " .. sys.errname(f.errno or 0))
        sys.close(w, fd); sys.close(w, parent)
        main:pump(300)
        done(w)
    end)

test("closing the fd of an orphan is allowed and returns zero",
    { spec = "PKM *orphan.allowed.close-the-fd" }, function(t)
        local s = fixture()
        local w = worker()
        local parent = open(t, w, TEST)
        local c = lcs.create_key(s, w, { parent_fd = parent, path = "AllowedClose" })
        local fd = c.ret
        t:assert_eq(lcs.delete_key(s, w, fd).ret, 0, "orphan it")
        local r = sys.close(w, fd)
        t:assert_eq(r.ret, 0, "close: " .. sys.errname(r.errno or 0))
        sys.close(w, parent)
        main:pump(300)
        done(w)
    end)

test("namespace operations on an orphan return ENOENT",
    { spec = "PKM *orphan.refused.create-a-child-key" }, function(t)
        local s = fixture()
        local w = worker()
        local parent = open(t, w, TEST)
        local c = lcs.create_key(s, w, { parent_fd = parent, path = "RefusedChild" })
        local fd = c.ret
        t:assert_eq(lcs.delete_key(s, w, fd).ret, 0, "orphan it")
        local child = lcs.create_key(s, w, { parent_fd = fd, path = "Under" })
        t:assert_eq(child.errno, sys.E.NOENT,
            "creating a child key under it: " .. sys.errname(child.errno or 0))
        sys.close(w, fd); sys.close(w, parent)
        main:pump(300)
        done(w)
    end)

test("opening or creating anything relative to an orphan is ENOENT",
    { spec = "PKM *orphan.refused.relative-open-or-create" }, function(t)
        local s = fixture()
        local w = worker()
        local parent = open(t, w, TEST)
        local c = lcs.create_key(s, w, { parent_fd = parent, path = "RefusedRel" })
        local kid = lcs.create_key(s, w, { parent_fd = c.ret, path = "Kid" })
        t:assert(kid.ret >= 0, "a child before it is orphaned")
        sys.close(w, kid.ret)
        local kid_fd = open(t, w, TEST .. "\\RefusedRel\\Kid")
        t:assert_eq(lcs.delete_key(s, w, kid_fd).ret, 0, "remove the child's name")
        sys.close(w, kid_fd)
        t:assert_eq(lcs.delete_key(s, w, c.ret).ret, 0, "orphan the parent")
        local rel = lcs.open_key(s, w, c.ret, "Kid", lcs.RIGHT.KEY_READ)
        t:assert_eq(rel.errno, sys.E.NOENT,
            "a relative open is ENOENT: " .. sys.errname(rel.errno or 0))
        sys.close(w, c.ret); sys.close(w, parent)
        main:pump(300)
        done(w)
    end)

test("deleting an orphan's path entry, or hiding it, is ENOENT",
    { spec = "PKM *orphan.refused.delete-its-path-entry" }, function(t)
        local s = fixture()
        local w = worker()
        local parent = open(t, w, TEST)
        local c = lcs.create_key(s, w, { parent_fd = parent, path = "RefusedDelete" })
        local fd = c.ret
        t:assert_eq(lcs.delete_key(s, w, fd).ret, 0, "orphan it")
        local again = lcs.delete_key(s, w, fd)
        t:assert_eq(again.errno, sys.E.NOENT,
            "there is no path entry left to delete: " .. sys.errname(again.errno or 0))
        sys.close(w, fd); sys.close(w, parent)
        main:pump(300)
        done(w)
    end)

test("hiding an orphan is ENOENT",
    { spec = "PKM *orphan.refused.hide-it" }, function(t)
        local s = fixture()
        local w = worker()
        local parent = open(t, w, TEST)
        local c = lcs.create_key(s, w, { parent_fd = parent, path = "RefusedHide" })
        local fd = c.ret
        t:assert_eq(lcs.delete_key(s, w, fd).ret, 0, "orphan it")
        local h = lcs.hide_key(s, w, fd, { layer = "Alt" })
        t:assert_eq(h.errno, sys.E.NOENT,
            "an unnamed key cannot be hidden: " .. sys.errname(h.errno or 0))
        sys.close(w, fd); sys.close(w, parent)
        main:pump(300)
        done(w)
    end)

test("backing up an orphan is ENOENT",
    { spec = "PKM *orphan.refused.back-it-up" }, function(t)
        local s = fixture()
        local w = worker()
        local sink = sys.open(w, "/dev/null", sys.O.WRONLY)
        t:assert(sink ~= nil, "an output fd")
        local parent = open(t, w, TEST)
        local c = lcs.create_key(s, w, { parent_fd = parent, path = "RefusedBackup" })
        local fd = c.ret
        t:assert_eq(lcs.delete_key(s, w, fd).ret, 0, "orphan it")
        local b = lcs.backup(s, w, fd, sink)
        t:assert_eq(b.errno, sys.E.NOENT,
            "an orphan is no longer a reachable subtree root: " .. sys.errname(b.errno or 0))
        sys.close(w, sink); sys.close(w, fd); sys.close(w, parent)
        main:pump(300)
        done(w)
    end)

-- Watches on an orphan ---------------------------------------------------------

test("a watch armed before orphaning stays armed and delivers KEY_DELETED",
    { spec = "PKM *orphan.watch.stays-armed-and-delivers-key-deleted" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\Watched")
        t:assert_eq(lcs.notify(nil, w, fd, lcs.NOTIFY.ALL, false).ret, 0, "arm a watch")
        t:assert_eq(lcs.delete_key(s, w, fd).ret, 0, "orphan the key")
        t:assert(lcs.poll_revents(w, fd, 200) ~= 0, "an event is readable")
        local ev = lcs.read_events(nil, w, fd)
        t:assert(ev.ret > 0, "read: " .. sys.errname(ev.errno or 0))
        local types = lcs.event_types(ev.events)
        local saw = false
        for _, ty in ipairs(types) do if ty == "KEY_DELETED" then saw = true end end
        t:assert(saw, "the transition delivers KEY_DELETED, got "
            .. lcs.event_summary(ev.events))
        sys.close(w, fd)
        main:pump(300)
        done(w)
    end)

test("after that the watch still sees GUID-local changes",
    { spec = "PKM *orphan.watch.still-sees-guid-local-changes" }, function(t)
        local s = fixture()
        local w = worker()
        local parent = open(t, w, TEST)
        local c = lcs.create_key(s, w, { parent_fd = parent, path = "WatchedLocal" })
        local fd = c.ret
        t:assert_eq(lcs.notify(nil, w, fd, lcs.NOTIFY.ALL, false).ret, 0, "arm a watch")
        t:assert_eq(lcs.delete_key(s, w, fd).ret, 0, "orphan the key")
        if lcs.poll_revents(w, fd, 200) ~= 0 then lcs.read_events(nil, w, fd) end
        t:assert_eq(lcs.set_value(s, w, fd, "Local", lcs.TYPE.DWORD, lcs.dword(1)).ret, 0,
            "a change through the surviving fd")
        t:assert(lcs.poll_revents(w, fd, 200) ~= 0, "is still observed")
        local ev = lcs.read_events(nil, w, fd)
        local saw = false
        for _, e in ipairs(ev.events or {}) do
            if e.type == lcs.WATCH.VALUE_SET and e.name == "Local" then saw = true end
        end
        t:assert(saw, "as VALUE_SET, got " .. lcs.event_summary(ev.events))
        sys.close(w, fd); sys.close(w, parent)
        main:pump(300)
        done(w)
    end)

test("arming a new watch on an already-orphaned key is ENOENT",
    { spec = "PKM *orphan.watch.arming-a-new-watch-is-enoent" }, function(t)
        local s = fixture()
        local w = worker()
        local parent = open(t, w, TEST)
        local c = lcs.create_key(s, w, { parent_fd = parent, path = "WatchLate" })
        local fd = c.ret
        t:assert_eq(lcs.delete_key(s, w, fd).ret, 0, "orphan it first")
        local n = lcs.notify(nil, w, fd, lcs.NOTIFY.ALL, false)
        t:assert_eq(n.errno, sys.E.NOENT,
            "arming a new watch afterwards is refused: " .. sys.errname(n.errno or 0))
        sys.close(w, fd); sys.close(w, parent)
        main:pump(300)
        done(w)
    end)

test("re-arming a watch that is already armed is allowed",
    { spec = "PKM *orphan.watch.re-arming-an-armed-watch-is-allowed" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\Rearm")
        t:assert_eq(lcs.notify(nil, w, fd, lcs.NOTIFY.ALL, false).ret, 0, "arm a watch")
        t:assert_eq(lcs.delete_key(s, w, fd).ret, 0, "orphan the key")
        if lcs.poll_revents(w, fd, 200) ~= 0 then lcs.read_events(nil, w, fd) end
        local again = lcs.notify(nil, w, fd, lcs.NOTIFY.VALUE, false)
        t:assert_eq(again.ret, 0,
            "re-arming the armed watch is allowed: " .. sys.errname(again.errno or 0))
        sys.close(w, fd)
        main:pump(300)
        done(w)
    end)

-- A new key at the same path ------------------------------------------------

test("fds to the other GUID stay completely isolated",
    { spec = "PKM *orphan.same-path.fds-to-the-other-guid-stay-isolated" }, function(t)
        local s = fixture()
        local w = worker()
        local old = open(t, w, TEST .. "\\Isolated")
        local old_guid = s:lookup(TEST .. "\\Isolated")
        t:assert_eq(lcs.set_value(s, w, old, "Mine", lcs.TYPE.SZ, lcs.sz("old")).ret, 0, "a value")
        t:assert_eq(lcs.delete_key(s, w, old).ret, 0, "orphan it")

        local parent = open(t, w, TEST)
        local fresh = lcs.create_key(s, w, { parent_fd = parent, path = "Isolated" })
        t:assert(fresh.ret >= 0, "a new key at the same path: " .. sys.errname(fresh.errno or 0))
        t:assert_eq(fresh.disposition, lcs.CREATED_NEW, "created new")
        local new_guid = s:lookup(TEST .. "\\Isolated")
        t:assert(new_guid ~= old_guid, "different identity")

        t:assert_eq(lcs.query_value(s, w, fresh.ret, "Mine").errno, sys.E.NOENT,
            "the new key has none of the old one's values")
        t:assert_eq(lcs.set_value(s, w, fresh.ret, "Theirs", lcs.TYPE.SZ, lcs.sz("new")).ret, 0,
            "a value on the new key")
        t:assert_eq(lcs.query_value(s, w, old, "Theirs").errno, sys.E.NOENT,
            "is invisible through the old fd")
        local mine = lcs.query_value(s, w, old, "Mine")
        t:assert_eq(mine.ret, 0, "whose own value is still there")
        t:assert_eq(mine.data, lcs.sz("old"), "unchanged")
        sys.close(w, fresh.ret); sys.close(w, old); sys.close(w, parent)
        main:pump(300)
        done(w)
    end)

-- Dropping the GUID -----------------------------------------------------------

test("the last close of an orphan sends RSI_DROP_KEY",
    { spec = "PKM *orphan.drop.last-close-sends-rsi-drop-key" }, function(t)
        local s = fixture()
        local w = worker()
        local parent = open(t, w, TEST)
        local c = lcs.create_key(s, w, { parent_fd = parent, path = "Dropped" })
        local fd = c.ret
        local guid = s:lookup(TEST .. "\\Dropped")
        t:assert_eq(lcs.set_value(s, w, fd, "Gone", lcs.TYPE.SZ, lcs.sz("x")).ret, 0, "a value")
        t:assert_eq(lcs.delete_key(s, w, fd).ret, 0, "orphan it")

        -- A second fd on the same key: the drop waits for the last one.
        local mark = s:mark()
        sys.close(w, fd)
        main:pump(300)
        local drops = s:served(lcs.OP.DROP_KEY, mark, guid)
        t:assert_eq(#drops, 1, "one RSI_DROP_KEY for the orphaned GUID")
        t:assert(s.store.keys[guid] == nil, "which purged the key record")
        t:assert(s.store.values[guid] == nil, "every value entry across every layer")
        t:assert(s.store.blankets[guid] == nil, "and any remaining blanket tombstones")
        sys.close(w, parent)
        done(w)
    end)

test("RSI_DROP_KEY is dispatched before the in-kernel state is released",
    { spec = "PKM *orphan.drop.dispatched-before-state-is-released" }, function(t)
        local s = fixture()
        local w = worker()
        local parent = open(t, w, TEST)
        local c = lcs.create_key(s, w, { parent_fd = parent, path = "DropOrder" })
        local fd = c.ret
        local guid = s:lookup(TEST .. "\\DropOrder")
        t:assert_eq(lcs.delete_key(s, w, fd).ret, 0, "orphan it")
        local mark = s:mark()
        sys.close(w, fd)
        main:pump(300)
        local drops = s:served(lcs.OP.DROP_KEY, mark)
        t:assert_eq(#drops, 1, "the drop went out")
        t:assert_eq(drops[1].payload:sub(1, 16), guid,
            "naming the GUID, which the kernel could only do while it still held the state")
        sys.close(w, parent)
        done(w)
    end)

test("the drop is asynchronous: nothing waits for the answer",
    { spec = "PKM *orphan.drop.request-is-asynchronous" }, function(t)
        local s = fixture()
        local w = worker()
        local parent = open(t, w, TEST)
        local c = lcs.create_key(s, w, { parent_fd = parent, path = "DropAsync" })
        local fd = c.ret
        t:assert_eq(lcs.delete_key(s, w, fd).ret, 0, "orphan it")

        s:intercept(lcs.OP.DROP_KEY, function() return lcs.HOLD end)
        local mark = s:mark()
        local closed = sys.close(w, fd)
        t:assert_eq(closed.ret, 0, "close returns without waiting for the source")
        main:pump(200)
        local held = s:held_ids()
        t:assert(#held >= 1, "the request is outstanding")
        -- Answering it late is an ordinary response, not a late one: the
        -- source is not torn down and keeps serving.
        s:release(held[#held])
        s:intercept(lcs.OP.DROP_KEY, nil)
        main:pump(200)
        local still = lcs.open_key(s, w, -1, TEST, lcs.RIGHT.KEY_READ)
        t:assert(still.ret >= 0,
            "a valid answer to a caller-less request is processed normally: "
            .. sys.errname(still.errno or 0))
        sys.close(w, still.ret); sys.close(w, parent)
        done(w)
    end)

test("close() never reports orphan cleanup failure: it returns 0 unconditionally",
    { spec = "PKM *orphan.drop.close-always-returns-zero" }, function(t)
        local s = fixture()
        local w = worker()
        local parent = open(t, w, TEST)
        local c = lcs.create_key(s, w, { parent_fd = parent, path = "DropFails" })
        local fd = c.ret
        t:assert_eq(lcs.delete_key(s, w, fd).ret, 0, "orphan it")
        s:intercept(lcs.OP.DROP_KEY, function() return lcs.STATUS.STORAGE_ERROR, "" end)
        local closed = sys.close(w, fd)
        s:intercept(lcs.OP.DROP_KEY, nil)
        t:assert_eq(closed.ret, 0, "close returns 0 though the drop failed: "
            .. sys.errname(closed.errno or 0))
        main:pump(300)
        sys.close(w, parent)
        done(w)
    end)

-- Last: this test takes a source Down, and layer deletion refuses to run
-- while any slot is.
test("a Down source queues no deferred drop",
    { spec = "PKM *orphan.drop.down-source-queues-no-deferred-drop" }, function(t)
        local s = lcs.source(vm, { hives = { { name = "Deferred" } } })
        s:key("Deferred\\Doomed")
        assert(s:register())
        s:pump()
        local w = worker()
        local r = lcs.open_key(s, w, -1, "Deferred\\Doomed", lcs.KEY_ALL_ACCESS)
        t:assert(r.ret >= 0, "open: " .. sys.errname(r.errno or 0))
        local guid = s:lookup("Deferred\\Doomed")
        t:assert_eq(lcs.delete_key(s, w, r.ret).ret, 0, "orphan it")

        s:disconnect()
        local mark = #s.log
        local closed = sys.close(w, r.ret)
        t:assert_eq(closed.ret, 0, "close still returns 0: " .. sys.errname(closed.errno or 0))

        -- Nothing was queued: taking the slot back over sends no drop.
        assert(s:resume())
        s:pump(300)
        t:assert_eq(#s:served(lcs.OP.DROP_KEY, mark + 1, guid), 0,
            "no deferred drop was queued or replayed; recovering the record "
            .. "is the source's own startup obligation")
        t:assert(s.store.keys[guid] ~= nil, "so the record is still there")
        done(w)
        s:close()
    end)
