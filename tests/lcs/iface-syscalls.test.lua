-- PKM §5.5.2 — The three syscalls: reg_open_key's parameters, step
-- order and errors; reg_create_key's open-or-create contract, flags,
-- layer, transaction and the re-check of the descriptor it just
-- inherited; and reg_begin_transaction's very small failure set.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")
local kacs = require("helpers.kacs")
local token = require("helpers.token")
local access = require("helpers.access")

local vm = provium:vm("v", "kernel-only"):boot()

local CI = access.ACE_FLAG.CONTAINER_INHERIT
local R = lcs.RIGHT
local ALL = lcs.KEY_ALL_ACCESS

local src = lcs.source(vm)
local TEST = src:key("Machine\\Software\\Test")
src:value(TEST, "Seeded", lcs.TYPE.DWORD, lcs.dword(1))
src:symlink("Machine\\Link", "Machine\\Software\\Test")
src:key("Machine\\Guarded", { sd = lcs.sd({
    access.ace(access.ACE.ALLOWED, ALL, kacs.SID.LOCAL_SYSTEM, CI),
}) })
-- A parent whose inheritable grant is narrower than what a creator asks
-- for, so §5.5.2 step 7 has something to refuse.
src:key("Machine\\Narrow", { sd = lcs.sd({
    access.ace(access.ACE.ALLOWED, ALL, kacs.SID.EVERYONE, 0),
    access.ace(access.ACE.ALLOWED, R.KEY_READ, kacs.SID.EVERYONE, CI),
}) })
src:key("Machine\\Parent")
src:key("Machine\\Parent\\Child")
src:key("Machine\\Walk\\A\\B")
src:key("Machine\\Doomed")
-- A chain just short of MaxKeyDepth (512 by default), seeded host-side
-- so the depth case costs one create rather than five hundred.
local DEEP = "Machine" .. string.rep("\\d", 505)
src:key(DEEP)
assert(src:register())
src:pump()

local w = vm:spawn_worker()

local function must_open(t, path, desired, parent_fd)
    local r = lcs.open_key(src, w, parent_fd or -1, path, desired or ALL)
    t:assert(r.ret >= 0, "open " .. path .. ": " .. sys.errname(r.errno or 0))
    return r.ret
end

-- reg_open_key ----------------------------------------------------------

test("parent_fd is an open key fd to resolve relative to, or -1 for an absolute path",
    { spec = "PKM *reg-syscall.open-key.parent-fd-or-minus-one" }, function(t)
        local absolute = must_open(t, "Machine\\Parent\\Child", R.KEY_READ, -1)
        sys.close(w, absolute)

        local parent = must_open(t, "Machine\\Parent", R.KEY_READ)
        local relative = lcs.open_key(src, w, parent, "Child", R.KEY_READ)
        t:assert(relative.ret >= 0, "and a key fd resolves a relative path: " ..
            sys.errname(relative.errno or 0))
        sys.close(w, relative.ret)
        sys.close(w, parent)

        local txn = assert(lcs.begin_transaction(w))
        local wrong = lcs.open_key(nil, w, txn, "Child", R.KEY_READ)
        t:assert(wrong.ret < 0, "an fd that is not a key fd is not a parent: " ..
            sys.errname(wrong.errno or 0))
        sys.close(w, txn)
        local closed = lcs.open_key(nil, w, 4242, "Child", R.KEY_READ)
        t:assert_eq(closed.errno, sys.E.BADF, "and neither is an fd that is not open")
    end)

test("the path is absolute with a hive prefix when parent_fd is -1, and parent-relative otherwise",
    { spec = "PKM *reg-syscall.open-key.path-is-absolute-or-parent-relative" }, function(t)
        local no_hive = lcs.open_key(src, w, -1, "Software\\Test", R.KEY_READ)
        t:assert_eq(no_hive.errno, sys.E.NOENT,
            "an absolute path's first component is a hive name, and Software is not one")

        local parent = must_open(t, "Machine\\Software", R.KEY_READ)
        local rel = lcs.open_key(src, w, parent, "Test", R.KEY_READ)
        t:assert(rel.ret >= 0, "a relative path starts at the parent key: " ..
            sys.errname(rel.errno or 0))
        sys.close(w, rel.ret)
        local rel_hive = lcs.open_key(src, w, parent, "Machine\\Software\\Test", R.KEY_READ)
        t:assert_eq(rel_hive.errno, sys.E.NOENT,
            "and a hive prefix under a parent fd is just three more components")
        sys.close(w, parent)
    end)

test("REG_OPEN_LINK is the only flag reg_open_key defines",
    { spec = "PKM *reg-syscall.open-key.flags-only-reg-open-link" }, function(t)
        local followed = must_open(t, "Machine\\Link", R.KEY_READ | R.READ_CONTROL, -1)
        local target = lcs.query_key_info(src, w, followed)
        t:assert_eq(target.name, "Test", "with no flag the link is followed to its target")
        sys.close(w, followed)

        local link = lcs.open_key(src, w, -1, "Machine\\Link",
            R.KEY_READ | R.READ_CONTROL, lcs.OPEN_LINK)
        t:assert(link.ret >= 0, "REG_OPEN_LINK opens the link itself: " ..
            sys.errname(link.errno or 0))
        local info = lcs.query_key_info(src, w, link.ret)
        t:assert_eq(info.name, "Link", "which is a different key")
        t:assert_eq(info.symlink, true, "and carries the symlink flag")
        sys.close(w, link.ret)

        for _, bit in ipairs({ 0x02, 0x04, 0x80000000 }) do
            local r = lcs.open_key(nil, w, -1, "Machine\\Link", R.KEY_READ, bit)
            t:assert_eq(r.errno, sys.E.INVAL,
                string.format("every other bit is reserved and must be zero (0x%X)", bit))
        end
    end)

test("the open runs in order: validate, rewrite, route, walk, AccessCheck, publish",
    { spec = "PKM *reg-syscall.open-key.step-order" }, function(t)
        -- 1. Argument validation precedes routing: a bad flag on a hive
        --    that does not exist is EINVAL, not ENOENT.
        local mark = src:mark()
        local bad_flag = lcs.open_key(nil, w, -1, "NoSuchHive\\Key", R.KEY_READ, 0x02)
        t:assert_eq(bad_flag.errno, sys.E.INVAL, "arguments are validated first")
        t:assert_eq(#src.log, mark - 1, "and nothing was routed or walked")

        -- 3. Routing precedes the walk: an unregistered hive never
        --    reaches a source.
        mark = src:mark()
        local unrouted = lcs.open_key(src, w, -1, "NoSuchHive\\Key", R.KEY_READ)
        t:assert_eq(unrouted.errno, sys.E.NOENT, "then the hive name is looked up")
        t:assert_eq(#src:served(lcs.OP.LOOKUP, mark), 0, "with no walk attempted")

        -- 4 before 5: a missing key under a descriptor that would deny
        --    the caller is ENOENT, because the walk fails before
        --    AccessCheck runs on anything.
        token.as_principal(t, vm, { user_sid = token.SID.TEST_USER }, function(w2)
            local denied = lcs.open_key(src, w2, -1, "Machine\\Guarded", R.KEY_READ)
            t:assert_eq(denied.errno, sys.E.ACCES, "the key itself denies this caller")
            local missing = lcs.open_key(src, w2, -1, "Machine\\Guarded\\Absent", R.KEY_READ)
            t:assert_eq(missing.errno, sys.E.NOENT,
                "and a name below it that does not resolve is ENOENT: the walk came first")
            -- 5 before 6: a denial publishes no fd.
            t:assert_eq(denied.ret, -1, "and a denied open publishes nothing")
        end)
    end)

test("the walk goes component by component through RSI_LOOKUP, each from the last result",
    { spec = "PKM *reg-syscall.open-key.walks-each-component-through-rsi-lookup" }, function(t)
        local mark = src:mark()
        local fd = must_open(t, "Machine\\Walk\\A\\B", R.KEY_READ)
        local lookups = src:served(lcs.OP.LOOKUP, mark)
        t:assert_eq(#lookups, 3, "three components below the hive root, three lookups")
        local expected_parent = src.hives[1].root
        for i, name in ipairs({ "Walk", "A", "B" }) do
            local req = lookups[i]
            t:assert_eq(req.payload:sub(1, 16), expected_parent,
                "lookup " .. i .. " starts from the previous component's key")
            t:assert_eq(string.unpack("<s4", req.payload, 17), name,
                "and asks for " .. name)
            expected_parent = src:lookup("Machine\\" ..
                table.concat({ "Walk", "A", "B" }, "\\", 1, i))
        end
        sys.close(w, fd)
    end)

test("the fd holds the key GUID, the granted mask, the resolved path and the ancestor chain",
    { spec = "PKM *reg-syscall.open-key.fd-holds-guid-mask-path-and-chain" }, function(t)
        local guid = src:lookup("Machine\\Software\\Test")
        -- KEY_QUERY_VALUE and KEY_SET_VALUE, deliberately without
        -- KEY_ENUMERATE_SUB_KEYS, so the mask has something to withhold.
        local fd = must_open(t, "Machine\\Software\\Test",
            R.QUERY_VALUE | R.SET_VALUE | R.READ_CONTROL)

        -- The key GUID: every request the fd drives names it.
        local mark = src:mark()
        t:assert_eq(lcs.query_values_batch(src, w, fd).ret, 0, "a read runs")
        local reads = src:served(lcs.OP.QUERY_VALUES, mark, guid)
        t:assert_eq(#reads, 1, "and the source is asked about this key's GUID")

        -- The granted mask: what was not asked for is not there.
        local denied = lcs.enum_subkeys(nil, w, fd, 0)
        t:assert_eq(denied.errno, sys.E.ACCES, "the mask granted at open is on the fd")

        -- The resolved path: its first component is the hive a flush
        -- names, its last is the key's own name.
        mark = src:mark()
        t:assert_eq(lcs.flush(src, w, fd).ret, 0, "a flush runs")
        local flushes = src:served(lcs.OP.FLUSH, mark)
        t:assert_eq(#flushes, 1, "and names one hive")
        t:assert_eq(string.unpack("<s4", flushes[1].payload), "Machine",
            "taken from the first component of the resolved path")
        sys.close(w, fd)

        -- The ancestor chain: a delete takes the parent GUID from it.
        local doomed = must_open(t, "Machine\\Doomed", R.DELETE)
        mark = src:mark()
        t:assert_eq(lcs.delete_key(src, w, doomed).ret, 0, "a delete runs")
        local deletes = src:served(lcs.OP.DELETE_ENTRY, mark)
        t:assert_eq(#deletes, 1, "removing one path entry")
        t:assert_eq(deletes[1].payload:sub(1, 16), src.hives[1].root,
            "under the parent GUID the open walk collected")
        t:assert_eq(string.unpack("<s4", deletes[1].payload, 17), "Doomed",
            "and the last component of the resolved path")
        sys.close(w, doomed)
    end)

test("the fd of a followed symlink stores the resolved path, and refers to the target",
    { spec = "PKM *reg-syscall.open-key.fd-holds-guid-mask-path-and-chain" }, function(t)
        local fd = must_open(t, "Machine\\Link", R.KEY_READ | R.READ_CONTROL)
        local info = lcs.query_key_info(src, w, fd)
        t:assert_eq(info.name, "Test", "the fd names the target, not the link")
        local mark = src:mark()
        t:assert_eq(lcs.query_values_batch(src, w, fd).ret, 0, "and reads go to the target")
        local reads = src:served(lcs.OP.QUERY_VALUES, mark,
            src:lookup("Machine\\Software\\Test"))
        t:assert_eq(#reads, 1, "by the target's GUID")
        sys.close(w, fd)
    end)

test("a key that does not exist after layer resolution is ENOENT",
    { spec = "PKM *reg-syscall.open-key.enoent-key-missing" }, function(t)
        local r = lcs.open_key(src, w, -1, "Machine\\Software\\Absent", R.KEY_READ)
        t:assert_eq(r.errno, sys.E.NOENT, "reg_open_key fails if the key does not exist")
        local hidden = lcs.open_key(src, w, -1, "Machine\\Software\\Test\\None", R.KEY_READ)
        t:assert_eq(hidden.errno, sys.E.NOENT, "at any depth")
    end)

test("a component or a whole path that is too long is ENAMETOOLONG",
    { spec = "PKM *reg-syscall.open-key.enametoolong" }, function(t)
        local mark = src:mark()
        local long_component = "Machine\\" .. string.rep("c", 300)
        local r = lcs.open_key(src, w, -1, long_component, R.KEY_READ)
        t:assert_eq(r.errno, sys.E.NAMETOOLONG,
            "a component beyond MaxPathComponentLength (255)")
        t:assert_eq(#src:served(lcs.OP.LOOKUP, mark), 0, "rejected before the walk")

        mark = src:mark()
        local long_path = "Machine" .. string.rep("\\" .. string.rep("p", 200), 100)
        local p = lcs.open_key(src, w, -1, long_path, R.KEY_READ)
        t:assert_eq(p.errno, sys.E.NAMETOOLONG,
            "and a whole path beyond MaxTotalPathLength (16383)")
        t:assert_eq(#src:served(lcs.OP.LOOKUP, mark), 0, "rejected before the walk too")
    end)

-- reg_create_key ---------------------------------------------------------

test("reg_create_key opens the key if it exists and creates it if it does not, and says which",
    { spec = "PKM *reg-syscall.create-key.opens-or-creates" }, function(t)
        local first = lcs.create_key(src, w, { path = "Machine\\Software\\Test\\Fresh" })
        t:assert(first.ret >= 0, "the first call creates: " .. sys.errname(first.errno or 0))
        t:assert_eq(first.disposition, lcs.CREATED_NEW, "and reports REG_CREATED_NEW")
        sys.close(w, first.ret)

        local second = lcs.create_key(src, w, { path = "Machine\\Software\\Test\\Fresh" })
        t:assert(second.ret >= 0, "the second opens: " .. sys.errname(second.errno or 0))
        t:assert_eq(second.disposition, lcs.OPENED_EXISTING, "and reports REG_OPENED_EXISTING")
        sys.close(w, second.ret)
    end)

test("the disposition values are REG_CREATED_NEW (1) and REG_OPENED_EXISTING (2), and may be null",
    { spec = "PKM *reg-syscall.create-key.disposition-values" }, function(t)
        local made = lcs.create_key(src, w, { path = "Machine\\Software\\Test\\Disp" })
        t:assert_eq(made.disposition, 1, "REG_CREATED_NEW is 1")
        sys.close(w, made.ret)
        local again = lcs.create_key(src, w, { path = "Machine\\Software\\Test\\Disp" })
        t:assert_eq(again.disposition, 2, "REG_OPENED_EXISTING is 2")
        sys.close(w, again.ret)
        local quiet = lcs.create_key(src, w,
            { path = "Machine\\Software\\Test\\Disp", no_disposition = true })
        t:assert(quiet.ret >= 0, "and a null disposition_ptr is allowed: " ..
            sys.errname(quiet.errno or 0))
        sys.close(w, quiet.ret)
    end)

test("an existing key is opened, the layer parameter ignored, and no path entry created",
    { spec = "PKM *reg-syscall.create-key.existing-key-is-opened" }, function(t)
        local mark = src:mark()
        local r = lcs.create_key(src, w, { path = "Machine\\Software\\Test",
            layer = "NoSuchLayer" })
        t:assert(r.ret >= 0, "the key exists, so it is opened: " .. sys.errname(r.errno or 0))
        t:assert_eq(r.disposition, lcs.OPENED_EXISTING, "as REG_OPENED_EXISTING")
        t:assert_eq(#src:served(lcs.OP.CREATE_ENTRY, mark), 0, "nothing was created")
        t:assert_eq(#src:served(lcs.OP.CREATE_KEY, mark), 0, "no key record either")
        sys.close(w, r.ret)
    end)

test("a created key reports REG_CREATED_NEW and is published with the granted mask",
    { spec = "PKM *reg-syscall.create-key.new-key-reports-created-new" }, function(t)
        local made = lcs.create_key(src, w,
            { path = "Machine\\Software\\Test\\Masked", access = R.KEY_READ })
        t:assert(made.ret >= 0, "create: " .. sys.errname(made.errno or 0))
        t:assert_eq(made.disposition, lcs.CREATED_NEW, "REG_CREATED_NEW")
        local q = lcs.query_value(src, w, made.ret, "Nothing")
        t:assert_eq(q.errno, sys.E.NOENT, "the fd carries KEY_QUERY_VALUE")
        local s = lcs.set_value(nil, w, made.ret, "X", lcs.TYPE.DWORD, lcs.dword(1))
        t:assert_eq(s.errno, sys.E.ACCES, "and no more than KEY_READ was asked for")
        sys.close(w, made.ret)
    end)

test("REG_OPTION_VOLATILE and REG_OPTION_CREATE_LINK are the flags; other bits are reserved",
    { spec = "PKM *reg-syscall.create-key.flags" }, function(t)
        local vol = lcs.create_key(src, w, { path = "Machine\\Software\\Test\\Vol",
            flags = lcs.OPTION_VOLATILE })
        t:assert(vol.ret >= 0, "REG_OPTION_VOLATILE creates: " .. sys.errname(vol.errno or 0))
        local info = lcs.query_key_info(src, w, vol.ret)
        t:assert_eq(info.volatile, true, "and the key carries the volatile flag")
        sys.close(w, vol.ret)

        local link = lcs.create_key(src, w, { path = "Machine\\Software\\Test\\NewLink",
            flags = lcs.OPTION_CREATE_LINK })
        t:assert(link.ret >= 0, "REG_OPTION_CREATE_LINK creates: " ..
            sys.errname(link.errno or 0))
        local linfo = lcs.query_key_info(src, w, link.ret)
        t:assert_eq(linfo.symlink, true, "and the key carries the symlink flag")
        sys.close(w, link.ret)

        for _, bit in ipairs({ 0x04, 0x08, 0x80000000 }) do
            local r = lcs.create_key(nil, w, { path = "Machine\\Software\\Test\\Bad",
                flags = bit })
            t:assert_eq(r.errno, sys.E.INVAL,
                string.format("and every other bit is reserved (0x%X)", bit))
        end
    end)

test("a null layer_ptr means the base layer",
    { spec = "PKM *reg-syscall.create-key.null-layer-means-base" }, function(t)
        local mark = src:mark()
        local made = lcs.create_key(src, w, { path = "Machine\\Software\\Test\\Based" })
        t:assert(made.ret >= 0, "create: " .. sys.errname(made.errno or 0))
        sys.close(w, made.ret)
        local entries = src:served(lcs.OP.CREATE_ENTRY, mark)
        t:assert_eq(#entries, 1, "one path entry was created")
        local at = 17
        local _, next_at = string.unpack("<s4", entries[1].payload, at)
        t:assert_eq(string.unpack("<s4", entries[1].payload, next_at), "base",
            "in the base layer")
    end)

test("a non-negative txn_fd makes creation transactional and binds that transaction",
    { spec = "PKM *reg-syscall.create-key.txn-fd-makes-creation-transactional" }, function(t)
        local txn = assert(lcs.begin_transaction(w))
        t:assert_eq(lcs.txn_status(nil, w, txn).state, lcs.TXN.ACTIVE_UNBOUND, "unbound")
        local made = lcs.create_key(src, w,
            { path = "Machine\\Software\\Test\\InTxn", txn_fd = txn })
        t:assert(made.ret >= 0, "create in the transaction: " .. sys.errname(made.errno or 0))
        sys.close(w, made.ret)
        t:assert_eq(lcs.txn_status(nil, w, txn).state, lcs.TXN.ACTIVE_BOUND,
            "which binds the transaction to the source and hive")

        local outside = lcs.open_key(src, w, -1, "Machine\\Software\\Test\\InTxn", R.KEY_READ)
        t:assert_eq(outside.errno, sys.E.NOENT, "and the key is not there for anyone else yet")
        t:assert_eq(lcs.commit(src, w, txn).ret, 0, "commit")
        sys.close(w, txn)
        local after = lcs.open_key(src, w, -1, "Machine\\Software\\Test\\InTxn", R.KEY_READ)
        t:assert(after.ret >= 0, "until the transaction commits: " ..
            sys.errname(after.errno or 0))
        sys.close(w, after.ret)
    end)

test("the parent must exist, and the parent's depth plus one must be within MaxKeyDepth",
    { spec = "PKM *reg-syscall.create-key.parent-must-exist-and-depth-checked" }, function(t)
        local orphan = lcs.create_key(src, w, { path = "Machine\\NoParentHere\\Child" })
        t:assert_eq(orphan.errno, sys.E.NOENT, "a missing parent is ENOENT")

        -- The seeded chain stops just short of the limit; creating past
        -- it fails, and §5.5.5 gives EINVAL for maximum key depth.
        local at, failure = DEEP, nil
        for _ = 1, 16 do
            at = at .. "\\d"
            local r = lcs.create_key(src, w, { path = at })
            if r.ret < 0 then failure = r; break end
            sys.close(w, r.ret)
        end
        t:assert(failure, "creating deeper eventually stops")
        t:assert_eq(failure.errno, sys.E.INVAL, "with EINVAL for maximum key depth exceeded")
    end)

test("the new key's inherited descriptor is re-checked against desired_access",
    { spec = "PKM *reg-syscall.create-key.inherited-descriptor-rechecked" }, function(t)
        -- The parent grants the creator everything; what it passes down
        -- is KEY_READ.
        local greedy = lcs.create_key(src, w, { path = "Machine\\Narrow\\Child",
            access = lcs.KEY_ALL_ACCESS })
        t:assert_eq(greedy.errno, sys.E.ACCES,
            "an inherited descriptor may not grant everything the creator asked for")

        -- The key was created before the re-check, and opening it for
        -- what it does grant works.
        local modest = lcs.open_key(src, w, -1, "Machine\\Narrow\\Child", R.KEY_READ)
        t:assert(modest.ret >= 0, "the key itself exists: " .. sys.errname(modest.errno or 0))
        sys.close(w, modest.ret)
    end)

test("intermediate path components are not auto-created: only the final one is",
    { spec = "PKM *reg-syscall.create-key.no-intermediate-creation" }, function(t)
        local mark = src:mark()
        local r = lcs.create_key(src, w, { path = "Machine\\Software\\Test\\Mid\\Leaf" })
        t:assert_eq(r.errno, sys.E.NOENT, "a missing intermediate is not created for you")
        t:assert_eq(#src:served(lcs.OP.CREATE_ENTRY, mark), 0, "and nothing was created")
        local mid = lcs.open_key(src, w, -1, "Machine\\Software\\Test\\Mid", R.KEY_READ)
        t:assert_eq(mid.errno, sys.E.NOENT, "the intermediate still does not exist")
    end)

test("ENOENT covers a missing parent and a layer that is not in the layer table",
    { spec = "PKM *reg-syscall.create-key.enoent-parent-missing" }, function(t)
        local parent = lcs.create_key(src, w, { path = "Machine\\Absent\\Child" })
        t:assert_eq(parent.errno, sys.E.NOENT, "the parent does not exist")
        local layer = lcs.create_key(src, w, { path = "Machine\\Software\\Test\\Layered",
            layer = "NotInTheTable" })
        t:assert_eq(layer.errno, sys.E.NOENT, "and the named layer is not in the layer table")
    end)

-- reg_begin_transaction ---------------------------------------------------

test("reg_begin_transaction contacts no source and can fail only with ENOMEM, EOVERFLOW or EINVAL",
    { spec = "PKM *reg-syscall.begin-transaction.failure-set" }, function(t)
        local mark = src:mark()
        local txn = assert(lcs.begin_transaction(w))
        t:assert_eq(#src.log, mark - 1, "no source was contacted")
        local st = lcs.txn_status(nil, w, txn)
        t:assert_eq(st.state, lcs.TXN.ACTIVE_UNBOUND,
            "and none was chosen: the transaction is unbound")
        sys.close(w, txn)

        -- Nothing about the caller can make it fail: no privilege, no
        -- access, no descriptor is consulted.
        token.as_principal(t, vm, { user_sid = token.SID.TEST_USER }, function(w2)
            local mine, e = lcs.begin_transaction(w2)
            t:assert(mine, "an unprivileged caller gets one too: " .. sys.errname(e or 0))
            if mine then sys.close(w2, mine) end
        end)
    end)
