-- Does the harness reach LCS at all? A Lua-served source registers, a
-- key opens through it, and one of every kind of call round-trips.
--
-- Kept deliberately small and first: when an LCS case fails, this says
-- whether the registry misbehaved or the source never got as far as
-- serving one.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")

local vm = provium:vm("v", "kernel-only"):boot()

test("a Lua-served Machine hive registers and serves a key open",
    { spec = "PKM *hive.routing.absolute-path-names-a-registered-hive" }, function(t)
        local src, test_key = assert(lcs.machine(vm))
        local w = vm:spawn_worker()
        local r = lcs.open_key(src, w, -1, "Machine\\Software\\Test", lcs.KEY_ALL_ACCESS)
        t:assert(r.ret >= 0, "open: " .. sys.errname(r.errno or 0))
        t:assert(#src:served(lcs.OP.LOOKUP) >= 2, "the walk looked up each component")
        local fd = r.ret

        -- Write, read back, and see the layer the answer came from.
        local s = lcs.set_value(src, w, fd, "Answer", lcs.TYPE.DWORD, lcs.dword(42))
        t:assert_eq(s.ret, 0, "set: " .. sys.errname(s.errno or 0))
        local q = lcs.query_value(src, w, fd, "Answer")
        t:assert_eq(q.ret, 0, "query: " .. sys.errname(q.errno or 0))
        t:assert_eq(q.type, lcs.TYPE.DWORD, "type")
        t:assert_eq(q.data, lcs.dword(42), "data")
        t:assert_eq(q.layer, "base", "the winning layer is spelled canonically")
        t:assert(q.sequence > 0, "with a sequence number")

        local b = lcs.query_values_batch(src, w, fd)
        t:assert_eq(b.ret, 0, "batch: " .. sys.errname(b.errno or 0))
        t:assert_eq(b.count, 1, "one effective value")
        t:assert_eq(b.values[1].name, "Answer", "by name")

        local e = lcs.enum_values(src, w, fd, 0)
        t:assert_eq(e.ret, 0, "enum: " .. sys.errname(e.errno or 0))
        t:assert_eq(e.name, "Answer", "enum names it too")
        local past = lcs.enum_values(src, w, fd, 1)
        t:assert_eq(past.errno, sys.E.NOENT, "and ENOENT past the end")

        local info = lcs.query_key_info(src, w, fd)
        t:assert_eq(info.ret, 0, "key info: " .. sys.errname(info.errno or 0))
        t:assert_eq(info.name, "Test", "the key's own name")
        t:assert_eq(info.value_count, 1, "value count")

        -- A child in a transaction, then the disposition on re-create.
        local txn = assert(lcs.begin_transaction(w))
        local st = lcs.txn_status(nil, w, txn)
        t:assert_eq(st.state, lcs.TXN.ACTIVE_UNBOUND, "fresh transaction is unbound")
        local c = lcs.create_key(src, w, { parent_fd = fd, path = "Child", txn_fd = txn })
        t:assert(c.ret >= 0, "create in txn: " .. sys.errname(c.errno or 0))
        t:assert_eq(c.disposition, lcs.CREATED_NEW, "created new")
        st = lcs.txn_status(nil, w, txn)
        t:assert_eq(st.state, lcs.TXN.ACTIVE_BOUND, "which bound the transaction")
        local cm = lcs.commit(src, w, txn)
        t:assert_eq(cm.ret, 0, "commit: " .. sys.errname(cm.errno or 0))
        sys.close(w, txn)
        local again = lcs.create_key(src, w, { parent_fd = fd, path = "Child" })
        t:assert_eq(again.disposition, lcs.OPENED_EXISTING, "second create opens existing")
        sys.close(w, again.ret)

        local sub = lcs.enum_subkeys(src, w, fd, 0)
        t:assert_eq(sub.ret, 0, "enum subkeys: " .. sys.errname(sub.errno or 0))
        t:assert_eq(sub.name, "Child", "the child is enumerated")

        -- A watch sees the next write.
        local n = lcs.notify(nil, w, fd, lcs.NOTIFY.ALL, false)
        t:assert_eq(n.ret, 0, "notify: " .. sys.errname(n.errno or 0))
        lcs.set_value(src, w, fd, "Answer", lcs.TYPE.DWORD, lcs.dword(43))
        local ev = lcs.read_events(nil, w, fd)
        t:assert(ev.ret > 0, "events readable: " .. sys.errname(ev.errno or 0))
        t:assert_eq(ev.events[1].type, lcs.WATCH.VALUE_SET, "VALUE_SET")
        t:assert_eq(ev.events[1].name, "Answer", "for the value")

        -- Security round trip.
        local g = lcs.get_security(src, w, fd, lcs.SI.OWNER | lcs.SI.GROUP | lcs.SI.DACL)
        t:assert_eq(g.ret, 0, "get security: " .. sys.errname(g.errno or 0))
        t:assert(g.sd and #g.sd > 20, "a descriptor came back")

        sys.close(w, c.ret)
        sys.close(w, fd)
        w:kill(); w:join()
        src:close()
    end)

-- A Down slot keeps its hive identities reserved (§5.8.2), so a second
-- source in the same VM cannot take "Machine" with a different root:
-- it registers a hive of its own.
test("a second source registers a global and a private hive of the same name",
    { spec = "PKM *private-hive.routing.invisible-without-scope" }, function(t)
        local scope = lcs.guid()
        local src = lcs.source(vm, { hives = {
            { name = "Smoke" }, { name = "Smoke", private = true, scope = scope },
        } })
        src:key("Smoke\\Global")
        src:key("Smoke\\Private", { root = src.hives[2].root })
        assert(src:register())
        src:pump()
        local w = vm:spawn_worker()
        local r = lcs.open_key(src, w, -1, "Smoke\\Global", lcs.RIGHT.KEY_READ)
        t:assert(r.ret >= 0, "the global hive answers a scopeless caller: " .. sys.errname(r.errno or 0))
        if r.ret >= 0 then sys.close(w, r.ret) end
        local p = lcs.open_key(src, w, -1, "Smoke\\Private", lcs.RIGHT.KEY_READ)
        t:assert_eq(p.errno, sys.E.NOENT, "and the private hive's key is not there for it")
        w:kill(); w:join()
        src:close()
    end)
