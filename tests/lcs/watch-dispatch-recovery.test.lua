-- PKM §5.6.3, second half — the three dispatch paths that are not an
-- ordinary per-mutation diff: a transaction's batch at commit, recovery
-- dispatch for the operations whose exact diff LCS does not attempt,
-- and what a source restart does to armed watches.
--
-- `MaxTransactionWatchEventBurst` is seeded at 256, the range minimum,
-- so one blanket tombstone over 300 seeded values is enough to put a
-- watcher over the cap.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")

local vm = provium:vm("v", "kernel-only"):boot()

local ROOT = "Machine\\Software\\Test"
local BURST_CAP = 256
local BURST_VALUES = 300

local src = lcs.source(vm, { hives = { { name = "Machine" }, { name = "Other" } } })
local other_root = src.hives[2].root
src:seed_param("MaxTransactionWatchEventBurst", BURST_CAP)
src:seed_layer("high", { precedence = 10, enabled = true })
src:key(ROOT)
src:key(ROOT .. "\\Uncommitted")
src:key(ROOT .. "\\Order")
src:key(ROOT .. "\\UnderCap")
src:key(ROOT .. "\\Recovery")
src:key(ROOT .. "\\Restore\\Child")
src:key(ROOT .. "\\Restart")
src:key("Other\\Thing", { root = other_root })

local burst_key = src:key(ROOT .. "\\Burst")
for i = 1, BURST_VALUES do
    src:value(burst_key, ("B%03d"):format(i), lcs.TYPE.DWORD, lcs.dword(i))
end

assert(src:register())
src:pump()

local w = vm:spawn_worker()

local function open_nb(path, parent_fd)
    local r = lcs.open_key(src, w, parent_fd or -1, path, lcs.KEY_ALL_ACCESS)
    assert(r.ret >= 0, "opening " .. path .. ": " .. sys.errname(r.errno or 0))
    lcs.nonblock(w, r.ret)
    return r.ret
end

local function arm(t, fd, subtree)
    local n = lcs.notify(nil, w, fd, lcs.NOTIFY.ALL, subtree or false)
    t:assert_eq(n.ret, 0, "REG_IOC_NOTIFY arms: " .. sys.errname(n.errno or 0))
end

local function count_of(events, etype)
    local n = 0
    for _, e in ipairs(events) do if e.type == etype then n = n + 1 end end
    return n
end

local function generation(fd)
    return lcs.query_key_info(src, w, fd).hive_generation
end

-- ---- transaction batches ----------------------------------------------

test("nothing inside an uncommitted transaction dispatches",
    { spec = "PKM *watch.dispatch.uncommitted-transaction-dispatches-nothing" },
    function(t)
        local fd = open_nb(ROOT .. "\\Uncommitted")
        arm(t, fd)
        local txn = assert(lcs.begin_transaction(w))
        for _, name in ipairs({ "A", "B", "C" }) do
            local s = lcs.set_value(src, w, fd, name, lcs.TYPE.DWORD, lcs.dword(1),
                { txn_fd = txn })
            t:assert_eq(s.ret, 0, "writing " .. name .. ": " .. sys.errname(s.errno or 0))
            t:assert_eq(#lcs.drain_events(w, fd), 0,
                "nothing was dispatched after " .. name)
        end
        local cm = lcs.commit(src, w, txn)
        t:assert_eq(cm.ret, 0, "commit: " .. sys.errname(cm.errno or 0))
        local ev = lcs.drain_events(w, fd)
        t:assert_eq(#ev, 3, "the whole set fires at commit: " .. lcs.event_summary(ev))
        sys.close(w, txn); sys.close(w, fd)
    end)

test("the commit batch is queued in operation order without interleaving",
    { spec = "PKM *watch.dispatch.commit-batch-queued-in-operation-order-without-interleaving" },
    function(t)
        local fd = open_nb(ROOT .. "\\Order")
        arm(t, fd)
        local txn = assert(lcs.begin_transaction(w))
        lcs.set_value(src, w, fd, "First", lcs.TYPE.DWORD, lcs.dword(1), { txn_fd = txn })
        -- A non-transactional write on the same key between two
        -- transactional ones: it dispatches immediately, so if the
        -- batch interleaved it would land inside it.
        lcs.set_value(src, w, fd, "Outside", lcs.TYPE.DWORD, lcs.dword(1))
        lcs.set_value(src, w, fd, "Second", lcs.TYPE.DWORD, lcs.dword(1), { txn_fd = txn })
        lcs.set_value(src, w, fd, "Third", lcs.TYPE.DWORD, lcs.dword(1), { txn_fd = txn })
        local before = lcs.drain_events(w, fd)
        t:assert_eq(#before, 1, "only the non-transactional write has been dispatched: " ..
            lcs.event_summary(before))
        t:assert_eq(before[1].name, "Outside", "and it is that one")

        local cm = lcs.commit(src, w, txn)
        t:assert_eq(cm.ret, 0, "commit: " .. sys.errname(cm.errno or 0))
        local ev = lcs.drain_events(w, fd)
        local names = {}
        for _, e in ipairs(ev) do names[#names + 1] = e.name end
        t:assert_eq(table.concat(names, ","), "First,Second,Third",
            "the mutation log was walked in operation order, as one uninterrupted batch")
        sys.close(w, txn); sys.close(w, fd)
    end)

test("a watcher whose share of a commit exceeds the burst cap gets one OVERFLOW " ..
     "and none of its events",
    { spec = "PKM *watch.dispatch.burst-cap-replaces-a-watchers-batch-with-one-overflow" },
    function(t)
        local over = open_nb(ROOT .. "\\Burst")
        local under = open_nb(ROOT .. "\\UnderCap")
        arm(t, over)
        arm(t, under)
        local txn = assert(lcs.begin_transaction(w))
        -- One blanket tombstone masking BURST_VALUES names expands to
        -- that many VALUE_DELETED events for the watcher on that key.
        local b = lcs.blanket_tombstone(src, w, over, "high", true, { txn_fd = txn })
        t:assert_eq(b.ret, 0, "the blanket: " .. sys.errname(b.errno or 0))
        local s = lcs.set_value(src, w, under, "One", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = txn })
        t:assert_eq(s.ret, 0, "and one ordinary write: " .. sys.errname(s.errno or 0))
        local cm = lcs.commit(src, w, txn)
        t:assert_eq(cm.ret, 0, "commit: " .. sys.errname(cm.errno or 0))

        local hit = lcs.drain_events(w, over)
        t:assert_eq(#hit, 1, "the over-cap watcher received exactly one record for " ..
            BURST_VALUES .. " events against a cap of " .. BURST_CAP .. ": " ..
            lcs.event_summary(hit))
        t:assert_eq(hit[1].type, lcs.WATCH.OVERFLOW, "and it is an OVERFLOW")
        local kept = lcs.drain_events(w, under)
        t:assert_eq(#kept, 1, "the cap is counted per watcher, so the other one kept its "
            .. "event: " .. lcs.event_summary(kept))
        t:assert_eq(kept[1].type, lcs.WATCH.VALUE_SET, "VALUE_SET")
        sys.close(w, txn); sys.close(w, under); sys.close(w, over)
    end)

test("the burst OVERFLOW is queued ahead of the batch",
    { spec = "PKM *watch.dispatch.burst-overflow-queued-ahead-of-the-batch" },
    function(t)
        local over = open_nb(ROOT .. "\\Burst")
        arm(t, over)
        -- Something already queued before the transaction, to fix where
        -- the batch starts in this watcher's queue.
        lcs.set_value(src, w, over, "Earlier", lcs.TYPE.DWORD, lcs.dword(1))
        local txn = assert(lcs.begin_transaction(w))
        lcs.blanket_tombstone(src, w, over, "high", false, { txn_fd = txn })
        local cm = lcs.commit(src, w, txn)
        t:assert_eq(cm.ret, 0, "commit: " .. sys.errname(cm.errno or 0))
        lcs.set_value(src, w, over, "Later", lcs.TYPE.DWORD, lcs.dword(1))

        local ev = lcs.drain_events(w, over)
        t:assert_eq(#ev, 3, "queue: " .. lcs.event_summary(ev))
        t:assert_eq(ev[1].name, "Earlier", "what was queued before the commit stays first")
        t:assert_eq(ev[2].type, lcs.WATCH.OVERFLOW,
            "the OVERFLOW is the first thing the commit contributed — ahead of the batch")
        t:assert_eq(ev[3].name, "Later",
            "and everything the watcher is owed afterwards comes after it")
        sys.close(w, txn); sys.close(w, over)
    end)

-- ---- recovery dispatch ------------------------------------------------

test("deleting a layer, changing its precedence and disabling it all trigger recovery",
    { spec = "PKM *watch.dispatch.recovery-triggering-operations" }, function(t)
        local fd = open_nb(ROOT .. "\\Recovery")
        arm(t, fd)
        local layer_fd = assert(lcs.create_layer(src, w, "Recover", { precedence = 40 }))
        lcs.drain_events(w, fd)

        local p = lcs.set_value(src, w, layer_fd, "Precedence", lcs.TYPE.DWORD, lcs.dword(41))
        t:assert_eq(p.ret, 0, "changing its precedence: " .. sys.errname(p.errno or 0))
        local ev = lcs.drain_events(w, fd)
        t:assert_eq(count_of(ev, lcs.WATCH.OVERFLOW), 1,
            "a precedence change is a recovery-triggering operation: " ..
            lcs.event_summary(ev))

        local d = lcs.set_value(src, w, layer_fd, "Enabled", lcs.TYPE.DWORD, lcs.dword(0))
        t:assert_eq(d.ret, 0, "disabling it: " .. sys.errname(d.errno or 0))
        ev = lcs.drain_events(w, fd)
        t:assert_eq(count_of(ev, lcs.WATCH.OVERFLOW), 1, "so is disabling: " ..
            lcs.event_summary(ev))

        local e = lcs.set_value(src, w, layer_fd, "Enabled", lcs.TYPE.DWORD, lcs.dword(1))
        t:assert_eq(e.ret, 0, "enabling it again: " .. sys.errname(e.errno or 0))
        ev = lcs.drain_events(w, fd)
        t:assert_eq(count_of(ev, lcs.WATCH.OVERFLOW), 1, "so is enabling: " ..
            lcs.event_summary(ev))

        local k = lcs.delete_key(src, w, layer_fd, {})
        t:assert_eq(k.ret, 0, "deleting the layer: " .. sys.errname(k.errno or 0))
        ev = lcs.drain_events(w, fd)
        t:assert_eq(count_of(ev, lcs.WATCH.OVERFLOW), 1, "and so is deleting it: " ..
            lcs.event_summary(ev))
        sys.close(w, layer_fd); sys.close(w, fd)
    end)

test("recovery increments the hive generation and queues a no-name OVERFLOW",
    { spec = "PKM *watch.dispatch.recovery-bumps-generation-and-queues-overflow" },
    function(t)
        local fd = open_nb(ROOT .. "\\Recovery")
        arm(t, fd)
        local layer_fd = assert(lcs.create_layer(src, w, "Generation", { precedence = 42 }))
        lcs.drain_events(w, fd)
        local before = generation(fd)
        local k = lcs.delete_key(src, w, layer_fd, {})
        t:assert_eq(k.ret, 0, "deleting the layer: " .. sys.errname(k.errno or 0))
        local after = generation(fd)
        t:assert(after > before,
            "the affected hive's generation number moved: " .. before .. " -> " .. after)
        local ev = lcs.drain_events(w, fd)
        t:assert_eq(#ev, 1, "one record: " .. lcs.event_summary(ev))
        t:assert_eq(ev[1].type, lcs.WATCH.OVERFLOW, "a no-name OVERFLOW is the notification")
        t:assert_eq(ev[1].name, "", "no name")
        sys.close(w, layer_fd); sys.close(w, fd)
    end)

test("recovery dispatch does not disarm anything",
    { spec = "PKM *watch.dispatch.recovery-does-not-disarm" }, function(t)
        local fd = open_nb(ROOT .. "\\Recovery")
        arm(t, fd)
        local layer_fd = assert(lcs.create_layer(src, w, "StaysArmed", { precedence = 43 }))
        lcs.drain_events(w, fd)
        lcs.delete_key(src, w, layer_fd, {})
        local ev = lcs.drain_events(w, fd)
        t:assert_eq(count_of(ev, lcs.WATCH.OVERFLOW), 1, "the OVERFLOW arrived")
        lcs.set_value(src, w, fd, "AfterRecovery", lcs.TYPE.DWORD, lcs.dword(1))
        local after = lcs.drain_events(w, fd)
        t:assert_eq(#after, 1, "and the watch is still armed: " .. lcs.event_summary(after))
        t:assert_eq(after[1].name, "AfterRecovery", "delivering ordinary events again")
        sys.close(w, layer_fd); sys.close(w, fd)
    end)

test("the scope of recovery delivery is the source, not the hive",
    { spec = "PKM *watch.dispatch.recovery-scope-is-the-source-not-the-hive" }, function(t)
        local machine = open_nb(ROOT .. "\\Recovery")
        local other = open_nb("Other\\Thing")
        arm(t, machine)
        arm(t, other)
        local layer_fd = assert(lcs.create_layer(src, w, "Scoped", { precedence = 44 }))
        lcs.drain_events(w, machine); lcs.drain_events(w, other)
        local k = lcs.delete_key(src, w, layer_fd, {})
        t:assert_eq(k.ret, 0, "deleting a layer, an operation in the Machine hive: " ..
            sys.errname(k.errno or 0))
        local hit = lcs.drain_events(w, machine)
        t:assert_eq(count_of(hit, lcs.WATCH.OVERFLOW), 1, "the Machine watch was told")
        local untouched = lcs.drain_events(w, other)
        t:assert_eq(count_of(untouched, lcs.WATCH.OVERFLOW), 1,
            "a watch on another hive of the same source, which the operation did not " ..
            "touch, was told too: " .. lcs.event_summary(untouched))
        local nothing_here = lcs.enum_subkeys(src, w, other, 0)
        t:assert_eq(nothing_here.errno, sys.E.NOENT,
            "that hive holds nothing the layer operation could have altered")
        sys.close(w, layer_fd); sys.close(w, other); sys.close(w, machine)
    end)

-- Kernel bug: recovery bumps the generation counter of every hive the
-- source backs, not only the affected one. Ordinary mutations keep the
-- counters independent — a write in `Machine` leaves `Other`'s alone —
-- so this is specific to the recovery path, and it defeats the point of
-- the generation number, which is to let a watcher that received an
-- OVERFLOW decide whether anything in *its* hive actually changed.
test("recovery increments only the affected hive's generation, though it delivers " ..
     "to every watch on the source",
    { spec = "PKM *watch.dispatch.recovery-scope-is-the-source-not-the-hive",
      tags = { "known-bug" } }, function(t)
        local machine = open_nb(ROOT .. "\\Recovery")
        local other = open_nb("Other\\Thing")
        arm(t, other)
        local layer_fd = assert(lcs.create_layer(src, w, "GenScope", { precedence = 45 }))
        lcs.drain_events(w, other)
        local before = generation(other)
        local k = lcs.delete_key(src, w, layer_fd, {})
        t:assert_eq(k.ret, 0, "deleting a Machine-hive layer: " .. sys.errname(k.errno or 0))
        t:assert_eq(count_of(lcs.drain_events(w, other), lcs.WATCH.OVERFLOW), 1,
            "the other hive's watch is told, because delivery is per source")
        t:assert_eq(generation(other), before,
            "but the generation counters are per hive, and that hive was not affected")
        sys.close(w, layer_fd); sys.close(w, other); sys.close(w, machine)
    end)

test("a restore publishes recovery only after the source commit succeeds",
    { spec = "PKM *watch.dispatch.restore-recovery-published-only-after-commit" },
    function(t)
        local fd = open_nb(ROOT .. "\\Restore")
        arm(t, fd)
        local r, _, bytes = lcs.backup_to_file(src, w, fd, "/restore-recovery.bak")
        t:assert_eq(r.ret, 0, "backing the subtree up: " .. sys.errname(r.errno or 0))
        t:assert(bytes and #bytes > 0, "a stream came back")
        lcs.drain_events(w, fd)

        local bad = lcs.restore_bytes(src, w, fd, "/restore-recovery.bad",
            bytes:sub(1, #bytes - 8))
        t:assert(bad.ret ~= 0, "a truncated stream fails the restore: " ..
            sys.errname(bad.errno or 0))
        local nothing = lcs.drain_events(w, fd)
        t:assert_eq(#nothing, 0,
            "a restore that fails before commit emits nothing: " ..
            lcs.event_summary(nothing))

        local ok = lcs.restore_bytes(src, w, fd, "/restore-recovery.ok", bytes)
        t:assert_eq(ok.ret, 0, "the whole stream restores: " .. sys.errname(ok.errno or 0))
        local ev = lcs.drain_events(w, fd)
        t:assert_eq(count_of(ev, lcs.WATCH.OVERFLOW), 1,
            "and recovery is published once the commit succeeded: " ..
            lcs.event_summary(ev))
        sys.close(w, fd)
    end)

-- ---- source restart ---------------------------------------------------
--
-- These take the source's slot down, so they run last.

test("a disconnected source leaves watches armed and silent while operations fail EIO",
    { spec = "PKM *watch.dispatch.disconnect-keeps-watches-armed-and-silent" }, function(t)
        local fd = open_nb(ROOT .. "\\Restart")
        arm(t, fd)
        src:disconnect()
        local ev = lcs.drain_events(w, fd)
        t:assert_eq(#ev, 0, "nothing is delivered on disconnect: " .. lcs.event_summary(ev))
        local q = lcs.query_value(nil, w, fd, "Anything")
        t:assert_eq(q.errno, sys.E.IO, "and an operation needing the source returns EIO")
        assert(src:resume())
        src:pump()
        sys.close(w, fd)
    end)

test("OVERFLOW arrives on re-registration, and fds resume without re-arming",
    { spec = "PKM *watch.dispatch.overflow-arrives-on-re-registration" }, function(t)
        local fd = open_nb(ROOT .. "\\Restart")
        arm(t, fd)
        src:disconnect()
        t:assert_eq(#lcs.drain_events(w, fd), 0, "the disconnect itself said nothing")
        assert(src:resume())
        src:pump()
        local ev = lcs.drain_events(w, fd)
        t:assert_eq(count_of(ev, lcs.WATCH.OVERFLOW), 1,
            "the OVERFLOW arrives when the source is back and can answer a re-read: " ..
            lcs.event_summary(ev))
        sys.close(w, fd)
    end)

test("existing fds resume without re-opening and no watcher has to re-arm",
    { spec = "PKM *watch.dispatch.fds-resume-without-re-arming" }, function(t)
        local fd = open_nb(ROOT .. "\\Restart")
        arm(t, fd)
        src:disconnect()
        assert(src:resume())
        src:pump()
        lcs.drain_events(w, fd)
        local s = lcs.set_value(src, w, fd, "AfterRestart", lcs.TYPE.DWORD, lcs.dword(1))
        t:assert_eq(s.ret, 0, "the same fd works again without re-opening: " ..
            sys.errname(s.errno or 0))
        local ev = lcs.drain_events(w, fd)
        t:assert_eq(#ev, 1, "and the watch delivers without a second REG_IOC_NOTIFY: " ..
            lcs.event_summary(ev))
        t:assert_eq(ev[1].name, "AfterRestart", "the event that followed the restart")
        sys.close(w, fd)
    end)
