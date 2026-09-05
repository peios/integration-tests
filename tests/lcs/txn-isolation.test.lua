-- PKM §5.7.2 — isolation and the mutation log: read-your-own-writes,
-- what the kernel keeps and what it does not, sequence numbers, layer
-- precedence coherency, and the absence of conflict detection.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")

local vm = provium:vm("v", "kernel-only"):boot()

local ROOT = "Machine\\Software\\Test"
local ETIMEDOUT = 110

local src = lcs.source(vm)
src:seed_param("RequestTimeoutMs", 30000)       -- the compiled-in default
src:seed_param("TransactionTimeoutMs", 30000)   -- the compiled-in default
src:seed_layer("alpha", { precedence = 5, enabled = true })
src:seed_layer("beta", { precedence = 10, enabled = true })
src:key(ROOT)
src:key(ROOT .. "\\Isolation")
src:key(ROOT .. "\\Log\\Deep")
src:key(ROOT .. "\\Sequences")
src:key(ROOT .. "\\Conflicts")
src:key(ROOT .. "\\Retained")

local coherency = src:key(ROOT .. "\\Coherency")
src:value(coherency, "Which", lcs.TYPE.SZ, lcs.sz("alpha"), { layer = "alpha" })
src:value(coherency, "Which", lcs.TYPE.SZ, lcs.sz("beta"), { layer = "beta" })

assert(src:register())
src:pump()

local w = vm:spawn_worker()

local function open_key(path, who)
    local r = lcs.open_key(src, who or w, -1, path, lcs.KEY_ALL_ACCESS)
    assert(r.ret >= 0, "opening " .. path .. ": " .. sys.errname(r.errno or 0))
    return r.ret
end

local params_fd = open_key(lcs.PARAMS_PATH)

local function set_param(t, name, value)
    local s = lcs.set_value(src, w, params_fd, name, lcs.TYPE.DWORD, lcs.dword(value))
    t:assert_eq(s.ret, 0, "setting " .. name .. ": " .. sys.errname(s.errno or 0))
end

-- ---- read-your-own-writes ---------------------------------------------

test("within a bound transaction, reads see the transaction's own uncommitted writes",
    { spec = "PKM *txn.isolation.read-your-own-writes" }, function(t)
        local fd = open_key(ROOT .. "\\Isolation")
        local txn = assert(lcs.begin_transaction(w))
        local s = lcs.set_value(src, w, fd, "Own", lcs.TYPE.DWORD, lcs.dword(7),
            { txn_fd = txn })
        t:assert_eq(s.ret, 0, "the write: " .. sys.errname(s.errno or 0))
        local inside = lcs.query_value(src, w, fd, "Own", { txn_fd = txn })
        t:assert_eq(inside.ret, 0, "a read tagged with the transaction finds it: " ..
            sys.errname(inside.errno or 0))
        t:assert_eq(inside.data, lcs.dword(7), "with the value it wrote")
        local outside = lcs.query_value(src, w, fd, "Own")
        t:assert_eq(outside.errno, sys.E.NOENT, "an untagged read does not")
        sys.close(w, txn); sys.close(w, fd); src:pump(50)
    end)

test("no uncommitted registry data is cached in the kernel to resolve reads",
    { spec = "PKM *txn.isolation.no-uncommitted-data-cached-in-the-kernel" }, function(t)
        local fd = open_key(ROOT .. "\\Isolation")
        local txn = assert(lcs.begin_transaction(w))
        lcs.set_value(src, w, fd, "Cached", lcs.TYPE.DWORD, lcs.dword(1), { txn_fd = txn })
        local mark = src:mark()
        local inside = lcs.query_value(src, w, fd, "Cached", { txn_fd = txn })
        t:assert_eq(inside.ret, 0, "the read succeeds: " .. sys.errname(inside.errno or 0))
        local served = src:served(lcs.OP.QUERY_VALUES, mark)
        t:assert(#served >= 1,
            "and it went to the source rather than being answered from the kernel")
        t:assert(served[1].txn ~= 0,
            "tagged with the transaction id, so the source executes it inside its " ..
            "own open transaction")
        sys.close(w, txn); sys.close(w, fd); src:pump(50)
    end)

test("a transaction's writes are invisible to another process until commit",
    { spec = "PKM *txn.isolation.uncommitted-writes-are-invisible-externally" },
    function(t)
        local w2 = vm:spawn_worker()
        local mine = open_key(ROOT .. "\\Isolation")
        local theirs = open_key(ROOT .. "\\Isolation", w2)
        local txn = assert(lcs.begin_transaction(w))
        lcs.set_value(src, w, mine, "Hidden", lcs.TYPE.DWORD, lcs.dword(1), { txn_fd = txn })
        local other = lcs.query_value(src, w2, theirs, "Hidden")
        t:assert_eq(other.errno, sys.E.NOENT,
            "another process sees only committed state")
        t:assert_eq(lcs.commit(src, w, txn).ret, 0, "commit")
        local after = lcs.query_value(src, w2, theirs, "Hidden")
        t:assert_eq(after.ret, 0, "and sees it once the transaction committed: " ..
            sys.errname(after.errno or 0))
        sys.close(w, txn); sys.close(w2, theirs); sys.close(w, mine)
        w2:kill(); w2:join()
    end)

-- ---- the mutation log --------------------------------------------------

test("the log records the affected name and ancestor chain for each operation",
    { spec = "PKM *txn.isolation.log-records-per-operation-context" }, function(t)
        -- What the log holds is only visible through what LCS can
        -- produce after the commit: the watch batch, with each
        -- operation's own name and its own relative path.
        local watcher = open_key(ROOT .. "\\Log")
        lcs.nonblock(w, watcher)
        local n = lcs.notify(nil, w, watcher, lcs.NOTIFY.ALL, true)
        t:assert_eq(n.ret, 0, "a subtree watch above both keys")
        local shallow = open_key(ROOT .. "\\Log")
        local deep = open_key(ROOT .. "\\Log\\Deep")
        local txn = assert(lcs.begin_transaction(w))
        lcs.set_value(src, w, shallow, "Near", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = txn })
        lcs.set_value(src, w, deep, "Far", lcs.TYPE.DWORD, lcs.dword(1), { txn_fd = txn })
        t:assert_eq(lcs.commit(src, w, txn).ret, 0, "commit")
        local ev = lcs.drain_events(w, watcher)
        t:assert_eq(#ev, 2, "one event per accepted operation: " .. lcs.event_summary(ev))
        t:assert_eq(ev[1].name, "Near", "the first operation's value name")
        t:assert_eq(ev[1].depth, 0, "with the ancestor chain it was recorded against")
        t:assert_eq(ev[2].name, "Far", "the second operation's value name")
        t:assert_eq(ev[2].depth, 1, "and its own, different chain")
        t:assert_eq(ev[2].components[1], "Deep", "naming the key it happened on")
        lcs.notify(nil, w, watcher, 0, false)
        sys.close(w, txn); sys.close(w, deep); sys.close(w, shallow); sys.close(w, watcher)
    end)

test("the log is not a rollback journal: the source rolls back, the kernel does not",
    { spec = "PKM *txn.isolation.log-is-not-a-rollback-journal" }, function(t)
        local fd = open_key(ROOT .. "\\Isolation")
        local txn = assert(lcs.begin_transaction(w))
        for _, name in ipairs({ "R1", "R2", "R3" }) do
            lcs.set_value(src, w, fd, name, lcs.TYPE.DWORD, lcs.dword(1), { txn_fd = txn })
        end
        local mark = src:mark()
        sys.close(w, txn)
        src:pump(150)
        t:assert_eq(#src:served(lcs.OP.ABORT_TXN, mark), 1,
            "the source is told to discard, once")
        for _, op in ipairs({ lcs.OP.SET_VALUE, lcs.OP.DELETE_VALUE, lcs.OP.DROP_KEY,
                              lcs.OP.DELETE_ENTRY }) do
            t:assert_eq(#src:served(op, mark), 0,
                "and LCS replayed no inverse " .. lcs.OP_NAME[op] .. " of its own")
        end
        for _, name in ipairs({ "R1", "R2", "R3" }) do
            t:assert_eq(lcs.query_value(src, w, fd, name).errno, sys.E.NOENT,
                name .. " is gone because the source's own transaction state was " ..
                "authoritative")
        end
        sys.close(w, fd)
    end)

test("the log is released with no events on an explicit abort and on a timeout " ..
     "before a commit is dispatched",
    { spec = "PKM *txn.isolation.log-release-conditions" }, function(t)
        local fd = open_key(ROOT .. "\\Isolation")
        lcs.nonblock(w, fd)
        local n = lcs.notify(nil, w, fd, lcs.NOTIFY.ALL, false)
        t:assert_eq(n.ret, 0, "arming a watch to see any events the log could produce")

        local abort = assert(lcs.begin_transaction(w))
        lcs.set_value(src, w, fd, "Aborted", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = abort })
        sys.close(w, abort); src:pump(150)
        t:assert_eq(#lcs.drain_events(w, fd), 0,
            "an explicit abort releases the log with no events emitted")

        set_param(t, "TransactionTimeoutMs", 1000)
        lcs.drain_events(w, fd)
        local timed = assert(lcs.begin_transaction(w))
        lcs.set_value(src, w, fd, "TimedOut", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = timed })
        sys.nanosleep(vm, 2, 0)
        src:pump(150)
        t:assert_eq(lcs.txn_status(nil, w, timed).state, lcs.TXN.TIMED_OUT, "it timed out")
        t:assert_eq(#lcs.drain_events(w, fd), 0,
            "a lifetime timeout before a commit is dispatched releases it too")
        sys.close(w, timed)
        set_param(t, "TransactionTimeoutMs", 30000)
        lcs.notify(nil, w, fd, 0, false)
        sys.close(w, fd)
    end)

test("the log is retained across a post-dispatch commit timeout",
    { spec = "PKM *txn.isolation.log-retained-across-a-post-dispatch-timeout" },
    function(t)
        local fd = open_key(ROOT .. "\\Retained")
        lcs.nonblock(w, fd)
        t:assert_eq(lcs.notify(nil, w, fd, lcs.NOTIFY.ALL, false).ret, 0, "armed")
        set_param(t, "RequestTimeoutMs", 1000)
        lcs.drain_events(w, fd)

        src:intercept(lcs.OP.COMMIT_TXN, function() return lcs.HOLD end)
        local txn = assert(lcs.begin_transaction(w))
        lcs.set_value(src, w, fd, "Retained", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = txn })
        local cm = lcs.commit(src, w, txn)
        t:assert_eq(cm.errno, ETIMEDOUT, "the commit request timed out after dispatch")
        t:assert_eq(lcs.txn_status(nil, w, txn).state, lcs.TXN.TIMED_OUT, "TIMED_OUT")
        t:assert_eq(#lcs.drain_events(w, fd), 0, "nothing has been dispatched yet")

        local held = src:held_ids()
        t:assert_eq(#held, 1, "the source still holds the commit request")
        src:release(held[1])
        sys.nanosleep(vm, 1, 0)
        src:pump(150)
        local ev = lcs.drain_events(w, fd)
        t:assert_eq(#ev, 1, "the late answer found the log still there: " ..
            lcs.event_summary(ev))
        t:assert_eq(ev[1].name, "Retained",
            "so the events the log exists to produce could still be produced")
        src:intercept(lcs.OP.COMMIT_TXN, nil)
        set_param(t, "RequestTimeoutMs", 30000)
        lcs.notify(nil, w, fd, 0, false)
        sys.close(w, txn); sys.close(w, fd)
    end)

test("the mutation log is bounded at 4096 entries",
    { spec = "PKM *txn.isolation.log-bounded-at-4096-entries",
      covered_by = "kunit:pkm_lcs_kunit_transaction",
      skip = "the bound is a compile-time constant with no configuration " ..
             "knob, so reaching it from a guest means 4097 accepted " ..
             "mutating operations in one transaction — measured at about " ..
             "half a second each through a Lua-served source, or half an " ..
             "hour for the file; runs under " ..
             "pkm_lcs_kunit_transaction_log_capacity_fails_before_reserve, " ..
             "which shrinks the capacity through a KUnit-only hook " ..
             "(pkm_lcs_kunit_transaction_fd_set_log_capacity) and asserts " ..
             "log.capacity" }, function(t) end)

test("exceeding the log bound fails the operation with ENOMEM",
    { spec = "PKM *txn.isolation.log-full-fails-the-operation-with-enomem",
      covered_by = "kunit:pkm_lcs_kunit_transaction",
      skip = "needs a full 4096-entry log, which no guest can build in " ..
             "reasonable time (see log-bounded-at-4096-entries); runs " ..
             "under pkm_lcs_kunit_transaction_log_capacity_fails_before_reserve, " ..
             "which expects -ENOMEM from the operation past the capacity" },
    function(t) end)

test("an operation whose log entry cannot be allocated fails before the source send",
    { spec = "PKM *txn.isolation.log-allocation-failure-precedes-the-source-send",
      covered_by = "kunit:pkm_lcs_kunit_transaction",
      skip = "the ordering is only visible when the log is full, which no " ..
             "guest can arrange (see log-bounded-at-4096-entries); runs " ..
             "under pkm_lcs_kunit_transaction_log_capacity_fails_before_reserve, " ..
             "which checks the mutation handle is left inactive so nothing " ..
             "is dispatched, and that the log's entry_count and " ..
             "last_sequence are unchanged" }, function(t) end)

-- ---- sequence numbers --------------------------------------------------

test("a transactional mutation is assigned its sequence when it is accepted",
    { spec = "PKM *txn.isolation.sequence-assigned-on-accept-not-at-commit" },
    function(t)
        local fd = open_key(ROOT .. "\\Sequences")
        local txn = assert(lcs.begin_transaction(w))
        lcs.set_value(src, w, fd, "Early", lcs.TYPE.DWORD, lcs.dword(1), { txn_fd = txn })
        -- A non-transactional write in between takes a later number.
        lcs.set_value(src, w, fd, "Between", lcs.TYPE.DWORD, lcs.dword(1))
        local between = lcs.query_value(src, w, fd, "Between")
        t:assert_eq(between.ret, 0, "the intervening write: " ..
            sys.errname(between.errno or 0))
        t:assert_eq(lcs.commit(src, w, txn).ret, 0, "commit")
        local early = lcs.query_value(src, w, fd, "Early")
        t:assert_eq(early.ret, 0, "the transactional write committed: " ..
            sys.errname(early.errno or 0))
        t:assert(early.sequence < between.sequence,
            "and carries the number it was given when accepted, not one from " ..
            "commit time: " .. early.sequence .. " vs " .. between.sequence)
        sys.close(w, txn); sys.close(w, fd)
    end)

test("the sequence numbers of an aborted transaction are simply never used",
    { spec = "PKM *txn.isolation.aborted-sequence-numbers-are-never-used" }, function(t)
        local fd = open_key(ROOT .. "\\Sequences")
        lcs.set_value(src, w, fd, "Before", lcs.TYPE.DWORD, lcs.dword(1))
        local before = lcs.query_value(src, w, fd, "Before").sequence
        local txn = assert(lcs.begin_transaction(w))
        for i = 1, 4 do
            lcs.set_value(src, w, fd, "Doomed" .. i, lcs.TYPE.DWORD, lcs.dword(i),
                { txn_fd = txn })
        end
        sys.close(w, txn); src:pump(150)
        lcs.set_value(src, w, fd, "After", lcs.TYPE.DWORD, lcs.dword(1))
        local after = lcs.query_value(src, w, fd, "After").sequence
        t:assert(after > before + 4,
            "the aborted numbers were consumed and left as a gap: " ..
            before .. " -> " .. after)
        t:assert_eq(lcs.query_value(src, w, fd, "Doomed1").errno, sys.E.NOENT,
            "and nothing carries them, so gaps in the sequence space mean nothing")
        sys.close(w, fd)
    end)

-- ---- layer precedence coherency ----------------------------------------

test("a precedence change does not take effect inside its own transaction",
    { spec = "PKM *txn.isolation.precedence-change-does-not-take-effect-in-its-own-transaction" },
    function(t)
        local fd = open_key(ROOT .. "\\Coherency")
        local beta = open_key(lcs.LAYERS_PATH .. "\\beta")
        local start = lcs.query_value(src, w, fd, "Which")
        t:assert_eq(start.data, lcs.sz("beta"), "beta is on top to begin with")

        local txn = assert(lcs.begin_transaction(w))
        local s = lcs.set_value(src, w, beta, "Precedence", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = txn })
        t:assert_eq(s.ret, 0, "lowering beta below alpha inside a transaction: " ..
            sys.errname(s.errno or 0))
        local inside = lcs.query_value(src, w, fd, "Which", { txn_fd = txn })
        t:assert_eq(inside.data, lcs.sz("beta"),
            "the value still resolves under the old order")
        t:assert_eq(lcs.commit(src, w, txn).ret, 0, "commit")
        local after = lcs.query_value(src, w, fd, "Which")
        t:assert_eq(after.data, lcs.sz("alpha"), "and the new order takes effect at commit")
        sys.close(w, txn)

        -- Put the fixture back for the cases below.
        local back = assert(lcs.begin_transaction(w))
        lcs.set_value(src, w, beta, "Precedence", lcs.TYPE.DWORD, lcs.dword(10),
            { txn_fd = back })
        t:assert_eq(lcs.commit(src, w, back).ret, 0, "restoring beta's precedence")
        sys.close(w, back); sys.close(w, beta); sys.close(w, fd)
    end)

test("resolution always uses the published layer cache, refreshed only at commit",
    { spec = "PKM *txn.isolation.resolution-uses-the-published-layer-cache" }, function(t)
        local fd = open_key(ROOT .. "\\Coherency")
        local beta = open_key(lcs.LAYERS_PATH .. "\\beta")
        local txn = assert(lcs.begin_transaction(w))
        lcs.set_value(src, w, beta, "Precedence", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = txn })
        -- An untagged read, from outside the transaction, also sees the
        -- published table: nothing about the pending change is live.
        local outside = lcs.query_value(src, w, fd, "Which")
        t:assert_eq(outside.data, lcs.sz("beta"),
            "an untagged read resolves under the published table")
        local tagged = lcs.query_value(src, w, fd, "Which", { txn_fd = txn })
        t:assert_eq(tagged.data, lcs.sz("beta"),
            "and so does a tagged one, because resolution never uses a pending cache")
        sys.close(w, txn); src:pump(150)
        t:assert_eq(lcs.query_value(src, w, fd, "Which").data, lcs.sz("beta"),
            "the refresh was dropped on abort")
        sys.close(w, beta); sys.close(w, fd)
    end)

test("reading Precedence back inside the transaction shows the new number",
    { spec = "PKM *txn.isolation.precedence-value-reads-back-as-the-new-number" },
    function(t)
        local beta = open_key(lcs.LAYERS_PATH .. "\\beta")
        local txn = assert(lcs.begin_transaction(w))
        lcs.set_value(src, w, beta, "Precedence", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = txn })
        local q = lcs.query_value(src, w, beta, "Precedence", { txn_fd = txn })
        t:assert_eq(q.ret, 0, "the read: " .. sys.errname(q.errno or 0))
        t:assert_eq(q.data, lcs.dword(1),
            "an ordinary read-your-own-writes read from the source")
        sys.close(w, txn); src:pump(150); sys.close(w, beta)
    end)

test("every other value in the same transaction resolves under the old precedence",
    { spec = "PKM *txn.isolation.other-values-resolve-under-the-old-precedence" },
    function(t)
        local fd = open_key(ROOT .. "\\Coherency")
        local beta = open_key(lcs.LAYERS_PATH .. "\\beta")
        local txn = assert(lcs.begin_transaction(w))
        lcs.set_value(src, w, beta, "Precedence", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = txn })
        local new_number = lcs.query_value(src, w, beta, "Precedence", { txn_fd = txn })
        t:assert_eq(new_number.data, lcs.dword(1), "Precedence reads back as 1")
        local other = lcs.query_value(src, w, fd, "Which", { txn_fd = txn })
        t:assert_eq(other.data, lcs.sz("beta"),
            "and any other value still resolves under the old precedence order")
        t:assert_eq(other.layer, "beta", "with the old winner named")
        sys.close(w, txn); src:pump(150); sys.close(w, beta); sys.close(w, fd)
    end)

test("the layer cache refresh completes before REG_IOC_COMMIT returns",
    { spec = "PKM *txn.isolation.layer-cache-refresh-completes-before-commit-returns" },
    function(t)
        local fd = open_key(ROOT .. "\\Coherency")
        local beta = open_key(lcs.LAYERS_PATH .. "\\beta")
        local txn = assert(lcs.begin_transaction(w))
        lcs.set_value(src, w, beta, "Precedence", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = txn })
        t:assert_eq(lcs.commit(src, w, txn).ret, 0, "commit returns 0")
        -- The very next read, with nothing in between, already resolves
        -- under the refreshed table.
        local q = lcs.query_value(src, w, fd, "Which")
        t:assert_eq(q.data, lcs.sz("alpha"), "the new order is already published")
        t:assert_eq(q.layer, "alpha", "and names the new winner")
        sys.close(w, txn)

        local back = assert(lcs.begin_transaction(w))
        lcs.set_value(src, w, beta, "Precedence", lcs.TYPE.DWORD, lcs.dword(10),
            { txn_fd = back })
        t:assert_eq(lcs.commit(src, w, back).ret, 0, "restoring beta's precedence")
        sys.close(w, back); sys.close(w, beta); sys.close(w, fd)
    end)

-- ---- conflicts ---------------------------------------------------------

test("transactions are atomic but not conflict-detecting: the second committer wins",
    { spec = "PKM *txn.isolation.second-committer-wins" }, function(t)
        local fd = open_key(ROOT .. "\\Conflicts")
        local first = assert(lcs.begin_transaction(w))
        local second = assert(lcs.begin_transaction(w))
        local a = lcs.set_value(src, w, fd, "Contended", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = first })
        t:assert_eq(a.ret, 0, "the first writes: " .. sys.errname(a.errno or 0))
        local b = lcs.set_value(src, w, fd, "Contended", lcs.TYPE.DWORD, lcs.dword(2),
            { txn_fd = second })
        t:assert_eq(b.ret, 0, "the second writes the same value name: " ..
            sys.errname(b.errno or 0))
        t:assert_eq(lcs.commit(src, w, first).ret, 0, "the first commit succeeds")
        t:assert_eq(lcs.commit(src, w, second).ret, 0, "and so does the second")
        local q = lcs.query_value(src, w, fd, "Contended")
        t:assert_eq(q.data, lcs.dword(2),
            "the one that committed second wins, on its higher sequence number")
        sys.close(w, second); sys.close(w, first); sys.close(w, fd)
    end)

test("there is no read set, no version check and no per-key validation in the commit path",
    { spec = "PKM *txn.isolation.no-conflict-detection" }, function(t)
        local fd = open_key(ROOT .. "\\Conflicts")
        local txn = assert(lcs.begin_transaction(w))
        lcs.set_value(src, w, fd, "Read", lcs.TYPE.DWORD, lcs.dword(1), { txn_fd = txn })
        local seen = lcs.query_value(src, w, fd, "Read", { txn_fd = txn })
        t:assert_eq(seen.ret, 0, "read inside the transaction: " ..
            sys.errname(seen.errno or 0))
        -- Something else changes what was read, outside the transaction.
        lcs.set_value(src, w, fd, "Read", lcs.TYPE.DWORD, lcs.dword(99))
        local mark = src:mark()
        t:assert_eq(lcs.commit(src, w, txn).ret, 0,
            "the commit is not validated against what the transaction read")
        for _, op in ipairs({ lcs.OP.QUERY_VALUES }) do
            local served = src:served(op, mark)
            for _, r in ipairs(served) do
                t:assert(r.txn == 0,
                    "and any post-commit query is an ordinary one, not a per-key " ..
                    "version check inside the transaction")
            end
        end
        sys.close(w, txn); sys.close(w, fd)
    end)

test("LCS sends one ordered, atomic commit and leaves serialisation to the source",
    { spec = "PKM *txn.isolation.rsi-requires-atomic-ordered-serialised-commits" },
    function(t)
        local fd = open_key(ROOT .. "\\Conflicts")
        local txn = assert(lcs.begin_transaction(w))
        local mark = src:mark()
        for _, name in ipairs({ "Ordered1", "Ordered2", "Ordered3" }) do
            lcs.set_value(src, w, fd, name, lcs.TYPE.DWORD, lcs.dword(1), { txn_fd = txn })
        end
        local writes = src:served(lcs.OP.SET_VALUE, mark)
        t:assert_eq(#writes, 3, "the three writes reached the source")
        local names = {}
        local txn_id
        for _, r in ipairs(writes) do
            names[#names + 1] = string.unpack("<s4", r.payload, 17)
            txn_id = txn_id or r.txn
            t:assert_eq(r.txn, txn_id, "each tagged with the same transaction id")
        end
        t:assert_eq(table.concat(names, ","), "Ordered1,Ordered2,Ordered3",
            "in the order the caller performed them, as the RSI requires")
        t:assert_eq(lcs.commit(src, w, txn).ret, 0, "commit")
        t:assert_eq(#src:served(lcs.OP.COMMIT_TXN, mark), 1,
            "and exactly one RSI_COMMIT_TRANSACTION asks for them to be applied " ..
            "atomically")
        sys.close(w, txn); sys.close(w, fd)
    end)

test("a conditional write is per-operation and tests the layer's own entry",
    { spec = "PKM *txn.isolation.conditional-write-is-per-operation-and-single-layer" },
    function(t)
        local fd = open_key(ROOT .. "\\Conflicts")
        local s = lcs.set_value(src, w, fd, "Cas", lcs.TYPE.DWORD, lcs.dword(1))
        t:assert_eq(s.ret, 0, "an initial write: " .. sys.errname(s.errno or 0))
        local seq = lcs.query_value(src, w, fd, "Cas").sequence

        local stale = lcs.set_value(src, w, fd, "Cas", lcs.TYPE.DWORD, lcs.dword(2),
            { expected_seq = seq + 1000 })
        t:assert_eq(stale.errno, sys.E.AGAIN, "a mismatched expected_sequence is EAGAIN")
        local ok = lcs.set_value(src, w, fd, "Cas", lcs.TYPE.DWORD, lcs.dword(3),
            { expected_seq = seq })
        t:assert_eq(ok.ret, 0, "the matching one succeeds: " .. sys.errname(ok.errno or 0))

        -- A higher-precedence layer overriding the value is not a
        -- conflict: the check is against the layer's own entry.
        local base_seq = lcs.query_value(src, w, fd, "Cas").sequence
        local high = lcs.set_value(src, w, fd, "Cas", lcs.TYPE.DWORD, lcs.dword(9),
            { layer = "beta" })
        t:assert_eq(high.ret, 0, "a beta-layer write: " .. sys.errname(high.errno or 0))
        t:assert_eq(lcs.query_value(src, w, fd, "Cas").data, lcs.dword(9),
            "which now wins the effective value")
        local still = lcs.set_value(src, w, fd, "Cas", lcs.TYPE.DWORD, lcs.dword(4),
            { expected_seq = base_seq })
        t:assert_eq(still.ret, 0,
            "and a base-layer conditional write on the same sequence still succeeds: "
            .. sys.errname(still.errno or 0))
        sys.close(w, fd)
    end)
