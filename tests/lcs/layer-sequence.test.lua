-- PKM §5.3.7 — The sequence counter: one global monotonic counter,
-- stamped on every layer-qualified entry, initialised from what the
-- sources report at registration, and never reused, decremented or
-- reset. `REG_IOC_QUERY_VALUE` hands the winning entry's number back,
-- so the counter is directly observable from the guest.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")

local vm = provium:vm("v", "kernel-only"):boot()

-- One Machine source for the file: a Down slot keeps its hive identity,
-- so a second `Machine` registration would be ESTALE (§5.8.2). Cases
-- that need another source register a hive name of their own.
local BASELINE = 5000
local src, test_key
local function machine()
    if src then return src end
    src = lcs.source(vm)
    test_key = src:key("Machine\\Software\\Test")
    src:seed_layer("base")
    src:seed_layer("alt")
    -- A stored entry from "a previous boot": below the reported maximum.
    src:value(test_key, "Stored", lcs.TYPE.DWORD, lcs.dword(1), { layer = "alt" })
    assert(src:register({ max_sequence = BASELINE }))
    src:pump()
    return src
end

local worker
local function w()
    if not worker then worker = vm:spawn_worker() end
    return worker
end

--- A fresh subkey of Machine\Software\Test, so cases do not share values.
local function subkey(t, name)
    local root = lcs.open_key(machine(), w(), -1, "Machine\\Software\\Test", lcs.KEY_ALL_ACCESS)
    t:assert(root.ret >= 0, "the test key opens: " .. sys.errname(root.errno or 0))
    local c = lcs.create_key(machine(), w(), { parent_fd = root.ret, path = name })
    t:assert(c.ret >= 0, "a fresh subkey: " .. sys.errname(c.errno or 0))
    sys.close(w(), root.ret)
    return c.ret
end

--- The sequence number stamped on the winning entry for `name`.
local function seq_of(t, fd, name)
    local q = lcs.query_value(machine(), w(), fd, name)
    t:assert_eq(q.ret, 0, "query " .. name .. ": " .. sys.errname(q.errno or 0))
    return q.sequence
end

--- Write `name` in the base layer and return the number it took.
local function write_and_seq(t, fd, name, v)
    local s = lcs.set_value(machine(), w(), fd, name, lcs.TYPE.DWORD, lcs.dword(v or 1))
    t:assert_eq(s.ret, 0, "set " .. name .. ": " .. sys.errname(s.errno or 0))
    return seq_of(t, fd, name)
end

test("each source reports its highest persisted sequence and the counter is raised above it",
    { spec = "PKM *layer.sequence.counter-raised-above-the-reported-source-maximum" },
    function(t)
        -- A hive of its own, reporting a maximum far above anything the
        -- rest of the file allocates, so the number the next write takes
        -- is unambiguously derived from what this source reported.
        local REPORTED = 2000000
        local high = lcs.source(vm, { hives = { { name = "RaisedHive" } } })
        high:key("RaisedHive\\K")
        t:assert(high:register({ max_sequence = REPORTED }),
            "a source registers reporting its highest persisted sequence")
        high:pump()
        local fd = lcs.open_key(high, w(), -1, "RaisedHive\\K", lcs.KEY_ALL_ACCESS)
        t:assert(fd.ret >= 0, "its hive routes: " .. sys.errname(fd.errno or 0))
        local s = lcs.set_value(high, w(), fd.ret, "First", lcs.TYPE.DWORD, lcs.dword(1))
        t:assert_eq(s.ret, 0, "set: " .. sys.errname(s.errno or 0))
        local q = lcs.query_value(high, w(), fd.ret, "First")
        t:assert_eq(q.ret, 0, "query: " .. sys.errname(q.errno or 0))
        t:assert_eq(q.sequence, REPORTED + 1,
            "the counter was raised to one above the maximum the source reported")
        sys.close(w(), fd.ret)
        high:close()
    end)

test("a new write outranks anything already in storage",
    { spec = "PKM *layer.sequence.new-writes-outrank-stored-entries" },
    function(t)
        -- `Stored` was persisted in layer `alt` before this boot; both
        -- layers sit at precedence 0, so the tie is broken on sequence.
        local root = lcs.open_key(machine(), w(), -1, "Machine\\Software\\Test", lcs.KEY_ALL_ACCESS)
        local before = lcs.query_value(machine(), w(), root.ret, "Stored")
        t:assert_eq(before.layer, "alt", "the stored entry wins while it is the only one")
        t:assert(before.sequence < BASELINE,
            "and carries a number the source persisted, below the reported maximum")
        local s = lcs.set_value(machine(), w(), root.ret, "Stored", lcs.TYPE.DWORD, lcs.dword(2))
        t:assert_eq(s.ret, 0, "set: " .. sys.errname(s.errno or 0))
        local after = lcs.query_value(machine(), w(), root.ret, "Stored")
        t:assert_eq(after.layer, "base", "the new write outranks the stored entry")
        t:assert(after.sequence > BASELINE, "because its number is above the reported maximum")
        sys.close(w(), root.ret)
    end)

test("every layer-qualified mutation takes the next number from one global counter",
    { spec = "PKM *layer.sequence.every-layer-qualified-mutation-takes-the-next-number" },
    function(t)
        local fd = subkey(t, "EveryMutation")
        local start = write_and_seq(t, fd, "A")
        -- One value write, one path entry, one blanket tombstone: three
        -- layer-qualified entries, three numbers.
        local c = lcs.create_key(machine(), w(), { parent_fd = fd, path = "Sub" })
        t:assert(c.ret >= 0, "create_key: " .. sys.errname(c.errno or 0))
        local b = lcs.blanket_tombstone(machine(), w(), c.ret, "alt", true)
        t:assert_eq(b.ret, 0, "blanket: " .. sys.errname(b.errno or 0))
        local h = lcs.hide_key(machine(), w(), c.ret)
        t:assert_eq(h.ret, 0, "hide: " .. sys.errname(h.errno or 0))
        local after = write_and_seq(t, fd, "B")
        t:assert_eq(after, start + 4,
            "a path entry, a blanket tombstone, a key hide and the write took one number each")
        sys.close(w(), c.ret)
        sys.close(w(), fd)
    end)

test("the counter is never decremented and never reset",
    { spec = "PKM *layer.sequence.never-decremented-or-reset" },
    function(t)
        local fd = subkey(t, "Monotonic")
        local last = 0
        for i = 1, 6 do
            local s = write_and_seq(t, fd, "M" .. i, i)
            t:assert(s > last, "number " .. i .. " is above the one before it")
            last = s
        end
        -- A failed operation does not wind it back either.
        local bad = lcs.set_value(machine(), w(), fd, "Nope", lcs.TYPE.DWORD, lcs.dword(1),
            { layer = "no-such-layer" })
        t:assert_eq(bad.errno, sys.E.NOENT, "a write naming an absent layer is ENOENT")
        local s = write_and_seq(t, fd, "After")
        t:assert(s > last, "and the next number is still above every number before it")
        sys.close(w(), fd)
    end)

test("allocated numbers are never reused, and the gaps that leaves carry no meaning",
    { spec = "PKM *layer.sequence.allocated-numbers-are-never-reused" },
    function(t)
        local fd = subkey(t, "NoReuse")
        local before = write_and_seq(t, fd, "Before")
        local txn = assert(lcs.begin_transaction(w()))
        for i = 1, 2 do
            local s = lcs.set_value(machine(), w(), fd, "Doomed" .. i, lcs.TYPE.DWORD,
                lcs.dword(i), { txn_fd = txn })
            t:assert_eq(s.ret, 0, "the transactional write is accepted: " .. sys.errname(s.errno or 0))
        end
        sys.close(w(), txn) -- closing an active transaction aborts it
        machine():pump()
        local after = write_and_seq(t, fd, "After")
        t:assert_eq(after, before + 3,
            "the two numbers the aborted transaction took are not handed out again")
        local gone = lcs.query_value(machine(), w(), fd, "Doomed1")
        t:assert_eq(gone.errno, sys.E.NOENT, "and the aborted writes left nothing behind")
        sys.close(w(), fd)
    end)

test("gaps in the sequence space are normal and carry no meaning",
    { spec = "PKM *layer.sequence.gaps-are-normal" },
    function(t)
        local fd = subkey(t, "Gaps")
        local a = write_and_seq(t, fd, "A")
        -- A create that opens an existing key allocates nothing; an
        -- aborted transaction allocates and discards. Neither the
        -- presence nor the absence of a gap means anything: only the
        -- order of the numbers that survive does.
        local txn = assert(lcs.begin_transaction(w()))
        lcs.set_value(machine(), w(), fd, "Discarded", lcs.TYPE.DWORD, lcs.dword(1), { txn_fd = txn })
        sys.close(w(), txn)
        machine():pump()
        local b = write_and_seq(t, fd, "B")
        t:assert(b > a + 1, "a gap is left behind where the discarded entry's number was")
        t:assert(b > a, "and the surviving entries are still ordered by the numbers they kept")
        sys.close(w(), fd)
    end)

test("a transactional mutation is numbered when it is accepted, not at commit",
    { spec = "PKM *layer.sequence.transactional-number-assigned-at-accept-not-commit" },
    function(t)
        local fd = subkey(t, "AcceptNotCommit")
        local txn = assert(lcs.begin_transaction(w()))
        -- Accepted first, committed last. `alt` and `base` are both at
        -- precedence 0, so the winner is whichever holds the higher
        -- number — the write that was performed second.
        local first = lcs.set_value(machine(), w(), fd, "Order", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = txn, layer = "alt" })
        t:assert_eq(first.ret, 0, "the transactional write is accepted: " .. sys.errname(first.errno or 0))
        local second = lcs.set_value(machine(), w(), fd, "Order", lcs.TYPE.DWORD, lcs.dword(2))
        t:assert_eq(second.ret, 0, "the later non-transactional write: " .. sys.errname(second.errno or 0))
        local c = lcs.commit(machine(), w(), txn)
        t:assert_eq(c.ret, 0, "commit: " .. sys.errname(c.errno or 0))
        sys.close(w(), txn)
        local q = lcs.query_value(machine(), w(), fd, "Order")
        t:assert_eq(q.ret, 0, "query: " .. sys.errname(q.errno or 0))
        t:assert_eq(q.layer, "base",
            "the order the caller performed the operations in is what tiebreaking sees, " ..
            "so the write performed second wins even though it committed first")
        t:assert_eq(q.data, lcs.dword(2), "and its data is the effective one")
        sys.close(w(), fd)
    end)

test("a source registering later advances the counter to max(current, source_max + 1)",
    { spec = "PKM *layer.sequence.late-registration-advances-the-counter" },
    function(t)
        local fd = subkey(t, "LateRegistration")
        local before = write_and_seq(t, fd, "Before")
        local late = lcs.source(vm, { hives = { { name = "LateHive" } } })
        late:key("LateHive\\K")
        t:assert(late:register({ max_sequence = before + 100000 }),
            "a second source registers with a higher persisted maximum")
        late:pump()
        local after = write_and_seq(t, fd, "After")
        t:assert(after > before + 100000,
            "and the global counter has advanced past the maximum it reported")
        late:close()
        sys.close(w(), fd)
    end)

test("a registration whose maximum plus one overflows 64 bits is EOVERFLOW and the slot is not Active",
    { spec = "PKM *layer.sequence.registration-overflow-is-eoverflow" },
    function(t)
        local over = lcs.source(vm, { hives = { { name = "OverflowHive" } } })
        over:key("OverflowHive\\K")
        local ok = over:register({ max_sequence = -1 }) -- U64_MAX
        t:assert(not ok, "registering with U64_MAX as the persisted maximum fails")
        t:assert_eq(over.errno, sys.E.OVERFLOW, "with EOVERFLOW")
        local r = lcs.open_key(nil, w(), -1, "OverflowHive\\K", lcs.RIGHT.KEY_READ)
        t:assert_eq(r.errno, sys.E.NOENT,
            "and the hive never routes, because the slot never became Active")
    end)

test("the hive generation number never reaches a source",
    { spec = "PKM *layer.sequence.generation-number-never-reaches-sources" },
    function(t)
        local fd = subkey(t, "Generation")
        local mark = machine():mark()
        write_and_seq(t, fd, "One")
        local info = lcs.query_key_info(machine(), w(), fd)
        t:assert_eq(info.ret, 0, "query_key_info: " .. sys.errname(info.errno or 0))
        local gen = info.hive_generation
        t:assert(gen > 0, "a hive generation is exposed to the caller")
        local packed = string.pack("<I8", gen)
        local seen = false
        for i = mark, #machine().log do
            if machine().log[i].raw:find(packed, 1, true) then seen = true end
        end
        t:assert(not seen,
            "and no RSI request carries it: sources never see it and never persist it")
        sys.close(w(), fd)
    end)

test("the generation baseline comes from the source's reported maximum sequence",
    { spec = "PKM *layer.sequence.generation-baseline-from-the-reported-source-maximum" },
    function(t)
        local fd = subkey(t, "GenerationBaseline")
        local seq = write_and_seq(t, fd, "Bump")
        local info = lcs.query_key_info(machine(), w(), fd)
        t:assert_eq(info.ret, 0, "query_key_info: " .. sys.errname(info.errno or 0))
        t:assert(info.hive_generation >= BASELINE,
            "the Machine hive's generation starts at the maximum sequence its own source " ..
            "reported, so observed generations are monotonic relative to persisted entries")
        t:assert(info.hive_generation < seq,
            "and after that the two are unrelated: the generation is not the global " ..
            "sequence counter, which other sources in this file have pushed far higher")
        local before = info.hive_generation
        write_and_seq(t, fd, "Bump2")
        local after = lcs.query_key_info(machine(), w(), fd)
        t:assert(after.hive_generation > before, "it advances as the hive changes")
        sys.close(w(), fd)
    end)

test("the counter refuses to hand out U64_MAX",
    { spec = "PKM *layer.sequence.u64-max-is-never-allocated" },
    function(t)
        -- U64_MAX - 1 reported: the counter's next number is U64_MAX
        -- itself, and it is never allocated.
        local edge = lcs.source(vm, { hives = { { name = "EdgeHive" } } })
        local k = edge:key("EdgeHive\\K")
        t:assert(edge:register({ max_sequence = -2 }), "registration with U64_MAX - 1 succeeds")
        edge:pump()
        local fd = lcs.open_key(edge, w(), -1, "EdgeHive\\K", lcs.KEY_ALL_ACCESS)
        t:assert(fd.ret >= 0, "the hive routes: " .. sys.errname(fd.errno or 0))
        local s = lcs.set_value(edge, w(), fd.ret, "X", lcs.TYPE.DWORD, lcs.dword(1))
        t:assert(s.ret ~= 0, "but a layer-qualified write cannot be numbered")
        t:assert_eq(s.errno, sys.E.OVERFLOW, "and fails rather than allocating U64_MAX")
        sys.close(w(), fd.ret)
        edge:close()
    end)
