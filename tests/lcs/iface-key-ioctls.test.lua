-- PKM §5.5.3 — The sixteen key-fd ioctls: what each returns, the
-- transaction fd they all accept, the hive generation number, the
-- conditional write, and the two ways a key stops resolving.
--
-- The source seeds MaxValueSize and MaxLayersPerValue at their floors so
-- the two ENOSPC bounds are reachable in a test rather than a benchmark,
-- and serves a second hive for the per-hive generation case.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")

local vm = provium:vm("v", "kernel-only"):boot()

local MAX_VALUE_SIZE = 4096
local MAX_LAYERS_PER_VALUE = 2

local src = lcs.source(vm, { hives = { { name = "Machine" }, { name = "Other" } } })
src:seed_param("MaxValueSize", MAX_VALUE_SIZE)
src:seed_param("MaxLayersPerValue", MAX_LAYERS_PER_VALUE)
src:key(lcs.LAYERS_PATH)
local TEST = src:key("Machine\\Software\\Test")
src:value(TEST, "Seeded", lcs.TYPE.DWORD, lcs.dword(1))
-- A value whose only entry is in a layer the source spells in a case of
-- its own: the layer table's spelling is what a query reports.
local CANON = src:key("Machine\\Canonical")
src:value(CANON, "Shouty", lcs.TYPE.SZ, lcs.sz("hi"), { layer = "BASE" })
-- Masked values, for the two ways a read finds nothing.
local MASKED = src:key("Machine\\Masked")
src:value(MASKED, "Tombstoned", lcs.TYPE.DWORD, lcs.dword(7))
src:tombstone(MASKED, "Tombstoned", "base")
src:value(MASKED, "Blanketed", lcs.TYPE.DWORD, lcs.dword(8))
src:blanket(MASKED, "base")
-- Enumeration fixtures.
local ENUM = src:key("Machine\\Enum")
src:value(ENUM, "Alpha", lcs.TYPE.DWORD, lcs.dword(1))
src:value(ENUM, "Bravo", lcs.TYPE.SZ, lcs.sz("two"))
src:key("Machine\\Enum\\KidOne")
local KID = src:key("Machine\\Enum\\KidTwo")
src:value(KID, "One", lcs.TYPE.DWORD, lcs.dword(1))
src:value(KID, "Two", lcs.TYPE.DWORD, lcs.dword(2))
src:key("Machine\\Enum\\KidTwo\\Grand")
-- Working keys for the mutating cases.
for i = 1, 10 do src:key("Machine\\Work\\W" .. i) end
src:key("Machine\\Work\\W1\\Under")
src:key("Other\\Room")
assert(src:register())
src:pump()

local w = vm:spawn_worker()

local function must_open(t, path, desired)
    local r = lcs.open_key(src, w, -1, path, desired or lcs.KEY_ALL_ACCESS)
    t:assert(r.ret >= 0, "open " .. path .. ": " .. sys.errname(r.errno or 0))
    return r.ret
end

local function generation(t, fd)
    local i = lcs.query_key_info(src, w, fd)
    t:assert_eq(i.ret, 0, "query key info: " .. sys.errname(i.errno or 0))
    return i.hive_generation
end

-- The surface --------------------------------------------------------

test("sixteen ioctls act on a key fd, each gated on the fd's granted mask first",
    { spec = "PKM *ioctl.sixteen-act-on-a-key-fd" }, function(t)
        local fd = must_open(t, "Machine\\Software\\Test")
        local numbers = { { 0, lcs.IOC_DIR.WR, 64 }, { 1, lcs.IOC_DIR.W, 64 },
            { 2, lcs.IOC_DIR.W, 40 }, { 3, lcs.IOC_DIR.W, 24 }, { 4, lcs.IOC_DIR.WR, 24 },
            { 5, lcs.IOC_DIR.WR, 40 }, { 6, lcs.IOC_DIR.WR, 40 }, { 7, lcs.IOC_DIR.WR, 64 },
            { 8, lcs.IOC_DIR.W, 24 }, { 9, lcs.IOC_DIR.W, 24 }, { 10, lcs.IOC_DIR.WR, 16 },
            { 11, lcs.IOC_DIR.W, 24 }, { 12, lcs.IOC_DIR.W, 8 }, { 13, lcs.IOC_DIR.NONE, 0 },
            { 14, lcs.IOC_DIR.W, 4 }, { 15, lcs.IOC_DIR.W, 4 } }
        t:assert_eq(#numbers, 16, "sixteen numbers, 0 through 15")
        for _, e in ipairs(numbers) do
            if e[1] ~= 13 then
                local r = w:syscall(sys.NR.ioctl,
                    { args = { fd, lcs.ioc(e[2], e[1], e[3]), 0 } })
                t:assert(r.errno ~= sys.E.NOTTY, "number " .. e[1] .. " is one of them")
            end
        end
        -- And the mask is tested before anything else: a fd without the
        -- right never reaches the source.
        local narrow = must_open(t, "Machine\\Software\\Test", lcs.RIGHT.NOTIFY)
        local mark = src:mark()
        t:assert_eq(lcs.query_value(nil, w, narrow, "Seeded").errno, sys.E.ACCES,
            "each checks the granted mask first")
        t:assert_eq(#src.log, mark - 1, "and returns EACCES without contacting the source")
        sys.close(w, narrow)
        sys.close(w, fd)
    end)

test("an ioctl number this fd type does not implement is ENOTTY",
    { spec = "PKM *ioctl.enotty-for-an-unimplemented-number" }, function(t)
        local fd = must_open(t, "Machine\\Software\\Test")
        for _, nr in ipairs({ 16, 17, 18, 40, 255 }) do
            local r = w:syscall(sys.NR.ioctl,
                { args = { fd, lcs.ioc(lcs.IOC_DIR.W, nr, 8), 0 } })
            t:assert_eq(r.errno, sys.E.NOTTY, "number " .. nr .. " is not a key-fd ioctl")
        end
        sys.close(w, fd)
    end)

test("kernel allocation failure inside an ioctl is ENOMEM",
    { spec = "PKM *ioctl.enomem-on-allocation-failure",
      covered_by = "kunit:",
      skip = "no guest can force a kernel allocation to fail at a chosen ioctl; the " ..
             "allocation sites are internal to key_fd.c — no LCS KUnit case found, " ..
             "candidate for a new one" },
    function(t) end)

test("every mutating ioctl accepts a transaction fd, and so do the four read ioctls",
    { spec = "PKM *ioctl.mutating-ioctls-accept-a-transaction-fd" }, function(t)
        local fd = must_open(t, "Machine\\Work\\W1")
        local txn = assert(lcs.begin_transaction(w))

        t:assert_eq(lcs.set_value(src, w, fd, "InTxn", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = txn }).ret, 0, "REG_IOC_SET_VALUE takes one")
        t:assert_eq(lcs.txn_status(nil, w, txn).state, lcs.TXN.ACTIVE_BOUND, "and binds it")

        -- A read inside the bound transaction sees its uncommitted write.
        local inside = lcs.query_value(src, w, fd, "InTxn", { txn_fd = txn })
        t:assert_eq(inside.ret, 0, "a read in the transaction sees it: " ..
            sys.errname(inside.errno or 0))
        local outside = lcs.query_value(src, w, fd, "InTxn")
        t:assert_eq(outside.errno, sys.E.NOENT, "and a read outside it does not")

        t:assert_eq(lcs.delete_value(src, w, fd, "InTxn", { txn_fd = txn }).ret, 0,
            "REG_IOC_DELETE_VALUE takes one")
        t:assert_eq(lcs.blanket_tombstone(src, w, fd, nil, true, { txn_fd = txn }).ret, 0,
            "REG_IOC_BLANKET_TOMBSTONE takes one")
        t:assert_eq(lcs.set_security(src, w, fd, lcs.SI.DACL, lcs.permissive_sd(),
            { txn_fd = txn }).ret, 0, "REG_IOC_SET_SECURITY takes one")
        t:assert_eq(lcs.commit(src, w, txn).ret, 0, "and they commit together")

        -- A committed transaction is EINVAL for any further use.
        local after = lcs.set_value(nil, w, fd, "Late", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = txn })
        t:assert_eq(after.errno, sys.E.INVAL, "a committed transaction is EINVAL")
        sys.close(w, txn)

        -- An unbound transaction does not bind on a read.
        local reader = assert(lcs.begin_transaction(w))
        local r = lcs.query_value(src, w, fd, "Nothing", { txn_fd = reader })
        t:assert_eq(r.errno, sys.E.NOENT, "a read runs non-transactionally: " ..
            sys.errname(r.errno or 0))
        t:assert_eq(lcs.txn_status(nil, w, reader).state, lcs.TXN.ACTIVE_UNBOUND,
            "and leaves the transaction unbound")

        -- A transaction bound to one hive is EXDEV for another.
        local other = must_open(t, "Other\\Room")
        local bind = must_open(t, "Machine\\Work\\W2")
        t:assert_eq(lcs.set_value(src, w, bind, "Bind", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = reader }).ret, 0, "the transaction binds to Machine")
        local cross = lcs.set_value(nil, w, other, "Nope", lcs.TYPE.DWORD, lcs.dword(1),
            { txn_fd = reader })
        t:assert_eq(cross.errno, sys.E.XDEV, "and another hive is EXDEV")
        sys.close(w, reader)
        sys.close(w, other)
        sys.close(w, bind)
        sys.close(w, fd)
    end)

-- Reading --------------------------------------------------------------

test("REG_IOC_QUERY_VALUE returns the type, data, winning sequence and canonical layer name",
    { spec = "PKM *ioctl.query-value.result-fields" }, function(t)
        local fd = must_open(t, "Machine\\Software\\Test")
        local q = lcs.query_value(src, w, fd, "Seeded")
        t:assert_eq(q.ret, 0, "query: " .. sys.errname(q.errno or 0))
        t:assert_eq(q.type, lcs.TYPE.DWORD, "the effective value's type")
        t:assert_eq(q.data, lcs.dword(1), "its data")
        t:assert(q.sequence > 0, "the sequence number of the winning entry")
        t:assert_eq(q.layer, "base", "and the layer table's spelling of the winning layer")
        sys.close(w, fd)

        -- The source stored "BASE"; the answer is the canonical "base".
        local canon = must_open(t, "Machine\\Canonical")
        local c = lcs.query_value(src, w, canon, "Shouty")
        t:assert_eq(c.ret, 0, "query: " .. sys.errname(c.errno or 0))
        t:assert_eq(c.layer, "base",
            "not whatever string the source stored, which here was \"BASE\"")
        sys.close(w, canon)
    end)

test("a winning tombstone, a blanket, or no entries at all is ENOENT",
    { spec = "PKM *ioctl.query-value.masked-is-enoent" }, function(t)
        local fd = must_open(t, "Machine\\Masked")
        t:assert_eq(lcs.query_value(src, w, fd, "Tombstoned").errno, sys.E.NOENT,
            "a winning tombstone reads as absent")
        t:assert_eq(lcs.query_value(src, w, fd, "Blanketed").errno, sys.E.NOENT,
            "and so does a blanket-masked value")
        t:assert_eq(lcs.query_value(src, w, fd, "NeverWritten").errno, sys.E.NOENT,
            "and a name with no entries at all")
        sys.close(w, fd)
    end)

test("REG_IOC_QUERY_VALUES_BATCH returns every effective value, masked ones omitted",
    { spec = "PKM *ioctl.query-values-batch.returns-every-effective-value" }, function(t)
        local fd = must_open(t, "Machine\\Enum")
        local b = lcs.query_values_batch(src, w, fd)
        t:assert_eq(b.ret, 0, "batch: " .. sys.errname(b.errno or 0))
        t:assert_eq(b.count, 2, "both values on the key, in one call")
        local by_name = {}
        for _, v in ipairs(b.values) do by_name[v.name] = v end
        t:assert_eq(by_name.Alpha.type, lcs.TYPE.DWORD, "name, type and data for each")
        t:assert_eq(by_name.Bravo.data, lcs.sz("two"), "and for the other")
        sys.close(w, fd)

        local masked = must_open(t, "Machine\\Masked")
        local m = lcs.query_values_batch(src, w, masked)
        t:assert_eq(m.ret, 0, "batch on the masked key: " .. sys.errname(m.errno or 0))
        t:assert_eq(m.count, 0, "tombstoned and blanket-masked values are omitted")
        sys.close(w, masked)
    end)

test("REG_IOC_ENUM_VALUES and ENUM_SUBKEYS return the entry at an index, and ENOENT past the end",
    { spec = "PKM *ioctl.enum.index-and-enoent-past-the-end" }, function(t)
        local fd = must_open(t, "Machine\\Enum")
        local names = {}
        for i = 0, 1 do
            local e = lcs.enum_values(src, w, fd, i)
            t:assert_eq(e.ret, 0, "value at index " .. i .. ": " .. sys.errname(e.errno or 0))
            names[e.name] = true
        end
        t:assert(names.Alpha and names.Bravo, "both values are reachable by index")
        t:assert_eq(lcs.enum_values(src, w, fd, 2).errno, sys.E.NOENT, "index 2 is past the end")

        local kids = {}
        for i = 0, 1 do
            local e = lcs.enum_subkeys(src, w, fd, i)
            t:assert_eq(e.ret, 0, "subkey at index " .. i .. ": " .. sys.errname(e.errno or 0))
            kids[e.name] = true
        end
        t:assert(kids.KidOne and kids.KidTwo, "both children are reachable by index")
        t:assert_eq(lcs.enum_subkeys(src, w, fd, 2).errno, sys.E.NOENT, "index 2 is past the end")
        sys.close(w, fd)
    end)

test("both enumerations re-resolve the full set on every call, and their order is undefined",
    { spec = "PKM *ioctl.enum.re-resolves-and-order-is-undefined" }, function(t)
        local fd = must_open(t, "Machine\\Work\\W3")
        t:assert_eq(lcs.enum_values(src, w, fd, 0).errno, sys.E.NOENT, "no values yet")
        t:assert_eq(lcs.set_value(src, w, fd, "Later", lcs.TYPE.DWORD, lcs.dword(1)).ret, 0,
            "write one")
        local mark = src:mark()
        local e = lcs.enum_values(src, w, fd, 0)
        t:assert_eq(e.ret, 0, "the next call sees it: " .. sys.errname(e.errno or 0))
        t:assert(#src:served(lcs.OP.QUERY_VALUES, mark) > 0,
            "because the call re-resolved the whole set at the source")

        -- Order is undefined, so a caller may only rely on the set.
        t:assert_eq(lcs.set_value(src, w, fd, "Another", lcs.TYPE.DWORD, lcs.dword(2)).ret, 0,
            "write a second")
        local seen = {}
        for i = 0, 1 do seen[lcs.enum_values(src, w, fd, i).name] = true end
        t:assert(seen.Later and seen.Another,
            "both appear across the indices, in whatever order the call chose")
        sys.close(w, fd)
    end)

test("REG_IOC_ENUM_SUBKEYS returns each visible child with its times and counts",
    { spec = "PKM *ioctl.enum-subkeys.child-fields" }, function(t)
        local fd = must_open(t, "Machine\\Enum")
        local found
        for i = 0, 1 do
            local e = lcs.enum_subkeys(src, w, fd, i)
            if e.name == "KidTwo" then found = e end
        end
        t:assert(found, "the child is enumerated")
        t:assert_eq(found.subkey_count, 1, "with its subkey count")
        t:assert_eq(found.value_count, 2, "its value count")
        t:assert(found.last_write_time ~= nil, "and its last write time")
        sys.close(w, fd)
    end)

test("REG_IOC_QUERY_KEY_INFO returns the key's name, times, counts, maxima, flags and generation",
    { spec = "PKM *ioctl.query-key-info.result-fields" }, function(t)
        local fd = must_open(t, "Machine\\Enum\\KidTwo")
        local i = lcs.query_key_info(src, w, fd)
        t:assert_eq(i.ret, 0, "query key info: " .. sys.errname(i.errno or 0))
        t:assert_eq(i.name, "KidTwo", "the key's own name")
        t:assert_eq(i.subkey_count, 1, "its subkey count")
        t:assert_eq(i.value_count, 2, "its value count")
        t:assert_eq(i.max_subkey_name_len, #"Grand", "the longest subkey name")
        t:assert_eq(i.max_value_name_len, #"Two", "the longest value name")
        t:assert_eq(i.max_value_data_size, 4, "the largest value data")
        t:assert(i.sd_size > 20, "the descriptor's size")
        t:assert_eq(i.volatile, false, "the volatile flag")
        t:assert_eq(i.symlink, false, "the symlink flag")
        t:assert(i.hive_generation ~= nil, "and the hive generation number")
        t:assert(i.last_write_time ~= nil, "with the last write time")
        sys.close(w, fd)
    end)

test("REG_IOC_QUERY_KEY_INFO is _IOWR: it reads the caller's output-buffer fields first",
    { spec = "PKM *ioctl.query-key-info.is-iowr" }, function(t)
        local fd = must_open(t, "Machine\\Enum\\KidTwo")
        -- name_len 0 is a probe: the kernel had to read the field to
        -- know that, which is what makes the argument bidirectional.
        local probe = lcs.query_key_info(src, w, fd, { name_len = 0 })
        t:assert(probe.errno ~= sys.E.FAULT, "a zero-length name buffer is not dereferenced")
        t:assert_eq(probe.name_len, #"KidTwo", "and the required size comes back")

        local short = lcs.query_key_info(src, w, fd, { name_len = 2 })
        t:assert_eq(short.errno, sys.E.RANGE, "an undersized one is ERANGE")
        t:assert_eq(short.name_len, #"KidTwo", "with the size it needed")

        local full = lcs.query_key_info(src, w, fd, { name_len = 64 })
        t:assert_eq(full.ret, 0, "and a big enough one is written back")
        t:assert_eq(full.name, "KidTwo", "with the name in it")
        sys.close(w, fd)
    end)

test("a binary built against the old _IOR constant gets ENOTTY",
    { spec = "PKM *ioctl.query-key-info.old-constant-gets-enotty" }, function(t)
        local fd = must_open(t, "Machine\\Enum\\KidTwo")
        local old = lcs.raw_call(nil, w, {
            nr = sys.NR.ioctl, args = { fd, lcs.ioc(lcs.IOC_DIR.R, 7, 64), 0 },
            ptr_slot = 2, struct = string.rep("\0", 64),
        })
        t:assert_eq(old.errno, sys.E.NOTTY,
            "the direction bits are part of the encoded number, so the old constant is " ..
            "simply an ioctl this kernel does not have")
        local new = lcs.query_key_info(src, w, fd)
        t:assert_eq(new.ret, 0, "while the _IOWR constant works: " ..
            sys.errname(new.errno or 0))
        sys.close(w, fd)
    end)

-- The hive generation number ---------------------------------------------

test("the hive generation increments once per committed mutation, and once per transaction",
    { spec = "PKM *ioctl.hive-generation.one-increment-per-commit" }, function(t)
        local fd = must_open(t, "Machine\\Work\\W4")
        local before = generation(t, fd)
        t:assert_eq(lcs.set_value(src, w, fd, "One", lcs.TYPE.DWORD, lcs.dword(1)).ret, 0,
            "one mutation")
        local after_one = generation(t, fd)
        t:assert_eq(after_one, before + 1, "moves the generation by one")

        local txn = assert(lcs.begin_transaction(w))
        for i = 1, 3 do
            t:assert_eq(lcs.set_value(src, w, fd, "T" .. i, lcs.TYPE.DWORD, lcs.dword(i),
                { txn_fd = txn }).ret, 0, "three mutations in a transaction")
        end
        t:assert_eq(lcs.commit(src, w, txn).ret, 0, "commit")
        sys.close(w, txn)
        local after_txn = generation(t, fd)
        t:assert_eq(after_txn, after_one + 1,
            "and a whole transaction moves it by one, however many operations it held")
        sys.close(w, fd)
    end)

test("an operation affecting several hives increments each independently",
    { spec = "PKM *ioctl.hive-generation.per-hive-independent" }, function(t)
        local machine = must_open(t, "Machine\\Work\\W5")
        local other = must_open(t, "Other\\Room")
        local m0, o0 = generation(t, machine), generation(t, other)
        t:assert_eq(lcs.set_value(src, w, machine, "Only", lcs.TYPE.DWORD, lcs.dword(1)).ret, 0,
            "a mutation in Machine")
        t:assert_eq(generation(t, machine), m0 + 1, "moves Machine's generation")
        t:assert_eq(generation(t, other), o0, "and leaves Other's where it was")
        t:assert_eq(lcs.set_value(src, w, other, "Only", lcs.TYPE.DWORD, lcs.dword(1)).ret, 0,
            "a mutation in Other")
        t:assert_eq(generation(t, other), o0 + 1, "moves Other's, independently")
        sys.close(w, machine)
        sys.close(w, other)
    end)

test("a layer operation produces a single generation increment covering all of its effects",
    { spec = "PKM *ioctl.hive-generation.layer-operation-is-one-increment" }, function(t)
        local fd = must_open(t, "Machine\\Work\\W6")
        local layer_fd, err = lcs.create_layer(src, w, "Doomed")
        t:assert(layer_fd, "a layer is created: " .. sys.errname(err or 0))
        t:assert_eq(lcs.set_value(src, w, fd, "Layered", lcs.TYPE.DWORD, lcs.dword(1),
            { layer = "Doomed" }).ret, 0, "and written into")
        local before = generation(t, fd)

        -- Deleting the metadata key is the layer deletion: the metadata
        -- removal, RSI_DELETE_LAYER, the recomputation and the watch
        -- effects are one epoch.
        local meta = must_open(t, lcs.LAYERS_PATH .. "\\Doomed")
        t:assert_eq(lcs.delete_key(src, w, meta).ret, 0, "the layer is deleted")
        sys.close(w, meta)
        sys.close(w, layer_fd)

        local after = generation(t, fd)
        t:assert_eq(after, before + 1, "one increment covers the whole layer operation")
        t:assert_eq(lcs.query_value(src, w, fd, "Layered").errno, sys.E.NOENT,
            "and there is no generation at which the metadata is gone but the entries resolve")
        sys.close(w, fd)
    end)

test("a hive generation saturating at U64_MAX is EOVERFLOW",
    { spec = "PKM *ioctl.hive-generation.saturation-is-eoverflow",
      covered_by = "kunit:",
      skip = "the generation baseline comes from the source's reported maximum sequence, " ..
             "and a source that reports one near U64_MAX is refused at registration " ..
             "rather than admitted with a saturating counter, so no guest can drive a " ..
             "live hive to the ceiling; no LCS KUnit case found — candidate for a new one" },
    function(t) end)

-- Writing ------------------------------------------------------------------

test("REG_IOC_SET_VALUE stores the (key GUID, value name, layer) tuple and updates the write time",
    { spec = "PKM *ioctl.set-value.stores-the-layer-tuple" }, function(t)
        local guid = src:lookup("Machine\\Work\\W7")
        local fd = must_open(t, "Machine\\Work\\W7")
        local mark = src:mark()
        t:assert_eq(lcs.set_value(src, w, fd, "Tuple", lcs.TYPE.QWORD, lcs.qword(9)).ret, 0,
            "a write runs")
        local writes = src:served(lcs.OP.SET_VALUE, mark, guid)
        t:assert_eq(#writes, 1, "one RSI_SET_VALUE, against this key's GUID")
        local p = writes[1].payload
        local name, at = string.unpack("<s4", p, 17)
        local layer; layer, at = string.unpack("<s4", p, at)
        local vtype = string.unpack("<I4", p, at); at = at + 4
        local data; data, at = string.unpack("<s4", p, at)
        local seq = string.unpack("<I8", p, at)
        t:assert_eq(name, "Tuple", "carrying the value name")
        t:assert_eq(layer, "base", "the layer")
        t:assert_eq(vtype, lcs.TYPE.QWORD, "the type")
        t:assert_eq(data, lcs.qword(9), "the data")
        t:assert(seq > 0, "and a sequence number LCS allocated")

        local touches = src:served(lcs.OP.WRITE_KEY, mark, guid)
        t:assert(#touches >= 1, "and the key's last write time is updated")
        sys.close(w, fd)
    end)

test("a non-zero expected_sequence is a conditional write the source evaluates atomically",
    { spec = "PKM *ioctl.set-value.expected-sequence-is-a-cas" }, function(t)
        local fd = must_open(t, "Machine\\Work\\W8")
        t:assert_eq(lcs.set_value(src, w, fd, "Cas", lcs.TYPE.DWORD, lcs.dword(1)).ret, 0,
            "an unconditional write")
        local seq = lcs.query_value(src, w, fd, "Cas").sequence

        -- The condition travels in the request.
        local mark = src:mark()
        local ok = lcs.set_value(src, w, fd, "Cas", lcs.TYPE.DWORD, lcs.dword(2),
            { expected_seq = seq })
        t:assert_eq(ok.ret, 0, "a matching condition writes: " .. sys.errname(ok.errno or 0))
        local sent = src:served(lcs.OP.SET_VALUE, mark)[1]
        local p = sent.payload
        local _, at = string.unpack("<s4", p, 17)
        _, at = string.unpack("<s4", p, at); at = at + 4
        _, at = string.unpack("<s4", p, at)
        local _, expected = string.unpack("<I8I8", p, at)
        t:assert_eq(expected, seq, "expected_sequence is passed to the source")

        local current = lcs.query_value(src, w, fd, "Cas").sequence
        local stale = lcs.set_value(src, w, fd, "Cas", lcs.TYPE.DWORD, lcs.dword(3),
            { expected_seq = seq })
        t:assert_eq(stale.errno, sys.E.AGAIN,
            "a stale condition is RSI_CAS_FAILED, which LCS returns as EAGAIN")

        -- And the verdict is the source's alone: LCS does not evaluate
        -- the condition, so a source that answers against the evidence is
        -- believed in both directions. (LCS does read the key's values
        -- before every write, conditional or not — that is the pre-image
        -- the watch machinery needs, not a check on the condition.)
        src:intercept(lcs.OP.SET_VALUE, function() return lcs.STATUS.OK, "" end)
        local believed = lcs.set_value(src, w, fd, "Cas", lcs.TYPE.DWORD, lcs.dword(4),
            { expected_seq = 999999 })
        src:intercept(lcs.OP.SET_VALUE, nil)
        t:assert_eq(believed.ret, 0,
            "a source that accepts a condition nothing could match is believed")

        src:intercept(lcs.OP.SET_VALUE, function() return lcs.STATUS.CAS_FAILED, "" end)
        local refused = lcs.set_value(src, w, fd, "Cas", lcs.TYPE.DWORD, lcs.dword(5),
            { expected_seq = current })
        src:intercept(lcs.OP.SET_VALUE, nil)
        t:assert_eq(refused.errno, sys.E.AGAIN,
            "and one that refuses a condition the kernel could see was current is believed too")
        sys.close(w, fd)
    end)

test("the condition is evaluated against the layer's own entry, not the effective value",
    { spec = "PKM *ioctl.set-value.cas-tests-the-layers-own-entry" }, function(t)
        local fd = must_open(t, "Machine\\Work\\W9")
        t:assert_eq(lcs.set_value(src, w, fd, "Shared", lcs.TYPE.DWORD, lcs.dword(1)).ret, 0,
            "the base layer writes")
        local base_seq = lcs.query_value(src, w, fd, "Shared").sequence

        local high, err = lcs.create_layer(src, w, "Higher", { precedence = 1 })
        t:assert(high, "a higher-precedence layer: " .. sys.errname(err or 0))
        t:assert_eq(lcs.set_value(src, w, fd, "Shared", lcs.TYPE.DWORD, lcs.dword(2),
            { layer = "Higher" }).ret, 0, "which overrides the value")
        local effective = lcs.query_value(src, w, fd, "Shared")
        t:assert_eq(effective.layer, "Higher", "so the effective value is the higher layer's")
        t:assert(effective.sequence ~= base_seq, "at a different sequence")

        local cas = lcs.set_value(src, w, fd, "Shared", lcs.TYPE.DWORD, lcs.dword(3),
            { expected_seq = base_seq })
        t:assert_eq(cas.ret, 0,
            "and a conditional write against the base layer's own sequence still succeeds: " ..
            sys.errname(cas.errno or 0))
        sys.close(w, high)
        sys.close(w, fd)
    end)

test("ENOSPC covers both the per-value layer cap and oversized value data",
    { spec = "PKM *ioctl.set-value.enospc-layer-cap-or-oversized-data" }, function(t)
        local fd = must_open(t, "Machine\\Work\\W10")
        local big = lcs.set_value(src, w, fd, "Big", lcs.TYPE.BINARY,
            string.rep("x", MAX_VALUE_SIZE + 1))
        t:assert_eq(big.errno, sys.E.NOSPC,
            "data beyond MaxValueSize is ENOSPC")
        local fits = lcs.set_value(src, w, fd, "Big", lcs.TYPE.BINARY,
            string.rep("x", MAX_VALUE_SIZE))
        t:assert_eq(fits.ret, 0, "and exactly MaxValueSize is not: " ..
            sys.errname(fits.errno or 0))

        -- MaxLayersPerValue is two here: base, one more, and no third.
        local a = assert(lcs.create_layer(src, w, "CapA"))
        local b = assert(lcs.create_layer(src, w, "CapB"))
        t:assert_eq(lcs.set_value(src, w, fd, "Capped", lcs.TYPE.DWORD, lcs.dword(1)).ret, 0,
            "the base layer writes")
        t:assert_eq(lcs.set_value(src, w, fd, "Capped", lcs.TYPE.DWORD, lcs.dword(2),
            { layer = "CapA" }).ret, 0, "a second layer writes")
        local third = lcs.set_value(src, w, fd, "Capped", lcs.TYPE.DWORD, lcs.dword(3),
            { layer = "CapB" })
        t:assert_eq(third.errno, sys.E.NOSPC,
            "and a layer beyond MaxLayersPerValue is ENOSPC")
        sys.close(w, a); sys.close(w, b)
        sys.close(w, fd)
    end)

test("a value name beyond MaxPathComponentLength is ENAMETOOLONG",
    { spec = "PKM *ioctl.set-value.enametoolong-value-name" }, function(t)
        local fd = must_open(t, "Machine\\Work\\W1")
        local mark = src:mark()
        local r = lcs.set_value(nil, w, fd, string.rep("n", 300), lcs.TYPE.DWORD, lcs.dword(1))
        t:assert_eq(r.errno, sys.E.NAMETOOLONG, "a 300-byte value name is refused")
        t:assert_eq(#src.log, mark - 1, "before the source is asked to store it")
        sys.close(w, fd)
    end)

test("REG_IOC_DELETE_VALUE removes one layer's entry, letting lower layers surface",
    { spec = "PKM *ioctl.delete-value.removes-one-layers-entry" }, function(t)
        local fd = must_open(t, "Machine\\Work\\W2")
        local layer = assert(lcs.create_layer(src, w, "Over"))
        t:assert_eq(lcs.set_value(src, w, fd, "Both", lcs.TYPE.DWORD, lcs.dword(1)).ret, 0,
            "base writes")
        t:assert_eq(lcs.set_value(src, w, fd, "Both", lcs.TYPE.DWORD, lcs.dword(2),
            { layer = "Over" }).ret, 0, "and a second layer writes")
        local won = lcs.query_value(src, w, fd, "Both")
        t:assert_eq(won.layer, "Over", "the second layer wins")

        t:assert_eq(lcs.delete_value(src, w, fd, "Both", { layer = "Over" }).ret, 0,
            "removing that layer's opinion")
        local now = lcs.query_value(src, w, fd, "Both")
        t:assert_eq(now.ret, 0, "lets the lower one surface: " .. sys.errname(now.errno or 0))
        t:assert_eq(now.layer, "base", "from the base layer")
        t:assert_eq(now.data, lcs.dword(1), "with its own data")

        -- A tombstone is an entry too, and deleting it is the same act.
        t:assert_eq(lcs.set_value(src, w, fd, "Both", lcs.TYPE.TOMBSTONE, "",
            { layer = "Over" }).ret, 0, "a tombstone in the upper layer")
        t:assert_eq(lcs.query_value(src, w, fd, "Both").errno, sys.E.NOENT, "masks it again")
        t:assert_eq(lcs.delete_value(src, w, fd, "Both", { layer = "Over" }).ret, 0,
            "and deleting the tombstone")
        t:assert_eq(lcs.query_value(src, w, fd, "Both").ret, 0, "brings the value back")
        sys.close(w, layer)
        sys.close(w, fd)
    end)

test("LCS does not mask a source's RSI_NOT_FOUND: idempotency is the source's obligation",
    { spec = "PKM *ioctl.delete-value.source-not-found-is-enoent" }, function(t)
        local fd = must_open(t, "Machine\\Work\\W3")
        src:intercept(lcs.OP.DELETE_VALUE, function() return lcs.STATUS.NOT_FOUND, "" end)
        local r = lcs.delete_value(src, w, fd, "NeverThere")
        t:assert_eq(r.errno, sys.E.NOENT, "a source that answers RSI_NOT_FOUND gives ENOENT")
        src:intercept(lcs.OP.DELETE_VALUE, nil)
        local honest = lcs.delete_value(src, w, fd, "NeverThere")
        t:assert_eq(honest.ret, 0,
            "while a source that answers RSI_OK for an absent entry looks idempotent")
        sys.close(w, fd)
    end)

test("REG_IOC_DELETE_KEY removes this key's path entry from a layer",
    { spec = "PKM *ioctl.delete-key.removes-the-path-entry" }, function(t)
        local fd = must_open(t, "Machine\\Work\\W4")
        local mark = src:mark()
        t:assert_eq(lcs.delete_key(src, w, fd).ret, 0, "the delete runs")
        t:assert_eq(#src:served(lcs.OP.DELETE_ENTRY, mark), 1,
            "as one RSI_DELETE_ENTRY: a path entry, not a key record")
        t:assert_eq(#src:served(lcs.OP.DROP_KEY, mark), 0, "the key object itself is not dropped")
        sys.close(w, fd)
        t:assert_eq(lcs.open_key(src, w, -1, "Machine\\Work\\W4", lcs.RIGHT.KEY_READ).errno,
            sys.E.NOENT, "and the name no longer resolves")

        local parent = must_open(t, "Machine\\Work\\W1")
        local busy = lcs.delete_key(src, w, parent)
        t:assert_eq(busy.errno, sys.E.NOTEMPTY, "a key with visible children is ENOTEMPTY")
        sys.close(w, parent)

        local root = must_open(t, "Machine")
        t:assert_eq(lcs.delete_key(src, w, root).errno, sys.E.INVAL, "and a hive root is EINVAL")
        sys.close(w, root)
    end)

test("the parent GUID comes from the fd's ancestor chain and the name from its resolved path",
    { spec = "PKM *ioctl.delete-key.parent-and-name-from-the-fd" }, function(t)
        local parent_guid = src:lookup("Machine\\Work\\W1")
        local fd = must_open(t, "Machine\\Work\\W1\\Under")
        local mark = src:mark()
        t:assert_eq(lcs.delete_key(src, w, fd).ret, 0, "the delete runs")
        local deletes = src:served(lcs.OP.DELETE_ENTRY, mark)
        t:assert_eq(#deletes, 1, "one entry removal")
        t:assert_eq(deletes[1].payload:sub(1, 16), parent_guid,
            "under the parent GUID from the fd's ancestor chain")
        t:assert_eq(string.unpack("<s4", deletes[1].payload, 17), "Under",
            "and the last component of the fd's resolved path")
        sys.close(w, fd)
    end)

test("REG_IOC_HIDE_KEY creates a HIDDEN path entry that masks lower-precedence entries",
    { spec = "PKM *ioctl.hide-key.creates-a-hidden-entry" }, function(t)
        local fd = must_open(t, "Machine\\Work\\W5")
        local mark = src:mark()
        t:assert_eq(lcs.hide_key(src, w, fd).ret, 0, "the hide runs")
        local hides = src:served(lcs.OP.HIDE_ENTRY, mark)
        t:assert_eq(#hides, 1, "as one RSI_HIDE_ENTRY at the same place")
        t:assert_eq(#src:served(lcs.OP.DELETE_ENTRY, mark), 0,
            "rather than a deletion")
        sys.close(w, fd)
        t:assert_eq(lcs.open_key(src, w, -1, "Machine\\Work\\W5", lcs.RIGHT.KEY_READ).errno,
            sys.E.NOENT, "and the name stops resolving")

        local root = must_open(t, "Machine")
        t:assert_eq(lcs.hide_key(src, w, root).errno, sys.E.INVAL, "a hive root is EINVAL")
        sys.close(w, root)
    end)

test("the caller must hold an open fd to the key, which is how it proved access to it",
    { spec = "PKM *ioctl.hide-key.requires-an-open-fd" }, function(t)
        -- The ioctl carries a layer and a transaction fd and no path:
        -- the key it hides is the one the fd names.
        local txn = assert(lcs.begin_transaction(w))
        local not_a_key = lcs.hide_key(nil, w, txn)
        t:assert_eq(not_a_key.errno, sys.E.NOTTY,
            "there is no way to name a key but the fd, and a transaction fd is not one")
        sys.close(w, txn)

        local fd = must_open(t, "Machine\\Work\\W6", lcs.RIGHT.KEY_READ)
        local unproven = lcs.hide_key(nil, w, fd)
        t:assert_eq(unproven.errno, sys.E.ACCES,
            "and the fd must have been opened for DELETE")
        sys.close(w, fd)
    end)

-- Durability -----------------------------------------------------------------

test("REG_IOC_FLUSH returns only when the source confirms persistence",
    { spec = "PKM *ioctl.flush.persists-and-waits-for-confirmation" }, function(t)
        local fd = must_open(t, "Machine\\Work\\W7")
        src:intercept(lcs.OP.FLUSH, function() return lcs.HOLD end)
        local pending = lcs.flush_async(w, fd)
        src:pump()
        local ids = src:held_ids()
        t:assert_eq(#ids, 1,
            "the flush reached the source and is unanswered, and the caller is still in it")
        src:release(ids[1])
        src:pump()
        local r = pending:await()
        t:assert_eq(r.ret, 0, "it returns when persistence is confirmed: " ..
            sys.errname(r.errno or 0))
        src:intercept(lcs.OP.FLUSH, nil)
        sys.close(w, fd)
    end)

test("the hive a flush names comes from the first component of the fd's resolved path",
    { spec = "PKM *ioctl.flush.hive-from-the-fd-path" }, function(t)
        local machine = must_open(t, "Machine\\Work\\W8")
        local mark = src:mark()
        t:assert_eq(lcs.flush(src, w, machine).ret, 0, "a flush on a Machine key")
        t:assert_eq(string.unpack("<s4", src:served(lcs.OP.FLUSH, mark)[1].payload), "Machine",
            "names the Machine hive")
        sys.close(w, machine)

        local other = must_open(t, "Other\\Room")
        mark = src:mark()
        t:assert_eq(lcs.flush(src, w, other).ret, 0, "and a flush on an Other key")
        t:assert_eq(string.unpack("<s4", src:served(lcs.OP.FLUSH, mark)[1].payload), "Other",
            "names the Other hive: this is the only RSI operation identified by hive name")
        sys.close(w, other)
    end)
