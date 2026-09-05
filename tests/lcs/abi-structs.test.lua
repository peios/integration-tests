-- PKM §5.A — the generated ABI appendix, structure half: every
-- `struct reg_*` layout, measured against live behaviour rather than
-- against the header it was generated from.
--
-- A published offset is testable because getting it wrong is visible: a
-- field read at the wrong offset carries the neighbour's value, a NULL
-- where a pointer belongs is EFAULT, and an ioctl whose encoded
-- argument size is not the published one is ENOTTY before the kernel
-- looks at the bytes at all. So each case drives the real call with the
-- documented layout and shows the documented field doing its work, then
-- perturbs exactly the offset or size under test.
--
-- The constant tables of the same appendix are in abi-tables, the
-- tracepoint vocabularies in abi-tracepoints, and §5.B in abi-notes.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")

local vm = provium:vm("v", "kernel-only"):boot()

local MACHINE_ROOT = lcs.guid()
local O_NONBLOCK = 0x800
local ETIMEDOUT = 110

--- A Machine source with a test key. `layered` adds a second layer,
--- `Over`, for the cases whose subject is a layer-naming field; the
--- rest go without it, because a hive that holds a layer other than
--- base cannot currently be backed up (see the report).
local function machine(seed, layered)
    local src = lcs.source(vm, { hives = {
        { name = "Machine", root = MACHINE_ROOT } } })
    src:key("Machine\\Software\\Test")
    if layered then src:seed_layer("Over", { precedence = 10, enabled = 1 }) end
    if seed then seed(src) end
    assert(src:register())
    src:pump()
    return src
end

local function open(t, src, w, path, mask, flags)
    local r = lcs.open_key(src, w, -1, path, mask or lcs.KEY_ALL_ACCESS, flags)
    t:assert(r.ret >= 0, "open " .. path .. ": " .. sys.errname(r.errno or 0))
    return r.ret
end

--- An ioctl with a hand-packed argument structure. `links` is a list of
--- `{ bytes, offset }`: a buffer the structure points to from that byte
--- offset, which is how a case puts a pointer somewhere it does not
--- belong.
local function ioctl_raw(src, w, fd, cmd, args, links)
    local bufs, nested = { args }, {}
    for _, l in ipairs(links or {}) do
        bufs[#bufs + 1] = l[1]
        nested[#nested + 1] = { parent = 1, child = #bufs, offset = l[2] }
    end
    local spec = { args = { fd, cmd, 0 }, bufs = bufs, ptrs = { 2 },
                   nested = nested }
    if src then
        return src:run(function() return w:syscall_async(sys.NR.ioctl, spec) end)
    end
    return w:syscall(sys.NR.ioctl, spec)
end

--- The same for reg_create_key, whose one argument is the structure.
local function create_raw(src, w, args, links)
    local bufs, nested = { args }, {}
    for _, l in ipairs(links or {}) do
        bufs[#bufs + 1] = l[1]
        nested[#nested + 1] = { parent = 1, child = #bufs, offset = l[2] }
    end
    local spec = { args = { 0 }, bufs = bufs, ptrs = { 0 }, nested = nested }
    return src:run(function()
        return w:syscall_async(lcs.SYS.CREATE_KEY, spec)
    end)
end

--- The published total size is the size field of the ioctl's encoded
--- number: one byte either way is a different ioctl, and ENOTTY.
local function assert_total_size(t, w, fd, name, encoded)
    local size = (encoded >> 16) & 0x3FFF
    t:assert_eq(ioctl_raw(nil, w, fd, encoded + (1 << 16),
        string.rep("\0", size + 1)).errno, sys.E.NOTTY,
        name .. " is " .. size .. " bytes: " .. (size + 1) .. " is not the ioctl")
    t:assert_eq(ioctl_raw(nil, w, fd, encoded - (1 << 16),
        string.rep("\0", size - 1)).errno, sys.E.NOTTY,
        name .. " is " .. size .. " bytes: " .. (size - 1) .. " is not it either")
end

local function zeros(n) return string.rep("\0", n) end

-- ---- the syscall argument structure ----------------------------------

test("struct reg_create_key_args: 48 bytes, path at 8, flags at 20, disposition at 40",
    { spec = "PKM *lcs-abi.struct-reg-create-key-args" }, function(t)
        local src = machine()
        local w = vm:spawn_worker()
        local ok, err = pcall(function()
            local key = open(t, src, w, "Machine\\Software\\Test")
            -- The documented layout, used as documented.
            local made = lcs.create_key(src, w,
                { parent_fd = key, path = "Documented", flags = 0x01 })
            t:assert(made.ret >= 0, "the documented layout creates a key: "
                .. sys.errname(made.errno or 0))
            t:assert_eq(made.disposition, lcs.CREATED_NEW,
                "the disposition is written through the pointer at offset 40")
            t:assert(lcs.query_key_info(src, w, made.ret).volatile,
                "REG_OPTION_VOLATILE was read from flags at offset 20, "
                    .. "not from desired_access at 16")
            sys.close(w, made.ret)

            -- The path pointer one slot along: offset 8 is then zero.
            local args = string.pack("<i4I4I8I4I4I8i4I4I8",
                key, 0, 0, lcs.KEY_ALL_ACCESS, 0, 0, -1, 0, 0)
            local shifted = create_raw(src, w, args,
                { { sys.cstr("Shifted"), 16 } })
            t:assert(shifted.ret < 0,
                "a path pointer at offset 16 leaves path_ptr NULL at 8: "
                    .. sys.errname(shifted.errno or 0))
            sys.close(w, key)
        end)
        w:kill(); w:join()
        src:close()
        if not ok then error(err, 0) end
    end)

-- ---- key-fd ioctl argument structures --------------------------------

test("struct reg_query_value_args: 64 bytes, type at 16, sequence at 40, layer at 48",
    { spec = "PKM *lcs-abi.struct-reg-query-value-args" }, function(t)
        local src = machine()
        local w = vm:spawn_worker()
        local ok, err = pcall(function()
            local key = open(t, src, w, "Machine\\Software\\Test")
            assert_total_size(t, w, key, "reg_query_value_args", 0xC0405200)
            lcs.set_value(src, w, key, "Doc", lcs.TYPE.DWORD, lcs.dword(9))
            local q = lcs.query_value(src, w, key, "Doc")
            t:assert_eq(q.ret, 0, "the documented layout queries: "
                .. sys.errname(q.errno or 0))
            t:assert_eq(q.type, lcs.TYPE.DWORD,
                "type comes back at offset 16")
            t:assert_eq(q.data_len, 4, "data_len at 20")
            t:assert_eq(q.data, lcs.dword(9),
                "and the data through the pointer at 32")
            t:assert(q.sequence > 0, "the sequence at 40")
            t:assert_eq(q.layer_len, #"base", "the layer length at 48")
            t:assert_eq(q.layer, "base",
                "and the layer name through the pointer at 56")
            -- name_len one slot along: offset 0 is then zero, and a
            -- nameless value is not this value.
            local args = string.pack("<I4I4I8I4I4i4I4I8I8I4I4I8",
                0, #"Doc", 0, 0, 4096, -1, 256, 0, 0, 0, 0, 0)
            local shifted = ioctl_raw(src, w, key, 0xC0405200, args,
                { { "Doc", 8 }, { zeros(4096), 32 }, { zeros(256), 56 } })
            t:assert_neq(shifted.ret, 0,
                "name_len read at offset 4 is not the name length: "
                    .. sys.errname(shifted.errno or 0))
            sys.close(w, key)
        end)
        w:kill(); w:join()
        src:close()
        if not ok then error(err, 0) end
    end)

test("struct reg_set_value_args: 64 bytes, layer at 32, txn_fd at 48, expected_seq at 56",
    { spec = "PKM *lcs-abi.struct-reg-set-value-args" }, function(t)
        local src = machine(nil, true)
        local w = vm:spawn_worker()
        local ok, err = pcall(function()
            local key = open(t, src, w, "Machine\\Software\\Test")
            assert_total_size(t, w, key, "reg_set_value_args", 0x40405201)
            -- layer_len at 32 and layer_ptr at 40 name the layer written.
            t:assert_eq(lcs.set_value(src, w, key, "Where", lcs.TYPE.DWORD,
                lcs.dword(1), { layer = "Over" }).ret, 0,
                "a write naming a layer succeeds")
            t:assert_eq(lcs.query_value(src, w, key, "Where").layer, "Over",
                "and lands in the layer named at offsets 32 and 40")
            -- expected_seq at 56 is the conditional write's condition.
            local seq = lcs.query_value(src, w, key, "Where").sequence
            local stale = lcs.set_value(src, w, key, "Where", lcs.TYPE.DWORD,
                lcs.dword(2), { layer = "Over", expected_seq = seq + 1 })
            t:assert_eq(stale.errno, sys.E.AGAIN,
                "a wrong expected_seq at offset 56 fails the conditional write")
            t:assert_eq(lcs.set_value(src, w, key, "Where", lcs.TYPE.DWORD,
                lcs.dword(3), { layer = "Over", expected_seq = seq }).ret, 0,
                "and the right one succeeds")
            -- txn_fd at 48: a write bound to a transaction is not
            -- visible until it commits.
            local txn = assert(lcs.begin_transaction(w))
            t:assert_eq(lcs.set_value(src, w, key, "Pending", lcs.TYPE.DWORD,
                lcs.dword(1), { txn_fd = txn }).ret, 0,
                "a write naming a transaction at offset 48 succeeds")
            t:assert_eq(lcs.query_value(src, w, key, "Pending").errno,
                sys.E.NOENT, "and is not yet visible outside it")
            sys.close(w, txn)
            sys.close(w, key)
        end)
        w:kill(); w:join()
        src:close()
        if not ok then error(err, 0) end
    end)

test("struct reg_delete_value_args: 40 bytes, layer at 16, txn_fd at 32",
    { spec = "PKM *lcs-abi.struct-reg-delete-value-args" }, function(t)
        local src = machine(nil, true)
        local w = vm:spawn_worker()
        local ok, err = pcall(function()
            local key = open(t, src, w, "Machine\\Software\\Test")
            assert_total_size(t, w, key, "reg_delete_value_args", 0x40285202)
            lcs.set_value(src, w, key, "Two", lcs.TYPE.DWORD, lcs.dword(1))
            lcs.set_value(src, w, key, "Two", lcs.TYPE.DWORD, lcs.dword(2),
                { layer = "Over" })
            t:assert_eq(lcs.query_value(src, w, key, "Two").layer, "Over",
                "the higher layer wins before the delete")
            t:assert_eq(lcs.delete_value(src, w, key, "Two",
                { layer = "Over" }).ret, 0,
                "a delete naming a layer at offsets 16 and 24 succeeds")
            local left = lcs.query_value(src, w, key, "Two")
            t:assert_eq(left.ret, 0, "the other layer's entry is still there")
            t:assert_eq(left.layer, "base",
                "so the layer name was read where the appendix puts it")
            sys.close(w, key)
        end)
        w:kill(); w:join()
        src:close()
        if not ok then error(err, 0) end
    end)

test("struct reg_blanket_tombstone_args: 24 bytes, set is one byte at 16",
    { spec = "PKM *lcs-abi.struct-reg-blanket-tombstone-args" }, function(t)
        local src = machine(nil, true)
        local w = vm:spawn_worker()
        local ok, err = pcall(function()
            local key = open(t, src, w, "Machine\\Software\\Test")
            local guid = src:lookup("Machine\\Software\\Test")
            assert_total_size(t, w, key, "reg_blanket_tombstone_args", 0x40185203)
            t:assert_eq(lcs.blanket_tombstone(src, w, key, "Over", true).ret, 0,
                "set = 1 at offset 16 applies a blanket")
            t:assert((src.store.blankets[guid] or {})["over"],
                "and the source holds it")
            t:assert_eq(lcs.blanket_tombstone(src, w, key, "Over", false).ret, 0,
                "set = 0 clears it")
            t:assert(not (src.store.blankets[guid] or {})["over"],
                "and the source no longer holds it")
            -- The byte one along is _pad1, not set.
            local r = lcs.blanket_tombstone(src, w, key, "Over", true,
                { pad1 = 0 })
            t:assert_eq(r.ret, 0, "a blanket is applied again")
            t:assert((src.store.blankets[guid] or {})["over"],
                "with set at 16 and the three pad bytes at 17 ignored")
            sys.close(w, key)
        end)
        w:kill(); w:join()
        src:close()
        if not ok then error(err, 0) end
    end)

test("struct reg_query_values_batch_args: 24 bytes, buf_len at 0, count at 4",
    { spec = "PKM *lcs-abi.struct-reg-query-values-batch-args" }, function(t)
        local src = machine()
        local w = vm:spawn_worker()
        local ok, err = pcall(function()
            local key = open(t, src, w, "Machine\\Software\\Test")
            assert_total_size(t, w, key, "reg_query_values_batch_args", 0xC0185204)
            lcs.set_value(src, w, key, "One", lcs.TYPE.DWORD, lcs.dword(1))
            lcs.set_value(src, w, key, "Two", lcs.TYPE.DWORD, lcs.dword(2))
            local b = lcs.query_values_batch(src, w, key)
            t:assert_eq(b.ret, 0, "the documented layout answers: "
                .. sys.errname(b.errno or 0))
            t:assert_eq(b.count, 2,
                "the count of records comes back at offset 4")
            t:assert(b.buf_len > 0,
                "and the bytes used at offset 0")
            t:assert_eq(#b.values, 2,
                "through the buffer pointer at offset 8")
            -- The two-pass convention: a zero buffer reports the size.
            local probe = lcs.query_values_batch(src, w, key, { buf_len = 0 })
            t:assert(probe.buf_len > 0,
                "and a zero buf_len at offset 0 is answered with the size there")
            sys.close(w, key)
        end)
        w:kill(); w:join()
        src:close()
        if not ok then error(err, 0) end
    end)

test("struct reg_enum_value_args: 40 bytes, index at 0, name_len at 4",
    { spec = "PKM *lcs-abi.struct-reg-enum-value-args" }, function(t)
        local src = machine()
        local w = vm:spawn_worker()
        local ok, err = pcall(function()
            local key = open(t, src, w, "Machine\\Software\\Test")
            assert_total_size(t, w, key, "reg_enum_value_args", 0xC0285205)
            lcs.set_value(src, w, key, "Alpha", lcs.TYPE.DWORD, lcs.dword(1))
            lcs.set_value(src, w, key, "Beta", lcs.TYPE.SZ, lcs.sz("b"))
            local first = lcs.enum_values(src, w, key, 0)
            local second = lcs.enum_values(src, w, key, 1)
            t:assert_eq(first.ret, 0, "index 0 at offset 0 selects a value")
            t:assert_eq(second.ret, 0, "index 1 selects another")
            t:assert_neq(first.name, second.name,
                "and they are different: the index is read at offset 0")
            t:assert_eq(first.name_len, #first.name,
                "name_len comes back at offset 4")
            t:assert(first.type == lcs.TYPE.DWORD or first.type == lcs.TYPE.SZ,
                "the type at 16")
            t:assert_eq(second.data_len, #second.data, "and data_len at 20")
            t:assert_eq(lcs.enum_values(src, w, key, 2).errno, sys.E.NOENT,
                "index 2 is past the end")
            sys.close(w, key)
        end)
        w:kill(); w:join()
        src:close()
        if not ok then error(err, 0) end
    end)

test("struct reg_enum_subkey_args: 40 bytes, counts at 24 and 28",
    { spec = "PKM *lcs-abi.struct-reg-enum-subkey-args" }, function(t)
        local src = machine()
        local w = vm:spawn_worker()
        local ok, err = pcall(function()
            local key = open(t, src, w, "Machine\\Software\\Test")
            assert_total_size(t, w, key, "reg_enum_subkey_args", 0xC0285206)
            local child = lcs.create_key(src, w, { parent_fd = key, path = "Kid" })
            t:assert(child.ret >= 0, "a child key exists")
            lcs.set_value(src, w, child.ret, "V", lcs.TYPE.DWORD, lcs.dword(1))
            local grand = lcs.create_key(src, w,
                { parent_fd = child.ret, path = "Grand" })
            local e = lcs.enum_subkeys(src, w, key, 0)
            t:assert_eq(e.ret, 0, "index 0 at offset 0 enumerates it")
            t:assert_eq(e.name, "Kid", "the name through the pointer at 8")
            t:assert_eq(e.name_len, #"Kid", "with its length at 4")
            t:assert_eq(e.subkey_count, 1,
                "the child's own subkey count at offset 24")
            t:assert_eq(e.value_count, 1, "and its value count at 28")
            t:assert_eq(lcs.enum_subkeys(src, w, key, 1).errno, sys.E.NOENT,
                "index 1 is past the end")
            sys.close(w, grand.ret); sys.close(w, child.ret); sys.close(w, key)
        end)
        w:kill(); w:join()
        src:close()
        if not ok then error(err, 0) end
    end)

test("struct reg_query_key_info_args: 64 bytes, volatile at 48 and symlink at 49",
    { spec = "PKM *lcs-abi.struct-reg-query-key-info-args" }, function(t)
        local src = machine(function(s)
            s:symlink("Machine\\Software\\Link", "Machine\\Software\\Test")
        end)
        local w = vm:spawn_worker()
        local ok, err = pcall(function()
            local key = open(t, src, w, "Machine\\Software\\Test")
            assert_total_size(t, w, key, "reg_query_key_info_args", 0xC0405207)
            lcs.set_value(src, w, key, "V", lcs.TYPE.DWORD, lcs.dword(1))
            local child = lcs.create_key(src, w, { parent_fd = key, path = "Kid" })
            local info = lcs.query_key_info(src, w, key)
            t:assert_eq(info.ret, 0, "the documented layout answers")
            t:assert_eq(info.name, "Test", "the key's name at 8, its length at 0")
            t:assert_eq(info.subkey_count, 1, "the subkey count at 24")
            t:assert_eq(info.value_count, 1, "the value count at 28")
            t:assert(info.sd_size > 0, "the descriptor size at 44")
            t:assert(info.hive_generation > 0, "and the hive generation at 56")
            -- The two one-byte flags are neighbours, and each is read
            -- from its own byte.
            t:assert_eq(info.volatile, false, "an ordinary key is not volatile")
            t:assert_eq(info.symlink, false, "and not a symlink")
            local vol = lcs.create_key(src, w,
                { parent_fd = key, path = "Vol", flags = 0x01 })
            local vinfo = lcs.query_key_info(src, w, vol.ret)
            t:assert_eq(vinfo.volatile, true, "volatile_key is the byte at 48")
            t:assert_eq(vinfo.symlink, false, "and it is not the byte at 49")
            local link = open(t, src, w, "Machine\\Software\\Link",
                lcs.KEY_ALL_ACCESS, 0x01)
            local linfo = lcs.query_key_info(src, w, link)
            t:assert_eq(linfo.symlink, true, "symlink is the byte at 49")
            t:assert_eq(linfo.volatile, false, "and it is not the byte at 48")
            sys.close(w, link); sys.close(w, vol.ret); sys.close(w, child.ret)
            sys.close(w, key)
        end)
        w:kill(); w:join()
        src:close()
        if not ok then error(err, 0) end
    end)

test("struct reg_delete_key_args: 24 bytes, layer at 0, txn_fd at 16",
    { spec = "PKM *lcs-abi.struct-reg-delete-key-args" }, function(t)
        local src = machine(nil, true)
        local w = vm:spawn_worker()
        local ok, err = pcall(function()
            local key = open(t, src, w, "Machine\\Software\\Test")
            assert_total_size(t, w, key, "reg_delete_key_args", 0x40185208)
            -- The key exists in the base layer only, so a delete that
            -- names Over has nothing to delete: if the layer name were
            -- read from anywhere else the base entry would go.
            local both = lcs.create_key(src, w, { parent_fd = key, path = "Both" })
            t:assert(both.ret >= 0, "a key is created in the base layer")
            t:assert(lcs.delete_key(src, w, both.ret, { layer = "Over" }).ret < 0,
                "a delete naming Over at offsets 0 and 8 finds no entry there")
            local left = lcs.open_key(src, w, -1,
                "Machine\\Software\\Test\\Both", lcs.RIGHT.KEY_READ)
            t:assert(left.ret >= 0,
                "and the base entry survives: the layer was read where "
                    .. "the appendix puts it")
            -- txn_fd at 16: a delete inside a transaction that never
            -- commits leaves the key.
            local txn = assert(lcs.begin_transaction(w))
            t:assert_eq(lcs.delete_key(src, w, both.ret, { txn_fd = txn }).ret, 0,
                "a delete naming a transaction at offset 16 succeeds")
            sys.close(w, txn)
            local still = lcs.open_key(src, w, -1,
                "Machine\\Software\\Test\\Both", lcs.RIGHT.KEY_READ)
            t:assert(still.ret >= 0, "and the abandoned transaction took it back")
            -- Naming no layer at all deletes the base entry.
            t:assert_eq(lcs.delete_key(src, w, both.ret, {}).ret, 0,
                "a delete naming nothing takes the base entry")
            t:assert_eq(lcs.open_key(src, w, -1,
                "Machine\\Software\\Test\\Both", lcs.RIGHT.KEY_READ).errno,
                sys.E.NOENT, "and the key is gone")
            sys.close(w, still.ret); sys.close(w, left.ret)
            sys.close(w, both.ret); sys.close(w, key)
        end)
        w:kill(); w:join()
        src:close()
        if not ok then error(err, 0) end
    end)

test("struct reg_hide_key_args: 24 bytes, layer at 0, txn_fd at 16",
    { spec = "PKM *lcs-abi.struct-reg-hide-key-args" }, function(t)
        local src = machine(nil, true)
        local w = vm:spawn_worker()
        local ok, err = pcall(function()
            local key = open(t, src, w, "Machine\\Software\\Test")
            assert_total_size(t, w, key, "reg_hide_key_args", 0x40185209)
            local child = lcs.create_key(src, w,
                { parent_fd = key, path = "Hidden" })
            t:assert(child.ret >= 0, "a key to mask exists")
            local guid = src:lookup("Machine\\Software\\Test")
            t:assert_eq(lcs.hide_key(src, w, child.ret, { layer = "Over" }).ret,
                0, "a hide naming Over at offsets 0 and 8 succeeds")
            local entry = lcs.entry(src, guid, "Hidden", "Over")
            t:assert(entry and entry.hidden,
                "and the source holds a HIDDEN entry in that layer, not another")
            sys.close(w, child.ret); sys.close(w, key)
        end)
        w:kill(); w:join()
        src:close()
        if not ok then error(err, 0) end
    end)

test("struct reg_get_security_args: 16 bytes, sd_len at 4, sd_ptr at 8",
    { spec = "PKM *lcs-abi.struct-reg-get-security-args" }, function(t)
        local src = machine()
        local w = vm:spawn_worker()
        local ok, err = pcall(function()
            local key = open(t, src, w, "Machine\\Software\\Test")
            assert_total_size(t, w, key, "reg_get_security_args", 0xC010520A)
            local full = lcs.get_security(src, w, key, lcs.SI.DACL)
            t:assert_eq(full.ret, 0, "the documented layout reads a descriptor")
            t:assert_eq(full.sd_len, #full.sd,
                "the length comes back at offset 4 and matches the bytes at 8")
            -- The two-pass convention of §5.5: no buffer, and the length
            -- is reported in the same field.
            local probe = lcs.get_security(src, w, key, lcs.SI.DACL,
                { sd_len = 0 })
            t:assert_eq(probe.sd_len, full.sd_len,
                "a zero sd_len at offset 4 is answered with the size there")
            sys.close(w, key)
        end)
        w:kill(); w:join()
        src:close()
        if not ok then error(err, 0) end
    end)

test("struct reg_set_security_args: 24 bytes, sd at 4 and 8, txn_fd at 16",
    { spec = "PKM *lcs-abi.struct-reg-set-security-args" }, function(t)
        local src = machine()
        local w = vm:spawn_worker()
        local ok, err = pcall(function()
            local key = open(t, src, w, "Machine\\Software\\Test")
            assert_total_size(t, w, key, "reg_set_security_args", 0x4018520B)
            local before = lcs.get_security(src, w, key, lcs.SI.DACL).sd
            local wanted = lcs.permissive_sd()
            t:assert_eq(lcs.set_security(src, w, key, lcs.SI.DACL, wanted).ret, 0,
                "the documented layout writes a descriptor")
            local after = lcs.get_security(src, w, key, lcs.SI.DACL).sd
            t:assert(after and #after > 0, "and it reads back")
            -- txn_fd at 16: a descriptor change inside a transaction that
            -- never commits does not take.
            local txn = assert(lcs.begin_transaction(w))
            t:assert_eq(lcs.set_security(src, w, key, lcs.SI.DACL,
                lcs.sd({}), { txn_fd = txn }).ret, 0,
                "a write naming a transaction at offset 16 succeeds")
            sys.close(w, txn)
            local final = lcs.get_security(src, w, key, lcs.SI.DACL).sd
            t:assert_eq(final, after,
                "and the abandoned transaction left the descriptor alone")
            sys.close(w, key)
        end)
        w:kill(); w:join()
        src:close()
        if not ok then error(err, 0) end
    end)

test("struct reg_notify_args: 8 bytes, filter at 0 and subtree one byte at 4",
    { spec = "PKM *lcs-abi.struct-reg-notify-args" }, function(t)
        local src = machine()
        local w = vm:spawn_worker()
        local ok, err = pcall(function()
            local root = open(t, src, w, "Machine")
            assert_total_size(t, w, root, "reg_notify_args", 0x4008520C)
            local deep = open(t, src, w, "Machine\\Software\\Test")
            -- subtree = 1 at offset 4: a change below the key is seen.
            t:assert_eq(lcs.notify(nil, w, root, lcs.NOTIFY.VALUE, true).ret, 0,
                "a subtree watcher is armed")
            lcs.set_value(src, w, deep, "Below", lcs.TYPE.DWORD, lcs.dword(1))
            local sub = lcs.read_events(nil, w, root)
            t:assert(#sub.events > 0,
                "and the change three components below reaches it")
            -- Only the byte at 4 is subtree: the three that follow are
            -- `_pad`, and a 1 in them is not a smaller subtree flag but
            -- a malformed argument.
            local flat = open(t, src, w, "Machine")
            t:assert_eq(lcs.notify(nil, w, flat, lcs.NOTIFY.VALUE, 0,
                { pad = "\1\0\0" }).errno, sys.E.INVAL,
                "a 1 at offset 5 is padding, and padding must be zero")
            t:assert_eq(lcs.notify(nil, w, flat, lcs.NOTIFY.VALUE, 0).ret, 0,
                "the same call with the byte at 4 clear and the padding zero "
                    .. "arms a plain watcher")
            lcs.set_value(src, w, deep, "Below2", lcs.TYPE.DWORD, lcs.dword(2))
            lcs.set_value(src, w, flat, "Here", lcs.TYPE.DWORD, lcs.dword(3))
            local none = lcs.read_events(nil, w, flat)
            t:assert_eq(#none.events, 1,
                "which sees only the change on its own key: subtree was the "
                    .. "byte at 4")
            t:assert_eq(none.events[1].name, "Here",
                "and nothing from below it")
            sys.close(w, flat); sys.close(w, deep); sys.close(w, root)
        end)
        w:kill(); w:join()
        src:close()
        if not ok then error(err, 0) end
    end)

test("struct reg_backup_args: 4 bytes, output_fd at 0",
    { spec = "PKM *lcs-abi.struct-reg-backup-args" }, function(t)
        local src = machine()
        local w = vm:spawn_worker()
        local ok, err = pcall(function()
            local root = open(t, src, w, "Machine")
            assert_total_size(t, w, root, "reg_backup_args", 0x4004520E)
            local rd, wr = sys.pipe(w)
            t:assert_eq(lcs.backup(src, w, root, wr).ret, 0,
                "the fd at offset 0 is where the stream goes")
            sys.close(w, wr)
            local data = sys.read(w, rd, 65536)
            t:assert(data and #data > 0, "and the stream arrives on it")
            t:assert_eq(data:sub(7, 14), "PEIOSREG", "as a backup stream")
            sys.close(w, rd)
            -- A closed descriptor in the same four bytes is EBADF, not
            -- something read from elsewhere in the structure.
            t:assert_eq(lcs.backup(src, w, root, wr).errno, sys.E.BADF,
                "a stale fd at offset 0 is refused as one")
            sys.close(w, root)
        end)
        w:kill(); w:join()
        src:close()
        if not ok then error(err, 0) end
    end)

test("struct reg_restore_args: 4 bytes, input_fd at 0",
    { spec = "PKM *lcs-abi.struct-reg-restore-args" }, function(t)
        local src = machine()
        local w = vm:spawn_worker()
        local ok, err = pcall(function()
            local root = open(t, src, w, "Machine")
            assert_total_size(t, w, root, "reg_restore_args", 0x4004520F)
            local rd, wr = sys.pipe(w)
            sys.close(w, wr)
            local empty = lcs.restore(src, w, root, rd)
            t:assert(empty.ret < 0,
                "the fd at offset 0 is where the stream is read from, and an "
                    .. "empty one is not a stream: " .. sys.errname(empty.errno or 0))
            t:assert_neq(empty.errno, sys.E.BADF,
                "it was read as a descriptor, not as zero")
            sys.close(w, rd)
            t:assert_eq(lcs.restore(src, w, root, -1).errno, sys.E.BADF,
                "and -1 in the same four bytes is EBADF")
            sys.close(w, root)
        end)
        w:kill(); w:join()
        src:close()
        if not ok then error(err, 0) end
    end)

-- ---- transaction-fd ioctl argument structure -------------------------

test("struct reg_txn_status_args: 8 bytes, state at 0 and terminal_errno at 4",
    { spec = "PKM *lcs-abi.struct-reg-txn-status-args" }, function(t)
        local src = machine(function(s)
            s:key(lcs.PARAMS_PATH)
            s:seed_param("TransactionTimeoutMs", 1000)
        end)
        local w = vm:spawn_worker()
        local ok, err = pcall(function()
            local txn = assert(lcs.begin_transaction(w))
            assert_total_size(t, w, txn, "reg_txn_status_args", 0x80085211)
            local fresh = lcs.txn_status(nil, w, txn)
            t:assert_eq(fresh.ret, 0, "the documented layout answers")
            t:assert_eq(fresh.state, lcs.TXN.ACTIVE_UNBOUND,
                "the state is a u32 at offset 0")
            t:assert_eq(fresh.terminal_errno, 0,
                "and terminal_errno at 4 is zero while nothing has gone wrong")
            local key = open(t, src, w, "Machine\\Software\\Test")
            lcs.set_value(src, w, key, "A", lcs.TYPE.DWORD, lcs.dword(1),
                { txn_fd = txn })
            sys.nanosleep(vm, 2, 0)
            local dead = lcs.txn_status(nil, w, txn)
            t:assert_eq(dead.state, lcs.TXN.TIMED_OUT,
                "a timed-out transaction reports its state at 0")
            t:assert_eq(dead.terminal_errno, ETIMEDOUT,
                "and the errno that ended it at 4, in the next four bytes")
            sys.close(w, key); sys.close(w, txn)
        end)
        w:kill(); w:join()
        src:close()
        if not ok then error(err, 0) end
    end)

-- ---- source-device argument structures -------------------------------

test("struct reg_src_register_args: 24 bytes, max_sequence at 8, hives_ptr at 16",
    { spec = "PKM *lcs-abi.struct-reg-src-register-args" }, function(t)
        -- The documented layout registers, and max_sequence at offset 8
        -- is what LCS advances next_sequence past.
        local src = lcs.source(vm, { hives = { { name = "Structs" } } })
        src:key("Structs\\Software\\Test")
        assert(src:register({ max_sequence = 900 }))
        src:pump()
        local w = vm:spawn_worker()
        local ok, err = pcall(function()
            local key = open(t, src, w, "Structs\\Software\\Test")
            lcs.set_value(src, w, key, "First", lcs.TYPE.DWORD, lcs.dword(1))
            t:assert_eq(lcs.query_value(src, w, key, "First").sequence, 901,
                "max_sequence was read at offset 8: the next sequence is 901")
            sys.close(w, key)

            -- hive_count lives at offset 0. Read one slot along, it is
            -- the padding, which is zero, and no hives is not a
            -- registration.
            local dev = sys.open(w, lcs.DEVICE, sys.O.RDWR | O_NONBLOCK)
            t:assert(dev, "a second source device fd opens")
            local entry = string.pack("<I4I4I8", #"Nope", 0, 0)
                .. lcs.guid() .. string.pack("<I4I4", 0, 0) .. lcs.NULL_GUID
            local shifted = w:syscall(sys.NR.ioctl, {
                args = { dev, 0x40185200, 0 },
                bufs = { string.pack("<I4I4I8I8", 0, 1, 0, 0), entry, "Nope" },
                ptrs = { 2 },
                nested = { { parent = 1, child = 2, offset = 16 },
                           { parent = 2, child = 3, offset = 8 } },
            })
            t:assert(shifted.ret < 0,
                "hive_count read at offset 4 is not the count: "
                    .. sys.errname(shifted.errno or 0))
            sys.close(w, dev)
        end)
        w:kill(); w:join()
        src:close()
        if not ok then error(err, 0) end
    end)

test("struct reg_src_hive_entry: 56 bytes, root_guid at 16, flags at 32, scope at 40",
    { spec = "PKM *lcs-abi.struct-reg-src-hive-entry" }, function(t)
        -- Two entries in one array: the second is at byte 56, and its
        -- flags word at offset 32 of it is what makes it private.
        local scope = lcs.guid()
        local src = lcs.source(vm, { hives = {
            { name = "Entries" },
            { name = "Private", flags = 0x01, scope = scope },
        } })
        src:key("Entries\\Visible")
        src:key("Private\\Hidden", { root = src.hives[2].root })
        assert(src:register())
        src:pump()
        local w = vm:spawn_worker()
        local ok, err = pcall(function()
            local seen = lcs.open_key(src, w, -1, "Entries\\Visible",
                lcs.RIGHT.KEY_READ)
            t:assert(seen.ret >= 0,
                "the first entry's name at 0 and 8 and root GUID at 16 route: "
                    .. sys.errname(seen.errno or 0))
            t:assert_eq(lcs.query_key_info(src, w, seen.ret).name, "Visible",
                "to the key under that root")
            local hidden = lcs.open_key(src, w, -1, "Private\\Hidden",
                lcs.RIGHT.KEY_READ)
            t:assert_eq(hidden.errno, sys.E.NOENT,
                "and the second entry, 56 bytes along, carries "
                    .. "RSI_HIVE_PRIVATE in flags at offset 32")
            sys.close(w, seen.ret)
        end)
        w:kill(); w:join()
        src:close()
        if not ok then error(err, 0) end
    end)
