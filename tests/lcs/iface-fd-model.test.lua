-- PKM §5.5.1 — The fd model: three syscalls and eighteen ioctls, what a
-- key fd and a transaction fd hold, the reserved-field rule, the
-- (len, ptr) string convention, and the variable-size output buffer
-- contract shared by six ioctls.
--
-- One source serves two hives so the transaction-binding case has a
-- second one to cross into.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")

local vm = provium:vm("v", "kernel-only"):boot()

local src = lcs.source(vm, { hives = { { name = "Machine" }, { name = "Second" } } })
local TEST = src:key("Machine\\Software\\Test")
src:key("Second\\Room")
assert(src:register())
src:pump()

local w = vm:spawn_worker()

--- A fresh subkey of Machine\Software\Test, so cases do not share one.
local function scratch(t, name)
    local r = lcs.create_key(src, w, { path = "Machine\\Software\\Test\\" .. name })
    t:assert(r.ret >= 0, "scratch " .. name .. ": " .. sys.errname(r.errno or 0))
    return r.ret
end

local function open_test(t, access)
    local r = lcs.open_key(src, w, -1, "Machine\\Software\\Test", access or lcs.KEY_ALL_ACCESS)
    t:assert(r.ret >= 0, "open Test: " .. sys.errname(r.errno or 0))
    return r.ret
end

-- The eighteen (number, direction, size) triples of §5.A. The first
-- sixteen act on a key fd, the last two on a transaction fd.
local KEY_IOCTLS = {
    { 0, lcs.IOC_DIR.WR, 64, "QUERY_VALUE" },
    { 1, lcs.IOC_DIR.W, 64, "SET_VALUE" },
    { 2, lcs.IOC_DIR.W, 40, "DELETE_VALUE" },
    { 3, lcs.IOC_DIR.W, 24, "BLANKET_TOMBSTONE" },
    { 4, lcs.IOC_DIR.WR, 24, "QUERY_VALUES_BATCH" },
    { 5, lcs.IOC_DIR.WR, 40, "ENUM_VALUES" },
    { 6, lcs.IOC_DIR.WR, 40, "ENUM_SUBKEYS" },
    { 7, lcs.IOC_DIR.WR, 64, "QUERY_KEY_INFO" },
    { 8, lcs.IOC_DIR.W, 24, "DELETE_KEY" },
    { 9, lcs.IOC_DIR.W, 24, "HIDE_KEY" },
    { 10, lcs.IOC_DIR.WR, 16, "GET_SECURITY" },
    { 11, lcs.IOC_DIR.W, 24, "SET_SECURITY" },
    { 12, lcs.IOC_DIR.W, 8, "NOTIFY" },
    { 13, lcs.IOC_DIR.NONE, 0, "FLUSH" },
    { 14, lcs.IOC_DIR.W, 4, "BACKUP" },
    { 15, lcs.IOC_DIR.W, 4, "RESTORE" },
}

-- Syscalls ------------------------------------------------------------

test("the three syscalls occupy 1100, 1101 and 1102",
    { spec = "PKM *fd.three-syscalls-numbered-1100-to-1102" }, function(t)
        local o = lcs.open_key(src, w, -1, "Machine\\Software\\Test", lcs.RIGHT.KEY_READ)
        t:assert(o.ret >= 0, "1100 is reg_open_key: " .. sys.errname(o.errno or 0))
        sys.close(w, o.ret)

        local c = lcs.create_key(src, w, { path = "Machine\\Software\\Test\\Numbered" })
        t:assert(c.ret >= 0, "1101 is reg_create_key: " .. sys.errname(c.errno or 0))
        sys.close(w, c.ret)

        local txn = lcs.begin_transaction(w)
        t:assert(txn, "1102 is reg_begin_transaction")
        sys.close(w, txn)

        local past = w:syscall(1103)
        t:assert_eq(past.errno, sys.E.NOSYS, "and 1103 is not an LCS syscall")
    end)

test("eighteen ioctls, all under type byte 'R', sixteen on a key fd and two on a transaction fd",
    { spec = "PKM *fd.eighteen-ioctls-under-type-r" }, function(t)
        local fd = open_test(t)
        for _, e in ipairs(KEY_IOCTLS) do
            local nr, dir, size, name = e[1], e[2], e[3], e[4]
            if nr == 13 then
                -- _IO with no argument: it really runs, so run it honestly.
                local r = lcs.flush(src, w, fd)
                t:assert_eq(r.ret, 0, "REG_IOC_" .. name .. " is implemented on a key fd: " ..
                    sys.errname(r.errno or 0))
            else
                local r = w:syscall(sys.NR.ioctl, { args = { fd, lcs.ioc(dir, nr, size), 0 } })
                t:assert(r.errno ~= sys.E.NOTTY,
                    "REG_IOC_" .. name .. " is implemented on a key fd, not ENOTTY")
            end
        end
        -- The two transaction numbers are not key-fd ioctls.
        for _, e in ipairs({ { 16, lcs.IOC_DIR.NONE, 0, "COMMIT" },
                             { 17, lcs.IOC_DIR.R, 8, "TXN_STATUS" } }) do
            local r = w:syscall(sys.NR.ioctl, { args = { fd, lcs.ioc(e[2], e[1], e[3]), 0 } })
            t:assert_eq(r.errno, sys.E.NOTTY,
                "REG_IOC_" .. e[4] .. " is not a key-fd ioctl")
        end
        -- Eighteen and no more, and nothing under another type byte.
        local past = w:syscall(sys.NR.ioctl, { args = { fd, lcs.ioc(lcs.IOC_DIR.W, 18, 8), 0 } })
        t:assert_eq(past.errno, sys.E.NOTTY, "number 18 is not one of them")
        local other_type = (lcs.IOC_DIR.W << 30) | (8 << 16) | (0x53 << 8) | 0 -- type 'S'
        local foreign = w:syscall(sys.NR.ioctl, { args = { fd, other_type, 0 } })
        t:assert_eq(foreign.errno, sys.E.NOTTY, "and a type byte other than 'R' is not one either")
        sys.close(w, fd)
    end)

test("close() releases a key fd and a transaction fd through the ordinary fd lifecycle",
    { spec = "PKM *fd.close-releases-both-kinds" }, function(t)
        local fd = open_test(t)
        t:assert_eq(sys.close(w, fd).ret, 0, "a key fd closes")
        local after = lcs.query_key_info(nil, w, fd)
        t:assert_eq(after.errno, sys.E.BADF, "and is gone: EBADF")

        local txn = assert(lcs.begin_transaction(w))
        t:assert_eq(sys.close(w, txn).ret, 0, "a transaction fd closes")
        local st = lcs.txn_status(nil, w, txn)
        t:assert_eq(st.errno, sys.E.BADF, "and is gone: EBADF")
    end)

-- Key fds -------------------------------------------------------------

test("a key fd is an anonymous inode created with O_CLOEXEC",
    { spec = "PKM *fd.key-fd-is-an-anonymous-inode-with-cloexec" }, function(t)
        local fd = open_test(t)
        local pid = w:syscall(sys.NR.getpid).ret
        local link = sys.readlink(vm, "/proc/" .. pid .. "/fd/" .. fd)
        t:assert(link and link:match("^anon_inode:"),
            "the fd is an anonymous inode: " .. tostring(link))
        local F_GETFD, FD_CLOEXEC = 1, 1
        local flags = w:syscall(72, fd, F_GETFD, 0)
        t:assert(flags.ret >= 0, "F_GETFD: " .. sys.errname(flags.errno or 0))
        t:assert_eq(flags.ret & FD_CLOEXEC, FD_CLOEXEC, "and it is close-on-exec")
        sys.close(w, fd)
    end)

test("a key fd behaves like any other fd: poll reports its pending events",
    { spec = "PKM *fd.key-fds-are-ordinary-fds" }, function(t)
        local fd = scratch(t, "Pollable")
        local function poll_in()
            local p = w:syscall(sys.NR.poll, {
                args = { 0, 1, 0 }, bufs = { string.pack("<i4i2i2", fd, 1, 0) }, ptrs = { 0 },
            })
            local revents = select(3, string.unpack("<i4i2i2", p.out_bufs[1]))
            return p.ret, revents
        end
        local ret = poll_in()
        t:assert_eq(ret, 0, "an unarmed key fd polls with nothing ready")
        t:assert_eq(lcs.notify(nil, w, fd, lcs.NOTIFY.VALUE, false).ret, 0, "a watch arms")
        lcs.set_value(src, w, fd, "Poked", lcs.TYPE.DWORD, lcs.dword(1))
        local ret2, revents = poll_in()
        t:assert_eq(ret2, 1, "and after a write poll reports the fd ready")
        t:assert_eq(revents & 1, 1, "with POLLIN")
        sys.close(w, fd)
    end)

test("a transaction fd holds its id and, once bound, its source and hive",
    { spec = "PKM *fd.txn-fd-holds-id-source-and-hive" }, function(t)
        local txn = assert(lcs.begin_transaction(w))
        local st = lcs.txn_status(nil, w, txn)
        t:assert_eq(st.state, lcs.TXN.ACTIVE_UNBOUND,
            "a fresh transaction holds an id and nothing else")

        local machine = open_test(t)
        local bind = lcs.set_value(src, w, machine, "Bound", lcs.TYPE.DWORD,
            lcs.dword(1), { txn_fd = txn })
        t:assert_eq(bind.ret, 0, "a mutation binds it: " .. sys.errname(bind.errno or 0))
        st = lcs.txn_status(nil, w, txn)
        t:assert_eq(st.state, lcs.TXN.ACTIVE_BOUND, "the fd now names a source and a hive")

        local other = lcs.open_key(src, w, -1, "Second\\Room", lcs.KEY_ALL_ACCESS)
        t:assert(other.ret >= 0, "the second hive opens: " .. sys.errname(other.errno or 0))
        local cross = lcs.set_value(src, w, other.ret, "Nope", lcs.TYPE.DWORD,
            lcs.dword(1), { txn_fd = txn })
        t:assert_eq(cross.errno, sys.E.XDEV,
            "and an operation on another hive is EXDEV, which is the bound hive speaking")
        sys.close(w, other.ret)
        sys.close(w, machine)
        sys.close(w, txn)
    end)

-- Reserved fields and layout ------------------------------------------

test("every argument structure uses the natural C layout its encoded ioctl size names",
    { spec = "PKM *fd.structs-use-natural-c-layout" }, function(t)
        local fd = open_test(t)
        -- The size is part of the encoded number, so a structure of any
        -- other size is a different ioctl and does not exist.
        for _, e in ipairs(KEY_IOCTLS) do
            local nr, dir, size, name = e[1], e[2], e[3], e[4]
            local wrong = w:syscall(sys.NR.ioctl,
                { args = { fd, lcs.ioc(dir, nr, size + 8), 0 } })
            t:assert_eq(wrong.errno, sys.E.NOTTY,
                "REG_IOC_" .. name .. " at any size but " .. size .. " is not an ioctl LCS has")
        end
        -- And the documented offsets are the ones the kernel reads and
        -- writes: a query decoded at §5.A's offsets returns the value.
        local s = lcs.set_value(src, w, fd, "Natural", lcs.TYPE.QWORD, lcs.qword(7))
        t:assert_eq(s.ret, 0, "set: " .. sys.errname(s.errno or 0))
        local q = lcs.query_value(src, w, fd, "Natural")
        t:assert_eq(q.type, lcs.TYPE.QWORD, "type lands at offset 16")
        t:assert_eq(q.data_len, 8, "data_len at offset 20")
        t:assert(q.sequence > 0, "sequence at offset 40")
        sys.close(w, fd)
    end)

test("a non-zero reserved or padding field is EINVAL, before any source dispatch",
    { spec = "PKM *fd.non-zero-reserved-field-is-einval" }, function(t)
        local fd = open_test(t)
        local probes = {
            { "reg_create_key _pad0", function()
                return lcs.create_key(nil, w, { path = "Machine\\Software\\Test\\P", pad0 = 1 })
            end },
            { "reg_create_key _pad1", function()
                return lcs.create_key(nil, w, { path = "Machine\\Software\\Test\\P", pad1 = 1 })
            end },
            { "reg_set_value _pad0", function()
                return lcs.set_value(nil, w, fd, "V", lcs.TYPE.DWORD, lcs.dword(1), { pad0 = 1 })
            end },
            { "reg_set_value _pad1", function()
                return lcs.set_value(nil, w, fd, "V", lcs.TYPE.DWORD, lcs.dword(1), { pad1 = 1 })
            end },
            { "reg_set_value _pad2", function()
                return lcs.set_value(nil, w, fd, "V", lcs.TYPE.DWORD, lcs.dword(1), { pad2 = 1 })
            end },
            { "reg_query_value _pad0", function()
                return lcs.query_value(nil, w, fd, "V", { pad0 = 1 })
            end },
            { "reg_query_value _pad1", function()
                return lcs.query_value(nil, w, fd, "V", { pad1 = 1 })
            end },
            { "reg_delete_value _pad2", function()
                return lcs.delete_value(nil, w, fd, "V", { pad2 = 1 })
            end },
            { "reg_enum_value _pad", function()
                return lcs.enum_values(nil, w, fd, 0, { pad = 1 })
            end },
            { "reg_enum_subkey _pad", function()
                return lcs.enum_subkeys(nil, w, fd, 0, { pad = 1 })
            end },
            { "reg_query_key_info _pad0", function()
                return lcs.query_key_info(nil, w, fd, { pad0 = 1 })
            end },
            { "reg_query_key_info _pad1", function()
                return lcs.query_key_info(nil, w, fd, { pad1 = "\1\0\0\0\0\0" })
            end },
            { "reg_query_values_batch _pad", function()
                return lcs.query_values_batch(nil, w, fd, { pad = 1 })
            end },
            { "reg_notify _pad", function()
                return lcs.notify(nil, w, fd, lcs.NOTIFY.VALUE, false, { pad = "\1\0\0" })
            end },
        }
        for _, p in ipairs(probes) do
            local mark = src:mark()
            local r = p[2]()
            t:assert_eq(r.errno, sys.E.INVAL, p[1] .. " set to one is EINVAL")
            t:assert_eq(#src.log, mark - 1, p[1] .. " failed before the source was contacted")
        end
        sys.close(w, fd)
    end)

test("LCS zeroes every reserved and padding byte of an output structure",
    { spec = "PKM *fd.output-padding-is-zeroed" }, function(t)
        local fd = open_test(t)
        local info = lcs.query_key_info(src, w, fd)
        t:assert_eq(info.ret, 0, "query key info: " .. sys.errname(info.errno or 0))
        local a = info.out_bufs[1]
        t:assert_eq(a:sub(5, 8), "\0\0\0\0", "reg_query_key_info_args._pad0 comes back zeroed")
        t:assert_eq(a:sub(51, 56), string.rep("\0", 6),
            "reg_query_key_info_args._pad1[6] comes back zeroed")

        local q = lcs.query_value(src, w, fd, "Natural")
        local qa = q.out_bufs[1]
        t:assert_eq(qa:sub(5, 8), "\0\0\0\0", "reg_query_value_args._pad0 comes back zeroed")
        t:assert_eq(qa:sub(53, 56), "\0\0\0\0", "reg_query_value_args._pad1 comes back zeroed")

        local e = lcs.enum_subkeys(src, w, fd, 0)
        local ea = e.out_bufs[1]
        t:assert_eq(ea:sub(37, 40), "\0\0\0\0", "reg_enum_subkey_args._pad comes back zeroed")
        sys.close(w, fd)
    end)

test("an unknown or reserved flag bit is EINVAL",
    { spec = "PKM *fd.unknown-flag-bit-is-einval" }, function(t)
        local o = lcs.open_key(nil, w, -1, "Machine\\Software\\Test", lcs.KEY_ALL_ACCESS, 0x02)
        t:assert_eq(o.errno, sys.E.INVAL, "reg_open_key defines only REG_OPEN_LINK")
        local c = lcs.create_key(nil, w, { path = "Machine\\Software\\Test\\F", flags = 0x04 })
        t:assert_eq(c.errno, sys.E.INVAL,
            "reg_create_key defines only REG_OPTION_VOLATILE and REG_OPTION_CREATE_LINK")
        local fd = open_test(t)
        local n = lcs.notify(nil, w, fd, 0x08, false)
        t:assert_eq(n.errno, sys.E.INVAL, "REG_IOC_NOTIFY's filter defines only three bits")
        sys.close(w, fd)
    end)

-- Strings --------------------------------------------------------------

test("a string in an ioctl structure is a (len, ptr) pair and LCS reads exactly len bytes",
    { spec = "PKM *fd.string-is-a-len-ptr-pair" }, function(t)
        local fd = scratch(t, "Strings")
        -- name_len 5 against a ten-byte buffer: the name is "Alpha".
        local args = string.pack("<I4I4I8I4I4I8I4I4I8i4I4I8",
            5, 0, 0, lcs.TYPE.DWORD, 4, 0, 0, 0, 0, -1, 0, 0)
        local r = lcs.raw_call(src, w, {
            nr = sys.NR.ioctl, args = { fd, lcs.IOC.SET_VALUE, 0 }, ptr_slot = 2,
            struct = args,
            children = { { offset = 8, bytes = "AlphaBRAVO" }, { offset = 24, bytes = lcs.dword(9) } },
        })
        t:assert_eq(r.ret, 0, "a five-byte name out of a ten-byte buffer writes: " ..
            sys.errname(r.errno or 0))
        local q = lcs.query_value(src, w, fd, "Alpha")
        t:assert_eq(q.ret, 0, "and the value is at \"Alpha\", not \"AlphaBRAVO\": " ..
            sys.errname(q.errno or 0))
        t:assert_eq(q.data, lcs.dword(9), "with the data written")

        -- A terminator counted in the length is a null byte in a name.
        local nul = string.pack("<I4I4I8I4I4I8I4I4I8i4I4I8",
            6, 0, 0, lcs.TYPE.DWORD, 4, 0, 0, 0, 0, -1, 0, 0)
        local bad = lcs.raw_call(nil, w, {
            nr = sys.NR.ioctl, args = { fd, lcs.IOC.SET_VALUE, 0 }, ptr_slot = 2,
            struct = nul,
            children = { { offset = 8, bytes = "Alpha\0" }, { offset = 24, bytes = lcs.dword(9) } },
        })
        t:assert_eq(bad.errno, sys.E.INVAL,
            "a terminator inside the length is a null byte in the name and is invalid")
        sys.close(w, fd)
    end)

-- Variable-size output buffers -----------------------------------------

test("six ioctls return variable-size data, and a zero length probes for the size",
    { spec = "PKM *fd.six-ioctls-return-variable-size-data" }, function(t)
        local fd = scratch(t, "Probes")
        lcs.set_value(src, w, fd, "Sized", lcs.TYPE.BINARY, string.rep("z", 40))
        lcs.create_key(src, w, { parent_fd = fd, path = "Kid" })

        local probes = {
            { "REG_IOC_QUERY_VALUE", function()
                return lcs.query_value(src, w, fd, "Sized", { data_len = 0, layer_len = 0 })
            end },
            { "REG_IOC_QUERY_VALUES_BATCH", function()
                return lcs.query_values_batch(src, w, fd, { buf_len = 0 })
            end },
            { "REG_IOC_ENUM_VALUES", function()
                return lcs.enum_values(src, w, fd, 0, { name_len = 0, data_len = 0 })
            end },
            { "REG_IOC_ENUM_SUBKEYS", function()
                return lcs.enum_subkeys(src, w, fd, 0, { name_len = 0 })
            end },
            { "REG_IOC_QUERY_KEY_INFO", function()
                return lcs.query_key_info(src, w, fd, { name_len = 0 })
            end },
            { "REG_IOC_GET_SECURITY", function()
                return lcs.get_security(src, w, fd, lcs.SI.OWNER | lcs.SI.GROUP | lcs.SI.DACL,
                    { sd_len = 0 })
            end },
        }
        for _, p in ipairs(probes) do
            local r = p[2]()
            t:assert(r.errno ~= sys.E.FAULT,
                p[1] .. " does not dereference a null pointer behind a zero length")
        end
        -- And the sizes come back.
        local q = lcs.query_value(src, w, fd, "Sized", { data_len = 0, layer_len = 0 })
        t:assert_eq(q.data_len, 40, "the probe reports the data size")
        t:assert_eq(q.layer_len, #"base", "and the winning layer name's size")
        local g = lcs.get_security(src, w, fd, lcs.SI.OWNER | lcs.SI.GROUP | lcs.SI.DACL,
            { sd_len = 0 })
        t:assert(g.sd_len > 20, "and a descriptor probe reports its size")
        sys.close(w, fd)
    end)

test("a zero-length output buffer is a size probe whose pointer is never dereferenced",
    { spec = "PKM *fd.zero-length-is-a-size-probe" }, function(t)
        local fd = scratch(t, "ZeroProbe")
        lcs.set_value(src, w, fd, "Sized", lcs.TYPE.BINARY, string.rep("z", 40))
        -- data_len 0, and a pointer that is not null but is nowhere
        -- writable: the probe must not touch it.
        local args = string.pack("<I4I4I8I4I4i4I4I8I8I4I4I8",
            5, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0)
        local r = lcs.raw_call(src, w, {
            nr = sys.NR.ioctl, args = { fd, lcs.IOC.QUERY_VALUE, 0 }, ptr_slot = 2,
            struct = args, children = { { offset = 8, bytes = "Sized" } },
        })
        t:assert(r.errno ~= sys.E.FAULT, "a zero length ignores its pointer entirely")
        local out = r.args_out
        t:assert_eq(string.unpack("<I4", out, 21), 40, "and reports the required data size")
        sys.close(w, fd)
    end)

test("a non-zero output length needs a pointer writable for that many bytes",
    { spec = "PKM *fd.non-zero-length-needs-a-writable-pointer" }, function(t)
        local fd = scratch(t, "NeedsPtr")
        lcs.set_value(src, w, fd, "Sized", lcs.TYPE.BINARY, string.rep("z", 40))
        -- data_len 4096 with a null data_ptr.
        local args = string.pack("<I4I4I8I4I4i4I4I8I8I4I4I8",
            5, 0, 0, 0, 4096, -1, 0, 0, 0, 0, 0, 0)
        local r = lcs.raw_call(src, w, {
            nr = sys.NR.ioctl, args = { fd, lcs.IOC.QUERY_VALUE, 0 }, ptr_slot = 2,
            struct = args, children = { { offset = 8, bytes = "Sized" } },
        })
        t:assert_eq(r.errno, sys.E.FAULT,
            "a length greater than zero with a null pointer is EFAULT")
        sys.close(w, fd)
    end)

test("ERANGE writes every required size it can determine, not just the first",
    { spec = "PKM *fd.erange-writes-every-determinable-size" }, function(t)
        local fd = scratch(t, "Erange")
        lcs.set_value(src, w, fd, "Sized", lcs.TYPE.BINARY, string.rep("z", 40))
        local q = lcs.query_value(src, w, fd, "Sized", { data_len = 1, layer_len = 1 })
        t:assert_eq(q.errno, sys.E.RANGE, "two undersized buffers are ERANGE")
        t:assert_eq(q.data_len, 40, "the data size is reported")
        t:assert_eq(q.layer_len, #"base", "and so is the layer name size, from the same call")
        sys.close(w, fd)
    end)

test("on ERANGE the output buffers are not partially filled",
    { spec = "PKM *fd.erange-leaves-buffers-unfilled" }, function(t)
        local fd = scratch(t, "Unfilled")
        lcs.set_value(src, w, fd, "Sized", lcs.TYPE.BINARY, string.rep("z", 40))
        local sentinel = string.rep("\xA5", 16)
        local args = string.pack("<I4I4I8I4I4i4I4I8I8I4I4I8",
            5, 0, 0, 0, 16, -1, 16, 0, 0, 0, 0, 0)
        local r = lcs.raw_call(src, w, {
            nr = sys.NR.ioctl, args = { fd, lcs.IOC.QUERY_VALUE, 0 }, ptr_slot = 2,
            struct = args,
            children = { { offset = 8, bytes = "Sized" }, { offset = 32, bytes = sentinel },
                         { offset = 56, bytes = sentinel } },
        })
        t:assert_eq(r.errno, sys.E.RANGE, "sixteen bytes is too small for forty")
        t:assert_eq(r.child_out[2], sentinel, "the data buffer was left untouched")
        t:assert_eq(r.child_out[3], sentinel, "and so was the layer buffer")
        sys.close(w, fd)
    end)

test("output scalar metadata is meaningful only on success, and on ERANGE only the sizes",
    { spec = "PKM *fd.output-scalars-meaningful-only-on-success" }, function(t)
        local fd = scratch(t, "Scalars")
        lcs.set_value(src, w, fd, "Sized", lcs.TYPE.BINARY, string.rep("z", 40))
        local ok = lcs.query_value(src, w, fd, "Sized")
        t:assert_eq(ok.ret, 0, "on success every scalar is meaningful")
        t:assert_eq(ok.type, lcs.TYPE.BINARY, "the type is the value's")
        t:assert(ok.sequence > 0, "and the sequence is the winning entry's")

        -- ERANGE documents its required-size fields, and nothing else.
        local short = lcs.query_value(src, w, fd, "Sized", { data_len = 1 })
        t:assert_eq(short.errno, sys.E.RANGE, "an undersized buffer is ERANGE")
        t:assert_eq(short.data_len, 40, "and data_len carries the required size, as documented")
        sys.close(w, fd)
    end)

test("an invalid input pointer is EFAULT, validated before source dispatch",
    { spec = "PKM *fd.input-pointer-fault-is-efault" }, function(t)
        local fd = scratch(t, "InputFault")
        -- name_len 5 with a null name_ptr.
        local args = string.pack("<I4I4I8I4I4I8I4I4I8i4I4I8",
            5, 0, 0, lcs.TYPE.DWORD, 4, 0, 0, 0, 0, -1, 0, 0)
        local mark = src:mark()
        local r = lcs.raw_call(nil, w, {
            nr = sys.NR.ioctl, args = { fd, lcs.IOC.SET_VALUE, 0 }, ptr_slot = 2,
            struct = args, children = { { offset = 24, bytes = lcs.dword(1) } },
        })
        t:assert_eq(r.errno, sys.E.FAULT, "a null input pointer behind a length is EFAULT")
        t:assert_eq(#src.log, mark - 1, "and nothing was asked of the source")
        sys.close(w, fd)
    end)
