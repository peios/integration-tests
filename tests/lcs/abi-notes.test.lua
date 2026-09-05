-- PKM §5.B — what the generated ABI tables cannot say for themselves:
-- which byte of a backup stream the magic is, and the kernel
-- configuration LCS is built by.
--
-- The appendix is prose about the ABI rather than the ABI itself, so
-- each case drives the behaviour the prose describes: the magic is
-- located in a real stream and a stream without it is refused, and each
-- build option is shown by the thing it makes possible. Two halves of
-- two sentences are properties of the kernel source tree rather than of
-- a booted kernel, and are documented skips.
--
-- The generated tables are in abi-tables, abi-structs and
-- abi-tracepoints.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")

local vm = provium:vm("v", "kernel-only"):boot()
local MACHINE_ROOT = lcs.guid()

--- A Machine source with a test key holding one value and one subkey,
--- closed however the case ends.
local function with_machine(seed, fn)
    local src = lcs.source(vm, { hives = {
        { name = "Machine", root = MACHINE_ROOT } } })
    local key = src:key("Machine\\Software\\Test")
    src:value(key, "Answer", lcs.TYPE.DWORD, lcs.dword(42))
    if seed then seed(src) end
    assert(src:register())
    src:pump()
    local w = vm:spawn_worker()
    local ok, err = pcall(fn, src, w)
    w:kill(); w:join()
    src:close()
    if not ok then error(err, 0) end
end

--- Take a backup of a hive root into a string.
local function backup_stream(t, src, w, root)
    local rd, wr = sys.pipe(w)
    local b = lcs.backup(src, w, root, wr)
    t:assert_eq(b.ret, 0, "a backup is taken: " .. sys.errname(b.errno or 0))
    sys.close(w, wr)
    local chunks = {}
    while true do
        local d = sys.read(w, rd, 65536)
        if not d or #d == 0 then break end
        chunks[#chunks + 1] = d
    end
    sys.close(w, rd)
    return table.concat(chunks)
end

test("REG_BACKUP_MAGIC is the eight-byte header magic, not part of the framing",
    { spec = "PKM *lcs-abi-notes.backup-magic-is-eight-byte-header" },
    function(t)
        with_machine(nil, function(src, w)
            local root = lcs.open_key(src, w, -1, "Machine",
                lcs.KEY_ALL_ACCESS).ret
            local stream = backup_stream(t, src, w, root)
            -- The framing is the record type code and length: two bytes
            -- and four. The magic is the first eight bytes of what
            -- follows, inside the HEADER record's payload.
            local rtype, rlen = string.unpack("<I2I4", stream, 1)
            t:assert_eq(rtype, lcs.BACKUP_RECORD.HEADER,
                "the stream opens with a REG_BACKUP_HEADER record code")
            t:assert(rlen >= 14,
                "whose length covers the framing and the magic")
            t:assert_eq(stream:sub(7, 14), "PEIOSREG",
                "and REG_BACKUP_MAGIC is the eight bytes after the framing")
            t:assert_eq(#"PEIOSREG", 8, "eight bytes exactly")

            -- A reader rejects a stream whose magic does not match, and
            -- the record type codes alone are not enough to make one.
            local function restore(bytes)
                local rd, wr = sys.pipe(w)
                sys.write(w, wr, bytes)
                sys.close(w, wr)
                local r = lcs.restore(src, w, root, rd)
                sys.close(w, rd)
                return r
            end
            t:assert_eq(restore(stream).ret, 0,
                "the stream restores as it stands")
            local broken = stream:sub(1, 6) .. "XEIOSREG" .. stream:sub(15)
            t:assert_eq(#broken, #stream,
                "the same stream with one byte of the magic changed")
            t:assert_eq(restore(broken).errno, sys.E.INVAL,
                "is refused: the magic is checked, and it is those eight bytes")
            sys.close(w, root)
        end)
    end)

test("CONFIG_SECURITY_PKM is a boolean: LCS is linked into vmlinux, not loaded",
    { spec = "PKM *lcs-abi-notes.built-in-by-config-security-pkm" }, function(t)
        -- This guest has loaded no module and has none to load: the
        -- registry was there from the first instant a syscall could be
        -- made, which is what a built-in option gives and a loadable
        -- one could not.
        t:assert_eq(vm:read_file("/proc/modules"), "",
            "no module is loaded in this guest")
        local dev = sys.stat(vm, lcs.DEVICE)
        t:assert(dev, "/dev/pkm_registry exists all the same")
        local w = vm:spawn_worker()
        local txn = lcs.begin_transaction(w)
        t:assert(txn, "and the LCS syscalls answer")
        if txn then sys.close(w, txn) end
        local open = lcs.open_key(nil, w, -1, "Unbacked\\Anything",
            lcs.RIGHT.KEY_READ)
        t:assert_eq(open.errno, sys.E.NOENT,
            "reg_open_key answers as LCS, routing a name no source backs, "
                .. "rather than as an unregistered syscall")
        w:kill(); w:join()
    end)

test("CONFIG_RUST=y: the resolution core, RSI codec, backup serialiser and log are Rust",
    { spec = "PKM *lcs-abi-notes.requires-config-rust" }, function(t)
        -- Each of the four is exercised, because each is the Rust half
        -- of a path a guest can drive: an answer from any of them is an
        -- answer from lcs_core.
        with_machine(nil, function(src, w)
            local key = lcs.open_key(src, w, -1, "Machine\\Software\\Test",
                lcs.KEY_ALL_ACCESS)
            t:assert(key.ret >= 0, "the resolution core walks a path: "
                .. sys.errname(key.errno or 0))
            local fd = key.ret
            local q = lcs.query_value(src, w, fd, "Answer")
            t:assert_eq(q.data, lcs.dword(42),
                "and resolves a value to its winning layer")
            t:assert_eq(q.layer, "base", "naming it")

            -- The RSI codec: LCS built the request frame and decoded the
            -- answer this source wrote.
            t:assert(#src:served(lcs.OP.QUERY_VALUES) > 0,
                "the RSI codec framed the request")
            local req = src:served(lcs.OP.QUERY_VALUES)[1]
            t:assert_eq(string.unpack("<I4", req.raw, 1), #req.raw,
                "with the length prefix the wire format asks for")

            -- The transaction log: mutations accumulate and commit
            -- together.
            local txn = assert(lcs.begin_transaction(w))
            lcs.set_value(src, w, fd, "One", lcs.TYPE.DWORD, lcs.dword(1),
                { txn_fd = txn })
            lcs.set_value(src, w, fd, "Two", lcs.TYPE.DWORD, lcs.dword(2),
                { txn_fd = txn })
            t:assert_eq(lcs.query_value(src, w, fd, "One").errno, sys.E.NOENT,
                "the transaction log holds two mutations back")
            t:assert_eq(lcs.commit(src, w, txn).ret, 0, "and commits them")
            t:assert_eq(lcs.query_value(src, w, fd, "One").ret, 0,
                "after which both are there")
            t:assert_eq(lcs.query_value(src, w, fd, "Two").ret, 0, "both of them")
            sys.close(w, txn)

            -- The backup serialiser.
            local root = lcs.open_key(src, w, -1, "Machine",
                lcs.KEY_ALL_ACCESS).ret
            local stream = backup_stream(t, src, w, root)
            t:assert(#stream > 0 and stream:sub(7, 14) == "PEIOSREG",
                "and the backup serialiser writes a stream")
            sys.close(w, root); sys.close(w, fd)
        end)
    end)

test("CONFIG_SECURITY_PKM_KUNIT compiles in the in-kernel test harness",
    { spec = "PKM *lcs-abi-notes.kunit-option-compiles-test-harness",
      covered_by = "kunit:pkm_lcs_kunit_misc",
      skip = "the option's whole effect is that the in-kernel suites exist to " ..
             "be run, and the conformance profile boots the production kernel, " ..
             "which compiles them out — a guest can no more see a suite that " ..
             "is not there than it can see one that is; every pkm_lcs_kunit_* " ..
             "suite running under the KUnit build (pkm_lcs_kunit_key, _open, " ..
             "_source, _transaction, _layer, _backup, _rsi, _misc, _symlink, " ..
             "_kmes) is the observation" },
    function(t) end)

test("the three syscall numbers are in the syscall table the patch writes",
    { spec = "PKM *lcs-abi-notes.syscall-numbers-added-by-patch" }, function(t)
        -- What the patch does to arch/x86/entry/syscalls/syscall_64.tbl
        -- is visible here as three numbers that dispatch and neighbours
        -- that do not.
        local w = vm:spawn_worker()
        local src = lcs.source(vm, { hives = {
            { name = "Machine", root = MACHINE_ROOT } } })
        src:key("Machine\\Software\\Test")
        assert(src:register())
        src:pump()
        local open = lcs.open_key(src, w, -1, "Machine\\Software\\Test",
            lcs.RIGHT.KEY_READ)
        t:assert(open.ret >= 0, "1100 dispatches to reg_open_key: "
            .. sys.errname(open.errno or 0))
        sys.close(w, open.ret)
        local made = lcs.create_key(src, w, { path = "Machine\\Software\\Patched" })
        t:assert(made.ret >= 0, "1101 to reg_create_key: "
            .. sys.errname(made.errno or 0))
        sys.close(w, made.ret)
        local txn = lcs.begin_transaction(w)
        t:assert(txn, "1102 to reg_begin_transaction")
        if txn then sys.close(w, txn) end
        for _, hole in ipairs({ 1098, 1099, 1103, 1104 }) do
            t:assert_eq(w:syscall(hole, 0, 0, 0, 0).errno, sys.E.NOSYS,
                hole .. " is not one of the three the patch adds")
        end
        w:kill(); w:join()
        src:close()
    end)

test("the patch writes the same three rows into the tools/perf copy of the table",
    { spec = "PKM *lcs-abi-notes.syscall-numbers-added-by-patch",
      covered_by = "unreachable",
      skip = "a booted kernel has one syscall table and cannot say how many " ..
             "files in the source tree declared it; that " ..
             "kernel/patches/arch/syscall-table-pkm.patch touches both " ..
             "arch/x86/entry/syscalls/syscall_64.tbl and the copy under " ..
             "tools/perf/ is a property of the patch, checked where the " ..
             "kernel is built, not where it runs" },
    function(t) end)

test("the three numbers are reachable from the x86-64 entry",
    { spec = "PKM *lcs-abi-notes.syscalls-registered-common" }, function(t)
        -- `common` is the ABI column: the row applies to the 64-bit
        -- entry and to x32. The 64-bit half is what this guest runs on,
        -- and all three answer through it — including the two that take
        -- pointers, which a row registered for the wrong ABI would
        -- mistranslate rather than simply refuse.
        local w = vm:spawn_worker()
        local src = lcs.source(vm, { hives = {
            { name = "Machine", root = MACHINE_ROOT } } })
        src:key("Machine\\Software\\Test")
        assert(src:register())
        src:pump()
        local open = lcs.open_key(src, w, -1, "Machine\\Software\\Test",
            lcs.RIGHT.KEY_READ)
        t:assert(open.ret >= 0,
            "1100 takes a 64-bit user pointer to its path and finds the key")
        sys.close(w, open.ret)
        local made = lcs.create_key(src, w,
            { path = "Machine\\Software\\Common" })
        t:assert(made.ret >= 0,
            "1101 takes a 64-bit pointer to its argument structure")
        t:assert_eq(made.disposition, lcs.CREATED_NEW,
            "and writes back through the pointer inside it")
        sys.close(w, made.ret)
        local txn = lcs.begin_transaction(w)
        t:assert(txn, "and 1102 answers with no arguments at all")
        if txn then sys.close(w, txn) end
        w:kill(); w:join()
        src:close()
    end)

test("and from the x32 ABI, which the same `common` row covers",
    { spec = "PKM *lcs-abi-notes.syscalls-registered-common",
      covered_by = "unreachable",
      skip = "no process in this guest can issue an x32 syscall: the " ..
             "conformance kernel is built without CONFIG_X86_X32_ABI, so the " ..
             "x32 half of every `common` row — LCS's three included — is " ..
             "unreachable here, and a number carrying __X32_SYSCALL_BIT is " ..
             "ENOSYS whatever row declared it" },
    function(t) end)
