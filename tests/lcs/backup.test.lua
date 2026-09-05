-- §5.9.1 and §5.9.2: what REG_IOC_BACKUP writes, and the terms it
-- writes it on — the privilege, the read-only snapshot, the audit, and
-- the shape of the stream the exporter produces.
--
-- The stream itself is decoded rather than counted: helpers/lcs's
-- decoder splits it into records and verifies the trailer's count and
-- SHA-256, so the record-level claims can be asserted directly.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")
local kacs = require("helpers.kacs")
local kmes = require("helpers.kmes")
local token = require("helpers.token")
local access = require("helpers.access")

local vm = provium:vm("v", "kernel-only"):boot()
assert(kacs.new_mount(vm, "tmpfs", "/streams", kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL))

local ENOTSUP, ETIMEDOUT = 95, 110
local PATH = "Machine\\Software\\Test"
local REC = lcs.BACKUP_RECORD

-- One snapshot per source at a time, so the EBUSY case needs only one
-- backup held open; and a second of deadline, so a held request does
-- not stall the file for thirty.
local src = lcs.source(vm)
src:seed_param("MaxReadOnlyTransactionsPerSource", 1)
src:seed_param("RequestTimeoutMs", 1000)
local ROOT = src:key(PATH)
local CHILD = src:key(PATH .. "\\Child")
local GRANDCHILD = src:key(PATH .. "\\Child\\Grand")
local GUARDED = src:key(PATH .. "\\Guarded", { sd = lcs.sd({
    access.ace(access.ACE.ALLOWED, lcs.RIGHT.KEY_ALL_ACCESS, kacs.SID.LOCAL_SYSTEM, 0),
}) })
src:seed_layer("Policy", { precedence = 5, enabled = true, owner = kacs.SID.ADMINISTRATORS })
src:value(ROOT, "Base", lcs.TYPE.DWORD, lcs.dword(1))
src:value(ROOT, "Both", lcs.TYPE.DWORD, lcs.dword(1))
src:value(ROOT, "Both", lcs.TYPE.DWORD, lcs.dword(2), { layer = "Policy" })
src:value(CHILD, "Inner", lcs.TYPE.SZ, lcs.sz("inner"))
src:blanket(CHILD, "Policy")
-- A layer hiding a child that exists, and a layer hiding a name where
-- no key exists in any layer.
src:hide(ROOT, "Child", "Policy")
src:hide(ROOT, "NothingHere", "Policy")
assert(src:register())
src:pump()

local w = vm:spawn_worker()
local FD = assert(lcs.open_key(src, w, -1, PATH, lcs.KEY_ALL_ACCESS).ret)

local stream_seq = 0
local function stream_path()
    stream_seq = stream_seq + 1
    return "/streams/s" .. stream_seq
end

--- Back the file's root subtree up and decode the result.
local function backup_root(who, fd)
    return lcs.backup_to_file(src, who or w, fd or FD, stream_path())
end

--- A stream sink another principal owns outright. The tmpfs is
--- SYSTEM's, and a pipe needs no filesystem permission at all; these
--- subtrees are far below a pipe's capacity, so the write never blocks.
--- Returns the write fd and a reader for what went into it.
local function principal_sink(who)
    local rd, wr = sys.pipe(who)
    assert(rd and wr, "a pipe for the principal")
    return wr, function()
        sys.close(who, wr)
        local out = {}
        while true do
            local chunk = sys.read(who, rd, 65536)
            if not chunk or #chunk == 0 then break end
            out[#out + 1] = chunk
        end
        sys.close(who, rd)
        return table.concat(out)
    end
end

--- The index into `stream.keys` of the section a record belongs to.
local function section_of(stream, rec) return lcs.backup_section_of(stream, rec) end

-- What is written -----------------------------------------------------

test("REG_IOC_BACKUP exports the key on the fd and its entire subtree",
    { spec = { "PKM *backup.exports-the-key-and-its-subtree", "PKM *backup.stream.depth-first-pre-order" } }, function(t)
        local r, stream = backup_root()
        t:assert_eq(r.ret, 0, "backup: " .. sys.errname(r.errno or 0))
        local seen = {}
        for i, k in ipairs(stream.keys) do seen[k.guid] = i end
        for name, guid in pairs({ root = ROOT, child = CHILD,
                                  grandchild = GRANDCHILD, guarded = GUARDED }) do
            t:assert(seen[guid], "the " .. name .. " key is in the stream")
        end
        t:assert_eq(seen[ROOT], 1, "the backup root is the first KEY record")
        t:assert(seen[CHILD] < seen[GRANDCHILD],
            "and a parent always precedes its children: depth-first pre-order")
    end)

test("the header carries the magic, the format version and the minimum reader version, both 21",
    { spec = { "PKM *backup.stream.header-carries-version-and-minimum-reader", "PKM *backup.stream.current-version-is-21" } }, function(t)
        local r, stream = backup_root()
        t:assert_eq(r.ret, 0, "backup: " .. sys.errname(r.errno or 0))
        t:assert_eq(stream.records[1].type, REC.HEADER, "HEADER is the first record")
        t:assert_eq(stream.header.magic, lcs.BACKUP_MAGIC, "the PEIOSREG magic")
        t:assert_eq(stream.header.version, 21, "FormatVersion 21")
        t:assert_eq(stream.header.min_reader, 21, "MinReaderVersion 21")
        t:assert_eq(stream.header.root_guid, ROOT, "and the root GUID of the backup")
        t:assert_eq(stream.header.hive, "Machine", "and the hive it came from")
    end)

test("the trailer carries a record count and a SHA-256 over everything before it",
    { spec = "PKM *backup.stream.trailer-carries-count-and-sha256" }, function(t)
        local r, stream, bytes = backup_root()
        t:assert_eq(r.ret, 0, "backup: " .. sys.errname(r.errno or 0))
        t:assert_eq(stream.records[#stream.records].type, REC.TRAILER,
            "TRAILER is the last record")
        t:assert(stream.count_ok, "RecordCount matches the records in the stream (" ..
            stream.trailer.count .. " of " .. #stream.records .. ")")
        t:assert(stream.checksum_ok,
            "and the SHA-256 covers every byte through RecordCount")
        -- Which is what makes truncation and corruption detectable.
        local corrupt = lcs.decode_backup_stream(
            bytes:sub(1, 40) .. string.char(bytes:byte(41) ~ 0xFF) .. bytes:sub(42))
        t:assert(not corrupt.checksum_ok, "flipping one byte breaks the checksum")
    end)

test("every path entry, value and blanket tombstone carries its layer tag",
    { spec = "PKM *backup.stream.entries-carry-their-layer-tag" }, function(t)
        local r, stream = backup_root()
        t:assert_eq(r.ret, 0, "backup: " .. sys.errname(r.errno or 0))
        local layers = {}
        for _, v in ipairs(stream.values) do layers[v.layer] = true end
        for _, p in ipairs(stream.path_entries) do
            t:assert(p.layer and #p.layer > 0, "a path entry names its layer")
            layers[p.layer] = true
        end
        for _, b in ipairs(stream.blankets) do
            t:assert(b.layer and #b.layer > 0, "a blanket tombstone names its layer")
            layers[b.layer] = true
        end
        t:assert(layers["base"], "the base layer's entries are tagged base")
        t:assert(layers["Policy"], "and the Policy layer's are tagged Policy")

        -- The same value name appears once per layer, not flattened.
        local both = {}
        for _, v in ipairs(stream.values) do
            if v.name == "Both" then both[v.layer] = v end
        end
        t:assert(both["base"] and both["Policy"],
            "a value present in two layers is stored twice, once per layer")
        t:assert_eq(both["base"].data, lcs.dword(1), "with each layer's own data")
        t:assert_eq(both["Policy"].data, lcs.dword(2), "and the other's")
    end)

test("each key record carries its own descriptor, with no deduplication",
    { spec = "PKM *backup.stream.descriptors-inline-without-dedup" }, function(t)
        local r, stream = backup_root()
        t:assert_eq(r.ret, 0, "backup: " .. sys.errname(r.errno or 0))
        local identical = {}
        for _, k in ipairs(stream.keys) do
            t:assert(k.sd and #k.sd > 20, "every KEY record carries a full descriptor")
            identical[k.sd] = (identical[k.sd] or 0) + 1
        end
        local repeated = 0
        for _, n in pairs(identical) do if n > 1 then repeated = repeated + n end end
        t:assert(repeated >= 2,
            "keys sharing a descriptor each carry their own copy (" .. repeated ..
            " records share one), rather than referring to a single one")
    end)

test("the exporter writes no GUID-bearing path entries for the backup root",
    { spec = "PKM *backup.root-section-has-no-guid-path-entries" }, function(t)
        local r, stream = backup_root()
        t:assert_eq(r.ret, 0, "backup: " .. sys.errname(r.errno or 0))
        local root_entries = 0
        for _, p in ipairs(stream.path_entries) do
            if section_of(stream, p) == 1 then
                root_entries = root_entries + 1
                t:assert(p.hidden,
                    "the root's section contains only its hidden entries, not a " ..
                    "GUID-bearing one for " .. p.name)
            end
        end
        t:assert(root_entries > 0, "the root section does carry its hidden entries")
    end)

test("hidden entries belong to the parent's section, and one masking a name with no key is still valid",
    { spec = { "PKM *backup.hidden-entries-live-in-the-parent-section", "PKM *backup.hidden-entry-without-a-key-is-valid" } }, function(t)
        local r, stream = backup_root()
        t:assert_eq(r.ret, 0, "backup: " .. sys.errname(r.errno or 0))
        local by_name = {}
        for _, p in ipairs(stream.path_entries) do
            if p.hidden then by_name[p.name] = p end
        end
        local masking_a_key = by_name["Child"]
        t:assert(masking_a_key, "the hidden entry masking Child is written")
        t:assert_eq(masking_a_key.child, lcs.NULL_GUID, "with an all-zero child GUID")
        t:assert_eq(masking_a_key.parent, ROOT, "and its parent is the root")
        t:assert_eq(section_of(stream, masking_a_key), 1,
            "and it sits in the parent's section: a hidden entry has no key of its own")

        local masking_nothing = by_name["NothingHere"]
        t:assert(masking_nothing,
            "a hidden entry masking a name where no key exists in any layer is written too")
        t:assert_eq(masking_nothing.child, lcs.NULL_GUID, "also with an all-zero GUID")
        t:assert_eq(section_of(stream, masking_nothing), 1, "also in the parent's section")
    end)

test("the layer manifest is written from the live layer table",
    { spec = "PKM *backup.manifest-is-written-from-the-live-layer-table" }, function(t)
        local r, stream = backup_root()
        t:assert_eq(r.ret, 0, "backup: " .. sys.errname(r.errno or 0))
        local by_name = {}
        for _, l in ipairs(stream.layers) do by_name[l.name] = l end
        t:assert(by_name["base"], "base is in the manifest")
        local policy = by_name["Policy"]
        t:assert(policy, "and so is Policy, which the subtree's entries reference")
        t:assert_eq(policy.precedence, 5,
            "carrying the precedence the live layer table holds, not one from the entries")
        t:assert_eq(policy.enabled, 1, "and its enabled flag")
        t:assert_eq(policy.owner, kacs.SID.ADMINISTRATORS, "and its owner SID")
        -- Every LAYER record precedes all key data.
        local first_key
        for i, rec in ipairs(stream.records) do
            if rec.type == REC.KEY then first_key = i; break end
        end
        for i, rec in ipairs(stream.records) do
            if rec.type == REC.LAYER then
                t:assert(i < first_key, "and every LAYER record precedes the key data")
            end
        end
    end)

test("a layer definition is backed up only when its metadata subtree is inside the export",
    { spec = "PKM *backup.layer-definition-backed-up-only-if-inside-the-subtree" },
    function(t)
        -- Machine\System\Registry\Layers is not under Machine\Software,
        -- so the Policy layer's own definition is not in this stream:
        -- only the manifest entry naming it.
        local r, stream = backup_root()
        t:assert_eq(r.ret, 0, "backup: " .. sys.errname(r.errno or 0))
        local names = {}
        for _, v in ipairs(stream.values) do names[v.name] = true end
        t:assert(not names["Precedence"],
            "no Precedence value: the layer's definition is outside the subtree")

        -- Exporting from a root that does contain it picks it up as
        -- ordinary key and value data.
        local layers_fd = lcs.open_key(src, w, -1, lcs.LAYERS_PATH .. "\\Policy",
            lcs.KEY_ALL_ACCESS)
        t:assert(layers_fd.ret >= 0, "open the layer metadata key: " ..
            sys.errname(layers_fd.errno or 0))
        local r2, stream2 = lcs.backup_to_file(src, w, layers_fd.ret, stream_path())
        t:assert_eq(r2.ret, 0, "backup of the metadata subtree: " ..
            sys.errname(r2.errno or 0))
        local names2 = {}
        for _, v in ipairs(stream2.values) do names2[v.name] = v end
        t:assert(names2["Precedence"],
            "there it is ordinary key and value data like anything else")
        t:assert_eq(names2["Precedence"].data, lcs.dword(5), "with its value")
        sys.close(w, layers_fd.ret)
    end)

test("the stream is written to an arbitrary fd with no seeking, so a pipe is a valid output",
    { spec = "PKM *backup.stream.written-and-read-without-seeking" }, function(t)
        local rd, wr = sys.pipe(w)
        t:assert(rd and wr, "a pipe")
        local r = lcs.backup(src, w, FD, wr)
        t:assert_eq(r.ret, 0, "backup into the write end: " .. sys.errname(r.errno or 0))
        sys.close(w, wr)
        local out = {}
        while true do
            local chunk = sys.read(w, rd, 65536)
            if not chunk or #chunk == 0 then break end
            out[#out + 1] = chunk
        end
        sys.close(w, rd)
        local stream = lcs.decode_backup_stream(table.concat(out))
        t:assert(stream.count_ok and stream.checksum_ok,
            "and what comes out the other end is a complete, self-verifying stream")
        t:assert_eq(stream.header.root_guid, ROOT, "of the right subtree")
    end)

test("the stream is an LCS-level format: no source ever sees it",
    { spec = "PKM *backup.stream.lcs-level-sources-never-see-it" }, function(t)
        local mark = src:mark()
        local r = backup_root()
        t:assert_eq(r.ret, 0, "backup: " .. sys.errname(r.errno or 0))
        local during = {}
        for i = mark, #src.log do during[src.log[i].op] = true end
        t:assert(next(during), "the backup did talk to the source")
        local allowed = {
            [lcs.OP.BEGIN_TXN] = true, [lcs.OP.ABORT_TXN] = true,
            [lcs.OP.LOOKUP] = true, [lcs.OP.ENUM_CHILDREN] = true,
            [lcs.OP.READ_KEY] = true, [lcs.OP.QUERY_VALUES] = true,
        }
        for op in pairs(during) do
            t:assert(allowed[op],
                "only ordinary RSI reads crossed the wire, not stream records (saw " ..
                (lcs.OP_NAME[op] or tostring(op)) .. ")")
        end
    end)

-- The snapshot --------------------------------------------------------

test("backup opens a read-only source transaction and releases it with an abort, never a commit",
    { spec = { "PKM *backup.opens-a-read-only-snapshot-transaction", "PKM *backup.snapshot-released-with-abort-never-committed" } }, function(t)
        local mark = src:mark()
        local r = backup_root()
        t:assert_eq(r.ret, 0, "backup: " .. sys.errname(r.errno or 0))
        local begins = src:served(lcs.OP.BEGIN_TXN, mark)
        t:assert_eq(#begins, 1, "exactly one RSI_BEGIN_TRANSACTION")
        local txn_id, mode = string.unpack("<I8I4", begins[1].payload)
        t:assert_eq(mode, lcs.RSI_TXN_READ_ONLY, "with mode RSI_TXN_READ_ONLY")
        local aborts = src:served(lcs.OP.ABORT_TXN, mark)
        t:assert_eq(#aborts, 1, "and one RSI_ABORT_TRANSACTION")
        t:assert_eq(string.unpack("<I8", aborts[1].payload), txn_id, "for that transaction")
        t:assert_eq(#src:served(lcs.OP.COMMIT_TXN, mark), 0,
            "there is no commit call anywhere in the backup path")
    end)

test("a source that does not support read-only snapshots makes the backup ENOTSUP",
    { spec = "PKM *backup.unsupported-snapshot-is-enotsup" }, function(t)
        src.refuse_txn_mode = { [lcs.RSI_TXN_READ_ONLY] = true }
        local r = backup_root()
        src.refuse_txn_mode = nil
        t:assert_eq(r.errno, ENOTSUP,
            "RSI_TXN_NOT_SUPPORTED for a read-only snapshot: ENOTSUP")
        local ok = backup_root()
        t:assert_eq(ok.ret, 0, "and a source that does support one still works")
    end)

test("backing up an orphaned key is ENOENT",
    { spec = "PKM *backup.orphaned-key-is-enoent" }, function(t)
        local c = lcs.create_key(src, w, { parent_fd = FD, path = "Orphan",
            access = lcs.KEY_ALL_ACCESS })
        t:assert(c.ret >= 0, "create a key: " .. sys.errname(c.errno or 0))
        t:assert_eq(lcs.delete_key(src, w, c.ret).ret, 0, "delete its last name")
        local out = assert(lcs.stream_file(w, stream_path()))
        local r = lcs.backup(src, w, c.ret, out)
        t:assert_eq(r.errno, sys.E.NOENT,
            "an orphaned key is no longer a reachable subtree root: ENOENT")
        sys.close(w, out)
        sys.close(w, c.ret)
    end)

test("the output fd must be writable, or EBADF",
    { spec = "PKM *backup.output-fd-must-be-writable" }, function(t)
        local path = stream_path()
        local seed = assert(lcs.stream_file(w, path))
        sys.close(w, seed)
        local ro = assert(sys.open(w, path, sys.O.RDONLY))
        local r = lcs.backup(src, w, FD, ro)
        t:assert_eq(r.errno, sys.E.BADF, "a read-only output fd: EBADF")
        sys.close(w, ro)
    end)

-- Privilege and audit --------------------------------------------------

test("backup requires SeBackupPrivilege and performs no per-key AccessCheck",
    { spec = "PKM *backup.requires-sebackupprivilege-and-checks-no-key" }, function(t)
        local BACKUP = token.bit(token.PRIV.BACKUP)
        -- Machine\Software\Test\Guarded is readable only by SYSTEM. A
        -- principal holding SeBackupPrivilege exports it anyway; the
        -- privilege is the whole authorisation.
        token.as_principal(t, vm, { privs_present = BACKUP, privs_enabled = BACKUP },
            function(w2)
                local denied = src:run(function()
                    return lcs.open_key_async(w2, -1, PATH .. "\\Guarded",
                        lcs.RIGHT.KEY_READ)
                end)
                t:assert_eq(denied.errno, sys.E.ACCES,
                    "the principal cannot open the guarded key at all")

                local fd = src:run(function()
                    return lcs.open_key_async(w2, -1, PATH, lcs.RIGHT.KEY_READ)
                end)
                t:assert(fd.ret >= 0, "but may open the subtree root: " ..
                    sys.errname(fd.errno or 0))
                local out, drain = principal_sink(w2)
                local r = lcs.backup(src, w2, fd.ret, out)
                t:assert_eq(r.ret, 0, "and back the whole subtree up: " ..
                    sys.errname(r.errno or 0))
                local stream = lcs.decode_backup_stream(drain())
                local found = false
                for _, k in ipairs(stream.keys) do
                    if k.guid == GUARDED then found = true end
                end
                t:assert(found,
                    "including the key it could not read: no per-key AccessCheck at all")
                sys.close(w2, fd.ret)
            end)

        token.as_principal(t, vm, {}, function(w2)
            local fd = src:run(function()
                return lcs.open_key_async(w2, -1, PATH, lcs.RIGHT.KEY_READ)
            end)
            t:assert(fd.ret >= 0, "a principal without the privilege opens the root")
            local out = principal_sink(w2)
            local r = lcs.backup(src, w2, fd.ret, out)
            t:assert_eq(r.errno, sys.E.PERM, "but cannot back it up: EPERM")
            sys.close(w2, fd.ret)
        end)
    end)

test("LCS_BACKUP_START is emitted before any subtree data is read, and LCS_BACKUP_COMPLETE reports the result afterwards",
    { spec = { "PKM *backup.start-event-precedes-any-data-or-eio", "PKM *backup.complete-event-cannot-change-the-result" } }, function(t)
        -- Holding the backup's first subtree read stops it before a
        -- single byte of key data has come back, so what is in the ring
        -- at that point is what was emitted before any data was read.
        local w2 = vm:spawn_worker()
        local key = src:run(function()
            return lcs.open_key_async(w2, -1, PATH, lcs.KEY_ALL_ACCESS)
        end)
        t:assert(key.ret >= 0, "a key fd in the backing-up process")
        local out = assert(lcs.stream_file(w2, stream_path()))
        local held_one = false
        local function hold_first()
            if held_one then return nil end
            held_one = true
            return lcs.HOLD
        end
        local DATA_OPS = { lcs.OP.ENUM_CHILDREN, lcs.OP.QUERY_VALUES, lcs.OP.READ_KEY }
        for _, op in ipairs(DATA_OPS) do src:intercept(op, hold_first) end
        local mark = src:mark()
        local held_events = kmes.recording(t, vm, function()
            local pending = lcs.backup_async(w2, key.ret, out)
            for _ = 1, 60 do
                if #src:held_ids() >= 1 then break end
                src:pump(50)
            end
            t:assert_eq(#src:held_ids(), 1, "the first subtree read is held unanswered")
            for _, op in ipairs(DATA_OPS) do src:intercept(op, nil) end
            t:assert_eq(pending:await().errno, ETIMEDOUT, "so the backup times out")
        end)
        local answered = 0
        for _, op in ipairs(DATA_OPS) do
            answered = answered + #src:served(op, mark)
        end
        t:assert_eq(answered, 1,
            "exactly the one held request, so no subtree data was ever returned")
        local starts = kmes.of_type(held_events, "LCS_BACKUP_START")
        t:assert_eq(#starts, 1, "LCS_BACKUP_START was already emitted")
        t:assert_eq(starts[1].payload.key_guid, ROOT, "and it names the subtree root")
        for _, id in ipairs(src:held_ids()) do src:release(id) end
        src:pump(100)
        sys.close(w2, out); sys.close(w2, key.ret)
        w2:kill(); w2:join()

        -- LCS_BACKUP_COMPLETE reports a result that has already
        -- happened: it carries the errno rather than deciding it. (A
        -- failure to emit it is a KMES-side fault no guest can stage.)
        local ok_events = kmes.recording(t, vm, function()
            t:assert_eq(backup_root().ret, 0, "a successful backup")
        end)
        local done = kmes.of_type(ok_events, "LCS_BACKUP_COMPLETE")
        t:assert_eq(#done, 1, "emits one LCS_BACKUP_COMPLETE")
        t:assert_eq(done[1].payload.result_errno, 0, "carrying the result it had")

        -- A backup that fails *after* it started emits one too, and
        -- what it carries is the errno the operation already had.
        local failed_errno
        local fail_events = kmes.recording(t, vm, function()
            src:intercept(lcs.OP.QUERY_VALUES, function()
                return lcs.STATUS.STORAGE_ERROR, ""
            end)
            local r = backup_root()
            src:intercept(lcs.OP.QUERY_VALUES, nil)
            t:assert(r.ret < 0, "a backup whose subtree read fails")
            failed_errno = r.errno
        end)
        local failed = kmes.of_type(fail_events, "LCS_BACKUP_COMPLETE")
        t:assert_eq(#failed, 1, "emits one too")
        t:assert_eq(failed[1].payload.result_errno, failed_errno,
            "carrying the errno the operation had already produced")
    end)

-- Last: this case leans on MaxReadOnlyTransactionsPerSource being 1.

test("a source already holding MaxReadOnlyTransactionsPerSource snapshots yields EBUSY",
    { spec = "PKM *backup.snapshot-limit-is-ebusy" }, function(t)
        local holder = vm:spawn_worker()
        local key = src:run(function()
            return lcs.open_key_async(holder, -1, PATH, lcs.KEY_ALL_ACCESS)
        end)
        t:assert(key.ret >= 0, "a key fd in the holding process")
        local out = assert(lcs.stream_file(holder, stream_path()))
        -- Hold one backup inside its snapshot by holding the first read
        -- it makes after opening the transaction.
        src:intercept(lcs.OP.ENUM_CHILDREN, function() return lcs.HOLD end)
        local pending = lcs.backup_async(holder, key.ret, out)
        for _ = 1, 60 do
            if #src:held_ids() >= 1 then break end
            src:pump(50)
        end
        t:assert_eq(#src:held_ids(), 1, "one backup is inside its snapshot")

        local blocked = backup_root()
        t:assert_eq(blocked.errno, sys.E.BUSY,
            "a second snapshot is past the limit of one: EBUSY")

        src:intercept(lcs.OP.ENUM_CHILDREN, nil)
        for _, id in ipairs(src:held_ids()) do src:release(id) end
        src:pump(200)
        pending:await()
        sys.close(holder, out); sys.close(holder, key.ret)
        holder:kill(); holder:join()
        local after = backup_root()
        t:assert_eq(after.ret, 0,
            "and once the snapshot is released a backup works again: " ..
            sys.errname(after.errno or 0))
    end)
