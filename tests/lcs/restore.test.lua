-- §5.9.3 (and the reader half of §5.9.1): REG_IOC_RESTORE. A replace
-- rather than a merge, wrapped in one transaction, with the target key
-- object surviving, the stream's root GUID remapped onto it, sequence
-- numbers remapped above everything present, and a precedence gate in
-- front of the whole thing.
--
-- Streams are built here rather than round-tripped, so a case can get
-- exactly one record wrong; helpers/lcs computes the trailer's count
-- and SHA-256 so an edited stream still verifies.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")
local kacs = require("helpers.kacs")
local kmes = require("helpers.kmes")
local token = require("helpers.token")
local access = require("helpers.access")

local vm = provium:vm("v", "kernel-only"):boot()
assert(kacs.new_mount(vm, "tmpfs", "/streams", kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL))

local ENOTSUP, ETIMEDOUT, POLLIN = 95, 110, 0x1
local PATH = "Machine\\Software\\Test"
local U64_MAX = 0xFFFFFFFFFFFFFFFF

local src = lcs.source(vm)
src:seed_param("RequestTimeoutMs", 5000)
local ROOT = src:key(PATH)
src:key(lcs.LAYERS_PATH)
src:seed_layer("Policy", { precedence = 0, enabled = true })
assert(src:register())
src:pump()
local w = vm:spawn_worker()

local n = 0
local function stream_path() n = n + 1; return "/streams/r" .. n end

--- A fresh restore target under the test key, with `o.values` seeded
--- and `o.children` created. Returns the fd and its GUID.
local target_seq = 0
local function target(o)
    o = o or {}
    target_seq = target_seq + 1
    local name = "T" .. target_seq
    local r = lcs.create_key(src, w, { parent_fd = -1, path = PATH .. "\\" .. name,
        access = lcs.KEY_ALL_ACCESS })
    assert(r.ret >= 0, "create target: " .. sys.errname(r.errno or 0))
    for vname, data in pairs(o.values or {}) do
        assert(lcs.set_value(src, w, r.ret, vname, lcs.TYPE.DWORD, lcs.dword(data)).ret == 0)
    end
    for _, child in ipairs(o.children or {}) do
        local c = lcs.create_key(src, w, { parent_fd = r.ret, path = child,
            access = lcs.KEY_ALL_ACCESS })
        assert(c.ret >= 0, "create child")
        sys.close(w, c.ret)
    end
    local guid
    for g, k in pairs(src.store.keys) do
        if k.name == name then guid = g end
    end
    return r.ret, guid, name
end

--- Build a backup stream. `spec.root_*` describe the root section;
--- `spec.keys` is a list of `{ guid, name, parent, layer, seq, values,
--- entries, flags, sd, lwt }`, each producing a KEY record followed by
--- the anchoring path entry in its own section. `spec.trailer` reaches
--- `lcs.backup_stream` for the cases about a stream that fails its own
--- self-verification.
local function stream_of(spec)
    spec = spec or {}
    local root = spec.root or lcs.guid()
    local recs = { lcs.backup_header(root, spec.hive or "Machine", spec.header) }
    for _, l in ipairs(spec.layers or { { name = "base" } }) do
        -- A manifest owner must parse as a SID, so it is never empty.
        recs[#recs + 1] = lcs.backup_layer(l.name,
            { precedence = l.precedence, enabled = l.enabled,
              owner = l.owner or kacs.SID.LOCAL_SYSTEM })
    end
    recs[#recs + 1] = lcs.backup_key(root, spec.root_key or {})
    for _, p in ipairs(spec.root_entries or {}) do
        recs[#recs + 1] = lcs.backup_path_entry(p.parent or root, p.name, p.child,
            p.layer, p.seq)
    end
    for _, v in ipairs(spec.root_values or {}) do
        recs[#recs + 1] = lcs.backup_value(v.key or root, v.name, v.type or lcs.TYPE.DWORD,
            v.data or lcs.dword(1), v.layer, v.seq)
    end
    for _, b in ipairs(spec.root_blankets or {}) do
        recs[#recs + 1] = lcs.backup_blanket(b.key or root, b.layer, b.seq)
    end
    for _, k in ipairs(spec.keys or {}) do
        recs[#recs + 1] = lcs.backup_key(k.guid, k)
        if not k.no_anchor then
            recs[#recs + 1] = lcs.backup_path_entry(k.parent or root, k.name,
                k.anchor or k.guid, k.layer, k.seq)
        end
        for _, p in ipairs(k.entries or {}) do
            recs[#recs + 1] = lcs.backup_path_entry(p.parent or k.guid, p.name, p.child,
                p.layer, p.seq)
        end
        for _, v in ipairs(k.values or {}) do
            recs[#recs + 1] = lcs.backup_value(v.key or k.guid, v.name,
                v.type or lcs.TYPE.DWORD, v.data or lcs.dword(1), v.layer, v.seq)
        end
    end
    for _, extra in ipairs(spec.extra or {}) do recs[#recs + 1] = extra end
    return lcs.backup_stream(recs, spec.trailer), root
end

local function restore(fd, bytes) return lcs.restore_bytes(src, w, fd, stream_path(), bytes) end

--- Watch events queued on a key fd, without blocking on an empty queue.
local function events_on(who, fd)
    local p = who:syscall(sys.NR.poll, {
        args = { 0, 1, 100 }, bufs = { string.pack("<i4i2i2", fd, POLLIN, 0) }, ptrs = { 0 },
    })
    if p.ret <= 0 then return {} end
    if select(3, string.unpack("<i4i2i2", p.out_bufs[1])) & POLLIN == 0 then return {} end
    local e = lcs.read_events(nil, who, fd)
    return e.ret > 0 and e.events or {}
end

--- Every mutating RSI request served since `mark`.
local MUTATIONS = { lcs.OP.CREATE_ENTRY, lcs.OP.HIDE_ENTRY, lcs.OP.DELETE_ENTRY,
                    lcs.OP.CREATE_KEY, lcs.OP.WRITE_KEY, lcs.OP.DROP_KEY,
                    lcs.OP.SET_VALUE, lcs.OP.DELETE_VALUE, lcs.OP.BLANKET_TOMBSTONE }
local function mutations_since(mark)
    local out = {}
    for i = mark, #src.log do
        for _, op in ipairs(MUTATIONS) do
            if src.log[i].op == op then out[#out + 1] = src.log[i] end
        end
    end
    return out
end

-- Replace, not merge ---------------------------------------------------

test("restore replaces the target's contents and descendants rather than merging into them",
    { spec = "PKM *restore.replaces-rather-than-merges" }, function(t)
        local fd = target({ values = { Old = 1 }, children = { "Gone" } })
        local child = lcs.guid()
        local bytes = stream_of({ keys = {
            { guid = child, name = "Fresh", values = { { name = "New", data = lcs.dword(9) } } },
        } })
        local r = restore(fd, bytes)
        t:assert_eq(r.ret, 0, "restore: " .. sys.errname(r.errno or 0))
        t:assert_eq(lcs.query_value(src, w, fd, "Old").errno, sys.E.NOENT,
            "the target's own value is gone")
        local subs = {}
        for i = 0, 8 do
            local e = lcs.enum_subkeys(src, w, fd, i)
            if e.ret ~= 0 then break end
            subs[e.name] = true
        end
        t:assert(not subs["Gone"], "and so is the descendant it had")
        t:assert(subs["Fresh"], "the stream's descendant is there instead")
    end)

test("the whole restore is one read-write source transaction, and the teardown happens inside it",
    { spec = { "PKM *restore.wrapped-in-one-read-write-transaction", "PKM *restore.tears-down-the-target-inside-the-transaction" } }, function(t)
        local fd = target({ values = { Old = 1 }, children = { "Gone" } })
        local mark = src:mark()
        local r = restore(fd, stream_of({ keys = {
            { guid = lcs.guid(), name = "Fresh" } } }))
        t:assert_eq(r.ret, 0, "restore: " .. sys.errname(r.errno or 0))
        local begins = src:served(lcs.OP.BEGIN_TXN, mark)
        t:assert_eq(#begins, 1, "exactly one RSI_BEGIN_TRANSACTION")
        local txn_id, mode = string.unpack("<I8I4", begins[1].payload)
        t:assert_eq(mode, lcs.RSI_TXN_READ_WRITE, "with mode RSI_TXN_READ_WRITE")
        t:assert_eq(#src:served(lcs.OP.COMMIT_TXN, mark), 1, "and one commit")
        local teardown = 0
        for _, e in ipairs(mutations_since(mark)) do
            t:assert_eq(e.txn, txn_id, "every mutation carries that transaction id")
            if e.op == lcs.OP.DELETE_ENTRY or e.op == lcs.OP.DELETE_VALUE
                or e.op == lcs.OP.DROP_KEY then
                teardown = teardown + 1
            end
        end
        t:assert(teardown > 0, "and the teardown was dispatched inside it")
    end)

test("a source that cannot offer a read-write transaction cannot be a restore target",
    { spec = "PKM *restore.requires-read-write-transaction-support" }, function(t)
        local fd = target()
        src.refuse_txn_mode = { [lcs.RSI_TXN_READ_WRITE] = true }
        local r = restore(fd, stream_of())
        src.refuse_txn_mode = nil
        t:assert(r.ret < 0, "the restore fails: there is no partial-restore mode")
        t:assert_eq(r.errno, ENOTSUP, "ENOTSUP, as for a refused snapshot")
    end)

test("every failure path aborts the transaction, so a failed restore rolls back the teardown too",
    { spec = { "PKM *restore.failure-rolls-back-the-teardown", "PKM *restore.external-guid-collision-is-eexist-mid-restore" } }, function(t)
        -- A non-root GUID that already exists outside the subtree being
        -- replaced. LCS keeps no index of those, so the source rejects
        -- the create part-way through the replay.
        local outside = lcs.create_key(src, w, { parent_fd = -1,
            path = PATH .. "\\Outside", access = lcs.KEY_ALL_ACCESS })
        t:assert(outside.ret >= 0, "a key outside the subtree")
        local outside_guid
        for g, k in pairs(src.store.keys) do if k.name == "Outside" then outside_guid = g end end
        t:assert(outside_guid, "whose GUID we know")
        sys.close(w, outside.ret)

        local fd = target({ values = { Kept = 7 }, children = { "Survives" } })
        local mark = src:mark()
        local r = restore(fd, stream_of({ keys = {
            { guid = outside_guid, name = "Collides" } } }))
        t:assert_eq(r.errno, sys.E.EXIST,
            "the collision surfaces mid-restore as EEXIST")
        t:assert_eq(#src:served(lcs.OP.ABORT_TXN, mark), 1, "the transaction is aborted")
        t:assert_eq(#src:served(lcs.OP.COMMIT_TXN, mark), 0, "and never committed")
        local q = lcs.query_value(src, w, fd, "Kept")
        t:assert_eq(q.ret, 0, "so the target's value survived the rolled-back teardown")
        t:assert_eq(q.data, lcs.dword(7), "unchanged")
        local e = lcs.enum_subkeys(src, w, fd, 0)
        t:assert_eq(e.ret, 0, "and so did its descendant")
        t:assert_eq(e.name, "Survives", "by name")
    end)

-- The target key survives -----------------------------------------------

test("the stream's root GUID is remapped to the target, whose key object is not replaced",
    { spec = { "PKM *restore.root-guid-remapped-to-the-target", "PKM *restore.target-key-object-is-not-replaced", "PKM *restore.descendants-keep-their-backup-guids" } }, function(t)
        local fd, guid, name = target()
        local before = lcs.query_key_info(src, w, fd)
        t:assert_eq(before.ret, 0, "read the target's identity first")
        local before_parent = src.store.keys[guid].parent
        local stream_root, child = lcs.guid(), lcs.guid()
        local bytes = stream_of({ root = stream_root, keys = {
            { guid = child, name = "Kid", values = { { name = "V", data = lcs.dword(3) } } },
        }, root_values = { { name = "OnRoot", data = lcs.dword(4) } } })
        local mark = src:mark()
        t:assert_eq(restore(fd, bytes).ret, 0, "restore")

        -- Nothing was created for the stream's root GUID; its records
        -- landed on the target instead.
        for _, e in ipairs(src:served(lcs.OP.CREATE_KEY, mark)) do
            t:assert(e.payload:sub(1, 16) ~= stream_root,
                "the backup root GUID is never created as a new key")
        end
        local wrote_on_target = false
        for _, e in ipairs(src:served(lcs.OP.SET_VALUE, mark)) do
            if e.payload:sub(1, 16) == guid then wrote_on_target = true end
        end
        t:assert(wrote_on_target, "the root section's values were written to the target")
        t:assert_eq(src.store.keys[child] ~= nil, true,
            "and a descendant keeps its backup GUID verbatim")

        local after = lcs.query_key_info(src, w, fd)
        t:assert_eq(after.name, name, "the target keeps its own name")
        t:assert_eq(after.volatile, before.volatile, "its volatile flag")
        t:assert_eq(after.symlink, before.symlink, "and its symlink flag")
        t:assert_eq(src.store.keys[guid].parent, before_parent, "and its parent")
        t:assert_eq(lcs.query_value(src, w, fd, "OnRoot").data, lcs.dword(4),
            "while the root record's section landed on it")
    end)

test("the root record supplies the target's descriptor and last write time, written with RSI_WRITE_KEY inside the transaction",
    { spec = { "PKM *restore.root-record-supplies-descriptor-and-write-time", "PKM *restore.writes-root-mutable-fields-then-its-section" } }, function(t)
        local fd, guid = target()
        local sd = lcs.sd({
            access.ace(access.ACE.ALLOWED, lcs.RIGHT.KEY_ALL_ACCESS, kacs.SID.EVERYONE, 0),
            access.ace(access.ACE.ALLOWED, lcs.RIGHT.KEY_READ,
                kacs.SID.AUTHENTICATED_USERS, 0),
        })
        local mark = src:mark()
        local bytes = stream_of({ root_key = { sd = sd, lwt = 123456789 },
            root_values = { { name = "AfterTheKey", data = lcs.dword(5) } } })
        t:assert_eq(restore(fd, bytes).ret, 0, "restore")

        local writes = src:served(lcs.OP.WRITE_KEY, mark)
        local root_write
        for _, e in ipairs(writes) do
            if e.payload:sub(1, 16) == guid then root_write = root_write or e end
        end
        t:assert(root_write, "the root's mutable fields go through RSI_WRITE_KEY")
        t:assert(root_write.txn ~= 0, "inside the restore's transaction")
        t:assert_eq(src.store.keys[guid].sd, sd, "the descriptor comes from the stream")
        t:assert_eq(src.store.keys[guid].lwt, 123456789, "and so does the last write time")

        local first_root_value
        for _, e in ipairs(src:served(lcs.OP.SET_VALUE, mark)) do
            if e.payload:sub(1, 16) == guid then first_root_value = e; break end
        end
        t:assert(first_root_value, "and the root's section is replayed")
        t:assert(root_write.id < first_root_value.id,
            "after its mutable fields, not before")
    end)

test("the root record's immutable flags must match the target's",
    { spec = "PKM *restore.immutable-flag-mismatch-is-einval" }, function(t)
        local fd = target()
        local volatile = restore(fd, stream_of({
            root_key = { flags = lcs.KEY_FLAG_VOLATILE } }))
        t:assert_eq(volatile.errno, sys.E.INVAL,
            "a volatile root restored onto a non-volatile key: EINVAL")
        local symlink = restore(fd, stream_of({
            root_key = { flags = lcs.KEY_FLAG_SYMLINK } }))
        t:assert_eq(symlink.errno, sys.E.INVAL,
            "a symlink root restored onto a non-symlink key: EINVAL")
    end)

test("non-root keys are replayed in stream order",
    { spec = "PKM *restore.replays-non-root-keys-in-stream-order" }, function(t)
        local fd = target()
        local a, b, c = lcs.guid(), lcs.guid(), lcs.guid()
        local mark = src:mark()
        t:assert_eq(restore(fd, stream_of({ keys = {
            { guid = a, name = "A" }, { guid = b, name = "B" }, { guid = c, name = "C" },
        } })).ret, 0, "restore three keys")
        local order = {}
        for _, e in ipairs(src:served(lcs.OP.CREATE_KEY, mark)) do
            order[#order + 1] = e.payload:sub(1, 16)
        end
        t:assert_eq(#order, 3, "three creates")
        t:assert_eq(order[1], a, "A first")
        t:assert_eq(order[2], b, "then B")
        t:assert_eq(order[3], c, "then C, in the order the stream had them")
    end)

-- Validation before mutation ---------------------------------------------

test("the whole stream is validated first, so a checksum failure aborts before any source mutation",
    { spec = { "PKM *restore.validates-the-whole-stream-first", "PKM *backup.stream.trailer-carries-count-and-sha256" } }, function(t)
        local fd = target({ values = { Kept = 1 } })
        local mark = src:mark()
        local bad = restore(fd, stream_of({ keys = { { guid = lcs.guid(), name = "K" } },
            trailer = { checksum = string.rep("\0", 32) } }))
        t:assert(bad.ret < 0, "a stream whose checksum does not verify is refused")
        t:assert_eq(#mutations_since(mark), 0,
            "and nothing was torn down: not one mutation reached the source")

        local mark2 = src:mark()
        local miscounted = restore(fd, stream_of({ keys = { { guid = lcs.guid(), name = "K" } },
            trailer = { count = 99 } }))
        t:assert(miscounted.ret < 0, "nor does one whose record count does not match")
        t:assert_eq(#mutations_since(mark2), 0, "also with nothing torn down")
        t:assert_eq(lcs.query_value(src, w, fd, "Kept").ret, 0, "the target is untouched")
    end)

test("a stream whose minimum reader version is above the supported one is rejected outright",
    { spec = "PKM *backup.stream.rejects-minimum-above-supported-version" }, function(t)
        local fd = target({ values = { Kept = 1 } })
        local mark = src:mark()
        local r = restore(fd, stream_of({ header = { min_reader = 22, version = 22 } }))
        t:assert(r.ret < 0, "MinReaderVersion 22 is above the reader's 21")
        t:assert_eq(#mutations_since(mark), 0, "and it is refused before touching anything")
        t:assert_eq(lcs.query_value(src, w, fd, "Kept").ret, 0, "the target is untouched")
    end)

test("unknown record types are skipped, but still count toward the record count and the checksum",
    { spec = "PKM *backup.stream.unknown-records-skipped-but-counted" }, function(t)
        local fd = target()
        local child = lcs.guid()
        -- 0x7F is not a record type this version defines. It is inert:
        -- it neither begins a section nor satisfies anything.
        local bytes = stream_of({ keys = { { guid = child, name = "Kid" } },
            extra = { lcs.backup_record(0x7F, "ignored bytes") } })
        t:assert_eq(restore(fd, bytes).ret, 0,
            "a stream carrying one still restores, with the record skipped")
        -- The count includes it, and the checksum covered it: had it not,
        -- the stream would have been rejected above.
        local decoded = lcs.decode_backup_stream(bytes)
        t:assert(decoded.count_ok, "the trailer's RecordCount includes the skipped record")
        t:assert(decoded.checksum_ok, "and the checksum covered it in full")
    end)

test("trailing bytes inside a record of a known type are an error",
    { spec = "PKM *backup.stream.trailing-bytes-in-a-record-are-an-error" }, function(t)
        local fd = target({ values = { Kept = 1 } })
        -- A KEY record whose record_len accommodates a byte its payload
        -- does not define. The RSI would skip it in a request; a stream
        -- may not.
        local guid = lcs.guid()
        local fat = lcs.backup_key(guid, {}) .. ""
        local payload = fat:sub(7) .. "\0"
        local bytes = stream_of({ extra = {
            lcs.backup_record(lcs.BACKUP_RECORD.KEY, payload) } })
        local mark = src:mark()
        local r = restore(fd, bytes)
        t:assert(r.ret < 0, "the record is not consumed exactly, so the stream is invalid")
        t:assert_eq(#mutations_since(mark), 0, "and nothing was applied")
    end)

-- GUID rules --------------------------------------------------------------

test("a GUID appearing twice in one stream, or equal to the target root, is EINVAL",
    { spec = { "PKM *restore.duplicate-guid-in-the-stream-is-einval", "PKM *restore.non-root-guid-equal-to-the-root-is-einval" } }, function(t)
        local fd, guid = target()
        local twice = lcs.guid()
        local dup = restore(fd, stream_of({ keys = {
            { guid = twice, name = "A" }, { guid = twice, name = "B" } } }))
        t:assert_eq(dup.errno, sys.E.INVAL, "a non-root GUID twice in one stream: EINVAL")

        local as_target = restore(fd, stream_of({ keys = {
            { guid = guid, name = "SameAsTarget" } } }))
        t:assert_eq(as_target.errno, sys.E.INVAL,
            "a non-root GUID equal to the restore target's: EINVAL")
    end)

test("a path entry's parent must be the restore root or a key already processed in the stream",
    { spec = "PKM *restore.path-entry-parent-must-be-in-the-stream" }, function(t)
        local fd = target()
        -- A parent GUID that belongs to the existing namespace outside
        -- the subtree being replaced: exactly the injection this check
        -- exists to stop.
        local elsewhere = ROOT
        local child = lcs.guid()
        local mark = src:mark()
        local r = restore(fd, stream_of({ keys = {
            { guid = child, name = "Injected", parent = elsewhere } } }))
        t:assert(r.ret < 0, "a path entry naming a parent outside the stream is refused")
        t:assert_eq(#mutations_since(mark), 0, "and the check is made up front")
    end)

test("a GUID-bearing path entry in the root's section is skipped rather than treated as an error",
    { spec = "PKM *backup.reader-skips-root-path-entries", tags = { "known-bug" } },
    function(t)
        -- KERNEL BUG. §5.9.2 says a reader "tolerates and skips them if
        -- some other writer produces them", and PSPK §5.2 makes it a
        -- MUST. Observed: the restore fails EINVAL. A HIDDEN entry in
        -- the root section is accepted, so it is specifically the
        -- GUID-bearing one that is rejected rather than discarded —
        -- and it is rejected whether or not the stream also carries a
        -- KEY record for the GUID it names.
        local fd = target()
        local ghost = lcs.guid()
        local bytes = stream_of({
            root_entries = { { name = "WouldBeDiscarded", child = ghost } } })
        local mark = src:mark()
        t:assert_eq(restore(fd, bytes).ret, 0,
            "another writer's root path entry does not make the stream invalid")
        for _, e in ipairs(src:served(lcs.OP.CREATE_ENTRY, mark)) do
            local name = string.unpack("<s4", e.payload, 17)
            t:assert(name ~= "WouldBeDiscarded",
                "and it is not applied: the target's existing name is authoritative")
        end
    end)

-- The precedence gate ------------------------------------------------------

test("a manifest declaring a layer above precedence 0 aborts with EPERM without SeTcbPrivilege, before a byte reaches the source",
    { spec = "PKM *restore.precedence-gate-is-eperm-without-setcbprivilege" }, function(t)
        local RESTORE = token.bit(token.PRIV.RESTORE)
        local fd = target({ values = { Kept = 1 } })
        local bytes = stream_of({
            layers = { { name = "base" }, { name = "HighPolicy", precedence = 9 } },
            keys = { { guid = lcs.guid(), name = "K",
                       values = { { name = "V", layer = "HighPolicy" } } } } })

        token.as_principal(t, vm, { privs_present = RESTORE, privs_enabled = RESTORE },
            function(w2)
                local key = src:run(function()
                    return lcs.open_key_async(w2, -1, PATH .. "\\T" .. target_seq,
                        lcs.KEY_ALL_ACCESS)
                end)
                t:assert(key.ret >= 0, "the principal opens the target: " ..
                    sys.errname(key.errno or 0))
                local rd, wr = sys.pipe(w2)
                t:assert_eq(sys.write(w2, wr, bytes).ret, #bytes, "stage the stream in a pipe")
                sys.close(w2, wr)
                local mark = src:mark()
                local r = lcs.restore(src, w2, key.ret, rd)
                t:assert_eq(r.errno, sys.E.PERM,
                    "a Group Policy-tier layer cannot be smuggled past with " ..
                    "SeRestorePrivilege alone: EPERM")
                t:assert_eq(#mutations_since(mark), 0, "before a single byte reaches the source")
                sys.close(w2, rd); sys.close(w2, key.ret)
            end)

        -- The agent holds SeTcbPrivilege, so the same stream restores.
        t:assert_eq(restore(fd, bytes).ret, 0, "the gate lets SeTcbPrivilege through")
    end)

test("restore requires SeRestorePrivilege, performs no per-key AccessCheck, and so confers descriptor control",
    { spec = { "PKM *restore.requires-serestoreprivilege-and-checks-no-key", "PKM *source.model.restore-implies-descriptor-control" } }, function(t)
        local RESTORE = token.bit(token.PRIV.RESTORE)
        local fd, guid, name = target()
        -- A descriptor the principal has no WRITE_DAC to set, arriving
        -- through the stream's root record instead.
        local rewritten = lcs.sd({
            access.ace(access.ACE.ALLOWED, lcs.RIGHT.KEY_ALL_ACCESS, kacs.SID.EVERYONE, 0),
        })
        local bytes = stream_of({ root_key = { sd = rewritten } })

        token.as_principal(t, vm, {}, function(w2)
            local key = src:run(function()
                return lcs.open_key_async(w2, -1, PATH .. "\\" .. name, lcs.RIGHT.KEY_READ)
            end)
            t:assert(key.ret >= 0, "an unprivileged principal opens the target for reading")
            local rd, wr = sys.pipe(w2)
            sys.write(w2, wr, bytes); sys.close(w2, wr)
            local r = lcs.restore(src, w2, key.ret, rd)
            t:assert_eq(r.errno, sys.E.PERM, "but cannot restore onto it: EPERM")
            sys.close(w2, rd); sys.close(w2, key.ret)
        end)

        token.as_principal(t, vm, { privs_present = RESTORE, privs_enabled = RESTORE },
            function(w2)
                local key = src:run(function()
                    return lcs.open_key_async(w2, -1, PATH .. "\\" .. name, lcs.RIGHT.KEY_READ)
                end)
                t:assert(key.ret >= 0, "with SeRestorePrivilege it opens for reading only")
                local rd, wr = sys.pipe(w2)
                sys.write(w2, wr, bytes); sys.close(w2, wr)
                local r = lcs.restore(src, w2, key.ret, rd)
                t:assert_eq(r.ret, 0, "and the restore succeeds: " ..
                    sys.errname(r.errno or 0))
                sys.close(w2, rd); sys.close(w2, key.ret)
            end)
        t:assert_eq(src.store.keys[guid].sd, rewritten,
            "the descriptor was rewritten by a caller holding no WRITE_DAC over the key: " ..
            "SeRestorePrivilege effectively confers WRITE_DAC and WRITE_OWNER")
    end)

-- Layers in a restored stream ------------------------------------------------

test("manifest records define nothing, and entries in an unknown layer are latent until real metadata exists",
    { spec = { "PKM *restore.manifest-records-change-no-layers", "PKM *restore.unknown-layer-entries-become-latent" } }, function(t)
        local fd = target()
        local child = lcs.guid()
        local bytes = stream_of({
            layers = { { name = "base" }, { name = "Ghost" } },
            root_values = { { name = "Ghosted", layer = "Ghost", data = lcs.dword(11) },
                            { name = "Ghosted", layer = "base", data = lcs.dword(1) } },
            keys = { { guid = child, name = "K" } } })
        t:assert_eq(restore(fd, bytes).ret, 0, "restore a stream naming a layer nothing defines")

        -- The manifest created, enabled and authorised nothing: no
        -- metadata key appeared for it.
        local ghost = lcs.open_key(src, w, -1, lcs.LAYERS_PATH .. "\\Ghost",
            lcs.RIGHT.KEY_READ)
        t:assert_eq(ghost.errno, sys.E.NOENT, "no layer definition was created")

        local q = lcs.query_value(src, w, fd, "Ghosted")
        t:assert_eq(q.ret, 0, "the value resolves: " .. sys.errname(q.errno or 0))
        t:assert_eq(q.layer, "base",
            "from base — the unknown layer's entry is latent and ignored in resolution")
        t:assert_eq(q.data, lcs.dword(1), "with base's data")
    end)

test("a metadata subtree included in the stream is what defines the layer",
    { spec = "PKM *restore.included-metadata-subtree-defines-the-layer" }, function(t)
        -- Restoring onto Machine\System\Registry\Layers brings the
        -- layer's definition in as ordinary key and value data, and
        -- that — not the manifest — is what makes the layer real.
        local layers_fd = lcs.open_key(src, w, -1, lcs.LAYERS_PATH, lcs.KEY_ALL_ACCESS)
        t:assert(layers_fd.ret >= 0, "open the layers key: " ..
            sys.errname(layers_fd.errno or 0))
        local defined = lcs.guid()
        local bytes = stream_of({ keys = {
            { guid = defined, name = "Defined", values = {
                { name = "Precedence", data = lcs.dword(0) },
                { name = "Enabled", data = lcs.dword(1) },
            } },
        } })
        t:assert_eq(restore(layers_fd.ret, bytes).ret, 0, "restore the metadata subtree")
        local key = lcs.open_key(src, w, -1, lcs.LAYERS_PATH .. "\\Defined",
            lcs.RIGHT.KEY_READ)
        t:assert(key.ret >= 0, "the layer's metadata key exists as ordinary registry data")
        t:assert_eq(lcs.query_value(src, w, key.ret, "Enabled").data, lcs.dword(1),
            "with the values the stream carried")
        sys.close(w, key.ret)
        sys.close(w, layers_fd.ret)
    end)

-- Sequence remapping ------------------------------------------------------------

test("backup sequence numbers are remapped to offset plus the backup sequence, not written through",
    { spec = { "PKM *restore.sequences-are-remapped-not-written-through", "PKM *restore.remapped-sequence-is-offset-plus-backup" } }, function(t)
        local fd, guid = target({ values = { Anchor = 1 } })
        local before = lcs.query_value(src, w, fd, "Anchor")
        t:assert_eq(before.ret, 0, "a value written before the restore")
        local mark = src:mark()
        local bytes = stream_of({ root_values = {
            { name = "Low", data = lcs.dword(1), seq = 3 },
            { name = "High", data = lcs.dword(2), seq = 7 },
        } })
        t:assert_eq(restore(fd, bytes).ret, 0, "restore")

        local seqs = {}
        for _, e in ipairs(src:served(lcs.OP.SET_VALUE, mark)) do
            local at = 17
            local name; name, at = string.unpack("<s4", e.payload, at)
            local _; _, at = string.unpack("<s4", e.payload, at)
            at = at + 4
            _, at = string.unpack("<s4", e.payload, at)
            seqs[name] = string.unpack("<I8", e.payload, at)
        end
        t:assert(seqs.Low and seqs.High, "both values were written")
        t:assert(seqs.Low ~= 3 and seqs.High ~= 7,
            "the backup's own numbers were not written through")
        t:assert_eq(seqs.High - seqs.Low, 4,
            "the offset preserves the backup's internal ordering")
        t:assert(seqs.Low > before.sequence,
            "and places the whole set above what was already present (" ..
            seqs.Low .. " > " .. before.sequence .. ")")
    end)

test("a remapped sequence that would overflow fails EOVERFLOW at validation, before the teardown",
    { spec = "PKM *restore.sequence-remap-overflow-is-eoverflow" }, function(t)
        local fd = target({ values = { Kept = 1 } })
        local mark = src:mark()
        local r = restore(fd, stream_of({ root_values = {
            { name = "TooBig", data = lcs.dword(1), seq = U64_MAX - 1 } } }))
        t:assert_eq(r.errno, sys.E.OVERFLOW, "EOVERFLOW")
        t:assert_eq(#mutations_since(mark), 0, "and it fails before anything is torn down")
        t:assert_eq(lcs.query_value(src, w, fd, "Kept").ret, 0, "the target is untouched")
    end)

test("the global counter is advanced past the numbers a failed restore dispatched, and not rolled back",
    { spec = "PKM *restore.counter-advanced-at-any-terminal-state" }, function(t)
        local fd = target({ values = { Anchor = 1 } })
        local mark = src:mark()
        -- A restore that gets as far as dispatching layer-qualified
        -- records and then fails: the source refuses the last create.
        local doomed = lcs.guid()
        src:intercept(lcs.OP.CREATE_KEY, function() return lcs.STATUS.ALREADY_EXISTS, "" end)
        local r = restore(fd, stream_of({
            root_values = { { name = "Dispatched", data = lcs.dword(1), seq = 5 } },
            keys = { { guid = doomed, name = "NeverMade" } } }))
        src:intercept(lcs.OP.CREATE_KEY, nil)
        t:assert(r.ret < 0, "the restore fails")
        local highest = 0
        for _, e in ipairs(src:served(lcs.OP.SET_VALUE, mark)) do
            local at = 17
            local _; _, at = string.unpack("<s4", e.payload, at)
            _, at = string.unpack("<s4", e.payload, at)
            at = at + 4
            _, at = string.unpack("<s4", e.payload, at)
            local s = string.unpack("<I8", e.payload, at)
            if s > highest then highest = s end
        end
        t:assert(highest > 0, "but it did dispatch a layer-qualified record")
        t:assert_eq(lcs.set_value(src, w, fd, "Next", lcs.TYPE.DWORD, lcs.dword(1)).ret, 0,
            "a later write succeeds")
        local after = lcs.query_value(src, w, fd, "Next")
        t:assert(after.sequence > highest,
            "and gets a number above the highest the failed restore dispatched (" ..
            after.sequence .. " > " .. highest .. "): the advance is not rolled back")
    end)

test("the sequence gate is taken before the first layer-qualified record and blocks other mutations but not reads",
    { spec = { "PKM *restore.takes-the-sequence-gate-before-the-first-record", "PKM *restore.gate-blocks-mutations-not-reads" } }, function(t)
        local fd = target({ values = { Anchor = 1 } })
        local other = vm:spawn_worker()
        local other_fd = src:run(function()
            return lcs.open_key_async(other, -1, PATH, lcs.KEY_ALL_ACCESS)
        end)
        t:assert(other_fd.ret >= 0, "another caller with a key fd of its own")

        -- Hold the restore at the dispatch of its first layer-qualified
        -- record, which is where the gate is already held.
        local held_one = false
        src:intercept(lcs.OP.SET_VALUE, function()
            if held_one then return nil end
            held_one = true
            return lcs.HOLD
        end)
        local staged = assert(lcs.stream_file(w, stream_path()))
        local bytes = stream_of({ root_values = { { name = "Gated", data = lcs.dword(1) } } })
        t:assert_eq(sys.write(w, staged, bytes).ret, #bytes, "stage the stream")
        sys.lseek(w, staged, 0, 0)
        local pending = lcs.restore_async(w, fd, staged)
        for _ = 1, 60 do
            if #src:held_ids() >= 1 then break end
            src:pump(50)
        end
        t:assert_eq(#src:held_ids(), 1, "the restore is inside the gate")

        -- A read goes straight through.
        local read = lcs.query_value(src, other, other_fd.ret, "Anchor")
        t:assert(read.ret == 0 or read.errno == sys.E.NOENT,
            "reads are not blocked by the gate: " .. sys.errname(read.errno or 0))

        -- A sequence-allocating mutation does not: it waits for the
        -- gate, so its request never even reaches the source while the
        -- restore holds it.
        local mark = src:mark()
        local blocked = lcs.set_value_async(other, other_fd.ret, "Blocked",
            lcs.TYPE.DWORD, lcs.dword(1))
        for _ = 1, 6 do src:pump(50) end
        t:assert_eq(#src:served(lcs.OP.SET_VALUE, mark), 0,
            "the waiting mutation has not been dispatched at all")

        for _, id in ipairs(src:held_ids()) do src:release(id) end
        src:pump(200)
        local done = pending:await()
        t:assert_eq(done.ret, 0, "the restore completes: " .. sys.errname(done.errno or 0))
        src:pump(200)
        local after = blocked:await()
        t:assert_eq(after.ret, 0, "and the waiting mutation then goes through: " ..
            sys.errname(after.errno or 0))
        t:assert(#src:served(lcs.OP.SET_VALUE, mark) >= 1,
            "reaching the source only once the gate was released")
        src:intercept(lcs.OP.SET_VALUE, nil)
        sys.close(w, staged); sys.close(other, other_fd.ret)
        other:kill(); other:join()
    end)

test("a restore with no layer-qualified records never takes the sequence gate",
    { spec = "PKM *restore.no-layer-records-never-takes-the-gate" }, function(t)
        local fd = target()
        local other = vm:spawn_worker()
        local other_fd = src:run(function()
            return lcs.open_key_async(other, -1, PATH, lcs.KEY_ALL_ACCESS)
        end)
        t:assert(other_fd.ret >= 0, "another caller with a key fd of its own")

        -- A stream of nothing but the root record: no path entries, no
        -- values, no blankets, so nothing is layer-qualified.
        local held_one = false
        src:intercept(lcs.OP.WRITE_KEY, function()
            if held_one then return nil end
            held_one = true
            return lcs.HOLD
        end)
        local staged = assert(lcs.stream_file(w, stream_path()))
        local bytes = stream_of({ root_key = { lwt = 42 } })
        t:assert_eq(sys.write(w, staged, bytes).ret, #bytes, "stage the stream")
        sys.lseek(w, staged, 0, 0)
        local pending = lcs.restore_async(w, fd, staged)
        for _ = 1, 60 do
            if #src:held_ids() >= 1 then break end
            src:pump(50)
        end
        t:assert_eq(#src:held_ids(), 1, "the restore is held mid-flight")

        local mark = src:mark()
        local write = lcs.set_value(src, other, other_fd.ret, "NotBlocked",
            lcs.TYPE.DWORD, lcs.dword(1))
        t:assert_eq(write.ret, 0,
            "and another sequence-allocating mutation goes straight through: " ..
            sys.errname(write.errno or 0))
        t:assert(#src:served(lcs.OP.SET_VALUE, mark) >= 1,
            "reaching the source while the restore is still in flight")

        for _, id in ipairs(src:held_ids()) do src:release(id) end
        src:pump(200)
        local done = pending:await()
        t:assert_eq(done.ret, 0, "the restore completes: " .. sys.errname(done.errno or 0))
        src:intercept(lcs.OP.WRITE_KEY, nil)
        sys.close(w, staged); sys.close(other, other_fd.ret)
        other:kill(); other:join()
    end)

-- Streamability, watches, and the fd -----------------------------------------------

test("the stream is read once, sequentially, so a pipe is a valid input",
    { spec = "PKM *restore.stream-read-once-sequentially" }, function(t)
        local fd = target()
        local bytes = stream_of({ keys = { { guid = lcs.guid(), name = "FromAPipe",
            values = { { name = "V", data = lcs.dword(8) } } } } })
        local rd, wr = sys.pipe(w)
        t:assert_eq(sys.write(w, wr, bytes).ret, #bytes, "write the stream into a pipe")
        sys.close(w, wr)
        local r = lcs.restore(src, w, fd, rd)
        t:assert_eq(r.ret, 0, "restore from the read end: " .. sys.errname(r.errno or 0))
        sys.close(w, rd)
        local e = lcs.enum_subkeys(src, w, fd, 0)
        t:assert_eq(e.name, "FromAPipe", "and the subtree came through")
    end)

test("the input fd must be readable, or EBADF, and an orphaned target is ENOENT",
    { spec = { "PKM *restore.input-fd-must-be-readable", "PKM *restore.orphaned-target-is-enoent" } }, function(t)
        local fd = target()
        local path = stream_path()
        local seed = assert(lcs.stream_file(w, path))
        sys.write(w, seed, stream_of())
        sys.close(w, seed)
        local wo = assert(sys.open(w, path, sys.O.WRONLY))
        t:assert_eq(lcs.restore(src, w, fd, wo).errno, sys.E.BADF,
            "a write-only input fd: EBADF")
        sys.close(w, wo)

        local orphan = lcs.create_key(src, w, { parent_fd = fd, path = "Orphan",
            access = lcs.KEY_ALL_ACCESS })
        t:assert(orphan.ret >= 0, "a key to orphan")
        t:assert_eq(lcs.delete_key(src, w, orphan.ret).ret, 0, "delete its last name")
        local rd = assert(sys.open(w, path, sys.O.RDONLY))
        t:assert_eq(lcs.restore(src, w, orphan.ret, rd).errno, sys.E.NOENT,
            "restoring onto an orphaned key: ENOENT")
        sys.close(w, rd); sys.close(w, orphan.ret)
    end)

test("a successful restore publishes the generation increment and a no-name OVERFLOW; a failed one emits nothing",
    { spec = { "PKM *restore.commit-publishes-generation-and-overflow", "PKM *restore.failed-restore-emits-nothing" } }, function(t)
        local fd = target({ values = { Kept = 1 } })
        t:assert_eq(lcs.notify(nil, w, fd, lcs.NOTIFY.ALL, false).ret, 0, "arm a watch")
        local before = lcs.query_key_info(src, w, fd).hive_generation

        -- A restore that fails validation publishes nothing at all.
        local failed = restore(fd, stream_of({ trailer = { count = 3 } }))
        t:assert(failed.ret < 0, "a failing restore")
        t:assert_eq(#events_on(w, fd), 0, "emits nothing")
        t:assert_eq(lcs.query_key_info(src, w, fd).hive_generation, before,
            "and does not move the generation")

        t:assert_eq(restore(fd, stream_of({ keys = {
            { guid = lcs.guid(), name = "Committed" } } })).ret, 0, "a successful one")
        local evs = events_on(w, fd)
        t:assert(#evs >= 1, "publishes a watch event")
        local overflow
        for _, e in ipairs(evs) do
            if e.type == lcs.WATCH.OVERFLOW then overflow = e end
        end
        t:assert(overflow, "an OVERFLOW, since no exact before-and-after diff is retained")
        t:assert_eq(overflow.name, "", "with no name")
        t:assert(lcs.query_key_info(src, w, fd).hive_generation > before,
            "and the hive's generation increment is published")
    end)
