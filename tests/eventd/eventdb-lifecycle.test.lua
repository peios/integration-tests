-- eventd TRM §3.3 "Database Lifecycle" (3--event-storage/3--database-lifecycle.md):
-- the event store directory and its protection, shard naming, creation and
-- opening, quarantine, historical shards, query-path discovery, and the
-- connection model.
--
-- Two VMs, one vCPU each (so StorageShards 0 means one shard):
--
--   * `vm` keeps a working eventd throughout. Its cases read the store and
--     the daemon's descriptor table (/proc/<pid>/fd and fdinfo flags tell a
--     read-write connection from a read-only one), change StorageShards
--     and restart, and plant files in the store between a stop and a
--     start. The renamed-directory case puts the directory back.
--   * `bad` is where eventd is made to fail. Each failing case stops it,
--     breaks one thing, starts it, sees it not come up, then stops it
--     again, resets its restart budget (`svctl reset`: eventd is
--     ErrorControl=Critical, and an exhausted budget reboots the machine),
--     repairs the damage and starts it cleanly. The quarantine and
--     bad-historical cases end with eventd running.
--
-- Databases are edited between a stop and a start by copying them to the
-- host and back (`rewrite`); a stopped eventd has removed its WAL, so the
-- main file is the whole database.
--
-- Not reachable from a guest: `PRAGMA synchronous` is a property of a
-- connection, not of the file, so what eventd sets is gone with its
-- connection; and the `.N` quarantine suffix needs two quarantines in one
-- nanosecond. Those are unit-test stubs.

local eventd = require("helpers.eventd")
local peinit = require("helpers.peinit")
local kmes = require("helpers.kmes")
local kacs = require("helpers.kacs")
local access = require("helpers.access")
local token = require("helpers.token")
peinit.claim(2) -- vm and bad, both for the whole file

local vm = eventd.boot({ name = "ev-db" })
-- eventd is ErrorControl=Critical with RestartMaxRetries 5: the sixth
-- consecutive failed start reboots the machine, and this VM fails a dozen
-- on purpose. Its service definition is seeded Normal with a deep budget
-- so that a failing start is only ever a failed start.
local bad = eventd.boot({
    name = "ev-db-bad",
    config = {},
    config_keys = {
        { path = [[Machine\System\Services]] },
        { path = [[Machine\System\Services\eventd]], values = {
            { name = "ErrorControl", type = "dword", data = 0 },
            { name = "RestartMaxRetries", type = "dword", data = 1000 },
        } },
    },
})

local STORE = eventd.STORE.events
local SHARD0 = STORE .. "/shard-0000.db"
-- eventd's service SID (S-1-5-80-1963885778-1835409261-1671587836-
-- 2279113866-1994761124), which its required store descriptor includes.
local SERVICE_SID_BIN = token.sid(5, 80, 1963885778, 1835409261, 1671587836, 2279113866, 1994761124)

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

local function host_tmpdir()
    local p = assert(io.popen("mktemp -d", "r"))
    local dir = p:read("l")
    p:close()
    return dir
end

local function host_write(path, bytes)
    local f = assert(io.open(path, "wb"))
    f:write(bytes)
    f:close()
end

--- Copy guest database `src` to the host, run `script` there, and write
--- the result to guest `dst` (default `src`). eventd must be stopped.
local function rewrite(v, src, script, dst)
    local dir = host_tmpdir()
    host_write(dir .. "/db", v:read_file(src))
    host_write(dir .. "/q.sql", script)
    host_write(dir .. "/run.py", [[
import sqlite3, sys
d = sys.argv[1]
c = sqlite3.connect(d + "/db")
c.executescript(open(d + "/q.sql").read())
c.commit()
c.close()
]])
    local p = assert(io.popen("python3 " .. dir .. "/run.py " .. dir .. " 2>&1", "r"))
    local out = p:read("a")
    local ok = p:close()
    local f = assert(io.open(dir .. "/db", "rb"))
    local bytes = f:read("a")
    f:close()
    os.execute("rm -rf '" .. dir .. "'")
    assert(ok, "host sqlite rewrite failed: " .. out)
    v:write_file(dst or src, bytes)
end

local function stop(v)
    v:run("svctl stop eventd"):assert_ok()
    wait_until(function() return eventd.pid(v) == nil end,
        { timeout = 30, interval = 0.25, desc = "eventd to stop" })
end

local function start(v)
    v:run("svctl start eventd")
    eventd.ready(v)
end

--- Start eventd expecting it to fail; returns the state it reached.
--- Leaves it stopped with its restart budget reset.
local function start_fails(v)
    v:run("svctl start eventd")
    local state
    pcall(wait_until, function()
        state = eventd.status(v).state
        return state ~= "starting" and state ~= "activating"
    end, { timeout = 30, interval = 0.25, desc = "eventd's start to resolve" })
    local answered = eventd.query(v, "EVENTS TAKE 1").ok
    v:run("svctl stop eventd")
    v:run("svctl reset eventd")
    return state, answered
end

local function guest_now(v)
    return math.tointeger(tonumber(v:run("date +%s%N").stdout:match("%d+")))
end

local function exists(v, path)
    return v:run("test -e '" .. path .. "'").exit_code == 0
end

local function listing(v, dir)
    local out = {}
    for _, e in ipairs(v:listdir(dir)) do out[#out + 1] = type(e) == "table" and e.name or e end
    table.sort(out)
    return out
end

local function has(list, x)
    for _, y in ipairs(list) do if y == x then return true end end
    return false
end

--- eventd's descriptors on `file`: list of {fd, flags} (flags octal text).
local function fds_on(v, file)
    local pid = eventd.pid(v)
    local out = {}
    local r = v:run("for f in /proc/" .. pid .. "/fd/*; do t=$(readlink $f); " ..
        "if [ \"$t\" = '" .. file .. "' ]; then echo ${f##*/} $(grep '^flags' /proc/" .. pid ..
        "/fdinfo/${f##*/} | awk '{print $2}') $(stat -L -c %i $f); fi; done")
    for fd, flags, ino in r.stdout:gmatch("(%d+) (%d+) (%d+)") do
        out[#out + 1] = { fd = tonumber(fd), flags = tonumber(flags, 8), ino = ino }
    end
    return out
end

local O_ACCMODE, O_RDONLY, O_RDWR = 3, 0, 2

local function rw_count(list)
    local n = 0
    for _, e in ipairs(list) do if e.flags & O_ACCMODE == O_RDWR then n = n + 1 end end
    return n
end

--- A DACL as a list of "flags:mask:sid" strings, and the descriptor's
--- control word and owner/group.
local function descriptor(v, path)
    local bytes, err = kacs.get_sd(v, path, kacs.SI.OWNER | kacs.SI.GROUP | kacs.SI.DACL)
    assert(bytes, "read the descriptor of " .. path .. ": errno " .. tostring(err))
    local sd = access.parse_sd(bytes)
    local aces = {}
    for _, a in ipairs(sd.dacl and sd.dacl.aces or {}) do
        aces[#aces + 1] = { type = a.type, flags = a.flags, mask = a.mask, sid = token.sid_string(a.sid) }
    end
    return { control = sd.control, owner = sd.owner and token.sid_string(sd.owner),
             group = sd.group and token.sid_string(sd.group), aces = aces }
end

local function emit_stored(v, event_type, tag)
    local r = eventd.emit(v, event_type, { tag = tag })
    assert(r.ret == 0, "kmes_emit: errno " .. tostring(r.errno))
    return eventd.wait_rows(v, "EVENTS " .. event_type .. ' WHERE tag == "' .. tag .. '" SINCE 10m ago',
        function(rs) return #rs == 1 end)[1]
end

--- A shard copy emptied of rows, with one event of `ty` tagged `tag`.
local function planted_shard(v, ty, tag)
    local payload = eventd.msgpack({ tag = tag }):gsub(".", function(c) return string.format("%02X", c:byte()) end)
    return "DELETE FROM events; DELETE FROM event_types; DELETE FROM receipt_ranges; " ..
        "INSERT INTO events (boot_id, timestamp, cpu_id, sequence, origin_class, event_type, " ..
        "effective_token_guid, true_token_guid, process_guid, payload) VALUES (zeroblob(16), " ..
        guest_now(v) .. ", 0, 1, 0, '" .. ty .. "', zeroblob(16), zeroblob(16), zeroblob(16), X'" .. payload .. "'); " ..
        "INSERT INTO event_types VALUES ('" .. ty .. "');"
end

local function found(v, ty, tag)
    return #eventd.rows(v, "EVENTS " .. ty .. ' WHERE tag == "' .. tag .. '" SINCE 1h ago')
end

-- ---------------------------------------------------------------------------
-- The directory, on vm
-- ---------------------------------------------------------------------------

test("the shards and the metadata database live in the EventStorePath directory, and nowhere else", {
    spec = "eventd *eventdb.shards-and-the-metadata-database-live-in-the-eventstorepath-directory",
}, function(t)
    local configured = vm:run("reg get '" .. eventd.KEY .. "' EventStorePath").stdout:gsub("%s+$", "")
    t:assert(configured ~= "", "EventStorePath is set")
    local dir = configured:gsub("/$", "")
    local files = listing(vm, dir)
    t:assert(has(files, "shard-0000.db"), "the shard is there: " .. table.concat(files, " "))
    t:assert(has(files, "eventd-meta.db"), "and the metadata database")
    local strays = vm:run("find /var /run /tmp /etc /root /home \\( -name 'shard-*.db' -o -name 'eventd-meta.db' \\) " ..
        "2>/dev/null | grep -v '^" .. dir .. "/'").stdout
    t:assert_eq(strays, "", "no event database anywhere else")
end)

test("the standard event store path is /var/state/eventd/events/", {
    spec = "eventd *eventdb.the-standard-event-store-path-is-var-state-eventd-events",
}, function(t)
    local configured = vm:run("reg get '" .. eventd.KEY .. "' EventStorePath").stdout:gsub("%s+$", "")
    t:assert_eq(configured, "/var/state/eventd/events/", "the image's eventd-config.reg sets the standard path")
    t:assert(exists(vm, "/var/state/eventd/events/shard-0000.db"), "and eventd uses it")
end)

test("the package ships the state directory and three store directories; the three are required provisioned paths", {
    spec = "eventd *eventdb.the-package-ships-the-state-directory-and-its-three-store-directories"
        .. " eventd *eventdb.the-three-store-directories-are-required-peinit-provisioned-directories",
}, function(t)
    local base = [[Machine\System\Init\ProvisionedPaths]]
    local required = {}
    for name in vm:run("reg ls '" .. base .. "' --keys-only").stdout:gmatch("[^\n]+") do
        name = name:gsub("^%s+", ""):gsub("%s+$", ""):gsub("^.*\\", "")
        local vals = vm:run("reg get '" .. base .. "\\" .. name .. "'").stdout
        local path = vals:match('Path = REG_SZ "(.-)"')
        local req = vals:match("Required = REG_DWORD (%d+)")
        local kind = vals:match('Kind = REG_SZ "(.-)"')
        if path then required[path:gsub("/$", "")] = (req == "1" and kind == "directory") end
    end
    t:assert(vm:run("test -d /var/state/eventd").exit_code == 0, "/var/state/eventd exists")
    t:assert(required["/var/state/eventd"] == nil,
        "/var/state/eventd is not a provisioned directory: " .. json.encode(required))
    for _, d in ipairs({ "/var/state/eventd/events", "/var/state/eventd/logs", "/var/state/eventd/metrics" }) do
        t:assert(vm:run("test -d " .. d).exit_code == 0, d .. " exists")
        t:assert(required[d], d .. " is a required provisioned directory: " .. json.encode(required))
    end
end)

test("each store directory is protected, inheritable, full control to SYSTEM, Administrators and eventd's service SID only", {
    spec = "eventd *eventdb.store-directories-grant-full-control-only-to-system-administrators-and-eventds-service-sid",
}, function(t)
    for _, d in ipairs({ "/var/state/eventd", "/var/state/eventd/events", "/var/state/eventd/logs",
                         "/var/state/eventd/metrics" }) do
        local sd = descriptor(vm, d)
        t:assert_eq(sd.owner, "S-1-5-18", d .. ": owner SYSTEM")
        t:assert_eq(sd.group, "S-1-5-18", d .. ": group SYSTEM")
        t:assert(sd.control & access.CONTROL.DACL_PROTECTED ~= 0, d .. ": the DACL is protected")
        local sids = {}
        for _, a in ipairs(sd.aces) do
            t:assert_eq(a.type, access.ACE.ALLOWED, d .. ": allow ACEs only")
            t:assert(a.flags & 3 == 3, d .. ": each is object- and container-inherit")
            sids[#sids + 1] = a.sid
        end
        t:assert_eq(table.concat(sids, " "),
            "S-1-5-18 S-1-5-32-544 S-1-5-80-1963885778-1835409261-1671587836-2279113866-1994761124",
            d .. ": exactly SYSTEM, Administrators, then eventd's service SID")
        for _, a in ipairs(sd.aces) do
            t:assert_eq(a.mask, 0x10000000, d .. ": each grants GENERIC_ALL (" .. a.sid .. ")")
        end
    end
end)

test("the database, WAL and shared-memory files take their protection from the directory", {
    spec = "eventd *eventdb.database-wal-and-shm-files-inherit-the-directory-protection",
}, function(t)
    local dir = descriptor(vm, STORE)
    local inheritable = {}
    for _, a in ipairs(dir.aces) do
        if a.flags & access.ACE_FLAG.OBJECT_INHERIT ~= 0 then inheritable[#inheritable + 1] = a.sid end
    end
    for _, f in ipairs({ SHARD0, SHARD0 .. "-wal", SHARD0 .. "-shm" }) do
        t:assert(exists(vm, f), f .. " exists")
        local sd = descriptor(vm, f)
        local sids = {}
        for _, a in ipairs(sd.aces) do
            t:assert(a.flags & access.ACE_FLAG.INHERITED ~= 0, f .. ": every ACE is inherited (" .. a.sid .. ")")
            sids[#sids + 1] = a.sid
        end
        t:assert_eq(table.concat(sids, " "), table.concat(inheritable, " "),
            f .. ": the directory's inheritable ACEs, and only those")
    end
end)

test("files are opened relative to the retained directory descriptor, not by path", {
    spec = "eventd *eventdb.store-files-are-handled-relative-to-a-directory-descriptor-opened-without-following-symlinks",
}, function(t)
    -- Every query opens its shards afresh. With the directory renamed and
    -- an empty decoy in its place, a query still reads the real shards:
    -- they are reached through the descriptor eventd opened at startup.
    local tag = eventd.marker("anch")
    emit_stored(vm, "pt.db.anchor", tag)
    vm:run("mv " .. STORE .. " " .. STORE .. ".moved && mkdir " .. STORE):assert_ok()
    local n = found(vm, "pt.db.anchor", tag)
    local decoy = listing(vm, STORE)
    vm:run("rmdir " .. STORE .. " && mv " .. STORE .. ".moved " .. STORE):assert_ok()
    t:assert_eq(#decoy, 0, "nothing was created in the decoy")
    t:assert_eq(n, 1, "the query found the event through the moved directory")
end)

-- ---------------------------------------------------------------------------
-- Naming, creation, historical shards and discovery, on vm
-- ---------------------------------------------------------------------------

local FEWER = { tag = eventd.marker("few") }

test("starting with more shards creates them, named by a four-digit shard index", {
    spec = "eventd *eventdb.starting-with-more-shards-than-exist-creates-the-new-ones"
        .. " eventd *eventdb.active-shards-are-named-by-a-four-digit-zero-padded-shard-index",
}, function(t)
    t:assert(not exists(vm, STORE .. "/shard-0001.db"), "one shard to begin with")
    eventd.set(vm, "StorageShards", "dword:2"):assert_ok()
    eventd.restart(vm)
    local files = listing(vm, STORE)
    t:assert(has(files, "shard-0000.db") and has(files, "shard-0001.db"),
        "shard-0000.db and shard-0001.db: " .. table.concat(files, " "))
    for _, f in ipairs(files) do
        if f:match("^shard") and not f:match("%-wal$") and not f:match("%-shm$") then
            t:assert(f:match("^shard%-%d%d%d%d%.db$"), "four-digit index: " .. f)
        end
    end
end)

test("a new shard is created in WAL mode with the four tables, the timestamp index and its metadata", {
    spec = "eventd *eventdb.a-new-shard-is-created-in-wal-mode"
        .. " eventd *eventdb.a-new-shard-is-created-with-all-four-tables"
        .. " eventd *eventdb.a-new-shard-is-created-with-the-timestamp-index"
        .. " eventd *eventdb.a-new-shard-is-created-with-schema-version-and-created-at-entries",
}, function(t)
    local db = STORE .. "/shard-0001.db"
    t:assert_eq(eventd.sql(vm, db, "PRAGMA journal_mode")[1][1], "wal", "the file is in WAL mode")
    local schema = eventd.schema(vm, db)
    for _, tbl in ipairs({ "events", "event_types", "receipt_ranges", "metadata" }) do
        t:assert(schema[tbl], "table " .. tbl .. " exists")
    end
    t:assert(schema.idx_events_timestamp, "idx_events_timestamp exists")
    local meta = {}
    for _, r in ipairs(eventd.sql(vm, db, "SELECT key, value FROM metadata")) do meta[r[1]] = r[2] end
    t:assert_eq(meta.schema_version, "1", "schema_version is the current version")
    t:assert(meta.created_at and meta.created_at:match("^%d%d%d%d%-%d%d%-%d%dT%d%d:%d%d:%d%dZ$"),
        "created_at is a UTC timestamp: " .. tostring(meta.created_at))
end)

-- Route closed: synchronous is a per-connection setting that is not
-- stored in the database file, and eventd's connection is not reachable
-- from outside the process.
test("a new shard's connection runs with synchronous=FULL", {
    spec = "eventd *eventdb.a-new-shard-is-created-with-synchronous-full",
    skip = true,
    covered_by = "cargo:eventd eventd-core shard::tests::a_new_shard_is_created_with_synchronous_full",
}, function() end)

-- Route closed: as above, for an existing shard.
test("an active shard's connection is opened with synchronous=FULL", {
    spec = "eventd *eventdb.an-active-shard-is-opened-with-synchronous-full",
    skip = true,
    covered_by = "cargo:eventd eventd-core shard::tests::an_active_shard_is_opened_with_synchronous_full",
}, function() end)

test("each shard has one read-write connection, its writer's, held for the life of the process", {
    spec = "eventd *eventdb.each-shard-has-exactly-one-read-write-connection-owned-by-its-writer"
        .. " eventd *eventdb.writer-threads-never-share-connections"
        .. " eventd *eventdb.a-writer-creates-and-owns-its-connection-for-the-process-lifetime",
}, function(t)
    -- Two active shards (the case above). A read-write connection is an
    -- O_RDWR descriptor on the database file.
    local before = {}
    for i, s in ipairs({ SHARD0, STORE .. "/shard-0001.db" }) do
        local fds = fds_on(vm, s)
        t:assert_eq(rw_count(fds), 1, s .. ": exactly one read-write descriptor: " .. json.encode(fds))
        for _, e in ipairs(fds) do if e.flags & O_ACCMODE == O_RDWR then before[i] = e end end
    end
    t:assert_neq(before[1].fd, before[2].fd, "two shards, two connections")
    -- Work, then look again: the same descriptors, still the only ones.
    local entries = {}
    for i = 1, 200 do entries[i] = { type = "pt.db.work", payload = eventd.msgpack({ i = i }) } end
    kmes.emit_batch(vm, entries)
    eventd.rows(vm, "EVENTS pt.db.work SINCE 10m ago TAKE 5")
    for i, s in ipairs({ SHARD0, STORE .. "/shard-0001.db" }) do
        local fds = fds_on(vm, s)
        t:assert_eq(rw_count(fds), 1, s .. ": still one read-write descriptor")
        for _, e in ipairs(fds) do
            if e.flags & O_ACCMODE == O_RDWR then
                t:assert_eq(e.fd, before[i].fd, s .. ": the same descriptor as before")
                t:assert_eq(e.ino, before[i].ino, s .. ": on the same file")
            end
        end
    end
end)

test("starting with fewer shards leaves the excess as historical shards, kept and still queried", {
    spec = "eventd *eventdb.starting-with-fewer-shards-keeps-the-excess-as-queryable-historical-shards",
}, function(t)
    -- One CPU's events are striped across its shards 1024 sequences at a
    -- time, so push past a stripe until a tagged event lands in
    -- shard-0001.
    local s1 = STORE .. "/shard-0001.db"
    local function in_s1()
        return eventd.sql(vm, s1, "SELECT count(*), max(sequence) FROM events WHERE event_type = 'pt.db.fewer'")[1]
    end
    local emitted = 0
    for _ = 1, 12 do
        if in_s1()[1] > 0 then break end
        local entries = {}
        for i = 1, 200 do entries[i] = { type = "pt.db.fewer", payload = eventd.msgpack({ tag = FEWER.tag }) } end
        emitted = emitted + kmes.emit_batch(vm, entries).emitted
        wait_until(function()
            local n = 0
            for _, s in ipairs({ SHARD0, s1 }) do
                n = n + eventd.sql(vm, s, "SELECT count(*) FROM events WHERE event_type = 'pt.db.fewer'")[1][1]
            end
            return n == emitted
        end, { timeout = 30, interval = 0.25, desc = "the batch to be stored" })
    end
    local held = in_s1()
    t:assert(held[1] > 0, "events reached shard-0001")
    eventd.unset(vm, "StorageShards")
    eventd.restart(vm)
    t:assert(exists(vm, s1), "shard-0001.db is still there with one active shard")
    t:assert_eq(in_s1()[1], held[1], "with its rows")
    t:assert_eq(#eventd.rows(vm, "EVENTS pt.db.fewer WHERE sequence == " .. held[2] .. " SINCE 1h ago"), 1,
        "and a query finds a row that only the historical shard holds")
end)

test("the query path opens every valid shard-NNNN.db, whatever its number, and nothing else", {
    spec = "eventd *eventdb.the-query-path-opens-every-valid-shard-file-whatever-their-number"
        .. " eventd *eventdb.the-query-path-ignores-files-not-matching-the-shard-name-pattern",
}, function(t)
    local tags = { n9 = eventd.marker("q9"), short = eventd.marker("qs"), other = eventd.marker("qo"),
                   meta = eventd.marker("qm") }
    stop(vm)
    rewrite(vm, SHARD0, planted_shard(vm, "pt.db.found", tags.n9), STORE .. "/shard-0009.db")
    rewrite(vm, SHARD0, planted_shard(vm, "pt.db.found", tags.short), STORE .. "/shard-9.db")
    rewrite(vm, SHARD0, planted_shard(vm, "pt.db.found", tags.other), STORE .. "/other.db")
    rewrite(vm, SHARD0, planted_shard(vm, "pt.db.found", tags.meta), STORE .. "/shard-0009.db.bak")
    start(vm)
    t:assert_eq(found(vm, "pt.db.found", tags.n9), 1, "shard-0009.db, with 0002..0008 absent, is read")
    t:assert_eq(found(vm, "pt.db.found", tags.short), 0, "shard-9.db is not a shard")
    t:assert_eq(found(vm, "pt.db.found", tags.other), 0, "other.db is not a shard")
    t:assert_eq(found(vm, "pt.db.found", tags.meta), 0, "shard-0009.db.bak is not a shard")
end)

test("the query path reads shards through read-only connections", {
    spec = "eventd *eventdb.the-query-path-opens-shards-with-read-only-connections",
}, function(t)
    -- A query opens its shard connections for as long as it reads, and
    -- closes them after. Several thousand rows make each query last long
    -- enough to see: queries run back to back in the guest while a loop
    -- there samples eventd's descriptor table for the shard file.
    local entries = {}
    for i = 1, 256 do entries[i] = { type = "pt.db.bulk", payload = eventd.msgpack({ s = string.rep("r", 1000) }) } end
    for _ = 1, 20 do kmes.emit_batch(vm, entries) end
    wait_until(function()
        return eventd.sql(vm, SHARD0, "SELECT count(*) FROM events WHERE event_type = 'pt.db.bulk'")[1][1] >= 5120
    end, { timeout = 60, interval = 0.5, desc = "the bulk events to be stored" })
    local pid = eventd.pid(vm)
    local q = eventd.guest_tmp(vm, "EVENTS pt.db.bulk SINCE 1h ago", "bulk")
    local script = eventd.guest_tmp(vm, table.concat({
        "( for i in 1 2 3 4 5 6 7 8; do evctl --format jsonl --file " .. q .. " >/dev/null 2>&1; done ) &",
        "end=$(($(date +%s) + 6))",
        "while [ $(date +%s) -lt $end ]; do",
        "  for f in /proc/" .. pid .. "/fd/*; do",
        "    if [ \"$(readlink $f 2>/dev/null)\" = '" .. SHARD0 .. "' ]; then",
        "      echo \"${f##*/} $(grep '^flags' /proc/" .. pid .. "/fdinfo/${f##*/} 2>/dev/null | awk '{print $2}') $(stat -L -c %i $f 2>/dev/null)\"",
        "    fi",
        "  done",
        "done | sort -u",
    }, "\n"), "sample")
    -- SQLite's unix VFS parks a closed descriptor while another
    -- connection in the process holds locks on the file and hands it to
    -- the next open with the same flags, so query connections show up as
    -- a recurring descriptor rather than a fresh one each time. Whatever
    -- the numbering: while queries run, the writer's is the only
    -- read-write descriptor on the shard, and the rest are read-only.
    local out = vm:run("sh " .. script).stdout
    local writer
    for _, f in ipairs(fds_on(vm, SHARD0)) do
        if f.flags & O_ACCMODE == O_RDWR then writer = f.fd end
    end
    t:assert(writer, "the writer's read-write descriptor is known")
    local readers = 0
    for fd, flags in out:gmatch("(%d+) (%d+) %d+") do
        fd, flags = tonumber(fd), tonumber(flags, 8)
        if fd ~= writer then
            t:assert_eq(flags & O_ACCMODE, O_RDONLY, "descriptor " .. fd .. " is read-only: " .. out)
            readers = readers + 1
        end
    end
    t:assert(readers > 0, "query connections were on the shard: " .. out)
end)

test("an existing active shard is opened in WAL mode", {
    spec = "eventd *eventdb.an-active-shard-is-opened-in-wal-mode",
}, function(t)
    stop(vm)
    rewrite(vm, SHARD0, "PRAGMA journal_mode=DELETE;")
    t:assert_eq(eventd.sql(vm, SHARD0, "PRAGMA journal_mode")[1][1], "delete", "the file was left in rollback mode")
    start(vm)
    t:assert_eq(eventd.sql(vm, SHARD0, "PRAGMA journal_mode")[1][1], "wal", "eventd opened it in WAL mode")
end)

-- ---------------------------------------------------------------------------
-- Failing starts, on bad
-- ---------------------------------------------------------------------------

local STD = "/var/state/eventd/events/"

local function set_store(v, value)
    if value then
        eventd.set(v, "EventStorePath", "sz:" .. value):assert_ok()
    else
        eventd.unset(v, "EventStorePath"):assert_ok()
    end
end

test("EventStorePath has no default: missing or invalid, eventd does not start", {
    spec = "eventd *eventdb.eventstorepath-has-no-default-and-a-missing-or-invalid-value-fails-startup",
}, function(t)
    stop(bad)
    set_store(bad, nil)
    local missing, missing_answered = start_fails(bad)
    set_store(bad, "var/state/eventd/events")
    local relative, relative_answered = start_fails(bad)
    set_store(bad, STD)
    start(bad)
    t:assert(missing ~= "active" and not missing_answered, "with no EventStorePath it does not come up: " .. tostring(missing))
    t:assert(relative ~= "active" and not relative_answered, "with a relative one it does not either: " .. tostring(relative))
end)

test("eventd never creates a store directory", {
    spec = "eventd *eventdb.eventd-never-creates-store-directories",
}, function(t)
    stop(bad)
    set_store(bad, "/var/state/eventd/pt-absent/")
    local state = start_fails(bad)
    local made = exists(bad, "/var/state/eventd/pt-absent")
    set_store(bad, STD)
    start(bad)
    t:assert(state ~= "active", "it does not start: " .. tostring(state))
    t:assert(not made, "and /var/state/eventd/pt-absent was not created")
end)

test("a missing, non-directory, symlinked or weakly protected store path fails startup", {
    spec = "eventd *eventdb.a-missing-non-directory-symlinked-or-weakly-protected-store-path-fails-startup",
}, function(t)
    stop(bad)
    bad:run("touch /var/state/eventd/pt-file && ln -s /var/state/eventd /var/state/pt-link")
    bad:run("mkdir /var/state/eventd/pt-weak")
    local weak_sddl = access.sd({
        owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM,
        dacl = access.acl({
            access.ace(access.ACE.ALLOWED, 0x10000000, token.SID.LOCAL_SYSTEM, 3),
            access.ace(access.ACE.ALLOWED, 0x10000000, token.SID.ADMINISTRATORS, 3),
            access.ace(access.ACE.ALLOWED, 0x10000000, SERVICE_SID_BIN, 3),
            access.ace(access.ACE.ALLOWED, 0x10000000, token.SID.EVERYONE, 3),
        }),
        control = access.CONTROL.DACL_PROTECTED,
    })
    local set = kacs.set_sd(bad, "/var/state/eventd/pt-weak", weak_sddl,
        kacs.SI.OWNER | kacs.SI.GROUP | kacs.SI.DACL)
    t:assert_eq(set.ret, 0, "the weak directory's descriptor is written")
    local cases = {
        { "missing", "/var/state/eventd/pt-nothing/" },
        { "non-directory component", "/var/state/eventd/pt-file/events/" },
        { "symlink component", "/var/state/pt-link/events/" },
        { "everyone may replace children", "/var/state/eventd/pt-weak/" },
    }
    local results = {}
    for _, c in ipairs(cases) do
        set_store(bad, c[2])
        results[#results + 1] = { c[1], (start_fails(bad)) }
    end
    set_store(bad, STD)
    start(bad)
    for _, r in ipairs(results) do
        t:assert(r[2] ~= "active", r[1] .. ": eventd does not start (" .. tostring(r[2]) .. ")")
    end
end)

test("an active shard with a missing or unrecognised schema_version fails startup and is not migrated", {
    spec = "eventd *eventdb.a-missing-or-unrecognised-active-shard-schema-version-fails-startup"
        .. " eventd *events.a-shard-schema-is-never-migrated",
}, function(t)
    stop(bad)
    rewrite(bad, SHARD0, "UPDATE metadata SET value = '99' WHERE key = 'schema_version';")
    local unknown = start_fails(bad)
    local after = eventd.sql(bad, SHARD0, "SELECT value FROM metadata WHERE key = 'schema_version'")[1][1]
    rewrite(bad, SHARD0, "DELETE FROM metadata WHERE key = 'schema_version';")
    local missing = start_fails(bad)
    rewrite(bad, SHARD0, "INSERT INTO metadata VALUES ('schema_version', '1');")
    start(bad)
    t:assert(unknown ~= "active", "schema_version 99: no start (" .. tostring(unknown) .. ")")
    t:assert_eq(after, "99", "and the shard still says 99: nothing migrated it")
    t:assert(missing ~= "active", "no schema_version: no start (" .. tostring(missing) .. ")")
end)

test("an active shard missing a required table or the timestamp index fails startup", {
    spec = "eventd *eventdb.an-active-shard-missing-required-tables-or-indexes-fails-startup",
}, function(t)
    stop(bad)
    local saved = bad:read_file(SHARD0)
    rewrite(bad, SHARD0, "DROP TABLE receipt_ranges;")
    local no_table = start_fails(bad)
    bad:write_file(SHARD0, saved)
    rewrite(bad, SHARD0, "DROP INDEX idx_events_timestamp;")
    local no_index = start_fails(bad)
    bad:write_file(SHARD0, saved)
    start(bad)
    t:assert(no_table ~= "active", "without receipt_ranges: no start (" .. tostring(no_table) .. ")")
    t:assert(no_index ~= "active", "without idx_events_timestamp: no start (" .. tostring(no_index) .. ")")
end)

test("a historical shard that will not verify is logged and left out, never failing startup or quarantined", {
    spec = "eventd *eventdb.a-historical-shard-is-never-required-for-startup"
        .. " eventd *eventdb.a-bad-historical-shard-is-logged-and-excluded-without-failing-startup-or-quarantine",
}, function(t)
    local tags = { v99 = eventd.marker("h99"), notab = eventd.marker("hnt"), good = eventd.marker("hok") }
    stop(bad)
    rewrite(bad, SHARD0, planted_shard(bad, "pt.db.hist", tags.v99) ..
        "UPDATE metadata SET value = '99' WHERE key = 'schema_version';", STORE .. "/shard-0003.db")
    rewrite(bad, SHARD0, planted_shard(bad, "pt.db.hist", tags.notab) .. "DROP TABLE receipt_ranges;",
        STORE .. "/shard-0004.db")
    local garbage = string.rep("not a database at all. ", 300)
    bad:write_file(STORE .. "/shard-0005.db", garbage)
    rewrite(bad, SHARD0, planted_shard(bad, "pt.db.hist", tags.good), STORE .. "/shard-0006.db")
    local since = guest_now(bad)
    bad:run("svctl start eventd")
    eventd.ready(bad)
    t:assert_eq(eventd.status(bad).state, "active", "eventd starts")
    t:assert_eq(found(bad, "pt.db.hist", tags.good), 1, "a good historical shard is read")
    t:assert_eq(found(bad, "pt.db.hist", tags.v99), 0, "the unrecognised-version one is not")
    t:assert_eq(found(bad, "pt.db.hist", tags.notab), 0, "nor the one missing a table")
    local files = listing(bad, STORE)
    for _, f in ipairs(files) do
        t:assert(not f:find("corrupt", 1, true), "nothing was quarantined: " .. f)
    end
    t:assert_eq(bad:read_file(STORE .. "/shard-0005.db"), garbage, "the unreadable one is untouched")
    local logs = eventd.rows(bad, "LOGS FROM eventd SINCE 10m ago")
    local named = {}
    for _, l in ipairs(logs) do
        if l.timestamp >= since and l.message:find("historical", 1, true) then
            for _, n in ipairs({ "0003", "0004", "0005" }) do
                if l.message:find("shard-" .. n, 1, true) then named[n] = true end
            end
        end
    end
    t:assert(named["0003"] and named["0004"] and named["0005"],
        "each exclusion was logged: " .. json.encode(named))
    stop(bad)
    for _, n in ipairs({ "0003", "0004", "0005", "0006" }) do bad:run("rm -f " .. STORE .. "/shard-" .. n .. ".db*") end
    start(bad)
end)

--- Quarantined copies of shard-0000's files: {[base] = suffix}.
local function quarantined(v)
    local files = listing(v, STORE)
    local suffix = {}
    for _, f in ipairs(files) do
        local base, ts = f:match("^(shard%-0000%.db[%-a-z]*)%.corrupt%.([%d%.]+)$")
        if base then suffix[base] = ts end
    end
    return suffix, files
end

test("SQLite-reported corruption in the active shard renames it aside, starts a fresh one, logs and records it", {
    spec = "eventd *eventdb.corruption-reported-while-opening-an-active-shard-quarantines-and-replaces-it"
        .. " eventd *eventdb.a-corrupt-required-store-is-renamed-aside-and-replaced-at-its-path"
        .. " eventd *eventdb.quarantine-is-logged-and-emits-a-storage-error-event-once-a-shard-is-writable",
}, function(t)
    stop(bad)
    local body = string.rep("garbage database ", 500)
    bad:write_file(SHARD0, body)
    local since = guest_now(bad)
    start(bad)
    local suffix, files = quarantined(bad)
    local ts = suffix["shard-0000.db"]
    t:assert(ts, "the database was renamed aside: " .. table.concat(files, " "))
    t:assert(math.tointeger(tonumber(ts)) and tonumber(ts) >= since, "to .corrupt.<now in ns>: " .. ts)
    t:assert_eq(bad:read_file(STORE .. "/shard-0000.db.corrupt." .. ts), body, "holding what it held")
    local schema = eventd.schema(bad, SHARD0)
    t:assert(schema.events and schema.metadata, "a fresh shard-0000.db stands at the original path")
    local errs = eventd.rows(bad, "EVENTS " .. eventd.T.storage_error .. " SINCE 10m ago")
    local hit = false
    for _, e in ipairs(errs) do
        if e.store == "event" and e.shard_index == 0 and e.timestamp >= since then hit = true end
    end
    t:assert(hit, "a storage_error for the event store's shard 0 was recorded: " .. json.encode(errs))
    local logs = eventd.rows(bad, "LOGS FROM eventd SINCE 10m ago")
    local logged = false
    for _, l in ipairs(logs) do
        if l.timestamp >= since and l.message:find("quarantined corrupt event shard 0", 1, true) then logged = true end
    end
    t:assert(logged, "and the quarantine was logged")
end)

test("quarantine moves the database, its WAL and its shared memory under one suffix, deleting none of them", {
    spec = "eventd *eventdb.quarantine-gives-the-database-wal-and-shm-one-shared-corrupt-timestamp-suffix"
        .. " eventd *eventdb.a-corrupt-store-is-never-deleted-or-automatically-repaired",
    tags = { "known-bug" },
}, function(t)
    -- PEI-1287 (PEI-TBD-quarantine-loses-wal): Shard::open_recovering (shard.rs:76-90)
    -- quarantines only after Shard::open has failed, and that open runs
    -- SQLite against the database with its -wal and -shm in place
    -- (shard.rs:96-110). SQLite opens a present -wal, rebuilds the -shm,
    -- and on closing the failed connection deletes both, so by the time
    -- quarantine::database (quarantine.rs:14-21) looks for sidecars there
    -- are none to move. The WAL, which can hold the newest committed
    -- transactions, is the part lost.
    stop(bad)
    for _, f in ipairs(listing(bad, STORE)) do
        if f:find("corrupt", 1, true) then bad:run("rm -f " .. STORE .. "/" .. f) end
    end
    local body = { db = string.rep("garbage database ", 500), wal = string.rep("garbage wal ", 300),
                   shm = string.rep("garbage shm ", 3000) }
    bad:write_file(SHARD0, body.db)
    bad:write_file(SHARD0 .. "-wal", body.wal)
    bad:write_file(SHARD0 .. "-shm", body.shm)
    start(bad)
    local suffix, files = quarantined(bad)
    local ts = suffix["shard-0000.db"]
    t:assert(ts, "the database was renamed aside: " .. table.concat(files, " "))
    t:assert_eq(suffix["shard-0000.db-wal"], ts, "its WAL under the same suffix: " .. table.concat(files, " "))
    t:assert_eq(suffix["shard-0000.db-shm"], ts, "its shared memory under the same suffix")
    t:assert_eq(bad:read_file(STORE .. "/shard-0000.db.corrupt." .. ts), body.db, "the database kept byte for byte")
    t:assert_eq(bad:read_file(STORE .. "/shard-0000.db-wal.corrupt." .. ts), body.wal, "the WAL kept")
    t:assert_eq(bad:read_file(STORE .. "/shard-0000.db-shm.corrupt." .. ts), body.shm, "the shared memory kept")
end)

-- Route closed: the suffix is the nanosecond clock at quarantine
-- (quarantine.rs:9-13), so a collision needs two quarantines of one
-- database in the same nanosecond, or a guest that predicts the clock
-- reading eventd will take; neither is arrangeable from outside.
test("a taken quarantine name gets the lowest free .N", {
    spec = "eventd *eventdb.a-taken-quarantine-name-gets-the-lowest-free-positive-integer-suffix",
    skip = true,
    covered_by = "cargo:eventd eventd-core quarantine::tests::a_taken_quarantine_name_gets_the_lowest_free_positive_suffix",
}, function() end)
