-- Helpers for the eventd conformance testset.
--
-- eventd is tested where it runs: the image's own instance, booted by the
-- peinit profile as one Phase 2 service among the rest. A second instance
-- is not an option the way it was for loregd. eventd reads its whole
-- configuration from one fixed registry key and takes no arguments, so two
-- instances on one machine would share it. Everything here therefore drives
-- the real system sink, and a test varies it in three ways:
--
--   * at boot, by seeding values under `Machine\System\eventd` before
--     Phase 2 reads them (`boot{config = …}`) — the only route for a value
--     that applies at restart;
--   * live, with `set` and `unset`, which eventd's registry watch applies;
--   * by restarting the service (`restart`), which re-runs the whole
--     bootstrap sequence against the same stores.
--
-- What goes in comes through the three real channels: `emit` writes a KMES
-- event, `send_log` and `send_metric` send a datagram to the log and metric
-- sockets. What comes out is read through the fourth, the query socket,
-- with `query` (evctl, JSON lines), or straight out of the stores with
-- `sql`, which copies a database to the host and asks sqlite there — the
-- guest ships no sqlite3.
--
-- The agent runs as SYSTEM, so it is admitted to all three sockets
-- (`datagram.rs`: the log socket allows SY and denies only the Service
-- logon group; the metric and query sockets allow SY, BA and Authenticated
-- Users). A test that needs a less privileged caller mints one through
-- `helpers.token` / `helpers.peinit_client` as the rest of the suite does.
--
-- The stores live under /var/state on the live root, an overlay over a
-- tmpfs: they survive a restart of eventd and nothing survives a reboot. A
-- test about reboots or power loss mounts a disk under the store paths from
-- a Phase 1 autorun, which runs before path provisioning stamps them (peinit
-- §2.3 step 7, then step 8); see `boot{disk = …}`.

local peinit = require("helpers.peinit")
local kmes = require("helpers.kmes")
local unixsock = require("helpers.unixsock")

local M = {}

M.KEY = [[Machine\System\eventd]]
M.SECURITY = M.KEY .. [[\Security]]

M.SOCKET = {
    query = "/run/eventd/query.sock",
    log = "/run/eventd/log.sock",
    metric = "/run/eventd/metric.sock",
}

M.STORE = {
    events = "/var/state/eventd/events",
    logs = "/var/state/eventd/logs",
    metrics = "/var/state/eventd/metrics",
}

--- The one database file of each single-file store, and the metadata
--- database beside the event shards.
M.DB = {
    logs = M.STORE.logs .. "/logs.db",
    metrics = M.STORE.metrics .. "/metrics.db",
    meta = M.STORE.events .. "/eventd-meta.db",
}

--- Every event type and payload key a test depends on, spelled once.
---
--- An event-naming pass (PEI-617) may rename the `synthetic.*` family; when
--- it lands this table is the only place the suite changes. Write
--- `eventd.T.startup`, never the literal.
M.T = {
    startup = "synthetic.startup",
    shutdown = "synthetic.shutdown",
    gap = "synthetic.gap",
    config_change = "synthetic.config_change",
    storage_error = "synthetic.storage_error",
}

-- ---------------------------------------------------------------------------
-- MessagePack encoding
--
-- The log and metric channels carry MessagePack, and so does a KMES event's
-- payload. kmes.lua decodes; this encodes. Lua cannot tell an array from a
-- map, an integer-valued float from an integer, or a string from bytes, so
-- each of those is said explicitly when the default guess is wrong:
--
--   eventd.array{…}    an array, even when empty
--   eventd.map{…}      a map, even when empty or holding only [1]..[n]
--   eventd.bin(s)      bin 8/16/32 rather than str
--   eventd.float(x)    float 64 even for a whole number
--   eventd.NIL         nil, inside a table
--
-- Otherwise: a table with [1] is an array, any other table a map with its
-- keys sorted (so the bytes are deterministic), an integer is the smallest
-- integer form, a float is float 64, a string is str.
-- ---------------------------------------------------------------------------

local ARRAY, MAP, BIN, FLOAT = {}, {}, {}, {}
M.NIL = setmetatable({}, { __tostring = function() return "eventd.NIL" end })

function M.array(t) return { [ARRAY] = t or {} } end
function M.map(t) return { [MAP] = t or {} } end
function M.bin(s) return { [BIN] = s } end
function M.float(x) return { [FLOAT] = x } end

local encode

local function encode_int(n)
    if n >= 0 then
        if n < 0x80 then return string.char(n) end
        if n < 0x100 then return "\xcc" .. string.pack(">I1", n) end
        if n < 0x10000 then return "\xcd" .. string.pack(">I2", n) end
        if n < 0x100000000 then return "\xce" .. string.pack(">I4", n) end
        return "\xcf" .. string.pack(">I8", n)
    end
    if n >= -32 then return string.pack("b", n) end
    if n >= -0x80 then return "\xd0" .. string.pack(">i1", n) end
    if n >= -0x8000 then return "\xd1" .. string.pack(">i2", n) end
    if n >= -0x80000000 then return "\xd2" .. string.pack(">i4", n) end
    return "\xd3" .. string.pack(">i8", n)
end

local function encode_str(s, as_bin)
    local n = #s
    if as_bin then
        if n < 0x100 then return "\xc4" .. string.pack(">I1", n) .. s end
        if n < 0x10000 then return "\xc5" .. string.pack(">I2", n) .. s end
        return "\xc6" .. string.pack(">I4", n) .. s
    end
    if n < 32 then return string.char(0xa0 + n) .. s end
    if n < 0x100 then return "\xd9" .. string.pack(">I1", n) .. s end
    if n < 0x10000 then return "\xda" .. string.pack(">I2", n) .. s end
    return "\xdb" .. string.pack(">I4", n) .. s
end

local function encode_array(t)
    local n, parts = #t, {}
    if n < 16 then parts[1] = string.char(0x90 + n)
    elseif n < 0x10000 then parts[1] = "\xdc" .. string.pack(">I2", n)
    else parts[1] = "\xdd" .. string.pack(">I4", n) end
    for i = 1, n do parts[#parts + 1] = encode(t[i]) end
    return table.concat(parts)
end

local function encode_map(t)
    local keys = {}
    for k in pairs(t) do keys[#keys + 1] = k end
    table.sort(keys, function(a, b) return tostring(a) < tostring(b) end)
    local n, parts = #keys, {}
    if n < 16 then parts[1] = string.char(0x80 + n)
    elseif n < 0x10000 then parts[1] = "\xde" .. string.pack(">I2", n)
    else parts[1] = "\xdf" .. string.pack(">I4", n) end
    for _, k in ipairs(keys) do
        parts[#parts + 1] = encode(k)
        parts[#parts + 1] = encode(t[k])
    end
    return table.concat(parts)
end

encode = function(v)
    local ty = type(v)
    if v == nil or v == M.NIL then return "\xc0" end
    if ty == "boolean" then return v and "\xc3" or "\xc2" end
    if ty == "number" then
        if math.type(v) == "integer" then return encode_int(v) end
        return "\xcb" .. string.pack(">d", v)
    end
    if ty == "string" then return encode_str(v) end
    assert(ty == "table", "msgpack: cannot encode a " .. ty)
    if v[ARRAY] then return encode_array(v[ARRAY]) end
    if v[MAP] then return encode_map(v[MAP]) end
    if v[BIN] then return encode_str(v[BIN], true) end
    if v[FLOAT] then return "\xcb" .. string.pack(">d", v[FLOAT]) end
    if v[1] ~= nil or next(v) == nil then return encode_array(v) end
    return encode_map(v)
end

--- Encode a Lua value as MessagePack (see the section comment above).
M.msgpack = encode

-- ---------------------------------------------------------------------------
-- Boot, readiness and the service
-- ---------------------------------------------------------------------------

--- A registry seed setting values under `Machine\System\eventd`.
---
--- `values` is a list of `{name, type, data}` in the shape `reg apply`
--- reads (`type` is "sz", "dword", "qword", "multi", "binary"). The image's
--- own eventd-config.reg has created the key by the time an autoapply seed
--- runs, but every level is named anyway, as a seed must.
function M.config_seed(values, extra_keys)
    local keys = {
        { path = [[Machine\System]] },
        { path = M.KEY, values = values },
    }
    for _, k in ipairs(extra_keys or {}) do keys[#keys + 1] = k end
    return peinit.seed("zz-pt-eventd-config", keys)
end

--- Boot a peinit VM and wait until eventd answers a query.
---
--- opts (all optional):
---   name, memory, cpus, append, boot, stage — as `peinit.boot`
---   config  a `config_seed` values list, applied before Phase 2
---   files   further `peinit.stage` files, merged with the seed
---   wait    false to skip waiting for eventd (a test that expects it
---           not to start)
---
--- Each boot is one VM against the file's `peinit.claim`. One vCPU unless
--- a test is about per-CPU structure: the KMES ring buffers, drain threads
--- and the default shard count are one per CPU, and on one vCPU there is
--- exactly one of each.
function M.boot(opts)
    opts = opts or {}
    local files = {}
    if opts.config then
        for k, v in pairs(M.config_seed(opts.config, opts.config_keys)) do files[k] = v end
    end
    for k, v in pairs(opts.files or {}) do files[k] = v end
    local vm = peinit.boot({
        name = opts.name or "ev",
        memory = opts.memory,
        cpus = opts.cpus,
        append = opts.append,
        boot = opts.boot,
        stage = opts.stage,
        files = next(files) and files or nil,
    })
    if opts.wait ~= false then M.ready(vm) end
    return vm
end

--- Write `text` to a fresh guest file and return its path.
local seq = 0
local function guest_tmp(vm, text, stem)
    seq = seq + 1
    local path = string.format("/tmp/pt-eventd-%s-%d", stem or "f", seq)
    vm:write_file(path, text)
    return path
end
M.guest_tmp = guest_tmp

--- Run a query through evctl and decode its JSON lines.
---
--- Returns a table:
---   ok         exit status 0
---   exit_code  evctl's status: 0 success, 1 eventd answered with an error
---              or the channel failed, 2 a usage error
---   rows       the decoded records, in order (empty when not ok)
---   stdout, stderr
---
--- The query is passed by file, never on a command line, so a test can
--- send any text — quotes, backslashes, newlines — without a shell
--- between it and eventd. `opts.socket` overrides the query socket.
function M.query(vm, text, opts)
    opts = opts or {}
    local path = guest_tmp(vm, text, "q")
    local cmd = "evctl --format jsonl --file " .. path
    if opts.socket then cmd = cmd .. " --socket '" .. opts.socket .. "'" end
    local r = vm:run(cmd)
    local out = { exit_code = r.exit_code, ok = r.exit_code == 0,
                  stdout = r.stdout, stderr = r.stderr, rows = {} }
    if out.ok then
        for line in r.stdout:gmatch("[^\n]+") do
            local okd, row = pcall(json.decode, line)
            assert(okd, "evctl emitted a line that is not JSON: " .. line)
            out.rows[#out.rows + 1] = row
        end
    end
    return out
end

--- `query`, asserting success, returning the rows.
function M.rows(vm, text, opts)
    local r = M.query(vm, text, opts)
    assert(r.ok, "query failed (exit " .. tostring(r.exit_code) .. "): " ..
        text .. "\nstderr: " .. tostring(r.stderr))
    return r.rows
end

--- Poll a query until `pred(rows)` is true; returns the rows that
--- satisfied it. Ingestion is asynchronous on every channel — a record is
--- queryable once its writer commits, not when the sender returns — so a
--- test that sends and then reads must wait rather than read once.
function M.wait_rows(vm, text, pred, opts)
    opts = opts or {}
    local last
    local ok = wait_until(function()
        local r = M.query(vm, text)
        if not r.ok then last = r.stderr; return false end
        last = r.rows
        return pred(r.rows)
    end, { timeout = opts.timeout or 30, interval = opts.interval or 0.25,
           desc = opts.desc or ("rows for: " .. text) })
    return last, ok
end

--- Wait until eventd answers a query on its socket: the service has
--- signalled readiness, which by §8.2 is after every store and socket is
--- open and `synthetic.startup` is durably committed.
function M.ready(vm, timeout)
    wait_until(function()
        return M.query(vm, "EVENTS TAKE 1").ok
    end, { timeout = timeout or 90, interval = 0.5,
           desc = "eventd to answer on its query socket" })
end

--- `svctl --json status eventd`, decoded.
function M.status(vm)
    local r = vm:run("svctl --json status eventd")
    assert(r.exit_code == 0, "svctl status eventd: " .. r.stdout .. r.stderr)
    return json.decode(r.stdout)
end

--- eventd's main pid, or nil when it is not running. From the service
--- manager rather than a process scan: the image ships no pidof.
function M.pid(vm)
    local r = vm:run("svctl --json status eventd")
    if r.exit_code ~= 0 then return nil end
    return tonumber(r.stdout:match('"pid":(%d+)'))
end

--- Restart eventd through the service manager and wait until it answers
--- again with a new process. Returns the new pid.
function M.restart(vm)
    local before = M.pid(vm)
    vm:run("svctl restart eventd"):assert_ok()
    wait_until(function()
        local now = M.pid(vm)
        return now ~= nil and now ~= before
    end, { timeout = 60, interval = 0.25, desc = "a new eventd process" })
    M.ready(vm)
    return M.pid(vm)
end

-- ---------------------------------------------------------------------------
-- Configuration at runtime
-- ---------------------------------------------------------------------------

--- `reg set` one value under the eventd key (or `opts.key`). `value` is
--- `reg`'s typed form: "dword:64", "sz:/run/x", "qword:5".
function M.set(vm, name, value, opts)
    local key = (opts and opts.key) or M.KEY
    return vm:run(string.format("reg set '%s' '%s' '%s'", key, name, value))
end

--- `reg del` one value under the eventd key.
function M.unset(vm, name, opts)
    local key = (opts and opts.key) or M.KEY
    return vm:run(string.format("reg del '%s' '%s'", key, name))
end

-- ---------------------------------------------------------------------------
-- The three ingestion channels
-- ---------------------------------------------------------------------------

--- Emit a KMES event as `who` (default the agent, SYSTEM). `payload` is a
--- Lua value encoded with `msgpack`, or raw bytes via `{raw = "…"}`.
--- Returns the kmes_emit result (`r.ret == 0` on success).
function M.emit(who, event_type, payload)
    local bytes
    if type(payload) == "table" and payload.raw then
        bytes = payload.raw
    elseif payload == nil then
        bytes = M.msgpack(M.map{})
    else
        bytes = M.msgpack(payload)
    end
    return kmes.emit(who, event_type, bytes)
end

local function send(who, path, bytes, pass_token)
    local fd, errno = unixsock.socket(who, unixsock.AF_UNIX, unixsock.SOCK.DGRAM)
    assert(fd, "socket: " .. tostring(errno))
    if pass_token then
        local p = unixsock.set_pass_token(who, fd, true)
        assert(p.ret == 0, "KACS_SO_PASS_TOKEN: errno " .. tostring(p.errno))
    end
    local r = unixsock.sendto(who, fd, bytes, path)
    who:syscall(3, fd) -- close
    return r
end

--- Send one log datagram. `record` is a record map, a list of them (one
--- datagram, an array), or `{raw = "…"}` bytes. Returns the sendto result.
---
--- No token is attached: the log channel's only producer is peinit, and
--- the socket's descriptor is its whole access control (§7.1).
--- `opts.path` overrides the socket, `opts.pass_token` attaches one.
function M.send_log(who, record, opts)
    opts = opts or {}
    local bytes = record.raw or M.msgpack(record)
    return send(who, opts.path or M.SOCKET.log, bytes, opts.pass_token)
end

--- Send one metric datagram; as `send_log`, except that the sender's
--- token IS attached by default. eventd checks EVENTD_PUBLISH per record
--- against that token (§7.6) and counts a datagram arriving without one as
--- `metric_missing_identity`, storing nothing — so a test that wants the
--- record stored must send with `KACS_SO_PASS_TOKEN` set, and a test about
--- that rejection passes `{pass_token = false}`.
function M.send_metric(who, record, opts)
    opts = opts or {}
    local bytes = record.raw or M.msgpack(record)
    local pass = opts.pass_token
    if pass == nil then pass = true end
    return send(who, opts.path or M.SOCKET.metric, bytes, pass)
end

--- A process-unique marker, for telling this test's records from
--- everything else the system writes into the same stores.
local marker_seq = 0
function M.marker(stem)
    marker_seq = marker_seq + 1
    return string.format("pt%s%d%d", stem or "", os.time() % 100000, marker_seq)
end

-- ---------------------------------------------------------------------------
-- The stores, read directly
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

--- Run SQL against a copy of a guest SQLite database, on the host.
---
--- `db` is a guest path (`eventd.DB.logs`, a shard under
--- `eventd.STORE.events`). The database and its `-wal`, if present, are
--- copied out together, so committed transactions still in the WAL are
--- seen. Returns a list of rows, each a list of column values (JSON
--- types; blobs as lowercase hex).
---
--- The copy is not a snapshot: a writer committing while the two files
--- are read can leave them inconsistent. Read schema, metadata and rows a
--- test has already waited for, not a store under load.
function M.sql(vm, db, query)
    local dir = host_tmpdir()
    host_write(dir .. "/db", vm:read_file(db))
    local okw, wal = pcall(vm.read_file, vm, db .. "-wal")
    if okw and wal and #wal > 0 then host_write(dir .. "/db-wal", wal) end
    host_write(dir .. "/q.sql", query)
    local script = [[
import json, sqlite3, sys
d = sys.argv[1]
c = sqlite3.connect(d + "/db")
q = open(d + "/q.sql").read()
rows = c.execute(q).fetchall()
def v(x):
    return x.hex() if isinstance(x, (bytes, bytearray)) else x
print(json.dumps([[v(x) for x in r] for r in rows]))
]]
    host_write(dir .. "/run.py", script)
    local p = assert(io.popen("python3 " .. dir .. "/run.py " .. dir .. " 2>&1", "r"))
    local out = p:read("a")
    local ok = p:close()
    os.execute("rm -rf '" .. dir .. "'")
    assert(ok, "sqlite on host failed: " .. out)
    return json.decode(out)
end

--- The CREATE statements of a guest database, by object name.
function M.schema(vm, db)
    local out = {}
    for _, r in ipairs(M.sql(vm, db, "SELECT name, sql FROM sqlite_master WHERE sql IS NOT NULL")) do
        out[r[1]] = r[2]
    end
    return out
end

--- The event shard files currently in the event store, sorted.
function M.shards(vm)
    local out = {}
    for _, name in ipairs(vm:listdir(M.STORE.events)) do
        local n = type(name) == "table" and name.name or name
        if n:match("^shard%-%d+%.db$") then out[#out + 1] = M.STORE.events .. "/" .. n end
    end
    table.sort(out)
    return out
end

return M
