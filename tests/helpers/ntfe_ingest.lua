-- Helpers for the NTFE ingestion testset (PKM §6.5).
--
-- Two hive shapes matter to ingestion, and a file uses one of them.
--
-- `ntfe.engine()` alone serves a Machine hive with nothing but the
-- Network key. Missing the other kernel-read keys (Registry, Layers,
-- KMES, PortReservations, Generic\Events), LCS arms its machine-root
-- fallback watch, and every key created anywhere under Machine re-runs
-- the whole bootstrap refresh — an NTFE walk included, synchronously,
-- inside the creating syscall, uncounted. `M.engine()` here seeds them,
-- so the self-watch is targeted, as on a real machine, and the only
-- walks are the debounced ones the Network watch schedules.
--
-- The stock `E:write` / `E:create` serve the source until it has been
-- quiet for 100 ms, which is longer than the debounce: the walk the
-- write schedules runs inside them. The `quick_*` forms serve the
-- source only until the syscall returns, so a test can look at the
-- engine between a write and the walk that reads it.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")
local ntfe = require("helpers.ntfe")

local M = {}

M.CLOCK_REALTIME, M.CLOCK_MONOTONIC = 0, 1
M.EINVAL, M.E2BIG, M.EMSGSIZE = 22, 7, 90

--- The guest clock in milliseconds (CLOCK_MONOTONIC unless `clock`).
function M.now_ms(who, clock)
    local r = who:syscall(228, {
        args = { clock or M.CLOCK_MONOTONIC, 0 },
        bufs = { string.rep("\0", 16) }, ptrs = { 1 },
    })
    local s, ns = string.unpack("<i8i8", r.out_bufs[1])
    return s * 1000 + ns / 1e6
end

--- The guest's CLOCK_REALTIME in nanoseconds.
function M.realtime_ns(who)
    local r = who:syscall(228, {
        args = { M.CLOCK_REALTIME, 0 },
        bufs = { string.rep("\0", 16) }, ptrs = { 1 },
    })
    local s, ns = string.unpack("<i8i8", r.out_bufs[1])
    return s * 1000000000 + ns
end

--- Seed the kernel-read keys besides Network, so LCS arms targeted
--- watches and no machine-root fallback.
function M.targeted_seed(src)
    src:key("Machine\\System\\Registry\\Layers")
    src:key("Machine\\System\\KMES")
    src:key(ntfe.NETWORK_KEY .. "\\TcpIp\\PortReservations")
    -- The event emission policy (KMES §2.8): absent, it too keeps the
    -- machine-root fallback armed.
    src:key("Machine\\Generic\\Events")
end

--- `ntfe.engine` on a targeted hive (see above). `o.inventory = {
--- networks, interfaces }` seeds netd's inventory before registration;
--- `o.fallback = true` leaves the hive untargeted.
function M.engine(vm, policy, o)
    o = o or {}
    local E = ntfe.engine(vm, policy, {
        no_network = o.no_network,
        fallback = o.fallback,
        seed = function(src)
            if not o.fallback then M.targeted_seed(src) end
            if o.inventory then
                ntfe.seed_inventory(src, o.inventory[1], o.inventory[2])
            end
            if o.seed then o.seed(src) end
        end,
    })
    E.net_guid = E.src:lookup(ntfe.NETWORK_KEY)
    return E
end

-- `Source:step`, reading into a 4 KiB buffer first: a walk's requests
-- are small, and a 64 KiB buffer carried both ways per request is most
-- of what a walk of thousands of rules costs. The device answers a
-- frame too big for the buffer with EMSGSIZE and keeps it queued, so
-- the big read is the fallback.
local function step(src)
    local r
    for _, size in ipairs({ 4096, 65536 }) do
        r = src.worker:syscall(sys.NR.read, {
            args = { src.fd, 0, size }, bufs = { string.rep("\0", size) }, ptrs = { 1 },
        })
        if not (r.ret < 0 and r.errno == M.EMSGSIZE) then break end
    end
    if r.ret < 0 then
        if r.errno == sys.E.AGAIN then return nil end
        error("source read: " .. sys.errname(r.errno))
    end
    if r.ret == 0 then src.eof = true; return nil end
    local msg = r.out_bufs[1]:sub(1, r.ret)
    local total, id, op, txn = string.unpack("<I4I8I2I8", msg)
    assert(total == #msg, "framing: total_len " .. total .. " of " .. #msg)
    local req = { id = id, op = op, txn = txn, payload = msg:sub(23), raw = msg }
    src.log[#src.log + 1] = req
    local status, body
    local hook = src.intercepts[op]
    if hook then
        local a, b = hook(src, req)
        if a == lcs.HOLD then
            src.held[id] = req
            req.held = true
            return req
        elseif type(a) == "string" and b == nil then
            src:write_frame(a)
            req.raw_response = a
            return req
        elseif a ~= nil then
            status, body = a, b or ""
        end
    end
    if status == nil then status, body = src:dispatch(req) end
    req.status = status
    src:respond(req, status, body)
    return req
end

--- Serve the source like `Source:pump`, stamping every request served
--- with the guest's monotonic clock (`req.t`, ms) as it is read.
function M.pump(E, quiet_ms)
    local src = E.src
    local served = 0
    while src.fd and not src.eof do
        local p = src.worker:syscall(sys.NR.poll, {
            args = { 0, 1, quiet_ms or 100 },
            bufs = { string.pack("<i4i2i2", src.fd, 1, 0) }, ptrs = { 0 },
        })
        if p.ret <= 0 then return served end
        local n = 0
        while true do
            local t = M.now_ms(src.worker)
            local req = step(src)
            if not req then break end
            req.t = t
            served = served + 1; n = n + 1
        end
        if n == 0 then return served end
    end
    return served
end

--- `E:settle` served by the pump above. Returns the status that
--- satisfied it; raises after `timeout_ms` (default 5 s; 0 = none).
function M.settle(E, timeout_ms)
    local target = E:status().changes_noted
    local start = M.now_ms(E.vm)
    while true do
        M.pump(E, 20)
        local s = E:status()
        if s.changes_walked >= target then return s end
        local limit = timeout_ms or 5000
        if limit > 0 and M.now_ms(E.vm) - start > limit then
            error(string.format("the engine did not walk: noted %d, walked %d",
                s.changes_noted, s.changes_walked))
        end
    end
end

--- Launch a registry call on the writer, serve the source only until it
--- returns (5 ms of quiet), and return its result. The walk the call
--- schedules has not started: the debounce is 50 ms.
function M.quick(E, launch)
    local pending = launch(E.writer)
    M.pump(E, 5)
    return pending:await()
end

function M.quick_write(E, fd, name, v, o)
    local vtype, data = ntfe.lower(v)
    return M.quick(E, function(w)
        return lcs.set_value_async(w, fd, name, vtype, data, o)
    end)
end

--- reg_create_key at a path relative to the Network key. Returns the
--- raw result (`ret` is the fd).
function M.quick_create(E, path, o)
    o = o or {}
    return M.quick(E, function(w)
        return lcs.create_key_async(w, {
            path = ntfe.NETWORK_KEY .. "\\" .. path, txn_fd = o.txn_fd,
        })
    end)
end

-- Entries seeded after registration must resolve at the sequence the
-- kernel already knows (as helpers/ntfe's `replace` does).
local function seed_pinned(src, fn)
    local saved, real = src.seq, src.next_seq
    src.next_seq = function() return 1 end
    local ok, err = pcall(fn)
    src.next_seq = real
    src.seq = saved
    if not ok then error(err, 0) end
end

--- `E:replace`, with the poke served only until it returns: the same
--- harness shortcut, a few times faster. Returns the settled status.
function M.replace(E, policy)
    M.stage(E, policy)
    M.poke(E)
    return M.settle(E, 120000)
end

--- The first half of `replace`: swap the policy in the source's store
--- and tell the engine nothing. The GUIDs of the new rule keys can be
--- looked up (`E.src:lookup(path)`) before a `poke`.
function M.stage(E, policy)
    local src = E.src
    local rules = assert(src:lookup(ntfe.RULES_KEY), "no Rules key")
    src.store.entries[rules] = nil
    src.store.values[rules] = nil
    seed_pinned(src, function() ntfe.seed(src, policy) end)
end

--- One real write under the Network key, served only until it returns.
function M.poke(E)
    E.pokes = E.pokes + 1
    local r = M.quick_write(E, E.net_fd, "TestPoke", E.pokes)
    assert(r.ret == 0, "poke: " .. sys.errname(r.errno))
    return r
end

--- `E:replace_inventory`, likewise.
function M.replace_inventory(E, networks, interfaces)
    M.stage_inventory(E, networks, interfaces)
    M.poke(E)
    return M.settle(E, 120000)
end

--- The first half of `replace_inventory` (see `stage`).
function M.stage_inventory(E, networks, interfaces)
    local src = E.src
    for _, name in ipairs({ "Networks", "Interfaces" }) do
        local guid = src:lookup(ntfe.NETWORK_KEY .. "\\" .. name)
        if guid then src.store.entries[guid] = nil end
    end
    seed_pinned(src, function() ntfe.seed_inventory(src, networks, interfaces) end)
end

--- Open a key (path relative to the Network key) on the writer.
--- Returns the fd.
function M.open(E, path)
    local r = lcs.open_key(E.src, E.writer, -1, ntfe.NETWORK_KEY .. "\\" .. path)
    assert(r.ret >= 0, "open " .. path .. ": " .. sys.errname(r.errno))
    return r.ret
end

--- Hold the next request of `op` against key `guid` unanswered, from
--- now on. Returns a box whose `req` is set once one is held; pass it
--- to `release`.
function M.hold_next(E, op, guid)
    local box = { op = op }
    E.src:intercept(op, function(_, req)
        if not box.req and req.payload:sub(1, 16) == guid then
            box.req = req
            return lcs.HOLD
        end
    end)
    return box
end

--- Answer a held request honestly and stop holding that op.
function M.release(E, box)
    E.src:intercept(box.op, nil)
    return E.src:release(box.req.id)
end

--- Serve the source (stamped) until `pred()` holds; raises after
--- `timeout_ms` (default 3000).
function M.pump_until(E, pred, timeout_ms)
    local start = M.now_ms(E.vm)
    while not pred() do
        M.pump(E, 10)
        if M.now_ms(E.vm) - start > (timeout_ms or 3000) then
            error("pump_until: condition never held")
        end
    end
end

--- Requests served since `from` that are an NTFE walk beginning: an
--- ENUM_CHILDREN of the Network key itself.
function M.walk_starts(E, from)
    return E.src:served(lcs.OP.ENUM_CHILDREN, from, E.net_guid)
end

--- The key GUID a request names (its first 16 payload bytes).
function M.guid_of(req) return req.payload:sub(1, 16) end

--- Index in `E.src.log` of `req`, or nil.
function M.index_of(E, req)
    for i, r in ipairs(E.src.log) do if r == req then return i end end
    return nil
end

-- ---- traffic verdicts on lo ------------------------------------------

local listeners = {}

--- What the engine does to a TCP connection to 127.0.0.1:`port` (a
--- listener is opened once and kept): "pass", "reject", or "drop".
function M.verdict(vm, port, timeout_ms)
    if not listeners[port] then
        listeners[port] = assert(ntfe.tcp_listen(vm, "127.0.0.1", port))
    end
    local fd, why = ntfe.tcp_connect(vm, "127.0.0.1", port, timeout_ms or 400)
    if fd then
        sys.close(vm, fd)
        local a = ntfe.tcp_accept(vm, listeners[port], 0)
        if a then sys.close(vm, a) end
        return "pass"
    end
    if why == "timeout" then return "drop" end
    if why == sys.E.CONNREFUSED or why == sys.E.HOSTUNREACH then return "reject" end
    return "error " .. tostring(why)
end

-- ---- policies ---------------------------------------------------------

M.PASS_ALL = { all = { Actions = { "PASS" } } }

--- A working policy: PASS in every layer, and the Flow rules given.
function M.policy(flow, extra)
    local p = { RawPacket = M.PASS_ALL, Packet = M.PASS_ALL, Flow = { all = { Actions = { "PASS" } } } }
    for name, rule in pairs(flow or {}) do p.Flow[name] = rule end
    for k, v in pairs(extra or {}) do p[k] = v end
    return p
end

-- ---- FNV-1a-64 collisions ---------------------------------------------
--
-- Distinct names with equal store hashes, found offline by Brent's cycle
-- detection over x -> fnv1a(prefix .. base64(x)) (2^32 steps, seconds of
-- CPU). Valid tag and stream names: no comma, parenthesis, dot or space.
M.COLLIDING = {
    { "c1-_2KSZ5PRxHn", "c1-Vo-7V6-l-Nk" },
    { "c2-MQHcLxTwHLc", "c2-Ep7OpD2LWTg" },
    { "c3-CdAND8f-49l", "c3-uVmDh2wFXTc" },
    { "c4-fp6VTeMrRxd", "c4-r1xaqZn7RFj" },
}
for _, pair in ipairs(M.COLLIDING) do
    assert(pair[1] ~= pair[2] and ntfe.name_hash(pair[1]) == ntfe.name_hash(pair[2]),
        "not a collision: " .. pair[1] .. " / " .. pair[2])
end

return M
