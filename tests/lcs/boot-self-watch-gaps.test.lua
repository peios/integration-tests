-- PKM §5.10.4 — the self-watch refreshes each dirty layer once per
-- delivery. A transaction's commit is one delivery; its batch may name
-- one layer many times — creating its metadata key and writing its
-- three values is four events on one key — and the layer is refreshed
-- once however many of them there were.
--
-- Two witnesses, both counted across the commit alone (every write is
-- made first, then the mark, then the commit):
--
--   * the RSI reads LCS makes of the layer's metadata key for itself —
--     its record (RSI_READ_KEY, for the descriptor) and its values
--     (RSI_QUERY_VALUES);
--   * `lcs:lcs_layer_publish`, which the layer table fires once for
--     every upsert a refresh makes, told apart by the layer name's
--     length (each layer here has a name of a length nobody else uses).
--
-- A commit with one event on the key calibrates both; a commit with
-- several events on it must cost exactly the same. The calibration is
-- not 1: a commit refreshes each layer its log touched once itself
-- (transaction_fd.c), and the self-watch delivery that follows
-- refreshes it once more — two refreshes per commit, whatever the
-- event count. Were either per event, three events would cost more.
--
-- Every key the kernel reads for itself is seeded, so the Machine-root
-- fallback watch is not armed and no bootstrap re-walk (which
-- refreshes every layer) lands inside a commit being counted.
--
-- Belongs in boot-self-watch.test.lua beside "the callback identifies
-- dirty layers and publishes nothing itself".

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")
local hooks = require("helpers.hooks")
local kacs = require("helpers.kacs")

local vm = provium:vm("v", "kernel-only"):boot()

local PUBLISH = "lcs/lcs_layer_publish"

local src = lcs.source(vm)
src:key(lcs.LAYERS_PATH .. "\\base", { sd = lcs.permissive_sd() })
src:key("Machine\\Software\\Test")
src:key("Machine\\System\\KMES")
src:key("Machine\\System\\Network\\TcpIp\\PortReservations")
-- Published layers to write metadata on. Name lengths 6, 7.
src:seed_layer("calibr", { precedence = 0, enabled = 1 })
src:seed_layer("multiev", { precedence = 0, enabled = 1 })
assert(src:register())
src:pump()

local w = vm:spawn_worker()

--- The self-reads of `guid` served since `mark`.
local function self_reads(mark, guid)
    return #src:served(lcs.OP.READ_KEY, mark, guid)
        + #src:served(lcs.OP.QUERY_VALUES, mark, guid)
end

--- The trace lines of upserts for a layer whose name is `len` bytes.
local function publishes(lines, len)
    local n = 0
    for _, l in ipairs(lines or {}) do
        if l:find("lcs_layer_publish:", 1, true) and l:find(" name_len=" .. len .. " ", 1, true)
            and l:find("ret=0", 1, true) then
            n = n + 1
        end
    end
    return n
end

--- What the commit did, for a failure message: the RSI ops served
--- since `mark` and the publish lines.
local function dump(mark, lines)
    local ops = {}
    for i = mark, #src.log do
        local e = src.log[i]
        local name = lcs.lookup_name(e)
        ops[#ops + 1] = (lcs.OP_NAME[e.op] or tostring(e.op)) .. (name and ("(" .. name .. ")") or "")
    end
    return "\n  rsi: " .. table.concat(ops, " ") .. "\n  trace:\n    "
        .. table.concat(lines or {}, "\n    ")
end

--- Inside one transaction run `writes(txn)`, then commit with the
--- trace on. Returns the commit's mark, its publish trace lines, and
--- the commit result.
local function commit_traced(t, writes)
    local txn = assert(lcs.begin_transaction(w))
    writes(txn)
    local started, err = hooks.trace_start(vm, PUBLISH)
    t:assert(started, "trace " .. PUBLISH .. ": " .. tostring(err))
    local mark = src:mark()
    local c = lcs.commit(src, w, txn)
    local lines = hooks.trace_stop(vm, PUBLISH)
    sys.close(w, txn)
    t:assert_eq(c.ret, 0, "the commit: " .. sys.errname(c.errno or 0))
    return mark, lines
end

local function set(t, fd, txn, name, value)
    local r = lcs.set_value(src, w, fd, name, lcs.TYPE.DWORD, lcs.dword(value), { txn_fd = txn })
    t:assert_eq(r.ret, 0, "set " .. name .. " in the transaction: " .. sys.errname(r.errno or 0))
end

test("several metadata events in one commit cost the layer refreshes of one",
    { spec = "PKM *self-watch.layer-refreshed-once-per-delivery" }, function(t)
        local calib = src:lookup(lcs.LAYERS_PATH .. "\\calibr")
        local multi = src:lookup(lcs.LAYERS_PATH .. "\\multiev")
        local cfd = lcs.open_key(src, w, -1, lcs.LAYERS_PATH .. "\\calibr", lcs.KEY_ALL_ACCESS).ret
        local mfd = lcs.open_key(src, w, -1, lcs.LAYERS_PATH .. "\\multiev", lcs.KEY_ALL_ACCESS).ret
        t:assert(cfd >= 0 and mfd >= 0, "both metadata keys open")

        -- One event on `calibr`: what a commit's refreshes cost.
        local m1, l1 = commit_traced(t, function(txn) set(t, cfd, txn, "Enabled", 1) end)
        local reads1, ups1 = self_reads(m1, calib), publishes(l1, 6)
        t:assert(reads1 >= 1 and ups1 >= 1,
            "a one-event commit makes LCS read the layer back and upsert it" .. dump(m1, l1))

        -- Three events on `multiev` in one commit.
        local m3, l3 = commit_traced(t, function(txn)
            set(t, mfd, txn, "Precedence", 0)
            set(t, mfd, txn, "Enabled", 1)
            set(t, mfd, txn, "Precedence", 0)
        end)
        t:assert_eq(self_reads(m3, multi), reads1,
            "three events on one layer cost the reads of one, not three" .. dump(m3, l3))
        t:assert_eq(publishes(l3, 7), ups1,
            "and the upserts of one, not three" .. dump(m3, l3))
        sys.close(w, cfd); sys.close(w, mfd)
    end)

test("creating a layer and writing its three values in one commit costs the refreshes of the create alone",
    { spec = "PKM *self-watch.layer-refreshed-once-per-delivery" }, function(t)
        -- §5.10.4's own example, against a creation with no values as
        -- the calibration. Name lengths 9 and 10.
        local function create(name, values)
            return commit_traced(t, function(txn)
                local made = lcs.create_key(src, w, {
                    path = lcs.LAYERS_PATH .. "\\" .. name, txn_fd = txn,
                })
                t:assert(made.ret >= 0, "create " .. name .. " in the transaction: "
                    .. sys.errname(made.errno or 0))
                if values then
                    set(t, made.ret, txn, "Precedence", 0)
                    set(t, made.ret, txn, "Enabled", 1)
                    local o = lcs.set_value(src, w, made.ret, "Owner", lcs.TYPE.BINARY,
                        kacs.SID.LOCAL_SYSTEM, { txn_fd = txn })
                    t:assert_eq(o.ret, 0, "set Owner in the transaction: "
                        .. sys.errname(o.errno or 0))
                end
                sys.close(w, made.ret)
            end)
        end
        local m0, l0 = create("bareLayer", false)
        local reads0 = self_reads(m0, src:lookup(lcs.LAYERS_PATH .. "\\bareLayer"))
        local ups0 = publishes(l0, 9)
        t:assert(reads0 >= 1 and ups0 >= 1,
            "a created layer is read back and published" .. dump(m0, l0))

        local m4, l4 = create("fullLayer1", true)
        t:assert_eq(self_reads(m4, src:lookup(lcs.LAYERS_PATH .. "\\fullLayer1")), reads0,
            "the create and its three values, four events, cost the reads of the create alone"
            .. dump(m4, l4))
        t:assert_eq(publishes(l4, 10), ups0,
            "and its upserts, not four times as many" .. dump(m4, l4))
    end)
