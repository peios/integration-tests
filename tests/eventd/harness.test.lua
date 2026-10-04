-- The eventd testset's own machinery, asserted directly, so that a fault in
-- `helpers.eventd` shows up here rather than as a puzzling failure in a
-- chapter file. Every route a chapter test uses to put a record in or get
-- one out is exercised once: a KMES event, a log datagram and a metric
-- datagram in; evctl and the host-side sqlite copy out; a live registry
-- change; a seeded configuration; and a restart of the service.
--
-- None of this cites the TRM. The anchors are the chapter files' to prove.

local eventd = require("helpers.eventd")
local peinit = require("helpers.peinit")
peinit.claim(2) -- one file-scope VM, plus the seeded boot

local vm = eventd.boot({ name = "ev-harness" })

test("eventd answers on its query socket once the boot is done", {}, function(t)
    local rows = eventd.rows(vm, "EVENTS " .. eventd.T.startup .. " TAKE 5")
    t:assert(#rows >= 1, "a startup record is queryable: " .. #rows)
    t:assert_eq(rows[1].event_type, eventd.T.startup, "and it is the startup type")
end)

test("a KMES event emitted by the agent comes back through evctl", {}, function(t)
    local tag = eventd.marker("ev")
    local r = eventd.emit(vm, "pt.harness", { tag = tag, n = 7 })
    t:assert_eq(r.ret, 0, "kmes_emit succeeded (errno " .. tostring(r.errno) .. ")")
    local rows = eventd.wait_rows(vm,
        'EVENTS pt.harness WHERE tag == "' .. tag .. '" SINCE 10m ago',
        function(rs) return #rs == 1 end)
    t:assert_eq(#rows, 1, "exactly the one event")
    t:assert_eq(rows[1].n, 7, "its payload field decoded: " .. json.encode(rows[1]))
end)

test("a log datagram sent to the log socket comes back through evctl", {}, function(t)
    local origin = eventd.marker("log")
    local r = eventd.send_log(vm, { origin = origin, is_error = false, message = "hello harness" })
    t:assert_eq(r.ret, #eventd.msgpack({ origin = origin, is_error = false, message = "hello harness" }),
        "sendto took the whole datagram (errno " .. tostring(r.errno) .. ")")
    local rows = eventd.wait_rows(vm, "LOGS FROM " .. origin .. " SINCE 10m ago",
        function(rs) return #rs == 1 end)
    t:assert_eq(rows[1].message, "hello harness", "the message round-tripped")
end)

test("a metric datagram sent to the metric socket comes back through evctl", {}, function(t)
    local name = eventd.marker("m")
    local r = eventd.send_metric(vm, { name = name, type = "gauge", value = 42 })
    t:assert(r.ret and r.ret > 0, "sendto succeeded (errno " .. tostring(r.errno) .. ")")
    local rows = eventd.wait_rows(vm, "METRIC " .. name .. " SINCE 10m ago",
        function(rs) return #rs == 1 end)
    t:assert_eq(rows[1].value, 42, "the sample round-tripped: " .. json.encode(rows[1]))
end)

test("the host-side sqlite copy reads a store's schema", {}, function(t)
    local schema = eventd.schema(vm, eventd.DB.logs)
    t:assert(schema.logs, "logs.db has a logs table; objects: " .. json.encode(schema))
    local shards = eventd.shards(vm)
    t:assert(#shards >= 1, "the event store holds at least one shard")
    local ev = eventd.schema(vm, shards[1])
    t:assert(ev.events, "a shard has an events table")
end)

test("a live registry change is applied and recorded as a config change", {}, function(t)
    eventd.set(vm, "LogRetentionDays", "dword:13"):assert_ok()
    local rows = eventd.wait_rows(vm,
        "EVENTS " .. eventd.T.config_change .. " SINCE 10m ago",
        function(rs)
            for _, r in ipairs(rs) do
                if json.encode(r):find("LogRetentionDays", 1, true) then return true end
            end
            return false
        end)
    t:assert(#rows >= 1, "a config change record names the key")
    eventd.unset(vm, "LogRetentionDays")
end)

test("a restart brings up a new eventd that still answers", {}, function(t)
    local before = eventd.pid(vm)
    t:assert(before, "eventd has a pid")
    local after = eventd.restart(vm)
    t:assert(after and after ~= before, "a new process: " .. tostring(before) .. " -> " .. tostring(after))
    local rows = eventd.rows(vm, "EVENTS " .. eventd.T.startup .. " SINCE 10m ago")
    t:assert(#rows >= 2, "both starts recorded a startup event: " .. #rows)
end)

test("a seeded value is in force from the first start", {}, function(t)
    local seeded = eventd.boot({
        name = "ev-harness-seed",
        config = { { name = "LogRetentionDays", type = "dword", data = 11 } },
    })
    local r = seeded:run("reg get '" .. eventd.KEY .. "' LogRetentionDays")
    t:assert(r.stdout:find("11", 1, true), "the seed applied before Phase 2: " .. r.stdout .. r.stderr)
    t:assert(eventd.query(seeded, "EVENTS TAKE 1").ok, "and eventd started with it")
end)
