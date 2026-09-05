-- PKM §5.A — the `lcs:` tracepoint diagnostic codes.
--
-- These tables are a contract with ftrace, perf and eBPF consumers: a
-- tool decodes a record's `op`, `reason`, `stage`, `state`, `cmd` or
-- `field` against §5.A without recompiling against a kernel. What
-- carries that contract into the running kernel is each event's
-- tracefs `format` file, whose `print fmt` line expands the header's
-- symbol table into literal `{ value, "name" }` pairs — so a code that
-- moved would show up there as a different number beside the same
-- name. Every case reads that file and checks the published numbers
-- against it, then drives the machinery and shows the vocabulary being
-- emitted.
--
-- The appendix names the constants (`LCS_OP_LOOKUP`); the tracepoint
-- prints the label the header pairs with each (`"lookup"`), so a case
-- gives both and asserts the number under the label.
--
-- tracefs mounts with a synthesize-ephemeral policy exactly as the KMES
-- and KACS tracepoint suites do (helpers/hooks).

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")
local hooks = require("helpers.hooks")

local vm = provium:vm("v", "kernel-only"):boot()
local MACHINE_ROOT = lcs.guid()
local O_NONBLOCK = 0x800

--- The `{ value, "label" }` table one event's `format` file publishes
--- for one symbolically printed field.
local function symbols(t, event, field)
    local started, err = hooks.trace_start(vm, "lcs/" .. event)
    t:assert(started, "tracing starts on lcs:" .. event .. ": " .. tostring(err))
    local path = hooks.TRACEFS_AT .. "/events/lcs/" .. event .. "/format"
    local fd, e = sys.open(vm, path, sys.O.RDONLY)
    t:assert(fd, "the format file opens: " .. sys.errname(e or 0))
    local chunks = {}
    while true do
        local d = sys.read(vm, fd, 8192)
        if not d or #d == 0 then break end
        chunks[#chunks + 1] = d
    end
    sys.close(vm, fd)
    hooks.trace_stop(vm, "lcs/" .. event)
    local text = table.concat(chunks)
    local at = text:find("__print_symbolic(REC->" .. field .. ",", 1, true)
    t:assert(at, "lcs:" .. event .. " prints " .. field .. " symbolically")
    local tail = text:sub(at + 1)
    local nextcall = tail:find("__print_symbolic", 1, true)
    if nextcall then tail = tail:sub(1, nextcall - 1) end
    local map, count = {}, 0
    for value, label in tail:gmatch("{%s*(%d+)U?%s*,%s*\"([^\"]*)\"%s*}") do
        map[tonumber(value)] = label
        count = count + 1
    end
    return map, count
end

--- Assert a whole published table: every constant sits at its value,
--- and the kernel publishes no code the appendix does not.
local function assert_table(t, event, field, published)
    local map, count = symbols(t, event, field)
    for _, row in ipairs(published) do
        t:assert_eq(map[row[2]], row[3],
            row[1] .. " is " .. row[2] .. " in lcs:" .. event .. "." .. field)
    end
    t:assert_eq(count, #published,
        "and lcs:" .. event .. "." .. field .. " publishes exactly the "
            .. #published .. " codes §5.A lists")
end

--- Enable one lcs: event, run `fn`, and return the buffer's lines.
local function traced(t, event, fn)
    local started, err = hooks.trace_start(vm, "lcs/" .. event)
    t:assert(started, "tracing starts on lcs:" .. event .. ": " .. tostring(err))
    local ran, raised = pcall(fn)
    local lines = hooks.trace_stop(vm, "lcs/" .. event)
    if not ran then error(raised, 0) end
    t:assert(lines, "the trace buffer reads back")
    return lines
end

--- Every value one field carried across the traced lines of one event.
local function field_values(lines, event, field)
    local out = {}
    for _, l in ipairs(lines) do
        local rest = l:match(event .. ": (.*)$")
        if rest then
            local v = rest:match("[ ]?" .. field .. "=([%w%-_]+)")
            if v then out[#out + 1] = v end
        end
    end
    return out
end

--- The property the published table asserts: every symbol the run
--- produced is one the appendix documents, and there was at least one.
local function decodes(t, lines, event, field, published, what)
    local allowed = {}
    for _, row in ipairs(published) do allowed[row[3]] = true end
    local seen = field_values(lines, event, field)
    t:assert(#seen > 0, what .. " produced at least one lcs:" .. event .. " record")
    for _, v in ipairs(seen) do
        t:assert(allowed[v],
            "undocumented " .. field .. " symbol on lcs:" .. event .. ": " .. v)
    end
    return seen
end

local function has(list, want)
    for _, v in ipairs(list) do if v == want then return true end end
    return false
end

--- A Machine source of this case's own, closed however the case ends.
local function with_machine(seed, fn)
    local src = lcs.source(vm, { hives = {
        { name = "Machine", root = MACHINE_ROOT } } })
    src:key("Machine\\Software\\Test")
    if seed then seed(src) end
    assert(src:register())
    src:pump()
    local w = vm:spawn_worker()
    local ok, err = pcall(fn, src, w)
    w:kill(); w:join()
    src:close()
    if not ok then error(err, 0) end
end

-- ---- the published tables --------------------------------------------

local OPS = {
    { "LCS_OP_LOOKUP", 0, "lookup" },
    { "LCS_OP_READ_KEY", 1, "read-key" },
    { "LCS_OP_ENUM_CHILDREN", 2, "enum-children" },
    { "LCS_OP_QUERY_VALUES", 3, "query-values" },
    { "LCS_OP_SET_VALUE", 4, "set-value" },
    { "LCS_OP_DELETE_VALUE", 5, "delete-value" },
    { "LCS_OP_BLANKET_TOMBSTONE", 6, "blanket-tombstone" },
    { "LCS_OP_DROP_KEY", 7, "drop-key" },
    { "LCS_OP_CREATE_ENTRY", 8, "create-entry" },
    { "LCS_OP_HIDE_ENTRY", 9, "hide-entry" },
    { "LCS_OP_DELETE_ENTRY", 10, "delete-entry" },
    { "LCS_OP_CREATE_KEY", 11, "create-key" },
    { "LCS_OP_WRITE_KEY", 12, "write-key" },
    { "LCS_OP_TXN_BEGIN", 13, "txn-begin" },
    { "LCS_OP_TXN_COMMIT", 14, "txn-commit" },
    { "LCS_OP_TXN_ABORT", 15, "txn-abort" },
    { "LCS_OP_FLUSH", 16, "flush" },
    { "LCS_OP_DELETE_LAYER", 17, "delete-layer" },
}

local RESP_REASONS = {
    { "LCS_RESP_ACCEPTED", 0, "accepted" },
    { "LCS_RESP_DESYNC", 1, "desync" },
    { "LCS_RESP_OP_MISMATCH", 2, "op-mismatch" },
    { "LCS_RESP_UNKNOWN_STATUS", 3, "unknown-status" },
    { "LCS_RESP_MALFORMED_PAYLOAD", 4, "malformed-payload" },
    { "LCS_RESP_LATE_COMMIT_FAIL", 5, "late-commit-fail" },
    { "LCS_RESP_LATE_MUTATION_FAIL", 6, "late-mutation-fail" },
    { "LCS_RESP_LATE_BEGIN_FAIL", 7, "late-begin-fail" },
}

local SRC_REASONS = {
    { "LCS_SRC_OPEN", 0, "open" },
    { "LCS_SRC_RELEASE", 1, "release" },
    { "LCS_SRC_MALFORMED", 2, "malformed" },
    { "LCS_SRC_EXPLICIT", 3, "explicit" },
    { "LCS_SRC_MARK_BY_ID", 4, "mark-by-id" },
}

local IF_REASONS = {
    { "LCS_IF_INSERT", 0, "insert" },
    { "LCS_IF_DELIVERED", 1, "delivered" },
    { "LCS_IF_RELEASE", 2, "release" },
}

local ROUTE_OPS = {
    { "LCS_ROUTE_HIVE_NAME", 0, "hive-name" },
    { "LCS_ROUTE_ABSOLUTE_PATH", 1, "absolute-path" },
    { "LCS_ROUTE_SYMLINK_TARGET", 2, "symlink-target" },
}

local REG_DECISIONS = {
    { "LCS_REG_NEW", 0, "new" },
    { "LCS_REG_RESUME_DOWN", 1, "resume-down" },
    { "LCS_REG_COPY", 2, "copy" },
    { "LCS_REG_REPLAY_FAIL", 3, "replay-fail" },
    { "LCS_REG_OVERFLOW_FAIL", 4, "overflow-fail" },
}

local BOOT_STAGES = {
    { "LCS_BOOT_REGISTRY", 0, "registry" },
    { "LCS_BOOT_KMES", 1, "kmes" },
    { "LCS_BOOT_LAYERS", 2, "layers" },
    { "LCS_BOOT_SELF_WATCH", 3, "self-watch" },
    { "LCS_BOOT_COMPLETE", 4, "complete" },
    { "LCS_BOOT_SELF_CONFIG_REFRESH", 5, "self-config-refresh" },
    { "LCS_BOOT_SELF_CONFIG_PARAM_INVALID", 6, "self-config-param-invalid" },
}

local LIMIT_FIELDS = {
    { "LCS_LIM_REQUEST_TIMEOUT_MS", 0, "request_timeout_ms" },
    { "LCS_LIM_TRANSACTION_TIMEOUT_MS", 1, "transaction_timeout_ms" },
    { "LCS_LIM_NOTIFICATION_QUEUE_SIZE", 2, "notification_queue_size" },
    { "LCS_LIM_SYMLINK_DEPTH_LIMIT", 3, "symlink_depth_limit" },
    { "LCS_LIM_MAX_VALUE_SIZE", 4, "max_value_size" },
    { "LCS_LIM_MAX_KEY_DEPTH", 5, "max_key_depth" },
    { "LCS_LIM_MAX_PATH_COMPONENT_LENGTH", 6, "max_path_component_length" },
    { "LCS_LIM_MAX_TOTAL_PATH_LENGTH", 7, "max_total_path_length" },
    { "LCS_LIM_MAX_LAYERS_PER_VALUE", 8, "max_layers_per_value" },
    { "LCS_LIM_MAX_BOUND_TRANSACTIONS_PER_SOURCE", 9,
      "max_bound_transactions_per_source" },
    { "LCS_LIM_MAX_READ_ONLY_TRANSACTIONS_PER_SOURCE", 10,
      "max_read_only_transactions_per_source" },
    { "LCS_LIM_MAX_TOTAL_LAYERS", 11, "max_total_layers" },
    { "LCS_LIM_MAX_REGISTERED_SOURCES", 12, "max_registered_sources" },
    { "LCS_LIM_MAX_HIVES_PER_SOURCE", 13, "max_hives_per_source" },
    { "LCS_LIM_MAX_CONCURRENT_RSI_REQUESTS", 14, "max_concurrent_rsi_requests" },
    { "LCS_LIM_MAX_SCOPE_GUIDS_PER_TOKEN", 15, "max_scope_guids_per_token" },
    { "LCS_LIM_MAX_PRIVATE_LAYERS_PER_TOKEN", 16, "max_private_layers_per_token" },
    { "LCS_LIM_MAX_SUBTREE_WATCH_DEPTH", 17, "max_subtree_watch_depth" },
    { "LCS_LIM_MAX_TRANSACTION_WATCH_EVENT_BURST", 18,
      "max_transaction_watch_event_burst" },
    { "LCS_LIM_ALL", 19, "all" },
}

local AUDIT_TYPES = {
    { "LCS_AUDIT_KEY_OPEN", 0, "key-open" },
    { "LCS_AUDIT_BACKUP_START", 1, "backup-start" },
    { "LCS_AUDIT_BACKUP_COMPLETE", 2, "backup-complete" },
    { "LCS_AUDIT_RESTORE_START", 3, "restore-start" },
    { "LCS_AUDIT_RESTORE_COMPLETE", 4, "restore-complete" },
    { "LCS_AUDIT_VALIDATION_FAILURE", 5, "validation-failure" },
    { "LCS_AUDIT_SELF_CONFIG_INVALID", 6, "self-config-invalid" },
}

local TXN_STATES = {
    { "LCS_TXN_ST_ACTIVE_UNBOUND", 0, "active-unbound" },
    { "LCS_TXN_ST_ACTIVE_BOUND", 1, "active-bound" },
    { "LCS_TXN_ST_COMMITTED", 2, "committed" },
    { "LCS_TXN_ST_ABORTED", 3, "aborted" },
    { "LCS_TXN_ST_TIMED_OUT", 4, "timed-out" },
    { "LCS_TXN_ST_SOURCE_DOWN", 5, "source-down" },
}

local KEY_CMDS = {
    { "LCS_KCMD_NONE", 0, "none" },
    { "LCS_KCMD_SET_VALUE", 1, "set-value" },
    { "LCS_KCMD_DELETE_VALUE", 2, "delete-value" },
    { "LCS_KCMD_BLANKET_TOMBSTONE", 3, "blanket-tombstone" },
    { "LCS_KCMD_DELETE_KEY", 4, "delete-key" },
    { "LCS_KCMD_HIDE_KEY", 5, "hide-key" },
    { "LCS_KCMD_QUERY_VALUE", 6, "query-value" },
    { "LCS_KCMD_QUERY_VALUES_BATCH", 7, "query-values-batch" },
    { "LCS_KCMD_ENUM_VALUES", 8, "enum-values" },
    { "LCS_KCMD_ENUM_SUBKEYS", 9, "enum-subkeys" },
    { "LCS_KCMD_QUERY_KEY_INFO", 10, "query-key-info" },
    { "LCS_KCMD_GET_SECURITY", 11, "get-security" },
    { "LCS_KCMD_SET_SECURITY", 12, "set-security" },
    { "LCS_KCMD_FLUSH", 13, "flush" },
    { "LCS_KCMD_BACKUP", 14, "backup" },
    { "LCS_KCMD_RESTORE", 15, "restore" },
    { "LCS_KCMD_NOTIFY", 16, "notify" },
}

-- ---- the cases -------------------------------------------------------

test("lcs_rsi_request op is the eighteen RSI dispatch verbs",
    { spec = "PKM *lcs-abi.trace.rsi-request-ops" }, function(t)
        assert_table(t, "lcs_rsi_request", "op", OPS)
        local lines = traced(t, "lcs_rsi_request", function()
            with_machine(nil, function(src, w)
                local key = lcs.open_key(src, w, -1, "Machine\\Software\\Test",
                    lcs.KEY_ALL_ACCESS).ret
                lcs.set_value(src, w, key, "V", lcs.TYPE.DWORD, lcs.dword(1))
                lcs.query_value(src, w, key, "V")
                sys.close(w, key)
            end)
        end)
        local seen = decodes(t, lines, "lcs_rsi_request", "op", OPS,
            "a walk and a write")
        t:assert(has(seen, "lookup"), "the walk's lookups decode as LCS_OP_LOOKUP")
        t:assert(has(seen, "set-value"),
            "and the write as LCS_OP_SET_VALUE")
    end)

test("lcs_rsi_response reason is the accept, reject and late-effect outcomes",
    { spec = "PKM *lcs-abi.trace.rsi-response-reasons" }, function(t)
        assert_table(t, "lcs_rsi_response", "reason", RESP_REASONS)
        local lines = traced(t, "lcs_rsi_response", function()
            with_machine(nil, function(src, w)
                local key = lcs.open_key(src, w, -1, "Machine\\Software\\Test",
                    lcs.KEY_ALL_ACCESS).ret
                lcs.set_value(src, w, key, "V", lcs.TYPE.DWORD, lcs.dword(1))
                -- An answer whose status is not a status: the accept-time
                -- reject rung.
                src:intercept(lcs.OP.QUERY_VALUES, function(_, req)
                    return string.pack("<I4I8I2I4", 18, req.id,
                        req.op | lcs.RESPONSE_BIT, 10)
                end)
                lcs.query_value(src, w, key, "V")
                src:intercept(lcs.OP.QUERY_VALUES, nil)
                sys.close(w, key)
            end)
        end)
        local seen = decodes(t, lines, "lcs_rsi_response", "reason",
            RESP_REASONS, "honest and dishonest answers")
        t:assert(has(seen, "accepted"),
            "an answer that matches its request decodes as LCS_RESP_ACCEPTED")
        t:assert(has(seen, "unknown-status"),
            "and a status outside the set as LCS_RESP_UNKNOWN_STATUS")
    end)

test("lcs_source_fd reason is the source-fd lifecycle transitions",
    { spec = "PKM *lcs-abi.trace.source-fd-reasons" }, function(t)
        assert_table(t, "lcs_source_fd", "reason", SRC_REASONS)
        local lines = traced(t, "lcs_source_fd", function()
            local w = vm:spawn_worker()
            local fd = sys.open(w, lcs.DEVICE, sys.O.RDWR | O_NONBLOCK)
            if fd then sys.close(w, fd) end
            w:kill(); w:join()
        end)
        local seen = decodes(t, lines, "lcs_source_fd", "reason", SRC_REASONS,
            "opening and closing the device")
        t:assert(has(seen, "open"),
            "a fresh /dev/pkm_registry fd decodes as LCS_SRC_OPEN")
        t:assert(has(seen, "release"),
            "and its teardown as LCS_SRC_RELEASE")
    end)

test("lcs_in_flight reason is the in-flight request table transitions",
    { spec = "PKM *lcs-abi.trace.in-flight-reasons" }, function(t)
        assert_table(t, "lcs_in_flight", "reason", IF_REASONS)
        local lines = traced(t, "lcs_in_flight", function()
            with_machine(nil, function(src, w)
                local key = lcs.open_key(src, w, -1, "Machine\\Software\\Test",
                    lcs.KEY_ALL_ACCESS).ret
                sys.close(w, key)
            end)
        end)
        local seen = decodes(t, lines, "lcs_in_flight", "reason", IF_REASONS,
            "a round trip")
        t:assert(has(seen, "insert"), "admission decodes as LCS_IF_INSERT")
        t:assert(has(seen, "delivered"),
            "the hand to the source's read() as LCS_IF_DELIVERED")
        t:assert(has(seen, "release"),
            "and completion as LCS_IF_RELEASE")
    end)

test("lcs_route op is the three resolutions the route event describes",
    { spec = "PKM *lcs-abi.trace.route-ops" }, function(t)
        assert_table(t, "lcs_route", "op", ROUTE_OPS)
        local lines = traced(t, "lcs_route", function()
            with_machine(function(s)
                s:symlink("Machine\\Software\\Link", "Machine\\Software\\Test")
            end, function(src, w)
                local key = lcs.open_key(src, w, -1, "Machine\\Software\\Link",
                    lcs.KEY_ALL_ACCESS)
                if key.ret >= 0 then sys.close(w, key.ret) end
            end)
        end)
        local seen = decodes(t, lines, "lcs_route", "op", ROUTE_OPS,
            "a walk through a symlink")
        t:assert(has(seen, "absolute-path") or has(seen, "hive-name"),
            "the path's own resolution is one of the route ops")
    end)

test("lcs_registration decision is the source registration verdicts",
    { spec = "PKM *lcs-abi.trace.registration-decisions" }, function(t)
        -- One table, three events: the two publish verdicts ride on
        -- lcs_registration_publish, the input-copy stage on
        -- lcs_registration_copy, and lcs_source_register carries the
        -- two resume post-publish failures.
        assert_table(t, "lcs_source_register", "decision", REG_DECISIONS)
        assert_table(t, "lcs_registration_publish", "decision", REG_DECISIONS)
        assert_table(t, "lcs_registration_copy", "decision", REG_DECISIONS)
        local function register_and_resume()
            local src = lcs.source(vm, { hives = { { name = "Traced" } } })
            src:key("Traced\\Thing")
            assert(src:register())
            src:pump()
            -- A resume of the same identity is the other publish verdict.
            assert(src:resume())
            src:pump()
            src:close()
        end
        local lines = traced(t, "lcs_registration_publish", register_and_resume)
        local seen = decodes(t, lines, "lcs_registration_publish", "decision",
            REG_DECISIONS, "a registration and a resume")
        t:assert(has(seen, "new"), "a new slot decodes as LCS_REG_NEW")
        t:assert(has(seen, "resume-down"),
            "and taking a Down slot back as LCS_REG_RESUME_DOWN")
        local copied = traced(t, "lcs_registration_copy", function()
            local src = lcs.source(vm, { hives = { { name = "Copied" } } })
            src:key("Copied\\Thing")
            assert(src:register())
            src:pump()
            src:close()
        end)
        local stage = decodes(t, copied, "lcs_registration_copy", "decision",
            REG_DECISIONS, "the registration input copy")
        t:assert(has(stage, "copy"),
            "the input-copy stage decodes as LCS_REG_COPY")
    end)

test("lcs_bootstrap stage is the phases of a bootstrap or self-config refresh",
    { spec = "PKM *lcs-abi.trace.bootstrap-stages" }, function(t)
        assert_table(t, "lcs_bootstrap_refresh", "stage", BOOT_STAGES)
        local lines = traced(t, "lcs_bootstrap_refresh", function()
            with_machine(function(s) s:key(lcs.PARAMS_PATH) end,
                function(src, w) end)
        end)
        local seen = decodes(t, lines, "lcs_bootstrap_refresh", "stage",
            BOOT_STAGES, "a registration")
        t:assert(has(seen, "complete"),
            "a refresh that got all the way decodes as LCS_BOOT_COMPLETE")
    end)

test("lcs_runtime_limits field_id names the parameter a validate reject is about",
    { spec = "PKM *lcs-abi.trace.runtime-limit-fields" }, function(t)
        assert_table(t, "lcs_limits_validate", "field_id", LIMIT_FIELDS)
        local lines = traced(t, "lcs_limits_validate", function()
            with_machine(function(s)
                s:key(lcs.PARAMS_PATH)
                -- Below the range minimum of 4096.
                s:seed_param("MaxValueSize", 100)
            end, function(src, w) end)
        end)
        -- A rejected parameter is retained rather than published, so
        -- the validate event may not fire on this path; what the table
        -- must hold is that nothing outside it is ever printed.
        local seen = field_values(lines, "lcs_limits_validate", "field")
        local allowed = {}
        for _, row in ipairs(LIMIT_FIELDS) do allowed[row[3]] = true end
        for _, v in ipairs(seen) do
            t:assert(allowed[v], "undocumented runtime-limit field: " .. v)
        end
        local pub = traced(t, "lcs_limits_publish", function()
            with_machine(function(s)
                s:key(lcs.PARAMS_PATH)
                s:seed_param("MaxValueSize", 8192)
            end, function(src, w) end)
        end)
        local published = field_values(pub, "lcs_limits_publish", "field")
        t:assert(#published > 0, "a whole-structure publish is traced")
        t:assert(has(published, "all"),
            "as LCS_LIM_ALL, the code §5.A gives the successful publish")
    end)

test("lcs_audit event_type_id names the LCS audit event a record describes",
    { spec = "PKM *lcs-abi.trace.audit-event-types" }, function(t)
        assert_table(t, "lcs_audit_emit", "event_type_id", AUDIT_TYPES)
        local lines = traced(t, "lcs_audit_emit", function()
            -- A registration with an empty configuration key emits the
            -- nineteen self-config-invalid audits of §5.10.3.
            with_machine(function(s) s:key(lcs.PARAMS_PATH) end,
                function(src, w) end)
        end)
        local seen = decodes(t, lines, "lcs_audit_emit", "event", AUDIT_TYPES,
            "a refresh over an empty configuration key")
        t:assert(has(seen, "self-config-invalid"),
            "the retained-parameter audits decode as LCS_AUDIT_SELF_CONFIG_INVALID")
    end)

test("lcs_txn state is the transaction-fd state machine",
    { spec = "PKM *lcs-abi.trace.txn-states" }, function(t)
        assert_table(t, "lcs_txn_begin", "old_state", TXN_STATES)
        assert_table(t, "lcs_txn_commit", "new_state", TXN_STATES)
        -- The txn events print the pair as `old->new` with no field
        -- labels, both decoded through the same table.
        local function transitions(lines, event)
            local out = {}
            for _, l in ipairs(lines) do
                local rest = l:match(event .. ": (.*)$")
                if rest then
                    local from, to = rest:match("([%w%-]+)%->([%w%-]+)")
                    if from then out[#out + 1] = from .. "->" .. to end
                end
            end
            return out
        end
        local allowed = {}
        for _, row in ipairs(TXN_STATES) do allowed[row[3]] = true end
        local lines = traced(t, "lcs_txn_commit", function()
            with_machine(nil, function(src, w)
                local key = lcs.open_key(src, w, -1, "Machine\\Software\\Test",
                    lcs.KEY_ALL_ACCESS).ret
                local txn = assert(lcs.begin_transaction(w))
                lcs.set_value(src, w, key, "T", lcs.TYPE.DWORD, lcs.dword(1),
                    { txn_fd = txn })
                lcs.commit(src, w, txn)
                sys.close(w, txn); sys.close(w, key)
            end)
        end)
        local seen = transitions(lines, "lcs_txn_commit")
        t:assert(#seen > 0, "a commit produced an lcs:lcs_txn_commit record")
        for _, pair in ipairs(seen) do
            local from, to = pair:match("([%w%-]+)%->([%w%-]+)")
            t:assert(allowed[from], "undocumented old_state symbol: " .. from)
            t:assert(allowed[to], "undocumented new_state symbol: " .. to)
        end
        t:assert(has(seen, "active-bound->committed"),
            "a commit is LCS_TXN_ST_ACTIVE_BOUND to LCS_TXN_ST_COMMITTED")
    end)

test("lcs_key_fd cmd is the key-fd ioctl verbs",
    { spec = "PKM *lcs-abi.trace.key-fd-cmds" }, function(t)
        assert_table(t, "lcs_key_ioctl", "cmd", KEY_CMDS)
        local lines = traced(t, "lcs_key_ioctl", function()
            with_machine(nil, function(src, w)
                local key = lcs.open_key(src, w, -1, "Machine\\Software\\Test",
                    lcs.KEY_ALL_ACCESS).ret
                lcs.set_value(src, w, key, "V", lcs.TYPE.DWORD, lcs.dword(1))
                lcs.query_value(src, w, key, "V")
                lcs.query_key_info(src, w, key)
                lcs.enum_values(src, w, key, 0)
                lcs.get_security(src, w, key, lcs.SI.DACL)
                lcs.notify(nil, w, key, lcs.NOTIFY.ALL, false)
                sys.close(w, key)
            end)
        end)
        local seen = decodes(t, lines, "lcs_key_ioctl", "cmd", KEY_CMDS,
            "a battery of key-fd ioctls")
        for _, want in ipairs({ "set-value", "query-value", "query-key-info",
                                "enum-values", "get-security", "notify" }) do
            t:assert(has(seen, want),
                "the " .. want .. " ioctl decodes as its own LCS_KCMD code")
        end
    end)
