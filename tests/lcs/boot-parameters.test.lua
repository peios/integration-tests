-- PKM §5.10.3 — the nineteen operational parameters LCS reads from
-- `Machine\System\Registry\`, their validation, and what hot-swapping
-- one does to in-flight operations.
--
-- Two guests, because the active configuration is kernel-global and a
-- hot-swap in one case would be the starting state of the next.
--
--  * `vm` is the *defaults* guest. Nothing here ever writes a value
--    that validates, so every refresh reports all nineteen parameters
--    as missing, and each report carries the row §5.10.3 tabulates: the
--    expected type, the valid range, and the value being retained —
--    which, nothing having been applied, is the compiled-in default.
--  * `live` is the *hot-swap* guest, where values are written and their
--    effect observed. Each case there writes the parameters it depends
--    on rather than assuming a default, and no two cases share one.
--
-- Both use one Machine root GUID throughout: a Down slot keeps its hive
-- identity (§5.8.2), so a second root for the same name would be
-- ESTALE, while the same root lets every case bring its own source with
-- its own seeded database.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")
local kmes = require("helpers.kmes")
local token = require("helpers.token")

local vm = provium:vm("v", "kernel-only"):boot()
local live = provium:vm("live", "kernel-only"):boot()

local DEFAULTS_ROOT = lcs.guid()
local LIVE_ROOT = lcs.guid()

-- Not in helpers/sys: the errno a source round trip that outlives
-- RequestTimeoutMs returns.
local ETIMEDOUT = 110

--- §5.10.3's table: name, default, range minimum, range maximum, and
--- the citation naming the row.
local PARAMS = {
    { "RequestTimeoutMs", 30000, 1000, 600000, "request-timeout-ms" },
    { "TransactionTimeoutMs", 30000, 1000, 600000, "transaction-timeout-ms" },
    { "NotificationQueueSize", 256, 16, 65536, "notification-queue-size" },
    { "SymlinkDepthLimit", 16, 1, 64, "symlink-depth-limit" },
    { "MaxValueSize", 1048576, 4096, 67108864, "max-value-size" },
    { "MaxKeyDepth", 512, 32, 4096, "max-key-depth" },
    { "MaxPathComponentLength", 255, 64, 1024, "max-path-component-length" },
    { "MaxTotalPathLength", 16383, 1024, 65535, "max-total-path-length" },
    { "MaxLayersPerValue", 128, 1, 1024, "max-layers-per-value" },
    { "MaxBoundTransactionsPerSource", 16, 1, 256,
      "max-bound-transactions-per-source" },
    { "MaxReadOnlyTransactionsPerSource", 16, 1, 256,
      "max-read-only-transactions-per-source" },
    { "MaxTotalLayers", 1024, 16, 65536, "max-total-layers" },
    { "MaxRegisteredSources", 32, 1, 256, "max-registered-sources" },
    { "MaxHivesPerSource", 64, 1, 1024, "max-hives-per-source" },
    { "MaxConcurrentRSIRequests", 256, 8, 4096, "max-concurrent-rsi-requests" },
    { "MaxScopeGUIDsPerToken", 8, 1, 256, "max-scope-guids-per-token" },
    { "MaxPrivateLayersPerToken", 16, 1, 256, "max-private-layers-per-token" },
    { "MaxSubtreeWatchDepth", 0, 0, 4096, "max-subtree-watch-depth" },
    { "MaxTransactionWatchEventBurst", 4096, 256, 65536,
      "max-transaction-watch-event-burst" },
}

--- A Machine source with `Machine\System\Registry` present, seeded by
--- `seed`, registered while a KMES ring records. Returns the
--- `LCS_SELF_CONFIG_INVALID` payloads keyed by parameter name, and the
--- list in emission order. The bootstrap refresh reads and validates
--- the whole key, so one registration is one full pass over the
--- nineteen.
local function refresh_audits(t, guest, root, seed)
    local src = lcs.source(guest, { hives = { { name = "Machine", root = root } } })
    src:key(lcs.PARAMS_PATH)
    if seed then seed(src) end
    local events
    local ok, err = pcall(function()
        events = kmes.recording(t, guest, function()
            assert(src:register())
            src:pump()
        end)
    end)
    src:close()
    if not ok then error(err, 0) end
    local list = kmes.of_type(events, "LCS_SELF_CONFIG_INVALID")
    local by_name = {}
    for _, e in ipairs(list) do
        by_name[e.payload.configuration_name] = e.payload
    end
    return by_name, list
end

--- A registered source on the hot-swap guest, plus a worker and an fd
--- on `Machine\System\Registry` to write parameters through and one on
--- `Machine\Software\Test` to observe them with. `fn(ctx)` receives
--- `{ src, w, registry, test }`.
local function with_live(t, seed, fn)
    local src = lcs.source(live, { hives = { { name = "Machine", root = LIVE_ROOT } } })
    src:key("Machine\\Software\\Test")
    src:key(lcs.PARAMS_PATH)
    if seed then seed(src) end
    assert(src:register())
    src:pump()
    local w = live:spawn_worker()
    local ok, err = pcall(function()
        local reg = lcs.open_key(src, w, -1, lcs.PARAMS_PATH, lcs.KEY_ALL_ACCESS)
        assert(reg.ret >= 0, "open the parameters key: " .. sys.errname(reg.errno or 0))
        local test = lcs.open_key(src, w, -1, "Machine\\Software\\Test",
            lcs.KEY_ALL_ACCESS)
        assert(test.ret >= 0, "open the test key: " .. sys.errname(test.errno or 0))
        fn({ src = src, w = w, registry = reg.ret, test = test.ret })
        sys.close(w, test.ret)
        sys.close(w, reg.ret)
    end)
    w:kill(); w:join()
    src:close()
    if not ok then error(err, 0) end
end

--- Write one parameter live and let the self-watch hot-swap it.
local function set_param(ctx, name, value)
    return lcs.set_value(ctx.src, ctx.w, ctx.registry, name, lcs.TYPE.DWORD,
        lcs.dword(value))
end

-- ---- the table ------------------------------------------------------

test("LCS reads exactly nineteen parameters, and they live under Machine\\System\\Registry",
    { spec = "PKM *param.nineteen-under-registry-key" }, function(t)
        -- Every parameter is reported once per refresh while unset, so
        -- one refresh over an empty key names the whole set.
        local by_name, list = refresh_audits(t, vm, DEFAULTS_ROOT)
        t:assert_eq(#list, 19,
            "a refresh over an empty key reports nineteen parameters")
        for _, p in ipairs(PARAMS) do
            t:assert(by_name[p[1]], p[1] .. " is one of the nineteen")
            t:assert_eq(by_name[p[1]].configuration_parent_path,
                "Machine\\System\\Registry",
                p[1] .. " is read from Machine\\System\\Registry")
        end
    end)

test("all nineteen are REG_DWORD, and a value of another type is refused",
    { spec = "PKM *param.all-are-reg-dword" }, function(t)
        local by_name = refresh_audits(t, vm, DEFAULTS_ROOT)
        for _, p in ipairs(PARAMS) do
            t:assert_eq(by_name[p[1]].expected_type, lcs.TYPE.DWORD,
                p[1] .. " is expected as REG_DWORD")
        end
        -- A REG_SZ written where a REG_DWORD belongs is the wrong type,
        -- which is invalid: the value is ignored and reported.
        local wrong = refresh_audits(t, vm, DEFAULTS_ROOT, function(src)
            src:seed_param("MaxValueSize", lcs.sz("8192"), lcs.TYPE.SZ)
        end)
        t:assert_eq(wrong["MaxValueSize"].received_kind, "wrong_type",
            "a REG_SZ MaxValueSize is reported as the wrong type")
        t:assert_eq(wrong["MaxValueSize"].received_type, lcs.TYPE.SZ,
            "naming the type that arrived")
        t:assert_eq(wrong["MaxValueSize"].retained_value, 1048576,
            "and the previously active value is retained")
    end)

for _, p in ipairs(PARAMS) do
    local name, default, min, max = p[1], p[2], p[3], p[4]
    test(("%s: default %d, range %d-%d"):format(name, default, min, max),
        { spec = "PKM *param." .. p[5] }, function(t)
            local by_name = refresh_audits(t, vm, DEFAULTS_ROOT)
            local a = by_name[name]
            t:assert(a, name .. " is read from Machine\\System\\Registry")
            t:assert_eq(a.expected_type, lcs.TYPE.DWORD, name .. " is a REG_DWORD")
            t:assert_eq(a.expected_min, min, name .. " has minimum " .. min)
            t:assert_eq(a.expected_max, max, name .. " has maximum " .. max)
            t:assert_eq(a.received_kind, "missing", name .. " is unset here")
            t:assert_eq(a.retained_value, default,
                name .. " runs on its compiled-in default of " .. default
                    .. " until the registry says otherwise")
        end)
end

test("unknown values under the key are ignored",
    { spec = "PKM *param.unknown-values-ignored" }, function(t)
        -- Not one of the nineteen, so not a parameter: no audit names
        -- it, nothing about the refresh changes, and there are still
        -- exactly nineteen.
        local by_name, list = refresh_audits(t, vm, DEFAULTS_ROOT, function(src)
            src:seed_param("NotAParameter", 12345)
            src:seed_param("MaxValueSizeExtra", 99)
        end)
        t:assert_eq(#list, 19, "the refresh still reports exactly nineteen")
        t:assert(not by_name["NotAParameter"],
            "an unknown value is ignored, not reported")
        t:assert(not by_name["MaxValueSizeExtra"],
            "and a name that merely resembles one is still unknown")
        t:assert_eq(by_name["MaxValueSize"].retained_value, 1048576,
            "and the parameter it resembles is untouched")
    end)

-- ---- validation -----------------------------------------------------

test("a valid value is hot-swapped into the configuration new operations use",
    { spec = "PKM *param.validation.valid-is-hot-swapped" }, function(t)
        with_live(t, nil, function(ctx)
            t:assert_eq(set_param(ctx, "MaxValueSize", 4096).ret, 0,
                "MaxValueSize is written")
            local over = lcs.set_value(ctx.src, ctx.w, ctx.test, "Over",
                lcs.TYPE.BINARY, string.rep("x", 8192))
            t:assert_eq(over.errno, sys.E.NOSPC,
                "and bounds one value's data at 4096 bytes for a new operation")
            local under = lcs.set_value(ctx.src, ctx.w, ctx.test, "Under",
                lcs.TYPE.BINARY, string.rep("x", 4096))
            t:assert_eq(under.ret, 0, "while a value inside it is still written")
        end)
    end)

test("an out-of-range value is ignored and the previously active one kept",
    { spec = "PKM *param.validation.invalid-is-ignored-previous-kept" },
    function(t)
        with_live(t, nil, function(ctx)
            t:assert_eq(set_param(ctx, "MaxValueSize", 8192).ret, 0,
                "a valid MaxValueSize of 8192 is applied")
            local audits = kmes.recording(t, live, function()
                -- 100 is below the range minimum of 4096.
                assert(set_param(ctx, "MaxValueSize", 100).ret == 0,
                    "the registry accepts the write: the source enforces no kernel semantics")
            end)
            local a
            for _, e in ipairs(kmes.of_type(audits, "LCS_SELF_CONFIG_INVALID")) do
                if e.payload.configuration_name == "MaxValueSize" then a = e.payload end
            end
            t:assert(a, "an LCS_SELF_CONFIG_INVALID event names the parameter")
            t:assert_eq(a.received_kind, "dword_out_of_range", "saying what was wrong")
            t:assert_eq(a.received_u32, 100, "and the value that arrived")
            t:assert_eq(a.retained_value, 8192, "and the value being retained")
            local still = lcs.set_value(ctx.src, ctx.w, ctx.test, "Still",
                lcs.TYPE.BINARY, string.rep("x", 6000))
            t:assert_eq(still.ret, 0,
                "the last known-good 8192 is still what is in force")
        end)
    end)

test("values are never clamped or silently corrected",
    { spec = "PKM *param.validation.never-clamped" }, function(t)
        with_live(t, nil, function(ctx)
            t:assert_eq(set_param(ctx, "MaxValueSize", 8192).ret, 0,
                "a valid MaxValueSize of 8192 is applied")
            t:assert_eq(set_param(ctx, "MaxValueSize", 100).ret, 0,
                "a write of 100 succeeds: the registry stores what was written")
            local q = lcs.query_value(ctx.src, ctx.w, ctx.registry, "MaxValueSize")
            t:assert_eq(q.data, lcs.dword(100),
                "and the registry shows 100, not the range minimum")
            -- Clamping to the minimum would put 4096 in force; retaining
            -- the last known-good leaves 8192. A 6000-byte value tells
            -- them apart.
            local mid = lcs.set_value(ctx.src, ctx.w, ctx.test, "Mid",
                lcs.TYPE.BINARY, string.rep("x", 6000))
            t:assert_eq(mid.ret, 0,
                "LCS refuses to use it rather than clamping it to 4096")
        end)
    end)

test("the hard ceilings on path length and key depth match the range maxima",
    { spec = "PKM *param.hard-ceilings-match-range-maxima" }, function(t)
        with_live(t, nil, function(ctx)
            t:assert_eq(set_param(ctx, "MaxTotalPathLength", 65535).ret, 0,
                "MaxTotalPathLength is configured to its range maximum")
            t:assert_eq(set_param(ctx, "MaxKeyDepth", 4096).ret, 0,
                "MaxKeyDepth is configured to its range maximum")
            -- A hard ceiling below the range maximum would refuse these.
            local parts, total = { "Machine" }, 7
            while total + 256 <= 65535 do
                parts[#parts + 1] = string.rep("a", 255); total = total + 256
            end
            parts[#parts + 1] = string.rep("b", 65535 - total - 1)
            local at_max = table.concat(parts, "\\")
            t:assert_eq(#at_max, 65535, "a path of exactly 65535 bytes")
            local walked = lcs.open_key(ctx.src, ctx.w, -1, at_max,
                lcs.RIGHT.KEY_READ)
            t:assert_eq(walked.errno, sys.E.NOENT,
                "is validated and walked: no hard ceiling below 65535 exists")
            local over = lcs.open_key(nil, ctx.w, -1, at_max .. "c",
                lcs.RIGHT.KEY_READ)
            t:assert_eq(over.errno, sys.E.NAMETOOLONG,
                "and 65536 is refused, so the two never conflict")

            local deep = { "Machine" }
            for _ = 2, 4096 do deep[#deep + 1] = "a" end
            local at_depth = lcs.open_key(ctx.src, ctx.w, -1,
                table.concat(deep, "\\"), lcs.RIGHT.KEY_READ)
            t:assert_eq(at_depth.errno, sys.E.NOENT,
                "a 4096-component path is validated and walked")
            deep[#deep + 1] = "a"
            local past = lcs.open_key(nil, ctx.w, -1, table.concat(deep, "\\"),
                lcs.RIGHT.KEY_READ)
            t:assert_eq(past.errno, sys.E.INVAL,
                "and 4097 is refused at the configured maximum")
        end)
    end)

-- ---- what a configured value does ------------------------------------

test("RequestTimeoutMs bounds a source round trip",
    { spec = "PKM *param.request-timeout-ms" }, function(t)
        with_live(t, function(src) src:seed_param("RequestTimeoutMs", 1000) end,
            function(ctx)
                t:assert_eq(set_param(ctx, "RequestTimeoutMs", 1000).ret, 0,
                    "RequestTimeoutMs is 1000 ms")
                local test_key = ctx.src:lookup("Machine\\Software\\Test")
                ctx.src:intercept(lcs.OP.QUERY_VALUES, function(_, req)
                    if req.payload:sub(1, 16) == test_key then return lcs.HOLD end
                    return nil
                end)
                local started = os.time()
                local q = lcs.query_value(ctx.src, ctx.w, ctx.test, "Never")
                local elapsed = os.time() - started
                ctx.src:intercept(lcs.OP.QUERY_VALUES, nil)
                t:assert_eq(q.errno, ETIMEDOUT,
                    "a round trip the source never answers times out")
                t:assert(elapsed <= 3,
                    "after about the configured second, not the 30 the default gives: "
                        .. elapsed .. "s")
                for _, id in ipairs(ctx.src:held_ids()) do
                    ctx.src:release(id, lcs.STATUS.OK, string.pack("<I4I4", 0, 0))
                end
            end)
    end)

test("NotificationQueueSize bounds the events queued for one watcher",
    { spec = "PKM *param.notification-queue-size" }, function(t)
        with_live(t, function(src) src:seed_param("NotificationQueueSize", 16) end,
            function(ctx)
                t:assert_eq(set_param(ctx, "NotificationQueueSize", 16).ret, 0,
                    "NotificationQueueSize is 16 entries")
                t:assert_eq(lcs.notify(nil, ctx.w, ctx.test, lcs.NOTIFY.ALL, false).ret,
                    0, "a watcher is armed on the test key")
                for i = 1, 20 do
                    lcs.set_value(ctx.src, ctx.w, ctx.test, "V" .. i,
                        lcs.TYPE.DWORD, lcs.dword(i))
                end
                local ev = lcs.read_events(nil, ctx.w, ctx.test)
                t:assert_eq(#ev.events, 16,
                    "sixteen records are queued for it, not twenty")
                local overflowed = false
                for _, e in ipairs(ev.events) do
                    overflowed = overflowed or e.type == lcs.WATCH.OVERFLOW
                end
                t:assert(overflowed,
                    "and the queue overflowed at sixteen, as REG_WATCH_OVERFLOW says")
            end)
    end)

-- ---- hot-swap and in-flight operations -------------------------------

test("configuration is published as one structure",
    { spec = "PKM *param.hot-swap.published-as-one-structure" }, function(t)
        -- One refresh is one publication covering all nineteen fields:
        -- the eighteen it did not find are reported and retained in the
        -- same pass that applies the nineteenth, and the structure that
        -- results is what the next reader copies.
        local seed = function(src) src:seed_param("MaxLayersPerValue", 64) end
        local by_name, list = refresh_audits(t, live, LIVE_ROOT, seed)
        t:assert_eq(#list, 18,
            "one refresh reported the eighteen it could not apply")
        t:assert(not by_name["MaxLayersPerValue"],
            "the nineteenth validated and was applied in the same pass")
        local again = refresh_audits(t, live, LIVE_ROOT)
        t:assert_eq(again["MaxLayersPerValue"].retained_value, 64,
            "and the published structure carries it: a reader takes a complete copy")
        for _, p in ipairs(PARAMS) do
            t:assert(again[p[1]],
                p[1] .. " is part of the same structure, published with it")
        end
    end)

test("a syscall snapshots the configuration once and threads the snapshot through",
    { spec = "PKM *param.hot-swap.syscall-snapshots-once" }, function(t)
        with_live(t, function(src) src:seed_param("RequestTimeoutMs", 30000) end,
            function(ctx)
                t:assert_eq(set_param(ctx, "RequestTimeoutMs", 30000).ret, 0,
                    "the operation starts with RequestTimeoutMs at 30000")
                local test_key = ctx.src:lookup("Machine\\Software\\Test")
                ctx.src:intercept(lcs.OP.QUERY_VALUES, function(_, req)
                    if req.payload:sub(1, 16) == test_key then return lcs.HOLD end
                    return nil
                end)
                local w2 = live:spawn_worker()
                local ok, err = pcall(function()
                    local fd = lcs.open_key(ctx.src, w2, -1,
                        "Machine\\Software\\Test", lcs.KEY_ALL_ACCESS).ret
                    local pending = lcs.query_value_async(w2, fd, "Never")
                    ctx.src:pump()
                    t:assert_eq(#ctx.src:held_ids(), 1,
                        "a query is in flight, held by the source")
                    -- Hot-swap under it: new work would get 1000 ms.
                    t:assert_eq(set_param(ctx, "RequestTimeoutMs", 1000).ret, 0,
                        "RequestTimeoutMs is hot-swapped to 1000 while it is in flight")
                    sys.nanosleep(live, 3, 0)
                    ctx.src:pump(50)
                    t:assert_eq(#ctx.src:held_ids(), 1,
                        "the in-flight operation still uses the 30000 it snapshotted")
                    ctx.src:intercept(lcs.OP.QUERY_VALUES, nil)
                    ctx.src:release(ctx.src:held_ids()[1], lcs.STATUS.OK,
                        string.pack("<I4I4", 0, 0))
                    local r = pending:await()
                    t:assert_eq(r.errno, sys.E.NOENT,
                        "and completes on the answer rather than timing out")
                    sys.close(w2, fd)
                end)
                w2:kill(); w2:join()
                ctx.src:intercept(lcs.OP.QUERY_VALUES, nil)
                if not ok then error(err, 0) end
            end)
    end)

test("some call sites read a live value rather than a snapshot",
    { spec = "PKM *param.hot-swap.some-call-sites-read-live-values" }, function(t)
        -- reg_begin_transaction's timeout is one of the three §5.10.3
        -- names (the bound-transaction cap and the in-flight request cap
        -- are the others). It contacts no source and no caller threads a
        -- snapshot into it: the deadline it arms is whatever the live
        -- configuration says at the moment of the call.
        with_live(t, nil, function(ctx)
            t:assert_eq(set_param(ctx, "TransactionTimeoutMs", 1000).ret, 0,
                "TransactionTimeoutMs is hot-swapped to 1000 ms")
            local txn = assert(lcs.begin_transaction(ctx.w))
            local bind = lcs.set_value(ctx.src, ctx.w, ctx.test, "InTxn",
                lcs.TYPE.DWORD, lcs.dword(1), { txn_fd = txn })
            t:assert_eq(bind.ret, 0, "a transaction is opened and bound")
            sys.nanosleep(live, 2, 0)
            local st = lcs.txn_status(nil, ctx.w, txn)
            t:assert_eq(st.state, lcs.TXN.TIMED_OUT,
                "and the hot-swapped second is the lifetime it was given")
            t:assert_eq(st.terminal_errno, ETIMEDOUT, "with ETIMEDOUT recorded")
            sys.close(ctx.w, txn)
        end)
    end)

-- ---- security --------------------------------------------------------

test("an unprivileged process cannot change any of this",
    { spec = "PKM *param.security.unprivileged-cannot-change" }, function(t)
        -- The Machine hive root descriptor — SYSTEM and Administrators
        -- KEY_ALL_ACCESS, Authenticated Users KEY_READ, all
        -- container-inheritable — is what Machine\System\Registry
        -- inherits, so the key is created live rather than seeded with
        -- a descriptor of its own.
        local src = lcs.source(live, { hives = {
            { name = "Machine", root = LIVE_ROOT, sd = lcs.machine_root_sd() } } })
        assert(src:register())
        src:pump()
        local w = live:spawn_worker()
        local ok, err = pcall(function()
            local sysk = lcs.create_key(src, w, { path = "Machine\\System" })
            assert(sysk.ret >= 0, "create Machine\\System: "
                .. sys.errname(sysk.errno or 0))
            local reg = lcs.create_key(src, w,
                { parent_fd = sysk.ret, path = "Registry" })
            assert(reg.ret >= 0, "create Machine\\System\\Registry: "
                .. sys.errname(reg.errno or 0))
            t:assert_eq(lcs.set_value(src, w, reg.ret, "MaxValueSize",
                lcs.TYPE.DWORD, lcs.dword(8192)).ret, 0,
                "SYSTEM writes a parameter through it")
            token.as_principal(t, live, {}, function(w2)
                local readable = lcs.open_key(src, w2, -1, lcs.PARAMS_PATH,
                    lcs.RIGHT.KEY_READ)
                t:assert(readable.ret >= 0,
                    "an ordinary principal is an Authenticated User and gets KEY_READ: "
                        .. sys.errname(readable.errno or 0))
                if readable.ret >= 0 then sys.close(w2, readable.ret) end
                local writable = lcs.open_key(src, w2, -1, lcs.PARAMS_PATH,
                    lcs.RIGHT.SET_VALUE)
                t:assert_eq(writable.errno, sys.E.ACCES,
                    "and cannot open it for KEY_SET_VALUE: it cannot change any of this")
                if writable.ret >= 0 then sys.close(w2, writable.ret) end
            end)
            sys.close(w, reg.ret); sys.close(w, sysk.ret)
        end)
        w:kill(); w:join()
        src:close()
        if not ok then error(err, 0) end
    end)
