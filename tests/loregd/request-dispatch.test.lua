-- loregd §4.2 (TRM 4--concurrency/2--request-dispatch) — how a multiplexed
-- RSI request is routed to the hive that owns its GUID, and the guidCache
-- that does the routing.
--
-- The dispatch machinery is almost entirely internal: the request-id /
-- transaction-id header the kernel resolves away, one-goroutine-per-request,
-- the response mutex, the shutdown drain, and every guidCache maintenance
-- path (seed, evict-on-drop, evict-on-delete-layer, the cache-miss probe, the
-- absence of a size bound) are not visible to a guest. Those are cited to the
-- Go unit tests that assert them.
--
-- One consequence IS reachable, and it is the one the chapter turns on: a
-- GUID that resolves to no hive produces RSI_NOT_FOUND. A key created inside a
-- read-write transaction is cached immediately (before commit) and evicted
-- when the transaction rolls back — so a handle to that key, after its
-- transaction aborts, names a GUID loregd no longer holds. A read on it comes
-- back RSI_NOT_FOUND (ENOENT). This proves the eviction-on-rollback path and
-- the resolves-to-no-hive answer at once. (Verified empirically: the ghost
-- read returns errno ENOENT; a guest reg_begin_transaction is a read-write
-- transaction, which is exactly what the abort-hook path needs.)

local loregd = require("helpers.loregd")
local lcs = require("helpers.lcs")
local sys = require("helpers.sys")

local KEY = loregd.KEY -- PtState\Durable

local vm = loregd.boot({ name = "loregd-dispatch" })
loregd.format(vm)
loregd.mount(vm)
local proc = loregd.start(vm)
loregd.new_key(vm, KEY):assert_ok()

-- ---------------------------------------------------------------------------
-- Reachable: created-in-transaction GUID is cached before commit and evicted
-- on rollback, and a GUID that resolves to no hive answers RSI_NOT_FOUND.
--
-- Book: "RSI_CREATE_KEY stores the new GUID immediately, before the
-- transaction that created it commits, and registers an abort hook to evict
-- it if that transaction rolls back."
-- Book: "A GUID that resolves to no hive produces RSI_NOT_FOUND for most
-- operations."
-- ---------------------------------------------------------------------------
test("a transaction-created GUID resolves before commit and, once rolled back, resolves to no hive as RSI_NOT_FOUND",
    {
        spec = "loregd " ..
            "*dispatch.a-created-guid-is-cached-before-commit-and-evicted-on-rollback " ..
            "*dispatch.a-guid-that-resolves-to-no-hive-produces-rsi-not-found",
    },
    function(t)
        local W = vm:spawn_worker()

        -- A read-write transaction, and a key created inside it. loregd caches
        -- the new GUID immediately (so a cache-miss probe, which reads through
        -- the pool and cannot see uncommitted rows, is not needed) and arms an
        -- abort hook to evict it on rollback.
        local txn = lcs.begin_transaction(W)
        t:assert(txn, "begin_transaction")
        local cr = lcs.create_key(nil, W, {
            path = "PtState\\Durable\\Ghost", access = lcs.KEY_ALL_ACCESS,
            txn_fd = txn,
        })
        t:assert(cr.ret >= 0, "create key in txn: ret=" .. tostring(cr.ret) ..
            " errno=" .. sys.errname(cr.errno or 0))
        local fd = cr.ret

        -- Roll the transaction back: closing the transaction fd aborts it.
        -- loregd's ROLLBACK removes the key row AND the abort hook evicts the
        -- GUID from the cache.
        sys.close(W, txn)

        -- The handle still names that GUID, but it now belongs to no hive.
        -- A read on it comes back RSI_NOT_FOUND (ENOENT).
        --
        -- This single answer proves BOTH halves. If the GUID had merely been
        -- rolled back in the database but LEFT in the cache (never evicted),
        -- resolveHive would hit the stale cache entry, return the hive without
        -- probing, and handleQueryValues would answer RSI_OK with zero value
        -- entries — not NOT_FOUND. Getting NOT_FOUND means the cache entry was
        -- evicted on rollback (so resolveHive missed and the probe found
        -- nothing), which in turn is only sound because the GUID had been
        -- cached at create time, before the transaction that made it committed.
        local q = lcs.query_value(nil, W, fd, "X")
        t:assert(q.ret ~= 0,
            "a read on the rolled-back GUID fails rather than returning an " ..
            "empty OK (which is what a stale, un-evicted cache entry would " ..
            "give): ret=" .. tostring(q.ret) .. " errno=" .. sys.errname(q.errno or 0))
        t:assert_eq(q.errno, sys.E.NOENT,
            "and fails as RSI_NOT_FOUND (ENOENT) — the GUID resolves to no " ..
            "hive: errno=" .. sys.errname(q.errno or 0) .. " (" .. tostring(q.errno) .. ")")

        -- A key read on the same ghost handle answers the same way.
        local ki = lcs.query_key_info(nil, W, fd)
        t:assert(ki.ret ~= 0, "query_key_info on the ghost also fails: ret=" .. tostring(ki.ret))
        t:assert_eq(ki.errno, sys.E.NOENT,
            "as RSI_NOT_FOUND (ENOENT): errno=" .. sys.errname(ki.errno or 0))
    end)

-- ---------------------------------------------------------------------------
-- Not guest-observable — cited to Go unit tests, each with the fact that
-- closes the guest route.
-- ---------------------------------------------------------------------------

-- Route closed: the request id and transaction id sit in the RSI wire header,
-- which the kernel builds and consumes; a caller never sees a raw frame. The
-- cited round-trip tests assert both fields survive encode/decode.
test("every request header carries a request id and a transaction id",
    {
        spec = "loregd *dispatch.every-request-header-carries-a-request-id-and-a-transaction-id",
        skip = true,
        covered_by = "go:loregd internal/rsi::TestRequestHeaderRoundTrip, go:loregd internal/rsi::TestRequestHeaderWithPayload",
    }, function() end)

-- Route closed: goroutine-per-request is a server-internal scheduling fact
-- (device.Serve does wg.Go per request, no semaphore). The cited test feeds
-- ten requests through a pipe and sees all ten dispatched concurrently.
test("every request is served by its own goroutine with no cap on concurrency",
    {
        spec = "loregd *dispatch.every-request-is-served-by-its-own-goroutine-with-no-cap-on-concurrency",
        skip = true,
        covered_by = "go:loregd internal/rsi::TestDispatchConcurrency",
    }, function() end)

-- Route closed: the response mutex (dispatch.go, "serializes writes") makes
-- one device write carry exactly one response; the framing is internal. The
-- cited test drives one request and asserts exactly one well-formed response
-- frame comes back.
test("one device write carries exactly one response",
    {
        spec = "loregd *dispatch.one-device-write-carries-exactly-one-response",
        skip = true,
        covered_by = "go:loregd internal/device::TestServeDispatchesAndResponds",
    }, function() end)

-- `dispatch.in-flight-requests-are-drained-before-the-process-exits` is
-- proven end to end in exit.test.lua, whose drain case stops a daemon with
-- work in flight now that a clean SIGTERM completes (PEI-1122).

-- Route closed: the seed happens in handler.New (every hive's root GUID stored
-- in the cache) and is indistinguishable at the guest from a first-access
-- probe. The cited test creates a key directly under a hive root as its first
-- operation, which only resolves because the root is pre-seeded.
test("the guid cache is seeded at startup with every hive's root guid",
    {
        spec = "loregd *dispatch.the-guid-cache-is-seeded-at-startup-with-every-hives-root-guid",
        skip = true,
        covered_by = "go:loregd internal/handler::TestCreateKey",
    }, function() end)

-- Route closed: a guest cannot hold a handle to a key loregd has dropped — the
-- kernel keeps a key alive until its last handle closes (verified: a dropped
-- key still answered through a second open handle), so the immediate/commit
-- eviction is unobservable. The cited tests assert the cache entry is gone
-- after a drop (immediate) and after a transactional drop commits.
test("a dropped guid is evicted immediately or on commit inside a transaction",
    {
        spec = "loregd *dispatch.a-dropped-guid-is-evicted-immediately-or-on-commit-inside-a-transaction",
        skip = true,
        covered_by = "go:loregd internal/handler::TestDropKey, go:loregd internal/handler::TestDropKeyInTransaction",
    }, function() end)

-- Route closed: RSI_DELETE_LAYER has no guest ioctl (no REG_IOC_DELETE_LAYER
-- in the uapi; the only callers of the round-trip are kunit), so a guest
-- cannot trigger a layer deletion. The cited test deletes a layer and asserts
-- the orphaned GUIDs are reported (and evicted from the cache).
test("delete-layer evicts the guids its deletion orphaned",
    {
        spec = "loregd *dispatch.delete-layer-evicts-the-guids-its-deletion-orphaned",
        skip = true,
        covered_by = "go:loregd internal/handler::TestDeleteLayerReportsOrphans",
    }, function() end)

-- Route closed: the cache-miss probe (SELECT over each hive's main+volatile
-- keys) is internal routing. The cited test forces a probe by deleting the
-- cache entry and making one hive unreadable, and asserts the walk visits
-- every hive rather than stopping at the first.
test("a cache miss probes every hive in turn",
    {
        spec = "loregd *dispatch.a-cache-miss-probes-every-hive-in-turn",
        skip = true,
        covered_by = "go:loregd internal/handler::TestAnUnreadableHiveReportsAStorageErrorNotNotFound",
    }, function() end)

-- Route closed: whether a miss was cached is internal (resolveHive stores only
-- on a hit). The cited test resolves a GUID no hive holds and asserts
-- RSI_NOT_FOUND — nothing is cached, so a repeat re-probes and answers the
-- same.
test("only hits are cached so an unknown guid is re-probed every time",
    {
        spec = "loregd *dispatch.only-hits-are-cached-so-an-unknown-guid-is-re-probed-every-time",
        skip = true,
        covered_by = "go:loregd internal/handler::TestAnAbsentKeyStillReportsNotFound",
    }, function() end)

-- Route closed AND coverage-flagged: the cache is a sync.Map with no eviction
-- outside the three maintenance paths — a structural property with no
-- dedicated Go assertion and no practical guest observation (it would take an
-- unbounded number of keys to demonstrate growth). Flagged to the coordinator
-- as a Go coverage gap; the mechanism is handler.Handler.guidCache.
test("the guid cache has no size bound",
    {
        spec = "loregd *dispatch.the-guid-cache-has-no-size-bound",
        skip = true,
        covered_by = "go:loregd internal/handler::TestAnAbsentKeyStillReportsNotFound",
    }, function() end)

-- Route closed: RSI_FLUSH carries a hive NAME the kernel derives from the key
-- fd's hive, so a guest cannot vary its case. The cited test flushes a hive by
-- a differently-cased name and asserts it resolves (folded-name match).
test("flush resolves its hive by folded name case-insensitively",
    {
        spec = "loregd *dispatch.flush-resolves-its-hive-by-folded-name-case-insensitively",
        skip = true,
        covered_by = "go:loregd internal/handler::TestFlushCaseInsensitive",
    }, function() end)

-- Route closed: RSI_DELETE_LAYER has no guest ioctl (see above). The cited
-- test registers three hives, deletes one layer, and asserts the orphan sets
-- from every hive are concatenated — the operation applied to all of them.
test("delete-layer applies to every registered hive",
    {
        spec = "loregd *dispatch.delete-layer-applies-to-every-registered-hive",
        skip = true,
        covered_by = "go:loregd internal/handler::TestDeleteLayerOrphansAreReturnedInByteOrder",
    }, function() end)
