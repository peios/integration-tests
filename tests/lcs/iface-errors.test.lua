-- PKM §5.5.5 — The error model: the ordinary -1/errno convention, the
-- fact that the errno is the whole interface, and the reading of
-- ETIMEDOUT that says an operation may or may not have happened.
--
-- The source seeds RequestTimeoutMs at its minimum and
-- MaxConcurrentRSIRequests at its floor of eight, so the "the deadline
-- expired before a slot was reserved" half of ETIMEDOUT is reachable
-- inside a test's lifetime.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")

local vm = provium:vm("v", "kernel-only"):boot()

-- helpers/sys names most errnos; this section needs one it does not.
local ETIMEDOUT = 110

local src = lcs.source(vm, { hives = { { name = "Machine" } } })
src:seed_param("RequestTimeoutMs", 1000)
src:seed_param("MaxConcurrentRSIRequests", 8)
local TEST = src:key("Machine\\Software\\Test")
src:value(TEST, "Detail", lcs.TYPE.DWORD, lcs.dword(1))
assert(src:register())
src:pump()

local w = vm:spawn_worker()

local function open_test(t)
    local r = lcs.open_key(src, w, -1, "Machine\\Software\\Test", lcs.KEY_ALL_ACCESS)
    t:assert(r.ret >= 0, "open Test: " .. sys.errname(r.errno or 0))
    return r.ret
end

test("syscalls and ioctls follow the ordinary Linux convention: -1 and errno",
    { spec = "PKM *errno.minus-one-and-errno" }, function(t)
        local ok = lcs.open_key(src, w, -1, "Machine\\Software\\Test", lcs.RIGHT.KEY_READ)
        t:assert(ok.ret >= 0, "success is a non-negative return, the fd itself")
        sys.close(w, ok.ret)

        local missing = lcs.open_key(src, w, -1, "Machine\\Software\\Absent", lcs.RIGHT.KEY_READ)
        t:assert_eq(missing.ret, -1, "a failing syscall returns -1")
        t:assert_eq(missing.errno, sys.E.NOENT, "with the errno beside it")

        local fd = open_test(t)
        local bad = lcs.query_value(src, w, fd, "Absent")
        t:assert_eq(bad.ret, -1, "a failing ioctl returns -1 too")
        t:assert_eq(bad.errno, sys.E.NOENT, "with the errno beside it")
        local good = lcs.query_value(src, w, fd, "Detail")
        t:assert_eq(good.ret, 0, "and a succeeding ioctl returns zero")
        sys.close(w, fd)
    end)

test("the errno is the whole interface: source-specific detail is never surfaced",
    { spec = "PKM *errno.no-source-detail-surfaced" }, function(t)
        local fd = open_test(t)
        local detail = "sector 42 unreadable; controller reset pending"
        src:intercept(lcs.OP.QUERY_VALUES, function()
            return lcs.STATUS.STORAGE_ERROR, detail
        end)
        -- Sentinel-filled output buffers and a structure whose bytes are
        -- known, so anything the source said would have to show up here.
        local args = string.pack("<I4I4I8I4I4i4I4I8I8I4I4I8",
            6, 0, 0, 0, 4096, -1, 256, 0, 0, 0, 0, 0)
        local data_buf, layer_buf = string.rep("\xA5", 4096), string.rep("\xA5", 256)
        local r = lcs.raw_call(src, w, {
            nr = sys.NR.ioctl, args = { fd, lcs.IOC.QUERY_VALUE, 0 }, ptr_slot = 2,
            struct = args,
            children = { { offset = 8, bytes = "Detail" }, { offset = 32, bytes = data_buf },
                         { offset = 56, bytes = layer_buf } },
        })
        t:assert_eq(r.ret, -1, "the source's storage error fails the ioctl")
        t:assert_eq(r.errno, sys.E.IO, "as a bare EIO")
        t:assert(not r.args_out:find("sector", 1, true),
            "the source's explanation is nowhere in the argument structure")
        t:assert_eq(r.child_out[2], data_buf,
            "and not one byte of it reached the data buffer")
        t:assert_eq(r.child_out[3], layer_buf, "nor the layer buffer")

        -- The same failure through a different call is the same errno:
        -- there is no channel by which the two could be told apart.
        local b = lcs.query_values_batch(src, w, fd)
        t:assert_eq(b.errno, sys.E.IO, "a batch read of the same key is the same bare EIO")
        src:intercept(lcs.OP.QUERY_VALUES, nil)
        sys.close(w, fd)
    end)

test("ETIMEDOUT before a slot was reserved means no request was sent at all",
    { spec = "PKM *errno.etimedout-before-dispatch-means-nothing-was-sent" }, function(t)
        -- Fill every one of the eight in-flight RSI slots by holding the
        -- lookups, then ask for a ninth. The ninth waits for a slot, the
        -- deadline expires, and the source never hears about it.
        src:intercept(lcs.OP.LOOKUP, function() return lcs.HOLD end)
        local holders = {}
        for i = 1, 8 do
            local wi = vm:spawn_worker()
            holders[i] = { w = wi,
                p = lcs.open_key_async(wi, -1, "Machine\\Software", lcs.RIGHT.KEY_READ) }
        end
        src:pump()
        t:assert_eq(#src:held_ids(), 8, "eight lookups are in flight and unanswered")

        local mark = src:mark()
        local w9 = vm:spawn_worker()
        local p9 = lcs.open_key_async(w9, -1, "Machine\\Software", lcs.RIGHT.KEY_READ)
        src:pump()
        t:assert_eq(#src.log, mark - 1, "no ninth request reached the source")

        local r9 = p9:await()
        t:assert_eq(r9.errno, ETIMEDOUT,
            "the ninth caller gets ETIMEDOUT: " .. sys.errname(r9.errno or 0))
        t:assert_eq(#src.log, mark - 1,
            "and still nothing was sent — this ETIMEDOUT did not happen at the source")
        w9:kill(); w9:join()

        src:intercept(lcs.OP.LOOKUP, nil)
        for _, id in ipairs(src:held_ids()) do src:release(id) end
        for _, h in ipairs(holders) do
            src:pump()
            h.p:await()
            h.w:kill(); h.w:join()
        end
    end)
