-- PKM §2.A — the kmes: trace system's diagnostic codes, observed from
-- tracefs while the machinery they describe is driven. The reason
-- values render through their symbolic names, so each test drives one
-- path and expects its documented symbol in the buffer.
--
-- tracefs mounts with a synthesize-ephemeral policy exactly as the
-- stratafs coherency tests do (helpers/hooks).

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local kmes = require("helpers.kmes")
local hooks = require("helpers.hooks")

local vm = provium:vm("v", "kernel-only"):boot()

local CONSUMER_PAGE = 4096

local function traced(t, event, fn)
    t:assert(hooks.trace_start(vm, event), "tracing starts")
    local ok, err = pcall(fn)
    local lines = hooks.trace_stop(vm, event)
    if not ok then error(err, 0) end
    t:assert(lines, "the buffer reads back")
    return lines
end

local function matching(lines, pattern)
    local out = {}
    for _, l in ipairs(lines) do
        if l:match(pattern) then out[#out + 1] = l end
    end
    return out
end

test("attaching a consumer emits a ring-lifecycle marker",
    { spec = "PKM *abi.trace.ring-lifecycle" }, function(t)
        local lines = traced(t, "kmes/kmes_ring_lifecycle", function()
            local ring = kmes.attach(vm, 0)
            t:assert(ring, "a consumer attaches")
            kmes.detach(ring)
        end)
        t:assert(#matching(lines, "kmes_ring_lifecycle:.*reason=consumer%-fd") > 0,
            "a consumer-fd transition is traced")
    end)

test("an oversize emit is an ingress rejection",
    { spec = "PKM *abi.trace.ingress-reject-reasons" }, function(t)
        local lines = traced(t, "kmes/kmes_ingress_reject", function()
            t:assert_eq(kmes.emit(vm, "PIT_TRC", nil, {
                payload_ptr = 0xdead0000,
                payload_len = kmes.DEFAULT.MAX_EVENT_SIZE,
            }).errno, sys.E.NOSPC, "the emit is refused ENOSPC")
        end)
        local hits = matching(lines, "kmes_ingress_reject:.*reason=over%-max")
        t:assert(#hits > 0, "and traced as over-max")
        t:assert(hits[1]:match("ret=%-28"), "carrying the errno")
    end)

test("a payload the validator rejects is traced at the C boundary",
    { spec = "PKM *abi.trace.validate-reasons" }, function(t)
        local lines = traced(t, "kmes/kmes_validate", function()
            t:assert_eq(kmes.emit(vm, "PIT_TRC", "\xc1").errno, sys.E.INVAL,
                "the emit is refused EINVAL")
        end)
        t:assert(#matching(lines, "kmes_validate:.*reason=einval") > 0,
            "and the Rust validator's verdict is traced as einval")
    end)

test("the wake path traces the note and the futex wake",
    { spec = "PKM *abi.trace.wake-reasons" }, function(t)
        -- NOTE fires for the counter increment; FUTEX only when a
        -- blocked consumer is actually woken, so one must be parked.
        local ring = kmes.attach(vm, 0)
        t:assert(ring, "a ring attaches")
        local worker = vm:spawn_worker()
        local lines
        local ok, err = pcall(function()
            local at = worker:syscall(kmes.SYS.ATTACH, {
                args = { 0, 0 }, bufs = { string.rep("\0", 8) }, ptrs = { 1 },
            })
            t:assert(at.ret >= 0, "a sleeper attaches")
            local capacity = string.unpack("<I8", at.out_bufs[1])
            local m = worker:syscall(sys.NR.mmap, 0, 8192 + 2 * capacity,
                sys.PROT.READ | sys.PROT.WRITE, sys.MAP.SHARED, at.ret, 0)
            t:assert(m.ret > 0, "and maps")
            local val = string.unpack("<I4", kmes.peek(worker, m.ret + 128, 4))
            lines = traced(t, "kmes/kmes_wake", function()
                t:assert(kmes.poke(vm, ring.addr + CONSUMER_PAGE, "\x01"),
                    "need_wake set")
                local pending = worker:syscall_async(sys.NR.futex, {
                    args = { m.ret + 128, 0, val, 0, 0, 0 },
                    bufs = { string.pack("<i8i8", 5, 0) }, ptrs = { 3 },
                })
                sys.nanosleep(vm, 0, 50 * 1000 * 1000)
                t:assert_eq(kmes.emit(vm, "PIT_TRC", kmes.PAYLOAD).ret, 0,
                    "emit while it sleeps")
                t:assert_eq(pending:await().ret, 0, "the sleeper wakes")
                kmes.poke(vm, ring.addr + CONSUMER_PAGE, "\x00")
            end)
        end)
        worker:kill(); worker:join()
        kmes.detach(ring)
        if not ok then error(err, 0) end
        t:assert(#matching(lines, "kmes_wake:.*reason=note") > 0,
            "the armed wake is a note")
        t:assert(#matching(lines, "kmes_wake:.*reason=futex") > 0,
            "and the woken sleeper is a futex marker")
    end)

test("a throttled process is traced with its shortfall",
    { spec = "PKM *abi.trace.rate-reasons" }, function(t)
        local entries = {}
        for i = 1, kmes.BATCH_MAX_ENTRIES do
            entries[i] = { type = "PIT_TRC", payload = kmes.PAYLOAD }
        end
        local lines
        kacs.as_dacl_bound(t, vm, function(worker)
            lines = traced(t, "kmes/kmes_rate", function()
                for _ = 1, 300 do
                    if kmes.emit_batch(worker, entries).ret ~= 0 then return end
                end
                t:assert(false, "the bucket never emptied")
            end)
        end, { privs = kmes.PRIV.TCB })
        local hits = matching(lines, "kmes_rate:.*reason=throttle")
        t:assert(#hits > 0, "the EAGAIN is traced as a throttle")
        t:assert(hits[1]:match("requested=256"),
            "naming the reservation that did not fit")
    end)

test("overwrite losses are traced as ring-full drops",
    { spec = "PKM *abi.trace.drop-reasons" }, function(t)
        local content = string.rep("ab", 29956)
        local payload = "\xda" .. string.pack(">I2", #content) .. content
        local lines = traced(t, "kmes/kmes_drop", function()
            for i = 1, 80 do
                t:assert_eq(kmes.emit(vm, "PIT_TRC", payload).ret, 0,
                    "fill " .. i)
            end
        end)
        t:assert(#matching(lines, "kmes_drop:.*reason=ring%-full") > 0,
            "each overwritten event is a ring-full drop")
    end)

test("every traced reason is from the documented vocabulary",
    { spec = "PKM *abi.trace.diagnostic-contract" }, function(t)
        -- The whole point of publishing the codes: a tool reading the
        -- kmes: system decodes reasons against §2.A without knowing
        -- the kernel build. Drive several paths with the whole system
        -- enabled and check every reason= token is a documented one.
        local documented = {
            ["ring-full"] = true, ["tail-resync"] = true,
            ["validate"] = true, ["batch-struct-invalid"] = true,
            ["begin"] = true, ["complete"] = true,
            ["migrate-skip"] = true, ["failed"] = true,
            ["throttle"] = true, ["reconfigure"] = true,
            ["note"] = true, ["futex"] = true,
            ["alloc"] = true, ["free"] = true,
            ["producer-page"] = true, ["consumer-fd"] = true,
            ["over-max"] = true, ["over-cap-half"] = true,
            ["size-overflow"] = true, ["emit-oversize"] = true,
            ["batch-partial"] = true, ["einval"] = true,
        }
        local lines = traced(t, "kmes", function()
            local ring = kmes.attach(vm, 0)
            kmes.poke(vm, ring.addr + CONSUMER_PAGE, "\x01")
            kmes.emit(vm, "PIT_TRC", kmes.PAYLOAD)
            kmes.poke(vm, ring.addr + CONSUMER_PAGE, "\x00")
            kmes.emit(vm, "PIT_TRC", "\xc1")
            kmes.emit(vm, "PIT_TRC", nil, {
                payload_ptr = 0xdead0000,
                payload_len = kmes.DEFAULT.MAX_EVENT_SIZE,
            })
            kmes.detach(ring)
        end)
        local seen = 0
        for _, l in ipairs(lines) do
            local reason = l:match("kmes_[%w_]+:.*reason=([%w%-]+)")
            if reason then
                seen = seen + 1
                t:assert(documented[reason],
                    "undocumented reason symbol: " .. reason)
            end
        end
        t:assert(seen >= 3, "several kmes: events were decoded: " .. seen)
    end)

test("the tail resynchronisation guard",
    { spec = "PKM *ring.tail-resync-guard",
      covered_by = "unreachable",
      skip = "fires only on a corrupt size field read back at the tail, " ..
             "and consumers cannot write the data region (the mmap " ..
             "clears the write upgrade), so no guest can plant the " ..
             "corruption; NOTE: no KUnit case covers it either" }, function(t)
    end)
