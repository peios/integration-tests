-- PKM §2.4 — kmes_emit, the single-event userspace emission syscall:
-- its privilege gate, its validation order, its error vocabulary, and
-- what an accepted event looks like from the consumer side.
--
-- The rate limit has its own file (rate.test.lua): the agent holds
-- SeTcbPrivilege and is exempt, so nothing here consumes from a
-- bucket.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local kmes = require("helpers.kmes")

local vm = provium:vm("v", "kernel-only"):boot()

test("an accepted event returns 0 and is immediately visible",
    { spec = "PKM *emit.success-immediately-visible" }, function(t)
        local ring = kmes.attach(vm, 0)
        t:assert(ring, "a ring attaches")
        local r = kmes.emit(vm, "PIT_VISIBLE", kmes.PAYLOAD)
        t:assert_eq(r.ret, 0, "the emit returns 0: " .. sys.errname(r.errno))
        local events = kmes.of_type(kmes.drain(ring), "PIT_VISIBLE")
        kmes.detach(ring)
        t:assert_eq(#events, 1,
            "and the event is already in the ring, with no flush step")
    end)

test("the caller's bytes are copied verbatim",
    { spec = "PKM *event.emitter-bytes-verbatim" }, function(t)
        -- The payload is opaque to KMES (§2.2): whatever msgpack value
        -- the emitter supplies crosses the ring bit-for-bit, and the
        -- type string does the same.
        local payload = "\x82\xa3odd\xcd\x02\x9a\xa1z\xc3" -- {odd:666, z:true}
        local events = kmes.recording(t, vm, function()
            t:assert_eq(kmes.emit(vm, "PIT_VERBATIM", payload).ret, 0,
                "the emit is accepted")
        end)
        local e = kmes.of_type(events, "PIT_VERBATIM")[1]
        t:assert(e, "the event arrives")
        t:assert_eq(e.raw:sub(e.header_size + 1), payload,
            "the payload bytes after header_size are the caller's, unmodified")
        t:assert_eq(e.raw:sub(kmes.HEADER_BASE + 1, e.header_size),
            "PIT_VERBATIM", "as are the type string's")
    end)

test("the origin class is 0 and not the caller's to choose",
    { spec = "PKM *emit.origin-forced-zero" }, function(t)
        -- There is no origin argument in the signature (§2.A) — the
        -- syscall stamps userspace unconditionally, which is what makes
        -- an event's origin_class trustworthy.
        local events = kmes.recording(t, vm, function()
            t:assert_eq(kmes.emit(vm, "PIT_ORIGIN", kmes.PAYLOAD).ret, 0,
                "the emit is accepted")
        end)
        local e = kmes.of_type(events, "PIT_ORIGIN")[1]
        t:assert(e, "the event arrives")
        t:assert_eq(e.origin, kmes.ORIGIN.USERSPACE,
            "stamped origin 0, where KACS's kernel emitter stamps 2")
    end)

-- ---- privilege gate -------------------------------------------------

test("a caller without SeAuditPrivilege is refused EPERM",
    { spec = "PKM *emit.privilege-gate" }, function(t)
        kacs.as_dacl_bound(t, vm, function(worker)
            local r = kmes.emit(worker, "PIT_UNPRIVILEGED", kmes.PAYLOAD)
            t:assert_eq(r.errno, sys.E.PERM,
                "emit without the privilege: " .. sys.errname(r.errno))
        end, { privs = kmes.PRIV.AUDIT })
    end)

test("holding SeAuditPrivilege disabled is not holding it",
    { spec = "PKM *syscalls.privilege-enabled-and-recorded" }, function(t)
        -- §2.B: held is not enough — the gate wants the privilege
        -- enabled. The worker takes a private token first (RESTRICT
        -- deleting nothing), so disabling on it cannot touch the
        -- agent's own credential.
        kacs.as_dacl_bound(t, vm, function(worker)
            t:assert(kmes.adjust_priv(worker, kacs, kmes.PRIV.AUDIT, false),
                "the worker disables SeAuditPrivilege on its own token")
            local r = kmes.emit(worker, "PIT_DISABLED", kmes.PAYLOAD)
            t:assert_eq(r.errno, sys.E.PERM,
                "emit with it disabled: " .. sys.errname(r.errno))
            t:assert(kmes.adjust_priv(worker, kacs, kmes.PRIV.AUDIT, true),
                "re-enabled")
            t:assert_eq(kmes.emit(worker, "PIT_DISABLED", kmes.PAYLOAD).ret, 0,
                "and the same call is accepted")
        end, { privs = 0 })
    end)

-- ---- validation, in order -------------------------------------------

test("an empty event type is EINVAL",
    { spec = "PKM *emit.empty-type-einval" }, function(t)
        local r = kmes.emit(vm, "", kmes.PAYLOAD, { type_len = 0 })
        t:assert_eq(r.errno, sys.E.INVAL, sys.errname(r.errno))
    end)

test("declared sizes are judged without touching the pointers",
    { spec = "PKM *emit.size-computed-without-deref" }, function(t)
        -- Both calls carry a payload pointer at an unmapped address.
        -- If the kernel computed the size from anything but the length
        -- fields, these would be EFAULT; the errno proves the length
        -- arithmetic runs first, on the declared values alone.
        local r = kmes.emit(vm, "PIT_NODEREF", nil,
            { payload_ptr = 0xdead0000, payload_len = 0xFFFFFFFF })
        t:assert_eq(r.errno, sys.E.INVAL,
            "u32 overflow of 77 + type + payload: " .. sys.errname(r.errno))

        r = kmes.emit(vm, "PIT_NODEREF", nil,
            { payload_ptr = 0xdead0000, payload_len = kmes.DEFAULT.MAX_EVENT_SIZE })
        t:assert_eq(r.errno, sys.E.NOSPC,
            "an oversize declaration: " .. sys.errname(r.errno))
    end)

test("the size ceiling is MaxEventSize exactly",
    { spec = "PKM *emit.max-event-size-enospc" }, function(t)
        -- 77 + type_len + payload_len against the configured maximum,
        -- which on this profile is the compiled-in default (§2.6). At
        -- the bound the event is accepted; one byte past it is ENOSPC.
        local type_name = "PIT_CEILING"
        local exact = kmes.DEFAULT.MAX_EVENT_SIZE - kmes.HEADER_BASE - #type_name
        local payload = "\xda" .. string.pack(">I2", exact - 3) ..
            string.rep("x", exact - 3)
        t:assert_eq(#payload, exact, "the payload fills the event exactly")
        local r = kmes.emit(vm, type_name, payload)
        t:assert_eq(r.ret, 0, "at the bound: accepted: " .. sys.errname(r.errno))
        r = kmes.emit(vm, type_name, nil,
            { payload_ptr = 0xdead0000, payload_len = exact + 1 })
        t:assert_eq(r.errno, sys.E.NOSPC,
            "one past it: " .. sys.errname(r.errno))
    end)

test("an inaccessible pointer is EFAULT, after the size checks",
    { spec = "PKM *emit.errors" }, function(t)
        local r = kmes.emit(vm, "PIT_FAULT", nil,
            { payload_ptr = 0xdead0000, payload_len = 8 })
        t:assert_eq(r.errno, sys.E.FAULT,
            "a bad payload pointer of a plausible size: " .. sys.errname(r.errno))
        r = kmes.emit(vm, "", nil,
            { type_ptr = 0xdead0000, type_len = 8, payload_len = 0 })
        t:assert_eq(r.errno, sys.E.FAULT,
            "a bad type pointer: " .. sys.errname(r.errno))
    end)

test("the event type must be UTF-8",
    { spec = "PKM *emit.type-utf8-einval" }, function(t)
        local r = kmes.emit(vm, "PIT_\xff\xfe", kmes.PAYLOAD)
        t:assert_eq(r.errno, sys.E.INVAL, sys.errname(r.errno))
        t:assert_eq(kmes.emit(vm, "PIT_caf\xc3\xa9", kmes.PAYLOAD).ret, 0,
            "while valid multibyte UTF-8 is an ordinary type")
    end)

test("the payload must be exactly one msgpack value",
    { spec = "PKM *event.payload.exactly-one-value" }, function(t)
        local r = kmes.emit(vm, "PIT_MSGPACK", kmes.PAYLOAD .. "\x01")
        t:assert_eq(r.errno, sys.E.INVAL,
            "trailing bytes after a complete value: " .. sys.errname(r.errno))
        r = kmes.emit(vm, "PIT_MSGPACK", "\xc1")
        t:assert_eq(r.errno, sys.E.INVAL,
            "the never-used 0xc1 type byte: " .. sys.errname(r.errno))
        r = kmes.emit(vm, "PIT_MSGPACK", "\x91\x01\x02")
        t:assert_eq(r.errno, sys.E.INVAL,
            "and a value with trailing garbage: " .. sys.errname(r.errno))
    end)

test("a zero-length payload is not a msgpack value",
    { spec = "PKM *event.payload.empty-rejected" }, function(t)
        local r = kmes.emit(vm, "PIT_EMPTY", nil)
        t:assert_eq(r.errno, sys.E.INVAL, sys.errname(r.errno))
    end)

test("nesting depth is bounded by MaxNestingDepth",
    { spec = "PKM *event.payload.depth-model" }, function(t)
        local max = kmes.DEFAULT.MAX_NESTING_DEPTH
        t:assert_eq(kmes.emit(vm, "PIT_DEPTH", kmes.nested(max)).ret, 0,
            "an empty container at the maximum depth is valid")
        local r = kmes.emit(vm, "PIT_DEPTH", kmes.nested(max + 1))
        t:assert_eq(r.errno, sys.E.INVAL,
            "a non-empty container at it is not: " .. sys.errname(r.errno))
        -- Map keys and values each occupy a child slot: a map whose
        -- value is 31 containers deep reaches depth 32 and passes, one
        -- level more does not.
        t:assert_eq(kmes.emit(vm, "PIT_DEPTH",
            "\x81\xa1k" .. kmes.nested(max - 1)).ret, 0,
            "a map's value sits one deeper than the map")
        r = kmes.emit(vm, "PIT_DEPTH", "\x81\xa1k" .. kmes.nested(max))
        t:assert_eq(r.errno, sys.E.INVAL, sys.errname(r.errno))
    end)

test("a rejected emit writes nothing and consumes no sequence",
    { spec = "PKM *event.payload.reject-writes-nothing" }, function(t)
        -- §2.7: syscall validation completes before the write phase,
        -- so a failure leaves no gap — the two accepted events around
        -- a rejected one abut in the sequence.
        local ring = kmes.attach(vm, 0)
        t:assert(ring, "a ring attaches")
        t:assert_eq(kmes.emit(vm, "PIT_GAP", kmes.PAYLOAD).ret, 0, "first")
        t:assert_eq(kmes.emit(vm, "PIT_GAP", "\xc1").errno, sys.E.INVAL,
            "a rejected emit between them")
        t:assert_eq(kmes.emit(vm, "PIT_GAP", kmes.PAYLOAD).ret, 0, "second")
        local events = kmes.of_type(kmes.drain(ring), "PIT_GAP")
        kmes.detach(ring)
        t:assert_eq(#events, 2, "the ring holds exactly the two accepted")
        t:assert_eq(events[2].sequence, events[1].sequence + 1,
            "with adjacent sequence numbers — the rejection consumed none")
    end)

test("validation stops at the first failing check",
    { spec = "PKM *emit.validation-order" }, function(t)
        -- Each call fails two checks at once; the errno is the earlier
        -- one's. Zero type length beats oversize, oversize beats the
        -- pointer, the pointer beats UTF-8 (the copy faults before the
        -- staged bytes can be judged).
        local r = kmes.emit(vm, "", nil,
            { type_len = 0, payload_ptr = 0xdead0000,
              payload_len = kmes.DEFAULT.MAX_EVENT_SIZE * 2 })
        t:assert_eq(r.errno, sys.E.INVAL,
            "type length before size: " .. sys.errname(r.errno))
        r = kmes.emit(vm, "PIT_ORDER", nil,
            { payload_ptr = 0xdead0000,
              payload_len = kmes.DEFAULT.MAX_EVENT_SIZE * 2 })
        t:assert_eq(r.errno, sys.E.NOSPC,
            "size before the pointer: " .. sys.errname(r.errno))
        r = kmes.emit(vm, "PIT_\xff\xfe", nil,
            { payload_ptr = 0xdead0000, payload_len = 8 })
        t:assert_eq(r.errno, sys.E.FAULT,
            "the copy before UTF-8: " .. sys.errname(r.errno))
    end)
