-- §5.8.4, Validation: LCS validates every response before using it,
-- and the split between malformed *data* — EIO to the caller, an audit
-- event naming one of twelve classes, and a source that stays alive —
-- and malformed *protocol*, which is treated as a crash.
--
-- The dishonest answers here are built field by field rather than by
-- corrupting bytes, so each case names exactly one thing wrong.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")
local kmes = require("helpers.kmes")

local vm = provium:vm("v", "kernel-only"):boot()

local PATH = "Machine\\Software\\Test"

local src = lcs.source(vm)
local TEST_KEY = src:key(PATH)
local CHILD = src:key(PATH .. "\\Child")
src:value(TEST_KEY, "V", lcs.TYPE.DWORD, lcs.dword(1))
src:key(lcs.LAYERS_PATH)
assert(src:register())
src:pump()
local w = vm:spawn_worker()
local FD = assert(lcs.open_key(src, w, -1, PATH, lcs.KEY_ALL_ACCESS).ret)

local function s4(x) return string.pack("<s4", x) end

--- An RSI_LOOKUP response body: path entries, then the per-GUID key
--- metadata block. Every field is caller-supplied so a case can get
--- exactly one of them wrong.
local function lookup_body(entries, metas)
    local out = { string.pack("<I4", #entries) }
    for _, e in ipairs(entries) do
        out[#out + 1] = s4(e.layer or "base") .. string.pack("<I1", e.hidden and 1 or 0) ..
            (e.guid or lcs.NULL_GUID) .. string.pack("<I8", e.seq or 1)
    end
    out[#out + 1] = string.pack("<I4", #metas)
    for _, m in ipairs(metas) do
        out[#out + 1] = (m.guid or lcs.NULL_GUID) .. s4(m.sd or lcs.permissive_sd()) ..
            string.pack("<I1I1I8", m.volatile and 1 or 0, m.symlink and 1 or 0, m.lwt or 0)
    end
    return table.concat(out)
end

--- An RSI_QUERY_VALUES response body: value entries, then blankets.
local function values_body(rows, blankets)
    local out = { string.pack("<I4", #rows) }
    for _, v in ipairs(rows) do
        out[#out + 1] = s4(v.name) .. s4(v.layer or "base") ..
            string.pack("<I4", v.type) .. s4(v.data or "") .. string.pack("<I8", v.seq or 1)
    end
    out[#out + 1] = string.pack("<I4", #(blankets or {}))
    for _, b in ipairs(blankets or {}) do
        out[#out + 1] = s4(b.layer) .. string.pack("<I8", b.seq or 1)
    end
    return table.concat(out)
end

local function lookup_name(req) return (string.unpack("<s4", req.payload, 17)) end

--- Answer `op` with `responder` for the duration of `call`, recording
--- the audit events it produced. Returns the call's result and the
--- validation classes named by the LCS_SOURCE_VALIDATION_FAILURE
--- events, in order.
local function under(t, op, responder, call)
    src:intercept(op, responder)
    local result
    local events = kmes.recording(t, vm, function() result = call() end)
    src:intercept(op, nil)
    local classes = {}
    for _, e in ipairs(kmes.of_type(events, "LCS_SOURCE_VALIDATION_FAILURE")) do
        classes[#classes + 1] = e.payload and e.payload.validation_class
    end
    return result, classes, events
end

--- A lookup responder that mangles only the walk's final component.
local function bad_test_lookup(body_for)
    return function(self, req)
        if lookup_name(req) ~= "Test" then return nil end
        return lcs.STATUS.OK, body_for()
    end
end

local function open_test()
    local r = lcs.open_key(src, w, -1, PATH, lcs.RIGHT.KEY_READ)
    if r.ret >= 0 then sys.close(w, r.ret) end
    return r
end

local function still_serving(t)
    local r = lcs.query_value(src, w, FD, "V")
    t:assert_eq(r.ret, 0, "and the source is still Active: an honest call after it succeeds")
end

-- Malformed data -------------------------------------------------------

test("a Security Descriptor that will not parse is malformed data: EIO, an audit event, and a live source",
    { spec = { "PKM *source.validate.every-response-is-validated", "PKM *source.validate.malformed-data-returns-eio", "PKM *source.validate.malformed-data-emits-an-audit-event", "PKM *source.validate.malformed-data-keeps-the-source-alive", "PKM *source.validate.descriptors-must-parse" } }, function(t)
        local r, classes, events = under(t, lcs.OP.LOOKUP,
            bad_test_lookup(function()
                return lookup_body({ { guid = TEST_KEY } }, { { guid = TEST_KEY, sd = "\1\2\3\4" } })
            end), open_test)
        t:assert_eq(r.errno, sys.E.IO, "the request returns EIO to its caller")
        t:assert_eq(classes[1], "malformed_security_descriptor",
            "and the audit event names the validation class")
        local ev = kmes.of_type(events, "LCS_SOURCE_VALIDATION_FAILURE")[1]
        t:assert(ev, "an LCS_SOURCE_VALIDATION_FAILURE was emitted")
        t:assert(ev.payload.source_slot ~= nil, "naming the source slot")
        t:assert_eq(ev.payload.op_code, lcs.OP.LOOKUP, "and the operation code")
        still_serving(t)
    end)

test("names must be valid for their kind, and the class says which kind",
    { spec = "PKM *source.validate.names-must-be-valid" }, function(t)
        local _, layer_classes = under(t, lcs.OP.LOOKUP,
            bad_test_lookup(function()
                return lookup_body({ { guid = TEST_KEY, layer = "bad\\layer" } },
                    { { guid = TEST_KEY } })
            end), open_test)
        t:assert_eq(layer_classes[1], "malformed_layer_name", "a layer name field")

        local _, child_classes = under(t, lcs.OP.ENUM_CHILDREN, function()
            local body = { string.pack("<I4", 1) }
            body[#body + 1] = s4("bad\\child") .. string.pack("<I4", 1) ..
                s4("base") .. string.pack("<I1", 0) .. CHILD .. string.pack("<I8", 1)
            body[#body + 1] = string.pack("<I4", 1) .. CHILD .. s4(lcs.permissive_sd()) ..
                string.pack("<I1I1I8", 0, 0, 0)
            return lcs.STATUS.OK, table.concat(body)
        end, function() return lcs.enum_subkeys(src, w, FD, 0) end)
        t:assert_eq(child_classes[1], "malformed_key_name", "a child-name field")

        local r, value_classes = under(t, lcs.OP.QUERY_VALUES, function()
            return lcs.STATUS.OK,
                values_body({ { name = "bad\0name", type = lcs.TYPE.DWORD, data = lcs.dword(1) } })
        end, function() return lcs.query_value(src, w, FD, "V") end)
        t:assert_eq(value_classes[1], "malformed_value_name", "a value-name field")
        t:assert_eq(r.errno, sys.E.IO, "each of them EIO")
        still_serving(t)
    end)

test("a sequence number at or above the next one LCS would allocate cannot be real",
    { spec = "PKM *source.validate.sequence-number-checks" }, function(t)
        local r, classes = under(t, lcs.OP.LOOKUP,
            bad_test_lookup(function()
                return lookup_body({ { guid = TEST_KEY, seq = 0x0FFFFFFFFFFFFFFF } },
                    { { guid = TEST_KEY } })
            end), open_test)
        t:assert_eq(r.errno, sys.E.IO, "EIO")
        t:assert_eq(classes[1], "future_sequence_number",
            "a sequence LCS has not allocated yet is rejected")
        still_serving(t)
    end)

test("a response payload of the wrong shape, or with trailing bytes, is malformed data",
    { spec = "PKM *source.validate.payload-shape-checks" }, function(t)
        local r, classes = under(t, lcs.OP.LOOKUP, function(self, req)
            if lookup_name(req) ~= "Test" then return nil end
            local st, body = self:dispatch(req)
            return st, body .. "\0\0"
        end, open_test)
        t:assert_eq(r.errno, sys.E.IO, "trailing bytes after a complete lookup payload: EIO")
        t:assert_eq(classes[1], "malformed_response_payload", "malformed_response_payload")

        -- The rule holds for a status-only payload too: RSI_SET_VALUE
        -- defines none at all, so one byte is one byte too many.
        local r2, classes2 = under(t, lcs.OP.SET_VALUE,
            function() return lcs.STATUS.OK, "\0" end,
            function() return lcs.set_value(src, w, FD, "W", lcs.TYPE.DWORD, lcs.dword(2)) end)
        t:assert_eq(r2.errno, sys.E.IO, "a status-only response with a payload: EIO")
        t:assert_eq(classes2[1], "malformed_response_payload", "malformed_response_payload")
        still_serving(t)
    end)

test("a per-GUID metadata block must cover exactly the GUIDs the entries name",
    { spec = "PKM *source.validate.metadata-closure-checks" }, function(t)
        local unrelated = lcs.guid()
        local cases = {
            { "missing", {} },
            { "nil", { { guid = lcs.NULL_GUID } } },
            { "duplicated", { { guid = TEST_KEY }, { guid = TEST_KEY } } },
            { "unreferenced", { { guid = TEST_KEY }, { guid = unrelated } } },
        }
        for _, case in ipairs(cases) do
            local r, classes = under(t, lcs.OP.LOOKUP,
                bad_test_lookup(function()
                    return lookup_body({ { guid = TEST_KEY } }, case[2])
                end), open_test)
            t:assert_eq(r.errno, sys.E.IO, "a " .. case[1] .. " metadata entry: EIO")
            t:assert_eq(classes[1], "malformed_key_metadata",
                "a " .. case[1] .. " metadata entry: malformed_key_metadata")
        end
        still_serving(t)
    end)

test("a HIDDEN entry must carry an all-zero GUID",
    { spec = "PKM *source.validate.hidden-entry-carries-a-zero-guid" }, function(t)
        local r, classes = under(t, lcs.OP.LOOKUP,
            bad_test_lookup(function()
                return lookup_body({ { guid = TEST_KEY, hidden = true } }, { { guid = TEST_KEY } })
            end), open_test)
        t:assert_eq(r.errno, sys.E.IO, "a HIDDEN entry naming a key is refused: EIO")
        t:assert_eq(classes[1], "malformed_response_payload", "malformed_response_payload")
        still_serving(t)
    end)

test("value payloads are checked for type, tombstone shape and size",
    { spec = "PKM *source.validate.value-payload-checks" }, function(t)
        local r, classes = under(t, lcs.OP.QUERY_VALUES, function()
            return lcs.STATUS.OK,
                values_body({ { name = "V", type = lcs.TYPE.TOMBSTONE, data = "data" } })
        end, function() return lcs.query_value(src, w, FD, "V") end)
        t:assert_eq(r.errno, sys.E.IO, "a tombstone carrying data: EIO")
        t:assert_eq(classes[1], "malformed_value_payload", "malformed_value_payload")

        local r2, classes2 = under(t, lcs.OP.QUERY_VALUES, function()
            return lcs.STATUS.OK, values_body({ { name = "V", type = 12, data = "" } })
        end, function() return lcs.query_value(src, w, FD, "V") end)
        t:assert_eq(r2.errno, sys.E.IO, "a value type that does not exist: EIO")
        t:assert_eq(classes2[1], "malformed_value_payload", "malformed_value_payload")
        still_serving(t)
    end)

test("an RSI_DELETE_LAYER orphan list may not carry a nil or duplicated GUID",
    { spec = "PKM *source.validate.orphan-list-checks" }, function(t)
        local fd, errno = lcs.create_layer(src, w, "OrphanList")
        t:assert(fd, "a layer to delete: " .. sys.errname(errno or 0))
        local r, classes = under(t, lcs.OP.DELETE_LAYER, function()
            return lcs.STATUS.OK, string.pack("<I4", 1) .. lcs.NULL_GUID
        end, function()
            local d = lcs.delete_key(src, w, fd)
            src:pump(100)
            return d
        end)
        t:assert_eq(r.errno, sys.E.IO, "EIO")
        t:assert_eq(classes[1], "malformed_delete_layer_orphan_list",
            "malformed_delete_layer_orphan_list")
        still_serving(t)
    end)

test("a status code outside the defined vocabulary is malformed data",
    { spec = "PKM *source.validate.unknown-status-code" }, function(t)
        local r, classes = under(t, lcs.OP.LOOKUP, function(self, req)
            if lookup_name(req) ~= "Test" then return nil end
            return 99, ""
        end, open_test)
        t:assert_eq(r.errno, sys.E.IO, "status 99 is not in the vocabulary: EIO")
        t:assert_eq(classes[1], "unknown_rsi_status_code", "unknown_rsi_status_code")
        still_serving(t)
    end)

-- The asymmetry ---------------------------------------------------------

test("a request may carry trailing fields a source does not recognise; a response may not",
    { spec = { "PKM *source.validate.requests-may-carry-trailing-fields", "PKM *source.validate.payload-shape-checks" } }, function(t)
        -- RSI_SET_VALUE's payload ends with expected_sequence, the
        -- conditional-write field. A source built before it existed
        -- parses up to the sequence, skips the rest using total_len,
        -- and answers — which is exactly what the request convention
        -- promises such a source may do.
        local saw_trailing = false
        local r = select(1, under(t, lcs.OP.SET_VALUE, function(self, req)
            local p = req.payload
            local at = 17
            local _; _, at = string.unpack("<s4", p, at)  -- name
            _, at = string.unpack("<s4", p, at)           -- layer
            at = at + 4                                    -- type
            _, at = string.unpack("<s4", p, at)           -- data
            at = at + 8                                    -- sequence
            saw_trailing = at <= #p
            return lcs.STATUS.OK, ""
        end, function()
            return lcs.set_value(src, w, FD, "Trailing", lcs.TYPE.DWORD, lcs.dword(3))
        end))
        t:assert(saw_trailing,
            "the request carried a field past the ones this parse consumed")
        t:assert_eq(r.ret, 0, "and skipping it is fine: the write succeeds")

        -- The same trailing byte in the response is malformed data.
        local r2, classes2 = under(t, lcs.OP.SET_VALUE,
            function() return lcs.STATUS.OK, "\0" end,
            function() return lcs.set_value(src, w, FD, "Trailing", lcs.TYPE.DWORD, lcs.dword(4)) end)
        t:assert_eq(r2.errno, sys.E.IO, "a response may not be extended that way: EIO")
        t:assert_eq(classes2[1], "malformed_response_payload", "malformed_response_payload")
    end)

-- Malformed protocol ----------------------------------------------------

test("a response shorter than the response header is malformed protocol, and is treated as a crash",
    { spec = "PKM *source.validate.malformed-protocol-is-treated-as-a-crash" }, function(t)
        local bad = lcs.source(vm, { hives = { { name = "Truncated" } } })
        bad:key("Truncated\\K")
        assert(bad:register())
        bad:pump()
        local w2 = vm:spawn_worker()
        bad:intercept(lcs.OP.LOOKUP, function(self, req)
            return lcs.response_frame(req.id, req.op, lcs.STATUS.OK, ""):sub(1, 10)
        end)
        local events = kmes.recording(t, vm, function()
            local r = lcs.open_key(bad, w2, -1, "Truncated\\K", lcs.RIGHT.KEY_READ)
            t:assert_eq(r.errno, sys.E.IO, "the waiter is completed EIO by the teardown")
        end)
        t:assert_eq(#kmes.of_type(events, "LCS_SOURCE_VALIDATION_FAILURE"), 0,
            "this is not a data validation failure and emits no such event")
        local after = lcs.open_key(bad, w2, -1, "Truncated\\K", lcs.RIGHT.KEY_READ)
        t:assert_eq(after.errno, sys.E.IO,
            "the slot is Down and its hives are unavailable")
        w2:kill(); w2:join()
    end)

test("a second response to a request already answered is malformed protocol, and is treated as a crash",
    { spec = "PKM *source.validate.malformed-protocol-is-treated-as-a-crash" }, function(t)
        local bad = lcs.source(vm, { hives = { { name = "Duplicate" } } })
        bad:key("Duplicate\\K")
        assert(bad:register())
        bad:pump()
        local w2 = vm:spawn_worker()
        local last
        bad:intercept(lcs.OP.LOOKUP, function(self, req) last = req; return nil end)
        local r = lcs.open_key(bad, w2, -1, "Duplicate\\K", lcs.RIGHT.KEY_READ)
        t:assert(r.ret >= 0, "an honest answer first: " .. sys.errname(r.errno or 0))
        sys.close(w2, r.ret)
        local ret, errno = bad:write_frame(
            lcs.response_frame(last.id, last.op, lcs.STATUS.NOT_FOUND, ""))
        t:assert(ret < 0, "answering it again is rejected")
        t:assert_eq(errno, sys.E.INVAL, "EINVAL")
        local after = lcs.open_key(bad, w2, -1, "Duplicate\\K", lcs.RIGHT.KEY_READ)
        t:assert_eq(after.errno, sys.E.IO, "and the connection was torn down with it")
        w2:kill(); w2:join()
    end)
