-- PKM §6.A — the generated NTFE ABI tables, each published number checked
-- against what the running kernel does: the four ioctl request numbers
-- are the ones it accepts; every structure is exactly its published size
-- (a buffer one byte short holds no record; the bytes after one are left
-- alone); every field sits at its published offset, read here from a real
-- event, status, counter cell, flow and listener by the table's offsets,
-- not the helper's decoder; and every enumeration value is the one real
-- events carry.
--
-- Own VM: the policy is machine-wide state.

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")
local token = require("helpers.token")
local stream = require("helpers.ntfe_stream")

local vm = provium:vm("vntfeabi", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))

local PASS_ALL = { all = { Actions = { "PASS" } } }
local BASE = { RawPacket = PASS_ALL, Packet = PASS_ALL, Flow = PASS_ALL }
local E = ntfe.engine(vm, BASE)
local LO = assert(ntfe.if_index(vm, "lo"))
local SELF_USER = token.query(vm, assert(token.open_self(vm)), token.CLASS.USER)

local function with(layer, rules)
    local p = { RawPacket = PASS_ALL, Packet = PASS_ALL, Flow = PASS_ALL }
    local merged = { all = { Actions = { "PASS" } } }
    for name, rule in pairs(rules) do merged[name] = rule end
    p[layer] = merged
    return p
end

-- Every event this file sees, for the values no event may carry.
local seen = {}
local function during(fn)
    local d, events = E:during(fn)
    for _, e in ipairs(events) do seen[#seen + 1] = e end
    return d, events
end

local function u8(b, off) return b:byte(off + 1) end
local function u16(b, off) return (string.unpack("<I2", b, off + 1)) end
local function u32(b, off) return (string.unpack("<I4", b, off + 1)) end
local function s32(b, off) return (string.unpack("<i4", b, off + 1)) end
local function u64(b, off) return (string.unpack("<I8", b, off + 1)) end
local function bytes(b, off, n) return b:sub(off + 1, off + n) end
local function cstr(b, off, n) return (bytes(b, off, n):match("^[^%z]*")) end
local function zero(n) return string.rep("\0", n) end
local function addr4(s) return ntfe.ip4(s) .. zero(12) end
local function sid_field(sid, n) return sid .. zero(n - #sid) end

local function local_port(fd)
    local r = vm:syscall(ntfe.NR.getsockname, {
        args = { fd, 0, 0 }, bufs = { zero(16), string.pack("<I4", 16) }, ptrs = { 1, 2 },
    })
    return (string.unpack(">I2", r.out_bufs[1], 3))
end

local function thread_comm()
    local r = vm:syscall(157, { args = { 16, 0 }, bufs = { zero(16) }, ptrs = { 1 } })
    return (r.out_bufs[1]:match("^[^%z]*"))
end

-- ---- provenance -------------------------------------------------------

test("every name, value, offset and size in §6.A is generated from the uapi header",
    { spec = "PKM *abi.ntfe-generated-from-source",
      covered_by = "build:pkm/tools/gen-ntfe-abi.py",
      skip = "a statement about how the appendix is made: the generator " ..
             "and its compiled probe against pkm/uapi/pkm/ntfe.h hold it; " ..
             "every number it emits is checked live in this file" },
    function(t) end)

-- ---- request numbers --------------------------------------------------

test("the four ioctl request numbers are the ones the device answers",
    { spec = "PKM *abi.ioctl-numbers" }, function(t)
        local dev = E.dev
        local function ioc(dir, nr, size) return (dir << 30) | (size << 16) | (0x4E << 8) | nr end
        t:assert_eq(0x81704E01, ioc(2, 1, 368), "STATUS packs _IOR('N', 1, 368 bytes)")
        t:assert_eq(0xC0184E02, ioc(3, 2, 24), "COUNTERS packs _IOWR('N', 2, 24 bytes)")
        t:assert_eq(0xC0184E03, ioc(3, 3, 24), "FLOWS packs _IOWR('N', 3, 24 bytes)")
        t:assert_eq(0xC0184E04, ioc(3, 4, 24), "LISTENERS packs _IOWR('N', 4, 24 bytes)")

        t:assert_eq(stream.status_raw(vm, dev, 368, "\0", 0x81704E01).ret, 0,
            "PEIOS_NTFE_IOC_STATUS 0x81704E01 is answered")
        for _, req in ipairs({ 0xC0184E02, 0xC0184E03, 0xC0184E04 }) do
            local r = stream.dump_raw(vm, dev, req, 0)
            t:assert_eq(r.ret, 0, string.format("%#x is answered: %s", req, sys.errname(r.errno or 0)))
        end
        for _, req in ipairs({
            0x81684E01, -- STATUS with the size of a 45-word status
            0x41704E01, -- STATUS as a write
            0xC0184E05, -- a fifth number
            0xC0204E02, -- COUNTERS with a 32-byte query
            0x81704F01, -- another type byte
        }) do
            t:assert_eq(stream.status_raw(vm, dev, 368, "\0", req).errno, sys.E.NOTTY,
                string.format("while its neighbour %#x is ENOTTY", req))
        end
    end)

-- ---- structures ---------------------------------------------------------

test("struct peios_ntfe_event is 456 bytes with every field at its published offset",
    { spec = "PKM *abi.struct-peios-ntfe-event" }, function(t)
        E:replace(with("Packet", {
            ["abi-path"] = { ["Direction.Equal"] = "in", ["DstPort.Equal"] = 7500, Priority = 10,
                             Actions = { "PASS", "TAG(a, Set)", "COUNT(c)", "COUNT(c)",
                                         "REPORT(1)", "PROMPT(h, PASS)" } },
        }))
        local tx = stream.udp_pair(vm, 7500)
        local sport = local_port(tx)
        local comm = thread_comm()
        E:drain()
        local fd = E:stream()
        local t0 = stream.now_ns(vm)
        ntfe.send(vm, tx, "abcd")
        local t1 = stream.now_ns(vm)
        t:assert_eq(stream.read_raw(vm, fd, 455).errno, sys.E.INVAL,
            "455 bytes cannot hold one record")
        local r = stream.read_raw(vm, fd, 6 * 456 + 8, "\xAA")
        t:assert_eq(r.ret, 6 * 456, "six events arrive as 6 × 456 bytes")
        local buf = r.out_bufs[1]
        t:assert_eq(buf:sub(r.ret + 1), string.rep("\xAA", 8), "and nothing is written past them")

        local recs = {}
        for i = 0, 5 do recs[i + 1] = buf:sub(i * 456 + 1, (i + 1) * 456) end
        for i = 2, 6 do
            t:assert_eq(u64(recs[i], 0), u64(recs[i - 1], 0) + 1, "seq at 0, one record apart")
        end
        local pkt, flow
        for _, b in ipairs(recs) do
            if u8(b, 16) == 3 and u8(b, 17) == 0 then pkt = b end
            if u8(b, 16) == 4 and u8(b, 17) == 2 then flow = b end
        end
        t:assert(pkt and flow, "the LOCAL_IN Packet event and the LOCAL_OUT Flow event, by seat at 16 and layer at 17")

        t:assert(u64(pkt, 8) >= t0 and u64(pkt, 8) <= t1, "t_ns at 8")
        t:assert_eq(u8(pkt, 18), 0, "verdict at 18")
        t:assert_eq(u8(pkt, 19), 0, "flags at 19")
        t:assert_eq(u8(pkt, 20), 0, "direction at 20")
        t:assert_eq(u8(pkt, 21), 4, "addr_family at 21")
        t:assert_eq(u8(pkt, 22), 17, "protocol at 22")
        t:assert_eq(u8(pkt, 23), 1, "flow_state at 23")
        t:assert_eq(u32(pkt, 24), LO, "ifindex at 24")
        t:assert_eq(u16(pkt, 28), sport, "src_port at 28")
        t:assert_eq(u16(pkt, 30), 7500, "dst_port at 30")
        t:assert_eq(u16(pkt, 32), 0x0800, "ether_type at 32")
        t:assert_eq(u8(pkt, 34), 0, "reject_kind at 34")
        t:assert_eq(bytes(pkt, 36, 16), addr4("127.0.0.1"), "src_addr at 36")
        t:assert_eq(bytes(pkt, 52, 16), addr4("127.0.0.1"), "dst_addr at 52")
        t:assert_eq(u32(pkt, 68), 20 + 8 + 4, "length at 68")
        t:assert_eq(u32(pkt, 72), 1 | 2 << 8 | 1 << 16 | 1 << 24, "effects at 72")
        t:assert_eq(cstr(pkt, 76, 96), "abi-path", "attributed at 76")
        t:assert_eq(bytes(pkt, 176, 280), zero(280), "identity fields from 176 empty on a Packet event")

        t:assert_eq(u8(flow, 176), ntfe.LOCAL.PROGRAM, "local_kind at 176")
        t:assert_eq(u8(flow, 177), ntfe.LOCAL.PROGRAM, "remote_kind at 177")
        t:assert_eq(u8(flow, 178), 0, "local_unresolved at 178")
        t:assert_eq(u8(flow, 179), 0, "remote_unresolved at 179")
        t:assert_eq(s32(flow, 180), 1, "local_pid at 180")
        t:assert_eq(s32(flow, 184), 1, "remote_pid at 184")
        t:assert_neq(bytes(flow, 188, 16), zero(16), "local_guid at 188")
        t:assert_eq(bytes(flow, 204, 16), bytes(flow, 188, 16), "remote_guid at 204, the same process")
        t:assert_eq(cstr(flow, 220, 16), comm, "local_comm at 220")
        t:assert(#cstr(flow, 236, 16) > 0, "remote_comm at 236")
        t:assert_eq(bytes(flow, 252, 68), sid_field(SELF_USER, 68), "local_user at 252")
        t:assert_eq(bytes(flow, 320, 68), sid_field(SELF_USER, 68), "remote_user at 320")
        t:assert_eq(bytes(flow, 388, 64), zero(64), "both service SIDs at 388 and 420, absent")
        t:assert_eq(bytes(flow, 452, 4), zero(4), "and _pad2 at 452 closes the record")
        E:replace(BASE)
    end)

-- Each status member's published offset.
local STATUS_OFFSETS = {
    abi = 0, generation = 8, enforcing = 16, events_dropped = 24,
    seen_ingress = 32, seen_egress = 40, seen_local_in = 48, deferred = 56,
    fallback_judged = 64, parse_errors = 72, judged = 80, permissive = 88,
    fail_closed = 96, verdict_pass = 104, verdict_drop = 112, verdict_reject = 120,
    reject_degraded = 128, fx_tags = 136, fx_counts = 144, fx_reports = 152,
    fx_prompts = 160, last_ingest_error = 168, last_ingest_t_ns = 176,
    tag_writes = 184, tag_untracked = 192, tag_refused = 200, count_writes = 208,
    count_key_absent = 216, count_refused = 224, reports_emitted = 232,
    counter_cells = 240, reporting_level = 248, seen_local_out = 256,
    flow_judged = 264, flow_cached = 272, flow_rejudged = 280, flow_expired = 288,
    flow_uncached = 296, refusals_emitted = 304, refusals_bypassed = 312,
    teardowns_emitted = 320, identity_unresolved = 328, changes_noted = 336,
    changes_walked = 344, contexts = 352, _reserved = 360,
}

test("struct peios_ntfe_status is 368 bytes with every member at its published offset",
    { spec = "PKM *abi.struct-peios-ntfe-status" }, function(t)
        local function raw()
            local r = stream.status_raw(vm, E.dev, 376, "\xAA", 0x81704E01)
            t:assert_eq(r.ret, 0, "the status is filled")
            return r.out_bufs[1]
        end
        local function at(b, name) return u64(b, STATUS_OFFSETS[name]) end
        local tx = stream.udp_pair(vm, 7505)
        ntfe.send(vm, tx, "x")
        local before = raw()
        t:assert_eq(before:sub(369), string.rep("\xAA", 8), "exactly 368 bytes are written")
        t:assert_eq(at(before, "_reserved"), 0, "the last of them _reserved, at 360")
        t:assert_eq(at(before, "abi"), 5, "abi at 0")
        t:assert_eq(at(before, "generation"), E:status().generation, "generation at 8")
        t:assert_eq(at(before, "enforcing"), 1, "enforcing at 16")
        t:assert_eq(at(before, "reporting_level"), 1, "reporting_level at 248")
        t:assert_eq(at(before, "changes_noted"), at(before, "changes_walked"),
            "changes_noted at 336 and changes_walked at 344, caught up")

        -- One datagram of a flow with sentences moves exactly these.
        E:drain()
        ntfe.send(vm, tx, "x")
        local after = raw()
        local moved = {
            seen_ingress = 1, seen_egress = 1, seen_local_in = 1, seen_local_out = 1,
            deferred = 1, judged = 4, verdict_pass = 4, flow_cached = 2,
        }
        for name, off in pairs(STATUS_OFFSETS) do
            if name ~= "last_ingest_t_ns" and name ~= "generation" then
                t:assert_eq(at(after, name) - at(before, name), moved[name] or 0,
                    name .. " at " .. off)
            end
        end
        local d = E:during(function() stream.garbage_ipv4(vm) end)
        t:assert_eq(d.parse_errors, 2, "and parse_errors at 72 counts what it names")
        t:assert_eq(#ntfe.STATUS_FIELDS * 8, 368, "46 words")
    end)

test("struct peios_ntfe_counter_rec is 232 bytes with every field at its published offset",
    { spec = "PKM *abi.struct-peios-ntfe-counter-rec" }, function(t)
        E:replace(with("Packet", {
            tally = { ["Direction.Equal"] = "in", ["DstPort.Equal"] = 7510,
                      Actions = { "PASS", "COUNT(abi, 5)" } },
            v10 = { ["Counter.abi(10s, DstAddr).GreaterThan"] = 1000000, Actions = { "DROP" } },
            v60 = { ["Counter.abi(1m, DstAddr).GreaterThan"] = 1000000, Actions = { "DROP" } },
        }))
        local tx = stream.udp_pair(vm, 7510)
        local now = stream.now_ns(vm) // 1000000000
        ntfe.send(vm, tx, "x")
        local short = stream.dump_raw(vm, E.dev, ntfe.IOC.COUNTERS, 231)
        t:assert_eq(short.count, 0, "231 bytes hold no cell")
        t:assert(short.total >= 1, "though one exists")
        local r = stream.dump_raw(vm, E.dev, ntfe.IOC.COUNTERS, 232 + 8, { rec_fill = "\xAA" })
        t:assert_eq(r.count, 1, "232 bytes hold one")
        local b = r.out_bufs[2]
        t:assert_eq(b:sub(233), string.rep("\xAA", 8), "and nothing is written past it")
        t:assert_eq(cstr(b, 0, 64), "abi", "name at 0")
        t:assert_eq(u64(b, 64), ntfe.name_hash("abi"), "hash at 64")
        t:assert_eq(u8(b, 72), ntfe.KEY.DST_ADDR, "keyspec at 72")
        t:assert_eq(u8(b, 73), 4, "family at 73")
        t:assert_eq(s32(b, 76), 0, "ifindex at 76, unkeyed")
        t:assert_eq(bytes(b, 80, 16), zero(16), "src_addr at 80, unkeyed")
        t:assert_eq(bytes(b, 96, 16), addr4("127.0.0.1"), "dst_addr at 96")
        t:assert_eq(u64(b, 112), 5, "total at 112")
        t:assert(math.abs(u64(b, 120) - now) <= 2, "last_secs at 120")
        t:assert_eq(u32(b, 128), 2, "n_windows at 128")
        local w = { [u32(b, 136)] = u64(b, 168), [u32(b, 140)] = u64(b, 176) }
        t:assert_eq(w[10], 5, "window_secs at 136 and window_value at 168: the 10 s window")
        t:assert_eq(w[60], 5, "and the minute")
        E:replace(BASE)
    end)

local function query_shape(t, req, name)
    local r = stream.dump_raw(vm, E.dev, req, 0, { query_size = 32, fill = "\xAA" })
    t:assert_eq(r.ret, 0, name .. " is answered")
    local q = r.out_bufs[1]
    t:assert_eq(u32(q, 8), 0, "buf_len at 8 is the caller's")
    t:assert_eq(u32(q, 12), 0, "count at 12: none written")
    t:assert(u32(q, 16) >= 1, "total at 16: what exists")
    t:assert_eq(u32(q, 20), 0, "_pad0 at 20")
    t:assert_eq(q:sub(25), string.rep("\xAA", 8), "and the kernel reads and writes exactly 24 bytes")
end

test("struct peios_ntfe_counters_query is 24 bytes: buf, buf_len, count, total",
    { spec = "PKM *abi.struct-peios-ntfe-counters-query" }, function(t)
        E:replace(with("Packet", {
            tally = { ["DstPort.Equal"] = 7515, Actions = { "PASS", "COUNT(q)" } },
            view = { ["Counter.q.GreaterThan"] = 1000000, Actions = { "DROP" } },
        }))
        ntfe.send(vm, (stream.udp_pair(vm, 7515)), "x")
        query_shape(t, ntfe.IOC.COUNTERS, "the counters query")
        E:replace(BASE)
    end)

test("struct peios_ntfe_flow_rec is 568 bytes with every field at its published offset",
    { spec = "PKM *abi.struct-peios-ntfe-flow-rec" }, function(t)
        local s = E:replace(with("Flow", {
            ["abi-flow"] = { ["DstPort.Equal"] = 7520, Priority = 10,
                             Actions = { "PASS", "TAG(abi, Set, 7)" } },
        }))
        local listener = assert(ntfe.tcp_listen(vm, "127.0.0.1", 7520))
        local client = assert(ntfe.tcp_connect(vm, "127.0.0.1", 7520))
        local server = assert(ntfe.tcp_accept(vm, listener))
        ntfe.send(vm, client, "ping")
        t:assert_eq(ntfe.recv(vm, server), "ping", "a connection carries data")
        local sport = local_port(client)
        local now = stream.now_ns(vm) // 1000000000

        t:assert_eq(stream.dump_raw(vm, E.dev, ntfe.IOC.FLOWS, 567).count, 0,
            "567 bytes hold no flow")
        t:assert_eq(stream.dump_raw(vm, E.dev, ntfe.IOC.FLOWS, 568).count, 1, "568 hold one")
        local r = stream.dump_raw(vm, E.dev, ntfe.IOC.FLOWS, 64 * 568)
        t:assert(r.count >= 1 and r.count == r.total, "every flow fits in 64 records")
        local b
        for i = 0, r.count - 1 do
            local rec = r.out_bufs[2]:sub(i * 568 + 1, (i + 1) * 568)
            if u16(rec, 54) == 7520 and u8(rec, 5) == 6 then b = rec end
        end
        t:assert(b, "the connection's record, found by dst_port at 54 and protocol at 5")
        t:assert(u32(b, 0) ~= 0, "id at 0")
        t:assert_eq(u8(b, 4), 4, "family at 4")
        t:assert_eq(u8(b, 6), ntfe.DIR.OUT, "direction at 6")
        t:assert_eq(u8(b, 7), 1, "loopback at 7")
        t:assert_eq(u8(b, 8), 1, "seen_reply at 8")
        t:assert_eq(u8(b, 9), 1, "assured at 9")
        t:assert_eq(u8(b, 10), 0, "related at 10")
        t:assert_eq(u8(b, 11), 1, "judged at 11")
        t:assert_eq(s32(b, 12), LO, "ifindex at 12")
        t:assert(u32(b, 16) > 0, "timeout_secs at 16")
        t:assert_eq(bytes(b, 20, 16), addr4("127.0.0.1"), "src_addr at 20")
        t:assert_eq(bytes(b, 36, 16), addr4("127.0.0.1"), "dst_addr at 36")
        t:assert_eq(u16(b, 52), sport, "src_port at 52")
        t:assert_eq(u8(b, 56) + u8(b, 57), 0, "icmp_type and icmp_code at 56, 57: not ICMP")
        t:assert_eq(u8(b, 58), 1, "n_tags at 58")
        t:assert(math.abs(u64(b, 64) - now) <= 5, "start_secs at 64")
        t:assert(u64(b, 72) >= 3 and u64(b, 80) >= 2, "packets at 72, original then reply")
        t:assert(u64(b, 88) > u64(b, 96), "bytes at 88, the original side carrying the data")
        for slot = 0, 1 do
            local o = string.format(" (slot %d)", slot)
            t:assert_eq(u64(b, 104 + 8 * slot), s.generation, "sentence_generation at 104" .. o)
            t:assert_eq(u64(b, 120 + 8 * slot), 0, "sentence_expires_at at 120" .. o)
            t:assert_eq(u64(b, 136 + 8 * slot), ntfe.name_hash("abi-flow"),
                "sentence_rule_hash at 136" .. o)
            t:assert_eq(u8(b, 152 + slot), ntfe.VERDICT.PASS, "sentence_verdict at 152" .. o)
            t:assert_eq(u8(b, 154 + slot), 0, "sentence_reject_kind at 154" .. o)
            t:assert_eq(u8(b, 288 + slot), ntfe.LOCAL.PROGRAM, "owner_kind at 288" .. o)
            t:assert_eq(u8(b, 290 + slot), 0, "owner_unresolved at 290" .. o)
            t:assert_eq(s32(b, 296 + 4 * slot), 1, "owner_pid at 296" .. o)
            t:assert_neq(bytes(b, 304 + 16 * slot, 16), zero(16), "owner_guid at 304" .. o)
            t:assert(#cstr(b, 336 + 16 * slot, 16) > 0, "owner_comm at 336" .. o)
            t:assert_eq(bytes(b, 368 + 68 * slot, 68), sid_field(SELF_USER, 68),
                "owner_user at 368" .. o)
            t:assert_eq(bytes(b, 504 + 32 * slot, 32), zero(32), "owner_service at 504" .. o)
        end
        t:assert_eq(u64(b, 160), ntfe.name_hash("abi"), "tag_hash at 160")
        t:assert_eq(u64(b, 224), 7, "tag_value at 224")
        sys.close(vm, client); sys.close(vm, server); sys.close(vm, listener)
        E:replace(BASE)
    end)

test("struct peios_ntfe_flows_query is 24 bytes: buf, buf_len, count, total",
    { spec = "PKM *abi.struct-peios-ntfe-flows-query" }, function(t)
        query_shape(t, ntfe.IOC.FLOWS, "the flows query")
    end)

test("struct peios_ntfe_listener_rec is 168 bytes with every field at its published offset",
    { spec = "PKM *abi.struct-peios-ntfe-listener-rec" }, function(t)
        local listener = assert(ntfe.tcp_listen(vm, "127.0.0.1", 7530))
        local comm = thread_comm()
        t:assert_eq(stream.dump_raw(vm, E.dev, ntfe.IOC.LISTENERS, 167).count, 0,
            "167 bytes hold no listener")
        t:assert_eq(stream.dump_raw(vm, E.dev, ntfe.IOC.LISTENERS, 168).count, 1, "168 hold one")
        local r = stream.dump_raw(vm, E.dev, ntfe.IOC.LISTENERS, 64 * 168)
        local b
        for i = 0, r.count - 1 do
            local rec = r.out_bufs[2]:sub(i * 168 + 1, (i + 1) * 168)
            if u16(rec, 8) == 7530 and u8(rec, 1) == 6 then b = rec end
        end
        sys.close(vm, listener)
        t:assert(b, "the listener's record, found by port at 8 and protocol at 1")
        t:assert_eq(u8(b, 0), 4, "family at 0")
        t:assert_eq(u8(b, 2), 0, "reuseport at 2")
        t:assert_eq(u8(b, 3), 0, "connected at 3")
        t:assert_eq(u8(b, 4), 0, "v6only at 4")
        t:assert_eq(u8(b, 5), ntfe.LOCAL.PROGRAM, "owner_kind at 5")
        t:assert_eq(u8(b, 6), 0, "owner_unresolved at 6")
        t:assert_eq(s32(b, 12), 0, "ifindex at 12")
        t:assert_eq(bytes(b, 16, 16), addr4("127.0.0.1"), "addr at 16")
        t:assert_eq(s32(b, 32), 1, "owner_pid at 32")
        t:assert_neq(bytes(b, 36, 16), zero(16), "owner_guid at 36")
        t:assert_eq(cstr(b, 52, 16), comm, "owner_comm at 52")
        t:assert_eq(bytes(b, 68, 68), sid_field(SELF_USER, 68), "owner_user at 68")
        t:assert_eq(bytes(b, 136, 32), zero(32), "owner_service at 136, to the end")
    end)

test("struct peios_ntfe_listeners_query is 24 bytes: buf, buf_len, count, total",
    { spec = "PKM *abi.struct-peios-ntfe-listeners-query" }, function(t)
        local l = assert(ntfe.tcp_listen(vm, "127.0.0.1", 7531))
        query_shape(t, ntfe.IOC.LISTENERS, "the listeners query")
        sys.close(vm, l)
    end)

-- ---- enumerations -------------------------------------------------------

test("the seat values are 1 ingress, 2 egress, 3 LOCAL_IN, 4 LOCAL_OUT",
    { spec = "PKM *abi.seat-values" }, function(t)
        -- A loopback datagram crosses LOCAL_OUT, egress, ingress, LOCAL_IN
        -- in that order, and each seat judges its own layers.
        local tx = stream.udp_pair(vm, 7540)
        local _, events = during(function() ntfe.send(vm, tx, "x") end)
        local order = {}
        for _, e in ipairs(events) do order[#order + 1] = e.seat .. ":" .. e.layer end
        t:assert_eq(table.concat(order, " "), "4:2 2:0 2:1 1:1 3:0 3:2",
            "LOCAL_OUT (Flow), egress (Packet, RawPacket), ingress (RawPacket), LOCAL_IN (Packet, Flow)")
        for _, e in ipairs(events) do
            if e.seat == 1 then t:assert_eq(e.flow_state, 0, "seat 1 stands before conntrack") end
        end
    end)

test("the layer values are 0 Packet, 1 RawPacket, 2 Flow",
    { spec = "PKM *abi.layer-values" }, function(t)
        local function named() return { ["DstPort.Equal"] = 7545, Priority = 10, Actions = { "PASS" } } end
        E:replace({
            RawPacket = { all = { Actions = { "PASS" } }, ["raw-rule"] = named() },
            Packet = { all = { Actions = { "PASS" } }, ["packet-rule"] = named() },
            Flow = { all = { Actions = { "PASS" } }, ["flow-rule"] = named() },
        })
        local tx = stream.udp_pair(vm, 7545)
        local _, events = during(function() ntfe.send(vm, tx, "x") end)
        for name, layer in pairs({ ["packet-rule"] = 0, ["raw-rule"] = 1, ["flow-rule"] = 2 }) do
            local hits = ntfe.matching(events, { attributed = name })
            t:assert(#hits >= 1, name .. " judged: " .. ntfe.describe(events))
            for _, e in ipairs(hits) do
                t:assert_eq(e.layer, layer, name .. " is in layer " .. layer)
            end
        end
        E:replace(BASE)
    end)

test("the verdict values are 0 PASS, 1 REJECT, 2 DROP",
    { spec = "PKM *abi.verdict-values" }, function(t)
        E:replace(with("Packet", {
            ["v-pass"] = { ["Direction.Equal"] = "in", ["DstPort.Equal"] = 7550, Priority = 10, Actions = { "PASS" } },
            ["v-reject"] = { ["Direction.Equal"] = "in", ["DstPort.Equal"] = 7551, Priority = 10, Actions = { "REJECT" } },
            ["v-drop"] = { ["Direction.Equal"] = "in", ["DstPort.Equal"] = 7552, Priority = 10, Actions = { "DROP" } },
        }))
        local l = {}
        for port = 7550, 7552 do l[port] = assert(ntfe.tcp_listen(vm, "127.0.0.1", port)) end
        local outcome = {}
        local _, events = during(function()
            for port = 7550, 7552 do
                local fd, why = ntfe.tcp_connect(vm, "127.0.0.1", port, 300)
                outcome[port] = fd and "connected" or why
                if fd then sys.close(vm, fd) end
            end
        end)
        for _, fd in pairs(l) do sys.close(vm, fd) end
        t:assert_eq(outcome[7550], "connected", "PASS lets it in")
        t:assert_eq(outcome[7551], sys.E.CONNREFUSED, "REJECT refuses it")
        t:assert_eq(outcome[7552], "timeout", "DROP swallows it")
        for name, v in pairs({ ["v-pass"] = 0, ["v-reject"] = 1, ["v-drop"] = 2 }) do
            local e = ntfe.matching(events, { attributed = name })[1]
            t:assert(e, name .. " judged")
            t:assert_eq(e.verdict, v, name .. " carries verdict " .. v)
        end
        E:replace(BASE)
    end)

test("the reject kinds are 0 Refused and 1 Prohibited",
    { spec = "PKM *abi.reject-kinds" }, function(t)
        E:replace(with("Packet", {
            refused = { ["Direction.Equal"] = "in", ["DstPort.Equal"] = 7560, Priority = 10,
                        Actions = { "REJECT(Refused)" } },
            prohibited = { ["Direction.Equal"] = "in", ["DstPort.Equal"] = 7561, Priority = 10,
                           Actions = { "REJECT(Prohibited)" } },
        }))
        local why = {}
        local _, events = during(function()
            why[0] = select(2, ntfe.tcp_connect(vm, "127.0.0.1", 7560, 300))
            why[1] = select(2, ntfe.tcp_connect(vm, "127.0.0.1", 7561, 300))
        end)
        t:assert_eq(why[0], sys.E.CONNREFUSED, "Refused answers with a reset")
        t:assert_eq(why[1], sys.E.HOSTUNREACH, "Prohibited with admin-prohibited")
        t:assert_eq(ntfe.matching(events, { attributed = "refused" })[1].reject_kind, 0,
            "and the first event's reject_kind is 0")
        t:assert_eq(ntfe.matching(events, { attributed = "prohibited" })[1].reject_kind, 1,
            "the second's 1")
        E:replace(BASE)
    end)

test("the direction values are 0 in and 1 out",
    { spec = "PKM *abi.direction-values" }, function(t)
        local tx = stream.udp_pair(vm, 7565)
        local _, events = during(function() ntfe.send(vm, tx, "x") end)
        for _, e in ipairs(events) do
            if e.seat == ntfe.SEAT.EGRESS or e.seat == ntfe.SEAT.LOCAL_OUT then
                t:assert_eq(e.direction, 1, "an outbound seat's event says 1")
            else
                t:assert_eq(e.direction, 0, "an inbound seat's event says 0")
            end
        end
    end)

test("the flow states are 0 absent, 1 new, 2 established, 3 related, 5 untracked; 4 is reserved",
    { spec = "PKM *abi.flow-state-values" }, function(t)
        local function at_local_in(events, proto)
            return ntfe.matching(events, { seat = ntfe.SEAT.LOCAL_IN, layer = ntfe.LAYER.PACKET,
                                           protocol = proto })
        end
        local tx = stream.udp_pair(vm, 7570)
        local _, first = during(function() ntfe.send(vm, tx, "x") end)
        local _, second = during(function() ntfe.send(vm, tx, "x") end)
        t:assert_eq(ntfe.matching(first, { seat = ntfe.SEAT.INGRESS })[1].flow_state, 0,
            "the ingress seat, before conntrack: 0")
        t:assert_eq(at_local_in(first, 17)[1].flow_state, 1, "a flow's first packet: 1")
        local listener = assert(ntfe.tcp_listen(vm, "127.0.0.1", 7570))
        local _, tcp = during(function()
            local fd = assert(ntfe.tcp_connect(vm, "127.0.0.1", 7570))
            ntfe.send(vm, fd, "x")
            sys.close(vm, fd)
        end)
        sys.close(vm, listener)
        local est = stream.where(at_local_in(tcp, 6), function(e) return e.flow_state == 2 end)
        t:assert(#est >= 1, "a connection's later packets: 2")
        t:assert(#second >= 1, "(a second datagram, too, is judged)")

        -- Nobody bound to 7571: the stack's port-unreachable belongs to
        -- the datagram's flow.
        local orphan = assert(ntfe.udp_connect(vm, "127.0.0.1", 7571))
        local _, icmp = during(function() ntfe.send(vm, orphan, "x") end)
        sys.close(vm, orphan)
        local rel = at_local_in(icmp, 1)[1]
        t:assert(rel, "the ICMP error is judged inbound: " .. ntfe.describe(icmp))
        t:assert_eq(rel.flow_state, 3, "an ICMP error for a live flow: 3")

        -- SYN and FIN together, from a raw socket: conntrack refuses to
        -- track it.
        local raw = assert(ntfe.socket(vm, ntfe.AF_INET, ntfe.SOCK_RAW, { protocol = 6 }))
        local seg = ntfe.tcp("127.0.0.1", "127.0.0.1", 40000, 7572, ntfe.TCP.SYN | ntfe.TCP.FIN)
        local _, bad = during(function()
            t:assert_eq(ntfe.sendto(vm, raw, seg, "127.0.0.1", 0).ret, #seg, "a SYN+FIN segment")
        end)
        sys.close(vm, raw)
        local untracked = at_local_in(bad, 6)[1]
        t:assert(untracked, "the incoherent segment is judged inbound: " .. ntfe.describe(bad))
        t:assert_eq(untracked.flow_state, 5, "an untracked packet: 5")

        -- §6.3: `invalid` is reserved; the seat never receives conntrack's
        -- verdict, so no event carries it.
        for _, e in ipairs(seen) do
            t:assert(e.flow_state ~= 4, "4 (INVALID) is carried by no event")
        end
    end)

test("the event flags are BACKSTOP 0x01, REJECT_DEGRADED 0x04 and REJUDGED 0x08 as events carry them",
    { spec = "PKM *abi.event-flags" }, function(t)
        -- FAIL_CLOSED (0x02) and IDENTITY_UNRESOLVED (0x10) have no guest
        -- route (stream-confessions); no event here carries a bit outside
        -- the five published ones.
        E:replace({
            RawPacket = {
                all = { Actions = { "PASS" } },
                refuse = { ["EtherType.Equal"] = stream.ETH_EXPERIMENTAL, Actions = { "REJECT" } },
            },
            Packet = {
                only = { ["DstPort.Equal"] = 7576, Actions = { "PASS" } },
                frames = { ["EtherType.Equal"] = stream.ETH_EXPERIMENTAL, Actions = { "PASS" } },
            },
            Flow = PASS_ALL,
        })
        local tx = stream.udp_pair(vm, 7575)
        local _, ev = during(function() ntfe.send(vm, tx, "x") end)
        t:assert_eq(ntfe.matching(ev, { attributed = "backstop" })[1].flags, 0x01,
            "the backstop's event: 0x01")
        _, ev = during(function() stream.lo_frame(vm) end)
        t:assert_eq(ntfe.matching(ev, { attributed = "refuse" })[1].flags, 0x04,
            "a REJECT with nothing to send: 0x04")
        local kept = stream.udp_pair(vm, 7576)
        ntfe.send(vm, kept, "x")
        E:replace(BASE)
        _, ev = during(function() ntfe.send(vm, kept, "x") end)
        local flow = ntfe.matching(ev, { layer = ntfe.LAYER.FLOW })
        t:assert(#flow >= 1, "a new generation re-judges the flow")
        for _, e in ipairs(flow) do t:assert_eq(e.flags, 0x08, "a re-judged sentence: 0x08") end
        for _, e in ipairs(seen) do
            t:assert_eq(e.flags & ~0x1F, 0, "no event carries an unpublished flag bit")
        end
    end)

test("the key-spec bits are 0x01 SrcAddr, 0x02 DstAddr, 0x04 Interface, OR'd for a compound",
    { spec = "PKM *abi.keyspec-bits" }, function(t)
        local actions = { "PASS", "COUNT(ks_src)", "COUNT(ks_dst)", "COUNT(ks_if)", "COUNT(ks_pair)" }
        E:replace(with("Packet", {
            tally = { ["Direction.Equal"] = "in", ["DstPort.Equal"] = 7580, Actions = actions },
            v1 = { ["Counter.ks_src(SrcAddr).GreaterThan"] = 1000000, Actions = { "DROP" } },
            v2 = { ["Counter.ks_dst(DstAddr).GreaterThan"] = 1000000, Actions = { "DROP" } },
            v3 = { ["Counter.ks_if(Interface).GreaterThan"] = 1000000, Actions = { "DROP" } },
            v4 = { ["Counter.ks_pair(SrcAddr+DstAddr).GreaterThan"] = 1000000, Actions = { "DROP" } },
        }))
        local tx = stream.udp_pair(vm, 7580)
        ntfe.send(vm, tx, "x")
        local cells = {}
        for _, c in ipairs(E:counters()) do cells[c.name] = c end
        local lo4 = "127.0.0.1"
        local want = {
            ks_src = { 0x01, lo4, nil, 0 }, ks_dst = { 0x02, nil, lo4, 0 },
            ks_if = { 0x04, nil, nil, LO }, ks_pair = { 0x03, lo4, lo4, 0 },
        }
        for name, w in pairs(want) do
            local c = cells[name]
            t:assert(c, name .. " has a cell")
            t:assert_eq(c.keyspec, w[1], string.format("%s's keyspec is %#x", name, w[1]))
            t:assert_eq(c.family ~= 0 and c.src ~= "0.0.0.0" and c.src or nil, w[2],
                name .. " keys the source exactly when the SrcAddr bit is set")
            t:assert_eq(c.family ~= 0 and c.dst ~= "0.0.0.0" and c.dst or nil, w[3],
                name .. " the destination exactly when DstAddr is")
            t:assert_eq(c.ifindex, w[4], name .. " the interface exactly when Interface is")
        end
        E:replace(BASE)
    end)
