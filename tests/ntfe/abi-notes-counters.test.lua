-- PKM §6.B — "Counter records": what each member of `struct
-- peios_ntfe_counter_rec` means. The stream name and its hash, which key
-- facts a cell holds and that the rest are zero, the address family, the
-- windows and their values, the cumulative total and how it survives a
-- migration, the last-write time, and that a table's cells come out of
-- the dump together.
--
-- A table exists only while some rule views its stream, so every policy
-- here pairs a counting rule with a never-matching rule that holds the
-- views (`Counter.<name>(...)` conditions) the test is about.
--
-- Own VM: the policy and the counter store are machine-wide state, and
-- one test sets the guest clock.

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")
local raw = require("helpers.ntfe_abi_notes")

local vm = provium:vm("vntfeabictr", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))

local PASS_ALL = { all = { Actions = { "PASS" } } }
local E = ntfe.engine(vm, { RawPacket = PASS_ALL, Packet = PASS_ALL, Flow = PASS_ALL })

--- A policy that counts every inbound datagram to `port` into `stream`
--- and views it through each of `views` (the text inside the
--- parentheses; "" for the plain total).
local function counting(stream, port, views)
    local holder = { ["DstPort.Equal"] = 1, Actions = { "DROP" } }
    for _, v in ipairs(views) do
        local name = v == "" and stream or (stream .. "(" .. v .. ")")
        holder["Counter." .. name .. ".GreaterThan"] = 4000000000
    end
    return {
        RawPacket = PASS_ALL, Flow = PASS_ALL,
        Packet = {
            all = { Actions = { "PASS" } },
            count = { ["DstPort.Equal"] = port, ["Direction.Equal"] = "in",
                      Actions = { "COUNT(" .. stream .. ")", "PASS" } },
            views = holder,
        },
    }
end

--- `n` datagrams to `dst`:`port` from the source address `src`.
local function send(n, port, src, dst)
    dst = dst or (src:find(":", 1, true) and "::1" or "127.0.0.1")
    local fd = assert(ntfe.udp_connect(vm, dst, port, { bind = { src, 0 } }))
    for _ = 1, n do ntfe.send(vm, fd, "c") end
    sys.close(vm, fd)
end

--- Every record of the dump with its raw bytes, decoded as helpers/ntfe
--- decodes them.
local function cells()
    local d = raw.dump(vm, E.dev, "counters", 256)
    assert(d.ret == 0, "counters dump: " .. sys.errname(d.errno))
    local list = assert(E:counters(256))
    for i, c in ipairs(list) do c.raw = raw.record(d, "counters", i) end
    return list
end

local function of(list, name, keyspec)
    local out = {}
    for _, c in ipairs(list) do
        if c.name == name and c.keyspec == keyspec then out[#out + 1] = c end
    end
    return out
end

local function all_zero(bytes) return not bytes:find("[^%z]") end
local function bytes_at(c, off, len) return c.raw:sub(off + 1, off + len) end

local rx4 = assert(ntfe.udp_bind(vm, "0.0.0.0", 7600))
local rx6 = assert(ntfe.udp_bind(vm, "::", 7601))

test("`name` is the stream, NUL-terminated, and `hash` its FNV-1a identity",
    { spec = "PKM *ntfe-abi-notes.counter-rec-name-and-hash" }, function(t)
        local s = E:replace(counting("hits", 7600, { "" }))
        t:assert_eq(s.last_ingest_error, 0, "the policy is accepted")
        send(1, 7600, "127.0.0.1")
        local c = of(cells(), "hits", 0)
        t:assert_eq(#c, 1, "one cell: the stream's global total")
        t:assert_eq(bytes_at(c[1], 0, 5), "hits\0", "`name` is the stream a COUNT names, then a NUL")
        t:assert_eq(c[1].hash, ntfe.name_hash("hits"), "`hash` is FNV-1a-64 of that name")
    end)

test("`keyspec` says which key facts are meaningful; the others are zero",
    { spec = "PKM *ntfe-abi-notes.counter-rec-keyspec-unkeyed-zero" }, function(t)
        E:replace(counting("keyed", 7600, { "SrcAddr", "DstAddr", "Interface" }))
        send(1, 7600, "127.0.0.2")
        local list = cells()
        local lo = assert(ntfe.if_index(vm, "lo"))
        local src = of(list, "keyed", ntfe.KEY.SRC_ADDR)[1]
        t:assert(src, "the SrcAddr table has the cell")
        t:assert_eq(bytes_at(src, 80, 4), ntfe.ip4("127.0.0.2"), "keyed by source: `src_addr` is set")
        t:assert(all_zero(bytes_at(src, 96, 16)), "`dst_addr` is zero")
        t:assert_eq(src.ifindex, 0, "and `ifindex` is zero")
        local dst = of(list, "keyed", ntfe.KEY.DST_ADDR)[1]
        t:assert(dst, "the DstAddr table has the cell")
        t:assert_eq(bytes_at(dst, 96, 4), ntfe.ip4("127.0.0.1"), "keyed by destination: `dst_addr` is set")
        t:assert(all_zero(bytes_at(dst, 80, 16)), "`src_addr` is zero")
        t:assert_eq(dst.ifindex, 0, "and `ifindex` is zero")
        local ifc = of(list, "keyed", ntfe.KEY.INTERFACE)[1]
        t:assert(ifc, "the Interface table has the cell")
        t:assert_eq(ifc.ifindex, lo, "keyed by interface: `ifindex` is the loopback's")
        t:assert(all_zero(bytes_at(ifc, 80, 32)), "both addresses are zero")
    end)

test("`family` is 4 or 6 for an address key, 0 when no address is keyed",
    { spec = "PKM *ntfe-abi-notes.counter-rec-family" }, function(t)
        local p = counting("fam", 7600, { "SrcAddr", "Interface", "" })
        p.Packet.count["DstPort.Equal"] = { "7600", "7601" }
        E:replace(p)
        send(1, 7600, "127.0.0.1")
        send(1, 7601, "::1")
        local list = cells()
        local by_family = {}
        for _, c in ipairs(of(list, "fam", ntfe.KEY.SRC_ADDR)) do by_family[c.family] = c end
        t:assert(by_family[4], "an IPv4 source is a family-4 cell")
        t:assert(by_family[6], "an IPv6 source is a family-6 cell")
        t:assert_eq(bytes_at(by_family[6], 80, 16), ntfe.ip6("::1"), "holding all 16 bytes")
        for _, c in ipairs(of(list, "fam", ntfe.KEY.INTERFACE)) do
            t:assert_eq(c.family, 0, "an Interface-keyed cell has family 0")
        end
        local global = of(list, "fam", 0)
        t:assert_eq(#global, 1, "the unkeyed table has one cell")
        t:assert_eq(global[1].family, 0, "of family 0")
    end)

test("`window_secs[i]` and `window_value[i]` below `n_windows` are the table's windows and the cell's values",
    { spec = "PKM *ntfe-abi-notes.counter-rec-window-values" }, function(t)
        E:replace(counting("win", 7600, { "1h", "1d", "" }))
        send(3, 7600, "127.0.0.1")
        local c = of(cells(), "win", 0)[1]
        t:assert(c, "the cell exists")
        t:assert_eq(c.n_windows, 2, "two windows: the plain view is the total, not a window")
        t:assert_eq(c.windows[3600], 3, "the hour holds the three datagrams")
        t:assert_eq(c.windows[86400], 3, "and so does the day")
        for i = c.n_windows, 7 do
            t:assert_eq(string.unpack("<I4", c.raw, 137 + i * 4), 0, "window_secs[" .. i .. "] is unused: 0")
            t:assert_eq(string.unpack("<I8", c.raw, 169 + i * 8), 0, "window_value[" .. i .. "] is unused: 0")
        end
    end)

test("`total` is cumulative since the cell was created, and survives a migration",
    { spec = "PKM *ntfe-abi-notes.counter-rec-total-cumulative" }, function(t)
        E:replace(counting("cum", 7600, { "1h" }))
        send(3, 7600, "127.0.0.1")
        local before = of(cells(), "cum", 0)[1]
        t:assert_eq(before.total, 3, "three counted")
        -- A changed window set migrates the table's cells.
        E:replace(counting("cum", 7600, { "1h", "1d" }))
        local after = of(cells(), "cum", 0)[1]
        t:assert_eq(after.total, 3, "the migrated cell keeps its total")
        t:assert_eq(after.windows[3600], 3, "and the window both sets share")
        t:assert_eq(after.windows[86400], 0, "while the new window starts empty")
        send(2, 7600, "127.0.0.1")
        local later = of(cells(), "cum", 0)[1]
        t:assert_eq(later.total, 5, "and the total goes on from where it was")
        t:assert_eq(later.windows[86400], 2, "the new window counts only since it began")
    end)

test("`last_secs` is the CLOCK_REALTIME second of the cell's last write",
    { spec = "PKM *ntfe-abi-notes.counter-rec-last-secs" }, function(t)
        E:replace(counting("stale", 7600, { "" }))
        local t0 = 2000000000
        vm:clock():set(t0)
        send(1, 7600, "127.0.0.1")
        local c = of(cells(), "stale", 0)[1]
        t:assert(c, "the cell exists")
        t:assert(c.last_secs >= t0 and c.last_secs <= t0 + 5,
            "written just now on the wall clock: " .. c.last_secs)
        vm:clock():set(t0 + 1000)
        send(1, 7600, "127.0.0.1")
        c = of(cells(), "stale", 0)[1]
        t:assert(c.last_secs >= t0 + 1000 and c.last_secs <= t0 + 1005,
            "and moved by the next write: " .. c.last_secs)
    end)

test("the dump lists each table's cells consecutively",
    { spec = "PKM *ntfe-abi-notes.counter-dump-tables-consecutive" }, function(t)
        local a = counting("grp", 7600, { "", "SrcAddr", "DstAddr" })
        local b = counting("other", 7600, { "SrcAddr" })
        a.Packet.count2 = b.Packet.count
        a.Packet.views2 = b.Packet.views
        E:replace(a)
        for i = 1, 3 do
            send(1, 7600, "127.0.0." .. i, "127.0.0.1")
            send(1, 7600, "127.0.0." .. i, "127.0.0.4")
        end
        local list = cells()
        local seen, current = {}, nil
        local groups = 0
        for _, c in ipairs(list) do
            local key = c.name .. "/" .. c.keyspec
            if key ~= current then
                t:assert(not seen[key], "table " .. key .. " does not reappear after another's cells")
                seen[key] = true
                current = key
                groups = groups + 1
            end
        end
        t:assert_eq(groups, 4, "four tables: (grp, none), (grp, SrcAddr), (grp, DstAddr), (other, SrcAddr)")
        t:assert_eq(#of(list, "grp", ntfe.KEY.SRC_ADDR), 3, "grouped by (name, keyspec), the source table has three cells")
        t:assert_eq(#of(list, "grp", ntfe.KEY.DST_ADDR), 2, "the destination table two")
        t:assert_eq(#of(list, "other", ntfe.KEY.SRC_ADDR), 3, "and the other stream's table three")
    end)
