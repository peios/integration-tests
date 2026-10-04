-- PKM §6.6 — the stores: the counter table's cap. A keyed table's
-- keyspace is chosen by whoever sends packets, so a table holds at most
-- 4096 cells. At the cap the store reaps cells idle for longer than the
-- table's longest window (floor 60 s) and only then admits the new key;
-- when nothing is idle the new key is refused and confessed in
-- `count_refused`. Never silent eviction.
--
-- 4096 sources are hand-built frames from the peer, a thousand to a
-- sendmmsg. Two tables of one stream, with different horizons, are
-- filled by the same COUNTs: SrcAddr with a 2 m window (idle after
-- 120 s) and SrcAddr+DstAddr with a 10 s window (idle after the 60 s
-- floor). Idleness is measured on the guest's wall clock, which the
-- tests set.
--
-- The tests run in order on one filled pair of tables.
--
-- Own VM: the policy and the counter store are machine-wide state, the
-- tables are left full, and the guest's clock is moved.

local ntfe = require("helpers.ntfe")
local S = require("helpers.ntfe_store")

local vm = provium:vm("vntfestcap", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))
local peer, net = ntfe.peer(vm)
local pfd = assert(ntfe.packet_socket(peer, net.peer))
local batch = S.batch_sender(peer, 1024, 64)

local PASS_ALL = { all = { Actions = { "PASS" } } }
local PORT = 7401
local CAP = 4096
local LONG = ntfe.KEY.SRC_ADDR                       -- 2 m window
local SHORT = ntfe.KEY.SRC_ADDR | ntfe.KEY.DST_ADDR  -- 10 s window

local E = ntfe.engine(vm, {
    RawPacket = PASS_ALL, Flow = PASS_ALL,
    Packet = {
        all = { Actions = { "PASS" } },
        count = { ["DstPort.Equal"] = PORT, Actions = { "COUNT(flood)" } },
        views = { ["DstPort.Equal"] = 1, Actions = { "PASS" },
                  ["Counter.flood(2m, SrcAddr).GreaterThan"] = 1000000000,
                  ["Counter.flood(10s, SrcAddr+DstAddr).GreaterThan"] = 1000000000 },
    },
})

-- Source number i, avoiding .0 and .255.
local function source(i)
    return string.format("10.%d.%d.%d", 80 + i // 62500, (i // 250) % 250, i % 250 + 1)
end

local function send_all(first, last)
    local frames = {}
    for i = first, last do
        frames[#frames + 1] = S.udp_frame(net, source(i), net.addr, 40000, PORT)
        if #frames == 1024 or i == last then
            local n = batch:send(pfd, frames)
            assert(n == #frames, "sendmmsg took " .. tostring(n))
            frames = {}
        end
    end
end

local function one(i)
    ntfe.send_frame(peer, pfd, S.udp_frame(net, source(i), net.addr, 40000, PORT))
end

local function tables()
    local all = E:counters(2 * CAP + 64)
    return S.cells(all, "flood", LONG), S.cells(all, "flood", SHORT)
end

local function clock_at(secs) vm:clock():set(secs + 0.5) end

local T = (math.floor(vm:clock():get() / 1000) + 2) * 1000

test("a table holds at most 4096 cells; a new key at the cap with nothing idle is refused and confessed",
    { spec = "PKM *ntfe-store.table-capped-at-4096-cells PKM *ntfe-store.cap-refuses-new-key-when-none-idle" },
    function(t)
        clock_at(T)
        local filled = E:during(function() send_all(0, CAP - 1) end)
        t:assert_eq(filled.count_writes, CAP, "4096 sources are counted")
        t:assert_eq(filled.count_refused, 0, "with nothing refused")
        local long, short = tables()
        t:assert_eq(#long, CAP, "the SrcAddr table holds 4096 cells")
        t:assert_eq(#short, CAP, "as does the SrcAddr+DstAddr table")

        local refused = E:during(function() one(CAP) end)
        t:assert_eq(refused.fx_counts, 1, "the 4097th source's COUNT is issued")
        t:assert_eq(refused.count_refused, 2, "both full tables refuse its new key, confessed")
        t:assert_eq(refused.count_writes, 0, "and no table took it")
        long, short = tables()
        t:assert_eq(#long, CAP, "the table is still at the cap")
        t:assert_eq(S.cell_from(long, source(CAP)), nil, "without the refused key")
        t:assert(S.cell_from(long, source(0)), "and without having evicted anybody")

        local known = E:during(function() one(0) end)
        t:assert_eq(known.count_refused, 0, "a key the table already holds is never refused")
        t:assert_eq(known.count_writes, 1, "it is counted")
        t:assert_eq(S.cell_from(tables(), source(0)).total, 2, "in its own cell")
    end)

test("at the cap, cells idle past the table's longest window (floor 60 s) are reaped to admit a new key",
    { spec = "PKM *ntfe-store.cap-reaps-idle-cells-first" }, function(t)
        -- 30 s on: past the short table's 10 s window but inside the 60 s
        -- floor, so nothing is idle in either table.
        clock_at(T + 30)
        local d = E:during(function() one(CAP + 1) end)
        t:assert_eq(d.count_refused, 2, "under the 60 s floor nothing is idle: both refuse")

        -- 65 s on, keep ten sources fresh, then bring a new one.
        clock_at(T + 65)
        send_all(1, 10)
        d = E:during(function() one(CAP + 2) end)
        t:assert_eq(d.count_refused, 1,
            "the 2 m table still refuses: its cells are idle 65 s, not past 120 s")
        t:assert_eq(d.count_writes, 1, "the 10 s table admits the key")
        local long, short = tables()
        t:assert_eq(#long, CAP, "the 2 m table is untouched")
        t:assert_eq(#short, 11, "the 10 s table reaped every cell idle past 60 s: ten fresh ones and the new key remain")
        for i = 1, 10 do
            t:assert(S.cell_from(short, source(i)), "fresh source " .. i .. " survives")
        end
        t:assert(S.cell_from(short, source(CAP + 2)), "beside the new key")

        -- 125 s on: the 2 m table's untouched cells are idle past 120 s;
        -- the ten refreshed at 65 s are not.
        clock_at(T + 125)
        d = E:during(function() one(CAP + 3) end)
        t:assert_eq(d.count_refused, 0, "the 2 m table now admits a new key")
        long = tables()
        t:assert_eq(#long, 11, "after reaping its idle cells: ten fresh ones and the new key remain")
        for i = 1, 10 do
            t:assert(S.cell_from(long, source(i)), "fresh source " .. i .. " survives there too")
        end
        t:assert(S.cell_from(long, source(CAP + 3)), "beside the new key")
        t:assert_eq(E:status().counter_cells, #long + #select(2, tables()),
            "and the status counts only the cells that remain")
    end)
