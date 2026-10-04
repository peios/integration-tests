-- PKM §6.6 — the stores: counters. COUNT emits into a stream; every
-- `Counter.<n>(...)` a rule reads is a view, and publication
-- materializes one table per (stream, key-spec), answering every window
-- its views ask for. Cells are keyed by the facts the key-spec names,
-- hashed into 1024 buckets; windows are rings of eight period-stamped
-- buckets, advanced lazily and approximate by one bucket. The store
-- outlives generations: tables are kept, created, migrated and retired
-- as the views change. The counters dump reports every cell.
--
-- Traffic is hand-built frames from the peer, so each datagram's source
-- address is whatever the test needs. The window tests set the guest's
-- wall clock, which is the clock the store stamps buckets with.
--
-- The 4096-cell cap is store-cap.test.lua's; reads and dumps racing
-- the publisher are store-race.test.lua's.
--
-- Own VM: the policy and the counter store are machine-wide state, and
-- these tests move the guest's clock.

local ntfe = require("helpers.ntfe")
local S = require("helpers.ntfe_store")

local vm = provium:vm("vntfestcnt", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))
local peer, net = ntfe.peer(vm)
local pfd = assert(ntfe.packet_socket(peer, net.peer))
local batch = S.batch_sender(peer, 512, 64)

local PASS_ALL = { all = { Actions = { "PASS" } } }

-- A policy passing everything plus `packet` rules in the Packet layer.
local function with(packet)
    local p = { all = { Actions = { "PASS" } } }
    for name, rule in pairs(packet or {}) do p[name] = rule end
    return { RawPacket = PASS_ALL, Packet = p, Flow = PASS_ALL }
end

-- A rule that never matches, whose conditions are the views listed:
-- views exist only where a rule reads them.
local function views(list)
    local rule = { ["DstPort.Equal"] = 1, Actions = { "PASS" } }
    for _, v in ipairs(list) do rule["Counter." .. v .. ".GreaterThan"] = 1000000000 end
    return rule
end

local E = ntfe.engine(vm, with())

-- One datagram from `src` to the VM's `dport`, on the wire. The veth
-- hands a frame to the VM within the peer's send, so the VM's seats have
-- judged it by the time this returns: nothing to wait for.
local function from(src, dport, payload)
    ntfe.send_frame(peer, pfd, S.udp_frame(net, src, net.addr, 40000, dport, payload))
end

-- One datagram from each of `sources`, in one sendmmsg.
local function from_each(sources, dport)
    local frames = {}
    for i, src in ipairs(sources) do frames[i] = S.udp_frame(net, src, net.addr, 40000, dport) end
    local n = batch:send(pfd, frames)
    assert(n == #frames, "sendmmsg took " .. tostring(n))
end

-- Move the guest's wall clock to `secs` (plus half a second, so the
-- whole second is unambiguous).
local function clock_at(secs)
    vm:clock():set(secs + 0.5)
end

-- A clock origin aligned to 1000 s and later than anything used before.
local function fresh_origin()
    return (math.floor(vm:clock():get() / 1000) + 2) * 1000
end

-- ---- tables --------------------------------------------------------------

test("publication makes one table per stream and key-spec, answering every window its views ask for",
    { spec = "PKM *ntfe-store.one-table-per-stream-and-key-spec PKM *ntfe-store.count-increments-every-table-of-stream" },
    function(t)
        local s = E:replace(with({
            count = { ["DstPort.Equal"] = 7301, Actions = { "COUNT(hits)" } },
            views = views({ "hits", "hits(10s)", "hits(1m)", "hits(SrcAddr)", "hits(30s, SrcAddr)" }),
        }))
        t:assert_eq(s.last_ingest_error, 0, "five views of one stream are accepted")
        local d = E:during(function()
            from("10.70.0.1", 7301); from("10.70.0.1", 7301); from("10.70.0.2", 7301)
        end)
        t:assert_eq(d.count_writes, 3, "three COUNTs land")
        local all = S.cells(E:counters(), "hits")
        local global, keyed = S.cells(all, "hits", 0), S.cells(all, "hits", ntfe.KEY.SRC_ADDR)
        t:assert_eq(#all, #global + #keyed, "the stream has tables for exactly two key-specs")
        t:assert_eq(#global, 1, "the unkeyed views share one table of one cell")
        local g = global[1]
        t:assert_eq(g.n_windows, 2, "which answers both its views' windows")
        t:assert_eq(g.windows[10], 3, "10 s: all three")
        t:assert_eq(g.windows[60], 3, "1 m: all three")
        t:assert_eq(g.total, 3, "plus the cumulative total, which no view had to ask for")
        t:assert_eq(#keyed, 2, "the SrcAddr views share the other table, a cell per source")
        t:assert_eq(keyed[1].n_windows, 1, "answering the one window they ask for")
        local a, b = S.cell_from(keyed, "10.70.0.1"), S.cell_from(keyed, "10.70.0.2")
        t:assert(a and b, "one cell for each source")
        t:assert_eq(a.total, 2, "the first source counted twice")
        t:assert_eq(b.total, 1, "the second once")
        t:assert_eq(a.windows[30], 2, "in its window too")
        t:assert_eq(a.total + b.total, g.total,
            "every COUNT incremented both tables of the stream")
    end)

test("a cell's key holds the facts its key-spec names, and zero for the rest",
    { spec = "PKM *ntfe-store.cell-key-holds-only-named-facts" }, function(t)
        E:replace(with({
            count = { ["DstPort.Equal"] = 7302, Actions = { "COUNT(keys)" } },
            views = views({ "keys", "keys(SrcAddr)", "keys(DstAddr)", "keys(Interface)",
                            "keys(SrcAddr+DstAddr+Interface)" }),
        }))
        from("10.71.0.5", 7302)
        local cells = S.cells(E:counters(), "keys")
        local function only(spec)
            local list = S.cells(cells, "keys", spec)
            t:assert_eq(#list, 1, "one cell for key-spec " .. spec)
            return list[1]
        end
        local src = only(ntfe.KEY.SRC_ADDR)
        t:assert_eq(src.family, 4, "SrcAddr: the family is kept")
        t:assert_eq(src.src, "10.71.0.5", "with the source")
        t:assert_eq(src.dst, "0.0.0.0", "the destination zero")
        t:assert_eq(src.ifindex, 0, "and no interface")
        local dst = only(ntfe.KEY.DST_ADDR)
        t:assert_eq(dst.src, "0.0.0.0", "DstAddr: the source zero")
        t:assert_eq(dst.dst, net.addr, "the destination kept")
        t:assert_eq(dst.ifindex, 0, "no interface")
        local iface = only(ntfe.KEY.INTERFACE)
        t:assert_eq(iface.family, 0, "Interface: no address family")
        t:assert_eq(iface.src, nil, "no addresses")
        t:assert_eq(iface.ifindex, net.ifindex, "just the interface")
        local every = only(ntfe.KEY.SRC_ADDR | ntfe.KEY.DST_ADDR | ntfe.KEY.INTERFACE)
        t:assert(every.src == "10.71.0.5" and every.dst == net.addr
            and every.ifindex == net.ifindex, "all three when all three are named")
        local none = only(0)
        t:assert(none.family == 0 and none.ifindex == 0, "and nothing for the unkeyed cell")
    end)

test("a table is a 1024-bucket jhash of its cells: the dump walks them in bucket order",
    { spec = "PKM *ntfe-store.table-is-1024-bucket-hash-under-bh-lock" }, function(t)
        E:replace(with({
            count = { ["DstPort.Equal"] = 7303, Actions = { "COUNT(spread)" } },
            views = views({ "spread(SrcAddr)" }),
        }))
        local sources = {}
        for i = 1, 300 do sources[i] = string.format("10.72.%d.%d", i // 200, i % 200 + 1) end
        from_each(sources, 7303)
        local cells = S.cells(E:counters(512), "spread", ntfe.KEY.SRC_ADDR)
        t:assert_eq(#cells, 300, "300 sources, 300 cells")
        local last, distinct, seen, ordered = -1, 0, {}, true
        for _, c in ipairs(cells) do
            local b = S.bucket_of(c)
            if b < last then ordered = false end
            last = b
            if not seen[b] then seen[b] = true; distinct = distinct + 1 end
        end
        t:assert(ordered, "the dump order is jhash(key, 0x504e5043) & 1023, ascending")
        t:assert(distinct > 200, "with the keys spread over many of the buckets: " .. distinct)
    end)

-- ---- the absent-fact law, both sides ---------------------------------------

test("a packet lacking a keyed fact has no cell: its COUNT no-ops into that table and is confessed",
    { spec = "PKM *ntfe-store.count-without-key-fact-no-ops PKM *ntfe-store.view-without-key-fact-reads-absent" },
    function(t)
        local MAC = "\x02\x00\x00\x00\x73\x04"
        local mine = { ["Direction.Equal"] = "in", ["SrcMac.Equal"] = "02:00:00:00:73:04" }
        local function rule(extra)
            local r = {}
            for k, v in pairs(mine) do r[k] = v end
            for k, v in pairs(extra) do r[k] = v end
            return r
        end
        E:replace({
            RawPacket = {
                all = { Actions = { "PASS" } },
                count = rule({ Actions = { "COUNT(frames)" } }),
                keyed = rule({ ["Counter.frames(SrcAddr).LessThan"] = 1000000000,
                               Priority = 20, Actions = { "PASS" } }),
                global = rule({ ["Counter.frames.GreaterThan"] = 0,
                                Priority = 10, Actions = { "PASS" } }),
            },
            Packet = PASS_ALL, Flow = PASS_ALL,
        })
        local function arp()
            return ntfe.eth(ntfe.MAC_BROADCAST, MAC, ntfe.ETH_P.ARP)
                .. ntfe.arp_request(MAC, "10.73.0.1", "10.73.0.254")
        end
        local function ip()
            local udp = ntfe.udp("10.73.0.1", net.addr, 40000, 7304, "x")
            return ntfe.eth(net.mac, MAC, ntfe.ETH_P.IP)
                .. ntfe.ipv4("10.73.0.1", net.addr, ntfe.IPPROTO.UDP, #udp) .. udp
        end
        local function judged(frame)
            local d, events = E:during(function() ntfe.send_frame(peer, pfd, frame) end)
            local at = ntfe.matching(events, { layer = ntfe.LAYER.RAWPACKET, seat = ntfe.SEAT.INGRESS })
            return at[1] and at[1].attributed, d
        end
        local by, d = judged(arp())
        t:assert_eq(d.count_key_absent, 1, "an ARP frame's COUNT finds no SrcAddr for the keyed table")
        t:assert_eq(d.count_writes, 1, "while the unkeyed table still takes it")
        t:assert_eq(by, "all", "the first frame reads neither view: nothing was counted yet")
        by = judged(arp())
        t:assert_eq(by, "global", "the second ARP frame reads the unkeyed view, never the keyed one")
        by = judged(ip())
        t:assert_eq(by, "global", "an IPv4 frame's own keyed cell does not exist before its COUNT")
        by, d = judged(ip())
        t:assert_eq(by, "keyed", "the next one from that source reads its keyed cell")
        t:assert_eq(d.count_key_absent, 0, "and an IPv4 frame is never absent from the keyed table")
        local keyed = S.cells(E:counters(), "frames", ntfe.KEY.SRC_ADDR)
        t:assert_eq(#keyed, 1, "the keyed table holds the IPv4 source's cell alone")
        t:assert_eq(keyed[1].src, "10.73.0.1", "keyed by its address")
        t:assert_eq(keyed[1].total, 2, "counting only the IPv4 frames")
        t:assert_eq(S.cells(E:counters(), "frames", 0)[1].total, 4,
            "while the unkeyed cell counted all four")
    end)

-- ---- windows -----------------------------------------------------------

test("a window is a ring of eight period-stamped buckets, read as the sum of the last eight periods",
    { spec = "PKM *ntfe-store.ring-is-eight-period-stamped-buckets PKM *ntfe-store.read-sums-last-eight-periods" },
    function(t)
        E:replace(with({
            count = { ["DstPort.Equal"] = 7305, Actions = { "COUNT(ring)" } },
            views = views({ "ring(80s)" }),
        }))
        -- 80 s / 8: buckets are 10 s periods.
        local base = fresh_origin()
        local function window()
            local c = S.cells(E:counters(), "ring")[1]
            return c.windows[80], c.total
        end
        for k = 0, 7 do
            clock_at(base + 10 * k + 1)
            for _ = 0, k do from("10.74.0.1", 7305) end
        end
        local w, total = window()
        t:assert_eq(total, 36, "1 + 2 + ... + 8 datagrams over eight periods")
        t:assert_eq(w, 36, "all eight periods are inside the window")
        clock_at(base + 80 + 1)
        w = window()
        t:assert_eq(w, 35, "a period later the first bucket (1) has aged out, alone")
        clock_at(base + 90 + 1)
        w = window()
        t:assert_eq(w, 33, "then the second (2), bucket by bucket")
        from("10.74.0.1", 7305)
        w, total = window()
        t:assert_eq(w, 34, "a new period's write lands in the ring")
        t:assert_eq(total, 37, "and the total never forgets")
        clock_at(base + 160 + 1)
        w = window()
        t:assert_eq(w, 1, "seven periods on, only that newest bucket remains")
        clock_at(base + 170 + 1)
        t:assert_eq(window(), 0, "and at the eighth, none")
    end)

test("a write into a bucket whose stamp is stale zeroes it first",
    { spec = "PKM *ntfe-store.write-zeroes-stale-bucket" }, function(t)
        E:replace(with({
            count = { ["DstPort.Equal"] = 7306, Actions = { "COUNT(stale, 5)" } },
            views = views({ "stale(80s)" }),
        }))
        local base = fresh_origin()
        clock_at(base + 1)
        from("10.74.0.2", 7306)
        t:assert_eq(S.cells(E:counters(), "stale")[1].windows[80], 5, "5 in the period's bucket")
        -- Eight periods later the ring has come round to the same bucket.
        clock_at(base + 80 + 1)
        from("10.74.0.2", 7306)
        local c = S.cells(E:counters(), "stale")[1]
        t:assert_eq(c.windows[80], 5, "the same bucket reads 5, not 10: the old count was zeroed")
        t:assert_eq(c.total, 10, "while the total holds both")
    end)

test("the window is approximate by up to one bucket",
    { spec = "PKM *ntfe-store.window-approximate-to-one-bucket" }, function(t)
        E:replace(with({
            count = { ["DstPort.Equal"] = 7307, Actions = { "COUNT(approx)" } },
            views = views({ "approx(80s)" }),
        }))
        local base = fresh_origin()
        local function window() return S.cells(E:counters(), "approx")[1].windows[80] end
        clock_at(base + 9)  -- the last second of a 10 s period
        from("10.74.0.3", 7307)
        clock_at(base + 10) -- the first second of the next
        from("10.74.0.3", 7307)
        clock_at(base + 80)
        t:assert_eq(window(), 1,
            "71 s after it, the first datagram has already left an 80 s window")
        clock_at(base + 89)
        t:assert_eq(window(), 1, "79 s after it, the second is still inside")
        clock_at(base + 90)
        t:assert_eq(window(), 0, "and leaves at 80 s")
    end)

-- ---- generations ----------------------------------------------------------

test("the store outlives generations: a table whose views did not change is kept as it was",
    { spec = "PKM *ntfe-store.counter-store-outlives-generations PKM *ntfe-store.republish-keeps-unchanged-tables" },
    function(t)
        local count = { ["DstPort.Equal"] = 7308, Actions = { "COUNT(keep)" } }
        local before = E:replace(with({ count = count, views = views({ "keep(1m)" }) }))
        from("10.75.0.1", 7308); from("10.75.0.1", 7308); from("10.75.0.1", 7308)
        local was = S.cells(E:counters(), "keep")[1]
        local after = E:replace(with({
            count = count, views = views({ "keep(1m)" }),
            unrelated = { ["DstPort.Equal"] = 7399, Actions = { "DROP" } },
        }))
        t:assert_eq(after.generation, before.generation + 1, "a new generation is published")
        local now = S.cells(E:counters(), "keep")
        t:assert_eq(#now, 1, "the stream's one cell is still there")
        t:assert_eq(now[1].total, was.total, "its total untouched")
        t:assert_eq(now[1].windows[60], 3, "its window untouched")
        t:assert_eq(now[1].last_secs, was.last_secs, "its last write untouched")
        from("10.75.0.1", 7308)
        t:assert_eq(S.cells(E:counters(), "keep")[1].total, 4,
            "and the next COUNT carries on from it")
    end)

test("re-publication creates the tables new views ask for, empty",
    { spec = "PKM *ntfe-store.republish-creates-new-tables" }, function(t)
        local count = { ["DstPort.Equal"] = 7309, Actions = { "COUNT(grow)" } }
        E:replace(with({ count = count, views = views({ "grow" }) }))
        from("10.75.0.2", 7309); from("10.75.0.2", 7309)
        local s = E:replace(with({ count = count, views = views({ "grow", "grow(SrcAddr)" }) }))
        t:assert_eq(s.last_ingest_error, 0, "a view on a new key-spec is accepted")
        t:assert_eq(#S.cells(E:counters(), "grow", ntfe.KEY.SRC_ADDR), 0,
            "its table starts with no cells")
        from("10.75.0.2", 7309)
        local keyed = S.cells(E:counters(), "grow", ntfe.KEY.SRC_ADDR)
        t:assert_eq(#keyed, 1, "the next COUNT gives it one")
        t:assert_eq(keyed[1].total, 1, "counting from that COUNT on")
        t:assert_eq(S.cells(E:counters(), "grow", 0)[1].total, 3,
            "beside the old table, which kept its history")
    end)

test("re-publication migrates a table whose windows changed: the total and shared windows carry over, new windows start empty",
    { spec = "PKM *ntfe-store.republish-migrates-changed-tables" }, function(t)
        local count = { ["DstPort.Equal"] = 7310, Actions = { "COUNT(mig)" } }
        E:replace(with({ count = count, views = views({ "mig(1m)", "mig(5m)" }) }))
        for _ = 1, 4 do from("10.75.0.3", 7310) end
        E:replace(with({ count = count, views = views({ "mig(1m)", "mig(30s)" }) }))
        local c = S.cells(E:counters(), "mig")
        t:assert_eq(#c, 1, "the cell survives the migration")
        c = c[1]
        t:assert_eq(c.n_windows, 2, "re-laid out for the new window set")
        t:assert_eq(c.windows[300], nil, "the dropped window is gone")
        t:assert_eq(c.windows[60], 4, "the window both sets share carried over")
        t:assert_eq(c.windows[30], 0, "the new window starts empty")
        t:assert_eq(c.total, 4, "the total carried over")
        from("10.75.0.3", 7310)
        c = S.cells(E:counters(), "mig")[1]
        t:assert_eq(c.windows[30], 1, "and converges from there")
        t:assert_eq(c.windows[60], 5, "beside the carried window")
    end)

test("re-publication retires a table no forest views any more, cells and all",
    { spec = "PKM *ntfe-store.republish-retires-unviewed-tables" }, function(t)
        local count = { ["DstPort.Equal"] = 7311, Actions = { "COUNT(gone)" } }
        E:replace(with({ count = count, views = views({ "gone", "gone(SrcAddr)" }) }))
        from("10.75.0.4", 7311); from("10.75.0.5", 7311)
        t:assert_eq(#S.cells(E:counters(), "gone"), 3, "two tables, three cells")
        E:replace(with({ count = count }))
        local live = E:counters()
        t:assert_eq(#S.cells(live, "gone"), 0,
            "once nothing views the stream, its tables leave the dump")
        -- The cells are freed after an RCU grace period, when the status'
        -- cell count falls to what the live tables hold.
        local freed = false
        for _ = 1, 100 do
            if E:status().counter_cells == #live then freed = true; break end
            vm:clock():sleep("20ms")
        end
        t:assert(freed, "and their cells are freed: " .. E:status().counter_cells)
        local d = E:during(function() from("10.75.0.4", 7311) end)
        t:assert_eq(d.fx_counts, 1, "a COUNT into the stream is still issued")
        t:assert_eq(d.count_writes, 0, "but lands nowhere")
        E:replace(with({ count = count, views = views({ "gone" }) }))
        from("10.75.0.4", 7311)
        t:assert_eq(S.cells(E:counters(), "gone")[1].total, 1,
            "viewing it again starts a fresh table: the history was freed")
    end)

-- ---- the dump -----------------------------------------------------------

test("the counters dump reports every cell: stream, key-spec, key, total, last write and each window",
    { spec = "PKM *ntfe-store.counters-ioctl-dumps-every-cell" }, function(t)
        E:replace(with({
            count = { ["DstPort.Equal"] = 7312, Actions = { "COUNT(dumped, 3)" } },
            views = views({ "dumped(10s, SrcAddr)", "dumped(2m, SrcAddr)" }),
        }))
        local t0 = math.floor(vm:clock():get())
        from("10.76.0.1", 7312); from("10.76.0.2", 7312); from("10.76.0.2", 7312)
        local t1 = math.floor(vm:clock():get())
        local all = E:counters()
        t:assert_eq(#all, all.total, "a big enough buffer receives every cell there is")
        local cells = S.cells(all, "dumped")
        t:assert_eq(#cells, 2, "this stream's two")
        local c = S.cell_from(cells, "10.76.0.2")
        t:assert_eq(c.name, "dumped", "named by stream")
        t:assert_eq(c.hash, ntfe.name_hash("dumped"), "with the stream's hash")
        t:assert_eq(c.keyspec, ntfe.KEY.SRC_ADDR, "its key-spec")
        t:assert_eq(c.family, 4, "the key's family")
        t:assert_eq(c.src, "10.76.0.2", "and address")
        t:assert_eq(c.total, 6, "the total: two COUNTs of 3")
        t:assert(c.last_secs >= t0 and c.last_secs <= t1,
            "the last write, in CLOCK_REALTIME seconds: " .. c.last_secs)
        t:assert_eq(c.n_windows, 2, "and every window the table answers")
        t:assert_eq(c.windows[10], 6, "10 s")
        t:assert_eq(c.windows[120], 6, "2 m")
        local short = E:counters(1)
        t:assert_eq(#short, 1, "a buffer of one record receives one")
        t:assert_eq(short.total, all.total, "and is told how many cells exist")
    end)
