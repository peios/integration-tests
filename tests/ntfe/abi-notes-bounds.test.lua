-- PKM §6.B — "Bounds not in the header": the event ring, the records one
-- read() returns, the cells a counter table holds, the distinct tags a
-- flow carries, the depth of a rule tree, and the longest counter
-- window. Each is driven to the bound and one past it.
--
-- The 4096-rules-per-layer half of the ingestion bound has its own file
-- (abi-notes-rules), because a walk of 4096 rules takes tens of seconds.
--
-- Own VM: the policy, the ring and the stores are machine-wide state.

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")
local raw = require("helpers.ntfe_abi_notes")

local vm = provium:vm("vntfeabibnd", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))

local PASS_ALL = { all = { Actions = { "PASS" } } }
-- Port 7777 is dropped by the Packet layer at egress, past the flow's
-- sentence: one datagram, one event.
local BASE = {
    RawPacket = PASS_ALL, Flow = PASS_ALL,
    Packet = { all = { Actions = { "PASS" } },
               sink = { ["DstPort.Equal"] = 7777, Actions = { "DROP" } } },
}
local E = ntfe.engine(vm, BASE)
local sink = assert(ntfe.udp_connect(vm, "127.0.0.1", 7777))

-- A dummy link with a /16: NOARP, so a datagram to any address on it
-- reaches the egress seat at once, and a flow there has one local end.
assert(ntfe.link_add(vm, "dum0", "dummy"))
assert(ntfe.if_addr(vm, "dum0", "10.200.0.1", 16))

--- Empty the ring through the engine's reader, the sink's flow fresh so
--- that each datagram after this is exactly one event. Returns the last
--- sequence number read.
local function quiet()
    raw.flood(vm, sink, 1)
    local last = raw.drain(vm, E:stream())
    return last[#last] and last[#last].seq
end

-- ---- the event ring ----

test("the event ring holds 4096 records and overwrites the oldest",
    { spec = "PKM *ntfe-abi-notes.bound-event-ring-4096" }, function(t)
        local last = quiet()
        local s0 = E:status()
        -- Fill to exactly 4096 without reading, counting from the status.
        local emitted = 0
        while emitted < 4096 do
            raw.flood(vm, sink, 4096 - emitted)
            emitted = raw.emitted(s0, E:status())
        end
        local full = E:status()
        t:assert_eq(emitted, 4096, "4096 events are waiting")
        t:assert_eq(full.events_dropped, s0.events_dropped, "and the ring holds them all")
        raw.flood(vm, sink, 1)
        local over = E:status()
        t:assert_eq(raw.emitted(s0, over), 4097, "one more")
        t:assert_eq(over.events_dropped - s0.events_dropped, 1, "overwrites one")
        local got = raw.drain(vm, E:stream())
        t:assert_eq(#got, 4096, "the ring gives back 4096")
        t:assert_eq(got[1].seq, last + 2, "the oldest is the one lost")
        t:assert_eq(got[#got].seq, last + 4097, "and the newest is kept")
    end)

test("one read() returns at most 64 records",
    { spec = "PKM *ntfe-abi-notes.bound-read-64-records" }, function(t)
        quiet()
        raw.flood(vm, sink, 200)
        local fd = E:stream()
        local function read(room) return (raw.read(vm, fd, room * ntfe.EVENT_SIZE)) end
        t:assert_eq(read(64), 64 * ntfe.EVENT_SIZE, "room for 64 reads 64")
        t:assert_eq(read(65), 64 * ntfe.EVENT_SIZE, "room for 65 still reads 64")
        t:assert_eq(read(200), 64 * ntfe.EVENT_SIZE, "and so does room for 200")
        t:assert_eq(read(200), 8 * ntfe.EVENT_SIZE, "the 8 left come with the next read")
    end)

-- ---- the stores ----

test("a counter table holds at most 4096 cells; the next key is refused and counted",
    { spec = "PKM *ntfe-abi-notes.bound-counter-cells-per-table-4096" }, function(t)
        -- Destinations across the dummy link's /16, each a new DstAddr key.
        local s = E:replace({
            RawPacket = PASS_ALL, Flow = PASS_ALL,
            Packet = {
                all = { Actions = { "PASS" } },
                count = { ["Interface.Equal"] = "dum0", ["Direction.Equal"] = "out",
                          Actions = { "COUNT(dests)", "PASS" } },
                view = { ["DstPort.Equal"] = 1, ["Counter.dests(DstAddr).GreaterThan"] = 4000000000,
                         Actions = { "DROP" } },
            },
        })
        t:assert_eq(s.last_ingest_error, 0, "the counting policy is accepted")
        local dests = {}
        for i = 2, 4098 do dests[#dests + 1] = string.format("10.200.%d.%d", i // 256, i % 256) end
        local fd = assert(ntfe.socket(vm, ntfe.AF_INET, ntfe.SOCK_DGRAM))
        local s0 = E:status()
        raw.spray(vm, fd, { table.unpack(dests, 1, 4096) }, 9)
        local s1 = E:status()
        t:assert_eq(raw.dump(vm, E.dev, "counters", 0).total, 4096, "4096 destinations, 4096 cells")
        t:assert_eq(s1.count_refused, s0.count_refused, "every one accepted")
        raw.spray(vm, fd, { dests[4097] }, 9)
        local s2 = E:status()
        t:assert_eq(s2.count_refused - s1.count_refused, 1, "the 4097th key is refused and counted")
        t:assert_eq(raw.dump(vm, E.dev, "counters", 0).total, 4096, "and the table stays at 4096")
        sys.close(vm, fd)
        E:replace(BASE)
    end)

test("a flow carries at most 64 distinct tags; the next is refused and counted",
    { spec = "PKM *ntfe-abi-notes.bound-tags-per-flow-64" }, function(t)
        local function tags(n)
            local a = { "PASS" }
            for i = 1, n do a[#a + 1] = "TAG(t" .. i .. ", Set)" end
            return a
        end
        E:replace({ RawPacket = PASS_ALL, Packet = PASS_ALL, Flow = {
            all = { Actions = { "PASS" } },
            sixty_four = { ["DstPort.Equal"] = 7781, Actions = tags(64) },
            sixty_five = { ["DstPort.Equal"] = 7782, Actions = tags(65) },
        } })
        local function flow_to(port)
            local before = E:status()
            -- Off the loopback: a flow judged once, at one end.
            local fd = assert(ntfe.udp_connect(vm, "10.200.9.9", port))
            ntfe.send(vm, fd, "t")
            sys.close(vm, fd)
            local after = E:status()
            return after.tag_writes - before.tag_writes, after.tag_refused - before.tag_refused
        end
        local w, r = flow_to(7781)
        t:assert_eq(w, 64, "a flow takes 64 distinct tags")
        t:assert_eq(r, 0, "none refused")
        w, r = flow_to(7782)
        t:assert_eq(w, 64, "a 65th distinct tag is not written")
        t:assert_eq(r, 1, "it is refused and counted")
        E:replace(BASE)
    end)

-- ---- ingestion ----

--- A chain of `n` rule keys, each the only exception of the one above.
local function chain(n)
    local rule = { Actions = { "PASS" } }
    for i = n - 1, 1, -1 do
        rule = { Actions = { "PASS" }, children = { ["d" .. i] = rule } }
    end
    return { d0 = rule }
end

test("a rule tree nests at most 12 deep below its root",
    { spec = "PKM *ntfe-abi-notes.bound-rule-depth-12-rules-4096" }, function(t)
        local before = E:status().generation
        local s = E:replace({ RawPacket = PASS_ALL, Packet = PASS_ALL, Flow = chain(13) })
        t:assert_eq(s.last_ingest_error, 0, "a root with exceptions 12 levels below it is accepted")
        t:assert_eq(s.generation, before + 1, "and published")
        s = E:replace({ RawPacket = PASS_ALL, Packet = PASS_ALL, Flow = chain(14) })
        t:assert_eq(s.last_ingest_error, sys.E.BIG2, "one level more refuses the generation (E2BIG)")
        t:assert_eq(s.generation, before + 1, "and the previous one stands")
        E:replace(BASE)
    end)

test("the longest counter window is 86 400 s",
    { spec = "PKM *ntfe-abi-notes.bound-counter-window-86400s" }, function(t)
        local function with_window(w)
            return E:replace({ RawPacket = PASS_ALL, Flow = PASS_ALL, Packet = {
                all = { Actions = { "PASS" } },
                count = { ["DstPort.Equal"] = 7783, ["Direction.Equal"] = "in",
                          Actions = { "COUNT(w)", "PASS" } },
                view = { ["DstPort.Equal"] = 1, ["Counter.w(" .. w .. ").GreaterThan"] = 4000000000,
                         Actions = { "DROP" } },
            } })
        end
        local s = with_window("86400s")
        t:assert_eq(s.last_ingest_error, 0, "a window of 86400 s is accepted")
        local fd = assert(ntfe.udp_connect(vm, "127.0.0.1", 7783))
        ntfe.send(vm, fd, "w")
        sys.close(vm, fd)
        local cell = nil
        for _, c in ipairs(assert(E:counters())) do if c.name == "w" then cell = c end end
        t:assert(cell and cell.windows[86400] == 1, "and the table keeps it")
        t:assert_eq(with_window("1d").last_ingest_error, 0, "so is `1d`")
        local gen = E:status().generation
        s = with_window("86401s")
        t:assert(s.last_ingest_error ~= 0, "one second longer refuses the generation")
        t:assert_eq(s.generation, gen, "and the previous one stands")
        t:assert(with_window("2d").last_ingest_error ~= 0, "as does `2d`")
        E:replace(BASE)
    end)
