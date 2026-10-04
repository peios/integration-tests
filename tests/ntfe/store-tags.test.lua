-- PKM §6.6 — the stores: identities and flow tags. Names cross into the
-- stores as FNV-1a-64 hashes and nothing else, so a tag outlives every
-- policy that wrote it and a colliding pair of names refuses the
-- generation that holds both. Flow tags live behind NTFE's conntrack
-- extension: a table allocated by the first TAG, grown by doubling to
-- the 64-tag tripwire, with Set / Add / Clear, saturation, tombstones,
-- and the three confessions.
--
-- The tags are read two ways: the flows dump, which reports up to eight
-- tags per flow by hash and in table order (helpers/ntfe_store keeps
-- the order), and a second packet of the same flow whose rules condition
-- on `Tag.<name>` — effects land after collation, so a packet reads what
-- the packets before it wrote. Datagrams of one flow are told apart by
-- their `Length` (28 bytes of IPv4 and UDP header plus the payload).
--
-- The memory-ordering statements of the tag store (lock-free readers,
-- serialized writers, entry before length) are exercised under real
-- concurrency in store-race.test.lua.
--
-- Own VM: the policy is machine-wide state, and the flow-death test
-- turns conntrack's UDP timeout down for the whole machine.

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")
local S = require("helpers.ntfe_store")

local vm = provium:vm("vntfestags", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))
local peer, net = ntfe.peer(vm)

local PASS_ALL = { all = { Actions = { "PASS" } } }

-- A policy passing everything, plus `packet` rules in the Packet layer
-- and `flow` rules in the Flow layer.
local function with(packet, flow)
    local p = { all = { Actions = { "PASS" } } }
    for name, rule in pairs(packet or {}) do p[name] = rule end
    local f = { all = { Actions = { "PASS" } } }
    for name, rule in pairs(flow or {}) do f[name] = rule end
    return { RawPacket = PASS_ALL, Packet = p, Flow = f }
end

local E = ntfe.engine(vm, with())

-- One peer-to-VM UDP flow per port: a VM socket bound to it and a peer
-- socket connected to it, kept for the whole file so later datagrams
-- belong to the same flow.
local socks = {}
local function sock(port)
    if not socks[port] then
        socks[port] = {
            l = assert(ntfe.udp_bind(vm, net.addr, port)),
            c = assert(ntfe.udp_connect(peer, net.addr, port)),
        }
    end
    return socks[port]
end

-- One datagram of the flow to `port`, `Length` = 28 + #payload.
local function send(port, payload)
    local s = sock(port)
    local r = ntfe.send(peer, s.c, payload)
    assert(r.ret == #payload, "send: " .. sys.errname(r.errno or 0))
    ntfe.recv(vm, s.l, 200)
end

-- Send one datagram; return the rule the Packet layer attributed it to
-- at the inbound seat, and the status deltas.
local function judged(port, payload)
    local delta, events = E:during(function() send(port, payload) end)
    local at = ntfe.matching(events, {
        layer = ntfe.LAYER.PACKET, seat = ntfe.SEAT.LOCAL_IN, dst_port = port,
    })
    return at[1] and at[1].attributed, delta, events
end

-- The flow to `port` in the flows dump (helpers/ntfe's decoding).
local function flow_to(port)
    for _, f in ipairs(E:flows()) do
        if f.protocol == ntfe.IPPROTO.UDP and f.dst_port == port then return f end
    end
end

-- The same flow's tags in table order.
local function ordered_tags(port)
    for _, f in ipairs(S.flow_tag_order(vm, E.dev)) do
        if f.protocol == ntfe.IPPROTO.UDP and f.dst_port == port then return f.tags end
    end
    return {}
end

local function hashes(names)
    local out = {}
    for i, n in ipairs(names) do out[i] = ntfe.name_hash(n) end
    return out
end

local function hash_list(tags)
    local out = {}
    for i, tg in ipairs(tags) do out[i] = tg.hash end
    return out
end

local function same_list(a, b)
    if #a ~= #b then return false end
    for i = 1, #a do if a[i] ~= b[i] then return false end end
    return true
end

-- A Lua list of `TAG(<prefix><i>, Set, <i>)` for i = first..last.
local function set_tags(prefix, first, last)
    local out = {}
    for i = first, last do
        out[#out + 1] = string.format("TAG(%s%d, Set, %d)", prefix, i, i)
    end
    return out
end

-- ---- identities -------------------------------------------------------

test("tag and stream names reach the stores as their FNV-1a-64 hashes",
    { spec = "PKM *ntfe-store.names-cross-as-fnv1a-hashes" }, function(t)
        local s = E:replace(with({
            w = { ["DstPort.Equal"] = 7201, Actions = { "TAG(alpha, Set, 5)", "COUNT(beta)" } },
            view = { ["Counter.beta.GreaterThan"] = 1000000, Actions = { "PASS" } },
        }))
        t:assert_eq(s.last_ingest_error, 0, "the policy is accepted")
        send(7201, "x")
        local f = flow_to(7201)
        t:assert(f, "the flow is in the dump")
        t:assert_eq(f.n_tags, 1, "carrying one tag")
        t:assert_eq(f.tags[ntfe.name_hash("alpha")], 5,
            "filed under FNV-1a-64(\"alpha\")")
        t:assert_eq(f.tags[ntfe.name_hash("Alpha")], nil,
            "a hash of the bytes as written, not of a folded name")
        local cells = S.cells(E:counters(), "beta")
        t:assert_eq(#cells, 1, "the stream has its cell")
        t:assert_eq(cells[1].hash, ntfe.name_hash("beta"),
            "and the counter table is keyed by FNV-1a-64(\"beta\")")
    end)

test("the stores know a tag or a stream by its hash alone, not by the rule or generation that wrote it",
    { spec = "PKM *ntfe-store.stores-hold-no-strings-or-generations" }, function(t)
        local view = { ["Counter.shared-stream.GreaterThan"] = 1000000, Actions = { "PASS" } }
        local first = E:replace(with({
            ["first-writer"] = { ["DstPort.Equal"] = 7203,
                Actions = { "TAG(shared, Add, 1)", "COUNT(shared-stream)" } },
            view = view,
        }))
        send(7203, "x")
        send(7203, "x")
        -- A different rule, in a later generation, writing the same names.
        local second = E:replace(with({
            ["second-writer"] = { ["DstPort.Equal"] = 7203,
                Actions = { "TAG(shared, Add, 10)", "COUNT(shared-stream, 10)" } },
            view = view,
        }))
        t:assert_eq(second.generation, first.generation + 1, "a new generation is in force")
        send(7203, "x")
        local f = flow_to(7203)
        t:assert_eq(f.tags[ntfe.name_hash("shared")], 12,
            "the second writer adds to what the first wrote: one tag, 2 + 10")
        local cells = S.cells(E:counters(), "shared-stream")
        t:assert_eq(#cells, 1, "one counter cell")
        t:assert_eq(cells[1].total, 12, "whose total runs on across the generations")
    end)

test("a tag survives a policy reload: the next generation reads what the last one wrote",
    { spec = "PKM *ntfe-store.tags-survive-policy-reload" }, function(t)
        E:replace(with({
            w = { ["DstPort.Equal"] = 7202, Actions = { "TAG(survivor, Set, 42)" } },
        }))
        send(7202, "x")
        -- The new generation no longer writes the tag at all; it reads it.
        local before = E:status().generation
        local s = E:replace(with({
            probe = { ["DstPort.Equal"] = 7202, ["Tag.survivor.Equal"] = 42,
                      Priority = 10, Actions = { "PASS" } },
        }))
        t:assert_eq(s.generation, before + 1, "the policy was reloaded")
        local by = judged(7202, "x")
        t:assert_eq(by, "probe", "a rule of the new generation reads the tag at 42")
        t:assert_eq(flow_to(7202).tags[ntfe.name_hash("survivor")], 42,
            "and the dump still shows it")
    end)

-- Two 16-character names with one FNV-1a-64 hash, found by a
-- distinguished-point rho search over hex names.
local COLLIDE_A, COLLIDE_B = "ed3da0c39046a113", "15bcce11382f7d0e"

test("a generation whose distinct tag or stream names collide is refused",
    { spec = "PKM *ntfe-store.colliding-names-refuse-generation" }, function(t)
        t:assert_eq(ntfe.name_hash(COLLIDE_A), ntfe.name_hash(COLLIDE_B),
            "the two names share a hash")
        t:assert(COLLIDE_A ~= COLLIDE_B, "and are distinct names")
        local function attempt(policy)
            local before = E:status().generation
            local s = E:replace(policy)
            return s.last_ingest_error, s.generation - before
        end
        -- Each name alone is an ordinary name.
        local err, moved = attempt(with({
            a = { ["DstPort.Equal"] = 7204, Actions = { "TAG(" .. COLLIDE_A .. ", Set, 1)" } },
        }))
        t:assert_eq(err, 0, "one of the pair alone is accepted")
        t:assert_eq(moved, 1, "and published")
        err, moved = attempt(with({
            b = { ["DstPort.Equal"] = 7204, Actions = { "TAG(" .. COLLIDE_B .. ", Set, 1)" } },
        }))
        t:assert_eq(err, 0, "as is the other")
        t:assert_eq(moved, 1, "published too")

        err, moved = attempt(with({
            a = { ["DstPort.Equal"] = 7204, Actions = {
                "TAG(" .. COLLIDE_A .. ", Set, 1)", "TAG(" .. COLLIDE_B .. ", Set, 1)" } },
        }))
        t:assert(err ~= 0, "both tags in one forest refuse the walk")
        t:assert_eq(moved, 0, "and the previous generation stands")

        err, moved = attempt(with({
            a = { ["DstPort.Equal"] = 7204, Actions = { "TAG(" .. COLLIDE_A .. ", Set, 1)" } },
        }, {
            b = { ["Tag." .. COLLIDE_B .. ".Present"] = 1, Actions = { "PASS" } },
        }))
        t:assert(err ~= 0, "a written tag colliding with one another forest reads is refused")
        t:assert_eq(moved, 0, "the store is machine-wide, so the check spans the forests")

        err, moved = attempt(with({
            a = { ["DstPort.Equal"] = 7204, Actions = {
                "COUNT(" .. COLLIDE_A .. ")", "COUNT(" .. COLLIDE_B .. ")" } },
        }))
        t:assert(err ~= 0, "two colliding stream names are refused the same way")
        t:assert_eq(moved, 0, "with nothing published")
    end)

-- ---- the conntrack extension -----------------------------------------

test("every flow carries the extension from creation, so a TAG lands even after conntrack confirmed the flow",
    { spec = "PKM *ntfe-store.ct-extension-added-at-flow-creation" }, function(t)
        -- The VM sends: the Packet layer judges this outbound traffic at
        -- the egress seat, after POST_ROUTING confirmed the flow and froze
        -- its extension block.
        E:replace(with({
            out = { ["Direction.Equal"] = "out", ["DstPort.Equal"] = 7205,
                    Actions = { "TAG(outbound, Set, 3)" } },
        }))
        local l = assert(ntfe.udp_bind(peer, net.peer_addr, 7205))
        local c = assert(ntfe.udp_connect(vm, net.peer_addr, 7205))
        local sent, got
        local delta = E:during(function()
            sent = ntfe.send(vm, c, "x").ret
            got = ntfe.recv(peer, l, 500)
        end)
        sys.close(vm, c); sys.close(peer, l)
        t:assert_eq(sent, 1, "a datagram goes out")
        t:assert(got, "and reaches the peer")
        t:assert_eq(delta.tag_writes, 1, "the egress seat applied the TAG")
        t:assert_eq(delta.tag_refused, 0, "with nothing refused for want of an extension")
        local f = flow_to(7205)
        t:assert(f, "the outbound flow is in the dump")
        t:assert_eq(f.tags[ntfe.name_hash("outbound")], 3, "carrying the tag")
    end)

test("an untagged flow has no tag table until its first TAG",
    { spec = "PKM *ntfe-store.tag-table-null-until-first-tag" }, function(t)
        E:replace(with({
            w = { ["DstPort.Equal"] = 7206, ["Length.Equal"] = 33,
                  Actions = { "TAG(late, Set, 1)" } },
            untagged = { ["DstPort.Equal"] = 7206, ["Tag.late.Present"] = 0,
                         Priority = 10, Actions = { "PASS" } },
        }))
        t:assert_eq(judged(7206, "x"), "untagged", "a flow's first packet finds no tag")
        local by, delta = judged(7206, "x")
        t:assert_eq(by, "untagged", "nor does its second")
        t:assert_eq(delta.tag_writes, 0, "while nothing writes one")
        t:assert_eq(flow_to(7206).n_tags, 0, "and the dump shows an empty table")
        local _, wrote = judged(7206, "write")
        t:assert_eq(wrote.tag_writes, 1, "the first TAG is applied")
        t:assert_eq(judged(7206, "x"), "all", "after which the tag is there to read")
        t:assert_eq(flow_to(7206).n_tags, 1, "one tag in the table")
    end)

test("the extension holds the flow's start time and its sentences, untagged or not",
    { spec = "PKM *ntfe-store.ct-extension-holds-start-and-sentences" }, function(t)
        local s = E:replace(with())
        local before = math.floor(vm:clock():get())
        send(7207, "x")
        local after = math.floor(vm:clock():get()) + 1
        local f = flow_to(7207)
        t:assert(f, "the flow is in the dump")
        t:assert_eq(f.n_tags, 0, "it carries no tags")
        t:assert(f.start_secs >= before and f.start_secs <= after,
            "yet its start time is recorded: " .. f.start_secs)
        t:assert_eq(f.sentences[0].generation, s.generation,
            "and so is its sentence, from the generation that judged it")
        t:assert_eq(f.sentences[0].verdict, ntfe.VERDICT.PASS, "saying PASS")
        t:assert_eq(f.sentences[0].rule_hash, ntfe.name_hash("all"),
            "attributed to the Flow rule that spoke")
    end)

-- ---- the table ---------------------------------------------------------

-- The table's capacity is not reported anywhere, so "eight" is seen as
-- what it allows: eight tags fit the first table, and the ninth needs
-- the copy into a bigger one, which keeps the eight where they were.
test("eight tags fill the first table, and a ninth grows it with every entry kept in place",
    { spec = "PKM *ntfe-store.first-tag-allocates-eight-entries PKM *ntfe-store.full-tag-table-doubles" },
    function(t)
        local eight = set_tags("t", 1, 8)
        E:replace(with({
            eight = { ["DstPort.Equal"] = 7208, ["Length.Equal"] = 29, Actions = eight },
            ninth = { ["DstPort.Equal"] = 7208, ["Length.Equal"] = 30,
                      Actions = { "TAG(t9, Set, 9)" } },
            ["all-nine"] = { ["DstPort.Equal"] = 7208, ["Tag.t1.Equal"] = 1,
                             ["Tag.t8.Equal"] = 8, ["Tag.t9.Equal"] = 9,
                             Priority = 10, Actions = { "PASS" } },
        }))
        local _, d1 = judged(7208, "1")
        t:assert_eq(d1.tag_writes, 8, "eight tags are written into a fresh table")
        t:assert_eq(d1.tag_refused, 0, "all of them fit")
        t:assert(same_list(hash_list(ordered_tags(7208)),
            hashes({ "t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8" })),
            "filling it in the order written")
        local _, d2 = judged(7208, "22")
        t:assert_eq(d2.tag_writes, 1, "a ninth tag on the full table is applied")
        t:assert_eq(d2.tag_refused, 0, "not refused: the table was replaced by a bigger one")
        t:assert(same_list(hash_list(ordered_tags(7208)),
            hashes({ "t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8" })),
            "the first eight copied across in place")
        t:assert_eq(judged(7208, "333"), "all-nine",
            "and the next packet reads the first, the eighth and the ninth")
    end)

test("a flow holds at most 64 distinct tags; the 65th is refused and confessed",
    { spec = "PKM *ntfe-store.tag-tripwire-64-per-flow PKM *ntfe-store.tag-refused-confessions" },
    function(t)
        E:replace(with({
            many = { ["DstPort.Equal"] = 7209, ["Length.Equal"] = 29, Actions = set_tags("u", 1, 65) },
            ["has-64"] = { ["DstPort.Equal"] = 7209, ["Length.Equal"] = 30,
                           ["Tag.u9.Equal"] = 9, ["Tag.u17.Equal"] = 17,
                           ["Tag.u33.Equal"] = 33, ["Tag.u64.Equal"] = 64,
                           Priority = 10, Actions = { "PASS" } },
            ["lacks-65"] = { ["DstPort.Equal"] = 7209, ["Length.Equal"] = 31,
                             ["Tag.u65.Present"] = 0, Priority = 10, Actions = { "PASS" } },
        }))
        local _, d = judged(7209, "1")
        t:assert_eq(d.tag_writes, 64, "64 tags are written, through every growth of the table")
        t:assert_eq(d.tag_refused, 1, "and the 65th is refused, counted in tag_refused")
        t:assert_eq(judged(7209, "22"), "has-64",
            "the 9th, 17th, 33rd and 64th tags are all there")
        t:assert_eq(judged(7209, "333"), "lacks-65", "and the 65th is not")
        local _, again = judged(7209, "1")
        t:assert_eq(again.tag_writes, 64, "rewriting the 64 present tags needs no new slot")
        t:assert_eq(again.tag_refused, 1, "while the 65th is refused again")
    end)

test("Clear leaves a tombstone where the tag stood, and the next new tag fills that slot",
    { spec = "PKM *ntfe-store.clear-tombstones-without-compacting PKM *ntfe-store.set-reuses-tombstoned-slot" },
    function(t)
        E:replace(with({
            abc = { ["DstPort.Equal"] = 7210, ["Length.Equal"] = 29,
                    Actions = { "TAG(a, Set, 1)", "TAG(b, Set, 2)", "TAG(c, Set, 3)" } },
            ["clear-b"] = { ["DstPort.Equal"] = 7210, ["Length.Equal"] = 30,
                            Actions = { "TAG(b, Clear)" } },
            ["set-d"] = { ["DstPort.Equal"] = 7210, ["Length.Equal"] = 31,
                          Actions = { "TAG(d, Set, 4)" } },
            ["b-gone"] = { ["DstPort.Equal"] = 7210, ["Length.Equal"] = 32,
                           ["Tag.b.Present"] = 0, ["Tag.c.Equal"] = 3,
                           Priority = 10, Actions = { "PASS" } },
        }))
        send(7210, "1")
        t:assert(same_list(hash_list(ordered_tags(7210)), hashes({ "a", "b", "c" })),
            "three tags in the order written")
        local _, d = judged(7210, "22")
        t:assert_eq(d.tag_writes, 1, "the Clear is applied")
        t:assert(same_list(hash_list(ordered_tags(7210)), hashes({ "a", "c" })),
            "and b no longer shows")
        t:assert_eq(judged(7210, "4444"), "b-gone", "b reads as absent, c is untouched")
        send(7210, "333")
        t:assert(same_list(hash_list(ordered_tags(7210)), hashes({ "a", "d", "c" })),
            "the new tag d took b's slot between a and c: nothing was compacted")
    end)

test("on a full table, a new tag takes a cleared slot instead of tripping the limit",
    { spec = "PKM *ntfe-store.set-reuses-tombstoned-slot" }, function(t)
        E:replace(with({
            full = { ["DstPort.Equal"] = 7216, ["Length.Equal"] = 29, Actions = set_tags("v", 1, 64) },
            swap = { ["DstPort.Equal"] = 7216, ["Length.Equal"] = 30,
                     Actions = { "TAG(v1, Clear)", "TAG(v65, Set, 65)" } },
            swapped = { ["DstPort.Equal"] = 7216, ["Length.Equal"] = 31,
                        ["Tag.v1.Present"] = 0, ["Tag.v65.Equal"] = 65,
                        Priority = 10, Actions = { "PASS" } },
        }))
        local _, d1 = judged(7216, "1")
        t:assert_eq(d1.tag_writes, 64, "64 tags fill the table to the tripwire")
        t:assert_eq(d1.tag_refused, 0, "with none refused")
        local _, d2 = judged(7216, "22")
        t:assert_eq(d2.tag_writes, 2, "a Clear then a Set of a 65th name are both applied")
        t:assert_eq(d2.tag_refused, 0, "the Set is not refused")
        t:assert_eq(judged(7216, "333"), "swapped", "v1 is gone and v65 holds 65")
    end)

test("Add saturates at the largest unsigned 64-bit value",
    { spec = "PKM *ntfe-store.tag-add-saturates" }, function(t)
        E:replace(with({
            big = { ["DstPort.Equal"] = 7211, ["Length.Equal"] = 29,
                    Actions = { "TAG(sat, Set, 18446744073709551600)" } },
            more = { ["DstPort.Equal"] = 7211, ["Length.Equal"] = 30,
                     Actions = { "TAG(sat, Add, 100)" } },
        }))
        -- Lua integers are 64-bit two's complement: the hex literals below
        -- are the unsigned values bit for bit, as the dump unpacks them.
        send(7211, "1")
        t:assert_eq(flow_to(7211).tags[ntfe.name_hash("sat")], 0xFFFFFFFFFFFFFFF0,
            "the tag holds the value set, 2^64 - 16")
        send(7211, "22")
        t:assert_eq(flow_to(7211).tags[ntfe.name_hash("sat")], 0xFFFFFFFFFFFFFFFF,
            "adding 100 does not wrap: it stops at U64_MAX")
        send(7211, "22")
        t:assert_eq(flow_to(7211).tags[ntfe.name_hash("sat")], 0xFFFFFFFFFFFFFFFF,
            "and stays there")
    end)

-- ---- confessions -------------------------------------------------------

test("tag_writes counts every operation applied",
    { spec = "PKM *ntfe-store.tag-writes-counts-applied-ops" }, function(t)
        E:replace(with({
            three = { ["DstPort.Equal"] = 7212,
                      Actions = { "TAG(p, Set, 5)", "TAG(p, Add, 2)", "TAG(q, Add)" } },
        }))
        local _, d = judged(7212, "x")
        t:assert_eq(d.fx_tags, 3, "three TAG effects are handed to the store")
        t:assert_eq(d.tag_writes, 3, "and three applications are counted")
        local f = flow_to(7212)
        t:assert_eq(f.tags[ntfe.name_hash("p")], 7, "Set then Add: 5 + 2")
        t:assert_eq(f.tags[ntfe.name_hash("q")], 1, "Add of an absent tag starts from 0, by 1")
    end)

test("a TAG on a packet with no flow is a no-op counted in tag_untracked",
    { spec = "PKM *ntfe-store.tag-without-flow-is-untracked-no-op" }, function(t)
        local SRC_MAC = "\x02\x00\x00\x00\x52\x13"
        local s = E:replace({
            -- RawPacket stands at the ingress seat, before conntrack.
            RawPacket = {
                all = { Actions = { "PASS" } },
                raw = { ["Direction.Equal"] = "in", ["DstPort.Equal"] = 7213,
                        Actions = { "TAG(raw-seen, Set, 1)" } },
            },
            -- An ARP frame is judged by the Packet layer at ingress too,
            -- as the fallback: it has no IP seat and no flow.
            Packet = {
                all = { Actions = { "PASS" } },
                arp = { ["Direction.Equal"] = "in", ["SrcMac.Equal"] = "02:00:00:00:52:13",
                        Actions = { "TAG(arp-seen, Set, 1)" } },
            },
            Flow = PASS_ALL,
        })
        t:assert_eq(s.last_ingest_error, 0, "the policy is accepted")
        local pfd = assert(ntfe.packet_socket(peer, net.peer))
        local arp = E:during(function()
            ntfe.send_frame(peer, pfd, ntfe.eth(ntfe.MAC_BROADCAST, SRC_MAC, ntfe.ETH_P.ARP)
                .. ntfe.arp_request(SRC_MAC, "10.9.0.99", "10.9.0.77"))
            ntfe.frames(peer, pfd, 100)
        end)
        sys.close(peer, pfd)
        t:assert_eq(arp.fx_tags, 1, "the ARP frame's TAG is issued")
        t:assert_eq(arp.tag_untracked, 1, "and counted as untracked")
        t:assert_eq(arp.tag_writes, 0, "with nothing written")
        t:assert_eq(arp.tag_refused, 0, "and nothing refused")
        local ingress = E:during(function() send(7213, "x") end)
        t:assert_eq(ingress.tag_untracked, 1, "a TAG at the ingress seat is untracked too")
        t:assert_eq(ingress.tag_writes, 0, "and writes nothing")
        t:assert_eq(flow_to(7213).n_tags, 0, "the flow the datagram then joined holds no tag")
    end)

test("clearing a tag that is not there is a no-op, not a refusal",
    { spec = "PKM *ntfe-store.clearing-absent-tag-is-no-op" }, function(t)
        E:replace(with({
            ghost = { ["DstPort.Equal"] = 7214, ["Length.Equal"] = 29,
                      Actions = { "TAG(ghost, Clear)" } },
            real = { ["DstPort.Equal"] = 7214, ["Length.Equal"] = 30,
                     Actions = { "TAG(real, Set, 1)" } },
        }))
        local _, d = judged(7214, "1")
        t:assert_eq(d.tag_refused, 0, "a Clear on a flow that has never been tagged is not refused")
        t:assert_eq(flow_to(7214).n_tags, 0, "and leaves it untagged")
        send(7214, "22")
        local _, d2 = judged(7214, "1")
        t:assert_eq(d2.tag_refused, 0, "a Clear of a name the table lacks is not refused either")
        local f = flow_to(7214)
        t:assert_eq(f.n_tags, 1, "the table is unchanged")
        t:assert_eq(f.tags[ntfe.name_hash("real")], 1, "holding only the tag that was set")
    end)

-- ---- flow death -------------------------------------------------------

local UDP_TIMEOUT = "/proc/sys/net/netfilter/nf_conntrack_udp_timeout"

local function write_sysctl(path, value)
    local fd = assert(sys.open(vm, path, sys.O.WRONLY))
    local r = sys.write(vm, fd, value)
    sys.close(vm, fd)
    return r.ret == #value
end

test("a flow's tags die with it: the same tuple's next flow starts with none",
    { spec = "PKM *ntfe-store.tag-table-freed-after-grace-on-flow-death" }, function(t)
        E:replace(with({
            w = { ["DstPort.Equal"] = 7215, ["Length.Equal"] = 30,
                  Actions = { "TAG(mortal, Set, 7)" } },
            fresh = { ["DstPort.Equal"] = 7215, ["Tag.mortal.Present"] = 0,
                      Priority = 10, Actions = { "PASS" } },
        }))
        t:assert(write_sysctl(UDP_TIMEOUT, "1"), "conntrack's UDP timeout is turned down to 1 s")
        local ok, err = pcall(function()
            send(7215, "22")
            local first = flow_to(7215)
            t:assert(first, "the flow exists")
            t:assert_eq(first.tags[ntfe.name_hash("mortal")], 7, "tagged")
            -- Conntrack's timeout runs on its own clock: wait for it.
            local gone = false
            for _ = 1, 40 do
                if not flow_to(7215) then gone = true; break end
                vm:clock():sleep("250ms")
            end
            t:assert(gone, "the unreplied flow times out and leaves the table")
            t:assert_eq(judged(7215, "x"), "fresh",
                "a datagram on the same tuple finds no tag")
            local second = flow_to(7215)
            t:assert(second, "it made a new flow")
            -- Conntrack's ids hash the entry's address, which the slab may
            -- hand back; the start time cannot repeat.
            t:assert(second.start_secs > first.start_secs,
                "born after the first one died")
            t:assert_eq(second.n_tags, 0, "with an empty table")
        end)
        write_sysctl(UDP_TIMEOUT, "30")
        if not ok then error(err, 0) end
    end)
