-- PKM §6.6 — the stores under concurrency. The tag store's readers walk
-- a flow's table under RCU with no lock while writers serialize on the
-- flow's own lock, and an entry is published before the length that
-- exposes it; the counter store's packet path reads its tables and
-- cells under RCU while the publisher rebuilds them, and its dump is a
-- best-effort snapshot.
--
-- None of that is visible directly from a guest. What is visible is
-- each statement's consequence under real contention, and these tests
-- assert those: two CPUs writing one flow's tags lose no update, no
-- reader sees a tag present before its value was written (on x86's
-- store order, the one torn state a guest can detect), no COUNT is
-- lost while the publisher migrates the table it lands in, and dumps
-- taken mid-flood are well-formed. They are consequence tests, not proofs of ordering:
-- a pass is evidence, a failure is a bug.
--
-- The contention: two workers pinned to the VM's two CPUs, each with a
-- UDP socket bound to the same 127.0.0.1 port and connected to the same
-- destination, so both sockets' datagrams belong to one conntrack entry.
-- Each fires a 1024-datagram sendmmsg without waiting for the other.
-- Loopback delivers in the sender's own softirq, so the inbound seat
-- runs on both CPUs at once. Each flow has its own destination address,
-- so a DstAddr-keyed counter counts each flow independently of its tags.
--
-- Own VM: two vCPUs, which no other NTFE file wants, and machine-wide
-- policy.

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")
local S = require("helpers.ntfe_store")

local vm = provium:vm("vntfestrace", "kernel-only", { cpus = 2 }):boot()
assert(ntfe.if_up(vm, "lo"))

local PORT = 7600
local BURST = 1024

local function pinned(cpu)
    local w = vm:spawn_worker()
    local r = w:syscall(sys.NR.sched_setaffinity, {
        args = { 0, 8, 0 }, bufs = { string.pack("<I8", 1 << cpu) }, ptrs = { 2 },
    })
    assert(r.ret == 0, "sched_setaffinity: " .. sys.errname(r.errno))
    return w
end
local workers = { pinned(0), pinned(1) }
local senders = {}
for i, w in ipairs(workers) do
    senders[i] = S.batch_sender(w, BURST, 16)
    local frames = {}
    for n = 1, BURST do frames[n] = "x" end
    senders[i]:load(frames)
end
local sink = assert(ntfe.udp_bind(vm, "0.0.0.0", PORT))

-- Flow `n`: 127.0.0.1:(31000 + n) → 127.0.1.n:7600, one socket on each
-- worker.
local function flow_sockets(n)
    local fds = {}
    for i, w in ipairs(workers) do
        fds[i] = assert(ntfe.udp_connect(w, "127.0.1." .. n, PORT,
            { bind = { "127.0.0.1", 31000 + n } }))
    end
    return fds
end

-- Both workers' bursts on flow `n` at once; `during` runs while they
-- are in flight. Returns how many datagrams the two sendmmsg calls took.
local function contend(n, during)
    local fds = flow_sockets(n)
    local pending = { senders[1]:fire(fds[1]), senders[2]:fire(fds[2]) }
    if during then during() end
    local sent = 0
    for _, p in ipairs(pending) do
        local r = p:await()
        assert(r.ret >= 0, "sendmmsg: " .. sys.errname(r.errno))
        sent = sent + r.ret
    end
    return sent
end

local GROW = {}
for i = 1, 12 do GROW[i] = string.format("TAG(g%d, Add, 1)", i) end
GROW[#GROW + 1] = "COUNT(sent)"

local inbound = { ["Direction.Equal"] = "in", ["DstPort.Equal"] = PORT }
local function rule(extra)
    local r = {}
    for k, v in pairs(inbound) do r[k] = v end
    for k, v in pairs(extra) do r[k] = v end
    return r
end

local PASS_ALL = { all = { Actions = { "PASS" } } }

-- `windows`: the window set the `sent` table is viewed through.
local function policy(windows)
    local views = { ["DstPort.Equal"] = 1, Actions = { "PASS" },
                    ["Counter.sent(DstAddr).GreaterThan"] = 1000000000,
                    ["Counter.torn.GreaterThan"] = 1000000000 }
    for _, w in ipairs(windows or {}) do
        views["Counter.sent(" .. w .. ", DstAddr).GreaterThan"] = 1000000000
    end
    return {
        RawPacket = PASS_ALL, Flow = PASS_ALL,
        Packet = {
            all = { Actions = { "PASS" } },
            writer = rule({ Actions = GROW }),
            -- Add creates an entry at 0, not present, and only then
            -- writes the value and marks it present: a reader that sees
            -- a present tag at 0 saw an entry before it was complete.
            ["torn-first"] = rule({ ["Tag.g1.Equal"] = 0, Actions = { "COUNT(torn)" } }),
            ["torn-last"] = rule({ ["Tag.g12.Equal"] = 0, Actions = { "COUNT(torn)" } }),
            views = views,
        },
    }
end

local E = ntfe.engine(vm, policy({ "10s" }))

local function flow_tags(n)
    for _, f in ipairs(E:flows()) do
        if f.protocol == ntfe.IPPROTO.UDP and f.dst == "127.0.1." .. n
            and f.dst_port == PORT then
            return f
        end
    end
end

local function sent_total(n)
    for _, c in ipairs(S.cells(E:counters(), "sent", ntfe.KEY.DST_ADDR)) do
        if c.dst == "127.0.1." .. n then return c.total end
    end
end

local function torn_total()
    local c = S.cells(E:counters(), "torn")[1]
    return c and c.total or 0
end

test("two CPUs adding to one flow's tags lose no update: writers serialize on the flow",
    { spec = "PKM *ntfe-store.tag-writers-serialize-on-ct-lock" }, function(t)
        for n = 1, 4 do
            local sent = contend(n)
            local f = flow_tags(n)
            t:assert(f, "flow " .. n .. " exists")
            local counted = sent_total(n)
            t:assert_eq(counted, sent, "flow " .. n .. ": every datagram reached the inbound seat")
            for g = 1, 8 do
                t:assert_eq(f.tags[ntfe.name_hash("g" .. g)], counted,
                    "flow " .. n .. ": g" .. g .. " was added to once per datagram")
            end
        end
    end)

test("readers on one CPU walk a table another CPU is growing, and never see a tag present before its value was written",
    { spec = "PKM *ntfe-store.tag-readers-lockless-under-rcu PKM *ntfe-store.tag-entry-published-before-length" },
    function(t)
        local before = torn_total()
        local judged = E:status().judged
        for n = 11, 18 do contend(n) end
        t:assert(E:status().judged - judged >= 8 * 2 * BURST,
            "every datagram of eight contended flows was judged, each reading twelve tags")
        t:assert_eq(torn_total() - before, 0,
            "and no reader saw a present tag before its value was written")
        for n = 11, 18 do
            local f = flow_tags(n)
            t:assert_eq(f.n_tags, 12, "flow " .. n .. " counts its twelve tags (the record lists eight)")
            t:assert_eq(f.tags[ntfe.name_hash("g8")], sent_total(n),
                "with the values the contended writers left")
        end
    end)

test("COUNTs racing the publisher's migration of their table are all kept",
    { spec = "PKM *ntfe-store.counter-reads-under-rcu" }, function(t)
        -- Each publication changes the window set of `sent`'s table, so
        -- the publisher re-lays out every cell while both CPUs count
        -- into them and read them.
        local sets = { { "10s", "20s" }, { "20s" }, { "30s", "1m" }, { "10s" } }
        local start = E:status().generation
        for i, set in ipairs(sets) do
            local n = 20 + i
            local sent = contend(n, function()
                local s = E:replace(policy(set))
                t:assert_eq(s.last_ingest_error, 0, "republication " .. i .. " is accepted")
            end)
            local f = flow_tags(n)
            t:assert_eq(sent_total(n), sent,
                "flow " .. n .. ": no COUNT was lost to the migration")
            t:assert_eq(f.tags[ntfe.name_hash("g1")], sent,
                "and the tag store, counting the same datagrams, agrees")
        end
        t:assert_eq(E:status().generation, start + #sets, "every republication was published")
        local any = S.cells(E:counters(), "sent", ntfe.KEY.DST_ADDR)[1]
        t:assert_eq(any.n_windows, 1, "and the tables ended in the last window set")
        t:assert(any.windows[10] ~= nil, "answering 10 s")
    end)

test("a counters dump taken mid-flood is a well-formed best-effort snapshot",
    { spec = "PKM *ntfe-store.counters-dump-is-best-effort" }, function(t)
        local dumps = {}
        local sent = contend(31, function()
            for i = 1, 6 do dumps[i] = E:counters() end
        end)
        dumps[#dumps + 1] = E:counters()
        local last = {}
        for i, d in ipairs(dumps) do
            t:assert(#d <= d.total, "dump " .. i .. ": no more records than cells")
            for _, c in ipairs(d) do
                t:assert(c.n_windows <= 8, "dump " .. i .. ": a cell has at most eight windows")
                for w, v in pairs(c.windows) do
                    t:assert(v <= c.total, "dump " .. i .. ": window " .. w .. " within the total")
                end
                local key = c.name .. "|" .. c.keyspec .. "|" .. tostring(c.dst)
                t:assert(c.total >= (last[key] or 0),
                    "dump " .. i .. ": a total never runs backwards between dumps")
                last[key] = c.total
            end
        end
        t:assert_eq(sent_total(31), sent, "once the flood is over, the dump is exact")
    end)
