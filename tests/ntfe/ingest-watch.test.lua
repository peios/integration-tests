-- PKM §6.5 — Discovery, change notification and "In force": how the
-- kernel finds `Machine\System\Network` at LCS bootstrap, the one watch
-- it arms there, the 50 ms debounce that turns a burst of watch events
-- into one walk, the digest that keeps a walk which read nothing new
-- from publishing, and the `changes_noted` / `changes_walked` pair a
-- writer reads to learn whether what it wrote is enforced.
--
-- Everything here goes through the real registry calls. The hive is
-- targeted (helpers/ntfe_ingest): it holds every kernel-read key, so
-- LCS arms no machine-root fallback and the only walks are the ones the
-- Network watch schedules. Writes are served only until they return
-- (`quick_*`), so the engine can be looked at between a write and its
-- walk; a walk is held mid-way by leaving one of its source requests
-- unanswered.
--
-- Own VM: the policy, the watch and the in-force counters are
-- machine-wide state, and the first test reads the bootstrap.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")
local ntfe = require("helpers.ntfe")
local ing = require("helpers.ntfe_ingest")

local vm = provium:vm("vntfeiw", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))

local NET = ntfe.NETWORK_KEY
local POLICY = ing.policy({
    gate = { ["DstPort.Equal"] = 6401, Actions = { "REJECT" } },
})

local E = ing.engine(vm, POLICY, {
    inventory = {
        { ["7d1c0000-0000-4000-8000-000000000001"] = { Name = "lab", Trust = "home" } },
        { ["if-a"] = { Name = "nosuchif0" } }, -- no Network: makes no entry
    },
    seed = function(src)
        -- netd's and resolvd's subtrees beside NTFE's, and a key
        -- outside the Network key altogether.
        src:value(src:key(NET .. "\\Profiles\\home"), "Mode", lcs.TYPE.DWORD, lcs.dword(1))
        src:value(src:key(NET .. "\\Dns\\Servers"), "List", lcs.TYPE.SZ, lcs.sz("10.0.0.53"))
        src:key("Machine\\Software\\Elsewhere")
    end,
})
local boot = E:status()
local boot_log = #E.src.log

local function walks_since(m) return #ing.walk_starts(E, m) end

-- ---- discovery --------------------------------------------------------

test("the Network key is discovered at LCS bootstrap, fifth, with its Machine component resolved locally",
    { spec = "PKM *ntfe-ingest.key-discovered-at-bootstrap " ..
             "PKM *ntfe-ingest.machine-component-resolved-locally" }, function(t)
        local log = E.src.log
        local first_walk
        for i = 1, boot_log do
            if log[i].op == lcs.OP.ENUM_CHILDREN and ing.guid_of(log[i]) == E.net_guid then
                first_walk = i
                break
            end
        end
        t:assert(first_walk, "the registration's bootstrap walked the Network key")
        t:assert(boot.generation >= 1 and boot.enforcing == 1,
            "and published the policy it found there")
        -- Discovery is the two lookups just before the walk: System from
        -- the hive root, then Network. Nobody was asked for "Machine".
        local sys_req, net_req = log[first_walk - 2], log[first_walk - 1]
        t:assert_eq(lcs.lookup_name(sys_req), "System", "discovery asks for System")
        t:assert_eq(ing.guid_of(sys_req), E.src.roots["machine"],
            "under the hive root, which was resolved without a round trip")
        t:assert_eq(lcs.lookup_name(net_req), "Network", "then for Network")
        t:assert_eq(ing.guid_of(net_req), E.src:lookup("Machine\\System"), "under System")
        for i = 1, boot_log do
            t:assert(lcs.lookup_name(log[i]) ~= "Machine",
                "no lookup ever names the hive component (request " .. i .. ")")
        end
        -- Fifth: after the Registry, KMES, Layers and PortReservations keys.
        local seen = {}
        for i = 1, first_walk - 3 do
            local n = lcs.lookup_name(log[i])
            if n then seen[n] = true end
        end
        for _, n in ipairs({ "Registry", "KMES", "Layers", "PortReservations" }) do
            t:assert(seen[n], n .. " was discovered before the Network key")
        end
    end)

test("the bootstrap walk is not a noted change and moves neither counter",
    { spec = "PKM *ntfe-ingest.bootstrap-walk-moves-neither-counter" }, function(t)
        t:assert_eq(E.zero.generation, 0, "before registration nothing was ever ingested")
        t:assert(boot.generation > E.zero.generation, "the bootstrap walk published")
        t:assert_eq(boot.changes_noted, E.zero.changes_noted, "yet noted nothing")
        t:assert_eq(boot.changes_walked, E.zero.changes_walked, "and walked nothing")
        t:assert(boot.last_ingest_t_ns > E.zero.last_ingest_t_ns, "though it recorded its outcome")
    end)

-- ---- the watch ----------------------------------------------------------

test("one watch on the Network key notes a write at any depth beneath it, and nothing outside it",
    { spec = "PKM *ntfe-ingest.one-unbounded-watch-on-network-key" }, function(t)
        local path = "Profiles"
        for i = 1, 10 do
            path = path .. "\\deep" .. i
            local r = ing.quick_create(E, path)
            t:assert(r.ret >= 0, "create " .. path)
        end
        local deep = ing.open(E, path)
        local before = E:status()
        ing.quick_write(E, deep, "Leaf", 1)
        t:assert_eq(E:status().changes_noted, before.changes_noted + 1,
            "a value set eleven keys below Network is one noted change")
        local gate = ing.open(E, "Rules\\Flow\\gate")
        before = E:status()
        ing.quick_write(E, gate, "Priority", 0)
        t:assert_eq(E:status().changes_noted, before.changes_noted + 1,
            "a rule's value is one noted change: there is one watch, not one per key")
        local r = lcs.open_key(E.src, E.writer, -1, "Machine\\Software\\Elsewhere")
        before = E:status()
        ing.quick_write(E, r.ret, "Other", 1)
        t:assert_eq(E:status().changes_noted, before.changes_noted,
            "a write outside the Network key is not NTFE's")
        ing.settle(E)
    end)

test("the watch is delivered a value set, a value deleted, a subkey created, a subkey deleted and a key deleted, and no descriptor change",
    { spec = "PKM *ntfe-ingest.one-unbounded-watch-on-network-key",
      -- PEI-1311: the TRM once armed the watch "for every mutation", descriptors included.
    }, function(t)
        local function noted() return E:status().changes_noted end
        ing.settle(E)
        local home = ing.open(E, "Profiles\\home")
        local n = noted()
        ing.quick_write(E, home, "Watched", 1)
        t:assert_eq(noted(), n + 1, "a value set is noted")
        n = noted()
        local r = lcs.delete_value(E.src, E.writer, home, "Watched")
        t:assert_eq(r.ret, 0, "(the value is deleted)")
        t:assert_eq(noted(), n + 1, "a value deleted is noted")
        n = noted()
        r = ing.quick_create(E, "Profiles\\home\\watched")
        t:assert(r.ret >= 0, "(the subkey is created)")
        t:assert_eq(noted(), n + 1, "a subkey created is noted")
        n = noted()
        local d = lcs.delete_key(E.src, E.writer, r.ret)
        t:assert_eq(d.ret, 0, "(the subkey is deleted)")
        t:assert_eq(noted(), n + 2,
            "a deletion is noted twice: the subkey deleted from its parent, the key deleted itself")
        sys.close(E.writer, r.ret)
        ing.settle(E)

        -- A descriptor change is delivered to nobody here: noted is
        -- unmoved, and no walk starts once the debounce has passed.
        local m = E.src:mark()
        n = noted()
        r = ing.quick(E, function(w)
            return lcs.set_security_async(w, home, lcs.SI.DACL, lcs.permissive_sd())
        end)
        t:assert_eq(r.ret, 0, "(the descriptor is changed)")
        t:assert_eq(noted(), n, "a descriptor change is not delivered")
        ing.pump(E, 150)
        t:assert_eq(walks_since(m), 0, "and starts no walk")
        sys.close(E.writer, home)
    end)

test("NTFE reads Rules, Interfaces and Networks beneath the key and nothing else",
    { spec = "PKM *ntfe-ingest.ntfe-reads-rules-interfaces-networks" }, function(t)
        local foreign = {}
        for _, p in ipairs({ "Profiles", "Profiles\\home", "Dns", "Dns\\Servers",
                             "TcpIp", "TcpIp\\PortReservations" }) do
            foreign[E.src:lookup(NET .. "\\" .. p)] = p
        end
        local wanted = {}
        for _, p in ipairs({ "Rules", "Interfaces", "Networks" }) do
            wanted[E.src:lookup(NET .. "\\" .. p)] = p
        end
        local m = E.src:mark()
        ing.poke(E)
        ing.settle(E)
        t:assert_eq(walks_since(m), 1, "one walk")
        local read = {}
        for i = m, #E.src.log do
            local g = ing.guid_of(E.src.log[i])
            t:assert(not foreign[g], "the walk never reads " .. tostring(foreign[g]))
            if wanted[g] then read[wanted[g]] = true end
        end
        for _, p in ipairs({ "Rules", "Interfaces", "Networks" }) do
            t:assert(read[p], "it reads " .. p)
        end
    end)

test("a write under Profiles or Dns fires the watch and costs a walk that publishes nothing",
    { spec = "PKM *ntfe-ingest.foreign-subtree-write-publishes-nothing" }, function(t)
        for _, p in ipairs({ "Profiles\\home", "Dns\\Servers" }) do
            local fd = ing.open(E, p)
            local before = ing.settle(E)
            local m = E.src:mark()
            ing.quick_write(E, fd, "Touched", before.changes_noted)
            t:assert_eq(E:status().changes_noted, before.changes_noted + 1,
                "a write under " .. p .. " is noted")
            local after = ing.settle(E)
            t:assert_eq(walks_since(m), 1, "and walked")
            t:assert_eq(after.generation, before.generation, "but publishes nothing")
            t:assert_eq(after.last_ingest_error, 0, "and is no failure")
        end
    end)

-- ---- the debounce -------------------------------------------------------

test("the re-walk runs 50 ms after the change that scheduled it",
    { spec = "PKM *ntfe-ingest.rewalk-debounced-50ms" }, function(t)
        ing.settle(E)
        local m = E.src:mark()
        ing.poke(E)
        local last_write = E.src.log[#E.src.log].t
        t:assert_eq(walks_since(m), 0, "nothing walks while the write is being made")
        ing.pump_until(E, function() return walks_since(m) > 0 end)
        local walk = ing.walk_starts(E, m)[1]
        local gap = walk.t - last_write
        t:assert(gap >= 45, string.format("the walk waits out the debounce: %.1f ms", gap))
        t:assert(gap < 300, string.format("and no longer than it must: %.1f ms", gap))
        ing.settle(E)
    end)

test("a burst of writes yields one re-walk, after the burst goes quiet",
    { spec = "PKM *ntfe-ingest.burst-yields-one-rewalk " ..
             "PKM *ntfe-ingest.rewalk-debounced-50ms" }, function(t)
        local before = ing.settle(E)
        local m = E.src:mark()
        local stamps = {}
        for i = 1, 15 do
            ing.poke(E)
            stamps[i] = E.src.log[#E.src.log].t
        end
        local span, widest = stamps[#stamps] - stamps[1], 0
        for i = 2, #stamps do widest = math.max(widest, stamps[i] - stamps[i - 1]) end
        t:assert(widest < 45, string.format(
            "(the writes came closer together than the debounce: %.1f ms apart)", widest))
        t:assert(span > 100, string.format(
            "(and the burst outlasted it twice: %.1f ms)", span))
        t:assert_eq(walks_since(m), 0,
            "no walk ran during the burst: every write restarted the window")
        ing.pump_until(E, function() return walks_since(m) > 0 end)
        t:assert(ing.walk_starts(E, m)[1].t - stamps[#stamps] >= 45,
            "the walk began a debounce after the last write")
        local after = ing.settle(E)
        ing.pump(E, 150)
        t:assert_eq(walks_since(m), 1, "and it was the only one")
        t:assert_eq(after.changes_noted, before.changes_noted + 15, "though fifteen changes were noted")
        t:assert_eq(after.changes_walked, after.changes_noted, "and it covered them all")
    end)

test("a transaction's changes are noted at commit, walked once, and published as one generation",
    { spec = "PKM *ntfe-ingest.burst-yields-one-rewalk " ..
             "PKM *ntfe-ingest.inventory-write-changes-no-generation" }, function(t)
        local before = ing.settle(E)
        local txn = assert(lcs.begin_transaction(E.writer))
        local c = ing.quick_create(E, "Rules\\Flow\\txrule", { txn_fd = txn })
        t:assert(c.ret >= 0, "a rule key is created in the transaction")
        ing.quick_write(E, c.ret, "DstPort.Equal", 6402, { txn_fd = txn })
        ing.quick_write(E, c.ret, "Actions", { "REJECT" }, { txn_fd = txn })
        t:assert_eq(E:status().changes_noted, before.changes_noted,
            "nothing is delivered before the commit")
        local m = E.src:mark()
        local r = ing.quick(E, function(w) return lcs.commit_async(w, txn) end)
        sys.close(E.writer, txn)
        t:assert_eq(r.ret, 0, "the transaction commits")
        t:assert_eq(E:status().changes_noted, before.changes_noted + 3,
            "and its three changes are delivered by the commit")
        local after = ing.settle(E)
        ing.pump(E, 150)
        t:assert_eq(walks_since(m), 1, "they are walked once")
        t:assert_eq(after.generation, before.generation + 1, "into one generation")
        t:assert_eq(ing.verdict(vm, 6402), "reject", "which enforces the new rule")
        -- Another delivery of the same state (the TRM's second watch
        -- delivery of a transaction) walks again and publishes nothing.
        ing.poke(E)
        t:assert_eq(ing.settle(E).generation, after.generation,
            "a further walk of the same rules publishes nothing")
    end)

test("an inventory write that changes no context walks and publishes nothing",
    { spec = "PKM *ntfe-ingest.inventory-write-changes-no-generation" }, function(t)
        local status = ing.open(E, "Interfaces\\if-a\\Status")
        local before = ing.settle(E)
        local m = E.src:mark()
        ing.quick_write(E, status, "Mtu", 1500)
        local after = ing.settle(E)
        t:assert_eq(walks_since(m), 1, "netd's write is walked")
        t:assert_eq(after.generation, before.generation, "and changes no generation")
        t:assert_eq(after.contexts, before.contexts, "nor the context table")
    end)

-- ---- in force -----------------------------------------------------------

test("a write that has returned is noted but not enforced until the walk that reads it",
    { spec = "PKM *ntfe-ingest.returned-write-not-yet-enforced " ..
             "PKM *ntfe-ingest.writer-sees-own-change-noted " ..
             "PKM *ntfe-ingest.in-force-when-walked-reaches-noted" }, function(t)
        ing.replace(E, POLICY)
        t:assert_eq(ing.verdict(vm, 6401), "reject", "the gate rejects")
        local gate = ing.open(E, "Rules\\Flow\\gate")
        local before = ing.settle(E)
        local r = ing.quick_write(E, gate, "Enabled", 0)
        t:assert_eq(r.ret, 0, "the gate is disabled in the registry")
        local now = E:status()
        t:assert_eq(now.changes_noted, before.changes_noted + 1,
            "the writer, reading the status after its write, sees its change noted")
        t:assert_eq(now.changes_walked, before.changes_walked, "but not yet walked")
        t:assert_eq(ing.verdict(vm, 6401), "reject", "so the gate still rejects")
        t:assert_eq(E:status().generation, before.generation, "under the old generation")
        local target = now.changes_noted
        local s = ing.settle(E)
        t:assert(s.changes_walked >= target, "once walked reaches what was noted")
        t:assert_eq(s.generation, before.generation + 1, "the write is published")
        t:assert_eq(ing.verdict(vm, 6401), "pass", "and enforced")
    end)

test("changes_noted counts every watch event",
    { spec = "PKM *ntfe-ingest.changes-noted-counts-watch-events" }, function(t)
        local function noted() return E:status().changes_noted end
        local n = noted()
        local c = ing.quick_create(E, "Rules\\Flow\\counted")
        t:assert_eq(noted(), n + 1, "a key created: one event"); n = noted()
        ing.quick_write(E, c.ret, "DstPort.Equal", 6403)
        t:assert_eq(noted(), n + 1, "a value set: one"); n = noted()
        ing.quick_write(E, c.ret, "DstPort.Equal", 6404)
        t:assert_eq(noted(), n + 1, "a value overwritten: one"); n = noted()
        ing.quick(E, function(w) return lcs.delete_value_async(w, c.ret, "DstPort.Equal") end)
        t:assert_eq(noted(), n + 1, "a value deleted: one"); n = noted()
        local d = ing.quick(E, function(w) return lcs.delete_key_async(w, c.ret) end)
        t:assert_eq(d.ret, 0, "the key is deleted")
        -- SUBKEY_DELETED on the parent and KEY_DELETED on the key.
        t:assert_eq(noted(), n + 2, "a key deleted: two events, one per watched key it touches")
        ing.settle(E)
    end)

test("changes_walked is what was noted when the walk began, and a change mid-walk re-arms the work",
    { spec = "PKM *ntfe-ingest.changes-walked-set-from-pre-walk-noted " ..
             "PKM *ntfe-ingest.mid-walk-change-rearms-work" }, function(t)
        ing.replace(E, POLICY)
        local base = ing.settle(E)
        local n = base.changes_noted
        t:assert_eq(base.changes_walked, n, "the engine starts caught up")
        -- The statuses are gathered with the walks held and asserted once
        -- both are released, so a failure cannot leave the engine stalled.
        local held = ing.hold_next(E, lcs.OP.QUERY_VALUES, E.src:lookup(ntfe.RULES_KEY .. "\\Flow\\gate"))
        ing.poke(E)
        ing.pump_until(E, function() return held.req ~= nil end)
        local s1 = E:status()
        -- A second change lands while the first walk is stalled.
        ing.poke(E)
        local s2 = E:status()
        -- Let the first walk finish, and catch the next one at its start.
        local next_walk = ing.hold_next(E, lcs.OP.ENUM_CHILDREN, E.net_guid)
        ing.release(E, held)
        ing.pump_until(E, function() return next_walk.req ~= nil end)
        local s3 = E:status()
        ing.release(E, next_walk)
        local s4 = ing.settle(E)
        t:assert_eq(s1.changes_noted, n + 1, "the first change is noted")
        t:assert_eq(s1.changes_walked, n, "and its walk is under way, not finished")
        t:assert_eq(s2.changes_noted, n + 2, "a change mid-walk is noted")
        t:assert_eq(s2.changes_walked, n, "while the walk is still out")
        t:assert_eq(s3.changes_walked, n + 1,
            "the first walk recorded what was noted before it began, not what is noted now")
        t:assert_eq(s3.changes_noted, n + 2, "so the pair stays unequal")
        t:assert_eq(s4.changes_walked, n + 2, "until the re-armed walk covers the change")
    end)

test("a refused walk still advances changes_walked",
    { spec = "PKM *ntfe-ingest.refused-walk-advances-changes-walked" }, function(t)
        ing.replace(E, POLICY)
        local gate = ing.open(E, "Rules\\Flow\\gate")
        local before = ing.settle(E)
        ing.quick_write(E, gate, "Enabled", 5)
        local target = E:status().changes_noted
        local s = ing.settle(E)
        t:assert_eq(s.changes_walked, target, "the walk that read the bad value counts as walked")
        t:assert_eq(s.last_ingest_error, ing.EINVAL, "and the writer learns it was refused")
        t:assert_eq(s.generation, before.generation, "nothing was published")
        ing.quick_write(E, gate, "Enabled", 1)
        t:assert_eq(ing.settle(E).last_ingest_error, 0, "(repaired)")
    end)

-- ---- readers during a walk -------------------------------------------

test("while a walk is stalled, traffic is judged at once and wholly by the active generation",
    { spec = "PKM *ntfe-ingest.hook-readers-never-block " ..
             "PKM *ntfe-ingest.readers-never-see-mixed-generation" }, function(t)
        -- The named rules outrank `all`, so the attribution says which
        -- policy judged each layer.
        local function policy(tag)
            return {
                RawPacket = ing.PASS_ALL,
                Packet = { all = { Actions = { "PASS" } },
                           ["p" .. tag] = { ["DstPort.Equal"] = 6405, Priority = 1,
                                            Actions = { "PASS" } } },
                Flow = { all = { Actions = { "PASS" } },
                         ["f" .. tag] = { ["DstPort.Equal"] = 6405, Priority = 1,
                                          Actions = { "PASS" } } },
            }
        end
        local function attributions(events)
            local seen = {}
            for _, e in ipairs(events) do
                if e.dst_port == 6405 then seen[e.attributed] = true end
            end
            return seen
        end
        local a = ing.replace(E, policy("A"))
        ing.stage(E, policy("B"))
        -- Hold the walk inside the Flow layer: the Packet forest of B is
        -- already read and built.
        local held = ing.hold_next(E, lcs.OP.QUERY_VALUES,
            E.src:lookup(ntfe.RULES_KEY .. "\\Flow\\fB"))
        ing.poke(E)
        ing.pump_until(E, function() return held.req ~= nil end)
        local t0 = ing.now_ms(vm)
        local verdict
        local _, events = E:during(function() verdict = ing.verdict(vm, 6405) end)
        local took = ing.now_ms(vm) - t0
        local during = E:status()
        ing.release(E, held)
        t:assert_eq(verdict, "pass", "a connection is made")
        t:assert(took < 300, string.format("without waiting on the walk (%.1f ms)", took))
        local seen = attributions(events)
        t:assert(seen.pA and seen.fA, "judged by A in both layers: " .. ntfe.describe(events))
        t:assert(not seen.pB and not seen.fB, "and by no part of B")
        t:assert_eq(during.generation, a.generation, "A is still the generation")
        local b = ing.settle(E)
        t:assert_eq(b.generation, a.generation + 1, "B is published whole")
        _, events = E:during(function() ing.verdict(vm, 6405) end)
        seen = attributions(events)
        t:assert(seen.pB and seen.fB and not seen.pA and not seen.fA,
            "and judges in both layers at once: " .. ntfe.describe(events))
    end)

-- ---- the digest --------------------------------------------------------

test("rewriting a rule with the bytes it already holds walks and publishes nothing",
    { spec = "PKM *ntfe-ingest.unchanged-digest-publishes-nothing" }, function(t)
        ing.replace(E, POLICY)
        local gate = ing.open(E, "Rules\\Flow\\gate")
        local before = ing.settle(E)
        local m = E.src:mark()
        ing.quick_write(E, gate, "DstPort.Equal", 6401)
        ing.quick_write(E, gate, "Actions", { "REJECT" })
        local after = ing.settle(E)
        t:assert(walks_since(m) >= 1, "the rewrite is walked")
        t:assert_eq(after.generation, before.generation, "but the policy is the one in force")
        t:assert_eq(after.last_ingest_error, 0, "and that is no failure")
    end)

-- ---- generations and flows --------------------------------------------

test("a new generation stales every sentence without walking the flows",
    { spec = "PKM *ntfe-ingest.new-generation-stales-sentences-without-flow-walk" }, function(t)
        local g = ing.replace(E, POLICY).generation
        local l = assert(ntfe.tcp_listen(vm, "127.0.0.1", 6406))
        local c = assert(ntfe.tcp_connect(vm, "127.0.0.1", 6406))
        local a = assert(ntfe.tcp_accept(vm, l))
        ntfe.send(vm, c, "one")
        t:assert_eq(ntfe.recv(vm, a), "one", "an established flow carries data")
        local function sentence_generations()
            local out = {}
            for _, f in ipairs(E:flows()) do
                if f.dst_port == 6406 or f.src_port == 6406 then
                    for s = 0, 1 do
                        local gen = f.sentences[s].generation
                        if gen ~= 0 then out[gen] = true end
                    end
                end
            end
            return out
        end
        t:assert(sentence_generations()[g], "its sentence was written under generation " .. g)
        local new = ing.replace(E, ing.policy({
            gate = { ["DstPort.Equal"] = 6401, Actions = { "REJECT" } },
            other = { ["DstPort.Equal"] = 6407, Actions = { "REJECT" } },
        })).generation
        t:assert_eq(new, g + 1, "a new generation is published")
        local gens = sentence_generations()
        t:assert(gens[g] and not gens[new],
            "and the flow's sentence still names the old one: nothing walked the flows")
        local delta, events = E:during(function()
            ntfe.send(vm, c, "two")
            t:assert_eq(ntfe.recv(vm, a), "two", "the flow's next packet")
        end)
        t:assert(delta.flow_rejudged >= 1, "is re-judged")
        local rejudged = false
        for _, e in ipairs(events) do if e.rejudged then rejudged = true end end
        t:assert(rejudged, "and says so: " .. ntfe.describe(events))
        t:assert(sentence_generations()[new], "and its sentence now names the new generation")
        sys.close(vm, c); sys.close(vm, a); sys.close(vm, l)
    end)

-- Last: it takes the Rules key away.
test("with no Rules key the previous generation stands",
    { spec = "PKM *ntfe-ingest.absent-rules-key-keeps-generation" }, function(t)
        local before = ing.replace(E, {
            RawPacket = ing.PASS_ALL, Packet = ing.PASS_ALL,
            Flow = { all = { Actions = { "PASS" } },
                     gate = { ["DstPort.Equal"] = 6401, Actions = { "REJECT" } } },
        })
        -- Delete the whole Rules subtree, leaves first, in one
        -- transaction: one walk sees the key gone.
        local txn = assert(lcs.begin_transaction(E.writer))
        for _, p in ipairs({ "Rules\\RawPacket\\all", "Rules\\Packet\\all", "Rules\\Flow\\all",
                             "Rules\\Flow\\gate", "Rules\\RawPacket", "Rules\\Packet",
                             "Rules\\Flow", "Rules" }) do
            local fd = ing.open(E, p)
            local r = ing.quick(E, function(w) return lcs.delete_key_async(w, fd, { txn_fd = txn }) end)
            t:assert_eq(r.ret, 0, "delete " .. p .. ": " .. sys.errname(r.errno or 0))
        end
        local r = ing.quick(E, function(w) return lcs.commit_async(w, txn) end)
        sys.close(E.writer, txn)
        t:assert_eq(r.ret, 0, "the deletion commits")
        local m = E.src:mark()
        local s = ing.settle(E)
        t:assert(walks_since(m) >= 1, "the walk runs")
        t:assert_eq(s.generation, before.generation, "and the previous generation stands")
        t:assert_eq(s.enforcing, 1, "enforcing")
        t:assert_eq(s.last_ingest_error, 0, "with no error: an absent key is no failure")
        t:assert_eq(ing.verdict(vm, 6401), "reject", "the deleted gate still rejects")
    end)
