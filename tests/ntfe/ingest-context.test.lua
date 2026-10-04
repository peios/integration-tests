-- PKM §6.5 — The context stage: netd's inventory (`Networks\` records,
-- `Interfaces\<id>\Status`) read beside the rules into the network
-- context table, the join, its bounds and truncations, what is skipped
-- and what refuses, and how a changed table reaches running flows by
-- advancing the generation.
--
-- Whether an interface carries a context, and which, is read the way a
-- policy reads it: Flow rules on `Network.Id`, `Network.Name` and
-- `Network.Trust`, each on its own port, REJECT when the fact matches.
-- A peer on a veth pair gives a second interface (veth0) beside lo.
--
-- Own VM: the context table is machine-wide state.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")
local ntfe = require("helpers.ntfe")
local ing = require("helpers.ntfe_ingest")

local vm = provium:vm("vntfeictx", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))
local peer, net = ntfe.peer(vm)

local NET = ntfe.NETWORK_KEY
local LAB = "7d1c0000-0000-4000-8000-00000000000a"
local DMZ = "7d1c0000-0000-4000-8000-00000000000b"
local NETWORKS = {
    [LAB] = { Name = "lab", Trust = "home" },
    [DMZ] = { Name = "dmz", Trust = "public" },
}

-- A Flow rule that REJECTs `port` when `Network.<fact>` equals `value`.
local function probe(fact, value, port)
    return { ["Network." .. fact .. ".Equal"] = value, ["DstPort.Equal"] = port,
             Priority = 1, Actions = { "REJECT" } }
end

-- The probes most tests read: lo's Id, Name and Trust against LAB.
local function lab_probes(extra)
    local flow = {
        lab_id = probe("Id", LAB, 6701),
        lab_name = probe("Name", "lab", 6702),
        lab_trust = probe("Trust", "home", 6703),
        dmz_id = probe("Id", DMZ, 6704),
    }
    for k, v in pairs(extra or {}) do flow[k] = v end
    return ing.policy(flow)
end

local E = ing.engine(vm, lab_probes(), {
    inventory = { NETWORKS, { ["if-lo"] = { Name = "lo", Network = LAB } } },
})

-- What the lo probes say: a table of fact -> matched.
local function lo_context()
    return {
        id = ing.verdict(vm, 6701) == "reject",
        name = ing.verdict(vm, 6702) == "reject",
        trust = ing.verdict(vm, 6703) == "reject",
    }
end

local peer_listeners = {}
local function verdict_from_peer(port)
    if not peer_listeners[port] then
        peer_listeners[port] = assert(ntfe.tcp_listen(vm, net.addr, port))
    end
    local fd, why = ntfe.tcp_connect(peer, net.addr, port, 400)
    if fd then sys.close(peer, fd); return "pass" end
    if why == "timeout" then return "drop" end
    return "reject"
end

-- Answer one request about `guid` with a storage error, for the rest
-- of `fn`.
local function failing(op, guid, fn)
    E.src:intercept(op, function(_, req)
        if ing.guid_of(req) == guid then return lcs.STATUS.STORAGE_ERROR, "" end
    end)
    local ok, err = pcall(fn)
    E.src:intercept(op, nil)
    if not ok then error(err, 0) end
end

-- ---- reading the inventory ---------------------------------------------

test("the walk reads netd's inventory with the rules, after them, into the context table",
    { spec = "PKM *ntfe-ingest.walk-reads-inventory-with-rules " ..
             "PKM *ntfe-ingest.rules-stage-then-context-stage " ..
             "PKM *ntfe-ingest.interface-status-read " ..
             "PKM *ntfe-ingest.interface-entry-joins-network-record " ..
             "PKM *ntfe-ingest.status-contexts-counts-interfaces" }, function(t)
        local s = ing.replace_inventory(E, NETWORKS, {
            ["if-lo"] = { Name = "lo", Network = LAB },
            ["if-veth"] = { Name = net.name, Network = DMZ },
        })
        t:assert_eq(s.last_ingest_error, 0, "the walk succeeds")
        t:assert_eq(s.contexts, 2, "two interfaces carry a context")
        local c = lo_context()
        t:assert(c.id and c.name and c.trust,
            "lo's entry carries the id its Status names, joined to that record's Name and Trust")
        t:assert_eq(ing.verdict(vm, 6704), "pass", "and not the other network's id")
        t:assert_eq(verdict_from_peer(6704), "reject", "veth0 stands on the other network")
        t:assert_eq(verdict_from_peer(6701), "pass", "and not lo's")
        -- One walk, in order: every rules request, then the inventory.
        local m = E.src:mark()
        ing.poke(E)
        ing.settle(E)
        local function guid(p) return E.src:lookup(NET .. "\\" .. p) end
        local last_rules, first_inventory = 0, nil
        local rules_guids = {}
        for _, p in ipairs({ "Rules", "Rules\\Flow", "Rules\\Packet", "Rules\\RawPacket",
                             "Rules\\Flow\\all", "Rules\\Flow\\lab_id" }) do
            rules_guids[guid(p)] = true
        end
        local inventory = {
            [guid("Networks")] = "Networks", [guid("Interfaces")] = "Interfaces",
            [guid("Networks\\" .. LAB)] = "LAB", [guid("Networks\\" .. DMZ)] = "DMZ",
            [guid("Interfaces\\if-lo")] = "if-lo", [guid("Interfaces\\if-lo\\Status")] = "lo Status",
            [guid("Interfaces\\if-veth")] = "if-veth",
            [guid("Interfaces\\if-veth\\Status")] = "veth Status",
        }
        local reads = {}
        for i = m, #E.src.log do
            local r = E.src.log[i]
            local g = ing.guid_of(r)
            if rules_guids[g] then last_rules = i end
            if inventory[g] then
                first_inventory = first_inventory or i
                local key = inventory[g] .. " " .. lcs.OP_NAME[r.op]
                reads[key] = (reads[key] or 0) + 1
            end
        end
        t:assert(first_inventory and first_inventory > last_rules,
            "the context stage follows the rules stage")
        for _, k in ipairs({ "Networks ENUM_CHILDREN", "LAB QUERY_VALUES", "DMZ QUERY_VALUES",
                             "Interfaces ENUM_CHILDREN", "if-lo ENUM_CHILDREN",
                             "lo Status QUERY_VALUES", "if-veth ENUM_CHILDREN",
                             "veth Status QUERY_VALUES" }) do
            t:assert_eq(reads[k], 1, k .. " once")
        end
    end)

test("a Status missing Name or Network makes no entry",
    { spec = "PKM *ntfe-ingest.incomplete-status-makes-no-entry " ..
             "PKM *ntfe-ingest.status-contexts-counts-interfaces" }, function(t)
        for _, c in ipairs({
            { { Name = "lo" }, "no Network identified" },
            { { Network = LAB }, "no interface Name" },
            { { Mtu = 1500 }, "neither" },
            { { Name = "lo", Network = 7 }, "a Network that is not a string" },
        }) do
            local s = ing.replace_inventory(E, NETWORKS, { ["if-lo"] = c[1] })
            t:assert_eq(s.contexts, 0, c[2] .. ": no interface carries a context")
            t:assert_eq(s.last_ingest_error, 0, c[2] .. ": and nothing failed")
            local ctx = lo_context()
            t:assert(not ctx.id and not ctx.name and not ctx.trust, c[2] .. ": lo has none")
        end
        local s = ing.replace_inventory(E, NETWORKS, { ["if-lo"] = { Name = "lo", Network = LAB } })
        t:assert_eq(s.contexts, 1, "(and back)")
    end)

test("a record's Name and Trust are empty when absent or unreadable, and the id is still a fact",
    { spec = "PKM *ntfe-ingest.unreadable-name-or-trust-is-empty " ..
             "PKM *ntfe-ingest.interface-entry-joins-network-record" }, function(t)
        local function with_record(record)
            return ing.replace_inventory(E, { [LAB] = record },
                { ["if-lo"] = { Name = "lo", Network = LAB } })
        end
        with_record({ Name = "lab" })
        local c = lo_context()
        t:assert(c.id and c.name and not c.trust, "with no Trust, Trust is empty")
        with_record({ Name = 7, Trust = "home" })
        c = lo_context()
        t:assert(c.id and not c.name and c.trust, "a Name that is not a string is empty")
        with_record({})
        c = lo_context()
        t:assert(c.id and not c.name and not c.trust, "a record with no values still gives the id")
        -- A Network naming no record at all: the id, and nothing joined.
        ing.replace_inventory(E, {}, { ["if-lo"] = { Name = "lo", Network = LAB } })
        c = lo_context()
        t:assert(c.id and not c.name and not c.trust, "an id with no record is still the id")
        -- A record whose values cannot be read at all.
        ing.stage_inventory(E, NETWORKS, { ["if-lo"] = { Name = "lo", Network = LAB } })
        local s
        failing(lcs.OP.QUERY_VALUES, E.src:lookup(NET .. "\\Networks\\" .. LAB), function()
            ing.poke(E)
            s = ing.settle(E)
        end)
        t:assert_eq(s.last_ingest_error, 0, "an unreadable record fails nothing")
        c = lo_context()
        t:assert(c.id and not c.name and not c.trust, "and leaves the id with an empty Name and Trust")
        ing.replace_inventory(E, NETWORKS, { ["if-lo"] = { Name = "lo", Network = LAB } })
    end)

test("an interface whose Status cannot be read is skipped, and the rest are read",
    { spec = "PKM *ntfe-ingest.unreadable-record-skipped " ..
             "PKM *ntfe-ingest.context-stage-never-refuses" }, function(t)
        ing.stage_inventory(E, NETWORKS, {
            ["if-lo"] = { Name = "lo", Network = LAB },
            ["if-veth"] = { Name = net.name, Network = DMZ },
        })
        local s
        failing(lcs.OP.QUERY_VALUES, E.src:lookup(NET .. "\\Interfaces\\if-veth\\Status"), function()
            ing.poke(E)
            s = ing.settle(E)
        end)
        t:assert_eq(s.last_ingest_error, 0, "the walk does not fail")
        t:assert_eq(s.contexts, 1, "the unreadable interface carries no context")
        t:assert(lo_context().id, "and the readable one does")
        t:assert_eq(verdict_from_peer(6704), "pass", "veth0 has none")
    end)

test("an interface whose key cannot be enumerated is skipped, and the stage does not refuse",
    { spec = "PKM *ntfe-ingest.context-stage-never-refuses " ..
             "PKM *ntfe-ingest.unreadable-record-skipped", tags = { "known-bug" },
      -- PEI-1306. The TRM: "Nothing in the
      -- stage refuses. A record that cannot be read is logged and
      -- skipped." An interface whose own key fails its ENUM_CHILDREN
      -- (the round trip that finds Status) aborts the whole stage
      -- instead: ntfe_interface_child_cb returns the error from
      -- ntfe_for_each_child, ntfe_refresh_context fails, the new table
      -- is not published (lo keeps the network it stood on before) and
      -- the walk's last_ingest_error is EIO (observed: 5). The same
      -- code path fails the stage on a failed enumeration of
      -- `Networks\` or `Interfaces\` themselves.
    }, function(t)
        ing.replace_inventory(E, NETWORKS, { ["if-lo"] = { Name = "lo", Network = DMZ } })
        ing.stage_inventory(E, NETWORKS, {
            ["if-lo"] = { Name = "lo", Network = LAB },
            ["if-veth"] = { Name = net.name, Network = DMZ },
        })
        local s
        failing(lcs.OP.ENUM_CHILDREN, E.src:lookup(NET .. "\\Interfaces\\if-veth"), function()
            ing.poke(E)
            s = ing.settle(E)
        end)
        local c = lo_context()
        ing.replace_inventory(E, NETWORKS, { ["if-lo"] = { Name = "lo", Network = LAB } })
        t:assert_eq(s.last_ingest_error, 0, "the walk does not fail")
        t:assert_eq(s.contexts, 1, "the unreadable interface is skipped")
        t:assert(c.id, "and the readable one has its new context")
    end)

-- ---- bounds ---------------------------------------------------------------

test("the context table holds 64 interfaces; the 65th carries no context",
    { spec = "PKM *ntfe-ingest.context-table-at-most-64-entries " ..
             "PKM *ntfe-ingest.interface-beyond-64th-has-no-context " ..
             "PKM *ntfe-ingest.status-contexts-counts-interfaces" }, function(t)
        -- Interface keys enumerate in name order; lo's comes `at` place.
        local function with_lo_at(at)
            local ifs, n = {}, 0
            for i = 0, 64 do
                local key = string.format("if%03d", i)
                if i == at then
                    ifs[key] = { Name = "lo", Network = LAB }
                else
                    n = n + 1
                    ifs[key] = { Name = string.format("fake%02d", n), Network = DMZ }
                end
            end
            return ing.replace_inventory(E, NETWORKS, ifs)
        end
        local s = with_lo_at(64)
        t:assert_eq(s.contexts, 64, "65 complete interfaces fill the table at 64")
        t:assert_eq(s.last_ingest_error, 0, "without failing")
        t:assert(not lo_context().id, "the 65th, lo, carries no context")
        s = with_lo_at(63)
        t:assert_eq(s.contexts, 64, "with lo 64th")
        t:assert(lo_context().id, "it does")
        ing.replace_inventory(E, NETWORKS, { ["if-lo"] = { Name = "lo", Network = LAB } })
    end)

test("up to 256 network records are read",
    { spec = "PKM *ntfe-ingest.network-records-up-to-256" }, function(t)
        -- One walk of 257 records (each a round trip, and slow ones: about
        -- 20 ms apiece here), with lo on the 256th and veth0 on the 257th
        -- in enumeration order.
        ing.replace(E, lab_probes({
            n255 = probe("Name", "n255", 6705),
            n256 = probe("Name", "n256", 6706),
            id256 = probe("Id", "net-256", 6707),
        }))
        local nets = {}
        for i = 0, 256 do
            nets[string.format("net-%03d", i)] = { Name = string.format("n%03d", i) }
        end
        local s = ing.replace_inventory(E, nets, {
            ["if-lo"] = { Name = "lo", Network = "net-255" },
            ["if-veth"] = { Name = net.name, Network = "net-256" },
        })
        local lo_named = ing.verdict(vm, 6705)
        local veth_named, veth_id = verdict_from_peer(6706), verdict_from_peer(6707)
        ing.replace_inventory(E, NETWORKS, { ["if-lo"] = { Name = "lo", Network = LAB } })
        ing.replace(E, lab_probes())
        t:assert_eq(s.last_ingest_error, 0, "257 records fail nothing")
        t:assert_eq(s.contexts, 2, "and both interfaces carry a context")
        t:assert_eq(lo_named, "reject", "the 256th record is read and joined")
        t:assert_eq(veth_named, "pass", "the 257th is not")
        t:assert_eq(veth_id, "reject", "though the interface on it still stands on its id")
    end)

test("a network record whose name is too long for an id is ignored",
    { spec = "PKM *ntfe-ingest.overlong-network-id-ignored-once-loudly " ..
             "PKM *ntfe-ingest.overlong-context-value-truncated" }, function(t)
        local fits, long = string.rep("f", 39), string.rep("L", 40)
        ing.replace(E, lab_probes({
            fits_name = probe("Name", "fits", 6711),
            long_name = probe("Name", "long", 6712),
            long_id = probe("Id", long:sub(1, 39), 6713),
        }))
        local nets = { [fits] = { Name = "fits" }, [long] = { Name = "long" } }
        ing.replace_inventory(E, nets, { ["if-lo"] = { Name = "lo", Network = fits } })
        t:assert_eq(ing.verdict(vm, 6711), "reject", "a 39-character id is a record")
        local s = ing.replace_inventory(E, nets, { ["if-lo"] = { Name = "lo", Network = long } })
        t:assert_eq(s.last_ingest_error, 0, "a 40-character one fails nothing")
        t:assert_eq(s.contexts, 1, "and lo still carries a context")
        t:assert_eq(ing.verdict(vm, 6712), "pass", "but the record is ignored")
        t:assert_eq(ing.verdict(vm, 6713), "reject",
            "and the interface's Network is truncated to the field: 39 characters")
        ing.replace(E, lab_probes())
        ing.replace_inventory(E, NETWORKS, { ["if-lo"] = { Name = "lo", Network = LAB } })
    end)

test("a Name or Trust longer than its field is truncated",
    { spec = "PKM *ntfe-ingest.overlong-context-value-truncated" }, function(t)
        local name, trust = string.rep("n", 70), string.rep("t", 40)
        ing.replace(E, lab_probes({
            name_cut = probe("Name", name:sub(1, 63), 6714),
            name_full = probe("Name", name, 6715),
            trust_cut = probe("Trust", trust:sub(1, 31), 6716),
            trust_full = probe("Trust", trust, 6717),
        }))
        local s = ing.replace_inventory(E, { [LAB] = { Name = name, Trust = trust } },
            { ["if-lo"] = { Name = "lo", Network = LAB } })
        t:assert_eq(s.last_ingest_error, 0, "an overlong value fails nothing")
        t:assert_eq(ing.verdict(vm, 6714), "reject", "the Name is its first 63 bytes")
        t:assert_eq(ing.verdict(vm, 6715), "pass", "not all 70")
        t:assert_eq(ing.verdict(vm, 6716), "reject", "the Trust its first 31")
        t:assert_eq(ing.verdict(vm, 6717), "pass", "not all 40")
        ing.replace(E, lab_probes())
        ing.replace_inventory(E, NETWORKS, { ["if-lo"] = { Name = "lo", Network = LAB } })
    end)

-- ---- publication ----------------------------------------------------------

test("a context table equal to the active one publishes nothing; a changed one is a generation",
    { spec = "PKM *ntfe-ingest.equal-context-table-publishes-nothing " ..
             "PKM *ntfe-ingest.changed-context-table-advances-generation " ..
             "PKM *ntfe-ingest.status-contexts-counts-interfaces" }, function(t)
        local before = ing.replace_inventory(E, NETWORKS, { ["if-lo"] = { Name = "lo", Network = LAB } })
        -- netd rewriting Status with what it already says.
        local status = ing.open(E, "Interfaces\\if-lo\\Status")
        ing.quick_write(E, status, "Network", LAB)
        ing.quick_write(E, status, "Name", "lo")
        local same = ing.settle(E)
        t:assert_eq(same.generation, before.generation, "the same table again is nothing")
        t:assert_eq(same.contexts, 1, "and lo keeps its one entry")
        -- The operator changes the word on the network.
        local record = ing.open(E, "Networks\\" .. LAB)
        ing.quick_write(E, record, "Trust", "public")
        local changed = ing.settle(E)
        t:assert_eq(changed.generation, before.generation + 1, "a changed table is a new generation")
        t:assert(not lo_context().trust, "and lo's Trust is no longer home")
        -- A second interface: a generation, and the count.
        local s = ing.replace_inventory(E, NETWORKS, {
            ["if-lo"] = { Name = "lo", Network = LAB },
            ["if-veth"] = { Name = net.name, Network = DMZ },
        })
        t:assert_eq(s.generation, changed.generation + 1, "another interface on a network is one more")
        t:assert_eq(s.contexts, 2, "and `contexts` counts it")
        s = ing.replace_inventory(E, NETWORKS, {})
        t:assert_eq(s.contexts, 0, "an empty table counts none")
        ing.replace_inventory(E, NETWORKS, { ["if-lo"] = { Name = "lo", Network = LAB } })
    end)

test("a context change reaches a running flow on its next packet, as a rule change would",
    { spec = "PKM *ntfe-ingest.context-change-rejudges-flows-on-next-packet " ..
             "PKM *ntfe-ingest.changed-context-table-advances-generation" }, function(t)
        ing.replace(E, lab_probes({
            trusted = { ["Network.Trust.Equal"] = "home", ["DstPort.Equal"] = 6720,
                        Priority = 2, Actions = { "PASS" } },
            closed = { ["DstPort.Equal"] = 6720, Priority = 1, Actions = { "DROP" } },
        }))
        ing.replace_inventory(E, NETWORKS, { ["if-lo"] = { Name = "lo", Network = LAB } })
        local l = assert(ntfe.tcp_listen(vm, "127.0.0.1", 6720))
        local c = assert(ntfe.tcp_connect(vm, "127.0.0.1", 6720), "lo is home: the flow is passed")
        local a = assert(ntfe.tcp_accept(vm, l))
        ntfe.send(vm, c, "before")
        t:assert_eq(ntfe.recv(vm, a), "before", "and carries data")
        local g = E:status().generation
        local record = ing.open(E, "Networks\\" .. LAB)
        ing.quick_write(E, record, "Trust", "public")
        t:assert_eq(ing.settle(E).generation, g + 1, "the network's Trust changes: a new generation")
        local delta, events = E:during(function()
            ntfe.send(vm, c, "after")
            t:assert_eq(select(2, ntfe.recv(vm, a, 300)), "timeout",
                "the flow's next packet is re-judged and dropped")
        end)
        t:assert(delta.flow_rejudged >= 1, "re-judged")
        local dropped = ntfe.matching(events, { attributed = "closed", verdict = ntfe.VERDICT.DROP })
        t:assert(#dropped >= 1 and dropped[1].rejudged, "by the rule that now speaks: " ..
            ntfe.describe(events))
        sys.close(vm, c); sys.close(vm, a); sys.close(vm, l)
        ing.replace_inventory(E, NETWORKS, { ["if-lo"] = { Name = "lo", Network = LAB } })
    end)

test("a refused rules stage does not skip the context stage",
    { spec = "PKM *ntfe-ingest.rules-failure-does-not-skip-context" }, function(t)
        ing.replace(E, lab_probes())
        local before = ing.replace_inventory(E, NETWORKS, { ["if-lo"] = { Name = "lo", Network = LAB } })
        ing.stage(E, lab_probes({ broken = { ["NoSuchFact.Equal"] = 1 } }))
        ing.stage_inventory(E, NETWORKS, { ["if-lo"] = { Name = "lo", Network = DMZ } })
        ing.poke(E)
        local s = ing.settle(E)
        t:assert_eq(s.last_ingest_error, ing.EINVAL, "the walk reports the rules' refusal")
        t:assert_eq(s.generation, before.generation + 1, "yet one generation is published: the context's")
        t:assert_eq(ing.verdict(vm, 6704), "reject", "lo now stands on the other network")
        t:assert_eq(ing.verdict(vm, 6701), "pass", "and the rules judging it are the ones before")
        ing.replace(E, lab_probes())
        ing.replace_inventory(E, NETWORKS, { ["if-lo"] = { Name = "lo", Network = LAB } })
    end)

-- lo frames carry no MAC, so ingest-walk cannot show this one; frames
-- from the peer arrive on veth0 addressed to its MAC.
test("DstMac is never true in a Flow forest",
    { spec = "PKM *ntfe-ingest.layer-impossible-facts-lint-not-refuse" }, function(t)
        local mac = string.format("%02x:%02x:%02x:%02x:%02x:%02x", net.mac:byte(1, 6))
        local s = ing.replace(E, lab_probes({
            by_mac = { ["DstMac.Equal"] = mac, ["DstPort.Equal"] = 6730,
                       Priority = 1, Actions = { "REJECT" } },
        }))
        local v = verdict_from_peer(6730)
        ing.replace(E, lab_probes())
        t:assert_eq(s.last_ingest_error, 0, "the rule is accepted")
        t:assert_eq(v, "pass", "and a connection to veth0's own MAC is not rejected by it")
    end)
