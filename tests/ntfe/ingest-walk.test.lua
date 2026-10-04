-- PKM §6.5 — The walk and the build: what the rules stage reads from
-- `Rules\` and how (the reporting level, the three layer keys, two round
-- trips per rule), how registry types are lowered for the builder and
-- which types refuse, the digest that decides whether a walk publishes,
-- and what the builder does with a forest that validates — live-time
-- conditions ordered last, priority inherited, layer-impossible facts
-- linted rather than refused, and the name sets the stores are built
-- from.
--
-- Policies are swapped with the harness shortcut (`ing.replace`): these
-- are statements about what a walk reads, not about how it was told to.
--
-- Own VM: the policy is machine-wide state.

local lcs = require("helpers.lcs")
local ntfe = require("helpers.ntfe")
local ing = require("helpers.ntfe_ingest")

local vm = provium:vm("vntfeiwk", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))

local E = ing.engine(vm, ing.policy())

local T = lcs.TYPE
local function typed(vtype, data) return { type = vtype, data = data } end

-- ---- the reporting level ----------------------------------------------

test("CurrentReportingLevel is a DWORD, big-endian DWORD or QWORD from 1 to 6, and 1 when absent",
    { spec = "PKM *ntfe-ingest.reporting-level-type-and-range" }, function(t)
        local function with_level(v)
            return ing.policy(nil, { values = v ~= nil and { CurrentReportingLevel = v } or nil })
        end
        local s = ing.replace(E, with_level(nil))
        t:assert_eq(s.reporting_level, 1, "absent is 1")
        for _, c in ipairs({
            { 3, 3, "a DWORD" },
            { typed(T.DWORD_BIG_ENDIAN, string.pack(">I4", 4)), 4, "a big-endian DWORD" },
            { typed(T.QWORD, lcs.qword(6)), 6, "a QWORD" },
            { 1, 1, "the lowest level" },
        }) do
            s = ing.replace(E, with_level(c[1]))
            t:assert_eq(s.last_ingest_error, 0, c[3] .. " is accepted")
            t:assert_eq(s.reporting_level, c[2], c[3] .. " reads as " .. c[2])
        end
        s = ing.replace(E, with_level(5))
        for _, c in ipairs({
            { 0, "zero" },
            { 7, "seven" },
            { typed(T.QWORD, lcs.qword((1 << 32) + 3)), "a QWORD whose low word is in range" },
            { "3", "a string" },
            { typed(T.BINARY, "\3"), "a binary value" },
        }) do
            local r = ing.replace(E, with_level(c[1]))
            t:assert_eq(r.last_ingest_error, ing.EINVAL, c[2] .. " refuses the walk")
            t:assert_eq(r.generation, s.generation, c[2] .. ": nothing is published")
            t:assert_eq(r.reporting_level, 5, c[2] .. ": the level in force stays")
        end
        ing.replace(E, with_level(nil))
    end)

-- ---- what the walk reads ---------------------------------------------

test("the kernel reads the Packet, RawPacket and Flow layer keys and ignores every other",
    { spec = "PKM *ntfe-ingest.kernel-reads-three-layer-keys-only" }, function(t)
        -- Rules that would refuse the walk, under keys the kernel must
        -- not read: netd's Interface layer and a name nobody owns.
        local junk = { broken = { ["NoSuchFact.Equal"] = 1, Actions = { "FROB" } } }
        local s = ing.replace(E, ing.policy(nil, { Interface = junk, Bogus = junk }))
        t:assert_eq(s.last_ingest_error, 0, "the walk succeeds: neither key was read")
        local unread = {}
        for _, p in ipairs({ "Interface", "Interface\\broken", "Bogus", "Bogus\\broken" }) do
            unread[E.src:lookup(ntfe.RULES_KEY .. "\\" .. p)] = p
        end
        local m = E.src:mark()
        ing.poke(E)
        ing.settle(E)
        for i = m, #E.src.log do
            local g = ing.guid_of(E.src.log[i])
            t:assert(not unread[g], "nothing asks about " .. tostring(unread[g]))
        end
        t:assert_eq(ing.verdict(vm, 6601), "pass", "and the three layers' rules judge")
    end)

test("each rule is one QUERY_VALUES and one ENUM_CHILDREN round trip, exceptions recursively",
    { spec = "PKM *ntfe-ingest.rule-read-is-two-round-trips" }, function(t)
        local policy = ing.policy({
            outer = { ["DstPort.Equal"] = 6602, Actions = { "REJECT" }, children = {
                middle = { ["SrcAddr.Equal"] = "10.0.0.1", Actions = { "PASS" }, children = {
                    inner = { ["SrcPort.Equal"] = 1, Actions = { "REJECT" } },
                } },
            } },
        })
        ing.replace(E, policy)
        local m = E.src:mark()
        ing.poke(E)
        ing.settle(E)
        local function count(op, path)
            return #E.src:served(op, m, E.src:lookup(ntfe.RULES_KEY .. "\\" .. path))
        end
        for _, p in ipairs({ "Flow\\all", "Flow\\outer", "Flow\\outer\\middle",
                             "Flow\\outer\\middle\\inner", "Packet\\all", "RawPacket\\all" }) do
            t:assert_eq(count(lcs.OP.QUERY_VALUES, p), 1, p .. ": its values in one round trip")
            t:assert_eq(count(lcs.OP.ENUM_CHILDREN, p), 1, p .. ": its exceptions in one more")
        end
        for _, p in ipairs({ "Flow", "Packet", "RawPacket" }) do
            t:assert_eq(count(lcs.OP.QUERY_VALUES, p), 0, "the layer key " .. p .. " has no values read")
            t:assert_eq(count(lcs.OP.ENUM_CHILDREN, p), 1, "its rules are enumerated once")
        end
        -- And what came back is the rule: the innermost exception speaks.
        t:assert_eq(ing.verdict(vm, 6602), "reject", "the walked tree judges")
    end)

-- ---- registry types ----------------------------------------------------

test("registry types are lowered as the builder expects",
    { spec = "PKM *ntfe-ingest.registry-type-lowering" }, function(t)
        local function reject(port, v) return { ["DstPort.Equal"] = v, Actions = { "REJECT" } } end
        local s = ing.replace(E, ing.policy({
            sz = reject(6611, typed(T.SZ, "6611\0")),
            sz_bare = reject(6612, typed(T.SZ, "6612")),
            sz_padded = reject(6613, typed(T.SZ, "6613\0\0\0")),
            expand = reject(6614, typed(T.EXPAND_SZ, "6614\0")),
            dword = reject(6615, typed(T.DWORD, string.pack("<I4", 6615))),
            big = reject(6616, typed(T.DWORD_BIG_ENDIAN, string.pack(">I4", 6616))),
            qword = reject(6617, typed(T.QWORD, string.pack("<i8", 6617))),
            multi = reject(6618, typed(T.MULTI_SZ, ntfe.multi_sz({ "6618", "6619" }))),
            -- A QWORD is signed: -5 is below the default priority 0, so
            -- the REJECT beside it wins. Read unsigned it would outrank it.
            negative = { ["DstPort.Equal"] = 6620, Priority = typed(T.QWORD, string.pack("<i8", -5)),
                         Actions = { "PASS" } },
            beside = { ["DstPort.Equal"] = 6620, Actions = { "REJECT" } },
        }))
        t:assert_eq(s.last_ingest_error, 0, "every type is accepted")
        for _, c in ipairs({
            { 6611, "REG_SZ, its NUL stripped" }, { 6612, "REG_SZ with no NUL" },
            { 6613, "REG_SZ with several NULs" }, { 6614, "REG_EXPAND_SZ" },
            { 6615, "REG_DWORD" }, { 6616, "REG_DWORD_BIG_ENDIAN, read big-endian" },
            { 6617, "REG_QWORD" }, { 6618, "REG_MULTI_SZ, a list" },
            { 6619, "every element of the list" }, { 6620, "a negative REG_QWORD" },
        }) do
            t:assert_eq(ing.verdict(vm, c[1]), "reject", c[2] .. " matches port " .. c[1])
        end
        t:assert_eq(ing.verdict(vm, 6621), "pass", "and a port nobody named passes")
    end)

-- A type number LCS does not know never reaches NTFE: its materializer
-- refuses the record (EIO). Every type it does know but NTFE does not
-- lower is NTFE's refusal (EINVAL).
for _, c in ipairs({
    { T.BINARY, "\x22\x1a", "REG_BINARY", ing.EINVAL },
    { T.NONE, "", "REG_NONE", ing.EINVAL },
    { T.LINK, "Machine\\Elsewhere", "REG_LINK", ing.EINVAL },
    { T.RESOURCE_LIST, "\0\0\0\0", "REG_RESOURCE_LIST", ing.EINVAL },
    { 0x1234, "\1\2\3\4", "an unassigned type number", 5 },
}) do
    test("a " .. c[3] .. " value in a rule refuses the walk",
        { spec = "PKM *ntfe-ingest.other-value-type-refuses-walk" }, function(t)
            local good = ing.replace(E, ing.policy({
                r = { ["DstPort.Equal"] = 6622, Actions = { "REJECT" } },
            }))
            local bad = ing.replace(E, ing.policy({
                r = { ["DstPort.Equal"] = 6622, Actions = { "REJECT" }, Note = typed(c[1], c[2]) },
            }))
            t:assert_eq(bad.last_ingest_error, c[4], "the walk is refused")
            t:assert_eq(bad.generation, good.generation, "and nothing is published")
            t:assert_eq(ing.verdict(vm, 6622), "reject", "the rule as it was still judges")
        end)
end

-- ---- the digest ---------------------------------------------------------

test("everything fed to the builder is digested; anything else is not",
    { spec = "PKM *ntfe-ingest.rules-input-digested " ..
             "PKM *ntfe-ingest.unchanged-digest-publishes-nothing" }, function(t)
        local function rule(v, name, extra)
            return ing.policy({ [name or "d"] = { ["DstPort.Equal"] = v, Actions = { "REJECT" } } }, extra)
        end
        local g = ing.replace(E, rule(6631)).generation
        t:assert_eq(ing.replace(E, rule(6631)).generation, g, "the same rules again publish nothing")
        -- The same meaning in a different registry type is a different
        -- input: the type is digested.
        g = g + 1
        t:assert_eq(ing.replace(E, rule("6631")).generation, g,
            "a value retyped from DWORD to REG_SZ is a new generation")
        t:assert_eq(ing.verdict(vm, 6631), "reject", "which means the same")
        g = g + 1
        t:assert_eq(ing.replace(E, rule("6631", "renamed")).generation, g,
            "a renamed rule is a new generation")
        g = g + 1
        t:assert_eq(ing.replace(E, rule("6631", "renamed", { values = { CurrentReportingLevel = 2 } })).generation,
            g, "a new reporting level is a new generation")
        -- The level is digested as the level, not as the value that set
        -- it: writing the default explicitly changes nothing fed.
        g = g + 1
        t:assert_eq(ing.replace(E, rule("6631", "renamed")).generation, g, "(back to the default)")
        t:assert_eq(ing.replace(E, rule("6631", "renamed", { values = { CurrentReportingLevel = 1 } })).generation,
            g, "an explicit level 1 is what absent already was")
        -- What the walk does not feed the builder is not digested.
        t:assert_eq(ing.replace(E, rule("6631", "renamed", { values = { Comment = "hello" } })).generation,
            g, "another value on the Rules key is not fed, and publishes nothing")
        t:assert_eq(ing.replace(E, rule("6631", "renamed", {
            Interface = { x = { Actions = { "IGNORE" } } } })).generation,
            g, "nor do netd's Interface rules")
    end)

-- ---- the build -----------------------------------------------------------

test("live-time conditions are evaluated last, whatever order the registry gives them",
    { spec = "PKM *ntfe-ingest.build-orders-live-time-conditions-last" }, function(t)
        -- The registry serves values by name, so `Time.Hour.Equal` comes
        -- before `Vlan.Equal`. A consulted clock condition bounds the
        -- flow's sentence by its next flip; one never consulted does not.
        local hour = 10
        ing.replace(E, ing.policy({
            consulted = { ["DstPort.Equal"] = 6641, ["Time.Hour.Equal"] = hour,
                          Priority = 1, Actions = { "PASS" } },
            behind = { ["Time.Hour.Equal"] = hour, ["Vlan.Equal"] = 5,
                       Priority = 1, Actions = { "REJECT" } },
        }))
        t:assert_eq(ing.verdict(vm, 6641), "pass", "a flow whose rule reads the clock")
        t:assert_eq(ing.verdict(vm, 6642), "pass", "and one only `behind` could have read it for")
        local expiry = {}
        for _, f in ipairs(E:flows()) do
            for s = 0, 1 do
                local port = f.dst_port
                if (port == 6641 or port == 6642) and f.sentences[s].generation ~= 0 then
                    expiry[port] = math.max(expiry[port] or 0, f.sentences[s].expires_at)
                end
            end
        end
        t:assert(expiry[6641] and expiry[6641] > 0,
            "a consulted clock condition gives the sentence an expiry: " .. tostring(expiry[6641]))
        t:assert_eq(expiry[6642], 0,
            "behind's VLAN condition failed before its clock was consulted, though the clock came first")
    end)

test("priority is inherited down the tree",
    { spec = "PKM *ntfe-ingest.build-resolves-priority-inheritance" }, function(t)
        local function policy(kid_priority)
            local kid = { ["DstPort.Equal"] = 6651, Actions = { "PASS" }, Priority = kid_priority }
            return ing.policy({
                parent = { Priority = 10, Actions = { "PASS" }, children = { kid = kid } },
                blocker = { ["DstPort.Equal"] = 6651, Priority = 5, Actions = { "REJECT" } },
            })
        end
        ing.replace(E, policy(nil))
        local _, events = E:during(function()
            t:assert_eq(ing.verdict(vm, 6651), "pass",
                "an exception with no Priority outranks 5 with its parent's 10")
        end)
        local kid = false
        for _, e in ipairs(events) do
            if e.dst_port == 6651 and e.attributed:find("kid", 1, true) then kid = true end
        end
        t:assert(kid, "and the exception speaks: " .. ntfe.describe(events))
        ing.replace(E, policy(0))
        t:assert_eq(ing.verdict(vm, 6651), "reject", "given its own priority 0, it does not")
    end)

-- Conditions on facts the TRM calls impossible at their layer. Each
-- would hold for a TCP connection on lo if the fact existed there, and
-- sits in a REJECT rule that outranks `all`: a connection that passes is
-- one the condition was false for. `impossible` installs them all in one
-- policy, each on its own port (6660 + i).
local IMPOSSIBLE = {
    { "RawPacket", { ["Tag.nobody.Equal"] = 0 }, "a tag in RawPacket" },
    { "RawPacket", { ["Related.Equal"] = 0 }, "Related in RawPacket" },
    { "RawPacket", { ["Start.Year.GreaterThan"] = 0 }, "Start.* in RawPacket" },
    { "Packet", { ["Related.Equal"] = 0 }, "Related in Packet" },
    { "Packet", { ["Start.Hour.GreaterThan"] = "-1" }, "Start.* in Packet" },
    -- (DstMac in Flow needs a frame with a MAC: ingest-context, with
    -- the peer.)
    -- The cases below hold where the TRM says they never do (the
    -- known-bug test after this one).
    { "RawPacket", { ["FlowState.Equal"] = "new" }, "FlowState in RawPacket", bug = true },
    { "Flow", { ["Length.GreaterThan"] = 0 }, "Length in Flow", bug = true },
    { "Flow", { ["TcpFlags.Has"] = { "SYN" } }, "TcpFlags in Flow", bug = true },
    { "Flow", { ["Fragment.Equal"] = 0 }, "Fragment in Flow", bug = true },
    { "Flow", { ["Ttl.GreaterThan"] = 0 }, "Ttl in Flow", bug = true },
    { "Flow", { ["Dscp.Equal"] = 0 }, "Dscp in Flow", bug = true },
    { "Flow", { ["EtherType.Equal"] = "ipv4" }, "EtherType in Flow", bug = true },
    { "Flow", { ["FlowState.Equal"] = "new" }, "FlowState in Flow", bug = true },
}

local function impossible()
    local policy = { RawPacket = { all = { Actions = { "PASS" } } },
                     Packet = { all = { Actions = { "PASS" } } },
                     Flow = { all = { Actions = { "PASS" } } } }
    for i, c in ipairs(IMPOSSIBLE) do
        local rule = { ["DstPort.Equal"] = 6660 + i, Priority = 1, Actions = { "REJECT" } }
        for k, v in pairs(c[2]) do rule[k] = v end
        policy[c[1]]["lint" .. i] = rule
    end
    return ing.replace(E, policy)
end

test("conditions on facts impossible at their layer are linted, not refused",
    { spec = "PKM *ntfe-ingest.layer-impossible-facts-lint-not-refuse" }, function(t)
        local before = E:status()
        local s = impossible()
        t:assert_eq(s.last_ingest_error, 0, "a policy full of them is accepted")
        t:assert(s.generation > before.generation, "and published")
        for i, c in ipairs(IMPOSSIBLE) do
            if not c.bug then
                t:assert_eq(ing.verdict(vm, 6660 + i), "pass", c[3] .. " is never true")
            end
        end
    end)

test("per-packet facts are never true in a Flow forest, nor FlowState in a RawPacket one",
    { spec = "PKM *ntfe-ingest.layer-impossible-facts-lint-not-refuse", tags = { "known-bug" },
      -- PEI-1302. The TRM lists
      -- `Length`, `TcpFlags`, `Fragment`, `Ttl`, `Dscp`, `EtherType`,
      -- `DstMac` and `FlowState` as never true in a Flow forest, and
      -- `FlowState` as never true in RawPacket. Live, a Flow rule on any
      -- of the other seven matches the connection's first packet and
      -- its REJECT is the verdict (events attribute LOCAL_OUT Flow
      -- REJECT to the lint rule; DstMac, tested with the peer in
      -- ingest-context, is indeed never true); a RawPacket `FlowState.Equal new`
      -- rule matches at the EGRESS seat (the event shows seat 2, layer
      -- 1, REJECT degraded to a drop). The bridge's snapshot conversion
      -- (ntfe_runtime.rs, snapshot_from_c) copies every per-packet fact
      -- and flow_state into every layer's snapshot; only tags and the
      -- flow-only facts are withheld by layer. pnp-core's own lint says
      -- the Flow snapshot is never given them.
    }, function(t)
        impossible()
        for i, c in ipairs(IMPOSSIBLE) do
            if c.bug then
                t:assert_eq(ing.verdict(vm, 6660 + i), "pass", c[3] .. " is never true")
            end
        end
    end)

test("the build collects the tag, stream and view names the stores are built from",
    { spec = "PKM *ntfe-ingest.build-collects-name-sets" }, function(t)
        local s = ing.replace(E, ing.policy({
            -- Read in Flow, written in Packet: the read side's name set
            -- is what makes Flow look the tag up.
            tagged = { ["DstPort.Equal"] = 6681, ["Tag.marked.Equal"] = 7, Actions = { "REJECT" } },
            -- Written only by a PROMPT's fallback.
            prompted = { ["DstPort.Equal"] = 6682, ["Tag.asked.Equal"] = 3, Actions = { "REJECT" } },
            -- Two views of the stream, in two forests.
            unkeyed = { ["DstPort.Equal"] = 6685, ["Counter.hits(1m).GreaterThan"] = 1000000,
                        Actions = { "DROP" } },
        }, {
            Packet = {
                all = { Actions = { "PASS", "COUNT(hits)" } },
                mark = { ["DstPort.Equal"] = 6681, Actions = { "TAG(marked, Set, 7)", "PASS" } },
                ask = { ["DstPort.Equal"] = 6682, Actions = { "PROMPT(nobody, TAG(asked, Set, 3))", "PASS" } },
            },
            RawPacket = {
                all = { Actions = { "PASS" } },
                view = { ["DstPort.Equal"] = 6683, ["Counter.hits(30s, DstAddr).GreaterThan"] = 1000000,
                         Actions = { "DROP" } },
            },
        }))
        t:assert_eq(s.last_ingest_error, 0, "the policy is accepted")
        t:assert_eq(ing.verdict(vm, 6681), "reject", "a tag written in Packet is read in Flow")
        t:assert_eq(ing.verdict(vm, 6682), "reject", "and one written by a PROMPT fallback")
        t:assert_eq(ing.verdict(vm, 6684), "pass", "while other flows are untouched")
        local tables = {}
        for _, c in ipairs(E:counters()) do
            if c.name == "hits" then tables[c.keyspec] = c end
        end
        -- The counter store is materialized from the views every forest
        -- collected, and filled by the stream COUNT writes.
        t:assert(tables[0] and tables[0].windows[60] ~= nil,
            "the view Flow reads has its table, with its window")
        t:assert(tables[ntfe.KEY.DST_ADDR] and tables[ntfe.KEY.DST_ADDR].windows[30] ~= nil,
            "and so does the keyed view RawPacket reads")
        t:assert(tables[0].total > 0, "and the stream Packet writes fills them")
    end)

test("counter views are deduplicated and each condition reads its own by index",
    { spec = "PKM *ntfe-ingest.views-deduplicated-and-indexed" }, function(t)
        -- Two streams far apart: `big` grows a hundred per packet,
        -- `small` one. Three rules mention two views; the first and third
        -- mention the same one, so a condition reading by the wrong index
        -- would read the other stream.
        ing.replace(E, ing.policy({
            first = { ["DstPort.Equal"] = 6691, ["Counter.big.GreaterThan"] = 50,
                      Priority = 1, Actions = { "REJECT" } },
            second = { ["DstPort.Equal"] = 6692, ["Counter.small.GreaterThan"] = 100000,
                       Priority = 1, Actions = { "REJECT" } },
            third = { ["DstPort.Equal"] = 6693, ["Counter.big.GreaterThan"] = 50,
                      Priority = 1, Actions = { "REJECT" } },
        }, { RawPacket = { all = { Actions = { "PASS", "COUNT(big, 100)", "COUNT(small)" } } } }))
        t:assert_eq(ing.verdict(vm, 6694), "pass", "(some traffic is counted)")
        t:assert_eq(ing.verdict(vm, 6691), "reject", "the first rule reads `big`")
        t:assert_eq(ing.verdict(vm, 6692), "pass", "the second reads `small`, not `big`")
        t:assert_eq(ing.verdict(vm, 6693), "reject", "the third reads the view the first did")
    end)
