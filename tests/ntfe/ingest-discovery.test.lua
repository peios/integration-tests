-- PKM §6.5 — A machine whose hive has no `Machine\System\Network` key:
-- generation 0 and what it means, the absent key that is no error, a
-- Network key with no Rules key, and the walks of a hive that still
-- runs LCS's bootstrap refresh on every key created (helpers/ntfe_ingest
-- explains the machine-root fallback), which is the one place a
-- bootstrap walk and the deferred walk can meet.
--
-- Own VM: the first tests need a kernel that has never ingested a
-- policy, and the hive is built up from nothing through the registry.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")
local ntfe = require("helpers.ntfe")
local ing = require("helpers.ntfe_ingest")

local vm = provium:vm("vntfeidc", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))

-- A Machine hive with nothing in it at all.
local E = ing.engine(vm, nil, { no_network = true, fallback = true })
local registered = E:status()

local function walks_since(m) return E.net_guid and #ing.walk_starts(E, m) or 0 end

-- reg_create_key from the hive root, served until it returns.
local function create(path)
    local r = lcs.create_key(E.src, E.writer, { path = path })
    assert(r.ret >= 0, "create " .. path .. ": " .. sys.errname(r.errno or 0))
    return r.ret
end

test("with no Network key there is no policy and no error, and generation 0 stands",
    { spec = "PKM *ntfe-ingest.absent-network-key-is-not-an-error" }, function(t)
        t:assert_eq(registered.generation, 0, "registering a hive without the key publishes nothing")
        t:assert_eq(registered.last_ingest_error, 0, "and the absence is not an error")
        t:assert_eq(registered.contexts, 0, "there is no context either")
        local enum = 0
        for _, r in ipairs(E.src.log) do
            if r.op == lcs.OP.ENUM_CHILDREN then enum = enum + 1 end
        end
        t:assert_eq(enum, 0, "nothing was walked")
        t:assert_eq(registered.changes_noted, 0, "nothing is watched")
    end)

test("generation 0 is permissive in every layer",
    { spec = "PKM *ntfe-ingest.generation-zero-is-permissive " ..
             "PKM *ntfe-ingest.generation-zero-status-and-no-events" }, function(t)
        local delta, events, after = E:during(function()
            t:assert_eq(ing.verdict(vm, 6501), "pass", "a TCP connection is let through")
            local u = assert(ntfe.udp_bind(vm, "127.0.0.1", 6502))
            local c = assert(ntfe.udp_connect(vm, "127.0.0.1", 6502))
            ntfe.send(vm, c, "datagram")
            t:assert_eq(ntfe.recv(vm, u), "datagram", "and a UDP datagram")
            sys.close(vm, u); sys.close(vm, c)
        end)
        t:assert_eq(after.generation, 0, "still at generation 0")
        t:assert_eq(after.enforcing, 0, "the status says nothing is enforced")
        t:assert_eq(delta.judged, 0, "no forest judged anything")
        t:assert(delta.permissive > 0, "every traversal was counted as permissive: " .. delta.permissive)
        t:assert_eq(#events, 0, "and no event was emitted: there was no decision to attribute")
        t:assert_eq(delta.verdict_pass + delta.verdict_drop + delta.verdict_reject, 0,
            "nor any verdict counted")
    end)

test("a Network key with no Rules key is walked and leaves the generation where it was",
    { spec = "PKM *ntfe-ingest.absent-rules-key-keeps-generation " ..
             "PKM *ntfe-ingest.absent-network-key-is-not-an-error" }, function(t)
        create("Machine\\System")
        local m = E.src:mark()
        create(ntfe.NETWORK_KEY)
        E.net_guid = E.src:lookup(ntfe.NETWORK_KEY)
        t:assert(walks_since(m) >= 1,
            "the key, once it exists, is found by LCS's bootstrap refresh and walked")
        local s = E:status()
        t:assert_eq(s.generation, 0, "with no Rules key nothing is published")
        t:assert_eq(s.last_ingest_error, 0, "and nothing failed")
        t:assert(s.last_ingest_t_ns > 0, "though the walk recorded its outcome")
        t:assert_eq(ing.verdict(vm, 6501), "pass", "generation 0 is still permissive")
        -- The watch is armed now: a write beneath the key is noted.
        E.net_fd = lcs.open_key(E.src, E.writer, -1, ntfe.NETWORK_KEY).ret
        local before = E:status()
        ing.quick_write(E, E.net_fd, "TestPoke", 1)
        t:assert_eq(E:status().changes_noted, before.changes_noted + 1, "the key is watched")
        s = ing.settle(E)
        t:assert_eq(s.generation, 0, "and still nothing is published")
    end)

test("an empty Rules key is a policy with no forests: published, and still permissive",
    { spec = "PKM *ntfe-ingest.generation-zero-is-permissive" }, function(t)
        create(ntfe.RULES_KEY)
        local s = ing.settle(E)
        t:assert_eq(s.generation, 1, "the first successful ingestion is generation 1")
        t:assert_eq(s.enforcing, 0, "but with no forest nothing is enforced")
        t:assert_eq(ing.verdict(vm, 6501), "pass", "and traffic still passes")
    end)

test("the first policy written through the registry is enforced",
    { spec = "PKM *ntfe-ingest.refused-walk-keeps-previous-generation" }, function(t)
        for _, layer in ipairs({ "RawPacket", "Packet", "Flow" }) do
            create(ntfe.RULES_KEY .. "\\" .. layer)
            E:write_rule("Rules\\" .. layer .. "\\all", { Actions = { "PASS" } })
        end
        E:write_rule("Rules\\Flow\\zz", { ["DstPort.Equal"] = 6503, Actions = { "REJECT" } })
        local s = ing.settle(E)
        t:assert_eq(s.enforcing, 1, "a policy is enforcing")
        t:assert_eq(ing.verdict(vm, 6503), "reject", "and judges")
        -- A refusal now keeps that generation, not generation 0.
        local zz = ing.open(E, "Rules\\Flow\\zz")
        ing.quick_write(E, zz, "Enabled", 9)
        local bad = ing.settle(E)
        t:assert(bad.last_ingest_error ~= 0, "a broken write is refused")
        t:assert_eq(bad.generation, s.generation, "the generation stays")
        t:assert_eq(ing.verdict(vm, 6503), "reject", "and the policy before it judges")
        ing.quick_write(E, zz, "Enabled", 1)
        t:assert_eq(ing.settle(E).last_ingest_error, 0, "(repaired)")
    end)

test("a bootstrap walk and the deferred walk never run at once",
    { spec = "PKM *ntfe-ingest.walks-serialized-under-mutex " ..
             "PKM *ntfe-ingest.publish-serialized-under-mutex" }, function(t)
        ing.settle(E)
        -- The deferred walk, held at the last rule it reads.
        local zz = E.src:lookup(ntfe.RULES_KEY .. "\\Flow\\zz")
        local held = ing.hold_next(E, lcs.OP.QUERY_VALUES, zz)
        ing.poke(E)
        ing.pump_until(E, function() return held.req ~= nil end)
        -- A key created anywhere under Machine re-runs the bootstrap
        -- refresh inside the creating call, and its NTFE walk with it.
        local m = E.src:mark()
        local creating = lcs.create_key_async(E.writer, { path = "Machine\\Elsewhere" })
        ing.pump(E, 150)
        local discovered = false
        for i = m, #E.src.log do
            if lcs.lookup_name(E.src.log[i]) == "Network" then discovered = true end
        end
        local second_started = walks_since(m)
        -- Let the first walk finish.
        local after_release = E.src:mark()
        ing.release(E, held)
        ing.pump_until(E, function() return walks_since(after_release) > 0 end)
        local r = creating:await()
        ing.settle(E)
        t:assert_eq(r.ret >= 0, true, "the key is created")
        t:assert(discovered, "the bootstrap refresh reached the Network key while the walk was held")
        t:assert_eq(second_started, 0, "but its walk did not start while the other was out")
        -- Released, the held walk reads the rest of its last rule (its
        -- exceptions) before the second walk asks for anything.
        local log = E.src.log
        local first = log[after_release]
        t:assert(first.op == lcs.OP.ENUM_CHILDREN and ing.guid_of(first) == zz,
            "the first request after the release is the held walk's own next one")
        local second = ing.walk_starts(E, after_release)[1]
        t:assert(ing.index_of(E, second) > after_release,
            "and the second walk begins only after it")
        for i = after_release + 1, ing.index_of(E, second) - 1 do
            t:assert(ing.guid_of(log[i]) ~= E.net_guid, "with nothing of the second walk before it")
        end
    end)
