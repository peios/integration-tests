-- PKM §6.9 — the principal behind a program end, as the Flow layer's
-- `Local.*` conditions ask it: the user SID, enabled-group membership
-- with deny-only groups invisible, the integrity level, the confinement
-- SID and its capabilities, the per-service SID found among the
-- enabled groups, and the process GUID as text — answered from the
-- token the flow holds, live, without copying a group list that may run
-- to a thousand SIDs. Names in rules are SIDs by the time the kernel
-- sees them: a service by the derivation peinit uses, a well-known
-- principal by pnp-core's table. And `Local.*` has no meaning in the
-- per-packet layers.
--
-- Each case stamps one socket with the principal it is about and asks
-- one question per policy generation: a new generation re-judges the
-- flow on its next packet, against the identity recorded at its first
-- judgment.
--
-- Own VM: the policy is machine-wide state.

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")
local token = require("helpers.token")
local id = require("helpers.ntfe_identity")

local vm = provium:vm("vntfeidq", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))
local peer, net = ntfe.peer(vm)

local w = vm:spawn_worker()
id.set_comm(w, "pit-principal")
local W_PID = id.pid(w)

local E = ntfe.engine(vm, id.policy())

-- Per-service SIDs computed on the host from the documented rule (SHA-1
-- of the uppercased name in UTF-16LE, five little-endian 32-bit
-- sub-authorities under S-1-5-80), not read out of the guest.
local RESOLVD_SID = "S-1-5-80-3864064249-1823296737-2008945602-1354971773-2894779966"
local MADE_UP = "pit-made-up-service"
local MADE_UP_SID = "S-1-5-80-3095137330-2605304957-776117086-986963462-3218873278"

local LOCAL_SERVICE = token.sid(5, 19)

--- A UDP socket of w's connected to a peer port that takes datagrams,
--- stamped by `spec`. Returns the socket, the peer's sink and the port.
local next_port = 7400
local function socket_of(spec)
    next_port = next_port + 1
    local port = next_port
    local sink = assert(ntfe.udp_bind(peer, net.peer_addr, port))
    local fd
    id.as(w, spec, function() fd = assert(ntfe.udp_connect(w, net.peer_addr, port)) end)
    return { fd = fd, sink = sink, port = port }
end

local function close(s)
    sys.close(w, s.fd); sys.close(peer, s.sink)
end

--- Publish a policy whose one exception is `name` = `cond`, send one
--- datagram on `s`, and return the Flow event that judged it.
local function ask(t, s, name, cond)
    cond.Actions = { "PASS" }
    local status = E:replace(id.policy({ [name] = cond }))
    t:assert_eq(status.last_ingest_error, 0, name .. " is a policy the engine accepts")
    local _, events = E:during(function() ntfe.send(w, s.fd, name) end)
    local got = id.flow_events(events, { dst_port = s.port })
    t:assert_eq(#got, 1, name .. ": the flow is judged once more: " .. ntfe.describe(events))
    return got[1] or { ["local"] = {} }
end

--- Whether the exception `name` decided the judgment `ask` made.
local function holds(t, s, name, cond)
    return ask(t, s, name, cond).attributed == "all/" .. name
end

-- ---- the view the judgment reads -------------------------------------

test("a judgment sees the end's kind, its process facts and, through the token, its principal",
    { spec = "PKM *ntfe-identity.flow-view-carries-borrowed-token" }, function(t)
        local guid = id.process_guid(t, vm, w)
        local s = socket_of({ user_sid = token.SID.TEST_USER })
        local e = ask(t, s, "x-user", { ["Local.User.Equal"] = token.sid_string(token.SID.TEST_USER) })
        close(s)
        t:assert_eq(e.attributed, "all/x-user", "Local.User was answered from the end's token")
        local l = e["local"]
        t:assert_eq(l.kind, ntfe.LOCAL.PROGRAM, "the same judgment carries the end's kind")
        t:assert_eq(l.pid, W_PID, "its pid")
        t:assert_eq(l.comm, "pit-principal", "its comm")
        t:assert_eq(l.guid, guid, "and its process GUID")
    end)

test("group questions see enabled groups only: deny-only and disabled groups are invisible",
    { spec = "PKM *ntfe-identity.deny-only-groups-invisible" }, function(t)
        -- TEST_GROUP_2 is made deny-only the way a restricted token is
        -- made (FilterToken), on a principal of its own.
        local G3 = token.sid(5, 21, 1000, 2000, 3000, 5003)
        local x = vm:spawn_worker()
        local ok, err = pcall(function()
            local src = assert(token.mint(x, { user_sid = token.SID.TEST_USER, groups = {
                { sid = token.SID.EVERYONE, attributes = id.ENABLED },
                { sid = token.SID.TEST_GROUP, attributes = id.ENABLED },
                { sid = token.SID.TEST_GROUP_2, attributes = id.ENABLED },
                { sid = G3, attributes = 0 },
            } }))
            local filtered = assert(token.restrict(x, src, { deny_indices = { 2 } }))
            local groups = assert(token.groups(x, filtered))
            local deny = token.find_group(groups, token.SID.TEST_GROUP_2)
            t:assert(deny and deny.attributes & token.GROUP.USE_FOR_DENY_ONLY ~= 0,
                string.format("TEST_GROUP_2 is deny-only in the token (attributes %#x)",
                    deny and deny.attributes or 0))
            -- FilterToken leaves SE_GROUP_ENABLED set, so nothing but the
            -- deny-only bit can keep the group from policy.
            t:assert(deny and deny.attributes & token.GROUP.ENABLED ~= 0,
                "and still marked enabled beside it")
            t:assert_eq(token.install(x, filtered).ret, 0, "and the token is installed")
            sys.close(x, src); sys.close(x, filtered)

            local port = 7490
            local sink = assert(ntfe.udp_bind(peer, net.peer_addr, port))
            local fd = assert(ntfe.udp_connect(x, net.peer_addr, port))
            local s = { fd = fd, port = port }
            local function q(name, sid)
                local cond = { ["Local.Group.Equal"] = token.sid_string(sid), Actions = { "PASS" } }
                E:replace(id.policy({ [name] = cond }))
                local _, events = E:during(function() ntfe.send(x, fd, name) end)
                local got = id.flow_events(events, { dst_port = port })
                t:assert_eq(#got, 1, name .. " is asked: " .. ntfe.describe(events))
                return got[1] and got[1].attributed == "all/" .. name
            end
            t:assert(q("enabled", token.SID.TEST_GROUP), "an enabled group is a member")
            t:assert(not q("deny-only", token.SID.TEST_GROUP_2), "a deny-only group is not, to policy")
            t:assert(not q("disabled", G3), "nor is a disabled one")
            sys.close(x, s.fd); sys.close(peer, sink)
        end)
        x:kill(); x:join()
        if not ok then error(err, 0) end
    end)

test("every Principal question is answered from a thousand-group token in the judgment",
    { spec = "PKM *ntfe-identity.principal-view-without-copying-groups" }, function(t)
        local groups = {}
        for i = 1, 1000 do
            groups[i] = { sid = token.sid(5, 21, 77, 88, 99, 10000 + i), attributes = id.ENABLED }
        end
        local s = socket_of({
            user_sid = token.SID.TEST_USER, groups = groups,
            integrity_level = token.INTEGRITY.LOW,
            confinement_sid = token.sid(15, 2, 1),
            confinement_capabilities = { { sid = token.sid(15, 3, 1), attributes = token.GROUP.ENABLED } },
        })
        local ok, err = pcall(function()
            for _, c in ipairs({
                { "user", { ["Local.User.Equal"] = token.sid_string(token.SID.TEST_USER) }, true },
                { "first-group", { ["Local.Group.Equal"] = "S-1-5-21-77-88-99-10001" }, true },
                { "last-group", { ["Local.Group.Equal"] = "S-1-5-21-77-88-99-11000" }, true },
                { "not-a-member", { ["Local.Group.Equal"] = "S-1-5-21-77-88-99-11001" }, false },
                { "integrity", { ["Local.Integrity.Equal"] = token.INTEGRITY.LOW }, true },
                { "below-medium", { ["Local.Integrity.LessThan"] = "medium" }, true },
                { "confinement", { ["Local.Confinement.Equal"] = "S-1-15-2-1" }, true },
                { "capability", { ["Local.Capability.Equal"] = "S-1-15-3-1" }, true },
                { "other-capability", { ["Local.Capability.Equal"] = "S-1-15-3-2" }, false },
                { "no-service", { ["Local.Service.Present"] = 0 }, true },
            }) do
                t:assert_eq(holds(t, s, c[1], c[2]), c[3],
                    c[1] .. (c[3] and " holds" or " does not hold") .. " for the token")
            end
        end)
        close(s)
        if not ok then error(err, 0) end
    end)

test("Local.Process names the process by its GUID in the canonical text",
    { spec = "PKM *ntfe-identity.principal-view-without-copying-groups",
      tags = { "known-bug" },
      -- PEI-1309. The bridge's guid_text()
      -- (kacs/ntfe_runtime.rs) hex-encodes the 16 bytes in storage
      -- order, so Data1, Data2 and Data3 come out byte-reversed against
      -- PCDS §2 (String Format), which writes them as numbers. A rule
      -- naming a process by its PCDS text never matches; the storage-
      -- order text does (asserted below as the evidence). pnpd's own
      -- guid_text (pnp/pnpd/src/sid.rs, guid_text_is_hyphenated_lowercase)
      -- uses the same storage order, so kernel and viewer agree with
      -- each other and both disagree with PCDS: a conflict for the
      -- coordinator to settle, not an obvious TRM slip.
    }, function(t)
        local guid = id.process_guid(t, vm, w)
        local s = socket_of({ user_sid = token.SID.TEST_USER })
        local storage = holds(t, s, "storage-order", { ["Local.Process.Equal"] = id.guid_storage_order(guid) })
        local canonical = holds(t, s, "pcds-text", { ["Local.Process.Equal"] = id.guid_pcds(guid) })
        local upper = holds(t, s, "pcds-text-upper", { ["Local.Process.Equal"] = id.guid_pcds(guid):upper() })
        close(s)
        t:log("storage-order text " .. id.guid_storage_order(guid) .. " matched: " .. tostring(storage))        t:assert(canonical, "the GUID's PCDS text " .. id.guid_pcds(guid) .. " names the process")
        t:assert(upper, "in either case")
    end)

test("a group's attributes are read live from the token: disabling a group shows at the next judgment",
    { spec = "PKM *ntfe-identity.principal-view-lock-free" }, function(t)
        local x = id.principal(t, vm, { user_sid = token.SID.TEST_USER, groups = {
            { sid = token.SID.EVERYONE, attributes = id.ENABLED },
            { sid = token.SID.TEST_GROUP, attributes = token.GROUP.ENABLED_BY_DEFAULT | token.GROUP.ENABLED },
        } })
        local ok, err = pcall(function()
            local own = assert(token.open_self(x, token.RIGHT.QUERY | token.RIGHT.ADJUST_GROUPS))
            local _, index = token.find_group(assert(token.groups(x, own)), token.SID.TEST_GROUP)
            t:assert(index, "the token carries TEST_GROUP")
            local port = 7491
            local sink = assert(ntfe.udp_bind(peer, net.peer_addr, port))
            local fd = assert(ntfe.udp_connect(x, net.peer_addr, port))
            local function member(label)
                local cond = { ["Local.Group.Equal"] = token.sid_string(token.SID.TEST_GROUP), Actions = { "PASS" } }
                E:replace(id.policy({ [label] = cond }))
                local _, events = E:during(function() ntfe.send(x, fd, label) end)
                local got = id.flow_events(events, { dst_port = port })
                t:assert_eq(#got, 1, label .. " is asked: " .. ntfe.describe(events))
                return got[1] and got[1].attributed == "all/" .. label
            end
            t:assert(member("enabled-at-stamp"), "the group counts while enabled")
            t:assert_eq(token.adjust_groups(x, own, { { index - 1, 0 } }).ret, 0, "the program disables it")
            t:assert(not member("disabled-since"), "the same flow's next judgment no longer counts it")
            t:assert_eq(token.adjust_groups(x, own, { { index - 1, 1 } }).ret, 0, "and enables it again")
            t:assert(member("enabled-again"), "which the judgment after sees")
            sys.close(x, fd); sys.close(x, own); sys.close(peer, sink)
        end)
        x:kill(); x:join()
        if not ok then error(err, 0) end
    end)

-- ---- names are SIDs by ingestion -------------------------------------

test("Local.Service names a service, turned into its SID at ingestion by peinit's derivation",
    { spec = "PKM *ntfe-identity.service-name-to-sid-at-ingestion" }, function(t)
        local s = socket_of({ user_sid = LOCAL_SERVICE, groups = {
            { sid = token.SID.EVERYONE, attributes = id.ENABLED },
            { sid = id.sid(RESOLVD_SID), attributes = id.ENABLED },
        } })
        local ok, err = pcall(function()
            local e = ask(t, s, "by-name", { ["Local.Service.Equal"] = "resolvd" })
            t:assert_eq(e.attributed, "all/by-name", "the name matches the token's service SID")
            t:assert_eq(e["local"].service, id.sid(RESOLVD_SID),
                "which is the SID the event reports: " .. id.sid_text(e["local"].service))
            t:assert(holds(t, s, "by-upper-name", { ["Local.Service.Equal"] = "RESOLVD" }),
                "the derivation uppercases, so the name's case does not matter")
            t:assert(holds(t, s, "by-sid", { ["Local.Service.Equal"] = RESOLVD_SID }),
                "the SID itself is the same pattern")
            t:assert(not holds(t, s, "other-service", { ["Local.Service.Equal"] = "netd" }),
                "another service's name is another SID")
        end)
        close(s)
        if not ok then error(err, 0) end
    end)

test("the kernel knows nothing of what a SID means: a service nothing defines still matches its derived SID",
    { spec = "PKM *ntfe-identity.no-sid-meaning-in-kernel" }, function(t)
        -- This hive holds no service definitions at all, so nothing the
        -- kernel could consult says what MADE_UP is; the rule's name is
        -- a SID by derivation alone, and the event carries the SID, not
        -- a name.
        t:assert_eq(E.src:lookup("Machine\\System\\Services"), nil, "no service is defined anywhere")
        local s = socket_of({ user_sid = token.SID.TEST_USER, groups = {
            { sid = token.SID.EVERYONE, attributes = id.ENABLED },
            { sid = id.sid(MADE_UP_SID), attributes = id.ENABLED },
        } })
        local e = ask(t, s, "made-up", { ["Local.Service.Equal"] = MADE_UP })
        close(s)
        t:assert_eq(e.attributed, "all/made-up", "the undefined service's name matches its derived SID")
        t:assert_eq(e["local"].service, id.sid(MADE_UP_SID), "and the event reports the SID")
    end)

test("well-known principal names resolve by a table, in any case",
    { spec = "PKM *ntfe-identity.well-known-user-names-by-table" }, function(t)
        local s = socket_of({ user_sid = LOCAL_SERVICE })
        local ok, err = pcall(function()
            for _, c in ipairs({
                { "LocalService", { ["Local.User.Equal"] = "LocalService" }, true },
                { "lowercase", { ["Local.User.Equal"] = "localservice" }, true },
                { "as-sid", { ["Local.User.Equal"] = "S-1-5-19" }, true },
                { "NetworkService", { ["Local.User.Equal"] = "NetworkService" }, false },
                { "SYSTEM", { ["Local.User.Equal"] = "SYSTEM" }, false },
                { "Everyone", { ["Local.Group.Equal"] = "Everyone" }, true },
                { "Administrators", { ["Local.Group.Equal"] = "Administrators" }, false },
            }) do
                t:assert_eq(holds(t, s, c[1], c[2]), c[3],
                    c[1] .. (c[3] and " names" or " does not name") .. " a LocalService token")
            end
        end)
        close(s)
        if not ok then error(err, 0) end
        local before = E:status().generation
        local refused = E:replace(id.policy({
            root = { ["Local.User.Equal"] = "root", Actions = { "PASS" } },
        }))
        t:assert(refused.last_ingest_error ~= 0, "a name outside the table is refused, not guessed")
        t:assert_eq(refused.generation, before, "and the generation stands")
    end)

test("the viewer resolves service SIDs back to names from the registry's service definitions",
    { spec = "PKM *ntfe-identity.viewer-resolves-sids-from-registry",
      covered_by = "build:pnp/pnpd/src/sid.rs",
      skip = "the viewer is pnpd, a userspace daemon absent from the " ..
             "kernel-only profile; the kernel emits SIDs and never names " ..
             "(asserted above). Its reverse resolution over " ..
             "Machine\\System\\Services lives in pnp/pnpd/src/sid.rs " ..
             "(service_name), whose own tests cover the derivation only" },
    function(t) end)

-- ---- not in the per-packet layers ------------------------------------

test("Local.* in a Packet rule is accepted and never present",
    { spec = "PKM *ntfe-identity.local-in-packet-rule-linted-never-present" }, function(t)
        -- The lint itself is pnp-core's authoring-time diagnostic (the
        -- in-kernel ingestion drops lints, kacs/ntfe_runtime.rs); what
        -- the kernel shows is its meaning: the rule is no refusal, and
        -- it never matches.
        local before = E:status().generation
        local s = E:replace({
            RawPacket = id.PASS_ALL,
            Packet = {
                all = { Actions = { "PASS" } },
                ["by-user"] = { ["Local.User.Equal"] = "SYSTEM", Actions = { "DROP" } },
                ["by-kind"] = { ["Local.Equal"] = "program", Actions = { "DROP" } },
            },
            Flow = id.PASS_ALL,
        })
        t:assert_eq(s.last_ingest_error, 0, "the generation is accepted")
        t:assert_eq(s.generation, before + 1, "and published")
        local l = assert(ntfe.tcp_listen(w, "127.0.0.1", 7495))
        local _, events = E:during(function()
            local fd, why = ntfe.tcp_connect(vm, "127.0.0.1", 7495)
            t:assert(fd, "SYSTEM's own connection is not dropped: " .. tostring(why))
            if fd then sys.close(vm, fd) end
        end)
        sys.close(w, l)
        for _, e in ipairs(events) do
            t:assert(e.attributed ~= "by-user" and e.attributed ~= "by-kind",
                "no Packet judgment found an identity to match: " .. ntfe.describe({ e }))
        end
        E:replace(id.policy())
    end)

test("Present over Local.* in a Packet rule refuses the generation",
    { spec = "PKM *ntfe-identity.present-local-in-packet-rule-refuses-generation" }, function(t)
        E:replace(id.policy())
        for _, c in ipairs({
            { "Local.Present", 0 }, { "Local.User.Present", 1 }, { "Remote.Present", 0 },
        }) do
            local before = E:status().generation
            local s = E:replace({
                RawPacket = id.PASS_ALL,
                Packet = { all = { Actions = { "PASS" } },
                           probe = { [c[1]] = c[2], Actions = { "DROP" } } },
                Flow = id.PASS_ALL,
            })
            t:assert(s.last_ingest_error ~= 0, c[1] .. " = " .. c[2] .. " in a Packet rule is refused")
            t:assert_eq(s.generation, before, "and the previous generation stands")
        end
    end)
