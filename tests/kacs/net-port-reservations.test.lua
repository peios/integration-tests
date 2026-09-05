-- PKM §3.12.1 — port reservations: binding a non-zero TCP or UDP port
-- is an access check against a security descriptor selected by
-- (protocol, port), read from one registry key, loaded whole and
-- rejected whole, with a compiled-in SYSTEM-only table answering until
-- the first successful load.
--
-- Three VMs, because the table is global state and its history matters:
--
--   vport    a rich table, seeded before the source registers, plus the
--            live edits and finally the rejected loads (once a bad
--            value is in the key every later load is rejected too, so
--            those cases come last).
--   vportfb  no table at first — the compiled-in fallback — then one
--            load that does not grant SYSTEM, which is what tells
--            replacement from a merge.
--   vportseed the shipped seed from pkm/regim/port-reservations.reg,
--            byte for byte.
--
-- helpers/registry serves the Machine hive from Lua, so anything that
-- bounces through the source runs as a worker async under
-- `Source:pump_during`.

local sys = require("helpers.sys")
local token = require("helpers.token")
local kacs = require("helpers.kacs")
local access = require("helpers.access")
local registry = require("helpers.registry")
local hooks = require("helpers.hooks")
local kmes = require("helpers.kmes")
local netobj = require("helpers.netobj")

local vm = provium:vm("vport", "kernel-only"):boot()

local PORT_BIND = netobj.PORT_BIND
local STD = access.STD
local TCB = token.bit(token.PRIV.TCB)
-- SeBindPrivilegedPortPrivilege was bit 63 before this object existed.
local RETIRED_PORT_PRIVILEGE = 1 << 63

local EVERYONE, SYSTEM = token.SID.EVERYONE, token.SID.LOCAL_SYSTEM
local USER1, USER2 = token.SID.TEST_USER, token.SID.TEST_USER_2

--- A SACL auditing both outcomes, so a port decision reaches KMES.
local AUDIT_SACL = access.acl({
    access.ace(access.ACE.AUDIT, PORT_BIND, EVERYONE,
        access.ACE_FLAG.SUCCESSFUL_ACCESS | access.ACE_FLAG.FAILED_ACCESS),
})

-- The table every case below is judged on. Widths: `tcp:80` and
-- `udp:53` cover one port each, `tcp,udp:1-1023` covers 1023, so the
-- nested overlap is unambiguous and the narrow entry wins.
local SEED = {
    { "@",              netobj.port_sd({ EVERYONE }) },
    { "tcp:80",         netobj.port_sd({ USER1 }, PORT_BIND, AUDIT_SACL) },
    { "tcp,udp:1-1023", netobj.port_sd({ SYSTEM }) },
    { "udp:53",         netobj.port_sd({ USER2 }) },
    { "*:8080",         netobj.port_sd({ USER2 }) },
    { "tcp:7001",       netobj.port_sd({ USER1 }, STD.GENERIC_EXECUTE) },
    { "tcp:7002",       netobj.port_sd({ USER1 }, STD.GENERIC_READ) },
    { "tcp:7003",       netobj.port_sd({ USER1 }, STD.GENERIC_WRITE) },
    { "tcp:7004",       netobj.port_sd({ USER1 }, STD.GENERIC_ALL) },
    { "tcp:7005",       netobj.port_sd({}) },
}

local src = registry.Source.new(vm)
netobj.seed_port_table(src, SEED)
assert(src:register())
src:pump()

--- The registry writer, for the live-edit cases.
local writer = vm:spawn_worker()
local PORT_KEY = (function()
    local o = src:pump_during(function()
        return registry.open_key_async(writer, netobj.PORT_KEY_ABSOLUTE)
    end)
    assert(o.ret >= 0, "open the port key: " .. sys.errname(o.errno))
    return o.ret
end)()

local function write_reservation(selector, descriptor)
    return src:pump_during(function()
        return registry.set_value_async(writer, PORT_KEY, selector,
            registry.TYPE.BINARY, descriptor)
    end)
end

--- bind(2) `port` as a principal built from `spec`; returns
--- "ret/ERRNO" so a message names what happened.
local function bind_as(spec, port, opts)
    local answer
    token.as_principal(nil, vm, spec, function(w)
        local r = netobj.bind(w, port, opts)
        answer = { ret = r.ret, errno = r.errno }
    end)
    return answer
end

--- Two principals, kept alive together so one can hold a bound socket
--- while the other tries to rebind. `fn` receives the workers.
local function with_principals(t, specs, fn)
    local workers = {}
    local ok, err = pcall(function()
        for i, spec in ipairs(specs) do
            local w = vm:spawn_worker()
            workers[i] = w
            local fd = assert(token.mint(w, spec))
            assert(token.install(w, fd).ret == 0, "install")
            sys.close(w, fd)
        end
        fn(table.unpack(workers))
    end)
    for _, w in ipairs(workers) do w:kill(); w:join() end
    if not ok then error(err, 0) end
end

-- ---- the decision ----------------------------------------------------

test("the Linux privileged-port floor never refuses first",
    { spec = "PKM *net.port.floor-never-refuses" }, function(t)
        -- Port 80 is below 1024. The principal holds no privilege at
        -- all — under Linux's own rule it could not have it — and the
        -- reservation names its user SID, so the bind succeeds.
        local r = bind_as({ user_sid = USER1 }, 80)
        t:assert_eq(r.ret, 0,
            "an unprivileged principal claims a privileged port: " .. sys.errname(r.errno))
        -- And a principal the reservation does not name is refused by
        -- KACS, not by the floor.
        local denied = bind_as({ user_sid = USER2 }, 80)
        t:assert_eq(denied.ret, -1, "another principal is refused the same port")
        t:assert_eq(denied.errno, sys.E.ACCES, "EACCES")
    end)

test("every legal selector spelling parses and takes effect",
    { spec = "PKM *net.port.selector-grammar" }, function(t)
        -- One case per shape in `<proto>[,<proto>]:<lo>[-<hi>]`.
        t:assert_eq(bind_as({ user_sid = USER1 }, 80).ret, 0,
            "`tcp:80` — a single protocol and a single port")
        t:assert_eq(bind_as({ user_sid = USER2 }, 53,
            { socktype = netobj.SOCK_DGRAM }).ret, 0,
            "`udp:53` — the other protocol")
        t:assert_eq(bind_as({ user_sid = USER2 }, 8080).ret, 0,
            "`*:8080` — both protocols by wildcard")
        t:assert_eq(bind_as({ user_sid = USER1 }, 8080).errno, sys.E.ACCES,
            "and the wildcard entry binds who it names and no one else")
        -- `tcp,udp:1-1023` — a protocol list and a range. SYSTEM is the
        -- trustee; the agent is SYSTEM.
        t:assert_eq(netobj.bind(vm, 443).ret, 0,
            "`tcp,udp:1-1023` — a protocol list over a range")
        t:assert_eq(netobj.bind(vm, 443, { socktype = netobj.SOCK_DGRAM }).ret, 0,
            "covering udp as well as tcp")
        t:assert_eq(bind_as({ user_sid = USER1 }, 443).errno, sys.E.ACCES,
            "and nobody else")
    end)

test("a reservation covers IPv4 and IPv6 alike",
    { spec = "PKM *net.port.family-agnostic" }, function(t)
        -- `tcp:80` names no address family, so the v6 side of port 80 is
        -- the same claim: dual-stack squatting would otherwise bypass it.
        t:assert_eq(bind_as({ user_sid = USER1 }, 80,
            { family = netobj.AF_INET6 }).ret, 0,
            "the trustee binds the v6 side of a reservation written once")
        local denied = bind_as({ user_sid = USER2 }, 80,
            { family = netobj.AF_INET6 })
        t:assert_eq(denied.ret, -1, "and a stranger cannot squat it over v6")
        t:assert_eq(denied.errno, sys.E.ACCES, "EACCES")
    end)

test("the generic rights map to PORT_BIND and READ_CONTROL only",
    { spec = "PKM *net.port.generic-mapping" }, function(t)
        t:assert_eq(bind_as({ user_sid = USER1 }, 7001).ret, 0,
            "GENERIC_EXECUTE maps to PORT_BIND")
        t:assert_eq(bind_as({ user_sid = USER1 }, 7004).ret, 0,
            "and GENERIC_ALL grants it too")
        local read_only = bind_as({ user_sid = USER1 }, 7002)
        t:assert_eq(read_only.ret, -1, "GENERIC_READ maps to READ_CONTROL alone")
        t:assert_eq(read_only.errno, sys.E.ACCES, "so it does not permit a bind")
        local write_only = bind_as({ user_sid = USER1 }, 7003)
        t:assert_eq(write_only.ret, -1, "and GENERIC_WRITE maps to nothing")
        t:assert_eq(write_only.errno, sys.E.ACCES, "EACCES")
    end)

test("the unnamed default value governs every port no selector contains",
    { spec = "PKM *net.port.default-reservation" }, function(t)
        -- 9999 is in no selector; `@` grants Everyone.
        for _, who in ipairs({ USER1, USER2 }) do
            t:assert_eq(bind_as({ user_sid = who }, 9999).ret, 0,
                "an unreserved port is anyone's: " .. token.sid_string(who))
        end
        t:assert_eq(bind_as({ user_sid = USER1 }, 9999,
            { socktype = netobj.SOCK_DGRAM }).ret, 0,
            "for udp as much as tcp")
    end)

test("the most specific reservation containing the port is selected",
    { spec = "PKM *net.port.most-specific-match" }, function(t)
        -- Port 80 is in `tcp:80` (one port) and `tcp,udp:1-1023` (1023
        -- ports). The narrow one wins, so TEST_USER binds and SYSTEM —
        -- which the wide one names — does not.
        t:assert_eq(bind_as({ user_sid = USER1 }, 80).ret, 0,
            "the one-port selector decides port 80")
        t:assert_eq(netobj.bind(vm, 80).errno, sys.E.ACCES,
            "SYSTEM's grant on the 1023-port selector does not reach it")
        -- Port 443 is in the wide selector only.
        t:assert_eq(netobj.bind(vm, 443).ret, 0, "which still decides port 443")
        -- Port 8080 is in `*:8080` (one port) and nothing else but the
        -- default: the selector beats the default.
        t:assert_eq(bind_as({ user_sid = USER1 }, 8080).errno, sys.E.ACCES,
            "and a one-port selector beats the default reservation")
    end)

test("binding port 0 is never checked, and a protocol no reservation covers passes untouched",
    { spec = "PKM *net.port.ephemeral-unchecked" }, function(t)
        -- `tcp:7005` grants nobody; an ephemeral bind on the same
        -- socket is not a claim and is not checked.
        t:assert_eq(bind_as({ user_sid = USER1 }, 7005).errno, sys.E.ACCES,
            "port 7005 is claimed by nobody")
        t:assert_eq(bind_as({ user_sid = USER1 }, 0).ret, 0,
            "and port 0 is allocated without a check")
        t:assert_eq(bind_as({ user_sid = USER2 }, 0,
            { socktype = netobj.SOCK_DGRAM }).ret, 0, "for udp too")
        -- A raw socket carries no reservation protocol, so the bind is
        -- untouched even at a port the table denies. CAP_NET_RAW maps to
        -- SeTcbPrivilege, which is what opens the socket, not what binds.
        token.as_principal(t, vm, { privs_present = TCB, privs_enabled = TCB },
            function(w)
                local fd, errno = netobj.socket(w, netobj.AF_INET, netobj.SOCK_RAW,
                    netobj.IPPROTO_ICMP)
                t:assert(fd, "a raw socket opens: " .. sys.errname(errno or 0))
                local r = w:syscall(netobj.NR.bind, {
                    args = { fd, 0, 16 }, bufs = { netobj.sockaddr_in(7005) }, ptrs = { 1 },
                })
                t:assert_eq(r.ret, 0,
                    "and binds at a port no principal may claim over tcp: "
                    .. sys.errname(r.errno))
                sys.close(w, fd)
            end)
    end)

test("the decision is the ordinary AccessCheck pipeline, and a port SACL reaches KMES",
    { spec = "PKM *net.port.access-check" }, function(t)
        -- `tcp:80` carries a SACL auditing success and failure.
        local events = kmes.recording(t, vm, function()
            t:assert_eq(bind_as({ user_sid = USER1 }, 80).ret, 0, "a granted claim")
            t:assert_eq(bind_as({ user_sid = USER2 }, 80).errno, sys.E.ACCES,
                "and a refused one")
        end)
        local audits = kmes.of_type(events, "access-audit")
        t:assert(#audits >= 2,
            "the port descriptor's SACL produced audit events like any other object's: "
            .. #audits)
    end)

test("a denied claim is EACCES",
    { spec = "PKM *net.port.deny-eacces" }, function(t)
        for _, port in ipairs({ 80, 443, 7005 }) do
            local r = bind_as({ user_sid = USER2 }, port)
            t:assert_eq(r.ret, -1, "port " .. port .. " is refused")
            t:assert_eq(r.errno, sys.E.ACCES,
                "with EACCES: " .. sys.errname(r.errno))
        end
    end)

-- ---- rebinding -------------------------------------------------------

test("rebinding onto a bound port is still a bind and still meets the reservation",
    { spec = "PKM *net.port.rebind-meets-reservation" }, function(t)
        with_principals(t, { { user_sid = USER1, projected_uid = 8001 },
                             { user_sid = USER2, projected_uid = 8002 } },
            function(a, b)
                local r, held = netobj.bind(a, 80,
                    { reuse = { netobj.SO_REUSEPORT }, keep = true })
                t:assert_eq(r.ret, 0, "the trustee binds port 80 with SO_REUSEPORT")
                local other = netobj.bind(b, 80, { reuse = { netobj.SO_REUSEPORT } })
                t:assert_eq(other.ret, -1, "a principal the reservation denies cannot rebind")
                t:assert_eq(other.errno, sys.E.ACCES,
                    "and is refused by the reservation, not by the address conflict")
                sys.close(a, held)
            end)
    end)

test("a rebind by the same user SID is permitted",
    { spec = "PKM *net.port.rebind-same-sid-or-tcb" }, function(t)
        -- Port 9999 is the default reservation's, which grants Everyone,
        -- so the reservation is not what decides here.
        with_principals(t, { { user_sid = USER1, projected_uid = 8101 },
                             { user_sid = USER1, projected_uid = 8101 } },
            function(a, b)
                local first, held = netobj.bind(a, 9999,
                    { reuse = { netobj.SO_REUSEPORT }, keep = true })
                t:assert_eq(first.ret, 0, "the first binder claims the port")
                local second = netobj.bind(b, 9999, { reuse = { netobj.SO_REUSEPORT } })
                t:assert_eq(second.ret, 0,
                    "and a second process of the same principal rebinds: "
                    .. sys.errname(second.errno))
                sys.close(a, held)
            end)
        -- A different user SID may not.
        with_principals(t, { { user_sid = USER1, projected_uid = 8201 },
                             { user_sid = USER2, projected_uid = 8202 } },
            function(a, b)
                local first, held = netobj.bind(a, 9998,
                    { reuse = { netobj.SO_REUSEPORT }, keep = true })
                t:assert_eq(first.ret, 0, "the first binder claims another port")
                local second = netobj.bind(b, 9998, { reuse = { netobj.SO_REUSEPORT } })
                t:assert_eq(second.ret, -1,
                    "a different principal may not rebind onto it, though the "
                    .. "reservation grants Everyone")
                sys.close(a, held)
            end)
    end)

test("a rebind by a holder of SeTcbPrivilege is permitted",
    { spec = "PKM *net.port.rebind-same-sid-or-tcb", tags = { "known-bug" } }, function(t)
        with_principals(t, { { user_sid = USER1, projected_uid = 8301 },
                             { user_sid = USER2, projected_uid = 8302,
                               privs_present = TCB, privs_enabled = TCB } },
            function(a, b)
                local first, held = netobj.bind(a, 9997,
                    { reuse = { netobj.SO_REUSEPORT }, keep = true })
                t:assert_eq(first.ret, 0, "the first binder claims the port")
                local second = netobj.bind(b, 9997, { reuse = { netobj.SO_REUSEPORT } })
                t:assert_eq(second.ret, 0,
                    "§3.12.1 says SeTcbPrivilege is the alternative to a matching "
                    .. "user SID; got " .. sys.errname(second.errno))
                sys.close(a, held)
            end)
    end)

-- ---- the table's life ------------------------------------------------

test("nested and differing-width overlap is accepted",
    { spec = "PKM *net.port.nested-overlap-accepted" }, function(t)
        -- The seeded table has `tcp:80` nested inside `tcp,udp:1-1023`
        -- and `udp:53` nested in the same wide selector. If either had
        -- been rejected the whole load would have been, and the
        -- compiled-in fallback would still be answering — under which
        -- no principal binds anything.
        t:assert_eq(bind_as({ user_sid = USER1 }, 80).ret, 0,
            "the nested tcp entry is in force")
        t:assert_eq(bind_as({ user_sid = USER2 }, 53,
            { socktype = netobj.SOCK_DGRAM }).ret, 0,
            "and the nested udp entry")
        t:assert_eq(netobj.bind(vm, 443).ret, 0, "alongside the selector they nest in")
        -- Add a third nesting level live: one port inside `tcp:1-1023`
        -- inside nothing wider.
        t:assert_eq(write_reservation("tcp:1-200",
            netobj.port_sd({ USER2 })).ret, 0, "a middle-width selector is written")
        t:assert_eq(bind_as({ user_sid = USER2 }, 100).ret, 0,
            "which decides a port only it and the wide selector contain")
        t:assert_eq(bind_as({ user_sid = USER1 }, 80).ret, 0,
            "while the narrowest still decides port 80")
    end)

test("a change to the key is live without a restart",
    { spec = "PKM *net.port.table-watched-live" }, function(t)
        -- 7100 is in no selector, so the default answers: Everyone.
        t:assert_eq(bind_as({ user_sid = USER2 }, 7100).ret, 0,
            "before the edit the default reservation admits everyone")
        t:assert_eq(write_reservation("tcp:7100", netobj.port_sd({ USER1 })).ret, 0,
            "an administrator writes a new reservation")
        t:assert_eq(bind_as({ user_sid = USER2 }, 7100).errno, sys.E.ACCES,
            "and the very next bind is judged on it")
        t:assert_eq(bind_as({ user_sid = USER1 }, 7100).ret, 0,
            "with the trustee it names admitted")
    end)

test("SeBindPrivilegedPortPrivilege is retired and its bit grants nothing",
    { spec = "PKM *net.port.privilege-retired" }, function(t)
        -- Bit 63 is what CAP_NET_BIND_SERVICE mapped to before the
        -- reservation object existed. A token carrying it is judged on
        -- the reservation like anything else.
        local held = bind_as({ user_sid = USER2,
            privs_present = RETIRED_PORT_PRIVILEGE,
            privs_enabled = RETIRED_PORT_PRIVILEGE }, 80)
        t:assert_eq(held.ret, -1, "bit 63 does not open a privileged port")
        t:assert_eq(held.errno, sys.E.ACCES, "EACCES: an ACE names a SID, not a privilege")
        local nobody = bind_as({ user_sid = USER1,
            privs_present = RETIRED_PORT_PRIVILEGE,
            privs_enabled = RETIRED_PORT_PRIVILEGE }, 7005)
        t:assert_eq(nobody.errno, sys.E.ACCES, "nor a port nobody is granted")
        -- The grant that does work is the ACE.
        t:assert_eq(bind_as({ user_sid = USER1 }, 80).ret, 0,
            "which is what the reservation's ACE is for")
    end)

test("every decision and every table load is traced",
    { spec = "PKM *net.port.tracing" }, function(t)
        assert(hooks.trace_start(vm, "kacs/kacs_socket_bind"))
        t:assert_eq(bind_as({ user_sid = USER1 }, 80).ret, 0, "a granted claim")
        t:assert_eq(bind_as({ user_sid = USER2 }, 80).errno, sys.E.ACCES, "a refused one")
        t:assert_eq(write_reservation("tcp:7200", netobj.port_sd({ USER1 })).ret, 0,
            "and a table load")
        local lines = hooks.trace_stop(vm, "kacs/kacs_socket_bind")
        t:assert(lines, "the trace buffer reads back")
        local allow, deny, table_load = nil, nil, false
        for _, line in ipairs(lines) do
            if line:match("reason=port%-bind") then
                if line:match("verdict=allow") then allow = line else deny = line end
            elseif line:match("reason=port%-table") then
                table_load = true
            end
        end
        t:assert(allow, "a permitted claim emits reason=port-bind")
        t:assert(allow:match("desired=0x1"), "`desired` carries PORT_BIND: " .. allow)
        t:assert(allow:match("max_imp=80"), "`max_imp` carries the port: " .. allow)
        t:assert(allow:match("ret=0"), "and `ret` the verdict: " .. allow)
        t:assert(deny, "a refused claim emits one too")
        t:assert(deny:match("ret=%-13"), "carrying -EACCES: " .. deny)
        t:assert(table_load, "and a table load emits reason=port-table")
    end)

-- ---- rejection -------------------------------------------------------
--
-- Everything from here leaves a value in the key that no load can
-- accept, so these cases come last: once one is written, every later
-- load is rejected and the last good table is what answers.

test("the table is rejected whole when any part of it is bad",
    { spec = "PKM *net.port.table-all-or-nothing" }, function(t)
        local function still_good(why)
            t:assert_eq(bind_as({ user_sid = USER1 }, 80).ret, 0,
                "the last good table still answers after " .. why)
        end
        -- A name that does not parse.
        for _, bad in ipairs({ "tcp:bogus", "tcp,tcp:90", "tcp:0", "tcp:080",
                               "tcp:200-100", "tcp:70000", "90" }) do
            t:assert_eq(write_reservation(bad, netobj.port_sd({ EVERYONE })).ret, 0,
                "`" .. bad .. "` is written to the registry")
            still_good("the malformed selector `" .. bad .. "`")
            t:assert_eq(bind_as({ user_sid = USER2 }, 80).errno, sys.E.ACCES,
                "and nothing about `" .. bad .. "` took effect")
        end
        -- A descriptor that does not parse.
        t:assert_eq(write_reservation("tcp:7300", "not a descriptor").ret, 0,
            "an unparseable descriptor is written")
        still_good("an unparseable descriptor")
        -- Two selectors of equal width that overlap: no most-specific
        -- match would exist, and the kernel refuses to guess.
        t:assert_eq(write_reservation("*:80", netobj.port_sd({ USER2 })).ret, 0,
            "`*:80` is written alongside `tcp:80`, same width, overlapping")
        still_good("an equal-width overlap")
        t:assert_eq(bind_as({ user_sid = USER2 }, 80).errno, sys.E.ACCES,
            "the ambiguous entry decided nothing")
    end)

test("a rejected load leaves the previous table in force and is audited",
    { spec = "PKM *net.port.rejected-load-keeps-previous" }, function(t)
        -- The key now holds several values no load can accept. Every
        -- reservation the last good table carried still answers.
        t:assert_eq(bind_as({ user_sid = USER1 }, 80).ret, 0, "`tcp:80` still answers")
        t:assert_eq(netobj.bind(vm, 443).ret, 0, "`tcp,udp:1-1023` still answers")
        t:assert_eq(bind_as({ user_sid = USER2 }, 8080).ret, 0, "`*:8080` still answers")
        t:assert_eq(bind_as({ user_sid = USER1 }, 7100).ret, 0,
            "and so does the entry written live before the rejections")
        t:assert_eq(bind_as({ user_sid = USER1 }, 9999).ret, 0,
            "with the default reservation behind them")
        -- The load is audited: the refresh emits reason=port-table.
        assert(hooks.trace_start(vm, "kacs/kacs_socket_bind"))
        write_reservation("tcp:7400", netobj.port_sd({ USER1 }))
        local lines = hooks.trace_stop(vm, "kacs/kacs_socket_bind")
        local saw = false
        for _, line in ipairs(lines or {}) do
            if line:match("reason=port%-table") then
                saw = true
                t:assert(not line:match("ret=0"),
                    "the rejected load is traced with its failure: " .. line)
            end
        end
        t:assert(saw, "a rejected load is audited")
        t:assert_eq(bind_as({ user_sid = USER1 }, 7400).ret, 0,
            "and 7400 falls to the default reservation, not the new entry")
    end)

-- ---- before the registry ---------------------------------------------

local fb = provium:vm("vportfb", "kernel-only"):boot()

test("until the first load a compiled-in table admits SYSTEM and nobody else",
    { spec = "PKM *net.port.compiled-in-fallback" }, function(t)
        -- No source has registered on this VM yet.
        t:assert_eq(netobj.bind(fb, 9000).ret, 0, "SYSTEM claims a port")
        t:assert_eq(netobj.bind(fb, 80).ret, 0, "including a privileged one")
        local answer
        token.as_principal(nil, fb, { user_sid = USER1 }, function(w)
            answer = netobj.bind(w, 9000)
        end)
        t:assert_eq(answer.ret, -1, "and nothing else may claim anything")
        t:assert_eq(answer.errno, sys.E.ACCES,
            "EACCES — stricter than the shipped seed, on purpose")
    end)

test("the fallback is replaced by the first load, never merged with it",
    { spec = "PKM *net.port.fallback-replaced-not-merged" }, function(t)
        -- A table whose default grants TEST_USER and not SYSTEM. If the
        -- fallback were merged in, SYSTEM would keep its grant.
        local src2 = registry.Source.new(fb)
        netobj.seed_port_table(src2, {
            { "@", netobj.port_sd({ USER1 }) },
        })
        t:assert(src2:register(), "a source registers with a table of its own")
        src2:pump()
        local answer
        token.as_principal(nil, fb, { user_sid = USER1 }, function(w)
            answer = netobj.bind(w, 9001)
        end)
        t:assert_eq(answer.ret, 0, "the loaded table's trustee may now claim a port")
        local system = netobj.bind(fb, 9001)
        t:assert_eq(system.ret, -1,
            "and SYSTEM may not, though the fallback granted it everything")
        t:assert_eq(system.errno, sys.E.ACCES,
            "EACCES: the fallback was replaced, not merged")
        src2:close()
    end)

-- ---- the shipped seed ------------------------------------------------

local seedvm = provium:vm("vportseed", "kernel-only"):boot()

--- The two values of pkm/regim/port-reservations.reg, byte for byte.
--- Regenerated by tools/gen-port-reservations-seed.py; copied here so
--- the claim about what the seed grants is tested against the seed.
local function unhex(s) return (s:gsub("%x%x", function(b) return string.char(tonumber(b, 16)) end)) end
local SHIPPED = {
    { "@", unhex("010004801400000020000000000000002c0000000101000000000005120000000101"
        .. "0000000000051200000002001c00010000000000140001000200010100000000000100000000") },
    { "tcp,udp:1-1023", unhex("010004801400000020000000000000002c0000000101000000000005"
        .. "12000000010100000000000512000000020050000200000000001400010002000101000000"
        .. "000005120000000000340001000200010900000000000f0300000052daa0d2347e4f5503cc"
        .. "beae01bf4bee034df44c8e305756c3b0b28862d276ae") },
}

test("the shipped seed grants Everyone the unreserved ports and reserves 1-1023",
    { spec = "PKM *net.port.shipped-seed" }, function(t)
        local src3 = registry.Source.new(seedvm)
        netobj.seed_port_table(src3, SHIPPED)
        t:assert(src3:register(), "the shipped seed registers as a table")
        src3:pump()

        -- What the descriptors say.
        local default_sd = token.parse_sd(SHIPPED[1][2])
        t:assert_eq(default_sd.dacl[1].sid, EVERYONE,
            "`@` names Everyone: " .. token.sid_string(default_sd.dacl[1].sid))
        t:assert_eq(default_sd.dacl[1].mask & PORT_BIND, PORT_BIND, "at PORT_BIND")
        local low_sd = token.parse_sd(SHIPPED[2][2])
        t:assert_eq(#low_sd.dacl, 2, "`tcp,udp:1-1023` names two trustees")
        t:assert_eq(low_sd.dacl[1].sid, SYSTEM, "SYSTEM first")
        t:assert_eq(token.parse_sid(low_sd.dacl[2].sid).authority, 15,
            "and a capability SID second (S-1-15-3-…, the bind-low-ports capability)")

        -- What they do.
        local answer
        token.as_principal(nil, seedvm, { user_sid = USER1 }, function(w)
            answer = { unreserved = netobj.bind(w, 9500), low = netobj.bind(w, 80) }
        end)
        t:assert_eq(answer.unreserved.ret, 0, "an unreserved port is anyone's")
        t:assert_eq(answer.low.ret, -1, "a low port is not")
        t:assert_eq(answer.low.errno, sys.E.ACCES, "EACCES")
        t:assert_eq(netobj.bind(seedvm, 80).ret, 0,
            "SYSTEM claims one — the Linux convention restated as policy")
        src3:close()
    end)
