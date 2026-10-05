-- netd §9.1 — the control socket and its object: the socket's path, modes
-- and descriptor, the control object's compiled default, how a written
-- `ControlSecurity` replaces it, the rights and their generic mapping,
-- the real access check against the peer's token, and the one-at-a-time
-- service that lets an idle peer hold netd's loop (PEI-1329).
--
-- Harness: the scripted gateway (helpers.gateway) and a whole Peios
-- (helpers.network). The agent is SYSTEM; every other caller is a token
-- minted in a worker (helpers.token `as_principal`), which installs it as
-- the worker's primary token, so the identity netd reads back from the
-- connection (KACS_SO_PEER_TOKEN, captured at connect) is that token.
--
-- Own VMs: the descriptor tests rewrite `Machine\System\Network
-- ControlSecurity`, which is machine-wide, and the last test stalls
-- netd's loop on purpose. Every test puts back what it wrote; the stall
-- test is last because it also holds up DHCP for several seconds.
--
-- Non-obvious: ControlSecurity is a REG_BINARY written with `reg set …
-- hex:`; netd rebuilds the object on the registry watch event, so each
-- step waits for the new behaviour rather than asserting at once. A
-- denied caller is told `access denied` in an ordinary `{ok=false}` reply,
-- which `network.call` returns rather than raises on.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local unixsock = require("helpers.unixsock")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local token = require("helpers.token")
local msgpack = require("helpers.msgpack")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
local sut = network.boot({ bridges = { lan }, gateway = gw })

local NETWORK_QUERY, NETWORK_CONTROL, NETWORK_ALL_ACCESS = 0x1, 0x2, 0x000F0003
local GENERIC_READ, GENERIC_WRITE = 0x80000000, 0x40000000
local GENERIC_EXECUTE, GENERIC_ALL = 0x20000000, 0x10000000

local G = token.GROUP
local ENABLED = G.MANDATORY | G.ENABLED_BY_DEFAULT | G.ENABLED

-- Token specs are built fresh for every mint: `as_principal` writes the
-- new LogonSession's id into the table it is given, so a reused table
-- names a session that has since gone (EINVAL).
-- An ordinary user: Everyone, Authenticated Users, a test group.
local function USER() return {} end
local function ADMIN_GROUPS()
    return {
        { sid = token.SID.EVERYONE, attributes = ENABLED },
        { sid = token.SID.AUTHENTICATED_USERS, attributes = ENABLED },
        { sid = token.SID.ADMINISTRATORS, attributes = ENABLED },
    }
end
-- The same user, also a member of Administrators.
local function ADMIN() return { groups = ADMIN_GROUPS() } end

local function hexs(s) return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end)) end

-- A request as `who` (the agent, or a worker): the decoded reply, or a
-- table whose `error` says why there was none.
local function ask(who, query, extra)
    local req = { query = query }
    for k, v in pairs(extra or {}) do req[k] = v end
    local r, err = network.call(sut, req, { who = who })
    return r or { ok = nil, error = "no reply: " .. tostring(err) }
end

local function allowed(r) return r.ok == true end
local function denied(r) return r.ok == false and r.error == "access denied" end

-- Write `Machine\System\Network ControlSecurity` (hex), or delete it (nil).
local function control_security(hex)
    if hex then
        network.reg(sut, { "set", network.KEY, "ControlSecurity", "hex:" .. hex }):assert_ok()
    else
        network.reg(sut, { "del", network.KEY, "ControlSecurity" })
    end
end

test("netd listens on /run/netd/control.sock, both it and /run/netd carrying the descriptor that lets Everyone connect, and a restart removes the stale socket first",
    { spec = "netd *control.socket-path-and-descriptor" }, function(t)
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "netd bound a lease")

        local function check_paths(when)
            local dir = assert(sys.stat(sut, "/run/netd"), "stat /run/netd")
            t:log(string.format("%s: /run/netd mode %o", when, dir.mode))
            t:assert_eq(dir.mode & 0xF000, 0x4000, when .. ": /run/netd is a directory")
            t:assert_eq(dir.mode & 0xFFF, 0x1ED, when .. ": /run/netd is 0755")
            local so = assert(sys.stat(sut, network.CONTROL), "stat the socket")
            t:log(string.format("%s: control.sock mode %o", when, so.mode))
            t:assert_eq(so.mode & 0xF000, sys.S_IFSOCK, when .. ": control.sock is a socket")
            t:assert_eq(so.mode & 0xFFF, 0x1B6, when .. ": control.sock is 0666")
            for _, p in ipairs({ "/run/netd", network.CONTROL }) do
                local bytes, e = kacs.get_sd(sut, p, kacs.SI.OWNER | kacs.SI.GROUP | kacs.SI.DACL)
                t:assert(bytes, when .. ": read the descriptor of " .. p .. ": " .. tostring(e))
                t:log(when .. ": " .. p .. " = " .. hexs(bytes))
                local sd = token.parse_sd(bytes)
                t:assert_eq(sd.owner, token.SID.LOCAL_SYSTEM, p .. ": owner SYSTEM")
                t:assert_eq(sd.group, token.SID.LOCAL_SYSTEM, p .. ": group SYSTEM")
                t:assert(sd.dacl and #sd.dacl == 2, p .. ": a DACL of two ACEs")
                t:assert_eq(sd.dacl[1].type, 0, p .. ": ACE 1 allows")
                t:assert_eq(sd.dacl[1].sid, token.SID.LOCAL_SYSTEM, p .. ": ACE 1 is SYSTEM")
                t:assert_eq(sd.dacl[1].mask, GENERIC_ALL, p .. ": SYSTEM GENERIC_ALL")
                t:assert_eq(sd.dacl[2].type, 0, p .. ": ACE 2 allows")
                t:assert_eq(sd.dacl[2].sid, token.SID.EVERYONE, p .. ": ACE 2 is Everyone")
                t:assert_eq(sd.dacl[2].mask, GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE,
                    p .. ": Everyone GENERIC_READ|WRITE|EXECUTE")
            end
        end
        check_paths("boot")

        -- Everyone may connect: an ordinary user reaches netd and is answered.
        token.as_principal(t, sut, USER(), function(w)
            local r = ask(w, "status")
            t:log("ordinary user status: ok=" .. tostring(r.ok) .. " error=" .. tostring(r.error))
            t:assert(allowed(r), "an ordinary user connects and is answered")
        end)

        -- A restart finds the previous run's socket file and removes it.
        local before = network.netd_pid(sut)
        local after = network.restart_netd(sut)
        t:log("netd " .. tostring(before) .. " -> " .. tostring(after))
        t:assert(after ~= before, "a new netd")
        local stale = false
        wait_until(function()
            stale = network.logged(sut, "netd: warn: removed a stale /run/netd/control.sock", { since = "1m ago" })
            return stale
        end, { timeout = 15, interval = 0.5, desc = "the stale-socket line" })
        t:assert(stale, "the new netd logged removing a stale /run/netd/control.sock")
        check_paths("after restart")
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }),
            "the new netd binds again")
    end)

test("the compiled default object: SYSTEM and Administrators may query and control, Everyone may only query",
    { spec = "netd *control.object-default-descriptor netd *control.access-check-on-peer-token" }, function(t)
        local s = network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 })
        t:assert(s, "netd holds a lease")
        t:assert(network.get(sut, network.KEY, "ControlSecurity") == nil, "no ControlSecurity is written")

        -- SYSTEM (the agent).
        t:assert(allowed(ask(sut, "status")), "SYSTEM: status")
        t:assert(allowed(ask(sut, "reconcile")), "SYSTEM: reconcile")

        -- Administrators.
        token.as_principal(t, sut, ADMIN(), function(w)
            local r = ask(w, "reconcile")
            t:log("admin reconcile: " .. tostring(r.ok) .. " " .. tostring(r.error))
            t:assert(allowed(r), "Administrators: reconcile")
            t:assert(allowed(ask(w, "status")), "Administrators: status")
        end)

        -- Everyone: query only.
        gw:forget()
        token.as_principal(t, sut, USER(), function(w)
            local r = ask(w, "status")
            t:assert(allowed(r) and r.interfaces ~= nil, "an ordinary user: status answers with the status")
            r = ask(w, "reconcile")
            t:log("user reconcile: " .. tostring(r.ok) .. " " .. tostring(r.error))
            t:assert(denied(r), "an ordinary user: reconcile is access denied")
            r = ask(w, "renew", { interface = "eth0" })
            t:log("user renew: " .. tostring(r.ok) .. " " .. tostring(r.error))
            t:assert(denied(r), "an ordinary user: renew is access denied")
            t:assert_eq(r.interfaces, nil, "a denial carries nothing else")
        end)
        -- "Nothing else happens": the refused renew sent no REQUEST.
        gw:serve({ timeout = 3 })
        local requests = gw:dhcp_messages(gateway.DHCP.REQUEST)
        t:log("DHCP REQUESTs after the refused renew: " .. #requests)
        t:assert_eq(#requests, 0, "the refused renew did not renew")
        local i = network.iface(network.status(sut), "eth0")
        t:assert_eq(i.lease and i.lease.state, "bound", "the lease is still simply bound")
    end)

test("the check is a real access check on the peer's token: a deny-only Administrators group and a restricted token are judged as KACS judges them",
    { spec = "netd *control.access-check-on-peer-token" }, function(t)
        -- Administrators present but deny-only: matches no allow ACE.
        token.as_principal(t, sut, { groups = {
            { sid = token.SID.EVERYONE, attributes = ENABLED },
            { sid = token.SID.AUTHENTICATED_USERS, attributes = ENABLED },
            { sid = token.SID.ADMINISTRATORS, attributes = G.USE_FOR_DENY_ONLY },
        } }, function(w)
            local r = ask(w, "reconcile")
            t:log("deny-only admin reconcile: " .. tostring(r.ok) .. " " .. tostring(r.error))
            t:assert(denied(r), "deny-only Administrators: reconcile denied")
            t:assert(allowed(ask(w, "status")), "deny-only Administrators: status still allowed (Everyone)")
        end)

        -- Administrators enabled, but restricted to Everyone: the
        -- restricted pass grants only what Everyone has.
        token.as_principal(t, sut, {
            groups = ADMIN_GROUPS(),
            restricted_sids = { { sid = token.SID.EVERYONE, attributes = 0 } },
        }, function(w)
            local r = ask(w, "reconcile")
            t:log("restricted admin reconcile: " .. tostring(r.ok) .. " " .. tostring(r.error))
            t:assert(denied(r), "a restricted token: reconcile denied")
            r = ask(w, "status")
            t:assert(allowed(r), "a restricted token: status allowed")
        end)
    end)

test("ControlSecurity replaces the object at the next connection; each right and each generic right maps as tabled; an invalid one falls back to the default",
    { spec = "netd *control.object-follows-control-security netd *control.rights-and-mapping netd *control.object-default-descriptor" }, function(t)
        -- Each step: a SYSTEM-only descriptor granting `mask`, and whether
        -- SYSTEM may then query (status) and control (reconcile).
        local steps = {
            { "NETWORK_QUERY", NETWORK_QUERY, true, false },
            { "NETWORK_CONTROL", NETWORK_CONTROL, false, true },
            { "GENERIC_READ", GENERIC_READ, true, false },
            { "GENERIC_WRITE", GENERIC_WRITE, false, true },
            { "GENERIC_EXECUTE", GENERIC_EXECUTE, true, false },
            { "GENERIC_ALL", GENERIC_ALL, true, true },
            { "READ_CONTROL only", 0x00020000, false, false },
            { "NETWORK_QUERY|NETWORK_CONTROL only", NETWORK_QUERY | NETWORK_CONTROL, true, true },
            { "NETWORK_QUERY again", NETWORK_QUERY, true, false },
            { "NETWORK_ALL_ACCESS", NETWORK_ALL_ACCESS, true, true },
        }
        -- Consecutive steps expect different outcomes, so each wait can
        -- only be met by the descriptor just written.
        local ok, err = pcall(function()
            for _, step in ipairs(steps) do
                local name, mask, q, c = step[1], step[2], step[3], step[4]
                control_security(peinit.system_descriptor_hex(mask))
                local sq, sc
                local reached = pcall(wait_until, function()
                    sq = allowed(ask(sut, "status"))
                    sc = allowed(ask(sut, "reconcile"))
                    return sq == q and sc == c
                end, { timeout = 10, interval = 0.3, desc = name })
                t:log(string.format("%s (0x%08x): status %s, reconcile %s", name, mask,
                    sq and "allowed" or "denied", sc and "allowed" or "denied"))
                t:assert(reached, name .. ": SYSTEM may query=" .. tostring(q) .. ", control=" .. tostring(c))
                -- Whatever the outcome, a denial is the plain reply.
                if not q then t:assert(denied(ask(sut, "status")), name .. ": status answered access denied") end
                if not c then t:assert(denied(ask(sut, "reconcile")), name .. ": reconcile answered access denied") end
                if name == "NETWORK_CONTROL" then
                    t:assert(denied(ask(sut, "subscribe")), "subscribe needs the query right")
                end
            end

            -- Not a descriptor: logged, and the compiled default stands.
            control_security(peinit.system_descriptor_hex(NETWORK_QUERY))
            wait_until(function() return denied(ask(sut, "reconcile")) end,
                { timeout = 10, interval = 0.3, desc = "query-only in force" })
            control_security("0102030405")
            local back = pcall(wait_until, function() return allowed(ask(sut, "reconcile")) end,
                { timeout = 10, interval = 0.3, desc = "the default again" })
            t:assert(back, "an invalid ControlSecurity: SYSTEM may control again (the default)")
            t:assert(network.logged(sut, "ControlSecurity is not a valid descriptor (", { since = "1m ago" }),
                "the invalid descriptor is logged")
            local line
            for _, l in ipairs(network.logs(sut, { since = "1m ago" })) do
                if l:find("ControlSecurity is not a valid descriptor", 1, true) then line = l; break end
            end
            t:log("log: " .. tostring(line))
            t:assert(line and line:find("); using the default", 1, true) ~= nil, "… ; using the default")
            token.as_principal(t, sut, USER(), function(w)
                t:assert(allowed(ask(w, "status")), "default in force: Everyone may query")
                t:assert(denied(ask(w, "reconcile")), "default in force: Everyone may not control")
            end)
        end)
        control_security(nil)
        wait_until(function() return allowed(ask(sut, "status")) and allowed(ask(sut, "reconcile")) end,
            { timeout = 10, interval = 0.3, desc = "ControlSecurity removed" })
        if not ok then error(err, 0) end
    end)

-- Guest CLOCK_MONOTONIC, in seconds.
local function mono()
    local r = sut:syscall(228, { args = { 1, 0 }, bufs = { string.rep("\0", 16) }, ptrs = { 1 } })
    assert(r.ret == 0, "clock_gettime")
    local s, ns = string.unpack("<i8i8", r.out_bufs[1])
    return s + ns / 1e9
end

-- PEI-1329: this is the documented current behaviour (one connection at a
-- time, 2 s timeouts, an idle peer holds the loop). The test passes on it.
test("connections are served one after another with a 2 s read timeout, so idle peers hold netd's loop 2 s each (PEI-1329)",
    { spec = "netd *control.serial-and-blocking" }, function(t)
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "netd bound")
        -- Baseline: an answer with nobody in the way is quick.
        local t0 = mono()
        t:assert(allowed(ask(sut, "status")), "status answers")
        local quick = mono() - t0
        t:log(string.format("unobstructed status: %.3f s", quick))
        t:assert(quick < 1.0, "an unobstructed request is answered well inside a second")

        for _, n in ipairs({ 1, 3 }) do
            local idle = {}
            local start = mono()
            for k = 1, n do
                local fd = assert(unixsock.socket(sut, unixsock.AF_UNIX, unixsock.SOCK.STREAM))
                local c = unixsock.connect(sut, fd, network.CONTROL)
                t:assert_eq(c.ret, 0, "idle peer " .. k .. " connects")
                idle[k] = fd
            end
            local r, err = network.call(sut, { query = "status" }, { timeout_ms = 20000 })
            local took = mono() - start
            t:log(string.format("%d idle peer(s): status answered after %.2f s (%s)", n, took,
                tostring(r and r.ok or err)))
            t:assert(r and r.ok, "status is answered in the end")
            t:assert(took >= 2 * n - 0.3, string.format("%d idle peer(s) held netd ~%d s (took %.2f)", n, 2 * n, took))
            t:assert(took < 2 * n + 3, string.format("and not much longer (took %.2f)", took))
            -- Each idle peer was timed out and told so, then closed.
            for k, fd in ipairs(idle) do
                local head = ntfe.recv(sut, fd, 1000, 4)
                local body = head and #head == 4 and ntfe.recv(sut, fd, 1000, string.unpack("<I4", head))
                local reply = body and msgpack.decode(body)
                t:log(string.format("idle peer %d got: ok=%s error=%s", k, tostring(reply and reply.ok),
                    tostring(reply and reply.error)))
                t:assert(reply and reply.ok == false, "idle peer " .. k .. " got an error reply")
                sys.close(sut, fd)
            end
        end
    end)
