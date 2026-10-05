-- resolvd §5.2 and PSPU §6.4 (the control object) — the access check
-- every native request passes: the peer's token, the right each request
-- names, the generic mapping, the compiled default descriptor and the
-- `ControlSecurity` that replaces it, a peer whose token cannot be opened
-- or checked, decoding before the check, a descriptor that changes while
-- a request is being answered, and the stub door the object does not
-- govern.
--
-- Harness: the scripted gateway (helpers.gateway) with its DNS server
-- (helpers.dns), and a whole Peios (helpers.network). The agent is
-- SYSTEM; every other caller is a token minted in a worker
-- (helpers.token `as_principal`), installed as the worker's primary
-- token, so the identity resolvd reads back from the connection
-- (KACS_SO_PEER_TOKEN, captured at connect) is that token. Synthetic
-- names (`localhost`, `127.0.0.1`) let `resolve`, `lookup` and `reverse`
-- be asked without the gateway; a name the gateway answers is used where
-- the network matters.
--
-- Own VMs: the tests rewrite `Machine\System\Network\Dns
-- ControlSecurity`, which is machine-wide; each removes it again.
--
-- Non-obvious:
-- * ControlSecurity is a REG_BINARY written with `reg set … hex:`;
--   resolvd rebuilds the object on the registry watch event, so each
--   step waits for the new behaviour rather than asserting at once.
-- * A check that cannot be completed: a client that sets
--   KACS_SO_IMPERSONATION_LEVEL to Identification before connecting is
--   captured at that level, and KACS bars an Identification-level token
--   from AccessCheck (PKM §3.5.1), so resolvd's check returns an error.
-- * A peer token that cannot be opened: the agent lowers resolvd's
--   RLIMIT_NOFILE (prlimit64) so that exactly one descriptor slot is
--   free. The accepted connection takes it, and opening the peer token
--   then fails with EMFILE. resolvd is stopped (SIGSTOP) while the limit
--   is set and the connection made, so nothing else takes the slot.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local dns = require("helpers.dns")
local unixsock = require("helpers.unixsock")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")
local token = require("helpers.token")
local msgpack = require("helpers.msgpack")

peinit.claim(2)

local SOCK = "/run/resolvd/resolv.sock"
local DNS_KEY = [[Machine\System\Network\Dns]]
local NR_KILL, SIGSTOP, SIGCONT = 62, 19, 18
local NR_PRLIMIT64, RLIMIT_NOFILE = 302, 7

local RESOLVER_QUERY, RESOLVER_CONTROL, RESOLVER_ALL_ACCESS = 0x1, 0x2, 0x000F0003
local READ_CONTROL = 0x00020000
local GENERIC_READ, GENERIC_WRITE = 0x80000000, 0x40000000
local GENERIC_EXECUTE, GENERIC_ALL = 0x20000000, 0x10000000

local hold = {}   -- names the gateway leaves unanswered while listed

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
dns.serve(gw, {
    zone = {
        ["www.example.test"] = { { type = "A", ttl = 60, data = "10.77.0.80" } },
        ["held.example.test"] = { { type = "A", ttl = 60, data = "10.77.0.83" } },
    },
    soa = { name = "example.test", data = { minimum = 30 } },
    on = function(q)
        local qn = q.questions[1] and q.questions[1].name or ""
        for name in pairs(hold) do
            if dns.same_name(qn, name) then return false end
        end
        return nil
    end,
})
local sut = network.boot({ bridges = { lan }, gateway = gw })

-- ---------------------------------------------------------------------------
-- Local helpers
-- ---------------------------------------------------------------------------

local G = token.GROUP
local ENABLED = G.MANDATORY | G.ENABLED_BY_DEFAULT | G.ENABLED

-- Token specs are built fresh for every mint (as_principal writes the
-- session it creates into the table).
local function USER() return {} end
local function ADMIN_GROUPS()
    return {
        { sid = token.SID.EVERYONE, attributes = ENABLED },
        { sid = token.SID.AUTHENTICATED_USERS, attributes = ENABLED },
        { sid = token.SID.ADMINISTRATORS, attributes = ENABLED },
    }
end
local function ADMIN() return { groups = ADMIN_GROUPS() } end

local function frame(payload) return string.pack("<I4", #payload) .. payload end
local function request(tbl) return frame(msgpack.encode(tbl)) end

local function read_exact(who, fd, n, timeout_ms)
    local got, have = {}, 0
    while have < n do
        local chunk, err = ntfe.recv(who, fd, timeout_ms or 5000, n - have)
        if not chunk then return nil, tostring(err) end
        if #chunk == 0 then return nil, "closed" end
        got[#got + 1] = chunk
        have = have + #chunk
    end
    return table.concat(got)
end

local function read_reply(who, fd, timeout_ms)
    local out = {}
    local head, err = read_exact(who, fd, 4, timeout_ms)
    if head then
        out.len = string.unpack("<I4", head)
        out.body, err = read_exact(who, fd, out.len, timeout_ms)
        if out.body then out.reply = msgpack.decode(out.body) end
    end
    out.err = err
    return out
end

--- Connect as `who` (optionally at impersonation level `o.level`).
local function open(who, o)
    o = o or {}
    local fd = assert(unixsock.socket(who, unixsock.AF_UNIX, unixsock.SOCK.STREAM))
    if o.level then
        local r = unixsock.set_level(who, fd, o.level)
        assert(r.ret == 0, "KACS_SO_IMPERSONATION_LEVEL: " .. sys.errname(r.errno or 0))
    end
    local c = unixsock.connect(who, fd, SOCK)
    assert(c.ret == 0, "connect: " .. unixsock.errname(c.errno))
    return fd
end

--- One request as `who`: the reply table (never nil: `error` says why
--- there was none), with `eof` (the connection closed after it) and
--- `body`.
local function ask(who, req, o)
    o = o or {}
    local fd = open(who, o)
    local bytes = type(req) == "string" and req or request(req)
    ntfe.send(who, fd, bytes)
    local r = read_reply(who, fd)
    local out = r.reply or { ok = nil, error = "no reply: " .. tostring(r.err) }
    out._body = r.body
    if r.body then out._eof = ntfe.recv(who, fd, 1500, 64) == "" end
    sys.close(who, fd)
    return out
end

local function allowed(r) return r.ok == true end
local function denied(r) return r.ok == false and r.error == "access denied" end
local function said(r) return tostring(r.ok) .. (r.error and (" " .. r.error) or "") end

-- The four requests that need RESOLVER_QUERY, each answerable without
-- the network, and the one that needs RESOLVER_CONTROL.
local QUERIES = {
    { query = "status" },
    { query = "resolve", name = "localhost", type = 1 },
    { query = "lookup", name = "localhost" },
    { query = "reverse", address = "127.0.0.1" },
}
local FLUSH = { query = "flush" }

--- Whether `who` may query (all four agree, else nil) and control.
local function rights_of(who)
    local q
    for _, req in ipairs(QUERIES) do
        local a = allowed(ask(who, req))
        if q == nil then q = a elseif q ~= a then return nil, nil end
    end
    return q, allowed(ask(who, FLUSH))
end

--- Write `Machine\System\Network\Dns ControlSecurity` (hex), or delete it.
local function control_security(hex)
    if hex then
        network.write(sut, DNS_KEY, { ControlSecurity = "hex:" .. hex })
    else
        network.reg(sut, { "del", DNS_KEY, "ControlSecurity" })
    end
end

--- Wait until SYSTEM's rights are (q, c).
local function wait_rights(q, c, desc)
    local sq, sc
    local ok = pcall(wait_until, function()
        sq, sc = rights_of(sut)
        return sq == q and sc == c
    end, { timeout = 10, interval = 0.3, desc = desc })
    return ok, sq, sc
end

local function restore_default(t)
    control_security(nil)
    local ok = wait_rights(true, true, "the default descriptor again")
    t:assert(ok, "with ControlSecurity removed SYSTEM may query and control again")
end

local function resolvd_logs()
    local r = sut:run("evctl 'LOGS FROM resolvd SINCE 5m ago TAKE 300'")
    local out = {}
    for line in r.stdout:gmatch("[^\n]+") do
        local msg = line:match('message="(.-)"  origin=')
        if msg then out[#out + 1] = (msg:gsub('\\"', '"')) end
    end
    return out
end

local function logged(text)
    for _, l in ipairs(resolvd_logs()) do
        if l:find(text, 1, true) then return l end
    end
end

local function resolvd_pid()
    local pid = peinit.pid_of_comm(sut, "resolvd")
    assert(pid, "resolvd is running")
    return tonumber(pid)
end

local function asked(name, timeout)
    return gw:serve({ timeout = timeout or 10, until_ = function()
        for _, q in ipairs(dns.queries(gw)) do
            local qq = q.msg and q.msg.questions[1]
            if qq and dns.same_name(qq.name, name) then return true end
        end
        return false
    end })
end

local function served(cmd, timeout)
    local p = sut:run_async("sh", { args = { "-c", cmd } })
    gw:serve({ timeout = timeout or 20, until_ = function() return p:status() == "exited" end })
    return p:wait(5)
end

--- Ask the stub door, as `who`, for `name` A; returns the decoded DNS reply.
local function stub_ask(who, name)
    local fd = assert(ntfe.udp_connect(who, "127.0.0.53", 53))
    ntfe.send(who, fd, dns.encode(dns.query(name, "A", { id = 0x5150 })))
    local got
    gw:serve({ timeout = 10, until_ = function()
        got = ntfe.recv(who, fd, 0, 4096)
        return got ~= nil
    end })
    sys.close(who, fd)
    return got and dns.decode(got)
end

local function a_records(m)
    local out = {}
    for _, a in ipairs((m and m.answers) or {}) do
        if a.type == dns.TYPE.A then out[#out + 1] = a.data end
    end
    return table.concat(out, ",")
end

local ready_done = false
local function ready(t)
    if ready_done then return end
    t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "netd bound a lease")
    local ok = pcall(wait_until, function()
        local s = network.call(sut, { query = "status" }, { path = SOCK })
        for _, sc in ipairs((s and s.scopes) or {}) do
            for _, a in ipairs(sc.servers or {}) do
                if a == "10.77.0.1" then return true end
            end
        end
        return false
    end, { timeout = 20, interval = 0.3, desc = "resolvd to hold 10.77.0.1" })
    t:assert(ok, "resolvd has a scope with server 10.77.0.1")
    t:assert(network.get(sut, DNS_KEY, "ControlSecurity") == nil, "no ControlSecurity is written")
    ready_done = true
end

-- ---------------------------------------------------------------------------
-- The compiled default
-- ---------------------------------------------------------------------------

test("the compiled default: Everyone may query, SYSTEM and Administrators may also flush; a denial is an access denied error reply",
    { spec = "resolvd *native-access.compiled-default-descriptor resolvd *native-access.denial-reply PSPU *nri-native.default-descriptor-grants PSPU *nri-native.denied-request-answered-with-error" },
    function(t)
        ready(t)
        local q, c = rights_of(sut)
        t:log("SYSTEM: query " .. tostring(q) .. ", flush " .. tostring(c))
        t:assert(q == true and c == true, "SYSTEM may query and flush")

        token.as_principal(t, sut, ADMIN(), function(w)
            local aq, ac = rights_of(w)
            t:log("Administrators: query " .. tostring(aq) .. ", flush " .. tostring(ac))
            t:assert(aq == true and ac == true, "Administrators may query and flush")
        end)

        token.as_principal(t, sut, USER(), function(w)
            for _, req in ipairs(QUERIES) do
                local r = ask(w, req)
                t:log("user " .. req.query .. ": " .. said(r))
                t:assert(allowed(r), "Everyone may " .. req.query)
            end
            local r = ask(w, FLUSH)
            t:log("user flush: " .. said(r) .. ", eof " .. tostring(r._eof))
            t:assert(denied(r), "Everyone may not flush: access denied")
            local m = msgpack.decode(r._body)
            local keys = {}
            for k in pairs(m) do keys[#keys + 1] = k end
            table.sort(keys)
            t:assert_eq(table.concat(keys, ","), "error,ok", "the denial is {ok: false, error} and nothing else")
            t:assert(r._eof, "an error reply, then the connection is closed (not closed silently)")
        end)
    end)

test("every process may connect: the socket admits an ordinary user even when the control object grants it nothing",
    { spec = "PSPU *nri-native.every-process-may-connect" }, function(t)
        ready(t)
        local ok, err = pcall(function()
            -- A descriptor granting SYSTEM READ_CONTROL and nobody anything.
            control_security(peinit.system_descriptor_hex(READ_CONTROL))
            t:assert(wait_rights(false, false, "nothing granted"), "the object now grants nothing")
            token.as_principal(t, sut, USER(), function(w)
                local fd = assert(unixsock.socket(w, unixsock.AF_UNIX, unixsock.SOCK.STREAM))
                local c = unixsock.connect(w, fd, SOCK)
                t:log("user connect: ret " .. c.ret .. " " .. unixsock.errname(c.errno or 0))
                t:assert_eq(c.ret, 0, "an ordinary user connects")
                ntfe.send(w, fd, request({ query = "status" }))
                local r = read_reply(w, fd)
                sys.close(w, fd)
                t:log("user status: " .. tostring(r.reply and said(r.reply)))
                t:assert(r.reply and denied(r.reply), "and is told access denied by the object, not refused by the socket")
            end)
        end)
        restore_default(t)
        if not ok then error(err, 0) end
        token.as_principal(t, sut, USER(), function(w)
            t:assert(allowed(ask(w, { query = "status" })), "under the default an ordinary user connects and is answered")
        end)
    end)

test("the check is a real access check of the peer's token: a deny-only Administrators group and a restricted token are judged as KACS judges them",
    { spec = "PSPU *nri-native.access-check-with-peer-token" }, function(t)
        ready(t)
        token.as_principal(t, sut, { groups = {
            { sid = token.SID.EVERYONE, attributes = ENABLED },
            { sid = token.SID.AUTHENTICATED_USERS, attributes = ENABLED },
            { sid = token.SID.ADMINISTRATORS, attributes = G.USE_FOR_DENY_ONLY },
        } }, function(w)
            local r = ask(w, FLUSH)
            t:log("deny-only Administrators, flush: " .. said(r))
            t:assert(denied(r), "deny-only Administrators: flush denied")
            t:assert(allowed(ask(w, { query = "status" })), "deny-only Administrators: status allowed (Everyone)")
        end)
        token.as_principal(t, sut, {
            groups = ADMIN_GROUPS(),
            restricted_sids = { { sid = token.SID.EVERYONE, attributes = 0 } },
        }, function(w)
            local r = ask(w, FLUSH)
            t:log("Administrators restricted to Everyone, flush: " .. said(r))
            t:assert(denied(r), "a restricted token: flush denied")
            t:assert(allowed(ask(w, { query = "status" })), "a restricted token: status allowed")
        end)
        -- The same groups, nothing deny-only or restricted: allowed.
        token.as_principal(t, sut, ADMIN(), function(w)
            t:assert(allowed(ask(w, FLUSH)), "the same groups, enabled and unrestricted: flush allowed")
        end)
    end)

test("a check that cannot be completed counts as a denial",
    { spec = "resolvd *native-access.failed-check-is-denial" }, function(t)
        ready(t)
        local L = token.LEVEL
        local r = ask(sut, { query = "status" }, { level = L.IMPERSONATION })
        t:log("SYSTEM at Impersonation level: " .. said(r))
        t:assert(allowed(r), "SYSTEM's connection at Impersonation level is checked and allowed")
        r = ask(sut, { query = "status" }, { level = L.IDENTIFICATION })
        t:log("SYSTEM at Identification level: " .. said(r))
        t:assert(denied(r), "at Identification level the check cannot be made, and status is access denied")
        r = ask(sut, FLUSH, { level = L.IDENTIFICATION })
        t:assert(denied(r), "and so is flush")
        -- The token was opened: this is the check failing, not the open.
        local line = logged("control: no peer token")
        t:log("no-peer-token line: " .. tostring(line))
        t:assert(line == nil, "no `no peer token` line: the token opened and the check itself failed")
    end)

test("a peer whose token cannot be opened is logged and denied",
    { spec = "resolvd *native-access.no-peer-token-is-denial" }, function(t)
        ready(t)
        local pid = resolvd_pid()
        local cur = sut:syscall(NR_PRLIMIT64, { args = { pid, RLIMIT_NOFILE, 0, 0 },
            bufs = { string.rep("\0", 16) }, ptrs = { 3 } })
        t:assert_eq(cur.ret, 0, "read resolvd's RLIMIT_NOFILE: " .. sys.errname(cur.errno or 0))
        local soft, hard = string.unpack("<I8I8", cur.out_bufs[1])
        t:log(string.format("resolvd RLIMIT_NOFILE %d/%d", soft, hard))
        local function set_soft(n)
            local r = sut:syscall(NR_PRLIMIT64, { args = { pid, RLIMIT_NOFILE, 0, 0 },
                bufs = { string.pack("<I8I8", n, hard) }, ptrs = { 2 } })
            return r
        end

        local fd, limit
        local stopped = sut:syscall(NR_KILL, pid, SIGSTOP)
        t:assert_eq(stopped.ret, 0, "SIGSTOP resolvd: " .. sys.errname(stopped.errno or 0))
        local ok, err = pcall(function()
            wait_until(function()
                local st = peinit.proc(sut, pid, "stat") or ""
                return st:match("^%d+ %b() (%a)") == "T"
            end, { timeout = 5, interval = 0.05, desc = "resolvd stopped" })
            -- The smallest limit leaving exactly one descriptor slot free.
            local open_fds = peinit.fds(sut, pid)
            local n = 0
            for _ in pairs(open_fds) do n = n + 1 end
            local below = 0
            for l = 1, 4096 do
                if open_fds[l - 1] then below = below + 1 end
                if l - below == 1 then limit = l; break end
            end
            t:log("resolvd holds " .. n .. " descriptors; soft limit to " .. tostring(limit))
            local r = set_soft(limit)
            t:assert_eq(r.ret, 0, "prlimit64 lowers resolvd's soft limit: " .. sys.errname(r.errno or 0))
            fd = open(sut)
            ntfe.send(sut, fd, request({ query = "status" }))
        end)
        sut:syscall(NR_KILL, pid, SIGCONT)
        local reply = fd and read_reply(sut, fd, 5000)
        if fd then sys.close(sut, fd) end
        local back = set_soft(soft)
        t:assert_eq(back.ret, 0, "the limit is put back")
        if not ok then error(err, 0) end
        t:log("status with one slot free: " .. tostring(reply.reply and said(reply.reply) or reply.err))
        t:assert(reply.reply and denied(reply.reply), "SYSTEM is denied: access denied")
        local line
        pcall(wait_until, function()
            line = logged("control: no peer token: ")
            return line ~= nil
        end, { timeout = 10, interval = 0.5, desc = "the no-peer-token line" })
        t:log("log: " .. tostring(line))
        t:assert(line, "control: no peer token: <error> is logged")
        t:assert(allowed(ask(sut, { query = "status" })), "with the limit back, SYSTEM is allowed again")
    end)

-- ---------------------------------------------------------------------------
-- Rights, the mapping, and ControlSecurity
-- ---------------------------------------------------------------------------

test("ControlSecurity replaces the default; resolve, lookup, reverse and status need RESOLVER_QUERY, flush RESOLVER_CONTROL, and each generic right maps as tabled; an invalid one falls back to the default",
    { spec = "resolvd *native-access.query-right-requests resolvd *native-access.control-right-requests resolvd *native-access.generic-mapping PSPU *nri-native.resolver-query-right PSPU *nri-native.resolver-control-right PSPU *nri-native.resolver-all-access PSPU *nri-native.control-descriptor-from-registry-else-default" },
    function(t)
        ready(t)
        -- Each step: a SYSTEM-only descriptor granting `mask`, and whether
        -- SYSTEM may then query (all four requests) and flush.
        local steps = {
            { "RESOLVER_QUERY", RESOLVER_QUERY, true, false },
            { "RESOLVER_CONTROL", RESOLVER_CONTROL, false, true },
            { "GENERIC_READ", GENERIC_READ, true, false },
            { "GENERIC_WRITE", GENERIC_WRITE, false, true },
            { "GENERIC_EXECUTE", GENERIC_EXECUTE, true, false },
            { "GENERIC_ALL", GENERIC_ALL, true, true },
            { "READ_CONTROL only", READ_CONTROL, false, false },
            { "RESOLVER_QUERY|RESOLVER_CONTROL", RESOLVER_QUERY | RESOLVER_CONTROL, true, true },
            { "RESOLVER_QUERY again", RESOLVER_QUERY, true, false },
            { "RESOLVER_ALL_ACCESS", RESOLVER_ALL_ACCESS, true, true },
            { "the standard rights only", 0x000F0000, false, false },
        }
        local ok, err = pcall(function()
            for _, step in ipairs(steps) do
                local name, mask, q, c = step[1], step[2], step[3], step[4]
                control_security(peinit.system_descriptor_hex(mask))
                local reached, sq, sc = wait_rights(q, c, name)
                t:log(string.format("%s (0x%08x): query %s, flush %s", name, mask, tostring(sq), tostring(sc)))
                t:assert(reached, name .. ": SYSTEM may query=" .. tostring(q) .. ", flush=" .. tostring(c))
                -- Each request on its own, with the plain denial.
                for _, req in ipairs(QUERIES) do
                    local r = ask(sut, req)
                    if q then t:assert(allowed(r), name .. ": " .. req.query .. " allowed")
                    else t:assert(denied(r), name .. ": " .. req.query .. " access denied (" .. said(r) .. ")") end
                end
                local f = ask(sut, FLUSH)
                if c then t:assert(allowed(f), name .. ": flush allowed")
                else t:assert(denied(f), name .. ": flush access denied (" .. said(f) .. ")") end
            end
            -- An ordinary user is in none of these SYSTEM-only descriptors.
            token.as_principal(t, sut, USER(), function(w)
                t:assert(denied(ask(w, { query = "status" })), "a SYSTEM-only descriptor: Everyone may not query")
            end)

            -- Not a descriptor: logged, and the compiled default stands.
            control_security(peinit.system_descriptor_hex(RESOLVER_QUERY))
            t:assert(wait_rights(true, false, "query-only in force"), "query-only in force")
            control_security("0102030405")
            local back = wait_rights(true, true, "the default again")
            t:assert(back, "an invalid ControlSecurity: SYSTEM may flush again (the default)")
            local line = logged("ControlSecurity is not a valid descriptor (")
            t:log("log: " .. tostring(line))
            t:assert(line and line:find("); using the default", 1, true) ~= nil,
                "ControlSecurity is not a valid descriptor (…); using the default")
            token.as_principal(t, sut, USER(), function(w)
                t:assert(allowed(ask(w, { query = "status" })), "the default in force: Everyone may query")
                t:assert(denied(ask(w, FLUSH)), "the default in force: Everyone may not flush")
            end)
        end)
        restore_default(t)
        if not ok then error(err, 0) end
    end)

test("a request is decoded before it is checked: a caller allowed nothing still gets decoding errors and unknown query",
    { spec = "resolvd *native-access.decode-before-check" }, function(t)
        ready(t)
        local ok, err = pcall(function()
            control_security(peinit.system_descriptor_hex(READ_CONTROL))
            t:assert(wait_rights(false, false, "nothing granted"), "SYSTEM is allowed nothing")
            local cases = {
                { "an unknown query", request({ query = "frobnicate" }), 'unknown query "frobnicate"' },
                { "a duplicate key", frame("\x82\xa5query\xa5flush\xa5query\xa5flush"), "duplicate field query" },
                { "a truncated map", frame("\x82\xa5query\xa6status"), "malformed message: truncated message" },
                { "a missing field", request({ query = "lookup" }), "missing or malformed field name" },
                { "a well-formed status", request({ query = "status" }), "access denied" },
            }
            for _, c in ipairs(cases) do
                local r = ask(sut, c[2])
                t:log(c[1] .. ": " .. said(r))
                t:assert_eq(r.error, c[3], c[1])
            end
        end)
        restore_default(t)
        if not ok then error(err, 0) end
        -- And under the default, an ordinary user's malformed flush.
        token.as_principal(t, sut, USER(), function(w)
            local r = ask(w, frame("\x82\xa5query\xa5flush\xa5query\xa5flush"))
            t:log("user, duplicated flush: " .. said(r))
            t:assert_eq(r.error, "duplicate field query", "a user's malformed flush gets its decoding error, not access denied")
            r = ask(w, request({ query = "flush", type = 70000 }))
            t:assert_eq(r.error, "missing or malformed field type", "nor does a flush with a bad type")
        end)
    end)

test("a new descriptor applies to requests decoded after it; one already being answered is not checked again",
    { spec = "resolvd *native-access.new-descriptor-applies-to-later-requests" }, function(t)
        ready(t)
        hold["held.example.test"] = true
        dns.forget(gw)
        local fd = open(sut)
        ntfe.send(sut, fd, request({ query = "resolve", name = "held.example.test", type = 1, no_cache = true }))
        local ok, err = pcall(function()
            t:assert(asked("held.example.test"), "resolvd checked and read the request, and asked upstream")
            -- Now a descriptor that denies SYSTEM every query.
            control_security(peinit.system_descriptor_hex(RESOLVER_CONTROL))
            t:assert(wait_rights(false, true, "control-only"), "a later status is checked against the new descriptor: denied")
            hold["held.example.test"] = nil
            local readable = gw:serve({ timeout = 20, until_ = function()
                return ntfe.poll(sut, fd, ntfe.POLLIN, 0) ~= 0
            end })
            t:assert(readable, "the held request is answered")
            local r = read_reply(sut, fd)
            t:log("the held request: " .. tostring(r.reply and said(r.reply)) .. " kind " .. tostring(r.reply and r.reply.kind))
            t:assert(r.reply and r.reply.ok == true and r.reply.kind == "answer",
                "with its answer, not access denied: it is not checked again")
            local rec = r.reply.records and r.reply.records[1]
            t:assert_eq(rec and rec.text, "10.77.0.83", "the answer is the network's")
        end)
        hold["held.example.test"] = nil
        sys.close(sut, fd)
        restore_default(t)
        if not ok then error(err, 0) end
    end)

-- ---------------------------------------------------------------------------
-- Identity and the stub door
-- ---------------------------------------------------------------------------

--- `resolve` as `who` with no_cache, pumping the gateway for the answer.
local function resolve_network(who, name)
    local fd = open(who)
    ntfe.send(who, fd, request({ query = "resolve", name = name, type = 1, no_cache = true }))
    gw:serve({ timeout = 20, until_ = function() return ntfe.poll(who, fd, ntfe.POLLIN, 0) ~= 0 end })
    local r = read_reply(who, fd)
    sys.close(who, fd)
    return r
end

--- An answer reply in a form to compare: owner names case-folded (the
--- question goes upstream in a random 0x20 case).
local function answer_text(reply)
    if not reply then return "nil" end
    local recs = {}
    for _, rec in ipairs(reply.records or {}) do
        recs[#recs + 1] = string.format("%s/%s/%s/%s/%s", tostring(rec.name):lower(), tostring(rec.type),
            tostring(rec.ttl), tostring(rec.text), tostring(rec.data and #rec.data))
    end
    return string.format("ok=%s kind=%s outcome=%s source=%s server=%s interface=%s validation=%s rcode=%s records=[%s]",
        tostring(reply.ok), tostring(reply.kind), tostring(reply.outcome), tostring(reply.source), tostring(reply.server),
        tostring(reply.interface), tostring(reply.validation), tostring(reply.rcode), table.concat(recs, " "))
end

test("the answer does not depend on the caller: SYSTEM, an administrator and an ordinary user get the same answer to the same question",
    { spec = "resolvd *native-access.answer-independent-of-caller PSPU *nri-native.no-identity-aware-policy" },
    function(t)
        ready(t)
        local results = {}
        local function run(label, who)
            local net = resolve_network(who, "www.example.test")
            local loc = read_reply(who, (function()
                local fd = open(who)
                ntfe.send(who, fd, request({ query = "lookup", name = "localhost" }))
                return fd
            end)())
            results[#results + 1] = { label, answer_text(net.reply), loc.body }
            t:log(label .. ": " .. answer_text(net.reply))
        end
        run("SYSTEM", sut)
        token.as_principal(t, sut, ADMIN(), function(w) run("Administrators", w) end)
        token.as_principal(t, sut, USER(), function(w) run("ordinary user", w) end)
        t:assert(results[1][2]:find("kind=answer", 1, true) and results[1][2]:find("10.77.0.80", 1, true),
            "SYSTEM's answer is the network's")
        for i = 2, #results do
            t:assert_eq(results[i][2], results[1][2], results[i][1] .. ": the same network answer as SYSTEM")
            t:assert_eq(results[i][3], results[1][3], results[i][1] .. ": the same lookup reply, byte for byte")
        end
    end)

test("the stub door is not governed by the control object: a caller denied RESOLVER_QUERY still resolves through 127.0.0.53, while the NSS shim fails",
    { spec = "resolvd *native-access.stub-not-governed" }, function(t)
        ready(t)
        -- Under the default, the shim resolves (so its failure below is
        -- the object's doing).
        local before = served("getent ahosts www.example.test")
        t:log("getent under the default: exit " .. before.exit_code .. "\n" .. before.stdout)
        t:assert_eq(before.exit_code, 0, "getent ahosts resolves under the default")
        t:assert(before.stdout:find("10.77.0.80", 1, true), "to the network's address")
        local ok, err = pcall(function()
            control_security(peinit.system_descriptor_hex(READ_CONTROL))
            t:assert(wait_rights(false, false, "nothing granted"), "SYSTEM is denied RESOLVER_QUERY")
            local m = stub_ask(sut, "www.example.test")
            t:log("SYSTEM via the stub: rcode " .. tostring(m and m.rcode) .. " A " .. a_records(m))
            t:assert_eq(a_records(m), "10.77.0.80", "SYSTEM still resolves through 127.0.0.53")
            token.as_principal(t, sut, USER(), function(w)
                t:assert(denied(ask(w, { query = "status" })), "an ordinary user is denied on the native socket")
                local um = stub_ask(w, "www.example.test")
                t:log("user via the stub: rcode " .. tostring(um and um.rcode) .. " A " .. a_records(um))
                t:assert_eq(a_records(um), "10.77.0.80", "and still resolves through 127.0.0.53")
            end)
            local after = served("getent ahosts www.example.test")
            t:log("getent while denied: exit " .. after.exit_code .. " " .. after.stdout .. after.stderr)
            t:assert(after.exit_code ~= 0, "getaddrinfo through the NSS shim fails")
        end)
        restore_default(t)
        if not ok then error(err, 0) end
    end)
