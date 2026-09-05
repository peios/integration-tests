-- PKM §3.2.7 — LogonSessions: the object a token's auth_id names, how it
-- is created and torn down, the rollback for an empty one, and what
-- revocation does not exist. Teardown is witnessed through the
-- logon-session-destroyed event on the KMES ring.

local sys = require("helpers.sys")
local token = require("helpers.token")
local kmes = require("helpers.kmes")
local access = require("helpers.access")

local vm = provium:vm("v", "kernel-only"):boot()

local TCB = token.bit(token.PRIV.TCB)
local DESTROYED = "logon-session-destroyed"

--- Events of the destroyed type carrying `sid` in their payload.
local function destroyed_for(events, sid)
    local out = {}
    for _, e in ipairs(kmes.of_type(events, DESTROYED)) do
        local p = e.payload
        local id = p and (p.logon_session_id or p.session_id or p.auth_id or p.id)
        if id == sid or (type(p) == "table" and p.session and p.session.id == sid) then out[#out + 1] = e end
    end
    return out
end

test("a LogonSession is created through a KACS syscall before the token that references it",
    { spec = "PKM *token.session.created-before-token" }, function(t)
        local sid = assert(token.create_logon_session(vm, { logon_type = token.LOGON_TYPE.SERVICE }))
        t:assert(sid >= 1000, "a dynamic session id: " .. sid)
        local fd = assert(token.create(vm, { auth_id = sid }))
        t:assert_eq(token.statistics(vm, fd).auth_id, sid, "the token references it")
        sys.close(vm, fd)
    end)

test("the session holds its id, logon type, user SID, package and creation time",
    { spec = "PKM *token.session.fields" }, function(t)
        for _, lt in ipairs({ token.LOGON_TYPE.INTERACTIVE, token.LOGON_TYPE.NETWORK,
            token.LOGON_TYPE.BATCH, token.LOGON_TYPE.SERVICE }) do
            local fd, sid = assert(token.mint(vm, { logon_type = lt, auth_package = "Kerberos" }))
            t:assert_eq(token.query_u32(vm, fd, token.CLASS.LOGON_TYPE), lt,
                "logon type " .. lt .. " is read from the session")
            t:assert_eq(token.query(vm, fd, token.CLASS.LOGON_SID), token.logon_sid(sid),
                "the logon SID is derived from the session id")
            sys.close(vm, fd)
        end
        -- A logon type outside the catalogue is refused.
        local bad, errno = token.create_logon_session(vm, { logon_type = 77 })
        t:assert(not bad, "an unknown logon type is refused: " .. sys.errname(errno or 0))
        bad, errno = token.create_logon_session(vm, { auth_package = "Neg\xffotiate" })
        t:assert(not bad, "a non-UTF-8 package name is refused: " .. sys.errname(errno or 0))
    end)

test("several tokens may share one session",
    { spec = "PKM *token.session.shared-by-many-tokens" }, function(t)
        local a, sid = assert(token.mint(vm, {}))
        local b = assert(token.create(vm, { auth_id = sid }))
        local c = assert(token.duplicate(vm, a, {}))
        for _, fd in ipairs({ a, b, c }) do
            t:assert_eq(token.statistics(vm, fd).auth_id, sid, "same auth_id")
            t:assert_eq(token.query(vm, fd, token.CLASS.LOGON_SID), token.logon_sid(sid), "same logon SID")
        end
        sys.close(vm, a); sys.close(vm, b); sys.close(vm, c)
    end)

test("freeing the last token destroys the session and emits logon-session-destroyed",
    { spec = "PKM *token.session.destroyed-with-last-token" }, function(t)
        local ring = assert(kmes.attach(vm, 0))
        local a, sid = assert(token.mint(vm, {}))
        local b = assert(token.create(vm, { auth_id = sid }))
        kmes.drain(ring)
        sys.close(vm, a)
        t:assert_eq(#destroyed_for(kmes.drain(ring), sid), 0, "one token left: no event yet")
        sys.close(vm, b)
        local ev = destroyed_for(kmes.drain(ring), sid)
        t:assert_eq(#ev, 1, "the last close destroys the session: exactly one event")
        t:assert_eq(ev[1].origin, kmes.ORIGIN.KACS, "from KACS")
        local again, errno = token.create(vm, { auth_id = sid })
        t:assert(not again, "and the session id no longer resolves: " .. sys.errname(errno or 0))
        kmes.detach(ring)
    end)

test("destroying an empty session requires SeTcbPrivilege and an empty session",
    { spec = "PKM *token.session.destroy-empty.gates" }, function(t)
        local sid = assert(token.create_logon_session(vm, {}))
        token.as_principal(t, vm, { privs_present = 0 }, function(w)
            local r = token.destroy_empty_logon_session(w, sid)
            t:assert(r.ret ~= 0, "a caller without SeTcbPrivilege is refused: " .. sys.errname(r.errno))
        end)
        token.as_principal(t, vm, { privs_present = TCB, privs_enabled = 0 }, function(w)
            local r = token.destroy_empty_logon_session(w, sid)
            t:assert(r.ret ~= 0, "held-but-disabled SeTcbPrivilege is refused: " .. sys.errname(r.errno))
        end)
        local fd = assert(token.create(vm, { auth_id = sid }))
        local busy = token.destroy_empty_logon_session(vm, sid)
        t:log("destroy on a busy session: ret=" .. busy.ret .. " errno=" .. tostring(busy.errno))
        t:assert_eq(busy.errno, sys.E.BUSY, "a live token: EBUSY")
        sys.close(vm, fd)
        -- Closing the only token destroyed the session, so the rollback
        -- finds nothing.
        t:assert_eq(token.destroy_empty_logon_session(vm, sid).errno, sys.E.NOENT, "then it is gone: ENOENT")
        local fresh = assert(token.create_logon_session(vm, {}))
        t:assert_eq(token.destroy_empty_logon_session(vm, fresh).ret, 0, "an empty session destroys cleanly")
    end)

test("the rollback emits the same logon-session-destroyed event",
    { spec = "PKM *token.session.destroy-empty.emits-event" }, function(t)
        local ring = assert(kmes.attach(vm, 0))
        local sid = assert(token.create_logon_session(vm, {}))
        kmes.drain(ring)
        t:assert_eq(token.destroy_empty_logon_session(vm, sid).ret, 0, "destroy")
        local ev = destroyed_for(kmes.drain(ring), sid)
        t:assert_eq(#ev, 1, "one logon-session-destroyed event")
        kmes.detach(ring)
    end)

test("a nonexistent session is ENOENT; a busy one is EBUSY",
    { spec = "PKM *token.session.destroy-empty.errors" }, function(t)
        t:assert_eq(token.destroy_empty_logon_session(vm, 0x7FFF000012345678).errno, sys.E.NOENT, "unknown id: ENOENT")
        t:assert_eq(token.destroy_empty_logon_session(vm, token.SYSTEM_LUID).errno, sys.E.BUSY,
            "the SYSTEM session has live tokens: EBUSY")
        local e, sid = assert(token.mint(vm, { privs_present = TCB, privs_enabled = TCB }))
        local l = assert(token.restrict(vm, e, { privs = TCB }))
        t:assert_eq(token.link(vm, e, e, l, sid).ret, 0, "link a pair in the session")
        t:assert_eq(token.destroy_empty_logon_session(vm, sid).errno, sys.E.BUSY,
            "live tokens and linked-token state: EBUSY")
        sys.close(vm, e); sys.close(vm, l)
    end)

--- securityfs, mounted where FACS can classify it.
---
--- FACS has no classification for securityfs, so a plain mount lands in
--- deny-missing and even SYSTEM's open of kacs/sessions fails EACCES
--- before the file's own read gate runs. A synthesising policy on the
--- mount gives its objects descriptors; the read handler's access check
--- (§3.2.7) is then what decides.
local SECURITYFS = "/mnt/securityfs"
local mounted = false
local function ensure_securityfs()
    if mounted then return true end
    local kacs = require("helpers.kacs")
    local ok, stage, errno = kacs.new_mount(vm, "securityfs", SECURITYFS, kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL)
    if not ok then return nil, stage .. ": " .. sys.errname(errno or 0) end
    mounted = true
    return true
end

--- Read the sessions file as `who`. Returns text, or nil, errno.
local function read_sessions(who)
    local fd, e = sys.open(who, SECURITYFS .. "/kacs/sessions", sys.O.RDONLY)
    if not fd then return nil, e end
    local out = {}
    while true do
        local chunk, re = sys.read(who, fd, 4096)
        if not chunk or #chunk == 0 then break end
        out[#out + 1] = chunk
    end
    sys.close(who, fd)
    return table.concat(out)
end

test("securityfs lists every live session with its fields",
    { spec = "PKM *token.session.securityfs-listing" }, function(t)
        local ok, why = ensure_securityfs()
        t:assert(ok, "securityfs mounts with a synthesise policy: " .. tostring(why))
        local fd, sid = assert(token.mint(vm, { logon_type = token.LOGON_TYPE.BATCH, auth_package = "PitPkg" }))
        local text, e = read_sessions(vm)
        t:assert(text, "the sessions file reads: " .. sys.errname(e or 0))
        local line
        for l in text:gmatch("[^\n]+") do if l:find(tostring(sid), 1, true) then line = l end end
        t:assert(line, "our session is listed: " .. text:sub(1, 200))
        -- Fields are key=value; SIDs and package names are hex-encoded bytes.
        local function hex(b) return (b:gsub(".", function(c) return string.format("%02x", c:byte()) end)) end
        t:assert(line:find("user_sid=" .. hex(token.SID.TEST_USER), 1, true), "with its user SID: " .. line)
        t:assert(line:find("auth_package=" .. hex("PitPkg"), 1, true), "its authentication package")
        t:assert(line:find("logon_type=4", 1, true), "its logon type")
        t:assert(line:find("created_at=%d+"), "and a creation time")
        t:assert(text:find(tostring(token.SYSTEM_LUID), 1, true), "and the SYSTEM session is there too")
        sys.close(vm, fd)
        local after = read_sessions(vm)
        t:assert(not after:find(tostring(sid), 1, true), "once destroyed it is gone from the list")
    end)

test("reading the sessions list is access-checked and PIP-checked",
    { spec = "PKM *token.session.securityfs-access-check" }, function(t)
        local ok, why = ensure_securityfs()
        t:assert(ok, "securityfs mounts with a synthesise policy: " .. tostring(why))
        local text, e = read_sessions(vm)
        t:assert(text, "SYSTEM reads it: " .. sys.errname(e or 0))
        token.as_principal(t, vm, {}, function(w)
            local text, e = read_sessions(w)
            t:assert(not text, "an ordinary principal is refused")
            t:assert_eq(e, sys.E.ACCES, "EACCES")
        end)
    end)

test("AccessCheck never consults auth_id; the logon SID acts as an ordinary group",
    { spec = "PKM *token.session.auth-id-not-consulted" }, function(t)
        local a, sid_a = assert(token.mint(vm, {}))
        local b, sid_b = assert(token.mint(vm, {}))
        -- Grant the first session's logon SID only.
        local sd = access.simple({ access.ace(access.ACE.ALLOWED, 0x1, token.logon_sid(sid_a)) })
        t:assert(access.check(vm, { token_fd = a, sd = sd, desired = 0x1 }).ok,
            "a token in session A is granted through its logon SID group")
        t:assert(access.check(vm, { token_fd = b, sd = sd, desired = 0x1 }).denied,
            "a token in session B is not")
        -- Disable nothing else; the logon SID is mandatory, so it cannot be
        -- turned off — which is the point of materialising it as a group.
        sys.close(vm, a); sys.close(vm, b)
    end)

test("a token lives while any reference to it does",
    { spec = "PKM *token.session.lifetime-by-refcount" }, function(t)
        local ring = assert(kmes.attach(vm, 0))
        local held, sid
        -- Mint in a worker and install it, keeping an fd on the agent side
        -- through the worker's pidfd; then kill the worker.
        token.as_principal(t, vm, {}, function(w)
            local pidfd = assert(token.pidfd_open(vm, w:syscall(sys.NR.getpid).ret))
            held = assert(token.open_process(vm, pidfd))
            sid = token.statistics(vm, held).auth_id
            sys.close(vm, pidfd)
        end)
        -- The worker is dead: its credential reference is gone, ours remains.
        -- Task teardown is asynchronous relative to the connection closing.
        sys.nanosleep(vm, 0, 100 * 1000 * 1000)
        kmes.drain(ring)
        t:assert_eq(token.query(vm, held, token.CLASS.USER), token.SID.TEST_USER, "the token is still alive through the fd")
        t:assert_eq(#destroyed_for(kmes.drain(ring), sid), 0, "and its session was not destroyed")
        sys.close(vm, held)
        t:assert_eq(#destroyed_for(kmes.drain(ring), sid), 1, "the last reference going destroys it")
        kmes.detach(ring)
    end)

test("there is no revocation primitive",
    { spec = "PKM *token.session.no-revocation-primitive" }, function(t)
        local fd, sid = assert(token.mint(vm, {}))
        t:assert_eq(token.destroy_empty_logon_session(vm, sid).errno, sys.E.BUSY,
            "the only session-destroying syscall refuses while a token references it")
        t:assert(token.query(vm, fd, token.CLASS.USER), "and the token goes on working")
        sys.close(vm, fd)
    end)

test("a token fd held elsewhere survives its session's process termination",
    { spec = "PKM *token.session.fd-reference-survives-termination" }, function(t)
        local held
        token.as_principal(t, vm, {}, function(w)
            local pidfd = assert(token.pidfd_open(vm, w:syscall(sys.NR.getpid).ret))
            held = assert(token.open_process(vm, pidfd))
            sys.close(vm, pidfd)
        end)
        t:assert_eq(token.sid_string(token.query(vm, held, token.CLASS.USER)), "S-1-5-21-1000-2000-3000-1101",
            "the process is gone; the token fd still answers")
        local dup = assert(token.duplicate(vm, held, {}))
        t:assert(dup, "and can still be duplicated")
        sys.close(vm, dup); sys.close(vm, held)
    end)
