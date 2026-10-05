-- Talking to peinit's sockets as a principal the console is not.
--
-- The console is SYSTEM, and svctl connects as whatever runs it. Several
-- of peinit's claims are about the identity a connection carries — which
-- one is captured, when, and what happens when the client changes its
-- mind — and a shell cannot connect *as* anyone but itself, nor change
-- identity between connecting and sending.
--
-- The provium worker can. It is a process the agent spawns on its own
-- token (SYSTEM, which holds SeCreateTokenPrivilege, SeTcbPrivilege and
-- SeImpersonatePrivilege), and it makes raw syscalls: it mints a token
-- for a principal of the test's choosing, impersonates it around a
-- `connect()`, reverts, and then speaks the socket's protocol by hand.
-- helpers/token and helpers/unixsock already carry the token and socket
-- surfaces; this module is only the peinit end of them.

local sys = require("helpers.sys")
local token = require("helpers.token")
local us = require("helpers.unixsock")

local M = {}

M.CONTROL_SOCKET = "/run/services/peinit/control.sock"
M.JOBS_SOCKET = "/run/services/peinit/jobs.sock"

local ENABLED = token.GROUP.MANDATORY | token.GROUP.ENABLED_BY_DEFAULT | token.GROUP.ENABLED

--- A self-relative security descriptor, hex-encoded for `reg set … hex:`.
---
--- `owner` is a binary SID (it is the group too); `aces` is a list of
--- `{ sid = <binary SID>, mask = <access mask> }`, each an allow ACE.
--- The layout is peinit.system_descriptor_hex's, generalised to any
--- grantee: MS-DTYP's header of revision, control and four offsets,
--- then the owner and group SIDs, then the DACL.
function M.descriptor_hex(owner, aces)
    local body = ""
    for _, ace in ipairs(aces) do
        body = body .. string.pack("<BBI2I4", 0, 0, 8 + #ace.sid, ace.mask) .. ace.sid
    end
    local acl = string.pack("<BBI2I2I2", 2, 0, 8 + #body, #aces, 0) .. body
    -- DACL_PRESENT | SELF_RELATIVE.
    local header = string.pack("<BBI2I4I4I4I4", 1, 0, 0x8004,
        20, 20 + #owner, 0, 20 + 2 * #owner)
    return ((header .. owner .. owner .. acl):gsub(".",
        function(byte) return string.format("%02x", byte:byte()) end))
end

--- An impersonation token for `user`, in Administrators.
---
--- Administrators because what peinit lets an administrator do is what
--- most control tests exercise. Reaching the socket needs less: since
--- PEI-1231 its descriptor admits SYSTEM, Administrators and every
--- authenticated user (peinit TRM §10.1).
--- SeChangeNotifyPrivilege because a minted token holds no privileges at
--- all, and without it the walk to /run/services/peinit fails on
--- traverse before the socket is reached.
---
--- `level` defaults to Impersonation. Returns fd, or nil, errno.
function M.mint_admin(who, user, level)
    local notify = token.bit(token.PRIV.CHANGE_NOTIFY)
    return token.mint(who, {
        user_sid = user,
        token_type = token.TYPE.IMPERSONATION,
        impersonation_level = level or token.LEVEL.IMPERSONATION,
        groups = {
            { sid = token.SID.EVERYONE, attributes = ENABLED },
            { sid = token.SID.AUTHENTICATED_USERS, attributes = ENABLED },
            { sid = token.SID.ADMINISTRATORS, attributes = ENABLED },
        },
        privs_present = notify,
        privs_enabled = notify,
    })
end

--- SO_RCVTIMEO, so a read the far end never answers fails instead of
--- hanging the worker for the rest of the run.
local function receive_timeout(who, fd, seconds)
    return who:syscall(us.NR.setsockopt, {
        args = { fd, 1, 20, 0, 16 },
        bufs = { string.pack("<i8i8", seconds, 0) }, ptrs = { 3 },
    })
end

--- A socket of `stype`, connected to `path` while impersonating
--- `as_token` (or as the worker's own identity when it is nil). The
--- worker reverts straight after the connect, so everything it does
--- afterwards is done as itself.
---
--- Returns fd, or nil and a message naming the step that failed.
function M.connect_as(who, path, stype, as_token)
    local fd, e = us.socket(who, us.AF_UNIX, stype or us.SOCK.STREAM)
    if not fd then return nil, "socket: " .. us.errname(e) end
    receive_timeout(who, fd, 30)
    if as_token then
        local r = token.impersonate(who, as_token)
        if r.ret ~= 0 then return nil, "impersonate: " .. us.errname(r.errno) end
    end
    local r = us.connect(who, fd, path)
    if as_token then token.revert(who) end
    if r.ret ~= 0 then return nil, "connect: " .. us.errname(r.errno) end
    return fd
end

--- Send one control-socket frame and read the answer, as the raw line.
---
--- Every answer peinit writes is one newline-terminated JSON object, so
--- a read loops until it has the newline rather than trusting one
--- `recvmsg` to carry the whole of it.
function M.control_request(who, fd, request)
    local sent = us.sendmsg(who, fd, request .. "\n")
    if sent.ret < 0 then return nil, "send: " .. us.errname(sent.errno) end
    local answer = ""
    while not answer:find("\n", 1, true) do
        local r = us.recvmsg(who, fd, 65536, { cmsg = 0 })
        if r.ret < 0 then return nil, "recv: " .. us.errname(r.errno) end
        if r.ret == 0 then return nil, "closed after: " .. answer end
        answer = answer .. r.data
    end
    return (answer:gsub("\n.*$", ""))
end

--- Send one jobs-socket record, optionally carrying `token_fd` as a
--- KACS_SCM_TOKEN, and read the answer record.
function M.jobs_request(who, fd, request, token_fd)
    local sent = us.sendmsg(who, fd, request, { token_fd = token_fd })
    if sent.ret < 0 then return nil, "send: " .. us.errname(sent.errno) end
    -- Room for the one pidfd a running job's answer carries.
    local r = us.recvmsg(who, fd, 65536, { cmsg = us.cmsg_space(4) })
    if r.ret < 0 then return nil, "recv: " .. us.errname(r.errno) end
    if r.ret == 0 then return nil, "closed" end
    for _, cmsg in ipairs(r.cmsgs) do
        if cmsg.level == 1 and cmsg.type == 1 and #cmsg.data >= 4 then
            sys.close(who, (string.unpack("<i4", cmsg.data)))
        end
    end
    return r.data
end

--- The user SID of the identity the far end of `fd` conveys: the
--- listener's captured identity for a client end (PKM §3.5.3).
function M.peer_user(who, fd)
    local peer, e = us.peer_token(who, fd)
    if not peer then return nil, "KACS_SO_PEER_TOKEN: " .. us.errname(e) end
    local user, qe = token.query(who, peer, token.CLASS.USER)
    sys.close(who, peer)
    if not user then return nil, "query user: " .. us.errname(qe) end
    return token.sid_string(user)
end

--- Run `fn(worker)` with a fresh worker, killing it afterwards whatever
--- `fn` did.
function M.with_worker(vm, fn)
    local worker = vm:spawn_worker()
    local ok, err = pcall(fn, worker)
    worker:kill(); worker:join()
    if not ok then error(err, 0) end
end

return M
