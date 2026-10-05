-- peinit TRM §10.1 and §10.4 — two claims the rest of the control
-- chapter's files leave open: the per-caller connection limit, and the
-- order a reload-config does its reading and its changing in.
--
-- The per-user limit is counted by the user SID of the connecting
-- token, and the console has only one — SYSTEM, which is exempt. So the
-- callers here are a provium worker's (helpers/peinit_client.lua): it
-- mints a token for a local account the image has never heard of,
-- impersonates it around `connect()`, and speaks the control protocol by
-- hand. Since PEI-1231 the control socket admits every authenticated
-- principal, so the minted user needs no Administrators membership to
-- reach peinit at all.
--
-- A connection over the limit is closed at the socket level, before any
-- request is read and without a response. That is observed as EOF on a
-- connection that has sent nothing: sending first would leave unread
-- data on peinit's side of a socket it closes, which AF_UNIX reports to
-- the client as a reset rather than an end of file, and the two would
-- be harder to tell from a peinit that read the request and failed.

local peinit = require("helpers.peinit")
local token = require("helpers.token")
local us = require("helpers.unixsock")
local sys = require("helpers.sys")
local f = require("helpers.peinit_client")
peinit.claim(1)

local INIT = [[Machine\System\Init]]
local STATUS = '{"command":"status","service":"registryd"}'

local vm = peinit.boot({
    name = "control-gaps",
    files = peinit.seed("pt-gaps", {
        { path = [[Machine\System]] },
        { path = INIT },
        { path = [[Machine\System\Services]] },
    }),
})

--- An impersonation token for `user`: Everyone and Authenticated Users,
--- no Administrators and no Service group. SeChangeNotifyPrivilege
--- because a minted token holds no privileges at all, and without it the
--- walk to /run/services/peinit fails on traverse before the socket is
--- reached.
local function mint_user(w, user)
    local enabled = token.GROUP.MANDATORY | token.GROUP.ENABLED_BY_DEFAULT
        | token.GROUP.ENABLED
    local notify = token.bit(token.PRIV.CHANGE_NOTIFY)
    return assert(token.mint(w, {
        user_sid = user,
        token_type = token.TYPE.IMPERSONATION,
        impersonation_level = token.LEVEL.IMPERSONATION,
        groups = {
            { sid = token.SID.EVERYONE, attributes = enabled },
            { sid = token.SID.AUTHENTICATED_USERS, attributes = enabled },
        },
        privs_present = notify,
        privs_enabled = notify,
    }))
end

--- Whether peinit answered a request on `fd`.
local function answered(w, fd)
    local answer = f.control_request(w, fd, STATUS)
    return answer ~= nil and answer:find('"status":', 1, true) ~= nil, tostring(answer)
end

--- Whether peinit closed `fd` without a word: EOF on a read, with
--- nothing sent. A connection peinit admitted is simply idle, and the
--- read times out after the 30 s SO_RCVTIMEO `connect_as` sets.
local function closed_unanswered(w, fd)
    local r = us.recvmsg(w, fd, 256, { cmsg = 0 })
    return r.ret == 0, "recv ret=" .. tostring(r.ret) .. " errno=" .. us.errname(r.errno or 0)
end

--- Open `n` control connections as `as_token` (nil: the worker's own
--- SYSTEM identity), sending nothing on them.
local function open(w, n, as_token)
    local fds = {}
    for i = 1, n do
        fds[i] = assert(f.connect_as(w, f.CONTROL_SOCKET, us.SOCK.STREAM, as_token))
    end
    return fds
end

local function close_all(w, fds)
    for _, fd in ipairs(fds) do sys.close(w, fd) end
end

test("one user may hold sixteen control connections, the seventeenth is closed unanswered, and SYSTEM is exempt",
    { spec = "peinit *control.max-control-connections-per-user" },
    function(t)
        -- Everything from the first connect to the seventeenth runs well
        -- inside the 30-second ConnectionTimeout: an idle connection that
        -- timed out would leave the count, and the seventeenth would be
        -- admitted for the wrong reason.
        f.with_worker(vm, function(w)
            local user = mint_user(w, token.SID.TEST_USER)
            local held = open(w, 16, user)

            local over = assert(f.connect_as(w, f.CONTROL_SOCKET, us.SOCK.STREAM, user))
            local closed, how = closed_unanswered(w, over)
            t:assert(closed,
                "the seventeenth connection from one user is closed before a request: " .. how)

            -- The sixteen are live, so it was the count that refused the
            -- seventeenth and not a socket that was refusing everyone.
            local ok, answer = answered(w, held[1])
            t:assert(ok, "the user's first connection is still served: " .. answer)

            -- Counted per user, not overall: another user is served while
            -- the first holds all sixteen of its own.
            local other = open(w, 1, mint_user(w, token.SID.TEST_USER_2))[1]
            ok, answer = answered(w, other)
            t:assert(ok, "a second user is served meanwhile: " .. answer)

            -- And SYSTEM is exempt: seventeen of its own, every one served.
            local system = open(w, 17, nil)
            ok, answer = answered(w, system[17])
            t:assert(ok, "SYSTEM's seventeenth connection is served: " .. answer)

            -- Freeing one makes room again. peinit has to notice the
            -- close before the next accept, so a refusal in between is
            -- retried rather than believed.
            sys.close(w, held[16])
            local again = wait_until(function()
                local fd = assert(f.connect_as(w, f.CONTROL_SOCKET, us.SOCK.STREAM, user))
                local served = answered(w, fd)
                sys.close(w, fd)
                return served or nil
            end, { timeout = 20, interval = 0.5,
                   desc = "a freed slot to admit the user's next connection" })
            t:assert(again, "with one closed, the user's next connection is served")

            held[16] = nil
            close_all(w, held)
            close_all(w, system)
            sys.close(w, other)
            sys.close(w, over)
        end)
    end)

test("MaxControlConnectionsPerUser sets the per-user limit",
    { spec = "peinit *control.max-control-connections-per-user" },
    function(t)
        -- The key is one of the three control socket limits a reload
        -- refreshes (§10.4). Two, then the third connection is refused.
        vm:run("reg set '" .. INIT .. "' MaxControlConnectionsPerUser dword:2"):assert_ok()
        vm:run("svctl --json reload-config"):assert_ok()

        f.with_worker(vm, function(w)
            local user = mint_user(w, token.SID.TEST_USER)
            local held = open(w, 2, user)
            local over = assert(f.connect_as(w, f.CONTROL_SOCKET, us.SOCK.STREAM, user))
            local closed, how = closed_unanswered(w, over)
            t:assert(closed, "the third connection is closed under a limit of two: " .. how)
            local ok, answer = answered(w, held[2])
            t:assert(ok, "while the two are served: " .. answer)
            close_all(w, held)
            sys.close(w, over)
        end)

        vm:run("reg del '" .. INIT .. "' MaxControlConnectionsPerUser"):assert_ok()
        vm:run("svctl --json reload-config"):assert_ok()
    end)

test("a reload whose registry read fails changes nothing, though it had already read the definitions",
    { spec = "peinit *control.reload-config.reads-precede-every-mutation" },
    function(t)
        -- A read failure is provoked with a value peinit cannot decode:
        -- MaxControlConnectionsPerUser as a string. peinit reads the
        -- control socket limits after the service definitions, so a
        -- reload that mutated as it read would already have taken the new
        -- definition below when the failure came. The claim is that it
        -- has not: every read happens before any mutation, and the
        -- failure returns an error with nothing touched.
        --
        -- Last in the file, because until the value is removed every
        -- reload fails.
        vm:run("reg set '" .. INIT .. "' MaxControlConnectionsPerUser sz:many"):assert_ok()

        local batch = peinit.encode_json({ keys = { {
            path = [[Machine\System\Services\pt-gaps-new]],
            values = {
                { name = "ImagePath", type = "sz", data = "/bin/true" },
                { name = "Type", type = "dword", data = 1 },
                { name = "Identity", type = "sz", data = "SYSTEM" },
            },
        } } })
        vm:run("cat > /tmp/pt-gaps.json <<'PT_JSON_EOF'\n" .. batch ..
            "\nPT_JSON_EOF\nreg apply /tmp/pt-gaps.json"):assert_ok()

        local reload = vm:run("svctl --json reload-config")
        t:assert(reload.stdout:find('"status":"error"', 1, true),
            "the reload is answered with an error: " .. reload.stdout .. tostring(reload.stderr))

        local status = vm:run("svctl --json status pt-gaps-new")
        t:assert(status.stdout:find("UNKNOWN_SERVICE", 1, true),
            "and the definition it read before failing was not taken: " .. status.stdout)

        -- With the value gone the same registry reloads, and the
        -- definition arrives: it was the failure that held it back.
        vm:run("reg del '" .. INIT .. "' MaxControlConnectionsPerUser"):assert_ok()
        local ok = wait_until(function()
            local r = vm:run("svctl --json reload-config")
            return r.stdout:find('"status":"ok"', 1, true) and true or nil
        end, { timeout = 30, interval = 0.5, desc = "a reload to succeed again" })
        t:assert(ok, "the reload succeeds once the value is removed")
        status = vm:run("svctl --json status pt-gaps-new")
        t:assert(status.stdout:find('"service":"pt-gaps-new"', 1, true),
            "and takes the definition: " .. status.stdout)
    end)
