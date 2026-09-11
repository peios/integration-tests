-- peinit TRM §10.1 — the peer token: whose identity a control connection
-- carries, and when peinit decides.
--
-- Everything else in the control chapters is driven from the console,
-- and the console is SYSTEM connecting as itself. That cannot say
-- anything about *which* identity peinit captured, because there is only
-- one on offer. The client here is a provium worker instead
-- (helpers/peinit_client.lua): it mints a second principal, impersonates it
-- around `connect()`, reverts, and speaks the control protocol by hand —
-- so the identity a connection was made under and the identity its
-- requests are later sent under can be made to differ on purpose.
--
-- The oracle is a `ServiceSecurity` descriptor that tells the two apart.
-- The control socket admits only SYSTEM and Administrators, so the
-- second principal is a member of Administrators — otherwise the kernel
-- would refuse it at `connect()` and peinit would never be asked. The
-- descriptor on `pt-peer` then grants that principal's user SID every
-- service right and SYSTEM none: a `status` evaluated as the minted user
-- is answered, and the same `status` evaluated as SYSTEM is refused.

local peinit = require("helpers.peinit")
local token = require("helpers.token")
local us = require("helpers.unixsock")
local f = require("helpers.peinit_client")

peinit.claim(1)

local SERVICE = "pt-peer"
local KEY = [[Machine\System\Services\]] .. SERVICE
-- A local account the image has never heard of; the descriptor names it
-- and nothing else does.
local USER = token.SID.TEST_USER
local USER_SID = token.sid_string(USER)
local SERVICE_ALL_ACCESS = 0x000F01FF

local vm = peinit.boot({
    name = "peertoken",
    files = peinit.seed("pt-peer", {
        { path = [[Machine\System]] },
        { path = [[Machine\System\Services]] },
        { path = KEY, values = {
            { name = "ImagePath", type = "sz", data = "/bin/true" },
            { name = "Type", type = "dword", data = 1 },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "Readiness", type = "dword", data = 1 },
        } },
    }),
})

local STATUS = '{"command":"status","service":"' .. SERVICE .. '"}'

--- "answered" or "denied", from one raw control-socket answer.
local function verdict(answer)
    assert(answer, "peinit gave no answer")
    if answer:find('"ACCESS_DENIED"', 1, true) then return "denied" end
    assert(answer:find('"status":"ok"', 1, true), "neither an answer nor a denial: " .. answer)
    return "answered"
end

-- The descriptor goes on once, for the whole file: the minted user may
-- do anything to pt-peer and SYSTEM may do nothing. The registry watch
-- carries it to peinit asynchronously, so the console's own `status` —
-- which is SYSTEM's — is polled until it is refused.
vm:run("reg set '" .. KEY .. "' ServiceSecurity hex:" ..
    f.descriptor_hex(token.SID.LOCAL_SYSTEM, { { sid = USER, mask = SERVICE_ALL_ACCESS } }))
    :assert_ok()
wait_until(function()
    return peinit.verdict(vm:run("svctl status " .. SERVICE)) == "denied" or nil
end, { timeout = 60, interval = 0.5, desc = "the descriptor naming only " .. USER_SID .. " to land" })

test("a peer that connects while impersonating is captured as the identity it impersonated",
    { spec = "peinit *control.an-impersonating-peer-is-captured-as-the-impersonated-identity" },
    function(t)
        f.with_worker(vm, function(w)
            local minted = assert(f.mint_admin(w, USER))

            -- The same process, twice. The only difference between the two
            -- connections is who the connecting thread was acting as at
            -- the moment it called connect(); both requests are then sent
            -- by the worker as itself, having reverted.
            local impersonating = assert(f.connect_as(w, f.CONTROL_SOCKET, us.SOCK.STREAM, minted))
            local own = assert(f.connect_as(w, f.CONTROL_SOCKET, us.SOCK.STREAM, nil))

            local as_minted = f.control_request(w, impersonating, STATUS)
            local as_self = f.control_request(w, own, STATUS)

            t:assert_eq(verdict(as_minted), "answered",
                "the connection made while impersonating " .. USER_SID ..
                " was evaluated as that user, whom the descriptor admits: " .. tostring(as_minted))
            t:assert_eq(verdict(as_self), "denied",
                "while the one made as the worker's own SYSTEM identity was refused, " ..
                "so the answer above was not SYSTEM's: " .. tostring(as_self))
        end)
    end)

test("the peer token is read once, at accept, and a later change of identity is not seen",
    { spec = "peinit *control.the-peer-token-is-read-once-at-accept" },
    function(t)
        -- A stream socket's conveyed identity is not fixed by the kernel:
        -- with KACS_SO_PASS_TOKEN set, every send carries the sender's
        -- effective token, and the far end's register moves to it as the
        -- data is read (PKM §3.5.3). A server that asked for the peer
        -- token per request would therefore see whoever sent the
        -- request. peinit asks once, when it accepts, so it goes on
        -- seeing whoever connected.
        f.with_worker(vm, function(w)
            local minted = assert(f.mint_admin(w, USER))

            -- First, that the client below really does convey a change.
            -- The same moves against a listener of the worker's own: a
            -- connection made as the minted user, then a send with
            -- PASS_TOKEN set. Before the read the accepted end's peer
            -- token is the minted user; after it, SYSTEM. So a server
            -- that asked per request would have seen the change.
            local probe = "/run/pt-peer-probe.sock"
            vm:run("rm -f " .. probe)
            local listener = assert(us.socket(w, us.AF_UNIX, us.SOCK.STREAM))
            t:assert_eq(us.bind(w, listener, probe).ret, 0, "the probe listener binds")
            t:assert_eq(us.listen(w, listener).ret, 0, "and listens")
            local client = assert(f.connect_as(w, probe, us.SOCK.STREAM, minted))
            local accepted = assert(us.accept(w, listener))
            t:assert_eq(f.peer_user(w, accepted), USER_SID,
                "the probe's accepted end captured the minted user at connect")
            t:assert_eq(us.set_pass_token(w, client, true).ret, 0, "PASS_TOKEN on the client")
            t:assert(us.sendmsg(w, client, "x\n").ret == 2, "one request's worth of bytes sent")
            t:assert_eq(us.recvmsg(w, accepted, 16, { cmsg = 0 }).ret, 2, "and read")
            t:assert_eq(f.peer_user(w, accepted), token.sid_string(token.SID.LOCAL_SYSTEM),
                "and once they are read, the accepted end's peer token is the sender's " ..
                "SYSTEM: a per-request read would have seen the change")

            -- Connected as the minted user; every request then sent as
            -- SYSTEM, and conveyed as SYSTEM.
            local connected_as_user = assert(f.connect_as(w, f.CONTROL_SOCKET, us.SOCK.STREAM, minted))
            t:assert_eq(us.set_pass_token(w, connected_as_user, true).ret, 0,
                "the client conveys its identity with every send from here on")
            local first = f.control_request(w, connected_as_user, STATUS)
            local second = f.control_request(w, connected_as_user, STATUS)
            t:assert_eq(verdict(first), "answered",
                "a request sent as SYSTEM on a connection made as " .. USER_SID ..
                " is still evaluated as " .. USER_SID .. ": " .. tostring(first))
            t:assert_eq(verdict(second), "answered",
                "and so is the next one on the same connection: " .. tostring(second))

            -- And the other way round: connected as SYSTEM, every request
            -- then sent while impersonating the minted user and conveyed
            -- as that user.
            local connected_as_self = assert(f.connect_as(w, f.CONTROL_SOCKET, us.SOCK.STREAM, nil))
            t:assert_eq(us.set_pass_token(w, connected_as_self, true).ret, 0,
                "this client conveys its identity with every send too")
            t:assert_eq(token.impersonate(w, minted).ret, 0,
                "the worker now acts as " .. USER_SID)
            local changed = f.control_request(w, connected_as_self, STATUS)
            token.revert(w)
            t:assert_eq(verdict(changed), "denied",
                "a request sent as " .. USER_SID .. " on a connection made as SYSTEM is " ..
                "still SYSTEM's, and refused: " .. tostring(changed))
        end)
    end)
