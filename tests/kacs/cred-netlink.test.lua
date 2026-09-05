-- PKM §3.10.4 — netlink: every permission test a netlink request makes
-- reaches the capability switchboard with a specific credential, and
-- the token on that credential decides. The two-point rule tests the
-- socket's opener and the sending thread; `netlink_allowed` tests the
-- sender alone.
--
-- The two subjects are separated with impersonation: a socket opened
-- while impersonating carries the impersonated token on its file
-- credential (KACS installs an impersonation token by overriding the
-- subjective credential), while a later send from the same process
-- after reverting is made by the primary. So one worker can be both
-- subjects, in either order.
--
-- RTM_NEWLINK on the loopback interface is the configuration request
-- under test: it changes nothing (ifi_flags 0, ifi_change IFF_UP leaves
-- lo down) and is answered with an ack or an error.

local sys = require("helpers.sys")
local token = require("helpers.token")
local creds = require("helpers.creds")

local vm = provium:vm("vcrednl", "kernel-only"):boot()

local TCB = token.bit(token.PRIV.TCB)
local CREATE = token.bit(token.PRIV.CREATE_TOKEN)
local IMPERSONATE = token.bit(token.PRIV.IMPERSONATE)
local ENABLED = token.GROUP.MANDATORY | token.GROUP.ENABLED_BY_DEFAULT | token.GROUP.ENABLED

--- A principal that can mint and impersonate a second token in its own
--- logon session, so a test can be two subjects at once. `fn` is called
--- with (worker, mint(spec) -> fd).
local function with_two_subjects(t, spec, fn)
    local base = { privs_present = CREATE | IMPERSONATE,
                   privs_enabled = CREATE | IMPERSONATE }
    for k, v in pairs(spec or {}) do base[k] = v end
    token.as_principal(t, vm, base, function(w, session)
        fn(w, function(extra)
            local s = { auth_id = session,
                        token_type = token.TYPE.IMPERSONATION,
                        impersonation_level = token.LEVEL.IMPERSONATION }
            for k, v in pairs(extra or {}) do s[k] = v end
            return assert(token.create(w, s))
        end)
    end)
end

test("a request is handled synchronously, inside the sender's own sendmsg",
    { spec = "PKM *cred.netlink.synchronous-delivery" }, function(t)
        token.as_principal(t, vm, { privs_present = TCB, privs_enabled = TCB },
            function(w)
                local fd = assert(creds.nl_open(w))
                t:assert_eq(creds.nl_bind(w, fd).ret, 0, "the socket binds")
                local sent = creds.nl_send(w, fd, creds.nlmsg(creds.RTM_NEWLINK,
                    creds.NLM_F_REQUEST | creds.NLM_F_ACK, 11,
                    creds.ifinfomsg(1, 0, 1)))
                t:assert_eq(sent.ret, 32, "sendto returns having written the message")
                -- No wait, no poll: the family's receive function ran
                -- inside that sendmsg, so the answer is already queued.
                local reply = creds.nl_recv(w, fd, creds.MSG_DONTWAIT)
                t:assert(reply, "a reply is already waiting the instant sendto returned")
                local _, mtype = string.unpack("<I4I2", reply)
                t:assert_eq(mtype, creds.NLMSG_ERROR,
                    "and it is the ack/error for that request")
                sys.close(w, fd)
            end)
    end)

test("the permission helpers test both the socket's opener and the sender",
    { spec = "PKM *cred.netlink.two-subject-check" }, function(t)
        with_two_subjects(t, {}, function(w, mint)
            local tcb = mint({ privs_present = TCB, privs_enabled = TCB })

            -- Opener without the privilege, sender with it.
            local opened_unprivileged = assert(creds.nl_open(w))
            t:assert_eq(token.impersonate(w, tcb).ret, 0, "the thread impersonates a TCB token")
            local opened_privileged = assert(creds.nl_open(w))
            t:assert_eq(creds.newlink_errno(w, opened_unprivileged, 21), sys.E.PERM,
                "a privileged sender on an unprivileged socket is refused EPERM")

            -- Both privileged: the same send on a socket the TCB token opened.
            t:assert_eq(creds.newlink_errno(w, opened_privileged, 22), 0,
                "the same sender on its own socket is answered")

            -- Opener with the privilege, sender without.
            t:assert_eq(token.revert(w).ret, 0, "the thread reverts")
            t:assert_eq(creds.newlink_errno(w, opened_privileged, 23), sys.E.PERM,
                "an unprivileged sender on a privileged socket is refused EPERM")

            sys.close(w, opened_unprivileged)
            sys.close(w, opened_privileged)
            sys.close(w, tcb)
        end)
    end)

test("netlink_allowed tests the sender alone",
    { spec = "PKM *cred.netlink.allowed-tests-sender" }, function(t)
        -- Sending to another netlink port is gated by netlink_allowed,
        -- which asks only about the current thread. The socket stays the
        -- same unprivileged one throughout, so any change in the answer
        -- is the sender's doing.
        with_two_subjects(t, {}, function(w, mint)
            local tcb = mint({ privs_present = TCB, privs_enabled = TCB })
            local fd = assert(creds.nl_open(w))
            t:assert_eq(creds.nl_bind(w, fd).ret, 0, "the unprivileged principal binds it")
            local msg = creds.nlmsg(creds.RTM_GETLINK, creds.NLM_F_REQUEST, 31,
                creds.ifinfomsg())

            local refused = creds.nl_send(w, fd, msg, 1)
            t:assert_eq(refused.ret, -1, "sending to another port is refused")
            t:assert_eq(refused.errno, sys.E.PERM, "EPERM")

            t:assert_eq(token.impersonate(w, tcb).ret, 0, "the same thread impersonates the TCB")
            local allowed = creds.nl_send(w, fd, msg, 1)
            t:assert_neq(allowed.errno, sys.E.PERM,
                "and the very same socket now passes the check: "
                .. sys.errname(allowed.errno))
            token.revert(w)
            sys.close(w, fd)
            sys.close(w, tcb)
        end)
    end)

test("the decision is made against the credential's token, not a projection of it",
    { spec = "PKM *cred.netlink.evaluated-against-cred-token" }, function(t)
        -- Two principals with the same projected uid and gid — the only
        -- thing a uid-based check could see — and different tokens.
        local function newlink_for(privs)
            local answer
            token.as_principal(t, vm, { projected_uid = 8080, projected_gid = 8081,
                privs_present = privs, privs_enabled = privs }, function(w)
                local fd = assert(creds.nl_open(w))
                t:assert_eq(creds.nl_bind(w, fd).ret, 0, "bound")
                t:assert_eq(creds.getuid(w), 8080, "projecting the same uid")
                answer = creds.newlink_errno(w, fd, 41)
                sys.close(w, fd)
            end)
            return answer
        end
        t:assert_eq(newlink_for(0), sys.E.PERM,
            "uid 8080 without SeTcbPrivilege is refused")
        t:assert_eq(newlink_for(TCB), 0,
            "uid 8080 with SeTcbPrivilege is answered — the token decided")
    end)

test("RTM_NEWLINK is a TCB operation: an administrator's session is refused",
    { spec = "PKM *cred.netlink.rtm-newlink-needs-tcb" }, function(t)
        token.as_principal(t, vm, {
            groups = {
                { sid = token.SID.EVERYONE, attributes = ENABLED },
                { sid = token.SID.ADMINISTRATORS, attributes = ENABLED },
                { sid = token.SID.AUTHENTICATED_USERS, attributes = ENABLED },
            },
            -- An administrator's ordinary privilege set, without the TCB.
            privs_present = token.bit(token.PRIV.BACKUP) | token.bit(token.PRIV.RESTORE)
                | token.bit(token.PRIV.SHUTDOWN) | token.bit(token.PRIV.TAKE_OWNERSHIP),
            privs_enabled = token.bit(token.PRIV.BACKUP) | token.bit(token.PRIV.RESTORE)
                | token.bit(token.PRIV.SHUTDOWN) | token.bit(token.PRIV.TAKE_OWNERSHIP),
        }, function(w)
            local fd = assert(creds.nl_open(w))
            t:assert_eq(creds.nl_bind(w, fd).ret, 0, "an administrator opens a route socket")
            t:assert_eq(creds.newlink_errno(w, fd, 51), sys.E.PERM,
                "and RTM_NEWLINK is answered with EPERM")
            sys.close(w, fd)
        end)
        token.as_principal(t, vm, { privs_present = TCB, privs_enabled = TCB },
            function(w)
                local fd = assert(creds.nl_open(w))
                t:assert_eq(creds.nl_bind(w, fd).ret, 0, "the TCB opens one")
                t:assert_eq(creds.newlink_errno(w, fd, 52), 0,
                    "and configuring the network is permitted")
                sys.close(w, fd)
            end)
    end)

test("requests that need no capability are answered for any caller",
    { spec = "PKM *cred.netlink.uncapped-requests-open" }, function(t)
        token.as_principal(t, vm, {}, function(w)
            local fd = assert(creds.nl_open(w))
            t:assert_eq(creds.nl_bind(w, fd).ret, 0, "an unprivileged principal binds")
            t:assert_eq(creds.rtm_getlink_dump(w, fd, 61).ret, 32,
                "and asks for the link list")
            local first = creds.nl_recv(w, fd)
            t:assert(first, "a reply arrives")
            local _, mtype = string.unpack("<I4I2", first)
            t:assert_eq(mtype, creds.RTM_NEWLINK,
                "and it is the dump, not an error: message type " .. mtype)
            t:assert(creds.nl_drain(w, fd) >= 1, "with the rest of the dump behind it")
            sys.close(w, fd)
        end)
    end)

test("NETLINK_CB carries the sender's projected uid and gid to a SO_PASSCRED reader",
    { spec = "PKM *cred.netlink.cb-carries-projected-ids" }, function(t)
        token.as_principal(t, vm, { projected_uid = 4711, projected_gid = 4712 },
            function(w)
                -- NETLINK_USERSOCK: two user sockets, which is the only
                -- shape that delivers the metadata to a reader.
                local reader = assert(creds.nl_open(w, creds.NETLINK_USERSOCK))
                local sender = assert(creds.nl_open(w, creds.NETLINK_USERSOCK))
                t:assert_eq(creds.nl_bind(w, reader).ret, 0, "the reader binds")
                t:assert_eq(creds.nl_bind(w, sender).ret, 0, "and the sender")
                local port = assert(creds.nl_port(w, reader))
                t:assert_eq(creds.set_passcred(w, reader).ret, 0,
                    "the reader asks for SO_PASSCRED")

                local msg = creds.nlmsg(20, creds.NLM_F_REQUEST, 71, "abcd")
                t:assert_eq(creds.nl_send(w, sender, msg, port).ret, #msg,
                    "one message crosses between the two user sockets")

                local got = assert(creds.recvmsg_with_cmsg(w, reader))
                t:assert_eq(got.cmsg_level, creds.SOL_SOCKET, "SOL_SOCKET ancillary data")
                t:assert_eq(got.cmsg_type, creds.SCM_CREDENTIALS, "of type SCM_CREDENTIALS")
                t:assert(got.creds, "carrying a struct ucred")
                t:assert_eq(got.creds.uid, 4711, "with the sender's projected uid")
                t:assert_eq(got.creds.gid, 4712, "and its projected gid")
                sys.close(w, reader); sys.close(w, sender)
            end)
    end)
