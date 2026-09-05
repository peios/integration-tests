-- PKM §3.5.3, per-message identity — the conveyed-identity register on
-- each end of a connection, the two ways a sender conveys identity with
-- its data (`KACS_SO_PASS_TOKEN` and an explicit `KACS_SCM_TOKEN`
-- cmsg), and the rules that keep the register exact on a byte stream.
--
-- The register is a per-end pointer at the identity the data consumed
-- so far was sent under. Everything below is about where it points and
-- when it moves, so the cases send under deliberately different
-- identities and read them back one at a time.
--
-- The sender is a worker holding SeImpersonatePrivilege, so it can
-- attach tokens for principals other than itself; without it every such
-- attach would fail loudly (§3.5.3) rather than convey.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local token = require("helpers.token")
local us = require("helpers.unixsock")

local vm = provium:vm("v", "kernel-only"):boot()

local P = token.PRIV
local L = token.LEVEL
local MINTER = token.bit(P.TCB) | token.bit(P.CREATE_TOKEN)
local IMPERSONATE = token.bit(P.IMPERSONATE)
local SERVER_PRIVS = MINTER | IMPERSONATE
local USER_A, USER_B = token.SID.TEST_USER_2, token.sid(5, 21, 1000, 2000, 3000, 1109)

local SOCKS = "/imp-msg"
sys.mkdir_p(vm, SOCKS)
kacs.set_sd(vm, SOCKS, kacs.grant(kacs.ALL_RIGHTS))
kacs.set_sd(vm, "/", kacs.grant(kacs.ALL_RIGHTS))

local next_name = 0
local function sock_path()
    next_name = next_name + 1
    return SOCKS .. "/s" .. next_name
end

--- A connected stream pair inside `who`: listener, accepted end, client.
local function pair_of(t, who, stype)
    local path = sock_path()
    local srv, acc, cli = us.connected(who, path, stype)
    t:assert(srv, "a connected pair on " .. path .. ": " .. tostring(acc))
    return srv, acc, cli
end

--- Run `fn(worker)` as a server that can mint and attach other
--- principals' tokens.
local function as_server(t, fn, spec)
    local s = { privs_present = SERVER_PRIVS, privs_enabled = SERVER_PRIVS }
    for k, v in pairs(spec or {}) do s[k] = v end
    token.as_principal(t, vm, s, fn)
end

local function client_token(w, user, level)
    local fd, errno = token.mint(w, { user_sid = user,
        token_type = token.TYPE.IMPERSONATION,
        impersonation_level = level or L.IMPERSONATION })
    assert(fd, "mint " .. sys.errname(errno or 0))
    return fd
end

local function user_of(who, fd) return token.query(who, fd, token.CLASS.USER) end
local function register_user(t, who, fd)
    local peer, e = us.peer_token(who, fd)
    t:assert(peer, "KACS_SO_PEER_TOKEN: " .. us.errname(e or 0))
    local user = user_of(who, peer)
    sys.close(who, peer)
    return user
end

-- The register ------------------------------------------------------------------

test("the connect-time capture is the register's first entry",
    { spec = "PKM *imp.register.connect-capture-is-first-entry" }, function(t)
        as_server(t, function(w)
            local srv, acc, cli = pair_of(t, w)
            t:assert_eq(register_user(t, w, acc), token.SID.TEST_USER,
                "before any data, the accepted end's register is the connect capture")
            -- And the connecting end's is the listener's identity.
            t:assert_eq(register_user(t, w, cli), token.SID.TEST_USER,
                "as is the connecting end's, from listen()")
            sys.close(w, srv); sys.close(w, acc); sys.close(w, cli)
        end)
    end)

test("the register is anchored at the read position, never at arrival",
    { spec = "PKM *imp.register.anchored-at-read-position" }, function(t)
        as_server(t, function(w)
            local srv, acc, cli = pair_of(t, w)
            local a = client_token(w, USER_A)
            -- One message with no identity of its own, then one carrying A.
            t:assert_eq(us.sendmsg(w, cli, "plain").ret, 5, "the first message is sent")
            t:assert_eq(us.sendmsg(w, cli, "underA", { token_fd = a }).ret, 6,
                "and a second, under A, is queued behind it")
            t:assert_eq(register_user(t, w, acc), token.SID.TEST_USER,
                "A is queued but unread, so the register has not moved")
            local first = us.recvmsg(w, acc, 32)
            t:assert_eq(first.data, "plain", "the reader consumes only the first message")
            t:assert_eq(register_user(t, w, acc), token.SID.TEST_USER,
                "and the register still names the connect capture")
            local second = us.recvmsg(w, acc, 32)
            t:assert_eq(second.data, "underA", "the reader reaches A's bytes")
            t:assert_eq(register_user(t, w, acc), USER_A, "and only now does the register move")
            for _, fd in ipairs({ a, srv, acc, cli }) do sys.close(w, fd) end
            if second.tokens[1] then sys.close(w, second.tokens[1]) end
        end)
    end)

test("KACS_SO_PEER_TOKEN returns a fresh fd to an immutable snapshot each time",
    { spec = "PKM *imp.peer-token.immutable-snapshot" }, function(t)
        as_server(t, function(w)
            local srv, acc, cli = pair_of(t, w)
            local first = assert(us.peer_token(w, acc))
            local second = assert(us.peer_token(w, acc))
            t:assert_neq(first, second, "two calls return two descriptors")
            t:assert_eq(user_of(w, first), user_of(w, second), "naming the same identity")
            -- Move the register on, and the old snapshot is unchanged.
            local a = client_token(w, USER_A)
            t:assert_eq(us.sendmsg(w, cli, "x", { token_fd = a }).ret, 1, "a message under A")
            local got = us.recvmsg(w, acc, 8)
            t:assert_eq(got.data, "x", "is read")
            local third = assert(us.peer_token(w, acc))
            t:assert_eq(user_of(w, third), USER_A, "so a later call names a different token")
            t:assert_eq(user_of(w, first), token.SID.TEST_USER,
                "while the token the first call named never changed")
            for _, fd in ipairs({ first, second, third, a, srv, acc, cli }) do sys.close(w, fd) end
            if got.tokens[1] then sys.close(w, got.tokens[1]) end
        end)
    end)

test("recvmsg followed by getsockopt gives the identity of what was just read",
    { spec = "PKM *imp.register.getsockopt-after-read" }, function(t)
        as_server(t, function(w)
            local srv, acc, cli = pair_of(t, w)
            local a, b = client_token(w, USER_A), client_token(w, USER_B)
            t:assert_eq(us.sendmsg(w, cli, "aa", { token_fd = a }).ret, 2, "a message under A")
            t:assert_eq(us.sendmsg(w, cli, "bb", { token_fd = b }).ret, 2, "and one under B")
            -- A handler that supplies no ancillary room still has the
            -- register after each read.
            local first = us.recvmsg(w, acc, 8, { cmsg = 0 })
            t:assert_eq(first.data, "aa", "the first read")
            t:assert_eq(#first.cmsgs, 0, "delivers no ancillary data")
            t:assert_eq(register_user(t, w, acc), USER_A, "but the register names A")
            local second = us.recvmsg(w, acc, 8, { cmsg = 0 })
            t:assert_eq(second.data, "bb", "the second read")
            t:assert_eq(register_user(t, w, acc), USER_B, "and the register names B")
            for _, fd in ipairs({ a, b, srv, acc, cli }) do sys.close(w, fd) end
        end)
    end)

test("MSG_PEEK does not advance the register; read and splice do",
    { spec = "PKM *imp.register.advances-on-consumption-only" }, function(t)
        as_server(t, function(w)
            local srv, acc, cli = pair_of(t, w)
            local a, b = client_token(w, USER_A), client_token(w, USER_B)
            t:assert_eq(us.sendmsg(w, cli, "aaaa", { token_fd = a }).ret, 4, "a message under A")
            local peeked = us.recvmsg(w, acc, 8, { flags = us.MSG.PEEK })
            t:assert_eq(peeked.data, "aaaa", "MSG_PEEK returns the bytes")
            t:assert_eq(register_user(t, w, acc), token.SID.TEST_USER,
                "without moving the register")
            -- read(2) consumes, and the register moves with the position.
            local data = sys.read(w, acc, 8)
            t:assert_eq(data, "aaaa", "read(2) consumes the same bytes")
            t:assert_eq(register_user(t, w, acc), USER_A,
                "and advances the register just as recvmsg does")
            -- splice(2) consumes too.
            t:assert_eq(us.sendmsg(w, cli, "bbbb", { token_fd = b }).ret, 4, "a message under B")
            local rd, wr = sys.pipe(w)
            t:assert(rd, "pipe2: " .. sys.errname(wr or 0))
            local spliced = sys.splice(w, acc, wr, 8, 0)
            t:assert_eq(spliced.ret, 4, "splice(2) moves the bytes: " .. sys.errname(spliced.errno))
            t:assert_eq(sys.read(w, rd, 8), "bbbb", "which arrive in the pipe")
            t:assert_eq(register_user(t, w, acc), USER_B,
                "and the register followed the consumption")
            for _, fd in ipairs({ a, b, rd, wr, srv, acc, cli }) do sys.close(w, fd) end
        end)
    end)

-- Sending -------------------------------------------------------------------------

test("with KACS_SO_PASS_TOKEN every send carries the sender's effective token",
    { spec = "PKM *imp.pass-token.every-send-carries-effective" }, function(t)
        as_server(t, function(w)
            local srv, acc, cli = pair_of(t, w)
            t:assert_eq(us.set_pass_token(w, cli, true).ret, 0, "the sender turns it on")
            t:assert_eq(us.pass_token(w, cli), 1, "and reads it back")
            local a = client_token(w, USER_A)
            -- Impersonate A, write, revert, write again — with no change
            -- to the library doing the writing.
            t:assert_eq(token.impersonate(w, a).ret, 0, "the thread impersonates A")
            t:assert_eq(us.sendmsg(w, cli, "one").ret, 3, "and writes")
            t:assert_eq(token.revert(w).ret, 0, "then reverts")
            t:assert_eq(us.sendmsg(w, cli, "two").ret, 3, "and writes again")
            local first = us.recvmsg(w, acc, 8)
            t:assert_eq(first.data, "one", "the first write")
            t:assert_eq(register_user(t, w, acc), USER_A, "conveyed A")
            local second = us.recvmsg(w, acc, 8)
            t:assert_eq(second.data, "two", "the second write")
            t:assert_eq(register_user(t, w, acc), token.SID.TEST_USER,
                "conveyed the sender's own identity")
            for _, fd in ipairs({ a, srv, acc, cli }) do sys.close(w, fd) end
            for _, r in ipairs({ first, second }) do
                if r.tokens[1] then sys.close(w, r.tokens[1]) end
            end
        end)
    end)

test("the automatic derivation is cached, so a run of sends under one identity costs one",
    { spec = "PKM *imp.pass-token.derivation-cached" }, function(t)
        as_server(t, function(w)
            local srv, acc, cli = pair_of(t, w)
            t:assert_eq(us.set_pass_token(w, cli, true).ret, 0, "KACS_SO_PASS_TOKEN on")
            for _, part in ipairs({ "aaa", "bbb", "ccc" }) do
                t:assert_eq(us.sendmsg(w, cli, part).ret, 3, "send " .. part)
            end
            -- One derivation means one token object across all three
            -- sends, so there is no identity boundary between them and a
            -- single read returns the lot.
            local got = us.recvmsg(w, acc, 32)
            t:assert_eq(got.data, "aaabbbccc",
                "three sends under one identity read back as one run")
            t:assert_eq(#got.tokens, 1, "with a single ancillary token for the whole run")
            -- A different identity replaces the cache entry.
            local a = client_token(w, USER_A)
            t:assert_eq(token.impersonate(w, a).ret, 0, "the sender becomes A")
            t:assert_eq(us.sendmsg(w, cli, "ddd").ret, 3, "and sends")
            token.revert(w)
            t:assert_eq(us.sendmsg(w, cli, "eee").ret, 3, "then sends as itself again")
            local under_a = us.recvmsg(w, acc, 32)
            t:assert_eq(under_a.data, "ddd", "the identity change ends the run")
            local own = us.recvmsg(w, acc, 32)
            t:assert_eq(own.data, "eee", "and the next identity starts a new one")
            for _, fd in ipairs({ a, srv, acc, cli }) do sys.close(w, fd) end
            for _, r in ipairs({ got, under_a, own }) do
                if r.tokens[1] then sys.close(w, r.tokens[1]) end
            end
        end)
    end)

test("a KACS_SCM_TOKEN attach is gated exactly as impersonating that token would be",
    { spec = "PKM *imp.scm-token.gated-as-impersonation" }, function(t)
        as_server(t, function(w)
            local srv, acc, cli = pair_of(t, w)
            -- The fd has to carry TOKEN_IMPERSONATE.
            local a = client_token(w, USER_A)
            local query_only = assert(token.duplicate(w, a, { access = token.RIGHT.QUERY,
                token_type = token.TYPE.IMPERSONATION, impersonation_level = L.IMPERSONATION }))
            local refused = us.sendmsg(w, cli, "no", { token_fd = query_only })
            t:assert(refused.ret < 0, "a handle without TOKEN_IMPERSONATE cannot be attached")
            t:assert_eq(refused.errno, sys.E.ACCES, "EACCES")
            -- A primary token is derived to an impersonation token first,
            -- at the lower of the end's level and its own.
            local primary = assert(token.mint(w, { user_sid = USER_A,
                impersonation_level = L.DELEGATION }))
            t:assert_eq(us.set_level(w, cli, L.IDENTIFICATION).ret, 0,
                "the sending end is at Identification")
            local sent = us.sendmsg(w, cli, "prim", { token_fd = primary })
            t:assert_eq(sent.ret, 4, "a primary token attaches: " .. sys.errname(sent.errno))
            local got = us.recvmsg(w, acc, 8)
            t:assert_eq(got.data, "prim", "and the data arrives")
            t:assert_eq(#got.tokens, 1, "with a token")
            t:assert_eq(token.query_u32(w, got.tokens[1], token.CLASS.TYPE),
                token.TYPE.IMPERSONATION, "derived to an impersonation token")
            t:assert_eq(token.query_u32(w, got.tokens[1], token.CLASS.IMPERSONATION_LEVEL),
                L.IDENTIFICATION, "at the end's level")
            for _, fd in ipairs({ a, query_only, primary, got.tokens[1], srv, acc, cli }) do
                sys.close(w, fd)
            end
        end)
    end)

test("an attach the gates would cap fails with EPERM rather than downgrading",
    { spec = "PKM *imp.scm-token.cap-fails-eperm" }, function(t)
        -- A sender without SeImpersonatePrivilege: installing another
        -- user's token would silently cap to Identification, so attaching
        -- it has to fail loudly instead.
        as_server(t, function(w)
            local srv, acc, cli = pair_of(t, w)
            local other = client_token(w, USER_A, L.IMPERSONATION)
            local r = us.sendmsg(w, cli, "cap", { token_fd = other })
            t:assert(r.ret < 0, "the attach is refused outright")
            t:assert_eq(r.errno, sys.E.PERM, "EPERM, not a silent downgrade")
            -- The same token at its own capped level attaches, because
            -- there is then nothing to cap.
            local at_ident = client_token(w, USER_A, L.IDENTIFICATION)
            local ok = us.sendmsg(w, cli, "ok", { token_fd = at_ident })
            t:assert_eq(ok.ret, 2, "at Identification it attaches: " .. sys.errname(ok.errno))
            local got = us.recvmsg(w, acc, 8)
            t:assert_eq(#got.tokens, 1, "and is conveyed")
            for _, fd in ipairs({ other, at_ident, got.tokens[1], srv, acc, cli }) do
                sys.close(w, fd)
            end
        end, { privs_present = MINTER, privs_enabled = MINTER })
    end)

test("an Anonymous-level token attaches with no gate at all",
    { spec = "PKM *imp.scm-token.anonymous-attaches-ungated" }, function(t)
        -- The same sender that could not attach another user's
        -- Impersonation-level token attaches an Anonymous-level one.
        as_server(t, function(w)
            local srv, acc, cli = pair_of(t, w)
            local anon = client_token(w, USER_A, L.ANONYMOUS)
            local r = us.sendmsg(w, cli, "anon", { token_fd = anon })
            t:assert_eq(r.ret, 4, "the attach succeeds: " .. sys.errname(r.errno))
            local got = us.recvmsg(w, acc, 8)
            t:assert_eq(#got.tokens, 1, "and the token is conveyed")
            t:assert_eq(token.query_u32(w, got.tokens[1], token.CLASS.IMPERSONATION_LEVEL),
                L.ANONYMOUS, "at Anonymous level")
            for _, fd in ipairs({ anon, got.tokens[1], srv, acc, cli }) do sys.close(w, fd) end
        end, { privs_present = MINTER, privs_enabled = MINTER })
    end)

test("at most one token per message",
    { spec = "PKM *imp.scm-token.one-per-message" }, function(t)
        as_server(t, function(w)
            local srv, acc, cli = pair_of(t, w)
            local a, b = client_token(w, USER_A), client_token(w, USER_B)
            local two = us.token_cmsg(a) .. us.token_cmsg(b)
            local r = us.sendmsg(w, cli, "two", { raw_control = two })
            t:assert(r.ret < 0, "two KACS_SCM_TOKEN cmsgs in one message are refused")
            t:assert_eq(r.errno, sys.E.INVAL, "EINVAL")
            local one = us.sendmsg(w, cli, "one", { token_fd = a })
            t:assert_eq(one.ret, 3, "one is accepted: " .. sys.errname(one.errno))
            local got = us.recvmsg(w, acc, 8)
            t:assert_eq(#got.tokens, 1, "and delivers exactly one token")
            for _, fd in ipairs({ a, b, got.tokens[1], srv, acc, cli }) do sys.close(w, fd) end
        end)
    end)

-- Receiving --------------------------------------------------------------------------

test("every fragment a large stream write produces carries the same conveyed identity",
    { spec = "PKM *imp.receive.identity-on-every-fragment" }, function(t)
        as_server(t, function(w)
            local srv, acc, cli = pair_of(t, w)
            t:assert_eq(us.set_pass_token(w, cli, true).ret, 0, "KACS_SO_PASS_TOKEN on")
            local a = client_token(w, USER_A)
            t:assert_eq(token.impersonate(w, a).ret, 0, "the sender is A")
            local BULK = 64 * 1024
            local sent = us.sendmsg(w, cli, string.rep("z", BULK))
            token.revert(w)
            t:assert_eq(sent.ret, BULK, "a single large write goes out whole: "
                .. sys.errname(sent.errno))
            -- The write spans many skbs; every read of it is under A, and
            -- no read stops early on an identity boundary.
            local total, reads, cmsgs = 0, 0, 0
            while total < BULK do
                local got = us.recvmsg(w, acc, 8192)
                t:assert(got.ret > 0, "read " .. reads .. ": " .. sys.errname(got.errno))
                total = total + got.ret
                reads = reads + 1
                cmsgs = cmsgs + #got.tokens
                for _, fd in ipairs(got.tokens) do sys.close(w, fd) end
                t:assert_eq(register_user(t, w, acc), USER_A,
                    "the register names A after read " .. reads)
            end
            t:assert_eq(total, BULK, "every byte arrives")
            t:assert(reads > 1, "across more than one read (" .. reads .. ")")
            t:assert_eq(cmsgs, 1,
                "and the identity changed exactly once, at the start of the run")
            for _, fd in ipairs({ a, srv, acc, cli }) do sys.close(w, fd) end
        end)
    end)

test("a stream read stops at an identity boundary rather than gluing the two together",
    { spec = "PKM *imp.receive.read-stops-at-identity-boundary" }, function(t)
        as_server(t, function(w)
            local srv, acc, cli = pair_of(t, w)
            local a, b = client_token(w, USER_A), client_token(w, USER_B)
            t:assert_eq(us.sendmsg(w, cli, "aaaa", { token_fd = a }).ret, 4, "four bytes under A")
            t:assert_eq(us.sendmsg(w, cli, "bbbb", { token_fd = b }).ret, 4, "four more under B")
            local first = us.recvmsg(w, acc, 64)
            t:assert_eq(first.data, "aaaa",
                "a 64-byte read returns only the bytes conveyed under A")
            t:assert_eq(register_user(t, w, acc), USER_A, "and the register names A")
            local second = us.recvmsg(w, acc, 64)
            t:assert_eq(second.data, "bbbb", "the next read picks up B's")
            t:assert_eq(register_user(t, w, acc), USER_B, "and moves the register to B")
            for _, r in ipairs({ first, second }) do
                for _, fd in ipairs(r.tokens) do sys.close(w, fd) end
            end
            -- On SOCK_SEQPACKET one send is one message and one identity,
            -- which is why it is the recommended type.
            local qsrv, qacc, qcli = pair_of(t, w, us.SOCK.SEQPACKET)
            t:assert_eq(us.sendmsg(w, qcli, "aaaa", { token_fd = a }).ret, 4, "a seqpacket under A")
            t:assert_eq(us.sendmsg(w, qcli, "bbbb", { token_fd = b }).ret, 4, "and one under B")
            local q1 = us.recvmsg(w, qacc, 64)
            t:assert_eq(q1.data, "aaaa", "the message boundary is the identity boundary")
            local q2 = us.recvmsg(w, qacc, 64)
            t:assert_eq(q2.data, "bbbb", "one message, one identity")
            for _, r in ipairs({ q1, q2 }) do
                for _, fd in ipairs(r.tokens) do sys.close(w, fd) end
            end
            for _, fd in ipairs({ a, b, srv, acc, cli, qsrv, qacc, qcli }) do sys.close(w, fd) end
        end)
    end)

test("a token cmsg is delivered only when there is room and the identity changed",
    { spec = "PKM *imp.cmsg.delivered-on-identity-change" }, function(t)
        as_server(t, function(w)
            local srv, acc, cli = pair_of(t, w)
            local a, b = client_token(w, USER_A), client_token(w, USER_B)
            -- Room supplied and the identity differs: delivered.
            t:assert_eq(us.sendmsg(w, cli, "a1", { token_fd = a }).ret, 2, "a message under A")
            local first = us.recvmsg(w, acc, 8)
            t:assert_eq(#first.tokens, 1, "the cmsg is delivered")
            t:assert_eq(user_of(w, first.tokens[1]), USER_A, "naming A")
            t:assert(not first.ctrunc, "and MSG_CTRUNC is not set")
            sys.close(w, first.tokens[1])
            -- Same identity as the register: nothing delivered.
            t:assert_eq(us.sendmsg(w, cli, "a2", { token_fd = a }).ret, 2, "a second under A")
            local second = us.recvmsg(w, acc, 8)
            t:assert_eq(second.data, "a2", "the data arrives")
            t:assert_eq(#second.tokens, 0, "with no cmsg — the register already names A")
            t:assert(not second.ctrunc, "and no MSG_CTRUNC")
            -- A token due with too little room for it: MSG_CTRUNC.
            t:assert_eq(us.sendmsg(w, cli, "b1", { token_fd = b }).ret, 2, "a message under B")
            local cramped = us.recvmsg(w, acc, 8, { cmsg = 8 })
            t:assert_eq(cramped.data, "b1", "the data still arrives")
            t:assert_eq(#cramped.cmsgs, 0, "with no ancillary data")
            t:assert(cramped.ctrunc, "and MSG_CTRUNC set, because a token was due")
            -- No token due and the same cramped buffer: no MSG_CTRUNC.
            t:assert_eq(us.sendmsg(w, cli, "b2", { token_fd = b }).ret, 2, "another under B")
            local quiet = us.recvmsg(w, acc, 8, { cmsg = 8 })
            t:assert_eq(quiet.data, "b2", "the data arrives")
            t:assert(not quiet.ctrunc, "and nothing was due, so no MSG_CTRUNC")
            for _, fd in ipairs({ a, b, srv, acc, cli }) do sys.close(w, fd) end
        end)
    end)
