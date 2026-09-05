-- PKM §5.4.1 — The access flow: which token is captured, why nothing is
-- checked on the way down, all-or-nothing granting, the mask that is
-- fixed on the fd at open, per-ioctl bitmask tests, and what an fd
-- carries when it is passed or when the descriptor behind it changes.
--
-- Every case that needs a caller the descriptor does not favour mints
-- one: the agent runs as SYSTEM, and a key whose DACL names SYSTEM
-- alone would otherwise never say no.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")
local kacs = require("helpers.kacs")
local token = require("helpers.token")
local access = require("helpers.access")
local us = require("helpers.unixsock")

local vm = provium:vm("v", "kernel-only"):boot()

local CI = access.ACE_FLAG.CONTAINER_INHERIT
local SOL_SOCKET, SCM_RIGHTS = 1, 1

--- SYSTEM alone, container-inheritable: a key an ordinary caller cannot
--- reach at all.
local SYSTEM_ONLY = lcs.sd({
    access.ace(access.ACE.ALLOWED, lcs.KEY_ALL_ACCESS, kacs.SID.LOCAL_SYSTEM, CI),
})
--- SYSTEM everything, Everyone KEY_READ: a key an ordinary caller may
--- read and no more.
local READ_ONLY = lcs.sd({
    access.ace(access.ACE.ALLOWED, lcs.KEY_ALL_ACCESS, kacs.SID.LOCAL_SYSTEM, CI),
    access.ace(access.ACE.ALLOWED, lcs.RIGHT.KEY_READ, kacs.SID.EVERYONE, CI),
})

local src = lcs.source(vm)
src:key("Machine\\Software\\Test")
src:key("Machine\\Effective", { sd = SYSTEM_ONLY })
src:key("Machine\\Guarded", { sd = SYSTEM_ONLY })
src:key("Machine\\Guarded\\Inner")
src:key("Machine\\ReadOnly", { sd = READ_ONLY })
local FIXED = src:key("Machine\\Fixed", { sd = READ_ONLY })
src:value(FIXED, "Seeded", lcs.TYPE.DWORD, lcs.dword(1))
local REVOKED = src:key("Machine\\Revoked")
src:value(REVOKED, "Seeded", lcs.TYPE.DWORD, lcs.dword(1))
src:key("Machine\\Passed", { sd = SYSTEM_ONLY })
src:key("Machine\\Parent")
src:key("Machine\\Parent\\Child")
assert(src:register())
src:pump()

local w = vm:spawn_worker()

-- A pathname socket the minted principal can reach, for the SCM_RIGHTS
-- case: the registry needs no traverse rights but the filesystem does.
local SOCKS = "/lcs-access-flow"
sys.mkdir_p(vm, SOCKS)
kacs.set_sd(vm, "/", kacs.grant(kacs.ALL_RIGHTS))
kacs.set_sd(vm, SOCKS, kacs.grant(kacs.ALL_RIGHTS))

--- Widen or narrow a key's DACL as SYSTEM.
local function rewrite_dacl(t, path, sd)
    local admin = lcs.open_key(src, w, -1, path, lcs.KEY_ALL_ACCESS)
    t:assert(admin.ret >= 0, "SYSTEM opens " .. path .. ": " .. sys.errname(admin.errno or 0))
    local r = lcs.set_security(src, w, admin.ret, lcs.SI.DACL, sd)
    t:assert_eq(r.ret, 0, "and rewrites its DACL: " .. sys.errname(r.errno or 0))
    sys.close(w, admin.ret)
end

test("LCS captures the calling thread's effective token: with none impersonated, the process primary",
    { spec = "PKM *access-flow.effective-token-capture" }, function(t)
        local primary = lcs.open_key(src, w, -1, "Machine\\Effective", lcs.RIGHT.KEY_READ)
        t:assert(primary.ret >= 0,
            "this process's primary token is SYSTEM and the key names SYSTEM: " ..
            sys.errname(primary.errno or 0))
        sys.close(w, primary.ret)

        token.as_principal(t, vm, { user_sid = token.SID.TEST_USER }, function(w2)
            local other = lcs.open_key(src, w2, -1, "Machine\\Effective", lcs.RIGHT.KEY_READ)
            t:assert_eq(other.errno, sys.E.ACCES,
                "and a process whose primary token is an ordinary user is judged on that token")
        end)
    end)

-- The other half of the capture rule. Every registry call that reaches a
-- served hive blocks in the kernel until the source answers, so the
-- harness must issue it on a thread it spawns for the call — and that
-- thread does not carry the impersonation token set on the caller's own
-- thread. LCS itself does no capturing: `source_open.c` and `key_fd.c`
-- pass `pkm_kacs_current_effective_token_ptr()` into every check, which
-- is the same KACS capture PKM §3.5.1 covers.
test("an impersonation token set on the calling thread is the one LCS captures",
    { spec = "PKM *access-flow.effective-token-capture",
      covered_by = "kunit:",
      skip = "a blocking registry call must be issued on a harness-spawned thread, which " ..
             "does not inherit the caller thread's impersonation token, so no guest can " ..
             "witness the impersonation branch; no LCS KUnit case found — candidate for a " ..
             "new one" },
    function(t) end)

test("no access check happens during the walk: only the final key is evaluated",
    { spec = "PKM *access-flow.no-check-during-walk" }, function(t)
        token.as_principal(t, vm, { user_sid = token.SID.TEST_USER }, function(w2)
            local parent = lcs.open_key(src, w2, -1, "Machine\\Guarded", lcs.RIGHT.KEY_READ)
            t:assert_eq(parent.errno, sys.E.ACCES,
                "the intermediate key's descriptor denies this caller outright")
            local child = lcs.open_key(src, w2, -1, "Machine\\Guarded\\Inner",
                lcs.RIGHT.KEY_READ)
            t:assert(child.ret >= 0,
                "yet its child opens: an ancestor's descriptor confers no protection on its " ..
                "descendants (" .. sys.errname(child.errno or 0) .. ")")
            if child.ret >= 0 then sys.close(w2, child.ret) end
        end)
    end)

test("every requested right must be granted or the open fails with EACCES: no partial grant",
    { spec = "PKM *access-flow.all-or-nothing-or-eacces" }, function(t)
        token.as_principal(t, vm, { user_sid = token.SID.TEST_USER }, function(w2)
            local more = lcs.open_key(src, w2, -1, "Machine\\ReadOnly",
                lcs.RIGHT.KEY_READ | lcs.RIGHT.SET_VALUE)
            t:assert_eq(more.errno, sys.E.ACCES,
                "asking for one right beyond the grant fails the whole open")
            t:assert_eq(more.ret, -1, "and no descriptor comes back: the caller gets nothing")
            local exact = lcs.open_key(src, w2, -1, "Machine\\ReadOnly", lcs.RIGHT.KEY_READ)
            t:assert(exact.ret >= 0, "asking for exactly what is granted succeeds: " ..
                sys.errname(exact.errno or 0))
            sys.close(w2, exact.ret)
        end)
    end)

test("MAXIMUM_ALLOWED is the only way to ask for whatever is available",
    { spec = "PKM *access-flow.maximum-allowed-grants-what-is-available" }, function(t)
        token.as_principal(t, vm, { user_sid = token.SID.TEST_USER }, function(w2)
            local m = lcs.open_key(src, w2, -1, "Machine\\ReadOnly", lcs.RIGHT.MAXIMUM_ALLOWED)
            t:assert(m.ret >= 0, "MAXIMUM_ALLOWED never fails on a key the caller can reach: " ..
                sys.errname(m.errno or 0))
            local q = lcs.query_value(src, w2, m.ret, "Nothing")
            t:assert_eq(q.errno, sys.E.NOENT,
                "the computed set includes KEY_QUERY_VALUE, so the read reaches the source")
            local s = lcs.set_value(nil, w2, m.ret, "X", lcs.TYPE.DWORD, lcs.dword(1))
            t:assert_eq(s.errno, sys.E.ACCES,
                "and stops at what was available: KEY_SET_VALUE was never granted")
            sys.close(w2, m.ret)
        end)
    end)

test("the granted mask is stored on the fd and never changes, even when the descriptor widens",
    { spec = "PKM *access-flow.granted-mask-fixed-at-open" }, function(t)
        token.as_principal(t, vm, { user_sid = token.SID.TEST_USER }, function(w2)
            -- KEY_NOTIFY alone: a right that carries no read.
            local fd = lcs.open_key(src, w2, -1, "Machine\\Fixed", lcs.RIGHT.NOTIFY)
            t:assert(fd.ret >= 0, "the caller opens for KEY_NOTIFY: " ..
                sys.errname(fd.errno or 0))
            local before = lcs.query_value(nil, w2, fd.ret, "Seeded")
            t:assert_eq(before.errno, sys.E.ACCES, "which does not include KEY_QUERY_VALUE")

            rewrite_dacl(t, "Machine\\Fixed", lcs.permissive_sd())

            local after = lcs.query_value(nil, w2, fd.ret, "Seeded")
            t:assert_eq(after.errno, sys.E.ACCES,
                "widening the descriptor does not widen a mask already stored on an fd")
            local fresh = lcs.open_key(src, w2, -1, "Machine\\Fixed", lcs.RIGHT.KEY_READ)
            t:assert(fresh.ret >= 0,
                "while a new open is decided on the new descriptor: " ..
                sys.errname(fresh.errno or 0))
            local read = lcs.query_value(src, w2, fresh.ret, "Seeded")
            t:assert_eq(read.ret, 0, "and reads through it: " .. sys.errname(read.errno or 0))
            sys.close(w2, fresh.ret)
            sys.close(w2, fd.ret)
        end)
    end)

test("a per-ioctl check is a bitmask test against the fd, decided without contacting the source",
    { spec = "PKM *access-flow.per-ioctl-bitmask-test" }, function(t)
        local fd = lcs.open_key(src, w, -1, "Machine\\Software\\Test", lcs.RIGHT.QUERY_VALUE)
        t:assert(fd.ret >= 0, "open for KEY_QUERY_VALUE alone: " .. sys.errname(fd.errno or 0))
        local mark = src:mark()
        local e = lcs.enum_subkeys(nil, w, fd.ret, 0)
        t:assert_eq(e.errno, sys.E.ACCES,
            "REG_IOC_ENUM_SUBKEYS needs KEY_ENUMERATE_SUB_KEYS, which the mask lacks")
        t:assert_eq(#src.log, mark - 1,
            "and LCS returned EACCES without contacting the source or re-reading the descriptor")
        local ok = lcs.query_value(src, w, fd.ret, "Nothing")
        t:assert_eq(ok.errno, sys.E.NOENT,
            "the right the mask does carry passes the bitmask test and reaches the source")
        sys.close(w, fd.ret)
    end)

test("opening relative to a parent fd skips path parsing and AccessCheck for the parent portion",
    { spec = "PKM *access-flow.parent-fd-skips-check" }, function(t)
        local mark = src:mark()
        local abs = lcs.open_key(src, w, -1, "Machine\\Parent\\Child", lcs.RIGHT.KEY_READ)
        t:assert(abs.ret >= 0, "an absolute open: " .. sys.errname(abs.errno or 0))
        local abs_lookups = #src:served(lcs.OP.LOOKUP, mark)
        sys.close(w, abs.ret)

        -- A parent fd granted a right that has nothing to do with
        -- traversal is still a base to open a child from.
        local parent = lcs.open_key(src, w, -1, "Machine\\Parent", lcs.RIGHT.NOTIFY)
        t:assert(parent.ret >= 0, "a parent fd granted only KEY_NOTIFY: " ..
            sys.errname(parent.errno or 0))
        mark = src:mark()
        local rel = lcs.open_key(src, w, parent.ret, "Child", lcs.RIGHT.KEY_READ)
        t:assert(rel.ret >= 0, "opens its child anyway: " .. sys.errname(rel.errno or 0))
        local rel_lookups = #src:served(lcs.OP.LOOKUP, mark)
        t:assert_eq(abs_lookups, 2, "an absolute path is walked component by component")
        t:assert_eq(rel_lookups, 1,
            "a relative one resolves only the child: the parent portion is not parsed or checked")
        sys.close(w, rel.ret)
        sys.close(w, parent.ret)
    end)

test("an fd passed over SCM_RIGHTS carries its granted mask to the recipient",
    { spec = "PKM *access-flow.fd-passing-carries-granted-mask" }, function(t)
        local path = SOCKS .. "/pass.sock"
        local a = vm:spawn_worker() -- SYSTEM: opens the key and sends the fd
        local ok, err = pcall(function()
            local srv = assert(us.socket(a, us.AF_UNIX, us.SOCK.STREAM))
            t:assert_eq(us.bind(a, srv, path).ret, 0, "bind")
            t:assert_eq(us.listen(a, srv).ret, 0, "listen")
            token.as_principal(t, vm, { user_sid = token.SID.TEST_USER }, function(b)
                local cli = assert(us.socket(b, us.AF_UNIX, us.SOCK.STREAM))
                t:assert_eq(us.connect(b, cli, path).ret, 0, "connect")
                local acc = assert(us.accept(a, srv))

                local mine = lcs.open_key(src, b, -1, "Machine\\Passed", lcs.RIGHT.KEY_READ)
                t:assert_eq(mine.errno, sys.E.ACCES,
                    "the recipient's own token would not have passed AccessCheck")

                local kfd = lcs.open_key(src, a, -1, "Machine\\Passed", lcs.RIGHT.KEY_READ)
                t:assert(kfd.ret >= 0, "the opener is granted KEY_READ: " ..
                    sys.errname(kfd.errno or 0))
                local control = string.pack("<I8I4I4i4", 16 + 4, SOL_SOCKET, SCM_RIGHTS, kfd.ret)
                    .. "\0\0\0\0"
                t:assert_eq(us.sendmsg(a, acc, "k", { raw_control = control }).ret, 1,
                    "and passes the fd")
                local got = us.recvmsg(b, cli, 8, { cmsg = us.cmsg_space(4) })
                local rights
                for _, c in ipairs(got.cmsgs) do
                    if c.level == SOL_SOCKET and c.type == SCM_RIGHTS then rights = c end
                end
                t:assert(rights, "the recipient gets an SCM_RIGHTS cmsg")
                local recv_fd = string.unpack("<i4", rights.data)

                local q = lcs.query_value(src, b, recv_fd, "Nothing")
                t:assert_eq(q.errno, sys.E.NOENT,
                    "and reads through it on the mask the original opener was granted")
                local s = lcs.set_value(nil, b, recv_fd, "X", lcs.TYPE.DWORD, lcs.dword(1))
                t:assert_eq(s.errno, sys.E.ACCES,
                    "and no further: the mask travelled with the fd, not the opener's identity")
                sys.close(b, recv_fd)
                sys.close(a, kfd.ret)
                sys.close(a, acc)
            end)
            sys.close(a, srv)
        end)
        a:kill(); a:join()
        if not ok then error(err, 0) end
    end)

test("a descriptor change takes effect for future opens and does not revoke an existing fd",
    { spec = "PKM *access-flow.descriptor-change-does-not-revoke-fd" }, function(t)
        token.as_principal(t, vm, { user_sid = token.SID.TEST_USER }, function(w2)
            local fd = lcs.open_key(src, w2, -1, "Machine\\Revoked", lcs.RIGHT.KEY_READ)
            t:assert(fd.ret >= 0, "the key is open to everyone to begin with: " ..
                sys.errname(fd.errno or 0))
            local before = lcs.query_value(src, w2, fd.ret, "Seeded")
            t:assert_eq(before.ret, 0, "and readable: " .. sys.errname(before.errno or 0))

            rewrite_dacl(t, "Machine\\Revoked", SYSTEM_ONLY)

            local again = lcs.open_key(src, w2, -1, "Machine\\Revoked", lcs.RIGHT.KEY_READ)
            t:assert_eq(again.errno, sys.E.ACCES, "a new open is decided on the new descriptor")
            local after = lcs.query_value(src, w2, fd.ret, "Seeded")
            t:assert_eq(after.ret, 0,
                "while the fd that already exists keeps the mask it was granted at open: " ..
                sys.errname(after.errno or 0))
            sys.close(w2, fd.ret)
        end)
    end)
