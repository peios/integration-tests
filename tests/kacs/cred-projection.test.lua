-- PKM §3.10.1 — credential projection: the numbers an unmodified Linux
-- program reads (getuid, getgid, getgroups) are copied off the token
-- when it is installed, one way only, and follow the *effective* token
-- so that a service acting for a client creates the client's files.
--
-- Everything here is observed from a worker running a minted principal:
-- the agent is SYSTEM, and SYSTEM's projection is uid 0, which proves
-- nothing about where the number came from. `token.build_spec` carries
-- `projected_uid`, `projected_gid` and `supplementary_gids`, so a test
-- names the numbers it expects to see.
--
-- The tmpfs at /mt is what makes file ownership observable: rootfs is a
-- deny-missing mount whose objects carry no descriptors, so a principal
-- cannot traverse it until the agent stamps one on `/`.

local sys = require("helpers.sys")
local token = require("helpers.token")
local kacs = require("helpers.kacs")
local creds = require("helpers.creds")

local vm = provium:vm("vcredproj", "kernel-only"):boot()

local CREATE = token.bit(token.PRIV.CREATE_TOKEN)
local IMPERSONATE = token.bit(token.PRIV.IMPERSONATE)
local ENABLED = token.GROUP.MANDATORY | token.GROUP.ENABLED_BY_DEFAULT | token.GROUP.ENABLED

-- A filesystem a principal can reach and write, so the uid a file lands
-- with is readable back.
assert(kacs.new_mount(vm, "tmpfs", "/mt", kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL))
assert(kacs.set_sd(vm, "/mt", kacs.grant(kacs.ALL_RIGHTS)).ret == 0)
assert(kacs.set_sd(vm, "/", kacs.grant(kacs.ALL_RIGHTS)).ret == 0)

--- Create a file at `path` as `who` and return its stat, or nil.
local function create_as(who, path)
    local fd, errno = sys.open(who, path, sys.O.CREAT | sys.O.RDWR,
        tonumber("644", 8))
    if not fd then return nil, errno end
    sys.close(who, fd)
    return sys.stat(vm, path)
end

test("installing a token sets the process's Linux credentials to match",
    { spec = "PKM *cred.projection.on-token-install" }, function(t)
        local worker = vm:spawn_worker()
        local ok, err = pcall(function()
            t:assert_eq(creds.getuid(worker), 0,
                "the worker starts as the agent's identity, uid 0")
            local fd, sid = token.mint(worker, {
                projected_uid = 2468, projected_gid = 2469,
                supplementary_gids = { 90, 91 },
            })
            t:assert(fd, "a principal mints: " .. sys.errname(sid or 0))
            t:assert_eq(token.install(worker, fd).ret, 0, "and installs")
            sys.close(worker, fd)
            t:assert_eq(creds.getuid(worker), 2468, "getuid is now the token's projected uid")
            t:assert_eq(creds.geteuid(worker), 2468, "and so is geteuid")
            t:assert_eq(creds.getgid(worker), 2469, "getgid is the projected gid")
            t:assert_eq(creds.getegid(worker), 2469, "and so is getegid")
            t:assert_eq(creds.groups_string(creds.getgroups(worker)), "[90,91]",
                "the supplementary groups came across too")
        end)
        worker:kill(); worker:join()
        if not ok then error(err, 0) end
    end)

test("the numbers are the token's own precomputed fields, not a lookup",
    { spec = "PKM *cred.projection.uid-from-token" }, function(t)
        -- Two principals differing only in the projected values: the
        -- same user SID, the same groups. If KACS resolved anything it
        -- would resolve them alike; it copies, so they differ.
        local seen = {}
        for _, want in ipairs({ { 7001, 7002, { 300, 301, 302 } },
                                { 7101, 7102, { 400 } } }) do
            token.as_principal(t, vm, {
                projected_uid = want[1], projected_gid = want[2],
                supplementary_gids = want[3],
            }, function(w)
                t:assert_eq(creds.getuid(w), want[1], "getuid is the user SID's projected uid")
                t:assert_eq(creds.getgid(w), want[2], "getgid is the primary group SID's projected gid")
                t:assert_eq(creds.groups_string(creds.getgroups(w)),
                    creds.groups_string(want[3]),
                    "one projected supplementary gid per group SID, in order")
                seen[#seen + 1] = creds.getuid(w)
            end)
        end
        t:assert_neq(seen[1], seen[2],
            "the same user SID projects to whatever the token says")
    end)

test("65534 is the anonymous sentinel, not a fallback",
    { spec = "PKM *cred.projection.anonymous-sentinel",
      covered_by = "kunit:pkm_kunit_signing",
      skip = "the boot anonymous token is never installable on a guest task, " ..
             "and an invalid token pointer cannot be presented from userspace; " ..
             "runs under pkm_kunit_boot_anonymous_defaults" },
    function(t) end)

test("a projected UID of 0 is refused for any user SID but SYSTEM",
    { spec = "PKM *cred.projection.uid0-system-only" }, function(t)
        local fd, errno = token.mint(vm, { projected_uid = 0 })
        t:assert(not fd, "an ordinary user projecting uid 0 is refused: "
            .. sys.errname(errno or 0))
        t:assert_eq(errno, sys.E.INVAL, "EINVAL")
        local ok = token.mint(vm, { projected_uid = 0,
            user_sid = token.SID.LOCAL_SYSTEM })
        t:assert(ok, "S-1-5-18 may project uid 0")
        sys.close(vm, ok)
        -- And the same for a group: the invariant is about the uid slot.
        local gid_ok = token.mint(vm, { projected_uid = 1234, projected_gid = 0 })
        t:assert(gid_ok, "the gid slot carries no such rule")
        sys.close(vm, gid_ok)
    end)

test("projection is one-way: no credential change reaches the token",
    { spec = "PKM *cred.projection.one-way" }, function(t)
        token.as_principal(t, vm, {
            projected_uid = 5501, projected_gid = 5502,
            supplementary_gids = { 800, 801 },
        }, function(w)
            local own = assert(token.open_self(w, token.RIGHT.QUERY))
            local user_before = token.query(w, own, token.CLASS.USER)
            local groups_before = token.query(w, own, token.CLASS.GROUPS)
            local proj_before = token.query(w, own,
                token.CLASS.PROJECTED_SUPPLEMENTARY_GIDS)

            t:assert_eq(creds.setuid(w, 0).ret, 0, "setuid(0) returns success")
            t:assert_eq(creds.setgid(w, 0).ret, 0, "setgid(0) returns success")
            t:assert_eq(creds.setgroups(w, { 4242 }).ret, 0, "setgroups returns success")

            t:assert_eq(token.query(w, own, token.CLASS.USER), user_before,
                "the token's user SID is untouched")
            t:assert_eq(token.query(w, own, token.CLASS.GROUPS), groups_before,
                "so are its groups")
            t:assert_eq(token.query(w, own, token.CLASS.PROJECTED_SUPPLEMENTARY_GIDS),
                proj_before, "and its projected supplementary gids")
            t:assert_eq(creds.getuid(w), 5501,
                "and the credential still answers with the token's number")
            sys.close(w, own)
        end)
    end)

test("every group projects regardless of enabled state, and adjusting them recalculates nothing",
    { spec = "PKM *cred.projection.all-groups" }, function(t)
        token.as_principal(t, vm, {
            groups = {
                { sid = token.SID.EVERYONE, attributes = ENABLED },
                { sid = token.SID.TEST_GROUP,
                  attributes = token.GROUP.ENABLED_BY_DEFAULT | token.GROUP.ENABLED },
                -- Present but not enabled: it still projects.
                { sid = token.SID.TEST_GROUP_2, attributes = 0 },
            },
            supplementary_gids = { 700, 701, 702 },
        }, function(w)
            t:assert_eq(creds.groups_string(creds.getgroups(w)), "[700,701,702]",
                "a group that is not enabled is projected all the same")
            local own = assert(token.open_self(w,
                token.RIGHT.ADJUST_GROUPS | token.RIGHT.QUERY))
            -- Disable the second caller group, then enable it again.
            t:assert_eq(token.adjust_groups(w, own, { { 2, 0 } }).ret, 0,
                "AdjustTokenGroups disables a group")
            t:assert_eq(creds.groups_string(creds.getgroups(w)), "[700,701,702]",
                "the projection did not move")
            t:assert_eq(token.adjust_groups(w, own, { { 1, 0 } }).ret, 0,
                "and disables another")
            t:assert_eq(creds.groups_string(creds.getgroups(w)), "[700,701,702]",
                "still unmoved")
            sys.close(w, own)
        end)
    end)

test("projected credentials follow the effective token, so an impersonating service creates the client's files",
    { spec = "PKM *cred.projection.effective-token" }, function(t)
        token.as_principal(t, vm, {
            privs_present = CREATE | IMPERSONATE, privs_enabled = CREATE | IMPERSONATE,
            projected_uid = 3001, projected_gid = 3002,
        }, function(w, session)
            local client = token.create(w, {
                auth_id = session,
                token_type = token.TYPE.IMPERSONATION,
                impersonation_level = token.LEVEL.IMPERSONATION,
                projected_uid = 9001, projected_gid = 9002,
            })
            t:assert(client, "the service mints a client token")
            local before = create_as(w, "/mt/effective-before")
            t:assert(before, "the service creates a file as itself")
            t:assert_eq(before.uid, 3001, "owned by the service's projected uid")
            t:assert_eq(before.gid, 3002, "and its projected gid")

            t:assert_eq(token.impersonate(w, client).ret, 0, "it impersonates the client")
            local during = create_as(w, "/mt/effective-during")
            t:assert(during, "and creates a file while impersonating")
            t:assert_eq(during.uid, 9001, "owned by the *client's* projected uid")
            t:assert_eq(during.gid, 9002, "and the client's projected gid")

            t:assert_eq(token.revert(w).ret, 0, "it reverts")
            local after = create_as(w, "/mt/effective-after")
            t:assert_eq(after.uid, 3001, "and is the service again")
            sys.close(w, client)
        end)
    end)

test("during impersonation getuid names the service and current_fsuid names the client",
    { spec = "PKM *cred.projection.getuid-vs-fsuid" }, function(t)
        token.as_principal(t, vm, {
            privs_present = CREATE | IMPERSONATE, privs_enabled = CREATE | IMPERSONATE,
            projected_uid = 3101, projected_gid = 3102,
        }, function(w, session)
            local client = assert(token.create(w, {
                auth_id = session,
                token_type = token.TYPE.IMPERSONATION,
                impersonation_level = token.LEVEL.IMPERSONATION,
                projected_uid = 9101, projected_gid = 9102,
            }))
            t:assert_eq(token.impersonate(w, client).ret, 0, "impersonating the client")
            -- getuid reads the *primary* credential.
            -- getuid(2) is patched to read current_real_cred(), so it
            -- answers with the primary credential throughout.
            t:assert_eq(creds.getuid(w), 3101, "getuid() answers with the service")
            t:assert_eq(creds.getgid(w), 3102, "and getgid() with the service's group")
            -- current_fsuid reads the *effective* credential, and file
            -- creation is what asks it.
            local st = create_as(w, "/mt/fsuid-split")
            t:assert(st, "the service creates a file while impersonating")
            t:assert_eq(st.uid, 9101,
                "current_fsuid() answered with the client — the two deliberately disagree")
            token.revert(w)
            sys.close(w, client)
        end)
    end)

test("a task carrying no token falls back to cred->fsuid and Linux DAC",
    { spec = "PKM *cred.projection.tokenless-dac-fallback",
      covered_by = "kunit:pkm_kunit_token",
      skip = "every task on a running system carries a token — a blank " ..
             "credential exists only before KACS initialises; runs under " ..
             "pkm_kunit_projected_fsids_fallback_to_raw_without_token" },
    function(t) end)
