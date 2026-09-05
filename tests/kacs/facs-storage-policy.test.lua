-- PKM §3.9.5 — administration: `kacs_set_mount_policy`, the mount-level
-- template, and the generation counter that decides which cached
-- descriptors a policy change throws away.
--
-- `helpers/kacs.set_mount_policy_ex` is the full argument block —
-- `helpers/kacs.set_mount_policy` sends a zero-filled one, which cannot
-- carry a template and cannot exercise the reserved fields. The
-- read-back form is `get_mount_policy_ex`, which reports the class, the
-- generation and the stored template.
--
-- The agent is SYSTEM with every privilege, so the privilege gate is
-- tested from minted principals: one with nothing, one with
-- SeTcbPrivilege present but disabled, one with it enabled.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local access = require("helpers.access")
local token = require("helpers.token")

local vm = provium:vm("v", "kernel-only"):boot()

local ALL_INFO = kacs.SI.OWNER | kacs.SI.GROUP | kacs.SI.DACL
local OI_CI = access.ACE_FLAG.OBJECT_INHERIT | access.ACE_FLAG.CONTAINER_INHERIT
local MP = kacs.MOUNT_POLICY

--- A complete, structurally valid descriptor, usable as a template.
local function descriptor(trustee, mask)
    return access.sd({
        owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM,
        dacl = access.acl({ access.ace(access.ACE.ALLOWED,
            mask or kacs.ALL_RIGHTS, trustee or token.SID.EVERYONE, OI_CI) }),
    })
end

--- A fresh mount in `class`, plus an O_PATH fd naming its superblock.
--- The fd is the handle every policy call takes; O_PATH is a valid
--- target and needs no rights on the object.
local function mounted(t, name, class, fstype)
    local at = "/mp-" .. name
    local ok, stage, errno = kacs.new_mount(vm, fstype or "tmpfs", at, class, nil)
    t:assert(ok, "mount at " .. at .. ": " .. tostring(stage) .. " " ..
        sys.errname(errno or 0))
    local fd = sys.open(vm, at, sys.O.PATH)
    t:assert(fd, "an O_PATH fd on the mount")
    return at, fd
end

--- Everything a principal needs to reach a mount point and nothing else:
--- SeChangeNotifyPrivilege gets it past the intermediate traverse checks
--- on `/`, whose DACL grants only SYSTEM.
local function principal_spec(privs)
    local bits = token.bit(token.PRIV.CHANGE_NOTIFY) | (privs or 0)
    return { privs_present = bits, privs_enabled = bits }
end

-- ---- adoption -------------------------------------------------------------

test("a mounted filesystem is adopted through a descriptor on any of its objects",
    { spec = "PKM *facs.storage.set-mount-policy" }, function(t)
        local at, fd = mounted(t, "adopt", nil)
        t:assert_eq(kacs.get_mount_policy(vm, fd), MP.DENY_MISSING, "it starts deny-missing")
        -- Repair the root so an object below it can be created, then name
        -- the superblock by *that* object rather than by the mount point.
        t:assert_eq(kacs.set_sd(vm, at, descriptor(), ALL_INFO).ret, 0, "root repaired")
        t:assert_eq(sys.mkdir(vm, at .. "/inner").ret, 0, "a directory below it")
        local inner = sys.open(vm, at .. "/inner", sys.O.PATH)
        local r = kacs.set_mount_policy_ex(vm, inner, MP.SYNTHESIZE_EPHEMERAL, {})
        t:assert_eq(r.ret, 0, "the class is set through an inner object: " ..
            sys.errname(r.errno))
        t:assert_eq(kacs.get_mount_policy(vm, fd), MP.SYNTHESIZE_EPHEMERAL,
            "and the change applied to the superblock, not to the pathname")
        sys.close(vm, inner); sys.close(vm, fd)
    end)

test("setting a mount policy needs SeTcbPrivilege held and enabled, and marks it used",
    { spec = "PKM *facs.storage.set-mount-policy-privilege" }, function(t)
        local at, fd = mounted(t, "priv", nil)
        t:assert_eq(kacs.set_sd(vm, at, descriptor(), ALL_INFO).ret, 0, "root repaired")
        sys.close(vm, fd)

        token.as_principal(t, vm, principal_spec(0), function(w)
            local pfd = assert(sys.open(w, at, sys.O.PATH), "the principal reaches the mount")
            local r = kacs.set_mount_policy_ex(w, pfd, MP.SYNTHESIZE_EPHEMERAL, {})
            t:assert_eq(r.ret, -1, "a principal with no SeTcbPrivilege is refused")
            t:assert_eq(r.errno, sys.E.PERM, "EPERM")
            sys.close(w, pfd)
        end)

        token.as_principal(t, vm, {
            privs_present = token.bit(token.PRIV.TCB) | token.bit(token.PRIV.CHANGE_NOTIFY),
            privs_enabled = token.bit(token.PRIV.CHANGE_NOTIFY),
        }, function(w)
            local pfd = assert(sys.open(w, at, sys.O.PATH))
            local r = kacs.set_mount_policy_ex(w, pfd, MP.SYNTHESIZE_EPHEMERAL, {})
            t:assert_eq(r.ret, -1, "held but disabled is refused too")
            t:assert_eq(r.errno, sys.E.PERM, "EPERM")
            sys.close(w, pfd)
        end)

        token.as_principal(t, vm, principal_spec(token.bit(token.PRIV.TCB)),
            function(w)
                local pfd = assert(sys.open(w, at, sys.O.PATH))
                local r = kacs.set_mount_policy_ex(w, pfd, MP.SYNTHESIZE_EPHEMERAL, {})
                t:assert_eq(r.ret, 0, "enabled SeTcbPrivilege succeeds: " ..
                    sys.errname(r.errno))
                local own = assert(token.open_self(w, token.RIGHT.QUERY))
                local privs = assert(token.privileges(w, own))
                t:assert(privs.used & token.bit(token.PRIV.TCB) ~= 0,
                    "and the exercise is recorded in the used state")
                sys.close(w, own); sys.close(w, pfd)
            end)
    end)

test("SeManageVolumePrivilege alone does not satisfy the mount-policy gate",
    { spec = "PKM *facs.storage.set-mount-policy-privilege", tags = { "known-bug" } },
    function(t)
        -- §3.9.5 names SeTcbPrivilege and nothing else. The kernel accepts
        -- SeManageVolumePrivilege as well (capability.c
        -- pkm_kacs_may_manage_volumes_for_token, with a comment arguing
        -- that adopting a volume is volume management) — so a principal
        -- holding only SeManageVolumePrivilege can reclassify a
        -- superblock, which the TRM does not permit.
        local at, fd = mounted(t, "mvp", nil)
        t:assert_eq(kacs.set_sd(vm, at, descriptor(), ALL_INFO).ret, 0, "root repaired")
        sys.close(vm, fd)
        token.as_principal(t, vm, principal_spec(token.bit(token.PRIV.MANAGE_VOLUME)),
            function(w)
                local pfd = assert(sys.open(w, at, sys.O.PATH))
                local r = kacs.set_mount_policy_ex(w, pfd, MP.SYNTHESIZE_EPHEMERAL, {})
                t:assert_eq(r.ret, -1,
                    "a principal without SeTcbPrivilege is refused: got " ..
                    sys.errname(r.errno))
                sys.close(w, pfd)
            end)
    end)

test("the public ABI accepts only the three managed classes and rejects malformed input",
    { spec = "PKM *facs.storage.set-mount-policy-input-validation" }, function(t)
        local at, fd = mounted(t, "validate", nil)
        local start = kacs.get_mount_policy_ex(vm, fd)
        local bad = {
            { "unmanaged", MP.UNMANAGED, {} },
            { "class 0", 0, {} },
            { "class 5", 5, {} },
            { "class 0xffffffff", 0xFFFFFFFF, {} },
            { "nonzero flags", MP.DENY_MISSING, { flags = 1 } },
            { "nonzero generation", MP.DENY_MISSING, { generation = 1 } },
            { "nonzero __pad0", MP.DENY_MISSING, { pad0 = 1 } },
            { "nonzero __pad1", MP.DENY_MISSING, { pad1 = 1 } },
            { "argsize below the minimum", MP.DENY_MISSING, { argsize = 8 } },
        }
        for _, c in ipairs(bad) do
            local r = kacs.set_mount_policy_ex(vm, fd, c[2], c[3])
            t:assert_eq(r.ret, -1, c[1] .. " is refused")
            t:assert_eq(r.errno, sys.E.INVAL, c[1] .. ": EINVAL")
        end
        local after = kacs.get_mount_policy_ex(vm, fd)
        t:assert_eq(after.policy, start.policy, "the class is unchanged")
        t:assert_eq(after.generation, start.generation,
            "and no failure moved the generation")
        -- Validation runs before the descriptor is even looked up.
        local r = kacs.set_mount_policy_ex(vm, -1, MP.UNMANAGED, {})
        t:assert_eq(r.errno, sys.E.INVAL,
            "malformed arguments are rejected before the fd is resolved")
        sys.close(vm, fd)
    end)

-- ---- the template ---------------------------------------------------------

test("a template is accepted only with a synthesise class",
    { spec = "PKM *facs.storage.template-requires-synthesise" }, function(t)
        local _, fd = mounted(t, "tpl-class", nil)
        local tpl = descriptor(token.SID.TEST_USER)
        local r = kacs.set_mount_policy_ex(vm, fd, MP.DENY_MISSING, { template = tpl })
        t:assert_eq(r.ret, -1, "deny-missing with a template is refused")
        t:assert_eq(r.errno, sys.E.INVAL, "EINVAL")
        for _, class in ipairs({ MP.SYNTHESIZE_EPHEMERAL, MP.SYNTHESIZE_PERSISTENT }) do
            local ok = kacs.set_mount_policy_ex(vm, fd, class, { template = tpl })
            t:assert_eq(ok.ret, 0, "class " .. class .. " takes one: " ..
                sys.errname(ok.errno))
            t:assert_eq(kacs.get_mount_policy_ex(vm, fd).template, tpl,
                "and stores it verbatim")
        end
        sys.close(vm, fd)
    end)

test("the template is a complete descriptor, structurally validated and size-bounded",
    { spec = "PKM *facs.storage.template-validation" }, function(t)
        local _, fd = mounted(t, "tpl-valid", MP.SYNTHESIZE_EPHEMERAL)
        local tpl = descriptor(token.SID.TEST_USER)
        t:assert_eq(kacs.set_mount_policy_ex(vm, fd, MP.SYNTHESIZE_EPHEMERAL,
            { template = tpl }).ret, 0, "a complete descriptor is accepted")
        local snap = kacs.get_mount_policy_ex(vm, fd)
        t:assert_eq(snap.template_len, #tpl, "stored whole")
        t:assert_eq(snap.template, tpl, "and byte-identical")

        local bad = {
            { "garbage bytes", { template = string.rep("\xff", 40) } },
            { "a truncated descriptor", { template = tpl:sub(1, 12) } },
            { "an ACL fragment rather than a descriptor",
              { template = access.acl({ access.ace(access.ACE.ALLOWED,
                    kacs.ALL_RIGHTS, token.SID.EVERYONE) }) } },
            { "a length past 65535", { template = tpl, template_len = 65536 } },
            { "a length with no pointer", { template_len = 32 } },
            { "a pointer with no length", { template = tpl, template_len = 0 } },
        }
        for _, c in ipairs(bad) do
            local r = kacs.set_mount_policy_ex(vm, fd, MP.SYNTHESIZE_EPHEMERAL, c[2])
            t:assert_eq(r.ret, -1, c[1] .. " is refused")
            t:assert_eq(r.errno, sys.E.INVAL, c[1] .. ": EINVAL")
        end
        t:assert_eq(kacs.get_mount_policy_ex(vm, fd).template, tpl,
            "and every failure left the stored template alone")
        sys.close(vm, fd)
    end)

test("a null pointer with a zero length clears the template",
    { spec = "PKM *facs.storage.template-null-clears" }, function(t)
        local _, fd = mounted(t, "tpl-null", MP.SYNTHESIZE_EPHEMERAL)
        local tpl = descriptor(token.SID.TEST_USER)
        t:assert_eq(kacs.set_mount_policy_ex(vm, fd, MP.SYNTHESIZE_EPHEMERAL,
            { template = tpl }).ret, 0, "a template is set")
        t:assert_eq(kacs.get_mount_policy_ex(vm, fd).template_len, #tpl, "and stored")
        local r = kacs.set_mount_policy_ex(vm, fd, MP.SYNTHESIZE_EPHEMERAL, {})
        t:assert_eq(r.ret, 0, "the same class with no template: " .. sys.errname(r.errno))
        local snap = kacs.get_mount_policy_ex(vm, fd)
        t:assert_eq(snap.template_len, 0, "clears it")
        t:assert_eq(snap.policy, MP.SYNTHESIZE_EPHEMERAL, "leaving the class in place")
        sys.close(vm, fd)
    end)

test("setting deny-missing clears the template and refuses to be given one",
    { spec = "PKM *facs.storage.deny-missing-clears-template" }, function(t)
        local _, fd = mounted(t, "tpl-deny", MP.SYNTHESIZE_PERSISTENT)
        local tpl = descriptor(token.SID.TEST_USER)
        t:assert_eq(kacs.set_mount_policy_ex(vm, fd, MP.SYNTHESIZE_PERSISTENT,
            { template = tpl }).ret, 0, "a template is set")
        local r = kacs.set_mount_policy_ex(vm, fd, MP.DENY_MISSING, { template = tpl })
        t:assert_eq(r.ret, -1, "deny-missing rejects non-empty template input")
        t:assert_eq(r.errno, sys.E.INVAL, "EINVAL")
        t:assert_eq(kacs.get_mount_policy_ex(vm, fd).template_len, #tpl,
            "and the refusal changed nothing")
        t:assert_eq(kacs.set_mount_policy_ex(vm, fd, MP.DENY_MISSING, {}).ret, 0,
            "deny-missing with no template succeeds")
        local snap = kacs.get_mount_policy_ex(vm, fd)
        t:assert_eq(snap.policy, MP.DENY_MISSING, "the class is deny-missing")
        t:assert_eq(snap.template_len, 0, "and the template is gone")
        sys.close(vm, fd)
    end)

-- ---- laziness and the generation counter ----------------------------------

test("a policy change walks nothing and stamps nothing",
    { spec = "PKM *facs.storage.policy-change-lazy" }, function(t)
        -- A deny-missing tmpfs whose root has no descriptor. Switching it
        -- to synthesise-persistent would, if the change walked the mount,
        -- write the synthesised descriptor to the root's xattr there and
        -- then. It does not: the xattr appears only once something asks
        -- for the descriptor.
        local at, fd = mounted(t, "lazy", nil)
        t:assert_eq(#(sys.listxattr(vm, at) or {}), 0, "the root stores nothing")
        t:assert_eq(kacs.set_mount_policy_ex(vm, fd, MP.SYNTHESIZE_PERSISTENT, {}).ret, 0,
            "the class becomes synthesise-persistent")
        t:assert_eq(#(sys.listxattr(vm, at) or {}), 0,
            "and the root still stores nothing — nothing was walked or stamped")
        t:assert(kacs.get_sd(vm, at, ALL_INFO), "the first read synthesises one")
        local names = sys.listxattr(vm, at) or {}
        t:assert_eq(#names, 1, "and only then is anything written")
        t:assert_eq(names[1], "security.peios.sd", "the canonical xattr")
        sys.close(vm, fd)
    end)

test("the superblock carries a monotonic generation, moved by every successful change",
    { spec = "PKM *facs.storage.generation-counter" }, function(t)
        local _, fd = mounted(t, "gen", nil)
        local tpl = descriptor(token.SID.TEST_USER)
        local seen = { kacs.get_mount_policy_ex(vm, fd).generation }
        local steps = {
            { MP.SYNTHESIZE_EPHEMERAL, {} },
            { MP.SYNTHESIZE_EPHEMERAL, { template = tpl } },
            { MP.SYNTHESIZE_EPHEMERAL, { template = tpl } },
            { MP.SYNTHESIZE_PERSISTENT, {} },
            { MP.DENY_MISSING, {} },
        }
        for i, s in ipairs(steps) do
            t:assert_eq(kacs.set_mount_policy_ex(vm, fd, s[1], s[2]).ret, 0,
                "step " .. i .. " succeeds")
            local g = kacs.get_mount_policy_ex(vm, fd).generation
            t:assert(g > seen[#seen],
                "step " .. i .. " advanced the generation: " .. seen[#seen] .. " -> " .. g)
            seen[#seen + 1] = g
        end
        local before = seen[#seen]
        t:assert_eq(kacs.set_mount_policy_ex(vm, fd, MP.UNMANAGED, {}).errno, sys.E.INVAL,
            "a rejected change")
        t:assert_eq(kacs.get_mount_policy_ex(vm, fd).generation, before,
            "leaves the generation where it was")
        sys.close(vm, fd)
    end)

test("a generation change discards synthetic cache entries and re-synthesises them",
    { spec = "PKM *facs.storage.generation-discards-synthetic" }, function(t)
        local at, fd = mounted(t, "gen-synth", MP.SYNTHESIZE_EPHEMERAL)
        local fallback = assert(kacs.get_sd(vm, at, ALL_INFO),
            "the root synthesises from the fallback")
        local tpl = descriptor(token.SID.TEST_USER)
        t:assert_eq(kacs.set_mount_policy_ex(vm, fd, MP.SYNTHESIZE_EPHEMERAL,
            { template = tpl }).ret, 0, "a template replaces it")
        local after = assert(kacs.get_sd(vm, at, ALL_INFO))
        t:assert_neq(after, fallback,
            "the cached synthetic entry was discarded and recomputed")
        local d = access.parse_sd(after)
        t:assert_eq(d.dacl.aces[1].sid, token.SID.TEST_USER,
            "from the new template")
        sys.close(vm, fd)
    end)

test("a policy change does not revalidate an xattr-backed cache",
    { spec = "PKM *facs.storage.policy-change-keeps-xattr-caches" }, function(t)
        local at, fd = mounted(t, "gen-xattr", nil)
        t:assert_eq(kacs.set_sd(vm, at, descriptor(), ALL_INFO).ret, 0, "root repaired")
        t:assert_eq(sys.mkdir(vm, at .. "/stored").ret, 0, "an object with a stored descriptor")
        local stored = assert(kacs.get_sd(vm, at .. "/stored", ALL_INFO))
        local tpl = descriptor(token.SID.TEST_USER)
        t:assert_eq(kacs.set_mount_policy_ex(vm, fd, MP.SYNTHESIZE_EPHEMERAL,
            { template = tpl }).ret, 0, "the class and template change under it")
        t:assert_eq(kacs.get_sd(vm, at .. "/stored", ALL_INFO), stored,
            "an xattr-backed descriptor is untouched by the change")
        sys.close(vm, fd)
    end)
