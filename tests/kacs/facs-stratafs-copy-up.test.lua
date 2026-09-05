-- PKM §3.9.7 — the StrataFS copy-up context.
--
-- Read §3.9.7's own opening claim first, because it decides most of this
-- file: "There is no userspace surface of any kind — no ABI, file
-- descriptor, token, ioctl, syscall or securityfs control — and the
-- copy-up API is declared in a kernel-private header with no exported
-- symbols." A conformance test in the guest can therefore reach the
-- context only through its *effects*: perform an operation on a StrataFS
-- handle that requires a copy-up, and look at what the copy came out
-- wearing and what the caller was and was not required to hold.
--
-- That covers the exemption's shape, the descriptor cloning, the
-- xattr protections and the audit rule. It does not reach the phase
-- state machine — arming, binding, mismatch, rebinding, generations,
-- internal-file scoping — because every one of those is a property of a
-- call sequence only the in-kernel StrataFS implementation can make.
-- Those citations are covered by the `pkm_kunit_copy_up` KUnit suite in
-- `pkm/kacs/copy_up.c`, which drives the same entry points StrataFS
-- calls against a tmpfs it mounts for itself, as a principal the tree
-- grants nothing; each stub below names the case that carries it.
--
-- The live cases run as a minted principal wherever the point is that a
-- right was *not* required: the agent is SYSTEM and would pass either
-- way. SeChangeNotifyPrivilege is present on those principals only so
-- they can traverse `/`, whose DACL names SYSTEM alone.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local facs = require("helpers.facs")
local access = require("helpers.access")
local token = require("helpers.token")
local stratafs = require("helpers.stratafs")
local kmes = require("helpers.kmes")

local vm = provium:vm("v", "kernel-only"):boot()

local SI = kacs.SI
local ALL_INFO = SI.OWNER | SI.GROUP | SI.DACL
local OI_CI = access.ACE_FLAG.OBJECT_INHERIT | access.ACE_FLAG.CONTAINER_INHERIT
local CANONICAL = "security.peios.sd"
local STAGING = "security.peios.stratafs_staging"
local CHANGE_NOTIFY = token.bit(token.PRIV.CHANGE_NOTIFY)

--- A descriptor recognisable by the trustee it names.
---
--- Everyone is granted `mask` (every right by default) first, because
--- the agent has to keep working on these objects — SYSTEM is bound by
--- the DACL like anyone else. `trustee`, when given, adds a second,
--- identical ACE naming a SID that appears nowhere else, so a copy can
--- be said to carry *this* descriptor rather than some other.
local function sd_for(trustee, mask)
    local aces = { access.ace(access.ACE.ALLOWED, mask or kacs.ALL_RIGHTS,
        token.SID.EVERYONE, OI_CI) }
    if trustee then
        aces[#aces + 1] = access.ace(access.ACE.ALLOWED, mask or kacs.ALL_RIGHTS,
            trustee, OI_CI)
    end
    return access.sd({
        owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM,
        dacl = access.acl(aces),
    })
end

--- Whether a parsed descriptor's DACL names `sid`.
local function names(d, sid)
    for _, a in ipairs(d.dacl and d.dacl.aces or {}) do
        if a.sid == sid then return true end
    end
    return false
end

--- The rights an ordinary read-write open and write need.
local RW = kacs.RIGHT.READ_DATA | kacs.RIGHT.WRITE_DATA | kacs.RIGHT.APPEND_DATA
    | kacs.RIGHT.READ_ATTRIBUTES | kacs.RIGHT.WRITE_ATTRIBUTES
    | kacs.RIGHT.READ_CONTROL | kacs.RIGHT.SYNCHRONIZE

--- The standard two-stratum stack: a read-only provider holding `f`, and
--- a create stratum for the copy to land in.
local function with_stack(name, fn, entries)
    stratafs.with(vm, name, {
        { name = "up", flags = { "create" } },
        { name = "lo", flags = { "ro" }, entries = entries or { f = "provider" } },
    }, fn)
end

--- Open the whole scenario tree to Everyone.
---
--- The scratch root inherits from `/`, whose DACL names SYSTEM alone, so
--- a minted principal cannot reach a stratum path at all until this runs.
--- A case then narrows exactly the object it is about.
local function permissive(t, s)
    for _, p in ipairs({ s.root, s:in_stratum("lo"), s:in_stratum("up") }) do
        t:assert_eq(kacs.set_sd(vm, p, sd_for(), ALL_INFO).ret, 0,
            "the principal can reach " .. p)
    end
end

local function as_user(t, fn)
    token.as_principal(t, vm, { privs_present = CHANGE_NOTIFY,
                                privs_enabled = CHANGE_NOTIFY }, fn)
end

local function kunit_stub(name, spec, case, why, suite)
    test(name, { spec = "PKM *" .. spec, covered_by = "kunit:" .. (suite or "pkm_kunit_file"),
                 skip = why .. "; runs under " .. case }, function(t) end)
end

-- ---- the exemption's shape ------------------------------------------------

test("the mechanics of a copy-up demand nothing of the task that executes them",
    { spec = "PKM *facs.stratafs-copy-up.exempt-operations" }, function(t)
        -- The caller is authorised against the StrataFS handle and nothing
        -- else: the create stratum's own descriptor names SYSTEM only, so
        -- every enforcement point §3.9.7 lists — the destination parent's
        -- permission check, the create, the staged object's own open and
        -- write, the publish — would deny this principal if it were
        -- evaluated against it.
        with_stack("exempt", function(s)
            permissive(t, s)
            local provider = s:in_stratum("lo", "f")
            t:assert_eq(kacs.set_sd(vm, provider, sd_for(nil, RW), ALL_INFO).ret, 0,
                "the principal may write the merged object")
            -- The create stratum may be traversed — StrataFS resolves the
            -- merged directory through it — but grants nothing that would
            -- let this caller put an object in it.
            local NO_ADD = kacs.ALL_RIGHTS & ~(kacs.RIGHT.ADD_FILE
                | kacs.RIGHT.ADD_SUBDIRECTORY | kacs.RIGHT.DELETE_CHILD)
            t:assert_eq(kacs.set_sd(vm, s:in_stratum("up"),
                sd_for(nil, NO_ADD), ALL_INFO).ret, 0,
                "and may not create anything in the create stratum")
            as_user(t, function(w)
                local made = sys.mkdir(w, s:in_stratum("up") .. "/direct")
                t:assert_eq(made.ret, -1, "which it proves by failing to create there")
                t:assert_eq(made.errno, sys.E.ACCES, "EACCES")
                local ok, errno, stage = stratafs.try_write(w, s:join("f"), "rewritten")
                t:assert(ok, "yet the write, and the copy-up it forces, succeed: " ..
                    (ok and "" or (sys.errname(errno) .. " at " .. tostring(stage))))
            end)
            t:assert(sys.stat(vm, s:in_stratum("up", "f")),
                "the copy landed in the create stratum")
            t:assert_eq(vm:read_file(s:join("f")), "rewritten", "and the write took")
        end)
    end)

test("the exemption covers KACS caller authorization only",
    { spec = "PKM *facs.stratafs-copy-up.exempts-kacs-only" }, function(t)
        -- An immutable create stratum is a filesystem-level refusal, not a
        -- KACS one, and nothing about the context suppresses it.
        with_stack("exempts-only", function(s)
            t:assert(sys.set_immutable(vm, s:in_stratum("up"), true),
                "the create stratum is made immutable")
            local ok, errno = stratafs.try_write(vm, s:join("f"), "rewritten")
            t:assert(not ok, "the copy-up fails")
            t:assert_eq(errno, sys.E.PERM,
                "EPERM — the immutable flag is not something the context waives")
            t:assert(not sys.stat(vm, s:in_stratum("up", "f")), "and nothing was created")
            sys.set_immutable(vm, s:in_stratum("up"), false)
            t:assert(stratafs.try_write(vm, s:join("f"), "rewritten"),
                "with the flag cleared the same copy-up succeeds")
        end)
    end)

test("every mutation goes through the ordinary VFS path under mnt_want_write",
    { spec = "PKM *facs.stratafs-copy-up.mutations-via-vfs" }, function(t)
        -- A read-only *mount* of the create stratum is the cleanest
        -- witness: mnt_want_write is what refuses, and the context does not
        -- make a read-only mount writable.
        local s = stratafs.scenario(vm, "vfs", {
            { name = "up", flags = { "create" } },
            { name = "lo", flags = { "ro" }, entries = { f = "provider" } },
        }, { mount = false })
        local ro = s.root .. "/up-ro"
        vm:mkdir(ro, { parents = true })
        kacs.set_sd(vm, ro, kacs.grant(kacs.ALL_RIGHTS))
        local bind = sys.bind_ro(vm, s:in_stratum("up"), ro)
        t:assert_eq(bind.ret, 0, "the create stratum is bound read-only: " ..
            sys.errname(bind.errno))
        local at = s.root .. "/ro-mnt"
        local m = stratafs.try_mount(vm, { at = at, strata = {
            { path = ro, flags = { "create" } },
            { path = s:in_stratum("lo"), flags = { "ro" } },
        } })
        t:assert_eq(m.ret, 0, "and a stack is mounted over it: " .. sys.errname(m.errno))
        local ok, errno = stratafs.try_write(vm, at .. "/f", "rewritten")
        t:assert(not ok, "the copy-up cannot write to it")
        t:assert_eq(errno, sys.E.ROFS, "EROFS, from the ordinary write path")
        sys.umount(vm, at)
        sys.umount(vm, ro)
    end)

test("there is no userspace surface for the context",
    { spec = "PKM *facs.stratafs-copy-up.no-userspace-surface" }, function(t)
        -- securityfs is where KACS and StrataFS both put what they do
        -- expose, so it is the place a control would be if one existed.
        local at = "/copyup-securityfs"
        t:assert(kacs.new_mount(vm, "securityfs", at,
            kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL, nil), "securityfs mounts")
        local function names_under(dir)
            local out = {}
            for _, e in ipairs(vm:listdir(dir) or {}) do
                out[#out + 1] = tostring(e.name or e)
            end
            table.sort(out)
            return out
        end
        local top = table.concat(names_under(at), ",")
        t:assert(top:match("kacs"), "KACS's own directory is there: " .. top)
        local kacs_entries = table.concat(names_under(at .. "/kacs"), ",")
        t:assert_eq(kacs_entries, "self,sessions",
            "and holds only the session and self files")
        -- StrataFS's securityfs directory holds the §4.A.2 test
        -- rendezvous points and nothing else; none of them creates,
        -- enters or arms a copy-up context.
        local strata = names_under(at .. "/stratafs/hooks")
        t:assert_eq(table.concat(strata, ","),
            "copy-up-begin,copy-up-publish,link-install,rename-provider",
            "the stratafs directory holds only the test rendezvous points")
    end)

test("caller-originated writes and removals of the staging marker are denied",
    { spec = "PKM *facs.stratafs-copy-up.staging-marker-writes-denied" }, function(t)
        with_stack("marker", function(s)
            for _, path in ipairs({ s:join("f"), s:in_stratum("lo", "f"),
                                    s:in_stratum("up") }) do
                local w = sys.setxattr(vm, path, STAGING, "forged")
                t:assert_eq(w.ret, -1, "a caller cannot write the marker on " .. path)
                t:assert_eq(w.errno, sys.E.PERM, "EPERM")
                local r = sys.removexattr(vm, path, STAGING)
                t:assert_eq(r.ret, -1, "nor remove it")
                t:assert_eq(r.errno, sys.E.PERM, "EPERM")
            end
            -- Even after a real copy-up, when the marker has genuinely been
            -- on the staged object, the caller-facing answer is the same.
            t:assert(stratafs.try_write(vm, s:join("f"), "rewritten"), "a copy-up runs")
            local w = sys.setxattr(vm, s:in_stratum("up", "f"), STAGING, "forged")
            t:assert_eq(w.errno, sys.E.PERM, "EPERM on the published copy too")
        end)
    end)

-- ---- descriptor cloning ---------------------------------------------------

test("KACS clones the provider's descriptor rather than letting inheritance run",
    { spec = "PKM *facs.stratafs-copy-up.descriptor-cloning" }, function(t)
        with_stack("cloning", function(s)
            local provider = s:in_stratum("lo", "f")
            local mine = sd_for(token.SID.TEST_GROUP)
            t:assert_eq(kacs.set_sd(vm, provider, mine, ALL_INFO).ret, 0,
                "the provider has its own descriptor")
            local pinned = assert(kacs.get_sd(vm, provider, ALL_INFO))
            t:assert(stratafs.try_write(vm, s:join("f"), "rewritten"), "a copy-up runs")
            t:assert_eq(kacs.get_sd(vm, s:in_stratum("up", "f"), ALL_INFO), pinned,
                "the copy wears the provider's descriptor")
        end)
    end)

test("the installed descriptor is an exact copy, not the result of inheritance",
    { spec = "PKM *facs.stratafs-copy-up.exact-copy-not-inheritance" }, function(t)
        with_stack("exact", function(s)
            -- Make inheritance from the create stratum produce a visibly
            -- different answer, so "exact copy" is distinguishable.
            t:assert_eq(kacs.set_sd(vm, s:in_stratum("up"),
                sd_for(token.SID.TEST_USER_2), ALL_INFO).ret, 0,
                "the create stratum would inherit a different trustee")
            local provider = s:in_stratum("lo", "f")
            local mine = sd_for(token.SID.TEST_GROUP)
            t:assert_eq(kacs.set_sd(vm, provider, mine, ALL_INFO).ret, 0,
                "the provider carries its own")
            local pinned = assert(kacs.get_sd(vm, provider, ALL_INFO))
            t:assert(stratafs.try_write(vm, s:join("f"), "rewritten"), "a copy-up runs")
            local d = access.parse_sd(assert(kacs.get_sd(vm, s:in_stratum("up", "f"),
                ALL_INFO)))
            t:assert(names(d, token.SID.TEST_GROUP),
                "the copy names the provider's trustee")
            t:assert(not names(d, token.SID.TEST_USER_2),
                "not the one inheritance from the staging parent would have given")
            t:assert_eq(kacs.get_sd(vm, s:in_stratum("up", "f"), ALL_INFO), pinned,
                "byte for byte")
        end)
    end)

test("the canonical xattr is installed and the parsed cache seeded from the same bytes",
    { spec = "PKM *facs.stratafs-copy-up.xattr-and-cache-seeded" }, function(t)
        with_stack("seeded", function(s)
            local provider = s:in_stratum("lo", "f")
            local mine = sd_for(token.SID.TEST_GROUP)
            t:assert_eq(kacs.set_sd(vm, provider, mine, ALL_INFO).ret, 0, "the provider")
            t:assert(stratafs.try_write(vm, s:join("f"), "rewritten"), "a copy-up runs")
            local staged = s:in_stratum("up", "f")
            local names = sys.listxattr(vm, staged) or {}
            local found = false
            for _, n in ipairs(names) do if n == CANONICAL then found = true end end
            t:assert(found, "the staged inode stores the canonical xattr")
            -- The cache is what get_sd answers from, and it agrees with what
            -- was installed at creation.
            t:assert_eq(kacs.get_sd(vm, staged, ALL_INFO),
                kacs.get_sd(vm, provider, ALL_INFO),
                "and the descriptor served for it is the pinned one")
        end)
    end)

test("the canonical descriptor is not carried by ordinary xattr traffic",
    { spec = "PKM *facs.stratafs-copy-up.canonical-xattr-cancelled" }, function(t)
        with_stack("cancelled", function(s)
            local provider = s:in_stratum("lo", "f")
            t:assert_eq(kacs.set_sd(vm, provider, sd_for(token.SID.TEST_GROUP),
                ALL_INFO).ret, 0, "the provider has a descriptor")
            -- Raw canonical access is denied on the provider, so no ordinary
            -- xattr replication could have read it.
            t:assert_eq(select(2, sys.getxattr(vm, provider, CANONICAL)), sys.E.ACCES,
                "the provider's canonical xattr is unreadable")
            t:assert(stratafs.try_write(vm, s:join("f"), "rewritten"), "a copy-up runs")
            local staged = s:in_stratum("up", "f")
            t:assert_eq(select(2, sys.getxattr(vm, staged, CANONICAL)), sys.E.ACCES,
                "and it stays unreadable on the staged copy")
            t:assert_eq(sys.setxattr(vm, staged, CANONICAL, sd_for()).errno, sys.E.ACCES,
                "and unwritable")
            t:assert_eq(kacs.get_sd(vm, staged, ALL_INFO),
                kacs.get_sd(vm, provider, ALL_INFO),
                "yet the descriptor arrived — by the pinned copy, not by enumeration")
        end)
    end)

test("raw setxattr cannot install security.capability",
    { spec = "PKM *facs.stratafs-copy-up.raw-setcap-denied" }, function(t)
        with_stack("setcap", function(s)
            -- A structurally valid VFS_CAP_REVISION_2 payload, so the
            -- refusal is the hook's and not the filesystem's.
            local cap = string.pack("<I4I4I4I4I4", 0x02000000, 0, 0, 0, 0)
            for _, path in ipairs({ s:join("f"), s:in_stratum("lo", "f") }) do
                local w = sys.setxattr(vm, path, "security.capability", cap)
                t:assert_eq(w.ret, -1, "installing a file capability on " .. path ..
                    " is refused")
                t:assert_eq(w.errno, sys.E.PERM, "EPERM")
            end
            t:assert(stratafs.try_write(vm, s:join("f"), "rewritten"), "a copy-up runs")
            local w = sys.setxattr(vm, s:in_stratum("up", "f"), "security.capability", cap)
            t:assert_eq(w.errno, sys.E.PERM, "and on the staged copy afterwards")
        end)
    end)

test("the removal path does not reject security.capability the way the set path does",
    { spec = "PKM *facs.stratafs-copy-up.removal-path-asymmetry" }, function(t)
        with_stack("asymmetry", function(s)
            local cap = string.pack("<I4I4I4I4I4", 0x02000000, 0, 0, 0, 0)
            local path = s:in_stratum("lo", "f")
            t:assert_eq(sys.setxattr(vm, path, "security.capability", cap).errno,
                sys.E.PERM, "the set path rejects the name outright")
            local r = sys.removexattr(vm, path, "security.capability")
            t:assert_eq(r.ret, -1, "the removal fails as well")
            t:assert_eq(r.errno, sys.E.NODATA,
                "but with ENODATA from the filesystem, not EPERM from the hook — " ..
                "the predicate that rejects the name on the set path is absent here")
        end)
    end)

test("provider access under the exemption is read-only",
    { spec = "PKM *facs.stratafs-copy-up.provider-read-only" }, function(t)
        with_stack("readonly", function(s)
            local provider = s:in_stratum("lo", "f")
            local before = sys.stat(vm, provider)
            local descriptor = assert(kacs.get_sd(vm, provider, ALL_INFO))
            t:assert(stratafs.try_write(vm, s:join("f"), "rewritten"), "a copy-up runs")
            t:assert_eq(vm:read_file(provider), "provider",
                "the provider's data is untouched")
            local after = sys.stat(vm, provider)
            t:assert_eq(after.ino, before.ino, "the same inode")
            t:assert_eq(after.size, before.size, "unchanged in size")
            t:assert_eq(after.mtime, before.mtime, "and unmodified")
            t:assert_eq(kacs.get_sd(vm, provider, ALL_INFO), descriptor,
                "with its descriptor as it was")
            t:assert_eq(#(sys.listxattr(vm, provider) or {}), 1,
                "and no staging marker or other xattr left on it")
        end)
    end)

test("the exemption list is exhaustive — it broadens nothing else for the caller",
    { spec = "PKM *facs.stratafs-copy-up.list-exhaustive" }, function(t)
        with_stack("exhaustive", function(s)
            permissive(t, s)
            -- Write access and nothing else. Performing the write drives a
            -- copy-up; the operations §3.9.7 says the context does not
            -- exempt are still decided against this caller's rights.
            local write_only = kacs.RIGHT.WRITE_DATA | kacs.RIGHT.APPEND_DATA
                | kacs.RIGHT.READ_ATTRIBUTES | kacs.RIGHT.WRITE_ATTRIBUTES
                | kacs.RIGHT.SYNCHRONIZE
            t:assert_eq(kacs.set_sd(vm, s:in_stratum("lo", "f"),
                sd_for(nil, write_only), ALL_INFO).ret, 0,
                "the merged object grants writing only")
            as_user(t, function(w)
                local fd, errno = sys.open(w, s:join("f"), sys.O.WRONLY)
                t:assert(fd, "the caller opens for write: " .. sys.errname(errno or 0))
                t:assert_eq(sys.write(w, fd, "rewritten").ret, 9, "and writes")
                -- The copy-up has now run under the exemption. Reading,
                -- executing and mapping are not on the exempt list.
                local r, rerr = sys.open(w, s:join("f"), sys.O.RDONLY)
                t:assert(not r, "reading is still refused")
                t:assert_eq(rerr, sys.E.ACCES, "EACCES")
                local x = facs.execveat_fd(w, fd)
                t:assert(x.ret < 0, "executing the descriptor is still refused")
                local io = facs.ioctl(w, fd, facs.IOC.FS_IOC_GETFLAGS,
                    string.pack("<I8", 0))
                t:assert(io.ret < 0, "and an ioctl needing a right it lacks")
                sys.close(w, fd)
            end)
            t:assert(sys.stat(vm, s:in_stratum("up", "f")), "the copy-up did happen")
        end)
    end)

-- ---- deferred deletion ----------------------------------------------------

--- A stack whose create stratum holds `f`, so a deletion has an entry to
--- remove. A `ro` provider cannot be unlinked from at all, which is a
--- StrataFS routing rule rather than anything §3.9.7 decides.
local function with_writable(name, fn)
    stratafs.with(vm, name, {
        { name = "up", flags = { "create" }, entries = { f = "staged" } },
        { name = "lo", flags = { "ro" }, entries = { other = "provider" } },
    }, fn)
end

test("delete-on-close deletes the provider entry with no re-authorization at close",
    { spec = "PKM *facs.stratafs-copy-up.close-no-reauth" }, function(t)
        with_writable("deleteonclose", function(s)
            t:assert_eq(kacs.set_sd(vm, s:in_stratum("up", "f"),
                sd_for(nil, kacs.ALL_RIGHTS), ALL_INFO).ret, 0, "a permissive object")
            local fd, status = facs.open(vm, s:join("f"), {
                access = RW | kacs.RIGHT.DELETE,
                options = kacs.CREATE_OPT.DELETE_ON_CLOSE })
            t:assert(fd, "the handle opens with delete-on-close: " ..
                sys.errname(status or 0))
            t:assert(sys.stat(vm, s:join("f")), "the object is still there while open")
            sys.close(vm, fd)
            t:assert(not sys.stat(vm, s:join("f")),
                "and is gone at final close, with no second check against the closer")
        end)
    end)

test("the deletion is armed against the descriptor's settled provider entry",
    { spec = "PKM *facs.stratafs-copy-up.deferred-deletion" }, function(t)
        with_writable("deferred", function(s)
            t:assert_eq(kacs.set_sd(vm, s:in_stratum("up", "f"),
                sd_for(nil, kacs.ALL_RIGHTS), ALL_INFO).ret, 0, "a permissive object")
            local fd = assert(facs.open(vm, s:join("f"), {
                access = RW | kacs.RIGHT.DELETE,
                options = kacs.CREATE_OPT.DELETE_ON_CLOSE }))
            sys.close(vm, fd)
            t:assert(not sys.stat(vm, s:join("f")), "the merged name is gone")
            t:assert(not sys.stat(vm, s:in_stratum("up", "f")),
                "and so is the exact provider entry the descriptor settled on")
            t:assert(sys.stat(vm, s:in_stratum("lo", "other")),
                "with no other entry in the stack touched")
        end)
    end)

-- ---- auditing -------------------------------------------------------------

test("no second caller AccessCheck or privilege-use audit is emitted for the internal work",
    { spec = "PKM *facs.stratafs-copy-up.no-second-audit" }, function(t)
        with_stack("audit", function(s)
            local provider = s:in_stratum("lo", "f")
            t:assert_eq(kacs.set_sd(vm, provider, sd_for(nil, kacs.ALL_RIGHTS),
                ALL_INFO).ret, 0, "a permissive object")
            local events = kmes.recording(t, vm, function()
                t:assert(stratafs.try_write(vm, s:join("f"), "rewritten"),
                    "the copy-up runs")
            end)
            t:assert_eq(#kmes.of_type(events, "privilege-use"), 0,
                "the internal sub-operations recorded no privilege use")
            t:assert_eq(#kmes.of_type(events, "access-audit"), 0,
                "and no caller access audit, since the object carries no SACL")
        end)
    end)

test("the outer authorized handle operation remains subject to ordinary audit",
    { spec = "PKM *facs.stratafs-copy-up.auditing" }, function(t)
        with_stack("audit-outer", function(s)
            local provider = s:in_stratum("lo", "f")
            local audited = access.sd({
                owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM,
                dacl = access.acl({ access.ace(access.ACE.ALLOWED, kacs.ALL_RIGHTS,
                    token.SID.EVERYONE, OI_CI) }),
                sacl = access.acl({ access.ace(access.ACE.AUDIT, kacs.ALL_RIGHTS,
                    token.SID.EVERYONE, access.ACE_FLAG.SUCCESSFUL_ACCESS
                        | access.ACE_FLAG.FAILED_ACCESS) }),
            })
            t:assert_eq(kacs.set_sd(vm, provider, audited, ALL_INFO | SI.SACL).ret, 0,
                "the object carries an audit SACL")
            local events = kmes.recording(t, vm, function()
                t:assert(stratafs.try_write(vm, s:join("f"), "rewritten"),
                    "the copy-up runs")
            end)
            local audits = kmes.of_type(events, "access-audit")
            t:assert(#audits > 0, "the outer open produced an audit event")
            t:assert_eq(#kmes.of_type(events, "privilege-use"), 0,
                "and still nothing attributing the internal mechanics to the caller")
        end)
    end)

-- ---- kernel-internal claims -----------------------------------------------
--
-- Everything below is a property of the copy-up API's own call sequence.
-- §3.9.7 states that the API has no userspace surface at all, so none of
-- it is reachable from the guest. Each claim runs under a case of the
-- `pkm_kunit_copy_up` suite (pkm/kacs/copy_up.c) unless another suite is
-- named. The suite has two kinds of case: the predicate cases build
-- synthetic dentries and ask the hook predicates directly
-- (scope_is_exact and its neighbours), and the flow cases mount a tmpfs,
-- create a provider and a destination parent, and drive the entry points
-- StrataFS calls — begin, begin_create, vfs_create, bind_staging,
-- begin_populate, set_capability, begin_publish_link, vfs_link,
-- finish_publish, rebind_staging, begin_cleanup, vfs_unlink — as a
-- LocalService principal the tree grants nothing, so that every
-- refusal is ordinary authorization and every admission is the context.

local NO_SURFACE = "the copy-up API is kernel-private with no ABI, fd, ioctl, " ..
    "syscall or securityfs control, so the guest cannot make the call sequence " ..
    "this is about"

local function copy_up(name, spec, case, why)
    kunit_stub(name, spec, case, why or NO_SURFACE, "pkm_kunit_copy_up")
end

copy_up("creating a context performs no authorization check of its own",
    "facs.stratafs-copy-up.creation-performs-no-check",
    "pkm_kunit_copy_up_begin_pins_provider_without_a_check, where a principal " ..
    "refused even a read of the provider creates a context over it")

copy_up("a context attaches to at most one task and a task carries at most one",
    "facs.stratafs-copy-up.one-context-per-task",
    "pkm_kunit_copy_up_attachment_is_exclusive_and_transferable (a second " ..
    "creation on an attached task is EBUSY, and a worker cannot enter a held " ..
    "context) and pkm_kunit_copy_up_context_is_non_nesting")

copy_up("a context is not inherited by fork, clone or execve",
    "facs.stratafs-copy-up.not-inherited",
    "pkm_kunit_copy_up_attachment_is_exclusive_and_transferable: a task the " ..
    "context was never attached to carries none, and the exec commit hook " ..
    "detaches and clears it — the task-allocation hook's explicit clearing is " ..
    "the fork half, by inspection")

copy_up("a refcounted context can be transferred to a kernel worker",
    "facs.stratafs-copy-up.worker-transfer",
    "pkm_kunit_copy_up_attachment_is_exclusive_and_transferable, where a " ..
    "kthread enters the context the originator left, arms and ends a phase " ..
    "with the next generation, and leaves it")

copy_up("leaving, exit, an error path and completion all clear the armed phase",
    "facs.stratafs-copy-up.detach-clears-phase",
    "pkm_kunit_copy_up_attachment_is_exclusive_and_transferable (leave, task " ..
    "exit, exec commit, a refused begin_create, end_phase) and " ..
    "pkm_kunit_copy_up_named_flow_is_exact_and_exempt (a failed finish_publish)")

copy_up("the interface fails closed on nesting, concurrent attachment, a stale phase or a mismatch",
    "facs.stratafs-copy-up.fails-closed-on-misuse",
    "pkm_kunit_copy_up_phases_are_exclusive_and_generations_sealed (a second " ..
    "arm is EBUSY, an unbound populate or publish EINVAL, an untracked cleanup " ..
    "victim ESTALE) with pkm_kunit_copy_up_attachment_is_exclusive_and_transferable " ..
    "and pkm_kunit_copy_up_context_is_non_nesting for attachment")

copy_up("a mismatched operation is evaluated normally and does not consume the exemption",
    "facs.stratafs-copy-up.mismatch-evaluated-normally",
    "pkm_kunit_copy_up_named_flow_is_exact_and_exempt: creating another name, " ..
    "or the right name as a directory, is refused for the principal by ordinary " ..
    "authorization and leaves the armed creation unconsumed")

copy_up("creation pins the provider path, inode, descriptor and capability value",
    "facs.stratafs-copy-up.creation-pins-provider",
    "pkm_kunit_copy_up_begin_pins_provider_without_a_check, which compares " ..
    "the pinned path, inode, descriptor bytes and capability (present and absent) " ..
    "against the provider's own")

copy_up("every later positive path is paired with a pinned inode",
    "facs.stratafs-copy-up.paths-paired-with-inode",
    "pkm_kunit_copy_up_scope_is_exact, where the provider dentry is re-pointed " ..
    "at another inode and every match fails")

copy_up("exactly one phase is armed at a time",
    "facs.stratafs-copy-up.one-phase-armed",
    "pkm_kunit_copy_up_phases_are_exclusive_and_generations_sealed")

copy_up("path comparison includes the mount",
    "facs.stratafs-copy-up.match-includes-mount",
    "pkm_kunit_copy_up_scope_is_exact, where the same dentry through a second " ..
    "mount of the same superblock does not match")

copy_up("a phase never acts as a wildcard for other objects",
    "facs.stratafs-copy-up.no-wildcard-matching",
    "pkm_kunit_copy_up_scope_is_exact (another inode of the same filesystem " ..
    "matches nothing) and pkm_kunit_copy_up_named_flow_is_exact_and_exempt " ..
    "(another name in the armed parent is refused)")

copy_up("a rename or parent substitution invalidates the staged binding",
    "facs.stratafs-copy-up.rename-invalidates-binding",
    "pkm_kunit_copy_up_named_flow_is_exact_and_exempt, where the bound staged " ..
    "file is renamed into another directory and the populate exemptions stop, " ..
    "then resume when it is renamed back; pkm_kunit_copy_up_scope_is_exact " ..
    "covers the parent-substitution predicate")

copy_up("named creation is bound to the exact final component",
    "facs.stratafs-copy-up.named-creation-exact-component",
    "pkm_kunit_copy_up_named_flow_is_exact_and_exempt")

copy_up("an anonymous object must be bound as the staged object before it can be used",
    "facs.stratafs-copy-up.anonymous-must-be-bound",
    "pkm_kunit_copy_up_anonymous_object_must_be_bound, where a tmpfile created " ..
    "under the phase can be neither populated, published nor cleaned up until " ..
    "bind_staging names it")

copy_up("a stacking destination's transition is authenticated at the exact outer dentry",
    "facs.stratafs-copy-up.stacking-transition-authenticated",
    "pkm_kunit_copy_up_stacked_tmpfile_binds_outer_inode")

copy_up("a missing, repeated, mismatched or out-of-order transition fails closed",
    "facs.stratafs-copy-up.transition-out-of-order-fails",
    "pkm_kunit_copy_up_stacked_tmpfile_binds_outer_inode, where a repeated " ..
    "transition is EACCES and the real filesystem's own post-create event is " ..
    "rejected as the outer anchor")

copy_up("cleanup can be armed only for a retained object or the bound staging object",
    "facs.stratafs-copy-up.cleanup-victim-restricted",
    "pkm_kunit_copy_up_named_flow_is_exact_and_exempt (the retained staging " ..
    "name and the bound object are admitted, the provider is ESTALE) and " ..
    "pkm_kunit_copy_up_scope_is_exact")

copy_up("rebinding the staging identity requires mount, inode and parent all to match",
    "facs.stratafs-copy-up.rebind-conditions",
    "pkm_kunit_copy_up_named_flow_is_exact_and_exempt: the published path " ..
    "rebinds, a different inode is ESTALE, and so is any rebind while a phase " ..
    "is armed")

copy_up("the rebind API exists and is not called by StrataFS",
    "facs.stratafs-copy-up.rebind-unused",
    "pkm_kunit_copy_up_named_flow_is_exact_and_exempt for the API's existence " ..
    "and conditions; that fs/stratafs never calls it is a property of the " ..
    "caller, checked by inspection rather than by a test")

copy_up("the staging marker is admitted only on the bound inode or during authenticated recovery",
    "facs.stratafs-copy-up.staging-marker-admission",
    "pkm_kunit_copy_up_orphan_recovery_binds_the_marker_object (a write as well " ..
    "as a removal on the exact orphan, nothing on its sibling) and " ..
    "pkm_kunit_copy_up_scope_is_exact for the bound staging inode in populate")

copy_up("orphan deletion is bound to the exact dentry, inode and parent supplied",
    "facs.stratafs-copy-up.orphan-deletion-exact-binding",
    "pkm_kunit_copy_up_orphan_recovery_binds_the_marker_object")

copy_up("a permission match must also match the requested mask",
    "facs.stratafs-copy-up.mask-must-match",
    "pkm_kunit_copy_up_named_flow_is_exact_and_exempt and " ..
    "pkm_kunit_copy_up_scope_is_exact")

copy_up("staging access is limited to the masks population needs",
    "facs.stratafs-copy-up.staging-mask-limits",
    "pkm_kunit_copy_up_named_flow_is_exact_and_exempt, where read, write and " ..
    "append are admitted on the staged file and execute is not")

copy_up("unknown mask bits fail closed",
    "facs.stratafs-copy-up.unknown-mask-fails-closed",
    "pkm_kunit_copy_up_named_flow_is_exact_and_exempt")

copy_up("internal copy-up files are additionally denied statfs, truncate, fsync and fallocate",
    "facs.stratafs-copy-up.internal-file-denied-ops",
    "pkm_kunit_copy_up_internal_file_is_denied_the_listed_operations")

copy_up("an internally opened file is marked copy-up-internal and carries a zero granted mask",
    "facs.stratafs-copy-up.internal-file-zero-mask",
    "pkm_kunit_copy_up_internal_file_fails_closed and " ..
    "pkm_kunit_copy_up_internal_file_is_denied_the_listed_operations")

copy_up("an internal file is unusable after phase completion, from another task, or after SCM_RIGHTS",
    "facs.stratafs-copy-up.internal-file-scope",
    "pkm_kunit_copy_up_internal_file_fails_closed")

copy_up("each armed phase has a distinct generation and an internal file is sealed to it",
    "facs.stratafs-copy-up.generation-seal",
    "pkm_kunit_copy_up_internal_file_fails_closed, " ..
    "pkm_kunit_copy_up_phases_are_exclusive_and_generations_sealed (the " ..
    "overflow) and pkm_kunit_copy_up_anonymous_object_must_be_bound (a file " ..
    "from the create phase is refused in populate)")

copy_up("the read-only provider-directory cursor resumes across a bounded recovery batch",
    "facs.stratafs-copy-up.directory-cursor-resume",
    "pkm_kunit_copy_up_source_directory_resume_is_exact")

kunit_stub("one copy-up-internal backing file can be adopted by the outer description",
    "facs.stratafs-copy-up.backing-adoption",
    "pkm_kunit_copy_up_backing_file_requires_explicit_adoption",
    NO_SURFACE)

kunit_stub("adoption copies the outer description's granted and continuous-audit snapshot",
    "facs.stratafs-copy-up.adoption-copies-snapshot",
    "pkm_kunit_backing_file_inherits_exact_outer_snapshot, with " ..
    "pkm_kunit_copy_up_adopts_outer_descriptor_snapshot in pkm_kunit_copy_up",
    NO_SURFACE)

kunit_stub("adoption is one-shot and requires the backing file mode",
    "facs.stratafs-copy-up.adoption-one-shot",
    "pkm_kunit_backing_file_rejects_unsettled_outer_handles",
    NO_SURFACE)

copy_up("adoption happens before the anonymous staged object is published",
    "facs.stratafs-copy-up.adoption-before-publish",
    "pkm_kunit_copy_up_anonymous_object_must_be_bound, where the backing file " ..
    "is adopted against the still-bound tmpfile binding, idle, and refused " ..
    "while a phase is armed — the ordering itself is StrataFS's")

copy_up("the deletion scope is bound once to the exact provider parent, dentry and inode",
    "facs.stratafs-copy-up.deletion-scope-binding",
    "pkm_kunit_copy_up_deferred_deletion_is_bound_to_the_exact_entry")

copy_up("an entry that no longer names the descriptor's inode is never unlinked",
    "facs.stratafs-copy-up.deletion-identity-check",
    "pkm_kunit_copy_up_deferred_deletion_is_bound_to_the_exact_entry, where " ..
    "the bound entry and the outer entry are each unlinked and re-created " ..
    "under the same name and the scope admits neither")

copy_up("an unresolvable, corrupt or oversized provider descriptor fails the phase",
    "facs.stratafs-copy-up.unresolvable-descriptor-fails-phase",
    "pkm_kunit_copy_up_begin_pins_provider_without_a_check, where a provider " ..
    "wearing bytes that do not parse fails begin_create with nothing armed " ..
    "and the destination still negative",
    "a corrupt descriptor cannot be planted from the guest (§3.9.5's raw-write " ..
    "denial), and a provider without one is denied before any phase is armed")

copy_up("there is no window in which a staging inode carries a weaker descriptor",
    "facs.stratafs-copy-up.no-weak-window",
    "pkm_kunit_copy_up_exact_sd_is_installed_and_cached (the descriptor is " ..
    "installed and the cache seeded inside inode creation, and a second " ..
    "initialisation fails) and pkm_kunit_copy_up_named_flow_is_exact_and_exempt")

copy_up("on a stacking destination the pinned bytes are installed on the real inode",
    "facs.stratafs-copy-up.stacking-real-inode-install",
    "pkm_kunit_copy_up_stacked_tmpfile_binds_outer_inode")

copy_up("the context does not override the unconditional denial of POSIX ACL mutation",
    "facs.stratafs-copy-up.posix-acl-still-denied",
    "pkm_kunit_copy_up_named_flow_is_exact_and_exempt, at the hook, on the " ..
    "bound staged object in populate",
    "no filesystem the kernel-only guest can mount supports POSIX ACLs, so " ..
    "the hook's denial cannot be told from the filesystem's refusal there")

copy_up("the capability clone call accepts only an exactly matching kernel buffer",
    "facs.stratafs-copy-up.clone-call-preconditions",
    "pkm_kunit_copy_up_anonymous_object_must_be_bound and " ..
    "pkm_kunit_copy_up_scope_is_exact")

copy_up("the clone re-reads the provider and fails with ESTALE if the value changed",
    "facs.stratafs-copy-up.clone-estale-on-change",
    "pkm_kunit_copy_up_anonymous_object_must_be_bound, where the provider's " ..
    "capability is changed between the pin and the install")

copy_up("the clone installs through the ordinary VFS path with XATTR_CREATE",
    "facs.stratafs-copy-up.clone-through-vfs",
    "pkm_kunit_copy_up_anonymous_object_must_be_bound, where the installed " ..
    "bytes are read back and a second install is the VFS's EEXIST")

copy_up("the CAP_SETFCAP gate is satisfied only synchronously inside the validated call",
    "facs.stratafs-copy-up.setfcap-synchronous-only",
    "pkm_kunit_copy_up_anonymous_object_must_be_bound (the install succeeds " ..
    "for a principal the gate would otherwise refuse, and the condition is " ..
    "clear on return) and pkm_kunit_copy_up_scope_is_exact",
    NO_SURFACE .. "; the caller-facing half — that raw setxattr can never install " ..
    "a file capability — is covered above")

copy_up("nothing is installed when the provider had no attribute or a different one",
    "facs.stratafs-copy-up.no-install-on-mismatch",
    "pkm_kunit_copy_up_anonymous_object_must_be_bound and " ..
    "pkm_kunit_copy_up_scope_is_exact")

kunit_stub("two copy-up event emissions are best-effort and drop silently",
    "facs.stratafs-copy-up.emission-best-effort",
    "pkm_kunit_stratafs_audit_emission_is_best_effort, for the over-long " ..
    "operation string and path; the allocation-failure condition has no witness",
    NO_SURFACE .. "; the drop conditions are an allocation failure and an " ..
    "operation string StrataFS itself chooses, neither of which a caller can " ..
    "influence", "pkm_kunit_misc")
