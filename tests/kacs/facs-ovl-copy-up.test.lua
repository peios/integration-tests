-- PKM §3.9.8 — overlayfs creates. Overlayfs performs the real creation
-- on the upper layer, in a directory the caller never named and under
-- the mounter's credentials, so KACS resolves the descriptor first and
-- hands it down on a credential.
--
-- Everything here is observed from the descriptor the created object
-- ends up wearing, which is the only thing the mechanism exists to get
-- right. The experiment that makes each case sharp is to give the
-- *backing* directories a descriptor that differs from the merged one:
-- if inheritance ran on the upper or the workdir the difference shows,
-- and if it ran under the mounter's identity the owner shows.
--
-- The agent mounts every overlay here, so "the mounter" is SYSTEM; a
-- create by a minted principal is therefore the case where a wrong
-- subject would be visible.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local facs = require("helpers.facs")
local access = require("helpers.access")
local token = require("helpers.token")

local vm = provium:vm("v", "kernel-only"):boot()

local SI = kacs.SI
local ALL_INFO = SI.OWNER | SI.GROUP | SI.DACL
local OI_CI = access.ACE_FLAG.OBJECT_INHERIT | access.ACE_FLAG.CONTAINER_INHERIT
local CANONICAL = "security.peios.sd"
local B = facs.workspace(vm, "ovl")
local CHANGE_NOTIFY = token.bit(token.PRIV.CHANGE_NOTIFY)
local CREATOR_OWNER = token.sid(3, 0)     -- S-1-3-0

--- A descriptor that is recognisable by which trustee it names.
---
--- Everyone is granted every right first, because the agent has to keep
--- working on these objects — SYSTEM is bound by the DACL like anyone
--- else once the object is not its own. `trustee` is the marker: a
--- second, identical ACE naming a SID that appears nowhere else, so a
--- child's DACL says which directory its inheritance came from.
local function sd_for(trustee, opts)
    opts = opts or {}
    local aces = opts.aces
    if not aces then
        aces = { access.ace(access.ACE.ALLOWED, kacs.ALL_RIGHTS,
            token.SID.EVERYONE, OI_CI) }
        if trustee then
            aces[#aces + 1] = access.ace(access.ACE.ALLOWED, kacs.ALL_RIGHTS,
                trustee, OI_CI)
        end
    end
    return access.sd({
        owner = opts.owner or token.SID.LOCAL_SYSTEM,
        group = opts.group or token.SID.LOCAL_SYSTEM,
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

--- Build an overlay. Returns a table of the paths involved.
---
--- `opts.lower` overrides the lower directory (for the cases whose lower
--- is on another filesystem); otherwise one is made under the workspace
--- and granted every right.
local function overlay(t, name, opts)
    opts = opts or {}
    local root = B .. "/" .. name
    local o = { root = root, mnt = root .. "/mnt", up = root .. "/up",
                wk = root .. "/wk", lo = opts.lower or (root .. "/lo") }
    vm:mkdir(root, { parents = true })
    kacs.set_sd(vm, root, kacs.grant(kacs.ALL_RIGHTS))
    for _, d in ipairs({ "up", "wk", "mnt" }) do
        vm:mkdir(root .. "/" .. d, { parents = true })
        kacs.set_sd(vm, root .. "/" .. d, kacs.grant(kacs.ALL_RIGHTS))
    end
    if not opts.lower then
        vm:mkdir(o.lo, { parents = true })
        kacs.set_sd(vm, o.lo, kacs.grant(kacs.ALL_RIGHTS))
    end
    local m = sys.mount(vm, { source = "overlay", target = o.mnt, fstype = "overlay",
        data = "lowerdir=" .. o.lo .. ",upperdir=" .. o.up .. ",workdir=" .. o.wk })
    t:assert_eq(m.ret, 0, "the overlay mounts: " .. sys.errname(m.errno))
    o.release = function() sys.umount(vm, o.mnt) end
    return o
end

--- Overlay for the duration of `fn`, always unmounted.
local function with_overlay(t, name, fn, opts)
    local o = overlay(t, name, opts)
    local ok, err = pcall(fn, o)
    o.release()
    if not ok then error(err, 0) end
end

--- Write to `path` through the overlay, which forces a copy-up.
local function write_through(t, path, data)
    local fd, errno = sys.open(vm, path, sys.O.WRONLY)
    t:assert(fd, "open " .. path .. " for write: " .. sys.errname(errno or 0))
    sys.write(vm, fd, data)
    sys.close(vm, fd)
end

--- A minted principal that can traverse to the overlay and nothing more.
local function as_user(t, fn)
    token.as_principal(t, vm, { privs_present = CHANGE_NOTIFY,
                                privs_enabled = CHANGE_NOTIFY }, fn)
end

-- ---- resolving before the create ------------------------------------------

test("the descriptor is resolved before the create, from the parent the caller named",
    { spec = "PKM *facs.ovl-copy-up.resolve-before-create" }, function(t)
        with_overlay(t, "before", function(o)
            -- The backing directories carry a descriptor that inheritance
            -- would produce a visibly different answer from.
            local backing = sd_for(token.SID.TEST_USER_2)
            t:assert_eq(kacs.set_sd(vm, o.up, backing, ALL_INFO).ret, 0, "upper marked")
            t:assert_eq(kacs.set_sd(vm, o.wk, backing, ALL_INFO).ret, 0, "workdir marked")
            local merged = sd_for(token.SID.TEST_USER)
            t:assert_eq(kacs.set_sd(vm, o.mnt, merged, ALL_INFO).ret, 0,
                "and the merged directory carries a different one")

            local fd = assert(sys.open(vm, o.mnt .. "/made", sys.O.WRONLY | sys.O.CREAT,
                tonumber("644", 8)))
            sys.close(vm, fd)
            local d = access.parse_sd(assert(kacs.get_sd(vm, o.mnt .. "/made", ALL_INFO)))
            t:assert(names(d, token.SID.TEST_USER),
                "it inherited from the directory the caller named")
            t:assert(not names(d, token.SID.TEST_USER_2),
                "not from the upper or work directory the create really happened in")
        end)
    end)

test("the copy-up hook resolves the source object's own effective descriptor",
    { spec = "PKM *facs.ovl-copy-up.copy-up-hook-resolves-source" }, function(t)
        with_overlay(t, "cuhook", function(o)
            local source = facs.file(vm, o.lo .. "/f", "lower")
            local distinctive = sd_for(token.SID.TEST_USER_2)
            t:assert_eq(kacs.set_sd(vm, source, distinctive, ALL_INFO).ret, 0,
                "the source has its own descriptor")
            local before = assert(kacs.get_sd(vm, source, ALL_INFO))

            write_through(t, o.mnt .. "/f", "rewritten")
            t:assert(sys.stat(vm, o.up .. "/f"), "the object was materialised in the upper")
            t:assert_eq(kacs.get_sd(vm, o.up .. "/f", ALL_INFO), before,
                "wearing the source's descriptor, byte for byte")
        end)
    end)

test("the create hook resolves inheritance from the overlay parent for the calling principal",
    { spec = "PKM *facs.ovl-copy-up.create-hook-resolves-inheritance" }, function(t)
        with_overlay(t, "crhook", function(o)
            local parent = sd_for(nil, { aces = {
                access.ace(access.ACE.ALLOWED, kacs.ALL_RIGHTS, token.SID.EVERYONE, OI_CI),
                access.ace(access.ACE.ALLOWED, kacs.ALL_RIGHTS, CREATOR_OWNER, OI_CI),
            } })
            t:assert_eq(kacs.set_sd(vm, o.mnt, parent, ALL_INFO).ret, 0, "the parent")
            as_user(t, function(w)
                local fd, errno = sys.open(w, o.mnt .. "/byuser",
                    sys.O.WRONLY | sys.O.CREAT, tonumber("644", 8))
                t:assert(fd, "a principal creates through the overlay: " ..
                    sys.errname(errno or 0))
                sys.close(w, fd)
                t:assert_eq(sys.mkdir(w, o.mnt .. "/byuserdir").ret, 0,
                    "and a directory")
            end)
            local d = access.parse_sd(assert(kacs.get_sd(vm, o.mnt .. "/byuser", ALL_INFO)))
            t:assert_eq(d.owner, token.SID.TEST_USER,
                "the object is owned by the principal, not by the mounter")
            t:assert_eq(d.dacl.count, 2, "two ACEs came down by inheritance")
        end)
    end)

test("the inode creation path prefers the attached descriptor over computing inheritance",
    { spec = "PKM *facs.ovl-copy-up.creation-prefers-attached" }, function(t)
        with_overlay(t, "prefers", function(o)
            -- Inheritance from the real create parent — the upper
            -- directory — would give the upper's ACE. The attached
            -- descriptor wins instead.
            t:assert_eq(kacs.set_sd(vm, o.up, sd_for(token.SID.TEST_USER_2),
                ALL_INFO).ret, 0, "a distinctive upper directory")
            local source = facs.file(vm, o.lo .. "/f", "lower")
            local mine = sd_for(token.SID.TEST_GROUP)
            t:assert_eq(kacs.set_sd(vm, source, mine, ALL_INFO).ret, 0,
                "and a distinctive source")
            write_through(t, o.mnt .. "/f", "rewritten")
            local d = access.parse_sd(assert(kacs.get_sd(vm, o.up .. "/f", ALL_INFO)))
            t:assert(names(d, token.SID.TEST_GROUP),
                "the created inode wears the attached descriptor")
            t:assert(not names(d, token.SID.TEST_USER_2),
                "rather than what inheritance from the real parent would give")
        end)
    end)

test("the descriptor rides on a credential rather than on any armed context",
    { spec = "PKM *facs.ovl-copy-up.descriptor-on-credential" }, function(t)
        -- Both hooks are exercised in one overlay, back to back, and each
        -- creation gets its own answer: a copy-up gets the source's, an
        -- ordinary create gets inheritance. Nothing is armed beforehand
        -- and nothing has to be disarmed between them.
        with_overlay(t, "cred", function(o)
            local parent = sd_for(token.SID.TEST_USER)
            t:assert_eq(kacs.set_sd(vm, o.mnt, parent, ALL_INFO).ret, 0, "the parent")
            local source = facs.file(vm, o.lo .. "/f", "lower")
            local sdesc = sd_for(token.SID.TEST_GROUP)
            t:assert_eq(kacs.set_sd(vm, source, sdesc, ALL_INFO).ret, 0, "the source")

            write_through(t, o.mnt .. "/f", "rewritten")
            local fd = assert(sys.open(vm, o.mnt .. "/new", sys.O.WRONLY | sys.O.CREAT,
                tonumber("644", 8)))
            sys.close(vm, fd)

            local copied = access.parse_sd(assert(kacs.get_sd(vm, o.up .. "/f", ALL_INFO)))
            t:assert(names(copied, token.SID.TEST_GROUP),
                "the copy-up used the source's descriptor")
            local created = access.parse_sd(assert(kacs.get_sd(vm, o.up .. "/new", ALL_INFO)))
            t:assert(names(created, token.SID.TEST_USER),
                "and the create immediately after used inheritance")
            t:assert(not names(created, token.SID.TEST_GROUP),
                "with nothing left over from the copy-up before it")
        end)
    end)

test("the credential is reverted on every exit path, including a failed create",
    { spec = "PKM *facs.ovl-copy-up.credential-reverted-on-every-path" }, function(t)
        with_overlay(t, "revert", function(o)
            local strict = sd_for(nil, { aces = {
                access.ace(access.ACE.ALLOWED, kacs.ALL_RIGHTS & ~kacs.RIGHT.ADD_FILE,
                    token.SID.EVERYONE, OI_CI) } })
            t:assert_eq(sys.mkdir(vm, o.mnt .. "/closed").ret, 0, "a directory")
            t:assert_eq(sys.mkdir(vm, o.mnt .. "/open").ret, 0, "and another")
            t:assert_eq(kacs.set_sd(vm, o.mnt .. "/closed", strict, ALL_INFO).ret, 0,
                "one refuses new files")
            t:assert_eq(kacs.set_sd(vm, o.mnt .. "/open", sd_for(token.SID.TEST_USER),
                ALL_INFO).ret, 0, "the other has a distinctive descriptor")
            as_user(t, function(w)
                local fd, errno = sys.open(w, o.mnt .. "/closed/nope",
                    sys.O.WRONLY | sys.O.CREAT, tonumber("644", 8))
                t:assert(not fd, "the first create fails")
                t:assert_eq(errno, sys.E.ACCES, "EACCES")
                local ok = sys.open(w, o.mnt .. "/open/yes",
                    sys.O.WRONLY | sys.O.CREAT, tonumber("644", 8))
                t:assert(ok, "the next one succeeds")
                sys.close(w, ok)
            end)
            local d = access.parse_sd(assert(kacs.get_sd(vm, o.mnt .. "/open/yes", ALL_INFO)))
            t:assert(names(d, token.SID.TEST_USER),
                "and wears its own parent's inheritance, not a descriptor left over " ..
                "from the failed create")
        end)
    end)

test("a create over a whiteout is one creation, not two",
    { spec = "PKM *facs.ovl-copy-up.one-creation-per-scope" }, function(t)
        with_overlay(t, "whiteout", function(o)
            facs.file(vm, o.lo .. "/gone", "lower")
            local parent = sd_for(token.SID.TEST_USER)
            t:assert_eq(kacs.set_sd(vm, o.mnt, parent, ALL_INFO).ret, 0,
                "a distinctive merged parent")
            t:assert_eq(sys.unlink(vm, o.mnt .. "/gone").ret, 0,
                "removing the lower-only file leaves a whiteout")
            local fd = assert(sys.open(vm, o.mnt .. "/gone", sys.O.WRONLY | sys.O.CREAT,
                tonumber("644", 8)))
            sys.close(vm, fd)
            -- The temporary object is renamed over the whiteout rather than
            -- a second one being made, so exactly one descriptor was
            -- computed and it is the one the caller's parent implies.
            local d = access.parse_sd(assert(kacs.get_sd(vm, o.mnt .. "/gone", ALL_INFO)))
            t:assert(names(d, token.SID.TEST_USER), "inherited from the merged parent")
            t:assert_eq(kacs.get_sd(vm, o.up .. "/gone", ALL_INFO),
                kacs.get_sd(vm, o.mnt .. "/gone", ALL_INFO),
                "and the one object in the upper layer is that same object")
        end)
    end)

test("releasing the credential releases the descriptor",
    { spec = "PKM *facs.ovl-copy-up.release-frees-descriptor",
      covered_by = "kunit:pkm_kunit_copy_up",
      skip = "the descriptor's lifetime is a kernel allocation freed by the " ..
             "credential destructor, with no guest-visible effect; runs under " ..
             "pkm_kunit_overlay_release_frees_the_pending_descriptor" },
    function(t) end)

test("a credential derived from one carrying a pending descriptor does not inherit it",
    { spec = "PKM *facs.ovl-copy-up.derived-credential-does-not-inherit",
      covered_by = "kunit:pkm_kunit_copy_up",
      skip = "deriving a credential inside the override scope is something " ..
             "only overlayfs itself can do — the scope wraps exactly one " ..
             "creation and never returns to userspace inside it; runs under " ..
             "pkm_kunit_overlay_copy_up_sd_is_not_inherited, for both the " ..
             "prepare and the transfer hook" }, function(t) end)

-- ---- what a copied-up object keeps ----------------------------------------

test("a copied-up object keeps its own descriptor rather than inheriting a new one",
    { spec = "PKM *facs.ovl-copy-up.copy-up-preserves-descriptor" }, function(t)
        with_overlay(t, "preserve", function(o)
            -- A deliberately narrow descriptor: if the copy-up inherited,
            -- writing to the file would widen it for everybody else.
            local source = facs.file(vm, o.lo .. "/narrow", "lower")
            local narrow = sd_for(nil, { aces = {
                access.ace(access.ACE.ALLOWED, kacs.ALL_RIGHTS
                    & ~(kacs.RIGHT.WRITE_DAC | kacs.RIGHT.WRITE_OWNER
                        | kacs.RIGHT.DELETE), token.SID.EVERYONE) } })
            t:assert_eq(kacs.set_sd(vm, source, narrow, ALL_INFO).ret, 0, "narrow source")
            t:assert_eq(kacs.set_sd(vm, o.mnt, sd_for(token.SID.EVERYONE),
                ALL_INFO).ret, 0, "a permissive merged parent")
            local before = assert(kacs.get_sd(vm, source, ALL_INFO))

            write_through(t, o.mnt .. "/narrow", "rewritten")
            t:assert_eq(kacs.get_sd(vm, o.mnt .. "/narrow", ALL_INFO), before,
                "the write did not re-decide the object's policy")
            t:assert_eq(kacs.get_sd(vm, o.lo .. "/narrow", ALL_INFO), before,
                "and the lower object is unchanged")
        end)
    end)

test("the source descriptor carried across may itself have been synthesised",
    { spec = "PKM *facs.ovl-copy-up.source-descriptor-may-be-synthesised" }, function(t)
        -- A ramfs lower: it declares no xattr support, so nothing on it can
        -- store a descriptor and every one is synthesised under the mount
        -- policy. The copy-up must still carry that answer across.
        local lower = "/ovl-ramfs"
        t:assert(kacs.new_mount(vm, "ramfs", lower, nil, nil), "a ramfs lower layer")
        local fd = assert(sys.open(vm, lower .. "/f", sys.O.WRONLY | sys.O.CREAT,
            tonumber("644", 8)))
        sys.write(vm, fd, "ramlower")
        sys.close(vm, fd)
        t:assert_eq(#(sys.listxattr(vm, lower .. "/f") or {}), 0,
            "the source stores no descriptor at all")
        local synthesised = assert(kacs.get_sd(vm, lower .. "/f", ALL_INFO),
            "but it has an effective one")

        with_overlay(t, "synth-source", function(o)
            write_through(t, o.mnt .. "/f", "rewritten")
            t:assert(sys.stat(vm, o.up .. "/f"), "the copy exists")
            t:assert_eq(kacs.get_sd(vm, o.up .. "/f", ALL_INFO), synthesised,
                "carrying the synthesised source descriptor")
        end, { lower = lower })
    end)

-- ---- what an ordinary create inherits -------------------------------------

test("a create inherits from the merged directory, including a descriptor set at runtime",
    { spec = "PKM *facs.ovl-copy-up.create-inherits-from-overlay" }, function(t)
        with_overlay(t, "inherit", function(o)
            local first = assert(sys.open(vm, o.mnt .. "/before",
                sys.O.WRONLY | sys.O.CREAT, tonumber("644", 8)))
            sys.close(vm, first)
            local before = assert(kacs.get_sd(vm, o.mnt .. "/before", ALL_INFO))
            -- Set through the overlay inode, which is a distinct inode from
            -- the backing directory the create really uses.
            t:assert_eq(kacs.set_sd(vm, o.mnt, sd_for(token.SID.TEST_GROUP_2),
                ALL_INFO).ret, 0, "the merged directory is given a new descriptor")
            local second = assert(sys.open(vm, o.mnt .. "/after",
                sys.O.WRONLY | sys.O.CREAT, tonumber("644", 8)))
            sys.close(vm, second)
            local after = access.parse_sd(assert(kacs.get_sd(vm, o.mnt .. "/after",
                ALL_INFO)))
            t:assert_neq(kacs.get_sd(vm, o.mnt .. "/after", ALL_INFO), before,
                "children created afterwards are governed by it")
            t:assert(names(after, token.SID.TEST_GROUP_2), "the new trustee inherited")
            t:assert(not names(access.parse_sd(before), token.SID.TEST_GROUP_2),
                "which the earlier child does not carry")
        end)
    end)

test("CREATOR OWNER resolves to the principal making the object, not to the mounter",
    { spec = "PKM *facs.ovl-copy-up.creator-owner-resolves-to-caller" }, function(t)
        with_overlay(t, "creator", function(o)
            local parent = sd_for(nil, { aces = {
                access.ace(access.ACE.ALLOWED, kacs.ALL_RIGHTS, token.SID.EVERYONE, OI_CI),
                access.ace(access.ACE.ALLOWED, kacs.ALL_RIGHTS, CREATOR_OWNER, OI_CI),
            } })
            t:assert_eq(kacs.set_sd(vm, o.mnt, parent, ALL_INFO).ret, 0,
                "the merged parent carries a CREATOR OWNER ACE")
            as_user(t, function(w)
                local fd = assert(sys.open(w, o.mnt .. "/mine",
                    sys.O.WRONLY | sys.O.CREAT, tonumber("644", 8)))
                sys.close(w, fd)
            end)
            local d = access.parse_sd(assert(kacs.get_sd(vm, o.mnt .. "/mine", ALL_INFO)))
            t:assert_eq(d.owner, token.SID.TEST_USER, "the owner is the creating principal")
            local resolved = {}
            for _, a in ipairs(d.dacl.aces) do resolved[#resolved + 1] = a.sid end
            local found = false
            for _, s in ipairs(resolved) do
                if s == token.SID.TEST_USER then found = true end
            end
            t:assert(found, "and CREATOR OWNER resolved to that principal")
            for _, s in ipairs(resolved) do
                t:assert_neq(s, CREATOR_OWNER, "no unresolved CREATOR OWNER survives")
            end
            t:assert_neq(d.owner, token.SID.LOCAL_SYSTEM,
                "which is not SYSTEM, the principal that mounted the overlay")
        end)
    end)

test("a descriptor supplied explicitly to a native create is honoured through the overlay",
    { spec = "PKM *facs.ovl-copy-up.supplied-descriptor-honoured" }, function(t)
        with_overlay(t, "supplied", function(o)
            t:assert_eq(kacs.set_sd(vm, o.mnt, sd_for(token.SID.TEST_USER),
                ALL_INFO).ret, 0, "an inheritable merged parent")
            local supplied = access.sd({
                owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM,
                dacl = access.acl({ access.ace(access.ACE.ALLOWED, kacs.ALL_RIGHTS,
                    token.SID.AUTHENTICATED_USERS) }),
            })
            local fd, status = facs.open(vm, o.mnt .. "/asked", {
                access = kacs.RIGHT.READ_DATA | kacs.RIGHT.WRITE_DATA
                    | kacs.RIGHT.READ_ATTRIBUTES | kacs.RIGHT.SYNCHRONIZE,
                disposition = kacs.DISPOSITION.CREATE, sd = supplied })
            t:assert(fd, "the native create succeeds: " .. sys.errname(status or 0))
            t:assert_eq(status, facs.STATUS.CREATED, "and created the file")
            sys.close(vm, fd)
            local d = access.parse_sd(assert(kacs.get_sd(vm, o.mnt .. "/asked", ALL_INFO)))
            t:assert_eq(d.dacl.count, 1, "the descriptor the caller asked for")
            t:assert_eq(d.dacl.aces[1].sid, token.SID.AUTHENTICATED_USERS, "verbatim")
            t:assert(not names(d, token.SID.TEST_USER),
                "not silently replaced by inheritance from the parent")
        end)
    end)

test("a caller with no token is left alone rather than denied here",
    { spec = "PKM *facs.ovl-copy-up.no-token-passes-through",
      covered_by = "kunit:pkm_kunit_copy_up",
      skip = "every task in the guest carries a KACS token — the boot token is " ..
             "installed before userspace — so a tokenless creator cannot be " ..
             "produced from a syscall; runs under " ..
             "pkm_kunit_overlay_create_without_a_token_defers and " ..
             "pkm_kunit_overlay_create_without_a_token_keeps_mounter_ids" },
    function(t) end)

-- ---- the canonical xattr --------------------------------------------------

test("the canonical descriptor xattr is discarded during the copy-up rather than replicated",
    { spec = "PKM *facs.ovl-copy-up.canonical-xattr-discarded" }, function(t)
        with_overlay(t, "xattr", function(o)
            local source = facs.file(vm, o.lo .. "/f", "lower")
            t:assert_eq(sys.setxattr(vm, source, "user.ordinary", "carried").ret, 0,
                "the source carries an ordinary xattr as well")
            local sdesc = sd_for(token.SID.TEST_GROUP)
            t:assert_eq(kacs.set_sd(vm, source, sdesc, ALL_INFO).ret, 0,
                "and its own descriptor")
            -- It could not be copied through the ordinary xattr path in any
            -- case: reading it there is denied for every caller.
            t:assert_eq(select(2, sys.getxattr(vm, source, CANONICAL)), sys.E.ACCES,
                "the canonical xattr is unreadable as an ordinary xattr")

            write_through(t, o.mnt .. "/f", "rewritten")
            local names = sys.listxattr(vm, o.up .. "/f") or {}
            local canonical, ordinary = 0, 0
            for _, n in ipairs(names) do
                if n == CANONICAL then canonical = canonical + 1 end
                if n == "user.ordinary" then ordinary = ordinary + 1 end
            end
            t:assert_eq(ordinary, 1, "the ordinary xattr was replicated by the copy")
            t:assert_eq(canonical, 1,
                "and the canonical name appears exactly once on the copy")
            t:assert_eq(kacs.get_sd(vm, o.up .. "/f", ALL_INFO), sdesc,
                "carrying the descriptor the credential brought, not a second copy")
            t:assert_eq(select(2, sys.getxattr(vm, o.up .. "/f", CANONICAL)), sys.E.ACCES,
                "still not readable or writable as an ordinary xattr")
            t:assert_eq(sys.setxattr(vm, o.up .. "/f", CANONICAL, sdesc).errno,
                sys.E.ACCES, "on the copy either")
        end)
    end)

-- ---- failure and the unmanaged case ---------------------------------------

test("failing to resolve the parent's descriptor, or being refused by it, fails the create",
    { spec = "PKM *facs.ovl-copy-up.resolve-failure-fails-create" }, function(t)
        with_overlay(t, "failure", function(o)
            local no_add = sd_for(nil, { aces = {
                access.ace(access.ACE.ALLOWED,
                    kacs.ALL_RIGHTS & ~(kacs.RIGHT.ADD_FILE | kacs.RIGHT.ADD_SUBDIRECTORY),
                    token.SID.EVERYONE, OI_CI) } })
            t:assert_eq(kacs.set_sd(vm, o.mnt, no_add, ALL_INFO).ret, 0,
                "the merged parent grants everything but the right to add an object")
            as_user(t, function(w)
                local fd, errno = sys.open(w, o.mnt .. "/nope",
                    sys.O.WRONLY | sys.O.CREAT, tonumber("644", 8))
                t:assert(not fd, "the create fails rather than falling back")
                t:assert_eq(errno, sys.E.ACCES, "EACCES")
                local mk = sys.mkdir(w, o.mnt .. "/nodir")
                t:assert_eq(mk.ret, -1, "and so does a mkdir")
                t:assert_eq(mk.errno, sys.E.ACCES, "EACCES")
            end)
            t:assert(not sys.stat(vm, o.up .. "/nope"),
                "nothing was left behind in the upper layer")
        end)
    end)

test("an object on an unmanaged mount passes through untouched",
    { spec = "PKM *facs.ovl-copy-up.unmanaged-untouched" }, function(t)
        -- sysfs is unmanaged, so a lower object on it has nothing to
        -- preserve. The overlay superblock itself is managed, so the merged
        -- inode needs a descriptor for the outer authorisation to pass —
        -- synthesise-ephemeral supplies one — and the copy that lands in
        -- the upper layer gets ordinary inheritance rather than a
        -- descriptor carried from a source that never had one.
        local o = overlay(t, "unmanaged", { lower = "/sys/kernel" })
        local ok, err = pcall(function()
            local fd = sys.open(vm, o.mnt, sys.O.PATH)
            t:assert_eq(kacs.set_mount_policy_ex(vm, fd,
                kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL, {}).ret, 0,
                "the overlay is adopted under a synthesise class")
            sys.close(vm, fd)
            t:assert_eq(kacs.get_sd(vm, "/sys/kernel/uevent_seqnum", ALL_INFO), nil,
                "the source is on an unmanaged mount and has no descriptor")
            local merged = assert(kacs.get_sd(vm, o.mnt .. "/uevent_seqnum", ALL_INFO),
                "the merged inode has a synthesised one")
            local c = sys.chmod(vm, o.mnt .. "/uevent_seqnum", tonumber("644", 8))
            t:assert_eq(c.ret, 0, "a metadata change forces a copy-up: " ..
                sys.errname(c.errno))
            t:assert(sys.stat(vm, o.up .. "/uevent_seqnum"), "the copy exists")
            local d = access.parse_sd(assert(kacs.get_sd(vm, o.up .. "/uevent_seqnum",
                ALL_INFO)))
            t:assert(d.dacl, "and it carries an ordinary descriptor of its own")
            t:assert(merged, "with nothing carried across from the unmanaged source")
        end)
        o.release()
        if not ok then error(err, 0) end
    end)
