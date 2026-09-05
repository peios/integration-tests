-- PKM §3.9.5 — the canonical descriptor xattr is sealed in all three
-- directions, and the parsed object in the inode blob is what readers
-- actually consult.
--
-- The seal is what makes the rest of the section testable at all: no
-- caller, SYSTEM included, can read, write or remove
-- `security.peios.sd`, so every descriptor in the guest arrived through
-- `kacs_set_sd`, inheritance, synthesis or the boot seed. It is also
-- what makes a corrupt descriptor unreachable from here — planting one
-- means writing invalid bytes into that xattr, which is precisely what
-- the hook refuses, so the two corruption cases are deferred to KUnit.
--
-- The cache cases are concurrency claims. A worker issues its syscalls
-- one at a time, so overlapping two of them means `syscall_async` on two
-- workers with both calls in flight before either is awaited.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local facs = require("helpers.facs")
local access = require("helpers.access")
local token = require("helpers.token")

local vm = provium:vm("v", "kernel-only"):boot()

local ALL_INFO = kacs.SI.OWNER | kacs.SI.GROUP | kacs.SI.DACL
local OI_CI = access.ACE_FLAG.OBJECT_INHERIT | access.ACE_FLAG.CONTAINER_INHERIT
local CANONICAL = "security.peios.sd"
local B = facs.workspace(vm, "storage")

--- A complete descriptor granting `mask` to Everyone.
local function descriptor(mask)
    return access.sd({
        owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM,
        dacl = access.acl({ access.ace(access.ACE.ALLOWED, mask or kacs.ALL_RIGHTS,
            token.SID.EVERYONE, OI_CI) }),
    })
end

--- An in-flight `kacs_set_sd` by pathname on `who`.
local function set_sd_async(who, path, sd)
    return who:syscall_async(kacs.SYS.SET_SD, {
        args = { sys.AT_FDCWD, 0, ALL_INFO, 0, #sd, 0 },
        bufs = { sys.cstr(path), sd }, ptrs = { 1, 3 },
    })
end

--- An in-flight `kacs_get_sd` by pathname on `who`.
local function get_sd_async(who, path)
    return who:syscall_async(kacs.SYS.GET_SD, {
        args = { sys.AT_FDCWD, 0, ALL_INFO, 0, 4096, 0 },
        bufs = { sys.cstr(path), string.rep("\0", 4096) }, ptrs = { 1, 3 },
    })
end

-- ---- the seal -------------------------------------------------------------

test("raw writes and removals of the canonical xattr are denied",
    { spec = "PKM *facs.storage.xattr-protection" }, function(t)
        local f = facs.file(vm, B .. "/sealed", "content")
        -- The agent is SYSTEM, holds every privilege, and the file's DACL
        -- grants Everyone every right — the denial is unconditional.
        local w = sys.setxattr(vm, f, CANONICAL, descriptor())
        t:assert_eq(w.ret, -1, "a raw write of a valid descriptor is refused")
        t:assert_eq(w.errno, sys.E.ACCES, "EACCES")
        local junk = sys.setxattr(vm, f, CANONICAL, "not a descriptor")
        t:assert_eq(junk.errno, sys.E.ACCES, "and so is a raw write of anything else")
        local rm = sys.removexattr(vm, f, CANONICAL)
        t:assert_eq(rm.ret, -1, "the descriptor is never detached from a file")
        t:assert_eq(rm.errno, sys.E.ACCES, "EACCES")
        -- An unrelated xattr on the same inode is unaffected: the hook
        -- keys on the canonical name, not on the operation.
        t:assert_eq(sys.setxattr(vm, f, "user.ordinary", "v").ret, 0,
            "an ordinary xattr is written normally")
        t:assert_eq(sys.removexattr(vm, f, "user.ordinary").ret, 0, "and removed normally")
        -- The same descriptor written through the dedicated interface
        -- lands, which is the point: the name is not unwritable, the
        -- ordinary xattr path to it is.
        local narrow = descriptor(kacs.RIGHT.READ_DATA | kacs.RIGHT.READ_ATTRIBUTES)
        t:assert_eq(kacs.set_sd(vm, f, narrow, ALL_INFO).ret, 0,
            "set-security writes it")
        t:assert_eq(kacs.get_sd(vm, f, ALL_INFO), narrow, "and it took effect")
    end)

test("raw reads of the canonical xattr are denied too, so no SACL leaks under READ_CONTROL",
    { spec = "PKM *facs.storage.xattr-read-denied" }, function(t)
        local f = facs.file(vm, B .. "/unreadable", "content")
        local sacl = access.acl({ access.ace(access.ACE.AUDIT, kacs.ALL_RIGHTS,
            token.SID.EVERYONE, access.ACE_FLAG.SUCCESSFUL_ACCESS) })
        local sd = access.sd({
            owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM,
            dacl = access.acl({ access.ace(access.ACE.ALLOWED, kacs.ALL_RIGHTS,
                token.SID.EVERYONE) }),
            sacl = sacl,
        })
        t:assert_eq(kacs.set_sd(vm, f, sd, ALL_INFO | kacs.SI.SACL).ret, 0,
            "the file carries a SACL")
        -- The xattr holds the whole descriptor, SACL included.
        local value, errno = sys.getxattr(vm, f, CANONICAL)
        t:assert(not value, "a raw read is refused")
        t:assert_eq(errno, sys.E.ACCES, "EACCES")
        t:assert(not sys.getxattr_size(vm, f, CANONICAL),
            "even asking only for its size")
        -- It is listed, so a caller knows it is there — it just cannot be
        -- read except through kacs_get_sd, which separates the two rights.
        local listed = false
        for _, n in ipairs(sys.listxattr(vm, f) or {}) do
            if n == CANONICAL then listed = true end
        end
        t:assert(listed, "the name is enumerable")
        t:assert(kacs.get_sd(vm, f, kacs.SI.DACL),
            "READ_CONTROL reaches the DACL through kacs_get_sd")
        local back = kacs.get_sd(vm, f, kacs.SI.SACL)
        t:assert(back, "and ACCESS_SYSTEM_SECURITY reaches the SACL")
        t:assert(access.parse_sd(back).sacl, "which is where the SACL is served from")
    end)

-- ---- the cached parsed object ---------------------------------------------

test("the validated descriptor is cached on the inode, not on the name it was reached by",
    { spec = "PKM *facs.storage.cache-parsed-in-inode-blob" }, function(t)
        local f = facs.file(vm, B .. "/blob", "content")
        local other = B .. "/blob-link"
        t:assert_eq(sys.link(vm, f, other).ret, 0, "a second name for one inode")
        local narrow = descriptor(kacs.RIGHT.READ_DATA | kacs.RIGHT.READ_ATTRIBUTES)
        t:assert_eq(kacs.set_sd(vm, f, narrow, ALL_INFO).ret, 0,
            "the descriptor is written through one name")
        t:assert_eq(kacs.get_sd(vm, other, ALL_INFO), narrow,
            "and the other name serves the same cached object")
        -- Readers never reparse untrusted storage bytes: the raw xattr is
        -- unreadable to anyone, yet every read answers, immediately and
        -- identically.
        t:assert(not sys.getxattr(vm, f, CANONICAL), "the storage bytes stay sealed")
        for _ = 1, 20 do
            t:assert_eq(kacs.get_sd(vm, other, ALL_INFO), narrow, "and every read agrees")
        end
    end)

test("a reader is not blocked by a writer, and never sees a partial descriptor",
    { spec = "PKM *facs.storage.readers-rcu-no-mutex" }, function(t)
        local f = facs.file(vm, B .. "/rcu-read", "content")
        local a = descriptor(kacs.RIGHT.READ_DATA)
        local b = descriptor(kacs.RIGHT.WRITE_DATA)
        t:assert_eq(kacs.set_sd(vm, f, a, ALL_INFO).ret, 0, "an initial descriptor")
        local writer, reader = vm:spawn_worker(), vm:spawn_worker()
        local ok, err = pcall(function()
            for i = 1, 40 do
                local want = (i % 2 == 0) and a or b
                -- Both calls are in flight before either is awaited, so the
                -- read overlaps the write.
                local w = set_sd_async(writer, f, want)
                local r = get_sd_async(reader, f)
                w:await()
                local res = r:await()
                t:assert(res.ret > 0, "round " .. i .. ": the read completed: " ..
                    sys.errname(res.errno))
                local seen = res.out_bufs[2]:sub(1, res.ret)
                t:assert(seen == a or seen == b,
                    "round " .. i .. ": it saw one whole descriptor, not a mixture")
            end
        end)
        writer:kill(); writer:join(); reader:kill(); reader:join()
        if not ok then error(err, 0) end
    end)

test("a writer swaps the pointer atomically — every observation is a complete object",
    { spec = "PKM *facs.storage.writers-rcu-swap" }, function(t)
        -- The two descriptors differ in length as well as content, so a
        -- torn read would be visible as a short or over-long buffer rather
        -- than only as odd bytes.
        local f = facs.file(vm, B .. "/rcu-swap", "content")
        local small = access.sd({
            owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM,
            dacl = access.acl({ access.ace(access.ACE.ALLOWED, kacs.ALL_RIGHTS,
                token.SID.EVERYONE) }),
        })
        local large = access.sd({
            owner = token.SID.LOCAL_SYSTEM, group = token.SID.LOCAL_SYSTEM,
            dacl = access.acl({
                access.ace(access.ACE.ALLOWED, kacs.ALL_RIGHTS, token.SID.EVERYONE),
                access.ace(access.ACE.ALLOWED, kacs.ALL_RIGHTS, token.SID.ADMINISTRATORS),
                access.ace(access.ACE.ALLOWED, kacs.ALL_RIGHTS, token.SID.TEST_USER),
            }),
        })
        t:assert_neq(#small, #large, "the two descriptors are different sizes")
        t:assert_eq(kacs.set_sd(vm, f, small, ALL_INFO).ret, 0, "an initial descriptor")
        local writer, reader = vm:spawn_worker(), vm:spawn_worker()
        local sizes = {}
        local ok, err = pcall(function()
            for i = 1, 40 do
                local want = (i % 2 == 0) and small or large
                local w = set_sd_async(writer, f, want)
                local r = get_sd_async(reader, f)
                w:await()
                local res = r:await()
                t:assert(res.ret > 0, "round " .. i .. ": the read completed")
                local seen = res.out_bufs[2]:sub(1, res.ret)
                t:assert(seen == small or seen == large,
                    "round " .. i .. ": a whole object, either the old one or the new")
                sizes[#seen] = true
            end
        end)
        writer:kill(); writer:join(); reader:kill(); reader:join()
        if not ok then error(err, 0) end
        t:assert(sizes[#small] or sizes[#large], "and at least one length was observed")
    end)

test("lazy population from the xattr installs the parsed object by compare-and-swap",
    { spec = "PKM *facs.storage.population-lazy-cas",
      covered_by = "kunit:pkm_kunit_file",
      skip = "the losing side of the CAS frees its own copy, which has no " ..
             "guest-visible effect — every racing reader answers correctly " ..
             "either way; runs under pkm_kunit_file_sd_cache_population_" ..
             "cas_loser_frees_copy and pkm_kunit_file_sd_cache_population_" ..
             "from_valid_xattr" }, function(t) end)

test("eviction frees the cached descriptor RCU-safely",
    { spec = "PKM *facs.storage.eviction-rcu-safe",
      covered_by = "kunit:pkm_kunit_file",
      skip = "inode eviction is not something the guest can schedule against " ..
             "an in-flight permission check; runs under " ..
             "pkm_kunit_inode_eviction_drains_pins_before_freeing, which pins a " ..
             "cached descriptor, runs the eviction destructor and finds the " ..
             "pinned object whole until the pin is released" },
    function(t) end)

test("set-security releases the inode security lock across the xattr write",
    { spec = "PKM *facs.storage.setsd-releases-lock-across-write" }, function(t)
        -- Holding it across the write would invert the ordering the access
        -- path takes (i_rwsem then the FACS lock), which is exactly what an
        -- ordinary xattr write does. Driving both against one inode at once
        -- is the reachable witness: with the lock held across the write the
        -- two orders deadlock, and neither call would ever return.
        local f = facs.file(vm, B .. "/lockorder", "content")
        -- Every right, because the churning caller needs FILE_WRITE_EA on
        -- the same inode the set-security call is rewriting.
        local a = descriptor(kacs.ALL_RIGHTS)
        local setter, xattrer = vm:spawn_worker(), vm:spawn_worker()
        local ok, err = pcall(function()
            for i = 1, 40 do
                local w = set_sd_async(setter, f, a)
                local x = xattrer:syscall_async(sys.NR.setxattr, {
                    args = { 0, 0, 0, 1, 0 },
                    bufs = { sys.cstr(f), sys.cstr("user.churn"), "v" },
                    ptrs = { 0, 1, 2 },
                })
                t:assert_eq(w:await().ret, 0, "round " .. i .. ": set_sd returned")
                t:assert_eq(x:await().ret, 0, "round " .. i .. ": setxattr returned")
            end
        end)
        setter:kill(); setter:join(); xattrer:kill(); xattrer:join()
        if not ok then error(err, 0) end
        t:assert_eq(kacs.get_sd(vm, f, ALL_INFO), a, "and the descriptor is intact")
    end)

test("two concurrent set-security calls are last-writer-wins, not a blend",
    { spec = "PKM *facs.storage.concurrent-setsd-last-writer-wins" }, function(t)
        local f = facs.file(vm, B .. "/lastwriter", "content")
        local a = descriptor(kacs.RIGHT.READ_DATA)
        local b = descriptor(kacs.RIGHT.WRITE_DATA)
        local w1, w2 = vm:spawn_worker(), vm:spawn_worker()
        local ok, err = pcall(function()
            for i = 1, 40 do
                local p1 = set_sd_async(w1, f, a)
                local p2 = set_sd_async(w2, f, b)
                t:assert_eq(p1:await().ret, 0, "round " .. i .. ": one write succeeded")
                t:assert_eq(p2:await().ret, 0, "round " .. i .. ": so did the other")
                local now = kacs.get_sd(vm, f, ALL_INFO)
                t:assert(now == a or now == b,
                    "round " .. i .. ": the survivor is exactly one of the two inputs")
            end
        end)
        w1:kill(); w1:join(); w2:kill(); w2:join()
        if not ok then error(err, 0) end
    end)

-- ---- invalidation from the other end --------------------------------------

--- An overlay over `lower`, returning the overlay root and the upper dir.
local function overlay(t, name, lower)
    local root = B .. "/" .. name
    for _, d in ipairs({ "up", "wk", "mnt" }) do
        vm:mkdir(root .. "/" .. d, { parents = true })
        kacs.set_sd(vm, root .. "/" .. d, kacs.grant(kacs.ALL_RIGHTS))
    end
    kacs.set_sd(vm, root, kacs.grant(kacs.ALL_RIGHTS))
    local m = sys.mount(vm, { source = "overlay", target = root .. "/mnt",
        fstype = "overlay",
        data = "lowerdir=" .. lower .. ",upperdir=" .. root .. "/up,workdir=" ..
            root .. "/wk" })
    t:assert_eq(m.ret, 0, "the overlay mounts: " .. sys.errname(m.errno))
    return root .. "/mnt", root .. "/up"
end

test("a descriptor set through a stacking filesystem reaches the inode beneath as well",
    { spec = "PKM *facs.storage.stacking-two-inodes" }, function(t)
        local lower = B .. "/two-lower"
        vm:mkdir(lower, { parents = true })
        kacs.set_sd(vm, lower, kacs.grant(kacs.ALL_RIGHTS))
        local wide = descriptor(kacs.ALL_RIGHTS)
        local file = facs.file(vm, lower .. "/f", "lower")
        t:assert_eq(kacs.set_sd(vm, file, wide, ALL_INFO).ret, 0, "the lower descriptor")
        local mnt, up = overlay(t, "two-inodes", lower)

        local narrow = descriptor(kacs.RIGHT.READ_DATA | kacs.RIGHT.READ_ATTRIBUTES)
        t:assert_eq(kacs.set_sd(vm, mnt .. "/f", narrow, ALL_INFO).ret, 0,
            "a set through the overlay")
        t:assert_eq(kacs.get_sd(vm, mnt .. "/f", ALL_INFO), narrow,
            "the inode the caller named carries it")
        t:assert(sys.stat(vm, up .. "/f"),
            "the write re-entered on the real inode beneath, materialising it")
        t:assert_eq(kacs.get_sd(vm, up .. "/f", ALL_INFO), narrow,
            "and that second inode carries the same descriptor")
        sys.umount(vm, mnt)
    end)

test("the canonical xattr landing on an inode drops that inode's cached entry",
    { spec = "PKM *facs.storage.xattr-write-drops-cache" }, function(t)
        -- The backing inode is the one that matters: overlayfs resolves and
        -- caches a descriptor for an upper inode during its own metadata
        -- work, so an entry can exist there from the moment the object did.
        -- Keying invalidation on the xattr rather than on the writer is
        -- what makes the second inode agree afterwards.
        local lower = B .. "/drop-lower"
        vm:mkdir(lower, { parents = true })
        kacs.set_sd(vm, lower, kacs.grant(kacs.ALL_RIGHTS))
        local file = facs.file(vm, lower .. "/f", "lower")
        t:assert_eq(kacs.set_sd(vm, file, descriptor(kacs.ALL_RIGHTS), ALL_INFO).ret, 0,
            "a wide descriptor on the lower object")
        local mnt, up = overlay(t, "drop-cache", lower)

        -- Materialise the upper copy and give the backing inode a cached
        -- entry of its own by reading its descriptor directly.
        t:assert_eq(kacs.set_sd(vm, mnt .. "/f", descriptor(kacs.ALL_RIGHTS),
            ALL_INFO).ret, 0, "the object is copied up")
        local first = assert(kacs.get_sd(vm, up .. "/f", ALL_INFO),
            "the backing inode's descriptor is cached")

        local narrow = descriptor(kacs.RIGHT.READ_DATA)
        t:assert_eq(kacs.set_sd(vm, mnt .. "/f", narrow, ALL_INFO).ret, 0,
            "a second set through the overlay")
        t:assert_neq(first, narrow, "which changes the descriptor")
        t:assert_eq(kacs.get_sd(vm, up .. "/f", ALL_INFO), narrow,
            "and the backing inode's stale entry was dropped rather than served")
        sys.umount(vm, mnt)
    end)

-- ---- corruption -----------------------------------------------------------

test("a structurally invalid descriptor xattr fails closed",
    { spec = "PKM *facs.storage.corrupt-fails-closed",
      covered_by = "kunit:pkm_kunit_file",
      skip = "planting one means writing invalid bytes into " ..
             "security.peios.sd, which §3.9.5's own write denial refuses " ..
             "for every caller including SYSTEM, and no filesystem the " ..
             "kernel-only guest can mount carries a pre-corrupted one; " ..
             "runs under pkm_kunit_file_sd_cache_population_corrupt_fails_closed" },
    function(t) end)

test("a corrupt descriptor emits one audit event per cache population, not per access",
    { spec = "PKM *facs.storage.corrupt-audit-once-per-population",
      covered_by = "kunit:pkm_kunit_file",
      skip = "same reason: the corrupt state cannot be produced from the " ..
             "guest; runs under pkm_kunit_file_sd_cache_population_corrupt_emits_once" },
    function(t) end)

test("an NFS mount is the one managed class where the server enforces independently",
    { spec = "PKM *facs.storage.nfs-dual-authority",
      skip = "no coverage anywhere: the kernel-only profile has no network " ..
             "and no NFS server, so a mount whose server can deny I/O FACS " ..
             "allowed cannot be constructed; no KUnit case models a second " ..
             "enforcement authority either" }, function(t) end)
