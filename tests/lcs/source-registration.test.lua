-- §5.8.2, Registration and Slots: the privilege the device open
-- demands, everything REG_SRC_REGISTER validates, what a source slot
-- is, and the exact failure vocabulary of resuming a Down one.
--
-- Slots are never freed, so every successful registration in this file
-- costs one of the thirty-two the kernel allows. `registered` counts
-- them, and the last case spends what is left deliberately.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")
local token = require("helpers.token")

local vm = provium:vm("v", "kernel-only"):boot()

local MAX_SOURCES = 32
local MAX_HIVES = 64
local U64_MAX = 0xFFFFFFFFFFFFFFFF

local registered = 0
--- Register and count the slot it consumed.
local function register(src, o)
    local ok, err = src:register(o)
    if ok then registered = registered + 1 end
    return ok, err
end

local src = lcs.source(vm)
local TEST_KEY = src:key("Machine\\Software\\Test")
assert(register(src))
src:pump()
local w = vm:spawn_worker()

--- A source that is expected to fail registration, so it costs no slot.
--- Returns its errno.
local function refused(hives, o)
    local s = lcs.source(vm, { hives = hives })
    local ok = s:register(o)
    local errno = s.errno
    if ok then registered = registered + 1; s:close() end
    return errno, ok
end

-- The device ---------------------------------------------------------

-- The device node's own file permissions are checked before the LCS
-- .open handler runs, and an ordinary principal is refused there with
-- EACCES without ever reaching it. These cases therefore use a SYSTEM
-- principal projected to uid 0, which passes that check and reaches
-- the handler, so the EPERM below is LCS's own.
local SYSTEM_UID0 = { user_sid = token.SID.LOCAL_SYSTEM,
                      projected_uid = 0, projected_gid = 0 }
local function system_principal(extra)
    local spec = {}
    for k, v in pairs(SYSTEM_UID0) do spec[k] = v end
    for k, v in pairs(extra or {}) do spec[k] = v end
    return spec
end

test("/dev/pkm_registry opens only for a caller holding SeTcbPrivilege enabled",
    { spec = "PKM *source.register.open-requires-enabled-setcbprivilege" }, function(t)
        local TCB = token.bit(token.PRIV.TCB)
        token.as_principal(t, vm, system_principal(), function(w2)
            local fd, errno = sys.open(w2, lcs.DEVICE, sys.O.RDWR)
            t:assert(not fd, "a principal without SeTcbPrivilege gets no descriptor at all")
            t:assert_eq(errno, sys.E.PERM, "EPERM from the open() handler")
        end)
        token.as_principal(t, vm, system_principal({ privs_present = TCB, privs_enabled = 0 }),
            function(w2)
                local fd, errno = sys.open(w2, lcs.DEVICE, sys.O.RDWR)
                t:assert(not fd, "holding it is not enough: the handler wants it enabled")
                t:assert_eq(errno, sys.E.PERM, "EPERM")
            end)
        token.as_principal(t, vm, system_principal({ privs_present = TCB, privs_enabled = TCB }),
            function(w2)
                local fd, errno = sys.open(w2, lcs.DEVICE, sys.O.RDWR)
                t:assert(fd, "with it enabled the device opens: " .. sys.errname(errno or 0))
                if fd then sys.close(w2, fd) end
            end)
    end)

-- What registration validates ----------------------------------------

test("a hive name must be valid, and CurrentUser is reserved in any casing",
    { spec = "PKM *source.register.hive-name-valid-and-not-currentuser" }, function(t)
        t:assert_eq(refused({ { name = "CurrentUser" } }), sys.E.INVAL,
            "CurrentUser is reserved: EINVAL")
        t:assert_eq(refused({ { name = "currentuser" } }), sys.E.INVAL,
            "and the reservation is on the folded name")
        t:assert_eq(refused({ { name = "Bad\\Name" } }), sys.E.INVAL,
            "a separator in a hive name is not a valid name")
        t:assert_eq(refused({ { name = "Bad\0Name" } }), sys.E.INVAL,
            "nor is an embedded null byte")
    end)

test("a hive's root GUID may not be nil",
    { spec = "PKM *source.register.root-guid-not-nil" }, function(t)
        t:assert_eq(refused({ { name = "NilRoot", root = lcs.NULL_GUID } }), sys.E.INVAL,
            "an all-zero root GUID is refused")
    end)

test("the root GUIDs within one request must be distinct from each other",
    { spec = "PKM *source.register.root-guids-distinct-within-request" }, function(t)
        local shared = lcs.guid()
        t:assert_eq(refused({ { name = "DupRootA", root = shared },
                              { name = "DupRootB", root = shared } }), sys.E.INVAL,
            "two hives in one request may not share a root GUID")
    end)

test("a hive without RSI_HIVE_PRIVATE carries no scope GUID",
    { spec = "PKM *source.register.scope-guid-only-for-private-hive" }, function(t)
        t:assert_eq(refused({ { name = "ScopedGlobal", scope = lcs.guid() } }), sys.E.INVAL,
            "a scope GUID on a global hive is refused")
    end)

test("no unknown flag bits may be set",
    { spec = "PKM *source.register.no-unknown-flag-bits" }, function(t)
        t:assert_eq(refused({ { name = "BadFlagsA", flags = 0x02 } }), sys.E.INVAL,
            "the bit above RSI_HIVE_PRIVATE is reserved")
        t:assert_eq(refused({ { name = "BadFlagsB", flags = 0x80000000 } }), sys.E.INVAL,
            "and so is the top one")
    end)

test("the reported maximum sequence must be one the kernel can allocate above",
    { spec = "PKM *source.register.max-sequence-overflow-is-eoverflow" }, function(t)
        -- Only the refusal is exercised here: a source that registers
        -- a near-U64_MAX maximum raises the kernel's global counter to
        -- match, and nothing in this VM could allocate a sequence
        -- number afterwards.
        t:assert_eq(refused({ { name = "SeqOverflow" } }, { max_sequence = U64_MAX }),
            sys.E.OVERFLOW, "U64_MAX cannot be advanced past: EOVERFLOW")
        t:assert(not select(2, refused({ { name = "SeqOverflow" } }, { max_sequence = U64_MAX })),
            "and the source is never made Active")
    end)

test("the hive count is bounded by MaxHivesPerSource, and exceeding it is ENOSPC",
    { spec = "PKM *source.register.hive-and-source-counts-are-enospc" }, function(t)
        local too_many = {}
        for i = 1, MAX_HIVES + 1 do too_many[i] = { name = "Wide" .. i } end
        t:assert_eq(refused(too_many), sys.E.NOSPC,
            (MAX_HIVES + 1) .. " hives is past MaxHivesPerSource (" .. MAX_HIVES .. "): ENOSPC")
    end)

-- Route identity ------------------------------------------------------

test("a route identity may not collide with one an Active source holds",
    { spec = "PKM *source.register.no-route-identity-collision" }, function(t)
        t:assert_eq(refused({ { name = "Machine" } }), sys.E.EXIST,
            "Machine is Active on another slot: EEXIST")
        t:assert_eq(refused({ { name = "MACHINE" } }), sys.E.EXIST,
            "and the identity is the folded name, so a different casing collides too")
    end)

test("private hive collisions are scoped: the same name in different scopes is fine",
    { spec = "PKM *source.register.private-hive-collisions-are-scoped" }, function(t)
        local scope_a, scope_b = lcs.guid(), lcs.guid()
        local a = lcs.source(vm, { hives = {
            { name = "Scoped", private = true, scope = scope_a } } })
        t:assert(register(a), "the first scope registers")
        local b = lcs.source(vm, { hives = {
            { name = "Scoped", private = true, scope = scope_b } } })
        local ok, err = register(b)
        t:assert(ok, "and a second source takes the same name in another scope: " ..
            tostring(err))
        local c = lcs.source(vm, { hives = {
            { name = "Scoped", private = true, scope = scope_a } } })
        t:assert(not c:register(), "but not the same name in the same scope")
        t:assert_eq(c.errno, sys.E.EXIST, "EEXIST, from the Active collision")
    end)

test("a successful registration creates a slot the hive routes through",
    { spec = "PKM *source.register.success-creates-a-slot" }, function(t)
        local r = lcs.open_key(src, w, -1, "Machine\\Software\\Test", lcs.RIGHT.KEY_READ)
        t:assert(r.ret >= 0, "the registered Machine hive answers an open: " ..
            sys.errname(r.errno or 0))
        sys.close(w, r.ret)
    end)

-- Slots, Down slots, and resume ---------------------------------------

test("a source's hives go Down together: status is a property of the slot",
    { spec = "PKM *source.register.status-is-per-slot" }, function(t)
        local pair = lcs.source(vm, { hives = { { name = "PairOne" }, { name = "PairTwo" } } })
        pair:key("PairOne\\K")
        pair:key("PairTwo\\K", { root = pair.hives[2].root })
        t:assert(register(pair), "a source backing two hives registers")
        pair:pump()
        for _, h in ipairs({ "PairOne", "PairTwo" }) do
            local r = lcs.open_key(pair, w, -1, h .. "\\K", lcs.RIGHT.KEY_READ)
            t:assert(r.ret >= 0, h .. " serves while the slot is Active")
            sys.close(w, r.ret)
        end
        pair:disconnect()
        for _, h in ipairs({ "PairOne", "PairTwo" }) do
            local r = lcs.open_key(pair, w, -1, h .. "\\K", lcs.RIGHT.KEY_READ)
            t:assert_eq(r.errno, sys.E.IO,
                h .. " is unavailable too: one connection closed, both hives Down")
        end
    end)

test("a Down slot keeps its hive identities reserved, and collision checks see it",
    { spec = { "PKM *source.register.down-slot-keeps-its-identities", "PKM *source.register.collision-checks-see-down-slots" } }, function(t)
        local first = lcs.source(vm, { hives = { { name = "Reserved" } } })
        t:assert(register(first), "a source registers Reserved")
        first:disconnect()
        -- Nothing was unregistered and no identity retired: a fresh
        -- source cannot simply take the name.
        local usurper = lcs.source(vm, { hives = { { name = "Reserved" } } })
        t:assert(not usurper:register(), "a new source with a new root cannot take the name")
        t:assert_eq(usurper.errno, sys.E.STALE,
            "the Down slot is still there to collide with, and its root does not match: ESTALE")
        t:assert(first:register(), "the original hive set still resumes it")
        first:close()
    end)

test("collision checks see Down slots, but EEXIST is reserved for an Active one",
    { spec = "PKM *source.register.eexist-only-from-active-collision" }, function(t)
        local down = lcs.source(vm, { hives = { { name = "NeverEexist" } } })
        t:assert(register(down), "register, then go Down")
        down:disconnect()
        local other = lcs.source(vm, { hives = { { name = "NeverEexist" } } })
        t:assert(not other:register(), "a colliding registration is refused")
        t:assert(other.errno ~= sys.E.EXIST,
            "but never with EEXIST, which only an Active collision produces (got " ..
            sys.errname(other.errno) .. ")")
        t:assert_eq(other.errno, sys.E.STALE, "ESTALE, the stale-identity failure")
    end)

test("a request whose only mismatch is a stale root GUID fails ESTALE",
    { spec = "PKM *source.register.stale-root-guid-is-estale" }, function(t)
        local s = lcs.source(vm, { hives = { { name = "StaleRoot" } } })
        t:assert(register(s), "register")
        s:disconnect()
        local stale = lcs.source(vm, { hives = { { name = "StaleRoot" } } })
        t:assert(not stale:register(), "the same name with a different root is refused")
        t:assert_eq(stale.errno, sys.E.STALE, "ESTALE: stale identity data, nothing else wrong")
    end)

test("other partial or malformed resume attempts fail EINVAL",
    { spec = { "PKM *source.register.other-resume-mismatch-is-einval", "PKM *source.register.resume-requires-exact-hive-set" } }, function(t)
        local s = lcs.source(vm, { hives = { { name = "ExactA" }, { name = "ExactB" } } })
        t:assert(register(s), "a two-hive source registers")
        s:disconnect()
        local roots = { s.hives[1].root, s.hives[2].root }

        local subset = lcs.source(vm, { hives = { { name = "ExactA", root = roots[1] } } })
        t:assert(not subset:register(), "one of the two hives is a partial resume")
        t:assert_eq(subset.errno, sys.E.INVAL, "EINVAL")

        local superset = lcs.source(vm, { hives = {
            { name = "ExactA", root = roots[1] }, { name = "ExactB", root = roots[2] },
            { name = "ExactC" } } })
        t:assert(not superset:register(), "and so is a superset: new hives need a new slot")
        t:assert_eq(superset.errno, sys.E.INVAL, "EINVAL")

        local visibility = lcs.source(vm, { hives = {
            { name = "ExactA", root = roots[1], private = true, scope = lcs.guid() },
            { name = "ExactB", root = roots[2] } } })
        t:assert(not visibility:register(), "a hive that changed visibility does not match")
        t:assert_eq(visibility.errno, sys.E.INVAL, "EINVAL")

        t:assert(s:register(), "the exact set still resumes")
        s:close()
    end)

test("nothing is implicitly retired: a failed superset resume leaves the Down slot as it was",
    { spec = "PKM *source.register.no-implicit-down-slot-retirement" }, function(t)
        local s = lcs.source(vm, { hives = { { name = "NoRetire" } } })
        t:assert(register(s), "register")
        s:disconnect()
        local grow = lcs.source(vm, { hives = {
            { name = "NoRetire", root = s.hives[1].root }, { name = "NoRetireExtra" } } })
        t:assert(not grow:register(), "adding a hive by resuming is refused")
        t:assert_eq(grow.errno, sys.E.INVAL, "EINVAL")
        -- And the slot is neither gone nor mutated.
        local fresh = lcs.source(vm, { hives = { { name = "NoRetire" } } })
        t:assert(not fresh:register(), "the identity is still reserved afterwards")
        t:assert_eq(fresh.errno, sys.E.STALE, "still ESTALE, not a free name")
        t:assert(s:register(), "and the original set still resumes it")
        s:close()
    end)

test("EEXIST wins when an Active collision and a stale Down slot both apply",
    { spec = "PKM *source.register.eexist-wins-over-estale" }, function(t)
        local down = lcs.source(vm, { hives = { { name = "BothStale" } } })
        t:assert(register(down), "one hive name goes Down with a root of its own")
        down:disconnect()
        local active = lcs.source(vm, { hives = { { name = "BothActive" } } })
        t:assert(register(active), "another is Active")
        -- One request, both problems: a stale root for BothStale and a
        -- collision with the Active BothActive.
        local both = lcs.source(vm, { hives = { { name = "BothStale" }, { name = "BothActive" } } })
        t:assert(not both:register(), "the request is refused")
        t:assert_eq(both.errno, sys.E.EXIST, "EEXIST, which takes precedence over ESTALE")
    end)

test("a hive's identity is its folded name, visibility, scope and root GUID",
    { spec = "PKM *source.register.hive-identity-fields" }, function(t)
        local s = lcs.source(vm, { hives = {
            { name = "IdentCase", private = true, scope = lcs.guid() } } })
        t:assert(register(s), "register a private hive")
        s:disconnect()
        local root, scope = s.hives[1].root, s.hives[1].scope

        local folded = lcs.source(vm, { hives = {
            { name = "IDENTCASE", root = root, private = true, scope = scope } } })
        t:assert(folded:register(),
            "a differently cased name is the same identity: the folded name is what is stored")
        folded:disconnect()

        -- Visibility and scope are identity fields too, so a *global*
        -- hive of the same name is a different route identity: it does
        -- not collide with the private one and takes a slot of its own.
        local global_same_name = lcs.source(vm, { hives = { { name = "IdentCase" } } })
        t:assert(register(global_same_name),
            "a global hive of the same name is a separate identity, not a collision")
        t:assert(s:register(), "and the private identity still resumes on its own slot")
        s:close()
    end)

test("a replacement source is authenticated by SeTcbPrivilege, not by process identity",
    { spec = "PKM *source.register.resume-authenticated-by-privilege-not-pid" }, function(t)
        local TCB = token.bit(token.PRIV.TCB)
        local s = lcs.source(vm, { hives = { { name = "Replaced" } } })
        s:key("Replaced\\K")
        t:assert(register(s), "the original process registers")
        s:pump()
        s:disconnect()
        -- A different process, a different token, no relationship to
        -- the first: the hive set and the privilege are the whole test.
        token.as_principal(t, vm, system_principal({ privs_present = TCB, privs_enabled = TCB }),
            function(w2)
            local ok, err = s:register({ who = w2 })
            t:assert(ok, "an unrelated principal holding SeTcbPrivilege takes the slot over: " ..
                tostring(err))
            local r = lcs.open_key(s, w, -1, "Replaced\\K", lcs.RIGHT.KEY_READ)
            t:assert(r.ret >= 0, "and the hive serves again: " .. sys.errname(r.errno or 0))
            if r.ret >= 0 then sys.close(w, r.ret) end
        end)
        -- The principal's worker died with the callback, so the slot is
        -- Down again; nothing recorded the pid either way.
        s.fd = nil
        s.registered = false
    end)

test("registering needs the privilege too: a principal without it never reaches the ioctl",
    { spec = "PKM *source.register.open-requires-enabled-setcbprivilege" }, function(t)
        local s = lcs.source(vm, { hives = { { name = "Unprivileged" } } })
        token.as_principal(t, vm, system_principal(), function(w2)
            local ok = s:register({ who = w2 })
            t:assert(not ok, "a principal without SeTcbPrivilege cannot register")
            t:assert_eq(s.errno, sys.E.PERM, "EPERM, refused at the device open")
        end)
    end)

test("on a successful resume the slot becomes Active again",
    { spec = "PKM *source.register.resume-activates-slot-and-replays" }, function(t)
        local s = lcs.source(vm, { hives = { { name = "Resumed" } } })
        s:key("Resumed\\K")
        t:assert(register(s), "register")
        s:pump()
        s:disconnect()
        local down = lcs.open_key(s, w, -1, "Resumed\\K", lcs.RIGHT.KEY_READ)
        t:assert_eq(down.errno, sys.E.IO, "while Down the hive is unavailable")
        t:assert(s:register(), "the same hive set resumes it")
        s:pump()
        local up = lcs.open_key(s, w, -1, "Resumed\\K", lcs.RIGHT.KEY_READ)
        t:assert(up.ret >= 0, "and the slot is Active again: " .. sys.errname(up.errno or 0))
        sys.close(w, up.ret)
        s:close()
    end)

test("existing key fds resume working without being reopened",
    { spec = "PKM *source.register.key-fds-survive-a-resume" }, function(t)
        local s = lcs.source(vm, { hives = { { name = "FdSurvives" } } })
        local key = s:key("FdSurvives\\K")
        s:value(key, "V", lcs.TYPE.DWORD, lcs.dword(11))
        t:assert(register(s), "register")
        s:pump()
        local r = lcs.open_key(s, w, -1, "FdSurvives\\K", lcs.KEY_ALL_ACCESS)
        t:assert(r.ret >= 0, "open a key: " .. sys.errname(r.errno or 0))
        local fd = r.ret

        s:disconnect()
        t:assert_eq(lcs.query_value(s, w, fd, "V").errno, sys.E.IO,
            "the fd stays valid while the source is away, and round trips fail EIO")
        t:assert(s:resume(), "resume the slot")
        s:pump()
        local q = lcs.query_value(s, w, fd, "V")
        t:assert_eq(q.ret, 0, "the same fd works again with no reopen: " ..
            sys.errname(q.errno or 0))
        t:assert_eq(q.data, lcs.dword(11), "and reads the value through it")
        sys.close(w, fd)
        s:close()
    end)

test("a key whose GUID is gone from the restarted source orphans its fd with ENOENT",
    { spec = "PKM *source.register.missing-guid-after-resume-orphans-fd" }, function(t)
        local s = lcs.source(vm, { hives = { { name = "LostGuid" } } })
        local key = s:key("LostGuid\\K")
        s:value(key, "V", lcs.TYPE.DWORD, lcs.dword(1))
        t:assert(register(s), "register")
        s:pump()
        local r = lcs.open_key(s, w, -1, "LostGuid\\K", lcs.KEY_ALL_ACCESS)
        t:assert(r.ret >= 0, "open a key: " .. sys.errname(r.errno or 0))
        local fd = r.ret

        s:disconnect()
        -- The source came back from an older backup: the key record is
        -- simply not there any more.
        s.store.keys[key] = nil
        s.store.values[key] = nil
        t:assert(s:register(), "resume with the same hive set")
        s:pump()
        local q = lcs.query_value(s, w, fd, "V")
        t:assert_eq(q.errno, sys.E.NOENT,
            "the first operation after the resume cannot find the GUID: ENOENT")
        sys.close(w, fd)
        s:close()
    end)

-- The source count ----------------------------------------------------
--
-- Last, because slots are never freed: this case spends every one that
-- is left.

test("the registered source count is bounded by MaxRegisteredSources, and exceeding it is ENOSPC",
    { spec = "PKM *source.register.hive-and-source-counts-are-enospc" }, function(t)
        t:assert(registered < MAX_SOURCES,
            "the file has not already exhausted the slot table (" .. registered .. " used)")
        local errno, at
        for i = registered + 1, MAX_SOURCES + 4 do
            local s = lcs.source(vm, { hives = { { name = "Fill" .. i } } })
            if s:register() then
                registered = registered + 1
            else
                errno, at = s.errno, i
                break
            end
        end
        t:assert(errno, "registration eventually fails")
        t:assert_eq(registered, MAX_SOURCES,
            "after exactly MaxRegisteredSources (" .. MAX_SOURCES .. ") slots exist")
        t:assert_eq(errno, sys.E.NOSPC, "and the source past the limit gets ENOSPC")
    end)
