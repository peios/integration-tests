-- PKM §5.2.1 Hives and Routing, §5.2.2 Private Hives — the routing
-- table built from registrations, route identity as (folded name,
-- scope), the Active/Unavailable status of a slot, the `CurrentUser\`
-- alias, and the private hives a scope GUID on the token unlocks.
--
-- The file never registers a hive called `Machine`: §5.2.1's claim that
-- the two names the kernel knows get no routing privilege is only
-- observable while `Machine` is unregistered.
--
-- A Down slot keeps its hive identities (§5.8.2), so each test that
-- takes a source down uses hive names of its own and never gives them
-- back.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")
local token = require("helpers.token")

local vm = provium:vm("v", "kernel-only"):boot()

local SCOPE_A, SCOPE_B = lcs.guid(), lcs.guid()
local USER_SID = token.sid_string(token.SID.TEST_USER)

-- The one source the read-only cases share: `Alpha`, `Users`, and three
-- routes called `Beta` — one global and two private, one per scope —
-- which is exactly the (name, scope) identity §5.2.1 describes.
local main_src
local function main()
    if main_src then return main_src end
    local src = lcs.source(vm, { hives = {
        { name = "Alpha" },
        { name = "Users" },
        { name = "Beta" },
        { name = "Beta", private = true, scope = SCOPE_A },
        { name = "Beta", private = true, scope = SCOPE_B },
    } })
    src.beta_global = src.hives[3].root
    src.beta_a = src.hives[4].root
    src.beta_b = src.hives[5].root

    src:key("Alpha\\Software\\Test")
    src:key("Users\\" .. USER_SID .. "\\Software")
    -- A key literally named CurrentUser, to show the alias is only ever
    -- the first component of a caller path.
    src:key("Users\\" .. USER_SID .. "\\CurrentUser\\Inner")
    src:symlink("Users\\" .. USER_SID .. "\\ToCurrentUser", "CurrentUser\\Software")
    src:symlink("Users\\" .. USER_SID .. "\\ToAlpha", "Alpha\\Software\\Test")
    src:symlink("Users\\" .. USER_SID .. "\\ToBeta", "Beta\\Where")

    src:key("Beta\\Where\\Global", { root = src.beta_global })
    src:key("Beta\\Where\\PrivateA", { root = src.beta_a })
    src:key("Beta\\Where\\PrivateB", { root = src.beta_b })
    assert(src:register())
    src:pump()
    main_src = src
    return src
end

--- Run `fn(worker)` as an ordinary user whose token carries `scopes`
--- (a list of 16-byte GUIDs) in that order.
local function as_scoped(t, scopes, fn)
    token.as_principal(t, vm, {
        lcs_credentials = lcs.lcs_credentials(scopes, {}),
    }, fn)
end

local function worker() return vm:spawn_worker() end
local function done(w) w:kill(); w:join() end

-- §5.2.1 routing ------------------------------------------------------

test("a name no source registered is ENOENT",
    { spec = "PKM *hive.routing.unregistered-is-enoent" }, function(t)
        local w = worker()
        local r = lcs.open_key(nil, w, -1, "Nowhere\\Anything", lcs.RIGHT.KEY_READ)
        t:assert_eq(r.errno, sys.E.NOENT,
            "an unregistered hive name is ENOENT: " .. sys.errname(r.errno or 0))
        done(w)
    end)

test("the routing table is built entirely from what registers",
    { spec = "PKM *hive.routing-table.built-from-registrations" }, function(t)
        local w = worker()
        -- Nothing static configures `Gamma`.
        local before = lcs.open_key(nil, w, -1, "Gamma\\Software", lcs.RIGHT.KEY_READ)
        t:assert_eq(before.errno, sys.E.NOENT,
            "before registration the name routes nowhere: " .. sys.errname(before.errno or 0))

        local src = lcs.source(vm, { hives = { { name = "Gamma" } } })
        src:key("Gamma\\Software")
        assert(src:register())
        src:pump()

        local after = lcs.open_key(src, w, -1, "Gamma\\Software", lcs.RIGHT.KEY_READ)
        t:assert(after.ret >= 0,
            "registering the name puts it in the table: " .. sys.errname(after.errno or 0))
        if after.ret >= 0 then sys.close(w, after.ret) end
        done(w)
        src:close()
    end)

test("an active route reaches the backing source, keyed by the root GUID it supplied",
    { spec = "PKM *hive.routing.active-routes-to-source" }, function(t)
        local src = main()
        local w = worker()
        local mark = src:mark()
        local r = lcs.open_key(src, w, -1, "Alpha\\Software\\Test", lcs.RIGHT.KEY_READ)
        t:assert(r.ret >= 0, "the open reached the source: " .. sys.errname(r.errno or 0))
        t:assert(#src:served(lcs.OP.LOOKUP, mark) >= 2,
            "and the source was asked to look each component up")
        if r.ret >= 0 then sys.close(w, r.ret) end
        done(w)
    end)

test("the hive's root GUID is the one the source supplied at registration",
    { spec = "PKM *hive.field.root-guid-supplied-by-source" }, function(t)
        local src = main()
        local w = worker()
        local mark = src:mark()
        local r = lcs.open_key(src, w, -1, "Alpha\\Software", lcs.RIGHT.KEY_READ)
        t:assert(r.ret >= 0, "open: " .. sys.errname(r.errno or 0))
        t:assert(#src:served(lcs.OP.LOOKUP, mark, src.hives[1].root) == 1,
            "the walk's first lookup names the root GUID the registration carried")
        if r.ret >= 0 then sys.close(w, r.ret) end
        done(w)
    end)

test("routing uses the first component of the path and nothing else",
    { spec = "PKM *hive.routing.uses-first-component" }, function(t)
        local src = main()
        local w = worker()
        local mark = src:mark()
        local r = lcs.open_key(src, w, -1, "Alpha\\Software\\Test", lcs.RIGHT.KEY_READ)
        t:assert(r.ret >= 0, "open: " .. sys.errname(r.errno or 0))
        local looked = src:served(lcs.OP.LOOKUP, mark)
        -- `Alpha` never appears as a child name: it was consumed by the
        -- routing table, and the walk starts at the root GUID.
        local names = {}
        for _, req in ipairs(looked) do
            names[#names + 1] = string.unpack("<s4", req.payload, 17)
        end
        t:assert_eq(table.concat(names, "/"), "Software/Test",
            "everything before the first separator routed; the rest was walked")
        if r.ret >= 0 then sys.close(w, r.ret) end
        done(w)
    end)

test("hive names are compared case-insensitively",
    { spec = "PKM *hive.field.name-case-insensitive" }, function(t)
        local src = main()
        local w = worker()
        for _, spelling in ipairs({ "ALPHA", "alpha", "aLpHa" }) do
            local r = lcs.open_key(src, w, -1, spelling .. "\\Software\\Test", lcs.RIGHT.KEY_READ)
            t:assert(r.ret >= 0,
                spelling .. " routes to the same hive as Alpha: " .. sys.errname(r.errno or 0))
            if r.ret >= 0 then sys.close(w, r.ret) end
        end
        done(w)
    end)

test("a hive name follows the rules for a key name component",
    { spec = "PKM *hive.name.follows-key-component-rules" }, function(t)
        local cases = {
            { name = "Back\\Slash", why = "no backslash" },
            { name = "Forward/Slash", why = "no forward slash" },
            { name = "Nul\0Byte", why = "no null byte" },
            { name = "", why = "non-empty" },
            { name = "\xff\xfe invalid", why = "valid UTF-8" },
            { name = string.rep("x", 256), why = "no longer than MaxPathComponentLength" },
        }
        for _, c in ipairs(cases) do
            local src = lcs.source(vm, { hives = { { name = c.name } } })
            local ok = src:register()
            t:assert(not ok, "a hive name must be " .. c.why)
            t:assert_eq(src.errno, sys.E.INVAL,
                "rejected with EINVAL (" .. c.why .. "): " .. sys.errname(src.errno or 0))
            src:close()
        end
    end)

-- §5.2.1 route identity -----------------------------------------------

test("a route is identified by the pair (folded name, scope)",
    { spec = "PKM *hive.route-identity.name-and-scope" }, function(t)
        local src = main()
        -- One source holds three routes called Beta: they differ only in
        -- scope, and all three were accepted at registration.
        t:assert_eq(#src.hives, 5, "the registration carried three Beta routes")
        local w = worker()
        local g = lcs.open_key(src, w, -1, "Beta\\Where\\Global", lcs.RIGHT.KEY_READ)
        t:assert(g.ret >= 0, "the global Beta is the one a scopeless thread reaches: "
            .. sys.errname(g.errno or 0))
        if g.ret >= 0 then sys.close(w, g.ret) end
        done(w)

        as_scoped(t, { SCOPE_A }, function(w2)
            local a = lcs.open_key(src, w2, -1, "Beta\\Where\\PrivateA", lcs.RIGHT.KEY_READ)
            t:assert(a.ret >= 0, "and scope A reaches a different Beta: "
                .. sys.errname(a.errno or 0))
            if a.ret >= 0 then sys.close(w2, a.ret) end
        end)
    end)

test("the same name may be held in different scopes",
    { spec = "PKM *hive.route-identity.same-name-in-different-scopes" }, function(t)
        local src = main()
        as_scoped(t, { SCOPE_B }, function(w2)
            local b = lcs.open_key(src, w2, -1, "Beta\\Where\\PrivateB", lcs.RIGHT.KEY_READ)
            t:assert(b.ret >= 0, "scope B's Beta is its own hive: " .. sys.errname(b.errno or 0))
            if b.ret >= 0 then sys.close(w2, b.ret) end
            local g = lcs.open_key(src, w2, -1, "Beta\\Where\\Global", lcs.RIGHT.KEY_READ)
            t:assert_eq(g.errno, sys.E.NOENT,
                "and the global Beta's key is not visible through it")
        end)
    end)

test("a source claiming a route another source already holds is rejected",
    { spec = "PKM *hive.route-identity.must-be-unique" }, function(t)
        local src = main()
        t:assert(src.registered, "the incumbent is Active")
        local rival = lcs.source(vm, { hives = { { name = "alpha" } } })
        local ok = rival:register()
        t:assert(not ok, "a second source may not claim a route that is already held")
        t:assert_eq(rival.errno, sys.E.EXIST,
            "the collision is reported: " .. sys.errname(rival.errno or 0))
        rival:close()
    end)

test("a hive is backed by exactly one source; a source may back many",
    { spec = "PKM *hive.one-source-per-hive" }, function(t)
        local src = main()
        -- One source backs five routes, and every one of them dispatches
        -- to it.
        local w = worker()
        local mark = src:mark()
        for _, path in ipairs({ "Alpha\\Software", "Users\\" .. USER_SID, "Beta\\Where" }) do
            local r = lcs.open_key(src, w, -1, path, lcs.RIGHT.KEY_READ)
            t:assert(r.ret >= 0, path .. " dispatches to the one source: "
                .. sys.errname(r.errno or 0))
            if r.ret >= 0 then sys.close(w, r.ret) end
        end
        t:assert(#src:served(lcs.OP.LOOKUP, mark) >= 3, "all three walks reached it")
        done(w)

        -- And a hive already backed cannot gain a second backing source.
        local rival = lcs.source(vm, { hives = { { name = "Beta" } } })
        t:assert(not rival:register(), "no second source may back Beta")
        rival:close()
    end)

-- §5.2.1 status -------------------------------------------------------

test("a slot's hives are Active together and Unavailable together",
    { spec = "PKM *hive.status-is-per-source-slot" }, function(t)
        local src = lcs.source(vm, { hives = { { name = "SlotA" }, { name = "SlotB" } } })
        src:key("SlotA\\Key")
        src:key("SlotB\\Key")
        assert(src:register())
        src:pump()
        local w = worker()
        for _, name in ipairs({ "SlotA", "SlotB" }) do
            local r = lcs.open_key(src, w, -1, name .. "\\Key", lcs.RIGHT.KEY_READ)
            t:assert(r.ret >= 0, name .. " is Active: " .. sys.errname(r.errno or 0))
            if r.ret >= 0 then sys.close(w, r.ret) end
        end

        src:disconnect()
        for _, name in ipairs({ "SlotA", "SlotB" }) do
            local r = lcs.open_key(nil, w, -1, name .. "\\Key", lcs.RIGHT.KEY_READ)
            t:assert_eq(r.errno, sys.E.IO,
                name .. " went Unavailable with the slot: " .. sys.errname(r.errno or 0))
        end
        done(w)
        src:close()
    end)

test("a hive's status is Active or Unavailable, tracking source connectivity",
    { spec = "PKM *hive.field.status-active-or-unavailable" }, function(t)
        local src = lcs.source(vm, { hives = { { name = "Statusy" } } })
        src:key("Statusy\\Key")
        assert(src:register())
        src:pump()
        local w = worker()
        local active = lcs.open_key(src, w, -1, "Statusy\\Key", lcs.RIGHT.KEY_READ)
        t:assert(active.ret >= 0, "Active while the source is connected: "
            .. sys.errname(active.errno or 0))
        if active.ret >= 0 then sys.close(w, active.ret) end

        src:disconnect()
        local down = lcs.open_key(nil, w, -1, "Statusy\\Key", lcs.RIGHT.KEY_READ)
        t:assert_eq(down.errno, sys.E.IO,
            "Unavailable once it disconnects: " .. sys.errname(down.errno or 0))

        -- And back: the same slot, taken over again, is Active.
        assert(src:resume())
        src:pump()
        local again = lcs.open_key(src, w, -1, "Statusy\\Key", lcs.RIGHT.KEY_READ)
        t:assert(again.ret >= 0, "and Active again when it comes back: "
            .. sys.errname(again.errno or 0))
        if again.ret >= 0 then sys.close(w, again.ret) end
        done(w)
        src:close()
    end)

test("a registered but Down hive is EIO",
    { spec = "PKM *hive.routing.down-is-eio" }, function(t)
        local src = lcs.source(vm, { hives = { { name = "Downish" } } })
        src:key("Downish\\Key")
        assert(src:register())
        src:pump()
        local w = worker()
        src:disconnect()
        local r = lcs.open_key(nil, w, -1, "Downish\\Key", lcs.RIGHT.KEY_READ)
        t:assert_eq(r.errno, sys.E.IO,
            "a Down route is EIO, distinct from an unregistered one: "
            .. sys.errname(r.errno or 0))
        done(w)
        src:close()
    end)

-- §5.2.1 CurrentUser --------------------------------------------------

test("CurrentUser\\ rewrites to Users\\<SID>\\ from the effective token",
    { spec = "PKM *hive.currentuser.rewrites-to-users-sid" }, function(t)
        local src = main()
        token.as_principal(t, vm, {}, function(w2)
            local mark = src:mark()
            local r = lcs.open_key(src, w2, -1, "CurrentUser\\Software", lcs.RIGHT.KEY_READ)
            t:assert(r.ret >= 0,
                "CurrentUser\\Software reaches Users\\" .. USER_SID .. "\\Software: "
                .. sys.errname(r.errno or 0))
            local looked = src:served(lcs.OP.LOOKUP, mark)
            t:assert(#looked >= 2, "the walk went through the Users hive")
            t:assert_eq(string.unpack("<s4", looked[1].payload, 17), USER_SID,
                "the first component looked up is the caller's textual SID")
            if r.ret >= 0 then sys.close(w2, r.ret) end
        end)
    end)

test("the rewritten path is re-checked against the total-length limit",
    { spec = "PKM *hive.currentuser.rewritten-path-rechecked-for-length" }, function(t)
        local src = main()
        local MAX = 16383 -- MaxTotalPathLength, §5.2.8

        -- A path of exactly MaxTotalPathLength, built from components
        -- of at most MaxPathComponentLength.
        local function exactly(prefix, total)
            local parts, len = { prefix }, #prefix
            while len + 1 + 255 <= total do
                parts[#parts + 1] = string.rep("x", 255)
                len = len + 256
            end
            if len < total then
                parts[#parts + 1] = string.rep("y", total - len - 1)
            end
            return table.concat(parts, "\\")
        end

        local aliased = exactly("CurrentUser", MAX)
        local direct = exactly("Users\\" .. USER_SID, MAX)
        t:assert_eq(#aliased, MAX, "the caller-supplied path is exactly the limit")
        t:assert_eq(#direct, MAX, "and so is the control")
        t:assert(#USER_SID > #"CurrentUser", "the SID is longer than the alias it replaces")

        token.as_principal(t, vm, {}, function(w2)
            local r = lcs.open_key(nil, w2, -1, aliased, lcs.RIGHT.KEY_READ)
            t:assert_eq(r.errno, sys.E.NAMETOOLONG,
                "the rewritten path exceeds MaxTotalPathLength: " .. sys.errname(r.errno or 0))
            local d = lcs.open_key(src, w2, -1, direct, lcs.RIGHT.KEY_READ)
            t:assert_eq(d.errno, sys.E.NOENT,
                "a path of the same length that needs no rewrite is only absent: "
                .. sys.errname(d.errno or 0))
        end)
    end)

test("the alias applies only to the first component of a caller-supplied path",
    { spec = "PKM *hive.currentuser.first-component-of-caller-path-only" }, function(t)
        local src = main()
        token.as_principal(t, vm, {}, function(w2)
            local r = lcs.open_key(src, w2, -1,
                "Users\\" .. USER_SID .. "\\CurrentUser\\Inner", lcs.RIGHT.KEY_READ)
            t:assert(r.ret >= 0,
                "a later component spelled CurrentUser is an ordinary key name: "
                .. sys.errname(r.errno or 0))
            if r.ret >= 0 then sys.close(w2, r.ret) end
        end)
    end)

test("CurrentUser rewriting is not applied to a symlink target",
    { spec = "PKM *hive.currentuser.not-applied-to-symlink-targets" }, function(t)
        local src = main()
        token.as_principal(t, vm, {}, function(w2)
            -- The link's own path resolves; its target `CurrentUser\Software`
            -- is followed literally and routes as a hive of that name.
            local r = lcs.open_key(src, w2, -1,
                "Users\\" .. USER_SID .. "\\ToCurrentUser", lcs.RIGHT.KEY_READ)
            t:assert_eq(r.errno, sys.E.NOENT,
                "a target beginning with CurrentUser\\ finds no hive: "
                .. sys.errname(r.errno or 0))
            -- And the caller-supplied form of the same path still works,
            -- so the failure is the target's, not the caller's.
            local direct = lcs.open_key(src, w2, -1, "CurrentUser\\Software", lcs.RIGHT.KEY_READ)
            t:assert(direct.ret >= 0, "while the caller path is rewritten as usual: "
                .. sys.errname(direct.errno or 0))
            if direct.ret >= 0 then sys.close(w2, direct.ret) end
        end)
    end)

test("CurrentUser cannot be registered as a hive name",
    { spec = "PKM *hive.currentuser.cannot-be-registered-einval" }, function(t)
        for _, spelling in ipairs({ "CurrentUser", "currentuser", "CURRENTUSER" }) do
            local src = lcs.source(vm, { hives = { { name = spelling } } })
            t:assert(not src:register(), spelling .. " may not be registered as a hive")
            t:assert_eq(src.errno, sys.E.INVAL,
                "rejected with EINVAL: " .. sys.errname(src.errno or 0))
            src:close()
        end
    end)

test("symlink targets are subject to ordinary hive routing, private hives included",
    { spec = "PKM *hive.symlink-targets-use-ordinary-routing" }, function(t)
        local src = main()
        token.as_principal(t, vm, {}, function(w2)
            local r = lcs.open_key(src, w2, -1,
                "Users\\" .. USER_SID .. "\\ToAlpha", lcs.RIGHT.KEY_READ)
            t:assert(r.ret >= 0, "a target naming another registered hive resolves there: "
                .. sys.errname(r.errno or 0))
            if r.ret >= 0 then sys.close(w2, r.ret) end
        end)

        -- The same link, resolved by a scoped thread, follows the same
        -- routing rules it would use directly: `Beta` is the private one.
        as_scoped(t, { SCOPE_A }, function(w2)
            local r = lcs.open_key(src, w2, -1,
                "Users\\" .. USER_SID .. "\\ToBeta\\PrivateA", lcs.RIGHT.KEY_READ)
            t:assert(r.ret >= 0,
                "a scoped thread resolving a target sees the same registry it sees directly: "
                .. sys.errname(r.errno or 0))
            if r.ret >= 0 then sys.close(w2, r.ret) end
            local g = lcs.open_key(src, w2, -1,
                "Users\\" .. USER_SID .. "\\ToBeta\\Global", lcs.RIGHT.KEY_READ)
            t:assert_eq(g.errno, sys.E.NOENT, "and not the global hive of that name")
        end)
    end)

test("the two names the kernel knows get no routing privilege",
    { spec = "PKM *hive.known-names.get-no-routing-privilege" }, function(t)
        main() -- Users is registered; Machine deliberately is not.
        local w = worker()
        local r = lcs.open_key(nil, w, -1, "Machine\\Software", lcs.RIGHT.KEY_READ)
        t:assert_eq(r.errno, sys.E.NOENT,
            "an unregistered Machine routes nowhere like any other name: "
            .. sys.errname(r.errno or 0))
        done(w)
    end)

-- §5.2.2 private hives ------------------------------------------------

test("a private hive is registered with the flag and a scope GUID",
    { spec = "PKM *private-hive.registered-with-flag-and-scope-guid" }, function(t)
        local scope = lcs.guid()
        local src = lcs.source(vm, { hives = {
            { name = "PrivOnly", private = true, scope = scope },
        } })
        src:key("PrivOnly\\Key", { root = src.hives[1].root })
        t:assert(src:register(), "RSI_HIVE_PRIVATE plus a scope GUID registers")
        src:pump()
        as_scoped(t, { scope }, function(w2)
            local r = lcs.open_key(src, w2, -1, "PrivOnly\\Key", lcs.RIGHT.KEY_READ)
            t:assert(r.ret >= 0, "and the scope reaches it: " .. sys.errname(r.errno or 0))
            if r.ret >= 0 then sys.close(w2, r.ret) end
        end)
        src:close()
    end)

test("a private hive is invisible globally and reachable only through its scope",
    { spec = "PKM *private-hive.invisible-globally-and-scope-gated" }, function(t)
        local src = main()
        local w = worker()
        -- Without a scope the name resolves to the *global* Beta, whose
        -- namespace has no such key: the private hive is not there at all.
        local r = lcs.open_key(src, w, -1, "Beta\\Where\\PrivateA", lcs.RIGHT.KEY_READ)
        t:assert_eq(r.errno, sys.E.NOENT,
            "a scopeless thread cannot see into a private hive: " .. sys.errname(r.errno or 0))
        done(w)

        -- Nor can a thread carrying a *different* scope.
        as_scoped(t, { SCOPE_B }, function(w2)
            local other = lcs.open_key(src, w2, -1, "Beta\\Where\\PrivateA", lcs.RIGHT.KEY_READ)
            t:assert_eq(other.errno, sys.E.NOENT, "and neither can another scope")
        end)
        as_scoped(t, { SCOPE_A }, function(w2)
            local mine = lcs.open_key(src, w2, -1, "Beta\\Where\\PrivateA", lcs.RIGHT.KEY_READ)
            t:assert(mine.ret >= 0, "the matching scope does: " .. sys.errname(mine.errno or 0))
            if mine.ret >= 0 then sys.close(w2, mine.ret) end
        end)
    end)

test("private hives are checked before global ones",
    { spec = "PKM *private-hive.routing.checked-before-global" }, function(t)
        local src = main()
        as_scoped(t, { SCOPE_A }, function(w2)
            local shadowed = lcs.open_key(src, w2, -1, "Beta\\Where\\Global", lcs.RIGHT.KEY_READ)
            t:assert_eq(shadowed.errno, sys.E.NOENT,
                "the global Beta is shadowed: the private table was consulted first")
            local mine = lcs.open_key(src, w2, -1, "Beta\\Where\\PrivateA", lcs.RIGHT.KEY_READ)
            t:assert(mine.ret >= 0, "and the private Beta answered instead: "
                .. sys.errname(mine.errno or 0))
            if mine.ret >= 0 then sys.close(w2, mine.ret) end
        end)
    end)

test("no name is exempt from shadowing: a private Users shadows the global one",
    { spec = "PKM *private-hive.routing.shadows-any-global-name" }, function(t)
        local scope = lcs.guid()
        local src = lcs.source(vm, { hives = {
            { name = "Users", private = true, scope = scope },
        } })
        src:key("Users\\Sandboxed", { root = src.hives[1].root })
        assert(src:register())
        src:pump()
        main() -- the global Users is registered too
        as_scoped(t, { scope }, function(w2)
            local r = lcs.open_key(src, w2, -1, "Users\\Sandboxed", lcs.RIGHT.KEY_READ)
            t:assert(r.ret >= 0, "the private Users answers a scoped thread: "
                .. sys.errname(r.errno or 0))
            if r.ret >= 0 then sys.close(w2, r.ret) end
            local global = lcs.open_key(src, w2, -1, "Users\\" .. USER_SID, lcs.RIGHT.KEY_READ)
            t:assert_eq(global.errno, sys.E.NOENT,
                "and the global Users is completely hidden from it")
        end)
        src:close()
    end)

test("the token's scope order decides: the first match wins",
    { spec = "PKM *private-hive.routing.token-order-first-match-wins" }, function(t)
        local src = main()
        as_scoped(t, { SCOPE_A, SCOPE_B }, function(w2)
            local a = lcs.open_key(src, w2, -1, "Beta\\Where\\PrivateA", lcs.RIGHT.KEY_READ)
            t:assert(a.ret >= 0, "scope A comes first and wins: " .. sys.errname(a.errno or 0))
            if a.ret >= 0 then sys.close(w2, a.ret) end
            local b = lcs.open_key(src, w2, -1, "Beta\\Where\\PrivateB", lcs.RIGHT.KEY_READ)
            t:assert_eq(b.errno, sys.E.NOENT, "scope B's Beta is not consulted at all")
        end)
        as_scoped(t, { SCOPE_B, SCOPE_A }, function(w2)
            local b = lcs.open_key(src, w2, -1, "Beta\\Where\\PrivateB", lcs.RIGHT.KEY_READ)
            t:assert(b.ret >= 0, "reversing the order reverses the winner: "
                .. sys.errname(b.errno or 0))
            if b.ret >= 0 then sys.close(w2, b.ret) end
            local a = lcs.open_key(src, w2, -1, "Beta\\Where\\PrivateA", lcs.RIGHT.KEY_READ)
            t:assert_eq(a.errno, sys.E.NOENT, "and scope A is no longer reached")
        end)
    end)

test("MaxScopeGUIDsPerToken bounds the per-syscall iteration, default 8",
    { spec = "PKM *private-hive.scope.max-guids-per-token" }, function(t)
        local src = main()
        local eight = {}
        for i = 1, 7 do eight[i] = lcs.guid() end
        eight[8] = SCOPE_A
        as_scoped(t, eight, function(w2)
            local r = lcs.open_key(src, w2, -1, "Beta\\Where\\PrivateA", lcs.RIGHT.KEY_READ)
            t:assert(r.ret >= 0, "eight scope GUIDs are within the default limit: "
                .. sys.errname(r.errno or 0))
            if r.ret >= 0 then sys.close(w2, r.ret) end
        end)

        local nine = {}
        for i = 1, 8 do nine[i] = lcs.guid() end
        nine[9] = SCOPE_A
        as_scoped(t, nine, function(w2)
            local r = lcs.open_key(nil, w2, -1, "Beta\\Where\\PrivateA", lcs.RIGHT.KEY_READ)
            t:assert(r.ret < 0,
                "a ninth scope GUID exceeds MaxScopeGUIDsPerToken and the routing fails")
            -- The configured cap is applied at use, not at token
            -- assembly, and the failure is E2BIG (§5.3.5, §5.10.3).
            t:assert_eq(r.errno, sys.E.BIG2, "with E2BIG: " .. sys.errname(r.errno or 0))
        end)
    end)

test("the credential extension rejects a nil scope GUID",
    { spec = "PKM *private-hive.credential.rejects-nil-guid" }, function(t)
        local w = worker()
        local fd, errno = token.mint(w, {
            lcs_credentials = lcs.lcs_credentials({ lcs.NULL_GUID }, {}),
        })
        t:assert(fd == nil, "a token may not carry a nil scope GUID")
        t:assert_eq(errno, sys.E.INVAL, "EINVAL: " .. sys.errname(errno or 0))
        done(w)
    end)

test("the credential extension rejects duplicate scope GUIDs",
    { spec = "PKM *private-hive.credential.rejects-duplicate-guids" }, function(t)
        local w = worker()
        local g = lcs.guid()
        local fd, errno = token.mint(w, {
            lcs_credentials = lcs.lcs_credentials({ g, g }, {}),
        })
        t:assert(fd == nil, "the same scope GUID may not appear twice")
        t:assert_eq(errno, sys.E.INVAL, "EINVAL: " .. sys.errname(errno or 0))
        done(w)
    end)

test("the credential extension caps the scope count at 256",
    { spec = "PKM *private-hive.credential.caps-count-at-256" }, function(t)
        local w = worker()
        local at_cap, over = {}, {}
        for i = 1, 256 do at_cap[i] = lcs.guid() end
        for i = 1, 257 do over[i] = lcs.guid() end

        local fd = token.mint(w, { lcs_credentials = lcs.lcs_credentials(at_cap, {}) })
        t:assert(fd ~= nil, "256 scope GUIDs is the hard KACS limit and is accepted")
        if fd then sys.close(w, fd) end

        local bad, errno = token.mint(w, { lcs_credentials = lcs.lcs_credentials(over, {}) })
        t:assert(bad == nil, "257 is above the cap")
        t:assert_eq(errno, sys.E.INVAL, "EINVAL: " .. sys.errname(errno or 0))
        done(w)
    end)

test("scope credentials propagate across impersonation",
    { spec = "PKM *private-hive.credential.propagates-across-fork-and-impersonation" },
    function(t)
        -- The route is put into a Down slot first, so routing answers
        -- from the table without contacting anyone: the thread that
        -- impersonates is then the thread that issues the syscall, which
        -- a call that had to block for a source would not be.
        --
        -- A thread without the scope cannot see the name at all (ENOENT);
        -- one with it sees a registered route whose source is Unavailable
        -- (EIO). The difference is the credential travelling with the
        -- impersonated identity.
        local scope = lcs.guid()
        local src = lcs.source(vm, { hives = {
            { name = "ImpHive", private = true, scope = scope },
        } })
        src:key("ImpHive\\Key", { root = src.hives[1].root })
        assert(src:register())
        src:pump()
        src:disconnect()

        local w = worker()
        local before = lcs.open_key(nil, w, -1, "ImpHive\\Key", lcs.RIGHT.KEY_READ)
        t:assert_eq(before.errno, sys.E.NOENT,
            "the thread's own token carries no scope: " .. sys.errname(before.errno or 0))

        local fd = assert(token.mint(w, {
            token_type = token.TYPE.IMPERSONATION,
            impersonation_level = token.LEVEL.IMPERSONATION,
            lcs_credentials = lcs.lcs_credentials({ scope }, {}),
        }))
        local imp = token.impersonate(w, fd)
        t:assert_eq(imp.ret, 0, "impersonate: " .. sys.errname(imp.errno or 0))
        sys.close(w, fd)

        local after = lcs.open_key(nil, w, -1, "ImpHive\\Key", lcs.RIGHT.KEY_READ)
        t:assert_eq(after.errno, sys.E.IO,
            "the impersonated token's scope reached routing: " .. sys.errname(after.errno or 0))
        token.revert(w)
        done(w)
        src:close()
    end)

test("attaching scope GUIDs is gated by SeCreateTokenPrivilege",
    { spec = "PKM *private-hive.scope.attaching-gated-by-secreatetokenprivilege" }, function(t)
        -- Scope GUIDs enter a token only at creation, and creation needs
        -- the privilege: a principal without it cannot claim a scope.
        local TCB = token.bit(token.PRIV.TCB)
        token.as_principal(t, vm, { privs_present = TCB, privs_enabled = TCB }, function(w2)
            local session = assert(token.create_logon_session(w2, {}))
            local fd, errno = token.create(w2, {
                auth_id = session,
                lcs_credentials = lcs.lcs_credentials({ SCOPE_A }, {}),
            })
            t:assert(fd == nil, "a caller without SeCreateTokenPrivilege cannot mint a token")
            t:assert_eq(errno, sys.E.PERM,
                "and so can never claim a scope: " .. sys.errname(errno or 0))
        end)
    end)

test("a scope GUID is opaque to LCS: neither created nor tracked",
    { spec = "PKM *private-hive.scope.opaque-and-untracked-by-lcs" }, function(t)
        local src = main()
        -- A scope nothing has ever registered is simply a number nobody
        -- uses: routing with it falls through to the global table rather
        -- than erroring, because LCS only ever compares.
        local unknown = lcs.guid()
        as_scoped(t, { unknown }, function(w2)
            local g = lcs.open_key(src, w2, -1, "Beta\\Where\\Global", lcs.RIGHT.KEY_READ)
            t:assert(g.ret >= 0,
                "an unreferenced scope is not an error; the global table answers: "
                .. sys.errname(g.errno or 0))
            if g.ret >= 0 then sys.close(w2, g.ret) end
        end)
        -- And the value is whatever userspace supplied: the same bytes
        -- the source registered are the bytes the token must carry.
        as_scoped(t, { SCOPE_A }, function(w2)
            local r = lcs.open_key(src, w2, -1, "Beta\\Where\\PrivateA", lcs.RIGHT.KEY_READ)
            t:assert(r.ret >= 0, "a userspace-chosen 128-bit value is all it is: "
                .. sys.errname(r.errno or 0))
            if r.ret >= 0 then sys.close(w2, r.ret) end
        end)
    end)

test("a private hive may not carry a nil scope GUID",
    { spec = "PKM *private-hive.registration.private-hive-requires-scope-guid" }, function(t)
        local src = lcs.source(vm, { hives = {
            { name = "NilScope", private = true, scope = lcs.NULL_GUID },
        } })
        t:assert(not src:register(),
            "a hive with RSI_HIVE_PRIVATE may not carry a nil scope GUID")
        t:assert_eq(src.errno, sys.E.INVAL, "EINVAL: " .. sys.errname(src.errno or 0))
        src:close()

        -- The converse rule from the same list, for contrast: a global
        -- hive may not carry a non-nil one.
        local other = lcs.source(vm, { hives = {
            { name = "GlobalScope", flags = 0, scope = lcs.guid() },
        } })
        t:assert(not other:register(), "and a global hive may not carry a scope GUID")
        t:assert_eq(other.errno, sys.E.INVAL, "EINVAL: " .. sys.errname(other.errno or 0))
        other:close()
    end)

test("nothing in the kernel generates a scope GUID",
    { spec = "PKM *private-hive.scope.not-generated-by-kernel" }, function(t)
        -- A value with none of the RFC 4122 version or variant bits the
        -- kernel's UUIDv4 generator sets. LCS takes it verbatim from
        -- userspace at registration and compares it verbatim on a token.
        local chosen = string.rep("\xab", 16)
        t:assert(chosen:byte(7) >> 4 ~= 4, "the chosen value is not UUIDv4-shaped")
        local src = lcs.source(vm, { hives = {
            { name = "Chosen", private = true, scope = chosen },
        } })
        src:key("Chosen\\Key", { root = src.hives[1].root })
        t:assert(src:register(), "a userspace-chosen scope GUID registers as given")
        src:pump()
        as_scoped(t, { chosen }, function(w2)
            local r = lcs.open_key(src, w2, -1, "Chosen\\Key", lcs.RIGHT.KEY_READ)
            t:assert(r.ret >= 0, "and the same bytes on a token reach it: "
                .. sys.errname(r.errno or 0))
            if r.ret >= 0 then sys.close(w2, r.ret) end
        end)
        src:close()
    end)
