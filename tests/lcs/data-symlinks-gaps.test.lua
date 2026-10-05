-- PKM §5.2.4 Symlinks — the write-time routing gate on a REG_LINK
-- target: REG_IOC_SET_VALUE routes the target's first component, with
-- the writer's scope GUIDs, and answers EINVAL if it names no
-- registered hive. A target that arrives in source data is not gated.
--
-- The gate is a routing question, so the cases vary what is
-- registered and who is asking: a hive nobody registered, a private
-- hive only one scope reaches, and a hive registered after the first
-- attempt. `src:served(SET_VALUE)` says whether a refused write ever
-- reached the source.
--
-- Belongs in data-symlinks.test.lua after "a relative-looking target is
-- not rejected as malformed".

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")
local token = require("helpers.token")

local vm = provium:vm("v", "kernel-only"):boot()

local TEST = "Machine\\Software\\Test"
local SCOPE = lcs.guid()

local src = lcs.source(vm, { hives = {
    { name = "Machine" },
    { name = "Hidden", private = true, scope = SCOPE },
} })
-- Writing into the base layer is authorised against its metadata key
-- (§5.3.4); a permissive one lets the scoped principal write at all.
src:key(lcs.LAYERS_PATH .. "\\base", { sd = lcs.permissive_sd() })
src:key(TEST .. "\\Target")
src:key(TEST .. "\\Other")
local LINK = src:symlink(TEST .. "\\Link", TEST .. "\\Target")
-- A target naming no hive, arriving as source data.
src:symlink(TEST .. "\\Dangling", "Ghost\\Anything")
src:key("Hidden\\Key", { root = src.hives[2].root })
assert(src:register())
src:pump()

local w = vm:spawn_worker()

--- Open the link itself, write `target` as its REG_LINK default value
--- as `who`, and return the result and how many SET_VALUEs reached the
--- source.
local function write_target(t, who, target)
    local r = lcs.open_key(src, who, -1, TEST .. "\\Link", lcs.KEY_ALL_ACCESS, lcs.OPEN_LINK)
    t:assert(r.ret >= 0, "open the link itself: " .. sys.errname(r.errno or 0))
    local mark = src:mark()
    local sv = lcs.set_value(src, who, r.ret, "", lcs.TYPE.LINK, target)
    local served = #src:served(lcs.OP.SET_VALUE, mark)
    sys.close(who, r.ret)
    return sv, served
end

--- The link's effective target as the source holds it.
local function stored_target()
    local per = src.store.values[LINK]
    local slot = per and per[""]
    local e = slot and slot.by_layer["base"]
    return e and e.data
end

--- Put the link back on Target, as SYSTEM.
local function restore(t)
    local sv = write_target(t, w, TEST .. "\\Target")
    t:assert_eq(sv.ret, 0, "the link is put back: " .. sys.errname(sv.errno or 0))
end

test("a REG_LINK target naming no registered hive is refused EINVAL at write time",
    { spec = "PKM *symlink.target-path.write-time-routing-gate" }, function(t)
        local sv, served = write_target(t, w, "Ghost\\Anything")
        t:assert(sv.ret ~= 0, "the write is refused")
        t:assert_eq(sv.errno, sys.E.INVAL, "with EINVAL: " .. sys.errname(sv.errno or 0))
        t:assert_eq(served, 0, "and the source was never asked to store it")
        t:assert_eq(stored_target(), TEST .. "\\Target", "the link's target is unchanged")

        -- The control: a target whose first component is a registered
        -- hive is written.
        local ok = write_target(t, w, TEST .. "\\Other")
        t:assert_eq(ok.ret, 0, "a target naming a registered hive is written: "
            .. sys.errname(ok.errno or 0))
        t:assert_eq(stored_target(), TEST .. "\\Other", "and stored")
        restore(t)
    end)

test("the gate routes with the writer's scope GUIDs",
    { spec = "PKM *symlink.target-path.write-time-routing-gate" }, function(t)
        -- `Hidden` is a private hive only SCOPE reaches. To SYSTEM, which
        -- carries no scope, it is no hive at all.
        local unscoped, served = write_target(t, w, "Hidden\\Key")
        t:assert(unscoped.ret ~= 0, "a writer whose scopes do not reach the hive is refused")
        t:assert_eq(unscoped.errno, sys.E.INVAL, "EINVAL: " .. sys.errname(unscoped.errno or 0))
        t:assert_eq(served, 0, "before the source is contacted")

        token.as_principal(t, vm, {
            lcs_credentials = lcs.lcs_credentials({ SCOPE }, {}),
        }, function(scoped)
            local sv = write_target(t, scoped, "Hidden\\Key")
            t:assert_eq(sv.ret, 0, "a writer carrying the scope may write the same target: "
                .. sys.errname(sv.errno or 0))
        end)
        t:assert_eq(stored_target(), "Hidden\\Key", "and it was stored")
        restore(t)
    end)

test("a symlink cannot forward-reference a hive registered after it",
    { spec = "PKM *symlink.target-path.write-time-routing-gate" }, function(t)
        local before = write_target(t, w, "Late\\Key")
        t:assert(before.ret ~= 0, "before `Late` is registered the target is refused")
        t:assert_eq(before.errno, sys.E.INVAL, "EINVAL: " .. sys.errname(before.errno or 0))

        local late = lcs.source(vm, { hives = { { name = "Late" } } })
        late:key("Late\\Key")
        t:assert(late:register(), "a second source registers `Late`")
        late:pump()
        local ok, err = pcall(function()
            local after = write_target(t, w, "Late\\Key")
            t:assert_eq(after.ret, 0, "and the same target is then written: "
                .. sys.errname(after.errno or 0))
            restore(t)
        end)
        late:close()
        if not ok then error(err, 0) end
    end)

test("a target that arrives in source data is not gated",
    { spec = "PKM *symlink.target-path.write-time-routing-gate" }, function(t)
        -- `Dangling` names a hive nobody registered. It was never written
        -- through the ioctl, so nothing refused it: it is there, and
        -- resolution treats it as a hive request that routes nowhere.
        local link = lcs.open_key(src, w, -1, TEST .. "\\Dangling", lcs.RIGHT.KEY_READ, lcs.OPEN_LINK)
        t:assert(link.ret >= 0, "the link exists: " .. sys.errname(link.errno or 0))
        if link.ret >= 0 then
            local q = lcs.query_value(src, w, link.ret, "")
            t:assert_eq(q.type, lcs.TYPE.LINK, "with a REG_LINK default value")
            t:assert_eq(q.data, "Ghost\\Anything", "naming the unregistered hive")
            sys.close(w, link.ret)
        end
        local r = lcs.open_key(src, w, -1, TEST .. "\\Dangling", lcs.RIGHT.KEY_READ)
        t:assert(r.ret < 0, "following it fails")
        t:assert_eq(r.errno, sys.E.NOENT,
            "as ENOENT, a hive request that found nothing, not a malformed target: "
            .. sys.errname(r.errno or 0))
    end)
