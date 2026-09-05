-- PKM §5.2.4 Symlinks — the structural flag and the REG_LINK default
-- value, resolution and what it does not validate, the target path's
-- rules, the depth limit, REG_OPEN_LINK, and what creating one costs.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")
local token = require("helpers.token")
local access = require("helpers.access")
local kacs = require("helpers.kacs")

local vm = provium:vm("v", "kernel-only"):boot()

local TEST = "Machine\\Software\\Test"
local P = token.PRIV
local TCB = token.bit(P.TCB)
local ENABLED_GROUP = token.GROUP.MANDATORY | token.GROUP.ENABLED_BY_DEFAULT | token.GROUP.ENABLED

local src, test_key, redirect_link
local function fixture()
    if src then return src end
    -- `Sub` is a hive of the fixture source's own, so the
    -- relative-looking-target case needs no second source to pump.
    local s = lcs.source(vm, { hives = { { name = "Machine" }, { name = "Sub" } } })
    -- Writing into a layer is authorised against the layer's metadata
    -- key (§5.3.4); without a permissive one on `base`, no principal but
    -- SYSTEM could create a key at all.
    s:key(lcs.LAYERS_PATH .. "\\base", { sd = lcs.permissive_sd() })
    s:seed_layer("Redirect", { precedence = 10 })
    -- A second layer, so the known-bug write case does not depend on
    -- whether the revert case has already deleted the first.
    s:seed_layer("Redirect2", { precedence = 20 })
    test_key = s:key(TEST)

    s:key(TEST .. "\\Target\\Inner")
    s:key(TEST .. "\\Other\\Inner")
    s:symlink(TEST .. "\\Link", TEST .. "\\Target")

    -- A link whose base target is Target and whose Redirect-layer target
    -- is Other: the same key, two layered REG_LINK default values.
    redirect_link = s:symlink(TEST .. "\\Redirected", TEST .. "\\Target")
    s:value(redirect_link, "", lcs.TYPE.LINK, TEST .. "\\Other", { layer = "Redirect" })

    -- Links with nothing to resolve to.
    s:key(TEST .. "\\NoTarget", { symlink = true })
    local wrong = s:key(TEST .. "\\WrongType", { symlink = true })
    s:value(wrong, "", lcs.TYPE.SZ, lcs.sz(TEST .. "\\Target"))
    s:symlink(TEST .. "\\NullInTarget", TEST .. "\\Tar\0get")
    s:symlink(TEST .. "\\TrailingSep", TEST .. "\\Target\\")
    s:symlink(TEST .. "\\EmptyComponent", "Machine\\\\Software")
    s:symlink(TEST .. "\\LongComponent", "Machine\\" .. string.rep("z", 256))
    s:symlink(TEST .. "\\Relative", "Sub\\Key")
    s:symlink(TEST .. "\\NoSuchHive", "Target\\Inner")

    s:symlink(TEST .. "\\Breakable", TEST .. "\\Target")

    -- A link part-way along a path, and one at the end.
    s:symlink(TEST .. "\\Mid", TEST .. "\\Target")

    -- A chain of seventeen links, one more than SymlinkDepthLimit.
    for i = 1, 17 do
        s:symlink(TEST .. "\\Chain" .. i, TEST .. "\\Chain" .. (i + 1))
    end
    s:key(TEST .. "\\Chain18")

    s:key("Sub\\Key\\Leaf", { root = s.hives[2].root })

    -- A parent a principal can be denied KEY_CREATE_LINK on.
    s:key(TEST .. "\\NoLinkRight", { sd = lcs.sd({
        access.ace(access.ACE.ALLOWED,
            lcs.RIGHT.KEY_ALL_ACCESS & ~lcs.RIGHT.CREATE_LINK,
            kacs.SID.EVERYONE, access.ACE_FLAG.CONTAINER_INHERIT),
    }) })
    s:key(TEST .. "\\NoSubKeyRight", { sd = lcs.sd({
        access.ace(access.ACE.ALLOWED,
            lcs.RIGHT.KEY_ALL_ACCESS & ~lcs.RIGHT.CREATE_SUB_KEY,
            kacs.SID.EVERYONE, access.ACE_FLAG.CONTAINER_INHERIT),
    }) })
    s:key(TEST .. "\\Linkable")

    assert(s:register())
    s:pump()
    src = s
    return s
end

local function worker() return vm:spawn_worker() end
local function done(w) w:kill(); w:join() end

local function open(t, w, path, mask, flags)
    local r = lcs.open_key(src, w, -1, path, mask or lcs.KEY_ALL_ACCESS, flags)
    t:assert(r.ret >= 0, "open " .. path .. ": " .. sys.errname(r.errno or 0))
    return r.ret
end

-- The two mechanisms ---------------------------------------------------

test("the symlink flag is set at creation and is immutable afterwards",
    { spec = "PKM *symlink.flag.set-at-creation-and-immutable" }, function(t)
        local s = fixture()
        local w = worker()
        local parent = open(t, w, TEST .. "\\Linkable")
        local c = lcs.create_key(s, w, {
            parent_fd = parent, path = "MadeLink", flags = lcs.OPTION_CREATE_LINK,
        })
        t:assert(c.ret >= 0, "REG_OPTION_CREATE_LINK: " .. sys.errname(c.errno or 0))
        local info = lcs.query_key_info(s, w, c.ret)
        t:assert_eq(info.symlink, true, "the key is marked a symbolic link")
        sys.close(w, c.ret)

        -- The flag belongs to the creation. Re-creating an ordinary key
        -- *with* the flag does not turn it into a link.
        local plain = lcs.create_key(s, w, { parent_fd = parent, path = "PlainKey" })
        t:assert(plain.ret >= 0, "create: " .. sys.errname(plain.errno or 0))
        t:assert_eq(lcs.query_key_info(s, w, plain.ret).symlink, false, "not a link")
        sys.close(w, plain.ret)
        local again = lcs.create_key(s, w, {
            parent_fd = parent, path = "PlainKey", flags = lcs.OPTION_CREATE_LINK,
        })
        t:assert_eq(again.disposition, lcs.OPENED_EXISTING, "the second create opens it")
        t:assert_eq(lcs.query_key_info(s, w, again.ret).symlink, false,
            "and the flag is not set after the fact")
        sys.close(w, again.ret); sys.close(w, parent)
        done(w)
    end)

test("RSI_WRITE_KEY can update only the descriptor and the last write time",
    { spec = "PKM *symlink.flag.rsi-write-key-cannot-change-it" }, function(t)
        local s = fixture()
        local w = worker()
        local fd = open(t, w, TEST .. "\\Link", lcs.KEY_ALL_ACCESS, lcs.OPEN_LINK)
        local mark = s:mark()
        local ss = lcs.set_security(s, w, fd, lcs.SI.DACL, lcs.permissive_sd())
        t:assert_eq(ss.ret, 0, "set security: " .. sys.errname(ss.errno or 0))
        local writes = s:served(lcs.OP.WRITE_KEY, mark)
        t:assert(#writes >= 1, "the descriptor change reached the source as RSI_WRITE_KEY")
        for _, req in ipairs(writes) do
            local mask = string.unpack("<I4", req.payload, 17)
            t:assert_eq(mask & ~0x3, 0,
                "its field mask carries only the descriptor and last-write-time bits")
        end
        local info = lcs.query_key_info(s, w, fd)
        t:assert_eq(info.symlink, true, "so the symlink flag is untouched")
        sys.close(w, fd)
        done(w)
    end)

test("the target is the REG_LINK default value",
    { spec = "PKM *symlink.target.is-the-reg-link-default-value" }, function(t)
        local s = fixture()
        local w = worker()
        -- Reading the link's own default value shows the target path.
        local link = open(t, w, TEST .. "\\Link", lcs.KEY_ALL_ACCESS, lcs.OPEN_LINK)
        local q = lcs.query_value(s, w, link, "")
        t:assert_eq(q.ret, 0, "the default value reads back: " .. sys.errname(q.errno or 0))
        t:assert_eq(q.type, lcs.TYPE.LINK, "typed REG_LINK")
        t:assert_eq(q.data, TEST .. "\\Target", "and holding the target path")

        -- And following the link lands where that value points.
        local followed = open(t, w, TEST .. "\\Link\\Inner", lcs.RIGHT.KEY_READ)
        local info = lcs.query_key_info(s, w, followed)
        t:assert_eq(info.name, "Inner", "resolution used it")
        sys.close(w, followed); sys.close(w, link)
        done(w)
    end)

test("a higher-precedence layer can redirect a symlink, and removing it reverts",
    { spec = "PKM *symlink.target.layer-can-redirect-and-revert" }, function(t)
        local s = fixture()
        local w = worker()
        -- The Redirect layer wins on precedence, so the link points at Other.
        local mark = s:mark()
        local fd = open(t, w, TEST .. "\\Redirected\\Inner", lcs.RIGHT.KEY_READ)
        t:assert(#s:served(lcs.OP.QUERY_VALUES, mark, redirect_link) >= 1,
            "the target was read from the link's default value")
        sys.close(w, fd)
        local other = lcs.open_key(s, w, -1, TEST .. "\\Other\\Inner", lcs.RIGHT.KEY_READ)
        t:assert(other.ret >= 0, "Other exists")
        sys.close(w, other.ret)

        -- Deleting the layer's metadata key removes the layer, and with
        -- it the redirecting entry; the base target comes back.
        local layer_fd = open(t, w, lcs.LAYERS_PATH .. "\\Redirect")
        local d = lcs.delete_key(s, w, layer_fd)
        t:assert_eq(d.ret, 0, "delete the layer: " .. sys.errname(d.errno or 0))
        sys.close(w, layer_fd)

        t:assert(lcs.entry(s, redirect_link, "", "Redirect") == nil
            or s.store.values[redirect_link]["" ] == nil
            or s.store.values[redirect_link][""].by_layer["redirect"] == nil,
            "the layer's REG_LINK entry is gone from the source")
        local back = lcs.open_key(s, w, -1, TEST .. "\\Redirected\\Inner", lcs.RIGHT.KEY_READ)
        t:assert(back.ret >= 0, "the base target is effective again: "
            .. sys.errname(back.errno or 0))
        local info = lcs.query_key_info(s, w, back.ret)
        t:assert_eq(info.name, "Inner", "resolving through the original target")
        sys.close(w, back.ret)
        done(w)
    end)

-- KNOWN BUG. §5.2.4 says a higher-precedence layer redirects a symlink
-- "by writing a different REG_LINK default value". No REG_LINK value can
-- be written at all: pkm_lcs_key_fd_set_value_symlink_target_gate
-- (lcs/key_fd.c) hands the length-delimited value data to
-- validate_syscall_path_c_string, which demands a NUL terminator, so
-- every REG_IOC_SET_VALUE of type REG_LINK fails EINVAL. Appending a
-- NUL makes the write succeed and stores a target that resolution then
-- rejects, because §5.2.4 permits no trailing null.
test("a layer redirects a symlink by writing a REG_LINK default value",
    { spec = "PKM *symlink.target.layer-can-redirect-and-revert",
      tags = { "known-bug" } }, function(t)
        local s = fixture()
        local w = worker()
        local link = open(t, w, TEST .. "\\Link", lcs.KEY_ALL_ACCESS, lcs.OPEN_LINK)
        local sv = lcs.set_value(s, w, link, "", lcs.TYPE.LINK, TEST .. "\\Other",
            { layer = "Redirect2" })
        t:assert_eq(sv.ret, 0,
            "writing a REG_LINK default value into a layer is how a redirect is authored: "
            .. sys.errname(sv.errno or 0))
        sys.close(w, link)
        done(w)
    end)

-- Resolution -----------------------------------------------------------

test("the fd refers to the target, not to the link",
    { spec = "PKM *symlink.resolution.fd-refers-to-the-target" }, function(t)
        local s = fixture()
        local w = worker()
        local through = open(t, w, TEST .. "\\Link")
        local direct = open(t, w, TEST .. "\\Target")
        local a = lcs.query_key_info(s, w, through)
        local b = lcs.query_key_info(s, w, direct)
        t:assert_eq(a.name, "Target", "the fd's name is the target's, not the link's")
        t:assert_eq(a.name, b.name, "the two fds are the same key")

        -- A value written through the link is visible through the target.
        local sv = lcs.set_value(s, w, through, "ViaLink", lcs.TYPE.DWORD, lcs.dword(5))
        t:assert_eq(sv.ret, 0, "set: " .. sys.errname(sv.errno or 0))
        local q = lcs.query_value(s, w, direct, "ViaLink")
        t:assert_eq(q.ret, 0, "and the target holds it: " .. sys.errname(q.errno or 0))
        lcs.delete_value(s, w, direct, "ViaLink")
        sys.close(w, through); sys.close(w, direct)
        done(w)
    end)

test("the target is read with a separate RSI_QUERY_VALUES and ordinary layer resolution",
    { spec = "PKM *symlink.resolution.target-read-with-layer-resolution" }, function(t)
        local s = fixture()
        local w = worker()
        local link_guid = s:lookup(TEST .. "\\Link")
        local mark = s:mark()
        local fd = open(t, w, TEST .. "\\Link", lcs.RIGHT.KEY_READ)
        local queries = s:served(lcs.OP.QUERY_VALUES, mark, link_guid)
        t:assert(#queries >= 1, "resolution issued RSI_QUERY_VALUES against the link key")
        -- The request names the default value (the empty name).
        local name = string.unpack("<s4", queries[1].payload, 17)
        t:assert_eq(name, "", "for the default value")
        sys.close(w, fd)
        done(w)
    end)

test("a missing or wrongly-typed default value fails resolution with EINVAL",
    { spec = "PKM *symlink.resolution.missing-or-wrong-type-is-einval" }, function(t)
        local s = fixture()
        local w = worker()
        local missing = lcs.open_key(s, w, -1, TEST .. "\\NoTarget", lcs.RIGHT.KEY_READ)
        t:assert_eq(missing.errno, sys.E.INVAL,
            "no effective default value: " .. sys.errname(missing.errno or 0))
        local wrong = lcs.open_key(s, w, -1, TEST .. "\\WrongType", lcs.RIGHT.KEY_READ)
        t:assert_eq(wrong.errno, sys.E.INVAL,
            "a REG_SZ default value is not a target: " .. sys.errname(wrong.errno or 0))
        done(w)
    end)

test("the target type is not validated at write time",
    { spec = "PKM *symlink.resolution.target-type-not-validated-at-write-time" }, function(t)
        local s = fixture()
        local w = worker()
        local link = open(t, w, TEST .. "\\Breakable", lcs.KEY_ALL_ACCESS, lcs.OPEN_LINK)
        local before = lcs.open_key(s, w, -1, TEST .. "\\Breakable", lcs.RIGHT.KEY_READ)
        t:assert(before.ret >= 0, "the link resolves to begin with: "
            .. sys.errname(before.errno or 0))
        sys.close(w, before.ret)
        -- Writing a REG_SZ default value over a symlink's target is
        -- accepted; nothing checks the type at write time.
        local sv = lcs.set_value(s, w, link, "", lcs.TYPE.SZ, lcs.sz(TEST .. "\\Target"))
        t:assert_eq(sv.ret, 0, "the write is accepted: " .. sys.errname(sv.errno or 0))
        local broken = lcs.open_key(s, w, -1, TEST .. "\\Breakable", lcs.RIGHT.KEY_READ)
        t:assert_eq(broken.errno, sys.E.INVAL,
            "and resolution breaks at the next open: " .. sys.errname(broken.errno or 0))
        sys.close(w, link)
        done(w)
    end)

test("a failed resolution writes nothing",
    { spec = "PKM *symlink.resolution.failed-resolution-writes-nothing" }, function(t)
        local s = fixture()
        local w = worker()
        local mark = s:mark()
        local r = lcs.open_key(s, w, -1, TEST .. "\\WrongType", lcs.RIGHT.KEY_READ)
        t:assert_eq(r.errno, sys.E.INVAL, "the open fails")
        for _, op in ipairs({ lcs.OP.SET_VALUE, lcs.OP.DELETE_VALUE, lcs.OP.WRITE_KEY,
                              lcs.OP.CREATE_ENTRY, lcs.OP.DELETE_ENTRY, lcs.OP.CREATE_KEY,
                              lcs.OP.HIDE_ENTRY, lcs.OP.DROP_KEY }) do
            t:assert_eq(#s:served(op, mark), 0,
                "no " .. lcs.OP_NAME[op] .. " was sent by the failed resolution")
        end
        -- The offending value is still there.
        local link = open(t, w, TEST .. "\\WrongType", lcs.KEY_ALL_ACCESS, lcs.OPEN_LINK)
        local q = lcs.query_value(s, w, link, "")
        t:assert_eq(q.ret, 0, "the offending value stays in the registry")
        t:assert_eq(q.type, lcs.TYPE.SZ, "with its wrong type intact")
        sys.close(w, link)
        done(w)
    end)

-- The target path -------------------------------------------------------

test("the REG_LINK payload is length-delimited and may not contain a null byte",
    { spec = "PKM *symlink.target-path.length-delimited-no-trailing-null" }, function(t)
        local s = fixture()
        local w = worker()
        -- A target carrying a null inside its length is rejected like
        -- any other string.
        local r = lcs.open_key(s, w, -1, TEST .. "\\NullInTarget", lcs.RIGHT.KEY_READ)
        t:assert_eq(r.errno, sys.E.INVAL,
            "a null byte inside the length is invalid: " .. sys.errname(r.errno or 0))
        -- And a target with no terminator at all resolves: the length
        -- delimits it.
        local ok = open(t, w, TEST .. "\\Link", lcs.RIGHT.KEY_READ)
        local link = open(t, w, TEST .. "\\Link", lcs.KEY_ALL_ACCESS, lcs.OPEN_LINK)
        local q = lcs.query_value(s, w, link, "")
        t:assert_eq(q.data, TEST .. "\\Target", "no trailing null is present or required")
        sys.close(w, link); sys.close(w, ok)
        done(w)
    end)

test("the target is validated with the same rules as a syscall path",
    { spec = "PKM *symlink.target-path.validated-like-a-syscall-path" }, function(t)
        local s = fixture()
        local w = worker()
        local cases = {
            { "TrailingSep", "a trailing separator" },
            { "EmptyComponent", "an empty component" },
            { "LongComponent", "a component over MaxPathComponentLength" },
        }
        for _, c in ipairs(cases) do
            local r = lcs.open_key(s, w, -1, TEST .. "\\" .. c[1], lcs.RIGHT.KEY_READ)
            t:assert(r.ret < 0, c[2] .. " makes the target invalid")
            t:assert(r.errno == sys.E.INVAL or r.errno == sys.E.NAMETOOLONG,
                "rejected as a syscall path would be (" .. c[2] .. "): "
                .. sys.errname(r.errno or 0))
        end
        done(w)
    end)

test("a target is always interpreted as absolute",
    { spec = "PKM *symlink.target-path.always-absolute" }, function(t)
        local s = fixture()
        local w = worker()
        -- `Target\Inner` names a key that exists beside the link, but a
        -- target's first component is a hive name: there is no hive
        -- called Target, so it routes nowhere.
        local sibling = lcs.open_key(s, w, -1, TEST .. "\\Target\\Inner", lcs.RIGHT.KEY_READ)
        t:assert(sibling.ret >= 0, "the sibling path exists: " .. sys.errname(sibling.errno or 0))
        sys.close(w, sibling.ret)
        local r = lcs.open_key(s, w, -1, TEST .. "\\NoSuchHive", lcs.RIGHT.KEY_READ)
        t:assert_eq(r.errno, sys.E.NOENT,
            "its first component routed as a hive name and found nothing: "
            .. sys.errname(r.errno or 0))
        done(w)
    end)

test("a relative-looking target is not rejected as malformed",
    { spec = "PKM *symlink.target-path.relative-looking-target-not-rejected" }, function(t)
        -- `Sub\Key` is a hive request. The fixture source also backs a
        -- hive called Sub, so the same target that would be ENOENT
        -- resolves there instead of being refused as malformed.
        local s = fixture()
        local w = worker()
        local r = lcs.open_key(s, w, -1, TEST .. "\\Relative\\Leaf", lcs.RIGHT.KEY_READ)
        t:assert(r.ret >= 0,
            "`Sub\\Key` is a hive request, not an error: " .. sys.errname(r.errno or 0))
        if r.ret >= 0 then
            local info = lcs.query_key_info(s, w, r.ret)
            t:assert_eq(info.name, "Leaf", "it resolved inside the hive named Sub")
            sys.close(w, r.ret)
        end
        done(w)
    end)

-- Depth ------------------------------------------------------------------

test("exceeding SymlinkDepthLimit is ELOOP",
    { spec = "PKM *symlink.depth.exceeding-the-limit-is-eloop" }, function(t)
        local s = fixture()
        local w = worker()
        -- Chain2..Chain18 is sixteen hops and resolves.
        local ok = lcs.open_key(s, w, -1, TEST .. "\\Chain2", lcs.RIGHT.KEY_READ)
        t:assert(ok.ret >= 0, "sixteen hops are within the limit: " .. sys.errname(ok.errno or 0))
        if ok.ret >= 0 then sys.close(w, ok.ret) end
        -- Chain1 adds one more.
        local loop = lcs.open_key(s, w, -1, TEST .. "\\Chain1", lcs.RIGHT.KEY_READ)
        t:assert_eq(loop.errno, sys.E.LOOP,
            "one hop past the default of 16 is ELOOP: " .. sys.errname(loop.errno or 0))
        done(w)
    end)

test("two paths in the walk use the compiled-in default rather than the configured value",
    { spec = "PKM *symlink.depth.limit-not-honoured-on-two-paths",
      covered_by = "kunit:",
      skip = "the two call sites are pkm_lcs_walk_absolute_components (path_walk.c), "
          .. "reached only from layer_metadata.c and self_config.c, which take their "
          .. "own limits snapshot rather than the caller's; both resolve "
          .. "Machine\\System\\Registry paths that no caller can put a symlink into "
          .. "while the refresh is running, so no guest can witness the difference. "
          .. "No KUnit case found — candidate for a new one" },
    function(t) end)

-- REG_OPEN_LINK ----------------------------------------------------------

test("REG_OPEN_LINK opens the link itself rather than following it",
    { spec = "PKM *symlink.open-link.opens-the-link-not-the-target" }, function(t)
        local s = fixture()
        local w = worker()
        local link = open(t, w, TEST .. "\\Link", lcs.KEY_ALL_ACCESS, lcs.OPEN_LINK)
        local info = lcs.query_key_info(s, w, link)
        t:assert_eq(info.name, "Link", "the fd is the link")
        t:assert_eq(info.symlink, true, "and it is marked one")
        local followed = open(t, w, TEST .. "\\Link")
        local other = lcs.query_key_info(s, w, followed)
        t:assert_eq(other.name, "Target", "without the flag the same path is the target")
        sys.close(w, followed); sys.close(w, link)
        done(w)
    end)

test("REG_OPEN_LINK applies to the final path component only",
    { spec = "PKM *symlink.open-link.final-component-only" }, function(t)
        local s = fixture()
        local w = worker()
        -- `Mid` is a link part-way along the path; the flag does not
        -- stop it being followed.
        local fd = open(t, w, TEST .. "\\Mid\\Inner", lcs.RIGHT.KEY_READ, lcs.OPEN_LINK)
        local info = lcs.query_key_info(s, w, fd)
        t:assert_eq(info.name, "Inner",
            "a symlink part-way along the path is followed whether or not the flag is set")
        sys.close(w, fd)
        done(w)
    end)

test("the access check follows the flag: against the link, or against the target",
    { spec = "PKM *symlink.open-link.access-check-follows-the-flag" }, function(t)
        local s = lcs.source(vm, { hives = { { name = "AccessSplit" } } })
        local deny_all = lcs.sd({
            access.ace(access.ACE.DENIED, lcs.RIGHT.KEY_ALL_ACCESS | lcs.RIGHT.GENERIC_ALL,
                kacs.SID.EVERYONE),
        })
        s:key("AccessSplit\\Target", { sd = deny_all })
        s:key("AccessSplit\\OpenTarget")
        -- A readable link pointing at an unreadable target ...
        s:symlink("AccessSplit\\ToDenied", "AccessSplit\\Target")
        -- ... and an unreadable link pointing at a readable target.
        local denied_link = s:symlink("AccessSplit\\DeniedLink", "AccessSplit\\OpenTarget")
        s.store.keys[denied_link].sd = deny_all
        assert(s:register())
        s:pump()

        token.as_principal(t, vm, {}, function(w)
            local followed = lcs.open_key(s, w, -1, "AccessSplit\\ToDenied", lcs.RIGHT.KEY_READ)
            t:assert_eq(followed.errno, sys.E.ACCES,
                "without the flag the check is against the target: "
                .. sys.errname(followed.errno or 0))
            local as_link = lcs.open_key(s, w, -1, "AccessSplit\\ToDenied",
                lcs.RIGHT.KEY_READ, lcs.OPEN_LINK)
            t:assert(as_link.ret >= 0,
                "with the flag it is against the link: " .. sys.errname(as_link.errno or 0))
            if as_link.ret >= 0 then sys.close(w, as_link.ret) end

            local through = lcs.open_key(s, w, -1, "AccessSplit\\DeniedLink", lcs.RIGHT.KEY_READ)
            t:assert(through.ret >= 0,
                "a link the caller may not read is still followed to a target it may: "
                .. sys.errname(through.errno or 0))
            if through.ret >= 0 then sys.close(w, through.ret) end
            local at_link = lcs.open_key(s, w, -1, "AccessSplit\\DeniedLink",
                lcs.RIGHT.KEY_READ, lcs.OPEN_LINK)
            t:assert_eq(at_link.errno, sys.E.ACCES,
                "while opening the link itself is denied: " .. sys.errname(at_link.errno or 0))
        end)
        s:close()
    end)

-- Creation ---------------------------------------------------------------

test("creating a symlink requires KEY_CREATE_SUB_KEY on the parent",
    { spec = "PKM *symlink.create.requires-key-create-sub-key" }, function(t)
        local s = fixture()
        token.as_principal(t, vm, {
            privs_present = TCB, privs_enabled = TCB,
        }, function(w)
            local parent = lcs.open_key(s, w, -1, TEST .. "\\NoSubKeyRight",
                lcs.RIGHT.KEY_READ | lcs.RIGHT.CREATE_LINK)
            t:assert(parent.ret >= 0, "open: " .. sys.errname(parent.errno or 0))
            local c = lcs.create_key(s, w, {
                parent_fd = parent.ret, path = "Nope", access = lcs.RIGHT.KEY_READ,
                flags = lcs.OPTION_CREATE_LINK,
            })
            t:assert(c.ret < 0, "without KEY_CREATE_SUB_KEY the creation is refused")
            t:assert_eq(c.errno, sys.E.ACCES,
                "as for any key: " .. sys.errname(c.errno or 0))
            sys.close(w, parent.ret)
        end)
    end)

test("creating a symlink requires KEY_CREATE_LINK on the parent",
    { spec = "PKM *symlink.create.requires-key-create-link" }, function(t)
        local s = fixture()
        token.as_principal(t, vm, {
            privs_present = TCB, privs_enabled = TCB,
        }, function(w)
            local parent = lcs.open_key(s, w, -1, TEST .. "\\NoLinkRight",
                lcs.RIGHT.KEY_READ | lcs.RIGHT.CREATE_SUB_KEY)
            t:assert(parent.ret >= 0, "open: " .. sys.errname(parent.errno or 0))
            -- An ordinary key is fine here ...
            local plain = lcs.create_key(s, w, {
                parent_fd = parent.ret, path = "Plain", access = lcs.RIGHT.KEY_READ,
            })
            t:assert(plain.ret >= 0, "an ordinary key needs no link right: "
                .. sys.errname(plain.errno or 0))
            if plain.ret >= 0 then sys.close(w, plain.ret) end
            -- ... a link is not.
            local link = lcs.create_key(s, w, {
                parent_fd = parent.ret, path = "Linky", access = lcs.RIGHT.KEY_READ,
                flags = lcs.OPTION_CREATE_LINK,
            })
            t:assert(link.ret < 0, "a symlink needs KEY_CREATE_LINK")
            t:assert_eq(link.errno, sys.E.ACCES, "EACCES: " .. sys.errname(link.errno or 0))
            sys.close(w, parent.ret)
        end)
    end)

test("creating a symlink requires an enabled SeTcbPrivilege or Administrators membership",
    { spec = "PKM *symlink.create.requires-setcbprivilege-or-administrators" }, function(t)
        local s = fixture()
        -- The privilege alone satisfies it.
        token.as_principal(t, vm, { privs_present = TCB, privs_enabled = TCB }, function(w)
            local parent = lcs.open_key(s, w, -1, TEST .. "\\Linkable", lcs.KEY_ALL_ACCESS)
            t:assert(parent.ret >= 0, "open: " .. sys.errname(parent.errno or 0))
            local c = lcs.create_key(s, w, {
                parent_fd = parent.ret, path = "ByPrivilege", access = lcs.RIGHT.KEY_READ,
                flags = lcs.OPTION_CREATE_LINK,
            })
            t:assert(c.ret >= 0, "SeTcbPrivilege alone is enough: " .. sys.errname(c.errno or 0))
            if c.ret >= 0 then sys.close(w, c.ret) end
            sys.close(w, parent.ret)
        end)

        -- Administrators membership alone satisfies it.
        token.as_principal(t, vm, {
            groups = {
                { sid = kacs.SID.EVERYONE, attributes = ENABLED_GROUP },
                { sid = kacs.SID.AUTHENTICATED_USERS, attributes = ENABLED_GROUP },
                { sid = kacs.SID.ADMINISTRATORS, attributes = ENABLED_GROUP },
            },
        }, function(w)
            local parent = lcs.open_key(s, w, -1, TEST .. "\\Linkable", lcs.KEY_ALL_ACCESS)
            t:assert(parent.ret >= 0, "open: " .. sys.errname(parent.errno or 0))
            local c = lcs.create_key(s, w, {
                parent_fd = parent.ret, path = "ByGroup", access = lcs.RIGHT.KEY_READ,
                flags = lcs.OPTION_CREATE_LINK,
            })
            t:assert(c.ret >= 0, "Administrators membership alone is enough: "
                .. sys.errname(c.errno or 0))
            if c.ret >= 0 then sys.close(w, c.ret) end
            sys.close(w, parent.ret)
        end)
    end)

test("the privilege branch marks SeTcbPrivilege used",
    { spec = "PKM *symlink.create.privilege-branch-marks-privilege-used" }, function(t)
        local s = fixture()
        token.as_principal(t, vm, { privs_present = TCB, privs_enabled = TCB }, function(w)
            local own = assert(token.open_self(w, token.RIGHT.QUERY))
            local before = assert(token.privileges(w, own))
            t:assert_eq(before.used & TCB, 0, "SeTcbPrivilege is not yet marked used")
            local parent = lcs.open_key(s, w, -1, TEST .. "\\Linkable", lcs.KEY_ALL_ACCESS)
            t:assert(parent.ret >= 0, "open: " .. sys.errname(parent.errno or 0))
            local c = lcs.create_key(s, w, {
                parent_fd = parent.ret, path = "MarksUsed", access = lcs.RIGHT.KEY_READ,
                flags = lcs.OPTION_CREATE_LINK,
            })
            t:assert(c.ret >= 0, "create: " .. sys.errname(c.errno or 0))
            local after = assert(token.privileges(w, own))
            t:assert(after.used & TCB ~= 0,
                "the privilege branch marks SeTcbPrivilege used")
            if c.ret >= 0 then sys.close(w, c.ret) end
            sys.close(w, parent.ret); sys.close(w, own)
        end)
    end)

test("failing the privilege requirement is EPERM",
    { spec = "PKM *symlink.create.failure-is-eperm" }, function(t)
        local s = fixture()
        -- Every right on the parent, neither the privilege nor the group.
        token.as_principal(t, vm, {}, function(w)
            local parent = lcs.open_key(s, w, -1, TEST .. "\\Linkable", lcs.KEY_ALL_ACCESS)
            t:assert(parent.ret >= 0, "open: " .. sys.errname(parent.errno or 0))
            local c = lcs.create_key(s, w, {
                parent_fd = parent.ret, path = "Refused", access = lcs.RIGHT.KEY_READ,
                flags = lcs.OPTION_CREATE_LINK,
            })
            t:assert(c.ret < 0, "neither branch is satisfied")
            t:assert_eq(c.errno, sys.E.PERM, "EPERM: " .. sys.errname(c.errno or 0))
            sys.close(w, parent.ret)
        end)
    end)
