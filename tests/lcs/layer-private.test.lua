-- PKM §5.3.5 — Private layers: a disabled layer attached to a thread's
-- credentials, invisible during ordinary resolution and treated as
-- enabled for a thread whose token names it. The names ride on the
-- KACS token's LCS credential extension, the same versioned block that
-- carries the scope GUIDs for private hives.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")
local token = require("helpers.token")

local vm = provium:vm("v", "kernel-only"):boot()

local SZ = lcs.TYPE.SZ
local TEST_PATH = "Machine\\Software\\Test"
-- U+017F LATIN SMALL LETTER LONG S folds to `s` under Unicode Simple
-- Case Folding and is unrelated to it under an ASCII comparison.
local LONG_S = "\u{017F}"
local SCOPE = lcs.guid()

local src = lcs.source(vm, { hives = {
    { name = "Machine" },
    { name = "Scoped", private = true, scope = SCOPE },
} })
local key = src:key(TEST_PATH)
local scoped = src:key("Scoped\\K", { root = src.hives[2].root })
src:seed_layer("base")
src:seed_layer("priv", { enabled = false })                     -- precedence 0
src:seed_layer("midp", { precedence = 3, enabled = false })
src:seed_layer("top", { precedence = 5 })
src:seed_layer("hip", { precedence = 9, enabled = false })
src:seed_layer("ROLEs", { enabled = false })

src:value(key, "P", SZ, lcs.sz("base"))
src:value(key, "P", SZ, lcs.sz("priv"), { layer = "priv" })     -- later: higher sequence
src:value(key, "Q", SZ, lcs.sz("top"), { layer = "top" })
src:value(key, "Q", SZ, lcs.sz("midp"), { layer = "midp" })     -- later, but precedence 3
src:value(key, "R", SZ, lcs.sz("top"), { layer = "top" })
src:value(key, "R", SZ, lcs.sz("hip"), { layer = "hip" })
src:value(key, "Fold", SZ, lcs.sz("base"))
src:value(key, "Fold", SZ, lcs.sz("folded"), { layer = "ROLEs" })
src:value(scoped, "S", SZ, lcs.sz("base"))
src:value(scoped, "S", SZ, lcs.sz("priv"), { layer = "priv" })
assert(src:register())
src:pump()

--- Credentials for `names` (and optionally scope GUIDs) as a spec.
local function creds(names, guids, extra)
    local spec = extra or {}
    spec.lcs_credentials = lcs.lcs_credentials(guids or {}, names or {})
    return spec
end

--- Run `fn(w, fd)` as a principal holding `names`, with the test key open.
local function with_layers(t, names, fn, guids)
    token.as_principal(t, vm, creds(names, guids), function(w)
        local r = lcs.open_key(src, w, -1, TEST_PATH, lcs.RIGHT.KEY_READ)
        t:assert(r.ret >= 0, "the test key opens: " .. sys.errname(r.errno or 0))
        fn(w, r.ret)
        sys.close(w, r.ret)
    end)
end

--- The winning layer for `name` under a token holding `names`.
local function layer_seen(t, names, name, guids)
    local out
    with_layers(t, names, function(w, fd)
        local q = lcs.query_value(src, w, fd, name)
        t:assert_eq(q.ret, 0, "query " .. name .. ": " .. sys.errname(q.errno or 0))
        out = q.layer
    end, guids)
    return out
end

test("a disabled layer is invisible in ordinary resolution and active for a thread whose token names it",
    { spec = "PKM *layer.private.disabled-layer-active-for-a-naming-thread" },
    function(t)
        t:assert_eq(layer_seen(t, {}, "P"), "base",
            "with no private layer attached the disabled layer is invisible")
        t:assert_eq(layer_seen(t, { "priv" }, "P"), "priv",
            "and a thread whose token names it resolves it as though it were enabled")
    end)

test("a private layer participates in normal precedence ordering rather than sitting on top",
    { spec = "PKM *layer.private.participates-in-normal-precedence" },
    function(t)
        t:assert_eq(layer_seen(t, { "midp" }, "Q"), "top",
            "a private layer at precedence 3 competes at precedence 3 and loses to " ..
            "an enabled layer at precedence 5")
        t:assert_eq(layer_seen(t, { "hip" }, "R"), "hip",
            "and one at precedence 9 wins there: it is not an overlay on top, it is a " ..
            "layer only that thread can see")
    end)

test("the activity test: enabled globally, or named in this thread's private layer set",
    { spec = "PKM *layer.private.activity-test" },
    function(t)
        t:assert_eq(layer_seen(t, {}, "Q"), "top",
            "a globally enabled layer is active without being named")
        t:assert_eq(layer_seen(t, { "hip" }, "P"), "base",
            "naming one disabled layer does not activate another")
        t:assert_eq(layer_seen(t, { "hip", "priv" }, "P"), "priv",
            "and every name in the set is active")
    end)

test("private layer names are matched by Unicode Simple Case Folding",
    { spec = "PKM *layer.private.names-matched-by-case-folding" },
    function(t)
        t:assert_eq(layer_seen(t, { "roles" }, "Fold"), "ROLEs",
            "an ASCII case variant names the same layer")
        t:assert_eq(layer_seen(t, { "ROLE" .. LONG_S }, "Fold"), "ROLEs",
            "and so does U+017F, which folds to `s` — the same algorithm as every " ..
            "other layer-name comparison, not an ASCII one")
    end)

test("private layer names reach a thread through the token's LCS credential extension",
    { spec = "PKM *layer.private.names-come-from-the-token-credential-extension" },
    function(t)
        token.as_principal(t, vm, {}, function(w)
            local r = lcs.open_key(src, w, -1, TEST_PATH, lcs.RIGHT.KEY_READ)
            local q = lcs.query_value(src, w, r.ret, "P")
            t:assert_eq(q.layer, "base",
                "a token minted without the extension carries no private layers")
            sys.close(w, r.ret)
        end)
        -- The same versioned block carries the scope GUIDs for private
        -- hives (§5.2.2): one extension, both credentials.
        token.as_principal(t, vm, creds({ "priv" }, { SCOPE }), function(w)
            local r = lcs.open_key(src, w, -1, "Scoped\\K", lcs.RIGHT.KEY_READ)
            t:assert(r.ret >= 0,
                "the scope GUID in the block routes to the private hive: " ..
                sys.errname(r.errno or 0))
            local q = lcs.query_value(src, w, r.ret, "S")
            t:assert_eq(q.layer, "priv",
                "and the private layer name in the same block resolves there")
            sys.close(w, r.ret)
        end)
    end)

test("LCS reads the credentials from the effective token on each operation",
    { spec = "PKM *layer.private.credentials-read-from-the-effective-token-per-operation" },
    function(t)
        -- One thread, one call, three effective tokens. A hive nobody
        -- registered contacts no source, so the whole exchange happens
        -- on the caller's own thread; an over-cap credential set is the
        -- visible marker that the credentials were read at all.
        local w = vm:spawn_worker()
        local names = {}
        for i = 1, 17 do names[i] = "over" .. i end
        local imp = assert(token.mint(w, {
            user_sid = token.SID.LOCAL_SYSTEM,
            token_type = token.TYPE.IMPERSONATION,
            impersonation_level = token.LEVEL.IMPERSONATION,
            lcs_credentials = lcs.lcs_credentials({}, names),
        }))
        local before = lcs.open_key(nil, w, -1, "NoSuchHive\\K", lcs.RIGHT.KEY_READ)
        t:assert_eq(before.errno, sys.E.NOENT, "the thread's own token carries none")
        t:assert_eq(token.impersonate(w, imp).ret, 0, "the thread impersonates another token")
        local during = lcs.open_key(nil, w, -1, "NoSuchHive\\K", lcs.RIGHT.KEY_READ)
        t:assert_eq(during.errno, sys.E.BIG2,
            "the next operation reads the credentials from the new effective token")
        token.revert(w)
        local after = lcs.open_key(nil, w, -1, "NoSuchHive\\K", lcs.RIGHT.KEY_READ)
        t:assert_eq(after.errno, sys.E.NOENT,
            "and the one after that reads them again, from the token that is effective then")
        w:kill(); w:join()
    end)

test("private layers are per-thread, not per-process",
    { spec = "PKM *layer.private.are-per-thread-not-per-process" },
    function(t)
        -- One process, two threads, two effective tokens. The worker's
        -- main thread impersonates; a syscall issued on another thread
        -- of the same process keeps the process's primary token.
        local w = vm:spawn_worker()
        local fd = lcs.open_key(src, w, -1, TEST_PATH, lcs.KEY_ALL_ACCESS)
        t:assert(fd.ret >= 0, "the test key opens: " .. sys.errname(fd.errno or 0))
        local names = {}
        for i = 1, 17 do names[i] = "over" .. i end
        local imp = assert(token.mint(w, {
            user_sid = token.SID.LOCAL_SYSTEM,
            token_type = token.TYPE.IMPERSONATION,
            impersonation_level = token.LEVEL.IMPERSONATION,
            lcs_credentials = lcs.lcs_credentials({}, names),
        }))
        t:assert_eq(token.impersonate(w, imp).ret, 0, "one thread impersonates")
        local main = lcs.open_key(nil, w, -1, "NoSuchHive\\K", lcs.RIGHT.KEY_READ)
        t:assert_eq(main.errno, sys.E.BIG2,
            "that thread's operations use that thread's private layer set")
        local other = lcs.query_value(src, w, fd.ret, "P")
        t:assert_eq(other.ret, 0,
            "while another thread of the same process is unaffected: " ..
            sys.errname(other.errno or 0))
        t:assert_eq(other.layer, "base", "and holds its own, different, private layer set")
        token.revert(w)
        sys.close(w, fd.ret)
        w:kill(); w:join()
    end)

test("MaxPrivateLayersPerToken defaults to 16",
    { spec = "PKM *layer.private.max-private-layers-per-token-default-16" },
    function(t)
        local sixteen, seventeen = {}, {}
        for i = 1, 16 do sixteen[i] = "n" .. i end
        for i = 1, 17 do seventeen[i] = "n" .. i end
        token.as_principal(t, vm, creds(sixteen), function(w)
            local r = lcs.open_key(src, w, -1, TEST_PATH, lcs.RIGHT.KEY_READ)
            t:assert(r.ret >= 0, "sixteen names are within the default: " ..
                sys.errname(r.errno or 0))
            sys.close(w, r.ret)
        end)
        token.as_principal(t, vm, creds(seventeen), function(w)
            local r = lcs.open_key(nil, w, -1, TEST_PATH, lcs.RIGHT.KEY_READ)
            t:assert(r.ret < 0, "seventeen are not")
        end)
    end)

test("the cap is described as a limit on attachment but is not enforced there",
    { spec = "PKM *layer.private.cap-not-enforced-at-attachment" },
    function(t)
        local w = vm:spawn_worker()
        local names = {}
        for i = 1, 17 do names[i] = "n" .. i end
        local fd, e = token.mint(w, creds(names, {}, { user_sid = token.SID.LOCAL_SYSTEM }))
        t:assert(fd, "a token carrying more than MaxPrivateLayersPerToken names is built: " ..
            sys.errname(e or 0))
        sys.close(w, fd)
        w:kill(); w:join()
    end)

test("KACS applies its own hard cap of 256 names when it parses the specification",
    { spec = "PKM *layer.private.kacs-hard-cap-of-256-at-parse" },
    function(t)
        local w = vm:spawn_worker()
        local n256, n257 = {}, {}
        for i = 1, 256 do n256[i] = "n" .. i end
        for i = 1, 257 do n257[i] = "n" .. i end
        local ok = token.mint(w, creds(n256, {}, { user_sid = token.SID.LOCAL_SYSTEM }))
        t:assert(ok, "256 names parse")
        if ok then sys.close(w, ok) end
        local bad, e = token.mint(w, creds(n257, {}, { user_sid = token.SID.LOCAL_SYSTEM }))
        t:assert(not bad, "257 do not: KACS refuses them when it parses the extension")
        t:assert_eq(e, sys.E.INVAL, "at token creation")
        w:kill(); w:join()
    end)

test("the configured LCS limit is applied when LCS acquires a thread's credentials",
    { spec = "PKM *layer.private.lcs-cap-applied-at-credential-acquisition" },
    function(t)
        local names = {}
        for i = 1, 17 do names[i] = "n" .. i end
        token.as_principal(t, vm, creds(names), function(w)
            local mark = src:mark()
            local r = lcs.open_key(nil, w, -1, TEST_PATH, lcs.RIGHT.KEY_READ)
            t:assert(r.ret < 0, "the operation fails")
            t:assert_eq(#src:served(lcs.OP.LOOKUP, mark), 0,
                "at credential acquisition, before anything reaches a source")
        end)
    end)

test("an over-cap token is accepted and then fails every operation any thread holding it performs",
    { spec = "PKM *layer.private.over-cap-token-accepted-then-fails-every-operation" },
    function(t)
        local names = {}
        for i = 1, 17 do names[i] = "n" .. i end
        token.as_principal(t, vm, creds(names), function(w)
            local o = lcs.open_key(nil, w, -1, TEST_PATH, lcs.RIGHT.KEY_READ)
            t:assert_eq(o.errno, sys.E.BIG2, "reg_open_key fails")
            local c = lcs.create_key(nil, w, { path = TEST_PATH .. "\\New" })
            t:assert_eq(c.errno, sys.E.BIG2, "reg_create_key fails")
            local u = lcs.open_key(nil, w, -1, "NoSuchHive\\K", lcs.RIGHT.KEY_READ)
            t:assert_eq(u.errno, sys.E.BIG2,
                "and so does one that would not have reached a source at all")
        end)
    end)

test("the over-cap failure is E2BIG, not an access-control denial",
    { spec = "PKM *layer.private.over-cap-is-e2big" },
    function(t)
        local names = {}
        for i = 1, 17 do names[i] = "n" .. i end
        token.as_principal(t, vm, creds(names), function(w)
            local r = lcs.open_key(nil, w, -1, TEST_PATH, lcs.RIGHT.KEY_READ)
            t:assert_eq(r.errno, sys.E.BIG2,
                "a count fixed when the token was assembled is not a descriptor problem")
            t:assert(r.errno ~= sys.E.ACCES, "so it is not reported as EACCES")
        end)
    end)

test("MaxScopeGUIDsPerToken shares the check and the errno",
    { spec = "PKM *layer.private.max-scope-guids-shares-the-check-and-errno" },
    function(t)
        local eight, nine = {}, {}
        for i = 1, 8 do eight[i] = lcs.guid() end
        for i = 1, 9 do nine[i] = lcs.guid() end
        token.as_principal(t, vm, creds({}, eight), function(w)
            local r = lcs.open_key(src, w, -1, TEST_PATH, lcs.RIGHT.KEY_READ)
            t:assert(r.ret >= 0, "eight scope GUIDs are within the default: " ..
                sys.errname(r.errno or 0))
            sys.close(w, r.ret)
        end)
        token.as_principal(t, vm, creds({}, nine), function(w)
            local r = lcs.open_key(nil, w, -1, TEST_PATH, lcs.RIGHT.KEY_READ)
            t:assert_eq(r.errno, sys.E.BIG2, "nine share the same check and the same errno")
        end)
    end)

test("a missing token is EACCES, because that one is an access decision",
    { spec = "PKM *layer.private.missing-token-is-eacces",
      covered_by = "kunit:pkm_lcs_kunit_open",
      skip = "every guest thread has an effective token, so no guest can present " ..
             "the NULL-token case to credential acquisition; runs under " ..
             "pkm_lcs_kunit_private_credentials_over_cap_is_e2big" },
    function(t) end)

test("KACS matches the private layer names it parses by the same folding LCS resolves them by",
    { spec = "PKM *layer.private.kacs-dedupes-names-by-case-folding",
      tags = { "known-bug" } },
    function(t)
        local w = vm:spawn_worker()
        -- An ASCII case pair is one identity to KACS: it will not let
        -- both onto a token.
        local ascii, e = token.mint(w, creds({ "Alpha", "ALPHA" }, {},
            { user_sid = token.SID.LOCAL_SYSTEM }))
        t:assert(not ascii, "`Alpha` and `ALPHA` are one name")
        t:assert_eq(e, sys.E.INVAL, "and cannot both sit on one token")
        w:kill(); w:join()
        -- `ROLEs` and `ROLEſ` fold equal too, so seventeen names of
        -- which two are that pair are sixteen layers, within
        -- MaxPrivateLayersPerToken, and every operation must work.
        --
        -- KERNEL: kacs/token_runtime.rs parse_lcs_credential_extension
        -- still compares with eq_ignore_ascii_case, so both spellings
        -- sit on the token, the raw count LCS reads is seventeen, and
        -- every operation fails E2BIG — exactly the divergence §5.3.5
        -- describes as gone.
        local names = { "ROLEs", "ROLE" .. LONG_S }
        for i = 1, 15 do names[#names + 1] = "n" .. i end
        token.as_principal(t, vm, creds(names), function(w2)
            local r = lcs.open_key(src, w2, -1, TEST_PATH, lcs.RIGHT.KEY_READ)
            t:assert(r.ret >= 0,
                "a name LCS treats as one layer is one layer to KACS too: " ..
                sys.errname(r.errno or 0))
            if r.ret >= 0 then sys.close(w2, r.ret) end
        end)
    end)

test("nothing on the attachment path looks up a layer's precedence or tests a privilege",
    { spec = "PKM *layer.private.no-precedence-or-privilege-check-on-attachment" },
    function(t)
        -- A token with no privileges at all, attaching a disabled layer
        -- at Group Policy precedence.
        token.as_principal(t, vm, creds({ "hip" }, {},
            { privs_present = 0, privs_enabled = 0 }), function(w)
            local r = lcs.open_key(src, w, -1, TEST_PATH, lcs.RIGHT.KEY_READ)
            t:assert(r.ret >= 0, "the key opens: " .. sys.errname(r.errno or 0))
            local q = lcs.query_value(src, w, r.ret, "R")
            t:assert_eq(q.layer, "hip",
                "an unprivileged process sees a precedence-9 layer it attached to itself")
            sys.close(w, r.ret)
        end)
        -- And KACS never consults the layer table: a name that is not a
        -- layer at all is accepted just the same.
        token.as_principal(t, vm, creds({ "not-a-layer-anywhere" }), function(w)
            local r = lcs.open_key(src, w, -1, TEST_PATH, lcs.RIGHT.KEY_READ)
            t:assert(r.ret >= 0,
                "there is no precedence lookup on the attachment path: " ..
                sys.errname(r.errno or 0))
            sys.close(w, r.ret)
        end)
    end)

test("what does gate attachment is SeCreateTokenPrivilege",
    { spec = "PKM *layer.private.attachment-gated-by-secreatetokenprivilege" },
    function(t)
        token.as_principal(t, vm, { privs_present = 0, privs_enabled = 0 }, function(w)
            local fd, e = token.mint(w, creds({ "priv" }))
            t:assert(not fd,
                "private layer names can only enter a token when the token is created")
            t:assert_eq(e, sys.E.PERM,
                "and that is gated by SeCreateTokenPrivilege, the same blanket gate as " ..
                "for scope GUIDs")
        end)
    end)
