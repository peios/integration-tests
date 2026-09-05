-- §5.8.1, The Source Model: what a source is obliged to return, what
-- it is never told, what LCS believes, and the trust boundary that
-- follows from all three.
--
-- The Lua source of helpers/lcs plays every part here. That it can is
-- itself the point of the last case: LCS knows nothing about loregd.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")
local kmes = require("helpers.kmes")
local token = require("helpers.token")
local kacs = require("helpers.kacs")
local access = require("helpers.access")

local vm = provium:vm("v", "kernel-only"):boot()

-- One source for the whole file: a Down slot keeps its hive identity,
-- so a second Machine source could not register here (§5.8.2).
local TRUSTED, GUARDED
local src, test_key = assert(lcs.machine(vm, {
    seed = function(s)
        s:seed_layer("Policy", { precedence = 10, enabled = true })
        -- Two keys differing only in the descriptor the source returns
        -- for them. Seeded before registration, so their sequence
        -- numbers are below the counter the kernel starts from.
        TRUSTED = s:key("Machine\\Software\\Test\\Trusted", { sd = lcs.permissive_sd() })
        GUARDED = s:key("Machine\\Software\\Test\\Guarded", { sd = lcs.sd({
            access.ace(access.ACE.ALLOWED, lcs.RIGHT.KEY_ALL_ACCESS, kacs.SID.LOCAL_SYSTEM, 0),
        }) })
    end,
}))
local w = vm:spawn_worker()

local function fresh(name)
    local r = lcs.create_key(src, w, { parent_fd = -1,
        path = "Machine\\Software\\Test\\" .. name, access = lcs.KEY_ALL_ACCESS })
    assert(r.ret >= 0, "create " .. name .. ": " .. sys.errname(r.errno or 0))
    return r.ret
end

test("a source returns every entry it holds for a key, in one answer, and LCS resolves them",
    { spec = "PKM *source.model.returns-all-entries" }, function(t)
        local fd = fresh("ReturnsAll")
        -- Two layers' worth of the same value name, plus a blanket
        -- tombstone in a third: everything the source holds for the key.
        t:assert_eq(lcs.set_value(src, w, fd, "V", lcs.TYPE.DWORD, lcs.dword(1)).ret, 0,
            "seed the base layer")
        t:assert_eq(lcs.set_value(src, w, fd, "V", lcs.TYPE.DWORD, lcs.dword(2),
            { layer = "Policy" }).ret, 0, "and the Policy layer")

        local mark = src:mark()
        local q = lcs.query_value(src, w, fd, "V")
        t:assert_eq(q.ret, 0, "query: " .. sys.errname(q.errno or 0))
        t:assert_eq(q.layer, "Policy", "the higher-precedence layer wins the resolution")
        t:assert_eq(q.data, lcs.dword(2), "with its data")

        local asked = src:served(lcs.OP.QUERY_VALUES, mark)
        t:assert_eq(#asked, 1, "one RSI_QUERY_VALUES answered the whole query: " ..
            "the source returns all of its entries rather than being asked per layer")
        -- The response the source built carried both layers' rows; the
        -- kernel picked between them. Nothing layer-aware crossed the
        -- wire in the request.
        sys.close(w, fd)
    end)

test("a source is never told who is asking",
    { spec = "PKM *source.model.does-no-policy" }, function(t)
        local fd = fresh("NoPolicy")
        sys.close(w, fd)
        local path = "Machine\\Software\\Test\\NoPolicy"

        local mark = src:mark()
        local r = lcs.open_key(src, w, -1, path, lcs.RIGHT.KEY_READ)
        t:assert(r.ret >= 0, "SYSTEM opens it: " .. sys.errname(r.errno or 0))
        sys.close(w, r.ret)
        local as_system = {}
        for _, e in ipairs(src:served(lcs.OP.LOOKUP, mark)) do
            as_system[#as_system + 1] = e.payload
        end
        t:assert(#as_system > 0, "and the walk reached the source")

        token.as_principal(t, vm, {}, function(w2)
            local mark2 = src:mark()
            local r2 = src:run(function()
                return lcs.open_key_async(w2, -1, path, lcs.RIGHT.KEY_READ)
            end)
            t:assert(r2.ret >= 0, "so does an ordinary user: " .. sys.errname(r2.errno or 0))
            sys.close(w2, r2.ret)
            local as_user = {}
            for _, e in ipairs(src:served(lcs.OP.LOOKUP, mark2)) do
                as_user[#as_user + 1] = e.payload
            end
            t:assert_eq(#as_user, #as_system, "the same walk")
            for i = 1, #as_user do
                t:assert_eq(as_user[i], as_system[i],
                    "and byte-identical requests: no caller identity reaches the source")
            end
        end)
    end)

test("LCS trusts the descriptor a source returns, and grants what it says",
    { spec = "PKM *source.model.lcs-trusts-source-data" }, function(t)
        -- LCS has no independent copy of either descriptor, so what
        -- the source says is what AccessCheck decides on.
        t:assert(TRUSTED and GUARDED, "both keys were seeded before registration")

        token.as_principal(t, vm, {}, function(w2)
            local ok = src:run(function()
                return lcs.open_key_async(w2, -1, "Machine\\Software\\Test\\Trusted",
                    lcs.RIGHT.KEY_ALL_ACCESS)
            end)
            t:assert(ok.ret >= 0,
                "an ordinary user gets KEY_ALL_ACCESS where the source returned a permissive " ..
                "descriptor: " .. sys.errname(ok.errno or 0))
            sys.close(w2, ok.ret)
            local no = src:run(function()
                return lcs.open_key_async(w2, -1, "Machine\\Software\\Test\\Guarded",
                    lcs.RIGHT.KEY_ALL_ACCESS)
            end)
            t:assert_eq(no.errno, sys.E.ACCES,
                "and is denied where it returned a restrictive one — the data is believed either way")
        end)
    end)

test("nothing in LCS knows which source is loregd: any source that registers Machine is the one it configures itself from",
    { spec = "PKM *source.model.loregd-is-not-special" }, function(t)
        -- LCS reads its own nineteen parameters out of Machine\System\
        -- Registry (§5.10) on registration. This source is not loregd
        -- and says so nowhere; it still gets the bootstrap, and the
        -- unseeded parameters produce the documented nineteen events.
        local other = lcs.source(vm, { hives = { { name = "Loregdless" } } })
        other:key("Loregdless\\Anything")
        local events = kmes.recording(t, vm, function()
            assert(other:register())
            other:pump()
        end)
        local invalid = kmes.of_type(events, "LCS_SELF_CONFIG_INVALID")
        t:assert_eq(#invalid, 0,
            "a source backing no Machine hive gets no self-configuration bootstrap at all")

        -- Where the Machine hive is concerned, the plain Lua source of
        -- this file is treated exactly as loregd would be: it answered
        -- the bootstrap that ran at its own registration.
        t:assert(#src:served(lcs.OP.LOOKUP) > 0,
            "and the Machine source, whoever it is, was asked for the registry's own configuration")
        other:close()
    end)
