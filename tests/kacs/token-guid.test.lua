-- Query the immutable token identity used by KMES, including impersonation.
local sys = require("helpers.sys")
local token = require("helpers.token")
local kmes = require("helpers.kmes")
local vm = provium:vm("v", "kernel-only"):boot()

local function guid(who, fd) return assert(token.query(who, fd, token.CLASS.GUID)) end

test("token GUID is exactly sixteen bytes with the usual query size contract",
    { spec = "PKM *token.query.guid-size-and-right" }, function(t)
        local fd = assert(token.open_self(vm, token.RIGHT.QUERY))
        for _, size in ipairs({ 0, 1, 15, 16, 17 }) do
            local r, need = token.query_raw(vm, fd, token.CLASS.GUID, size)
            t:assert_eq(need, 16, "reports sixteen bytes")
            if size > 0 and size < 16 then
                t:assert_eq(r.errno, sys.E.RANGE, "short buffer refused")
                t:assert_eq(r.out_bufs[2], string.rep("\0", size), "no partial payload")
            else
                t:assert_eq(r.ret, 0, "probe or sufficient buffer accepted")
                if size > 16 then t:assert_eq(r.out_bufs[2]:sub(17), "\0", "tail untouched") end
            end
        end
        local reopened = assert(token.open_self(vm, token.RIGHT.QUERY))
        t:assert_eq(guid(vm, reopened), guid(vm, fd), "same token through another handle")
        t:assert_neq(guid(vm, fd), string.rep("\0", 16), "not a null GUID")
        t:assert_eq(#assert(token.query(vm, fd, token.CLASS.STATISTICS)), 40,
            "statistics ABI remains forty bytes")
        sys.close(vm, reopened); sys.close(vm, fd)
        local denied = assert(token.open_self(vm, token.RIGHT.QUERY_SOURCE))
        local r, need = token.query_raw(vm, denied, token.CLASS.GUID, 0)
        t:assert_eq(r.errno, sys.E.ACCES, "QUERY_SOURCE alone cannot query GUID")
        t:assert_eq(need, 0, "denied even before reporting size")
        sys.close(vm, denied)
    end)

test("adjustments preserve a GUID while duplicate and restricted tokens get new GUIDs",
    { spec = "PKM *token.query.guid-immutable-instance" }, function(t)
        local fd = assert(token.mint(vm, {}))
        local original = guid(vm, fd)
        local modified = token.statistics(vm, fd).modified_id
        t:assert_eq(token.adjust_interactivity_scope(vm, fd, 9).ret, 0, "adjust token")
        t:assert(token.statistics(vm, fd).modified_id > modified, "actually modified")
        t:assert_eq(guid(vm, fd), original, "identity survives adjustment")
        local copy = assert(token.duplicate(vm, fd))
        local restricted = assert(token.restrict(vm, fd))
        t:assert_neq(guid(vm, copy), original, "duplicate has a new identity")
        t:assert_neq(guid(vm, restricted), original, "restricted copy has a new identity")
        t:assert_neq(guid(vm, restricted), guid(vm, copy), "derived identities differ")
        sys.close(vm, restricted); sys.close(vm, copy); sys.close(vm, fd)
    end)

test("queried effective and real token GUIDs match KMES bytes across impersonation",
    { spec = "PKM *token.query.guid-matches-kmes" }, function(t)
        local worker = vm:spawn_worker()
        local ok, err = pcall(function()
            local primary = assert(token.open_self(worker))
            local imp = assert(token.duplicate(worker, primary, {
                token_type = token.TYPE.IMPERSONATION,
                impersonation_level = token.LEVEL.IMPERSONATION }))
            local primary_guid, imp_guid = guid(worker, primary), guid(worker, imp)
            local events = kmes.recording(t, vm, function()
                t:assert_eq(kmes.emit(worker, "PIT_GUID_BEFORE", kmes.PAYLOAD).ret, 0)
                t:assert_eq(token.impersonate(worker, imp).ret, 0)
                local effective = assert(token.open_self(worker, token.RIGHT.QUERY))
                local real = assert(token.open_self(worker, token.RIGHT.QUERY, token.OPEN_REAL))
                t:assert_eq(guid(worker, effective), imp_guid, "effective query follows impersonation")
                t:assert_eq(guid(worker, real), primary_guid, "real query retains primary identity")
                t:assert_eq(kmes.emit(worker, "PIT_GUID_DURING", kmes.PAYLOAD).ret, 0)
                t:assert_eq(token.revert(worker).ret, 0)
                t:assert_eq(kmes.emit(worker, "PIT_GUID_AFTER", kmes.PAYLOAD).ret, 0)
                sys.close(worker, real); sys.close(worker, effective)
            end)
            for _, kind in ipairs({ "PIT_GUID_BEFORE", "PIT_GUID_DURING", "PIT_GUID_AFTER" }) do
                local event = kmes.of_type(events, kind)[1]
                t:assert(event, "event observed: " .. kind)
                t:assert_eq(event.true_token, primary_guid, "raw true-token bytes match query")
                t:assert_eq(event.effective_token,
                    kind == "PIT_GUID_DURING" and imp_guid or primary_guid,
                    "raw effective-token bytes match query")
            end
            sys.close(worker, imp); sys.close(worker, primary)
        end)
        worker:kill(); worker:join()
        if not ok then error(err, 0) end
    end)
