-- PKM §2.8 — the kernel's event-policy seed, applied the way an image
-- applies it.
--
-- The kernel-only profile has no `reg` and applies no seed, so this file
-- boots the peinit image. An autorun that sorts before the image's
-- `10-apply-seeds.sh` copies the seed the kernel package ships into
-- /lcl/policy/autoapply.d, so it is applied by the image's own
-- `reg apply --dir … --once-delete`, as SYSTEM, exactly as an image naming
-- it in [registry] autoapply would apply it. The key it leaves is then read
-- back with `reg`.

local peinit = require("helpers.peinit")
peinit.claim(1)

local SEED = "/usr/share/regim/event-policy.reg"
local EVENTS = [[Machine\Generic\Events]]

local vm = peinit.boot({
    name = "vpolicyseed",
    files = {
        ["lcl/policy/autorun.d/05-pt-event-policy.sh"] = {
            "#!/bin/sh\ncp " .. SEED .. " /lcl/policy/autoapply.d/event-policy.reg\n",
            exec = true,
        },
    },
})

--- The SYSTEM_ALARM ACE of a SACL in SDDL, or nil.
local function alarm_ace(sddl)
    return sddl and sddl:match("%(AL;[^)]*%)")
end

test("the seed leaves Events with no Enabled, so the tiers decide",
    { spec = "PKM *policy.seed-creates-key-without-enabled" }, function(t)
        local doc = json.decode(vm:read_file(SEED))
        local events
        for _, k in ipairs(doc and doc.keys or {}) do
            if k.path == EVENTS then events = k end
        end
        t:assert(events, "the shipped seed names Machine\\Generic\\Events")
        t:assert_eq(#(events.values or {}), 0, "and gives it no values")

        local out = vm:run("reg export --json '" .. EVENTS .. "'")
        out:assert_ok()
        local exported = json.decode(out.stdout)
        t:assert(exported and exported.keys and exported.keys[1],
            "the applied key exists: " .. out.stdout)
        t:assert_eq(exported.keys[1].path, EVENTS, "it is the policy key")
        t:assert_eq(#(exported.keys[1].values or {}), 0,
            "and holds no Enabled, nor anything else: " .. out.stdout)
    end)

test("the seeded key carries the SACL that audits writes to the policy",
    { spec = "PKM *policy.seed-sacl-audits-writes" }, function(t)
        local sd = vm:run("reg sd '" .. EVENTS .. "' --sacl")
        sd:assert_ok()
        local ace = alarm_ace(sd.stdout)
        t:assert(ace, "the key's SACL holds a SYSTEM_ALARM ACE: " .. sd.stdout)
        t:assert(ace:match("^%(AL;[^;]*CI"), "inherited by the keys beneath: " .. ace)
        t:assert(ace:match(";WD%)$"), "for Everyone: " .. ace)

        -- The mask, compared with the same SDDL applied to a key of the
        -- test's own and formatted by the same `reg sd`, so the check
        -- does not depend on how the formatter names KEY_SET_VALUE | DELETE.
        local ref = [[Machine\Software\PtPolicySaclReference]]
        local file = "/tmp/pt-sacl-ref.json"
        vm:run("cat > " .. file .. " <<'PT_JSON_EOF'\n" .. peinit.encode_json({
            keys = {
                { path = [[Machine\Software]] },
                { path = ref, descriptor = "S:(AL;CI;0x10002;;;WD)" },
            },
        }) .. "\nPT_JSON_EOF"):assert_ok()
        vm:run("reg apply " .. file):assert_ok()
        local want = vm:run("reg sd '" .. ref .. "' --sacl")
        want:assert_ok()
        t:assert_eq(ace, alarm_ace(want.stdout),
            "over KEY_SET_VALUE | DELETE, exactly as declared")

        -- Only the SACL was given, so the owner and DACL are the ones the
        -- key inherited: Authenticated Users may still read the policy.
        local dacl = vm:run("reg sd '" .. EVENTS .. "' --dacl")
        dacl:assert_ok()
        t:assert(dacl.stdout:match("AU%)") or dacl.stdout:match(";AU"),
            "the inherited DACL is untouched: " .. dacl.stdout)
        vm:run("reg del '" .. ref .. "' -r -y")
    end)
