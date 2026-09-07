-- Peinit TRM §13.1 — the two trust boundaries peinit sits at.
--
-- Both are claims about a state the machine is in rather than about a
-- transition, which is why a booted system is the right place to look:
-- the token the kernel handed PID 1 is still on PID 1, and the
-- filesystem enforcement the chapter says has no bypass can be put to
-- the test by creating something for it to refuse.

local peinit = require("helpers.peinit")
peinit.claim(1)

local vm = peinit.boot()

--- The `token privs` table, as name → attribute string.
---
--- Entries the tool has no name for render as `<privilege bit N>`, and
--- those matter here: they are how a reader tells a token carrying the
--- whole privilege mask from one carrying a curated set.
local function privileges(text)
    local out, count = {}, 0
    for _, line in ipairs(peinit.lines(text)) do
        local name, attrs = line:match("^%s+(.-)%s%s+([%a%s,]+)$")
        if name and attrs then
            out[name] = attrs
            count = count + 1
        end
    end
    return out, count
end

test("PID 1 holds the boot SYSTEM token, with every privilege",
    { spec = "peinit *trust.the-kernel-hands-peinit-the-system-token" },
    function(t)
        -- There is no authority above peinit in userspace that could
        -- vouch for it, so what makes this the root of trust is only
        -- that the kernel put it there. What can be checked from here is
        -- that PID 1 is holding exactly what the chapter says it was
        -- given.
        local user = vm:run("token user --pid 1")
        user:assert_ok()
        t:assert(user.stdout:find("S-1-5-18", 1, true),
            "PID 1 runs as SYSTEM: " .. user.stdout)

        local privs = vm:run("token privs --pid 1")
        privs:assert_ok()
        local held, count = privileges(privs.stdout)
        t:assert(count > 30, "the token carries the whole privilege set, not a subset: "
            .. count .. " privileges")

        -- "Every privilege" is the claim, so the interesting evidence is
        -- not the named ones but the bits the tool cannot name: a token
        -- built by naming privileges would carry only nameable ones.
        local unnamed = 0
        for name, attrs in pairs(held) do
            t:assert(attrs:find("enabled", 1, true),
                name .. " is enabled, not merely present: " .. attrs)
            if name:find("^<privilege bit") then unnamed = unnamed + 1 end
        end
        t:assert(unnamed > 0,
            "the token carries privilege bits this build has no name for, so it is the "
            .. "full mask rather than a list somebody wrote out")

        -- The two peinit actually spends, and the one §13.2 says it does
        -- not need, are all here — the boot token is not selective.
        for _, name in ipairs({ "SeCreateToken", "SeTcb", "SeImpersonate",
                                "SeDebug", "SeBackup", "SeRestore" }) do
            t:assert(held[name], name .. " is on PID 1's token")
        end

        -- And it is the token from a real logon session rather than a
        -- synthesised one: the kernel appends the session's logon SID to
        -- the group list when it creates a token, so its presence is the
        -- kernel's own mark on this one.
        local groups = vm:run("token groups --pid 1")
        groups:assert_ok()
        t:assert(groups.stdout:find("logon%-id"),
            "the group list carries the boot session's logon SID: " .. groups.stdout)
    end)

test("a filesystem with no descriptor is refused to SYSTEM as much as to anyone",
    { spec = "peinit *trust.descriptor-enforcement-has-no-bypass" },
    function(t)
        -- The claim is that a missing Security Descriptor has no way
        -- round it: no owner exemption, no privilege, no root escape.
        -- A freshly mounted tmpfs is the case that produces one, which is
        -- why Phase 1 seeding exists at all (§2.3) — so mounting one
        -- unseeded is how to ask the enforcement the question directly.
        --
        -- The caller is the agent, running on peinit's own SYSTEM token:
        -- the most privileged principal the machine has.
        local point = "/run/pt-trust-nosd"
        vm:run("mkdir -p " .. point):assert_ok()

        -- The same path, same caller, before the mount. It inherits the
        -- /run seed, so everything works.
        vm:run("ls -a " .. point):assert_ok()
        vm:run("touch " .. point .. "/before"):assert_ok()
        vm:run("sd show " .. point):assert_ok()

        vm:run("mount -t tmpfs tmpfs " .. point):assert_ok()

        -- The mount is really there — the denials below are a new
        -- filesystem refusing, not a path that went away.
        local mounted = false
        for _, line in ipairs(peinit.lines(vm:read_file("/proc/self/mountinfo"))) do
            local at, rest = line:match("^%d+ %d+ %S+ %S+ (%S+) (.*)$")
            if at == point then
                mounted = true
                t:assert(rest:find("%- tmpfs "), point .. " is a tmpfs: " .. line)
            end
        end
        t:assert(mounted, point .. " is mounted")

        -- Nothing on it is reachable. Reading the directory, creating in
        -- it, stat'ing it, and even reading the descriptor that is not
        -- there: all EACCES, to a caller that owns the machine.
        for _, command in ipairs({ "ls -a " .. point,
                                   "touch " .. point .. "/x",
                                   "stat " .. point,
                                   "sd show " .. point }) do
            local r = vm:run(command .. " 2>&1")
            t:assert(not r:ok(), "`" .. command .. "` was refused")
            t:assert(r.stdout:lower():find("permission denied", 1, true) or
                     r.stdout:find("errno 13", 1, true),
                "`" .. command .. "` was refused for want of access, not for another reason: "
                .. r.stdout)
        end

        -- And the refusal is not a DAC one that a privilege would lift.
        -- The caller holds SeBackup and SeRestore — the pair that on a
        -- system with an override *is* the override — and SeDebug, and
        -- is the owner of everything the seed stamped.
        local held = privileges(vm:run("token privs").stdout)
        for _, name in ipairs({ "SeBackup", "SeRestore", "SeDebug" }) do
            t:assert(held[name] and held[name]:find("enabled", 1, true),
                "the refused caller holds " .. name .. ", enabled")
        end

        vm:run("umount " .. point)
    end)
