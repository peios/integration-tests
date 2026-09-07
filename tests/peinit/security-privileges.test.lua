-- Peinit TRM §13.2 — peinit runs with every privilege, and spends a much
-- narrower set.
--
-- Both claims here are about privileges rather than about a command, and
-- KACS keeps the record that makes them observable: a token carries a
-- *used* mask alongside present and enabled, and the kernel sets a bit
-- in it when a privilege is what allowed something. A whole boot — four
-- platform services minted, every service launched with a token
-- installed on the child — is therefore enough history to ask which of
-- peinit's privileges it has ever had to spend.

local peinit = require("helpers.peinit")
peinit.claim(1)

local vm = peinit.boot()

--- The `token privs` table, as name → attribute string.
local function privileges(text)
    local out = {}
    for _, line in ipairs(peinit.lines(text)) do
        local name, attrs = line:match("^%s+(.-)%s%s+([%a%s,]+)$")
        if name and attrs then out[name] = attrs end
    end
    return out
end

test("the two privileges peinit requires are present, enabled and spent",
    { spec = "peinit *privilege.the-required-privileges-are-verified-at-startup" },
    function(t)
        -- The check runs before Phase 1 does anything that needs them,
        -- and a boot that reached Phase 2 is a boot that passed it. What
        -- can be inspected afterwards is the condition it applied.
        local held = privileges(vm:run("token privs --pid 1").stdout)

        -- Present *and* enabled, which is the whole point of the wording:
        -- a privilege the token carries but has not enabled is not
        -- usable, and would have failed the check identically to being
        -- absent.
        for _, name in ipairs({ "SeCreateToken", "SeTcb" }) do
            t:assert(held[name], name .. " is present on PID 1's token")
            t:assert(held[name]:find("enabled", 1, true),
                name .. " is enabled, not merely present: " .. held[name])
        end

        -- And the check earns its place because both are genuinely
        -- spent. The kernel marks a privilege used when it is what
        -- allowed an operation, so these two marks are the mint for
        -- registryd and the token install on a child — the operations a
        -- missing privilege used to fail at, several steps after the
        -- point where it could have been named.
        for _, name in ipairs({ "SeCreateToken", "SeTcb" }) do
            t:assert(held[name]:find("used", 1, true),
                name .. " was actually exercised during the boot: " .. held[name])
        end

        t:assert(vm:console():read_log():find(peinit.marks.phase1, 1, true),
            "and Phase 1 ran, which is only reached past the check")
    end)

test("SeImpersonatePrivilege is held and never spent",
    { spec = "peinit *privilege.se-impersonate-is-not-required" },
    function(t)
        -- peinit passes the peer's token descriptor to AccessCheck
        -- rather than impersonating the caller, so the privilege that
        -- would gate impersonating is never reached. The boot token
        -- carries it regardless — every privilege is on it — so the
        -- claim is about use, not possession.
        local held = privileges(vm:run("token privs --pid 1").stdout)
        t:assert(held.SeImpersonate, "the boot token carries SeImpersonate: "
            .. tostring(held.SeImpersonate))
        t:assert(not held.SeImpersonate:find("used", 1, true),
            "and nothing ever spent it: " .. held.SeImpersonate)

        -- That assertion is only worth something if the used mask is
        -- live on this token, which the two privileges peinit does spend
        -- establish. Without them the test above would pass on a system
        -- that never records anything.
        t:assert(held.SeCreateToken:find("used", 1, true) and
                 held.SeTcb:find("used", 1, true),
            "the used mask on this token does record what peinit spends")

        -- The mark is on peinit's own token, which every autorun child —
        -- this agent included — is running on, so a descendant that
        -- impersonated would set it too. The assertion can therefore
        -- fail spuriously but cannot pass spuriously, which is the right
        -- way round for a claim that something never happens.
        --
        -- The control socket has been served this boot: the agent's own
        -- svctl calls above went through peinit's AccessCheck path, and
        -- that is the path the privilege would have been needed on.
        vm:run("svctl status registryd"):assert_ok()
        local after = privileges(vm:run("token privs --pid 1").stdout)
        t:assert(not after.SeImpersonate:find("used", 1, true),
            "still unspent after a control command was authorised: " .. after.SeImpersonate)
    end)
