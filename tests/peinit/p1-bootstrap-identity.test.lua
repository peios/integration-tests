-- Peinit TRM §2.2 — bootstrap identity: the steady-state identity flow
-- cannot start the system, so a service that asks for SYSTEM gets a token
-- peinit mints itself and everything else waits for authd.
--
-- The two routes are distinguishable from outside, which is what makes
-- the chapter testable at all. A token peinit minted is a copy of its
-- own: same logon session, and Delegation, the level a credentialled
-- logon produces. A token authd attested belongs to a session peinit
-- never saw and stops at Impersonation. So "who minted this" is a
-- question a booted machine answers, and the four services §2.2 names
-- are not a special case of anything — the same seeded definitions below
-- get the same treatment.
--
-- The definitions are staged rather than borrowed from the image's own
-- graph deliberately: the claim is about what a *definition* asks for,
-- and a test that only ever looked at registryd and authd could not tell
-- the rule from the list.

local peinit = require("helpers.peinit")
peinit.claim(1)

local function resident(name, extra)
    local values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "900" } },
        { name = "Type", type = "dword", data = 0 },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "Triggers", type = "multi", data = { "boot" } },
    }
    for _, v in ipairs(extra or {}) do values[#values + 1] = v end
    return { path = [[Machine\System\Services\]] .. name, values = values }
end

-- Demand-only: started at the moment a test wants it, so the outcome
-- read back is that one attempt's.
local function on_demand(name, extra)
    local values = {
        { name = "ImagePath", type = "sz", data = "/bin/true" },
        { name = "Type", type = "dword", data = 1 },
        { name = "Readiness", type = "dword", data = 1 },
    }
    for _, v in ipairs(extra or {}) do values[#values + 1] = v end
    return { path = [[Machine\System\Services\]] .. name, values = values }
end

local SYSTEM = { name = "Identity", type = "sz", data = "SYSTEM" }

local vm = peinit.boot({
    name = "p1-bootstrap",
    files = peinit.seed("pt-bs", {
        { path = [[Machine\System]] },
        { path = [[Machine\System\Services]] },
        resident("pt-bs-system", { SYSTEM }),
        -- No Identity field at all: the defaulting claim needs the
        -- absence, not a definition that names LocalService.
        resident("pt-bs-default"),
        on_demand("pt-bs-ondemand"),
        on_demand("pt-bs-ondemand-system", { SYSTEM }),
    }),
})

-- Derived by §4.4's rule (SHA-1 over the UTF-16LE of the uppercased
-- name, five little-endian 32-bit sub-authorities under S-1-5-80) from
-- the two service names below, and computed outside the guest so this is
-- a check rather than a snapshot.
local SID = {
    ["pt-bs-system"] = "S-1-5-80-2883575608-695137064-1337423767-3240385803-637676565",
    ["pt-bs-default"] = "S-1-5-80-154766025-3589640390-2737900188-718047884-1128318716",
}

local function token_of(pid)
    local shown = vm:run("token show --pid " .. pid .. " --raw --all")
    shown:assert_ok()
    local out = { principal = {}, groups = {}, privileges = {} }
    local section
    for _, line in ipairs(peinit.lines(shown.stdout)) do
        local head = line:match("^%[(%a+)")
        if head then
            section = head
        elseif section and out[section] then
            local name, attrs = line:match("^%s+(.-)%s%s+(.*)$")
            if name then out[section][name] = attrs end
        end
    end
    return out
end

local function pid_of(service)
    for _ = 1, 40 do
        local pid = vm:run("svctl status " .. service).stdout:match("pid: (%d+)")
        if pid then return pid end
        vm:run("sleep 1")
    end
    error(service .. " never reported a pid")
end

local function logon_sid(token)
    for sid, attrs in pairs(token.groups) do
        if attrs:find("logon%-id") then return sid end
    end
end

test("a definition asking for SYSTEM gets a token peinit minted from its own, carrying the service's SID",
    {
        spec = {
            "peinit *bootstrap.a-system-identity-is-minted-by-peinit",
            "peinit *bootstrap.a-minted-system-token-carries-the-per-service-sid",
        },
    },
    function(t)
        local mine, theirs = token_of(1), token_of(pid_of("pt-bs-system"))

        t:assert_eq(theirs.principal.user, "S-1-5-18", "the service runs as SYSTEM")
        -- Minted from peinit's own, rather than issued by an authority:
        -- the copy keeps peinit's logon session, and mints at Delegation
        -- where an attestation stops one rung lower at Impersonation.
        t:assert_eq(logon_sid(theirs), logon_sid(mine),
            "in peinit's own logon session, which is where a copy of its token lands")
        t:assert_eq(theirs.principal.impersonation_level, "3",
            "and at Delegation, the level kacs_create_token produces")

        -- The group that keeps platform services distinguishable to an
        -- access check despite all of them being S-1-5-18. peinit
        -- computes it, so it is present on a token peinit minted and
        -- derived from the service's name alone.
        t:assert(theirs.groups[SID["pt-bs-system"]],
            "the minted token carries pt-bs-system's per-service SID")
        t:assert(not mine.groups[SID["pt-bs-system"]],
            "which peinit's own token does not, so it was added for this service")
    end)

test("nothing restricts which services may declare Identity=SYSTEM",
    { spec = "peinit *bootstrap.no-allowlist-governs-who-may-be-system" },
    function(t)
        -- pt-bs-system is not registryd, lpsd, authd or eventd. It is a
        -- definition this test wrote into the registry a few seconds
        -- before the boot read it, and it got SYSTEM — so the four
        -- services §2.2 lists are the ones that need it, not the ones
        -- allowed to have it. The boundary is the descriptor on
        -- Machine\System\Services\, which is what let this seed land at
        -- all.
        local platform = { registryd = true, lpsd = true, authd = true, eventd = true }
        t:assert(not platform["pt-bs-system"], "the service is not one of the four")
        t:assert_eq(token_of(pid_of("pt-bs-system")).principal.user, "S-1-5-18",
            "and it runs as SYSTEM regardless")

        -- The same for a service asked for on demand, so this is not an
        -- accident of the boot plan either.
        vm:run("svctl start pt-bs-ondemand-system")
        local status = vm:run("svctl status pt-bs-ondemand-system").stdout
        t:assert(not status:find("parent_setup_failure", 1, true),
            "an arbitrary on-demand SYSTEM service starts too: " .. status)
    end)

test("a SYSTEM start needs no authority, and every other start needs one",
    {
        spec = {
            "peinit *bootstrap.a-system-identity-does-not-consult-authd",
            "peinit *bootstrap.after-authd-every-token-comes-from-authd",
        },
    },
    function(t)
        -- The bootstrap circle in one experiment. Take the authority out
        -- of reach — by moving its socket rather than stopping it, so
        -- nothing else in the graph is disturbed — and the two routes
        -- come apart: the SYSTEM start still works, because peinit mints
        -- that token itself, and the ordinary one cannot, because its
        -- token was authd's to issue.
        local baseline = vm:run("svctl start pt-bs-ondemand")
        t:assert(not vm:run("svctl status pt-bs-ondemand").stdout
            :find("parent_setup_failure", 1, true),
            "the ordinary service starts while the authority is reachable: "
                .. baseline.stdout)

        vm:run("mv /run/logon.sock /run/pt-logon.hidden"):assert_ok()

        vm:run("svctl start pt-bs-ondemand-system")
        t:assert(not vm:run("svctl status pt-bs-ondemand-system").stdout
            :find("parent_setup_failure", 1, true),
            "a SYSTEM start is unaffected by an unreachable authority")

        vm:run("svctl start pt-bs-ondemand")
        local blocked = vm:run("svctl status pt-bs-ondemand").stdout
        t:assert(blocked:find("parent_setup_failure", 1, true),
            "while the ordinary start fails with nothing to ask: " .. blocked)

        vm:run("mv /run/pt-logon.hidden /run/logon.sock"):assert_ok()
        vm:run("svctl start pt-bs-ondemand")
        t:assert(not vm:run("svctl status pt-bs-ondemand").stdout
            :find("parent_setup_failure", 1, true),
            "and works again once the authority is back")
    end)

test("a definition with no Identity runs as LocalService, on a token the authority issued",
    {
        spec = {
            "peinit *bootstrap.identity-defaults-to-localservice",
            "peinit *bootstrap.authd-adds-the-per-service-sid",
        },
    },
    function(t)
        -- pt-bs-default names no identity, and S-1-5-19 is what it got:
        -- the default is a well-known principal rather than SYSTEM,
        -- which is the difference between a service manager that
        -- escalates by omission and one that does not.
        local theirs = token_of(pid_of("pt-bs-default"))
        t:assert_eq(theirs.principal.user, "S-1-5-19",
            "the default identity is LocalService")

        -- And it came from the authority: Impersonation rather than
        -- Delegation, and a logon session that is not peinit's.
        t:assert_eq(theirs.principal.impersonation_level, "2",
            "the token was attested, not minted")
        t:assert(logon_sid(theirs) ~= logon_sid(token_of(1)),
            "in a session peinit never saw: " .. tostring(logon_sid(theirs)))

        -- The per-service SID is in it all the same. peinit did not put
        -- it there — it did not mint this token — so the only place it
        -- can have come from is authd, computing it from the service
        -- name peinit asked about.
        t:assert(theirs.groups[SID["pt-bs-default"]],
            "the attested token carries pt-bs-default's per-service SID")

        -- A minimal privilege set is the other half of what the
        -- well-known principal is for: a LocalService token is not a
        -- SYSTEM token with a different name on it.
        local count = 0
        for _ in pairs(theirs.privileges) do count = count + 1 end
        local mine = 0
        for _ in pairs(token_of(1).privileges) do mine = mine + 1 end
        t:assert(count < mine,
            "and fewer privileges than peinit's own token (" .. count ..
                " against " .. mine .. ")")
    end)
