-- Peinit TRM §4.2 — the SYSTEM path: peinit mints the tokens of the
-- platform services itself, because the thing that would otherwise mint
-- them is one of them.
--
-- A minted token and the token it was copied from are both live on a
-- booted machine — peinit's own is PID 1's, and registryd's is the first
-- one it ever made — so the whole of the copy rule can be checked by
-- reading the two and comparing them. That comparison is the only way to
-- see this: nothing is written to the console, and the mint leaves no
-- artefact on disk.

local peinit = require("helpers.peinit")

-- Nothing here changes the boot, so one VM serves every test. Nothing is
-- staged either, which matters: the profile's staging hook perturbs the
-- root's descriptor (see identity-materialisation.test.lua), and a test
-- comparing tokens wants the machine the image really boots.
local vm = peinit.boot({ name = "identity-system-path" })

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
        local status = vm:run("svctl status " .. service).stdout
        local pid = status:match("pid: (%d+)")
        if pid then return pid end
        vm:run("sleep 1")
    end
    error(service .. " never reported a pid")
end

local function count(set)
    local n = 0
    for _ in pairs(set) do n = n + 1 end
    return n
end

test("a minted token carries the identity, integrity and privileges of the one it copied",
    { spec = "peinit *token.minting-copies-peinits-own-token" },
    function(t)
        local mine, theirs = token_of(1), token_of(pid_of("registryd"))

        t:assert_eq(theirs.principal.user, "S-1-5-18", "the minted token is SYSTEM")
        t:assert_eq(theirs.principal.user, mine.principal.user, "the same user SID as the template")
        t:assert_eq(theirs.principal.integrity, mine.principal.integrity,
            "the same integrity level")
        t:assert_eq(theirs.principal.type, "Primary", "and it is a primary token")

        -- registryd declares no RequiredPrivileges, so nothing was
        -- removed after the copy (§4.5) and the privilege set is the
        -- template's exactly — the same names, and the same count.
        t:assert_eq(count(theirs.privileges), count(mine.privileges),
            "the same number of privileges as peinit's own token")
        for name in pairs(mine.privileges) do
            t:assert(theirs.privileges[name], "the minted token also carries " .. name)
        end
    end)

test("peinit's own token is the primary SYSTEM token the mint asserts, and carries the privilege the mint needs",
    {
        spec = {
            "peinit *token.the-mint-requires-secreatetokenprivilege",
            "peinit *token.the-template-must-be-a-primary-system-token",
        },
    },
    function(t)
        local mine = token_of(1)
        t:assert_eq(mine.principal.user, "S-1-5-18", "PID 1 runs as SYSTEM")
        t:assert_eq(mine.principal.type, "Primary", "on a primary token")

        -- Present is not enough: the kernel refuses kacs_create_token with
        -- EPERM unless the privilege is held, and a privilege the token
        -- carries but has not enabled is not held.
        local create = mine.privileges.SeCreateToken
        t:assert(create, "peinit holds SeCreateTokenPrivilege")
        t:assert(create:find("enabled", 1, true),
            "and has it enabled: " .. tostring(create))

        -- The consequence, and the reason the assertion exists: the mint
        -- happened, so registryd is up.
        t:assert(vm:console():read_log():find("peinit: phase1 registryd started", 1, true),
            "a token was minted and the service it was minted for started")
    end)

test("a minted token stays in the logon session peinit was given at boot",
    {
        spec = {
            "peinit *token.the-logon-session-comes-from-the-token-statistics",
            "peinit *token.the-logon-sid-group-is-dropped-from-the-copy",
        },
    },
    function(t)
        -- The logon session shows up as the token's logon-id group. The
        -- claim is that the minted token belongs to the *same* session as
        -- peinit's: taking the auth_id from the statistics rather than
        -- from the interactivity scope or a well-known LUID is what makes
        -- that so, and any of the other two would name a session that
        -- does not exist.
        local function logon_sid(token)
            local found = {}
            for sid, attrs in pairs(token.groups) do
                if attrs:find("logon%-id") then found[#found + 1] = sid end
            end
            return found
        end

        local mine, theirs = logon_sid(token_of(1)), logon_sid(token_of(pid_of("eventd")))
        t:assert_eq(#mine, 1, "peinit's token names one logon session")

        -- Exactly one, not two: peinit filters the template's logon-SID
        -- group out before building, and the kernel re-appends the
        -- session's own. A copy that kept it would either be rejected at
        -- create time or arrive carrying the group twice.
        t:assert_eq(#theirs, 1,
            "the minted token names one logon session, not two: " .. table.concat(theirs, " "))
        t:assert_eq(theirs[1], mine[1],
            "and it is peinit's own session, so the minted token is attached to a real one")
    end)

test("a minted token gains the service's own SID and the Service group",
    { spec = "peinit *token.the-service-sid-and-service-group-are-added" },
    function(t)
        -- Two groups, and only those two: everything else in a minted
        -- token comes from the template.
        local mine, theirs = token_of(1), token_of(pid_of("eventd"))
        local added = {}
        for sid in pairs(theirs.groups) do
            if mine.groups[sid] == nil then added[sid] = true end
        end

        -- eventd's per-service SID, derived by the rule of §4.4 from the
        -- name "eventd".
        local service_sid = "S-1-5-80-1963885778-1835409261-1671587836-2279113866-1994761124"
        t:assert(added[service_sid], "the per-service SID was added")
        t:assert(added["S-1-5-6"], "and so was the Service group")
        t:assert_eq(count(added), 2, "and nothing else was")
    end)

test("restricting a service's privileges leaves peinit's own token untouched",
    { spec = "peinit *token.the-minted-token-is-independent-of-peinits" },
    function(t)
        -- The minted token is a new token rather than a view of peinit's,
        -- so the privilege restriction of §4.5 lands on it alone. A
        -- SYSTEM service asking to keep one privilege out of the thirty-
        -- six peinit holds is the sharpest way to see that: if the two
        -- were the same token, PID 1 would lose thirty-five of its own.
        local other = peinit.boot({
            name = "identity-mint-independent",
            files = peinit.seed("pt-mint", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Services]] },
                { path = [[Machine\System\Services\pt-mint-one-priv]], values = {
                    { name = "ImagePath", type = "sz", data = "/bin/sleep" },
                    { name = "Arguments", type = "multi", data = { "900" } },
                    { name = "Type", type = "dword", data = 0 },
                    { name = "Readiness", type = "dword", data = 1 },
                    { name = "Triggers", type = "multi", data = { "boot" } },
                    { name = "Identity", type = "sz", data = "SYSTEM" },
                    { name = "RequiredPrivileges", type = "multi",
                      data = { "SeChangeNotifyPrivilege" } },
                } },
            }),
        })

        local function privileges(vm_, pid)
            local shown = vm_:run("token privs --pid " .. pid)
            shown:assert_ok()
            local names = {}
            for _, line in ipairs(peinit.lines(shown.stdout)) do
                local name = line:match("^%s+(.-)%s%s+")
                if name then names[name] = true end
            end
            return names
        end

        local pid
        for _ = 1, 40 do
            pid = other:run("svctl status pt-mint-one-priv").stdout:match("pid: (%d+)")
            if pid then break end
            other:run("sleep 1")
        end
        t:assert(pid, "the service is running")

        local theirs = privileges(other, pid)
        t:assert_eq(count(theirs), 1, "the service kept exactly the one privilege it asked for")
        t:assert(theirs.SeChangeNotify, "and it is the one it named")

        local mine = privileges(other, 1)
        t:assert(count(mine) > 30,
            "while peinit still holds its whole set (" .. count(mine) .. ")")
        t:assert(mine.SeCreateToken,
            "including the one it needs to mint the next token")
    end)
