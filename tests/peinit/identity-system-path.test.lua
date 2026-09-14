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
local token = require("helpers.token")
local kacs = require("helpers.kacs")
local access = require("helpers.access")
local sys = require("helpers.sys")
peinit.claim(2)

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

-- The default DACL is the one field of a minted token the comparisons
-- above cannot reach. `token show` does not print it, and it is not a
-- value the mint copies from the template but one peinit states. So it is
-- read straight off each token handle (KACS_TOKEN_CLASS_DEFAULT_DACL) and
-- rendered in the TRM's own SDDL, so that a failure reads against the
-- sentence it breaks.
local SYSTEM_DEFAULT_DACL = "D:(A;;GA;;;SY)(A;;GA;;;BA)"
local SID_ALIAS = { ["S-1-5-18"] = "SY", ["S-1-5-32-544"] = "BA" }
local GENERIC_ALL, FILE_ALL_ACCESS = 0x10000000, 0x001F01FF

--- SDDL for a parsed ACL (helpers.access.parse_acl), or `none` when
--- there is no ACL at all.
local function sddl(acl, none)
    if acl == nil then return none end
    local out = { "D:" }
    for _, ace in ipairs(acl.aces) do
        local sid = token.sid_string(ace.sid)
        local mask = ace.mask == GENERIC_ALL and "GA"
            or ace.mask == FILE_ALL_ACCESS and "FA"
            or ("0x%08x"):format(ace.mask)
        out[#out + 1] = ("(%s;%s;%s;;;%s)"):format(
            ace.type == access.ACE.ALLOWED and "A" or ("0x%02x"):format(ace.type),
            ace.flags == 0 and "" or ("0x%02x"):format(ace.flags),
            mask, SID_ALIAS[sid] or sid)
    end
    return table.concat(out)
end

--- The default DACL on `pid`'s primary token in SDDL ("(none)" when the
--- token has none), and the token's user SID. Returns nil and a reason
--- when the process has gone.
local function default_dacl_of(pid)
    local pidfd, err = token.pidfd_open(vm, tonumber(pid))
    if not pidfd then return nil, "pidfd_open: " .. sys.errname(err or 0) end
    local fd, err2 = token.open_process(vm, pidfd, token.RIGHT.QUERY)
    sys.close(vm, pidfd)
    if not fd then return nil, "open its token: " .. sys.errname(err2 or 0) end
    local user = token.query(vm, fd, token.CLASS.USER)
    local dacl, err3 = token.query(vm, fd, token.CLASS.DEFAULT_DACL)
    sys.close(vm, fd)
    if not dacl then return nil, "query its default DACL: " .. sys.errname(err3 or 0) end
    -- An absent default DACL is zero bytes, not an empty ACL (PKM §3.D).
    return sddl(dacl ~= "" and access.parse_acl(dacl) or nil, "(none)"),
        user and token.sid_string(user)
end

test("every SYSTEM token peinit mints carries SYSTEM and Administrators full control as its default DACL",
    {
        spec = "peinit *token.the-minted-token-carries-the-system-default-dacl",
        -- PEI-194 item 1. The fix is peinit db515f5 ("set a default DACL
        -- on every minted SYSTEM token", src/boundary/linux_launch/
        -- system_token.rs). Red against 0.0.2-1, where every minted
        -- SYSTEM token had no default DACL at all; green since 0.0.5-2.
    },
    function(t)
        -- The four the bootstrap circle is about must be up and among the
        -- tokens read, so that an empty sweep cannot pass.
        local required = { "registryd", "lpsd", "authd", "eventd" }
        for _, name in ipairs(required) do pid_of(name) end

        -- Every service running on a SYSTEM token rather than a sample:
        -- the claim is "every", and a mint that took some other path
        -- would show up here as the odd one out. A service on another
        -- identity came from authd and is not this sentence's business.
        local read, wrong = {}, {}
        for name in vm:run("svctl --json list").stdout:gmatch('"service":"([^"]+)"') do
            local pid = vm:run("svctl status " .. name).stdout:match("pid: (%d+)")
            if pid then
                local dacl, user = default_dacl_of(pid)
                if dacl and user == "S-1-5-18" then
                    read[name] = true
                    if dacl ~= SYSTEM_DEFAULT_DACL then wrong[#wrong + 1] = name .. " " .. dacl end
                end
            end
        end
        for _, name in ipairs(required) do
            t:assert(read[name], name .. "'s minted SYSTEM token was read")
        end

        -- peinit's own token, for the message: the bootstrap token the TRM
        -- says the value is restated from. What that token carries is not
        -- itself this sentence's claim, so nothing is asserted on it.
        table.sort(wrong)
        t:assert_eq(#wrong, 0,
            "every minted SYSTEM token carries " .. SYSTEM_DEFAULT_DACL ..
            " (peinit's own token carries " .. tostring((default_dacl_of(1))) ..
            "); these do not: " .. table.concat(wrong, ", "))
    end)

test("an object a SYSTEM service creates with nothing to inherit from gets that DACL, not a null one",
    {
        spec = "peinit *token.the-minted-token-carries-the-system-default-dacl",
        -- PEI-194 item 1, as above: fixed in peinit db515f5, green since
        -- 0.0.5-2.
    },
    function(t)
        -- What the default DACL is for. A container written without
        -- inheritable ACEs (SYSTEM may add to it, nothing flows down),
        -- and protected, so that /run's own inheritable ACEs are not
        -- merged back in. Anything created in it has no parent to inherit
        -- from, which is the case the TRM names.
        local DIR = "/run/pt-default-dacl"
        local made = sys.mkdir(vm, DIR)
        t:assert_eq(made.ret, 0, "the container is made: " .. sys.errname(made.errno or 0))
        local container = access.sd({
            dacl = access.acl({
                access.ace(access.ACE.ALLOWED, FILE_ALL_ACCESS, token.SID.LOCAL_SYSTEM, 0) }),
            control = access.CONTROL.DACL_PROTECTED,
        })
        local set = kacs.set_sd(vm, DIR, container, kacs.SI.DACL)
        t:assert_eq(set.ret, 0, "and its DACL written: " .. sys.errname(set.errno or 0))
        local written = access.parse_sd(assert(kacs.get_sd(vm, DIR, kacs.SI.DACL)))
        local INHERITABLE = access.ACE_FLAG.OBJECT_INHERIT | access.ACE_FLAG.CONTAINER_INHERIT
        for _, ace in ipairs(written.dacl and written.dacl.aces or {}) do
            t:assert_eq(ace.flags & INHERITABLE, 0,
                "nothing on the container is inheritable: " .. sddl(written.dacl, "a null DACL"))
        end

        --- An object's DACL in SDDL, or "a null DACL".
        local function dacl_of(path)
            local bytes, err = kacs.get_sd(vm, path, kacs.SI.DACL)
            assert(bytes, "read the descriptor of " .. path .. ": " .. sys.errname(err or 0))
            return sddl(access.parse_sd(bytes).dacl, "a null DACL")
        end

        -- The control. The agent runs on peinit's own token, the bootstrap
        -- SYSTEM token, so a file it creates here shows what the fallback
        -- does with a token that has the value, and that this container
        -- really does leave the DACL to the fallback.
        local fd, err = sys.open(vm, DIR .. "/by-bootstrap", sys.O.WRONLY | sys.O.CREAT,
            tonumber("644", 8))
        t:assert(fd, "the agent creates a file in the container: " .. sys.errname(err or 0))
        sys.close(vm, fd)
        local bootstrap = dacl_of(DIR .. "/by-bootstrap")

        -- The subject: a SYSTEM service peinit starts on a token it mints
        -- for it. Defined at runtime rather than seeded, so that this file
        -- keeps booting the image unstaged; the registry watch loads it.
        local SERVICE = "pt-default-dacl"
        vm:write_file("/tmp/pt-default-dacl.json", peinit.encode_json({ keys = {
            { path = [[Machine\System\Services\]] .. SERVICE, values = {
                { name = "ImagePath", type = "sz", data = "/bin/sh" },
                { name = "Arguments", type = "multi",
                  data = { "-c", "echo x > " .. DIR .. "/by-service" } },
                { name = "Type", type = "dword", data = 1 },
                { name = "Identity", type = "sz", data = "SYSTEM" },
                { name = "Readiness", type = "dword", data = 1 },
                { name = "RestartPolicy", type = "dword", data = 0 },
            } },
        } }))
        vm:run("reg apply /tmp/pt-default-dacl.json"):assert_ok()
        wait_until(function()
            return not vm:run("svctl --json status " .. SERVICE).stdout
                :find("UNKNOWN_SERVICE", 1, true) or nil
        end, { timeout = 30, interval = 0.5, desc = SERVICE .. "'s definition to be loaded" })
        vm:run("svctl --json start " .. SERVICE, { timeout = 60 }):assert_ok()
        wait_until(function() return (kacs.get_sd(vm, DIR .. "/by-service", kacs.SI.DACL)) end,
            { timeout = 30, interval = 0.5, desc = "the service to create its file" })
        local theirs = dacl_of(DIR .. "/by-service")

        t:assert(theirs ~= "a null DACL",
            "the service's object got a DACL from its token, not a null DACL that grants " ..
            "everyone everything: " .. theirs)
        -- Full control either way KACS stores it: GA as the token states
        -- it, or FA should the kernel map generic rights at creation.
        t:assert(theirs == SYSTEM_DEFAULT_DACL or theirs == "D:(A;;FA;;;SY)(A;;FA;;;BA)",
            "and it is SYSTEM and Administrators full control, and nobody else: " .. theirs)
        t:assert_eq(theirs, bootstrap,
            "the same DACL an object gets in the same place from peinit's own token")
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
