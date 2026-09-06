-- Peinit TRM §4.5 — privilege restriction: `RequiredPrivileges` names
-- what a service keeps, and peinit removes everything else from the
-- token before exec.
--
-- The rule is subtractive in both directions, and both are visible on a
-- running process. What was removed is visible because the token peinit
-- copied or was handed is itself readable — peinit's own for a SYSTEM
-- service, and a sibling declaring no `RequiredPrivileges` for an
-- attested one — so a test can say what the source held and what
-- survived. What was *not* added is visible because a service may name a
-- privilege its source never granted, and still not have it.

local peinit = require("helpers.peinit")

local function resident(name, identity, required)
    local values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "900" } },
        { name = "Type", type = "dword", data = 0 },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "Triggers", type = "multi", data = { "boot" } },
        { name = "Identity", type = "sz", data = identity },
    }
    if required then
        values[#values + 1] =
            { name = "RequiredPrivileges", type = "multi", data = required }
    end
    return { path = [[Machine\System\Services\]] .. name, values = values }
end

-- Demand-only, so the cause `svctl status` reports is the one attempt
-- the test made rather than the tail of an exhausted restart budget.
local function on_demand(name, identity, required)
    local values = {
        { name = "ImagePath", type = "sz", data = "/bin/true" },
        { name = "Type", type = "dword", data = 1 },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "Identity", type = "sz", data = identity },
        { name = "RequiredPrivileges", type = "multi", data = required },
    }
    return { path = [[Machine\System\Services\]] .. name, values = values }
end

local vm = peinit.boot({
    name = "identity-privileges",
    files = peinit.seed("pt-priv", {
        { path = [[Machine\System]] },
        { path = [[Machine\System\Services]] },
        -- SYSTEM, so the source token is peinit's own and this test can
        -- read the before as well as the after.
        resident("pt-priv-one", "SYSTEM", { "SeChangeNotifyPrivilege" }),
        resident("pt-priv-open", "SYSTEM"),
        -- LocalService, so the source is whatever the authority grants;
        -- pt-priv-plain is the control that shows what that is.
        resident("pt-priv-plain", "LocalService"),
        resident("pt-priv-asks", "LocalService",
            { "SeTcbPrivilege", "SeChangeNotifyPrivilege" }),
        -- Names the published table does not match.
        on_demand("pt-priv-wrongcase", "SYSTEM", { "SeTCBPrivilege" }),
        on_demand("pt-priv-takeowner", "SYSTEM", { "SeTakeOwnershipPrivilege" }),
        on_demand("pt-priv-relabel", "SYSTEM", { "SeRelabelPrivilege" }),
    }),
})

-- The privilege rows of `token privs`, as name -> attribute string.
local function privileges_of(pid)
    local shown = vm:run("token privs --pid " .. pid)
    shown:assert_ok()
    local found = {}
    for _, line in ipairs(peinit.lines(shown.stdout)) do
        local name, attrs = line:match("^%s+(.-)%s%s+(.*)$")
        if name then found[name] = attrs end
    end
    return found
end

local function pid_of(service)
    for _ = 1, 40 do
        local pid = vm:run("svctl status " .. service).stdout:match("pid: (%d+)")
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

test("a service keeps the privileges it named and nothing else",
    { spec = "peinit *priv.everything-outside-requiredprivileges-is-removed" },
    function(t)
        -- pt-priv-one is SYSTEM, so its token began as a copy of
        -- peinit's; PID 1 is that copy's source and is still readable.
        local source = privileges_of(1)
        local kept = privileges_of(pid_of("pt-priv-one"))

        t:assert(count(source) > 30,
            "the source token carries a large set (" .. count(source) .. ")")
        t:assert_eq(count(kept), 1, "and the service ended up with one privilege")
        t:assert(kept.SeChangeNotify, "the one it named")
    end)

test("naming a privilege the source token does not carry does not grant it",
    { spec = "peinit *priv.peinit-never-adds-a-privilege" },
    function(t)
        -- pt-priv-asks declares LocalService and asks to keep
        -- SeTcbPrivilege. The authority does not put SeTcb in a
        -- LocalService token — pt-priv-plain, same identity and no
        -- `RequiredPrivileges`, shows what it does put there — so the
        -- request is one peinit could only satisfy by adding, and it
        -- does not add.
        local source = privileges_of(pid_of("pt-priv-plain"))
        t:assert(not source.SeTcb,
            "the identity's own token carries no SeTcbPrivilege")

        local asked = privileges_of(pid_of("pt-priv-asks"))
        t:assert(not asked.SeTcb,
            "and naming it in RequiredPrivileges did not produce one")
        t:assert(asked.SeChangeNotify,
            "while the privilege the source did carry was kept")
    end)

test("a removed privilege is gone from the token entirely",
    { spec = "peinit *priv.a-removal-is-total-and-irreversible" },
    function(t)
        -- `token privs` lists a token's *present* privileges with their
        -- enabled and default attributes. A privilege removed by peinit
        -- does not appear at all: present, enabled and enabled-by-default
        -- were cleared together, so there is no row left to carry a
        -- residual attribute.
        local source = privileges_of(1)
        local kept = privileges_of(pid_of("pt-priv-one"))
        for _, name in ipairs({ "SeCreateToken", "SeTcb", "SeBackup", "SeRestore",
                                "SeDebug", "SeShutdown" }) do
            t:assert(source[name], "peinit's own token carries " .. name)
            t:assert(kept[name] == nil,
                name .. " left no trace in the restricted token: " .. tostring(kept[name]))
        end
    end)

test("a privilege that survives keeps the enable state its source gave it",
    { spec = "peinit *priv.survivors-keep-their-source-enable-state" },
    function(t)
        -- peinit does not enable, disable or re-order anything; enable
        -- policy belongs to whoever minted the token. So the surviving
        -- row is the source's row, attributes and all.
        local source = privileges_of(1)
        local kept = privileges_of(pid_of("pt-priv-one"))

        local function state(attrs)
            -- `used` is a running tally of what the process has exercised
            -- and says nothing about what it was given.
            local flags = {}
            for flag in attrs:gmatch("[%w-]+") do
                if flag ~= "used" then flags[#flags + 1] = flag end
            end
            table.sort(flags)
            return table.concat(flags, ",")
        end

        t:assert_eq(state(kept.SeChangeNotify), state(source.SeChangeNotify),
            "SeChangeNotify arrived enabled and by default, exactly as in the source")
    end)

test("a privilege this build has no name for is stripped along with the rest",
    { spec = "peinit *priv.privileges-this-build-cannot-name-are-stripped-too" },
    function(t)
        -- peinit iterates all sixty-four bits rather than the ones it has
        -- names for. peinit's own token happens to carry several bits the
        -- privilege table cannot name — `token` renders them as
        -- `<privilege bit N>` — which makes the claim checkable: after a
        -- restriction naming one privilege, none of them is left.
        local source = privileges_of(1)
        local unnamed = 0
        for name in pairs(source) do
            if name:find("^<privilege bit") then unnamed = unnamed + 1 end
        end
        t:assert(unnamed > 0,
            "the source token carries bits the table cannot name (" .. unnamed .. ")")

        for name in pairs(privileges_of(pid_of("pt-priv-one"))) do
            t:assert(not name:find("^<privilege bit"),
                "the restricted token kept no unnameable bit, found " .. name)
        end
    end)

test("a definition with no RequiredPrivileges is left with its source's set",
    { spec = "peinit *priv.an-absent-list-leaves-the-token-untouched" },
    function(t)
        -- peinit does not query or adjust the token at all in this case,
        -- so a SYSTEM service without the field ends up with exactly
        -- peinit's own privilege set — every name, and no others.
        local source = privileges_of(1)
        local open = privileges_of(pid_of("pt-priv-open"))

        t:assert_eq(count(open), count(source), "the same number of privileges")
        for name in pairs(source) do
            t:assert(open[name], "the service also carries " .. name)
        end
    end)

test("a privilege name that does not match the table exactly fails the start",
    { spec = "peinit *priv.an-unmatched-privilege-name-fails-the-start" },
    function(t)
        -- Matched case-sensitively: `SeTCBPrivilege` is a real privilege
        -- misspelt, and the answer is to fail rather than to ignore the
        -- entry — ignoring it would silently leave the privilege in place
        -- while the definition believed it had asked for a restriction.
        vm:run("svctl start pt-priv-wrongcase")
        local status = vm:run("svctl status pt-priv-wrongcase").stdout
        t:assert(status:find("parent_setup_failure", 1, true),
            "the start failed in token materialisation: " .. status)
    end)

test("the two privileges the published table omits cannot be named at all",
    { spec = "peinit *priv.takeownership-and-relabel-cannot-be-named" },
    function(t)
        -- KACS enforces both, and neither is in the table peinit matches
        -- names against, so a definition that names one is a definition
        -- that does not start. A service needing either declares nothing
        -- and takes its source token's defaults instead.
        for _, service in ipairs({ "pt-priv-takeowner", "pt-priv-relabel" }) do
            vm:run("svctl start " .. service)
            local status = vm:run("svctl status " .. service).stdout
            t:assert(status:find("parent_setup_failure", 1, true),
                service .. " could not name it: " .. status)
        end
    end)
