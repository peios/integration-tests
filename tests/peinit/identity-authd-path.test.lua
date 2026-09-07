-- Peinit TRM §4.3 — the authd path: every identity that is not SYSTEM
-- gets its token from the authority, because the privilege set and the
-- integrity level an identity carries are policy and policy is authd's.
--
-- The two paths are distinguishable from outside, which is what makes
-- this testable: a token the authority attested sits one rung lower on
-- the impersonation ratchet than one peinit minted, and belongs to a
-- logon session the authority created rather than to peinit's own. So a
-- LocalService daemon and a SYSTEM daemon on the same machine carry
-- visibly different tokens, and the difference is the route.

local peinit = require("helpers.peinit")
peinit.claim(1)

local function resident(name, identity)
    return { path = [[Machine\System\Services\]] .. name, values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "900" } },
        { name = "Type", type = "dword", data = 0 },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "Triggers", type = "multi", data = { "boot" } },
        { name = "Identity", type = "sz", data = identity },
    } }
end

-- Demand-only, so a test can start it at the moment it wants to and read
-- the cause of that one attempt rather than the tail of a restart budget.
local function on_demand(name, identity)
    return { path = [[Machine\System\Services\]] .. name, values = {
        { name = "ImagePath", type = "sz", data = "/bin/true" },
        { name = "Type", type = "dword", data = 1 },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "Identity", type = "sz", data = identity },
    } }
end

local vm = peinit.boot({
    name = "identity-authd-path",
    files = peinit.seed("pt-authd", {
        { path = [[Machine\System]] },
        { path = [[Machine\System\Services]] },
        resident("pt-authd-local", "LocalService"),
        resident("pt-authd-network", "NetworkService"),
        on_demand("pt-authd-ondemand", "LocalService"),
        on_demand("pt-authd-system", "SYSTEM"),
        on_demand("pt-authd-stranger", "pt-nobody"),
    }),
})

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

test("a non-SYSTEM identity is resolved by the authority rather than by peinit",
    { spec = "peinit *token.a-non-system-identity-comes-from-authd" },
    function(t)
        -- peinit knows the string "LocalService" and nothing about what
        -- it means. The token that comes back names S-1-5-19 and sits in
        -- a logon session that is not peinit's — a session peinit did not
        -- create and could not have named.
        local theirs = token_of(pid_of("pt-authd-local"))
        t:assert_eq(theirs.principal.user, "S-1-5-19", "the token is LocalService's")

        local ours = token_of(1)
        t:assert(logon_sid(theirs), "the token names a logon session")
        t:assert(logon_sid(theirs) ~= logon_sid(ours),
            "and it is not peinit's own, so it was not copied from peinit's token: "
                .. tostring(logon_sid(theirs)))
    end)

test("the authority puts the service's own SID into the token it issues",
    { spec = "peinit *token.authd-adds-the-per-service-sid" },
    function(t)
        -- The `service` field of the request is the only way the
        -- authority could know which service this token is for, so a
        -- token carrying the SID derived from that name is evidence the
        -- field travelled and was used.
        local theirs = token_of(pid_of("pt-authd-local"))
        -- Derived by §4.4's rule from "PT-AUTHD-LOCAL".
        local expected = "S-1-5-80-1322559470-233204500-3057515935-1864350087-205673815"
        t:assert(theirs.groups[expected],
            "the attested token carries pt-authd-local's per-service SID")
    end)

test("an attested token stops at Impersonation where a minted one reaches Delegation",
    { spec = "peinit *token.an-attested-token-is-impersonation-not-delegation" },
    function(t)
        -- The evidence behind an attestation is peinit's word, which is
        -- evidence on this machine only, so the token must not be
        -- forwardable off it. The level is the ratchet that says so, and
        -- it is one rung below what a credentialled logon would produce —
        -- which is the level the SYSTEM path mints at, three lines down.
        local attested = token_of(pid_of("pt-authd-local"))
        local minted = token_of(pid_of("registryd"))
        t:assert_eq(attested.principal.impersonation_level, "2",
            "the attested token is Impersonation")
        t:assert_eq(minted.principal.impersonation_level, "3",
            "while a token peinit minted is Delegation")
    end)

test("the platform's own service identities are attestable",
    { spec = "peinit *token.the-platform-service-identities-may-be-attested" },
    function(t)
        -- No principal source holds these and no credential could exist
        -- for them, so the authority accepting them is the whole reason a
        -- service can run as anything other than SYSTEM.
        t:assert_eq(token_of(pid_of("pt-authd-local")).principal.user, "S-1-5-19",
            "LocalService was attested")
        t:assert_eq(token_of(pid_of("pt-authd-network")).principal.user, "S-1-5-20",
            "and so was NetworkService")
    end)

test("a definition naming an ordinary principal does not start",
    { spec = "peinit *token.an-undesignated-principal-is-refused" },
    function(t)
        -- The property the design exists to guarantee: without the
        -- designation the service manager would be an oracle that mints a
        -- credential-free token for anybody on the machine.
        vm:run("svctl start pt-authd-stranger")
        local status = vm:run("svctl status pt-authd-stranger").stdout
        t:assert(status:find("parent_setup_failure", 1, true),
            "the authority refused and the start failed: " .. status)
    end)

test("every service's reported identity is the one its token actually carries",
    { spec = "peinit *token.a-token-contradicting-the-declared-identity-fails-the-launch" },
    function(t)
        -- The rule is stated as a refusal, and the refusal is what makes
        -- the positive observable: where the declared identity predicts a
        -- user SID, a launch only survives if the token agrees. So on a
        -- machine that booted, a service's `identity:` line and its
        -- token's user SID correspond.
        --
        -- Named services rather than everything `svctl list` returns,
        -- because the rule is about the token peinit installs at exec and
        -- a service is free to replace its own afterwards — login-console
        -- does exactly that, and is reported as SYSTEM while its main
        -- process runs on the token of whoever logged in.
        local predicted = {
            SYSTEM = "S-1-5-18",
            LocalService = "S-1-5-19",
            NetworkService = "S-1-5-20",
        }
        local checked = 0
        for _, service in ipairs({ "registryd", "eventd", "netd", "authd",
                                   "resolvd", "pt-authd-local", "pt-authd-network" }) do
            local status = vm:run("svctl status " .. service).stdout
            local identity = status:match("identity: (%S+)")
            local pid = status:match("pid: (%d+)")
            if identity and pid then
                t:assert(predicted[identity],
                    service .. " declares an identity that predicts a SID: " .. identity)
                t:assert_eq(token_of(pid).principal.user, predicted[identity],
                    service .. " is reported as " .. identity ..
                        " and holds that identity's SID")
                checked = checked + 1
            end
        end
        t:assert(checked > 3, "several services were checked, not none (" .. checked .. ")")
    end)

test("an unreachable authority fails every non-SYSTEM start and no SYSTEM one",
    {
        spec = {
            "peinit *token.an-unreachable-authority-fails-the-start",
            "peinit *token.the-request-is-a-serviceattest-on-the-logon-socket",
        },
    },
    function(t)
        local socket = vm:run("stat -c %F /run/logon.sock")
        socket:assert_ok()
        t:assert(socket.stdout:find("socket"),
            "the authority listens on /run/logon.sock: " .. socket.stdout)

        -- A baseline first, so the failure below is attributable to the
        -- socket and not to the definition.
        vm:run("svctl start pt-authd-ondemand"):assert_ok()

        -- Move the socket aside rather than stopping the authority: what
        -- is under test is peinit's behaviour when the request cannot be
        -- delivered, and stopping authd would also take its dependents
        -- with it and start it again by dependency propagation.
        vm:run("mv /run/logon.sock /run/logon.sock.hidden"):assert_ok()

        vm:run("svctl start pt-authd-ondemand")
        local blocked = vm:run("svctl status pt-authd-ondemand").stdout
        t:assert(blocked:find("parent_setup_failure", 1, true),
            "the non-SYSTEM start failed with no authority to ask: " .. blocked)

        -- Platform services never take this route, so nothing about them
        -- changes while the authority is out of reach.
        vm:run("svctl start pt-authd-system")
        local system = vm:run("svctl status pt-authd-system").stdout
        t:assert(not system:find("parent_setup_failure", 1, true),
            "a SYSTEM service started regardless: " .. system)

        vm:run("mv /run/logon.sock.hidden /run/logon.sock"):assert_ok()
        vm:run("svctl start pt-authd-ondemand")
        local restored = vm:run("svctl status pt-authd-ondemand").stdout
        t:assert(not restored:find("parent_setup_failure", 1, true),
            "and it succeeds again once the socket is back: " .. restored)
    end)
