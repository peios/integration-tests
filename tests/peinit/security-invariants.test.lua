-- Peinit TRM §13.4 — two of the invariants: the only policy inputs
-- runtime access control has, and peinit never installing a token on
-- itself.
--
-- An invariant is a claim about the whole running system rather than
-- about one command, so the way to test one is to try to break it. Both
-- tests here are arranged so that the machine's most privileged
-- principal — SYSTEM, the identity PID 1 itself runs as, and the agent
-- with it — is the one being refused. Nothing weaker would say anything:
-- a denial of an unprivileged caller is consistent with a hardcoded
-- allowance for SYSTEM, which is exactly what the fifth invariant says
-- does not exist.

local peinit = require("helpers.peinit")
peinit.claim(2)

-- `O:BG G:BG D:(A;;0x0000000F;;;BG)` as the self-relative bytes a
-- descriptor is stored as (MS-DTYP 2.4.6): a 20-byte header carrying the
-- control word and four offsets, the owner and group SIDs, then a
-- one-ACE DACL. `BG` is BUILTIN\Guests, `S-1-5-32-546` — a principal no
-- token on this machine carries, and in particular not SYSTEM's and not
-- Administrators'.
--
-- Written out rather than built, because a registry value is bytes and
-- nothing in the image converts SDDL to them. The 0x0000000F grants all
-- four service rights, and the same value covers both system rights on
-- the control descriptor, so one blob serves both keys below.
local GUESTS_ONLY = table.concat({
    "01 00 04 80",                                     -- revision, sbz, SELF_RELATIVE|DACL_PRESENT
    "14 00 00 00 24 00 00 00 00 00 00 00 34 00 00 00", -- owner, group, sacl (none), dacl offsets
    "01 02 00 00 00 00 00 05 20 00 00 00 22 02 00 00", -- owner  S-1-5-32-546
    "01 02 00 00 00 00 00 05 20 00 00 00 22 02 00 00", -- group  S-1-5-32-546
    "02 00 20 00 01 00 00 00",                         -- ACL: revision 2, 32 bytes, one ACE
    "00 00 18 00 0f 00 00 00",                         -- ACE: allow, 24 bytes, mask 0x0000000F
    "01 02 00 00 00 00 00 05 20 00 00 00 22 02 00 00", -- ACE trustee S-1-5-32-546
}, " ")

local function service(name, extra)
    local values = {
        { name = "ImagePath", type = "sz", data = "/bin/true" },
        { name = "Type", type = "dword", data = 1 },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
    }
    for _, value in ipairs(extra or {}) do values[#values + 1] = value end
    return { path = [[Machine\System\Services\]] .. name, values = values }
end

-- One boot carrying both descriptors: a service whose ServiceSecurity
-- names only Guests, a sibling with no ServiceSecurity at all, and a
-- ControlSecurity that names only Guests.
local guarded = peinit.boot({
    name = "descriptors",
    files = peinit.seed("pt-inv", {
        { path = [[Machine\System]] },
        { path = [[Machine\System\Init]], values = {
            { name = "ControlSecurity", type = "binary", data = GUESTS_ONLY },
        } },
        { path = [[Machine\System\Services]] },
        service("pt-guarded", {
            { name = "ServiceSecurity", type = "binary", data = GUESTS_ONLY },
        }),
        service("pt-open"),
    }),
})

local vm = peinit.boot({ name = "plain" })

test("a ServiceSecurity descriptor naming nobody the caller is refuses SYSTEM",
    { spec = "peinit *invariant.the-descriptors-are-the-only-policy-inputs" },
    function(t)
        -- The sibling first. Same registry, same boot, same caller,
        -- differing only in carrying no ServiceSecurity value — so it
        -- takes the built-in default, which grants SYSTEM everything.
        local open = guarded:run("svctl status pt-open")
        open:assert_ok()
        t:assert(open.stdout:find("pt-open", 1, true), "the sibling answers: " .. open.stdout)

        -- And the guarded one does not, to the same caller. The message
        -- names the right that was checked, which is how a denial is told
        -- apart from a descriptor peinit could not parse: this went
        -- through AccessCheck and came back refused.
        local status = guarded:run("svctl status pt-guarded")
        t:assert(not status:ok(), "the guarded service refuses a status query")
        t:assert(status.stderr:find("ACCESS_DENIED", 1, true) and
                 status.stderr:find("SERVICE_QUERY_STATUS", 1, true),
            "with ACCESS_DENIED on the right the command needs: " .. status.stderr)

        -- A second right off the same descriptor, so what is being
        -- refused is the principal rather than one command.
        local start = guarded:run("svctl start pt-guarded")
        t:assert(not start:ok() and start.stderr:find("ACCESS_DENIED", 1, true),
            "and starting it: " .. start.stderr)

        -- The filtering half: `list` omits what the caller cannot query
        -- rather than denying the whole call.
        local list = guarded:run("svctl list")
        list:assert_ok()
        t:assert(list.stdout:find("pt%-open"), "the sibling is listed")
        t:assert(not list.stdout:find("pt%-guarded"),
            "the guarded one is not: " .. list.stdout)
    end)

test("the control descriptor is the only input to shutdown and reload-config",
    { spec = "peinit *invariant.the-descriptors-are-the-only-policy-inputs" },
    function(t)
        -- The two operations that are about no one service are checked
        -- against peinit's own descriptor, and this boot's names only
        -- Guests. SYSTEM is refused — there is no principal list behind
        -- the descriptor to fall back on.
        local reload = guarded:run("svctl reload-config")
        t:assert(not reload:ok(), "reload-config is refused")
        t:assert(reload.stderr:find("ACCESS_DENIED", 1, true) and
                 reload.stderr:find("SYSTEM_RELOAD_CONFIG", 1, true),
            "on the system right it needs: " .. reload.stderr)

        -- The connection itself is fine — a per-service command on the
        -- same socket is still answered — so what refused reload-config
        -- is the control descriptor and nothing about the transport.
        guarded:run("svctl status pt-open"):assert_ok()
    end)

test("a submitted job's descriptor refuses its own submitter",
    { spec = "peinit *invariant.the-descriptors-are-the-only-policy-inputs" },
    function(t)
        -- The third kind of descriptor. A submission may supply its own,
        -- and one that names nobody the submitter is locks the submitter
        -- out of its own job — peinit adds no entry of its own and holds
        -- no list of principals that could reach it anyway.
        local sddl = "O:S-1-5-32-546G:S-1-5-32-546D:(A;;0x00000007;;;S-1-5-32-546)"
        local submitted = vm:run(
            "svctl job submit --security-descriptor '" .. sddl .. "' -- /bin/sleep 60")
        submitted:assert_ok()
        local id = submitted.stdout:match("job ([%x%-]+)")
        t:assert(id, "the job was submitted: " .. submitted.stdout)

        -- Submitting is not checked against this descriptor — reaching
        -- the socket was the permission to submit — so the refusal
        -- arrives on the first command that names the job.
        local status = vm:run("svctl job status " .. id)
        t:assert(not status:ok(), "the submitter cannot query its own job")
        t:assert(status.stderr:find("ACCESS_DENIED", 1, true) and
                 status.stderr:find("JOB_QUERY", 1, true),
            "with ACCESS_DENIED on the job right: " .. status.stderr)

        -- A job submitted without a descriptor, in the same connection's
        -- identity, is queryable — the default names the submitter.
        local ordinary = vm:run("svctl job submit -- /bin/sleep 60")
        ordinary:assert_ok()
        local other = ordinary.stdout:match("job ([%x%-]+)")
        vm:run("svctl job status " .. other):assert_ok()

        -- And the guarded job is filtered out of the listing rather than
        -- making the listing fail.
        local list = vm:run("svctl job list")
        list:assert_ok()
        t:assert(list.stdout:find(other, 1, true), "the ordinary job is listed")
        t:assert(not list.stdout:find(id, 1, true),
            "the guarded one is not: " .. list.stdout)

        vm:run("svctl job stop " .. other)
    end)

test("peinit still holds the token the kernel gave it, and none it minted",
    { spec = "peinit *invariant.peinit-never-installs-a-token-on-itself" },
    function(t)
        -- peinit has minted and installed tokens throughout this boot —
        -- every platform service got one — so if it ever installed one on
        -- itself, PID 1's own token would carry the marks peinit puts on
        -- the tokens it builds. Those marks are exact: a minted service
        -- token gains the per-service SID and the Service group
        -- `S-1-5-6` that the template does not carry (§4.2).
        local mine = vm:run("token groups --pid 1")
        mine:assert_ok()
        t:assert(not mine.stdout:find("S%-1%-5%-80%-"),
            "PID 1 carries no per-service SID: " .. mine.stdout)
        t:assert(not mine.stdout:find("S%-1%-5%-6%f[%D]"),
            "and is not in the Service group: " .. mine.stdout)

        -- registryd's token is one peinit built from PID 1's as a
        -- template, and it carries both. Same user SID, different token:
        -- what peinit installs goes on the child.
        local pid = wait_until(function()
            local r = vm:run(
                'for p in /proc/[0-9]*; do ' ..
                '[ "$(cat "$p/comm" 2>/dev/null)" = registryd ] && echo "${p#/proc/}"; done')
            local pid = r.stdout:match("%d+")
            if pid then return pid end
        end, { timeout = 10, desc = "registryd to be running" })
        local theirs = vm:run("token groups --pid " .. pid)
        theirs:assert_ok()
        t:assert(theirs.stdout:find("S%-1%-5%-80%-"),
            "registryd's token carries a per-service SID: " .. theirs.stdout)
        t:assert(theirs.stdout:find("S%-1%-5%-6%f[%D]"),
            "and the Service group: " .. theirs.stdout)
        t:assert(vm:run("token user --pid " .. pid).stdout:find("S-1-5-18", 1, true),
            "while running as the same user SID, which is what makes the group list the "
            .. "thing that tells the two tokens apart")

        -- And PID 1 is still SYSTEM at the end of all of it, which is the
        -- other half: the identity is not dropped either.
        t:assert(vm:run("token user --pid 1").stdout:find("S-1-5-18", 1, true),
            "PID 1 is still SYSTEM")
    end)
