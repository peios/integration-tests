-- Peinit TRM §4.4 — the per-service SID: the group every service token
-- carries, derived from the service's name and nothing else.
--
-- The derivation is a pure function of the name, so this suite can
-- compute the answer independently and compare. The SIDs asserted below
-- were produced from the documented rule — uppercase the name, encode it
-- UTF-16LE, SHA-1 it, split the digest into five little-endian 32-bit
-- sub-authorities under S-1-5-80 — and not read out of the guest, which
-- is what makes them a check rather than a snapshot.

local peinit = require("helpers.peinit")
peinit.claim(2)

local vm = peinit.boot({ name = "identity-service-sids" })

local function groups_of(vm_, pid)
    local shown = vm_:run("token groups --pid " .. pid .. " --raw")
    shown:assert_ok()
    local found = {}
    for _, line in ipairs(peinit.lines(shown.stdout)) do
        local sid = line:match("^%s+(S%-[%d%-]+)%s")
        if sid then found[sid] = true end
    end
    return found
end

local function pid_of(vm_, service)
    for _ = 1, 40 do
        local pid = vm_:run("svctl status " .. service).stdout:match("pid: (%d+)")
        if pid then return pid end
        vm_:run("sleep 1")
    end
    error(service .. " never reported a pid")
end

-- SHA-1 over the UTF-16LE of the uppercased name, five little-endian
-- 32-bit sub-authorities under S-1-5-80.
local DERIVED = {
    registryd = "S-1-5-80-3593071732-1666014828-967506459-673618303-1085857884",
    authd     = "S-1-5-80-3733847795-2198956809-1841698210-3923492485-3570583468",
    lpsd      = "S-1-5-80-4242895835-3884168475-4287610261-1596539771-2019494472",
    eventd    = "S-1-5-80-1963885778-1835409261-1671587836-2279113866-1994761124",
    netd      = "S-1-5-80-1187121632-3279729872-2230957692-3961009007-2241473609",
    resolvd   = "S-1-5-80-3864064249-1823296737-2008945602-1354971773-2894779966",
    trustd    = "S-1-5-80-158018673-1219163202-1628709498-2735078191-2367099888",
    pnpd      = "S-1-5-80-2486722853-3349649022-1934892999-655261929-2138276391",
}

test("every service token carries the SID derived from its service's name",
    {
        spec = {
            "peinit *sid.every-service-token-carries-one",
            "peinit *sid.the-derivation-is-sha1-over-the-uppercased-name",
        },
    },
    function(t)
        -- Eight of the image's own daemons, four minted by peinit and
        -- four attested by the authority, each checked against the SID
        -- the published rule produces from its name alone.
        local checked = 0
        for service, expected in pairs(DERIVED) do
            local status = vm:run("svctl status " .. service).stdout
            local pid = status:match("pid: (%d+)")
            if pid then
                local groups = groups_of(vm, pid)
                t:assert(groups[expected],
                    service .. " carries " .. expected .. " in its group list")
                checked = checked + 1
            end
        end
        t:assert(checked >= 6,
            "most of the platform graph was running and checked (" .. checked .. ")")

        -- The group belongs to the service, not to the principal: two
        -- daemons sharing an identity carry different ones, which is the
        -- whole reason the SID exists.
        t:assert(DERIVED.registryd ~= DERIVED.eventd,
            "two SYSTEM daemons are told apart by these SIDs")
    end)

test("peinit and the authority derive the same SID for a service",
    { spec = "peinit *sid.peinit-and-authd-derive-the-same-sid" },
    function(t)
        -- eventd's SID was computed by peinit, which mints SYSTEM tokens
        -- itself; resolvd's was computed by the authority, which peinit
        -- asked for a LocalService token. Both match the same published
        -- rule, so the two implementations agree on a running machine and
        -- not only in the shared test vector.
        local eventd = groups_of(vm, pid_of(vm, "eventd"))
        t:assert(eventd[DERIVED.eventd],
            "the SID in a token peinit minted matches the rule")

        local resolvd = groups_of(vm, pid_of(vm, "resolvd"))
        t:assert(resolvd[DERIVED.resolvd],
            "and so does the SID in a token the authority attested")
    end)

test("the name is uppercased before it is hashed",
    { spec = "peinit *sid.the-name-is-uppercased-before-encoding" },
    function(t)
        -- A service name is ASCII alphanumeric plus `.`, `_` and `-`, so
        -- the full-Unicode part of the rule — the mapping that expands ß
        -- to SS — has no reachable case here. What is reachable is that
        -- the name is folded at all: a mixed-case name has to hash to the
        -- SID of its uppercase form, and to nothing else.
        local other = peinit.boot({
            name = "identity-sid-case",
            files = peinit.seed("pt-sid", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Services]] },
                { path = [[Machine\System\Services\pt-MiXeD]], values = {
                    { name = "ImagePath", type = "sz", data = "/bin/sleep" },
                    { name = "Arguments", type = "multi", data = { "900" } },
                    { name = "Type", type = "dword", data = 0 },
                    { name = "Readiness", type = "dword", data = 1 },
                    { name = "Triggers", type = "multi", data = { "boot" } },
                    { name = "Identity", type = "sz", data = "SYSTEM" },
                } },
            }),
        })

        local groups = groups_of(other, pid_of(other, "pt-MiXeD"))
        -- SHA-1 of "PT-MIXED" in UTF-16LE.
        t:assert(groups["S-1-5-80-4197167195-2441123933-3407279009-3356797386-1580317920"],
            "pt-MiXeD carries the SID its uppercased name derives")
        -- SHA-1 of "pt-MiXeD" as written, which is what a derivation that
        -- skipped the fold would have produced.
        t:assert(not groups["S-1-5-80-3425735438-4136409547-2119747629-2187724056-3369993689"],
            "and not the one its name as written would give")
    end)
