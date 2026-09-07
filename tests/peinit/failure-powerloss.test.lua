-- peinit TRM §14.5 — power loss and corruption: what peinit writes, and
-- what it does not.
--
-- The section's damaged-file rules are §2.7's and §2.3's, and are tested
-- there. What is stated here is the shape of the three writes, the claim
-- that a service's runtime state is not among them, and the timer
-- timestamp's position in the run — and those are all readable from a
-- booted machine.
--
-- What is *not* reachable is the loss itself. The harness's writes land
-- in the overlay's tmpfs upper, so nothing survives a reboot; a test
-- cannot cut the power, boot again, and ask what came back. The two
-- claims about what re-triggers across a loss are anchored and left
-- untested for that reason, and the timestamp test below proves the half
-- they rest on instead: that the timestamp is written when the run is
-- *initiated*, so a loss during the run finds it already recorded.

local peinit = require("helpers.peinit")
peinit.claim(1)

local SERVICES = {
    { path = [[Machine\System]] },
    { path = [[Machine\System\Services]] },
    { path = [[Machine\System\Services\login-console]], values = {
        { name = "Disabled", type = "dword", data = 1 },
    } },
    -- An ordinary service, run through a full activation, to show its
    -- key is not where peinit keeps what it knows about it.
    { path = [[Machine\System\Services\pt-live]], values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "100000" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "RestartPolicy", type = "dword", data = 0 },
    } },
    -- A persistent timer whose run is long. A trigger with no history
    -- catches up once at boot (§9.3), so this fires as the machine comes
    -- up and then sits in Starting for a minute — which is the window in
    -- which the timestamp is asked for.
    { path = [[Machine\System\Services\pt-timer]], values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "60" } },
        { name = "Type", type = "dword", data = 1 },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Triggers", type = "multi", data = { "timer:*-*-* *:*:00" } },
        { name = "StartTimeout", type = "dword", data = 120 },
    } },
}

local vm = peinit.boot({
    name = "powerloss",
    files = peinit.seed("pt-powerloss", SERVICES),
})

--- The value names on a registry key, from `reg ls`, sorted.
---
--- `reg ls` prints one `Name = value` line per value; only the names
--- matter here, and sorting makes two readings comparable.
local function value_names(key)
    local listing = vm:run("reg ls '" .. key .. "'")
    listing:assert_ok()
    local names = {}
    for _, line in ipairs(peinit.lines(listing.stdout)) do
        local name = line:match("^%s*([%w_%-%.]+)%s*=")
        if name then names[#names + 1] = name end
    end
    table.sort(names)
    return table.concat(names, ",")
end

test("the counter and the machine ID are where and what the table says",
    { spec = "peinit *powerloss.the-three-things-peinit-writes" },
    function(t)
        -- The counter: a plain decimal integer, rewritten each boot, on
        -- the root rather than in the registry — deliberately, because
        -- the registry may be why the boot is failing (§2.7).
        local counter = vm:read_file("/.peinit/boot-attempts")
        t:assert(counter:match("^%s*%d+%s*$"),
            "the boot attempt counter is a plain integer: " .. counter)

        -- The machine ID: the format §2.3 fixes, at the path this table
        -- names. The trailing newline is part of the value rather than
        -- incidental — a file missing it is one peinit replaces.
        local machine_id = vm:read_file("/lcl/etc/machine-id")
        t:assert(machine_id:match("^%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x" ..
            "%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x\n$"),
            "the machine ID is 32 hex digits and a newline: " .. machine_id)
        t:assert(not machine_id:match("%u"),
            "in lower case: " .. machine_id)

        -- The seed's row cannot be checked here: it is written at
        -- shutdown, and a machine that has shut down cannot be read.
        -- Its directory is the part that is on disk while the system
        -- runs.
        t:assert_eq(vm:stat("/var/state").entry_type, "directory",
            "and the random seed's directory is on the root filesystem")
    end)

test("nothing is left behind beside the machine ID for a reader to trip over",
    { spec = "peinit *powerloss.the-seed-and-the-machine-id-are-never-seen-half-written" },
    function(t)
        -- The write goes through a temporary file and a rename, so a
        -- reader sees the old value or the new one. What a test can
        -- check without racing the write is its residue: a rename leaves
        -- nothing behind, and the directory holds exactly the one name.
        local entries = {}
        for _, entry in ipairs(vm:listdir("/lcl/etc")) do
            if entry.name ~= "." and entry.name ~= ".." then
                entries[#entries + 1] = entry.name
            end
        end
        table.sort(entries)
        t:assert_eq(table.concat(entries, ","), "machine-id",
            "no temporary file survived the write")

        -- And what is there is a whole value rather than a prefix of
        -- one, which is the property that matters to a reader.
        t:assert_eq(#vm:read_file("/lcl/etc/machine-id"), 33,
            "the file holds a complete identifier")
    end)

test("a service's runtime state never reaches its registry key",
    { spec = "peinit *powerloss.no-service-state-is-written-to-the-registry" },
    function(t)
        -- The key as the seed wrote it, before peinit has run the
        -- service at all.
        local key = [[Machine\System\Services\pt-live]]
        local seeded = value_names(key)
        t:assert_eq(seeded, "Arguments,Identity,ImagePath,Readiness,RestartPolicy",
            "the key holds the definition the seed wrote: " .. seeded)

        -- A full activation: Inactive to Active and back, with a restart
        -- in between, which is every state a service ordinarily moves
        -- through.
        vm:run("svctl start pt-live"):assert_ok()
        vm:run("svctl restart pt-live"):assert_ok()
        vm:run("svctl stop pt-live"):assert_ok()
        t:assert_eq(json.decode(vm:run("svctl --json status pt-live").stdout).state,
            "inactive", "the service has been run and stopped")

        t:assert_eq(value_names(key), seeded,
            "and the key is exactly what it was: peinit wrote no state to it")
    end)

test("a persistent timer's last run is recorded when the run starts, not when it ends",
    { spec = "peinit *powerloss.the-last-run-timestamp-is-written-when-the-start-is-initiated" },
    function(t)
        -- The boot's catch-up firing starts a service that will sit in
        -- Starting for a minute. If the timestamp were written when the
        -- run completed there would be nothing to read yet.
        local view = wait_until(function()
            local status = json.decode(vm:run("svctl --json status pt-timer").stdout)
            return status.state == "starting" and status.cause == "timer" and status or nil
        end, { timeout = 90, interval = 1, desc = "the timer's run to be under way" })
        t:assert(view.current_job, "the timer's run has a live process")

        local timestamp = vm:run(
            [[reg get 'Machine\System\Services\pt-timer' LastTimerRun]])
        timestamp:assert_ok()
        t:assert(timestamp.stdout:match("%d%d%d%d"),
            "the last-run timestamp is already recorded: " .. timestamp.stdout)

        -- Still running when it was read, so the write really did
        -- precede the end of the run rather than merely racing it.
        t:assert_eq(json.decode(vm:run("svctl --json status pt-timer").stdout).state,
            "starting", "while the run it recorded is still in flight")
    end)
