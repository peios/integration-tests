-- peinit TRM §3.3 — field formats, from the running side.
--
-- `model-decode` owns which values are refused when the definition is
-- read. What is left here is what an accepted value then does: which
-- principal an empty `Identity` resolves to, whether a privilege name
-- that differs only in case still works, what `/run` looks like after a
-- service with `RuntimeDirectories` has started and stopped, and
-- whether a timeout written as `3` is three seconds.
--
-- Several subjects are demand-only, with no trigger at all, because
-- what is being measured is a start: the test starts them itself so it
-- knows when the clock began and can arrange the world beforehand.
-- `pt-rt-blocked` is the clearest of those -- the file that makes its
-- runtime directory impossible to create is put there by the test, a
-- moment before the start it breaks.

local peinit = require("helpers.peinit")
peinit.claim(1)

local FILES = {}

--- The identity probe, as a command string rather than a staged script.
---
--- A staged file is copied into the root with a descriptor granting
--- SYSTEM alone (`O:SY G:BA D:AI(A;CIOIID;FA;;;SY)`), so a service
--- running as LocalService cannot read one -- it crashes in the shell
--- before it can record anything, and a probe that cannot write its
--- answer is indistinguishable from one that never ran. `sh -c` with
--- the work inline reads nothing but `/bin/sh` and `/bin/token`, which
--- every identity can.
---
--- The answer goes into the service's own `RuntimeDirectories` entry,
--- which is created with a descriptor granting the service's own SID
--- full access -- the one place under /run a non-SYSTEM service can
--- write.
local function record_identity(label)
    return "/bin/token user > /run/" .. label .. "/id"
end

--- The same probe for a *hook* rather than a main process.
---
--- A hook cannot write into the service's `RuntimeDirectories`: §3.2
--- says those are created before the main process, and a pre-exec hook
--- runs before that — so the directory does not exist yet and the
--- redirect fails silently, leaving the test waiting for a file nothing
--- was ever going to write. It writes straight into /run instead, which
--- the identity under test can reach.
local function record_hook_identity(label)
    return "/bin/token user > /run/" .. label .. ".hookid"
end

local SERVICES = {
    { path = [[Machine\System]] },
    { path = [[Machine\System\Services]] },
}

local function service(name, values)
    SERVICES[#SERVICES + 1] =
        { path = [[Machine\System\Services\]] .. name, values = values }
end

--- A boot-triggered Oneshot that records the identity it ran as.
local function who(name, extra)
    local values = {
        { name = "ImagePath", type = "sz", data = "/bin/sh" },
        { name = "Arguments", type = "multi", data = { "-c", record_identity(name) } },
        { name = "Type", type = "dword", data = 1 },
        { name = "RemainAfterExit", type = "dword", data = 1 },
        { name = "Triggers", type = "multi", data = { "boot" } },
        { name = "RuntimeDirectories", type = "multi", data = { name } },
    }
    for _, value in ipairs(extra) do
        local replaced = false
        for i, existing in ipairs(values) do
            if existing.name:lower() == value.name:lower() then
                values[i] = value
                replaced = true
                break
            end
        end
        if not replaced then values[#values + 1] = value end
    end
    service(name, values)
end

-- An empty Identity is an absent one, so the schema default applies.
who("pt-id-empty", { { name = "Identity", type = "sz", data = "" } })
-- A well-known name in a case nobody would write it in.
who("pt-id-case", { { name = "Identity", type = "sz", data = "sYsTeM" } })
-- An empty HookIdentity falls back to the service's own Identity, which
-- here is deliberately not the default -- so "fell back" and "took the
-- default" are different answers.
service("pt-hookid-empty", {
    { name = "ImagePath", type = "sz", data = "/bin/true" },
    { name = "Identity", type = "sz", data = "SYSTEM" },
    { name = "HookIdentity", type = "sz", data = "" },
    { name = "Type", type = "dword", data = 1 },
    { name = "RemainAfterExit", type = "dword", data = 1 },
    { name = "Triggers", type = "multi", data = { "boot" } },
    { name = "RuntimeDirectories", type = "multi", data = { "pt-hookid-empty" } },
    { name = "ExecStartPre", type = "multi",
      data = { [[/bin/sh -c "]] .. record_hook_identity("pt-hookid-empty") .. [["]] } },
})

-- Privilege names, spelled correctly and spelled with the wrong case.
-- Everything else about the two is identical.
local function priv(name, privilege)
    service(name, {
        { name = "ImagePath", type = "sz", data = "/bin/true" },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Type", type = "dword", data = 1 },
        { name = "RemainAfterExit", type = "dword", data = 1 },
        { name = "Triggers", type = "multi", data = { "boot" } },
        { name = "RestartPolicy", type = "dword", data = 0 },
        { name = "RequiredPrivileges", type = "multi", data = { privilege } },
    })
end
priv("pt-priv-exact", "SeTcbPrivilege")
priv("pt-priv-case", "SeTCBPrivilege")

-- Runtime directories, on a daemon that can be stopped and started.
service("pt-rt", {
    { name = "ImagePath", type = "sz", data = "/bin/sleep" },
    { name = "Arguments", type = "multi", data = { "100000" } },
    { name = "Identity", type = "sz", data = "SYSTEM" },
    { name = "Readiness", type = "dword", data = 1 },
    { name = "Triggers", type = "multi", data = { "boot" } },
    { name = "RestartPolicy", type = "dword", data = 0 },
    -- A dot inside a name is legal, and is the case the rule is most
    -- easily got wrong on.
    { name = "RuntimeDirectories", type = "multi", data = { "pt-rt", "pt-rt.sock.d" } },
    -- A reload command, so that a hook process can be made to run
    -- without a start happening.
    { name = "ExecReload", type = "sz", data = "/bin/true" },
})

-- Demand-only subjects: the test arranges the world and then starts them.
service("pt-rt-blocked", {
    { name = "ImagePath", type = "sz", data = "/bin/true" },
    { name = "Identity", type = "sz", data = "SYSTEM" },
    { name = "Type", type = "dword", data = 1 },
    { name = "RestartPolicy", type = "dword", data = 0 },
    { name = "RuntimeDirectories", type = "multi", data = { "pt-rt-blocked" } },
})
service("pt-wd-missing", {
    { name = "ImagePath", type = "sz", data = "/bin/true" },
    { name = "Identity", type = "sz", data = "SYSTEM" },
    { name = "Type", type = "dword", data = 1 },
    { name = "RestartPolicy", type = "dword", data = 0 },
    { name = "WorkingDirectory", type = "sz", data = "/pt-no-such-directory" },
})
service("pt-secs", {
    { name = "ImagePath", type = "sz", data = "/bin/sleep" },
    { name = "Arguments", type = "multi", data = { "300" } },
    { name = "Identity", type = "sz", data = "SYSTEM" },
    { name = "Type", type = "dword", data = 1 },
    { name = "RestartPolicy", type = "dword", data = 0 },
    { name = "StartTimeout", type = "dword", data = 3 },
})
service("pt-ids", {
    { name = "ImagePath", type = "sz", data = "/bin/true" },
    { name = "Identity", type = "sz", data = "SYSTEM" },
    { name = "Type", type = "dword", data = 1 },
    { name = "RestartPolicy", type = "dword", data = 0 },
})

local vm = peinit.boot({
    name = "formats",
    files = peinit.merge(FILES, peinit.seed("pt-formats", SERVICES)),
})

local function status(service_name)
    local r = vm:run("svctl --json status " .. service_name)
    if r.stdout:find("UNKNOWN_SERVICE", 1, true) then return nil end
    local ok, decoded = pcall(json.decode, r.stdout)
    return ok and decoded or nil
end

local function settled(service_name, timeout)
    return wait_until(function()
        local st = status(service_name)
        if not st then return nil end
        if st.state == "starting" or st.state == "inactive" then return nil end
        return st
    end, {
        -- Generous: several agents share this host, so a boot and the
        -- starts behind it can take much longer than they do alone.
        timeout = timeout or 150, interval = 0.4,
        desc = service_name .. " to settle",
    })
end

--- What the identity probe recorded for `label`.
local function ran_as(label)
    return wait_until(function()
        local ok, text = pcall(function()
            return vm:read_file("/run/" .. label .. "/id")
        end)
        return ok and text ~= "" and text or nil
    end, { timeout = 150, interval = 0.4, desc = label .. " to record its identity" })
end

--- What a hook's identity probe recorded for `label`.
local function hook_ran_as(label)
    return wait_until(function()
        local ok, text = pcall(function()
            return vm:read_file("/run/" .. label .. ".hookid")
        end)
        return ok and text ~= "" and text or nil
    end, { timeout = 150, interval = 0.4,
           desc = label .. "'s hook to record its identity" })
end

local function is_system(text)
    return text:find("SYSTEM") ~= nil or text:find("System") ~= nil
        or text:find("S%-1%-5%-18") ~= nil
end

local function is_local_service(text)
    -- `token user` prints the display name, which is spelled with a
    -- space, so the SID is the reliable half of this.
    return text:find("Local Service") ~= nil or text:find("LocalService") ~= nil
        or text:find("S%-1%-5%-19") ~= nil
end

test("an empty Identity is an absent one, and an empty HookIdentity falls back to Identity",
    { spec = "peinit *fmt.three-fields-treat-the-empty-string-as-absence" },
    function(t)
        -- The behavioural half of §3.3's exception list. `model-decode`
        -- shows that these values are accepted; this is what they mean
        -- once they are.
        local empty = ran_as("pt-id-empty")
        t:assert(is_local_service(empty),
            "an empty Identity took the schema default of LocalService: " .. empty)
        t:assert(not is_system(empty), "and not anything else: " .. empty)

        -- The hook's fallback is to the service's Identity rather than
        -- to the default, which is why pt-hookid-empty's Identity is
        -- SYSTEM: LocalService would have been the same answer either
        -- way and would have proved nothing.
        local hook = hook_ran_as("pt-hookid-empty")
        t:assert(is_system(hook),
            "an empty HookIdentity fell back to the service's own Identity " ..
            "rather than to the default: " .. hook)
    end)

test("a well-known identity name is matched case-insensitively",
    { spec = "peinit *fmt.a-well-known-identity-is-matched-case-insensitively" },
    function(t)
        -- `sYsTeM` is not a spelling anything else in the system uses,
        -- so a service that ran as SYSTEM did so because the name was
        -- matched without regard to case and canonicalised.
        local cased = ran_as("pt-id-case")
        t:assert(is_system(cased),
            "`sYsTeM` resolved to SYSTEM: " .. cased)
    end)

test("privilege names are matched case-sensitively",
    { spec = "peinit *fmt.privilege-names-are-matched-case-sensitively" },
    function(t)
        -- Two definitions that differ in two letters. The published
        -- table spells it `SeTcbPrivilege`, and nothing normalises the
        -- name on the way in, so the other spelling matches nothing and
        -- fails token materialisation -- and therefore the start.
        local exact = settled("pt-priv-exact")
        t:assert_eq(exact.state, "completed",
            "the exactly-spelled privilege name started the service: " ..
            tostring(exact.state) .. "/" .. tostring(exact.cause))

        local cased = settled("pt-priv-case")
        t:assert_eq(cased.state, "failed",
            "and `SeTCBPrivilege` did not: " .. tostring(cased.state))
    end)

test("runtime directories are created under /run before the main process, and are not removed when it stops",
    {
        spec = {
            "peinit *fmt.a-runtime-directory-entry-is-one-relative-name",
            "peinit *fmt.runtime-directories-are-not-removed-when-a-service-stops",
        },
    },
    function(t)
        local st = settled("pt-rt")
        t:assert_eq(st.state, "active", "the service started")

        -- Both entries became directories directly under /run,
        -- including the one with dots in its name.
        for _, name in ipairs({ "pt-rt", "pt-rt.sock.d" }) do
            t:assert_eq(vm:run("test -d /run/" .. name).exit_code, 0,
                "/run/" .. name .. " was created")
        end

        -- Stopping the service leaves them: `/run` is boot-scoped and
        -- the next boot is what clears it, so peinit does not.
        vm:run("svctl --json stop pt-rt"):assert_ok()
        wait_until(function()
            local s = status("pt-rt")
            return s and s.state == "inactive" and s or nil
        end, { timeout = 60, interval = 0.4, desc = "pt-rt to stop" })
        for _, name in ipairs({ "pt-rt", "pt-rt.sock.d" }) do
            t:assert_eq(vm:run("test -d /run/" .. name).exit_code, 0,
                "/run/" .. name .. " is still there after the service stopped")
        end
    end)

test("a hook process does not cause runtime directories to be provisioned",
    { spec = "peinit *fmt.hooks-do-not-cause-runtime-directory-provisioning" },
    function(t)
        -- The directories belong to the main start. A hook is a process
        -- peinit launches with the service's environment and identity
        -- rules, and launching one is not a start -- so if a runtime
        -- directory is removed from under a running service, running a
        -- hook does not put it back.
        --
        -- `ExecReload` is the hook that can be made to run on demand,
        -- without a start happening alongside it to muddy the answer.
        vm:run("svctl --json start pt-rt"):assert_ok()
        wait_until(function()
            local s = status("pt-rt")
            return s and s.state == "active" and s or nil
        end, { timeout = 60, interval = 0.4, desc = "pt-rt to start again" })
        t:assert_eq(vm:run("test -d /run/pt-rt").exit_code, 0,
            "the start provisioned the directory")

        vm:run("rmdir /run/pt-rt"):assert_ok()
        t:assert(vm:run("test -e /run/pt-rt").exit_code ~= 0, "and it is gone")

        vm:run("svctl --json reload pt-rt --no-wait"):assert_ok()
        -- Give the reload hook time to be launched and reaped. There is
        -- nothing to wait *for* here -- the assertion is an absence --
        -- so the wait is a fixed one.
        vm:run("sleep 3")
        t:assert(vm:run("test -e /run/pt-rt").exit_code ~= 0,
            "running a hook did not provision it: only a start does")
    end)

test("a runtime directory that cannot be created fails the start with ParentSetupFailure",
    { spec = "peinit *fmt.a-failed-runtime-directory-is-a-parent-setup-failure" },
    function(t)
        -- A regular file where the directory has to go. The service is
        -- demand-only, so the file is put there first and the start that
        -- trips over it is the next thing that happens.
        vm:run("echo blocked > /run/pt-rt-blocked"):assert_ok()
        t:assert_eq(vm:run("test -f /run/pt-rt-blocked").exit_code, 0,
            "a regular file is in the way")

        vm:run("svctl --json start pt-rt-blocked --no-wait")
        local st = settled("pt-rt-blocked")
        t:assert_eq(st.state, "failed", "the start failed")
        t:assert_eq(st.cause, "parent_setup_failure",
            "as a parent setup failure, which is where provisioning lives: " ..
            tostring(st.cause))
    end)

test("WorkingDirectory is checked when the service starts, not when the definition is read",
    { spec = "peinit *fmt.workingdirectory-existence-is-checked-at-start-not-at-read" },
    function(t)
        -- The definition names a directory that does not exist. It
        -- decoded -- the service is in the model, Inactive, waiting to
        -- be started -- and it is the start that discovers the problem.
        local before = status("pt-wd-missing")
        t:assert(before, "the definition is in the model")
        t:assert_eq(before.state, "inactive",
            "and nothing was wrong with it at read time: " .. tostring(before.state))

        vm:run("svctl --json start pt-wd-missing --no-wait")
        local st = settled("pt-wd-missing")
        t:assert_eq(st.state, "failed",
            "the start is where it failed: " .. tostring(st.state) .. "/" ..
            tostring(st.cause))
    end)

test("a timeout written as 3 is three seconds",
    { spec = "peinit *fmt.timeouts-and-intervals-are-in-whole-seconds" },
    function(t)
        -- pt-secs is a Oneshot that sleeps for five minutes with a
        -- StartTimeout of 3. If the unit were milliseconds the start
        -- would be over before the fork; if it were minutes the test
        -- would still be waiting. Seconds puts the failure a few seconds
        -- after the start, which is what is measured.
        local began = tonumber(vm:run("date +%s").stdout:match("%d+"))
        vm:run("svctl --json start pt-secs --no-wait")
        local st = settled("pt-secs", 120)
        local ended = tonumber(vm:run("date +%s").stdout:match("%d+"))

        t:assert_eq(st.state, "failed", "the start timed out")
        t:assert_eq(st.cause, "readiness_timeout", "on its readiness timeout")
        local elapsed = ended - began
        t:assert(elapsed >= 2,
            "and it took at least about three seconds, so the unit is not " ..
            "milliseconds: " .. elapsed .. "s")
        t:assert(elapsed < 60,
            "and well under a minute, so it is not minutes either: " .. elapsed .. "s")
    end)

test("the identifiers peinit mints are UUIDv7, and sort by creation time",
    {
        spec = {
            "peinit *fmt.generated-identifiers-are-uuidv7",
            "peinit *fmt.identifiers-sort-by-creation-time",
        },
    },
    function(t)
        -- Every operation gets one, so three starts of a trivial Oneshot
        -- produce three identifiers minted in a known order.
        local ids = {}
        for _ = 1, 3 do
            local started = vm:run("svctl --json start pt-ids")
            started:assert_ok()
            local id = started.stdout:match('"operation_id":"([^"]+)"')
            t:assert(id, "the start reported an operation id: " .. started.stdout)
            ids[#ids + 1] = id
            vm:run("svctl --json reset pt-ids")
        end

        for _, id in ipairs(ids) do
            -- 8-4-4-4-12 lower-case hex, with 7 as the version nibble
            -- and the RFC 4122 variant bits in the next group.
            t:assert(id:match("^%x%x%x%x%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x$"),
                "the identifier is a canonical UUID: " .. id)
            t:assert_eq(id:sub(15, 15), "7", "with version 7: " .. id)
            t:assert(("89ab"):find(id:sub(20, 20), 1, true),
                "and the RFC 4122 variant: " .. id)
        end

        -- Time-ordered, which is the property the section is about: the
        -- identifiers sort into the order they were minted in, as plain
        -- strings, with no parsing.
        t:assert(ids[1] < ids[2] and ids[2] < ids[3],
            "the three sort into the order they were created in: " ..
            table.concat(ids, " < "))
    end)
