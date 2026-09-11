-- Peinit TRM §10.4 — reload-config: a full atomic re-read of the
-- registry rather than a live update.
--
-- The registry is writable from the guest, so a test can change the
-- configuration under a running peinit and then ask what it did with it.
-- One thing to keep in mind throughout: peinit holds a watch on the
-- registry and any drained event triggers the same full reload, so a
-- `reg` write has usually already been picked up by the time an explicit
-- `svctl reload-config` runs. That is not interference — it is §10.4's
-- own claim, and the first test below is about exactly it.

local peinit = require("helpers.peinit")
peinit.claim(1)

local function resident(name, argument)
    return {
        path = [[Machine\System\Services\]] .. name,
        values = {
            { name = "ImagePath", type = "sz", data = "/bin/sleep" },
            { name = "Arguments", type = "multi", data = { argument or "100000" } },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "Readiness", type = "dword", data = 1 },
            { name = "RestartPolicy", type = "dword", data = 0 },
            { name = "Triggers", type = "multi", data = { "boot" } },
        },
    }
end

--- Boot with pt-resident, plus any `extra.keys` in the seed and any
--- `extra.files` (a staged guest tool, say) alongside it.
local function boot(name, extra)
    extra = extra or {}
    local keys = {
        { path = [[Machine\System]] },
        { path = [[Machine\System\Services]] },
        resident("pt-resident"),
    }
    for _, key in ipairs(extra.keys or {}) do keys[#keys + 1] = key end
    local files = peinit.seed("pt-reload", keys)
    if extra.files then files = peinit.merge(files, extra.files) end
    return peinit.boot({ name = name, files = files })
end

--- Write `keys` in one `reg apply` transaction, so peinit's registry
--- watch sees a single change rather than a key assembled in steps.
local function apply(vm, keys, name)
    local file = "/tmp/pt-" .. (name or "apply") .. ".json"
    vm:run("cat > " .. file .. " <<'PT_JSON_EOF'\n" .. peinit.encode_json({ keys = keys })
        .. "\nPT_JSON_EOF"):assert_ok()
    vm:run("reg apply " .. file):assert_ok()
end

--- The main process's PID for `service`, or nil.
local function main_pid(vm, service)
    return vm:run("svctl --json status " .. service).stdout:match('"pid":(%d+)')
end

test("a registry change reloads the configuration without anyone asking",
    { spec = "peinit *control.reload-config.is-the-registry-watch-path" },
    function(t)
        -- reload-config is not only a command: it is the path a registry
        -- change notification takes. Any drained watch event triggers
        -- the same full reload rather than a targeted re-read of
        -- whatever moved.
        --
        -- So: write a whole new service into the registry and never
        -- issue reload-config. If the watch path exists, peinit knows
        -- about it anyway.
        local vm = boot("reload-watch")
        t:assert(vm:run("svctl --json status pt-watched").stdout:find("UNKNOWN_SERVICE", 1, true),
            "the service does not exist yet")

        vm:run([[reg new 'Machine\System\Services\pt-watched']]):assert_ok()
        vm:run([[reg set 'Machine\System\Services\pt-watched' ImagePath 'sz:/bin/sleep']])
            :assert_ok()
        vm:run([[reg set 'Machine\System\Services\pt-watched' Identity 'sz:SYSTEM']])
            :assert_ok()
        vm:run([[reg set 'Machine\System\Services\pt-watched' Readiness 'dword:1']])
            :assert_ok()

        local status = vm:run("svctl --json status pt-watched")
        status:assert_ok()
        t:assert_eq(status.stdout:match('"state":"([^"]+)"'), "inactive",
            "peinit re-read the registry on the watch event alone: " .. status.stdout)
    end)

test("a new definition is startable as soon as the reload has taken it",
    {
        spec = {
            "peinit *control.reload-config.every-definition-is-re-read",
            "peinit *control.reload-config.a-new-service-is-startable-at-once",
        },
    },
    function(t)
        -- New services become available for `start` immediately — not at
        -- the next boot, and not after some later trigger.
        local vm = boot("reload-new")
        vm:run([[reg new 'Machine\System\Services\pt-added']]):assert_ok()
        vm:run([[reg set 'Machine\System\Services\pt-added' ImagePath 'sz:/bin/sleep']])
            :assert_ok()
        vm:run([[reg set 'Machine\System\Services\pt-added' Arguments 'multi:100000']])
            :assert_ok()
        vm:run([[reg set 'Machine\System\Services\pt-added' Identity 'sz:SYSTEM']])
            :assert_ok()
        vm:run([[reg set 'Machine\System\Services\pt-added' Readiness 'dword:1']])
            :assert_ok()
        vm:run([[reg set 'Machine\System\Services\pt-added' RestartPolicy 'dword:0']])
            :assert_ok()

        local reload = vm:run("svctl --json reload-config")
        reload:assert_ok()

        local started = vm:run("svctl --json start pt-added")
        started:assert_ok()
        t:assert_eq(started.stdout:match('"state":"([^"]+)"'), "active",
            "the service peinit had never seen at boot started on demand: "
            .. started.stdout)
        t:assert(main_pid(vm, "pt-added"), "and it has a live main process")
    end)

test("a reload that fails validation leaves the running configuration exactly as it was",
    { spec = "peinit *control.reload-config.a-failed-validation-changes-nothing" },
    function(t)
        -- This is where the reload path differs sharply from boot. Boot
        -- marks individual services Failed and carries on because it has
        -- to produce a running system; a reload has a running system
        -- already, so it rejects the whole thing and returns the
        -- findings rather than applying half of it.
        local vm = boot("reload-invalid")
        local before = main_pid(vm, "pt-resident")
        t:assert(before, "the resident service is running")

        -- A hard dependency on a service nothing defines: the graph
        -- cannot validate, and the failure is a property of the graph
        -- rather than of one definition's syntax.
        --
        -- The definition is written in one `reg apply` transaction
        -- rather than value by value. peinit watches the registry and
        -- reloads on any change (see the first test in this file), so a
        -- key built up in steps is briefly a *valid* definition with no
        -- Requires yet — and a reload landing in that window would admit
        -- it before the invalid form ever existed.
        local batch = peinit.encode_json({ keys = { {
            path = [[Machine\System\Services\pt-badgraph]],
            values = {
                { name = "ImagePath", type = "sz", data = "/bin/true" },
                { name = "Identity", type = "sz", data = "SYSTEM" },
                { name = "Type", type = "dword", data = 1 },
                { name = "Requires", type = "multi", data = { "pt-nothing" } },
            },
        } } })
        vm:run("cat > /tmp/pt-badgraph.json <<'PT_JSON_EOF'\n" .. batch ..
            "\nPT_JSON_EOF"):assert_ok()
        vm:run("reg apply /tmp/pt-badgraph.json"):assert_ok()

        local reload = vm:run("svctl --json reload-config")
        t:assert(reload.exit_code ~= 0, "the reload was refused: " .. reload.stdout)
        t:assert(reload.stdout:find("pt%-nothing"),
            "and the findings name what was wrong, rather than a bare failure: "
            .. reload.stdout)

        -- The previous generation stays live: same service, same
        -- process, and the invalid definition was not admitted.
        t:assert_eq(main_pid(vm, "pt-resident"), before,
            "the running service kept its process across the refused reload")
        t:assert(vm:run("svctl --json status pt-badgraph").stdout
                :find("UNKNOWN_SERVICE", 1, true),
            "and the definition that failed validation was not half-applied")
    end)

test("a changed definition leaves the running process alone and applies at the next start",
    {
        spec = {
            "peinit *control.reload-config.running-services-are-unaffected",
            "peinit *control.reload-config.a-changed-definition-takes-effect-at-the-next-start",
        },
    },
    function(t)
        -- A reload does not live-update anything. A running service
        -- continues on the activation generation it started under, and
        -- what the registry now says takes effect the next time the
        -- service starts.
        --
        -- The argument vector is the visible half of that: it is fixed
        -- at exec, so /proc tells the truth about which generation the
        -- live process belongs to.
        local vm = boot("reload-change")
        local before = main_pid(vm, "pt-resident")
        t:assert(before, "the resident service is running")

        local function argv(pid)
            return (vm:read_file("/proc/" .. pid .. "/cmdline"):gsub("%z", " "))
        end
        t:assert(argv(before):find("100000", 1, true),
            "it was started with the argument the boot definition gave it: " .. argv(before))

        vm:run([[reg set 'Machine\System\Services\pt-resident' Arguments 'multi:200000']])
            :assert_ok()
        vm:run("svctl --json reload-config"):assert_ok()

        -- Unaffected: same process, same argument vector.
        t:assert_eq(main_pid(vm, "pt-resident"), before,
            "the reload did not disturb the running process")
        t:assert(argv(before):find("100000", 1, true),
            "which is still running on the old definition: " .. argv(before))

        -- And the new definition is what the next start uses.
        vm:run("svctl --json restart pt-resident"):assert_ok()
        local after = main_pid(vm, "pt-resident")
        t:assert(after and after ~= before, "the restart made a new process")
        t:assert(argv(after):find("200000", 1, true),
            "and it carries the changed definition: " .. argv(after))
    end)

test("registryd survives a reload that has no definition for it at all",
    { spec = "peinit *control.reload-config.registryd-is-exempt" },
    function(t)
        -- peinit started registryd from a compiled-in definition, before
        -- the registry existed. A reload that finds no definition for it
        -- cannot conclude that it should stop being managed — so the
        -- ordinary definition-removed handling of §3.8 does not apply.
        local vm = boot("reload-registryd")

        -- The premise: this image really does not define registryd.
        local keys = vm:run([[reg ls 'Machine\System\Services' --keys-only]])
        keys:assert_ok()
        t:assert(not keys.stdout:find("registryd", 1, true),
            "the registry has no registryd key: " .. keys.stdout)

        local before = main_pid(vm, "registryd")
        t:assert(before, "and registryd is running anyway, from the compiled-in definition")

        vm:run("svctl --json reload-config"):assert_ok()

        local status = vm:run("svctl --json status registryd")
        status:assert_ok()
        t:assert_eq(status.stdout:match('"state":"([^"]+)"'), "active",
            "registryd is still an active service after the reload: " .. status.stdout)
        t:assert(status.stdout:find('"definition_removed":false', 1, true),
            "and was not marked definition-removed by a reload that never mentioned it: "
            .. status.stdout)
        t:assert_eq(main_pid(vm, "registryd"), before,
            "nor restarted")
    end)

test("a registry definition for registryd is merged onto it rather than restarting it",
    { spec = "peinit *control.reload-config.registryd-is-exempt" },
    function(t)
        -- The other half: its provenance survives a registry entry that
        -- shadows it. peinit does not create a second inactive record
        -- and does not restart registryd because a definition appeared.
        local vm = boot("reload-registryd-shadow")
        local before = main_pid(vm, "registryd")
        t:assert(before, "registryd is running")

        vm:run([[reg new 'Machine\System\Services\registryd']]):assert_ok()
        vm:run([[reg set 'Machine\System\Services\registryd' ImagePath 'sz:/sbin/registryd']])
            :assert_ok()
        vm:run([[reg set 'Machine\System\Services\registryd' Identity 'sz:SYSTEM']])
            :assert_ok()
        vm:run([[reg set 'Machine\System\Services\registryd' DisplayName 'sz:Shadowed']])
            :assert_ok()
        vm:run("svctl --json reload-config"):assert_ok()

        local status = vm:run("svctl --json status registryd")
        status:assert_ok()
        t:assert_eq(status.stdout:match('"state":"([^"]+)"'), "active",
            "registryd is still active: " .. status.stdout)
        t:assert_eq(main_pid(vm, "registryd"), before,
            "and was not restarted because a definition appeared for it")

        -- Merged onto the retained activation rather than added beside
        -- it: one registryd, not two.
        local list = vm:run("svctl --json list")
        list:assert_ok()
        local count = select(2, list.stdout:gsub('"service":"registryd"', ""))
        t:assert_eq(count, 1, "there is exactly one registryd in the list")
    end)

local SERVICES = [[Machine\System\Services]]

--- The value of `field` in a `svctl --json status` answer, or nil.
local function status_field(vm, service, field)
    return vm:run("svctl --json status " .. service).stdout:match('"' .. field .. '":"([^"]*)"')
end

--- One transaction carrying three changes a reload will read in turn: a
--- new service, a new description on the running one, and a definition
--- whose StartTimeout is a string where a number belongs. The first two
--- are perfectly good; the third will not decode.
local function plant_undecodable(vm)
    apply(vm, {
            { path = SERVICES .. [[\pt-fresh]], values = {
                { name = "ImagePath", type = "sz", data = "/bin/true" },
                { name = "Identity", type = "sz", data = "SYSTEM" },
                { name = "Type", type = "dword", data = 1 },
                { name = "Readiness", type = "dword", data = 1 },
            } },
            { path = SERVICES .. [[\pt-resident]], values = {
                { name = "Description", type = "sz", data = "rewritten by the reload" },
            } },
            { path = SERVICES .. [[\pt-broken]], values = {
                { name = "ImagePath", type = "sz", data = "/bin/true" },
                { name = "Identity", type = "sz", data = "SYSTEM" },
                { name = "StartTimeout", type = "sz", data = "soon" },
            } },
        }, "undecodable")
end

test("an undecodable key fails the whole reload, and nothing read alongside it is applied",
    { spec = "peinit *control.reload-config.reads-precede-every-mutation" },
    function(t)
        local vm = boot("reload-undecodable")
        -- If peinit mutated anything before it had read everything, one
        -- of the two good changes would have landed by the time the third
        -- refused to decode.
        plant_undecodable(vm)

        local reload = vm:run("svctl --json reload-config")
        t:assert(reload.exit_code ~= 0, "the reload was refused: " .. reload.stdout)

        -- Nothing the reload read was applied: the new service does not
        -- exist and the running one kept its description.
        t:assert(vm:run("svctl --json status pt-fresh").stdout:find("UNKNOWN_SERVICE", 1, true),
            "the good new definition read alongside it was not admitted")
        t:assert(not vm:run("svctl --json status pt-resident").stdout
                :find("rewritten by the reload", 1, true),
            "and the good change to the running service was not applied either")

        -- Every reload fails the same way until the key is repaired —
        -- including this second explicit one, so no other configuration
        -- change can take effect in the meantime.
        local again = vm:run("svctl --json reload-config")
        t:assert(again.exit_code ~= 0, "a second reload fails the same way: " .. again.stdout)

        -- Repaired by removal, the same reload admits everything else it
        -- was holding back — which is what shows the two good changes
        -- were refused for the bad key's sake and not their own.
        vm:run("reg del '" .. SERVICES .. [[\pt-broken' --recursive]]):assert_ok()
        local repaired = wait_until(function()
            local r = vm:run("svctl --json reload-config")
            if r.exit_code == 0 then return r end
        end, { timeout = 30, desc = "a reload to succeed once the key is gone" })
        t:assert(repaired, "the reload succeeds once the key is gone")
        t:assert(not vm:run("svctl --json status pt-fresh").stdout:find("UNKNOWN_SERVICE", 1, true),
            "the new service is admitted now")
        t:assert_eq(status_field(vm, "pt-resident", "description"), "rewritten by the reload",
            "and so is the new description")
    end)

test("a reload refused for an undecodable key names the key and what was wrong",
    {
        spec = "peinit *control.reload-config.an-undecodable-definition-aborts-the-reload",
        -- PEI-1075. The refusal holds (the test above), the naming does
        -- not: `reload_config_error_response`
        -- (src/supervisor/control_command/error.rs) keeps a validation
        -- failure's findings but renders a registry read failure — where
        -- a decode error lands — as the generic
        -- {"code":"INTERNAL_ERROR","message":"control request failed"},
        -- discarding the error it was given.
        tags = { "known-bug" },
    },
    function(t)
        local vm = boot("reload-undecodable-named")
        plant_undecodable(vm)

        -- Every reload fails on this key until it is repaired, including
        -- the ones a registry change triggers, so the answer is the only
        -- place an operator learns which key to repair.
        local reload = vm:run("svctl --json reload-config")
        t:assert(reload.exit_code ~= 0, "the reload was refused: " .. reload.stdout)
        t:assert(reload.stdout:find("pt%-broken"),
            "naming the service that would not decode: " .. reload.stdout)
        t:assert(reload.stdout:find("StartTimeout", 1, true),
            "and what was wrong with it: " .. reload.stdout)
    end)

--- Every target PID 1 holds a descriptor on, from /proc/1/fd.
local function pid1_targets(vm)
    local out = {}
    for line in vm:run("ls -l /proc/1/fd 2>/dev/null").stdout:gmatch("[^\r\n]+") do
        local target = line:match("%->%s+(.*)$")
        if target then out[#out + 1] = (target:gsub("%s+$", "")) end
    end
    return out
end

--- How many of PID 1's descriptors point at `path`. Counting one file's
--- descriptors rather than PID 1's total is what makes this immune to
--- everything else PID 1 opens and closes meanwhile.
local function held(vm, path)
    local count = 0
    for _, target in ipairs(pid1_targets(vm)) do
        if target == path or target == path .. " (deleted)" then count = count + 1 end
    end
    return count
end

test("a reload prunes the fd store of a service that no longer exists",
    { spec = "peinit *control.reload-config.prunes-fd-stores-of-vanished-services" },
    function(t)
        -- Which store can outlive its service's definition? Not one whose
        -- service was stopped: an explicit stop clears the store (§10.6,
        -- `fdstore.an-explicit-stop-clears-the-store`). The store survives
        -- only an automatic restart. So the service here stores a
        -- descriptor and then crashes, and its restart policy holds it in
        -- Backoff for thirty seconds with nothing running — the store kept
        -- for a restart that is coming. Removing the definition in that
        -- window leaves a store whose service no longer exists, and that
        -- is what the reload has to prune.
        local MARKER = "/run/pt-keep.marker"
        local vm = boot("reload-prune", {
            files = peinit.tool("pt-notify"),
            keys = { { path = SERVICES .. [[\pt-keep]], values = {
                { name = "ImagePath", type = "sz", data = "/usr/bin/pt-notify" },
                { name = "Arguments", type = "multi", data = {
                    -- sleep 1 first: the first datagram after exec is
                    -- refused, before peinit has recorded the main job.
                    "--log", "/run/pt-keep.log", "sleep", "1",
                    "send-fd", MARKER, "FDSTORE=1\\nFDNAME=kept",
                    "write", "/run/pt-keep.done", "ok", "sleep", "1",
                    "exit", "1",
                } },
                { name = "Identity", type = "sz", data = "SYSTEM" },
                { name = "Readiness", type = "dword", data = 1 },
                { name = "RestartPolicy", type = "dword", data = 1 },
                { name = "RestartDelay", type = "dword", data = 30 },
                { name = "FdStoreMax", type = "dword", data = 4 },
            } } },
        })
        vm:run("echo kept > " .. MARKER):assert_ok()
        vm:run("svctl --json --no-wait start pt-keep"):assert_ok()
        wait_until(function() return vm:run("test -f /run/pt-keep.done"):ok() or nil end,
            { timeout = 60, interval = 0.2, desc = "pt-keep to store its descriptor" })

        wait_until(function()
            return vm:run("svctl --json status pt-keep").stdout:find('"state":"backoff"', 1, true)
        end, { timeout = 20, desc = "pt-keep to crash into Backoff" })
        t:assert_eq(held(vm, MARKER), 1,
            "the store is kept through the crash, for the restart Backoff is waiting to make")

        -- Remove the definition while nothing is running, which §3.8
        -- discards outright, and reload.
        vm:run("reg del '" .. SERVICES .. [[\pt-keep' --recursive]]):assert_ok()
        wait_until(function()
            return vm:run("svctl --json status pt-keep").stdout:find("UNKNOWN_SERVICE", 1, true)
        end, { timeout = 30, desc = "the definition's removal to be reloaded" })
        local pruned = wait_until(function() return held(vm, MARKER) == 0 or nil end,
            { timeout = 10, interval = 0.3, desc = "the store to be pruned" })
        t:assert(pruned, "the reload that forgot the service closed its stored descriptor")
    end)

test("a calendar timer a reload arms is armed from now, with no catch-up",
    { spec = "peinit *control.reload-config.calendar-timers-are-re-armed-without-catch-up" },
    function(t)
        -- The claim needs a timer that *would* catch up if the reload did
        -- what a boot does. §9.3 supplies one: a persistent trigger with
        -- no history catches up exactly once at boot
        -- (`persist.a-trigger-with-no-history-catches-up-once`). So two
        -- timers identical in every value, neither with history — one
        -- present at boot, one added after it and armed by a reload. The
        -- first is the control and must fire; the second must not.
        --
        -- Yearly, so that nothing fires legitimately in the few seconds
        -- the test watches: the next real occurrence is next January.
        local SCHEDULE = "timer:*-01-01 00:00:00"
        local function ticker(name)
            return { path = SERVICES .. [[\]] .. name, values = {
                { name = "ImagePath", type = "sz", data = "/bin/sh" },
                { name = "Arguments", type = "multi", data = {
                    "-c", "echo " .. name .. " >> /run/pt-ticks" } },
                { name = "Type", type = "dword", data = 1 },
                { name = "Identity", type = "sz", data = "SYSTEM" },
                { name = "Readiness", type = "dword", data = 1 },
                { name = "Triggers", type = "multi", data = { SCHEDULE } },
            } }
        end
        local function ticks(vm, name)
            local text = vm:run("cat /run/pt-ticks 2>/dev/null").stdout or ""
            return select(2, text:gsub(name, ""))
        end

        local vm = boot("reload-timers", { keys = { ticker("pt-cal-boot") } })
        wait_until(function() return ticks(vm, "pt%-cal%-boot") >= 1 or nil end,
            { timeout = 30, interval = 0.5, desc = "the boot-time catch-up" })
        t:assert_eq(ticks(vm, "pt%-cal%-boot"), 1,
            "a persistent timer with no history catches up once at boot")

        apply(vm, { ticker("pt-cal-reload") }, "timers")
        vm:run("svctl --json reload-config"):assert_ok()
        t:assert(not vm:run("svctl --json status pt-cal-reload").stdout
                :find("UNKNOWN_SERVICE", 1, true),
            "the reload took the second timer")

        -- Long enough for a catch-up to have happened: the boot one above
        -- landed within a second or two of the plan dispatching.
        vm:run("sleep 6")
        t:assert_eq(ticks(vm, "pt%-cal%-reload"), 0,
            "the same timer armed by a reload waits for its next occurrence instead")
        t:assert_eq(ticks(vm, "pt%-cal%-boot"), 1,
            "and re-arming the first one did not catch it up a second time")
    end)

test("a reload refreshes the socket limits, the global environment and the control descriptor",
    { spec = "peinit *control.reload-config.refreshes-more-than-definitions" },
    function(t)
        -- The sentence lists six things a reload refreshes besides
        -- definitions. Three are observable from a running guest and are
        -- asserted here: a control socket limit, the global environment
        -- layer, and the control descriptor. The shutdown settings are
        -- only observable during a shutdown, and the log configuration
        -- and eventd socket path only through eventd's own plumbing;
        -- none of the three is exercised. One reload moving three
        -- unrelated settings is what "more than definitions" claims.
        local vm = boot("reload-refresh", {
            files = peinit.tool("pt-ctl"),
            keys = {
                { path = [[Machine\System\Init]] },
                { path = [[Machine\System\Init\EnvVars]] },
                { path = SERVICES .. [[\pt-envprobe]], values = {
                    { name = "ImagePath", type = "sz", data = "/bin/sh" },
                    { name = "Arguments", type = "multi", data = {
                        "-c", 'echo "v=$PT_RELOAD_ENV" > /run/pt-envprobe.out' } },
                    { name = "Type", type = "dword", data = 1 },
                    { name = "Identity", type = "sz", data = "SYSTEM" },
                    { name = "Readiness", type = "dword", data = 1 },
                    { name = "RestartPolicy", type = "dword", data = 0 },
                } },
            },
        })

        --- One frame of `bytes` bytes on a fresh control connection.
        local function frame_answer(bytes)
            local frame = '{"command":"status","service":"pt-resident","pad":"'
                .. string.rep("A", bytes) .. '"}'
            vm:run("pt-ctl --log /run/pt-ctl-frame.log '" .. frame .. "'", { timeout = 30 })
            return tostring(vm:read_file("/run/pt-ctl-frame.log"))
        end

        local function probe_env()
            vm:run("svctl --json start pt-envprobe", { timeout = 60 }):assert_ok()
            return tostring(vm:read_file("/run/pt-envprobe.out")):gsub("%s+$", "")
        end

        -- Before: the default MaxRequestSize (64 KiB) takes a 5 KiB frame,
        -- and the global environment says nothing about PT_RELOAD_ENV.
        t:assert(frame_answer(5000):find('"status":"ok"', 1, true),
            "a 5 KiB frame is served under the default bound")
        t:assert_eq(probe_env(), "v=", "and a service starts with no PT_RELOAD_ENV")

        apply(vm, {
            { path = [[Machine\System\Init]], values = {
                { name = "MaxRequestSize", type = "dword", data = 4096 },
            } },
            { path = [[Machine\System\Init\EnvVars]], values = {
                { name = "PT_RELOAD_ENV", type = "sz", data = "after" },
            } },
        }, "refresh")
        vm:run("svctl --json reload-config"):assert_ok()

        t:assert(frame_answer(5000):find("REQUEST_TOO_LARGE", 1, true),
            "after the reload the same frame is past the new 4 KiB bound")
        t:assert_eq(probe_env(), "v=after",
            "and the next start sees the global environment the reload read")

        -- Last, because it takes reload-config away: a control descriptor
        -- granting SYSTEM shutdown alone. The registry watch's own reload
        -- is what applies it, and the next explicit reload is refused.
        vm:run("reg set 'Machine\\System\\Init' ControlSecurity hex:"
            .. peinit.system_descriptor_hex(0x0001)):assert_ok()
        local refused = wait_until(function()
            local r = vm:run("svctl --json reload-config")
            if r.stdout:find("ACCESS_DENIED", 1, true) then return r end
        end, { timeout = 30, desc = "the control descriptor to be refreshed" })
        t:assert(refused, "the reload refreshed the control descriptor, which now refuses reload-config")
    end)
