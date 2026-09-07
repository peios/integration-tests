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

local function boot(name)
    return peinit.boot({
        name = name,
        files = peinit.seed("pt-reload", {
            { path = [[Machine\System]] },
            { path = [[Machine\System\Services]] },
            resident("pt-resident"),
        }),
    })
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
