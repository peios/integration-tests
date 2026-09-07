-- Peinit TRM §2.6 — `peios.notifysocket=PATH` overrides the notification
-- socket path.
--
-- It is in the `peios.*` set at all because it is a Phase 1 value: registryd
-- is the first service to use the socket, and the socket has to be bound
-- before registryd is launched, so there is no registry to read it from
-- yet. The manual's claim is the whole of the parameter — the socket moves,
-- and the machine keeps working — so this file asserts both halves rather
-- than only the half that can be checked with `stat`.
--
-- The override stays inside /run/services/peinit deliberately. The notify
-- bind is what creates that directory chain, so a path anywhere else leaves
-- the control socket's own creation with no parent and takes PID 1 to
-- recovery for a second and unrelated reason.

local peinit = require("helpers.peinit")
peinit.claim(1)

local MOVED = "/run/services/peinit/pt-cmdline.sock"
local DEFAULT = "/run/services/peinit/notify.sock"

test("peios.notifysocket= moves the socket peinit binds and the one services are told about",
    {
        spec = "peinit *cmdline.notifysocket-overrides-the-socket-path",
        -- PEI-804: peinit advertises the overridden path to services and
        -- then binds the default one in the runtime, so nothing is
        -- listening where the services were told to write and every Notify
        -- readiness stalls in Starting.
        tags = { "known-bug" },
    },
    function(t)
        local vm = peinit.boot({ name = "cmdline-notifysocket", append = "peios.notifysocket=" .. MOVED })

        -- Where the command line said.
        local moved = vm:run("stat -c %F " .. MOVED)
        t:assert(moved.exit_code == 0 and moved.stdout:find("socket", 1, true),
            "a socket is bound where the command line named: " ..
            tostring(moved.stdout) .. tostring(moved.stderr))

        -- And nowhere else: an override that leaves the default in place is
        -- not an override, it is a second socket.
        t:assert(vm:run("stat -c %F " .. DEFAULT).exit_code ~= 0,
            "and nothing is left bound at the default path")

        -- The half that says the machine still works. authd ships with
        -- Notify readiness, so it can only reach Active on a READY=1 that
        -- peinit received — which it can only do if the socket peinit is
        -- listening on is the one authd was told to write to.
        local state
        for _ = 1, 30 do
            local status = vm:run("svctl --json status authd")
            state = status.stdout:match('"state":"([^"]+)"')
            if state ~= "starting" then break end
            vm:clock():sleep("500ms")
        end
        t:assert_eq(state, "active",
            "a Notify service reported itself ready through the moved socket")
    end)
