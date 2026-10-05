-- peinit TRM §12.2 step 5 — the global timeout: it fires once, and the
-- console says what it was waiting for.
--
-- The shape is shutdown-deadlines.test.lua's abandoned case, moved to the
-- global timeout. `pt-gt-stuck` ignores SIGTERM and has a StopTimeout far
-- beyond the six-second ShutdownTimeout, so only the global timeout ends
-- its stop. Its main process is moved out of the service tree before the
-- shutdown, where the sweep's cgroup kill cannot reach it, and a keeper
-- outside the service drops a fresh process into a sibling of `main/`
-- every second, so the root is still populated when the post-kill check
-- comes due. That check then abandons it, and the sequence goes on to its
-- final action.
--
-- What the claim excludes is the timeout firing again on the turns after
-- it: each time, it would kill the survivors again and push their
-- post-kill check back, so nothing would ever be abandoned and the
-- machine would never power off. So "fires once" is read three ways: one
-- `global timeout expired` line, an `abandoned` line, and `reboot: Power
-- down`.

local peinit = require("helpers.peinit")
peinit.claim(1)

local function with_vm(opts, body)
    local vm = peinit.boot(opts)
    local ok, err = pcall(body, vm)
    pcall(function() vm:shutdown() end)
    if not ok then error(err, 0) end
end

local function trigger(vm, command)
    pcall(function() vm:run(command, { timeout = 30 }) end)
end

local function count(haystack, needle)
    local n, from = 0, 1
    while true do
        local at = haystack:find(needle, from, true)
        if not at then return n end
        n, from = n + 1, at + #needle
    end
end

local ROOT = "/sys/fs/cgroup/peinit/pt-gt-stuck"

local FILES = {
    ["pt/stuck.sh"] = { [[
trap '' TERM
while : ; do /bin/sleep 1 ; done
]], exec = true },
    ["pt/keeper.sh"] = { [[
N=0
while [ $N -lt 120 ] ; do
  /bin/sleep 300 &
  echo $! > $1/cgroup.procs
  N=$((N+1))
  /bin/sleep 1
done
]], exec = true },
}

test("the global timeout fires once, names what it was waiting for, and the shutdown finishes",
    {
        spec = {
            "peinit *graceful.the-global-timeout-fires-once",
            "peinit *graceful.the-console-names-what-the-global-timeout-waited-for",
        },
    },
    function(t)
        with_vm({
            name = "shutdown-gt-once",
            append = "peios.quiet=0",
            files = peinit.merge(FILES, peinit.seed("pt-gt-once", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Boot]], values = {
                    { name = "ShutdownTimeout", type = "dword", data = 6 },
                    { name = "PostKillTimeout", type = "dword", data = 4 },
                } },
                { path = [[Machine\System\Services]] },
                { path = [[Machine\System\Services\pt-gt-stuck]], values = {
                    { name = "ImagePath", type = "sz", data = "/bin/sh" },
                    { name = "Arguments", type = "multi", data = { "/pt/stuck.sh" } },
                    { name = "Identity", type = "sz", data = "SYSTEM" },
                    { name = "Readiness", type = "dword", data = 1 },
                    { name = "RestartPolicy", type = "dword", data = 0 },
                    { name = "StopTimeout", type = "dword", data = 600 },
                    { name = "Triggers", type = "multi", data = { "boot" } },
                } },
            })),
        }, function(vm)
            peinit.settle(vm)
            local main_pid = wait_until(function()
                local ok, procs = pcall(function()
                    return vm:read_file(ROOT .. "/main/cgroup.procs")
                end)
                return ok and procs:match("^(%d+)") or nil
            end, { timeout = 60, interval = 0.5, desc = "pt-gt-stuck to have a main process" })

            -- Out of reach of the sweep's kill, and a root that stays
            -- populated: see the header.
            vm:run("mkdir -p /sys/fs/cgroup/pt-escape"):assert_ok()
            vm:run("echo " .. main_pid .. " > /sys/fs/cgroup/pt-escape/cgroup.procs"):assert_ok()
            vm:run("mkdir -p " .. ROOT .. "/pt-keep"):assert_ok()
            vm:run("/pt/keeper.sh " .. ROOT .. "/pt-keep > /dev/null 2>&1 &")
            t:assert(vm:read_file(ROOT .. "/pt-keep/cgroup.procs"):match("%d"),
                "premise: the keeper has a process in a sibling of main/")

            trigger(vm, "svctl shutdown poweroff")
            vm:console():expect("peinit: shutdown stopping pt-gt-stuck", 60)
            vm:console():expect("peinit: shutdown global timeout expired", 90)
            vm:console():expect("peinit: shutdown abandoned pt-gt-stuck", 90)
            vm:console():expect("reboot: Power down", 120)
            local log = vm:console():read_log()

            t:assert_eq(count(log, "peinit: shutdown global timeout expired"), 1,
                "the global timeout fired once")

            -- What it was waiting for, by name, with state and wave.
            local line = log:match("peinit: shutdown global timeout expired waiting for ([^\r\n]*)")
            t:assert(line, "the expiry line says what the sequence was waiting for")
            t:assert(line and line:find("pt%-gt%-stuck %(%a+, wave %d+%)"),
                "naming the participant with its state and wave: " .. tostring(line))

            -- The post-kill check that followed is what abandoned it, which
            -- a second sweep would have kept pushing back.
            local expired_at = log:find("peinit: shutdown global timeout expired", 1, true)
            local abandoned_at = log:find("peinit: shutdown abandoned pt-gt-stuck", 1, true)
            t:assert(abandoned_at and abandoned_at > expired_at,
                "the survivor was abandoned on its post-kill timeout after the sweep")
            local still = log:match("peinit: shutdown still waiting for ([^\r\n]*)")
            if still then
                t:assert(still:find("pt-gt-stuck", 1, true),
                    "a later turn still waiting names what remains: " .. still)
            end
        end)
    end)
