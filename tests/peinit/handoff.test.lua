-- Peinit TRM §2.1 — the initramfs contract.
--
-- Everything here is a claim about what peinit is HANDED rather than
-- about what it does, which is why the profile boots the real chain: the
-- assertions below are only worth anything because prelude and
-- live-boot really produced this state.

local peinit = require("helpers.peinit")

local vm = peinit.boot()

test("peinit assembles no root of its own", { spec = "peinit *handoff.peinit-performs-no-root-assembly" },
    function(t)
        -- Nothing peinit does mounts the root: by the time it exists the
        -- root is already `/`. The evidence is the console — every mount
        -- that produced the root is announced by a hook, before peinit's
        -- banner appears.
        local log = vm:console():read_log()
        local handoff = log:find("prelude: exec /bin/peinit2", 1, true)
        t:assert(handoff, "the handoff happened")
        local mount = log:find("live%-boot: mounted boot medium")
        t:assert(mount and mount < handoff,
            "the root was assembled before peinit was exec'd, not by it")
    end)

test("control arrives by chroot and exec, and the initramfs rootfs stays behind",
    {
        spec = {
            "peinit *handoff.control-arrives-by-chroot-and-exec",
            "peinit *handoff.peinit-never-pivots",
        },
    },
    function(t)
        local log = vm:console():read_log()
        t:assert(log:find("prelude: pivot: chroot", 1, true), "prelude chroot'd")
        t:assert(not log:find("pivot_root", 1, true),
            "and did not pivot_root, which the kernel refuses onto the initramfs rootfs")

        -- The consequence the contract draws: the initramfs rootfs is
        -- still the mount-namespace root, so what peinit sees is not a
        -- clean single-root topology. `/` has a parent it cannot name —
        -- its mountinfo parent id names a mount that is not in the list.
        local ids, root_parent = {}, nil
        for line in vm:read_file("/proc/self/mountinfo"):gmatch("[^\r\n]+") do
            local id, parent, _, _, point = line:match("^(%d+) (%d+) (%S+) (%S+) (%S+) ")
            ids[id] = true
            if point == "/" then root_parent = parent end
        end
        t:assert(root_parent, "the root is in mountinfo")
        t:assert(not ids[root_parent],
            "the root's parent mount is unreachable — the initramfs rootfs is still there")
    end)

test("peinit is reached at /bin/peinit2, the path the boot image names in init=",
    { spec = "peinit *handoff.peinit-is-reached-through-bin-peinit2" },
    function(t)
        local cmdline = vm:read_file("/proc/cmdline")
        t:assert(cmdline:find("init=/bin/peinit2", 1, true),
            "the image's own command line names the runtime path: " .. cmdline)
        t:assert(vm:console():read_log():find("prelude: exec /bin/peinit2", 1, true),
            "and prelude exec'd exactly that")
        -- Storage and runtime path are different files reached through
        -- the StrataFS view, and both are peinit.
        t:assert_eq(vm:read_file("/proc/1/comm"):gsub("%s+$", ""), "peinit2",
            "PID 1 is what was exec'd at that path")
    end)

test("the StrataFS /bin and /sbin views exist before peinit runs",
    { spec = "peinit *handoff.the-stratafs-views-exist-at-handoff" },
    function(t)
        -- peinit reaches every binary it execs through these, so they
        -- have to be assembled by the initramfs rather than by peinit.
        local mounts = vm:read_file("/proc/self/mountinfo")
        for _, view in ipairs({ "/bin", "/sbin" }) do
            local found = false
            for line in mounts:gmatch("[^\r\n]+") do
                local point = line:match("^%d+ %d+ %S+ %S+ (%S+) ")
                if point == view then
                    found = true
                    t:assert(line:find(" stratafs ", 1, true),
                        view .. " is a StrataFS view, not an ordinary directory")
                end
            end
            t:assert(found, view .. " is mounted")
        end

        -- The console says who built them, and it was not peinit: the
        -- lines come from the initramfs hook, ahead of the handoff.
        local log = vm:console():read_log()
        local built = log:find("stratafs%-base: mounted /bin in the root")
        local handoff = log:find("prelude: exec /bin/peinit2", 1, true)
        t:assert(built and handoff and built < handoff,
            "the views were assembled before peinit was exec'd")
    end)

test("the root is delivered read-write, which is registryd's requirement",
    {
        spec = {
            "peinit *handoff.the-root-is-mounted-read-write",
            "peinit *handoff.the-read-write-requirement-is-registryds",
        },
    },
    function(t)
        local root
        for line in vm:read_file("/proc/self/mountinfo"):gmatch("[^\r\n]+") do
            local point = line:match("^%d+ %d+ %S+ %S+ (%S+) ")
            if point == "/" then root = line end
        end
        t:assert(root:find(" rw,", 1, true), "the root is mounted rw: " .. root)

        -- And the requirement is registryd's rather than peinit's, which
        -- is observable in what a read-only root would have broken:
        -- registryd's storage writes even to answer a read. It is up and
        -- serving, so the delivery held.
        t:assert(vm:console():read_log():find("peinit: phase1 registryd started", 1, true),
            "registryd started on the writable root it needs")
    end)

test("proc, sys and dev were moved into the root rather than mounted by peinit",
    { spec = "peinit *handoff.proc-sys-dev-are-moved-into-the-root" },
    function(t)
        local log = vm:console():read_log()
        for _, fs in ipairs({ "/proc", "/sys", "/dev" }) do
            t:assert(log:find("prelude: mount%-move " .. fs .. " %->"),
                "prelude mount-moved " .. fs)
        end

        -- peinit's own mount step then finds them present and mounts only
        -- what is missing (§2.3), which is why the three carry the
        -- initramfs's devtmpfs rather than a second stacked instance.
        local mounts = vm:read_file("/proc/self/mountinfo")
        local dev_lines = 0
        for line in mounts:gmatch("[^\r\n]+") do
            local point = line:match("^%d+ %d+ %S+ %S+ (%S+) ")
            if point == "/dev" then dev_lines = dev_lines + 1 end
        end
        t:assert_eq(dev_lines, 1, "/dev is mounted once, not stacked twice")
    end)

test("peinit passes none of its own startup environment on to a service",
    { spec = "peinit *handoff.peinit-passes-none-of-its-environment-on" },
    function(t)
        -- peinit's own environment at handoff holds TERM and nothing
        -- else. registryd is the first thing it starts, and its
        -- environment is constructed from scratch — so whatever peinit
        -- was given does not appear in it.
        local mine = vm:read_file("/proc/1/environ")
        -- No pgrep in the image: peiosutils is a coreutils fork and does
        -- not carry the procps tools. /proc is the answer it would have
        -- read anyway.
        local pid = vm:run(
            'for p in /proc/[0-9]*; do ' ..
            '[ "$(cat "$p/comm" 2>/dev/null)" = registryd ] && echo "${p#/proc/}"; ' ..
            'done'
        ).stdout:match("%d+")
        t:assert(pid, "registryd is running")
        local theirs = vm:read_file("/proc/" .. pid .. "/environ")

        local function vars(blob)
            local set = {}
            for entry in blob:gmatch("[^%z]+") do
                set[entry:match("^([^=]+)")] = entry:match("=(.*)$")
            end
            return set
        end
        local peinit_env, service_env = vars(mine), vars(theirs)

        -- The claim is not that the two are disjoint — both may name
        -- PATH — but that nothing reaches the service by inheritance.
        -- TERM is the one variable peinit is handed, and a service's
        -- environment is built without it unless its definition asks.
        for name, value in pairs(peinit_env) do
            if service_env[name] ~= nil then
                t:assert(service_env[name] ~= value or name == "PATH",
                    name .. " reached the service unchanged from peinit's own environment")
            end
        end
    end)
