-- Does the harness reach prelude at all? The kernel execs the real
-- prelude, prelude runs the profile's three staged hooks, one of them
-- mounts a root, and prelude hands the machine to the provium agent
-- inside it.
--
-- Kept deliberately small and first: when a prelude case fails, this
-- says whether prelude misbehaved or the profile never got as far as
-- booting one.

local vm = provium:vm("v", "prelude"):boot()

test("prelude boots, runs its hooks, and hands off to the init on the mounted root",
    {}, function(t)
        local log = vm:console():read_log()

        -- prelude announced itself and read the command line.
        t:assert(log:find("prelude · initramfs · PID 1", 1, true),
            "the stage banner is on the console")

        -- Each hook ran, in the order mkirf resolved: the initramfs-ready
        -- contributor first (every other hook is implicitly ordered after
        -- it), then the root mount, then the hook requiring rootfs-ready.
        local order = {}
        for name in log:gmatch("hook: /usr/libexec/prelude/hooks%.d/pt%-([%w%-]+)%.sh") do
            order[#order + 1] = name
        end
        t:assert_eq(table.concat(order, ","), "topology,mount-root,late",
            "the three hooks ran in the resolved order")

        -- Each reported itself satisfied, once.
        for _, hook in ipairs({ "topology", "mount-root", "late" }) do
            t:assert(log:find("pt|" .. hook .. "|outcome=satisfied", 1, true),
                hook .. " reported satisfied")
            t:assert(log:find("pt|" .. hook .. "|pass=1|", 1, true),
                hook .. " ran on its first pass")
        end
        t:assert(log:find("ran 3 hook invocation(s)", 1, true),
            "prelude counted three invocations")

        -- The root was found and the handoff happened.
        t:assert(log:find("root mounted at /mnt/rootfs", 1, true), "prelude saw a root")
        t:assert(log:find("exec /bin/peinit2", 1, true),
            "prelude exec'd the first candidate in the fallback chain")

        -- And the far side of the handoff is alive: the agent answering
        -- this call IS the process prelude exec'd. Its comm is the name
        -- of the file at the fallback path rather than the agent's own,
        -- which is the clearest evidence available that prelude exec'd
        -- the path it said it would.
        t:assert_eq(vm:read_file("/proc/1/comm"):gsub("%s+$", ""), "peinit2",
            "PID 1 is the init prelude exec'd, under the name it exec'd it by")
    end)

test("the root the agent is running on is the one a hook mounted, not the initramfs",
    {}, function(t)
        -- The late hook wrote this after the mount, so its presence says
        -- the file survived the pivot and the cleanup walk.
        t:assert_eq(vm:read_file("/run/pt/late.ran"):gsub("%s+$", ""), "late",
            "what the last hook left in the new root is still there")

        -- prelude carried the kernel virtual filesystems across.
        local mounts = vm:read_file("/proc/self/mountinfo")
        for _, fs in ipairs({ "/proc", "/sys", "/dev" }) do
            t:assert(mounts:find(" " .. fs .. " ", 1, true),
                fs .. " was moved into the new root")
        end
    end)
