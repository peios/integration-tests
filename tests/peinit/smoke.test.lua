-- Does the harness reach peinit at all? The kernel execs prelude out of
-- the real initramfs, live-boot's hook finds the medium on the virtio
-- bus and assembles the root, prelude chroots in and execs
-- /bin/peinit2, and peinit's phase-1.5 autorun starts the agent this
-- test is talking to.
--
-- Kept deliberately small and first: when a peinit case fails, this says
-- whether peinit misbehaved or the profile never got as far as booting
-- one.

local peinit = require("helpers.peinit")
peinit.claim(1)

-- The agent answers from the autorun queue, between phase 1 and phase 2,
-- so a boot that has reached the agent is not yet a boot that has
-- finished. `peinit.boot` waits for the phase these assertions are
-- about.
local vm = peinit.boot()

test("a whole Peios boots, and PID 1 is peinit", {}, function(t)
    t:assert_eq(vm:read_file("/proc/1/comm"):gsub("%s+$", ""), "peinit2",
        "PID 1 is peinit, under the name live-boot's init= names it by")
end)

test("the root peinit is running on is live-boot's overlay over the medium's squashfs",
    {}, function(t)
        local mounts = vm:read_file("/proc/self/mountinfo")

        -- The root itself. An overlay, not the squashfs directly: the
        -- squashfs is read-only and registryd must write, so live-boot
        -- stacks a tmpfs on it (Peinit TRM §2.1 — the read-write
        -- requirement is registryd's).
        local root_line
        for line in mounts:gmatch("[^\r\n]+") do
            local mountpoint = line:match("^%d+ %d+ %S+ %S+ (%S+) ")
            if mountpoint == "/" then root_line = line end
        end
        t:assert(root_line, "there is a mount at /")
        t:assert(root_line:find(" overlay ", 1, true),
            "the root is an overlay, not the squashfs: " .. tostring(root_line))
        t:assert(root_line:find("lowerdir=/mnt/rootfs.lower", 1, true),
            "its lower layer is the squashfs live-boot loop-mounted")

        -- The squashfs mount itself is NOT in this list, and that is the
        -- handoff working rather than a gap: prelude chroots into the
        -- new root instead of pivoting, so everything the initramfs
        -- mounted outside /mnt/rootfs stays in the namespace but out of
        -- reach, and mountinfo lists only what peinit's root can name.
        --
        -- What is reachable is the medium, which live-boot mount-moved
        -- to /media/peios on its way past — and it is the ISO this
        -- profile attached, so the boot really did come off the disk.
        t:assert(mounts:find(" /media/peios ", 1, true),
            "the medium was carried into the new root")
        t:assert(mounts:find("iso9660", 1, true),
            "and it is the ISO9660 this profile attached")

        -- prelude carried the kernel virtual filesystems across the
        -- chroot; peinit's contract assumes they are already there.
        for _, fs in ipairs({ "/proc", "/sys", "/dev" }) do
            t:assert(mounts:find(" " .. fs .. " ", 1, true),
                fs .. " was moved into the new root")
        end
    end)

test("the console records the whole chain, prelude through peinit's phases",
    {}, function(t)
        local log = vm:console():read_log()

        -- prelude ran and handed off.
        t:assert(log:find("prelude · initramfs · PID 1", 1, true),
            "prelude announced itself")
        t:assert(log:find("exec /bin/peinit2", 1, true),
            "prelude exec'd the init live-boot's cmdline named")

        -- live-boot found the medium on the bus this profile attached it
        -- to, rather than timing out its scan.
        t:assert(log:find("mounted boot medium /dev/vd", 1, true),
            "live-boot found the medium")

        -- And peinit got through both boot phases, with registryd
        -- between them — phase 2 reads the service graph out of the
        -- registry, so a phase-2 line means the registry answered.
        t:assert(log:find("peinit · real root · PID 1", 1, true),
            "peinit announced itself")
        t:assert(log:find("peinit: phase1 registryd started", 1, true),
            "phase 1 started registryd")
        t:assert(log:find("peinit: phase2 boot complete", 1, true),
            "phase 2 completed")
    end)

test("peinit started the agent from the image's autorun queue", {}, function(t)
    local log = vm:console():read_log()

    -- The autorun this profile injects is what puts the agent in the
    -- guest, so a test that can ask this question at all is evidence the
    -- mechanism worked. Assert on it anyway: when a later change breaks
    -- the injection, the whole suite fails at boot, and this is the line
    -- that says why.
    t:assert(log:find("10-provium-agent.sh: provium-agent: started", 1, true),
        "the autorun script ran and started the agent")
    t:assert(log:find("peinit: ran 2 autorun script(s)", 1, true),
        "both autoruns ran: the image's seed-apply and this profile's")

    -- It is a plain process under peinit, not PID 1 — the one thing
    -- about this harness that differs from every other profile.
    local comm = vm:read_file("/proc/self/comm"):gsub("%s+$", "")
    t:assert_eq(comm, "provium-agent", "the agent is running under its own name")
end)
