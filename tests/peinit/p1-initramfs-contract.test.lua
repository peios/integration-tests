-- Peinit TRM §2.1 — the initramfs contract: the two clauses of it that
-- are about what peinit was handed and what it deliberately does not do.
--
-- handoff.test.lua covers the rest of the chapter. This file exists for
-- the two claims that need something the shipped boot does not produce
-- on its own: the exact contents of PID 1's environment and argv, and a
-- filesystem mounted after the boot by something that is not peinit.
--
-- Both are read from a booted machine rather than from a substitute,
-- which is the whole point of this profile: `/proc/1/environ` is what
-- prelude really handed the real peinit, and the tmpfs below is really
-- mounted by a service peinit really started.

local peinit = require("helpers.peinit")
peinit.claim(1)

-- A Oneshot that mounts a filesystem, which is exactly what §2.1 says
-- non-root storage is done by: "mounted at the services layer, typically
-- by a Oneshot service that runs `mount`". SYSTEM because mounting needs
-- the privilege; staged as a script because the definition's ImagePath
-- takes one program and this needs two commands.
local MOUNTER = [[#!/bin/sh
mkdir -p /mnt/pt-data
exec mount -t tmpfs tmpfs /mnt/pt-data
]]

local vm = peinit.boot({
    name = "p1-contract",
    files = peinit.merge(
        { ["lcl/pt/pt-mount.sh"] = { MOUNTER, exec = true } },
        peinit.seed("pt-contract", {
            { path = [[Machine\System]] },
            { path = [[Machine\System\Services]] },
            { path = [[Machine\System\Services\pt-data-mount]], values = {
                { name = "ImagePath", type = "sz", data = "/lcl/pt/pt-mount.sh" },
                { name = "Type", type = "dword", data = 1 },
                { name = "Readiness", type = "dword", data = 1 },
                { name = "Triggers", type = "multi", data = { "boot" } },
                { name = "Identity", type = "sz", data = "SYSTEM" },
            } },
        })
    ),
})

--- Every mount point in the guest's mountinfo, with its filesystem type.
local function mount_table()
    local at = {}
    for line in vm:read_file("/proc/self/mountinfo"):gmatch("[^\r\n]+") do
        local point, rest = line:match("^%d+ %d+ %S+ %S+ (%S+) (.*)$")
        if point then at[point] = rest:match("%- (%S+) ") end
    end
    return at
end

test("peinit is handed TERM and nothing else, and an argv of just its own path",
    { spec = "peinit *handoff.the-environment-holds-only-term" },
    function(t)
        -- The contract is a statement about the handoff, so the evidence
        -- has to be PID 1's own two /proc files: whatever prelude passed
        -- to execve is what these hold, and nothing since has changed
        -- them.
        local names, values = {}, {}
        for entry in vm:read_file("/proc/1/environ"):gmatch("[^%z]+") do
            local name, value = entry:match("^([^=]*)=(.*)$")
            names[#names + 1] = name
            values[name] = value
        end
        t:assert_eq(#names, 1,
            "one variable, and only one: " .. table.concat(names, " "))
        t:assert_eq(names[1], "TERM",
            "and it is TERM, which is a fact about the machine right now")
        t:assert(values.TERM ~= "" and values.TERM ~= nil,
            "TERM carries a value: " .. tostring(values.TERM))

        -- argv is peinit's own path and nothing else. The kernel builds
        -- it from `init=`, and peinit takes no arguments — a peinit that
        -- read one would be configuration arriving by a route the
        -- contract does not have.
        local argv = {}
        for arg in vm:read_file("/proc/1/cmdline"):gmatch("[^%z]+") do
            argv[#argv + 1] = arg
        end
        t:assert_eq(#argv, 1, "one argument: " .. table.concat(argv, " "))
        t:assert_eq(argv[1], "/bin/peinit2", "which is peinit's own runtime path")
    end)

test("a filesystem that is not the root is mounted by a service, not by peinit",
    { spec = "peinit *handoff.non-root-storage-is-not-peinits-concern" },
    function(t)
        -- The positive half: a Oneshot service ran `mount` and the
        -- filesystem is there. This is the documented route for data
        -- partitions, and nothing about it involves peinit beyond
        -- starting the service.
        vm:console():expect("peinit: service pt-data-mount started", peinit.STAGE_TIMEOUT)
        local at = mount_table()
        t:assert_eq(at["/mnt/pt-data"], "tmpfs",
            "the service's mount is in mountinfo")

        -- The negative half: peinit's own mount feature is the fixed
        -- Phase 1 set (§2.3) and stops there. Everything else mounted on
        -- this machine came from the initramfs — the medium, the root
        -- overlay and the StrataFS views, all of which the console
        -- attributes to a hook before the handoff — or from the service
        -- above. Nothing peinit mounts is outside the seven rows of the
        -- table, so a mount point that is neither is evidence about
        -- someone else.
        local peinit_owned = {
            ["/proc"] = true, ["/sys"] = true, ["/dev"] = true,
            ["/dev/pts"] = true, ["/dev/shm"] = true, ["/run"] = true,
            ["/sys/fs/cgroup"] = true,
        }
        local log = vm:console():read_log()
        local handoff = log:find("prelude: exec /bin/peinit2", 1, true)
        t:assert(handoff, "the handoff happened")
        for point, fstype in pairs(at) do
            if not peinit_owned[point] and point ~= "/mnt/pt-data" then
                -- StrataFS views and the root overlay: assembled before
                -- the handoff, which the console records.
                local assembled_by_the_initramfs = fstype == "stratafs"
                    or point == "/" or point == "/media/peios"
                t:assert(assembled_by_the_initramfs,
                    point .. " (" .. tostring(fstype) ..
                        ") is not peinit's to mount, and nothing else claims it")
            end
        end

        -- And peinit says nothing about it: the mount step reports the
        -- filesystems it mounted, and this is not one of them.
        t:assert(not log:find("/mnt/pt-data", 1, true),
            "peinit's console never mentions the service's filesystem")
    end)
