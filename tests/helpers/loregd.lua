-- A second, real loregd serving a hive of the test's own, for the
-- loregd conformance testset (PEI-1121).
--
-- Every durability and behaviour claim in the loregd book (learn's
-- loregd TRM) is testable end to end only against a running loregd we
-- control, rather than the image's registryd. registryd starts at
-- Phase 1, before the autorun queue that starts this agent, so its hive
-- is on the root filesystem before a test exists and can never be
-- relocated onto a disk a test mounts. A second source is legitimate:
-- registration collides only on a route identity held by another
-- *Active* source (PKM *source.register.no-route-identity-collision),
-- and the `PtState` hive is nobody's. Nothing in LCS knows which source
-- is loregd, so a hive of our own is served exactly as Machine is, and
-- `reg` and the LCS client ioctls route Caller -> kernel LCS -> loregd.
--
-- The disk is an ext4 filesystem on a scratch virtio device. ext4
-- classifies `facs_deny_missing` (PKM *facs.storage.default-deny-missing)
-- and a filesystem straight out of mkfs carries no descriptors at all,
-- so it must be adopted under a synthesise class at fsmount time —
-- which is what `helpers/kacs.new_mount` does. Ephemeral, not
-- persistent: a synthesised descriptor is never written back, so
-- adopting the mount adds no writes of its own to the disk.
--
-- Pass `mediated = true` to boot to make the disk a provium-mediated
-- one, so `vm:disk(id):power_cut()` can drop what was never flushed;
-- durability.test.lua needs that, most files do not.

local peinit = require("helpers.peinit")
local sys = require("helpers.sys")
local kacs = require("helpers.kacs")

local M = {}

-- The profile attaches its ISO medium first, so a boot disk is the
-- second virtio device. Boot disks are attached after the profile's and
-- ids share one namespace, so this cannot silently displace the medium.
M.DEVICE = "/dev/vdb"
M.MOUNT = "/mnt/pt-hive"
M.HIVE = "PtState"
M.HIVE_FILE = M.MOUNT .. "/pt-state.hive"
-- A key most tests can write under; `-p` creates the parent PtState root.
M.KEY = [[PtState\Durable]]

--- Boot a VM with a scratch disk ready to hold the hive.
---
--- `opts`: name (required-ish), mediated (bool), disk_size ("256M"),
--- and any other peinit.boot fields are merged.
function M.boot(opts)
    opts = opts or {}
    local disk = { scratch = opts.disk_size or "256M", id = "hive" }
    if opts.mediated then disk.mediated = true end
    return peinit.boot({
        name = opts.name or "loregd",
        boot = { disks = { disk } },
    })
end

--- `mkfs.ext4` the scratch device. Call once before the first mount;
--- the next case's data lives on the same filesystem.
function M.format(vm, t)
    local r = vm:run("mkfs.ext4 -F -q " .. M.DEVICE)
    if t then
        t:assert_eq(r.exit_code, 0, "mkfs.ext4 on " .. M.DEVICE .. ": " .. r.stderr)
    end
    return r
end

--- Adopt the disk's filesystem at MOUNT, usable.
---
--- `new_mount` sets the policy class on the mount fd between `fsmount`
--- and `move_mount`, which is the only window in which a superblock can
--- be named — after it is attached there is no fd to name it by.
function M.mount(vm, t)
    local ok, stage, errno = kacs.new_mount(vm, "ext4", M.MOUNT,
        kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL, { source = M.DEVICE })
    if t then
        t:assert(ok, "mounting " .. M.DEVICE .. " at " .. M.MOUNT .. ": " ..
            tostring(stage) .. " " .. sys.errname(errno or 0))
    end
    return ok, stage, errno
end

--- Whether `pid` has finished: gone from /proc, or a zombie the agent
--- has not reaped yet. A zombie still has a /proc entry, so "the entry
--- is gone" alone would call an exited daemon alive.
function M.exited(vm, pid)
    local ok, status = pcall(vm.read_file, vm, "/proc/" .. pid .. "/status")
    return not ok or status:find("\nState:%s*Z") ~= nil
end

--- Spawn loregd without waiting for anything. For the command-line and
--- startup-failure cases, which assert on how it *ends*, not that it
--- serves. `args` is the full argv after the program name.
function M.spawn(vm, args)
    return vm:run_async("/usr/sbin/loregd", { args = args })
end

--- Start loregd on the hive and wait until the kernel will route to it.
---
--- `opts`: hives (list of "Name=Path", default {PtState=HIVE_FILE}),
--- wait_for (hive name whose registration to poll, default the first
--- hive's name), timeout (30).
---
--- The Process belongs to whatever scope called this: a file-scope call
--- lives for the file and is shared by every case; a call inside a
--- test() is reaped (SIGTERM, then SIGKILL two seconds later) when that
--- test ends. Durability cases want the latter; most files want one
--- daemon at file scope.
---
--- Readiness is asked of LCS rather than read off the daemon's stdout:
--- what the test needs is not that loregd printed something but that a
--- `reg` invocation now reaches it, and those are different facts. The
--- daemon's own output is kept for the failure message.
function M.start(vm, t, opts)
    opts = opts or {}
    local hives = opts.hives or { M.HIVE .. "=" .. M.HIVE_FILE }
    local wait_for = opts.wait_for or hives[1]:match("^([^=]+)=")

    local proc = vm:run_async("/usr/sbin/loregd", { args = hives })

    -- Readiness is a lookup of the hive root (`reg info`), not an
    -- enumeration (`reg ls`). Both prove the kernel routes to loregd, but
    -- enumeration walks a parent's children, and a hive that has held a
    -- volatile child of a persistent parent carries a dangling persistent
    -- path entry after a restart (PEI-515); a loregd that predates the
    -- enum-tolerance fix (1b307c0, PEI-233) then answers RSI_ENUM_CHILDREN
    -- with a storage error, so an enumerating readiness probe would never
    -- succeed and would misreport a served hive as unregistered. Lookup
    -- tolerates the dangling entry, so it asks exactly the routing question
    -- readiness means to ask.
    local ok = pcall(wait_until, function()
        return vm:run("reg info " .. wait_for).exit_code == 0
    end, { timeout = opts.timeout or 30, interval = 0.5,
           desc = "loregd to register the " .. wait_for .. " hive" })

    if not ok then
        proc:kill("term")
        local r = proc:wait("5s")
        local msg = "loregd never registered " .. wait_for ..
            "; exit=" .. tostring(r.exit_code) ..
            " stdout=" .. tostring(r.stdout) ..
            " stderr=" .. tostring(r.stderr)
        if t then t:assert(false, msg) else error(msg) end
    end
    return proc
end

--- SIGTERM `proc` and say how it ended.
---
--- Returns the RunResult and a description for failure messages: the
--- exit status and loregd's own output — which says whether its signal
--- handler ever ran, since it logs `received terminated` before closing
--- the device. When the daemon is still alive after `grace` seconds the
--- description also carries where it is stuck: its /proc state and
--- signal masks, and every thread's wait channel, taken BEFORE
--- `proc:wait` gives up and SIGKILLs it.
function M.stop(proc, vm, grace)
    local pid = proc:pid()
    proc:kill("term")

    local gone = pcall(wait_until, function() return M.exited(vm, pid) end,
        { timeout = grace or 15, interval = 0.25, desc = "loregd to exit" })

    local where = ""
    if not gone then
        local lines = { "\n  still alive " .. (grace or 15) ..
            "s after SIGTERM (pid " .. pid .. "):" }
        local ok, status = pcall(vm.read_file, vm, "/proc/" .. pid .. "/status")
        if ok then
            for line in status:gmatch("[^\n]+") do
                if line:match("^State:") or line:match("^Sig") or line:match("^ShdPnd:") then
                    lines[#lines + 1] = "    " .. line
                end
            end
        end
        local tasks = vm:run("ls /proc/" .. pid .. "/task").stdout
        for tid in tasks:gmatch("%d+") do
            local _, wchan = pcall(vm.read_file, vm,
                "/proc/" .. pid .. "/task/" .. tid .. "/wchan")
            lines[#lines + 1] = "    thread " .. tid .. " waiting in " .. tostring(wchan)
        end
        where = table.concat(lines, "\n")
    end

    local r = proc:wait("5s")
    return r, ("exit=%s status=%s signal=%s%s\n  loregd stdout: %s\n  loregd stderr: %s")
        :format(tostring(r.exit_code), tostring(r.status), tostring(r.signal),
            where, tostring(r.stdout), tostring(r.stderr))
end

-- ---- reg convenience -------------------------------------------------
--
-- `reg get <key> <value>` prints the value bare — for a DWORD the number
-- and nothing else — so the trimmed stdout is the whole answer.

--- Read a value back through the registry; returns RunResult, trimmed.
function M.get(vm, key, name)
    local r = vm:run("reg get '" .. key .. "' " .. name)
    return r, (r.stdout:gsub("%s+$", ""))
end

--- Create a key (with parents), returning the RunResult.
function M.new_key(vm, key)
    return vm:run("reg new '" .. key .. "' -p")
end

--- Set a value, returning the RunResult. `spec` is reg's typed form,
--- e.g. "dword:1" or "sz:hello".
function M.set(vm, key, name, spec)
    return vm:run("reg set '" .. key .. "' " .. name .. " " .. spec)
end

return M
