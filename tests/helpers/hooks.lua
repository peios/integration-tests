-- The stratafs test rendezvous and fail points (PKM §4.A.2), and the
-- kernel trace ring, from inside a kernel-only guest.
--
-- Both interfaces live on kernel-populated filesystems (securityfs,
-- tracefs) whose inodes carry no descriptors, so a runtime mount of
-- either sits deny-missing and refuses everything. `kacs.new_mount`
-- sets a synthesize-ephemeral policy on the fsmount fd before
-- attaching — the one moment a policy can be named — which is the same
-- rescue the quota and provider-filesystem tests use.
--
-- securityfs, not debugfs: the kernel forces lockdown integrity mode,
-- which refuses every debugfs open that is not a read of an 0444 file.
-- tracefs is gated only at confidentiality level and stays reachable.
--
-- The hooks themselves exist only when the kernel was booted with
-- stratafs.test_hooks=1 (the kernel-only profile passes it).

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")

local M = {}

M.SECURITYFS_AT = "/sfs"
M.TRACEFS_AT = "/trc"

local mounted = {}

local function ensure_mount(vm, fstype, at)
    if mounted[at] then return true end
    local ok, step, errno = kacs.new_mount(vm, fstype, at,
        kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL)
    if not ok then
        return nil, ("%s: %s: %s"):format(fstype, step, sys.errname(errno))
    end
    mounted[at] = true
    return true
end

--- Mount securityfs (once) and return the path of one hook's control
--- file.
function M.hook_path(vm, name)
    local ok, err = ensure_mount(vm, "securityfs", M.SECURITYFS_AT)
    if not ok then return nil, err end
    return M.SECURITYFS_AT .. "/stratafs/hooks/" .. name
end

local function hook_write(vm, name, command)
    local path, err = M.hook_path(vm, name)
    if not path then return nil, err end
    local fd, errno = sys.open(vm, path, sys.O.WRONLY)
    if not fd then
        return nil, "open " .. path .. ": " .. sys.errname(errno)
    end
    local r = sys.write(vm, fd, command)
    sys.close(vm, fd)
    if r.ret ~= #command then
        return nil, "write " .. command .. ": " .. sys.errname(r.errno)
    end
    return true
end

--- Read a hook's state: mode string, waiting count, hits count.
function M.state(vm, name)
    local path, err = M.hook_path(vm, name)
    if not path then return nil, err end
    local fd, errno = sys.open(vm, path, sys.O.RDONLY)
    if not fd then
        return nil, "open " .. path .. ": " .. sys.errname(errno)
    end
    local data = sys.read(vm, fd, 128)
    sys.close(vm, fd)
    if not data then return nil, "read failed" end
    local mode, waiting, hits = data:match("^(%a+) waiting=(%d+) hits=(%d+)")
    if not mode then return nil, "unparsable state: " .. data end
    return mode, tonumber(waiting), tonumber(hits)
end

--- Arm a hold: tasks reaching the point block until M.clear.
function M.hold(vm, name) return hook_write(vm, name, "hold") end

--- Arm a one-shot failure with the given (positive) errno.
function M.fail(vm, name, errno)
    return hook_write(vm, name, ("fail %d"):format(errno))
end

--- Disarm; wake every held task.
function M.clear(vm, name) return hook_write(vm, name, "clear") end

--- Poll until `waiting` reaches at least `n` (default 1). The victim
--- syscall runs on another agent thread, so arrival is asynchronous.
function M.await_waiting(vm, name, n, attempts)
    n = n or 1
    for _ = 1, attempts or 200 do
        local mode, waiting = M.state(vm, name)
        if not mode then return nil, waiting end
        if waiting >= n then return true end
        sys.nanosleep(vm, 0, 10 * 1000 * 1000)
    end
    return nil, "hook " .. name .. " never reached waiting=" .. n
end

-- ---- tracefs ----

local function trace_write(vm, rel, data)
    local fd, errno = sys.open(vm, M.TRACEFS_AT .. "/" .. rel, sys.O.WRONLY)
    if not fd then return nil, "open " .. rel .. ": " .. sys.errname(errno) end
    local r = sys.write(vm, fd, data)
    sys.close(vm, fd)
    if r.ret ~= #data then return nil, "write " .. rel .. ": " .. sys.errname(r.errno) end
    return true
end

--- Mount tracefs (once), reset the buffer, and enable one event
--- (e.g. "stratafs/stratafs_d_revalidate").
function M.trace_start(vm, event)
    local ok, err = ensure_mount(vm, "tracefs", M.TRACEFS_AT)
    if not ok then return nil, err end
    -- Clearing the ring is an O_TRUNC open of `trace`; a plain write
    -- to it is accepted and ignored.
    local fd, errno = sys.open(vm, M.TRACEFS_AT .. "/trace",
        sys.O.WRONLY | sys.O.TRUNC)
    if not fd then return nil, "truncate trace: " .. sys.errname(errno) end
    sys.close(vm, fd)
    local steps = {
        { "events/" .. event .. "/enable", "1" },
        { "tracing_on", "1" },
    }
    for _, s in ipairs(steps) do
        local ok2, err2 = trace_write(vm, s[1], s[2])
        if not ok2 then return nil, err2 end
    end
    return true
end

--- Stop tracing, disable the event, and return the buffer's lines
--- (comment lines dropped).
function M.trace_stop(vm, event)
    trace_write(vm, "tracing_on", "0")
    trace_write(vm, "events/" .. event .. "/enable", "0")
    local fd, errno = sys.open(vm, M.TRACEFS_AT .. "/trace", sys.O.RDONLY)
    if not fd then return nil, "open trace: " .. sys.errname(errno) end
    local chunks = {}
    while true do
        local data = sys.read(vm, fd, 65536)
        if not data or #data == 0 then break end
        chunks[#chunks + 1] = data
    end
    sys.close(vm, fd)
    local lines = {}
    for line in table.concat(chunks):gmatch("[^\n]+") do
        if not line:match("^#") then lines[#lines + 1] = line end
    end
    return lines
end

return M
