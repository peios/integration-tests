-- Helpers for the shutdown chapter's files: a witness for PID 1's last
-- turn, and a reader for what it reports.
--
-- The end of a graceful shutdown — the random seed, the unmounts, the
-- read-only remounts, the sync and the final reboot(2) — prints nothing
-- when it works, what it would print is written after a reboot(2) that
-- does not return (PEI-827), and the machine is gone a moment later. So
-- for a long time the only evidence a test could offer for any of it
-- was the kernel's "reboot: Power down".
--
-- `pt-shutwatch` (tests/tools/pt-shutwatch.c) changes that. It runs in
-- the guest, outside PID 1 and in a mount namespace of its own, and
-- reports on the console, as it happens, three things about PID 1:
-- ftrace syscall events for the calls that matter (with their path
-- arguments and their results), inotify on the seed's directory, and
-- PID 1's mount table. The host reads the console after the guest is
-- gone. Read the tool's header for why the namespace matters: a watcher
-- in PID 1's namespace would hold mounts busy and change the outcomes
-- it was there to report.
--
-- A second vCPU is what lets it keep up. The finalising turn is a few
-- tens of milliseconds of syscalls ending in reboot(2), and the
-- witness has to read and forward each event before the kernel stops
-- the other CPUs. Boots that use it pass `cpus = 2`, and the file claims
-- accordingly.

local peinit = require("helpers.peinit")

local M = {}

--- The witness, as a `files` entry.
function M.tool()
    -- Signed: it traces and reads the /proc of PID 1, which is TCB-signed,
    -- and PIP refuses an unsigned process both.
    return peinit.tool("pt-shutwatch", { signed = true })
end

--- Start the witness and wait until all three of its sources are armed.
---
--- It detaches at once. Its first lines are PID 1's mount table as it
--- stands, then `pt-sw N ready trace=1 fs=1 mount=1 …`; anything short
--- of all three armed is a harness failure, raised here rather than
--- discovered as a missing event later.
---
--- opts:
---   hold  hold PID 1's final action back: its reboot(2) fails with EPERM
---         until this many attempts have failed, then succeeds (see the
---         tool's header). Every step before the reboot is the one a real
---         shutdown takes; what the hold buys is a machine that stays up
---         until the witness has written the whole record.
---   seed  the seed path, if not peinit's
function M.start(vm, opts)
    opts = opts or {}
    local args = ""
    if opts.seed then args = args .. " --seed " .. opts.seed end
    if opts.hold then args = args .. " --hold " .. tostring(opts.hold) end
    vm:run("/usr/bin/pt-shutwatch" .. args .. " > /dev/null 2>&1 &")
    local ready = wait_until(function()
        return vm:console():read_log():match("pt%-sw %d+ (ready[^\r\n]*)")
    end, { timeout = 30, interval = 0.25, desc = "pt-shutwatch to arm" })
    local want = "trace=1 fs=1 mount=1 hold=" .. (opts.hold and "1" or "0")
    assert(ready:find(want, 1, true),
        "pt-shutwatch did not arm everything asked of it (" .. want .. "): " .. ready .. "\n"
        .. table.concat(M.errors(vm:console():read_log()), "\n"))
    return ready
end

--- Wait until the witness has let a held final action through: it has
--- seen `hold` failed reboot(2) calls and re-enabled the privilege.
function M.released(vm, timeout)
    return wait_until(function()
        return vm:console():read_log():match("pt%-sw %d+ (hold released[^\r\n]*)")
    end, { timeout = timeout or 60, interval = 0.25, desc = "the held final action to be released" })
end

--- The witness's own error lines, for a failure message.
function M.errors(log)
    local out = {}
    for line in log:gmatch("[^\r\n]+") do
        local rest = line:match("pt%-sw %d+ (error .*)$")
        if rest then out[#out + 1] = rest end
    end
    return out
end

--- A tmpfs the test owns, mounted at `path`.
---
--- tmpfs carries no descriptors of its own and KACS refuses a
--- filesystem that has none, so the mount synthesises SYSTEM-only ones —
--- the same thing the image's own tmpfs mounts get by other means.
---
--- `options` is prepended to the mount's own `-o` list — `shared`, say,
--- for a mount whose submounts should propagate to its binds.
function M.tmpfs(vm, source, path, options)
    vm:run("mkdir -p " .. path):assert_ok()
    local o = (options and options .. "," or "") .. "policy=synth-ephemeral"
    vm:run("mount -t tmpfs -o " .. o .. " --synth-sddl "
        .. "'O:SYG:SYD:(A;OICI;GA;;;SY)' " .. source .. " " .. path):assert_ok()
end

--- A 64-bit two's-complement hex value, as a signed integer.
---
--- Syscall exit events print their result unsigned: -EBUSY is
--- 0xfffffffffffffff0. Lua integers wrap on overflow, so accumulating
--- the digits gives the signed value directly.
local function signed(hex)
    local v = 0
    for digit in hex:gsub("^0x", ""):gmatch("%x") do
        v = v * 16 + tonumber(digit, 16)
    end
    return v
end

M.EPERM, M.ENOENT, M.EBUSY, M.EINVAL = -1, -2, -16, -22

--- Everything the witness reported, in the order it reported it.
---
--- Each entry has `seq` (the witness's own line number) and `kind`:
---
---   call    one traced syscall of PID 1: `name`, `t` (trace timestamp,
---           seconds), `args` (the raw argument text), `path` (the
---           first quoted string, or for mount(2) the target), `ret`
---           (signed, or nil if its exit was never seen)
---   fs      an inotify event: `what` (comma-separated), `name`
---   seed    the seed landing: `size`, `inode`, `head`, `sd`, `populated`
---   at-start  a mount in PID 1's table when the witness armed:
---           `point`, `depth`, `opts`
---   gone    a mount that left PID 1's table: `point`, `batch`, `depth`,
---           `seed` (new|old|none, as it stood when the watcher looked)
---   changed a mount whose options changed: `point`, `batch`, `depth`,
---           `before`, `after`
---
--- `calls` is the call entries alone. A traced call's exit is paired
--- with the nearest enter of the same name before it: PID 1 is single
--- threaded, so its calls do not overlap.
function M.record(log)
    local entries, calls, open = {}, {}, {}
    for line in log:gmatch("[^\r\n]+") do
        local seq, rest = line:match("pt%-sw (%d+) (.*)$")
        if seq then
            seq = tonumber(seq)
            local entry
            local t, name, tail = rest:match("^trace%s+%S+%s+%[%d+%]%s+%S+%s+([%d%.]+):%s+sys_([%w_]+)(.*)$")
            if t then
                local ret = tail:match("^%s*%->%s*(0x%x+)")
                if ret then
                    local call = open[name]
                    if call then
                        call.ret = signed(ret)
                        open[name] = nil
                    end
                elseif tail:sub(1, 1) == "(" then
                    entry = { kind = "call", name = name, t = tonumber(t), args = tail }
                    if name == "mount" then
                        entry.path = tail:match('dir_name: %S+ "([^"]*)"')
                        entry.flags = tail:match("flags: (%w+)")
                    else
                        entry.path = tail:match('"([^"]*)"')
                    end
                    entry.newname = tail:match('newname: %S+ "([^"]*)"')
                    entry.fd = tail:match("%(fd: (%w+)")
                    entry.count = tail:match("count: (%w+)")
                    entry.cmd = tail:match("cmd: (%w+)")
                    calls[#calls + 1] = entry
                    open[name] = entry
                end
            else
                local what, fname = rest:match("^fs (%S+) (%S+) cookie=")
                if what then
                    entry = { kind = "fs", what = what, name = fname,
                              cookie = rest:match("cookie=(%d+)") }
                elseif rest:match("^seed landed") then
                    entry = {
                        kind = "seed",
                        size = tonumber(rest:match("size=(%d+)")),
                        inode = rest:match("inode=(%S+)"),
                        head = rest:match("head=(%x*)"),
                        sd = rest:match("sd=(%S+)"),
                        populated = rest:match("populated=(%S+)"),
                    }
                elseif rest:match("^mount at%-start ") then
                    local spoint, sdepth, sopts = rest:match("^mount at%-start (%S+) depth=(%d+) (%S+)")
                    entry = { kind = "at-start", point = spoint, depth = tonumber(sdepth),
                              opts = sopts }
                else
                    local point, batch, depth, seed = rest:match("^mount gone (%S+) batch=(%d+) depth=(%d+) seed=(%S+)")
                    if point then
                        entry = { kind = "gone", point = point, batch = tonumber(batch),
                                  depth = tonumber(depth), seed = seed }
                    else
                        local cpoint, cbatch, cdepth, before, after =
                            rest:match("^mount changed (%S+) batch=(%d+) depth=(%d+) (%S+) %-> (%S+)")
                        if cpoint then
                            entry = { kind = "changed", point = cpoint, batch = tonumber(cbatch),
                                      depth = tonumber(cdepth), before = before, after = after }
                        end
                    end
                end
            end
            if entry then
                entry.seq = seq
                entries[#entries + 1] = entry
            end
        end
    end
    return { entries = entries, calls = calls }
end

--- The traced calls named `name`, in order.
function M.calls(record, name)
    local out = {}
    for _, call in ipairs(record.calls) do
        if call.name == name then out[#out + 1] = call end
    end
    return out
end

--- The index in `record.calls` of the first call matching `pred`.
function M.index(record, pred)
    for i, call in ipairs(record.calls) do
        if pred(call) then return i end
    end
    return nil
end

--- The entries of one kind.
function M.entries(record, kind)
    local out = {}
    for _, entry in ipairs(record.entries) do
        if entry.kind == kind then out[#out + 1] = entry end
    end
    return out
end

--- A compact rendering of the calls, for failure messages.
function M.render(record)
    local parts = {}
    for _, call in ipairs(record.calls) do
        parts[#parts + 1] = string.format("%s(%s)=%s", call.name,
            call.path or call.fd or call.cmd or "", tostring(call.ret))
    end
    return table.concat(parts, " ")
end

local function hex_bytes(hex)
    local out = {}
    for pair in hex:gmatch("%x%x") do out[#out + 1] = tonumber(pair, 16) end
    return out
end

local function u16(b, at) return b[at + 1] | (b[at + 2] << 8) end
local function u32(b, at) return u16(b, at) | (u16(b, at + 2) << 16) end

local function sid_at(b, at)
    local count = b[at + 2]
    local authority = 0
    for i = 0, 5 do authority = (authority << 8) | b[at + 3 + i] end
    local parts = { "S", tostring(b[at + 1]), tostring(authority) }
    for i = 0, count - 1 do parts[#parts + 1] = tostring(u32(b, at + 8 + 4 * i)) end
    return table.concat(parts, "-"), 8 + 4 * count
end

--- A self-relative security descriptor, from hex, as
--- `{owner, group, aces = {{type, flags, mask, sid}, …}}`.
function M.decode_sd(hex)
    local b = hex_bytes(hex)
    assert(#b >= 20, "not a security descriptor: " .. tostring(hex))
    local sd = { aces = {} }
    local owner, group, dacl = u32(b, 4), u32(b, 8), u32(b, 16)
    if owner ~= 0 then sd.owner = sid_at(b, owner) end
    if group ~= 0 then sd.group = sid_at(b, group) end
    if dacl ~= 0 then
        local count = u16(b, dacl + 4)
        local at = dacl + 8
        for _ = 1, count do
            local size = u16(b, at + 2)
            sd.aces[#sd.aces + 1] = {
                type = b[at + 1], flags = b[at + 2], mask = u32(b, at + 4),
                sid = (sid_at(b, at + 8)),
            }
            at = at + size
        end
    end
    return sd
end

return M
