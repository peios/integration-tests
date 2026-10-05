-- Helpers for the peinit conformance testset.
--
-- The peinit profile boots a whole Peios: the kernel execs prelude out
-- of the real initramfs, live-boot assembles the root from the medium
-- this profile attaches, prelude chroots in and execs /bin/peinit2, and
-- peinit's phase-1.5 autorun starts the agent. Two things follow that
-- every test in the suite has to account for, and this module is where
-- they are accounted for once.
--
-- The first is that the agent answers EARLY. It is started from the
-- autorun queue, between phase 1 and phase 2, so a test that boots and
-- immediately reads the console sees a boot still in progress. `boot`
-- below waits for the phase it asks for.
--
-- The second is that the console is the only record of everything
-- before the agent existed — prelude, the hooks, phase 1 — and of
-- anything peinit does with a terminal a service owns. Reading it is
-- normal here rather than a fallback.

local M = {}

--- Console markers, so a test names a phase rather than a string.
M.marks = {
    -- prelude, before the handoff.
    prelude_banner = "prelude · initramfs · PID 1",
    handoff = "prelude: exec /bin/peinit2",
    -- peinit's own stages.
    banner = "peinit · real root · PID 1",
    phase1 = "peinit: phase1 starting",
    registryd = "peinit: phase1 registryd started",
    autoruns = "peinit: ran ",
    phase2_starting = "peinit: phase2 boot starting",
    phase2 = "peinit: phase2 boot complete",
}

--- How long a stage may take before a test calls the boot failed.
---
--- Generous, because these are real seconds on a real image and the
--- host may be running several VMs: a tight bound here would turn load
--- into a test failure, which is the least useful kind. A boot that is
--- genuinely broken fails on the assertion that follows, not on this.
M.STAGE_TIMEOUT = 60

--- Turn a table of root-relative paths into `vm:boot({files = …})`
--- entries the profile's `pt-stage.sh` hook copies into the root.
---
--- The image is built once and every test boots the same medium, so
--- this is the only way a test varies what peinit is handed. The files
--- go into the INITRAMFS, and the hook carries them across the handoff
--- before prelude chroots — which means they are in place before peinit
--- has run a single instruction.
---
---   peinit.stage({["lcl/policy/autorun.d/50-x.sh"] = {body, exec = true}})
---   peinit.stage({["lcl/etc/machine-id"] = "…"})
---
--- A value may be a string (the contents) or a table `{content, exec}`.
--- `exec` matters: under KACS the execute bit is the intrinsic "this is
--- executable" flag, so an autorun script staged without it is one
--- peinit refuses to spawn.
function M.stage(files)
    local out = {}
    for path, spec in pairs(files) do
        local content, exec
        if type(spec) == "table" then
            content, exec = spec[1] or spec.content, spec.exec
        else
            content = spec
        end
        out[#out + 1] = {
            path = "/fixtures/stage/" .. path:gsub("^/", ""),
            content = content,
            mode = exec and 0x1ed or 0x1a4,
        }
    end
    return out
end

--- A registry seed file, for `peinit.boot({files = …})`.
---
--- The image ships `10-apply-seeds.sh` in the autorun queue, which runs
--- `reg apply --dir /lcl/policy/autoapply.d --once-delete`. Autoruns are
--- Phase 1 step 7, and both path provisioning (step 8) and the Phase 2
--- read of the service graph come after — so a seed staged here is in
--- the registry before peinit looks at either. It sorts before
--- `10-provium-agent.sh`, so it has also applied before the agent this
--- test is talking to exists.
---
---   files = peinit.seed("pt-x", {
---       {path = [[Machine\System\Services\pt-x]], values = {
---           {name = "ImagePath", type = "sz", data = "/bin/true"},
---           {name = "Triggers", type = "multi", data = {"boot"}},
---       }},
---   })
---
--- Parent keys are not created implicitly: name every level, as the
--- image's own seeds do.
---
--- Returns a `files` table, so merge it rather than pass it whole when a
--- test also stages other files.
function M.seed(name, keys)
    local json = { keys = keys }
    return {
        ["lcl/policy/autoapply.d/" .. name .. ".reg"] = M.encode_json(json),
    }
end

--- Minimal JSON encoder — the guest's `reg apply` reads JSON and Lua has
--- no encoder in its standard library. Handles what a seed file needs:
--- strings, numbers, booleans, arrays and objects. An array is a table
--- with a `[1]`, or the empty table, which encodes as `[]`.
function M.encode_json(v)
    local t = type(v)
    if t == "nil" then return "null" end
    if t == "boolean" or t == "number" then return tostring(v) end
    if t == "string" then
        return '"' .. v:gsub('[\\"]', '\\%0'):gsub("\n", "\\n"):gsub("\r", "\\r") .. '"'
    end
    if t ~= "table" then error("encode_json: cannot encode a " .. t) end
    if v[1] ~= nil or next(v) == nil then
        local parts = {}
        for _, item in ipairs(v) do parts[#parts + 1] = M.encode_json(item) end
        return "[" .. table.concat(parts, ",") .. "]"
    end
    -- Sorted keys, so a staged seed is byte-identical run to run and a
    -- diff of two of them is about the content rather than about Lua's
    -- table order.
    local names = {}
    for k in pairs(v) do names[#names + 1] = k end
    table.sort(names)
    local parts = {}
    for _, k in ipairs(names) do
        parts[#parts + 1] = M.encode_json(tostring(k)) .. ":" .. M.encode_json(v[k])
    end
    return "{" .. table.concat(parts, ",") .. "}"
end

--- Stage one of the suite's own guest tools, as a `files` entry.
---
--- The image ships what a Peios ships, and some of what a test needs to
--- do has no tool there: nothing in it can write a Unix datagram with
--- ancillary data, for instance, so the whole notification protocol and
--- the fd store were unreachable until this existed. These tools are
--- small C programs in `tests/tools/`, compiled statically on the host
--- (the guest has no compiler) and staged into the boot that needs them.
---
---   local peinit = require("helpers.peinit")
---   local vm = peinit.boot({ files = peinit.tool("pt-notify") })
---   -- and then, in a service definition:
---   { name = "ImagePath", type = "sz", data = "/usr/bin/pt-notify" }
---
--- Merge it with `M.merge` when the test also stages seeds or scripts.
--- The build is cached and keyed on the source's mtime, so the first
--- caller in a run pays a sub-second compile and the rest pay nothing.
---
--- One trap, for `pt-notify` specifically. peinit authenticates a
--- notification by matching the sender's pid against a service's
--- current main job, and immediately after exec it has not yet
--- processed the launch that would record one — so the FIRST datagram a
--- service sends is routinely refused as an unauthenticated sender and
--- silently lost. Start every script with a `sleep 1` step:
---
---   { "sleep", "1", "send", "READY=1", "sleep", "300" }
---
--- Without it a Readiness=Notify service never reaches Active, and what
--- the test sees is a readiness timeout with nothing to explain it.
---
--- Staged rather than injected into the image: the tool is apparatus,
--- and a test that does not ask for it should not be booting a guest
--- that carries it.
---
--- `opts.signed` PIP-signs the tool at the TCB tier (tests/tools/sign.sh),
--- for one that must signal, trace or read the /proc of a TCB-signed
--- process: PID 1, authd, eventd. An unsigned tool is refused all three.
function M.tool(name, opts)
    local pipe = assert(io.popen("sh tests/tools/build.sh '" .. name .. "'", "r"))
    local path = pipe:read("*l")
    local ok = pipe:close()
    assert(ok and path and path ~= "",
        "peinit.tool: could not build `" .. name .. "` (see stderr)")
    if opts and opts.signed then
        local signed = path .. ".signed"
        assert(os.execute("sh tests/tools/sign.sh '" .. path .. "' '" .. signed .. "'"),
            "peinit.tool: could not PIP-sign `" .. name .. "` (see stderr)")
        path = signed
    end

    local file = assert(io.open(path, "rb"),
        "peinit.tool: built `" .. name .. "` but could not read " .. path)
    local bytes = file:read("*a")
    file:close()

    return { ["usr/bin/" .. name] = { bytes, exec = true } }
end

--- Merge several `files` tables into one.
function M.merge(...)
    local out = {}
    for _, set in ipairs({ ... }) do
        for k, v in pairs(set) do out[k] = v end
    end
    return out
end

--- Declare the file's peak: how many of this suite's VMs it has alive
--- at once, file-scope and test-scope together.
---
--- provium reserves a claim whole, up front, and every boot in the file
--- then draws from it, so a claimed file never queues mid-file. Without
--- one each boot reserves on its own, and a file that holds its
--- file-scope VM while it waits for a test-scope one is one of the
--- files that deadlocked a whole run once enough of them were dispatched
--- together (PEI-810). Count the peak carefully: a boot past the claim
--- fails at once rather than waiting.
---
--- opts:
---   memory_mib  per-VM memory the file boots with, in MiB (default
---               1024, matching `M.boot`'s "1G")
---   cpus        per-VM vCPUs (default 1, matching `M.boot`)
function M.claim(vms, opts)
    opts = opts or {}
    -- provium charges each boot its memory plus 100 MiB of VMM overhead.
    local per_vm_mib = (opts.memory_mib or 1024) + 100
    provium:claim({
        memory = vms * per_vm_mib * 1024 * 1024,
        cpus = vms * (opts.cpus or 1),
    })
end

--- Boot a peinit VM and wait until it has reached `stage`.
---
--- opts:
---   name    VM name (default "v")
---   stage   a key of `M.marks` to wait for (default "phase2")
---   memory  VM memory (default "1G" — a booted guest uses about
---           300 MiB, and the squashfs is read off the medium on demand
---           rather than held in RAM)
---   cpus    vCPU count (default 1, and this matters more than it looks)
---
--- One vCPU, not two, because provium admits a VM only while the total
--- DECLARED vCPUs fit the host's cores. At two apiece only a handful of
--- this testset's boots can run at once, so the files convoy and each
--- one blows its per-file time budget on a busy host. The same files at
--- one vCPU finish in a tenth of the time. peinit is not
--- compute-bound — what a test here waits for is a boot, and a boot is
--- waiting on I/O.
---
---   files   a table for `M.stage` — root-relative paths to place in
---           the root before peinit runs
---   append  kernel command-line tokens, appended after the image's own
---   boot    extra `vm:boot` opts, merged over the above
---   bridges provium bridges to attach the VM to before it boots, one
---           NIC each, in order
function M.boot(opts)
    opts = opts or {}
    local vm_opts = {
        memory = opts.memory or "1G",
        cpus = opts.cpus or 1,
    }
    local boot_opts = {}
    for k, v in pairs(opts.boot or {}) do boot_opts[k] = v end
    if opts.files then boot_opts.files = M.stage(opts.files) end
    if opts.append then boot_opts.kernel_cmdline_append = opts.append end
    local vm = provium:vm(opts.name or "v", "peinit", vm_opts)
    for _, br in ipairs(opts.bridges or {}) do br:attach(vm) end
    vm:boot(boot_opts)
    -- `opts.stage or "phase2"` would defeat `stage = false`, since false
    -- is falsy in Lua and `or` cannot tell it from an absent field. A
    -- test that passes false wants no wait at all — usually because it
    -- expects a boot that never reaches the stage.
    local stage = opts.stage
    if stage == nil then stage = "phase2" end
    if stage ~= false then
        local mark = M.marks[stage]
        assert(mark, "peinit.boot: no such stage `" .. tostring(stage) .. "`")
        vm:console():expect(mark, M.STAGE_TIMEOUT)
    end
    return vm
end

--- Boot a peinit VM that is expected NOT to reach an agent, and wait on
--- the console until `mark` appears.
---
--- Recovery mode runs no Phase 2 service, so the autorun that starts the
--- agent never runs and `vm:boot` fails once the agent timeout lapses.
--- That is the asserted outcome rather than a hang, so the timeout is
--- pulled right down: at the profile's 90 seconds a handful of these
--- would dominate the suite.
---
--- Returns the guest console text, taken from the error `vm:boot`
--- raises — which carries the tail of the console, and is the only
--- record such a boot leaves. The VM itself is not usable afterwards:
--- provium has given up on it, so `vm:console()` reads nothing and
--- cannot be written to. A test that wants to *drive* the recovery
--- shell has no route to it from here.
function M.boot_to_recovery(t, opts)
    opts = opts or {}
    local vm = provium:vm(opts.name or "rec", "peinit", {
        memory = opts.memory or "1G",
        cpus = opts.cpus or 1,
    })
    local boot_opts = { agent_timeout = opts.agent_timeout or 12 }
    for k, v in pairs(opts.boot or {}) do boot_opts[k] = v end
    if opts.files then boot_opts.files = M.stage(opts.files) end
    if opts.append then boot_opts.kernel_cmdline_append = opts.append end

    local ok, err = pcall(function() vm:boot(boot_opts) end)
    if ok then
        t:assert(false, "expected a boot that never reaches an agent, but one came up")
        return ""
    end
    return tostring(err)
end

--- Every line of the console log, with the CR/LF a serial console
--- produces stripped.
---
--- Matching on a raw `read_log` is a trap: the guest's console emits
--- CRLF, so a pattern anchored with `[^\n]` swallows the carriage
--- return and comparisons against a clean string fail for a reason
--- nothing in the output shows.
function M.lines(log)
    local out = {}
    for line in log:gmatch("[^\r\n]+") do
        out[#out + 1] = line
    end
    return out
end

--- The services peinit reported started, in the order it reported them.
function M.started_services(log)
    local names = {}
    for name in log:gmatch("peinit: service ([%w%-%._]+) started") do
        names[#names + 1] = name
    end
    return names
end

--- A self-relative security descriptor granting SYSTEM `mask`, hex
--- encoded for `reg set … hex:`.
---
--- `ServiceSecurity` and `ControlSecurity` are REG_BINARY values and the
--- registry has no SDDL form of either, so a test that wants to say
--- "SYSTEM may only query this" has to say it in bytes. The layout is
--- MS-DTYP's, which KACS uses verbatim (pkm/sd.h): a twenty-byte header
--- of revision, control and four offsets, then the owner and group SIDs,
--- then an ACL of one allow-ACE.
---
--- SYSTEM rather than a parameter because SYSTEM is the caller in every
--- test that uses this. The agent runs on peinit's own token, so a
--- descriptor naming SYSTEM is a descriptor about the caller — which is
--- what makes the whole rights surface reachable from a profile with one
--- principal on it. A second principal is not needed to observe a
--- denial; a descriptor that refuses the one we have is enough.
function M.system_descriptor_hex(mask)
    local sid = string.pack("BB", 1, 1) .. string.pack(">I2>I4", 0, 5)
        .. string.pack("<I4", 18)
    local ace = string.pack("<BBI2I4", 0, 0, 8 + #sid, mask) .. sid
    local acl = string.pack("<BBI2I2I2", 2, 0, 8 + #ace, 1, 0) .. ace
    -- DACL_PRESENT | SELF_RELATIVE.
    local header = string.pack("<BBI2I4I4I4I4", 1, 0, 0x8004,
        20, 20 + #sid, 0, 20 + 2 * #sid)
    return ((header .. sid .. sid .. acl):gsub(".",
        function(byte) return string.format("%02x", byte:byte()) end))
end

--- Wait until the boot has finished launching: no service of the
--- image's own has an operation in flight.
---
--- Every shutdown test needs this before it triggers, because of
--- PEI-826: a shutdown that lands while a service is still starting
--- takes PID 1 to recovery. The shutdown files each used to settle by
--- waiting for no image service to be in Starting — which misses a start
--- still *queued*, whose service is Inactive with an operation behind it
--- and becomes Starting a moment later. On an image with more services
--- than the suite was written against, that window was hit about one run
--- in three, and the test that tripped it failed waiting for a poweroff
--- from a machine already in the recovery shell. An operation is what a
--- queued start and a running one have in common, so that is what this
--- waits on.
---
--- Blind to this suite's own `pt-` services by default: some tests park
--- one in Starting on purpose, and waiting for it would deadlock.
--- `{all = true}` waits on those too, for a file whose own services must
--- also be past their boot start before it shuts down.
function M.settle(vm, opts)
    opts = opts or {}
    wait_until(function()
        local list = vm:run("svctl --json list").stdout
        local any = false
        for name in list:gmatch('"service":"([^"]+)"') do
            any = true
            if opts.all or not name:find("^pt%-") then
                local status = vm:run("svctl --json status " .. name).stdout
                if not status:find('"current_operation":null', 1, true) then return false end
            end
        end
        return any
    end, { timeout = opts.timeout or 90, interval = 0.5,
           desc = "every image service's boot operation to finish" })
end

--- Whether an `svctl` result was a denial: `"denied"` or `"allowed"`.
---
--- ACCESS_DENIED is peinit's answer to a failed check; any other answer
--- is the command running and succeeding or failing on its own merits.
--- The distinction matters: `reload` on an inactive Oneshot fails for a
--- reason that has nothing to do with the descriptor, and a test that
--- only read the exit code could not tell the two apart.
---
--- "Any other answer" has to be an answer, though, and this raises when
--- it is not one. svctl exits 0 on success and 1 when peinit answered
--- with an error; 69 means it never reached the socket and 127 that
--- there was no svctl to run. Reading those as "allowed" makes every
--- allowed-side assertion pass on a machine where peinit was never asked
--- anything — which is how control-rights.test.lua first went seven for
--- seven against an image that shipped no svctl (PEI-1071), and how the
--- chapter-4 descriptor files would have passed their "allowed" rows
--- against the same image without noticing.
function M.verdict(result)
    local out = result.stdout .. (result.stderr or "")
    if out:find("ACCESS_DENIED", 1, true) then
        return "denied"
    end
    assert(result.exit_code == 0 or result.exit_code == 1,
        "svctl got no answer from peinit (exit " .. tostring(result.exit_code) .. "): " .. out)
    return "allowed"
end

-- ---------------------------------------------------------------------------
-- A TCB-signed process, from the agent.
--
-- PID 1 (peinit), authd and eventd are PIP-signed at the TCB tier, and PIP
-- (PKM §3.7) refuses a process that does not dominate them every signal,
-- ptrace attach and /proc/<pid> read. The agent is signed at that tier
-- (tests/tools/sign.sh), but only its OWN operations carry it —
-- `vm:syscall`, `vm:read_file`, `vm:listdir` and a worker's syscalls. A
-- command run through `vm:run`/`vm:run_async`/`w:run` is a fresh, unsigned
-- exec and is refused: `kill 1`, `cat /proc/1/…`, `ls -l /proc/1/fd` and
-- `token … --pid 1` in the shell do not work against these processes.
-- Everything below goes through the agent instead.
--
-- `who` is a VM or a worker of one.
-- ---------------------------------------------------------------------------

local NR_KILL = 62

--- x86_64 signal numbers, by name.
M.SIG = {
    HUP = 1, INT = 2, QUIT = 3, ABRT = 6, KILL = 9, USR1 = 10, SEGV = 11,
    USR2 = 12, PIPE = 13, ALRM = 14, TERM = 15, CHLD = 17, CONT = 18,
    STOP = 19, TSTP = 20, WINCH = 28, PWR = 30,
}

local function signum(sig)
    if math.type(sig) == "integer" then return sig end
    local name = tostring(sig):upper():gsub("^SIG", "")
    return assert(M.SIG[name], "peinit: unknown signal " .. tostring(sig))
end

--- kill(2) from the agent: send `sig` (a number, or a name such as "TERM",
--- "KILL", "STOP", "CONT", with or without "SIG") to `pid`. Asserts
--- success unless `opts.check == false`. Returns the raw result (`ret`,
--- `errno`), which `ok()` turns into a boolean.
function M.signal(who, pid, sig, opts)
    local sys = require("helpers.sys")
    local r = who:syscall(NR_KILL, { args = { tonumber(pid), signum(sig) } })
    if not (opts and opts.check == false) then
        assert(r.ret == 0, "kill(" .. tostring(pid) .. ", " .. tostring(sig) .. "): "
            .. sys.errname(r.errno or 0))
    end
    return r
end

--- /proc/<pid>/<name> read by the agent (`"status"`, `"stat"`, `"comm"`,
--- `"fdinfo/7"`, `"task/1/children"` …), or nil and the error when it
--- cannot be read.
function M.proc(who, pid, name)
    local ok, text = pcall(who.read_file, who, "/proc/" .. tostring(pid) .. "/" .. name)
    if not ok then return nil, text end
    return text
end

--- readlink(2) of /proc/<pid>/<name> by the agent (`"exe"`, `"cwd"`,
--- `"fd/3"` …), or nil and the errno.
function M.proc_link(who, pid, name)
    return require("helpers.sys").readlink(who, "/proc/" .. tostring(pid) .. "/" .. name)
end

--- The pid (a string) of the first process whose comm is `name`, walking
--- /proc in the order the shell's `/proc/[0-9]*` glob does, or nil. The
--- agent reads every comm, so authd, eventd and PID 1 are found as well
--- as anything unsigned.
function M.pid_of_comm(who, name)
    local pids = {}
    for _, e in ipairs(who:listdir("/proc")) do
        local n = tostring(type(e) == "table" and e.name or e)
        if n:match("^%d+$") then pids[#pids + 1] = n end
    end
    table.sort(pids)
    for _, pid in ipairs(pids) do
        local comm = M.proc(who, pid, "comm")
        if comm and comm:gsub("%s+$", "") == name then return pid end
    end
    return nil
end

--- The descriptors process `pid` holds, read by the agent from
--- /proc/<pid>/fd: a map from fd number to its target, exactly as
--- `ls -l` shows it after the arrow ("/dev/console", "socket:[123]",
--- "anon_inode:[eventpoll]", "/x (deleted)"). A descriptor closed between
--- the listing and its read is left out.
function M.fds(who, pid)
    local base = "/proc/" .. tostring(pid) .. "/fd"
    local ok, names = pcall(who.listdir, who, base)
    assert(ok, "peinit.fds: cannot list " .. base .. ": " .. tostring(names))
    local out = {}
    for _, e in ipairs(names) do
        local n = type(e) == "table" and e.name or e
        if tostring(n):match("^%d+$") then
            local target = M.proc_link(who, pid, "fd/" .. n)
            if target then out[tonumber(n)] = target end
        end
    end
    return out
end

-- The privilege names `token` prints: the ABI header's (pkm/uapi/pkm/
-- token.h), `Privilege` suffix dropped, by bit. A present bit with no name
-- prints as `<privilege bit N>`, as the tool's does.
local PRIVILEGE_NAMES = {
    [2] = "SeCreateToken", [3] = "SeAssignPrimaryToken", [4] = "SeLockMemory",
    [5] = "SeIncreaseQuota", [7] = "SeTcb", [8] = "SeSecurity",
    [9] = "SeTakeOwnership", [10] = "SeLoadDriver", [11] = "SeSystemProfile",
    [12] = "SeSystemtime", [13] = "SeProfileSingleProcess",
    [14] = "SeIncreaseBasePriority", [17] = "SeBackup", [18] = "SeRestore",
    [19] = "SeShutdown", [20] = "SeDebug", [21] = "SeAudit",
    [23] = "SeChangeNotify", [24] = "SeRemoteShutdown", [28] = "SeManageVolume",
    [29] = "SeImpersonate", [32] = "SeRelabel", [35] = "SeCreateSymbolicLink",
}

-- The labels `token` gives a group's attributes, in its order.
local function group_labels(a)
    local out = {}
    if a & 0x01 ~= 0 then out[#out + 1] = "mandatory" end
    if a & 0x02 ~= 0 then out[#out + 1] = "default" end
    out[#out + 1] = (a & 0x04 ~= 0) and "enabled" or "disabled"
    if a & 0x08 ~= 0 then out[#out + 1] = "owner" end
    if a & 0x10 ~= 0 then out[#out + 1] = "deny-only" end
    if a & 0x20 ~= 0 then out[#out + 1] = "integrity" end
    if a & 0x40 ~= 0 then out[#out + 1] = "integrity-enabled" end
    if a & 0x20000000 ~= 0 then out[#out + 1] = "resource" end
    if a & 0xC0000000 == 0xC0000000 then out[#out + 1] = "logon-id" end
    return table.concat(out, ", ")
end

--- Process `pid`'s token, read by the agent: what `token show --pid PID
--- --raw --all` reports, as data.
---
---   principal   key -> value, the keys and values `token show` prints:
---               user, owner, primary_group, integrity (SIDs as
---               "S-1-5-18"), type ("Primary" | "Impersonation"),
---               impersonation_level, elevation_type, session_id (decimal)
---   groups      a list of { sid, attrs } in token order, `attrs` the
---               tool's label string ("mandatory, default, enabled")
---   privileges  a list of { name, attrs } in bit order, `attrs`
---               "enabled|disabled[, default][, used]"
---
--- `token` itself cannot do this for PID 1, authd or eventd: opening
--- another process's token is a process access, and PIP refuses it to a
--- caller that does not dominate the target.
function M.token(who, pid)
    local token = require("helpers.token")
    local sys = require("helpers.sys")
    local pidfd = assert(token.pidfd_open(who, tonumber(pid)),
        "peinit.token: pidfd_open(" .. tostring(pid) .. ")")
    local fd, err = token.open_process(who, pidfd, token.RIGHT.QUERY)
    who:syscall(sys.NR.close, pidfd)
    assert(fd, "peinit.token: kacs_open_process_token(" .. tostring(pid) .. "): "
        .. sys.errname(err or 0))

    local ok, out = pcall(function()
        local principal = {}
        local function sid_of(class)
            local p = token.query(who, fd, class)
            if p and #p >= 8 then return token.sid_string(p) end
        end
        principal.user = assert(sid_of(token.CLASS.USER), "peinit.token: no user SID")
        principal.owner = sid_of(token.CLASS.OWNER)
        principal.primary_group = sid_of(token.CLASS.PRIMARY_GROUP)
        principal.integrity = sid_of(token.CLASS.INTEGRITY_LEVEL)
        local ttype = token.query_u32(who, fd, token.CLASS.TYPE)
        if ttype then
            principal.type = ({ [1] = "Primary", [2] = "Impersonation" })[ttype] or tostring(ttype)
        end
        local level = token.query_u32(who, fd, token.CLASS.IMPERSONATION_LEVEL)
        if level then principal.impersonation_level = tostring(level) end
        local elevation = token.query_u32(who, fd, token.CLASS.ELEVATION_TYPE)
        if elevation then principal.elevation_type = tostring(elevation) end
        local stats = token.statistics(who, fd)
        if stats then principal.session_id = string.format("%d", stats.auth_id) end

        local groups = {}
        for _, g in ipairs(assert(token.groups(who, fd), "peinit.token: no groups")) do
            groups[#groups + 1] = { sid = token.sid_string(g.sid), attrs = group_labels(g.attributes) }
        end

        local p = assert(token.privileges(who, fd), "peinit.token: no privileges")
        local privileges = {}
        for bit = 0, 63 do
            local mask = 1 << bit
            if p.present & mask ~= 0 then
                local tags = { (p.enabled & mask ~= 0) and "enabled" or "disabled" }
                if p.default & mask ~= 0 then tags[#tags + 1] = "default" end
                if p.used & mask ~= 0 then tags[#tags + 1] = "used" end
                privileges[#privileges + 1] = {
                    name = PRIVILEGE_NAMES[bit] or ("<privilege bit " .. bit .. ">"),
                    attrs = table.concat(tags, ", "),
                }
            end
        end
        return { principal = principal, groups = groups, privileges = privileges }
    end)
    who:syscall(sys.NR.close, fd)
    if not ok then error(out, 0) end
    return out
end

local PRINCIPAL_ORDER = { "user", "owner", "primary_group", "integrity", "type",
    "impersonation_level", "elevation_type", "session_id" }

--- Process `pid`'s token as `token` prints it with `--raw`, read by the
--- agent (see `token`): `kind` is "show" (`token show --all`: the
--- principal block, then groups, then privileges), "user", "groups" or
--- "privs". Same sections, same two-space key column, same values — so a
--- parser written against the tool's output reads this unchanged.
function M.token_text(who, pid, kind)
    local tok = M.token(who, pid)
    local rows = {}
    local function section(s) rows[#rows + 1] = { section = s } end
    local function kv(k, v) rows[#rows + 1] = { k = k, v = v } end
    if kind == "show" then
        section("principal")
        for _, key in ipairs(PRINCIPAL_ORDER) do
            if tok.principal[key] then kv(key, tok.principal[key]) end
        end
    elseif kind == "user" then
        kv("user", tok.principal.user)
    end
    if kind == "show" or kind == "groups" then
        section("groups (" .. #tok.groups .. ")")
        for _, g in ipairs(tok.groups) do kv(g.sid, g.attrs) end
    end
    if kind == "show" or kind == "privs" then
        section("privileges (" .. #tok.privileges .. ")")
        for _, e in ipairs(tok.privileges) do kv(e.name, e.attrs) end
    end
    assert(#rows > 0, "peinit.token_text: unknown kind " .. tostring(kind))
    local width = 0
    for _, r in ipairs(rows) do if r.k and #r.k > width then width = #r.k end end
    local out = {}
    for _, r in ipairs(rows) do
        if r.section then
            out[#out + 1] = "\n[" .. r.section .. "]\n"
        else
            out[#out + 1] = "  " .. r.k .. string.rep(" ", width - #r.k) .. "  " .. r.v .. "\n"
        end
    end
    return table.concat(out)
end

--- `fds` as text, one `<fd> -> <target>` line each in fd order: the arrow
--- part of `ls -l /proc/<pid>/fd`, so a pattern written against that
--- output (`(%d+) %-> ([^\r\n]+)`, `%-> socket:`) matches unchanged.
function M.fd_listing(who, pid)
    local fds, order = M.fds(who, pid), {}
    for fd in pairs(fds) do order[#order + 1] = fd end
    table.sort(order)
    local lines = {}
    for _, fd in ipairs(order) do lines[#lines + 1] = fd .. " -> " .. fds[fd] end
    return table.concat(lines, "\n") .. (#lines > 0 and "\n" or "")
end

return M
