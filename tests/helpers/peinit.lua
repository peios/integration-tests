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
--- Staged rather than injected into the image: the tool is apparatus,
--- and a test that does not ask for it should not be booting a guest
--- that carries it.
function M.tool(name)
    local pipe = assert(io.popen("sh tests/tools/build.sh '" .. name .. "'", "r"))
    local path = pipe:read("*l")
    local ok = pipe:close()
    assert(ok and path and path ~= "",
        "peinit.tool: could not build `" .. name .. "` (see stderr)")

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

return M
