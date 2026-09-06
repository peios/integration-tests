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

--- Boot a peinit VM and wait until it has reached `stage`.
---
--- opts:
---   name    VM name (default "v")
---   stage   a key of `M.marks` to wait for (default "phase2")
---   memory  VM memory (default "2G" — the initramfs alone is ~90 MiB,
---           and the squashfs page cache and the overlay's tmpfs upper
---           both live in RAM on top of it)
---   cpus    vCPU count (default 2)
---   files   a table for `M.stage` — root-relative paths to place in
---           the root before peinit runs
---   append  kernel command-line tokens, appended after the image's own
---   boot    extra `vm:boot` opts, merged over the above
function M.boot(opts)
    opts = opts or {}
    local vm_opts = {
        memory = opts.memory or "2G",
        cpus = opts.cpus or 2,
    }
    local boot_opts = {}
    for k, v in pairs(opts.boot or {}) do boot_opts[k] = v end
    if opts.files then boot_opts.files = M.stage(opts.files) end
    if opts.append then boot_opts.kernel_cmdline_append = opts.append end
    local vm = provium:vm(opts.name or "v", "peinit", vm_opts)
    vm:boot(boot_opts)
    local stage = opts.stage or "phase2"
    if stage ~= false then
        local mark = M.marks[stage]
        assert(mark, "peinit.boot: no such stage `" .. tostring(stage) .. "`")
        vm:console():expect(mark, M.STAGE_TIMEOUT)
    end
    return vm
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
