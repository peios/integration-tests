-- Helpers for the prelude chapter: building the files a test injects
-- into the initramfs at boot, and reading what came back on the console.
--
-- The profile (`profiles/prelude/`) bakes an initramfs holding real
-- prelude, dash, peiosutils, three staged hooks and the payload that
-- becomes the real root. A test that wants a different hook graph does
-- not rebuild it: it writes its own `hooks.seq.2` and its own hook
-- scripts through `vm:boot({files = ...})`, which the kernel unpacks over
-- the baked tree.
--
-- Everything a hook does is reported on the console as a `pt|` line (see
-- `profiles/prelude/fixtures/pt-hook.sh`), and prelude's own progress
-- lines are beside them, so the console log is the oracle for everything
-- that happens before the handoff — including for a boot that halts,
-- where the console text arrives in `vm:boot()`'s error.

local M = {}

--- Where prelude looks for its hook sequence, newest format first.
M.SEQ_DIR = "/system/prelude"
M.SEQ_V2 = M.SEQ_DIR .. "/hooks.seq.2"
M.SEQ_V1 = M.SEQ_DIR .. "/hooks.seq.1"
--- The unsuffixed path prelude still reads, outranked by every numbered one.
M.SEQ_LEGACY = "/hooks.seq"

--- Where a packaged hook lives, and so where an injected one is written.
M.HOOK_DIR = "/usr/libexec/prelude/hooks.d"

--- The hooks the profile bakes, by the bare name they report under.
M.STAGED = { topology = "pt-topology.sh", ["mount-root"] = "pt-mount-root.sh",
             late = "pt-late.sh" }

--- The exit codes prelude reads as something other than failure.
M.DECLINED = 69
M.DEFERRED = 75

--- The body of a scripted hook: it sources the profile's library and
--- reports itself, so an injected hook behaves exactly as a staged one
--- and answers to the same `pt.<name>=<spec>` command-line control.
---
--- `decl` is the metadata block, already rendered.
local function hook_body(name, decl)
    return table.concat({
        "#!/usr/bin/sh",
        decl,
        "set -eu",
        ". /fixtures/pt-hook.sh",
        "pt_scripted " .. name,
        "",
    }, "\n")
end

--- Render a hook's metadata block from a spec table. `nil` for a hook
--- that carries no block at all — which is a case worth testing, since
--- an undeclared hook is ordered after every declaring one.
local function decl_block(spec)
    if spec.no_metadata then
        return "# (no metadata block)"
    end
    local lines = { "# /// hook" }
    for _, key in ipairs({ "provides", "contributes", "requires", "after" }) do
        local caps = spec[key]
        if caps then
            local quoted = {}
            for i, c in ipairs(caps) do quoted[i] = string.format("%q", c) end
            lines[#lines + 1] = "# " .. key .. " = [" .. table.concat(quoted, ", ") .. "]"
        end
    end
    lines[#lines + 1] = "# ///"
    return table.concat(lines, "\n")
end

--- One stanza of a version-2 sequence.
local function seq_stanza(path, spec)
    local lines = { "hook " .. path }
    for _, key in ipairs({ "provides", "contributes", "requires", "after" }) do
        local caps = spec[key]
        if caps and #caps > 0 then
            lines[#lines + 1] = key .. " " .. table.concat(caps, " ")
        end
    end
    return table.concat(lines, "\n")
end

--- Build the `files` list for a boot: a hook graph, as scripts plus the
--- sequence that names them.
---
--- opts.hooks   map of bare name -> declaration table (`provides`,
---              `contributes`, `requires`, `after`, `no_metadata`,
---              `body` to replace the script entirely). Their order in
---              the sequence follows `opts.order` when given, else the
---              names sorted, so a test that cares about the order says
---              so and one that does not still gets a stable one.
--- opts.keep    bare file names of the profile's staged hooks to include
---              in the sequence as well, appended in the order given.
---              `pt-mount-root.sh` is the one most tests want: without a
---              hook that mounts a root, every boot halts.
--- opts.version sequence format to write (2 by default; 1 writes the
---              flat list, "legacy" writes the unsuffixed /hooks.seq).
--- opts.seq     replace the generated sequence body entirely — for the
---              malformed and unreadable cases.
--- opts.extra   further `{path=, content=, mode=}` entries to inject.
function M.files(opts)
    opts = opts or {}
    local files = {}
    local order = opts.order
    if not order then
        order = {}
        for name in pairs(opts.hooks or {}) do order[#order + 1] = name end
        table.sort(order)
    end

    local stanzas, flat = {}, {}
    for _, name in ipairs(order) do
        local spec = (opts.hooks or {})[name]
        local path = M.HOOK_DIR .. "/" .. name .. ".sh"
        files[#files + 1] = {
            path = path,
            content = spec.body or hook_body(name, decl_block(spec)),
            mode = 0x1ed, -- 0755: the execute bit is what makes it a program
        }
        stanzas[#stanzas + 1] = seq_stanza(path, spec)
        flat[#flat + 1] = path
    end
    for _, file in ipairs(opts.keep or {}) do
        local path = M.HOOK_DIR .. "/" .. file
        stanzas[#stanzas + 1] = "hook " .. path
        flat[#flat + 1] = path
    end

    local version = opts.version or 2
    local body = opts.seq
    if not body then
        if version == 2 then
            body = "hookseq 2\n" .. table.concat(stanzas, "\n") .. "\n"
        else
            body = "hookseq 1\n" .. table.concat(flat, "\n") .. "\n"
        end
    end
    local seq_path = M.SEQ_V2
    if version == 1 then
        seq_path = M.SEQ_V1
    elseif version == "legacy" then
        seq_path = M.SEQ_LEGACY
    elseif type(version) == "number" and version > 2 then
        seq_path = M.SEQ_DIR .. "/hooks.seq." .. version
    end
    files[#files + 1] = { path = seq_path, content = body }

    for _, extra in ipairs(opts.extra or {}) do
        files[#files + 1] = extra
    end
    return files
end

--- Every `pt|<hook>|...` line in a console log, decoded, in the order
--- they were printed. Each entry carries `hook` plus every field.
function M.marks(log)
    local out = {}
    for line in log:gmatch("pt|[^\n]*") do
        local fields, hook = {}, nil
        for part in line:gmatch("[^|]+") do
            if part == "pt" then
                -- the prefix
            elseif not hook then
                hook = part
            else
                local k, v = part:match("^([^=]+)=(.*)$")
                if k then fields[k] = v end
            end
        end
        if hook then
            fields.hook = hook
            out[#out + 1] = fields
        end
    end
    return out
end

--- The names of the hooks prelude said it was running, in order — one
--- entry per invocation, so a hook that deferred appears more than once.
function M.ran(log)
    local out = {}
    for path in log:gmatch("prelude: hook: ([^\n]+)") do
        out[#out + 1] = path:match("([^/]+)$")
    end
    return out
end

--- Boot a VM that is expected to halt, and return the console text from
--- the failure. Fails the test if the guest reaches an agent instead.
function M.boot_halts(t, vm, opts)
    local ok, err = pcall(function() vm:boot(opts) end)
    if ok then
        t:assert(false, "expected prelude to refuse this boot, but an agent came up")
        return ""
    end
    return tostring(err)
end

return M
