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
    -- The guest console is CRLF, so the carriage return has to come out
    -- of the line before the last field is split off it.
    for line in log:gmatch("pt|[^\r\n]*") do
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
    -- `[^\r\n]` and not `[^\n]`: the console is CRLF, and a trailing
    -- carriage return would ride along on every name.
    for path in log:gmatch("prelude: hook: ([^\r\n]+)") do
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

--- The scheduler's stuck diagnosis, decoded: a map from a hook's file
--- name to the reason prelude gave for it, taken from the indented
--- `  <path>: <why>` lines under `hooks cannot proceed:`.
---
--- Those continuation lines are the only ones that begin with two spaces
--- and a slash — prelude's own lines carry a `[ TAG ] prelude: ` prefix
--- and a hook's report begins `pt|` — so this cannot pick up anything
--- else, and it reads a console log truncated at the head just as well,
--- since the diagnosis is the last thing before the halt.
function M.stuck_reasons(text)
    local out = {}
    for line in text:gmatch("[^\r\n]+") do
        local path, why = line:match("^  (/%S+): (.+)$")
        if path then out[path:match("([^/]+)$")] = why end
    end
    return out
end

--- How many times a scripted hook ran this boot, by its bare `pt` name.
---
--- Read from the `pass=` field of its LAST report rather than by counting
--- reports: the counter lives in the initramfs and survives the fresh
--- process each retry gets, so the final one is the total even when the
--- head of the console log has been truncated away — which is the usual
--- case for a boot that halted.
function M.invocations(text, hook)
    local n = 0
    for _, mark in ipairs(M.marks(text)) do
        if mark.hook == hook and mark.pass then n = tonumber(mark.pass) end
    end
    return n
end

--- The body of a hook that mounts the real root exactly as the profile's
--- own `pt-mount-root.sh` does — a tmpfs on `/mnt/rootfs`, seeded so KACS
--- lets anything touch it, with the staged payload copied in — and then
--- runs `after`, a shell fragment of the test's own.
---
--- That fragment is how a test shapes what prelude will find on the far
--- side of the hooks: an init at a different path, a root missing the
--- `sys` mountpoint the handoff moves onto, a directory in the initramfs
--- the cleanup walk cannot remove. Everything after the hooks is
--- prelude's alone, so the only way to steer it is to change what the
--- hooks leave behind.
---
--- The hook carries an empty metadata block and no declarations, so it is
--- ready on the first pass and runs on its own.
function M.root_hook(name, after)
    return table.concat({
        "#!/usr/bin/sh",
        "# /// hook",
        "# ///",
        "set -eu",
        ". /fixtures/pt-hook.sh",
        "pt_gate " .. name,
        "mount -t tmpfs tmpfs /mnt/rootfs",
        "seed-sd /mnt/rootfs",
        "cp -a /fixtures/rootfs/. /mnt/rootfs/",
        after or "",
        "pt_mark " .. name .. " outcome=satisfied",
        "exit 0",
        "",
    }, "\n")
end

-- mkirf, host-side ---------------------------------------------------------
--
-- mkirf is not a guest program: it reads an initramfs source tree on the
-- build host and writes the cpio a kernel later unpacks. So its cases
-- build a fixture tree in a temporary directory, run the real binary over
-- it, and read back what came out — no VM and no boot. That is also the
-- right seam. mkirf ships in peiosutils and prelude in its own package,
-- and `/system/prelude/hooks.seq.<n>` is the contract between them: these
-- helpers assert the writer's half of it, the rest of the chapter the
-- reader's.

--- The hook directories, relative to a source tree's root, highest
--- precedence first — mkirf's own `HOOK_DIRS`.
M.SRC_HOOKS_LCL = "lcl/libexec/prelude/hooks.d"
M.SRC_HOOKS_USR = "usr/libexec/prelude/hooks.d"
M.SRC_HOOKS_LEGACY = "hooks"

--- Where mkirf injects the generated sequences, relative to that root.
M.SRC_SEQ_DIR = "system/prelude"

local function shquote(s)
    return "'" .. (tostring(s):gsub("'", [['\'']])) .. "'"
end

--- Run a host command, returning its exit status and everything it wrote
--- to the stream(s) the caller left connected. This is the only place in
--- the chapter that runs anything outside a guest.
local function sh(cmd)
    local pipe = assert(io.popen(cmd, "r"))
    local out = pipe:read("a") or ""
    local ok, how, code = pipe:close()
    if how == "signal" then return 128 + (code or 0), out end
    if code == nil then code = ok and 0 or 1 end
    return code, out
end

--- The mkirf under test: the peiosutils applet an image actually carries,
--- found exactly as `profiles/prelude/build.sh` finds it — `$PT_MKIRF`,
--- then a repository build, then whatever is on PATH.
local function mkirf_binary()
    local from_env = os.getenv("PT_MKIRF")
    if from_env and from_env ~= "" then return from_env end
    local repo = (_PROVIUM_SOURCE_PATH or ""):match("^(.*)/tests/")
    if repo then
        for _, rel in ipairs({ "/../peiosutils/target/release/mkirf",
                               "/../peiosutils/target/debug/mkirf" }) do
            local f = io.open(repo .. rel, "r")
            if f then
                f:close()
                return repo .. rel
            end
        end
    end
    return "mkirf"
end

local function write_host_file(path, content, mode)
    sh("mkdir -p " .. shquote(path:match("^(.*)/[^/]*$") or "."))
    local f = assert(io.open(path, "w"))
    f:write(content)
    f:close()
    if mode then sh("chmod " .. mode .. " " .. shquote(path)) end
end

local function read_host_file(path)
    local f = io.open(path, "r")
    if not f then return nil end
    local content = f:read("a")
    f:close()
    return content
end

--- A hook script for a fixture tree: a shebang, the rendered metadata
--- block, and a body that does nothing. `spec` is the same declaration
--- table `M.files` takes, so a hook reads the same whether it is packed
--- by mkirf or injected into a boot.
function M.hook_script(spec)
    return table.concat({ "#!/usr/bin/sh", decl_block(spec), "exit 0", "" }, "\n")
end

--- Build a fixture initramfs source tree and run the real mkirf over it.
---
--- opts.hooks  map of path (relative to the tree root) -> hook. A table is
---             rendered into a metadata block by the same renderer the
---             injected guest hooks use; a string is the script text
---             verbatim, which is how the malformed cases are written.
--- opts.files  list of `{path=, content=, mode=}`, relative to the root.
--- opts.dirs   list of directories to create empty.
--- opts.links  list of `{path=, target=}` symlinks.
--- opts.init   false to leave the tree without its executable `init`.
--- opts.args   extra arguments, appended to the mkirf call verbatim.
---
--- The result:
---   status     mkirf's exit status — 0 built, 1 an operational failure
---              including an unresolvable hook set, 2 a usage error
---   output     everything it printed on either stream: the warnings, and
---              the diagnosis when it refused
---   seq1/seq2  the two generated sequence files, verbatim, or nil
---   listing    `cpio -tv` over the image — the modes, ownership and
---              timestamps the ARCHIVE records, which is not what
---              unpacking under a non-root umask would show
---   src        the source tree, `unpacked` the extracted image, and
---              `archive` the image itself, for a case that wants to look
---              further; `res:cleanup()` removes all three
---
--- Packed with gzip rather than mkirf's zstd default so the archive reads
--- back with zcat, as the prelude profile's own build does.
function M.mkirf(opts)
    opts = opts or {}
    local scratch = os.getenv("TMPDIR") or "/tmp"
    sh("mkdir -p " .. shquote(scratch))
    local _, dir = sh("mktemp -d " .. shquote(scratch .. "/mkirf-conformance.XXXXXXXX"))
    dir = dir:gsub("%s+$", "")
    assert(dir ~= "", "no temporary directory for the fixture tree (is $TMPDIR writable?)")
    local src, archive = dir .. "/src", dir .. "/image.cpio.gz"

    sh("mkdir -p " .. shquote(src))
    if opts.init ~= false then
        -- A tree with no executable `init` is one mkirf refuses, so every
        -- fixture carries one unless the case is about its absence.
        write_host_file(src .. "/init", "#!/usr/bin/sh\nexec /bin/true\n", "0755")
    end
    for _, d in ipairs(opts.dirs or {}) do
        sh("mkdir -p " .. shquote(src .. "/" .. d))
    end
    for path, hook in pairs(opts.hooks or {}) do
        write_host_file(src .. "/" .. path,
            type(hook) == "string" and hook or M.hook_script(hook), "0755")
    end
    for _, file in ipairs(opts.files or {}) do
        write_host_file(src .. "/" .. file.path, file.content, file.mode)
    end
    for _, link in ipairs(opts.links or {}) do
        local at = src .. "/" .. link.path
        sh("mkdir -p " .. shquote(at:match("^(.*)/[^/]*$") or "."))
        sh("ln -sfn " .. shquote(link.target) .. " " .. shquote(at))
    end

    local status, output = sh(table.concat({
        shquote(mkirf_binary()), "--compress", "gzip",
        shquote(src), shquote(archive), opts.args or "", "2>&1",
    }, " "))

    local res = { status = status, output = output,
                  dir = dir, src = src, archive = archive }
    if status == 0 then
        local unpacked = dir .. "/unpacked"
        sh("mkdir -p " .. shquote(unpacked))
        sh("zcat " .. shquote(archive) .. " | (cd " .. shquote(unpacked)
            .. " && cpio -idm) >/dev/null 2>&1")
        res.unpacked = unpacked
        res.seq1 = read_host_file(unpacked .. "/" .. M.SRC_SEQ_DIR .. "/hooks.seq.1")
        res.seq2 = read_host_file(unpacked .. "/" .. M.SRC_SEQ_DIR .. "/hooks.seq.2")
        local _, listing = sh("zcat " .. shquote(archive) .. " | cpio -tv 2>/dev/null")
        res.listing = listing
    end
    function res:cleanup()
        sh("rm -rf " .. shquote(self.dir))
    end
    return res
end

--- One entry of a `cpio -tv` listing, by its path in the archive:
--- `{mode, owner, group, time, name, target}`. nil when the archive has
--- no such entry.
function M.archive_entry(listing, name)
    for line in (listing or ""):gmatch("[^\n]+") do
        local mode, _, owner, group, _, mon, day, clock, rest = line:match(
            "^(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s+(.+)$")
        if rest then
            local path = rest:match("^(.-) %-> ") or rest
            if path == name then
                return { mode = mode, owner = owner, group = group,
                         time = mon .. " " .. day .. " " .. clock,
                         name = path, target = rest:match(" %-> (.+)$") }
            end
        end
    end
    return nil
end

return M
