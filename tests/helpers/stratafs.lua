-- Building and mounting stratum stacks.
--
-- Nearly every stratafs case is "given these strata holding these
-- files, mount them and look at the merged view". Written out longhand
-- that is a dozen lines of mkdir and one hand-escaped option string
-- before the test says anything. This module reduces it to a
-- declaration, so what a case is *about* is the part that varies.
--
-- The mount options grammar is PKM §4.2.2. The escaping is implemented
-- here rather than in each test, because a test that escapes a path by
-- hand is testing its own string handling as much as the filesystem's.

local sys = require("helpers.sys")

local M = {}

--- A directory entry, for `populate`.
M.DIR = { kind = "dir" }

--- A symlink entry, for `populate`.
function M.symlink(target) return { kind = "symlink", target = target } end

-- §4.2.2: within a path, a literal `:`, `+`, `,` or `\` is escaped by a
-- preceding `\`, and those four are the entire escapable set.
local function escape(path)
    return (path:gsub("[\\:+,]", "\\%0"))
end

--- One stratum's `strata=` element: its path plus its flags.
---
--- Accepts `"/path"`, `{"/path", "create"}`, or
--- `{path = "/path", flags = {"create", "am"}}`.
local function element(stratum)
    if type(stratum) == "string" then return escape(stratum) end
    local path = stratum.path or stratum[1]
    local flags = stratum.flags
    if not flags then
        flags = {}
        for i = 2, #stratum do flags[#flags + 1] = stratum[i] end
    end
    local out = escape(path)
    for _, flag in ipairs(flags) do out = out .. "+" .. flag end
    return out
end

--- The `strata=` mount option for a stack, highest precedence first.
---
--- Exposed on its own because the parse-failure cases assert on option
--- strings that `mount` would never be asked to build.
function M.options(strata)
    local parts = {}
    for i, stratum in ipairs(strata) do parts[i] = element(stratum) end
    return "strata=" .. table.concat(parts, ":")
end

--- Create directories and files under `root`.
---
--- `entries` maps a relative path to its content: a string for a file,
--- `M.DIR` for a directory, `M.symlink(target)` for a symlink. Parent
--- directories are created as needed, so an entry may be written
--- without declaring the directories above it.
function M.populate(vm, root, entries)
    vm:mkdir(root, { parents = true })
    -- Sorted, so a directory declared explicitly is created before
    -- anything the iteration order might otherwise place inside it.
    local paths = {}
    for path in pairs(entries or {}) do paths[#paths + 1] = path end
    table.sort(paths)
    for _, path in ipairs(paths) do
        local entry = entries[path]
        local full = root .. "/" .. path
        local parent = full:match("^(.*)/[^/]*$")
        if parent and parent ~= "" then vm:mkdir(parent, { parents = true }) end
        if entry == M.DIR then
            vm:mkdir(full, { parents = true })
        elseif type(entry) == "table" and entry.kind == "symlink" then
            local r = sys.symlink(vm, entry.target, full)
            assert(r.ret == 0, "symlink " .. full .. ": " .. sys.errname(r.errno))
        else
            vm:write_file(full, entry)
        end
    end
    return root
end

--- Mount a stratum stack. Returns the mount's path.
---
--- `spec.at` is the mount point (created if absent) and `spec.strata`
--- the stack, highest precedence first. `spec.flags` are generic
--- mount(2) flags. Raises on failure, naming the errno — a case that
--- expects a refusal should call `M.try_mount` instead.
function M.mount(vm, spec)
    local r = M.try_mount(vm, spec)
    assert(r.ret == 0,
        "mount " .. spec.at .. ": " .. sys.errname(r.errno) ..
        " (" .. M.options(spec.strata) .. ")")
    return spec.at
end

--- Mount without asserting, for the cases whose subject is the refusal.
---
--- `spec.data` overrides the generated option string outright, which is
--- what the parse-failure cases need: they assert on strings the
--- builder would not produce.
function M.try_mount(vm, spec)
    vm:mkdir(spec.at, { parents = true })
    return sys.mount(vm, {
        source = "stratafs",
        target = spec.at,
        fstype = "stratafs",
        flags  = spec.flags,
        data   = spec.data or M.options(spec.strata),
    })
end

-- Mutating the merged view without asserting.
--
-- `vm:write_file` raises, which is right for a case whose subject is
-- something else; a case whose subject *is* the refusal needs the
-- errno and needs to know which call produced it. Routing happens at
-- the write and not at the open (§4.5.1), so these are deliberately
-- two calls and report which one failed.

--- Write to an existing name. Returns `true`, or `nil, errno, stage`.
function M.try_write(vm, path, data)
    local fd, errno = sys.open(vm, path, sys.O.WRONLY)
    if not fd then return nil, errno, "open" end
    local r = sys.write(vm, fd, data)
    sys.close(vm, fd)
    if r.ret < 0 then return nil, r.errno, "write" end
    return true
end

--- Create a name that does not exist. Returns `true`, or `nil, errno`.
function M.try_create(vm, path, data)
    local flags = sys.O.WRONLY | sys.O.CREAT | sys.O.EXCL
    local fd, errno = sys.open(vm, path, flags, tonumber("644", 8))
    if not fd then return nil, errno end
    if data and #data > 0 then
        local r = sys.write(vm, fd, data)
        if r.ret < 0 then sys.close(vm, fd) return nil, r.errno end
    end
    sys.close(vm, fd)
    return true
end

--- Unmount, ignoring a mount that is already gone.
function M.umount(vm, at) return sys.umount(vm, at) end

--- A whole scenario: strata built and populated, then mounted.
---
--- `layers` is a **sequence**, highest precedence first — the same
--- order `strata=` takes, so the declaration reads as the stack does.
--- Each layer is named, and its name becomes both a directory under a
--- scratch root of its own and the key to reach it afterwards:
---
---     local s = stratafs.scenario(vm, "copy-up-owner", {
---         { name = "upper", flags = { "create" } },
---         { name = "lower", flags = { "ro" }, entries = { f = "original" } },
---     })
---     s.at            -- the mount point
---     s.path.lower    -- that stratum's directory on the host fs
---     s:join("f")     -- a path inside the merged view
---
--- Returns a table carrying those, plus `release()` to unmount. Pass
--- `opts.mount = false` to build the strata without mounting, which is
--- what the mount-admission cases want.
function M.scenario(vm, name, layers, opts)
    opts = opts or {}
    local root = (opts.root or "/stratafs") .. "/" .. name
    local scenario = { root = root, at = root .. "/mnt", path = {} }

    local strata = {}
    for i, layer in ipairs(layers) do
        assert(layer.name, "layer " .. i .. " has no name")
        local path = root .. "/" .. layer.name
        M.populate(vm, path, layer.entries)
        scenario.path[layer.name] = path
        strata[i] = { path = path, flags = layer.flags }
    end
    scenario.strata = strata

    if opts.mount ~= false then
        M.mount(vm, { at = scenario.at, strata = strata, flags = opts.flags })
    end

    function scenario.release() M.umount(vm, scenario.at) end
    --- A path inside the merged view: `s:join("d", "f")`.
    function scenario:join(...) return self.at .. "/" .. table.concat({ ... }, "/") end
    --- A path inside one stratum: `s:in_stratum("lower", "f")`.
    function scenario:in_stratum(layer, ...)
        local base = assert(self.path[layer], "no stratum named " .. layer)
        local rest = table.concat({ ... }, "/")
        return rest == "" and base or (base .. "/" .. rest)
    end
    return scenario
end

--- A scenario for the duration of one function, always unmounted.
---
--- The test framework has no per-test cleanup hook, so a case that
--- mounts and then fails an assertion would leave the mount behind.
--- Scoping it here means every case is unmounted whether it passed or
--- raised, and the raise still propagates — the runner has already
--- recorded the failure by then.
---
---     stratafs.with(vm, "copy-up-owner", {
---         { name = "upper", flags = { "create" } },
---         { name = "lower", flags = { "ro" }, entries = { f = "x" } },
---     }, function(s)
---         ...
---     end)
function M.with(vm, name, layers, fn, opts)
    local scenario = M.scenario(vm, name, layers, opts)
    local ok, err = pcall(fn, scenario)
    scenario.release()
    if not ok then error(err, 0) end
    return scenario
end

return M
