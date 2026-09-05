-- Binary signature verification (PKM §3.6), from inside a kernel-only
-- guest.
--
-- Three things this module knows.
--
-- **How to make an executable.** The guest ships one binary,
-- `/sbin/provium-agent`, and nothing else can be exec'd — but the
-- signing hooks only fire on a file the ELF loader actually accepts, so
-- a bare ELF header (helpers/psb.write_elf) never reaches them: the
-- loader rejects it before `begin_new_exec()`, which is where
-- `bprm_creds_from_file` — and with it the whole signing path — runs.
-- `M.elf()` emits a complete, loadable, 129-byte static ELF whose only
-- instruction is `exit(0)`, so a case can exec a file it authored byte
-- by byte.
--
-- **How to author signing material.** `M.craft()` appends a signature
-- blob, a section-name string table and a section header table to that
-- binary and points the ELF header at them. The loader reads only
-- program headers, so an arbitrarily malformed section header table
-- leaves the file perfectly executable — which is exactly what §3.6's
-- "commits the ELF path" cases need: the file has to *run* for the
-- verdict to be observable.
--
-- **How to read the verdict.** No syscall reports a file's signing
-- state. The kernel's own tracepoints do: `kacs:kacs_signing_probe`
-- names which branch of the material lookup fired,
-- `kacs:kacs_signing_verify` gives the trust verdict and the source it
-- came from, and `kacs:kacs_exec` carries the staged PIP tier and the
-- commit. `M.trace()` records a set of them across one operation and
-- returns them parsed.
--
-- Nothing here can produce a *valid* signature: signing needs an
-- ML-DSA-65 private key, the kernel holds none, and the guest has no
-- signing tool. Every case is therefore about what happens on the way
-- to "unsigned" — which is most of §3.6.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local hooks = require("helpers.hooks")

local M = {}

-- From uapi and kacs/signing.h.
M.BLOB_LEN = 3310
M.SIGNATURE_LEN = 3309
M.VERSION = 0x01
M.XATTR = "security.peios.sig"
M.SECTION = ".peios.sig"
M.PUBLIC_KEY_LEN = 1952
M.KEY_ENTRY_LEN = 1960

-- kacs_signing_probe / kacs_signing_verify `source` values.
M.SOURCE = { NONE = 0, ELF = 1, XATTR = 2 }

-- PIP tiers §3.6 names.
M.PIP_TYPE = { NONE = 0, ISOLATED = 1024, PROTECTED = 512 }
M.PIP_TRUST = { NONE = 0, PEIOS_TCB = 8192 }

-- ELF constants the crafting uses.
M.ELFCLASS64, M.ELFCLASS32 = 2, 1
M.ELFDATA2LSB, M.ELFDATA2MSB = 1, 2
M.EV_CURRENT = 1
M.SHT_PROGBITS, M.SHT_STRTAB, M.SHT_NOBITS = 1, 3, 8

-- `exit(0)`: mov eax,60 / xor edi,edi / syscall.
M.CODE_EXIT = "\xb8\x3c\x00\x00\x00\x31\xff\x0f\x05"
-- `for(;;) pause();`: mov eax,34 / syscall / jmp -9.
M.CODE_PAUSE = "\xb8\x22\x00\x00\x00\x0f\x05\xeb\xf7"

local EHDR_LEN, PHDR_LEN, SHDR_LEN = 64, 56, 64
local LOAD_VADDR = 0x400000

--- A 3310-byte signature blob: the version byte §3.6 requires, then
--- filler. It never verifies against any key — that is the point.
function M.blob(opts)
    opts = opts or {}
    return string.char(opts.version or M.VERSION)
        .. string.rep(opts.fill or "\xAA", (opts.len or M.BLOB_LEN) - 1)
end

--- The ELF header. `o` overrides the fields the §3.6 structural cases
--- vary: `class`, `data`, `ei_version`, `shoff`, `shentsize`, `shnum`,
--- `shstrndx`.
local function ehdr(o, code_len)
    return "\x7fELF"
        .. string.char(o.class or M.ELFCLASS64, o.data or M.ELFDATA2LSB,
                       o.ei_version or M.EV_CURRENT)
        .. string.rep("\0", 9)
        .. string.pack("<I2I2I4I8I8I8I4I2I2I2I2I2I2",
            2,                                     -- e_type = ET_EXEC
            0x3e,                                  -- e_machine = EM_X86_64
            1,                                     -- e_version
            LOAD_VADDR + EHDR_LEN + PHDR_LEN,      -- e_entry
            EHDR_LEN,                              -- e_phoff
            o.shoff or 0,                          -- e_shoff
            0, EHDR_LEN, PHDR_LEN, 1,              -- e_flags, sizes, e_phnum
            o.shentsize or 0, o.shnum or 0, o.shstrndx or 0)
        .. string.pack("<I4I4I8I8I8I8I8I8",
            1, 5, 0, LOAD_VADDR, LOAD_VADDR,       -- PT_LOAD, R|X, whole file
            EHDR_LEN + PHDR_LEN + code_len,
            EHDR_LEN + PHDR_LEN + code_len, 0x1000)
end

local function shdr(o)
    return string.pack("<I4I4I8I8I8I8I4I4I8I8",
        o.name or 0, o.type or 0, 0, 0,
        o.offset or 0, o.size or 0, 0, 0, 0, 0)
end

--- A minimal loadable static ELF that exits 0 (or runs `code`).
function M.elf(code)
    code = code or M.CODE_EXIT
    return ehdr({}, #code) .. code
end

--- A loadable ELF carrying a section header table, for the §3.6 lookup
--- cases. Every field a case might want to break is an override:
---
---   `code`            the payload (default `exit(0)`)
---   `class` `data` `ei_version`   e_ident bytes
---   `shoff` `shentsize` `shnum` `shstrndx`  header-table geometry
---   `sec_name`        the section's name (default ".peios.sig")
---   `sec_type` `sec_size` `sec_offset`      the signature section
---   `strtab_offset` `strtab_size`           the name string table
---   `blob_version`    the blob's first byte
---   `no_sections`     emit no section header table at all (e_shnum 0)
---
--- Layout: [ehdr][phdr][code][blob][strtab][shdrs]. The loader reads
--- only the program header, so everything after `code` is invisible to
--- it however malformed it is.
function M.craft(o)
    o = o or {}
    local code = o.code or M.CODE_EXIT
    local blob = M.blob({ version = o.blob_version })
    local name = o.sec_name or M.SECTION
    local strtab = "\0" .. name .. "\0"
    local sig_off = EHDR_LEN + PHDR_LEN + #code
    local str_off = sig_off + #blob
    local sh_off = str_off + #strtab
    local base = { class = o.class, data = o.data, ei_version = o.ei_version }

    if o.no_sections then
        base.shnum, base.shentsize, base.shstrndx = 0, SHDR_LEN, 0
        return ehdr(base, #code) .. code .. blob .. strtab
    end

    base.shoff = o.shoff or sh_off
    base.shentsize = o.shentsize or SHDR_LEN
    base.shnum = o.shnum or 3
    base.shstrndx = o.shstrndx or 1
    local shdrs = shdr({})
        .. shdr({ name = 0, type = M.SHT_STRTAB,
                  offset = o.strtab_offset or str_off,
                  size = o.strtab_size or #strtab })
        .. shdr({ name = 1, type = o.sec_type or M.SHT_PROGBITS,
                  offset = o.sec_offset or sig_off,
                  size = o.sec_size or M.BLOB_LEN })
    return ehdr(base, #code) .. code .. blob .. strtab .. shdrs
end

-- The workspace ------------------------------------------------------------

--- A FACS-managed directory under `/` whose descriptor grants
--- everything, for a §3.6 file to live in.
function M.workspace(vm, name)
    local at = "/sig-" .. name
    vm:mkdir(at, { parents = true })
    kacs.set_sd(vm, at, kacs.grant(kacs.ALL_RIGHTS))
    return at
end

--- Write `bytes` at `path`, make it executable to everyone, and
--- optionally stamp `security.peios.sig`. Returns the path.
---
--- `opts.rights` narrows the descriptor (default: every file right),
--- which is how the FACS-before-signing and xattr-hook cases produce a
--- caller the file's own descriptor decides.
function M.place(vm, path, bytes, opts)
    opts = opts or {}
    vm:write_file(path, bytes)
    sys.chmod(vm, path, tonumber("755", 8))
    if opts.xattr then
        local r = sys.setxattr(vm, path, M.XATTR, opts.xattr, 0)
        assert(r.ret == 0, "setxattr " .. M.XATTR .. ": " .. sys.errname(r.errno))
    end
    kacs.set_sd(vm, path, kacs.grant(opts.rights or kacs.ALL_RIGHTS))
    return path
end

-- Tracepoints --------------------------------------------------------------

local function trace_write(vm, rel, data)
    local fd, errno = sys.open(vm, hooks.TRACEFS_AT .. "/" .. rel, sys.O.WRONLY)
    assert(fd, "open tracefs/" .. rel .. ": " .. sys.errname(errno or 0))
    local r = sys.write(vm, fd, data)
    sys.close(vm, fd)
    assert(r.ret == #data, "write tracefs/" .. rel .. ": " .. sys.errname(r.errno))
end

--- One decoded tracepoint line: `event` plus its `reason=`-style fields
--- as strings, and `num(field)` for the numeric ones.
local Event = {}
Event.__index = Event
function Event:num(field)
    local v = self[field]
    if not v then return nil end
    return tonumber(v) or tonumber(v, 16)
end

--- A `a:b` field — `exec_pip`, `caller_pip`, `target_pip` — as two
--- numbers, or nil when the field is absent.
function Event:pair(field)
    local v = self[field]
    if not v then return nil end
    local a, b = v:match("^(%d+):(%d+)$")
    if not a then return nil end
    return tonumber(a), tonumber(b)
end

--- Parse the tracefs lines this module's events produce. Every one of
--- them prints `reason=` first, which is what anchors the split between
--- the ring's own prefix and the event body.
function M.parse(lines)
    local out = {}
    for _, line in ipairs(lines or {}) do
        local name, body = line:match("([%a_]+): (reason=.+)$")
        if name then
            local ev = setmetatable({ event = name, line = line }, Event)
            for k, v in body:gmatch("([%a_]+)=(%S+)") do ev[k] = v end
            out[#out + 1] = ev
        end
    end
    return out
end

--- Record `events` (tracefs names, e.g. "kacs/kacs_exec") across `fn`
--- and return everything the ring caught, parsed.
---
--- The ring is cleared before `fn` runs and every event is disabled
--- before it is read, so nothing another thread does afterwards lands
--- in the result.
function M.trace(vm, events, fn)
    local ok, err = hooks.trace_start(vm, events[1])
    assert(ok, tostring(err))
    for i = 2, #events do
        trace_write(vm, "events/" .. events[i] .. "/enable", "1")
    end
    local ret = fn()
    for i = 2, #events do
        trace_write(vm, "events/" .. events[i] .. "/enable", "0")
    end
    return M.parse(hooks.trace_stop(vm, events[1])), ret
end

--- The subset of `events` whose tracepoint is `name`.
function M.of(events, name)
    local out = {}
    for _, e in ipairs(events) do
        if e.event == name then out[#out + 1] = e end
    end
    return out
end

--- The first event of tracepoint `name`, or nil.
function M.first(events, name) return M.of(events, name)[1] end

--- Every `reason` seen for tracepoint `name`, in order, as one string —
--- what an assertion message wants when the expectation is "exactly
--- this branch fired".
function M.reasons(events, name)
    local out = {}
    for _, e in ipairs(M.of(events, name)) do out[#out + 1] = e.reason end
    return table.concat(out, ",")
end

-- Convenience: the three event sets §3.6 reads ------------------------------

M.EV_PROBE = "kacs/kacs_signing_probe"
M.EV_VERIFY = "kacs/kacs_signing_verify"
M.EV_EXEC = "kacs/kacs_exec"

--- Exec `path` (as the agent) and return the events `list` caught.
---
--- The binary exits immediately, so the run is synchronous and the
--- whole exec — stage, commit, and the signing lookup under it — has
--- happened by the time the ring is read.
function M.exec_traced(vm, list, path)
    local result
    local events = M.trace(vm, list, function()
        result = vm:run(path, {})
    end)
    return events, result
end

return M
