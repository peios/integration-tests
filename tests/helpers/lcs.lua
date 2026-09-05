-- LCS, the kernel half of the Peios registry, for the chapter 5 cases.
--
-- Two halves. The *source* half serves a real registry source from Lua
-- on the kernel-only profile, where no loregd exists: a worker holds
-- /dev/pkm_registry open O_NONBLOCK and registers one or more hives,
-- and the host pumps it, one RSI request read, one response written.
-- Unlike helpers/registry (the KMES suite's single-layer Machine hive)
-- this one is a faithful peer for the whole protocol: layer-tagged path
-- and value entries, hidden entries, tombstones and blankets, real
-- transaction isolation, conditional writes, RSI_DELETE_LAYER's orphan
-- list, deterministic ordering — plus the knobs a conformance test
-- needs that no honest source has: intercept a request, hold it and
-- answer late, write a malformed frame, drop the connection and resume.
--
-- The *client* half wraps the three syscalls and eighteen ioctls with
-- the argument layouts of PKM §5.A and decodes what comes back. Every
-- registry call that reaches a hive this helper serves round-trips to
-- the source and blocks in the kernel until it is answered, so it must
-- run as an async on a worker while the host pumps: `src:run(function()
-- return lcs.open_key_async(w, ...) end)`, or the sync forms that do
-- exactly that. `reg_begin_transaction` and the transaction ioctls
-- contact no source and may run anywhere.
--
-- Wire buffers cross the agent as `bufs`; a struct carrying a pointer
-- to another buffer names it through `nested` (1-based indices).

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local access = require("helpers.access")

local M = {}

-- ---- ABI ------------------------------------------------------------

M.SYS = { OPEN_KEY = 1100, CREATE_KEY = 1101, BEGIN_TRANSACTION = 1102 }

local function ioc(dir, nr, size)
    return (dir << 30) | (size << 16) | (0x52 << 8) | nr -- type byte 'R'
end
local IO, IOW, IOR, IOWR = 0, 1, 2, 3

M.IOC = {
    QUERY_VALUE = ioc(IOWR, 0, 64),
    SET_VALUE = ioc(IOW, 1, 64),
    DELETE_VALUE = ioc(IOW, 2, 40),
    BLANKET_TOMBSTONE = ioc(IOW, 3, 24),
    QUERY_VALUES_BATCH = ioc(IOWR, 4, 24),
    ENUM_VALUES = ioc(IOWR, 5, 40),
    ENUM_SUBKEYS = ioc(IOWR, 6, 40),
    QUERY_KEY_INFO = ioc(IOWR, 7, 64),
    DELETE_KEY = ioc(IOW, 8, 24),
    HIDE_KEY = ioc(IOW, 9, 24),
    GET_SECURITY = ioc(IOWR, 10, 16),
    SET_SECURITY = ioc(IOW, 11, 24),
    NOTIFY = ioc(IOW, 12, 8),
    FLUSH = ioc(IO, 13, 0),
    BACKUP = ioc(IOW, 14, 4),
    RESTORE = ioc(IOW, 15, 4),
    COMMIT = ioc(IO, 16, 0),
    TXN_STATUS = ioc(IOR, 17, 8),
    SRC_REGISTER = ioc(IOW, 0, 24),
}
--- The encoded number a given (direction, number, size) produces —
--- for the cases that probe a wrong direction or a foreign fd type.
M.ioc = ioc
M.IOC_DIR = { NONE = IO, W = IOW, R = IOR, WR = IOWR }

M.RIGHT = {
    QUERY_VALUE = 0x00000001, SET_VALUE = 0x00000002,
    CREATE_SUB_KEY = 0x00000004, ENUMERATE_SUB_KEYS = 0x00000008,
    NOTIFY = 0x00000010, CREATE_LINK = 0x00000020,
    DELETE = 0x00010000, READ_CONTROL = 0x00020000,
    WRITE_DAC = 0x00040000, WRITE_OWNER = 0x00080000,
    ACCESS_SYSTEM_SECURITY = 0x01000000, MAXIMUM_ALLOWED = 0x02000000,
    GENERIC_ALL = 0x10000000, GENERIC_EXECUTE = 0x20000000,
    GENERIC_WRITE = 0x40000000, GENERIC_READ = 0x80000000,
    KEY_READ = 0x00020019, KEY_WRITE = 0x00020006,
    KEY_ALL_ACCESS = 0x000F003F,
    VALID_DESIRED = 0xF30F003F, VALID_MAPPED = 0x010F003F,
    VALID_ACE = 0xF10F003F,
}
M.KEY_ALL_ACCESS = M.RIGHT.KEY_ALL_ACCESS

M.SI = { OWNER = 0x1, GROUP = 0x2, DACL = 0x4, SACL = 0x8, ALL = 0xF }

M.TYPE = {
    NONE = 0, SZ = 1, EXPAND_SZ = 2, BINARY = 3, DWORD = 4,
    DWORD_BIG_ENDIAN = 5, LINK = 6, MULTI_SZ = 7, RESOURCE_LIST = 8,
    FULL_RESOURCE_DESCRIPTOR = 9, RESOURCE_REQUIREMENTS_LIST = 10,
    QWORD = 11, TOMBSTONE = 0xFFFF,
}

M.WATCH = {
    VALUE_SET = 1, VALUE_DELETED = 2, SUBKEY_CREATED = 3,
    SUBKEY_DELETED = 4, SD_CHANGED = 5, KEY_DELETED = 6, OVERFLOW = 7,
}
M.NOTIFY = { VALUE = 0x1, SUBKEY = 0x2, SD = 0x4, ALL = 0x7 }

M.TXN = {
    ACTIVE_UNBOUND = 0, ACTIVE_BOUND = 1, COMMITTED = 2, ABORTED = 3,
    TIMED_OUT = 4, SOURCE_DOWN = 5,
}

M.OPEN_LINK = 0x01
M.OPTION_VOLATILE = 0x01
M.OPTION_CREATE_LINK = 0x02
M.CREATED_NEW, M.OPENED_EXISTING = 1, 2

M.OP = {
    LOOKUP = 0x01, CREATE_ENTRY = 0x02, HIDE_ENTRY = 0x03,
    DELETE_ENTRY = 0x04, ENUM_CHILDREN = 0x05,
    CREATE_KEY = 0x10, READ_KEY = 0x11, WRITE_KEY = 0x12, DROP_KEY = 0x13,
    QUERY_VALUES = 0x20, SET_VALUE = 0x21, DELETE_VALUE = 0x22,
    BLANKET_TOMBSTONE = 0x23,
    BEGIN_TXN = 0x30, COMMIT_TXN = 0x31, ABORT_TXN = 0x32,
    FLUSH = 0x40, DELETE_LAYER = 0x50,
}
M.OP_NAME = {}
for k, v in pairs(M.OP) do M.OP_NAME[v] = k end

M.STATUS = {
    OK = 0, NOT_FOUND = 1, ALREADY_EXISTS = 2, STORAGE_ERROR = 3,
    NOT_EMPTY = 4, TOO_LARGE = 5, TXN_BUSY = 6, INVALID = 7,
    CAS_FAILED = 8, TXN_NOT_SUPPORTED = 9,
}
M.RESPONSE_BIT = 0x8000
M.RSI_TXN_READ_WRITE, M.RSI_TXN_READ_ONLY = 0, 1
M.HIVE_PRIVATE = 0x01

M.BACKUP_RECORD = {
    HEADER = 0x01, LAYER = 0x02, KEY = 0x03, PATH_ENTRY = 0x04,
    VALUE = 0x05, BLANKET_TOMBSTONE = 0x06, TRAILER = 0xFF,
}

M.LAYERS_PATH = "Machine\\System\\Registry\\Layers"
M.PARAMS_PATH = "Machine\\System\\Registry"
M.DEVICE = "/dev/pkm_registry"

M.NULL_GUID = string.rep("\0", 16)
local O_NONBLOCK = 0x800

--- A REG_DWORD / REG_QWORD payload.
function M.dword(v) return string.pack("<I4", v) end
function M.qword(v) return string.pack("<I8", v) end
--- A REG_SZ payload: UTF-8 with a trailing NUL, as Windows stores it.
function M.sz(s) return s .. "\0" end

-- ---- descriptors ----------------------------------------------------

local CI = access.ACE_FLAG.CONTAINER_INHERIT
local ALL = M.RIGHT.KEY_ALL_ACCESS | M.RIGHT.GENERIC_ALL

--- A complete key descriptor (owner, group, DACL — LCS validates a
--- source's key SDs as complete, unlike the DACL-only file ones):
--- SYSTEM-owned, Everyone all rights, container-inheritable.
function M.permissive_sd(extra_aces)
    local aces = { access.ace(access.ACE.ALLOWED, ALL, kacs.SID.EVERYONE, CI) }
    for _, a in ipairs(extra_aces or {}) do aces[#aces + 1] = a end
    return access.sd({
        owner = kacs.SID.LOCAL_SYSTEM, group = kacs.SID.LOCAL_SYSTEM,
        dacl = access.acl(aces),
    })
end

--- The descriptor §5.10.3 describes on the Machine hive root: SYSTEM
--- and Administrators KEY_ALL_ACCESS, Authenticated Users KEY_READ,
--- all container-inheritable.
function M.machine_root_sd()
    return access.sd({
        owner = kacs.SID.LOCAL_SYSTEM, group = kacs.SID.LOCAL_SYSTEM,
        dacl = access.acl({
            access.ace(access.ACE.ALLOWED, M.RIGHT.KEY_ALL_ACCESS, kacs.SID.LOCAL_SYSTEM, CI),
            access.ace(access.ACE.ALLOWED, M.RIGHT.KEY_ALL_ACCESS, kacs.SID.ADMINISTRATORS, CI),
            access.ace(access.ACE.ALLOWED, M.RIGHT.KEY_READ, kacs.SID.AUTHENTICATED_USERS, CI),
        }),
    })
end

--- A descriptor from a DACL and optional SACL, SYSTEM-owned.
function M.sd(aces, opts)
    opts = opts or {}
    return access.sd({
        owner = opts.owner or kacs.SID.LOCAL_SYSTEM,
        group = opts.group or kacs.SID.LOCAL_SYSTEM,
        dacl = access.acl(aces), sacl = opts.sacl,
    })
end

-- ---- names ----------------------------------------------------------

--- ASCII-lower folding. Names this helper stores are ASCII; a case
--- that needs Unicode Simple Case Folding tests the kernel's, not
--- ours, and seeds through the syscalls.
local function fold(name) return name:lower() end
M.fold = fold

local guid_counter = 0
--- A GUID nobody else generates: a fixed prefix and a counter.
function M.guid()
    guid_counter = guid_counter + 1
    return string.pack("<I8I8", 0x1c51c51c51c51c50, guid_counter)
end

-- ---- the store ------------------------------------------------------
--
-- store.keys[guid]     = { name, parent, sd, volatile, symlink, lwt }
-- store.entries[pguid] = { [fold(name)] = { name, by_layer = { [fold(layer)] =
--                           { layer, hidden, guid, seq } } } }
-- store.values[guid]   = { [fold(name)] = { name, by_layer = { [fold(layer)] =
--                           { name, layer, type, data, seq } } } }
-- store.blankets[guid] = { [fold(layer)] = { layer, seq } }

local function deep_copy(v)
    if type(v) ~= "table" then return v end
    local out = {}
    for k, x in pairs(v) do out[k] = deep_copy(x) end
    return out
end

local function sorted_keys(t, key_of)
    local ks = {}
    for k in pairs(t) do ks[#ks + 1] = k end
    table.sort(ks, key_of and function(a, b) return key_of(a) < key_of(b) end or nil)
    return ks
end

local function new_store()
    return { keys = {}, entries = {}, values = {}, blankets = {} }
end

local function put_str(s) return string.pack("<s4", s) end
local function get_str(buf, at) return string.unpack("<s4", buf, at) end

local Source = {}
Source.__index = Source
M.Source = Source

--- A source serving `opts.hives` (default one hive, "Machine"). Each
--- hive: `{ name =, private = bool, scope = 16 bytes, sd = root SD }`.
--- Seed with `key`/`value`/... then `register`.
function M.source(vm, opts)
    opts = opts or {}
    local self = setmetatable({}, Source)
    self.vm = vm
    self.store = new_store()
    self.seq = 0
    self.log = {}
    self.txns = {}
    self.intercepts = {}
    self.held = {}
    self.hives = {}
    self.roots = {}
    for _, h in ipairs(opts.hives or { { name = "Machine" } }) do
        self:hive(h.name, h)
    end
    return self
end

--- Add a hive before registering. Returns its root GUID.
function Source:hive(name, o)
    o = o or {}
    local root = o.root or M.guid()
    self.store.keys[root] = {
        name = name, parent = M.NULL_GUID, sd = o.sd or M.permissive_sd(),
        volatile = false, symlink = false, lwt = 0,
    }
    self.hives[#self.hives + 1] = {
        name = name, root = root, private = o.private or false,
        scope = o.scope or M.NULL_GUID, flags = o.flags,
    }
    -- Two hives may share a name (one global, one private): the first
    -- registered owns the name for path seeding; seed the other through
    -- `o.root` on `key`.
    if not self.roots[fold(name)] then self.roots[fold(name)] = root end
    return root
end

function Source:next_seq()
    self.seq = self.seq + 1
    return self.seq
end

local function note_seq(self, seq)
    if seq > self.seq then self.seq = seq end
end

-- Store primitives, shared by host-side seeding and the RSI handlers.

local function entry_slot(store, parent, name)
    local per = store.entries[parent]
    if not per then per = {}; store.entries[parent] = per end
    local slot = per[fold(name)]
    if not slot then slot = { name = name, by_layer = {} }; per[fold(name)] = slot end
    return slot
end

local function value_slot(store, guid, name)
    local per = store.values[guid]
    if not per then per = {}; store.values[guid] = per end
    local slot = per[fold(name)]
    if not slot then slot = { name = name, by_layer = {} }; per[fold(name)] = slot end
    return slot
end

local function referenced(store, guid)
    for _, per in pairs(store.entries) do
        for _, slot in pairs(per) do
            for _, e in pairs(slot.by_layer) do
                if not e.hidden and e.guid == guid then return true end
            end
        end
    end
    return false
end

--- Resolve a backslash path from a hive root through this helper's own
--- view of the *base* layer (host-side convenience; the kernel is the
--- authority on resolution). Returns the GUID or nil.
function Source:lookup(path)
    local first, rest = path:match("^([^\\]+)\\?(.*)$")
    local at = self.roots[fold(first)]
    if not at then return nil end
    for part in rest:gmatch("[^\\]+") do
        local per = self.store.entries[at]
        local slot = per and per[fold(part)]
        local e = slot and slot.by_layer[fold("base")]
        if not e or e.hidden then return nil end
        at = e.guid
    end
    return at
end

--- Create (or return) a key at a path under a hive root, e.g.
--- "Machine\\Software\\Vendor", creating the intermediates in the same
--- layer. `o.layer` (default "base"), `o.sd`, `o.volatile`, `o.symlink`;
--- `o.root` names the hive root GUID explicitly (for a private hive that
--- shares its name with a global one). Host-side seeding: do it before
--- `register`. Returns the GUID.
function Source:key(path, o)
    o = o or {}
    local layer = o.layer or "base"
    local first, rest = path:match("^([^\\]+)\\?(.*)$")
    local at = o.root or assert(self.roots[fold(first)], "no hive " .. first)
    local parts = {}
    for part in rest:gmatch("[^\\]+") do parts[#parts + 1] = part end
    for i, part in ipairs(parts) do
        local slot = entry_slot(self.store, at, part)
        local e = slot.by_layer[fold(layer)]
        if not e or e.hidden then
            local guid = M.guid()
            local last = i == #parts
            self.store.keys[guid] = {
                name = part, parent = at,
                sd = (last and o.sd) or M.permissive_sd(),
                volatile = last and o.volatile or false,
                symlink = last and o.symlink or false, lwt = 0,
            }
            e = { layer = layer, hidden = false, guid = guid, seq = self:next_seq() }
            slot.by_layer[fold(layer)] = e
        end
        at = e.guid
    end
    return at
end

--- Seed one value entry on a key: `o.layer` (default "base").
function Source:value(guid, name, vtype, data, o)
    o = o or {}
    local layer = o.layer or "base"
    local slot = value_slot(self.store, guid, name)
    slot.by_layer[fold(layer)] = {
        name = name, layer = layer, type = vtype, data = data,
        seq = o.seq or self:next_seq(),
    }
end

--- Seed a value tombstone in a layer.
function Source:tombstone(guid, name, layer)
    self:value(guid, name, M.TYPE.TOMBSTONE, "", { layer = layer })
end

--- Seed a blanket tombstone for a layer on a key.
function Source:blanket(guid, layer)
    local per = self.store.blankets[guid]
    if not per then per = {}; self.store.blankets[guid] = per end
    per[fold(layer)] = { layer = layer, seq = self:next_seq() }
end

--- Seed a HIDDEN path entry at (parent, name) in a layer.
function Source:hide(parent, name, layer)
    local slot = entry_slot(self.store, parent, name)
    slot.by_layer[fold(layer)] = {
        layer = layer, hidden = true, guid = M.NULL_GUID, seq = self:next_seq(),
    }
end

--- Seed a symlink key whose default value names `target` (a path).
function Source:symlink(path, target, o)
    o = o or {}
    o.symlink = true
    local guid = self:key(path, o)
    self:value(guid, "", M.TYPE.LINK, target, { layer = o.layer })
    return guid
end

--- Seed a layer's metadata key under Machine\System\Registry\Layers.
--- `o.precedence` (default absent → 0), `o.enabled` (0/1), `o.owner`
--- (a SID). Values absent from `o` are not written, so the defaults
--- of §5.3.3 apply.
function Source:seed_layer(name, o)
    o = o or {}
    local guid = self:key(M.LAYERS_PATH .. "\\" .. name)
    if o.precedence then self:value(guid, "Precedence", M.TYPE.DWORD, M.dword(o.precedence)) end
    if o.enabled ~= nil then
        self:value(guid, "Enabled", M.TYPE.DWORD,
            M.dword(o.enabled == true and 1 or o.enabled == false and 0 or o.enabled))
    end
    if o.owner then self:value(guid, "Owner", M.TYPE.BINARY, o.owner) end
    return guid
end

--- Seed one of the nineteen operational parameters (§5.10.3).
function Source:seed_param(name, value, vtype)
    local guid = self:key(M.PARAMS_PATH)
    self:value(guid, name, vtype or M.TYPE.DWORD,
        type(value) == "number" and M.dword(value) or value)
    return guid
end

-- ---- RSI wire -------------------------------------------------------

local function key_meta(store, guid)
    local k = store.keys[guid]
    return guid .. put_str(k.sd) ..
        string.pack("<I1I1I8", k.volatile and 1 or 0, k.symlink and 1 or 0, k.lwt)
end

local function entry_bytes(e)
    return put_str(e.layer) .. string.pack("<I1", e.hidden and 1 or 0) ..
        (e.hidden and M.NULL_GUID or e.guid) .. string.pack("<I8", e.seq)
end

-- Entries of one name slot, in the deterministic order §4.5 asks for.
local function slot_entries(slot)
    local list = {}
    for _, e in pairs(slot.by_layer) do list[#list + 1] = e end
    table.sort(list, function(a, b)
        if fold(a.layer) ~= fold(b.layer) then return fold(a.layer) < fold(b.layer) end
        return a.seq < b.seq
    end)
    return list
end

-- One deduplicated metadata block for the GUIDs a set of entries names.
local function metadata_block(store, entries)
    local seen, guids = {}, {}
    for _, e in ipairs(entries) do
        if not e.hidden and not seen[e.guid] and store.keys[e.guid] then
            seen[e.guid] = true
            guids[#guids + 1] = e.guid
        end
    end
    table.sort(guids)
    local out = { string.pack("<I4", #guids) }
    for _, g in ipairs(guids) do out[#out + 1] = key_meta(store, g) end
    return table.concat(out)
end

-- Handlers: (self, store, payload, req) -> status, body. `store` is
-- the view the request's transaction sees; a mutating handler mutates
-- it, and the caller decides whether that view was the real store.
local H = {}
local ST = M.STATUS

H[M.OP.LOOKUP] = function(self, store, p)
    local parent = p:sub(1, 16)
    local name = get_str(p, 17)
    local per = store.entries[parent]
    local slot = per and per[fold(name)]
    if not slot or next(slot.by_layer) == nil then
        return ST.OK, string.pack("<I4I4", 0, 0)
    end
    local list = slot_entries(slot)
    local out = { string.pack("<I4", #list) }
    for _, e in ipairs(list) do out[#out + 1] = entry_bytes(e) end
    out[#out + 1] = metadata_block(store, list)
    return ST.OK, table.concat(out)
end

H[M.OP.ENUM_CHILDREN] = function(self, store, p)
    local parent = p:sub(1, 16)
    if not store.keys[parent] then return ST.NOT_FOUND, "" end
    local per = store.entries[parent] or {}
    local names = sorted_keys(per)
    local out, all, count = {}, {}, 0
    for _, fname in ipairs(names) do
        local slot = per[fname]
        local list = slot_entries(slot)
        if #list > 0 then
            count = count + 1
            local chunk = { put_str(slot.name), string.pack("<I4", #list) }
            for _, e in ipairs(list) do
                chunk[#chunk + 1] = entry_bytes(e)
                all[#all + 1] = e
            end
            out[#out + 1] = table.concat(chunk)
        end
    end
    return ST.OK, string.pack("<I4", count) .. table.concat(out) ..
        metadata_block(store, all)
end

H[M.OP.CREATE_ENTRY] = function(self, store, p)
    local parent = p:sub(1, 16)
    local at = 17
    local name; name, at = get_str(p, at)
    local layer; layer, at = get_str(p, at)
    local guid = p:sub(at, at + 15); at = at + 16
    local seq = string.unpack("<I8", p, at)
    if not store.keys[parent] then return ST.NOT_FOUND, "" end
    local slot = entry_slot(store, parent, name)
    if slot.by_layer[fold(layer)] then return ST.ALREADY_EXISTS, "" end
    slot.by_layer[fold(layer)] = { layer = layer, hidden = false, guid = guid, seq = seq }
    note_seq(self, seq)
    return ST.OK, ""
end

H[M.OP.HIDE_ENTRY] = function(self, store, p)
    local parent = p:sub(1, 16)
    local at = 17
    local name; name, at = get_str(p, at)
    local layer; layer, at = get_str(p, at)
    local seq = string.unpack("<I8", p, at)
    if not store.keys[parent] then return ST.NOT_FOUND, "" end
    local slot = entry_slot(store, parent, name)
    slot.by_layer[fold(layer)] = { layer = layer, hidden = true, guid = M.NULL_GUID, seq = seq }
    note_seq(self, seq)
    return ST.OK, ""
end

H[M.OP.DELETE_ENTRY] = function(self, store, p)
    local parent = p:sub(1, 16)
    local at = 17
    local name; name, at = get_str(p, at)
    local layer = get_str(p, at)
    local per = store.entries[parent]
    local slot = per and per[fold(name)]
    if not slot or not slot.by_layer[fold(layer)] then return ST.NOT_FOUND, "" end
    slot.by_layer[fold(layer)] = nil
    return ST.OK, ""
end

H[M.OP.CREATE_KEY] = function(self, store, p)
    local guid = p:sub(1, 16)
    local at = 17
    local name; name, at = get_str(p, at)
    local parent = p:sub(at, at + 15); at = at + 16
    local sd; sd, at = get_str(p, at)
    local volatile = p:byte(at) ~= 0
    local symlink = p:byte(at + 1) ~= 0
    if store.keys[guid] then return ST.ALREADY_EXISTS, "" end
    store.keys[guid] = {
        name = name, parent = parent, sd = sd, volatile = volatile,
        symlink = symlink, lwt = 0,
    }
    return ST.OK, ""
end

H[M.OP.READ_KEY] = function(self, store, p)
    local k = store.keys[p:sub(1, 16)]
    if not k then return ST.NOT_FOUND, "" end
    return ST.OK, put_str(k.name) .. k.parent .. put_str(k.sd) ..
        string.pack("<I1I1i8", k.volatile and 1 or 0, k.symlink and 1 or 0, k.lwt)
end

H[M.OP.WRITE_KEY] = function(self, store, p)
    local k = store.keys[p:sub(1, 16)]
    if not k then return ST.NOT_FOUND, "" end
    local mask = string.unpack("<I4", p, 17)
    if mask & ~0x3 ~= 0 then return ST.INVALID, "" end
    local at = 21
    if mask & 0x1 ~= 0 then k.sd, at = get_str(p, at) end
    if mask & 0x2 ~= 0 then k.lwt = string.unpack("<i8", p, at) end
    return ST.OK, ""
end

H[M.OP.DROP_KEY] = function(self, store, p)
    local guid = p:sub(1, 16)
    store.keys[guid] = nil
    store.values[guid] = nil
    store.blankets[guid] = nil
    store.entries[guid] = nil
    for _, per in pairs(store.entries) do
        for _, slot in pairs(per) do
            for fl, e in pairs(slot.by_layer) do
                if not e.hidden and e.guid == guid then slot.by_layer[fl] = nil end
            end
        end
    end
    return ST.OK, ""
end

H[M.OP.QUERY_VALUES] = function(self, store, p)
    local guid = p:sub(1, 16)
    local at = 17
    local name; name, at = get_str(p, at)
    local all = p:byte(at) ~= 0
    if not store.keys[guid] then return ST.NOT_FOUND, "" end
    local per = store.values[guid] or {}
    local rows = {}
    for _, fname in ipairs(sorted_keys(per)) do
        if all or fname == fold(name) then
            local list = {}
            for _, v in pairs(per[fname].by_layer) do list[#list + 1] = v end
            table.sort(list, function(a, b)
                if fold(a.layer) ~= fold(b.layer) then return fold(a.layer) < fold(b.layer) end
                return a.seq < b.seq
            end)
            for _, v in ipairs(list) do rows[#rows + 1] = v end
        end
    end
    local out = { string.pack("<I4", #rows) }
    for _, v in ipairs(rows) do
        out[#out + 1] = put_str(v.name) .. put_str(v.layer) ..
            string.pack("<I4", v.type) .. put_str(v.data) .. string.pack("<I8", v.seq)
    end
    local bl = store.blankets[guid] or {}
    local bkeys = sorted_keys(bl)
    out[#out + 1] = string.pack("<I4", #bkeys)
    for _, fl in ipairs(bkeys) do
        out[#out + 1] = put_str(bl[fl].layer) .. string.pack("<I8", bl[fl].seq)
    end
    return ST.OK, table.concat(out)
end

H[M.OP.SET_VALUE] = function(self, store, p)
    local guid = p:sub(1, 16)
    local at = 17
    local name; name, at = get_str(p, at)
    local layer; layer, at = get_str(p, at)
    local vtype = string.unpack("<I4", p, at); at = at + 4
    local data; data, at = get_str(p, at)
    local seq, expected = string.unpack("<I8I8", p, at)
    if not store.keys[guid] then return ST.NOT_FOUND, "" end
    local slot = value_slot(store, guid, name)
    if expected ~= 0 then
        local cur = slot.by_layer[fold(layer)]
        if not cur or cur.seq ~= expected then return ST.CAS_FAILED, "" end
    end
    slot.by_layer[fold(layer)] = { name = name, layer = layer, type = vtype, data = data, seq = seq }
    note_seq(self, seq)
    return ST.OK, ""
end

H[M.OP.DELETE_VALUE] = function(self, store, p)
    local guid = p:sub(1, 16)
    local at = 17
    local name; name, at = get_str(p, at)
    local layer = get_str(p, at)
    local per = store.values[guid]
    local slot = per and per[fold(name)]
    if slot then slot.by_layer[fold(layer)] = nil end
    return ST.OK, "" -- idempotent, as §4.4 requires
end

H[M.OP.BLANKET_TOMBSTONE] = function(self, store, p)
    local guid = p:sub(1, 16)
    local at = 17
    local layer; layer, at = get_str(p, at)
    local set = p:byte(at) ~= 0; at = at + 1
    local seq = string.unpack("<I8", p, at)
    if not store.keys[guid] then return ST.NOT_FOUND, "" end
    local per = store.blankets[guid]
    if not per then per = {}; store.blankets[guid] = per end
    if set then per[fold(layer)] = { layer = layer, seq = seq } else per[fold(layer)] = nil end
    note_seq(self, seq)
    return ST.OK, ""
end

H[M.OP.DELETE_LAYER] = function(self, store, p)
    local layer = get_str(p, 1)
    local fl = fold(layer)
    local touched = {}
    for _, per in pairs(store.entries) do
        for _, slot in pairs(per) do
            local e = slot.by_layer[fl]
            if e then
                if not e.hidden then touched[e.guid] = true end
                slot.by_layer[fl] = nil
            end
        end
    end
    for _, per in pairs(store.values) do
        for _, slot in pairs(per) do slot.by_layer[fl] = nil end
    end
    for _, per in pairs(store.blankets) do per[fl] = nil end
    local orphans = {}
    for guid in pairs(touched) do
        if store.keys[guid] and not referenced(store, guid) then orphans[#orphans + 1] = guid end
    end
    table.sort(orphans)
    return ST.OK, string.pack("<I4", #orphans) .. table.concat(orphans)
end

H[M.OP.FLUSH] = function() return ST.OK, "" end

-- Transactions are handled by dispatch, not by a store handler.

--- The view a request tagged with `txn` reads and mutates.
function Source:view(txn)
    if txn == 0 then return self.store, true end
    local t = self.txns[txn]
    if not t then return self.store, true end
    if t.mode == M.RSI_TXN_READ_ONLY then return t.snapshot, false end
    local view = deep_copy(self.store)
    for _, op in ipairs(t.ops) do H[op.op](self, view, op.payload) end
    return view, false
end

local MUTATING = {
    [M.OP.CREATE_ENTRY] = true, [M.OP.HIDE_ENTRY] = true, [M.OP.DELETE_ENTRY] = true,
    [M.OP.CREATE_KEY] = true, [M.OP.WRITE_KEY] = true, [M.OP.DROP_KEY] = true,
    [M.OP.SET_VALUE] = true, [M.OP.DELETE_VALUE] = true,
    [M.OP.BLANKET_TOMBSTONE] = true, [M.OP.DELETE_LAYER] = true,
}

function Source:dispatch(req)
    local op, p, txn = req.op, req.payload, req.txn
    if op == M.OP.BEGIN_TXN then
        local id, mode = string.unpack("<I8I4", p)
        if self.txns[id] then return ST.INVALID, "" end
        if self.refuse_txn_mode and self.refuse_txn_mode[mode] then
            return ST.TXN_NOT_SUPPORTED, ""
        end
        self.txns[id] = {
            mode = mode, ops = {},
            snapshot = mode == M.RSI_TXN_READ_ONLY and deep_copy(self.store) or nil,
        }
        return ST.OK, ""
    elseif op == M.OP.COMMIT_TXN then
        local id = string.unpack("<I8", p)
        local t = self.txns[id]
        if not t or t.mode ~= M.RSI_TXN_READ_WRITE then return ST.INVALID, "" end
        if self.commit_status and self.commit_status ~= ST.OK then
            return self.commit_status, ""
        end
        for _, o in ipairs(t.ops) do H[o.op](self, self.store, o.payload) end
        self.txns[id] = nil
        self.commits = (self.commits or 0) + 1
        return ST.OK, ""
    elseif op == M.OP.ABORT_TXN then
        local id = string.unpack("<I8", p)
        self.txns[id] = nil
        self.aborts = (self.aborts or 0) + 1
        return ST.OK, ""
    end
    local h = H[op]
    if not h then return ST.INVALID, "" end
    local view, real = self:view(txn)
    if MUTATING[op] and not real then
        local t = self.txns[txn]
        if t.mode == M.RSI_TXN_READ_ONLY then return ST.INVALID, "" end
        local status, body = h(self, view, p, req)
        if status == ST.OK then t.ops[#t.ops + 1] = { op = op, payload = p } end
        return status, body
    end
    return h(self, view, p, req)
end

-- ---- device ---------------------------------------------------------

local function hive_entries(self)
    local blob, names = {}, {}
    for _, h in ipairs(self.hives) do
        local flags = h.flags or (h.private and M.HIVE_PRIVATE or 0)
        blob[#blob + 1] = string.pack("<I4I4I8", #h.name, 0, 0) .. h.root ..
            string.pack("<I4I4", flags, 0) .. h.scope
        names[#names + 1] = h.name
    end
    return table.concat(blob), names
end

--- Open the device in a dedicated worker and register the hive set.
--- `o.max_sequence` overrides what the seeds imply; `o.who` supplies
--- the worker (a principal, say) instead of a fresh SYSTEM one.
--- Returns true, or nil and a message; the errno is in `self.errno`.
function Source:register(o)
    o = o or {}
    self.worker = o.who or self.vm:spawn_worker()
    self.owns_worker = o.who == nil
    local fd, errno = sys.open(self.worker, M.DEVICE, sys.O.RDWR | O_NONBLOCK)
    if not fd then
        self.errno = errno
        self:close()
        return nil, "open " .. M.DEVICE .. ": " .. sys.errname(errno)
    end
    self.fd = fd
    local entries, names = hive_entries(self)
    local max_seq = o.max_sequence or self.seq
    local bufs = { string.pack("<I4I4I8I8", #self.hives, o.pad or 0, max_seq, 0), entries }
    local nested = { { parent = 1, child = 2, offset = 16 } }
    for i, name in ipairs(names) do
        bufs[#bufs + 1] = name
        nested[#nested + 1] = { parent = 2, child = #bufs, offset = (i - 1) * 56 + 8 }
    end
    local r = self.worker:syscall(sys.NR.ioctl, {
        args = { fd, M.IOC.SRC_REGISTER, 0 }, bufs = bufs, ptrs = { 2 }, nested = nested,
    })
    if r.ret ~= 0 then
        self.errno = r.errno
        self:close()
        return nil, "REG_SRC_REGISTER: " .. sys.errname(r.errno)
    end
    self.registered = true
    return true
end

--- Sentinel an intercept returns to hold a request unanswered.
M.HOLD = setmetatable({}, { __tostring = function() return "HOLD" end })

--- Intercept requests of one op: `fn(self, req)` returns
--- `status, body` to answer, `lcs.HOLD` to keep the request (see
--- `release`), a string to write as the *raw* response frame, or nil
--- to fall through to the honest handler. `req` has `id`, `op`,
--- `txn`, `payload`, `raw`.
function Source:intercept(op, fn)
    self.intercepts[op] = fn
end

function Source:write_frame(frame)
    local w = self.worker:syscall(sys.NR.write, {
        args = { self.fd, 0, #frame }, bufs = { frame }, ptrs = { 1 },
    })
    return w.ret, w.errno
end

function M.response_frame(request_id, op, status, body)
    body = body or ""
    return string.pack("<I4I8I2I4", 14 + 4 + #body, request_id, op | M.RESPONSE_BIT, status) .. body
end

function Source:respond(req, status, body)
    local frame = M.response_frame(req.id, req.op, status, body)
    local ret, errno = self:write_frame(frame)
    if ret ~= #frame then
        error("source write: " .. sys.errname(errno or 0) .. " (ret " .. tostring(ret) .. ")")
    end
end

--- Answer a held request now. Returns what write() said, so a case can
--- assert a late answer was still accepted (or that the connection was
--- torn down in the meantime).
function Source:release(id, status, body)
    local req = assert(self.held[id], "no held request " .. tostring(id))
    self.held[id] = nil
    if status == nil then status, body = self:dispatch(req) end
    return self:write_frame(M.response_frame(req.id, req.op, status, body))
end

--- Ids of requests currently held, oldest first.
function Source:held_ids()
    local ids = {}
    for id in pairs(self.held) do ids[#ids + 1] = id end
    table.sort(ids)
    return ids
end

--- Serve at most one pending request. Returns the request served (a
--- table), nil when the device had nothing, or raises on a read error.
function Source:step()
    local r = self.worker:syscall(sys.NR.read, {
        args = { self.fd, 0, 65536 },
        bufs = { string.rep("\0", 65536) }, ptrs = { 1 },
    })
    if r.ret < 0 then
        if r.errno == sys.E.AGAIN then return nil end
        error("source read: " .. sys.errname(r.errno))
    end
    if r.ret == 0 then self.eof = true; return nil end
    local msg = r.out_bufs[1]:sub(1, r.ret)
    local total, id, op, txn = string.unpack("<I4I8I2I8", msg)
    assert(total == #msg, "framing: total_len " .. total .. " of " .. #msg)
    local req = { id = id, op = op, txn = txn, payload = msg:sub(23), raw = msg }
    self.log[#self.log + 1] = req
    local status, body
    local hook = self.intercepts[op]
    if hook then
        local a, b = hook(self, req)
        if a == M.HOLD then
            self.held[id] = req
            req.held = true
            return req
        elseif type(a) == "string" and b == nil then
            self:write_frame(a)
            req.raw_response = a
            return req
        elseif a ~= nil then
            status, body = a, b or ""
        end
    end
    if status == nil then status, body = self:dispatch(req) end
    req.status = status
    self:respond(req, status, body)
    return req
end

--- Pump until the device stays quiet for `quiet_ms` (default 100).
--- Returns the number of requests served.
function Source:pump(quiet_ms)
    quiet_ms = quiet_ms or 100
    local served = 0
    while self.fd and not self.eof do
        local p = self.worker:syscall(sys.NR.poll, {
            args = { 0, 1, quiet_ms },
            bufs = { string.pack("<i4i2i2", self.fd, 1, 0) }, ptrs = { 0 }, -- POLLIN
        })
        if p.ret == 0 then return served end
        assert(p.ret > 0, "source poll: " .. sys.errname(p.errno))
        local revents = select(3, string.unpack("<i4i2i2", p.out_bufs[1]))
        if revents & 0x18 ~= 0 and revents & 0x1 == 0 then -- HUP/ERR without data
            self.hup = true
            return served
        end
        local n = 0
        while true do
            local req = self:step()
            if not req then break end
            served = served + 1; n = n + 1
        end
        if n == 0 then return served end
    end
    return served
end

--- Launch a pending operation that bounces through this source, pump
--- until the traffic settles, then await it.
function Source:run(launch, quiet_ms)
    local pending = launch()
    self:pump(quiet_ms)
    return pending:await()
end
Source.pump_during = Source.run

--- Requests served since log index `from` (default 1) with op `op`,
--- optionally against key GUID `guid` (first 16 payload bytes).
function Source:served(op, from, guid)
    local out = {}
    for i = from or 1, #self.log do
        local e = self.log[i]
        if e.op == op and (not guid or e.payload:sub(1, 16) == guid) then out[#out + 1] = e end
    end
    return out
end

function Source:mark() return #self.log + 1 end

--- Close the device fd (the slot goes Down) but keep the store, so
--- the same hive set can be registered again with `resume`.
function Source:disconnect()
    if self.fd then sys.close(self.worker, self.fd); self.fd = nil end
    if self.worker and self.owns_worker then
        self.worker:kill(); self.worker:join(); self.worker = nil
    end
    self.registered = false
    self.eof, self.hup = nil, nil
end

--- Take the Down slot back over: the same hives, the same roots.
function Source:resume(o)
    self:disconnect()
    return self:register(o)
end

function Source:close()
    self:disconnect()
end

--- The commonest fixture: a Machine hive with `Machine\Software\Test`
--- seeded, registered and bootstrap-pumped. Returns the source and the
--- test key's GUID.
function M.machine(vm, o)
    o = o or {}
    local src = M.source(vm, { hives = o.hives })
    if o.seed then o.seed(src) end
    local test_key = src:key(o.test_path or "Machine\\Software\\Test")
    local ok, err = src:register(o)
    if not ok then return nil, err end
    src:pump()
    return src, test_key
end

-- ---- the client side ------------------------------------------------
--
-- Builders return `nr, spec, decode`; `<op>_async(who, ...)` launches
-- and returns the pending, `<op>(src, who, ...)` runs it under the
-- pump and decodes. `r` is provium's result: ret, errno, out_bufs.

local B = {}

-- A little buffer builder: add returns the 1-based index, nest records
-- a pointer from parent at offset to child.
local function bufset()
    local s = { bufs = {}, nested = {} }
    function s:add(bytes)
        if bytes == nil or bytes == "" then return nil end
        self.bufs[#self.bufs + 1] = bytes
        return #self.bufs
    end
    function s:nest(parent, child, offset)
        if child then self.nested[#self.nested + 1] = { parent = parent, child = child, offset = offset } end
    end
    function s:spec(args, ptrs)
        return { args = args, bufs = self.bufs, ptrs = ptrs, nested = self.nested }
    end
    return s
end

local function zeros(n) return string.rep("\0", n) end

B.open_key = function(parent_fd, path, desired, flags)
    local s = bufset()
    s:add(sys.cstr(path))
    return M.SYS.OPEN_KEY,
        s:spec({ parent_fd or -1, 0, desired or M.KEY_ALL_ACCESS, flags or 0 }, { 1 }),
        function(r) return r end
end

--- `o`: parent_fd (-1), path, access, flags, layer (string or nil),
--- txn_fd (-1), no_disposition (bool), pad0/pad1 (probe values).
B.create_key = function(o)
    local s = bufset()
    local args_i = s:add(zeros(48))
    local path_i = s:add(sys.cstr(o.path))
    local layer_i = o.layer and s:add(sys.cstr(o.layer)) or nil
    local disp_i = (not o.no_disposition) and s:add(zeros(4)) or nil
    s.bufs[args_i] = string.pack("<i4I4I8I4I4I8i4I4I8",
        o.parent_fd or -1, o.pad0 or 0, 0, o.access or M.KEY_ALL_ACCESS,
        o.flags or 0, 0, o.txn_fd or -1, o.pad1 or 0, 0)
    s:nest(args_i, path_i, 8)
    s:nest(args_i, layer_i, 24)
    s:nest(args_i, disp_i, 40)
    return M.SYS.CREATE_KEY, s:spec({ 0 }, { 0 }), function(r)
        if r.ret >= 0 and disp_i then
            r.disposition = string.unpack("<I4", r.out_bufs[disp_i])
        end
        return r
    end
end

--- `o`: txn_fd (-1), data_len (4096; 0 probes), layer_len (256; 0
--- probes), pad0/pad1.
B.query_value = function(fd, name, o)
    o = o or {}
    local data_len = o.data_len or 4096
    local layer_len = o.layer_len or 256
    local s = bufset()
    local args_i = s:add(zeros(64))
    local name_i = s:add(name)
    local data_i = data_len > 0 and s:add(zeros(data_len)) or nil
    local layer_i = layer_len > 0 and s:add(zeros(layer_len)) or nil
    s.bufs[args_i] = string.pack("<I4I4I8I4I4i4I4I8I8I4I4I8",
        #name, o.pad0 or 0, 0, 0, data_len, o.txn_fd or -1, layer_len, 0, 0, 0, o.pad1 or 0, 0)
    s:nest(args_i, name_i, 8)
    s:nest(args_i, data_i, 32)
    s:nest(args_i, layer_i, 56)
    return sys.NR.ioctl, s:spec({ fd, M.IOC.QUERY_VALUE, 0 }, { 2 }), function(r)
        local a = r.out_bufs[args_i]
        r.type = string.unpack("<I4", a, 17)
        r.data_len = string.unpack("<I4", a, 21)
        r.sequence = string.unpack("<I8", a, 41)
        r.layer_len = string.unpack("<I4", a, 49)
        if r.ret == 0 then
            r.data = data_i and r.out_bufs[data_i]:sub(1, r.data_len) or ""
            r.layer = layer_i and r.out_bufs[layer_i]:sub(1, r.layer_len) or ""
        end
        return r
    end
end

--- `o`: layer (nil → base), txn_fd (-1), expected_seq (0), pads.
B.set_value = function(fd, name, vtype, data, o)
    o = o or {}
    local s = bufset()
    local args_i = s:add(zeros(64))
    local name_i = s:add(name)
    local data_i = s:add(data)
    local layer_i = s:add(o.layer)
    s.bufs[args_i] = string.pack("<I4I4I8I4I4I8I4I4I8i4I4I8",
        #name, o.pad0 or 0, 0, vtype, #data, 0, o.layer and #o.layer or 0,
        o.pad1 or 0, 0, o.txn_fd or -1, o.pad2 or 0, o.expected_seq or 0)
    s:nest(args_i, name_i, 8)
    s:nest(args_i, data_i, 24)
    s:nest(args_i, layer_i, 40)
    return sys.NR.ioctl, s:spec({ fd, M.IOC.SET_VALUE, 0 }, { 2 }), function(r) return r end
end

B.delete_value = function(fd, name, o)
    o = o or {}
    local s = bufset()
    local args_i = s:add(zeros(40))
    local name_i = s:add(name)
    local layer_i = s:add(o.layer)
    s.bufs[args_i] = string.pack("<I4I4I8I4I4I8i4I4",
        #name, o.pad0 or 0, 0, o.layer and #o.layer or 0, o.pad1 or 0, 0,
        o.txn_fd or -1, o.pad2 or 0)
    s:nest(args_i, name_i, 8)
    s:nest(args_i, layer_i, 24)
    return sys.NR.ioctl, s:spec({ fd, M.IOC.DELETE_VALUE, 0 }, { 2 }), function(r) return r end
end

B.blanket_tombstone = function(fd, layer, set, o)
    o = o or {}
    local s = bufset()
    local args_i = s:add(zeros(24))
    local layer_i = s:add(layer)
    s.bufs[args_i] = string.pack("<I4I4I8I1I1I1I1i4",
        layer and #layer or 0, o.pad0 or 0, 0, set and 1 or 0,
        o.pad1 or 0, 0, 0, o.txn_fd or -1)
    s:nest(args_i, layer_i, 8)
    return sys.NR.ioctl, s:spec({ fd, M.IOC.BLANKET_TOMBSTONE, 0 }, { 2 }), function(r) return r end
end

--- `o`: buf_len (65536; 0 probes), txn_fd (-1), pad.
B.query_values_batch = function(fd, o)
    o = o or {}
    local buf_len = o.buf_len or 65536
    local s = bufset()
    local args_i = s:add(zeros(24))
    local buf_i = buf_len > 0 and s:add(zeros(buf_len)) or nil
    s.bufs[args_i] = string.pack("<I4I4I8i4I4", buf_len, 0, 0, o.txn_fd or -1, o.pad or 0)
    s:nest(args_i, buf_i, 8)
    return sys.NR.ioctl, s:spec({ fd, M.IOC.QUERY_VALUES_BATCH, 0 }, { 2 }), function(r)
        local a = r.out_bufs[args_i]
        r.buf_len = string.unpack("<I4", a, 1)
        r.count = string.unpack("<I4", a, 5)
        if r.ret == 0 and buf_i then
            r.values = M.decode_batch(r.out_bufs[buf_i]:sub(1, r.buf_len), r.count)
        end
        return r
    end
end

--- Records: name_len u32, name, type u32, data_len u32, data.
function M.decode_batch(buf, count)
    local out, at = {}, 1
    for _ = 1, count do
        local name_len = string.unpack("<I4", buf, at); at = at + 4
        local name = buf:sub(at, at + name_len - 1); at = at + name_len
        local vtype, data_len = string.unpack("<I4I4", buf, at); at = at + 8
        local data = buf:sub(at, at + data_len - 1); at = at + data_len
        out[#out + 1] = { name = name, type = vtype, data = data }
    end
    return out
end

--- `o`: name_len (256), data_len (4096), txn_fd (-1), pad.
B.enum_values = function(fd, index, o)
    o = o or {}
    local name_len, data_len = o.name_len or 256, o.data_len or 4096
    local s = bufset()
    local args_i = s:add(zeros(40))
    local name_i = name_len > 0 and s:add(zeros(name_len)) or nil
    local data_i = data_len > 0 and s:add(zeros(data_len)) or nil
    s.bufs[args_i] = string.pack("<I4I4I8I4I4I8i4I4",
        index, name_len, 0, 0, data_len, 0, o.txn_fd or -1, o.pad or 0)
    s:nest(args_i, name_i, 8)
    s:nest(args_i, data_i, 24)
    return sys.NR.ioctl, s:spec({ fd, M.IOC.ENUM_VALUES, 0 }, { 2 }), function(r)
        local a = r.out_bufs[args_i]
        r.name_len = string.unpack("<I4", a, 5)
        r.type = string.unpack("<I4", a, 17)
        r.data_len = string.unpack("<I4", a, 21)
        if r.ret == 0 then
            r.name = name_i and r.out_bufs[name_i]:sub(1, r.name_len) or ""
            r.data = data_i and r.out_bufs[data_i]:sub(1, r.data_len) or ""
        end
        return r
    end
end

B.enum_subkeys = function(fd, index, o)
    o = o or {}
    local name_len = o.name_len or 256
    local s = bufset()
    local args_i = s:add(zeros(40))
    local name_i = name_len > 0 and s:add(zeros(name_len)) or nil
    s.bufs[args_i] = string.pack("<I4I4I8I8I4I4i4I4",
        index, name_len, 0, 0, 0, 0, o.txn_fd or -1, o.pad or 0)
    s:nest(args_i, name_i, 8)
    return sys.NR.ioctl, s:spec({ fd, M.IOC.ENUM_SUBKEYS, 0 }, { 2 }), function(r)
        local a = r.out_bufs[args_i]
        r.name_len = string.unpack("<I4", a, 5)
        r.last_write_time = string.unpack("<I8", a, 17)
        r.subkey_count = string.unpack("<I4", a, 25)
        r.value_count = string.unpack("<I4", a, 29)
        if r.ret == 0 then r.name = name_i and r.out_bufs[name_i]:sub(1, r.name_len) or "" end
        return r
    end
end

--- `o`: name_len (256; 0 probes), pad0, pad1 (6 bytes).
B.query_key_info = function(fd, o)
    o = o or {}
    local name_len = o.name_len or 256
    local s = bufset()
    local args_i = s:add(zeros(64))
    local name_i = name_len > 0 and s:add(zeros(name_len)) or nil
    s.bufs[args_i] = string.pack("<I4I4I8I8I4I4I4I4I4I4I1I1c6I8",
        name_len, o.pad0 or 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, o.pad1 or zeros(6), 0)
    s:nest(args_i, name_i, 8)
    return sys.NR.ioctl, s:spec({ fd, M.IOC.QUERY_KEY_INFO, 0 }, { 2 }), function(r)
        local a = r.out_bufs[args_i]
        r.name_len = string.unpack("<I4", a, 1)
        r.last_write_time = string.unpack("<I8", a, 17)
        r.subkey_count, r.value_count, r.max_subkey_name_len, r.max_value_name_len,
            r.max_value_data_size, r.sd_size = string.unpack("<I4I4I4I4I4I4", a, 25)
        r.volatile = a:byte(49) ~= 0
        r.symlink = a:byte(50) ~= 0
        r.hive_generation = string.unpack("<I8", a, 57)
        if r.ret == 0 then r.name = name_i and r.out_bufs[name_i]:sub(1, r.name_len) or "" end
        return r
    end
end

local function layer_txn_op(cmd)
    return function(fd, o)
        o = o or {}
        local s = bufset()
        local args_i = s:add(zeros(24))
        local layer_i = s:add(o.layer)
        s.bufs[args_i] = string.pack("<I4I4I8i4I4",
            o.layer and #o.layer or 0, o.pad0 or 0, 0, o.txn_fd or -1, o.pad1 or 0)
        s:nest(args_i, layer_i, 8)
        return sys.NR.ioctl, s:spec({ fd, cmd, 0 }, { 2 }), function(r) return r end
    end
end
B.delete_key = layer_txn_op(M.IOC.DELETE_KEY)
B.hide_key = layer_txn_op(M.IOC.HIDE_KEY)

--- `o`: sd_len (4096; 0 probes).
B.get_security = function(fd, security_info, o)
    o = o or {}
    local sd_len = o.sd_len or 4096
    local s = bufset()
    local args_i = s:add(zeros(16))
    local sd_i = sd_len > 0 and s:add(zeros(sd_len)) or nil
    s.bufs[args_i] = string.pack("<I4I4I8", security_info, sd_len, 0)
    s:nest(args_i, sd_i, 8)
    return sys.NR.ioctl, s:spec({ fd, M.IOC.GET_SECURITY, 0 }, { 2 }), function(r)
        r.sd_len = string.unpack("<I4", r.out_bufs[args_i], 5)
        if r.ret == 0 and sd_i then r.sd = r.out_bufs[sd_i]:sub(1, r.sd_len) end
        return r
    end
end

B.set_security = function(fd, security_info, sd, o)
    o = o or {}
    local s = bufset()
    local args_i = s:add(zeros(24))
    local sd_i = s:add(sd)
    s.bufs[args_i] = string.pack("<I4I4I8i4I4", security_info, #sd, 0, o.txn_fd or -1, o.pad or 0)
    s:nest(args_i, sd_i, 8)
    return sys.NR.ioctl, s:spec({ fd, M.IOC.SET_SECURITY, 0 }, { 2 }), function(r) return r end
end

B.notify = function(fd, filter, subtree, o)
    o = o or {}
    local s = bufset()
    s:add(string.pack("<I4I1c3", filter, subtree and (subtree == true and 1 or subtree) or 0,
        o.pad or zeros(3)))
    return sys.NR.ioctl, s:spec({ fd, M.IOC.NOTIFY, 0 }, { 2 }), function(r) return r end
end

B.flush = function(fd)
    return sys.NR.ioctl, { args = { fd, M.IOC.FLUSH, 0 } }, function(r) return r end
end

B.backup = function(fd, output_fd)
    local s = bufset()
    s:add(string.pack("<i4", output_fd))
    return sys.NR.ioctl, s:spec({ fd, M.IOC.BACKUP, 0 }, { 2 }), function(r) return r end
end

B.restore = function(fd, input_fd)
    local s = bufset()
    s:add(string.pack("<i4", input_fd))
    return sys.NR.ioctl, s:spec({ fd, M.IOC.RESTORE, 0 }, { 2 }), function(r) return r end
end

B.commit = function(txn_fd)
    return sys.NR.ioctl, { args = { txn_fd, M.IOC.COMMIT, 0 } }, function(r) return r end
end

B.txn_status = function(txn_fd)
    local s = bufset()
    s:add(zeros(8))
    return sys.NR.ioctl, s:spec({ txn_fd, M.IOC.TXN_STATUS, 0 }, { 2 }), function(r)
        if r.ret == 0 then r.state, r.terminal_errno = string.unpack("<I4i4", r.out_bufs[1]) end
        return r
    end
end

--- Read queued watch events from a key fd into decoded records.
B.read_events = function(fd, size)
    size = size or 65536
    return sys.NR.read, { args = { fd, 0, size }, bufs = { zeros(size) }, ptrs = { 1 } },
        function(r)
            if r.ret >= 0 then r.events = M.decode_events(r.out_bufs[1]:sub(1, r.ret)) end
            return r
        end
end

M.build = B

-- Generate the two call forms from each builder.
for name, build in pairs(B) do
    M[name .. "_async"] = function(who, ...)
        local nr, spec, decode = build(...)
        local pending = who:syscall_async(nr, spec)
        return setmetatable({}, { __index = function(_, k)
            if k == "await" then
                return function() return decode(pending:await()) end
            end
            return pending[k]
        end })
    end
    M[name] = function(src, who, ...)
        local nr, spec, decode = build(...)
        local r
        if src then
            r = src:run(function() return who:syscall_async(nr, spec) end)
        else
            r = who:syscall(nr, spec)
        end
        return decode(r)
    end
end

--- reg_begin_transaction: contacts no source. Returns fd or nil, errno.
function M.begin_transaction(who)
    local r = who:syscall(M.SYS.BEGIN_TRANSACTION)
    if r.ret < 0 then return nil, r.errno end
    return r.ret
end

--- Decode watch records (§5.6.2): total_len u32, type u16, name_len
--- u16, name, then on a subtree watch path_depth u16 and that many
--- (len u16, bytes) components.
function M.decode_events(buf)
    local out, at = {}, 1
    while at + 8 <= #buf + 1 do
        local total, etype, name_len = string.unpack("<I4I2I2", buf, at)
        if total < 8 or at + total - 1 > #buf then break end
        local ev = { type = etype, total_len = total,
                     name = buf:sub(at + 8, at + 8 + name_len - 1) }
        local rest = at + 8 + name_len
        if rest + 2 <= at + total then
            local depth = string.unpack("<I2", buf, rest); rest = rest + 2
            ev.depth, ev.components = depth, {}
            for _ = 1, depth do
                if rest + 2 > at + total then break end
                local clen = string.unpack("<I2", buf, rest); rest = rest + 2
                ev.components[#ev.components + 1] = buf:sub(rest, rest + clen - 1)
                rest = rest + clen
            end
        end
        out[#out + 1] = ev
        at = at + total
    end
    return out
end

M.WATCH_NAME = {}
for k, v in pairs(M.WATCH) do M.WATCH_NAME[v] = k end

--- The token's LCS credential extension (PKM §3.2.2, §3.A): version 1,
--- reserved, scope GUID count, private layer count, the GUIDs, the
--- layer name lengths, the names. Pass as `lcs_credentials` in a
--- `token.mint` / `token.build_spec` spec to mint a principal that can
--- route to a private hive or resolve a private layer.
function M.lcs_credentials(scope_guids, private_layers, opts)
    opts = opts or {}
    scope_guids = scope_guids or {}
    private_layers = private_layers or {}
    local out = { string.pack("<I4I4I4I4", opts.version or 1, opts.reserved or 0,
        #scope_guids, #private_layers) }
    for _, g in ipairs(scope_guids) do out[#out + 1] = g end
    for _, n in ipairs(private_layers) do out[#out + 1] = string.pack("<I4", #n) end
    for _, n in ipairs(private_layers) do out[#out + 1] = n end
    return table.concat(out)
end

--- Create a layer live, as §5.3.3 says to: the metadata key and its
--- three values inside one transaction. Returns the layer key fd (or
--- nil, errno).
function M.create_layer(src, who, name, o)
    o = o or {}
    local txn = assert(M.begin_transaction(who))
    local r = M.create_key(src, who, {
        path = M.LAYERS_PATH .. "\\" .. name, txn_fd = txn, access = M.KEY_ALL_ACCESS,
    })
    if r.ret < 0 then sys.close(who, txn); return nil, r.errno end
    local fd = r.ret
    local function set(vname, vtype, data)
        local w = M.set_value(src, who, fd, vname, vtype, data, { txn_fd = txn })
        if w.ret ~= 0 then error("set " .. vname .. ": " .. sys.errname(w.errno)) end
    end
    set("Precedence", M.TYPE.DWORD, M.dword(o.precedence or 0))
    set("Enabled", M.TYPE.DWORD, M.dword(o.enabled == false and 0 or 1))
    if o.owner then set("Owner", M.TYPE.BINARY, o.owner) end
    local c = M.commit(src, who, txn)
    sys.close(who, txn)
    if c.ret ~= 0 then sys.close(who, fd); return nil, c.errno end
    return fd
end

--- A hand-built LCS call the builders above cannot express — a NULL
--- pointer behind a non-zero length, a sentinel-filled output buffer, a
--- deliberately wrong ioctl size or direction (§5.5.1).
---
--- `call.nr` is the syscall number (`sys.NR.ioctl` or one of `M.SYS`),
--- `call.args` the raw syscall arguments, `call.ptr_slot` the argument
--- slot that receives a pointer to `call.struct` (2 for an ioctl, 0 for
--- `reg_create_key`), and `call.children` a list of
--- `{ offset =, bytes = }` nested into that structure. A child with no
--- `bytes` leaves its pointer NULL, which is how a case probes a length
--- with no buffer; `bytes` may be pre-filled with a sentinel to show an
--- output buffer was left unwritten. `src` may be nil for a call that
--- contacts no source.
---
--- Returns the raw result plus `args_out` (the structure as it came
--- back) and `child_out[i]` for each child that carried bytes.
function M.raw_call(src, who, call)
    local s = bufset()
    local args_i = s:add(call.struct)
    local idx = {}
    for i, c in ipairs(call.children or {}) do
        local ci = c.bytes and s:add(c.bytes) or nil
        idx[i] = ci
        s:nest(args_i, ci, c.offset)
    end
    local spec = s:spec(call.args, { call.ptr_slot })
    local r
    if src then
        r = src:run(function() return who:syscall_async(call.nr, spec) end)
    else
        r = who:syscall(call.nr, spec)
    end
    r.args_out = r.out_bufs and r.out_bufs[args_i] or nil
    r.child_out = {}
    for i, ci in pairs(idx) do
        r.child_out[i] = r.out_bufs and r.out_bufs[ci] or nil
    end
    return r
end

-- ---- the backup stream (§5.9.1; the format is PSPK §5.2–§5.4) --------
--
-- A test about backup decodes what LCS wrote; a test about restore has
-- to build or edit a stream, and the trailer's SHA-256 means editing
-- one byte means recomputing the digest. Both halves live here.

local SHA_K = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}
local function rotr(x, n) return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF end

--- SHA-256 of a byte string, as the 32 raw bytes a `TRAILER` carries.
function M.sha256(msg)
    local h = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 }
    local len = #msg
    msg = msg .. "\128" .. string.rep("\0", (55 - len) % 64) .. string.pack(">I8", len * 8)
    for i = 1, #msg, 64 do
        local w = {}
        for j = 0, 15 do w[j] = string.unpack(">I4", msg, i + j * 4) end
        for j = 16, 63 do
            local x, y = w[j - 15], w[j - 2]
            local s0 = rotr(x, 7) ~ rotr(x, 18) ~ (x >> 3)
            local s1 = rotr(y, 17) ~ rotr(y, 19) ~ (y >> 10)
            w[j] = (w[j - 16] + s0 + w[j - 7] + s1) & 0xFFFFFFFF
        end
        local a, b, c, d, e, f, g, hh = h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8]
        for j = 0, 63 do
            local S1 = rotr(e, 6) ~ rotr(e, 11) ~ rotr(e, 25)
            local ch = (e & f) ~ ((~e & 0xFFFFFFFF) & g)
            local t1 = (hh + S1 + ch + SHA_K[j + 1] + w[j]) & 0xFFFFFFFF
            local S0 = rotr(a, 2) ~ rotr(a, 13) ~ rotr(a, 22)
            local t2 = (S0 + ((a & b) ~ (a & c) ~ (b & c))) & 0xFFFFFFFF
            hh = g; g = f; f = e; e = (d + t1) & 0xFFFFFFFF
            d = c; c = b; b = a; a = (t1 + t2) & 0xFFFFFFFF
        end
        local v = { a, b, c, d, e, f, g, hh }
        for j = 1, 8 do h[j] = (h[j] + v[j]) & 0xFFFFFFFF end
    end
    local out = {}
    for j = 1, 8 do out[j] = string.pack(">I4", h[j]) end
    return table.concat(out)
end

M.BACKUP_MAGIC = "PEIOSREG"
M.BACKUP_VERSION = 21
M.KEY_FLAG_VOLATILE, M.KEY_FLAG_SYMLINK = 0x1, 0x2

--- One record: the six-byte framing header (`record_type` u16,
--- `record_len` u32 counting the header) and the payload.
function M.backup_record(rtype, payload)
    payload = payload or ""
    return string.pack("<I2I4", rtype, 6 + #payload) .. payload
end

local function lp(s) return string.pack("<s4", s) end

--- `HEADER`. `o.version`, `o.min_reader` (both 21), `o.magic`,
--- `o.timestamp` — each so a case can write the wrong one.
function M.backup_header(root_guid, hive_name, o)
    o = o or {}
    return M.backup_record(M.BACKUP_RECORD.HEADER,
        (o.magic or M.BACKUP_MAGIC) ..
        string.pack("<I4I4i8", o.version or M.BACKUP_VERSION,
            o.min_reader or M.BACKUP_VERSION, o.timestamp or 0) ..
        root_guid .. lp(hive_name))
end

--- `LAYER`, a manifest entry: `o.precedence` (0), `o.enabled` (1),
--- `o.owner` (a binary SID, empty by default).
function M.backup_layer(name, o)
    o = o or {}
    return M.backup_record(M.BACKUP_RECORD.LAYER,
        lp(name) .. string.pack("<I4I1", o.precedence or 0,
            o.enabled == nil and 1 or (o.enabled and 1 or 0)) .. lp(o.owner or ""))
end

--- `KEY`: `o.flags` (bit 0 volatile, bit 1 symlink), `o.sd`
--- (a permissive one by default), `o.lwt`.
function M.backup_key(guid, o)
    o = o or {}
    return M.backup_record(M.BACKUP_RECORD.KEY,
        guid .. string.pack("<I4", o.flags or 0) ..
        lp(o.sd or M.permissive_sd()) .. string.pack("<i8", o.lwt or 0))
end

--- `PATH_ENTRY`. A nil `child_guid` writes the all-zero GUID, which is
--- what HIDDEN means.
function M.backup_path_entry(parent_guid, child_name, child_guid, layer, seq)
    return M.backup_record(M.BACKUP_RECORD.PATH_ENTRY,
        parent_guid .. lp(child_name) .. (child_guid or M.NULL_GUID) ..
        lp(layer or "base") .. string.pack("<I8", seq or 1))
end

--- `VALUE`.
function M.backup_value(key_guid, name, vtype, data, layer, seq)
    return M.backup_record(M.BACKUP_RECORD.VALUE,
        key_guid .. lp(name) .. string.pack("<I4", vtype) .. lp(data or "") ..
        lp(layer or "base") .. string.pack("<I8", seq or 1))
end

--- `BLANKET_TOMBSTONE`.
function M.backup_blanket(key_guid, layer, seq)
    return M.backup_record(M.BACKUP_RECORD.BLANKET_TOMBSTONE,
        key_guid .. lp(layer or "base") .. string.pack("<I8", seq or 1))
end

--- The records concatenated and closed with a `TRAILER` whose record
--- count and SHA-256 are computed over them, as §5.9.1 requires. The
--- checksum covers everything up to and including the trailer's own
--- framing header and `RecordCount`. `o.count` and `o.checksum`
--- override each, for the cases about a stream that fails its own
--- self-verification; `o.trailing` appends bytes after it.
function M.backup_stream(records, o)
    o = o or {}
    local body = table.concat(records)
    local count = o.count or (#records + 1)
    local prefix = body .. string.pack("<I2I4I8", M.BACKUP_RECORD.TRAILER, 46, count)
    return prefix .. (o.checksum or M.sha256(prefix)) .. (o.trailing or "")
end

local function decode_backup_record(rec)
    local p, at = rec.payload, 1
    if rec.type == M.BACKUP_RECORD.HEADER then
        rec.magic = p:sub(1, 8)
        rec.version, rec.min_reader, rec.timestamp = string.unpack("<I4I4i8", p, 9)
        rec.root_guid = p:sub(25, 40)
        rec.hive = string.unpack("<s4", p, 41)
    elseif rec.type == M.BACKUP_RECORD.LAYER then
        rec.name, at = string.unpack("<s4", p, 1)
        rec.precedence, rec.enabled, at = string.unpack("<I4I1", p, at)
        rec.owner = string.unpack("<s4", p, at)
    elseif rec.type == M.BACKUP_RECORD.KEY then
        rec.guid = p:sub(1, 16)
        rec.flags = string.unpack("<I4", p, 17)
        rec.sd, at = string.unpack("<s4", p, 21)
        rec.volatile = rec.flags & M.KEY_FLAG_VOLATILE ~= 0
        rec.symlink = rec.flags & M.KEY_FLAG_SYMLINK ~= 0
        rec.lwt = string.unpack("<i8", p, at)
    elseif rec.type == M.BACKUP_RECORD.PATH_ENTRY then
        rec.parent = p:sub(1, 16)
        rec.name, at = string.unpack("<s4", p, 17)
        rec.child = p:sub(at, at + 15); at = at + 16
        rec.hidden = rec.child == M.NULL_GUID
        rec.layer, at = string.unpack("<s4", p, at)
        rec.sequence = string.unpack("<I8", p, at)
    elseif rec.type == M.BACKUP_RECORD.VALUE then
        rec.key_guid = p:sub(1, 16)
        rec.name, at = string.unpack("<s4", p, 17)
        rec.vtype, at = string.unpack("<I4", p, at)
        rec.data, at = string.unpack("<s4", p, at)
        rec.layer, at = string.unpack("<s4", p, at)
        rec.sequence = string.unpack("<I8", p, at)
    elseif rec.type == M.BACKUP_RECORD.BLANKET_TOMBSTONE then
        rec.key_guid = p:sub(1, 16)
        rec.layer, at = string.unpack("<s4", p, 17)
        rec.sequence = string.unpack("<I8", p, at)
    elseif rec.type == M.BACKUP_RECORD.TRAILER then
        rec.count = string.unpack("<I8", p, 1)
        rec.checksum = p:sub(9, 40)
    end
    return rec
end

--- Split a stream into records, each `{ type, len, offset, payload }`
--- plus that type's fields. The result also carries `header`,
--- `trailer`, `records`, the records by type (`layers`, `keys`,
--- `path_entries`, `values`, `blankets`), and `count_ok` /
--- `checksum_ok` from verifying the trailer against the bytes.
--- Raises on framing the format forbids, since a test asserting on a
--- decoded field wants that as a failure, not as nil.
function M.decode_backup_stream(bytes)
    local s = { bytes = bytes, records = {}, layers = {}, keys = {},
                path_entries = {}, values = {}, blankets = {} }
    local at = 1
    while at <= #bytes do
        assert(#bytes - at + 1 >= 6, "truncated record framing at offset " .. at - 1)
        local rtype, rlen = string.unpack("<I2I4", bytes, at)
        assert(rlen >= 6, "record_len " .. rlen .. " below the six-byte minimum")
        assert(at + rlen - 1 <= #bytes, "record at offset " .. at - 1 .. " runs past the stream")
        local rec = decode_backup_record({ type = rtype, len = rlen, offset = at - 1,
                                           payload = bytes:sub(at + 6, at + rlen - 1) })
        s.records[#s.records + 1] = rec
        if rtype == M.BACKUP_RECORD.HEADER then s.header = rec
        elseif rtype == M.BACKUP_RECORD.LAYER then s.layers[#s.layers + 1] = rec
        elseif rtype == M.BACKUP_RECORD.KEY then s.keys[#s.keys + 1] = rec
        elseif rtype == M.BACKUP_RECORD.PATH_ENTRY then s.path_entries[#s.path_entries + 1] = rec
        elseif rtype == M.BACKUP_RECORD.VALUE then s.values[#s.values + 1] = rec
        elseif rtype == M.BACKUP_RECORD.BLANKET_TOMBSTONE then s.blankets[#s.blankets + 1] = rec
        elseif rtype == M.BACKUP_RECORD.TRAILER then s.trailer = rec end
        at = at + rlen
    end
    if s.trailer then
        s.count_ok = s.trailer.count == #s.records
        s.checksum_ok = s.trailer.checksum ==
            M.sha256(bytes:sub(1, s.trailer.offset + 14))
    end
    return s
end

--- The section a record belongs to: the index into `stream.keys` of
--- the last `KEY` record at or before it, or 0 for the records before
--- the first one.
function M.backup_section_of(stream, rec)
    local n = 0
    for _, r in ipairs(stream.records) do
        if r.type == M.BACKUP_RECORD.KEY then n = n + 1 end
        if r == rec then return n end
    end
    return nil
end

-- ---- streams through a file ------------------------------------------
--
-- Backup writes to an fd and restore reads from one. A file on a
-- tmpfs is the shape both cases want: no capacity limit to deadlock
-- against, and the bytes can be read back and decoded.

--- Create (or truncate) `path` in `who`'s process and return the fd.
function M.stream_file(who, path, flags)
    local fd, errno = sys.open(who, path,
        flags or (sys.O.RDWR | sys.O.CREAT | sys.O.TRUNC), 420)
    return fd, errno
end

--- Every byte of `fd` from offset 0.
function M.read_all(who, fd)
    sys.lseek(who, fd, 0, 0)
    local out = {}
    while true do
        local chunk, errno = sys.read(who, fd, 65536)
        if not chunk then return nil, errno end
        if #chunk == 0 then break end
        out[#out + 1] = chunk
    end
    return table.concat(out)
end

--- `REG_IOC_BACKUP` of `key_fd` into a fresh file at `path`, then the
--- stream decoded. Returns the ioctl result and, on success, the
--- decoded stream and its raw bytes.
function M.backup_to_file(src, who, key_fd, path)
    local fd = assert(M.stream_file(who, path), "creating " .. path)
    local r = M.backup(src, who, key_fd, fd)
    if r.ret ~= 0 then sys.close(who, fd); return r end
    local bytes = M.read_all(who, fd)
    sys.close(who, fd)
    return r, M.decode_backup_stream(bytes), bytes
end

--- Write `bytes` to `path` and `REG_IOC_RESTORE` `key_fd` from it.
--- Returns the ioctl result.
function M.restore_bytes(src, who, key_fd, path, bytes)
    local fd = assert(M.stream_file(who, path), "creating " .. path)
    local n = sys.write(who, fd, bytes)
    assert(n.ret == #bytes, "short write staging the stream")
    sys.lseek(who, fd, 0, 0)
    local r = M.restore(src, who, key_fd, fd)
    sys.close(who, fd)
    return r
end

-- ---- watch queues (§5.6) --------------------------------------------

local F_SETFL = 4

--- Put a key fd into `O_NONBLOCK`, so that `read_events` on an empty
--- queue answers `EAGAIN` instead of blocking the worker (§5.6.2).
--- A key fd comes back blocking, so every case that drains a watch
--- queue and then asserts it is empty wants this first.
function M.nonblock(who, fd)
    local r = who:syscall(72, { args = { fd, F_SETFL, O_NONBLOCK } }) -- fcntl
    return r.ret == 0, r.errno
end

--- Open a key and put its fd in non-blocking mode. Same arguments as
--- `open_key`; returns the raw result, whose `ret` is the fd.
function M.open_watchable(src, who, parent_fd, path, access, flags)
    local r = M.open_key(src, who, parent_fd, path, access, flags)
    if r.ret >= 0 then M.nonblock(who, r.ret) end
    return r
end

--- Every record queued on an armed non-blocking fd, across as many
--- `read()` calls as it takes. Returns the decoded list (empty when
--- the queue is), so a case can assert on what a mutation delivered.
function M.drain_events(who, fd, size)
    local out = {}
    while true do
        local r = M.read_events(nil, who, fd, size)
        if r.ret <= 0 or not r.events or #r.events == 0 then return out end
        for _, e in ipairs(r.events) do out[#out + 1] = e end
    end
end

--- A one-line summary of a record list — `VALUE_SET(Answer)
--- SUBKEY_CREATED(Child@1:A/B)` — for an assertion message.
function M.event_summary(events)
    local out = {}
    for _, e in ipairs(events or {}) do
        local s = (M.WATCH_NAME[e.type] or tostring(e.type)) .. "(" .. e.name
        if e.depth then
            s = s .. "@" .. e.depth
            if e.components and #e.components > 0 then
                s = s .. ":" .. table.concat(e.components, "/")
            end
        end
        out[#out + 1] = s .. ")"
    end
    return #out > 0 and table.concat(out, " ") or "<nothing>"
end

--- The event type names of a record list, in order.
function M.event_types(events)
    local out = {}
    for _, e in ipairs(events or {}) do
        out[#out + 1] = M.WATCH_NAME[e.type] or tostring(e.type)
    end
    return out
end

--- `poll()` one fd for `POLLIN`, returning the revents mask. This is
--- how §5.6.1's "the fd is pollable" is observed.
function M.poll_revents(who, fd, timeout_ms)
    local p = who:syscall(sys.NR.poll, {
        args = { 0, 1, timeout_ms or 0 },
        bufs = { string.pack("<i4i2i2", fd, 0x1, 0) }, ptrs = { 0 },
    })
    if p.ret < 0 then return nil, p.errno end
    return (select(3, string.unpack("<i4i2i2", p.out_bufs[1])))
end

--- Seed one key in one layer under an existing parent GUID, without
--- creating the intermediates `Source:key` would create in that layer.
--- §5.2.5's overlay pattern needs exactly this: a path entry for
--- `(parent, name, layer)` pointing at a fresh key record, with the
--- ancestors left in whatever layer already names them. `o`: `sd`,
--- `volatile`, `symlink`, `seq`, `guid`. Returns the new key's GUID.
--- Host-side seeding: call it before `register`.
function M.seed_key_in_layer(src, parent, name, layer, o)
    o = o or {}
    local guid = o.guid or M.guid()
    src.store.keys[guid] = {
        name = name, parent = parent, sd = o.sd or M.permissive_sd(),
        volatile = o.volatile or false, symlink = o.symlink or false, lwt = o.lwt or 0,
    }
    local per = src.store.entries[parent]
    if not per then per = {}; src.store.entries[parent] = per end
    local slot = per[M.fold(name)]
    if not slot then slot = { name = name, by_layer = {} }; per[M.fold(name)] = slot end
    slot.by_layer[M.fold(layer)] = {
        layer = layer, hidden = false, guid = guid, seq = o.seq or src:next_seq(),
    }
    return guid
end

--- The path entry the source holds for `(parent, name, layer)`, or nil
--- — `{ layer, hidden, guid, seq }`. What a source stores is what LCS
--- told it to store, so this is how a case checks that a create, a
--- hide or a delete reached the storage it claims to have reached.
function M.entry(src, parent, name, layer)
    local per = src.store.entries[parent]
    local slot = per and per[M.fold(name)]
    return slot and slot.by_layer[M.fold(layer or "base")] or nil
end

--- The GUID LCS minted in the most recent `RSI_CREATE_KEY` at or after
--- log index `from` (`src:mark()`), or nil. Key GUIDs are assigned by
--- LCS and pushed to the source (§5.2.3), so the request is the only
--- place a test can see one for a key it just created.
function M.created_guid(src, from)
    local reqs = src:served(M.OP.CREATE_KEY, from)
    local last = reqs[#reqs]
    return last and last.payload:sub(1, 16) or nil
end

--- The key name an `RSI_LOOKUP` request asked about, or nil for any
--- other op. A LOOKUP payload is the parent GUID followed by a
--- length-prefixed name, so this is how a case reads the bootstrap's
--- walk out of `src.log`: "System", "Registry", "Layers", "KMES",
--- "Network" (§5.10.4).
function M.lookup_name(req)
    if not req or req.op ~= M.OP.LOOKUP or #req.payload < 20 then return nil end
    local ok, name = pcall(string.unpack, "<s4", req.payload, 17)
    return ok and name or nil
end

return M
