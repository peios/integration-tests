-- A Machine-hive LCS registry source served from Lua, for the cases
-- that need KMES (or anything else kernel-side) to read live
-- configuration on the kernel-only profile — where no registryd
-- exists.
--
-- Shape: a worker holds /dev/pkm_registry open O_NONBLOCK (the source
-- read path honours it) and registers a "Machine" hive; the host pumps
-- it — read one request, dispatch against an in-Lua key/value store,
-- write one response. The wire protocol is PSD-005 §7 RSI: 22-byte
-- request header (total_len u32, request_id u64, op u16, txn u64),
-- responses of header + status u32 + payload, one read() per request
-- and one write() per response. loregd is the reference peer; this
-- mirrors its codec exactly.
--
-- LCS's source bootstrap runs on a kernel workqueue, so registration
-- returns first and the requests arrive to the pump afterwards — a
-- single serially-driven worker never deadlocks. Anything the TEST
-- does that triggers source traffic (a reg syscall, which LCS routes
-- here) must run as a worker async while the host pumps; see
-- `Source:pump_during`.
--
-- Deliberate simplifications, fine for a test hive: transactions are
-- applied eagerly (an abort does not roll back), sequence CAS is not
-- enforced, and name folding is ASCII-lower (the canonical KMES names
-- and everything tests seed are ASCII).

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")

local M = {}

local REG_SRC_REGISTER = 0x40185200
local O_NONBLOCK = 0x800

M.SYS = { OPEN_KEY = 1100, CREATE_KEY = 1101, BEGIN_TRANSACTION = 1102 }
M.IOC = {
    QUERY_VALUE = 0xC0405200, -- _IOWR('R', 0, 64)
    SET_VALUE = 0x40405201,   -- _IOW('R', 1, 64)
}
M.KEY_ALL_ACCESS = 0x000F003F
M.TYPE = { DWORD = 4, QWORD = 11, SZ = 1, BINARY = 3 }

local OP = {
    LOOKUP = 0x01, CREATE_ENTRY = 0x02, HIDE_ENTRY = 0x03,
    DELETE_ENTRY = 0x04, ENUM_CHILDREN = 0x05,
    CREATE_KEY = 0x10, READ_KEY = 0x11, WRITE_KEY = 0x12, DROP_KEY = 0x13,
    QUERY_VALUES = 0x20, SET_VALUE = 0x21, DELETE_VALUE = 0x22,
    BLANKET_TOMBSTONE = 0x23,
    BEGIN_TXN = 0x30, COMMIT_TXN = 0x31, ABORT_TXN = 0x32,
    FLUSH = 0x40, DELETE_LAYER = 0x50,
}
M.OP = OP

local STATUS = { OK = 0, NOT_FOUND = 1, EXISTS = 2, INVALID = 7 }

local RESPONSE_BIT = 0x8000
local LAYER = "base"

local function fold(name) return name:lower() end

-- A permissive key SD: Everyone gets KEY_ALL_ACCESS plus GENERIC_ALL,
-- inheritable. Unlike the DACL-only descriptors the file tests set,
-- LCS validates a source's key SDs as complete — owner and group must
-- be present — so this builds the full self-relative form: 20-byte
-- header, owner SID, group SID, DACL.
local function key_sd()
    local owner = kacs.SID.LOCAL_SYSTEM
    local group = kacs.SID.LOCAL_SYSTEM
    local acl = kacs.acl({
        kacs.ace(kacs.ACE_ALLOWED, M.KEY_ALL_ACCESS | 0x10000000,
            kacs.SID.EVERYONE, 3),
    })
    local SE_DACL_PRESENT, SE_SELF_RELATIVE = 0x0004, 0x8000
    local header = 20
    return string.pack("<I1I1I2I4I4I4I4", 1, 0,
        SE_DACL_PRESENT | SE_SELF_RELATIVE,
        header, header + #owner, 0, header + #owner + #group) ..
        owner .. group .. acl
end

-- ---- the store ------------------------------------------------------

local Source = {}
Source.__index = Source

local guid_counter = 0
function M.guid()
    guid_counter = guid_counter + 1
    return string.pack("<I8I8", 0x9e905e105e105e10, guid_counter)
end

function Source.new(vm)
    local self = setmetatable({}, Source)
    self.vm = vm
    self.keys = {}
    self.seq = 0
    self.log = {}
    self.root = M.guid()
    self.keys[self.root] = {
        name = "Machine", parent = string.rep("\0", 16), sd = key_sd(),
        children = {}, values = {}, volatile = false, symlink = false,
        lwt = 0,
    }
    return self
end

function Source:next_seq()
    self.seq = self.seq + 1
    return self.seq
end

--- Create (or return) a key at a backslash path under the root, e.g.
--- "System\\KMES". Host-side seeding; do it before `register`.
function Source:key(path)
    local at = self.root
    for part in path:gmatch("[^\\]+") do
        local k = self.keys[at]
        local child = k.children[fold(part)]
        if not child then
            local guid = M.guid()
            self.keys[guid] = {
                name = part, parent = at, sd = key_sd(), children = {},
                values = {}, volatile = false, symlink = false, lwt = 0,
            }
            child = { name = part, guid = guid, seq = self:next_seq() }
            k.children[fold(part)] = child
        end
        at = child.guid
    end
    return at
end

--- Seed one value on a key created with `Source:key`.
function Source:value(key_guid, name, vtype, data)
    self.keys[key_guid].values[fold(name)] = {
        name = name, type = vtype, data = data, seq = self:next_seq(),
    }
end

--- A REG_DWORD payload.
function M.dword(v) return string.pack("<I4", v) end
--- A REG_QWORD payload.
function M.qword(v) return string.pack("<I8", v) end

-- ---- wire -----------------------------------------------------------

local function put_str(s) return string.pack("<s4", s) end

local function get_str(buf, at)
    local s, nxt = string.unpack("<s4", buf, at)
    return s, nxt
end

local function meta_bytes(self, guid)
    local k = self.keys[guid]
    return guid .. put_str(k.sd) ..
        string.pack("<I1I1I8", k.volatile and 1 or 0, k.symlink and 1 or 0,
            k.lwt)
end

local function entry_bytes(child)
    return put_str(LAYER) .. string.pack("<I1", 0) .. child.guid ..
        string.pack("<I8", child.seq)
end

-- Handlers: payload in (after the header), status + payload out.
local handlers = {}

handlers[OP.LOOKUP] = function(self, p)
    local parent = p:sub(1, 16)
    local name = get_str(p, 17)
    local k = self.keys[parent]
    local child = k and k.children[fold(name)]
    if not child then return STATUS.NOT_FOUND, "" end
    return STATUS.OK, string.pack("<I4", 1) .. entry_bytes(child) ..
        string.pack("<I4", 1) .. meta_bytes(self, child.guid)
end

handlers[OP.ENUM_CHILDREN] = function(self, p)
    local parent = p:sub(1, 16)
    local k = self.keys[parent]
    if not k then return STATUS.NOT_FOUND, "" end
    local names, metas, count = {}, {}, 0
    for _, child in pairs(k.children) do
        count = count + 1
        names[#names + 1] = put_str(child.name) .. string.pack("<I4", 1) ..
            entry_bytes(child)
        metas[#metas + 1] = meta_bytes(self, child.guid)
    end
    return STATUS.OK, string.pack("<I4", count) .. table.concat(names) ..
        string.pack("<I4", #metas) .. table.concat(metas)
end

handlers[OP.READ_KEY] = function(self, p)
    local guid = p:sub(1, 16)
    local k = self.keys[guid]
    if not k then return STATUS.NOT_FOUND, "" end
    return STATUS.OK, put_str(k.name) .. k.parent .. put_str(k.sd) ..
        string.pack("<I1I1I8", k.volatile and 1 or 0, k.symlink and 1 or 0,
            k.lwt)
end

handlers[OP.QUERY_VALUES] = function(self, p)
    local guid = p:sub(1, 16)
    local at = 17
    local name; name, at = get_str(p, at)
    local all = p:byte(at) ~= 0
    local k = self.keys[guid]
    if not k then return STATUS.NOT_FOUND, "" end
    local out, count = {}, 0
    for _, v in pairs(k.values) do
        if all or fold(v.name) == fold(name) then
            count = count + 1
            out[#out + 1] = put_str(v.name) .. put_str(LAYER) ..
                string.pack("<I4", v.type) .. put_str(v.data) ..
                string.pack("<I8", v.seq)
        end
    end
    return STATUS.OK, string.pack("<I4", count) .. table.concat(out) ..
        string.pack("<I4", 0)
end

handlers[OP.CREATE_KEY] = function(self, p)
    local guid = p:sub(1, 16)
    local at = 17
    local name; name, at = get_str(p, at)
    local parent = p:sub(at, at + 15); at = at + 16
    local sd; sd, at = get_str(p, at)
    local volatile = p:byte(at) ~= 0
    local symlink = p:byte(at + 1) ~= 0
    self.keys[guid] = {
        name = name, parent = parent, sd = sd, children = {}, values = {},
        volatile = volatile, symlink = symlink, lwt = 0,
    }
    return STATUS.OK, ""
end

handlers[OP.CREATE_ENTRY] = function(self, p)
    local parent = p:sub(1, 16)
    local at = 17
    local name; name, at = get_str(p, at)
    local _; _, at = get_str(p, at) -- layer
    local child_guid = p:sub(at, at + 15); at = at + 16
    local seq = string.unpack("<I8", p, at)
    local k = self.keys[parent]
    if not k then return STATUS.NOT_FOUND, "" end
    k.children[fold(name)] = { name = name, guid = child_guid, seq = seq }
    if seq > self.seq then self.seq = seq end
    return STATUS.OK, ""
end

handlers[OP.SET_VALUE] = function(self, p)
    local guid = p:sub(1, 16)
    local at = 17
    local name; name, at = get_str(p, at)
    local _; _, at = get_str(p, at) -- layer
    local vtype = string.unpack("<I4", p, at); at = at + 4
    local data; data, at = get_str(p, at)
    local seq = string.unpack("<I8", p, at)
    local k = self.keys[guid]
    if not k then return STATUS.NOT_FOUND, "" end
    k.values[fold(name)] = { name = name, type = vtype, data = data,
                             seq = seq }
    if seq > self.seq then self.seq = seq end
    return STATUS.OK, ""
end

handlers[OP.DELETE_VALUE] = function(self, p)
    local guid = p:sub(1, 16)
    local name = get_str(p, 17)
    local k = self.keys[guid]
    if not k or not k.values[fold(name)] then return STATUS.NOT_FOUND, "" end
    k.values[fold(name)] = nil
    return STATUS.OK, ""
end

handlers[OP.WRITE_KEY] = function(self, p)
    local guid = p:sub(1, 16)
    local mask = string.unpack("<I4", p, 17)
    local at = 21
    local k = self.keys[guid]
    if not k then return STATUS.NOT_FOUND, "" end
    if mask & 1 ~= 0 then k.sd, at = get_str(p, at) end
    if mask & 2 ~= 0 then k.lwt = string.unpack("<I8", p, at) end
    return STATUS.OK, ""
end

local function drop_entry(self, p, hidden_only)
    local parent = p:sub(1, 16)
    local name = get_str(p, 17)
    local k = self.keys[parent]
    if not k or not k.children[fold(name)] then return STATUS.NOT_FOUND, "" end
    k.children[fold(name)] = nil
    return STATUS.OK, ""
end
handlers[OP.DELETE_ENTRY] = drop_entry
handlers[OP.HIDE_ENTRY] = drop_entry

handlers[OP.DROP_KEY] = function(self, p)
    self.keys[p:sub(1, 16)] = nil
    return STATUS.OK, ""
end

local function trivially_ok() return STATUS.OK, "" end
handlers[OP.BEGIN_TXN] = trivially_ok
handlers[OP.COMMIT_TXN] = trivially_ok
handlers[OP.ABORT_TXN] = trivially_ok
handlers[OP.FLUSH] = trivially_ok
handlers[OP.BLANKET_TOMBSTONE] = trivially_ok

handlers[OP.DELETE_LAYER] = function()
    return STATUS.OK, string.pack("<I4", 0)
end

-- ---- device ---------------------------------------------------------

--- Open the device in a dedicated worker and register the hive with
--- everything seeded so far. From here on, `pump` serves.
function Source:register()
    self.worker = self.vm:spawn_worker()
    local fd, errno = sys.open(self.worker, "/dev/pkm_registry",
        sys.O.RDWR | O_NONBLOCK)
    if not fd then
        self.worker:kill(); self.worker:join(); self.worker = nil
        return nil, "open /dev/pkm_registry: " .. sys.errname(errno)
    end
    self.fd = fd
    local hive_name = "Machine"
    local entry = string.pack("<I4I4I8", #hive_name, 0, 0) .. self.root ..
        string.pack("<I4I4", 0, 0) .. string.rep("\0", 16)
    local args = string.pack("<I4I4I8I8", 1, 0, self.seq, 0)
    local r = self.worker:syscall(sys.NR.ioctl, {
        args = { fd, REG_SRC_REGISTER, 0 },
        bufs = { args, entry, hive_name },
        ptrs = { 2 },
        nested = {
            { parent = 1, child = 2, offset = 16 },
            { parent = 2, child = 3, offset = 8 },
        },
    })
    if r.ret ~= 0 then
        self:close()
        return nil, "REG_SRC_REGISTER: " .. sys.errname(r.errno)
    end
    return true
end

--- Serve at most one pending request. Returns the op served, nil when
--- the device had nothing, or raises on a wire error.
function Source:step()
    local r = self.worker:syscall(sys.NR.read, {
        args = { self.fd, 0, 65536 },
        bufs = { string.rep("\0", 65536) },
        ptrs = { 1 },
    })
    if r.ret < 0 then
        if r.errno == sys.E.AGAIN then return nil end
        error("source read: " .. sys.errname(r.errno))
    end
    local msg = r.out_bufs[1]:sub(1, r.ret)
    local total, request_id, opcode = string.unpack("<I4I8I2", msg)
    assert(total == #msg, "framing: total_len " .. total .. " of " .. #msg)
    local payload = msg:sub(23)
    local handler = handlers[opcode]
    local status, body
    if handler then
        status, body = handler(self, payload)
    else
        status, body = STATUS.INVALID, ""
    end
    self.log[#self.log + 1] = { op = opcode, status = status,
                                guid = payload:sub(1, 16) }
    local resp = string.pack("<I4I8I2I4", 14 + 4 + #body, request_id,
        opcode | RESPONSE_BIT, status) .. body
    local w = self.worker:syscall(sys.NR.write, {
        args = { self.fd, 0, #resp },
        bufs = { resp },
        ptrs = { 1 },
    })
    assert(w.ret == #resp, "source write: " .. sys.errname(w.errno))
    return opcode
end

--- Pump until the device stays quiet for `quiet_ms` (default 150 —
--- the watch-refresh workqueue fires within a few ms of a commit).
--- Returns the number of requests served.
function Source:pump(quiet_ms)
    quiet_ms = quiet_ms or 150
    local served, idle = 0, 0
    while idle * 5 < quiet_ms do
        if self:step() then
            served = served + 1
            idle = 0
        else
            idle = idle + 1
            sys.nanosleep(self.vm, 0, 5 * 1000 * 1000)
        end
    end
    return served
end

--- Launch an operation that will bounce through this source (as a
--- pending async the caller constructs), pump until the traffic
--- settles, then await and return its result.
function Source:pump_during(launch, quiet_ms)
    local pending = launch()
    self:pump(quiet_ms)
    return pending:await()
end

--- True if an op with the given code (optionally against the given
--- key guid) was served since the log mark.
function Source:served(opcode, from, guid)
    for i = from or 1, #self.log do
        local e = self.log[i]
        if e.op == opcode and (not guid or e.guid == guid) then
            return true
        end
    end
    return false
end

function Source:close()
    if self.fd then sys.close(self.worker, self.fd); self.fd = nil end
    if self.worker then
        self.worker:kill(); self.worker:join(); self.worker = nil
    end
end

--- A source with Machine\System\KMES seeded with `values`
--- (name -> {type, data}), registered and bootstrap-pumped.
function M.kmes_source(vm, values)
    local src = Source.new(vm)
    local kmes_key = src:key("System\\KMES")
    for name, v in pairs(values or {}) do
        src:value(kmes_key, name, v[1], v[2])
    end
    src.kmes_key = kmes_key
    local ok, err = src:register()
    if not ok then return nil, err end
    src:pump()
    return src
end

M.Source = Source

-- ---- the writer side ------------------------------------------------

--- reg_open_key at an absolute path, e.g. "Machine\\System\\KMES".
--- The path walk round-trips to the source, so this — like every
--- registry syscall against a hive this helper serves — must run as
--- an async under `Source:pump_during`.
function M.open_key_async(who, path, access)
    return who:syscall_async(M.SYS.OPEN_KEY, {
        args = { -1, 0, access or M.KEY_ALL_ACCESS, 0 },
        bufs = { sys.cstr(path) },
        ptrs = { 1 },
    })
end

--- reg_create_key at an absolute path. Same async rule as open.
function M.create_key_async(who, path, access)
    return who:syscall_async(M.SYS.CREATE_KEY, {
        args = { 0, 0, 0 },
        -- parent_fd s32, pad, path_ptr, desired_access u32, flags u32,
        -- layer_ptr, txn_fd s32, pad, disposition_ptr
        bufs = {
            string.pack("<i4I4I8I4I4I8i4I4I8",
                -1, 0, 0, access or M.KEY_ALL_ACCESS, 0, 0, -1, 0, 0),
            sys.cstr(path),
        },
        ptrs = { 0 },
        nested = { { parent = 1, child = 2, offset = 8 } },
    })
end

--- REG_IOC_SET_VALUE on a key fd. Blocks in the kernel while LCS
--- round-trips to the source — run it through `Source:pump_during`.
function M.set_value_async(who, key_fd, name, vtype, data)
    return who:syscall_async(sys.NR.ioctl, {
        args = { key_fd, M.IOC.SET_VALUE, 0 },
        -- name_len u32, pad, name_ptr, type u32, data_len u32,
        -- data_ptr, layer_len u32, pad, layer_ptr, txn_fd s4, pad,
        -- expected_seq u64
        bufs = {
            string.pack("<I4I4I8I4I4I8I4I4I8i4I4I8",
                #name, 0, 0, vtype, #data, 0, 0, 0, 0, -1, 0, 0),
            name, data,
        },
        ptrs = { 2 },
        nested = {
            { parent = 1, child = 2, offset = 8 },
            { parent = 1, child = 3, offset = 24 },
        },
    })
end

return M
