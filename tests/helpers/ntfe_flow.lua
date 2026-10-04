-- The Flow layer's testset (PKM §6.8): what helpers/ntfe does not
-- already have.
--
-- `ct_create` makes a conntrack entry through ctnetlink, the one way to
-- give the kernel a flow that `init_conntrack()` never saw — and so one
-- that carries no NTFE extension and can hold no sentence. The rest finds
-- a flow in the dump by its tuple, and reads a socket's pending error
-- without hanging on it.

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")

local M = {}

-- ---- ctnetlink (<linux/netfilter/nfnetlink_conntrack.h>) ----------------

local NETLINK_NETFILTER = 12
local NFNL_SUBSYS_CTNETLINK = 1
local IPCTNL_MSG_CT_NEW = 0
local NLA_F_NESTED = 0x8000
local CTA = { TUPLE_ORIG = 1, TUPLE_REPLY = 2, TIMEOUT = 7 }
local CTA_TUPLE = { IP = 1, PROTO = 2 }
local CTA_IP = { V4_SRC = 1, V4_DST = 2 }
local CTA_PROTO = { NUM = 1, SRC_PORT = 2, DST_PORT = 3 }

local function nla(attr, payload)
    local len = 4 + #payload
    return string.pack("<I2I2", len, attr) .. payload .. string.rep("\0", (4 - len % 4) % 4)
end

local function nested(attr, payload) return nla(attr | NLA_F_NESTED, payload) end

local function tuple(src, dst, proto, sport, dport)
    return nested(CTA_TUPLE.IP,
            nla(CTA_IP.V4_SRC, ntfe.ip4(src)) .. nla(CTA_IP.V4_DST, ntfe.ip4(dst)))
        .. nested(CTA_TUPLE.PROTO,
            nla(CTA_PROTO.NUM, string.char(proto))
            .. nla(CTA_PROTO.SRC_PORT, string.pack(">I2", sport))
            .. nla(CTA_PROTO.DST_PORT, string.pack(">I2", dport)))
end

--- Create a conntrack entry with ctnetlink, in `who`'s network
--- namespace: `o` = { src, dst, sport, dport, protocol (UDP), timeout
--- (seconds, 60) }, IPv4. The entry is created by ctnetlink, not by
--- `init_conntrack()`, so it carries no NTFE extension. Returns true, or
--- nil, errno.
function M.ct_create(who, o)
    local proto = o.protocol or ntfe.IPPROTO.UDP
    local body = string.pack("<I1I1>I2", ntfe.AF_INET, 0, 0) -- struct nfgenmsg
        .. nested(CTA.TUPLE_ORIG, tuple(o.src, o.dst, proto, o.sport, o.dport))
        .. nested(CTA.TUPLE_REPLY, tuple(o.dst, o.src, proto, o.dport, o.sport))
        .. nla(CTA.TIMEOUT, string.pack(">I4", o.timeout or 60))
    local s = who:syscall(ntfe.NR.socket, 16, ntfe.SOCK_RAW, NETLINK_NETFILTER)
    if s.ret < 0 then return nil, s.errno end
    -- NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE
    local msg = string.pack("<I4I2I2I4I4", 16 + #body,
        (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_NEW,
        0x1 | 0x4 | 0x200 | 0x400, 1, 0) .. body
    local w = ntfe.send(who, s.ret, msg)
    if w.ret < 0 then sys.close(who, s.ret); return nil, w.errno end
    local r = who:syscall(sys.NR.read, {
        args = { s.ret, 0, 4096 }, bufs = { string.rep("\0", 4096) }, ptrs = { 1 },
    })
    sys.close(who, s.ret)
    if r.ret < 20 then return nil, r.errno end
    local _, reply_type = string.unpack("<I4I2", r.out_bufs[1])
    if reply_type ~= 2 then return nil, sys.E.IO end -- NLMSG_ERROR carries the ack
    local err = string.unpack("<i4", r.out_bufs[1], 17)
    if err ~= 0 then return nil, -err end
    return true
end

-- ---- finding things ---------------------------------------------------

--- The flows of a dump whose fields equal every field of `want`
--- (`src`, `dst`, `src_port`, `dst_port`, `protocol`, ...).
function M.flows_matching(flows, want)
    local out = {}
    for _, f in ipairs(flows) do
        local ok = true
        for k, v in pairs(want) do
            if f[k] ~= v then ok = false; break end
        end
        if ok then out[#out + 1] = f end
    end
    return out
end

--- The one flow of `E`'s dump matching `want`, or nil and how many did.
function M.flow(E, want)
    local list = M.flows_matching(assert(E:flows()), want)
    if #list ~= 1 then return nil, #list end
    return list[1]
end

--- The Flow-layer events of `events` matching `want`.
function M.flow_events(events, want)
    local w = { layer = ntfe.LAYER.FLOW }
    for k, v in pairs(want or {}) do w[k] = v end
    return ntfe.matching(events, w)
end

-- ---- sockets ----------------------------------------------------------

--- Wait up to `timeout_ms` (default 300) for an error to be pending on
--- `fd`, and take it (SO_ERROR). 0 when none came.
function M.pending_error(who, fd, timeout_ms)
    ntfe.poll(who, fd, ntfe.POLLERR, timeout_ms or 300)
    return ntfe.so_error(who, fd)
end

--- Read a /proc file whole. Returns the text, or nil, errno.
function M.read_file(who, path)
    local fd, e = sys.open(who, path, sys.O.RDONLY)
    if not fd then return nil, e end
    local data, err = sys.read(who, fd, 4096)
    sys.close(who, fd)
    return data, err
end

--- Write a /proc file. Returns the raw result.
function M.write_file(who, path, text)
    local fd, e = sys.open(who, path, sys.O.WRONLY)
    if not fd then return { ret = -1, errno = e } end
    local r = sys.write(who, fd, text)
    sys.close(who, fd)
    return r
end

return M
