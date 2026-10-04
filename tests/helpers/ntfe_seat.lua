-- Shared pieces for the §6.2 testset (seats, dispatch, refusals): a
-- policy that passes everything but what a test adds, hand-built frames
-- from the peer, IPv6 without DAD, and reading the wire.

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")

local M = {}

M.PASS_ALL = { all = { Actions = { "PASS" } } }

--- The baseline (PASS in all three layers) with `extra` rules merged in
--- per layer: `extra = { Flow = { name = rule }, ... }`. A layer named
--- with `false` is left out of the policy altogether.
function M.policy(extra)
    local p = {}
    for _, layer in ipairs({ "RawPacket", "Packet", "Flow" }) do
        local x = extra and extra[layer]
        if x ~= false then
            local roots = { all = { Actions = { "PASS" } } }
            for name, rule in pairs(x or {}) do roots[name] = rule end
            p[layer] = roots
        end
    end
    if extra and extra.values then p.values = extra.values end
    return p
end

--- Write a sysctl (or any small /proc, /sys file) as `who`. Returns
--- true, or nil, errno.
function M.write_file(who, path, value)
    local fd, errno = sys.open(who, path, sys.O.WRONLY)
    if not fd then return nil, errno end
    local r = sys.write(who, fd, tostring(value))
    sys.close(who, fd)
    if r.ret < 0 then return nil, r.errno end
    return true
end

--- Give `ifname` an IPv6 address with duplicate address detection off,
--- so the address is usable at once rather than tentative for a second.
function M.addr6(who, ifname, addr)
    assert(M.write_file(who, "/proc/sys/net/ipv6/conf/" .. ifname .. "/accept_dad", 0))
    return ntfe.if_addr(who, ifname, addr, 64)
end

--- SO_LINGER {on, 0}: the next close() sends a RST instead of a FIN.
function M.linger_zero(who, fd)
    return who:syscall(ntfe.NR.setsockopt, {
        args = { fd, 1, 13, 0, 8 },
        bufs = { string.pack("<i4i4", 1, 0) }, ptrs = { 3 },
    })
end

-- ---- frames ------------------------------------------------------------

--- An IPv4 UDP datagram as a frame from the peer to the VM. `o`: src,
--- dst (addresses), dst_mac, bad_csum, ip (options for ntfe.ipv4).
function M.udp4_frame(net, sport, dport, data, o)
    o = o or {}
    local src, dst = o.src or net.peer_addr, o.dst or net.addr
    local seg = ntfe.udp(src, dst, sport, dport, data or "x")
    if o.bad_csum then
        local csum = string.unpack(">I2", seg, 7)
        seg = seg:sub(1, 6) .. string.pack(">I2", csum ~ 0x5555) .. seg:sub(9)
    end
    return ntfe.eth(o.dst_mac or net.mac, net.peer_mac, ntfe.ETH_P.IP)
        .. ntfe.ipv4(src, dst, ntfe.IPPROTO.UDP, #seg, o.ip) .. seg
end

--- An IPv4 TCP segment as a frame from the peer to the VM.
function M.tcp4_frame(net, sport, dport, flags, o)
    o = o or {}
    local src, dst = o.src or net.peer_addr, o.dst or net.addr
    local seg = ntfe.tcp(src, dst, sport, dport, flags, o)
    return ntfe.eth(o.dst_mac or net.mac, net.peer_mac, ntfe.ETH_P.IP)
        .. ntfe.ipv4(src, dst, ntfe.IPPROTO.TCP, #seg, o.ip) .. seg
end

--- A raw IPv4 payload as a frame (a fragment, a mangled header...).
function M.ip4_raw_frame(net, ip_bytes, o)
    o = o or {}
    return ntfe.eth(o.dst_mac or net.mac, net.peer_mac, ntfe.ETH_P.IP) .. ip_bytes
end

-- ---- the wire ----------------------------------------------------------

--- Frames the peer's packet socket saw coming FROM the VM (`net.mac`),
--- within `ms` of quiet, filtered by `pred` when given.
function M.from_vm(peer, net, fd, ms, pred)
    local out = {}
    for _, f in ipairs(ntfe.frames(peer, fd, ms or 200)) do
        if f.src == net.mac and (not pred or pred(f)) then out[#out + 1] = f end
    end
    return out
end

--- Frames the peer's packet socket saw going TO the VM (sent by the peer).
function M.to_vm(peer, net, fd, ms, pred)
    local out = {}
    for _, f in ipairs(ntfe.frames(peer, fd, ms or 200)) do
        if f.src == net.peer_mac and (not pred or pred(f)) then out[#out + 1] = f end
    end
    return out
end

--- Discard whatever a packet socket holds.
function M.flush(who, fd)
    ntfe.frames(who, fd, 20)
end

-- ---- events ------------------------------------------------------------

M.SEAT_NAME = { [1] = "ingress", [2] = "egress", [3] = "local_in", [4] = "local_out" }
M.LAYER_NAME = { [0] = "Packet", [1] = "RawPacket", [2] = "Flow" }

--- The seat:layer judgments of `events` that satisfy `pred`, in seq
--- order, as one string: "ingress:RawPacket local_in:Packet ...".
function M.trail(events, pred)
    local list = {}
    for _, e in ipairs(events) do
        if not pred or pred(e) then list[#list + 1] = e end
    end
    table.sort(list, function(a, b) return a.seq < b.seq end)
    local out = {}
    for _, e in ipairs(list) do
        out[#out + 1] = M.SEAT_NAME[e.seat] .. ":" .. M.LAYER_NAME[e.layer]
    end
    return table.concat(out, " ")
end

return M
