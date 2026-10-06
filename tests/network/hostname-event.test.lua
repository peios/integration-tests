-- netd TRM §8.4 — what is recorded: `netd.hostname.changed` for each
-- sethostname(2) that changes the kernel's name, with the name before and
-- after; nothing for a call that leaves the name as it was; and as
-- `subject.token.sid` the principal that acted (PGSS §6.4): the requester
-- when the change is made on a `reconcile` request's pass, netd's own user
-- (SYSTEM) when netd made it on its own authority.
--
-- The records are read off the KMES ring (helpers.kmes), not out of
-- eventd: what is under test is what netd writes, and the ring has it the
-- moment it is written. One vCPU, so CPU 0's ring sees everything.
--
-- No gateway: the name comes from the registry's `Hostname`, which netd
-- applies with or without a network. The image boots with the kernel's
-- `(none)`.
--
-- The requester is a minted administrator (helpers.token `as_principal`),
-- not the agent: the agent is SYSTEM, which is netd's own user too, and a
-- requester indistinguishable from netd would prove nothing.
--
-- Order matters and the tests share the machine: the first change after
-- boot, a name the kernel already has, then a change on a requested pass.

local peinit = require("helpers.peinit")
local network = require("helpers.network")
local kmes = require("helpers.kmes")
local ntfe = require("helpers.ntfe")
local unixsock = require("helpers.unixsock")
local msgpack = require("helpers.msgpack")
local sys = require("helpers.sys")
local token = require("helpers.token")

peinit.claim(1)

local sut = network.boot({})

local TYPE = "netd.hostname.changed"
-- S-1-5-18, netd's own user, in its binary form.
local SYSTEM_SID = "\1\1\0\0\0\0\0\5\18\0\0\0"

local G = token.GROUP
local ENABLED = G.MANDATORY | G.ENABLED_BY_DEFAULT | G.ENABLED
-- A user who is also a member of Administrators, whom the control object's
-- default descriptor admits to `reconcile`. Built fresh for each mint.
local REQUESTER = token.SID.TEST_USER
local function ADMIN()
    return { user_sid = REQUESTER, groups = {
        { sid = token.SID.EVERYONE, attributes = ENABLED },
        { sid = token.SID.AUTHENTICATED_USERS, attributes = ENABLED },
        { sid = token.SID.ADMINISTRATORS, attributes = ENABLED },
    } }
end

local function kernel_name()
    return (sut:read_file("/proc/sys/kernel/hostname"):gsub("%s+$", ""))
end

--- Attach to the ring now; the returned reader collects `TYPE` records.
local function recorder(t)
    local ring, errno = kmes.attach(sut, 0)
    t:assert(ring, "a KMES ring attaches: " .. sys.errname(errno or 0))
    local seen = {}
    local r = {}
    function r.poll()
        for _, e in ipairs(kmes.drain(ring)) do
            if e.type == TYPE then seen[#seen + 1] = e end
        end
        return seen
    end
    --- Wait for at least `n` records; returns them.
    function r.wait(n, desc)
        local ok = pcall(wait_until, function() return #r.poll() >= n end,
            { timeout = 10, interval = 0.2, desc = desc })
        t:assert(ok, desc .. " (" .. #seen .. " seen)")
        return seen
    end
    function r.close() kmes.detach(ring) end
    return r
end

local function cfg(e) return e.payload and e.payload.config or {} end
local function subject_sid(e)
    local s = e.payload and e.payload.subject
    return s and s.token and s.token.sid
end

test("a name netd sets on its own authority is recorded as netd.hostname.changed, with the kernel's name before it and netd as the subject",
    { spec = "netd *hostname.change-recorded" }, function(t)
        t:assert_eq(kernel_name(), "(none)", "the machine boots with the kernel's own name")
        local rec = recorder(t)
        network.write(sut, network.KEY, { Hostname = "sz:evt-one" })
        t:assert(wait_until(function() return kernel_name() == "evt-one" end,
            { timeout = 15, interval = 0.25, desc = "the kernel to take the name" }), "netd set the name")
        local seen = rec.wait(1, "a netd.hostname.changed record")
        rec.close()
        t:assert_eq(#seen, 1, "one record for one change")
        local e = seen[1]
        t:assert(e.payload, "the payload decodes: " .. tostring(e.payload_error))
        t:assert_eq(e.origin, kmes.ORIGIN.USERSPACE, "written by a userspace emitter")
        t:assert_eq(cfg(e).name, "Hostname", "config.name is the setting")
        t:assert_eq(cfg(e).text, "evt-one", "config.text is the name now in force")
        t:assert_eq(cfg(e)["text-previous"], "(none)", "config.text-previous is the kernel's name before it")
        t:assert_eq(subject_sid(e), SYSTEM_SID,
            "a change after a registry write names netd's own user, SYSTEM, as subject.token.sid")
    end)

test("setting the name the kernel already has records nothing",
    { spec = "netd *hostname.change-recorded" }, function(t)
        sut:run("hostname evt-same"):assert_ok()
        t:assert_eq(kernel_name(), "evt-same", "the kernel took a hand change")
        local rec = recorder(t)
        network.write(sut, network.KEY, { Hostname = "sz:evt-same" })
        t:assert(wait_until(function() return network.status(sut).hostname == "evt-same" end,
            { timeout = 15, interval = 0.25, desc = "netd to set evt-same" }),
            "netd set the name the kernel already had")
        -- Give a record that was going to come time to arrive.
        sut:run("sleep 1")
        local seen = rec.poll()
        rec.close()
        t:assert_eq(#seen, 0, "no record: the kernel's name did not change")
    end)

test("a change made on a reconcile request's pass names the requester as the subject",
    { spec = "netd *hostname.requester-recorded" }, function(t)
        -- netd stopped, the registry written and a `reconcile` request
        -- queued by the administrator: when it continues, the watch is read
        -- first but only reloads the configuration, and the request's pass
        -- is the one that sets the name.
        local pid = network.netd_pid(sut)
        t:assert(pid, "netd is running")
        local rec = recorder(t)
        local ok, err = pcall(function()
            token.as_principal(t, sut, ADMIN(), function(w)
                local fd, e = unixsock.socket(w, unixsock.AF_UNIX, unixsock.SOCK.STREAM)
                t:assert(fd, "socket: " .. tostring(e))
                peinit.signal(sut, pid, "STOP")
                local inner_ok, inner_err = pcall(function()
                    network.write(sut, network.KEY, { Hostname = "sz:evt-asked" })
                    local r = unixsock.connect(w, fd, network.CONTROL)
                    t:assert_eq(r.ret, 0, "connect to netd's control socket while netd is stopped")
                    local payload = msgpack.encode({ query = "reconcile" })
                    ntfe.send(w, fd, string.pack("<I4", #payload) .. payload)
                    peinit.signal(sut, pid, "CONT")
                    local head = ntfe.recv(w, fd, 10000, 4)
                    t:assert(head and #head == 4, "netd answered the reconcile request")
                    local body = ntfe.recv(w, fd, 5000, string.unpack("<I4", head))
                    local reply = body and msgpack.decode(body)
                    t:assert(reply and reply.ok, "and the administrator's pass succeeded: "
                        .. tostring(reply and reply.error))
                end)
                peinit.signal(sut, pid, "CONT", { check = false })
                sys.close(w, fd)
                if not inner_ok then error(inner_err, 0) end
            end)
        end)
        peinit.signal(sut, pid, "CONT", { check = false })
        if not ok then rec.close(); error(err, 0) end
        t:assert_eq(kernel_name(), "evt-asked", "the requested pass set the name")
        local seen = rec.wait(1, "a netd.hostname.changed record")
        rec.close()
        t:assert_eq(#seen, 1, "one record")
        local e = seen[1]
        t:assert_eq(cfg(e).text, "evt-asked", "config.text is the new name")
        t:assert_eq(cfg(e)["text-previous"], "evt-same", "config.text-previous the name before it")
        t:assert(REQUESTER ~= SYSTEM_SID, "the requester is a principal other than netd")
        t:assert_eq(subject_sid(e), REQUESTER, "subject.token.sid is the requester's user SID, in binary")
    end)
