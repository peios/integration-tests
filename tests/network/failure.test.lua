-- netd §11.1 — Failure modes, where the evidence is: every netd log line
-- goes to standard error, which peinit forwards to eventd, and is
-- mirrored to /dev/kmsg at KERN_INFO, KERN_WARNING or KERN_ERR.
--
-- Harness: the scripted gateway (helpers.gateway) and a whole Peios
-- (helpers.network). /dev/kmsg is read from the agent, non-blocking,
-- record by record (`<prio>,<seq>,<ts>,<flags>;<text>`); a record's
-- level is its priority's low three bits (the facility is USER, since a
-- write to /dev/kmsg may not claim the kernel's).
--
-- A warning and an error are made on purpose: a `Duid` that is not hex
-- (a warning) and a profile with an unknown value (a refused
-- generation, an error). Both are undone.
--
-- Each mirrored record uses a fresh /dev/kmsg descriptor. The second
-- test puts more than ten records inside the kernel's five-second
-- per-open window and requires every one at its original severity.
--
-- The other half of the paragraph (the mirror that cannot be opened is
-- reported once on stderr) needs a netd that may not write /dev/kmsg,
-- and netd runs as SYSTEM, which may.
--
-- Own VMs: this is the article's only file, and it changes the Duid.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local sys = require("helpers.sys")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
local files = network.test_binary("netd", {})
local sut = network.boot({ bridges = { lan }, gateway = gw, files = files })

local KEY = network.KEY

local function guest_ns()
    return assert(tonumber(sut:run("date +%s%N").stdout:match("%d+")), "guest clock")
end

--- netd's log lines newer than `since` (guest ns), oldest first, in the
--- order eventd recorded them.
local function log_since(since)
    local r = sut:run("evctl 'LOGS FROM netd SINCE 1h ago TAKE 5000'")
    assert(r.exit_code == 0, "evctl: " .. r.stderr)
    local newest_first = {}
    for line in r.stdout:gmatch("[^\n]+") do
        local msg = line:match('message="(.-)"  origin=')
        local ts = tonumber(line:match("timestamp=(%d+)"))
        if msg and ts and ts > since then
            newest_first[#newest_first + 1] = { ts = ts, msg = (msg:gsub("\\(.)", "%1")) }
        end
    end
    local out = {}
    for i = #newest_first, 1, -1 do out[#out + 1] = newest_first[i] end
    return out
end

--- Every /dev/kmsg record now in the buffer: { prio, seq, text }.
local O_NONBLOCK, EAGAIN, EPIPE = 0x800, 11, 32
local function kmsg()
    local fd, err = sys.open(sut, "/dev/kmsg", sys.O.RDONLY | O_NONBLOCK)
    assert(fd, "open /dev/kmsg: " .. tostring(err))
    local out = {}
    for _ = 1, 20000 do
        local rec, e = sys.read(sut, fd, 8192)
        if not rec then
            if e == EAGAIN then break end
            assert(e == EPIPE, "read /dev/kmsg: errno " .. tostring(e))
        else
            local prio, seq, text = rec:match("^(%d+),(%d+),[^;]*;([^\n]*)")
            if prio then
                out[#out + 1] = { prio = tonumber(prio), seq = tonumber(seq), text = text }
            end
        end
    end
    sys.close(sut, fd)
    return out
end

--- The highest sequence number in the kernel log now.
local function kmsg_seq()
    local last = 0
    for _, r in ipairs(kmsg()) do last = math.max(last, r.seq) end
    return last
end

--- Match netd's eventd lines since `mark` against the kmsg records
--- after `seq0`, in order. Returns the pairs and the records' texts.
local function mirror(mark, seq0)
    local lines = log_since(mark)
    local recs = {}
    for _, r in ipairs(kmsg()) do
        if r.seq > seq0 and (r.text:find("^netd: ") or r.text:find("suppressed", 1, true)) then
            recs[#recs + 1] = r
        end
    end
    local pairs_, at = {}, 1
    for _, l in ipairs(lines) do
        local found
        for k = at, #recs do
            if recs[k].text == l.msg then found = recs[k]; at = k + 1; break end
        end
        pairs_[#pairs_ + 1] = { line = l.msg, rec = found, ts = l.ts }
    end
    return pairs_, recs
end

local function show(t, pairs_, recs)
    local out = {}
    for _, p in ipairs(pairs_) do
        out[#out + 1] = (p.rec and string.format("<%d> ", p.rec.prio) or "<missing> ") .. p.line
    end
    local k = {}
    for _, r in ipairs(recs) do k[#k + 1] = string.format("%d <%d> %s", r.seq, r.prio, r.text) end
    t:log("eventd's lines, with the kmsg priority of each one's mirror:\n" .. table.concat(out, "\n")
        .. "\nkmsg records in the window:\n" .. table.concat(k, "\n"))
end

local LEVEL = { info = 6, warn = 4, error = 3 }

-- The kernel rate-limits writes to /dev/kmsg per open file (by default
-- ten lines in five seconds), so the steps here are spaced out: this
-- test is about where each line goes and at what level.
local SPACE = "sleep 6"

local orig_duid

test("each log line reaches eventd through stderr and the kernel log at its own level",
    { spec = "netd *failure.log-mirrored-to-kmsg" }, function(t)
        local s = network.serve_until(gw, sut, network.bound, { iface = "eth0", timeout = 60 })
        t:assert(s, "bound")
        local orig = network.reg(sut, { "get", "--raw", KEY, "Duid" })
        orig:assert_ok()
        orig_duid = orig.stdout:gsub("%z.*$", "")
        sut:run(SPACE)
        local mark, seq0 = guest_ns(), kmsg_seq()
        -- A warning, an error, and the info lines that undo them.
        network.reg(sut, { "set", KEY, "Duid", "sz:pt-not-hex" }):assert_ok()
        sut:run("net reconcile"):assert_ok()
        sut:run(SPACE)
        network.reg(sut, { "set", KEY, "Duid", "sz:" .. orig_duid }):assert_ok()
        sut:run("net reconcile"):assert_ok()
        sut:run(SPACE)
        sut:write_file("/tmp/pt-batch.json", json.encode({ keys = { { path = KEY .. [[\Profiles\pt-fail]],
            values = { { name = "Address.Bogus", type = "dword", data = 1 } } } } }))
        network.reg(sut, { "apply", "/tmp/pt-batch.json" }):assert_ok()
        sut:run("net reconcile"):assert_ok()
        sut:run(SPACE)
        network.reg(sut, { "del", KEY .. [[\Profiles\pt-fail]] }):assert_ok()
        sut:run("net reconcile"):assert_ok()

        local pairs_, recs = mirror(mark, seq0)
        show(t, pairs_, recs)
        local want = {
            { 'netd: warn: Duid "pt-not-hex" is not hex; ignoring it', "KERN_WARNING" },
            { "netd: error: interface layer refused: profile pt-fail: unknown value Address.Bogus; the last good generation stands",
              "KERN_ERR" },
            { "netd: info: interface layer: 1 rule tree(s), 1 profile(s)", "KERN_INFO" },
        }
        for _, w in ipairs(want) do
            local hit
            for _, p in ipairs(pairs_) do if p.line == w[1] then hit = p end end
            t:assert(hit, "eventd has it (netd's stderr): " .. w[1])
            t:assert(hit.rec, "/dev/kmsg has it: " .. w[1])
        end
        t:assert(#pairs_ >= 5, "lines were logged")
        for _, p in ipairs(pairs_) do
            t:assert(p.rec, "mirrored: " .. p.line)
            t:assert_eq(p.rec.prio & 7, LEVEL[p.line:match("^netd: (%a+):")], "at its level: " .. p.line)
        end
    end)

test("a burst of more than ten log lines reaches both eventd and the kernel log",
    { spec = "netd *failure.log-mirrored-to-kmsg" }, function(t)
        -- A fresh per-record descriptor must preserve a burst that the
        -- old lifetime descriptor lost after its first ten records.
        sut:run(SPACE)
        local mark, seq0 = guest_ns(), kmsg_seq()
        for i = 1, 12 do
            network.reg(sut, { "set", KEY, "Hostname", "sz:pt-burst-" .. i }):assert_ok()
            sut:run("net reconcile"):assert_ok()
        end
        sut:run(SPACE)
        local pairs_, recs = mirror(mark, seq0)
        show(t, pairs_, recs)
        t:assert(#pairs_ > 10, "a burst of more than ten lines reached eventd")
        local within_window = 0
        local window_end = pairs_[1].ts + 4500000000
        for _, p in ipairs(pairs_) do
            if p.ts < window_end then within_window = within_window + 1 end
            t:assert(p.rec, "mirrored without burst loss: " .. p.line)
            t:assert_eq(p.rec.prio & 7, LEVEL[p.line:match("^netd: (%a+):")],
                "at its level: " .. p.line)
        end
        t:assert(within_window > 10, "the burst exceeded the old per-open budget inside one window")
    end)
