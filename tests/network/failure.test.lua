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
-- The kernel rate-limits /dev/kmsg writes per open file (ten lines per
-- five seconds by default), and netd opens it once: the first test
-- spaces its steps out, the second makes a burst and shows the lines
-- past the limit missing from the kernel log (PEI-1371).
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
local sut = network.boot({ bridges = { lan }, gateway = gw })

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

test("in a burst the kernel log has the first ten lines and not those after them; eventd has every one",
    { spec = "netd *failure.log-mirrored-to-kmsg" }, function(t)
        -- PEI-1371: netd opens /dev/kmsg once and the kernel rate-limits
        -- writes through one open file (printk.devkmsg=ratelimit, ten
        -- lines per five seconds), so in a burst every line past the
        -- tenth in the window is dropped from the kernel log. They all
        -- still reach eventd. This is the documented current behaviour.
        -- The window opens at the burst's first line (the SPACE before it
        -- lets the previous one lapse); lines within half a second of its
        -- end are not asserted either way, nor are those after it, which
        -- a new window may mirror.
        sut:run(SPACE)
        local mark, seq0 = guest_ns(), kmsg_seq()
        -- Twelve hostname changes in quick succession: each is logged as
        -- a configuration change and a new hostname.
        for i = 1, 12 do
            network.reg(sut, { "set", KEY, "Hostname", "sz:pt-burst-" .. i }):assert_ok()
            sut:run("net reconcile"):assert_ok()
        end
        sut:run(SPACE)
        sut:run("net reconcile"):assert_ok()
        local pairs_, recs = mirror(mark, seq0)
        show(t, pairs_, recs)
        local missing = 0
        for _, p in ipairs(pairs_) do if not p.rec then missing = missing + 1 end end
        t:log(#pairs_ .. " lines in eventd, " .. missing .. " of them not in /dev/kmsg")
        t:assert(#pairs_ > 10, "a burst of more than ten lines reached eventd")
        for k = 1, 10 do
            t:assert(pairs_[k].rec, "line " .. k .. " of the burst is in the kernel log: " .. pairs_[k].line)
        end
        -- mirror() pairs lines with records by text, in order, so a line
        -- whose text recurs (`configuration changed`) could be paired with
        -- a later line's record from a new window: only lines whose text
        -- is unique in the burst (`hostname is pt-burst-N`) are judged.
        local seen = {}
        for _, p in ipairs(pairs_) do seen[p.line] = (seen[p.line] or 0) + 1 end
        local window_end = pairs_[1].ts + 4500000000
        local dropped = 0
        for k = 11, #pairs_ do
            local p = pairs_[k]
            if p.ts < window_end and seen[p.line] == 1 then
                t:assert(p.rec == nil, "line " .. k .. ", inside the first five seconds, is not in the kernel log: " .. p.line)
                dropped = dropped + 1
            end
        end
        t:log(dropped .. " lines past the tenth fell inside the window")
        t:assert(dropped > 0, "the burst put more than ten lines inside one window")
    end)
