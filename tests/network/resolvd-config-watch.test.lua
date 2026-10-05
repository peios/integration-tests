-- resolvd §2.3 — when the registry watch fails: a failed read re-arms the
-- watch without reading the key, and a re-arm that also fails stops
-- watching for good, silently, until resolvd restarts. The rest of §2.3
-- is resolvd-config.test.lua.
--
-- Harness: a whole Peios (helpers.peinit) with no network at all, so
-- every question resolvd is asked is answered locally and at once: a
-- static name from source `hosts`, anything else `unavailable`. That
-- makes the native socket a safe, non-blocking probe of which Hosts\
-- values resolvd has taken.
--
-- The lever: resolvd reads watch events into a 16 384-byte buffer, and a
-- read() that cannot fit even the first queued event fails with EINVAL
-- (LCS §5.6.2). A subtree watch's record carries the changed key's path
-- below the watched key, two bytes of length per component, so a value
-- set deep enough, with a long enough name, makes a record larger than
-- the buffer while the key path itself stays within MaxTotalPathLength
-- (16 383). The test computes both sizes and asserts the premise. netd
-- watches the same key with the same buffer and re-arms the same way; its
-- log is not resolvd's.
--
-- A malformed ExtraSearchDomains string ("bad..sentinel") is kept in the
-- Dns key throughout: every read of the key logs it, so its absence from
-- the log shows that no read happened.
--
-- For the re-arm to fail, resolvd's RLIMIT_NOFILE is lowered, from the
-- agent, to its lowest free descriptor number, so opening the key again
-- fails with EMFILE, and it is put back once the failure is logged. If the
-- kernel refuses the agent that, the fallback is a deny ACE for resolvd's
-- service SID on Machine\System\Network (KEY_NOTIFY), which fails the
-- open with EACCES; the log says which lever was used.
--
-- Own VM, one: no gateway is needed, and the second test leaves resolvd
-- with no watch until it is restarted.

local peinit = require("helpers.peinit")
local network = require("helpers.network")

peinit.claim(1)

local sut = peinit.boot({ name = "sut" })

local KEY = network.KEY
local DNS = KEY .. [[\Dns]]
local HOSTS = DNS .. [[\Hosts]]
local SOCK = "/run/resolvd/resolv.sock"
local RESOLVD_SID = "S-1-5-80-3864064249-1823296737-2008945602-1354971773-2894779966"
local SENTINEL = 'resolvd: warn: Dns ExtraSearchDomains: ignoring malformed domain "bad..sentinel"'
local REARM = "resolvd: warn: registry watch: "

-- The deep key: PtDeep and K components of L bytes below the watched
-- key, and a value of NAME_LEN bytes on the deepest.
local K, L, NAME_LEN = 150, 106, 255
local WATCHED_LEN = #KEY
local COMPONENTS = { "PtDeep" }
for i = 1, K do COMPONENTS[#COMPONENTS + 1] = string.format("%03d", i) .. string.rep("d", L - 3) end
local DEEP_NAME = string.rep("v", NAME_LEN)

-- ---------------------------------------------------------------------------
-- Local instruments
-- ---------------------------------------------------------------------------

local function guest_ns()
    return assert(tonumber(sut:run("date +%s%N").stdout:match("%d+")), "guest clock")
end

local function log_since(since)
    local r = sut:run("evctl 'LOGS FROM resolvd SINCE 1h ago TAKE 5000'")
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

local function count(lines, text)
    local n = 0
    for _, l in ipairs(lines) do
        if l.msg:find(text, 1, true) then n = n + 1 end
    end
    return n
end

local function dump(t, lines)
    local out = {}
    for _, l in ipairs(lines) do out[#out + 1] = l.msg end
    t:log("resolvd log:\n" .. table.concat(out, "\n"))
end

local function reg(args) return network.reg(sut, args) end

local function apply(doc)
    sut:write_file("/tmp/pt-batch.json", json.encode(doc))
    local r = reg({ "apply", "/tmp/pt-batch.json" })
    assert(r.exit_code == 0, "reg apply: " .. r.stdout .. r.stderr)
end

local function is_static(name)
    local r, err = network.call(sut, { query = "resolve", name = name, type = 1, no_cache = false },
        { path = SOCK })
    assert(r, "resolve " .. name .. ": " .. tostring(err))
    return r.ok == true and r.source == "hosts"
end

--- Wait until resolvd has logged nothing for two seconds.
local function quiesce()
    wait_until(function()
        local m = guest_ns()
        sut:run("sleep 2")
        return #log_since(m) == 0
    end, { timeout = 30, interval = 0.1, desc = "resolvd's log to go quiet" })
end

local function deep_path(depth)
    return KEY .. "\\" .. table.concat(COMPONENTS, "\\", 1, depth)
end

local function resolvd_pid() return tonumber(peinit.pid_of_comm(sut, "resolvd")) end

local function restart_resolvd()
    local before = resolvd_pid()
    sut:run("svctl stop resolvd"):assert_ok()
    wait_until(function() return resolvd_pid() == nil end,
        { timeout = 20, interval = 0.25, desc = "resolvd to stop" })
    -- See resolvd-config.test.lua: a restarted resolvd cannot set up a
    -- /run/resolvd it has already run in; peinit provisions it anew.
    sut:run("rm -rf /run/resolvd"):assert_ok()
    sut:run("svctl start resolvd"):assert_ok()
    wait_until(function()
        local now = resolvd_pid()
        if not now or now == before then return false end
        local s = network.call(sut, { query = "status" }, { path = SOCK })
        return s ~= nil and s.ok == true
    end, { timeout = 30, interval = 0.25, desc = "a new resolvd answering" })
end

-- prlimit64(2) on another process: RLIMIT_NOFILE (7).
local function nofile(pid, soft, hard)
    local r
    if soft then
        r = sut:syscall(302, { args = { pid, 7, 0, 0 }, bufs = { string.pack("<I8I8", soft, hard) }, ptrs = { 2 } })
        return r.ret == 0, r.errno
    end
    r = sut:syscall(302, { args = { pid, 7, 0, 0 }, bufs = { string.rep("\0", 16) }, ptrs = { 3 } })
    assert(r.ret == 0, "prlimit64 read: errno " .. tostring(r.errno))
    return string.unpack("<I8I8", r.out_bufs[1])
end

-- ---------------------------------------------------------------------------

test("a failed read of watch events is logged and the watch re-armed; the key is not read on re-arming, so a change queued behind the failure waits for the next event",
    { spec = "resolvd *config.watch-error-re-arms" }, function(t)
        -- The premise: the record is larger than resolvd's buffer while
        -- the path stays within the registry's limit.
        local comp_bytes, path_bytes = 0, WATCHED_LEN
        for _, c in ipairs(COMPONENTS) do
            comp_bytes = comp_bytes + 2 + #c
            path_bytes = path_bytes + 1 + #c
        end
        local record = 8 + NAME_LEN + 2 + comp_bytes
        t:log(string.format("deep key path %d bytes (+ value name %d); VALUE_SET record %d bytes",
            path_bytes, NAME_LEN, record))
        t:assert(record > 16384, "the record does not fit resolvd's 16 384-byte buffer")
        t:assert(path_bytes + 1 + NAME_LEN <= 16383, "the path, value name included, is a legal one")

        -- phase2 can complete before resolvd has made its socket; wait for
        -- it to answer, so the probes below never meet a missing socket.
        wait_until(function()
            local s = network.call(sut, { query = "status" }, { path = SOCK })
            return s ~= nil and s.ok == true
        end, { timeout = 30, interval = 0.25, desc = "resolvd answering" })

        -- Setup: the sentinel, a static name, and the deep keys (their
        -- creation events fit the buffer and are read as usual).
        apply({ keys = {
            { path = DNS, values = { { name = "ExtraSearchDomains", type = "sz", data = "bad..sentinel" } } },
            { path = HOSTS, values = { { name = "pt-base.test", type = "sz", data = "10.0.0.1" } } },
        } })
        wait_until(function() return is_static("pt-base.test") end,
            { timeout = 15, interval = 0.25, desc = "the Hosts value to be taken" })
        local keys = {}
        for d = 1, #COMPONENTS do keys[#keys + 1] = { path = deep_path(d) } end
        local mark = guest_ns()
        apply({ keys = keys })
        quiesce()
        local lines = log_since(mark)
        t:assert(count(lines, SENTINEL) >= 1, "creating the deep keys was read as usual")
        t:assert_eq(count(lines, REARM), 0, "with no watch failure")

        -- One transaction: the oversized event first, then a new static
        -- name, both queued before resolvd wakes.
        mark = guest_ns()
        apply({ keys = {
            { path = deep_path(#COMPONENTS), values = { { name = DEEP_NAME, type = "sz", data = "1" } } },
            { path = HOSTS, values = { { name = "pt-lost.test", type = "sz", data = "10.0.0.2" } } },
        } })
        wait_until(function() return count(log_since(mark), REARM) >= 1 end,
            { timeout = 15, interval = 0.25, desc = "the watch failure to be logged" })
        sut:run("sleep 2")
        lines = log_since(mark)
        dump(t, lines)
        t:assert_eq(lines[1] and lines[1].msg, "resolvd: warn: registry watch: Invalid argument (os error 22); re-arming",
            "the failed read is logged, with its error, and the watch re-armed")
        t:assert_eq(count(lines, SENTINEL), 0, "the key was not read, neither for the failed batch nor on re-arming")
        t:assert_eq(count(lines, "configuration changed"), 0, "nothing applied")
        t:assert_eq(is_static("pt-lost.test"), false, "the change behind the failure is not in force")

        -- The next event, anywhere under the key, is read by the new watch.
        mark = guest_ns()
        reg({ "set", KEY, "PtNudge", "sz:1" }):assert_ok()
        wait_until(function() return is_static("pt-lost.test") end,
            { timeout = 15, interval = 0.25, desc = "the next event to apply the change" })
        lines = log_since(mark)
        dump(t, lines)
        t:assert(count(lines, SENTINEL) >= 1, "the key was read again at the next event")
        t:assert(count(lines, "resolvd: info: configuration changed") >= 1, "and the change applied")
        t:assert_eq(count(lines, REARM), 0, "through a working watch")
    end)

test("when re-arming fails too, watching stops without a further message until resolvd restarts",
    { spec = "resolvd *config.failed-re-arm-stops-watching-silently" }, function(t)
        quiesce()
        local pid = resolvd_pid()
        t:assert(pid, "resolvd is running")
        local fds = peinit.fds(sut, pid)
        local free = 0
        while fds[free] do free = free + 1 end
        local soft, hard = nofile(pid)
        local listing = {}
        for fd, target in pairs(fds) do listing[#listing + 1] = fd .. "=" .. target end
        table.sort(listing)
        t:log(string.format("resolvd %d: fds %s; lowest free %d; NOFILE %d/%d", pid,
            table.concat(listing, " "), free, soft, hard))

        -- Make the re-arm's open fail.
        local lever, restore_sddl
        local ok, errno = nofile(pid, free, hard)
        if ok then
            lever = "RLIMIT_NOFILE " .. free
        else
            t:log("prlimit64 refused, errno " .. tostring(errno) .. "; using a deny ACE")
            local sd = reg({ "sd", KEY })
            t:log("reg sd: " .. sd.stdout .. sd.stderr)
            sd:assert_ok()
            restore_sddl = (sd.stdout:gsub("%s+$", "")):match("([^\n]*)$")
            local dacl_at = restore_sddl:find("D:", 1, true)
            t:assert(dacl_at, "the key has a DACL: " .. restore_sddl)
            local first_ace = restore_sddl:find("(", dacl_at, true)
            local denied = restore_sddl:sub(1, first_ace - 1) .. "(D;;0x10;;;" .. RESOLVD_SID .. ")"
                .. restore_sddl:sub(first_ace)
            t:log("deny SDDL: " .. denied)
            reg({ "sd", KEY, "--set", denied }):assert_ok()
            quiesce()
            lever = "deny KEY_NOTIFY to resolvd's SID"
        end
        t:log("lever: " .. lever)

        local mark = guest_ns()
        apply({ keys = {
            { path = deep_path(#COMPONENTS), values = { { name = DEEP_NAME, type = "sz", data = "2" } } },
        } })
        wait_until(function() return count(log_since(mark), REARM) >= 1 end,
            { timeout = 15, interval = 0.25, desc = "the watch failure to be logged" })
        -- Put the lever back at once.
        if ok then
            t:assert(nofile(pid, soft, hard), "NOFILE restored")
        else
            reg({ "sd", KEY, "--set", restore_sddl }):assert_ok()
        end

        -- Changes now: a new static name, and a write elsewhere under the key.
        sut:run("sleep 1")
        reg({ "set", HOSTS, "pt-silent.test", "sz:10.0.0.3" }):assert_ok()
        reg({ "set", KEY, "PtNudge", "sz:2" }):assert_ok()
        sut:run("sleep 3")
        local lines = log_since(mark)
        dump(t, lines)
        t:assert_eq(count(lines, REARM), 1, "the failed read is logged once")
        t:assert_eq(#lines, 1, "and nothing else: the failed re-arm is silent, and no read follows")
        t:assert_eq(is_static("pt-silent.test"), false, "a change after it is not seen")
        t:assert_eq(count(lines, SENTINEL), 0, "the key is never read again")

        -- Until resolvd restarts, which reads the key afresh.
        mark = guest_ns()
        restart_resolvd()
        t:assert(is_static("pt-silent.test"), "a restarted resolvd has the change")
        lines = log_since(mark)
        t:assert(count(lines, SENTINEL) >= 1, "having read the key at startup")
    end)
