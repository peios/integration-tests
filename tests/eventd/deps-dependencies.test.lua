-- eventd TRM §8.1 — dependencies: the four subsystems eventd needs, the
-- one it does not need for ingestion, and where it sits in the boot.
--
-- Two VMs. The file-scope one boots with `peios.quiet=0`, so peinit's
-- start and stop lines reach the console, and with eventd made Normal and
-- RestartPolicy=Never: two tests take its inputs away (the registry, the
-- kernel boot ID) and need a failed start to stay failed rather than cost
-- a Critical restart budget. Its last test shuts the machine down to read
-- the stop order. The second VM keeps the image's own eventd definition
-- (Critical, restart on failure) and is spent proving what Critical
-- means: it ends in a reboot.

local eventd = require("helpers.eventd")
local peinit = require("helpers.peinit")
local token = require("helpers.token")
local client = require("helpers.peinit_client")
peinit.claim(2)

local SERVICE = [[Machine\System\Services\eventd]]
local EVENTD_SID = "S-1-5-80-1963885778-1835409261-1671587836-2279113866-1994761124"

local vm = eventd.boot({
    name = "ev-deps",
    append = "peios.quiet=0",
    files = peinit.seed("zz-pt-eventd-svc", {
        { path = [[Machine\System]] },
        { path = [[Machine\System\Services]] },
        { path = SERVICE, values = {
            { name = "ErrorControl", type = "dword", data = 0 },
            { name = "RestartPolicy", type = "dword", data = 0 },
        } },
    }),
})

local function now_ns()
    return tonumber(vm:run("date +%s%N").stdout:match("%d+"))
end

local function settled(machine)
    local raw
    wait_until(function()
        raw = machine:run("svctl --json status eventd").stdout
        return raw:find('"current_operation":null', 1, true) ~= nil
    end, { timeout = 60, interval = 0.25, desc = "eventd's operation to finish" })
    return json.decode(raw)
end

local function startups(since)
    local out = {}
    for _, r in ipairs(eventd.rows(vm, "EVENTS " .. eventd.T.startup .. " SINCE 1h ago")) do
        if r.timestamp >= (since or 0) then out[#out + 1] = r end
    end
    table.sort(out, function(a, b) return a.timestamp < b.timestamp end)
    return out
end

test("events come from KMES, with the header KMES stamps on them", {
    spec = "eventd *deps.events-are-ingested-from-kmes",
}, function(t)
    local tag = eventd.marker("kmes")
    t:assert_eq(eventd.emit(vm, "pt.kmes", { tag = tag }).ret, 0, "kmes_emit")
    local rows = eventd.wait_rows(vm, 'EVENTS pt.kmes WHERE tag == "' .. tag .. '" SINCE 10m ago',
        function(r) return #r == 1 end)
    local r = rows[1]
    t:assert(r and type(r.sequence) == "number" and type(r.cpu_id) == "number",
        "stored with the ring's CPU and sequence: " .. json.encode(r))
    t:assert(r and type(r.process_guid) == "string", "and the emitting process KMES recorded")
end)

test("eventd takes its configuration from the registry and nowhere else", {
    spec = "eventd *deps.eventd-reads-every-setting-from-the-registry",
}, function(t)
    local pid = eventd.pid(vm)
    local argv = vm:run("cat /proc/" .. pid .. "/cmdline | tr '\\0' ' '").stdout
    t:assert_eq(argv:gsub("%s+$", ""), "/usr/sbin/eventd", "no arguments: " .. argv)
    local since = now_ns()
    eventd.set(vm, "EventRetentionDays", "dword:51"):assert_ok()
    local _, ok = eventd.wait_rows(vm, "EVENTS " .. eventd.T.config_change .. " SINCE 10m ago", function(rows)
        for _, r in ipairs(rows) do
            if r.timestamp >= since and r.key == "EventRetentionDays" and r.new_value == "51" then return true end
        end
        return false
    end)
    t:assert(ok, "a registry value under its key is what it applies")
    eventd.unset(vm, "EventRetentionDays")
end)

test("queries are authorised by KACS against the caller's own token", {
    spec = "eventd *deps.kacs-provides-query-authorization-and-peer-token-caller-identification",
}, function(t)
    -- A descriptor for one event type that grants read to one principal.
    -- When it names SYSTEM, the agent (SYSTEM) sees the event; when it
    -- names Local Service instead, the same query sees nothing. Only the
    -- caller's identity, taken from its connection, differs between them.
    local etype = eventd.marker("who")
    local key = eventd.SECURITY .. [[\Events\]] .. etype
    eventd.emit(vm, etype, { n = 1 })
    eventd.wait_rows(vm, "EVENTS " .. etype .. " SINCE 10m ago", function(r) return #r == 1 end)
    vm:run("reg new '" .. key .. "' -p"):assert_ok()
    local function grant(sid)
        vm:run("reg set '" .. key .. "' '' hex:" .. client.descriptor_hex(token.SID.LOCAL_SYSTEM,
            { { sid = sid, mask = 0x1 } })):assert_ok()
    end
    grant(token.SID.LOCAL_SYSTEM)
    local seen = pcall(wait_until, function()
        return #eventd.rows(vm, "EVENTS " .. etype .. " SINCE 10m ago") == 1
    end, { timeout = 5, interval = 0.2 })
    grant(token.sid(5, 19))
    local hidden = pcall(wait_until, function()
        return #eventd.rows(vm, "EVENTS " .. etype .. " SINCE 10m ago") == 0
    end, { timeout = 5, interval = 0.2 })
    vm:run("reg del '" .. key .. "' ''")
    t:assert(seen, "granted to SYSTEM, SYSTEM's query sees it")
    t:assert(hidden, "granted to Local Service only, SYSTEM's query does not")
end)

test("peinit runs eventd and provisioned its state directories before it started", {
    spec = "eventd *deps.peinit-manages-the-lifecycle-and-provisions-state-directories-before-start",
}, function(t)
    local status = eventd.status(vm)
    t:assert_eq(status.state, "active", "eventd is a running peinit service")
    local pid = eventd.pid(vm)
    t:assert(vm:run("cat /proc/" .. pid .. "/status").stdout:find("PPid:%s+1\n"), "whose parent is peinit")
    for _, dir in pairs(eventd.STORE) do
        local sd = vm:run("sd show " .. dir).stdout
        t:assert(sd:find("DACL_PROTECTED", 1, true) and sd:find(EVENTD_SID, 1, true),
            dir .. " carries the protected descriptor ProvisionedPaths gives it: " .. sd)
    end
    -- eventd refuses a store directory without that descriptor
    -- (bootstrap-failure.test.lua), so its having started at all means
    -- the provisioning came first.
    t:assert(#startups() >= 1, "and eventd started on them")
end)

test("events emitted before eventd started were read by its first drain", {
    spec = "eventd *deps.events-emitted-before-eventd-starts-are-read-by-its-first-drain-from-tail-pos",
}, function(t)
    local first = startups()[1]
    t:assert(first and first.restart == false, "the boot's first start")
    -- KMES numbers each CPU's events from 1 in a boot; the first ones
    -- were emitted by the kernel and Phase 1 long before eventd existed.
    local early = eventd.rows(vm, "EVENTS WHERE cpu_id == 0 AND sequence == 1 SINCE 1h ago")
    t:assert_eq(#early, 1, "CPU 0's sequence 1 is in the store")
    t:assert(early[1] and early[1].timestamp < first.timestamp,
        "and it was emitted before eventd's first start")
    -- And the same while eventd is stopped, on purpose.
    vm:run("svctl stop eventd"):assert_ok()
    local tag = eventd.marker("pre")
    eventd.emit(vm, "pt.pre", { tag = tag })
    vm:run("svctl start eventd")
    eventd.ready(vm)
    local _, ok = eventd.wait_rows(vm, 'EVENTS pt.pre WHERE tag == "' .. tag .. '" SINCE 10m ago',
        function(r) return #r == 1 end)
    t:assert(ok, "an event emitted while eventd was stopped was read when it started")
end)

test("the boot ID is the kernel's, read from /proc/sys/kernel/random/boot_id", {
    spec = "eventd *deps.the-boot-id-is-read-from-proc-sys-kernel-random-boot-id",
}, function(t)
    local real = vm:read_file("/proc/sys/kernel/random/boot_id"):match("[%x%-]+")
    t:assert_eq(startups()[1].boot_id, "{" .. real .. "}", "the startup record's boot is the kernel's")
    -- And it is that file, not a service-manager API: put another valid
    -- UUID over it and a new eventd reports that one.
    local fake = "0badc0de-1234-4321-8765-0123456789ab"
    vm:run("mkdir -p /run/pt-dep-bid"):assert_ok()
    vm:run("mount -t tmpfs -o size=64k,policy=synth-ephemeral --synth-sddl "
        .. "'O:SYG:SYD:(A;OICI;GA;;;SY)(A;OICI;GR;;;WD)' none /run/pt-dep-bid"):assert_ok()
    vm:write_file("/run/pt-dep-bid/id", fake .. "\n")
    vm:run("mount --bind /run/pt-dep-bid/id /proc/sys/kernel/random/boot_id"):assert_ok()
    local since = now_ns()
    vm:run("svctl restart eventd")
    local ok = pcall(eventd.ready, vm, 30)
    local s = ok and startups(since)[1]
    vm:run("umount /proc/sys/kernel/random/boot_id")
    vm:run("svctl restart eventd")
    eventd.ready(vm)
    t:assert(s, "eventd started over the substituted file")
    t:assert_eq(s and s.boot_id, "{" .. fake .. "}", "and took its boot ID from it")
end)

test("eventd cannot start without the registry", {
    spec = "eventd *deps.eventd-cannot-start-without-the-registry",
}, function(t)
    -- The service's ExecStartPre hook writes registry defaults and would
    -- fail first without a registry; take it out for this start, so the
    -- failure is eventd's own.
    vm:run("reg set '" .. SERVICE .. "' ExecStartPre 'multi:'"):assert_ok()
    vm:run("svctl reload-config"):assert_ok()
    vm:run("svctl stop registryd")
    vm:run("svctl --no-wait restart eventd")
    local status = settled(vm)
    vm:run("svctl start registryd")
    wait_until(function() return vm:run("reg get '" .. eventd.KEY .. "'").exit_code == 0 end,
        { timeout = 30, interval = 0.5, desc = "the registry to return" })
    vm:run("reg set '" .. SERVICE .. "' ExecStartPre 'multi:/usr/sbin/eventd --prepare-security'"):assert_ok()
    vm:run("svctl reload-config"):assert_ok()
    vm:run("svctl start eventd")
    eventd.ready(vm)
    t:assert_eq(status.state, "failed", "with registryd stopped, eventd's start failed: " .. json.encode(status))
    local logged = pcall(eventd.wait_rows, vm, 'LOGS FROM eventd CONTAINING "cannot read Machine" SINCE 10m ago',
        function(r) return #r >= 1 end)
    t:assert(logged, "having been unable to read its key")
end)

-- Route closed: the claim is about which code paths call KACS. KACS is in
-- the kernel and cannot be taken away from a running system, so its
-- absence cannot be arranged for ingestion to survive; and a path that
-- never calls it leaves nothing to observe.
test("the drain, write and retention paths never call KACS", {
    spec = "eventd *deps.the-drain-write-and-retention-paths-never-call-kacs",
    skip = true,
    covered_by = "cargo:eventd TODO the drain->writer->Shard::commit and retention paths run in a host test (no KACS) end to end",
}, function() end)

test("eventd is Critical: a start it cannot complete ends in a reboot", {
    spec = "eventd *deps.eventd-is-critical-and-peinit-reboots-rather-than-continue-without-it",
}, function(t)
    local crit = eventd.boot({ name = "ev-deps-critical", append = "peios.quiet=0" })
    local pid = eventd.pid(crit)
    t:assert_eq(crit:run("cat /proc/" .. pid .. "/oom_score_adj").stdout:match("%-?%d+"), "-1000",
        "peinit runs eventd as Critical (oom_score_adj -1000)")
    -- A required value pointing nowhere: every restart attempt fails.
    eventd.set(crit, "EventStorePath", "sz:/var/state/eventd/pt-nowhere"):assert_ok()
    pcall(function() crit:run("svctl --no-wait restart eventd", { timeout = 10 }) end)
    local down = false
    for _ = 1, 90 do
        local ok, r = pcall(function() return crit:run("true", { timeout = 5 }) end)
        if not ok or r.exit_code ~= 0 then down = true; break end
        pcall(function() crit:run("sleep 1", { timeout = 5 }) end)
    end
    t:assert(down, "peinit rebooted the machine rather than run on without eventd")
end)

test("eventd starts after the registry and authd, and stops before them", {
    spec = "eventd *deps.eventd-starts-after-loregd-and-authd-and-stops-before-them",
}, function(t)
    local log = vm:console():read_log()
    local reg = log:find("peinit: phase1 registryd started", 1, true)
    local authd = log:find("peinit: service authd started", 1, true)
    local ev = log:find("peinit: service eventd started", 1, true)
    t:assert(reg and authd and ev, "all three starts are on the console")
    t:assert(reg < ev and authd < ev, "eventd started after the registry source and authd")
    peinit.settle(vm)
    pcall(function() vm:run("svctl shutdown poweroff", { timeout = 30 }) end)
    pcall(function() vm:console():expect("peinit: shutdown stopping authd", 60) end)
    pcall(function() vm:console():expect("peinit: shutdown service authd exited", 30) end)
    log = vm:console():read_log()
    local ev_gone = log:find("peinit: shutdown service eventd exited", 1, true)
    local authd_stop = log:find("peinit: shutdown stopping authd", 1, true)
    local reg_stop = log:find("peinit: shutdown stopping registryd", 1, true)
    t:assert(ev_gone, "eventd's stop is on the console")
    t:assert(authd_stop and ev_gone < authd_stop, "eventd had exited before authd was stopped")
    t:assert(not reg_stop or ev_gone < reg_stop, "and before the registry source was")
end)
