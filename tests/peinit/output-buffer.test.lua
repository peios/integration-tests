-- Peinit TRM §11.2 — the pre-eventd buffer.
--
-- The window this page is about is real on every boot and closes within
-- a second or two of Phase 2, which makes it awkward to observe from
-- inside the guest: by the time a test can ask a question, eventd is up
-- and the buffer is empty. So the tests here look at the window's
-- *residue* instead. If output produced while eventd did not exist is
-- queryable from eventd afterwards, it was held somewhere in between,
-- and the buffer is the only thing peinit has.
--
-- registryd is the natural subject: it is started in Phase 1, long
-- before eventd's socket is bound, and it writes its hive summary at
-- startup. For the bounded-buffer claim that is not enough output, so a
-- seeded service is put ahead of eventd in the graph — eventd's own
-- `Requires` is extended to name it — and given a few hundred numbered
-- lines to write. Every one of them is produced in the window, and the
-- numbering is what lets a test say which end of the buffer was lost.

local peinit = require("helpers.peinit")

-- One gigabyte rather than the helper's two. Chapter 11 boots more
-- machines than any other chapter here — a claim about output usually
-- needs a whole boot arranged around it — and provium reserves declared
-- memory for the life of a VM, so at the default these files queue
-- against the pool and each other. A booted guest uses about 300 MB
-- between its working set and the squashfs page cache, and the same
-- assertions hold at either size.
--
-- One vCPU for the same reason: provium admits VMs while the total
-- declared vCPU count fits the host's cores, so two apiece halves how
-- many of these boots can be in flight at once. Nothing here is
-- compute-bound.
local MEM, CPUS = "1G", 1

-- The default boot's producer. Small enough that the whole of it fits
-- the compiled-in one-megabyte buffer, so "all of it arrived" is a
-- meaningful thing to assert.
local LINES = 300

-- The constrained boot's. Sized so that its own output is what overruns
-- the buffer rather than the boot's other traffic: 1500 records of about
-- eighty bytes each against a sixty-four kilobyte buffer is roughly two
-- lines evicted for every three written.
local OVERRUN_LINES = 1500
local OVERRUN_BUFFER = 65536

-- Numbered, so a test can say *which* of them survived rather than only
-- how many. That is the whole difference between "the buffer is bounded"
-- and "the buffer drops its OLDEST entries".
local function early_script(lines)
    return "#!/bin/sh\n" ..
        "i=0\n" ..
        "while [ $i -lt " .. lines .. " ]; do\n" ..
        '    echo "pt-early-line-$i"\n' ..
        "    i=$((i + 1))\n" ..
        "done\n"
end

--- A boot in which `pt-early` runs before eventd does.
---
--- Extending eventd's `Requires` is the lever: peinit will not start a
--- service before something it requires, so naming pt-early there puts
--- every line it writes inside the pre-eventd window by construction
--- rather than by luck of the scheduler.
local function boot_with_early_service(name, opts)
    opts = opts or {}
    local keys = {
        { path = [[Machine\System]] },
        { path = [[Machine\System\Services]] },
        {
            path = [[Machine\System\Services\pt-early]],
            values = {
                { name = "ImagePath", type = "sz", data = "/lcl/pt/early.sh" },
                { name = "Type", type = "dword", data = 1 },
                { name = "Identity", type = "sz", data = "SYSTEM" },
                { name = "Readiness", type = "dword", data = 1 },
                { name = "Triggers", type = "multi", data = { "boot" } },
            },
        },
        {
            path = [[Machine\System\Services\eventd]],
            values = {
                { name = "Requires", type = "multi", data = { "authd", "pt-early" } },
            },
        },
    }
    if opts.buffer then
        keys[#keys + 1] = {
            path = [[Machine\System\Init]],
            values = { { name = "PreEventdBuffer", type = "dword", data = opts.buffer } },
        }
    end
    -- A service with a dependency nothing provides. It is blocked when
    -- the Phase 2 plan is built — before any service has started, so long
    -- before eventd is Active — and the finding is audited, which is what
    -- the audit-record test reads back.
    --
    -- Only on the boot that asks for it: a graph with a missing hard
    -- dependency is a *boot* finding but a *reload* rejection, so a boot
    -- carrying one cannot also be the boot the reload test uses.
    if opts.blocked then
        keys[#keys + 1] = {
            path = [[Machine\System\Services\pt-blocked]],
            values = {
                { name = "ImagePath", type = "sz", data = "/bin/true" },
                { name = "Type", type = "dword", data = 1 },
                { name = "Identity", type = "sz", data = "SYSTEM" },
                { name = "Readiness", type = "dword", data = 1 },
                { name = "Triggers", type = "multi", data = { "boot" } },
                { name = "Requires", type = "multi", data = { "pt-does-not-exist" } },
            },
        }
    end
    return peinit.boot({
        memory = MEM, cpus = CPUS,
        name = name,
        files = peinit.merge(
            { ["lcl/pt/early.sh"] = { early_script(opts.lines or LINES), exec = true } },
            peinit.seed("zz-pt-buffer", keys)
        ),
    })
end

local function wait_for_eventd(vm)
    for _ = 1, 60 do
        if vm:run("svctl status eventd").stdout:find("eventd: active") then return true end
        vm:run("sleep 1")
    end
    return false
end

--- Every log record eventd holds for `origin`, as message -> true.
---
--- `TAKE` is well above the number written so nothing is trimmed by the
--- query rather than by the buffer, which is the thing under test.
---
--- Polled until `want` records have arrived. What these tests read is a
--- replay, and a replay only starts once eventd is Active: a query
--- issued the instant it becomes so races the delivery rather than
--- measuring it.
local function messages_from(vm, origin, want)
    local seen, count = {}, 0
    for _ = 1, 30 do
        seen, count = {}, 0
        local out = vm:run(
            "evctl 'LOGS FROM " .. origin .. " SINCE 1h ago TAKE 5000' --format jsonl").stdout
        for line in out:gmatch("[^\r\n]+") do
            local message = line:match('"message":"([^"]*)"')
            if message then
                seen[message] = true
                count = count + 1
            end
        end
        if count >= (want or 1) then break end
        vm:run("sleep 1")
    end
    return seen, count
end

local vm = boot_with_early_service("buffer")
wait_for_eventd(vm)

-- The same boot with a buffer too small for what the producer writes.
-- The blocked service rides along here rather than on the boot above,
-- because the reload test needs a graph a reload will accept.
local small = boot_with_early_service("buffer-small", {
    lines = OVERRUN_LINES, buffer = OVERRUN_BUFFER, blocked = true,
})
wait_for_eventd(small)

test("output written before eventd existed is still queryable from eventd afterwards",
    { spec = "peinit *buffer.output-before-eventd-is-held-in-memory" },
    function(t)
        -- registryd is Phase 1's, started before Phase 2 has read a
        -- service graph and long before eventd's log socket exists.
        -- Its startup lines are nevertheless in the store.
        local registryd = messages_from(vm, "registryd")
        local found = false
        for message in pairs(registryd) do
            if message:find("registered", 1, true) and message:find("hive", 1, true) then
                found = true
            end
        end
        t:assert(found,
            "registryd's Phase 1 startup output reached eventd, so it was held until eventd could take it")

        -- And it was held rather than echoed: none of it is on the
        -- console, which is the only other place it could have gone.
        t:assert(not vm:console():read_log():find("entering request loop", 1, true),
            "the same output was not written to the console instead")

        -- The seeded service is the controlled case: every one of its
        -- lines was written before eventd, and with the default capacity
        -- every one of them survived.
        local _, count = messages_from(vm, "pt-early", LINES)
        t:assert_eq(count, LINES,
            "all " .. LINES .. " pre-eventd lines were retained and delivered")

    end)

test("a buffer too small for the window keeps the newest entries and drops the oldest",
    {
        spec = {
            "peinit *buffer.the-buffer-drops-the-oldest-entries",
            "peinit *buffer.the-pre-eventd-buffer-key",
        },
    },
    function(t)
        -- Sixty-four kilobytes against fifteen hundred records. The same
        -- boot with the compiled-in capacity kept every line its producer
        -- wrote, so the registry value is what changed the outcome.
        local kept, count = messages_from(small, "pt-early", 1)
        t:assert(count > 0, "some of the pre-eventd output survived")
        t:assert(count < OVERRUN_LINES,
            "but not all of it: " .. count .. " of " .. OVERRUN_LINES ..
            " records fit in " .. OVERRUN_BUFFER .. " bytes")

        -- Which end went is the claim. The point of the window is the
        -- boot that is happening now, so the most recent output is what
        -- explains where it got to, and the front of the buffer is what
        -- is evicted to keep it.
        t:assert(kept["pt-early-line-" .. (OVERRUN_LINES - 1)],
            "the last line written is among the survivors")
        t:assert(not kept["pt-early-line-0"],
            "the first line written was dropped to make room for it")
    end)

test("an audit event emitted before eventd was serving is collected from the ring buffer",
    {
        spec = {
            "peinit *buffer.audit-records-go-to-kmes-not-the-buffer",
            "peinit *buffer.eventd-collects-earlier-events-when-it-attaches",
        },
    },
    function(t)
        -- A boot-graph validation error is one of peinit's own audit
        -- records, and it is emitted while the Phase 2 plan is built —
        -- before any service has started, so long before eventd is
        -- Active. It goes to the KMES ring buffer rather than to the
        -- pre-eventd log buffer, and eventd picks it up when it attaches.
        local events
        for _ = 1, 20 do
            events = small:run(
                "evctl 'EVENTS graph.* SINCE 1h ago TAKE 200' --format jsonl").stdout
            if events:find("pt%-blocked") then break end
            small:run("sleep 1")
        end
        t:assert(events:find("pt-blocked", 1, true),
            "the boot-time validation finding is in eventd's event store")
        t:assert(events:find("pt-does-not-exist", 1, true),
            "naming the dependency that was missing")

        -- The distinction the page draws: the same boot's *logs* from
        -- that window went through the bounded buffer, while this went
        -- through KMES and so had no window in which it could be lost.
        t:assert(events:find('"phase":"boot"', 1, true),
            "and it is recorded as having happened at boot")
    end)

test("the buffer capacity is re-read on reload rather than fixed at boot",
    { spec = "peinit *buffer.the-capacity-is-refreshed-on-reload" },
    function(t)
        -- A reload with the key untouched has nothing to say about it.
        local before = vm:run("svctl --json reload-config")
        before:assert_ok()
        t:assert(not before.stdout:find("PreEventdBuffer", 1, true),
            "a reload of an unchanged registry reports nothing about the key")

        -- Setting the key below its minimum is the observable form of
        -- "the value is re-read": a value peinit never looked at again
        -- cannot produce a complaint about itself. The boot read it and
        -- found nothing there; this reload reads it and finds 64.
        vm:run([[reg set 'Machine\System\Init' PreEventdBuffer dword:64]]):assert_ok()
        local after = vm:run("svctl --json reload-config")
        after:assert_ok()
        t:assert(after.stdout:find("PreEventdBuffer", 1, true),
            "the reload read the key: " .. after.stdout)
        t:assert(after.stdout:find("below the minimum", 1, true),
            "and judged the value it found against the minimum")
    end)
