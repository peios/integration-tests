-- eventd TRM §9.5 — power loss: what each store's durability setting
-- keeps across a sudden loss of power, and what the next boot's start
-- does about the boundary.
--
-- The live root is a tmpfs, so nothing written in one boot survives to
-- the next and a real power cut cannot be followed by a start that finds
-- the stores. Five of the seven statements need exactly that and are
-- stubs below, blocked on the persistent-store route the coordinator is
-- adding (a provium-mediated disk mounted under the store paths before
-- provisioning, cut with `vm:disk(id):power_cut()`).
--
-- The other two are about how eventd treats a new boot, and a new boot
-- is a new kernel boot ID. One VM: a valid UUID that is not this boot's
-- is bound over /proc/sys/kernel/random/boot_id and eventd restarted, so
-- it starts as the first start of a boot it has no receipts for. Unlike a
-- real power cycle the KMES ring survives (its sequences are this boot's,
-- not a fresh 1..n), which is what makes "never reconciled against the
-- previous boot's receipts" observable: a reconciling eventd would skip
-- the survivors the old boot's receipts cover; one that keeps the boots
-- apart reads them all again under the new ID.

local eventd = require("helpers.eventd")
local peinit = require("helpers.peinit")
peinit.claim(1)

local vm = eventd.boot({ name = "ev-powerloss" })

local FAKE = "5eed0b00-7a11-4c0d-8e55-0123456789ab"

local function now_ns()
    return tonumber(vm:run("date +%s%N").stdout:match("%d+"))
end

local new = {}

test("a new boot's coverage for each CPU starts before sequence 1", {
    spec = "eventd *powerloss.a-new-boots-per-cpu-coverage-starts-before-sequence-1",
}, function(t)
    new.tag = eventd.marker("old")
    eventd.emit(vm, "pt.oldboot", { tag = new.tag })
    eventd.wait_rows(vm, 'EVENTS pt.oldboot WHERE tag == "' .. new.tag .. '" SINCE 10m ago',
        function(r) return #r == 1 end)
    vm:run("mkdir -p /run/pt-pl-bid"):assert_ok()
    vm:run("mount -t tmpfs -o size=64k,policy=synth-ephemeral --synth-sddl "
        .. "'O:SYG:SYD:(A;OICI;GA;;;SY)(A;OICI;GR;;;WD)' none /run/pt-pl-bid"):assert_ok()
    vm:write_file("/run/pt-pl-bid/id", FAKE .. "\n")
    vm:run("mount --bind /run/pt-pl-bid/id /proc/sys/kernel/random/boot_id"):assert_ok()
    new.since = now_ns()
    eventd.restart(vm)
    local s
    for _, r in ipairs(eventd.rows(vm, "EVENTS " .. eventd.T.startup .. " SINCE 10m ago")) do
        if r.timestamp >= new.since then s = r end
    end
    t:assert(s, "eventd started under the new boot ID")
    t:assert_eq(s and s.boot_id, "{" .. FAKE .. "}", "the new boot")
    t:assert_eq(s and s.restart, false, "as that boot's first start")
    -- Coverage that begins before sequence 1 has nothing covered and
    -- nothing missing below the ring's oldest survivor: that survivor
    -- (sequence 1, the ring has not wrapped) is the first event of the
    -- new boot, and no gap precedes it. (The startup record's
    -- resume_points are where coverage stands once the start's recovery
    -- has committed, not where it began.)
    local found
    pcall(wait_until, function()
        for _, r in ipairs(eventd.rows(vm, "EVENTS WHERE cpu_id == 0 AND sequence == 1 SINCE 1h ago")) do
            if r.boot_id == "{" .. FAKE .. "}" then found = r end
        end
        return found ~= nil
    end, { timeout = 15, interval = 0.5 })
    t:assert(found, "sequence 1 on CPU 0 was ingested for the new boot")
    local gaps = 0
    for _, g in ipairs(eventd.rows(vm, "EVENTS " .. eventd.T.gap .. " SINCE 10m ago")) do
        if g.timestamp >= new.since then gaps = gaps + 1 end
    end
    t:assert_eq(gaps, 0, "with no gap before it")
end)

test("a new boot's ring is never reconciled against the previous boot's receipts", {
    spec = "eventd *powerloss.a-new-boots-ring-is-never-reconciled-against-the-previous-boots-receipts",
}, function(t)
    t:assert(new.tag, "the restart under a new boot ID from the previous test")
    -- The event committed under the real boot is in the old boot's
    -- receipts and still in the ring. Read again under the new boot, it
    -- was not skipped on the old receipts' account.
    local rows = eventd.wait_rows(vm, 'EVENTS pt.oldboot WHERE tag == "' .. new.tag .. '" SINCE 10m ago',
        function(r) return #r >= 2 end)
    local boots = {}
    for _, r in ipairs(rows) do boots[r.boot_id] = true end
    vm:run("umount /proc/sys/kernel/random/boot_id")
    eventd.restart(vm)
    t:assert(boots["{" .. FAKE .. "}"], "the survivor was ingested for the new boot: " .. json.encode(rows))
    t:assert_eq(#rows, 2, "once for each boot, the old receipts having played no part")
end)

-- Blocked: needs the persistent-store route (event store on a mediated
-- disk, power cut with commits in flight, next boot's start reads it).
test("every committed event transaction survives power loss", {
    spec = "eventd *powerloss.every-committed-event-transaction-survives-power-loss",
    skip = true,
}, function() end)

-- Blocked: as above, for logs.db; needs a cut between a commit and the
-- next WAL checkpoint, with WalCheckpointPages high.
test("log transactions survive only up to the last checkpoint", {
    spec = "eventd *powerloss.log-transactions-survive-only-up-to-the-last-checkpoint",
    skip = true,
}, function() end)

-- Blocked: as above, for metrics.db.
test("metric transactions survive only up to the last checkpoint", {
    spec = "eventd *powerloss.metric-transactions-survive-only-up-to-the-last-checkpoint",
    skip = true,
}, function() end)

-- Blocked: needs a cut while an event batch is accumulating (long
-- MaxBatchLatencyMs, frozen writer), then the next boot's store.
test("the event store loses only the in-flight batch", {
    spec = "eventd *powerloss.the-event-store-loses-only-the-in-flight-batch",
    skip = true,
}, function() end)

-- Blocked: as above; the next boot's store must hold no synthetic.gap
-- for the lost batch's (old-boot) sequences.
test("no gap record is written for a batch lost to power loss", {
    spec = "eventd *powerloss.no-gap-record-is-written-for-a-batch-lost-to-power-loss",
    skip = true,
}, function() end)
