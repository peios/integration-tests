-- peipkg's audit events (peipkg.evman; peipkg TRM §13.3 and appendix A2):
-- what a real peipkg on a whole Peios writes into KMES for operations that
-- need no repository or network, read straight off the ring.
--
-- Harness: one peinit VM with the image's own peipkg, driven by the agent,
-- which runs as SYSTEM. One vCPU, so CPU 0's ring is every ring, and every
-- record peipkg writes is in the window `kmes.recording` reads.
--
-- Payload field paths are nested maps (PGSS §6.4): `subject.token.sid` is
-- `payload.subject.token.sid`, and a hyphenated segment needs brackets, as
-- in `payload.operation["succeeded-count"]`.
--
-- The cases change only what they put back: a failed repository add backs
-- out its own configuration, and the emission-policy case removes the
-- policy key it creates.

local peinit = require("helpers.peinit")
local kmes = require("helpers.kmes")
local token = require("helpers.token")
peinit.claim(1)

local vm = peinit.boot({ name = "pkg-audit" })

local POLICY = [[Machine\Generic\Events]]
-- A trust anchor no repository is signed with: the ceremony never gets far
-- enough to check it.
local ANCHOR = string.rep("ab", 32)

--- Run a peipkg command line and return its result and every peipkg.*
--- record it wrote.
local function peipkg(t, args)
    local r
    local events = kmes.recording(t, vm, function()
        r = vm:run("peipkg " .. args)
    end)
    -- Without SeAuditPrivilege peipkg warns and carries on unaudited, so a
    -- missing record would be this, not the emitter.
    t:assert(not r.stderr:find("audit emission failed", 1, true),
        "peipkg emitted its records: " .. r.stderr)
    local out = {}
    for _, e in ipairs(events) do
        if e.type:sub(1, 7) == "peipkg." then out[#out + 1] = e end
    end
    return r, out
end

local function only(t, records, event_type)
    local got = kmes.of_type(records, event_type)
    t:assert_eq(#got, 1, "exactly one " .. event_type .. " record")
    return got[1]
end

--- Every record names its principal: the agent's SYSTEM, as a binary SID.
local function assert_subject(t, e)
    t:assert(e.payload and e.payload.subject and e.payload.subject.token,
        "the record carries subject.token: " .. tostring(e.payload_error))
    t:assert_eq(token.sid_string(e.payload.subject.token.sid), "S-1-5-18",
        "subject.token.sid is the user SID of the token peipkg ran under")
end

test("a recover with nothing to recover writes peipkg.transaction.recovered", {}, function(t)
    local r, records = peipkg(t, "recover")
    t:assert_eq(r.exit_code, 0, "recover succeeds: " .. r.stderr)
    local e = only(t, records, "peipkg.transaction.recovered")
    assert_subject(t, e)
    t:assert_eq(e.payload.outcome.success, true, "a successful run")
    t:assert_eq(e.payload.operation["succeeded-count"], 0,
        "nothing rolled back, recorded as zero rather than left out")
    t:assert_eq(e.payload.outcome.detail, nil, "no detail on success")
    t:assert_eq(e.payload.timestamp, nil, "no timestamp of its own: the header has the time")
end)

test("a repository removal that fails writes a failed peipkg.repository.removed", {}, function(t)
    local r, records = peipkg(t, "repo remove ../pt-not-a-name")
    t:assert(r.exit_code ~= 0, "a name no repository file can have is refused")
    local e = only(t, records, "peipkg.repository.removed")
    assert_subject(t, e)
    t:assert_eq(e.payload.object.repository.name, "../pt-not-a-name", "the repository named")
    t:assert_eq(e.payload.outcome.success, false, "recorded as failed")
    t:assert(type(e.payload.outcome.detail) == "string" and #e.payload.outcome.detail > 0,
        "with the error as peipkg reported it")
end)

test("a repository add whose ceremony fails writes a failed peipkg.repository.added", {}, function(t)
    local url = "http://127.0.0.1:1/"
    local r, records = peipkg(t, "repo add --anchor " .. ANCHOR ..
        " --insecure pt-nowhere " .. url)
    t:assert(r.exit_code ~= 0, "an unreachable repository is not added")
    local e = only(t, records, "peipkg.repository.added")
    assert_subject(t, e)
    t:assert_eq(e.payload.object.repository.name, "pt-nowhere", "the repository named")
    t:assert_eq(e.payload.object.repository.url, url, "and its base URL")
    t:assert_eq(e.payload.outcome.success, false, "recorded as failed")
    t:assert_eq(e.payload.outcome.reason, "failed", "with peipkg's error code")
    t:assert_eq(#kmes.of_type(records, "peipkg.repository.reconfigured"), 0,
        "and no reconfiguration, since nothing was added")
    t:assert(vm:run("test -e /lcl/conf/peipkg/pt-nowhere.repo").exit_code ~= 0,
        "the failed add backed out the configuration it wrote")
end)

test("the emission policy switches a standard peipkg type off, and never an essential one",
    {}, function(t)
        local key = POLICY .. [[\peipkg]]
        vm:run("reg set -p '" .. key .. "' Enabled dword:0"):assert_ok()
        local ok, err = pcall(function()
            -- The policy applies within a second (PGSS §6.9); peipkg is a
            -- new process each run, so it reads the tree afresh.
            local _, records = peipkg(t, "recover")
            t:assert_eq(#kmes.of_type(records, "peipkg.transaction.recovered"), 0,
                "a standard type under a switched-off root is not written")
            local _, removed = peipkg(t, "repo remove ../pt-not-a-name")
            t:assert_eq(#kmes.of_type(removed, "peipkg.repository.removed"), 1,
                "an essential type is written whatever the policy says")
        end)
        vm:run("reg del '" .. key .. "' Enabled")
        if not ok then error(err, 0) end
    end)
