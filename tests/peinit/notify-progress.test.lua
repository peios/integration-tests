-- peinit TRM §10.5 — PROGRESS= and PROGRESS_UNIT=: how a service's
-- progress is retained and shown, when it becomes an event, and when it
-- is forgotten (PEI-1222).
--
-- The instrument is nf-notify.test.lua's: `pt-notify`
-- (tests/tools/pt-notify.c), a program whose Arguments are a script of
-- steps and whose datagrams authenticate because the process running
-- them *is* the service's main job. A script is fixed at exec, so "send
-- this datagram now" is spelled "define a service whose script sends it,
-- and start it", and the definitions are written at runtime through
-- `reg apply` and picked up by peinit's registry watch.
--
-- The progress object's shape is PSPU §4.19's: `current` is N, `total`
-- is T or null, `bounded` is true for `N/` and `N/T` and false for a bare
-- `N`, and `unit` is the last accepted PROGRESS_UNIT or null.

local peinit = require("helpers.peinit")
peinit.claim(1)

local vm = peinit.boot({ name = "notify-progress", files = peinit.tool("pt-notify") })

local function apply(keys)
    local batch = peinit.encode_json({ keys = keys })
    vm:run("cat > /tmp/np.json <<'PT_JSON_EOF'\n" .. batch ..
        "\nPT_JSON_EOF\nreg apply /tmp/np.json"):assert_ok()
end

local function status(name)
    local out = vm:run("svctl --json status " .. name)
    if not out:ok() then return nil end
    if out.stdout:find("UNKNOWN_SERVICE", 1, true) then return nil end
    local ok, view = pcall(json.decode, out.stdout)
    if not ok then return nil end
    return view, out.stdout
end

--- Define a pt-notify service whose script is `steps`.
---
--- The script opens with `sleep 1` — immediately after exec peinit has
--- not yet processed the launch, so a first datagram would be refused as
--- an unauthenticated sender — and closes with a marker file and a long
--- sleep, so that a test knows the steps ran without the process exiting
--- and taking its right to notify with it.
local function define(name, steps)
    local arguments = { "--log", "/run/" .. name .. ".log", "sleep", "1" }
    for _, step in ipairs(steps) do arguments[#arguments + 1] = step end
    for _, step in ipairs({ "write", "/run/" .. name .. ".done", "ok",
                            "sleep", "100000" }) do
        arguments[#arguments + 1] = step
    end
    apply({ { path = [[Machine\System\Services\]] .. name, values = {
        { name = "ImagePath", type = "sz", data = "/usr/bin/pt-notify" },
        { name = "Arguments", type = "multi", data = arguments },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "RestartPolicy", type = "dword", data = 0 },
        { name = "StartTimeout", type = "dword", data = 60 },
    } } })
    wait_until(function() return status(name) ~= nil or nil end,
        { timeout = 60, interval = 0.3, desc = "the registry watch to deliver " .. name })
end

--- Start a defined service and wait until its script has run to the
--- marker, then for peinit to have read what it sent.
local function run_steps(name)
    vm:run("svctl --json start " .. name):assert_ok()
    wait_until(function()
        return vm:run("test -f /run/" .. name .. ".done"):ok() or nil
    end, { timeout = 90, interval = 0.2, desc = name .. " to run its notification script" })
    vm:run("sleep 0.5")
end

local function launch(name, steps)
    define(name, steps)
    run_steps(name)
    return status(name)
end

local function main_pid(name)
    local view = wait_until(function()
        local current = status(name)
        return current and current.current_job and current.current_job.pid and current or nil
    end, { timeout = 60, interval = 0.3, desc = name .. " to have a running main job" })
    return view.current_job.pid
end

--- Every event of the given types still in the KMES ring, oldest first.
local function events(globs)
    local flags = ""
    for _, glob in ipairs(globs) do flags = flags .. " --type '" .. glob .. "'" end
    local r = vm:run("revstrm --snapshot --pretty" .. flags, { timeout = 60 })
    r:assert_ok()
    local out, current = {}, nil
    for line in r.stdout:gmatch("[^\r\n]+") do
        local h, m, s, kind = line:match(
            "^(%d%d):(%d%d):(%d%d[%.%d]*)%s+cpu.-#%d+%s+%u+%s+([%w_]+%.[%w_]+)%s*$")
        if kind then
            current = { type = kind, payload = "",
                        seconds = tonumber(h) * 3600 + tonumber(m) * 60 + tonumber(s) }
            out[#out + 1] = current
        elseif current and line:match("^%s") then
            current.payload = current.payload .. line .. "\n"
        end
    end
    return out
end

local function field(event, name)
    local value = event.payload:match("\n?%s+" .. name .. "%s%s+([^\r\n]*)")
    if not value then return nil end
    return (value:gsub('^"', ""):gsub('"$', ""))
end

local function events_for(kind, service)
    local out = {}
    for _, event in ipairs(events({ kind })) do
        if event.type == kind and field(event, "service") == service then
            out[#out + 1] = event
        end
    end
    return out
end

--- A progress object as one comparable string.
local function shape(progress)
    if type(progress) ~= "table" then return tostring(progress) end
    return string.format("current=%s total=%s bounded=%s unit=%s",
        tostring(progress.current), tostring(progress.total),
        tostring(progress.bounded), tostring(progress.unit))
end

test("progress is shown as {current, total, bounded, unit}, null until a PROGRESS= arrives",
    { spec = "peinit *notify.progress-is-exposed-as-progress" },
    function(t)
        -- Null until the service sends a PROGRESS=.
        local none = launch("pt-np-none", { "send", "STATUS=nothing counted" })
        t:assert_eq(none.status_text, "nothing counted", "the service's datagram arrived")
        t:assert(not none.progress, "and with no PROGRESS= sent, progress is null")

        -- The three forms, and a unit.
        local bar = launch("pt-np-bar", { "send", "PROGRESS=3/10\\nPROGRESS_UNIT=items" })
        t:assert_eq(shape(bar.progress), "current=3 total=10 bounded=true unit=items",
            "N/T is a bar, with its unit")
        local count = launch("pt-np-count", { "send", "PROGRESS=7" })
        t:assert_eq(shape(count.progress), "current=7 total=nil bounded=false unit=nil",
            "a bare N counts with no end, and no unit was sent")
        local open = launch("pt-np-open", { "send", "PROGRESS=4/" })
        t:assert_eq(shape(open.progress), "current=4 total=nil bounded=true unit=nil",
            "N/ counts towards an end not yet known")

        -- Each is replaced only by a datagram that carries it: a STATUS=
        -- alone leaves progress, and a PROGRESS= alone leaves the unit.
        local kept = launch("pt-np-keep", {
            "send", "PROGRESS=2/5\\nPROGRESS_UNIT=bytes",
            "send", "STATUS=later",
            "send", "PROGRESS=3/5",
        })
        t:assert_eq(kept.status_text, "later", "the STATUS= alone was applied")
        t:assert_eq(shape(kept.progress), "current=3 total=5 bounded=true unit=bytes",
            "progress moved only with a PROGRESS=, and kept the unit it had")

        -- A value outside the forms is dropped, never repaired, and the
        -- rest of its datagram is applied: each bad datagram carries a
        -- STATUS= of its own, which becomes a notify.status event.
        local bad = launch("pt-np-bad", {
            "send", "PROGRESS=1/4\\nPROGRESS_UNIT=percent",
            "send", "PROGRESS=5/0\\nSTATUS=a zero total",
            "send", "PROGRESS=6/5\\nSTATUS=N above T",
            "send", "PROGRESS=many\\nSTATUS=not a number",
            "send", "PROGRESS_UNIT=furlongs\\nSTATUS=an unknown unit",
        })
        t:assert_eq(shape(bad.progress), "current=1 total=4 bounded=true unit=percent",
            "none of the four bad values replaced or clamped what was retained")
        local said = {}
        for _, event in ipairs(events_for("notify.status", "pt-np-bad")) do
            said[#said + 1] = tostring(field(event, "status"))
        end
        t:assert_eq(table.concat(said, " | "),
            "a zero total | N above T | not a number | an unknown unit",
            "and the rest of every one of those datagrams was applied")
    end)

test("progress becomes an event at most once a second, carrying what is retained",
    { spec = "peinit *notify.progress-emits-at-most-one-event-a-second" },
    function(t)
        -- Twenty datagrams in a burst, then a pause, then one more. peinit
        -- emits when a second has passed since its last event, so the
        -- burst yields one event, or a few if a loaded host stretched it,
        -- and the status query reports the last value regardless. The
        -- datagram after the pause is past the second and yields one more.
        -- What is asserted is the claim itself: never one event per
        -- datagram, and no two events less than a second apart (less a
        -- tenth for the gap between peinit's clock and the event stamp).
        local steps = { "send", "PROGRESS=1/100\\nPROGRESS_UNIT=items" }
        for n = 2, 20 do
            steps[#steps + 1] = "send"
            steps[#steps + 1] = "PROGRESS=" .. n .. "/100"
        end
        for _, step in ipairs({ "sleep", "2", "send", "PROGRESS=21/100" }) do
            steps[#steps + 1] = step
        end
        local view = launch("pt-np-rate", steps)
        t:assert_eq(shape(view.progress), "current=21 total=100 bounded=true unit=items",
            "the status query reports the latest progress")

        local emitted = events_for("notify.progress", "pt-np-rate")
        t:assert(#emitted >= 2 and #emitted < 21,
            "twenty-one datagrams made at least two events, and not one per datagram: "
            .. #emitted)
        for i = 2, #emitted do
            local gap = emitted[i].seconds - emitted[i - 1].seconds
            if gap < -43200 then gap = gap + 86400 end -- across midnight
            t:assert(gap >= 0.9, ("events %d and %d are a second apart: %.3fs"):format(
                i - 1, i, gap))
        end

        -- The first datagram carried two lines and is one event, carrying
        -- the progress as retained after it, with the attribution.
        local first, last = emitted[1], emitted[#emitted]
        t:assert_eq(field(first, "progress_current"), "1",
            "the first event is the first datagram's: " .. first.payload)
        t:assert_eq(field(first, "progress_total"), "100", "with its total")
        t:assert_eq(field(first, "progress_bounded"), "true", "bounded")
        t:assert_eq(field(first, "progress_unit"), "items", "and the unit from the same datagram")
        t:assert(field(first, "job_id") and field(first, "generation"),
            "attributed to the job and the activation generation: " .. first.payload)
        t:assert_eq(field(last, "progress_current"), "21",
            "and the datagram after the pause made an event of its own: " .. last.payload)
    end)

test("progress is cleared with status_text at the start of every activation generation",
    { spec = "peinit *notify.progress-is-cleared-on-each-activation-generation" },
    function(t)
        -- The subject sends nothing itself: a restarted pt-notify runs
        -- its script again, and a subject that set its own progress would
        -- set it again a second after the restart. A second service sets
        -- the subject's progress by forging its pid, which leaves
        -- "cleared and stayed cleared" as a settled state.
        define("pt-np-gen", {})
        run_steps("pt-np-gen")
        local pid = main_pid("pt-np-gen")
        local job_before = status("pt-np-gen").current_job.id

        launch("pt-np-gen-set", {
            "send-cred", tostring(pid), "0", "0",
            "PROGRESS=2/9\\nPROGRESS_UNIT=items\\nSTATUS=generation one",
        })
        local before = status("pt-np-gen")
        t:assert_eq(shape(before.progress), "current=2 total=9 bounded=true unit=items",
            "the first activation generation carries a progress")
        t:assert_eq(before.status_text, "generation one", "and a status")

        vm:run("svctl --json restart pt-np-gen"):assert_ok()
        local view = wait_until(function()
            local current = status("pt-np-gen")
            return current and current.state == "active"
                and current.current_job
                and current.current_job.id ~= job_before and current or nil
        end, { timeout = 90, interval = 0.3,
               desc = "pt-np-gen to reach a second activation generation" })
        t:assert(not view.progress,
            "the new generation did not inherit the old one's progress: " .. shape(view.progress))
        t:assert(not view.status_text,
            "nor its status, cleared in the same step: " .. tostring(view.status_text))

        vm:run("sleep 3")
        t:assert(not status("pt-np-gen").progress, "and it stays cleared")
    end)
