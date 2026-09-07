-- Peinit TRM §11.3 — flood protection.
--
-- Three registry keys bound what one noisy service can cost the event
-- loop, and the page states a default and a minimum for each. Both
-- numbers are observable from one boot, because the warning peinit
-- writes when a value is below its minimum names the minimum it applied
-- and the default it fell back to — so seeding all three below their
-- floors makes peinit print its own table.
--
-- The truncation and no-drop claims need a service that actually
-- produces the output. Two are seeded: one that writes a single line far
-- longer than the limit, and one that writes eighty kilobytes in a tight
-- loop through a pipe deliberately shrunk to one page, so that reading
-- it is genuinely a flood rather than a formality — the service refills
-- the pipe twenty times over while peinit drains it.
--
-- The flood is sized in kilobytes rather than megabytes on purpose. A
-- pre-eventd backlog past about two hundred kilobytes is never delivered
-- at all (see the known-bug case in output-eventd.test.lua), and a test
-- of what the PIPE stage does must not be reading the symptom of a fault
-- two hops downstream of it.

local peinit = require("helpers.peinit")
peinit.claim(2)

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

local LIMIT = 256 -- MaxLogLineLength's documented minimum, and so honoured.
local FLOOD_LINES = 400
local FLOOD_WIDTH = 200

-- A line of 1000 identical characters, so the truncated remainder — if
-- there were one — would be unmistakable: a record of nothing but `x`.
-- The padding is written out in full rather than built in the shell,
-- because a literal is one fewer thing that can behave differently in
-- the guest's `sh` than in the author's.
local long = "#!/bin/sh\n" ..
    'echo "pt-long-' .. string.rep("x", 1000) .. '"\n' ..
    'echo "pt-after-the-long-line"\n'

local flood = "#!/bin/sh\n" ..
    "i=0\n" ..
    "while [ $i -lt " .. FLOOD_LINES .. " ]; do\n" ..
    '    echo "pt-flood-$i-' .. string.rep("y", FLOOD_WIDTH - 24) .. '"\n' ..
    "    i=$((i + 1))\n" ..
    "done\n"

local function oneshot(name, image)
    return {
        path = [[Machine\System\Services\]] .. name,
        values = {
            { name = "ImagePath", type = "sz", data = image },
            { name = "Type", type = "dword", data = 1 },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "Readiness", type = "dword", data = 1 },
            { name = "Triggers", type = "multi", data = { "boot" } },
        },
    }
end

local function wait_for_eventd(vm)
    for _ = 1, 60 do
        if vm:run("svctl status eventd").stdout:find("eventd: active") then return true end
        vm:run("sleep 1")
    end
    return false
end

--- Every log record eventd holds for `origin`, as a list of messages.
---
--- Polled until the expected count arrives or the wait runs out.
--- Delivery is asynchronous at two removes here: peinit drains the pipe
--- a budget at a time and forwards in batches, and the records these
--- tests care about were produced before eventd existed, so they arrive
--- as a replay that begins only once eventd is serving. A single query
--- issued the moment eventd goes Active races both.
local function messages_from(vm, origin, want)
    local messages = {}
    for _ = 1, 45 do
        messages = {}
        local out = vm:run(
            "evctl 'LOGS FROM " .. origin .. " SINCE 1h ago TAKE 5000' --format jsonl").stdout
        for line in out:gmatch("[^\r\n]+") do
            local message = line:match('"message":"([^"]*)"')
            if message then messages[#messages + 1] = message end
        end
        if #messages >= (want or 1) then return messages end
        vm:run("sleep 1")
    end
    return messages
end

-- Every knob one below its floor. Nothing here is honoured; the interest
-- is entirely in what peinit says about it.
local rejected = peinit.boot({
    memory = MEM, cpus = CPUS,
    name = "flood-min",
    files = peinit.seed("zz-pt-min", {
        { path = [[Machine\System]] },
        { path = [[Machine\System\Init]] },
        {
            path = [[Machine\System\Init]],
            values = {
                { name = "MaxLogLineLength", type = "dword", data = 255 },
                { name = "MaxLogBufferPerService", type = "dword", data = 4095 },
                { name = "LogReadBytesPerEvent", type = "dword", data = 511 },
            },
        },
    }),
})

-- MaxLogLineLength at exactly its minimum, which IS honoured, plus the
-- two services that produce the output.
local capped = peinit.boot({
    memory = MEM, cpus = CPUS,
    name = "flood-cap",
    files = peinit.merge(
        {
            ["lcl/pt/long.sh"] = { long, exec = true },
            ["lcl/pt/flood.sh"] = { flood, exec = true },
        },
        peinit.seed("zz-pt-flood", {
            { path = [[Machine\System]] },
            { path = [[Machine\System\Services]] },
            { path = [[Machine\System\Init]] },
            {
                path = [[Machine\System\Init]],
                values = {
                    { name = "MaxLogLineLength", type = "dword", data = LIMIT },
                    -- One page, the documented minimum, and so honoured.
                    -- Small enough that eighty kilobytes cannot be
                    -- absorbed by the pipe and has to be read out of it.
                    { name = "MaxLogBufferPerService", type = "dword", data = 4096 },
                },
            },
            oneshot("pt-long", "/lcl/pt/long.sh"),
            oneshot("pt-flood", "/lcl/pt/flood.sh"),
            -- Both must have written everything before eventd exists, so
            -- that delivery is the buffer's ordered replay rather than
            -- the lossy live path: §11.3 allows loss downstream of the
            -- pipe, and only the pipe stage is under test here.
            {
                path = [[Machine\System\Services\eventd]],
                values = {
                    { name = "Requires", type = "multi", data = { "authd", "pt-long", "pt-flood" } },
                },
            },
        })
    ),
})
wait_for_eventd(capped)

test("a knob below its minimum is refused in favour of the compiled-in default, with a warning naming both",
    {
        spec = {
            "peinit *flood.a-below-minimum-value-keeps-the-default-and-warns",
            "peinit *flood.the-max-log-line-length-key",
            "peinit *flood.the-max-log-buffer-per-service-key",
            "peinit *flood.the-log-read-bytes-per-event-key",
        },
    },
    function(t)
        local log = rejected:console():read_log()

        -- The warning states the key, the configured value, the minimum
        -- and what was used instead, which between them are the two
        -- numbers this page's table gives for each key.
        local expected = {
            { key = "MaxLogLineLength", configured = 255, minimum = 256, default = 8192 },
            { key = "MaxLogBufferPerService", configured = 4095, minimum = 4096, default = 65536 },
            { key = "LogReadBytesPerEvent", configured = 511, minimum = 512, default = 16384 },
        }
        for _, k in ipairs(expected) do
            local line = "Machine\\System\\Init\\" .. k.key .. " is " .. k.configured ..
                ", below the minimum " .. k.minimum .. "; using the default " .. k.default
            t:assert(log:find(line, 1, true),
                "peinit reported: " .. line)
        end

        -- And the boot survived it. A typo in a logging knob must not
        -- decide how the machine boots.
        t:assert(log:find("peinit: phase2 boot complete", 1, true),
            "none of the three failed the boot")
    end)

test("a line over the limit is cut to exactly the limit and marked, and its tail is not emitted again",
    {
        spec = {
            "peinit *flood.an-overlong-line-is-truncated-to-exactly-the-limit",
            "peinit *flood.the-remainder-of-a-truncated-line-is-suppressed",
        },
    },
    function(t)
        local messages = messages_from(capped, "pt-long", 2)
        local truncated
        for _, message in ipairs(messages) do
            if message:find("^pt%-long%-") then truncated = message end
        end
        t:assert(truncated, "the long line was captured in some form")

        -- Content and marker together come to exactly the limit, so a
        -- consumer laying the log out in columns gets a rectangle.
        t:assert_eq(#truncated, LIMIT,
            "the stored line is exactly " .. LIMIT .. " bytes, got " .. #truncated)
        t:assert_eq(truncated:sub(-11), "[truncated]",
            "and says so: " .. truncated:sub(-20))

        -- The rest is suppressed rather than emitted as a second line.
        -- The padding is a thousand identical characters, so a remainder
        -- would show up as a record of nothing but those.
        for _, message in ipairs(messages) do
            t:assert(not message:match("^x+$"),
                "no second record carries the tail of the truncated line: " .. message)
        end

        -- Suppressed up to the NEXT newline, not for ever: the line the
        -- service wrote afterwards is intact.
        local found = false
        for _, message in ipairs(messages) do
            if message == "pt-after-the-long-line" then found = true end
        end
        t:assert(found, "the line after the truncated one was emitted normally")
    end)

test("a service that writes far faster than the pipe holds loses no line at the pipe",
    { spec = "peinit *flood.nothing-is-dropped-at-the-pipe" },
    function(t)
        -- Eighty kilobytes written in a tight loop through a pipe this
        -- boot set to one page: the pipe fills twenty times over and the
        -- service blocks in write() while peinit drains it a budget at a
        -- time. Backpressure is the flow-control mechanism between the
        -- two, and the guarantee is that nothing is dropped in the
        -- process — every complete line is appended.
        local messages = messages_from(capped, "pt-flood", FLOOD_LINES)
        local seen = {}
        for _, message in ipairs(messages) do
            local index = message:match("^pt%-flood%-(%d+)%-")
            if index then seen[tonumber(index)] = true end
        end

        local missing = {}
        for i = 0, FLOOD_LINES - 1 do
            if not seen[i] then missing[#missing + 1] = i end
        end
        t:assert_eq(#missing, 0,
            "every one of the " .. FLOOD_LINES .. " lines survived the read; missing " ..
            #missing .. ", first few: " .. table.concat(missing, ",", 1, math.min(#missing, 8)))
    end)
