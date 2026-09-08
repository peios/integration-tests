-- peinit TRM §10.6 — the fd store: what a service pushes, what peinit
-- holds, and what comes back to the process that replaces it.
--
-- The store is directly observable from the guest, which is what makes
-- this article testable at all. peinit holds every stored descriptor
-- open, so `/proc/1/fd` is the store: one symlink per entry, naming
-- whatever the descriptor was opened on. A test that stores descriptors
-- on a marker file it chose can count them there, and a remove or a
-- clear is the count going back down.
--
-- The other half — what a restarted process is handed — is read from
-- `pt-notify`'s `report` step, which writes out `LISTEN_FDS`,
-- `LISTEN_FDNAMES`, `LISTEN_PID` and every descriptor from 3 up with its
-- type and, for a socket, its address.
--
-- Two things about restarts matter to the shape below. An
-- administrator's *stop* clears the store and an administrator's
-- *restart* does not (fd_store_lifecycle.rs: the clearing is keyed on
-- OperationType::Stop), so `svctl restart` is the cheap, deterministic
-- way to observe an injection. The store surviving an *automatic*
-- restart is a separate claim and gets a service that crashes and is
-- restarted by policy.
--
-- One claim here has no route from the guest:
--
--   fdstore.a-returned-listener-keeps-its-captured-identity
--     A listener's captured identity is visible only to a client reading
--     the peer token of a connection to it, and it would have to differ
--     between the two incarnations to be recognisable at all -- so the
--     test needs both a way to change the service's identity across the
--     restart and a client that reports a connection's peer token. The
--     image ships no such client, and `report` sees a descriptor's type
--     and address but not its token.

local peinit = require("helpers.peinit")
peinit.claim(1)

local vm = peinit.boot({ name = "nffdstore", files = peinit.tool("pt-notify") })

local function apply(keys)
    local batch = peinit.encode_json({ keys = keys })
    vm:run("cat > /tmp/nf.json <<'PT_JSON_EOF'\n" .. batch ..
        "\nPT_JSON_EOF\nreg apply /tmp/nf.json"):assert_ok()
end

local function status(name)
    local out = vm:run("svctl --json status " .. name)
    if not out:ok() then return nil end
    if out.stdout:find("UNKNOWN_SERVICE", 1, true) then return nil end
    local ok, view = pcall(json.decode, out.stdout)
    if not ok then return nil end
    return view
end

--- Define a pt-notify service whose script is `steps`.
---
--- The opening `sleep 1` is the documented trap in `peinit.tool`:
--- immediately after exec peinit has not yet processed the launch, so a
--- first datagram is refused as an unauthenticated sender and lost.
--- `values` overrides or adds registry values by name.
local function define(name, steps, values)
    local arguments = { "--log", "/run/" .. name .. ".log", "sleep", "1" }
    for _, step in ipairs(steps) do arguments[#arguments + 1] = step end
    for _, step in ipairs({ "write", "/run/" .. name .. ".done", "ok",
                            "sleep", "100000" }) do
        arguments[#arguments + 1] = step
    end

    local base = {
        { name = "ImagePath", type = "sz", data = "/usr/bin/pt-notify" },
        { name = "Arguments", type = "multi", data = arguments },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "RestartPolicy", type = "dword", data = 0 },
        { name = "StartTimeout", type = "dword", data = 60 },
        { name = "FdStoreMax", type = "dword", data = 8 },
    }
    for _, value in ipairs(values or {}) do
        local replaced = false
        for index, existing in ipairs(base) do
            if existing.name == value.name then
                base[index] = value
                replaced = true
            end
        end
        if not replaced then base[#base + 1] = value end
    end

    apply({ { path = [[Machine\System\Services\]] .. name, values = base } })
    wait_until(function() return status(name) ~= nil or nil end,
        { timeout = 60, interval = 0.3,
          desc = "the registry watch to deliver " .. name })
end

--- Wait until the running incarnation has reached the end of its script.
local function await_steps(name)
    wait_until(function()
        return vm:run("test -f /run/" .. name .. ".done"):ok() or nil
    end, { timeout = 90, interval = 0.2,
           desc = name .. " to run its notification script" })
    -- The marker is written after the last datagram is *sent*; peinit
    -- still has to read it. Half a second is many turns of its loop.
    vm:run("sleep 0.5")
end

local function launch(name, steps, values)
    define(name, steps, values)
    vm:run("svctl --json --no-wait start " .. name):assert_ok()
    await_steps(name)
end

--- Restart and wait for the new incarnation's script.
---
--- The marker is removed first, because the previous incarnation left
--- one and waiting for a file that is already there would prove nothing.
local function restart(name)
    vm:run("rm -f /run/" .. name .. ".done"):assert_ok()
    vm:run("svctl --json --no-wait restart " .. name):assert_ok()
    await_steps(name)
end

--- Every target PID 1 has a descriptor open on.
local function fd_targets()
    local listing = vm:run("ls -l /proc/1/fd 2>/dev/null").stdout
    local out = {}
    for line in listing:gmatch("[^\r\n]+") do
        local target = line:match("%->%s+(.*)$")
        if target then out[#out + 1] = (target:gsub("%s+$", "")) end
    end
    return out
end

--- How many descriptors peinit holds on `path`. A descriptor on an
--- unlinked file still names it, with ` (deleted)` appended.
local function held(path)
    local count = 0
    for _, target in ipairs(fd_targets()) do
        if target == path or target == path .. " (deleted)" then
            count = count + 1
        end
    end
    return count
end

--- Poll `path` until it holds `needle`, for up to `seconds`. Returns the
--- contents, or nil -- so the caller can say what the service was doing
--- instead when it never arrived.
local function await_content(path, needle, seconds)
    for _ = 1, (seconds or 90) do
        local text = vm:run("cat " .. path .. " 2>/dev/null").stdout
        if text and text:find(needle, 1, true) then return text end
        vm:run("sleep 1")
    end
    return nil
end

--- What a service and its tool log look like, for a failure message.
local function diagnose(name)
    local view = status(name)
    return "state=" .. tostring(view and view.state) ..
        " cause=" .. tostring(view and view.cause) ..
        " tool log=[" .. vm:run("cat /run/" .. name .. ".log 2>&1").stdout .. "]"
end

--- A pt-notify report, as a table of its `key=value` lines plus the
--- descriptor rows in order.
local function report(path)
    local text = vm:read_file(path)
    local out = { raw = text, fds = {} }
    for line in text:gmatch("[^\r\n]+") do
        local fd, rest = line:match("^fd(%d+)=(.*)$")
        if fd then
            out.fds[#out.fds + 1] = { fd = tonumber(fd), detail = rest }
        else
            local key, value = line:match("^([^=]+)=(.*)$")
            if key then out[key] = value end
        end
    end
    return out
end

local function events(globs)
    local flags = ""
    for _, glob in ipairs(globs) do flags = flags .. " --type '" .. glob .. "'" end
    local r = vm:run("revstrm --snapshot --pretty" .. flags, { timeout = 60 })
    r:assert_ok()
    local out, current = {}, nil
    for line in r.stdout:gmatch("[^\r\n]+") do
        local kind = line:match("^%d%d:%d%d:%d%d[%.%d]*%s+cpu.-#%d+%s+%u+%s+([%w_]+%.[%w_]+)%s*$")
        if kind then
            current = { type = kind, payload = "" }
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

--- Every `fd_store.rejected` event naming `service`.
local function rejections(service)
    local out = {}
    for _, event in ipairs(events({ "fd_store.rejected" })) do
        if field(event, "service") == service then out[#out + 1] = event end
    end
    return out
end

local function marker(name)
    local path = "/run/" .. name .. ".marker"
    vm:run("echo " .. name .. " > " .. path):assert_ok()
    return path
end

test("a store disabled by FdStoreMax=0 closes the descriptor and says why",
    {
        spec = {
            "peinit *fdstore.a-disabled-store-closes-the-descriptor",
            "peinit *fdstore.a-rejection-emits-an-event",
        },
    },
    function(t)
        -- The descriptor really is sent: pt-notify's log records
        -- sendmsg's return, and peinit received it, which is what an
        -- event about it proves. What must not happen is peinit keeping
        -- it -- a disabled store is not a store that quietly holds
        -- things it will never give back.
        local path = marker("pt-fs-off")
        launch("pt-fs-off", {
            "send-fd", path, "FDSTORE=1\\nFDNAME=hopeful",
        }, { { name = "FdStoreMax", type = "dword", data = 0 } })

        t:assert_eq(held(path), 0,
            "peinit holds no descriptor on the marker the service sent")

        local rejected = rejections("pt-fs-off")
        t:assert_eq(#rejected, 1, "and recorded exactly one rejection")
        t:assert_eq(field(rejected[1], "outcome"), "disabled",
            "naming the disabled store as the outcome: " .. rejected[1].payload)
        t:assert_eq(field(rejected[1], "name"), "hopeful",
            "and the name the service asked for, so it can tell which send was dropped")
    end)

test("a full store rejects the overflow and does not evict what it holds",
    {
        spec = {
            "peinit *fdstore.a-full-store-does-not-evict",
            "peinit *fdstore.a-rejection-emits-an-event",
        },
    },
    function(t)
        -- Two markers, so "what survived" is a question with an answer
        -- rather than a count. FdStoreMax is 2; the first two sends fill
        -- it and the third arrives on a different file, so if the store
        -- evicted to make room the two counts would swap.
        local keep = marker("pt-fs-full-keep")
        local late = marker("pt-fs-full-late")
        launch("pt-fs-full", {
            "send-fd", keep, "FDSTORE=1\\nFDNAME=first",
            "send-fd", keep, "FDSTORE=1\\nFDNAME=second",
            "send-fd", late, "FDSTORE=1\\nFDNAME=third",
        }, { { name = "FdStoreMax", type = "dword", data = 2 } })

        t:assert_eq(held(keep), 2,
            "the two descriptors that fitted are still held")
        t:assert_eq(held(late), 0,
            "and the one that did not was closed rather than swapped in")

        local rejected = rejections("pt-fs-full")
        t:assert_eq(#rejected, 1, "one rejection, for the third send")
        t:assert_eq(field(rejected[1], "outcome"), "full",
            "naming a full store: " .. rejected[1].payload)
        t:assert_eq(field(rejected[1], "name"), "third",
            "and the name the rejected descriptor was sent under")
    end)

test("several descriptors share one name, each subject to the limit on its own",
    { spec = "peinit *fdstore.several-descriptors-may-share-a-name" },
    function(t)
        -- One FDSTORE=1 carrying three descriptors against a store that
        -- can hold two. Three entries were asked for under one name; two
        -- are made and the third is refused, which is what "each
        -- independently subject to the limit" means -- the send is not
        -- accepted or refused as a unit.
        local path = marker("pt-fs-share")
        -- The report comes first in the script, so the copy left behind
        -- after the restart below is the one taken with the store full.
        launch("pt-fs-share", {
            "report", "/run/pt-fs-share.report",
            "send-fds", "3", path, "FDSTORE=1\\nFDNAME=shared",
        }, { { name = "FdStoreMax", type = "dword", data = 2 } })

        t:assert_eq(held(path), 2,
            "two of the three descriptors were stored under the one name")

        local rejected = rejections("pt-fs-share")
        t:assert_eq(#rejected, 1, "and the overflowing third was rejected")
        t:assert_eq(field(rejected[1], "outcome"), "full",
            "for a full store: " .. rejected[1].payload)

        -- And the two that fitted are genuinely two entries under one
        -- name, which the injected LISTEN_FDNAMES is what shows.
        restart("pt-fs-share")
        local handed = report("/run/pt-fs-share.report")
        t:assert_eq(handed.LISTEN_FDS, "2", "both came back")
        t:assert_eq(handed.LISTEN_FDNAMES, "shared:shared",
            "under the same name, once each: " .. tostring(handed.LISTEN_FDNAMES))
    end)

test("stored descriptors come back from fd 3 upward, named and counted",
    {
        spec = {
            "peinit *fdstore.descriptors-are-injected-from-descriptor-three-upward",
            "peinit *fdstore.listen-fds-is-the-count",
            "peinit *fdstore.listen-fdnames-is-colon-separated-and-in-order",
            "peinit *fdstore.listen-pid-is-appended-by-the-child",
        },
    },
    function(t)
        -- Two descriptors of different kinds, so the order claim has
        -- something to bite on: `alpha` is a listening socket and `beta`
        -- is a regular file, and LISTEN_FDNAMES must name them in the
        -- same order as the descriptor numbers rather than in any order
        -- that happens to be convenient.
        local path = marker("pt-fs-inject")
        launch("pt-fs-inject", {
            "report", "/run/pt-fs-inject.report",
            "send-listener", "/run/pt-fs-inject.sock", "FDSTORE=1\\nFDNAME=alpha",
            "send-fd", path, "FDSTORE=1\\nFDNAME=beta",
        })

        local before = report("/run/pt-fs-inject.report")
        t:assert_eq(before.LISTEN_FDS, "",
            "the first incarnation was handed nothing, the store being empty")
        -- pt-notify holds two descriptors of its own while it reports --
        -- the `--log` file and the report it is writing -- so two is the
        -- baseline every count below is measured against.
        t:assert_eq(#before.fds, 2,
            "with nothing above stderr but pt-notify's own two files: " .. before.raw)

        restart("pt-fs-inject")
        local handed = report("/run/pt-fs-inject.report")

        t:assert_eq(handed.LISTEN_FDS, "2",
            "LISTEN_FDS is the count: " .. handed.raw)
        t:assert_eq(handed.LISTEN_FDNAMES, "alpha:beta",
            "LISTEN_FDNAMES is colon-separated and in descriptor order")
        t:assert_eq(handed.LISTEN_PID, handed.pid,
            "LISTEN_PID is the child's own pid, appended after the clone")

        t:assert_eq(#handed.fds, 4,
            "the two injected descriptors, and pt-notify's own two, and " ..
            "nothing else: " .. handed.raw)
        t:assert_eq(handed.fds[1].fd, 3,
            "placed consecutively from SD_LISTEN_FDS_START")
        t:assert_eq(handed.fds[2].fd, 4, "and the next one after it")
        t:assert(handed.fds[1].detail:find("/run/pt-fs-inject.sock", 1, true),
            "fd 3 is `alpha`, the listener: " .. handed.fds[1].detail)
        t:assert(handed.fds[1].detail:find("listening=1", 1, true),
            "still listening, close-on-exec having been cleared rather than " ..
            "the socket remade: " .. handed.fds[1].detail)
        t:assert_eq(handed.fds[2].detail, "file",
            "and fd 4 is `beta`, the regular file")
    end)

test("an unnamed descriptor is stored under the name `stored`",
    { spec = "peinit *fdstore.an-unnamed-descriptor-is-named-stored" },
    function(t)
        -- No FDNAME at all, and an empty one: the article makes them the
        -- same case, so both must come back under the default rather
        -- than one of them under an empty name.
        local path = marker("pt-fs-unnamed")
        launch("pt-fs-unnamed", {
            "report", "/run/pt-fs-unnamed.report",
            "send-fd", path, "FDSTORE=1",
            "send-fd", path, "FDSTORE=1\\nFDNAME=",
        })
        t:assert_eq(held(path), 2, "both descriptors were stored")

        restart("pt-fs-unnamed")
        local handed = report("/run/pt-fs-unnamed.report")
        t:assert_eq(handed.LISTEN_FDNAMES, "stored:stored",
            "an absent and an empty FDNAME both mean `stored`: " ..
            tostring(handed.LISTEN_FDNAMES))
    end)

test("a named remove closes every descriptor of that name and leaves the rest",
    { spec = "peinit *fdstore.a-named-remove-closes-every-descriptor-of-that-name" },
    function(t)
        -- Two names on two markers, so the remove has something it must
        -- not touch. Then a remove of a name that matches nothing, which
        -- must be a no-op and not an error that voids the datagram.
        local doomed = marker("pt-fs-rm-doomed")
        local safe = marker("pt-fs-rm-safe")
        launch("pt-fs-rm", {
            "send-fds", "3", doomed, "FDSTORE=1\\nFDNAME=doomed",
            "send-fd", safe, "FDSTORE=1\\nFDNAME=safe",
            "send", "FDSTOREREMOVE=1\\nFDNAME=doomed",
        })

        t:assert_eq(held(doomed), 0,
            "every descriptor of the named entry was removed, not just one")
        t:assert_eq(held(safe), 1, "and the other name was left alone")

        -- A name matching nothing: a no-op rather than an error.
        define("pt-fs-rm-miss", {
            "send", "FDSTOREREMOVE=1\\nFDNAME=never-stored\\nSTATUS=survived",
        })
        vm:run("svctl --json --no-wait start pt-fs-rm-miss"):assert_ok()
        await_steps("pt-fs-rm-miss")
        local view = status("pt-fs-rm-miss")
        t:assert_eq(view.status_text, "survived",
            "a remove of an unknown name did not void the datagram it rode in")
    end)

test("an unnamed FDSTOREREMOVE alongside an FDSTORE performs neither",
    {
        spec = "peinit *fdstore.an-unnamed-remove-aborts-the-fd-store-step",
        -- PEI-836. supervisor/notify/fd_store.rs defaults an absent
        -- FDNAME to `stored` in `FdStoreDirective::from_message` (:90)
        -- whenever the datagram also carries FDSTORE=1 -- which happens
        -- before the abort guard at :18-21 reads `directive.name`. So
        -- the guard never sees an unnamed remove in exactly the case the
        -- article is about, and the datagram performs *both* halves
        -- instead of neither: the existing `stored` entry is removed and
        -- the new descriptor is stored.
        tags = { "known-bug" },
    },
    function(t)
        local existing = marker("pt-fs-abort-existing")
        local arriving = marker("pt-fs-abort-arriving")
        launch("pt-fs-abort", {
            -- One unnamed descriptor, so the store holds an entry called
            -- `stored`.
            "send-fd", existing, "FDSTORE=1",
            -- And now the datagram the article describes: an unnamed
            -- remove and a store, together, with a descriptor attached.
            "send-fd", arriving, "FDSTOREREMOVE=1\\nFDSTORE=1",
        })

        t:assert_eq(held(existing), 1,
            "the unnamed remove aborted the step, so the entry it would " ..
            "have matched is still held")
        t:assert_eq(held(arriving), 0,
            "and the attached descriptor was dropped and closed rather than stored")
    end)

test("stored descriptors are never monitored, and no flag makes them so",
    { spec = "peinit *fdstore.stored-descriptors-are-never-monitored" },
    function(t)
        -- FDPOLL=0 asks to be exempt from poll monitoring, and the
        -- article's claim is that the flag is recorded and nothing reads
        -- it -- so the exempt descriptor and the un-exempt one must fare
        -- identically. Unlinking the file both were opened on is the
        -- cheapest way to make them descriptors on something that is no
        -- longer reachable by name; a store that watched its entries for
        -- validity would be the kind of store that could act on that.
        local watched = marker("pt-fs-poll-watched")
        local exempt = marker("pt-fs-poll-exempt")
        launch("pt-fs-poll", {
            "report", "/run/pt-fs-poll.report",
            "send-fd", watched, "FDSTORE=1\\nFDNAME=watched",
            "send-fd", exempt, "FDSTORE=1\\nFDNAME=exempt\\nFDPOLL=0",
        })
        t:assert_eq(held(watched), 1, "the un-exempt descriptor is held")
        t:assert_eq(held(exempt), 1, "and so is the exempt one")

        vm:run("rm -f " .. watched .. " " .. exempt):assert_ok()
        vm:run("sleep 5")

        t:assert_eq(held(watched), 1,
            "nothing evicted the un-exempt descriptor for its file going away")
        t:assert_eq(held(exempt), 1, "and nothing evicted the exempt one either")

        -- And both are still real enough to be handed back.
        restart("pt-fs-poll")
        local handed = report("/run/pt-fs-poll.report")
        t:assert_eq(handed.LISTEN_FDS, "2",
            "both came back on the restart: " .. handed.raw)
        t:assert_eq(handed.LISTEN_FDNAMES, "watched:exempt",
            "FDPOLL having changed nothing about either")
    end)

test("hooks and the store: only the main process is handed descriptors",
    { spec = "peinit *fdstore.only-the-main-process-receives-stored-descriptors" },
    function(t)
        -- The hook is the same program as the service, so a difference
        -- in what the two are handed is a difference peinit made rather
        -- than one the program made.
        --
        -- An `ExecReload` command, because it is a hook that runs on a
        -- service that is already up: the store is at its fullest and
        -- the hook is forked while it is, so there is no restart in the
        -- way and no question about which launch is being looked at.
        local path = marker("pt-fs-hook")
        -- One of the two is a listening socket, so a descriptor from
        -- this store is recognisable by sight in any report that has it.
        launch("pt-fs-hook", {
            "report", "/run/pt-fs-hook.report",
            "send-listener", "/run/pt-fs-hook.sock", "FDSTORE=1\\nFDNAME=alpha",
            "send-fd", path, "FDSTORE=1\\nFDNAME=beta",
        }, { { name = "ExecReload", type = "sz",
               data = "/usr/bin/pt-notify report /run/pt-fs-hook.hook" } })
        -- The regular file is countable in /proc/1/fd; the listener
        -- shows there as a `socket:[…]` and is recognised by name in the
        -- injected report below instead.
        t:assert_eq(held(path), 1,
            "the store is populated while the hook runs")

        vm:run("svctl --json --no-wait reload pt-fs-hook"):assert_ok()
        wait_until(function()
            return vm:run("test -f /run/pt-fs-hook.hook"):ok() or nil
        end, { timeout = 60, interval = 0.3, desc = "the reload hook to report" })

        -- And the main process does get them, on the next launch, from
        -- exactly this store.
        restart("pt-fs-hook")
        local main = report("/run/pt-fs-hook.report")
        t:assert_eq(main.LISTEN_FDS, "2",
            "the main process was handed both stored descriptors")

        local hook = report("/run/pt-fs-hook.hook")
        t:assert_eq(hook.LISTEN_FDS, "",
            "and the hook, launched from the same store, was handed none: " ..
            hook.raw)
        t:assert_eq(hook.LISTEN_FDNAMES, "",
            "with no names either")
        -- One descriptor above stderr, and it is the report the hook is
        -- writing. Neither of the stored pair is there: `alpha` is a
        -- listening socket and would be unmistakable.
        t:assert_eq(#hook.fds, 1,
            "and nothing open above stderr but its own report: " .. hook.raw)
        t:assert_eq(hook.fds[1].detail, "file",
            "which is a file, not the stored listener")
    end)

test("the store survives an automatic restart",
    { spec = "peinit *fdstore.the-store-survives-an-automatic-restart" },
    function(t)
        -- The restart nobody asked for is the one the store exists for.
        -- This service stores two descriptors and then exits non-zero;
        -- RestartPolicy=OnFailure brings it back, and the budget of one
        -- retry stops it looping. The second incarnation's report is
        -- what the crash left it.
        local path = marker("pt-fs-crash")
        define("pt-fs-crash", {
            "report", "/run/pt-fs-crash.report",
            "send-fd", path, "FDSTORE=1\\nFDNAME=alpha",
            "send-fd", path, "FDSTORE=1\\nFDNAME=beta",
            "write", "/run/pt-fs-crash.first", "ok",
            -- A datagram is only *sent* when the step returns; peinit
            -- still has to read it, and it authenticates the sender
            -- against the service's live main job. Exiting the instant
            -- after the last send loses it -- the job is reaped before
            -- the datagram is read, and it is refused as an
            -- unauthenticated sender.
            "sleep", "2",
            "exit", "9",
        }, {
            { name = "RestartPolicy", type = "dword", data = 1 },
            { name = "RestartMaxRetries", type = "dword", data = 1 },
            { name = "RestartDelay", type = "dword", data = 1 },
        })
        vm:run("svctl --json --no-wait start pt-fs-crash"):assert_ok()
        -- The script ends in `exit`, so the closing marker is never
        -- written; the report is what says an incarnation ran.
        t:assert(await_content("/run/pt-fs-crash.report", "LISTEN_FDS=2", 120),
            "a second incarnation was handed the crashed one's descriptors: " ..
            diagnose("pt-fs-crash") .. " report=[" ..
            vm:run("cat /run/pt-fs-crash.report 2>&1").stdout .. "]")

        local handed = report("/run/pt-fs-crash.report")
        t:assert_eq(handed.LISTEN_FDNAMES, "alpha:beta",
            "the descriptors persisted through the restart the service " ..
            "did not choose: " .. handed.raw)
    end)

test("a failed launch does not clear the store",
    { spec = "peinit *fdstore.a-failed-launch-does-not-clear-the-store" },
    function(t)
        -- The clearing happens at the top of the started-launch
        -- handling, so a launch that never gets that far must leave the
        -- store where it was. The failure is arranged from outside: a
        -- gate file the test controls, which the service's own
        -- ExecStartPre refuses to start alongside. A restart then stops
        -- the service -- which does not clear the store, the clearing
        -- being keyed on an administrator's *stop* -- and fails on the
        -- way back up.
        local path = marker("pt-fs-relaunch")
        local block = "/run/pt-fs-relaunch.block"
        vm:run("rm -f " .. block):assert_ok()
        define("pt-fs-relaunch", {
            "report", "/run/pt-fs-relaunch.report",
            "send-fd", path, "FDSTORE=1\\nFDNAME=survivor",
        }, {
            -- Hook command lines are argv, split on whitespace with
            -- double quotes honoured (execution/command.rs), so the
            -- whole `sh -c` script has to be one quoted word.
            { name = "ExecStartPre", type = "multi",
              data = { '/bin/sh -c "! [ -f ' .. block .. ' ]"' } },
        })
        vm:run("svctl --json --no-wait start pt-fs-relaunch"):assert_ok()
        await_steps("pt-fs-relaunch")
        t:assert_eq(held(path), 1, "the service stored one descriptor")

        vm:run("echo blocked > " .. block):assert_ok()
        vm:run("rm -f /run/pt-fs-relaunch.done"):assert_ok()
        vm:run("svctl --json --no-wait restart pt-fs-relaunch")
        local failed = wait_until(function()
            local view = status("pt-fs-relaunch")
            return view and view.state == "failed" and view or nil
        end, { timeout = 90, interval = 0.3,
               desc = "pt-fs-relaunch's relaunch to fail" })
        t:assert_eq(failed.cause, "pre_hook_failure",
            "the launch failed before the process was ever started")
        t:assert(not vm:run("test -f /run/pt-fs-relaunch.done"):ok(),
            "and no new incarnation ran")
        -- Failed is reached a moment before the restart operation
        -- finishes unwinding; the next command belongs after that.
        vm:run("sleep 3")

        t:assert_eq(held(path), 1,
            "the descriptor stored before the failure is still held")

        -- And it is still injectable: the next launch to actually start
        -- gets it. The reset is not incidental -- a service left Failed
        -- by a pre-start hook does not take a start until its failure is
        -- cleared -- and a reset is not a stop, so it does not clear the
        -- store either.
        vm:run("rm -f " .. block):assert_ok()
        vm:run("rm -f /run/pt-fs-relaunch.report"):assert_ok()
        vm:run("svctl --json reset pt-fs-relaunch"):assert_ok()
        vm:run("sleep 2")
        t:assert_eq(held(path), 1, "the reset left the store alone")
        vm:run("svctl --json --no-wait start pt-fs-relaunch"):assert_ok()
        t:assert(await_content("/run/pt-fs-relaunch.report", "LISTEN_FDS=", 120),
            "pt-fs-relaunch launched again once its gate was removed: " ..
            diagnose("pt-fs-relaunch") ..
            " gate-present=" .. tostring(vm:run("test -f " .. block):ok()))
        local handed = report("/run/pt-fs-relaunch.report")
        t:assert_eq(handed.LISTEN_FDNAMES, "survivor",
            "and the descriptor that survived the failed attempt was " ..
            "available to the next one: " .. handed.raw)
    end)

test("an explicit stop clears the store",
    { spec = "peinit *fdstore.an-explicit-stop-clears-the-store" },
    function(t)
        -- An administrator's stop says the service is not coming back,
        -- so what it was holding on to is no longer worth holding. The
        -- same descriptors survived a restart two tests above, which is
        -- what makes this about the *stop* rather than about a process
        -- ending.
        local path = marker("pt-fs-stop")
        launch("pt-fs-stop", {
            "send-fd", path, "FDSTORE=1\\nFDNAME=alpha",
            "send-fd", path, "FDSTORE=1\\nFDNAME=beta",
        })
        t:assert_eq(held(path), 2, "two descriptors are held for the running service")

        vm:run("svctl --json stop pt-fs-stop"):assert_ok()
        wait_until(function()
            local view = status("pt-fs-stop")
            return view and view.state == "inactive" and view or nil
        end, { timeout = 90, interval = 0.3, desc = "pt-fs-stop to stop" })
        wait_until(function() return held(path) == 0 or nil end,
            { timeout = 30, interval = 0.3,
              desc = "the store to be cleared by the stop" })
        t:assert_eq(held(path), 0,
            "and the stop closed them")
    end)

test("a discarded definition clears the store",
    { spec = "peinit *fdstore.a-discarded-definition-clears-the-store" },
    function(t)
        -- The definition has to go while nothing is running, or the
        -- discard waits on the instance's exit and the stop that
        -- produced the exit would be the thing that cleared the store.
        -- So the service crashes with RestartPolicy=Never first: it is
        -- gone, its store is not, and then the key is deleted.
        local path = marker("pt-fs-discard")
        define("pt-fs-discard", {
            "send-fd", path, "FDSTORE=1\\nFDNAME=alpha",
            "write", "/run/pt-fs-discard.stored", "ok",
            "exit", "4",
        })
        vm:run("svctl --json --no-wait start pt-fs-discard"):assert_ok()
        wait_until(function()
            local view = status("pt-fs-discard")
            return view and view.state == "failed" and view or nil
        end, { timeout = 90, interval = 0.3, desc = "pt-fs-discard to fail" })
        t:assert_eq(held(path), 1,
            "a crash is not an explicit stop, so the store outlived the process")

        vm:run([[reg del 'Machine\System\Services\pt-fs-discard' --recursive]])
            :assert_ok()
        wait_until(function() return status("pt-fs-discard") == nil or nil end,
            { timeout = 60, interval = 0.5,
              desc = "the definition to be discarded" })
        wait_until(function() return held(path) == 0 or nil end,
            { timeout = 30, interval = 0.3,
              desc = "the store to go with the definition" })
        t:assert_eq(held(path), 0,
            "the descriptors went with the definition")
    end)
