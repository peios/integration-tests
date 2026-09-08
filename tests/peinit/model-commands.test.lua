-- peinit TRM §3.6 — command strings, read off the argv that actually
-- reached the process.
--
-- `model-decode` owns which command strings are refused. This file owns
-- what an accepted one turns into, which needs the split to be visible:
-- every subject here is a pre-exec hook that runs `/pt/argv.sh`, and
-- that script writes one `[entry]` line per positional parameter it was
-- given. The file it leaves behind is peinit's argv, one element per
-- line, with the brackets marking where each element began and ended so
-- that an empty one and a missing one are different things on the page.
--
-- The hooks all belong to Oneshots that do nothing else, so a service
-- reaching Completed means its hooks ran and exited zero, and the
-- recorded argv is the whole of what happened.
--
-- Two of the claims cannot be seeded. The five non-space whitespace
-- characters are control bytes, which a JSON seed file cannot carry, so
-- `pt-ws` is written into the registry at runtime with the guest's own
-- `printf` and started by hand. The SIGHUP default needs a process that
-- can catch a signal and say so, which is a shell rather than
-- `/bin/sleep`.

local peinit = require("helpers.peinit")
peinit.claim(1)

local FILES = {
    -- Records the argv it was handed, one bracketed element per line,
    -- into a file named by its first argument.
    ["pt/argv.sh"] = [[
f="/run/pt-argv-$1"
shift
for a in "$@"; do printf '[%s]\n' "$a" >> "$f"; done
exit 0
]],
    -- A main process that catches SIGHUP and records it. `sleep` in a
    -- loop rather than a single long sleep, because a shell runs a trap
    -- between commands and never during one.
    ["pt/hup.sh"] = [[
trap 'echo hup >> /run/pt-hup' HUP
while true; do /bin/sleep 1; done
]],
}

local SERVICES = {
    { path = [[Machine\System]] },
    { path = [[Machine\System\Services]] },
}

local function service(name, values)
    SERVICES[#SERVICES + 1] =
        { path = [[Machine\System\Services\]] .. name, values = values }
end

--- A boot-triggered Oneshot whose only work is one pre-exec hook.
local function hook_service(name, command)
    service(name, {
        { name = "ImagePath", type = "sz", data = "/bin/true" },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Type", type = "dword", data = 1 },
        { name = "RemainAfterExit", type = "dword", data = 1 },
        { name = "Triggers", type = "multi", data = { "boot" } },
        { name = "ExecStartPre", type = "multi", data = { command } },
    })
end

-- Shell metacharacters, none of which peinit expands, substitutes or
-- globs. `$(echo hi)` is two argv elements rather than one word, which
-- is both halves of the claim at once: no substitution, and the split
-- is on whitespace.
hook_service("pt-noshell",
    [[/bin/sh /pt/argv.sh noshell $HOME * $(echo hi) ~ `date` a&&b]])

-- Quotes group, are not retained, and may group inside an argument.
hook_service("pt-quotes",
    [[/bin/sh /pt/argv.sh quotes --name="hello world" a"b"c "x  y"]])

-- An empty quoted string is an argv element, not nothing.
hook_service("pt-empty", [[/bin/sh /pt/argv.sh empty "" tail]])

-- A backslash is a character, not an escape, and a single quote is an
-- ordinary character.
hook_service("pt-escapes", [[/bin/sh /pt/argv.sh escapes a\b it's "c\d"]])

-- The service the whitespace probe is installed on: no hook yet, and no
-- trigger, so it sits Inactive until the test writes one and starts it.
service("pt-ws", {
    { name = "ImagePath", type = "sz", data = "/bin/true" },
    { name = "Identity", type = "sz", data = "SYSTEM" },
    { name = "Type", type = "dword", data = 1 },
    { name = "RemainAfterExit", type = "dword", data = 1 },
})

-- A service that catches SIGHUP, with no ExecReload at all.
service("pt-hup", {
    { name = "ImagePath", type = "sz", data = "/bin/sh" },
    { name = "Arguments", type = "multi", data = { "/pt/hup.sh" } },
    { name = "Identity", type = "sz", data = "SYSTEM" },
    { name = "Readiness", type = "dword", data = 1 },
    { name = "Triggers", type = "multi", data = { "boot" } },
    { name = "RestartPolicy", type = "dword", data = 0 },
})

local vm = peinit.boot({
    name = "commands",
    files = peinit.merge(FILES, peinit.seed("pt-commands", SERVICES)),
})

local function status(service_name)
    local r = vm:run("svctl --json status " .. service_name)
    if r.stdout:find("UNKNOWN_SERVICE", 1, true) then return nil end
    local ok, decoded = pcall(json.decode, r.stdout)
    return ok and decoded or nil
end

--- The argv `label`'s hook recorded, as a list of strings, once the
--- service that runs it has finished.
local function argv_of(t, label, service_name)
    wait_until(function()
        local st = status(service_name)
        return st and (st.state == "completed" or st.state == "failed") and st or nil
    end, { timeout = 90, interval = 0.4, desc = service_name .. " to run its hook" })
    t:assert_eq(status(service_name).state, "completed",
        service_name .. "'s hook ran and exited zero")

    local text = vm:read_file("/run/pt-argv-" .. label)
    local out = {}
    for _, line in ipairs(peinit.lines(text)) do
        out[#out + 1] = line:match("^%[(.*)%]$")
    end
    return out
end

local function joined(list)
    local parts = {}
    for i, entry in ipairs(list) do parts[i] = "<" .. tostring(entry) .. ">" end
    return table.concat(parts, " ")
end

local function assert_argv(t, got, want, why)
    t:assert_eq(#got, #want, why .. ": " .. #want .. " argv elements, got " ..
        #got .. ": " .. joined(got))
    for i = 1, #want do
        t:assert_eq(got[i], want[i],
            why .. ": element " .. i .. " is `" .. want[i] .. "`, got `" ..
            tostring(got[i]) .. "` (whole argv: " .. joined(got) .. ")")
    end
end

test("there is no shell: nothing is expanded, substituted or globbed",
    { spec = "peinit *cmdstr.there-is-no-shell" },
    function(t)
        -- Every one of these means something to a shell and nothing to
        -- peinit. `$(echo hi)` arriving as two elements is the sharpest
        -- of them: a shell would have run it and produced one word, and
        -- an implementation that stripped the syntax without running it
        -- would have produced something other than the literal text.
        local argv = argv_of(t, "noshell", "pt-noshell")
        assert_argv(t, argv, {
            "$HOME",     -- no variable expansion
            "*",         -- no globbing: the working directory is not consulted
            "$(echo",    -- no command substitution, and the split is on space
            "hi)",
            "~",         -- no tilde expansion
            "`date`",    -- nor the older substitution syntax
            "a&&b",      -- and no operators: this is one argument
        }, "shell syntax is ordinary argument text")
    end)

test("double quotes group into one element, are not retained, and may group inside an argument",
    { spec = "peinit *cmdstr.quotes-group-and-are-not-retained" },
    function(t)
        local argv = argv_of(t, "quotes", "pt-quotes")
        assert_argv(t, argv, {
            -- Grouping inside an argument: the quotes are removed and
            -- what they held joins what was written outside them.
            "--name=hello world",
            -- The same, twice over, in the middle of a word.
            "abc",
            -- And the whitespace inside a group is kept exactly.
            "x  y",
        }, "quotes group and vanish")
    end)

test("an empty quoted string is preserved as an empty argv element",
    { spec = "peinit *cmdstr.an-empty-quoted-string-is-an-empty-argv-entry" },
    function(t)
        -- The distinction the brackets in the recording exist for: an
        -- empty element and no element at all look the same in a bare
        -- listing and are different things.
        local argv = argv_of(t, "empty", "pt-empty")
        assert_argv(t, argv, { "", "tail" },
            "an empty quoted string is an element")
    end)

test("a backslash and a single quote are ordinary characters",
    { spec = "peinit *cmdstr.a-backslash-and-a-single-quote-are-ordinary-characters" },
    function(t)
        -- A backslash has no escape semantics, so it is copied through
        -- and does not protect the character after it; a single quote
        -- groups nothing.
        local argv = argv_of(t, "escapes", "pt-escapes")
        assert_argv(t, argv, {
            [[a\b]],
            [[it's]],
            -- Inside double quotes the backslash is still just a
            -- backslash, so the quotes are removed and it is not.
            [[c\d]],
        }, "backslash and single quote are literal")
    end)

test("whitespace is exactly six ASCII characters, and every other Unicode space is argument text",
    { spec = "peinit *cmdstr.whitespace-is-exactly-six-ascii-characters" },
    function(t)
        -- The five non-space members are control bytes and cannot go
        -- through a JSON seed, so the command is written from the guest,
        -- where `printf` can produce them. One command carries all five
        -- as separators; the other carries U+00A0, which is whitespace
        -- to Unicode and an ordinary character here.
        --
        -- Keeping the split to a fixed six characters is what makes it
        -- independent of the Unicode version peinit was built against,
        -- so the NBSP case is the load-bearing half.
        -- One substitution for the whole run of separators, not one per
        -- character: a command substitution strips *trailing* newlines,
        -- so `$(printf '\n')` on its own produces nothing at all and the
        -- line feed silently vanishes from the command.
        local written = vm:run(
            [[reg set 'Machine\System\Services\pt-ws' ExecStartPre ]] ..
            [["multi:/bin/sh /pt/argv.sh ws A$(printf '\tB\nC\rD\vE\fF'),]] ..
            [[/bin/sh /pt/argv.sh nbsp X$(printf '\302\240')Y Z"]])
        written:assert_ok()

        local started = vm:run("svctl --json start pt-ws")
        started:assert_ok()

        local ws = argv_of(t, "ws", "pt-ws")
        assert_argv(t, ws, { "A", "B", "C", "D", "E", "F" },
            "tab, line feed, carriage return, vertical tab and form feed all split")

        -- And U+00A0 does not: `X\194\160Y` is one element, and the
        -- ordinary space after it is what separates it from `Z`.
        local nbsp = argv_of(t, "nbsp", "pt-ws")
        assert_argv(t, nbsp, { "X\194\160Y", "Z" },
            "a non-breaking space is an ordinary argument character")
    end)

test("an absent ExecReload means SIGHUP",
    { spec = "peinit *cmdstr.an-absent-execreload-means-sighup" },
    function(t)
        -- pt-hup names no ExecReload at all, so a reload has to be
        -- decided by the default. Its main process traps SIGHUP and
        -- records it, and records nothing otherwise -- so the file
        -- appearing is the signal arriving.
        wait_until(function()
            local st = status("pt-hup")
            return st and st.state == "active" and st or nil
        end, { timeout = 90, interval = 0.4, desc = "pt-hup to reach Active" })
        t:assert(vm:run("test -e /run/pt-hup").exit_code ~= 0,
            "nothing has signalled it yet")

        -- `--no-wait`: a signal reload is advisory, so peinit holds the
        -- operation open for its detection window rather than answering
        -- at once, and what this test is about has already happened by
        -- then.
        vm:run("svctl --json reload pt-hup --no-wait"):assert_ok()

        wait_until(function()
            return vm:run("test -e /run/pt-hup").exit_code == 0
        end, { timeout = 60, interval = 0.5, desc = "pt-hup to catch a SIGHUP" })
        t:assert_eq(vm:run("test -e /run/pt-hup").exit_code, 0,
            "a reload with no ExecReload delivered SIGHUP")
    end)
