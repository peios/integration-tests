-- prelude, area A continued: the knobs prelude takes off the kernel
-- command line once /proc is mounted, and the banner that is the first
-- thing to obey them.
--
-- Everything here is asserted on the console, because the console is
-- what these knobs are about: peios.quiet=2 decides which lines exist,
-- TERM decides which bytes they are made of, and the banner is the one
-- piece of output that is neither a log line nor a hook's.
--
-- The profile's own command line already carries `TERM=dumb` (so a test
-- matching prelude's text is not matching escape sequences too), which
-- makes it the fixture for colour-off; a test that wants colour ON
-- appends `TERM=linux`, and the last occurrence is the one prelude
-- honours.
--
-- The mounts, the /dev seed and the read itself are in startup.test.lua.

local prelude = require("helpers.prelude")

--- Codepoints, not bytes: the banner's rule and its separator are both
--- multi-byte, and its width is a column count.
local function cols(s)
    local _, n = s:gsub("[^\128-\191]", "")
    return n
end

--- The console log as lines, with the CR of the guest's CRLF removed.
local function lines(log)
    local out, from = {}, 1
    while true do
        local nl = log:find("\n", from, true)
        if not nl then
            out[#out + 1] = (log:sub(from):gsub("\r", ""))
            return out
        end
        out[#out + 1] = (log:sub(from, nl - 1):gsub("\r", ""))
        from = nl + 1
    end
end

test("peios.quiet=2 blacks out progress and success but never a failure",
    { spec = "prelude cmdline.quiet-suppresses-progress-not-failure" },
    function(t)
        -- A boot that has to refuse, so both halves are on one console:
        -- the lines a blackout removes, and the diagnosis it must not.
        local vm = provium:vm("quiet", "prelude")
        local out = prelude.boot_halts(t, vm, {
            kernel_cmdline_append = "peios.quiet=2 pt.mount-root=decline",
        })

        t:assert(out:find(
            "[FAILED] prelude: boot failed: no hook mounted a root " ..
            "filesystem at /mnt/rootfs", 1, true),
            "a failure is never silenced: a blackout is a preference about " ..
            "noise, not an instruction to hide a failure: " .. out:sub(-400))

        t:assert(not out:find("prelude · initramfs · PID 1", 1, true),
            "the banner is gone — status, not news")
        t:assert(not out:find("prelude: hook sequence:", 1, true),
            "and so is every `log` line")
        t:assert(not out:find("prelude: root mounted", 1, true),
            "and every `log_ok` line: a success is progress, and the tag is " ..
            "presentation rather than news")
        t:assert(not out:find("prelude: halting system", 1, true),
            "including the last line before the halt")
    end)

test("the last peios.quiet wins, and only the literal 2 blacks the console out",
    { spec = "prelude cmdline.quiet-suppresses-progress-not-failure" },
    function(t)
        -- `peios.quiet=2 peios.quiet=1`: last wins, as the kernel resolves
        -- a repeated parameter, and 1 is not 2 — the other levels are
        -- about a terminal a service owns, which has no meaning in an
        -- initramfs that exits before the first service exists.
        local vm = provium:vm("quietlast", "prelude")
        vm:boot({ kernel_cmdline_append = "peios.quiet=2 peios.quiet=1" })
        local log = vm:console():read_log()

        t:assert(log:find("prelude · initramfs · PID 1", 1, true),
            "the banner is back: the last peios.quiet is 1, and only 2 " ..
            "reaches prelude")
        t:assert(log:find("[  OK  ] prelude: root mounted at /mnt/rootfs", 1, true),
            "and so are the success lines")
    end)

test("TERM=dumb on the command line turns the SGR colour off",
    { spec = "prelude cmdline.term-dumb-turns-colour-off" }, function(t)
        -- The profile's own command line carries TERM=dumb, so an
        -- ordinary boot is the colour-off case.
        local vm = provium:vm("dumb", "prelude"):boot()
        local log = vm:console():read_log()

        t:assert(log:find("[  OK  ] prelude: root mounted at /mnt/rootfs", 1, true),
            "the OK tag is the bare word, with no escape around it")

        -- From the read onward. The one line before it — `seeded /dev` —
        -- is emitted while COLOUR is still at its default, and that
        -- ordering is startup.test.lua's subject, not this one's.
        local at = log:find("prelude: seeded /dev", 1, true)
        local after = log:sub(at)
        t:assert(not after:find("\27[1;32mOK", 1, true),
            "and the green SGR bytes appear on no line prelude wrote after " ..
            "reading the command line")
        t:assert(not after:find("\27[1mprelude · initramfs", 1, true),
            "the banner is uncoloured too")
    end)

test("the last TERM wins, so appending TERM=linux puts the colour back",
    { spec = "prelude cmdline.term-dumb-turns-colour-off" }, function(t)
        local vm = provium:vm("colour", "prelude")
        vm:boot({ kernel_cmdline_append = "TERM=linux" })
        local log = vm:console():read_log()

        t:assert(log:find("[  \27[1;32mOK\27[0m  ] prelude: root mounted at " ..
            "/mnt/rootfs", 1, true),
            "the OK tag is wrapped in SGR 1;32, and the brackets have not " ..
            "moved: colour changes the bytes and never the layout")
        t:assert(log:find("\27[1mprelude · initramfs · PID 1\27[0m", 1, true),
            "the banner's stage is bold")
    end)

test("the banner is 64 columns wide and stands between the seed line and the first log line",
    { spec = "prelude console.banner-on-stdout-logs-on-stderr" }, function(t)
        local vm = provium:vm("banner", "prelude"):boot()
        local log = vm:console():read_log()
        local ls = lines(log)

        local i
        for n, line in ipairs(ls) do
            if line:find("prelude · initramfs · PID 1", 1, true) then i = n end
        end
        t:assert(i, "the banner is on the console")

        for _, n in ipairs({ i - 1, i, i + 1 }) do
            t:assert_eq(cols(ls[n]), 64,
                "banner line " .. (n - i + 2) .. " is 64 columns: " .. ls[n])
        end
        t:assert(ls[i - 1] == ls[i + 1] and ls[i - 1]:find("  ═", 1, true) == 1,
            "the stage line sits between two identical rules")
        t:assert_eq(ls[i - 2], "", "with a blank line above")
        t:assert_eq(ls[i + 2], "", "and below")

        -- Where it sits: after the /dev seed, which precedes the
        -- command-line read, and before the first line prelude logs
        -- under whatever that read said.
        local seed = log:find("prelude: seeded /dev", 1, true)
        local banner = log:find("prelude · initramfs · PID 1", 1, true)
        local first_log = log:find("] prelude: no init=", 1, true)
        t:assert(seed and banner and first_log, "all three lines are present")
        t:assert(seed < banner and banner < first_log,
            "the banner is punctuation between the mounts and the boot proper")
    end)

test("the banner goes to stdout while every log line goes to stderr",
    { spec = "prelude console.banner-on-stdout-logs-on-stderr",
      covered_by = "unreachable",
      skip = "prelude is PID 1: the kernel hands it one console and both of " ..
             "its descriptors are that console, so a guest sees one " ..
             "interleaved stream and no test on this side of the handoff " ..
             "can say which descriptor a byte arrived on. The split is a " ..
             "property of the source — banner() writes through " ..
             "std::io::stdout().lock() and log_tagged() through eprint! — " ..
             "and prelude has no unit test that separates them either; the " ..
             "64-column geometry the same claim covers is asserted live in " ..
             "the test above" },
    function(t) end)

test("an init= with an empty value is ignored, so the fallback chain runs",
    { spec = "prelude cmdline.empty-init-is-ignored" }, function(t)
        local vm = provium:vm("emptyinit", "prelude")
        vm:boot({ kernel_cmdline_append = "init=" })
        local log = vm:console():read_log()

        t:assert(log:find(
            "prelude: no init= on cmdline; will try fallback chain on the " ..
            "new root", 1, true),
            "an empty value is no value at all: " .. log:sub(-600))
        t:assert(not log:find("prelude: target init from cmdline", 1, true),
            "prelude did not take the empty string as its target")
        t:assert(log:find("prelude: exec /bin/peinit2", 1, true),
            "and the fallback chain found the init")
    end)

test("init= takes the FIRST occurrence on the command line",
    { spec = "prelude cmdline.init-takes-the-first-occurrence" }, function(t)
        -- TENSION. Every other knob prelude reads takes the LAST
        -- occurrence — peios.quiet and TERM both use `next_back()`, and
        -- the kernel's own convention for a repeated parameter is the
        -- same — but `cmdline_init` returns on the first match. This test
        -- pins what the code does, not what it should do.
        --
        -- Neither candidate exists, so the boot goes on down the fallback
        -- chain and the console says which one prelude picked.
        local vm = provium:vm("firstinit", "prelude")
        vm:boot({ kernel_cmdline_append = "init=/bin/pt-first init=/bin/pt-second" })
        local log = vm:console():read_log()

        t:assert(log:find("prelude: target init from cmdline: /bin/pt-first", 1, true),
            "prelude took the first init=, not the last: " .. log:sub(-800))
        t:assert(log:find("prelude: skip /bin/pt-first: not present", 1, true),
            "and tried it before the chain")
        t:assert(not log:find("pt-second", 1, true),
            "the second init= was never looked at")
    end)
