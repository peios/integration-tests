-- Area B: choosing and parsing the hook sequence.
--
-- Before prelude runs anything it has to decide *what* to run, and that
-- decision is made from file names alone: every `hooks.seq.<n>` in
-- /system/prelude is a candidate at version <n>, the unsuffixed
-- /hooks.seq is a candidate at version 0, and the highest version this
-- prelude can parse wins. Only then is the file opened, its marker
-- checked against the version its name claimed, and its body parsed.
--
-- Everything here is injection: the profile's initramfs carries one
-- resolved graph, and a test that wants a different sequence — a
-- version from the future, a marker that disagrees with the name, a
-- stanza prelude must refuse — writes its own over the baked one.
--
-- Two claims cannot be reached from a guest at all. mkirf writes BOTH
-- hooks.seq.1 and hooks.seq.2 into every image, and `files` injection
-- can only overwrite a path, never remove one, so "no sequence at all"
-- and "only a sequence newer than prelude supports" are unreachable —
-- and so, in turn, is any boot that selects version 0 or 1. Those three
-- are documented skips against prelude's own unit tests.

local prelude = require("helpers.prelude")

--- The hook the profile bakes that mounts the real root. A boot meant to
--- succeed must name it, or prelude refuses for want of a root instead
--- of for the reason under test.
local MOUNT_ROOT = prelude.HOOK_DIR .. "/pt-mount-root.sh"

--- The console line prelude prints when it has chosen a sequence.
local function chose(path)
    return "hook sequence: " .. path
end

-- --- choosing --------------------------------------------------------

test("the highest supported version wins, and prelude says which file it read",
    { spec = { "prelude seq.highest-supported-version-wins",
               "prelude seq.chosen-path-is-logged" } },
    function(t)
        -- Both numbered sequences are present: the profile's own
        -- hooks.seq.2, and a version-1 one written here naming a hook
        -- that appears nowhere else. Version 2 is the highest prelude
        -- can parse, so it is the one read and the other is not.
        local vm = provium:vm("highest", "prelude")
        vm:boot({ files = prelude.files({
            version = 1,
            hooks = { ["only-in-v1"] = {} },
        }) })

        local log = vm:console():read_log()
        t:assert(log:find(chose(prelude.SEQ_V2), 1, true),
            "prelude logged the chosen sequence as " .. prelude.SEQ_V2)
        t:assert(not log:find(chose(prelude.SEQ_V1), 1, true),
            "hooks.seq.1 was outranked, not read")
        t:assert(not log:find("pt|only-in-v1|", 1, true),
            "the hook only the version-1 sequence names never ran")
        t:assert(log:find("pt|mount-root|outcome=satisfied", 1, true),
            "the version-2 sequence's hooks are the ones that ran")
    end)

test("a sequence newer than prelude understands, beside a usable one, is a warning",
    { spec = { "prelude seq.newer-beside-usable-is-a-warning",
               "prelude seq.candidates-are-numbered-suffixes" } },
    function(t)
        -- hooks.seq.3 is a candidate — the suffix parses as a version —
        -- but 3 is above the maximum this prelude can parse. Something
        -- usable sits beside it, so the boot continues on that, saying
        -- so: the image considers a manifest authoritative that this
        -- prelude is not running.
        local vm = provium:vm("newer-beside", "prelude")
        vm:boot({ files = prelude.files({
            version = 3,
            seq = "hookseq 3\nhook /usr/libexec/prelude/hooks.d/from-the-future.sh\n",
        }) })

        local log = vm:console():read_log()
        t:assert(log:find("/system/prelude/hooks.seq.3 is version 3", 1, true),
            "the warning names the newer sequence and its version")
        t:assert(log:find("newer than this prelude supports (max 2)", 1, true),
            "and says it is newer than this prelude supports")
        t:assert(log:find("using " .. prelude.SEQ_V2, 1, true),
            "and names the one it fell back on")
        t:assert(log:find(chose(prelude.SEQ_V2), 1, true),
            "the boot continued on the highest supported sequence")
        t:assert(log:find("root mounted at /mnt/rootfs", 1, true),
            "a newer sequence beside a usable one is survivable, not fatal")
    end)

test("a hooks.seq suffix that is not a number is not a candidate at all",
    { spec = "prelude seq.non-numeric-suffix-ignored" },
    function(t)
        -- Neither of these parses as an unsigned integer, so neither is
        -- a version of anything. They are ignored rather than guessed
        -- at — and ignored silently, not reported: if either were read
        -- as a candidate the marker check would end the boot.
        local vm = provium:vm("nonnumeric", "prelude")
        vm:boot({ files = prelude.files({
            extra = {
                { path = prelude.SEQ_DIR .. "/hooks.seq.next",
                  content = "hookseq 9\nhook /nowhere.sh\n" },
                { path = prelude.SEQ_DIR .. "/hooks.seq.3beta",
                  content = "not a sequence at all\n" },
            },
            seq = "hookseq 2\nhook " .. MOUNT_ROOT .. "\n",
        }) })

        local log = vm:console():read_log()
        t:assert(log:find(chose(prelude.SEQ_V2), 1, true),
            "prelude chose the numbered sequence")
        t:assert(not log:find("hooks.seq.next", 1, true),
            "a non-numeric suffix is ignored, not reported")
        t:assert(not log:find("hooks.seq.3beta", 1, true),
            "a suffix that merely starts with a digit is still not a version")
        t:assert(log:find("root mounted at /mnt/rootfs", 1, true),
            "and the boot was unaffected by either")
    end)

test("the legacy unsuffixed /hooks.seq is outranked by every numbered one",
    { spec = "prelude seq.legacy-unsuffixed-is-version-zero" },
    function(t)
        -- /hooks.seq is where mkirf used to write the sequence. prelude
        -- still reads it, as version 0 — below every numbered one, so
        -- it is a last resort and never a competitor.
        local vm = provium:vm("legacy", "prelude")
        vm:boot({ files = prelude.files({
            version = "legacy",
            hooks = { ["only-in-legacy"] = {} },
        }) })

        local log = vm:console():read_log()
        t:assert(log:find(chose(prelude.SEQ_V2), 1, true),
            "a numbered sequence outranks the legacy /hooks.seq")
        t:assert(not log:find(chose(prelude.SEQ_LEGACY), 1, true),
            "the legacy path was not the one read")
        t:assert(not log:find("pt|only-in-legacy|", 1, true),
            "the hook only /hooks.seq names never ran")
    end)

test("a sequence newer than prelude supports, as the only candidate, ends the boot",
    { spec = "prelude seq.only-newer-is-a-failure",
      covered_by = "cargo:prelude::tests::only_newer_sequences_is_an_error_naming_the_version",
      skip = "needs an image whose ONLY hooks.seq.<n> is above version 2. " ..
             "mkirf writes hooks.seq.1 and hooks.seq.2 into every image and " ..
             "`files` injection can only overwrite a path, never remove one, " ..
             "so a supported candidate is always present in this guest; " ..
             "runs under prelude's only_newer_sequences_is_an_error_naming_the_version" },
    function(t) t:fail("unreachable") end)

test("no hook sequence at all ends the boot, rather than running no hooks",
    { spec = "prelude seq.absent-is-a-failure",
      covered_by = "cargo:prelude::tests::no_sequence_at_all_is_an_error_not_an_empty_boot",
      skip = "needs an image with no hooks.seq.<n> and no /hooks.seq. The " ..
             "profile's initramfs carries both numbered files and injection " ..
             "cannot delete them, so `found` is never empty in this guest; " ..
             "runs under prelude's no_sequence_at_all_is_an_error_not_an_empty_boot" },
    function(t) t:fail("unreachable") end)

-- --- the marker ------------------------------------------------------

test("the version marker must agree with the name the file was chosen by",
    { spec = "prelude seq.marker-must-match-the-name" },
    function(t)
        -- The name selects the file and the marker confirms it. A
        -- version-1 marker inside hooks.seq.2 is a hard error naming
        -- both what was expected and what was found, rather than a body
        -- parsed by the wrong reader.
        local vm = provium:vm("marker", "prelude")
        local err = prelude.boot_halts(t, vm, { files = prelude.files({
            seq = "hookseq 1\nhook " .. MOUNT_ROOT .. "\n",
        }) })

        t:assert(err:find(prelude.SEQ_V2 .. ": expected version marker", 1, true),
            "the failure names the file whose marker disagreed: " .. err:sub(-400))
        t:assert(err:find('expected version marker "hookseq 2"', 1, true),
            "and what the marker should have said")
        t:assert(err:find('found Some("hookseq 1")', 1, true),
            "and what it said instead")
        t:assert(err:find("halting system", 1, true),
            "a sequence prelude cannot trust halts the machine")
    end)

-- --- version 1 -------------------------------------------------------

test("a version-1 body is one hook path per line, run as listed",
    { spec = "prelude seq.v1-is-a-flat-list",
      covered_by = "cargo:prelude::tests::a_sequence_with_no_declarations_runs_in_order",
      skip = "the version-1 reader runs only when a version-0 or -1 sequence " ..
             "is SELECTED, and the profile's baked hooks.seq.2 outranks every " ..
             "such file an injection could write, so no guest boot reaches it. " ..
             "The consequence it produces — hooks with no declarations, all " ..
             "immediately ready, run in file order — is asserted by prelude's " ..
             "a_sequence_with_no_declarations_runs_in_order" },
    function(t) t:fail("unreachable") end)

-- --- version 2 -------------------------------------------------------

test("a `hook` line with no path is refused, naming the line",
    { spec = "prelude seq.v2-hook-line-needs-a-path" },
    function(t)
        local vm = provium:vm("v2-nopath", "prelude")
        local err = prelude.boot_halts(t, vm, { files = prelude.files({
            seq = "hookseq 2\nhook\nhook " .. MOUNT_ROOT .. "\n",
        }) })

        t:assert(err:find(prelude.SEQ_V2 .. ": line 2: `hook` with no path", 1, true),
            "a bare `hook` line is an error naming its line number: " .. err:sub(-400))
        t:assert(err:find("halting system", 1, true), "and the machine halted")
    end)

test("a declaration before any `hook` line is refused",
    { spec = "prelude seq.v2-declaration-before-any-hook" },
    function(t)
        -- A declaration belongs to the stanza above it. One with no
        -- stanza to belong to has nothing to attach to and is an error,
        -- not a line quietly dropped.
        local vm = provium:vm("v2-orphan", "prelude")
        local err = prelude.boot_halts(t, vm, { files = prelude.files({
            seq = "hookseq 2\nprovides rootfs-ready\nhook " .. MOUNT_ROOT .. "\n",
        }) })

        t:assert(err:find(prelude.SEQ_V2 .. ": line 2: `provides` before any `hook` line",
                1, true),
            "a declaration with no open stanza is an error: " .. err:sub(-400))
        t:assert(err:find("halting system", 1, true), "and the machine halted")
    end)

test("an unknown key inside a stanza is refused",
    { spec = "prelude seq.v2-unknown-key" },
    function(t)
        -- Four keys are the whole vocabulary. Anything else means the
        -- image carries a manifest this prelude would misread, which is
        -- exactly what parsing strictly now is for.
        local vm = provium:vm("v2-unknown", "prelude")
        local err = prelude.boot_halts(t, vm, { files = prelude.files({
            seq = "hookseq 2\nhook " .. MOUNT_ROOT .. "\nprovydes rootfs-ready\n",
        }) })

        t:assert(err:find(prelude.SEQ_V2 .. ": line 3: unknown key `provydes`", 1, true),
            "an unknown key is an error naming the key and its line: " .. err:sub(-400))
        t:assert(err:find("halting system", 1, true), "and the machine halted")
    end)

test("reported line numbers count the marker as line 1",
    { spec = "prelude seq.v2-line-numbers-count-the-marker" },
    function(t)
        -- The marker is consumed before the body is parsed, so a
        -- reported line number is the physical line in the file only if
        -- the offset is right. Empty lines are skipped as content but
        -- still counted, so the bad key here is physical line 4.
        local vm = provium:vm("v2-lineno", "prelude")
        local err = prelude.boot_halts(t, vm, { files = prelude.files({
            seq = "hookseq 2\nhook " .. MOUNT_ROOT .. "\n\nprovydes rootfs-ready\n",
        }) })

        t:assert(err:find(prelude.SEQ_V2 .. ": line 4: unknown key `provydes`", 1, true),
            "the error names the physical line, counting the marker as line 1 " ..
            "and the blank line as line 3: " .. err:sub(-400))
    end)

test("a stanza key may repeat, and its names accumulate",
    { spec = "prelude seq.v2-repeated-key-accumulates" },
    function(t)
        -- Two `requires` lines on one stanza are one requirement set,
        -- not the first or the last of two. The sequence below is
        -- ordered so that dropping either line would be visible:
        -- x1 and x2 sit between their two providers, so a hook holding
        -- only its first name would run before pb and one holding only
        -- its last would run before pa's pass ended.
        --
        -- `provides cap-b cap-b2` is also the whitespace-separated case:
        -- taken as a single name, nothing would supply `cap-b` and both
        -- consumers would be vacuously ready in the first pass.
        local H = prelude.HOOK_DIR
        local seq = table.concat({
            "hookseq 2",
            "hook " .. H .. "/pa.sh",
            "provides cap-a",
            "hook " .. H .. "/x1.sh",
            "requires cap-a",
            "requires cap-b",
            "hook " .. H .. "/x2.sh",
            "requires cap-b",
            "requires cap-a",
            "hook " .. H .. "/pb.sh",
            "provides cap-b cap-b2",
            "hook " .. MOUNT_ROOT,
            "",
        }, "\n")

        local vm = provium:vm("v2-repeat", "prelude")
        vm:boot({ files = prelude.files({
            hooks = { pa = {}, pb = {}, x1 = {}, x2 = {} },
            seq = seq,
        }) })

        local log = vm:console():read_log()
        -- The console carries CRLF, so `ran` hands back names with the
        -- carriage return still attached; trim before comparing.
        local order = {}
        for i, name in ipairs(prelude.ran(log)) do
            order[i] = name:gsub("%s+$", "")
        end
        t:assert_eq(table.concat(order, ","),
            "pa.sh,pb.sh,pt-mount-root.sh,x1.sh,x2.sh",
            "both consumers waited for both of their required capabilities, " ..
            "so each ran a pass after the two providers")
    end)

test("a sequence with only a marker runs no hooks and goes on to the root check",
    { spec = "prelude seq.empty-runs-no-hooks" },
    function(t)
        -- An image can legitimately carry no hooks, and prelude says so
        -- and carries on — the boot then fails at the root check, which
        -- is a different failure from a sequence it could not read, and
        -- is the proof that it got past the sequence at all.
        local vm = provium:vm("empty-seq", "prelude")
        local err = prelude.boot_halts(t, vm, { files = prelude.files({
            seq = "hookseq 2\n",
        }) })

        t:assert(err:find("no hooks to run", 1, true),
            "an empty sequence is reported as having nothing to run: " .. err:sub(-400))
        t:assert(not err:find("ran 0 hook invocation", 1, true),
            "and the scheduler was not entered at all")
        t:assert(err:find("no hook mounted a root filesystem at /mnt/rootfs", 1, true),
            "the boot proceeded to the root check and failed there")
    end)
