-- mkirf, part one: how hooks are found and how their metadata block is
-- read. Claims G1-G7 (discovery) and H1-H10 (the block).
--
-- mkirf is a host tool, not a guest one: it reads an initramfs source
-- tree and writes the cpio a kernel later unpacks. So these cases build a
-- fixture tree in a temporary directory, run the real binary over it, and
-- read back what came out — the two generated sequence files and the
-- archive listing. Nothing boots, which is both faster than a VM and the
-- right seam: mkirf ships in peiosutils and prelude in its own package,
-- and `/system/prelude/hooks.seq.<n>` is the contract between them. This
-- file asserts the writer's half of that contract; the rest of the
-- chapter asserts the reader's.
--
-- Every case asserts the exit status as well as the message: 0 built,
-- 1 an operational failure (an invalid layout, an unresolvable hook set),
-- 2 a usage error. A test that only checked "the build failed" would pass
-- for the wrong reason.

local prelude = require("helpers.prelude")

local USR = prelude.SRC_HOOKS_USR
local LCL = prelude.SRC_HOOKS_LCL
local LEGACY = prelude.SRC_HOOKS_LEGACY

-- G. Discovery ---------------------------------------------------------------

test("all three hook directories are scanned, and a hook's recorded path names the one it came from",
    { spec = "prelude mkirf.hook-directory-precedence" }, function(t)
        local r = prelude.mkirf({ hooks = {
            [LCL .. "/local.sh"] = { provides = { "local-cap" } },
            [USR .. "/packaged.sh"] = { provides = { "packaged-cap" } },
            [LEGACY .. "/old.sh"] = { provides = { "old-cap" } },
        } })
        t:assert_eq(r.status, 0, "the image built: " .. r.output)
        -- The three are listed in file-name order (local, old, packaged),
        -- each under the directory it was discovered in — which is what
        -- says all three of HOOK_DIRS were scanned.
        t:assert_eq(r.seq1, table.concat({
            "hookseq 1",
            "/lcl/libexec/prelude/hooks.d/local.sh",
            "/hooks/old.sh",
            "/usr/libexec/prelude/hooks.d/packaged.sh",
            "",
        }, "\n"), "every hook is in the sequence under its own directory")
        r:cleanup()
    end)

test("the same file name in two directories is one hook: the local copy wins and the packaged one is reported shadowed",
    { spec = "prelude mkirf.same-name-is-one-hook-shadowed" }, function(t)
        local r = prelude.mkirf({ hooks = {
            [LCL .. "/dup.sh"] = { provides = { "operator-version" } },
            [USR .. "/dup.sh"] = { provides = { "packaged-version" } },
        } })
        t:assert_eq(r.status, 0, "a shadowed hook is a warning, not an error: " .. r.output)
        t:assert_contains(r.output,
            "hook `dup.sh` at /usr/libexec/prelude/hooks.d/dup.sh is shadowed by "
            .. "/lcl/libexec/prelude/hooks.d/dup.sh",
            "the build named the file that lost and the one that won")
        -- One hook, not two, and it is the operator's: the packaged
        -- body's declaration is nowhere in the sequence.
        t:assert_eq(r.seq1,
            "hookseq 1\n/lcl/libexec/prelude/hooks.d/dup.sh\n",
            "only the winning copy is scheduled")
        t:assert(not r.seq2:find("packaged-version", 1, true),
            "and the shadowed body's metadata was not read: " .. r.seq2)
        r:cleanup()
    end)

test("a hook in the legacy hooks/ directory is a warning naming where to move it, not an error",
    { spec = "prelude mkirf.legacy-directory-warns" }, function(t)
        local r = prelude.mkirf({ hooks = {
            [LEGACY .. "/legacy.sh"] = { provides = { "something" } },
        } })
        t:assert_eq(r.status, 0, "the legacy directory is read, not refused: " .. r.output)
        t:assert_contains(r.output, "is in the legacy",
            "the build warned about the legacy directory")
        t:assert_contains(r.output,
            "move it to /usr/libexec/prelude/hooks.d (packaged) or "
            .. "/lcl/libexec/prelude/hooks.d (local)",
            "and named both directories it could move to")
        t:assert_eq(r.seq1, "hookseq 1\n/hooks/legacy.sh\n",
            "the hook is still scheduled, from the legacy path")
        r:cleanup()
    end)

test("only regular files directly in a hook directory are hooks; a subdirectory is not searched",
    { spec = "prelude mkirf.only-regular-files-directly-in-the-directory" }, function(t)
        local r = prelude.mkirf({ hooks = {
            [USR .. "/top.sh"] = { provides = { "top" } },
            [USR .. "/sub/nested.sh"] = { provides = { "nested" } },
        } })
        t:assert_eq(r.status, 0, "the image built: " .. r.output)
        t:assert_eq(r.seq1, "hookseq 1\n/usr/libexec/prelude/hooks.d/top.sh\n",
            "the file one level down is not a hook")
        -- It is still packed — it is an ordinary file in the tree, just
        -- not a hook. So the sequence's silence is discovery's decision,
        -- not the walker dropping it.
        t:assert(prelude.archive_entry(r.listing, "usr/libexec/prelude/hooks.d/sub/nested.sh"),
            "the nested file is in the image all the same: " .. r.listing)
        r:cleanup()
    end)

test("a symlinked hook is judged by its target, so it is discovered and its target's block is read",
    { spec = "prelude mkirf.symlinked-hook-follows-its-target" }, function(t)
        local r = prelude.mkirf({
            files = { { path = "opt/real.sh",
                        content = prelude.hook_script({ provides = { "linked-cap" } }),
                        mode = "0755" } },
            links = { { path = USR .. "/link.sh", target = "../../../../opt/real.sh" } },
        })
        t:assert_eq(r.status, 0, "the image built: " .. r.output)
        t:assert_eq(r.seq1, "hookseq 1\n/usr/libexec/prelude/hooks.d/link.sh\n",
            "the symlink is a hook, at the path it occupies in the directory")
        t:assert_contains(r.seq2, "provides linked-cap",
            "and the metadata came from the file the link resolves to: " .. r.seq2)
        -- The link is stored as a link; only the hook scan followed it.
        local entry = prelude.archive_entry(r.listing, "usr/libexec/prelude/hooks.d/link.sh")
        t:assert_eq(entry and entry.target, "../../../../opt/real.sh",
            "the archive still holds a symlink, target verbatim")
        r:cleanup()
    end)

test("hooks are ordered by file name in byte order, not by locale collation",
    { spec = "prelude mkirf.name-order-is-the-tie-break" }, function(t)
        -- `B` (0x42), `_` (0x5f), `a` (0x61). A locale-aware sort would
        -- fold case and ignore the punctuation and put `a.sh` before
        -- `B.sh`; byte order does not.
        local r = prelude.mkirf({ hooks = {
            [USR .. "/a.sh"] = { no_metadata = true },
            [USR .. "/B.sh"] = { no_metadata = true },
            [USR .. "/_x.sh"] = { no_metadata = true },
        } })
        t:assert_eq(r.status, 0, "the image built: " .. r.output)
        t:assert_eq(r.seq1, table.concat({
            "hookseq 1",
            "/usr/libexec/prelude/hooks.d/B.sh",
            "/usr/libexec/prelude/hooks.d/_x.sh",
            "/usr/libexec/prelude/hooks.d/a.sh",
            "",
        }, "\n"), "the order is the LC_ALL=C byte order of the file names")
        r:cleanup()
    end)

test("the file extension is irrelevant: being a file in the directory is what makes a hook",
    { spec = "prelude mkirf.extension-is-irrelevant" }, function(t)
        local r = prelude.mkirf({ hooks = {
            [USR .. "/hook.bin"] = {},
            [USR .. "/hook.py"] = {},
            [USR .. "/noext"] = {},
        } })
        t:assert_eq(r.status, 0, "the image built: " .. r.output)
        t:assert_eq(r.seq1, table.concat({
            "hookseq 1",
            "/usr/libexec/prelude/hooks.d/hook.bin",
            "/usr/libexec/prelude/hooks.d/hook.py",
            "/usr/libexec/prelude/hooks.d/noext",
            "",
        }, "\n"), "all three are hooks whatever they are named")
        r:cleanup()
    end)

-- H. The metadata block ------------------------------------------------------

test("the block's fence lines are matched exactly, trailing whitespace aside",
    { spec = "prelude block.opens-and-closes-exactly" }, function(t)
        -- Trailing whitespace on either fence is ignored.
        local ok = prelude.mkirf({ hooks = {
            [USR .. "/h.sh"] = table.concat({
                "#!/usr/bin/sh",
                "# /// hook   ",
                '# provides = ["fenced"]',
                "# ///  ",
                "",
            }, "\n"),
        } })
        t:assert_eq(ok.status, 0, "trailing whitespace on a fence is ignored: " .. ok.output)
        t:assert_contains(ok.seq2, "provides fenced", "the block was read: " .. ok.seq2)
        ok:cleanup()

        -- An indented opener is not the opener. Nothing in the file is a
        -- block, so the hook is the no-metadata escape hatch instead —
        -- which is how a near-miss fence announces itself.
        local miss = prelude.mkirf({ hooks = {
            [USR .. "/h.sh"] = table.concat({
                "#!/usr/bin/sh",
                " # /// hook",
                '# provides = ["fenced"]',
                "# ///",
                "",
            }, "\n"),
        } })
        t:assert_eq(miss.status, 0, "a file with no block is still a valid hook: " .. miss.output)
        t:assert_contains(miss.output, "hook `h.sh` has no `# /// hook` metadata block",
            "an indented `# /// hook` does not open a block")
        miss:cleanup()
    end)

test("a second `# /// hook` block anywhere in the file is an error",
    { spec = "prelude block.two-blocks-is-an-error" }, function(t)
        local r = prelude.mkirf({ hooks = {
            [USR .. "/h.sh"] = table.concat({
                "#!/usr/bin/sh",
                "# /// hook",
                '# provides = ["a"]',
                "# ///",
                "echo work",
                "# /// hook",
                "# ///",
                "",
            }, "\n"),
        } })
        t:assert_eq(r.status, 1, "an unresolvable hook set is exit 1: " .. r.output)
        t:assert_contains(r.output, "hook `h.sh`: more than one `# /// hook` metadata block",
            "the diagnosis names the hook and the duplicate block")
        r:cleanup()
    end)

test("a block that is never closed is an error",
    { spec = "prelude block.unclosed-is-an-error" }, function(t)
        local r = prelude.mkirf({ hooks = {
            [USR .. "/h.sh"] = table.concat({
                "#!/usr/bin/sh",
                "# /// hook",
                '# provides = ["a"]',
                "",
            }, "\n"),
        } })
        t:assert_eq(r.status, 1, "an unresolvable hook set is exit 1: " .. r.output)
        t:assert_contains(r.output,
            "hook `h.sh`: `# /// hook` block is never closed with `# ///`",
            "the diagnosis says the fence was left open")
        r:cleanup()
    end)

test("a line inside the block that is not a comment is an error naming the line",
    { spec = "prelude block.lines-must-be-comments" }, function(t)
        local r = prelude.mkirf({ hooks = {
            [USR .. "/h.sh"] = table.concat({
                "#!/usr/bin/sh",       -- line 1
                "# /// hook",          -- line 2
                '# provides = ["a"]',  -- line 3
                'requires = ["b"]',    -- line 4: no `# ` prefix
                "# ///",               -- line 5
                "",
            }, "\n"),
        } })
        t:assert_eq(r.status, 1, "an unresolvable hook set is exit 1: " .. r.output)
        t:assert_contains(r.output,
            "hook `h.sh`: line 4: content inside the metadata block must be `# `-prefixed",
            "the diagnosis names the hook and the offending line, counting from the file's first line")
        r:cleanup()
    end)

test("blank lines and `#` comment lines inside the block are skipped",
    { spec = "prelude block.blank-and-comment-lines-are-skipped" }, function(t)
        local r = prelude.mkirf({ hooks = {
            [USR .. "/h.sh"] = table.concat({
                "#!/usr/bin/sh",
                "# /// hook",
                "#",
                "# # why this hook exists",
                '# provides = ["a"]',
                "#",
                "# ///",
                "",
            }, "\n"),
        } })
        t:assert_eq(r.status, 0, "a bare `#` and a commented line are not declarations: " .. r.output)
        t:assert_eq(r.seq2, table.concat({
            "hookseq 2",
            "hook /usr/libexec/prelude/hooks.d/h.sh",
            "provides a",
            "after initramfs-ready",
            "",
        }, "\n"), "only the one real declaration was read")
        r:cleanup()
    end)

test("a key that is not one of the four is an error",
    { spec = "prelude block.unknown-key-is-an-error" }, function(t)
        local r = prelude.mkirf({ hooks = {
            [USR .. "/h.sh"] = table.concat({
                "#!/usr/bin/sh",
                "# /// hook",
                '# needs = ["a"]',
                "# ///",
                "",
            }, "\n"),
        } })
        t:assert_eq(r.status, 1, "an unresolvable hook set is exit 1: " .. r.output)
        t:assert_contains(r.output,
            "hook `h.sh`: line 3: unknown key `needs` "
            .. "(expected `provides`, `contributes`, `requires` or `after`)",
            "the diagnosis names the key and lists the four that are accepted")
        r:cleanup()
    end)

test("a key given twice is an error",
    { spec = "prelude block.duplicate-key-is-an-error" }, function(t)
        local r = prelude.mkirf({ hooks = {
            [USR .. "/h.sh"] = table.concat({
                "#!/usr/bin/sh",
                "# /// hook",
                '# provides = ["a"]',
                '# provides = ["b"]',
                "# ///",
                "",
            }, "\n"),
        } })
        t:assert_eq(r.status, 1, "an unresolvable hook set is exit 1: " .. r.output)
        t:assert_contains(r.output, "hook `h.sh`: line 4: duplicate key `provides`",
            "the diagnosis names the repeated key at the line that repeated it")
        r:cleanup()
    end)

test("an empty array, a trailing comma and surrounding spaces are all accepted array syntax",
    { spec = "prelude block.array-grammar" }, function(t)
        local r = prelude.mkirf({ hooks = {
            [USR .. "/h.sh"] = table.concat({
                "#!/usr/bin/sh",
                "# /// hook",
                '# provides = [ "a" , "b", ]',
                "# after = []",
                "# ///",
                "",
            }, "\n"),
        } })
        t:assert_eq(r.status, 0, "the array forms TOML allows are accepted: " .. r.output)
        t:assert_contains(r.seq2, "provides a b",
            "both elements were read despite the trailing comma: " .. r.seq2)
        r:cleanup()
    end)

test("a value that is not an array, a doubled comma, and an unquoted element are each an error",
    { spec = "prelude block.array-grammar" }, function(t)
        local cases = {
            { value = '"a"', message = "line 3: expected an array `[...]`, found `\"a\"`" },
            { value = '["a",, "b"]', message = "line 3: empty array element (doubled comma?)" },
            { value = "[a]", message = "line 3: array element `a` is not a double-quoted string" },
        }
        for _, case in ipairs(cases) do
            local r = prelude.mkirf({ hooks = {
                [USR .. "/h.sh"] = table.concat({
                    "#!/usr/bin/sh",
                    "# /// hook",
                    "# provides = " .. case.value,
                    "# ///",
                    "",
                }, "\n"),
            } })
            t:assert_eq(r.status, 1, "`" .. case.value .. "` is exit 1: " .. r.output)
            t:assert_contains(r.output, "hook `h.sh`: " .. case.message,
                "the diagnosis says what was wrong with `" .. case.value .. "`")
            r:cleanup()
        end
    end)

test("a capability name must be a bare token: alphanumeric first, then alphanumerics and `.`, `_`, `-`",
    { spec = "prelude block.capability-names-are-bare-tokens" }, function(t)
        local ok = prelude.mkirf({ hooks = {
            [USR .. "/h.sh"] = { provides = { "9a.b_c-d" } },
        } })
        t:assert_eq(ok.status, 0, "every character of the charset is accepted: " .. ok.output)
        t:assert_contains(ok.seq2, "provides 9a.b_c-d", "and written out verbatim: " .. ok.seq2)
        ok:cleanup()

        -- A name carrying whitespace would produce a version-2 sequence
        -- that parsed as something else entirely, since that format
        -- separates names by whitespace. A leading `-` is refused for the
        -- same reason the charset exists: names are checked where they
        -- enter, not escaped where they leave.
        for _, bad in ipairs({ "not a token", "-lead" }) do
            local r = prelude.mkirf({ hooks = {
                [USR .. "/h.sh"] = { provides = { bad } },
            } })
            t:assert_eq(r.status, 1, "`" .. bad .. "` is exit 1: " .. r.output)
            t:assert_contains(r.output,
                "capability name `" .. bad .. "` is not a bare token "
                .. "(letters or digits, then any of letters, digits, `.`, `_`, `-`)",
                "the diagnosis names the rejected capability and the charset")
            r:cleanup()
        end
    end)

test("a hook with no metadata block at all is valid, scheduled last, and warned about",
    { spec = "prelude block.absent-is-valid-and-warned" }, function(t)
        local r = prelude.mkirf({ hooks = {
            -- `a-none.sh` sorts first by name and still runs last: having
            -- no block is what puts it there.
            [USR .. "/a-none.sh"] = { no_metadata = true },
            [USR .. "/z-declared.sh"] = { provides = { "work" } },
        } })
        t:assert_eq(r.status, 0, "a hook with no block is not an error: " .. r.output)
        t:assert_contains(r.output,
            "hook `a-none.sh` has no `# /// hook` metadata block; scheduling it last",
            "the build warned so a forgotten block is visible")
        t:assert_eq(r.seq1, table.concat({
            "hookseq 1",
            "/usr/libexec/prelude/hooks.d/z-declared.sh",
            "/usr/libexec/prelude/hooks.d/a-none.sh",
            "",
        }, "\n"), "the undeclared hook runs after the declaring one, name order notwithstanding")
        r:cleanup()
    end)
