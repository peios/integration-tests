-- mkirf, part two: resolving the capability DAG and writing it into the
-- image. Claims I1-I12 (resolution) and J1-J7 (the sequence files).
--
-- The same host-side seam as `mkirf-hooks.test.lua`: a fixture source
-- tree in a temporary directory, the real binary run over it, and the two
-- generated sequence files read back out of the cpio. The order mkirf
-- resolved is not an internal detail — it is written into
-- `/system/prelude/hooks.seq.1` and `.2`, which prelude reads at the next
-- boot, so the emitted text is the thing to assert.
--
-- Exit status is asserted alongside every message: 0 built, 1 an
-- operational failure including an unresolvable hook set, 2 a usage
-- error.

local prelude = require("helpers.prelude")

local USR = prelude.SRC_HOOKS_USR
local D = "/usr/libexec/prelude/hooks.d/" -- the same directory, as the sequence spells it

--- The hook paths a version-1 body lists, in order.
local function v1_paths(seq)
    local out = {}
    for line in seq:gmatch("[^\n]+") do
        if line ~= "hookseq 1" then out[#out + 1] = line end
    end
    return out
end

--- The hook paths a version-2 body opens a stanza for, in order.
local function v2_paths(seq)
    local out = {}
    for path in seq:gmatch("hook (%S+)") do out[#out + 1] = path end
    return out
end

-- I. Resolving the order -----------------------------------------------------

test("a capability that is both provided and contributed to is an error naming both sides",
    { spec = "prelude resolve.provided-and-contributed-is-an-error" }, function(t)
        local r = prelude.mkirf({ hooks = {
            [USR .. "/alt.sh"] = { provides = { "dual" } },
            [USR .. "/part.sh"] = { contributes = { "dual" } },
        } })
        t:assert_eq(r.status, 1, "an unresolvable hook set is exit 1: " .. r.output)
        t:assert_contains(r.output,
            "capability `dual` is both provided (by alt.sh) and contributed to (by part.sh)",
            "the diagnosis names the capability and the hooks on each side")
        t:assert_contains(r.output,
            "a capability is either alternatives, where one supplier suffices, "
            .. "or contributors, where all must complete — not both",
            "and says why the two cannot be mixed")
        r:cleanup()
    end)

test("a `requires` nothing supplies is an error naming the hook and the capability",
    { spec = "prelude resolve.unsupplied-requires-is-an-error" }, function(t)
        local r = prelude.mkirf({ hooks = {
            [USR .. "/needy.sh"] = { requires = { "nobody-supplies-this" } },
        } })
        t:assert_eq(r.status, 1, "an unresolvable hook set is exit 1: " .. r.output)
        t:assert_contains(r.output,
            "hook `needy.sh` requires capability `nobody-supplies-this`, which no hook provides",
            "the diagnosis names the hook and the capability it cannot have")
        r:cleanup()
    end)

test("an `after` naming a capability nothing supplies is explicitly not an error",
    { spec = "prelude resolve.unsupplied-after-is-fine" }, function(t)
        local r = prelude.mkirf({ hooks = {
            [USR .. "/soft.sh"] = { after = { "nobody-supplies-this" } },
        } })
        t:assert_eq(r.status, 0, "a soft edge with nothing to attach to just runs: " .. r.output)
        t:assert_eq(r.seq2, table.concat({
            "hookseq 2",
            "hook " .. D .. "soft.sh",
            "after nobody-supplies-this initramfs-ready",
            "",
        }, "\n"), "the unsupplied name is kept in the sequence, alongside the implicit edge")
        r:cleanup()
    end)

test("a hook whose only declaration is an empty array is unconstrained, unwarned, and gains no implicit edge",
    { spec = "prelude resolve.empty-lists-leave-a-hook-unconstrained" }, function(t)
        local r = prelude.mkirf({ hooks = {
            [USR .. "/a-empty.sh"] = { contributes = {} },
            [USR .. "/m-work.sh"] = { provides = { "thing" } },
            [USR .. "/z-none.sh"] = { no_metadata = true },
        } })
        t:assert_eq(r.status, 0, "the image built: " .. r.output)
        -- Constrained means supplying or consuming at least one NAME. An
        -- empty array supplies none, so the hook joins the tail — but it
        -- carries a block, so it is not the forgotten-metadata case and
        -- draws no warning.
        t:assert(not r.output:find("hook `a-empty.sh` has no", 1, true),
            "a hook carrying an empty declaration is not warned about: " .. r.output)
        t:assert_contains(r.output, "hook `z-none.sh` has no `# /// hook` metadata block",
            "while the hook with no block at all still is")
        t:assert_eq(r.seq2, table.concat({
            "hookseq 2",
            "hook " .. D .. "m-work.sh",
            "provides thing",
            "after initramfs-ready",
            "hook " .. D .. "a-empty.sh",
            "hook " .. D .. "z-none.sh",
            "",
        }, "\n"), "it runs last with the no-block hooks and carries no `after initramfs-ready`")
        r:cleanup()
    end)

test("unconstrained hooks are appended after every constrained one, in name order",
    { spec = "prelude resolve.unconstrained-hooks-run-last" }, function(t)
        local r = prelude.mkirf({ hooks = {
            [USR .. "/a-none.sh"] = { no_metadata = true },
            [USR .. "/b-empty.sh"] = {},
            [USR .. "/m-supplier.sh"] = { provides = { "cap" } },
            [USR .. "/z-consumer.sh"] = { requires = { "cap" } },
        } })
        t:assert_eq(r.status, 0, "the image built: " .. r.output)
        t:assert_eq(r.seq1, table.concat({
            "hookseq 1",
            D .. "m-supplier.sh",
            D .. "z-consumer.sh",
            D .. "a-none.sh",
            D .. "b-empty.sh",
            "",
        }, "\n"), "the two declaring hooks run in DAG order, then the two that declared nothing in name order")
        r:cleanup()
    end)

test("every constrained hook that does not supply initramfs-ready gains that edge, written into the sequence",
    { spec = "prelude resolve.implicit-initramfs-ready-edge" }, function(t)
        local r = prelude.mkirf({ hooks = {
            [USR .. "/10-ready.sh"] = { contributes = { "initramfs-ready" } },
            [USR .. "/20-work.sh"] = { provides = { "work" } },
        } })
        t:assert_eq(r.status, 0, "the image built: " .. r.output)
        -- The rule is materialised, not left for prelude to know: the
        -- edge is in the file, as an ordinary `after`, and the sequence
        -- explains in a rescue shell why the hook ran where it did.
        t:assert_eq(r.seq2, table.concat({
            "hookseq 2",
            "hook " .. D .. "10-ready.sh",
            "contributes initramfs-ready",
            "hook " .. D .. "20-work.sh",
            "provides work",
            "after initramfs-ready",
            "",
        }, "\n"), "the contributor is exempt and runs first; the other hook carries the implicit edge")
        r:cleanup()
    end)

test("a hook with no metadata block does not gain the implicit initramfs-ready edge",
    { spec = "prelude resolve.no-block-does-not-gain-the-edge" }, function(t)
        local r = prelude.mkirf({ hooks = {
            [USR .. "/10-ready.sh"] = { contributes = { "initramfs-ready" } },
            [USR .. "/20-plain.sh"] = { no_metadata = true },
        } })
        t:assert_eq(r.status, 0, "the image built: " .. r.output)
        -- It already runs after every declaring hook, so the edge would
        -- change nothing — and adding it would pull the escape hatch into
        -- the DAG.
        t:assert_eq(r.seq2, table.concat({
            "hookseq 2",
            "hook " .. D .. "10-ready.sh",
            "contributes initramfs-ready",
            "hook " .. D .. "20-plain.sh",
            "",
        }, "\n"), "the undeclared hook's stanza is a bare `hook` line")
        r:cleanup()
    end)

test("`requires` and `after` produce the identical ordering edge",
    { spec = "prelude resolve.requires-and-after-order-alike" }, function(t)
        -- The consumer sorts before the supplier by name, so an order
        -- that puts the supplier first can only have come from the edge.
        local hard = prelude.mkirf({ hooks = {
            [USR .. "/a-consumer.sh"] = { requires = { "cap" } },
            [USR .. "/z-supplier.sh"] = { provides = { "cap" } },
        } })
        local soft = prelude.mkirf({ hooks = {
            [USR .. "/a-consumer.sh"] = { after = { "cap" } },
            [USR .. "/z-supplier.sh"] = { provides = { "cap" } },
        } })
        t:assert_eq(hard.status, 0, "the `requires` image built: " .. hard.output)
        t:assert_eq(soft.status, 0, "the `after` image built: " .. soft.output)
        t:assert_eq(hard.seq1, table.concat({
            "hookseq 1", D .. "z-supplier.sh", D .. "a-consumer.sh", "",
        }, "\n"), "the supplier runs first, against name order")
        t:assert_eq(soft.seq1, hard.seq1,
            "and `after` resolves to exactly the same order as `requires`")
        hard:cleanup()
        soft:cleanup()
    end)

test("`provides` and `contributes` supply a capability alike, for ordering",
    { spec = "prelude resolve.provides-and-contributes-supply-alike" }, function(t)
        local alt = prelude.mkirf({ hooks = {
            [USR .. "/a-consumer.sh"] = { requires = { "cap" } },
            [USR .. "/z-supplier.sh"] = { provides = { "cap" } },
        } })
        local part = prelude.mkirf({ hooks = {
            [USR .. "/a-consumer.sh"] = { requires = { "cap" } },
            [USR .. "/z-supplier.sh"] = { contributes = { "cap" } },
        } })
        t:assert_eq(alt.status, 0, "the `provides` image built: " .. alt.output)
        t:assert_eq(part.status, 0, "the `contributes` image built: " .. part.output)
        t:assert_eq(alt.seq1, table.concat({
            "hookseq 1", D .. "z-supplier.sh", D .. "a-consumer.sh", "",
        }, "\n"), "the supplier runs first, against name order")
        t:assert_eq(part.seq1, alt.seq1,
            "and a contributor supplies exactly as a provider does; the two differ in "
            .. "what `satisfied` means, not in who runs first")
        alt:cleanup()
        part:cleanup()
    end)

test("hooks that could run in any order run in file-name order",
    { spec = "prelude resolve.ties-break-by-name" }, function(t)
        -- Every hook but the topology one becomes ready at the same
        -- moment; `z.sh` waits for `a.sh`'s capability and so falls in
        -- behind it. `C.sh` before `a.sh` is byte order, not collation.
        local r = prelude.mkirf({ hooks = {
            [USR .. "/00-ready.sh"] = { contributes = { "initramfs-ready" } },
            [USR .. "/C.sh"] = { after = { "initramfs-ready" } },
            [USR .. "/a.sh"] = { provides = { "cap-a" } },
            [USR .. "/b.sh"] = { provides = { "cap-b" } },
            [USR .. "/z.sh"] = { requires = { "cap-a" } },
        } })
        t:assert_eq(r.status, 0, "the image built: " .. r.output)
        t:assert_eq(r.seq1, table.concat({
            "hookseq 1",
            D .. "00-ready.sh",
            D .. "C.sh",
            D .. "a.sh",
            D .. "b.sh",
            D .. "z.sh",
            "",
        }, "\n"), "ties break by taking the name-smallest ready hook each time")
        r:cleanup()
    end)

test("a dependency cycle is an error naming every hook left unplaced",
    { spec = "prelude resolve.cycle-is-an-error" }, function(t)
        local r = prelude.mkirf({ hooks = {
            [USR .. "/a.sh"] = { provides = { "x" }, requires = { "y" } },
            [USR .. "/b.sh"] = { provides = { "y" }, requires = { "x" } },
        } })
        t:assert_eq(r.status, 1, "an unresolvable hook set is exit 1: " .. r.output)
        t:assert_contains(r.output, "hook dependency cycle involving: a.sh, b.sh",
            "the diagnosis names both hooks caught in the cycle")
        r:cleanup()
    end)

test("a hook that consumes a capability it also supplies does not get a self-edge",
    { spec = "prelude resolve.self-supply-is-not-an-edge" }, function(t)
        local r = prelude.mkirf({ hooks = {
            [USR .. "/self.sh"] = { provides = { "own" }, requires = { "own" } },
        } })
        -- Its own supply satisfies the requirement, and the edge it would
        -- otherwise draw to itself would be a one-hook cycle.
        t:assert_eq(r.status, 0, "a self-supplied requirement is neither unsupplied nor a cycle: " .. r.output)
        t:assert_eq(r.seq2, table.concat({
            "hookseq 2",
            "hook " .. D .. "self.sh",
            "provides own",
            "requires own",
            "after initramfs-ready",
            "",
        }, "\n"), "both declarations are recorded and the hook is scheduled")
        r:cleanup()
    end)

-- J. Writing the sequence ----------------------------------------------------

test("both sequence versions are written for every image, including one with no hooks at all",
    { spec = "prelude seqfile.both-versions-always-written" }, function(t)
        local r = prelude.mkirf({})
        t:assert_eq(r.status, 0, "an image with no hooks is a valid image: " .. r.output)
        -- A bare marker, not an absent file. This is what makes prelude's
        -- rule coherent: a MISSING sequence is a broken image, because an
        -- image with nothing to run still carries one.
        t:assert_eq(r.seq1, "hookseq 1\n", "hooks.seq.1 is the marker and nothing else")
        t:assert_eq(r.seq2, "hookseq 2\n", "hooks.seq.2 is the marker and nothing else")
        t:assert(prelude.archive_entry(r.listing, "system/prelude/hooks.seq.1")
            and prelude.archive_entry(r.listing, "system/prelude/hooks.seq.2"),
            "both files are in the image: " .. r.listing)
        r:cleanup()
    end)

test("version 1 is the marker then one hook path per line",
    { spec = "prelude seqfile.v1-shape" }, function(t)
        local r = prelude.mkirf({ hooks = {
            [USR .. "/10-topology.sh"] = { contributes = { "initramfs-ready" } },
            [USR .. "/20-mount.sh"] = { provides = { "rootfs-ready" } },
            [USR .. "/30-late.sh"] = { requires = { "rootfs-ready" } },
        } })
        t:assert_eq(r.status, 0, "the image built: " .. r.output)
        t:assert_eq(r.seq1, table.concat({
            "hookseq 1",
            D .. "10-topology.sh",
            D .. "20-mount.sh",
            D .. "30-late.sh",
            "",
        }, "\n"), "the flat resolved order, and nothing else")
        r:cleanup()
    end)

test("version 2 is the marker then one stanza per hook, with empty keys omitted",
    { spec = "prelude seqfile.v2-shape" }, function(t)
        local r = prelude.mkirf({ hooks = {
            [USR .. "/10-topology.sh"] = { contributes = { "initramfs-ready" } },
            [USR .. "/20-mount.sh"] = { provides = { "rootfs-ready" } },
            [USR .. "/30-late.sh"] = { requires = { "rootfs-ready" },
                                       after = { "an-optional-milestone" } },
        } })
        t:assert_eq(r.status, 0, "the image built: " .. r.output)
        t:assert_eq(r.seq2, table.concat({
            "hookseq 2",
            "hook " .. D .. "10-topology.sh",
            "contributes initramfs-ready",
            "hook " .. D .. "20-mount.sh",
            "provides rootfs-ready",
            "after initramfs-ready",
            "hook " .. D .. "30-late.sh",
            "requires rootfs-ready",
            "after an-optional-milestone initramfs-ready",
            "",
        }, "\n"), "a `hook` line opens each stanza, and a key with nothing to say is omitted rather than written empty")
        r:cleanup()
    end)

test("the version-2 stanzas are in the resolved order, so a reader that does not schedule gets version 1's behaviour",
    { spec = "prelude seqfile.v2-order-is-the-resolved-order" }, function(t)
        local r = prelude.mkirf({ hooks = {
            [USR .. "/a-consumer.sh"] = { requires = { "cap" } },
            [USR .. "/m-none.sh"] = { no_metadata = true },
            [USR .. "/z-supplier.sh"] = { provides = { "cap" } },
        } })
        t:assert_eq(r.status, 0, "the image built: " .. r.output)
        local v1, v2 = v1_paths(r.seq1), v2_paths(r.seq2)
        t:assert_eq(table.concat(v2, "\n"), table.concat(v1, "\n"),
            "the stanza order is the version-1 order")
        t:assert_eq(v2[1], D .. "z-supplier.sh",
            "and it is the resolved order, not the order the hooks were found in")
        r:cleanup()
    end)

test("the parent directories of /system/prelude are synthesised into the archive",
    { spec = "prelude seqfile.ancestors-are-synthesised" }, function(t)
        -- The source tree has no `system/` at all: the sequences are
        -- injected, not walked, and a cpio whose file entries have no
        -- parent directory entries does not unpack.
        local r = prelude.mkirf({ hooks = { [USR .. "/h.sh"] = {} } })
        t:assert_eq(r.status, 0, "the image built: " .. r.output)
        for _, dir in ipairs({ "system", "system/prelude" }) do
            local entry = prelude.archive_entry(r.listing, dir)
            t:assert(entry, dir .. " is an entry in the archive: " .. r.listing)
            t:assert_eq(entry.mode, "drwxr-xr-x", dir .. " is a directory entry")
        end
        r:cleanup()
    end)

test("a source tree that already contains a sequence file is refused",
    { spec = "prelude seqfile.pre-existing-sequence-is-refused" }, function(t)
        -- All three names: the legacy unsuffixed one prelude still reads
        -- as a fallback, and both generated ones. A stray copy would be
        -- picked up at boot as a sequence nothing generated.
        for _, path in ipairs({ "hooks.seq",
                                "system/prelude/hooks.seq.1",
                                "system/prelude/hooks.seq.2" }) do
            local r = prelude.mkirf({
                files = { { path = path, content = "hookseq 1\n" } },
            })
            t:assert_eq(r.status, 1, "a stray `" .. path .. "` is exit 1: " .. r.output)
            t:assert_contains(r.output,
                "contains a `" .. path .. "`; mkirf generates that file",
                "the diagnosis names the file mkirf would have written")
            r:cleanup()
        end
    end)

test("permissions are normalised and ownership, inodes and timestamps are zeroed",
    { spec = "prelude seqfile.permissions-are-normalised" }, function(t)
        local r = prelude.mkirf({
            files = {
                { path = "tree/private", content = "secret\n", mode = "0600" },
                { path = "tree/tool", content = "#!/usr/bin/sh\n", mode = "0700" },
                { path = "tree/wide-open", content = "x\n", mode = "0666" },
            },
            links = { { path = "tree/alias", target = "tool" } },
        })
        -- Only file TYPE and, for a regular file, EXECUTABILITY come from
        -- the source tree. Read/write bits are not Peios's access
        -- mechanism, so they are flattened to a constant — which is what
        -- makes the same tree compile to the same image byte for byte.
        t:assert_eq(r.status, 0, "the image built: " .. r.output)
        local expected = {
            ["tree/private"] = "-rw-r--r--",
            ["tree/wide-open"] = "-rw-r--r--",
            ["tree/tool"] = "-rwxr-xr-x",
            ["tree/alias"] = "lrwxrwxrwx",
            ["tree"] = "drwxr-xr-x",
            ["system/prelude/hooks.seq.2"] = "-rw-r--r--",
        }
        for path, mode in pairs(expected) do
            local entry = prelude.archive_entry(r.listing, path)
            t:assert(entry, path .. " is in the archive: " .. r.listing)
            t:assert_eq(entry.mode, mode, path .. " is emitted " .. mode)
        end
        local init = prelude.archive_entry(r.listing, "init")
        t:assert_eq(init.owner .. ":" .. init.group, "root:root",
            "ownership is emitted as zero, which cpio prints as root")
        t:assert_contains(init.time, "1970",
            "and the timestamp is zero rather than the source file's mtime")
        r:cleanup()
    end)
