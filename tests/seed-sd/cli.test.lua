-- seed-sd's command line: claims A1–A9 of the seed-sd inventory.
--
-- seed-sd parses its own arguments in nine lines of `match`, and the
-- shape that falls out of them is not the shape a getopt would give.
-- There is no `--`, no clustering, no "flags must come first", and —
-- the sharp end — no such thing as an unrecognised flag: the first
-- argument the match arms do not claim becomes the path, whatever it
-- looks like. `seed-sd --bogus` therefore seeds a file called
-- `--bogus`, and it is only the *second* unclaimed argument that is an
-- error. That is asserted here against a file genuinely named
-- `--bogus`, because nothing else demonstrates it.
--
-- Every case here is about the argument vector, so each one runs the
-- real binary the prelude package ships (`/bin/seed-sd`, staged into
-- the payload that becomes the guest's real root) and reads the
-- descriptor back through `kacs_get_sd` to see what the parse decided.
--
-- Two exit statuses carry the whole contract: 2 for a usage error,
-- printed on stderr and nowhere else, and 1 for a node that could not
-- be seeded. A test that accepted "non-zero" would pass for the wrong
-- reason on either, so both the status and the message are asserted.

local kacs = require("helpers.kacs")
local access = require("helpers.access")
local token = require("helpers.token")

local vm = provium:vm("cli", "prelude"):boot()

-- The binary, and the one line it prints when the parse gives up. The
-- program name in it is argv[0], which is the path the agent exec'd.
local SEED = "/bin/seed-sd"
local USAGE = "usage: " .. SEED .. " [-r|--recursive] [--sddl <descriptor>] <path>\n"

local ALL = kacs.SI.OWNER | kacs.SI.GROUP | kacs.SI.DACL
local CREATOR_OWNER = token.sid(3, 0)

--- A descriptor a test can tell apart from seed-sd's built-in at a
--- glance: owned by a principal the built-in never names, with a single
--- non-inheritable Everyone ACE where the built-in has three.
---
--- Every target below wears it before seed-sd runs, so "was this
--- stamped?" is answered by reading one descriptor rather than by
--- trusting an exit status.
local MARKER = access.sd({
    owner = token.SID.TEST_USER,
    group = token.SID.TEST_USER,
    dacl = access.acl({
        access.ace(access.ACE.ALLOWED, kacs.ALL_RIGHTS, token.SID.EVERYONE),
    }),
})

--- A directory under the root a hook mounted and seeded. Not `/tmp`:
--- the agent mounts a tmpfs of its own there when it comes up as PID 1,
--- and that one is DENY_MISSING with no descriptor on its root, so
--- nothing can be created in it.
local function workspace(name)
    local at = "/run/seed-sd-cli/" .. name
    vm:mkdir(at, { parents = true })
    return at
end

--- Create `path` (a file, or a directory when `dir` is true) and put
--- MARKER on it. Returns the path.
local function marked(path, dir)
    if dir then vm:mkdir(path, { parents = true }) else vm:write_file(path, "x") end
    assert(kacs.set_sd(vm, path, MARKER, ALL).ret == 0, "marking " .. path)
    return path
end

--- True when `path` carries seed-sd's built-in descriptor.
local function seeded(path)
    local bytes = kacs.get_sd(vm, path, ALL)
    if not bytes then return false end
    local sd = access.parse_sd(bytes)
    return sd.owner == token.SID.LOCAL_SYSTEM
        and sd.dacl ~= nil and sd.dacl.count == 3
        and sd.dacl.aces[1].sid == token.SID.LOCAL_SYSTEM
        and sd.dacl.aces[2].sid == token.SID.ADMINISTRATORS
        and sd.dacl.aces[3].sid == CREATOR_OWNER
end

--- True when `path` still wears MARKER — nothing touched it.
local function untouched(path)
    local bytes = kacs.get_sd(vm, path, ALL)
    if not bytes then return false end
    local sd = access.parse_sd(bytes)
    return sd.owner == token.SID.TEST_USER
        and sd.dacl ~= nil and sd.dacl.count == 1
        and sd.dacl.aces[1].sid == token.SID.EVERYONE
end

-- A descriptor nothing else in this suite produces, for the cases that
-- need to see which of two arguments `--sddl` consumed.
local SDDL = "O:BAG:BAD:(A;;GA;;;AU)"

-- ---- the flags ------------------------------------------------------------

test("-r and --recursive are the same flag",
    { spec = "seed-sd cli.recursive-has-two-spellings" }, function(t)
        for _, flag in ipairs({ "-r", "--recursive" }) do
            local dir = marked(workspace("recursive" .. flag), true)
            local child = marked(dir .. "/child")

            local r = vm:run(SEED, { flag, dir })
            t:assert_eq(r.exit_code, 0, flag .. " succeeded: " .. r.stderr)
            t:assert(seeded(child),
                flag .. " seeded a descendant, so it is the recursive flag")
        end
    end)

test("--sddl consumes the next argument as the descriptor",
    { spec = "seed-sd cli.sddl-takes-the-next-argument" }, function(t)
        local path = marked(workspace("sddl-value") .. "/f")

        local r = vm:run(SEED, { "--sddl", SDDL, path })
        t:assert_eq(r.exit_code, 0, "the run succeeded: " .. r.stderr)

        -- Had the descriptor text been taken as the path instead, the
        -- run would have failed on it and `path` would still be marked.
        local sd = access.parse_sd(assert(kacs.get_sd(vm, path, ALL)))
        t:assert_eq(sd.owner, token.SID.ADMINISTRATORS,
            "the argument after --sddl was compiled and stamped, not treated as the path")
        t:assert_eq(sd.dacl.count, 1, "the descriptor written is the one given")
    end)

test("--sddl with nothing after it is a usage error, not a fall back to the default",
    { spec = "seed-sd cli.sddl-without-a-value-is-a-usage-error" }, function(t)
        local path = marked(workspace("sddl-novalue") .. "/f")

        local r = vm:run(SEED, { path, "--sddl" })
        t:assert_eq(r.exit_code, 2, "a missing --sddl value is a usage error: " .. r.stderr)
        t:assert_eq(r.stderr, USAGE, "and prints the usage line")
        t:assert(untouched(path),
            "silently seeding the built-in default when the caller asked for " ..
            "something else is the failure this flag exists to make impossible")
    end)

-- ---- the path -------------------------------------------------------------

test("the first argument that is not a recognised flag is the path",
    { spec = "seed-sd cli.first-unmatched-argument-is-the-path" }, function(t)
        local path = marked(workspace("first-unmatched") .. "/f")

        -- `-r` and `--sddl <value>` are claimed by their match arms, so
        -- the only argument left over is the path. Had either been taken
        -- positionally, seed-sd would have tried to stamp `-r` or the
        -- descriptor text and failed.
        local r = vm:run(SEED, { "-r", "--sddl", SDDL, path })
        t:assert_eq(r.exit_code, 0, "the recognised flags were consumed as flags: " .. r.stderr)

        local sd = access.parse_sd(assert(kacs.get_sd(vm, path, ALL)))
        t:assert_eq(sd.owner, token.SID.ADMINISTRATORS, "the one unmatched argument was the path")
        t:assert_eq(sd.dacl.count, 1, "and it carries the descriptor that was asked for")
    end)

test("a second non-flag argument is a usage error",
    { spec = "seed-sd cli.a-second-path-is-a-usage-error" }, function(t)
        local dir = workspace("two-paths")
        local first, second = marked(dir .. "/one"), marked(dir .. "/two")

        local r = vm:run(SEED, { first, second })
        t:assert_eq(r.exit_code, 2, "two paths is a usage error: " .. r.stderr)
        t:assert_eq(r.stderr, USAGE, "and prints the usage line")
        t:assert(untouched(first), "the first path was not seeded")
        t:assert(untouched(second), "nor the second: the parse fails before anything is stamped")
    end)

test("no path at all is a usage error",
    { spec = "seed-sd cli.no-path-is-a-usage-error" }, function(t)
        local bare = vm:run(SEED, {})
        t:assert_eq(bare.exit_code, 2, "no arguments at all is a usage error: " .. bare.stderr)
        t:assert_eq(bare.stderr, USAGE, "and prints the usage line")

        -- A flag is not a path: `-r` is claimed by its match arm and
        -- leaves the path unset.
        local flag_only = vm:run(SEED, { "-r" })
        t:assert_eq(flag_only.exit_code, 2, "and so is a flag with no path: " .. flag_only.stderr)
        t:assert_eq(flag_only.stderr, USAGE, "with the same usage line")
    end)

test("the usage line goes to stderr and exits 2, distinct from 1 for an operational failure",
    { spec = "seed-sd cli.usage-goes-to-stderr-and-exits-two" }, function(t)
        local usage = vm:run(SEED, {})
        t:assert_eq(usage.exit_code, 2, "a usage error exits 2")
        t:assert_eq(usage.stderr, USAGE, "with the usage line on stderr")
        t:assert_eq(usage.stdout, "", "and nothing at all on stdout")

        -- An operational failure: the path parses fine and cannot be
        -- stamped. Different status, different stream content.
        local absent = workspace("statuses") .. "/absent"
        local failed = vm:run(SEED, { absent })
        t:assert_eq(failed.exit_code, 1, "a node that could not be seeded exits 1: " .. failed.stderr)
        t:assert_contains(failed.stderr, "seed-sd: set_sd " .. absent .. ": ",
            "naming the path it could not stamp")
        t:assert(not failed.stderr:find("usage:", 1, true),
            "and not the usage line: the two failures are told apart by their status and their message")
        t:assert_neq(usage.exit_code, failed.exit_code,
            "2 for a usage error, 1 for an operational failure")
    end)

test("flags may appear after the path",
    { spec = "seed-sd cli.flags-may-follow-the-path" }, function(t)
        -- Parsing is positional only in that the first unmatched
        -- argument wins; a flag is still a flag wherever it appears.
        local dir = marked(workspace("trailing-r"), true)
        local child = marked(dir .. "/child")
        local r = vm:run(SEED, { dir, "-r" })
        t:assert_eq(r.exit_code, 0, "-r after the path succeeded: " .. r.stderr)
        t:assert(seeded(child), "and still recursed: the descendant was seeded")

        local path = marked(workspace("trailing-sddl") .. "/f")
        local s = vm:run(SEED, { path, "--sddl", SDDL })
        t:assert_eq(s.exit_code, 0, "--sddl after the path succeeded: " .. s.stderr)
        local sd = access.parse_sd(assert(kacs.get_sd(vm, path, ALL)))
        t:assert_eq(sd.owner, token.SID.ADMINISTRATORS,
            "and still took its value: the trailing flag was honoured")
    end)

test("an unrecognised flag is taken as the path when no path has been seen yet",
    { spec = "seed-sd cli.an-unknown-flag-is-taken-as-the-path" }, function(t)
        -- There is no such thing as an unrecognised flag: the catch-all
        -- arm is `_ if path.is_none()`, so the first argument the named
        -- arms do not claim becomes the path whatever it looks like.
        -- `--bogus` is therefore a filename, and this is a file called
        -- `--bogus`. It has to be named relatively — an absolute path
        -- would not look like a flag at all.
        local dir = workspace("unknown-flag")
        local bogus = marked(dir .. "/--bogus")

        local r = vm:run(SEED, { args = { "--bogus" }, cwd = dir })
        t:assert_eq(r.exit_code, 0, "`seed-sd --bogus` succeeded: " .. r.stderr)
        t:assert_eq(r.stderr, "", "with no complaint about an unknown flag")
        t:assert(seeded(bogus), "it seeded a file called --bogus")

        -- Only a *second* unmatched argument is an error, and it is the
        -- ordinary two-paths one.
        marked(dir .. "/--other")
        local two = vm:run(SEED, { args = { "--bogus", "--other" }, cwd = dir })
        t:assert_eq(two.exit_code, 2, "a second unmatched argument is a usage error: " .. two.stderr)
        t:assert_eq(two.stderr, USAGE, "and prints the usage line")
        t:assert(untouched(dir .. "/--other"), "having stamped neither")
    end)
