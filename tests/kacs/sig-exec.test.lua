-- PKM §3.6 — PIP determination at `execve()`: what tier the exec takes,
-- that it proceeds whatever the answer, which file the answer is taken
-- from in a `#!` or symlink chain, and where FACS sits relative to the
-- whole thing.
--
-- The observation surface is the `kacs:kacs_exec` tracepoint. It fires
-- once per binfmt iteration that reaches `bprm_creds_from_file`, with
-- `exec_pip=<type>:<trust>` carrying the staged tier, and again from
-- `bprm_committed_creds` with reason `pip-committed` — so a whole exec
-- reads as "staged, then committed", which is what §3.6's transactional
-- rule describes. `kacs:kacs_signing_probe` names *which file* the
-- lookup ran against, through its `file_len`: that is how a case tells
-- an interpreter from the script that named it.
--
-- Every binary here is unsigned, so every tier is None/0. That is not a
-- weakness of the fixture — it is the case §3.6 spells out ("no
-- signature, an invalid or unstable one, a bad signature, or no
-- matching key all yield None/0"), and it is the whole of what a
-- keyless guest can witness.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local signing = require("helpers.signing")
local psb = require("helpers.psb")

local vm = provium:vm("v", "kernel-only"):boot()

local B = signing.workspace(vm, "exec")
local XATTR = signing.blob({ fill = "\xBB" })

--- The staging events of one exec: `kacs_exec` entries that carry a
--- tier, in the order the ring saw them.
local function staged(events)
    local out = {}
    for _, e in ipairs(signing.of(events, "kacs_exec")) do
        if e.reason == "creds-allow" then out[#out + 1] = e end
    end
    return out
end

-- The tier ------------------------------------------------------------------

test("an unsigned binary, and every unusable signature, execs at None/0",
    { spec = "PKM *sig.exec.tier-from-matched-key" }, function(t)
        local cases = {
            { "no signature at all", signing.craft({ no_sections = true }), nil },
            { "a signature no key matches", signing.craft({}), nil },
            { "an invalid ELF section", signing.craft({ sec_size = 1 }), XATTR },
            { "a malformed xattr blob",
              signing.craft({ no_sections = true }),
              signing.blob({ len = signing.BLOB_LEN - 2 }) },
        }
        for i, c in ipairs(cases) do
            local path = signing.place(vm, B .. "/tier" .. i, c[2],
                { xattr = c[3] })
            local events = signing.exec_traced(vm, { signing.EV_EXEC }, path)
            local first = staged(events)[1]
            t:assert(first, c[1] .. ": the exec staged a tier")
            local ptype, ptrust = first:pair("exec_pip")
            t:assert_eq(ptype, signing.PIP_TYPE.NONE,
                c[1] .. ": pip_type is None")
            t:assert_eq(ptrust, signing.PIP_TRUST.NONE,
                c[1] .. ": pip_trust is 0")
        end
    end)

test("exec proceeds in every case where the question could be answered",
    { spec = "PKM *sig.exec.proceeds-regardless" }, function(t)
        -- One of each shape §3.6 says yields None/0, plus the
        -- structural rejections that commit the ELF path. None of them
        -- is an execution gate.
        local shapes = {
            { "unsigned", { no_sections = true } },
            { "a signature with no matching key", {} },
            { "a bad section type", { sec_type = signing.SHT_NOBITS } },
            { "a bad blob version", { blob_version = 0xFF } },
            { "a 32-bit ELF ident", { class = signing.ELFCLASS32 } },
            { "an out-of-range section header table", { shoff = 1 << 30 } },
        }
        for i, s in ipairs(shapes) do
            local path = signing.place(vm, B .. "/proceed" .. i,
                signing.craft(s[2]), { xattr = XATTR })
            local run = vm:run(path, {})
            t:assert_eq(run.exit_code, 0,
                s[1] .. " still runs to completion")
            t:assert_eq(run.status, "exited", s[1] .. " exited normally")
        end
    end)

test("the tier is staged during the exec and committed only at the end of it",
    { spec = "PKM *sig.exec.stage-then-commit" }, function(t)
        local path = signing.place(vm, B .. "/stage",
            signing.craft({ no_sections = true }), { xattr = XATTR })
        local events = signing.exec_traced(vm, { signing.EV_EXEC }, path)
        local seq = {}
        for _, e in ipairs(signing.of(events, "kacs_exec")) do
            if e.reason == "creds-allow" or e.reason == "pip-committed" then
                seq[#seq + 1] = e.reason
            end
        end
        t:assert(#seq >= 2, "the exec produced both phases: " ..
            table.concat(seq, ","))
        t:assert_eq(seq[1], "creds-allow",
            "the tier is staged in bprm_creds_from_file first")
        t:assert_eq(seq[2], "pip-committed",
            "and only then committed from bprm_committed_creds")
    end)

test("an exec that fails between staging and commit leaves the process state alone",
    { spec = "PKM *sig.exec.failed-exec-leaves-state",
      covered_by = "kunit:pkm_kunit_process",
      skip = "staging happens inside begin_new_exec(), which is past the " ..
             "point of no return: an exec that fails after it kills the " ..
             "task, so there is no surviving process whose state could be " ..
             "inspected; runs under pkm_kunit_exec_pip_pending_is_transactional" },
    function(t) end)

test("a #! script takes its tier from the interpreter, which is the file hashed",
    { spec = "PKM *sig.exec.shebang-takes-interpreter" }, function(t)
        local interp = signing.place(vm, B .. "/interp",
            signing.craft({ no_sections = true }), { xattr = XATTR })
        local interp_len = vm:stat(interp).size
        local script_body = "#!" .. interp .. "\n"
        local script = signing.place(vm, B .. "/script", script_body)
        t:assert_neq(#script_body, interp_len,
            "the script and the interpreter are different lengths")

        local events, run = signing.exec_traced(vm, { signing.EV_PROBE }, script)
        t:assert_eq(run.exit_code, 0, "the script runs")
        local probes = signing.of(events, "kacs_signing_probe")
        t:assert_eq(#probes, 1, "the lookup ran against exactly one file")
        t:assert_eq(probes[1]:num("file_len"), interp_len,
            "and it was the interpreter — the last file processed — " ..
            "not the " .. #script_body .. "-byte script")
    end)

test("a symlink is resolved before the hooks see it, so it inherits its target's tier",
    { spec = "PKM *sig.exec.symlink-resolves-to-target" }, function(t)
        local target = signing.place(vm, B .. "/link-target",
            signing.craft({ no_sections = true, code = signing.CODE_EXIT }),
            { xattr = XATTR })
        local target_len = vm:stat(target).size
        local link = B .. "/the-link"
        t:assert_eq(sys.symlink(vm, target, link).ret, 0, "the symlink is made")

        local events, run = signing.exec_traced(vm, { signing.EV_PROBE }, link)
        t:assert_eq(run.exit_code, 0, "the symlink execs")
        local probes = signing.of(events, "kacs_signing_probe")
        t:assert_eq(#probes, 1, "one lookup ran")
        t:assert_eq(probes[1]:num("file_len"), target_len,
            "against the already-resolved target file")
    end)

test("a committed tier is fixed for the process image, inherited at fork and re-derived at exec",
    { spec = "PKM *sig.exec.fixed-and-inherited",
      covered_by = "kunit:pkm_kunit_process",
      skip = "every process in a keyless guest carries None/0, so " ..
             "inheritance and re-derivation are not distinguishable from " ..
             "each other or from no propagation at all; runs under " ..
             "pkm_kunit_exec_pip_unsigned_commit_clears_existing_pip and " ..
             "pkm_kunit_process_state_fork_gets_fresh_sd_and_rate_bucket" },
    function(t) end)

-- FACS ordering ---------------------------------------------------------------

test("FACS denies the open before signing is ever consulted",
    { spec = "PKM *sig.facs.open-denied-before-signing" }, function(t)
        -- The file carries perfectly good signing material; its
        -- descriptor withholds FILE_EXECUTE from the caller. If signing
        -- ran first the lookup would leave a trace event behind.
        local path = signing.place(vm, B .. "/unreachable",
            signing.craft({}),
            { xattr = XATTR,
              rights = kacs.ALL_RIGHTS & ~kacs.RIGHT.EXECUTE })
        local events = signing.trace(vm, { signing.EV_PROBE }, function()
            kacs.as_dacl_bound(t, vm, function(w)
                t:assert_eq(psb.execve(w, path), sys.E.ACCES,
                    "the exec is refused by FACS with EACCES")
            end)
        end)
        t:assert_eq(#signing.of(events, "kacs_signing_probe"), 0,
            "and the signature lookup never ran")
        -- The same file, executable, does reach the lookup — so the
        -- absence above is the descriptor and not the fixture.
        kacs.set_sd(vm, path, kacs.grant(kacs.ALL_RIGHTS))
        local after = signing.exec_traced(vm, { signing.EV_PROBE }, path)
        t:assert_eq(#signing.of(after, "kacs_signing_probe"), 1,
            "once the descriptor grants FILE_EXECUTE the lookup runs")
    end)
