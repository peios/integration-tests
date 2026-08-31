-- Does the harness reach a stratafs mount at all?
--
-- Kept deliberately small and first: when a stratafs case fails, this
-- says whether the filesystem misbehaved or the VM never got as far as
-- having one mounted.

local stratafs = require("helpers.stratafs")

local vm = provium:vm("v", "kernel-only"):boot()

test("a two-stratum stack mounts and merges",
    { spec = "PKM *strata.stack-fixed-and-ordered" }, function(t)
        stratafs.with(vm, "smoke", {
            { name = "upper", flags = { "create" }, entries = { ["only-upper"] = "u" } },
            { name = "lower", flags = { "ro" }, entries = { ["only-lower"] = "l" } },
        }, function(s)
            t:assert_eq(vm:read_file(s:join("only-upper")), "u",
                "the create stratum's file is visible")
            t:assert_eq(vm:read_file(s:join("only-lower")), "l",
                "and the read-only stratum's")
        end)
    end)

test("the highest-precedence stratum holding a name provides it",
    { spec = "PKM *strata.stack-fixed-and-ordered" }, function(t)
        stratafs.with(vm, "smoke-precedence", {
            { name = "upper", flags = { "create" }, entries = { f = "from upper" } },
            { name = "lower", flags = { "ro" }, entries = { f = "from lower" } },
        }, function(s)
            t:assert_eq(vm:read_file(s:join("f")), "from upper",
                "index 0 is the highest precedence")
        end)
    end)
