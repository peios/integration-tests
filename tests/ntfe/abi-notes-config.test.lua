-- PKM §6.B — "Build configuration": what CONFIG_PEIOS_NTFE depends on,
-- what CONFIG_PEIOS_NTFE_KUNIT defaults to, what the production fragment
-- sets and what the config gate asserts.
--
-- These are properties of the kernel build. The one with a consequence a
-- running kernel shows — NTFE in, nf_tables and xtables out — is checked
-- on the kernel under test; the rest are cited as skips naming the file
-- that holds them.
--
-- Own VM: nothing here changes state, but every file boots its own.

local sys = require("helpers.sys")
local fixtures = require("helpers.fixtures")
local ntfe = require("helpers.ntfe")

local vm = provium:vm("vntfeabicfg", "kernel-only"):boot()

test("CONFIG_PEIOS_NTFE depends on SECURITY_PKM, NETFILTER_INGRESS, NETFILTER_EGRESS and a built-in conntrack",
    { spec = "PKM *ntfe-abi-notes.config-ntfe-dependencies",
      covered_by = "build:pkm/ntfe/Kconfig",
      skip = "a Kconfig dependency is enforced when the kernel is configured; " ..
             "the kernel under test exists because the configuration satisfied it" },
    function(t) end)

test("CONFIG_PEIOS_NTFE_KUNIT builds pkm_kunit_ntfe and defaults to SECURITY_PKM_KUNIT",
    { spec = "PKM *ntfe-abi-notes.config-kunit-default",
      covered_by = "build:pkm/ntfe/Kconfig",
      skip = "a Kconfig default; the guest has no decompressor for /proc/config.gz " ..
             "and the KUnit suite runs at build time, not in this VM" },
    function(t) end)

test("the production fragment enables NTFE and configures nf_tables and xtables out",
    { spec = "PKM *ntfe-abi-notes.production-fragment-ntfe-on-nftables-off" }, function(t)
        local st = sys.stat(vm, ntfe.DEVICE)
        t:assert(st, "NTFE is built in: its device exists with no module loaded")
        local dev = assert(ntfe.open(vm))
        t:assert_eq(assert(ntfe.status(vm, dev)).abi, ntfe.ABI, "and answers")
        sys.close(vm, dev)
        for _, path in ipairs({
            "/sys/module/nf_tables", "/proc/net/ip_tables_names",
            "/proc/net/ip6_tables_names", "/sys/module/x_tables",
        }) do
            t:assert(not fixtures.present(vm, path), path .. " does not exist")
        end
    end)

test("kernel/verify-kernel-config.sh asserts what the fragment sets",
    { spec = "PKM *ntfe-abi-notes.verify-kernel-config-asserts-fragment",
      covered_by = "build:pkm/kernel/verify-kernel-config.sh",
      skip = "a property of the kernel build, which fails when the gate does; " ..
             "the kernel under test exists because it passed" },
    function(t) end)
