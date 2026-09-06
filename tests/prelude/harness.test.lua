-- The two mechanisms every other file in this chapter is built on,
-- asserted directly so that a failure in one of them is diagnosed here
-- rather than as a puzzling failure somewhere downstream.
--
-- **Injection.** A test chooses prelude's hook graph by writing the
-- sequence file and the hooks themselves into the guest at boot, with
-- `files`. They ride in a cpio appended to the initramfs, which the
-- kernel unpacks last, so an injected path replaces whatever the profile
-- baked at the same path. That is what lets one initramfs cover graphs
-- that could not be built at the same time — a cycle, an unsatisfied
-- requirement, a sequence version prelude does not understand.
--
-- **Halting.** prelude does not limp: a boot it cannot complete ends with
-- the machine halted, so no agent ever appears and `vm:boot()` fails.
-- That failure is an asserted outcome here, not an error, and the guest
-- console comes back in its message — which is the only way to see a
-- boot that leaves nothing behind to ask.

local prelude = require("helpers.prelude")

test("an injected sequence replaces the one mkirf baked into the initramfs",
    {}, function(t)
        local vm = provium:vm("inject", "prelude")
        vm:boot({ files = prelude.files({
            hooks = { one = { contributes = { "rootfs-ready" } } },
            keep = { "pt-mount-root.sh" },
        }) })

        local log = vm:console():read_log()
        t:assert(log:find("pt|one|outcome=satisfied", 1, true),
            "the injected hook ran")
        t:assert(not log:find("pt|topology|", 1, true),
            "and the profile's own hooks did not: the injected sequence is the whole list")
        t:assert(log:find("ran 2 hook invocation(s)", 1, true),
            "two hooks, not the profile's three")
    end)

test("a boot prelude refuses halts the machine, and its console says why",
    {}, function(t)
        local vm = provium:vm("halt", "prelude")
        local ok, err = pcall(function()
            vm:boot({ kernel_cmdline_append = "pt.mount-root=decline" })
        end)
        t:assert(not ok, "the boot failed rather than reaching an agent")
        err = tostring(err)
        t:assert(err:find("pt|mount-root|outcome=declined", 1, true),
            "the hook declined")
        t:assert(err:find("no hook mounted a root filesystem at /mnt/rootfs", 1, true),
            "and prelude refused the boot for want of a root: " .. err:sub(-400))
        t:assert(err:find("halting system", 1, true), "then halted")
    end)
