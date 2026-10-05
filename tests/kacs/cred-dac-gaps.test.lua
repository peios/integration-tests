-- PKM §3.10.2 — the LSM stack: Yama is not among the non-MAC LSMs that
-- stack with KACS, and is not built. Its relational ptrace_scope would
-- decide every attach to a non-descendant ahead of the process
-- descriptor and PIP dominance (§3.7).
--
-- "Not built" has two independent witnesses in a running guest: the
-- registered stack in securityfs/lsm, and the kernel.yama sysctl
-- directory Yama registers when it initialises. (The kernel-only guest
-- carries no copy of the build configuration: its root is the initramfs,
-- and the composed root holds only /boot.)
--
-- Belongs in cred-dac.test.lua after "non-MAC LSMs stack safely
-- alongside KACS" — whose allowed set still lists yama, and counts it
-- towards the non-MAC LSMs it looks for; that should go.

local sys = require("helpers.sys")
local hooks = require("helpers.hooks")

local vm = provium:vm("vcreddacgaps", "kernel-only"):boot()

--- The registered LSM list, from securityfs.
local function registered_lsms()
    assert(hooks.hook_path(vm, "unused"))   -- mounts securityfs once
    local fd, errno = sys.open(vm, hooks.SECURITYFS_AT .. "/lsm", sys.O.RDONLY)
    assert(fd, "open securityfs/lsm: " .. sys.errname(errno or 0))
    local data = sys.read(vm, fd, 512)
    sys.close(vm, fd)
    local out = {}
    for name in (data or ""):gmatch("[%w_]+") do out[name] = true end
    return out, data
end

test("Yama is not registered in the LSM stack",
    { spec = "PKM *cred.dac.yama-not-built" }, function(t)
        local present, raw = registered_lsms()
        t:assert(present.pkm, "the list is the real one — KACS is on it: " .. tostring(raw))
        t:assert(not present.yama, "yama is not registered: " .. tostring(raw))
    end)

test("Yama's ptrace_scope sysctl does not exist",
    { spec = "PKM *cred.dac.yama-not-built" }, function(t)
        -- The control: /proc/sys/kernel is there and populated.
        t:assert(sys.stat(vm, "/proc/sys/kernel/osrelease"), "/proc/sys/kernel is mounted")
        local st, errno = sys.stat(vm, "/proc/sys/kernel/yama")
        t:assert(not st, "the kernel.yama sysctl directory is absent")
        t:assert_eq(errno, sys.E.NOENT, "ENOENT: " .. sys.errname(errno or 0))
    end)
