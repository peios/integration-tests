-- PKM §3.6 — the key table as securityfs shows it:
-- /sys/kernel/security/kacs/signing_keys lists one line per entry
-- before the terminator, `key_sha256=<hex> pip_type=<u32>
-- pip_trust=<u32>`, and reading it is not access-checked — it can be
-- opened once the mount has a synthesising policy, and whoever can open
-- it can read it.
--
-- What a guest cannot check is that the hash names the right key: the
-- kernel holds the public key in a data section nothing reads back, and
-- this file does not bind itself to whichever keyring built the image.
-- pkm_kunit_signing_key_listing_names_each_key does that binding
-- against the KUnit key. Table order and the listing of an entry the
-- validator would refuse need a table of more than the one valid key
-- this kernel carries.
--
-- securityfs has one superblock, and a mount's FACS class belongs to
-- the superblock, so the case that needs it still deny-missing runs
-- first, before anything mounts it with a policy.
--
-- Belongs in sig-keys.test.lua under "The table".

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local hooks = require("helpers.hooks")
local token = require("helpers.token")

local vm = provium:vm("v", "kernel-only"):boot()

local FILE = "/kacs/signing_keys"

--- Read a whole file as `who`. Returns text, or nil, errno and which of
--- open and read refused.
local function read_all(who, path)
    local fd, e = sys.open(who, path, sys.O.RDONLY)
    if not fd then return nil, e, "open" end
    local out = {}
    while true do
        local chunk, re = sys.read(who, fd, 4096)
        if not chunk then
            sys.close(who, fd)
            return nil, re, "read"
        end
        if #chunk == 0 then break end
        out[#out + 1] = chunk
    end
    sys.close(who, fd)
    return table.concat(out)
end

test("on a securityfs mount with no synthesising policy the listing cannot be opened",
    { spec = "PKM *sig.key-table.securityfs-unchecked" }, function(t)
        local at = "/sfs-plain"
        local ok, stage, errno = kacs.new_mount(vm, "securityfs", at, nil, nil)
        t:assert(ok, "securityfs mounts: " .. tostring(stage) .. " " .. sys.errname(errno or 0))
        local fd = sys.open(vm, at, sys.O.PATH)
        t:assert_eq(kacs.get_mount_policy(vm, fd), kacs.MOUNT_POLICY.DENY_MISSING,
            "the superblock is deny-missing")
        sys.close(vm, fd)
        local text, e, which = read_all(vm, at .. FILE)
        t:assert(not text, "even SYSTEM cannot read the listing there")
        t:assert_eq(e, sys.E.ACCES, "EACCES: " .. sys.errname(e or 0))
        t:assert_eq(which, "open", "refused at open, before the file's own read handler")
        sys.umount(vm, at, 0)
    end)

test("signing_keys lists each key as key_sha256, pip_type and pip_trust",
    { spec = "PKM *sig.key-table.securityfs-listing" }, function(t)
        t:assert(hooks.hook_path(vm, "unused"), "securityfs mounts with a synthesising policy")
        local text, e, which = read_all(vm, hooks.SECURITYFS_AT .. FILE)
        t:assert(text, "the listing reads: " .. sys.errname(e or 0) .. " on " .. tostring(which))
        -- The kernel this profile boots is the one the peinit profile
        -- runs TCB-signed binaries under, so its table holds a key.
        t:assert(#text > 0, "and is not empty")
        t:assert_eq(text:sub(-1), "\n", "every line is newline-terminated")
        local n = 0
        for line in text:gmatch("([^\n]*)\n") do
            n = n + 1
            local hex, ptype, ptrust =
                line:match("^key_sha256=(%x+) pip_type=(%d+) pip_trust=(%d+)$")
            t:assert(hex, "line " .. n .. " has exactly the three fields: " .. line)
            if hex then
                t:assert_eq(#hex, 64, "the key is named by a SHA-256: 64 hex digits")
                t:assert_eq(hex, hex:lower(), "in lowercase")
                -- The validator accepts no other tier, and a table it
                -- refused would disable every verification — the
                -- existing sig-keys case shows a real per-key trial.
                t:assert_eq(tonumber(ptype), 512, "pip_type in decimal: Protected")
                t:assert_eq(tonumber(ptrust), 8192, "pip_trust in decimal: PeiosTcb")
            end
        end
        t:assert(n >= 1, "one line per key, at least one key: " .. n)
        local again = read_all(vm, hooks.SECURITYFS_AT .. FILE)
        t:assert_eq(again, text, "and it reads the same each time")
    end)

test("reading signing_keys is not access-checked",
    { spec = "PKM *sig.key-table.securityfs-unchecked" }, function(t)
        t:assert(hooks.hook_path(vm, "unused"), "securityfs mounts with a synthesising policy")
        local path = hooks.SECURITYFS_AT .. FILE
        local as_system = assert(read_all(vm, path))
        -- An ordinary signed-in principal: no administrators, no
        -- privilege but traverse.
        local CHANGE_NOTIFY = token.bit(token.PRIV.CHANGE_NOTIFY)
        token.as_principal(t, vm, { privs_present = CHANGE_NOTIFY, privs_enabled = CHANGE_NOTIFY },
            function(w)
                local text, e, which = read_all(w, path)
                t:assert(text, "an ordinary principal reads the listing: "
                    .. sys.errname(e or 0) .. " on " .. tostring(which))
                t:assert_eq(text, as_system, "and reads exactly what SYSTEM reads")
                -- The control: the sessions file beside it on the same
                -- mount does check on read, and refuses this caller.
                local s, se, swhich = read_all(w, hooks.SECURITYFS_AT .. "/kacs/sessions")
                t:assert(not s, "the sessions listing, which is checked, refuses the same caller")
                t:assert_eq(se, sys.E.ACCES, "EACCES: " .. sys.errname(se or 0))
                t:assert_eq(swhich, "read", "at its own read check")
            end)
    end)
