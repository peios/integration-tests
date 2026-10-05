-- PKM §3.13 — a private mount table seen from inside and from outside:
-- an unprivileged copy is a slave of the table it came from, an ordinary
-- program can make a directory of its choosing its whole world, and
-- none of that buys it any authority over the objects it rearranged.
--
-- The private-root case is PEI-1173's acceptance demonstration: a real
-- program (tests/tools/pt-mntns), run under a minted principal holding
-- no privilege and making no user namespace, unshares, bind mounts a
-- directory, pivots onto it and lists `/`.
--
-- Every namespace change happens on a worker: the agent is PID 1 and
-- its own table is the initial one.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local token = require("helpers.token")
local facs = require("helpers.facs")

local vm = provium:vm("vmntnsroot", "kernel-only"):boot()

-- A minted principal holds no SeChangeNotifyPrivilege; `/` grants
-- traverse instead, so nothing here hands one a privilege to walk.
kacs.set_sd(vm, "/", kacs.grant(kacs.ALL_RIGHTS))
local B = facs.workspace(vm, "mntns-root")

local P = token.PRIV
local MANAGE_VOLUME = token.bit(P.MANAGE_VOLUME)
local NR = { unshare = 272 }
local CLONE_NEWNS = 0x00020000
local MS = { BIND = 4096, SHARED = 1 << 20 }
local MNT_DETACH = 2
local R = kacs.RIGHT

local function principal(privs, over)
    local s = { privs_present = privs or 0, privs_enabled = privs or 0 }
    for k, v in pairs(over or {}) do s[k] = v end
    return s
end

local function pid_of(w) return w:syscall(sys.NR.getpid).ret end
local function unshare(w) return w:syscall(NR.unshare, CLONE_NEWNS) end
local function bind(w, from, to)
    return sys.mount(w, { source = from, target = to, flags = MS.BIND })
end
local function ok(t, r, what)
    t:assert_eq(r.ret, 0, what .. ": " .. sys.errname(r.errno or 0))
end

--- The mountinfo line whose mount point is `path`, from `file`.
local function mount_line(file, path)
    local found
    for line in vm:read_file(file):gmatch("[^\n]+") do
        local point = line:match("^%S+ %S+ %S+ %S+ (%S+)")
        if point == path then found = line end
    end
    return found
end

--- The optional fields of a mountinfo line, as one string.
local function optional(line)
    return line and line:match("^%S+ %S+ %S+ %S+ %S+ %S+ (.-) %- ") or ""
end

-- A slave copy -------------------------------------------------------------------

test("a table created without the mount privilege receives its mounts as slaves of the parent's",
    { spec = "PKM *mntns.unprivileged-copy-is-slave" }, function(t)
        -- Something to propagate: a shared mount in the initial table.
        -- Every mount the kernel-only root starts with is private, which
        -- would make a slave copy indistinguishable from a peer one.
        local D = B .. "/shared"
        for _, d in ipairs({ D, D .. "/in", D .. "/out", D .. "/peer", B .. "/src" }) do
            vm:mkdir(d, { parents = true })
        end
        vm:write_file(B .. "/src/marker", "src")
        ok(t, bind(vm, D, D), "the agent makes the directory a mount")
        ok(t, sys.mount(vm, { target = D, flags = MS.SHARED }), "and shares it")
        local agent_line = assert(mount_line("/proc/self/mountinfo", D))
        local group = optional(agent_line):match("shared:(%d+)")
        t:assert(group, "it is a peer group in the initial table: " .. agent_line)

        local ran, err = pcall(function()
            -- The unprivileged copy, and the privileged one beside it.
            local plain = vm:spawn_worker()
            local privileged = vm:spawn_worker()
            local inner, inner_err = pcall(function()
                for _, w in ipairs({ { plain, principal() },
                                     { privileged, principal(MANAGE_VOLUME) } }) do
                    local fd, e = token.mint(w[1], w[2])
                    assert(fd, "mint: " .. sys.errname(e or 0))
                    assert(token.install(w[1], fd).ret == 0, "install")
                    ok(t, unshare(w[1]), "unshare")
                end
                local plain_info = "/proc/" .. pid_of(plain) .. "/mountinfo"
                local priv_info = "/proc/" .. pid_of(privileged) .. "/mountinfo"

                local slave = optional(mount_line(plain_info, D))
                t:assert_eq(slave:match("master:(%d+)"), group,
                    "the unprivileged copy is a slave of the parent's peer group: " .. slave)
                t:assert(not slave:find("shared:", 1, true),
                    "and no peer of it: " .. slave)
                local peer = optional(mount_line(priv_info, D))
                t:assert_eq(peer:match("shared:(%d+)"), group,
                    "the privileged copy is copied as upstream copies it, a peer: " .. peer)

                -- Parent to child: the agent's new mount reaches the copy.
                ok(t, bind(vm, B .. "/src", D .. "/in"), "the agent mounts under the shared mount")
                t:assert(mount_line(plain_info, D .. "/in"),
                    "and it propagates into the unprivileged copy")

                -- Child to parent: never.
                ok(t, bind(plain, B .. "/src", D .. "/out"),
                    "the unprivileged creator mounts in its copy")
                t:assert(not mount_line("/proc/self/mountinfo", D .. "/out"),
                    "and nothing appears in the table it copied")
                t:assert(not mount_line(priv_info, D .. "/out"),
                    "nor in the parent's other copies")

                -- Whereas a peer copy's mount does come back.
                ok(t, bind(privileged, B .. "/src", D .. "/peer"),
                    "the privileged creator mounts in its copy")
                t:assert(mount_line("/proc/self/mountinfo", D .. "/peer"),
                    "and it propagates to its peer in the initial table")
            end)
            for _, w in ipairs({ plain, privileged }) do w:kill(); w:join() end
            if not inner then error(inner_err, 0) end
        end)
        for _, m in ipairs({ D .. "/peer", D .. "/in", D }) do
            sys.umount(vm, m, MNT_DETACH)
        end
        if not ran then error(err, 0) end
    end)

-- A private root ------------------------------------------------------------------

--- tests/tools/pt-mntns, staged into the workspace and executable by
--- everyone.
local HELPER = (function()
    local pipe = assert(io.popen("sh tests/tools/build.sh pt-mntns", "r"))
    local path = pipe:read("*l")
    assert(pipe:close() and path and path ~= "", "could not build pt-mntns")
    local f = assert(io.open(path, "rb"))
    local bytes = f:read("*a")
    f:close()
    local at = B .. "/pt-mntns"
    vm:write_file(at, bytes)
    sys.chmod(vm, at, tonumber("755", 8))
    kacs.set_sd(vm, at, kacs.grant(kacs.ALL_RIGHTS))
    return at
end)()

test("an ordinary user unshares, bind mounts a directory, pivots onto it and lists /",
    { spec = "PKM *mntns.private-root-sequence" }, function(t)
        local world = B .. "/world"
        vm:mkdir(world .. "/etc", { parents = true })
        vm:mkdir(world .. "/home", { parents = true })
        vm:write_file(world .. "/README", "a world of my own")
        local before = vm:read_file("/proc/self/mountinfo")

        token.as_principal(t, vm, {}, function(w)
            local self = assert(token.open_self(w, token.RIGHT.QUERY))
            t:assert_eq(assert(token.privileges(w, self)).present, 0,
                "the principal holds no privilege at all")
            sys.close(w, self)
            local user_ns = assert(sys.readlink(w, "/proc/self/ns/user"))

            local run = w:run(HELPER, { args = { "root", world }, timeout = "20s" })
            t:assert_eq(run.exit_code, 0, "pt-mntns root runs to the end:\n" .. tostring(run.stdout))
            for _, s in ipairs({ "unshare", "bind", "chdir-dir", "pivot_root", "umount",
                                 "chdir-root" }) do
                t:assert(run.stdout:find("step " .. s .. " ok", 1, true),
                    s .. " succeeds:\n" .. run.stdout)
            end
            local entries = {}
            for name in run.stdout:gmatch("entry (%S+)") do entries[#entries + 1] = name end
            table.sort(entries)
            t:assert_eq(table.concat(entries, " "), "README etc home",
                "`/` is the chosen directory and nothing else:\n" .. run.stdout)
            t:assert(run.stdout:find("\ndone", 1, true), "and the listing completes")

            t:assert_eq(sys.readlink(w, "/proc/self/ns/user"), user_ns,
                "no user namespace was involved")
        end)
        t:assert_eq(vm:read_file("/proc/self/mountinfo"), before,
            "and the initial table is exactly as it was")
    end)

-- No new authority ----------------------------------------------------------------

test("a private table confers no authority: a bind mount shows a name and denies at open",
    { spec = "PKM *mntns.no-new-authority" }, function(t)
        -- `secret` grants the principal nothing; `mine` grants it
        -- everything. Binding the first over the second — a fake file at
        -- a name the principal controls — changes what the name shows,
        -- not who may open what is behind it.
        local secret, mine = B .. "/secret", B .. "/mine"
        local secret_dir, mine_dir = B .. "/secret-dir", B .. "/mine-dir"
        vm:write_file(secret, "not yours")
        vm:write_file(mine, "yours")
        vm:mkdir(secret_dir, { parents = true })
        vm:write_file(secret_dir .. "/inside", "x")
        vm:mkdir(mine_dir, { parents = true })
        kacs.set_sd(vm, secret, kacs.descriptor(kacs.acl({
            kacs.ace(kacs.ACE_ALLOWED, kacs.ALL_RIGHTS, token.SID.LOCAL_SYSTEM) })))
        kacs.set_sd(vm, secret_dir, kacs.descriptor(kacs.acl({
            kacs.ace(kacs.ACE_ALLOWED, kacs.ALL_RIGHTS, token.SID.LOCAL_SYSTEM) })))
        kacs.set_sd(vm, mine, kacs.grant(kacs.ALL_RIGHTS))

        token.as_principal(t, vm, {}, function(w)
            local fd = assert(sys.open(w, mine, sys.O.RDONLY))
            t:assert_eq(sys.read(w, fd, 16), "yours", "the principal reads its own file")
            sys.close(w, fd)
            local _, e0 = sys.open(w, secret, sys.O.RDONLY)
            t:assert_eq(e0, sys.E.ACCES, "and cannot read the secret: " .. sys.errname(e0 or 0))

            ok(t, unshare(w), "unshare")
            ok(t, bind(w, secret, mine), "the secret is bound over its own file")
            ok(t, bind(w, secret_dir, mine_dir), "the secret directory over its own directory")

            local got, e = sys.open(w, mine, sys.O.RDONLY)
            t:assert(not got, "opening its own name now reaches the secret, and is refused")
            t:assert_eq(e, sys.E.ACCES, "EACCES, decided on the real object: " ..
                sys.errname(e or 0))
            if got then sys.close(w, got) end
            local dfd, de = sys.open(w, mine_dir, sys.O.RDONLY | sys.O.DIRECTORY)
            t:assert(not dfd, "listing its own directory name is refused too")
            t:assert_eq(de, sys.E.ACCES, "EACCES: " .. sys.errname(de or 0))
            if dfd then sys.close(w, dfd) end

            -- The process's identity is untouched by the table it built.
            local self = assert(token.open_self(w, token.RIGHT.QUERY))
            t:assert_eq(token.query(w, self, token.CLASS.USER), token.SID.TEST_USER,
                "it is still TEST_USER")
            t:assert_eq(assert(token.privileges(w, self)).present, 0, "holding nothing")
            sys.close(w, self)
        end)
    end)
