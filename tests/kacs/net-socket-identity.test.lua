-- PKM §3.12.2 — socket identity: KACS records on every AF_INET and
-- AF_INET6 socket the identity that governs its traffic, taken at each
-- act that commits the socket to a role, and the network policy engine
-- reads it later.
--
-- Nothing in userspace reads the stamp back — `pkm_kacs_socket_owner()`
-- is a kernel API for the policy engine — so what a guest can witness
-- is the act of stamping, through the `kacs:kacs_socket_token`
-- tracepoint whose `max_imp` field carries the owner kind (1 program,
-- 2 kernel). The shape of what was stamped is KUnit's to check.
--
-- The kernel-socket case is driven by unshare(CLONE_NEWNET): setting up
-- a network namespace creates the per-namespace control sockets with
-- `sock_create_kern`, which is the one way a guest makes the kernel
-- open an inet socket.

local sys = require("helpers.sys")
local token = require("helpers.token")
local hooks = require("helpers.hooks")
local netobj = require("helpers.netobj")

local vm = provium:vm("vnetsock", "kernel-only"):boot()

local EVENT = "kacs/kacs_socket_token"
local CLONE_NEWNET = 0x40000000
local NR_unshare = 272
local OWNER_PROGRAM, OWNER_KERNEL = 1, 2

--- Run `fn` with the socket-identity tracepoint enabled and return the
--- `reason=owner` lines it produced.
local function stamps(t, fn)
    t:assert(hooks.trace_start(vm, EVENT), "tracing starts")
    local ok, err = pcall(fn)
    local lines = hooks.trace_stop(vm, EVENT)
    if not ok then error(err, 0) end
    t:assert(lines, "the buffer reads back")
    local owners = {}
    for _, line in ipairs(lines) do
        if line:match("reason=owner") then owners[#owners + 1] = line end
    end
    return owners
end

local function field(line, name)
    return tonumber(line:match(name .. "=(%d+)"))
end

test("an AF_INET or AF_INET6 socket is stamped; an AF_UNIX socket is not",
    { spec = "PKM *net.socket.stamp-on-inet-sockets" }, function(t)
        local inet4 = stamps(t, function()
            local fd = assert(netobj.socket(vm, netobj.AF_INET))
            sys.close(vm, fd)
        end)
        t:assert_eq(#inet4, 1, "creating an AF_INET socket stamps it once")
        t:assert_eq(field(inet4[1], "family"), netobj.AF_INET, "for AF_INET")

        local inet6 = stamps(t, function()
            local fd = assert(netobj.socket(vm, netobj.AF_INET6))
            sys.close(vm, fd)
        end)
        t:assert_eq(#inet6, 1, "and an AF_INET6 socket likewise")
        t:assert_eq(field(inet6[1], "family"), netobj.AF_INET6, "for AF_INET6")

        local unix = stamps(t, function()
            local fd = assert(netobj.socket(vm, 1))   -- AF_UNIX
            sys.close(vm, fd)
        end)
        t:assert_eq(#unix, 0,
            "an AF_UNIX socket carries the peer-identity machinery of §3.5 instead")
    end)

test("the stamp is the effective token plus the process facts of that moment",
    { spec = "PKM *net.socket.stamp-contents",
      covered_by = "kunit:pkm_kunit_token",
      skip = "the stamp is read only by pkm_kacs_socket_owner(), a kernel " ..
             "API with no userspace surface, so the token pointer, process " ..
             "GUID, tgid and comm cannot be compared from the guest; runs " ..
             "under pkm_kunit_socket_owner_is_stamped_at_creation" },
    function(t) end)

test("every act that commits the socket to a role stamps it again",
    { spec = "PKM *net.socket.last-act-governs" }, function(t)
        local listener = stamps(t, function()
            local fd = assert(netobj.socket(vm, netobj.AF_INET))
            local r = vm:syscall(netobj.NR.bind, {
                args = { fd, 0, 16 }, bufs = { netobj.sockaddr_in(9310) }, ptrs = { 1 },
            })
            t:assert_eq(r.ret, 0, "bind: " .. sys.errname(r.errno))
            t:assert_eq(vm:syscall(netobj.NR.listen, fd, 5).ret, 0, "listen")
            t:assert_eq(netobj.restamp(vm, fd).ret, 0, "KACS_SO_RESTAMP")
            sys.close(vm, fd)
        end)
        t:assert_eq(#listener, 4,
            "creation, bind, listen and the restamp each stamped: " .. #listener)
        for i, line in ipairs(listener) do
            t:assert_eq(field(line, "family"), netobj.AF_INET, "stamp " .. i .. " is the socket's")
            t:assert_eq(field(line, "max_imp"), OWNER_PROGRAM,
                "and a program's: " .. line)
        end

        local connector = stamps(t, function()
            local fd = assert(netobj.socket(vm, netobj.AF_INET))
            -- Connecting to a port nothing listens on still commits the
            -- socket: the hook runs before the stack answers.
            vm:syscall(netobj.NR.connect, {
                args = { fd, 0, 16 }, bufs = { netobj.sockaddr_in(9311) }, ptrs = { 1 },
            })
            sys.close(vm, fd)
        end)
        t:assert_eq(#connector, 2, "creation and connect stamp: " .. #connector)
    end)

test("a kernel socket is stamped as the kernel's, with no token",
    { spec = "PKM *net.socket.kernel-socket-stamp" }, function(t)
        local worker = vm:spawn_worker()
        local kernel_stamps
        local ok, err = pcall(function()
            kernel_stamps = stamps(t, function()
                -- A new network namespace: the kernel opens the per-namespace
                -- control sockets with sock_create_kern.
                local r = worker:syscall(NR_unshare, CLONE_NEWNET)
                t:assert_eq(r.ret, 0, "unshare(CLONE_NEWNET): " .. sys.errname(r.errno))
            end)
        end)
        worker:kill(); worker:join()
        if not ok then error(err, 0) end
        t:assert(#kernel_stamps > 0, "the kernel's own sockets are stamped too")
        for _, line in ipairs(kernel_stamps) do
            t:assert_eq(field(line, "max_imp"), OWNER_KERNEL,
                "as the kernel's, kind 2: " .. line)
        end
    end)

test("an accepted socket inherits its listener's stamp",
    { spec = "PKM *net.socket.accept-inherits",
      covered_by = "kunit:pkm_kunit_token",
      skip = "inheritance happens in sk_clone_security, which emits no " ..
             "tracepoint and has no userspace surface, so the child's stamp " ..
             "cannot be compared with the listener's from the guest; runs " ..
             "under pkm_kunit_socket_owner_is_inherited_at_accept" },
    function(t) end)

test("KACS_SO_RESTAMP is self-gated: any caller may restamp its own socket",
    { spec = "PKM *net.socket.restamp-self-gated" }, function(t)
        token.as_principal(t, vm, {}, function(w)
            -- A principal holding no privilege at all, on a socket in
            -- every state: a program can always attest to what it is.
            local fresh = assert(netobj.socket(w, netobj.AF_INET))
            t:assert_eq(netobj.restamp(w, fresh).ret, 0,
                "an unbound socket restamps")
            -- Port 0: this VM has no registry table, so the compiled-in
            -- fallback admits SYSTEM alone and an ephemeral bind is the
            -- one a principal can make (§3.12.1).
            local bound, fd = netobj.bind(w, 0, { keep = true })
            t:assert_eq(bound.ret, 0, "a bound one: " .. sys.errname(bound.errno))
            t:assert_eq(netobj.restamp(w, fd).ret, 0, "restamps too")
            t:assert_eq(w:syscall(netobj.NR.listen, fd, 5).ret, 0, "and once listening")
            t:assert_eq(netobj.restamp(w, fd).ret, 0, "still restamps")
            sys.close(w, fresh); sys.close(w, fd)
            -- The AF_UNIX form of the option is the listener hand-off of
            -- §3.5 and needs a listening socket; an inet socket needs no
            -- state at all.
            local unix = assert(netobj.socket(w, 1))
            local r = netobj.restamp(w, unix)
            t:assert_eq(r.ret, -1, "on a non-listening AF_UNIX socket it is refused")
            t:assert_eq(r.errno, sys.E.INVAL, "EINVAL")
            sys.close(w, unix)
        end)
        -- And the restamp really is a stamp: it emits one.
        local seen = stamps(t, function()
            local fd = assert(netobj.socket(vm, netobj.AF_INET))
            t:assert_eq(netobj.restamp(vm, fd).ret, 0, "the caller restamps")
            sys.close(vm, fd)
        end)
        t:assert_eq(#seen, 2, "creation plus the restamp")
    end)

test("a socket that never passed through the hooks reads as unstamped",
    { spec = "PKM *net.socket.unstamped-reads-kernel",
      covered_by = "kunit:pkm_kunit_token",
      skip = "every task on a running system carries a token, so the " ..
             "unstamped branch is unreachable from the guest; runs under " ..
             "pkm_kunit_socket_owner_is_stamped_at_creation, which reads an " ..
             "unstamped socket back" },
    function(t) end)

test("the engine reads the stamp through pkm_kacs_socket_owner with a counted reference",
    { spec = "PKM *net.socket.owner-accessor",
      covered_by = "kunit:pkm_kunit_token",
      skip = "pkm_kacs_socket_owner() and its _put() are a <linux/peios_pnp.h> " ..
             "kernel API with no syscall surface; runs under " ..
             "pkm_kunit_socket_owner_query_is_a_counted_reference" },
    function(t) end)

test("every stamp is traced with the owner kind",
    { spec = "PKM *net.socket.tracing" }, function(t)
        local program = stamps(t, function()
            local fd = assert(netobj.socket(vm, netobj.AF_INET))
            sys.close(vm, fd)
        end)
        t:assert_eq(#program, 1, "a program's socket emits one event")
        t:assert(program[1]:match("kacs_socket_token:"),
            "on kacs:kacs_socket_token: " .. program[1])
        t:assert(program[1]:match("reason=owner"), "with reason=owner")
        t:assert_eq(field(program[1], "max_imp"), OWNER_PROGRAM,
            "and max_imp carrying kind 1, a program")

        local worker = vm:spawn_worker()
        local kernel
        local ok, err = pcall(function()
            kernel = stamps(t, function()
                t:assert_eq(worker:syscall(NR_unshare, CLONE_NEWNET).ret, 0,
                    "a new network namespace")
            end)
        end)
        worker:kill(); worker:join()
        if not ok then error(err, 0) end
        t:assert(#kernel > 0, "the kernel's sockets emit events as well")
        t:assert_eq(field(kernel[1], "max_imp"), OWNER_KERNEL,
            "with max_imp carrying kind 2, the kernel: " .. kernel[1])
    end)
