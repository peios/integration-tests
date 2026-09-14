-- §5.8.2: root GUIDs are checked for uniqueness within one request, and
-- against every existing slot: a request whose root GUID is already the
-- root of a differently-named hive is refused EEXIST.
--
-- Its own file because the kernel used to disagree in a way that took
-- the whole VM with it (PEI-769): the second registration was admitted,
-- and from then on the slot table failed its own consistency check, so
-- every later registration and every hive route returned EINVAL. Kept
-- separate so a regression cannot take the rest of the testset down.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")

local vm = provium:vm("v", "kernel-only"):boot()

test("a root GUID already held by another slot is refused, and the registry keeps working",
    { spec = "PKM *source.register.root-guids-compared-across-slots" }, function(t)
        local machine = lcs.source(vm)
        machine:key("Machine\\Software\\Test")
        assert(machine:register())
        machine:pump()
        local w = vm:spawn_worker()

        local shared = lcs.guid()
        local a = lcs.source(vm, { hives = { { name = "RootShareA", root = shared } } })
        t:assert(a:register(), "the first source registers the root")
        local b = lcs.source(vm, { hives = { { name = "RootShareB", root = shared } } })
        t:assert(not b:register(),
            "a second slot may not reuse it: an incoming request's roots are " ..
            "compared against existing slots")
        t:assert_eq(b.errno, sys.E.EXIST,
            "refused as a collision: " .. sys.errname(b.errno or 0))

        -- Refused at admission, nothing was admitted, so nothing else
        -- changed: the table stays consistent.
        local later = lcs.source(vm, { hives = { { name = "RootShareC" } } })
        t:assert(later:register(),
            "an unrelated source still registers afterwards: " ..
            sys.errname(later.errno or 0))
        local r = lcs.open_key(machine, w, -1, "Machine\\Software\\Test", lcs.RIGHT.KEY_READ)
        t:assert(r.ret >= 0,
            "and an unrelated hive still routes: " .. sys.errname(r.errno or 0))
        if r.ret >= 0 then sys.close(w, r.ret) end
    end)
