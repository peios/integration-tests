-- §5.8.2: "Root GUIDs are checked for uniqueness within one request,
-- and the already-registered state is checked for consistency, but an
-- incoming request's root GUIDs are not compared against those of
-- existing slots."
--
-- Its own file because the kernel disagrees in a way that takes the
-- whole VM with it: the second registration is admitted, and from then
-- on the slot table fails its own consistency check, so every later
-- registration and every hive route returns EINVAL. Nothing can follow
-- it here.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")

local vm = provium:vm("v", "kernel-only"):boot()

test("two slots may hold the same hive root GUID, and the registry keeps working",
    { spec = "PKM *source.register.root-guids-not-compared-across-slots",
      tags = { "known-bug" } }, function(t)
        -- KERNEL BUG. The registration below is admitted, exactly as
        -- the manual says it should be. But the slot table it leaves
        -- behind is then rejected by validate_existing_source_slots
        -- (lcs-core source.rs, reached from validate_source_registration
        -- and for_each_source_slot_hive), so afterwards *every*
        -- registration fails EINVAL and *every* path walk fails EINVAL:
        -- the registry is unusable until reboot. Admitting a
        -- registration that makes the table permanently invalid is the
        -- contradiction — either the admission check should compare
        -- roots across slots, or the consistency check should not.
        local machine = lcs.source(vm)
        machine:key("Machine\\Software\\Test")
        assert(machine:register())
        machine:pump()
        local w = vm:spawn_worker()

        local shared = lcs.guid()
        local a = lcs.source(vm, { hives = { { name = "RootShareA", root = shared } } })
        t:assert(a:register(), "the first source registers the root")
        local b = lcs.source(vm, { hives = { { name = "RootShareB", root = shared } } })
        t:assert(b:register(),
            "and a second slot may reuse it: an incoming request's roots are not " ..
            "compared against existing slots")

        -- The manual says nothing else changed, so nothing else should
        -- have. Observed: EINVAL from both.
        local later = lcs.source(vm, { hives = { { name = "RootShareC" } } })
        t:assert(later:register(),
            "an unrelated source still registers afterwards: " ..
            sys.errname(later.errno or 0))
        local r = lcs.open_key(machine, w, -1, "Machine\\Software\\Test", lcs.RIGHT.KEY_READ)
        t:assert(r.ret >= 0,
            "and an unrelated hive still routes: " .. sys.errname(r.errno or 0))
        if r.ret >= 0 then sys.close(w, r.ret) end
    end)
