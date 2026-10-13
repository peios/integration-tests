-- PEI-1444: malformed stored descriptors arrive from an offline image;
-- the guest's prohibition on forging the canonical xattr remains intact.
local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local kmes = require("helpers.kmes")
local stratafs = require("helpers.stratafs")
local image = require("helpers.image")
local vm = provium:vm("corrupt-descriptor", "kernel-only"):boot()

for _, policy in ipairs({ kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL,
                         kacs.MOUNT_POLICY.SYNTHESIZE_PERSISTENT }) do
    test("a corrupt provider never falls back to synthesis policy " .. policy,
        { spec = "PKM *security.corrupt-descriptor-does-not-use-mount-policy" }, function(t)
            local at = "/corrupt-sd-" .. policy
            local release = image.mount(t, vm, {
                name = "corrupt-sd-" .. policy,
                host_image = "../fixtures/corrupt-descriptor.img",
                fstype = "ext2", at = at, policy = policy,
            })
            local merged = at .. "-merged"
            local mounted = false
            local ok, err = pcall(function()
                -- Give only the healthy ancestor/control their own descriptors.
                for _, suffix in ipairs({ "", "/good" }) do
                    local path = at .. "/stratum" .. suffix
                    local sd = kacs.get_sd(vm, path)
                    t:assert(sd, "healthy provider synthesizes a descriptor")
                    t:assert_eq(kacs.set_sd(vm, path, sd).ret, 0)
                end
                stratafs.mount(vm, { at = merged, strata = {
                    { path = at .. "/stratum", flags = { "create" } },
                } })
                mounted = true
                local good, e = kacs.open(vm, merged .. "/good")
                t:assert(good, "a stored valid descriptor permits the control: " .. sys.errname(e or 0))
                sys.close(vm, good)

                local events = kmes.recording(t, vm, function()
                    local bad, errno = kacs.open(vm, merged .. "/bad-file")
                    if bad then sys.close(vm, bad) end
                    t:assert(not bad, "a corrupt regular-file descriptor denies the open")
                    t:assert_eq(errno, sys.E.ACCES)
                end)
                t:assert(#kmes.of_type(events, "kacs.descriptor.rejected") > 0,
                    "the open takes the corrupt-descriptor cache/event path")

                local child, errno = sys.stat(vm, merged .. "/bad-dir/child")
                t:assert(not child and errno == sys.E.ACCES,
                    "merged-directory validation also refuses corrupt bytes")
                kacs.as_dacl_bound(t, vm, function(worker)
                    local missing, me = kacs.open(worker, merged .. "/missing")
                    t:assert(missing,
                        "a healthy provider can answer with a synthesized descriptor: " .. sys.errname(me or 0))
                    sys.close(worker, missing)
                    local direct, de = kacs.open(worker, at .. "/stratum/missing")
                    t:assert(direct, "the provider's synthesis policy is active: " .. sys.errname(de or 0))
                    sys.close(worker, direct)
                end)
                local direct, de = kacs.open(vm, at .. "/stratum/bad-file")
                if direct then sys.close(vm, direct) end
                t:assert(not direct and de == sys.E.ACCES,
                    "even direct provider synthesis cannot replace a corrupt descriptor")
            end)
            if mounted then stratafs.umount(vm, merged) end
            release()
            if not ok then error(err, 0) end
        end)
end
