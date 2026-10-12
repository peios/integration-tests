-- PEI-772: recursive backup must retain parent identity while its staging
-- array grows. A named-layer definition exposed this by enlarging the tree;
-- ordinary keys can trigger the same failure.
local sys = require("helpers.sys")
local lcs = require("helpers.lcs")
local kacs = require("helpers.kacs")

local vm = provium:vm("v", "kernel-only"):boot()
assert(kacs.new_mount(vm, "tmpfs", "/streams", kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL))
local hive = lcs.guid()

for _, case in ipairs({
    { name = "ordinary keys", layer = false },
    { name = "an unused named layer", layer = true },
    { name = "values in a named layer", layer = true, used = true },
}) do
    test("whole-hive backup preserves a branching tree with " .. case.name,
        { tags = { "pei772" }, spec = {
            "PKM *backup.exports-the-key-and-its-subtree",
            "PKM *backup.stream.depth-first-pre-order",
        } }, function(t)
            local src = lcs.source(vm, { hives = {{ name = "Machine", root = hive }} })
            local expected, links, values = { [hive] = true }, {}, {}
            local function add(path, parent, name)
                local guid = src:key(path)
                expected[guid] = true
                links[guid] = { parent = parent, name = name }
                local value = lcs.dword(#values + 1)
                src:value(guid, "Marker", lcs.TYPE.DWORD, value)
                values[#values + 1] = { guid = guid, data = value, layer = "base" }
                return guid
            end
            -- 35 descendants cross four growth boundaries and leave siblings
            -- to visit after recursion has relocated their parent's record.
            for branch = 1, 5 do
                local name = "Branch" .. branch
                local path = "Machine\\" .. name
                local parent = add(path, hive, name)
                for leaf = 1, 3 do
                    local leaf_name = "Leaf" .. leaf
                    local child_path = path .. "\\" .. leaf_name
                    local child = add(child_path, parent, leaf_name)
                    add(child_path .. "\\Twig", child, "Twig")
                end
            end
            if case.layer then
                src:seed_layer("Over", { precedence = 10, enabled = true,
                    owner = case.used and kacs.SID.ADMINISTRATORS or nil })
                if case.used then
                    src:value(hive, "LayerValue", lcs.TYPE.DWORD, lcs.dword(42), { layer = "Over" })
                end
            end
            assert(src:register())
            src:pump()
            local w = vm:spawn_worker()
            local ok, err = pcall(function()
                local fd = lcs.open_key(src, w, -1, "Machine", lcs.KEY_ALL_ACCESS).ret
                t:assert(fd >= 0, "the hive opens")
                local result, stream = lcs.backup_to_file(src, w, fd, "/streams/tree")
                sys.close(w, fd)
                t:assert_eq(result.ret, 0, "backup: " .. sys.errname(result.errno or 0))
                t:assert(stream.count_ok and stream.checksum_ok, "the complete stream has a valid trailer")
                local positions, anchors, markers = {}, {}, {}
                for index, key in ipairs(stream.keys) do
                    t:assert(not positions[key.guid], "each key is exported exactly once")
                    positions[key.guid] = index
                end
                for _, entry in ipairs(stream.path_entries) do
                    if links[entry.child] then
                        t:assert(not anchors[entry.child], "each base child has one parent anchor")
                        anchors[entry.child] = entry
                    end
                end
                for _, value in ipairs(stream.values) do
                    if value.name == "Marker" then markers[value.key_guid] = value end
                end
                for guid in pairs(expected) do t:assert(positions[guid], "every data key survives traversal") end
                for guid, link in pairs(links) do
                    local anchor = anchors[guid]
                    t:assert(anchor, "every child has an anchor")
                    t:assert_eq(anchor.parent, link.parent, "the original parent GUID is retained")
                    t:assert_eq(anchor.name, link.name, "the child name is retained")
                    t:assert(positions[link.parent] < positions[guid], "parents precede children")
                end
                for _, expected_value in ipairs(values) do
                    local actual = markers[expected_value.guid]
                    t:assert(actual, "every data key keeps its value")
                    t:assert_eq(actual.data, expected_value.data, "the value bytes are retained")
                    t:assert_eq(actual.layer, expected_value.layer, "the value layer is retained")
                end
                local over
                for _, layer in ipairs(stream.layers) do if layer.name == "Over" then over = layer end end
                if case.used then
                    t:assert(over, "the referenced layer has a manifest")
                    t:assert_eq(over.owner, kacs.SID.ADMINISTRATORS, "the layer owner survives")
                    local found = false
                    for _, value in ipairs(stream.values) do
                        if value.name == "LayerValue" then
                            found = value.key_guid == hive and value.layer == "Over" and value.data == lcs.dword(42)
                        end
                    end
                    t:assert(found, "the named-layer value survives")
                else
                    t:assert(not over, "an unreferenced layer needs no manifest")
                end
            end)
            w:kill(); w:join(); src:close()
            if not ok then error(err, 0) end
        end)
end
