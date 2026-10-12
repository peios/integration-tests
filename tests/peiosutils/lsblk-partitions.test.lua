-- PEI-1206: libblkid must be asked for partition-entry details, not only
-- filesystem signatures. Only the VM's newly allocated scratch disk is written.
local peinit = require("helpers.peinit")
peinit.claim(1)

local vm = peinit.boot({
    name = "lsblk-gpt",
    boot = { disks = { { scratch = "128M", id = "partition-fixture" } } },
})
local disk = "/dev/vdb" -- profile medium is vda; this boot adds one scratch disk

local function run(command)
    local result = vm:run(command)
    result:assert_ok()
    return result.stdout
end

local function partition_guid(index)
    -- part creates 512-byte sectors with the entry array at LBA 2 and
    -- 128-byte entries. Read the unique GUID directly, independent of blkid.
    local offset = 1024 + (index - 1) * 128 + 16
    local bytes = {}
    for byte in run("od -An -tx1 -j" .. offset .. " -N16 " .. disk):gmatch("%x%x") do
        bytes[#bytes + 1] = byte:lower()
    end
    assert(#bytes == 16, "read exactly one partition GUID")
    local function part(indices)
        local out = {}
        for _, i in ipairs(indices) do out[#out + 1] = bytes[i] end
        return table.concat(out)
    end
    return table.concat({ part({4,3,2,1}), part({6,5}), part({8,7}),
        part({9,10}), part({11,12,13,14,15,16}) }, "-")
end

test("lsblk reports GPT partition type, label and unique GUID without a filesystem",
    { tags = { "pei1206" } }, function(t)
        run("part create " .. disk .. " --yes")
        run("part add " .. disk .. " --size 32M --type esp --name boot-one --yes")
        run("part add " .. disk .. " --size 32M --type linux --name 'Data two' --yes")
        wait_until(function() return pcall(vm.stat, vm, disk .. "2") end,
            { timeout = 15, interval = 0.1, desc = "scratch GPT partition nodes" })
        local output = run("lsblk --json -o NAME,PTTYPE,PARTTYPE,PARTLABEL,PARTUUID " .. disk)
        t:log(output)
        local result = json.decode(output)
        local rows = {}
        local function collect(devices)
            for _, row in ipairs(devices) do
                rows[row.name] = row
                if row.children then collect(row.children) end
            end
        end
        collect(result.blockdevices)
        t:assert_eq(rows.vdb.pttype, "gpt", "whole disk table type")
        for index, expected in ipairs({
            { type = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b", label = "boot-one" },
            { type = "0fc63daf-8483-4772-8e79-3d69d8477de4", label = "Data two" },
        }) do
            local row = rows["vdb" .. index]
            t:assert(row, "partition appears in lsblk")
            t:assert_eq(row.parttype, expected.type, "partition type GUID")
            t:assert_eq(row.partlabel, expected.label, "partition name, including spaces")
            t:assert_eq(row.partuuid, partition_guid(index), "unique GUID matches the on-disk entry")
        end
    end)
