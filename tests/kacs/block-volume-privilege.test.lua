-- PEI-549: raw block maintenance uses the native volume privilege while the
-- general CAP_SYS_ADMIN mapping remains TCB-only. The disk is disposable.
local sys=require('helpers.sys')
local token=require('helpers.token')
local kacs=require('helpers.kacs')
local access=require('helpers.access')
local vm=provium:vm('v','kernel-only'):boot({disks={{scratch='64M',id='blank'}}})
-- The minimal profile has no device-policy daemon. Stamp this scratch device
-- with the SYSTEM/Administrators grant used by the full image, so these tests
-- isolate the ioctl privilege gate rather than missing device policy.
local descriptor=access.simple({access.ace(0,0x10000000,token.SID.LOCAL_SYSTEM),access.ace(0,0x10000000,token.SID.ADMINISTRATORS)})
assert(kacs.set_sd(vm,'/dev/vda',descriptor,kacs.SI.DACL).ret==0)
local volume=token.bit(token.PRIV.MANAGE_VOLUME)
local tcb=token.bit(token.PRIV.TCB)
local traverse=token.bit(token.PRIV.CHANGE_NOTIFY)
local function blkpg(w,fd,op)
 local part=string.pack('<i8i8i4',1048576,1048576,1)..string.rep('\0',132)
 return w:syscall(sys.NR.ioctl,{args={fd,0x1269,0},
  bufs={string.pack('<i4i4i4I4I8',op,0,#part,0,0),part},ptrs={2},nested={{parent=1,child=2,offset=16}}})
end
local function principal(t,present,enabled,allowed)
 local w=vm:spawn_worker()
 local ok,err=pcall(function()
  local tf=assert(token.mint(w,{groups={{sid=token.SID.EVERYONE,attributes=7},{sid=token.SID.ADMINISTRATORS,attributes=7}},privs_present=present|traverse,privs_enabled=enabled|traverse,integrity_level=token.INTEGRITY.HIGH}))
  t:assert_eq(token.install(w,tf).ret,0,'install administrator test token')
  local fd,errno=sys.open(w,'/dev/vda',sys.O.RDWR)
  t:assert(fd~=nil,'administrator can open raw disk: '..tostring(errno))
  for _,cmd in ipairs({0x125f,0x1261}) do
   local r=w:syscall(sys.NR.ioctl,fd,cmd,0)
   if allowed then t:assert_eq(r.ret,0,'native volume ioctl '..cmd)
   else t:assert_eq(r.errno,sys.E.ACCES,'group membership or disabled privilege cannot administer disk') end
  end
  local r=blkpg(w,fd,1)
  if allowed then
   t:assert_eq(r.ret,0,'BLKPG adds a partition')
   t:assert_eq(blkpg(w,fd,2).ret,0,'BLKPG removes the partition')
   local privileges=assert(token.privileges(w,tf))
   t:assert((privileges.used & enabled)~=0,'volume authority is marked used')
  else t:assert_eq(r.errno,sys.E.ACCES,'BLKPG denies missing authority') end
  if enabled==volume then
   local other=w:syscall(sys.NR.ioctl,{args={fd,0x125d,0},bufs={string.pack('<i4',0)},ptrs={2}})
   t:assert_eq(other.errno,sys.E.ACCES,'unrelated CAP_SYS_ADMIN operation remains TCB-only')
  end
  sys.close(w,fd)
 end)
 w:kill();w:join();if not ok then error(err,0) end
end

test('enabled SeManageVolume permits partition maintenance without SeTcb',function(t) principal(t,volume,volume,true) end)
test('SeTcb still permits partition maintenance',function(t) principal(t,tcb,tcb,true) end)
test('Administrators membership alone does not grant volume authority',function(t) principal(t,0,0,false) end)
test('a present but disabled volume privilege does not grant authority',function(t) principal(t,volume,0,false) end)
