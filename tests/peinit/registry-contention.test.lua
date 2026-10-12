-- PEI-230 / PEI-1241: the real kernel and loregd must keep readers usable
-- while an RSI transaction owns the hive writer. An optional local binary
-- can be injected before registry bootstrap for pre-publication validation.
local peinit=require('helpers.peinit')
local lcs=require('helpers.lcs')
local sys=require('helpers.sys')
local token=require('helpers.token')
local kacs=require('helpers.kacs')
local access=require('helpers.access')
peinit.claim(1)
local files={}
local binary=os.getenv('LOREGD_TEST_BINARY')
if binary then
 local f=assert(io.open(binary,'rb'));files['usr/sbin/loregd']={f:read('*a'),exec=true};f:close()
end
local vm=peinit.boot({files=files})

test('sibling opens and enumeration finish while a delete transaction stays active',function(t)
 local parent=lcs.create_key(nil,vm,{path=[[Machine\Software\Pei230]]})
 t:assert(parent.ret>=0,'create parent: '..tostring(parent.errno))
 local one=lcs.create_key(nil,vm,{parent_fd=parent.ret,path='One'})
 local two=lcs.create_key(nil,vm,{parent_fd=parent.ret,path='Two'})
 t:assert(one.ret>=0 and two.ret>=0,'create siblings')
 sys.close(vm,two.ret)
 local txn=assert(lcs.begin_transaction(vm))
 local deleted=lcs.delete_key(nil,vm,one.ret,{txn_fd=txn})
 t:assert_eq(deleted.ret,0,'delete first sibling')
 -- No SQL activity for longer than the five-second cleanup lease: the
 -- live transaction fd must keep ownership independently of activity.
 sys.nanosleep(vm,6,0)
 local opened=lcs.open_key(nil,vm,parent.ret,'Two',lcs.RIGHT.KEY_READ)
 t:assert(opened.ret>=0,'open second sibling: '..tostring(opened.errno))
 local enumerated=lcs.enum_subkeys(nil,vm,parent.ret,0)
 t:assert_eq(enumerated.ret,0,'enumerate during transaction')
 local status=lcs.txn_status(nil,vm,txn)
 t:assert_eq(status.ret,0,'transaction status')
 t:assert_eq(status.state,lcs.TXN.ACTIVE_BOUND,'writer is still ActiveBound, not timed out')
 sys.close(vm,opened.ret)
 -- Final close tells LCS to abort, so the daemon must release its writer.
 sys.close(vm,txn)
 local next=lcs.create_key(nil,vm,{parent_fd=parent.ret,path='AfterAbort'})
 t:assert(next.ret>=0,'writer released after client abort: '..tostring(next.errno))
 sys.close(vm,next.ret);sys.close(vm,one.ret);sys.close(vm,parent.ret)
end)

test('volatile store files inherit SYSTEM-only authority',function(t)
 local paths=vm:run([[sh -c 'for f in /run/loregd/hive-*/*; do echo "$f"; done']])
 paths:assert_ok()
 local all={}
 for path in paths.stdout:gmatch('[^\n]+') do
  t:assert(not path:find('*',1,true),'volatile files exist')
  all[#all+1]=path
 end
 t:assert(#all>0,'runtime databases exist')
 local descriptor=assert(kacs.get_sd(vm,'/run/loregd',kacs.SI.OWNER|kacs.SI.DACL))
 local parsed=access.parse_sd(descriptor)
 t:assert((parsed.control & access.CONTROL.DACL_PROTECTED)~=0,'protected parent DACL')
 local worker=vm:spawn_worker()
 local ok,err=pcall(function()
  local notify=token.bit(token.PRIV.CHANGE_NOTIFY)
  local fd=assert(token.mint(worker,{privs_present=notify,privs_enabled=notify}))
  t:assert_eq(token.install(worker,fd).ret,0,'install ordinary user token')
  for _,path in ipairs(all) do
   local opened,errno=sys.open(worker,path,sys.O.RDONLY)
   if opened then sys.close(worker,opened) end
   t:assert_eq(opened,nil,'ordinary user cannot read '..path)
   t:assert_eq(errno,sys.E.ACCES,'native DACL denies database access')
  end
 end)
 worker:kill();worker:join();if not ok then error(err,0) end
end)

test('client commit and internal backup/restore use the negotiated ownership protocol',function(t)
 local key=lcs.create_key(nil,vm,{path=[[Machine\Software\Pei230RoundTrip]]})
 t:assert(key.ret>=0,'create backup root')
 local txn=assert(lcs.begin_transaction(vm))
 t:assert_eq(lcs.set_value(nil,vm,key.ret,'Value',lcs.TYPE.DWORD,lcs.dword(41),{txn_fd=txn}).ret,0,'stage write')
 t:assert_eq(lcs.commit(nil,vm,txn).ret,0,'commit through negotiated source')
 sys.close(vm,txn)
 local value=lcs.query_value(nil,vm,key.ret,'Value')
 t:assert_eq(value.ret,0,'read committed value')
 t:assert_eq(value.data,lcs.dword(41),'committed value is published')
 local result,stream,bytes=lcs.backup_to_file(nil,vm,key.ret,'/tmp/pei230-backup.bin')
 t:assert_eq(result.ret,0,'backup with operation-owned read-only transaction')
 t:assert(stream~=nil and bytes~=nil,'backup stream is valid')
 t:assert_eq(lcs.set_value(nil,vm,key.ret,'Value',lcs.TYPE.DWORD,lcs.dword(99)).ret,0,'change after backup')
 t:assert_eq(lcs.restore_bytes(nil,vm,key.ret,'/tmp/pei230-restore.bin',bytes).ret,0,'restore with operation-owned write transaction')
 value=lcs.query_value(nil,vm,key.ret,'Value')
 t:assert_eq(value.ret,0,'read restored value')
 t:assert_eq(value.data,lcs.dword(41),'restore committed its original value')
 sys.close(vm,key.ret)
end)
