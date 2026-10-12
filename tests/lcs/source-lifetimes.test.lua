-- The renewable lease describes a kernel-owned transaction, independent of
-- source activity or process existence. Exercise the actual control ABI.
local sys=require('helpers.sys')
local lcs=require('helpers.lcs')
local vm=provium:vm('v','kernel-only'):boot()
local src=lcs.source(vm)
src:seed_param('TransactionTimeoutMs',7000)
src:seed_param('RequestTimeoutMs',1000)
src:seed_param('MaxConcurrentRSIRequests',1)
src:key([[Machine\Software\Lifetime]])
assert(src:register({lifetime=true}))
src:pump()
local w=vm:spawn_worker()
local key=lcs.open_key(src,w,-1,[[Machine\Software\Lifetime]],lcs.KEY_ALL_ACCESS)
assert(key.ret>=0)
local querykey=lcs.open_key(src,vm,-1,[[Machine\Software\Lifetime]],lcs.KEY_ALL_ACCESS)
assert(querykey.ret>=0)
local function control(cmd,blob)
 return src.worker:syscall(sys.NR.ioctl,{args={src.fd,cmd,0},bufs={blob},ptrs={2}})
end
local function renew(id,session)
 local r=control(0xc0205203,string.pack('<I8I8I8I8',session or src.session,id,0,0))
 if r.ret==0 then r.lifetime,r.lease=string.unpack('<I8I8',r.out_bufs[1],17) end
 return r
end
local function begin(t)
 local txn=assert(lcs.begin_transaction(w))
 local captured
 src:intercept(lcs.OP.BEGIN_TXN,function(_,req)
  captured=string.unpack('<I8',req.payload)
  local r=control(0xc0285202,string.pack('<I8I8I8I8I8',src.session,req.id,0,0,0))
  t:assert_eq(r.ret,0,'request context')
  local deadline,lifetime,lease=string.unpack('<I8I8I8',r.out_bufs[1],17)
  t:assert(deadline>0 and lifetime>deadline and lease<lifetime,'three distinct deadlines')
 end)
 local r=lcs.set_value(src,w,key.ret,'V',lcs.TYPE.DWORD,lcs.dword(1),{txn_fd=txn})
 src:intercept(lcs.OP.BEGIN_TXN,nil)
 t:assert_eq(r.ret,0,'bind transaction')
 t:assert(captured~=nil,'BEGIN carries transaction id')
 return txn,captured
end

test('renewal requires this source session and a live transaction owner',
 { spec = {
  'PKM *source.dispatch.lease-renewal-requires-a-live-owner-and-session',
  'PKM *source.dispatch.context-preserves-the-original-request-deadline',
  'PKM *lcs-abi.struct-reg-src-renew-args',
  'PKM *lcs-abi.struct-reg-src-request-context-args',
 } },function(t)
 t:assert(src.session>0,'negotiated session')
 t:assert_eq(renew(999999).errno,116,'unknown transaction is stale')
 local txn,id=begin(t)
 t:assert_eq(renew(id,src.session+1).errno,116,'foreign session is stale')
 t:assert_eq(renew(id).ret,0,'live owner renews')
 src:intercept(lcs.OP.QUERY_VALUES,function() return lcs.HOLD end)
 local pending=lcs.query_value_async(vm,querykey.ret,'V')
 src:pump(50)
 src:intercept(lcs.OP.QUERY_VALUES,nil)
 local held=src:held_ids()
 t:assert_eq(#held,1,'ordinary request occupies the only slot')
 t:assert_eq(renew(id).ret,0,'renewal bypasses full ordinary request queue')
 local before=control(0xc0285202,string.pack('<I8I8I8I8I8',src.session,held[1],0,0,0))
 sys.nanosleep(w,1,200000000)
 t:assert_eq(pending:await().errno,110,'request times out while slot stays occupied')
 local after=control(0xc0285202,string.pack('<I8I8I8I8I8',src.session,held[1],0,0,0))
 t:assert_eq(after.ret,0,'detached request retains context')
 t:assert_eq(after.out_bufs[1],before.out_bufs[1],'query does not restart deadline')
 sys.close(w,txn)
 -- Do not deliver the queued ABORT. Ownership is already gone.
 t:assert_eq(renew(id).errno,116,'final close revokes even when ABORT cannot enqueue')
 src:release(held[1]);src:pump()
end)

test('an expired cleanup lease cannot be renewed by a living source',function(t)
 local txn,id=begin(t)
 sys.nanosleep(vm,5,200000000)
 t:assert_eq(renew(id).errno,116,'expired lease remains terminal')
 t:assert_eq(renew(id).errno,116,'repeated renewal cannot revive it')
 sys.close(w,txn);src:pump()
end)

test('renewal preserves the original transaction lifetime deadline',function(t)
 local txn,id=begin(t)
 local first=renew(id)
 for _=1,3 do
  sys.nanosleep(vm,2,0)
  local next=renew(id)
  t:assert_eq(next.ret,0,'renew before expiry')
  t:assert_eq(next.lifetime,first.lifetime,'lifetime never slides')
  t:assert(next.lease<=next.lifetime,'cleanup lease capped by lifetime')
 end
 sys.nanosleep(vm,1,200000000)
 t:assert_eq(renew(id).errno,116,'renewal cannot extend lifetime')
 sys.close(w,txn);src:pump()
end)

test('definitive BEGIN failure allows retry without changing owner lifetime',function(t)
 local txn=assert(lcs.begin_transaction(w))
 local original
 src:intercept(lcs.OP.BEGIN_TXN,function(_,req)
  local r=control(0xc0285202,string.pack('<I8I8I8I8I8',src.session,req.id,0,0,0))
  original=string.unpack('<I8',r.out_bufs[1],25)
  return lcs.STATUS.TXN_BUSY,''
 end)
 local r=lcs.set_value(src,w,key.ret,'Retry',lcs.TYPE.DWORD,lcs.dword(1),{txn_fd=txn})
 t:assert(r.ret<0,'explicit failed BEGIN is returned')
 src:intercept(lcs.OP.BEGIN_TXN,function(_,req)
  local context=control(0xc0285202,string.pack('<I8I8I8I8I8',src.session,req.id,0,0,0))
  t:assert_eq(string.unpack('<I8',context.out_bufs[1],25),original,'retry keeps original lifetime')
 end)
 r=lcs.set_value(src,w,key.ret,'Retry',lcs.TYPE.DWORD,lcs.dword(1),{txn_fd=txn})
 src:intercept(lcs.OP.BEGIN_TXN,nil)
 t:assert_eq(r.ret,0,'definite failure can retry')
 sys.close(w,txn);src:pump()
end)

test('an in-kernel read-only operation owns the same renewable lease',function(t)
 local params=lcs.open_key(src,w,-1,lcs.PARAMS_PATH,lcs.KEY_ALL_ACCESS)
 t:assert(params.ret>=0,'open runtime parameters')
 t:assert_eq(lcs.set_value(src,w,params.ret,'RequestTimeoutMs',lcs.TYPE.DWORD,lcs.dword(10000)).ret,0,'allow long individual read')
 local holder=vm:spawn_worker()
 local key=lcs.open_key(src,holder,-1,[[Machine\Software\Lifetime]],lcs.KEY_ALL_ACCESS)
 local output=assert(lcs.stream_file(holder,'/lease-backup.bin'))
 local transaction
 src:intercept(lcs.OP.BEGIN_TXN,function(_,req)
  transaction=string.unpack('<I8',req.payload)
  local ctx=control(0xc0285202,string.pack('<I8I8I8I8I8',src.session,req.id,0,0,0))
  t:assert_eq(ctx.ret,0,'internal operation context')
  t:assert_eq(string.unpack('<I8',ctx.out_bufs[1],25),0,'operation scope has no guessed lifetime ceiling')
 end)
 src:intercept(lcs.OP.ENUM_CHILDREN,function() return lcs.HOLD end)
 local pending=lcs.backup_async(holder,key.ret,output)
 src:pump(50)
 src:intercept(lcs.OP.BEGIN_TXN,nil)
 src:intercept(lcs.OP.ENUM_CHILDREN,nil)
 local held=src:held_ids()
 t:assert(transaction~=nil and #held==1,'operation owns a snapshot with a held read')
 for _=1,3 do
  sys.nanosleep(w,2,0)
  local r=renew(transaction)
  t:assert_eq(r.ret,0,'live operation renews while ordinary queue is occupied')
  t:assert_eq(r.lifetime,0,'renewal leaves operation lifetime policy unchanged')
 end
 src:release(held[1]);src:pump(100)
 t:assert_eq(pending:await().ret,0,'snapshot operation completes after multiple cleanup leases')
 t:assert_eq(renew(transaction).errno,116,'operation completion releases ownership')
 sys.close(holder,output);sys.close(holder,key.ret);holder:kill();holder:join()
 t:assert_eq(lcs.set_value(src,w,params.ret,'RequestTimeoutMs',lcs.TYPE.DWORD,lcs.dword(1000)).ret,0,'restore request budget')
 sys.close(w,params.ret)
end)

test('cleanup lease expiry does not discard a late successful commit',
 { spec = 'PKM *source.dispatch.lease-expiry-does-not-infer-a-commit-outcome' },function(t)
 local before=lcs.query_key_info(src,vm,querykey.ret).hive_generation
 t:assert_eq(lcs.notify(nil,vm,querykey.ret,lcs.NOTIFY.ALL,false).ret,0,'arm watch')
 local txn,id=begin(t)
 src:intercept(lcs.OP.COMMIT_TXN,function() return lcs.HOLD end)
 local pending=lcs.commit_async(w,txn)
 src:pump(100)
 src:intercept(lcs.OP.COMMIT_TXN,nil)
 local held=src:held_ids()
 t:assert_eq(#held,1,'commit admitted by source')
 t:assert_eq(pending:await().errno,110,'caller times out without a commit outcome')
 sys.nanosleep(vm,5,200000000)
 t:assert_eq(renew(id).errno,116,'cleanup lease is terminal')
 t:assert(src:release(held[1],lcs.STATUS.OK,'')>0,'late actual commit result accepted')
 src:pump(100)
 local poll=vm:syscall(sys.NR.poll,{args={0,1,100},
  bufs={string.pack('<i4i2i2',querykey.ret,1,0)},ptrs={0}})
 t:assert(poll.ret>0,'actual successful commit publishes its retained watch effects')
 local events=lcs.read_events(nil,vm,querykey.ret)
 local found=false
 for _,event in ipairs(events.events or {}) do
  if event.type==lcs.WATCH.VALUE_SET and event.name=='V' then found=true end
 end
 t:assert(found,'the committed value publishes a watch event')
 local after=lcs.query_key_info(src,vm,querykey.ret).hive_generation
 t:assert(before and after and after>before,'actual success advances hive generation')
 sys.close(w,txn);src:pump()
end)

test('source reconnect fences the previous session',
 { spec = {
  'PKM *source.dispatch.lifetime-extension-is-negotiated-before-registration',
  'PKM *lcs-abi.struct-reg-src-negotiate-args',
 } },function(t)
 local old=src.session
 src:disconnect()
 t:assert(src:resume({lifetime=true}),'source reconnects')
 src:pump()
 t:assert(src.session~=old,'new source session')
 t:assert_eq(renew(1,old).errno,116,'old session cannot renew')
end)
