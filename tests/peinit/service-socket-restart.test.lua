-- PEI-1229 / PEI-1373: runtime socket ACLs must permit replacement by
-- the next service instance, without deleting directories from the test.
local peinit = require('helpers.peinit')
peinit.claim(1)
local vm = peinit.boot()
for _, service in ipairs({ {name='timed', command='clock status'},
                          {name='trustd', command='trust status'},
                          {name='resolvd', command='resolv status'} }) do
    test(service.name .. ' replaces stale sockets across restart and crash', function(t)
        local function ready(old)
            return wait_until(function()
                local r=vm:run('svctl --json status '..service.name)
                if r.exit_code ~= 0 then return false end
                local st=json.decode(r.stdout)
                local pid=st.current_job and st.current_job.pid
                if st.state ~= 'active' or not pid or pid == old then return false end
                if vm:run(service.command).exit_code ~= 0 then return false end
                return pid
            end, {timeout=30, interval=0.2, desc=service.name..' answering on a new process'})
        end
        local pid=ready(nil)
        vm:run('svctl restart '..service.name):assert_ok()
        local restarted=ready(pid)
        vm:run('kill -KILL '..restarted):assert_ok()
        local recovered=ready(restarted)
        t:log('pids '..pid..' -> '..restarted..' -> '..recovered)
    end)
end
