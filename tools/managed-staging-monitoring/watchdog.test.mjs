import test from 'node:test';
import assert from 'node:assert/strict';
import {evaluateHealth,check} from './watchdog.mjs';
const now=1790350000000,body={status:'operational',operational:true,mode:'invited-managed-sites',verifierCheck:'configured-only',checkedAt:new Date(now).toISOString()},headers={'Content-Type':'application/json','Cache-Control':'no-store'};
test('watchdog fails closed on stale, configured-only old API, HTTP failure, cacheable or malformed data',()=>{
  assert.equal(evaluateHealth(new Response('{}',{headers}),body,{now}).ok,true);
  for(const delta of [{status:503},{headers:{'Content-Type':'application/json'}},{headers:{'Cache-Control':'no-store'}}])assert.equal(evaluateHealth(new Response('{}',{headers,...delta}),body,{now}).ok,false);
  for(const delta of [{operational:false},{status:'configured'},{checkedAt:'invalid'},{checkedAt:new Date(now-120001).toISOString()},{checkedAt:new Date(now+120001).toISOString()}])assert.equal(evaluateHealth(new Response('{}',{headers}),{...body,...delta},{now}).ok,false);
});
test('watchdog performs one bounded exact HTTPS GET without credentials and never prints raw failures',async()=>{
  let calls=0;const result=await check({now:()=>now,fetchImpl:async(url,options)=>{calls++;assert.equal(url,'https://wpcl-managed-staging.bw-a81.workers.dev/health');assert.equal(options.redirect,'error');assert.deepEqual(options.headers,{Accept:'application/json'});return new Response(JSON.stringify(body),{headers});}});assert.equal(result.ok,true);assert.equal(calls,1);
  assert.equal((await check({fetchImpl:async()=>new Response('x'.repeat(4097),{headers})})).ok,false);
  assert.deepEqual(await check({fetchImpl:async()=>{throw Error('do not print private transport data');}}),{ok:false,status:'watchdog_failed',nativeVerifier:'not-tested'});
});
