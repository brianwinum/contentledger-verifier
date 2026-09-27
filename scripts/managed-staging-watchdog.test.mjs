import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {evaluateHealth,check} from './managed-staging-watchdog.mjs';
const now=1790350000000,body={status:'operational',operational:true,mode:'invited-managed-sites',ingestionEnabled:true,indexingPolicy:'reviewed-certificates',verifierCheck:'configured-only',checkedAt:new Date(now).toISOString()},headers={'Content-Type':'application/json','Cache-Control':'no-store'};
const urls=['https://wpcl-managed-staging.bw-a81.workers.dev/health','https://certificates.wpcontentledger.com/health'];
const healthy=()=>new Response(JSON.stringify(body),{headers});
test('health requires current operational managed ingestion, reviewed indexing and noncacheable JSON',()=>{
  assert.equal(evaluateHealth(healthy(),body,{now}).ok,true);
  for(const delta of [{status:503},{headers:{'Content-Type':'application/json'}},{headers:{'Cache-Control':'no-store'}},{headers:{...headers,'Content-Type':'text/application/json'}}])assert.equal(evaluateHealth(new Response('{}',{headers,...delta}),body,{now}).ok,false);
  for(const delta of [{operational:false},{status:'configured'},{mode:'production-pilot'},{ingestionEnabled:false},{indexingPolicy:'disabled'},{verifierCheck:'unconfigured'},{checkedAt:'invalid'},{checkedAt:new Date(now-120001).toISOString()},{checkedAt:new Date(now+120001).toISOString()}])assert.equal(evaluateHealth(healthy(),{...body,...delta},{now}).ok,false);
  for(const offset of [-120000,120000])assert.equal(evaluateHealth(healthy(),{...body,checkedAt:new Date(now+offset).toISOString()},{now}).ok,true);
});
test('each fixed HTTPS target gets exactly one bounded credential-free GET and an independent timeout',async()=>{
  const calls=[],signals=[];
  const result=await check({now:()=>now,fetchImpl:async(url,options)=>{calls.push(url);signals.push(options.signal);assert.equal(options.method,'GET');assert.equal(options.redirect,'error');assert.equal(options.cache,'no-store');assert.equal(options.credentials,'omit');assert.deepEqual(options.headers,{Accept:'application/json'});assert.ok(options.signal instanceof AbortSignal);return healthy();}});
  assert.deepEqual(calls,urls);assert.notEqual(signals[0],signals[1]);assert.equal(result.ok,true);assert.equal(result.nativeVerifier,'not-tested');
  assert.deepEqual(result.checks.map(v=>[v.target,v.ok,v.nativeVerifier]),[['staging',true,'not-tested'],['production',true,'not-tested']]);
});

test('one transport failure never prevents checking the other target and has no raw failure output',async()=>{
  for(const failed of urls){const calls=[];const result=await check({now:()=>now,fetchImpl:async url=>{calls.push(url);if(url===failed)throw Error('private transport error must not be printed');return healthy();}});
    assert.deepEqual(calls,urls);assert.equal(result.ok,false);assert.deepEqual(result.checks.map(v=>v.ok),urls.map(url=>url!==failed));assert.doesNotMatch(JSON.stringify(result),/private transport/);
  }
});

test('both requests start independently while a first endpoint is still pending',async()=>{
  let release;const calls=[],pending=new Promise(done=>{release=done;});
  const run=check({now:()=>now,fetchImpl:async url=>{calls.push(url);if(url===urls[0])await pending;return healthy();}});
  await Promise.resolve();assert.deepEqual(calls,urls);release();assert.equal((await run).ok,true);
});

test('stale, wrong-mode and disabled health fail only their endpoint and fail the aggregate',async()=>{
  for(const failed of urls)for(const delta of [{checkedAt:new Date(now-120001).toISOString()},{mode:'production-pilot'},{ingestionEnabled:false},{operational:false}]){
    const result=await check({now:()=>now,fetchImpl:async url=>new Response(JSON.stringify({...body,...(url===failed?delta:{})}),{headers})});
    assert.equal(result.ok,false);assert.deepEqual(result.checks.map(v=>v.ok),urls.map(url=>url!==failed));
  }
});

test('oversized, invalid UTF-8, malformed JSON, HTTP failures and interrupted bodies fail per endpoint',async()=>{
  const bad=[()=>new Response('x'.repeat(4097),{headers}),()=>new Response(new Uint8Array([255]),{headers}),()=>new Response('{',{headers}),()=>new Response(JSON.stringify(body),{status:503,headers}),()=>new Response(new ReadableStream({start(controller){controller.error(Error('private stream error'));}}),{headers})];
  for(const failed of urls)for(const response of bad){const result=await check({now:()=>now,fetchImpl:async url=>url===failed?response():healthy()});assert.equal(result.ok,false);assert.deepEqual(result.checks.map(v=>v.ok),urls.map(url=>url!==failed));assert.doesNotMatch(JSON.stringify(result),/private stream/);}
});

test('intentional manual STAGING TEST remains the same separate failure path',()=>{
  const run=spawnSync(process.execPath,[fileURLToPath(new URL('./managed-staging-watchdog.mjs',import.meta.url))],{env:{WPCL_WATCHDOG_TEST_ALERT:'true'},encoding:'utf8',timeout:5000,maxBuffer:4096});
  assert.equal(run.status,1);assert.equal(run.stdout,'');assert.equal(run.stderr.trim(),'[STAGING TEST] Intentional watchdog failure to verify GitHub notification delivery.');
  const workflow=readFileSync(new URL('../.github/workflows/managed-staging-watchdog.yml',import.meta.url),'utf8');
  assert.match(workflow,/cron: '11,41 \* \* \* \*'/);assert.match(workflow,/staging_test_alert:/);assert.match(workflow,/WPCL_WATCHDOG_TEST_ALERT:.*inputs\.staging_test_alert/);assert.match(workflow,/persist-credentials: false/);
});
