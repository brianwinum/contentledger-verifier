import path from 'node:path';
import {fileURLToPath} from 'node:url';
const TARGETS=Object.freeze([
  Object.freeze({name:'staging',url:'https://wpcl-managed-staging.bw-a81.workers.dev/health'}),
  Object.freeze({name:'production',url:'https://certificates.wpcontentledger.com/health'})
]);
export function evaluateHealth(response,value,{now=Date.now(),target='staging'}={}){
  // Production must report the deployed synthetic parity check, not merely a
  // configured verifier binding. Staging may retain its older configured mode.
  const nativeAt=Date.parse(value?.verifierCheckedAt);
  const nativeHealthy=value?.verifierCheck==='native-synthetic-parity'&&value.verifierHealthy===true
    && Number.isFinite(nativeAt)&&now-nativeAt<=900000&&nativeAt-now<=30000;
  const verifierValid=nativeHealthy||(target==='staging'&&value?.verifierCheck==='configured-only');
  const valid=response.status===200&&/^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type')||'')
    && /(?:^|,)\s*no-store\s*(?:,|$)/i.test(response.headers.get('cache-control')||'')
    && value?.operational===true&&value.status==='operational'&&value.mode==='invited-managed-sites'
    && value.ingestionEnabled===true&&value.indexingPolicy==='reviewed-certificates'
    && ['staging','production'].includes(target)&&verifierValid
    && Number.isFinite(Date.parse(value.checkedAt))&&Math.abs(now-Date.parse(value.checkedAt))<=120000;
  const nativeVerifier=nativeHealthy?'reported-healthy':target==='production'||value?.verifierCheck==='native-synthetic-parity'?'unhealthy-or-unverified':'not-tested';
  return {ok:Boolean(valid),status:valid?'operational':'watchdog_failed',nativeVerifier};
}
async function checkEndpoint(url,{fetchImpl,now,target}){
  let response;try{
    response=await fetchImpl(url,{method:'GET',redirect:'error',cache:'no-store',credentials:'omit',headers:{Accept:'application/json'},signal:AbortSignal.timeout(15000)});
    const reader=response.body?.getReader();if(!reader)throw Error('body');let bytes=0,text='';const decoder=new TextDecoder('utf-8',{fatal:true});
    try{while(true){const chunk=await reader.read();if(chunk.done)break;bytes+=chunk.value.length;if(bytes>4096){await reader.cancel();throw Error('size');}text+=decoder.decode(chunk.value,{stream:true});}text+=decoder.decode();}finally{reader.releaseLock();}
    return evaluateHealth(response,JSON.parse(text),{now:now(),target});
  }catch{return {ok:false,status:'watchdog_failed',nativeVerifier:'not-tested'};}
}
export async function check({fetchImpl=fetch,now=Date.now,target='all'}={}){
  if(!['all','staging','production'].includes(target))throw Error('invalid_watchdog_target');
  // Each endpoint has its own timeout/result; one failure never skips the other.
  const selected=target==='all'?TARGETS:TARGETS.filter(item=>item.name===target);
  const checks=await Promise.all(selected.map(async item=>({target:item.name,...await checkEndpoint(item.url,{fetchImpl,now,target:item.name})})));
  const ok=checks.every(report=>report.ok);
  const reported=checks.filter(report=>report.nativeVerifier!=='not-tested');
  const nativeVerifier=reported.length===0?'not-tested':reported.every(report=>report.nativeVerifier==='reported-healthy')?'reported-healthy':'unhealthy-or-unverified';
  return {ok,status:ok?'operational':'watchdog_failed',nativeVerifier,checks};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  // Manual workflow failure qualification is separate from the normal check.
  if(process.env.WPCL_WATCHDOG_TEST_ALERT==='true'){console.error('[STAGING TEST] Intentional watchdog failure to verify GitHub notification delivery.');process.exitCode=1;}
  else check({target:process.env.WPCL_WATCHDOG_TARGET||'all'}).then(report=>{console.log(JSON.stringify(report));if(!report.ok)process.exitCode=1;}).catch(()=>{console.error('Invalid watchdog target.');process.exitCode=1;});
}
