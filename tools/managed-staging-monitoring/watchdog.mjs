import path from 'node:path';
import {fileURLToPath} from 'node:url';
const URL='https://wpcl-managed-staging.bw-a81.workers.dev/health';
export function evaluateHealth(response,value,{now=Date.now()}={}){
  const valid=response.status===200&&/application\/json/i.test(response.headers.get('content-type')||'')
    && /(?:^|,)\s*no-store\s*(?:,|$)/i.test(response.headers.get('cache-control')||'')
    && value?.operational===true&&value.status==='operational'&&value.mode==='invited-managed-sites'
    && value.verifierCheck==='configured-only'&&Number.isFinite(Date.parse(value.checkedAt))&&Math.abs(now-Date.parse(value.checkedAt))<=120000;
  return {ok:Boolean(valid),status:valid?'operational':'watchdog_failed',nativeVerifier:'not-tested'};
}
export async function check({fetchImpl=fetch,now=Date.now}={}){
  let response;try{
    response=await fetchImpl(URL,{redirect:'error',cache:'no-store',headers:{Accept:'application/json'},signal:AbortSignal.timeout(15000)});
    const reader=response.body?.getReader();if(!reader)throw Error('body');let bytes=0,text='';const decoder=new TextDecoder('utf-8',{fatal:true});
    try{while(true){const chunk=await reader.read();if(chunk.done)break;bytes+=chunk.value.length;if(bytes>4096){await reader.cancel();throw Error('size');}text+=decoder.decode(chunk.value,{stream:true});}text+=decoder.decode();}finally{reader.releaseLock();}
    return evaluateHealth(response,JSON.parse(text),{now:now()});
  }catch{return {ok:false,status:'watchdog_failed',nativeVerifier:'not-tested'};}
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  // Manual workflow failure qualification is separate from the normal check.
  if(process.env.WPCL_WATCHDOG_TEST_ALERT==='true'){console.error('[STAGING TEST] Intentional watchdog failure to verify GitHub notification delivery.');process.exitCode=1;}
  else check().then(report=>{console.log(JSON.stringify(report));if(!report.ok)process.exitCode=1;});
}
