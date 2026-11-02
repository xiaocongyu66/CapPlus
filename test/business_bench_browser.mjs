// Local-only official-browser solver. No fabricated instrumentation or authentication bypass.
import { pathToFileURL } from 'node:url';
import { appendFileSync, readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { performance } from 'node:perf_hooks';
const E = process.env;
const base = E.BENCH_URL;
const url = new URL(base);
if (url.hostname !== '127.0.0.1' || ['8401', '6379', ''].includes(url.port)) throw Error('isolated loopback required');
const { chromium } = await import(pathToFileURL(E.BENCH_PLAYWRIGHT));
const output = `${E.BENCH_OUT}/results.jsonl`;
const emit = x => { const s = JSON.stringify(x); appendFileSync(output, s + '\n'); console.log(s); };
const tick = Number(execFileSync('getconf', ['CLK_TCK']).toString());
function procStats() {
  const stat = readFileSync(`/proc/${E.BENCH_SERVER_PID}/stat`, 'utf8').split(') ')[1].split(' ');
  const status = readFileSync(`/proc/${E.BENCH_SERVER_PID}/status`, 'utf8');
  return { cpu: (Number(stat[11]) + Number(stat[12])) / tick, rss_kib: Number(status.match(/^VmRSS:\s+(\d+)/m)?.[1] || 0) };
}
function redisStats() {
  const text = execFileSync('redis-cli', ['-h', '127.0.0.1', '-p', E.BENCH_REDIS_PORT, '--raw', 'INFO', 'commandstats'], {timeout:3000}).toString();
  if (!text.includes('# Commandstats')) throw Error('Redis metrics unavailable');
  return Object.fromEntries([...text.matchAll(/^cmdstat_([^:]+):calls=(\d+)/gm)].map(m => [m[1], Number(m[2])]));
}
class Histogram {
  constructor() { this.bins = new Uint32Array(60001); this.count = 0; this.sum = 0; this.overflow = 0; }
  add(ms) { if (!Number.isFinite(ms) || ms < 0) return; this.bins[Math.min(60000, Math.ceil(ms))]++; this.count++; this.sum += ms; if(ms > 60000)this.overflow++; }
  summary() {
    const pct = p => { if (!this.count) return null; let n = 0; for(let i=0;i<this.bins.length;i++) { n += this.bins[i]; if(n >= Math.ceil(this.count*p))return i; } };
    return {count:this.count, p50_ms:pct(.5), p95_ms:pct(.95), p99_ms:pct(.99), mean_ms:this.count?this.sum/this.count:null, overflow:this.overflow, resolution_ms:1};
  }
}
const browser = await chromium.launch({executablePath:E.BENCH_CHROMIUM, headless:false, args:['--no-sandbox', '--disable-dev-shm-usage', '--disable-background-networking']});
for (const signal of ['SIGINT','SIGTERM']) process.once(signal, async () => { await browser.close(); process.exit(128); });
try {
  const context = await browser.newContext();
  // All browser network traffic is constrained to the owned server.
  await context.route('**/*', route => new URL(route.request().url()).origin === base ? route.continue() : route.abort());
  const pages = [];
  async function newPage() {
    const page = await context.newPage();
    page.setDefaultTimeout(12000);
    await page.goto(`${base}/embed/benchsite?parent=${encodeURIComponent(base)}`, {waitUntil:'networkidle'});
    await page.evaluate(async () => {
      await customElements.whenDefined('cap-widget');
      const nativeFetch = window.fetch;
      window.bench = { events:[], lastRedeem:null, lastToken:null };
      window.fetch = async (input, init) => {
        const req = input instanceof Request ? input.clone() : new Request(new URL(input, location.href), init);
        const path = new URL(req.url).pathname;
        const stage = path.split('/').pop();
        if (!['challenge','redeem','siteverify'].includes(stage)) return nativeFetch(input, init);
        const start = performance.now();
        if(stage === 'redeem') window.bench.lastRedeem = await req.clone().json();
        try {
          const response = await nativeFetch(input, init);
          const body = await response.clone().json();
          const end = performance.now();
          const valid = stage === 'challenge' ? typeof body.token === 'string' && (Array.isArray(body.challenges) || !!body.challenge) : body.success === true && (stage !== 'redeem' || typeof body.token === 'string');
          if(window.bench.events.length < 32) window.bench.events.push({stage,status:response.status,valid,start,end, error:body.error || body['error-codes']});
          return response;
        } catch(e) {
          if(window.bench.events.length < 32) window.bench.events.push({stage,status:0,valid:false,start,end:performance.now(),error:String(e)});
          throw e;
        }
      };
    });
    return page;
  }
  async function flow(page) {
    // A timed-out page is never reused: its worker stops for the current phase.
    return await page.evaluate(async ({secret}) => {
      const begin = performance.now();
      const b = window.bench;
      b.events = [];
      let timer;
      try {
        return await Promise.race([
          (async () => {
            const widget = document.querySelector('cap-widget');
            widget.reset();
            const solved = await widget.solve();
            if(!solved?.success || typeof solved.token !== 'string' || !solved.token) throw Error('widget_business_failure');
            b.lastToken = solved.token;
            const response = await fetch('/benchsite/siteverify', {method:'POST', headers:{'content-type':'application/json','x-cap-client-ua':navigator.userAgent}, body:JSON.stringify({secret,response:solved.token}), signal:AbortSignal.timeout(10000)});
            const body = await response.json();
            if(!response.ok || body.success !== true) throw Error('siteverify_business_failure');
            const rd = b.events.findLast(x => x.stage === 'redeem');
            const ch = b.events.findLast(x => x.stage === 'challenge' && x.end <= rd?.start);
            if(!ch?.valid || !rd?.valid || ch.status !== 200 || rd.status !== 200) throw Error('missing_successful_protocol_stages');
            return {ok:true, elapsed:performance.now()-begin, solve_probe_ms:rd.start-ch.end, events:b.events};
          })(),
          new Promise((_,reject) => { timer = setTimeout(() => reject(Error('flow_timeout')), 12000); })
        ]);
      } catch(e) { return {ok:false, elapsed:performance.now()-begin, error:String(e), events:b.events}; }
      finally { clearTimeout(timer); }
    }, {secret:E.BENCH_SECRET});
  }
  pages.push(await newPage());
  const coldStart = procStats(), coldRedis = redisStats();
  const cold = await flow(pages[0]);
  emit({phase:'cold_first_flow', result:cold, server_cpu_s:procStats().cpu-coldStart.cpu, server_rss_kib:procStats().rss_kib, redis_before:coldRedis, redis_after:redisStats()});
  if(!cold.ok) {
    emit({phase:'rejection_or_failure', scenario:'strict_automated_browser', counted_as_success:false, successful_flows:0, result:cold, interpretation:'Observed rejection/failure only; no signal details, bottleneck or false-positive conclusion.'});
    emit({phase:'blocked', reason:'strict automated browser flow failed; successful end-to-end baseline unavailable', planned_concurrency:E.BENCH_CONCURRENCY, planned_rounds:Number(E.BENCH_ROUNDS), planned_seconds:Number(E.BENCH_SECONDS), completed_load_rounds:0, negative_scenarios_not_run:['token_replay','unknown_site','bad_mac']});
    throw Error('strict automated browser flow failed; refusing to publish fake throughput');
  }
  const negatives = await pages[0].evaluate(async ({secret}) => {
    const send = async (path, body) => { const r = await fetch(path,{method:'POST',headers:{'content-type':'application/json','x-cap-client-ua':navigator.userAgent},body:JSON.stringify(body)}); return {status:r.status,body:await r.json()}; };
    const replay = await send('/benchsite/siteverify', {secret,response:window.bench.lastToken});
    const unknown = await send('/benchmissing/challenge', {});
    const bad = {...window.bench.lastRedeem};
    const parts = bad.token.split('.');
    if(parts.length !== 3) throw Error('expected signed challenge token');
    parts[2] = (parts[2][0] === 'A' ? 'B' : 'A') + parts[2].slice(1);
    bad.token = parts.join('.');
    const badMac = await send('/benchsite/redeem',bad);
    return {replay,unknown,badMac};
  },{secret:E.BENCH_SECRET});
  emit({phase:'separate_rejections', counted_as_success:false, successful_flows:0, scenarios:['token_replay','unknown_site','bad_mac'], ...negatives});
  if(negatives.replay.body.success !== false || negatives.unknown.status < 400 || negatives.badMac.status < 400) throw Error('negative scenario unexpectedly accepted');
  for(const concurrency of E.BENCH_CONCURRENCY.split(',').map(Number)) {
    while(pages.length < concurrency) pages.push(await newPage());
    for(let i=0;i<concurrency;i++) {
      const warm = await flow(pages[i]);
      emit({phase:'warmup', concurrency, worker:i, result:warm});
      if(!warm.ok) throw Error('warmup failed');
    }
    for(let round=1;round<=Number(E.BENCH_ROUNDS);round++) {
      const latency = new Histogram(), successfulLatency = new Histogram(), solver = new Histogram();
      const reqLatency = new Histogram(), errors = {}, http = {};
      let successful = 0, successfulRequests = 0, attempts = 0, lateSuccess = 0;
      const cpu = procStats(), redis = redisStats();
      let peakRss = cpu.rss_kib;
      const sampler = setInterval(() => { peakRss = Math.max(peakRss, procStats().rss_kib); },100);
      const start = performance.now(), deadline = start + Number(E.BENCH_SECONDS)*1000;
      await Promise.all(pages.slice(0,concurrency).map(async page => {
        while(performance.now() < deadline) {
          const result = await flow(page);
          const inWindow = performance.now() <= deadline;
          attempts++; latency.add(result.elapsed);
          for(const e of result.events) {
            const key = `${e.stage}:${e.status}`; http[key] = (http[key] || 0)+1;
            reqLatency.add(e.end-e.start);
            if(inWindow && e.status >= 200 && e.status < 300 && e.valid) successfulRequests++;
          }
          if(result.ok) {
            successfulLatency.add(result.elapsed); solver.add(result.solve_probe_ms);
            if(inWindow)successful++; else lateSuccess++;
          } else {
            const bad = result.events.find(x => x.status === 429 || x.status === 503 || x.status === 0 || !x.valid || x.status >= 400);
            const key = result.error.includes('timeout') ? 'timeout' : bad ? `${bad.stage}:${bad.status || 'connection_or_decode'}:${JSON.stringify(bad.error || 'business')}` : result.error;
            // Error cardinality bounded independently of server error strings.
            const bucket = Object.hasOwn(errors,key) || Object.keys(errors).length < 24 ? key : 'other';
            errors[bucket] = (errors[bucket] || 0)+1;
            if(result.error.includes('timeout')) break;
          }
        }
      }));
      clearInterval(sampler);
      const elapsed = (performance.now()-start)/1000, after = procStats(), rafter = redisStats();
      const delta = Object.fromEntries(Object.entries(rafter).map(([k,v])=>[k,v-(redis[k] || 0)]));
      emit({phase:'warm', concurrency, round, window_s:Number(E.BENCH_SECONDS), elapsed_including_drain_s:elapsed, attempts, successful, late_success_excluded:lateSuccess,
        successful_flows_per_s:successful/Number(E.BENCH_SECONDS), successful_business_requests_per_s:successfulRequests/Number(E.BENCH_SECONDS),
        latency:latency.summary(), successful_latency:successfulLatency.summary(), solve_and_probe_wall:solver.summary(), http_latency:reqLatency.summary(), http, errors,
        server_cpu_s:after.cpu-cpu.cpu, server_cpu_percent:100*(after.cpu-cpu.cpu)/elapsed, server_rss_peak_sampled_kib:peakRss,
        redis_command_delta:delta, redis_commands_total:Object.values(delta).reduce((a,b)=>a+b,0), redis_measurement_overhead:'includes one INFO command; background metrics flush may cross phase boundaries'});
      // Timeout leaves an in-flight solve; replace pages rather than reusing its token.
      if(errors.timeout) { for(let i=0;i<pages.length;i++) { await pages[i].close(); pages[i]=await newPage(); } }
    }
  }
} finally { await browser.close(); }
