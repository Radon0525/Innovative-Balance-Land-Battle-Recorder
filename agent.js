// CONFIG and COUNTER_SOURCE are prepended by the host.
const state = Memory.alloc(16384);
const width_filter = Memory.alloc(24);
const trace = Memory.alloc(320032);
trace.writeU64(0);
const traceBuffer = Memory.alloc(320032);
state.add(80).writeS32(CONFIG.defense_offset);
state.add(84).writeS32(CONFIG.test ? 0 : CONFIG.side_offset);
const kernel = Process.getModuleByName('kernel32.dll');
const cm = new CModule(COUNTER_SOURCE, {
  state, trace, width_filter,
  acquire: kernel.getExportByName('AcquireSRWLockExclusive'),
  release: kernel.getExportByName('ReleaseSRWLockExclusive'),
  thread_id: kernel.getExportByName('GetCurrentThreadId')
});
const buf = Memory.alloc(144);
const takeSnapshot = new NativeFunction(cm.snapshot, 'void', ['pointer']);
const takeTrace = new NativeFunction(cm.trace_snapshot, 'void', ['pointer']);
let listeners = [];
let detailListeners = [];
let fixture = null;
const fixtureOffset=Memory.alloc(4);
let runFixture = null;
let filterFixtureInstalled = false;

function install(hit, ground) {
  listeners.push(Interceptor.attach(ground, {onEnter:cm.ground_enter, onLeave:cm.ground_leave}));
  listeners.push(Interceptor.attach(hit, {onEnter:cm.hit_enter, onLeave:cm.hit_leave}));
  Interceptor.flush();
}
if (CONFIG.test) {
  fixture = new CModule(`
    extern int fixture_offset;
    typedef int (*Hit)(void *,int,int);
    typedef void (*Ground)(void *,Hit,void *);
    int fake_hit(void *p,int defended,int hit) {
      if(defended) (*(int *)p)++;
      return hit;
    }
    void fake_ground(void *side,Hit fn,void *p) {
      fn(p,1,0); fn(p,1,1); fn(p,0,0); fn(p,0,1);
    }
    void run(Ground fn,Hit hit,void *p,int n) {
      int i; for(i=0;i<n;i++) { int side=i%2; fn(&side,hit,p); }
      hit(p,1,0); hit(p,0,1);
    }
    typedef struct { Ground ground; Hit hit; void *target; int n; } Work;
    unsigned long worker(void *data) {
      Work *w = (Work *) data;
      run(w->ground,w->hit,w->target,w->n);
      return 0;
    }
    void detail_round(long long value) { volatile long long v=value; v++; }
    int detail_hit(void *p,long long threshold,int flags) {
      if(flags&1) (*(int *)((char *)p+fixture_offset))++;
      return flags>>1;
    }
    void detail_dice(void *side,int count,void *target,long long factor) {
      detail_hit(target,800000,1); detail_hit(target,800000,3);
      detail_hit(target,800000,0); detail_hit(target,800000,2);
    }
    void detail_ground(void *side,void *unused,void *src,void *target,long long share) {
      detail_round(450000);
      detail_dice(side,4,target,100000);
    }
    long long *fake_width(void *unit,long long *out,void *unused) {
      *out=*(long long *)((char *)unit+0x280);return out;
    }
    void detail_allocation(void *side,void *enemy,void *src,void *target) {
      detail_ground(side,enemy,src,target,50000);
      detail_ground(enemy,side,target,src,50000);
    }
  `,{fixture_offset:fixtureOffset});
  install(fixture.fake_hit, fixture.fake_ground);
  runFixture = new NativeFunction(fixture.run,'void',['pointer','pointer','pointer','int']);
} else {
  const module = Process.getModuleByName('hoi4.exe');
  function verified(name) {
    const f = CONFIG.functions[name];
    const address = module.base.add(f.rva);
    const bytes = Array.from(new Uint8Array(address.readByteArray(f.prologue.length/2)));
    const actual = bytes.map(b=>b.toString(16).padStart(2,'0')).join('');
    if(actual!==f.prologue) throw new Error(name+': メモリ上の命令が対応表と一致しません');
    return address;
  }
  const hit = verified('hit'), ground = verified('ground');
  const dice = verified('dice');
  const rounding = CONFIG.details ? verified('rounding') : null;
  if(CONFIG.width40) {
    const width=verified('width'), allocation=verified('allocation');
    width_filter.add(4).writeS32(CONFIG.active_list_offset);
    width_filter.add(8).writeS32(CONFIG.active_count_offset);
    width_filter.add(16).writePointer(width);
    listeners.push(Interceptor.attach(allocation,{onEnter:cm.allocation_enter,onLeave:cm.allocation_leave}));
    width_filter.writeS32(1);
  }
  install(hit,ground);
  if(CONFIG.details) {
    detailListeners.push(Interceptor.attach(dice,{onEnter:cm.dice_enter}));
    detailListeners.push(Interceptor.attach(rounding,{onEnter:cm.rounding_enter}));
    Interceptor.flush();
    trace.writeU64(1);
  }
}
rpc.exports = {
  widthcase(value, placement) {
    if(!CONFIG.test) throw new Error('test only');
    if(!filterFixtureInstalled) {
      listeners.push(Interceptor.attach(fixture.detail_allocation,{onEnter:cm.allocation_enter,onLeave:cm.allocation_leave}));
      listeners.push(Interceptor.attach(fixture.detail_ground,{onEnter:cm.ground_enter,onLeave:cm.ground_leave}));
      listeners.push(Interceptor.attach(fixture.detail_hit,{onEnter:cm.hit_enter,onLeave:cm.hit_leave}));
      listeners.push(Interceptor.attach(fixture.detail_dice,{onEnter:cm.dice_enter}));
      listeners.push(Interceptor.attach(fixture.detail_round,{onEnter:cm.rounding_enter}));
      width_filter.add(4).writeS32(8);width_filter.add(8).writeS32(16);
      width_filter.add(16).writePointer(fixture.fake_width);width_filter.writeS32(1);
      trace.writeU64(1);Interceptor.flush();filterFixtureInstalled=true;
    }
    const vt=Memory.alloc(0x180);vt.add(0x170).writePointer(fixture.fake_width);
    const keep=[vt];
    function unit(width) {
      const u=Memory.alloc(0x300),s=Memory.alloc(0x300);
      u.writePointer(vt);u.add(0x138).writePointer(s);u.add(0x280).writeS64(width);
      keep.push(u,s);return u;
    }
    const src=unit(2000000),dst=unit(2000000),extra=unit(value);
    function side(flag,first,extraActive) {
      const p=Memory.alloc(32),list=Memory.alloc(16);
      p.writeU8(flag);list.writePointer(first);list.add(8).writePointer(extra);
      p.add(8).writePointer(list);p.add(16).writeS32(extraActive ? 2 : 1);
      keep.push(p,list);return p;
    }
    const a=side(1,src,placement==='left'),b=side(0,dst,placement==='right');
    const call=new NativeFunction(fixture.detail_allocation,'void',['pointer','pointer','pointer','pointer']);
    // Fixture defense-use counter must not overlap the vtable pointer.
    state.add(80).writeS32(0x254);
    fixtureOffset.writeS32(0x254);
    call(a,b,src,dst);
    return {counts:this.snapshot(),details:this.details()};
  },
  exercisedetails(n) {
    if(!CONFIG.test) throw new Error('test only');
    listeners.push(Interceptor.attach(fixture.detail_ground,{onEnter:cm.ground_enter,onLeave:cm.ground_leave}));
    listeners.push(Interceptor.attach(fixture.detail_dice,{onEnter:cm.dice_enter}));
    listeners.push(Interceptor.attach(fixture.detail_round,{onEnter:cm.rounding_enter}));
    listeners.push(Interceptor.attach(fixture.detail_hit,{onEnter:cm.hit_enter,onLeave:cm.hit_leave}));
    Interceptor.flush(); trace.writeU64(1);
    const src=Memory.alloc(0x300), target=Memory.alloc(0x300);
    const ss=Memory.alloc(0x300), ts=Memory.alloc(0x300), side=Memory.alloc(8);
    src.add(0x138).writePointer(ss);target.add(0x138).writePointer(ts);
    [ss,ts].forEach((s,i)=>{
      s.add(0xc0).writeS64(10000000+i*10000000); s.add(0xc8).writeS64(5000000);
      s.add(0xb8).writeS64(25000);s.add(0xa8).writeS64(8000000);s.add(0xb0).writeS64(12000000);
    });
    const call=new NativeFunction(fixture.detail_ground,'void',['pointer','pointer','pointer','pointer','int64']);
    for(let i=0;i<n;i++) {side.writeU8(i%2); call(side,ptr(0),src,target,50000);}
    return this.details();
  },
  details() {
    takeTrace(traceBuffer);
    const records=[];
    for(let i=0;i<1000;i++) {
      const p=traceBuffer.add(32+i*320);
      if(p.readU64().toString()==='1')
        records.push(Array.from({length:40},(_,j)=>p.add(j*8).readS64().toString()));
    }
    if(records.length===1000) {
      for(const listener of detailListeners) listener.detach();
      detailListeners=[]; Interceptor.flush();
    }
    return {records,reserved:[traceBuffer.add(16).readU64().toString(),traceBuffer.add(24).readU64().toString()]};
  },
  snapshot() {
    takeSnapshot(buf);
    return Array.from({length:17},(_,i)=>buf.add(i*8).readU64().toString());
  },
  exercise(n) {
    if(!CONFIG.test) throw new Error('test only');
    const target = Memory.alloc(8);
    runFixture(fixture.fake_ground,fixture.fake_hit,target,n);
    return target.readS32();
  },
  parallel(n, count) {
    if(!CONFIG.test) throw new Error('test only');
    const create = new NativeFunction(kernel.getExportByName('CreateThread'),'pointer',
      ['pointer','size_t','pointer','pointer','uint','pointer']);
    const wait = new NativeFunction(kernel.getExportByName('WaitForSingleObject'),'uint',['pointer','uint']);
    const close = new NativeFunction(kernel.getExportByName('CloseHandle'),'int',['pointer']);
    const jobs=[];
    for(let i=0;i<count;i++) {
      const target=Memory.alloc(8), work=Memory.alloc(32);
      work.writePointer(fixture.fake_ground);
      work.add(8).writePointer(fixture.fake_hit);
      work.add(16).writePointer(target);
      work.add(24).writeS32(n);
      const thread=create(ptr(0),0,fixture.worker,work,0,ptr(0));
      if(thread.isNull()) throw new Error('CreateThread failed');
      jobs.push({target,work,thread});
    }
    for(const job of jobs) {
      if(wait(job.thread,30000)!==0) throw new Error('worker timeout');
      close(job.thread);
    }
    return jobs.map(job=>job.target.readS32());
  },
  async stop() {
    for(const listener of detailListeners) listener.detach();
    detailListeners=[];
    for(const listener of listeners) listener.detach();
    listeners=[];
    Interceptor.flush();
    for(let i=0;i<500;i++) {
      takeSnapshot(buf);
      if(buf.add(136).readU64().toString()==='0') return this.snapshot();
      await new Promise(resolve=>setTimeout(resolve,10));
    }
    throw new Error('実行中の判定が終了しません。最後の保存分を使用してください。');
  }
};
