#include <gum/guminterceptor.h>
#include <stdint.h>

/* State and lock live in writable memory owned by JS, never in game objects. */
extern void acquire(void *lock);
extern void release(void *lock);
extern unsigned long thread_id(void);
typedef struct { unsigned long id; int depth; int role; int64_t *record; int allocation_depth; int allowed; int selected; } Thread;
typedef int64_t *(*WidthGetter)(void *,int64_t *,void *);
typedef struct { int enabled,list_offset,count_offset,pad; WidthGetter width; } Filter;
extern Filter width_filter;
typedef struct { uint64_t enabled, sequence, reserved[2]; int64_t records[1000][40]; } Trace;
extern Trace trace;
typedef struct { int role; int64_t *record; int64_t *current; int selected; } Ground;
typedef struct {
  void *lock;
  uint64_t counts[8];
  uint64_t errors;
  int offset;
  int side_offset;
  Thread threads[256];
  uint64_t active;
  uint64_t roles[8];
} State;
extern State state;
typedef struct { int *used; int before; int group; int role; int64_t *record; } Hit;

static void stats(int64_t *out, void *unit) {
  char *s=*(char **)((char *)unit+0x138);
  out[0]=*(int64_t *)(s+0xc0); out[1]=*(int64_t *)(s+0xc8);
  out[2]=*(int64_t *)(s+0xb8); out[3]=*(int64_t *)(s+0xa8);
  out[4]=*(int64_t *)(s+0xb0);
}

static Thread *get_thread(void) {
  unsigned long id = thread_id();
  unsigned int i;
  for (i=0; i<256; i++) {
    if (state.threads[i].id == id) return &state.threads[i];
    if (state.threads[i].id == 0) {
      state.threads[i].id = id;
      return &state.threads[i];
    }
  }
  state.errors++;
  return 0;
}
/* Read the same width query used by targeting, with no tooltip output or RNG call. */
static int side_has_40(char *side) {
  int i,n=*(int *)(side+width_filter.count_offset);
  void **units=*(void ***)(side+width_filter.list_offset);
  if(n<0 || n>10000 || (n && !units)) return -1;
  for(i=0;i<n;i++) {
    void *unit=units[i]; int64_t width=0;
    if(!unit || !*(void **)unit) return -1;
    if(*(WidthGetter *)((char *)*(void **)unit+0x170)!=width_filter.width) return -1;
    if(width_filter.width(unit,&width,0)!=&width || width<0 || width>100000000) return -1;
    if(width==4000000) return 1;
  }
  return 0;
}
void allocation_enter(GumInvocationContext *ctx) {
  int *previous=gum_invocation_context_get_listener_invocation_data(ctx,sizeof(int));
  Thread *t;
  acquire(&state.lock);t=get_thread();
  if(t) { *previous=t->allowed;t->allowed=-1;t->allocation_depth++;state.active++; }
  release(&state.lock);
}
void allocation_leave(GumInvocationContext *ctx) {
  int *previous=gum_invocation_context_get_listener_invocation_data(ctx,sizeof(int));
  Thread *t;
  acquire(&state.lock);t=get_thread();
  if(t && t->allocation_depth>0) {t->allowed=*previous;t->allocation_depth--;state.active--;}
  else state.errors++;
  release(&state.lock);
}
static int selected_ground(GumInvocationContext *ctx) {
  Thread *t;int result,a,b;
  if(!width_filter.enabled) return 1;
  acquire(&state.lock);t=get_thread();
  if(!t || !t->allocation_depth) {state.errors++;release(&state.lock);return 0;}
  result=t->allowed;release(&state.lock);
  if(result>=0) return result;
  /* First ground call occurs after reinforcement. Cache only for this allocation call. */
  a=side_has_40(gum_invocation_context_get_nth_argument(ctx,0));
  b=side_has_40(gum_invocation_context_get_nth_argument(ctx,1));
  result=(a==1 || b==1);
  acquire(&state.lock);
  if(a<0 || b<0) {state.errors++;result=0;}
  t->allowed=result;release(&state.lock);return result;
}
void ground_enter(GumInvocationContext *ctx) {
  Thread *t;
  int selected=selected_ground(ctx);
  Ground *previous = gum_invocation_context_get_listener_invocation_data(ctx, sizeof(Ground));
  unsigned char flag = *((unsigned char *)gum_invocation_context_get_nth_argument(ctx,0)+state.side_offset);
  acquire(&state.lock);
  t = get_thread();
  if (t) {
    previous->role=t->role; previous->record=t->record; previous->current=0;
    previous->selected=t->selected;t->selected=selected;
    t->record=0;
    t->depth++;
    /* Same context passed to dice: flag 0 selects breakthrough (+0xb0), 1 defense (+0xa8). */
    t->role=flag<=1 ? flag : -1;
    if(flag>1) state.errors++;
    state.active++;
    if(trace.enabled && flag<=1) {
      uint64_t sequence=++trace.sequence;
      if(selected && trace.reserved[flag]<500) {
        uint64_t n=trace.reserved[flag]++;
        int64_t *r=trace.records[flag*500+n];
        r[1]=sequence; r[2]=n+1; r[3]=flag;
        r[4]=(intptr_t)gum_invocation_context_get_nth_argument(ctx,0);
        r[5]=(intptr_t)gum_invocation_context_get_nth_argument(ctx,2);
        r[6]=(intptr_t)gum_invocation_context_get_nth_argument(ctx,3);
        r[7]=(intptr_t)gum_invocation_context_get_nth_argument(ctx,4);
        stats(r+8,(void *)(intptr_t)r[5]); stats(r+13,(void *)(intptr_t)r[6]);
        r[21]=*(int *)((char *)(intptr_t)r[6]+state.offset);
        t->record=r; previous->current=r;
        if(trace.reserved[0]==500 && trace.reserved[1]==500) trace.enabled=0;
      }
    }
  }
  release(&state.lock);
}
void ground_leave(GumInvocationContext *ctx) {
  Thread *t;
  Ground *previous = gum_invocation_context_get_listener_invocation_data(ctx, sizeof(Ground));
  acquire(&state.lock);
  t = get_thread();
  if (t && t->depth>0) {
    if(previous->current) {
      int64_t *r=previous->current;
      r[22]=*(int *)((char *)(intptr_t)r[6]+state.offset); r[0]=1;
    }
    t->depth--; t->role=previous->role; t->record=previous->record; t->selected=previous->selected; state.active--;
  }
  else state.errors++;
  release(&state.lock);
}
void hit_enter(GumInvocationContext *ctx) {
  Hit *h = gum_invocation_context_get_listener_invocation_data(ctx, sizeof(Hit));
  Thread *t;
  h->used = (int *)((char *)gum_invocation_context_get_nth_argument(ctx,0)+state.offset);
  h->before = *h->used;
  acquire(&state.lock);
  state.active++;
  t = get_thread();
  h->group = t ? (t->depth>0 ? (t->selected ? 0 : -2) : (width_filter.enabled ? -2 : 1)) : -1;
  h->role=t ? t->role : -1;
  h->record=t ? t->record : 0;
  if(h->record) {
    int64_t threshold=(intptr_t)gum_invocation_context_get_nth_argument(ctx,1);
    if(h->record[31] && threshold!=h->record[20]) h->record[27]++;
    h->record[20]=threshold; h->record[31]=1;
  }
  release(&state.lock);
}
void hit_leave(GumInvocationContext *ctx) {
  Hit *h = gum_invocation_context_get_listener_invocation_data(ctx, sizeof(Hit));
  int delta = *h->used-h->before;
  int hit = ((uintptr_t)gum_invocation_context_get_return_value(ctx) & 255) != 0;
  acquire(&state.lock);
  if (h->group>=0 && (delta==0 || delta==1)) {
    /* Each group: defended miss, defended hit, undefended miss, undefended hit. */
    state.counts[h->group*4 + (delta==1 ? 0 : 2) + hit]++;
    if(h->group==0 && h->role>=0) state.roles[h->role*4 + (delta==1 ? 0 : 2) + hit]++;
    if(h->record) h->record[23+(delta==1 ? 0 : 2)+hit]++;
  } else if(h->group!=-2) { state.errors++; if(h->record) h->record[27]++; }
  state.active--;
  release(&state.lock);
}
void dice_enter(GumInvocationContext *ctx) {
  Thread *t;
  acquire(&state.lock); t=get_thread();
  if(t && t->record) {
    t->record[18]=(int)(intptr_t)gum_invocation_context_get_nth_argument(ctx,1);
    t->record[19]=(intptr_t)gum_invocation_context_get_nth_argument(ctx,3);
    t->record[28]++;
  }
  release(&state.lock);
}
void rounding_enter(GumInvocationContext *ctx) {
  Thread *t;
  acquire(&state.lock); t=get_thread();
  if(t && t->record) {
    t->record[29]=ctx->cpu_context->rcx; t->record[30]++;
  }
  release(&state.lock);
}
void trace_snapshot(Trace *out) {
  unsigned int i,j;
  acquire(&state.lock);
  out->enabled=trace.enabled; out->sequence=trace.sequence;
  out->reserved[0]=trace.reserved[0]; out->reserved[1]=trace.reserved[1];
  for(i=0;i<1000;i++) for(j=0;j<40;j++) out->records[i][j]=trace.records[i][j];
  release(&state.lock);
}
void snapshot(uint64_t *out) {
  int i;
  acquire(&state.lock);
  for(i=0;i<8;i++) out[i]=state.counts[i];
  out[8]=state.errors;
  for(i=0;i<8;i++) out[9+i]=state.roles[i];
  out[17]=state.active;
  release(&state.lock);
}
