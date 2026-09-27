"""HOI4 defense telemetry: native counters, bounded memory, cumulative checkpoints."""
import argparse
import csv
import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import hashlib
import html
import json
import os
from pathlib import Path
import queue
import threading
import time
import uuid

BASE = Path(__file__).resolve().parent
LABELS = ['防御適用・不命中', '防御適用・命中', '防御超過・不命中', '防御超過・命中']
COLUMNS = ['utc', 'elapsed_seconds'] + [f'{group}_{key}' for group in ('ground','other')
           for key in ('defended_miss','defended_hit','undefended_miss','undefended_hit')] + ['measurement_errors']
COLUMNS += [f'{role}_{key}' for role in ('attacker_breakthrough','defender_defense')
            for key in ('covered_miss','covered_hit','uncovered_miss','uncovered_hit')]

def source(config):
    return ('const CONFIG = '+json.dumps(config)+';\nconst COUNTER_SOURCE = '+
            json.dumps((BASE/'counter.c').read_text(encoding='utf-8'))+';\n'+
            (BASE/'agent.js').read_text(encoding='utf-8'))

def process_path(pid):
    k = ctypes.WinDLL('kernel32', use_last_error=True)
    k.OpenProcess.argtypes = [wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]
    k.OpenProcess.restype = wintypes.HANDLE
    k.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE,wintypes.DWORD,wintypes.LPWSTR,ctypes.POINTER(wintypes.DWORD)]
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = k.OpenProcess(0x1000,False,pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        buf = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(buf))
        if not k.QueryFullProcessImageNameW(handle,0,buf,ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        return Path(buf.value)
    finally:
        k.CloseHandle(handle)

def profile_for(path):
    with path.open('rb') as f:
        digest = hashlib.file_digest(f,'sha256').hexdigest()
    for profile in json.loads((BASE/'profiles.json').read_text(encoding='utf-8')):
        if profile['sha256'] == digest:
            return profile
    raise RuntimeError('未対応のHOI4です。誤計測を避けるため接続しません。SHA-256: '+digest)

def metrics(values):
    total = sum(values)
    defended = values[0]+values[1]
    un = values[2]+values[3]
    return {'attacks':total,'defended':defended,'undefended':un,
            'defense_coverage':defended/total if total else None,
            'defended_hit_rate':values[1]/defended if defended else None,
            'undefended_hit_rate':values[3]/un if un else None}

def percent(value):
    return '—' if value is None else f'{value:.2%}'

def role_metrics(counts):
    if len(counts)<17:return None
    result={}
    for name,start in [('attacker_breakthrough',9),('defender_defense',13)]:
        m=metrics(counts[start:start+4])
        m['covered_avoid_rate']=counts[start]/m['defended'] if m['defended'] else None
        result[name]=m
    return result

def atomic_text(path, text):
    tmp = path.with_suffix(path.suffix+'.tmp')
    tmp.write_text(text,encoding='utf-8')
    tmp.replace(path)

def filter_label(meta):
    return '40幅の師団が交戦中の戦闘のみ' if meta.get('width40_filter') else '幅による絞り込みなし'

def save_report(folder, counts, meta):
    roles=role_metrics(counts)
    summary = dict(meta, counts=counts, ground=metrics(counts[:4]), other=metrics(counts[4:8]), measurement_errors=counts[8],roles=roles)
    atomic_text(folder/'summary.json',json.dumps(summary,ensure_ascii=False,indent=2)+'\n')
    m = summary['ground']
    rows=''.join(f'<tr><td>{label}</td><td>{counts[i]:,}</td></tr>' for i,label in enumerate(LABELS))
    if roles is None:
        role_html='<p>この記録は旧版の合算データです。攻撃側の突破・防御側の防御には分離できません。</p>'
    else:
        role_html='<h2>攻撃側の突破・防御側の防御</h2><table><tr><th>受け手の役割</th><th>受けた攻撃</th><th>適用率</th><th>適用中の不命中率</th></tr>'
        for key,label in [('attacker_breakthrough','攻撃側の突破'),('defender_defense','防御側の防御')]:
            r=roles[key]
            role_html+=f"<tr><td>{label}</td><td>{r['attacks']:,}</td><td>{percent(r['defense_coverage'])}</td><td>{percent(r['covered_avoid_rate'])}</td></tr>"
        role_html+='</table><p>適用率＝その役割の師団が受けた攻撃のうち、突破／防御の枠が使われた割合。戦闘勝率・敵陣突破率ではありません。国を切り替えても各戦闘での受け手の役割により分類します。</p>'
    atomic_text(folder/'report.html',f'''<!doctype html><html lang="ja"><meta charset="utf-8">
<title>HOI4 戦闘計測</title><style>body{{background:#101827;color:#e2e8f0;font:17px system-ui;margin:40px auto;max-width:850px;padding:24px}}h1{{color:#7dd3fc}}table{{border-collapse:collapse;width:100%}}td{{padding:12px;border-bottom:1px solid #334155}}.cards{{display:flex;gap:24px;flex-wrap:wrap}}.card{{background:#1e293b;padding:22px;border-radius:12px}}b{{font-size:30px;display:block}}small,p{{line-height:1.8}}</style>
<h1>HOI4 戦闘計測</h1><p>{html.escape(meta['version'])} ／ 状態：{html.escape(meta['status'])}<br>
開始：{html.escape(meta['started_at'])} ／ 最終保存：{html.escape(meta.get('updated_at',''))}<br>記録対象：{filter_label(meta)}</p>
{role_html}
{'<p><a href="details.html">個別1000件の表と計算を見る</a></p>' if (folder/'details.json').exists() else ''}
<h2>全体の合算</h2><div class="cards"><div class="card">地上攻撃判定<b>{m['attacks']:,}</b></div><div class="card">防御・突破の適用率<b>{percent(m['defense_coverage'])}</b></div></div>
<p>防御適用中の命中率：{percent(m['defended_hit_rate'])} ／ 防御超過後の命中率：{percent(m['undefended_hit_rate'])}</p>
<table>{rows}</table><p>別集計の判定：{sum(counts[4:8]):,} 回 ／ 計測異常：{counts[8]:,} 回</p>
<p>「防御適用」は防御／突破の使用カウンターが増えた攻撃です。不命中そのものを防御の効果と数えてはいません。
地上師団の損害処理内の判定を主集計にし、それ以外（CAS等の可能性を含む）は別集計です。</p>
<p>接続中にこのPCのゲームが処理した判定の合計です。国・師団名・戦闘数・ゲーム内日時による分類は未実装です。
複数プレイヤーの記録を足すと重複する可能性があります。途中開始・ロード・再試合は別セッションにしてください。
地上攻撃が0なら、計測期間中に対象判定を観測できていません。</p>
<p>異常終了時は直近の保存分までが有効です。保存間隔は実時間の5秒です。マルチの負荷・同期は未検証です。</p></html>''')

class Recorder:
    def __init__(self, notify=lambda event: None):
        self.notify=notify
        self.stop_event=threading.Event()
        self.folder=None

    def run(self, pid=None, interval=5, details=False, width40=False):
        import frida
        session=script=None
        counts=[0]*17
        meta=None
        failure=None
        detached=threading.Event()
        agent_errors=queue.Queue()
        try:
            device=frida.get_local_device()
            candidates=[p for p in device.enumerate_processes() if p.name.lower()=='hoi4.exe' and (pid is None or p.pid==pid)]
            if len(candidates)!=1:
                raise RuntimeError('HOI4を1つ起動してから開始してください。複数起動時はCLIの --pid で指定できます。')
            pid=candidates[0].pid
            exe=process_path(pid)
            profile=profile_for(exe)
            profile=dict(profile,details=details,width40=width40)
            self.folder=BASE/'recordings'/(datetime.now().strftime('%Y%m%d-%H%M%S')+'-'+uuid.uuid4().hex[:6])
            self.folder.mkdir(parents=True)
            meta={'version':profile['version'],'exe':str(exe),'sha256':profile['sha256'],'pid':pid,
                  'started_at':datetime.now(timezone.utc).isoformat(),'status':'準備中','interval_seconds':interval,
                  'scope':'All observed ground damage calls on this process; no country or division filter',
                  'counts':'Cumulative since attach; do not sum checkpoint rows','format_version':2,
                  'width40_filter':width40}
            save_report(self.folder,counts,meta)
            if details:
                from detail_report import save_details
                save_details(self.folder,{'records':[],'reserved':[0,0],'width40_filter':width40})
            session=device.attach(pid)
            session.on('detached',lambda *args: detached.set())
            script=session.create_script(source(profile))
            def message(msg,data):
                if msg['type']=='error':
                    agent_errors.put(msg.get('stack',msg.get('description','agent error')))
            script.on('message',message)
            script.load()
            started=time.monotonic()
            meta['status']='収集中'
            self.notify({'status':'収集中','folder':str(self.folder),'version':profile['version']})
            with (self.folder/'checkpoints.csv').open('w',encoding='utf-8-sig',newline='') as f:
                writer=csv.writer(f)
                writer.writerow(COLUMNS)
                def checkpoint(final=False):
                    nonlocal counts
                    new=[int(n) for n in (script.exports_sync.stop() if final else script.exports_sync.snapshot())]
                    if len(new)!=17 or any(a<b for a,b in zip(new,counts)):
                        raise RuntimeError('集計カウンターの整合性エラー')
                    counts=new
                    meta['updated_at']=datetime.now(timezone.utc).isoformat()
                    writer.writerow([meta['updated_at'],round(time.monotonic()-started,3),*counts])
                    f.flush()
                    os.fsync(f.fileno())
                    save_report(self.folder,counts,meta)
                    if details:
                        progress=save_details(self.folder,dict(script.exports_sync.details(),width40_filter=width40))
                        self.notify({'detail_progress':progress})
                    self.notify({'counts':counts,'folder':str(self.folder)})
                checkpoint()
                while not self.stop_event.wait(interval):
                    if detached.is_set():
                        meta['status']='ゲーム終了・切断（最終保存分まで）'
                        break
                    if not agent_errors.empty():
                        raise RuntimeError(agent_errors.get())
                    checkpoint()
                if not detached.is_set():
                    meta['status']='停止済み'
                    checkpoint(final=True)
        except Exception as exc:
            failure=str(exc)
            if meta:
                meta['status']='エラー（最終保存分まで）'
                meta['error']=failure
        finally:
            if script:
                try: script.unload()
                except Exception: pass
            if session:
                try: session.detach()
                except Exception: pass
            if meta:
                try: save_report(self.folder,counts,meta)
                except Exception as exc: failure=f'{failure or "保存エラー"}: {exc}'
            self.notify({'done':True,'error':failure,'folder':str(self.folder) if self.folder else None,
                         'status':meta['status'] if meta else '開始できませんでした'})

def latest_report():
    reports=list((BASE/'recordings').glob('*/summary.json'))
    return max(reports,key=lambda p:p.stat().st_mtime).parent if reports else None

def show_report_window(root,folder):
    import tkinter as tk
    from tkinter import ttk,messagebox
    folder=Path(folder)
    try:
        data=json.loads((folder/'summary.json').read_text(encoding='utf-8'))
        counts=data['counts']
        ground=metrics(counts[:4])
    except (OSError,ValueError,KeyError,TypeError) as exc:
        messagebox.showerror('結果を開けません',f'保存された集計を読み込めません。\n{folder}\n{exc}',parent=root)
        return None
    window=tk.Toplevel(root);window.title('陸戦の収集結果');window.geometry('760x770')
    frame=ttk.Frame(window,padding=20);frame.pack(fill='both',expand=True)
    ttk.Label(frame,text='陸戦の収集結果',font=('',18,'bold')).pack(anchor='w')
    ttk.Label(frame,text=f"{data.get('version','')} ／ {data.get('status','')}\n最終保存：{data.get('updated_at','')} ／ {filter_label(data)}",wraplength=630).pack(anchor='w',pady=10)
    table=ttk.Treeview(frame,columns=('value',),show='tree',height=18)
    table.column('#0',width=400);table.column('value',width=180,anchor='e')
    rows=[('地上攻撃の判定数',f"{ground['attacks']:,} 回"),
          ('防御・突破が適用された回数',f"{ground['defended']:,} 回"),
          ('防御・突破を超えた回数',f"{ground['undefended']:,} 回"),
          ('防御・突破の適用率',percent(ground['defense_coverage'])),
          ('防御適用中の命中率',percent(ground['defended_hit_rate'])),
          ('防御超過後の命中率',percent(ground['undefended_hit_rate'])),
          ('別集計の判定数',f'{sum(counts[4:8]):,} 回'),
          ('計測異常',f'{counts[8]:,} 回')]
    roles=role_metrics(counts)
    if roles:
        separate=[]
        for key,label in [('attacker_breakthrough','攻撃側の突破'),('defender_defense','防御側の防御')]:
            r=roles[key]
            separate.extend([(f'{label}：受けた攻撃',f"{r['attacks']:,} 回"),
                             (f'{label}：適用回数',f"{r['defended']:,} 回"),
                             (f'{label}：適用率',percent(r['defense_coverage'])),
                             (f'{label}：適用中の不命中率',percent(r['covered_avoid_rate']))])
        rows=separate+rows
    else:rows.insert(0,('攻守別の内訳','旧版のため未記録'))
    for label,value in rows:table.insert('', 'end',text=label,values=(value,))
    table.pack(fill='x',pady=8)
    ttk.Label(frame,text='接続中の全体集計です。防御が適用された回数と、不命中の回数は別です。\n収集中は「更新」で最新の保存内容を読み直せます。',wraplength=630).pack(anchor='w',pady=10)
    path_var=tk.StringVar(value=str(folder))
    ttk.Entry(frame,textvariable=path_var,state='readonly').pack(fill='x',pady=8)
    controls=ttk.Frame(frame);controls.pack(anchor='w',pady=8)
    def open_external(path):
        try:os.startfile(str(path))
        except OSError as exc:messagebox.showerror('外部アプリで開けません',f'{path}\n{exc}',parent=window)
    def refresh():
        replacement=show_report_window(root,folder)
        if replacement is not None:window.destroy()
    ttk.Button(controls,text='更新',command=refresh).pack(side='left',padx=4)
    ttk.Button(controls,text='HTMLを開く',command=lambda:open_external(folder/'report.html')).pack(side='left',padx=4)
    ttk.Button(controls,text='保存先を開く',command=lambda:open_external(folder)).pack(side='left',padx=4)
    if (folder/'details.json').exists():
        from detail_report import show_details
        ttk.Button(controls,text='個別1000件の表',command=lambda:show_details(root,folder)).pack(side='left',padx=4)
        from group_report import show_groups
        ttk.Button(frame,text='攻撃先ごとのまとめ',command=lambda:show_groups(root,folder)).pack(anchor='w',padx=4)
    return window

def gui(smoke_test=False):
    # Tcl path normalization in this bundled runtime drops some Windows path components.
    # Use the local, unmodified Tcl/Tk scripts via relative paths.
    if (BASE/'.venv/tcl/tcl8.6/init.tcl').exists():
        os.chdir(BASE)
        os.environ['TCL_LIBRARY']='.venv/tcl/tcl8.6'
        os.environ['TK_LIBRARY']='.venv/tcl/tk8.6'
    import tkinter as tk
    from tkinter import ttk, messagebox
    root=tk.Tk()
    root.title('HOI4 戦闘の自動収集')
    root.geometry('780x690')
    frame=ttk.Frame(root,padding=24); frame.pack(fill='both',expand=True)
    ttk.Label(frame,text='HOI4 戦闘の自動収集',font=('',20,'bold')).pack(anchor='w')
    ttk.Label(frame,text='HOI4を起動 → 収集開始 → 試合 → 停止して結果を見る',padding=(0,12)).pack(anchor='w')
    status=tk.StringVar(value='待機中（対応：1.19.2 / 確認済み1.19.3）')
    stats=tk.StringVar(value='攻撃判定：0回\n防御・突破の適用率：—')
    ttk.Label(frame,textvariable=status,wraplength=640).pack(anchor='w',pady=8)
    ttk.Label(frame,textvariable=stats,font=('',15),justify='left').pack(anchor='w',pady=14)
    detail_enabled=tk.BooleanVar(value=True)
    detail_status=tk.StringVar(value='個別記録：a 0 / 500件・b 0 / 500件')
    detail_check=ttk.Checkbutton(frame,text='個別攻撃も記録（攻撃側500件＋防御側500件）',variable=detail_enabled)
    detail_check.pack(anchor='w')
    width40_enabled=tk.BooleanVar(value=False)
    width40_check=ttk.Checkbutton(frame,text='40幅の師団が交戦中の戦闘のみ記録',variable=width40_enabled)
    width40_check.pack(anchor='w')
    ttk.Label(frame,textvariable=detail_status).pack(anchor='w',pady=4)
    ttk.Label(frame,text='地上攻撃を全体集計。国別・師団別の分類は未実装です。\nゲームの能力値・乱数・命中結果は変更しません。\nまずシングルで確認してください。マルチの負荷・同期は未検証です。',wraplength=640).pack(anchor='w',pady=8)
    events=queue.Queue(); active=[None]; last_folder=[latest_report()]; closing=[False]
    buttons=ttk.Frame(frame); buttons.pack(anchor='w',pady=16)
    def start():
        active[0]=Recorder(events.put)
        start_button.config(state='disabled'); stop_button.config(state='normal')
        detail_check.config(state='disabled')
        width40_check.config(state='disabled')
        detail_status.set('個別記録：準備中' if detail_enabled.get() else '個別記録：無効')
        status.set('対応確認・接続中…')
        threading.Thread(target=active[0].run,kwargs={'details':detail_enabled.get(),'width40':width40_enabled.get()},daemon=False).start()
    def stop():
        if active[0]: active[0].stop_event.set(); status.set('保存して停止中…')
    def show_result():
        folder=last_folder[0] or latest_report()
        if folder:show_report_window(root,folder)
        else:messagebox.showinfo('収集結果','保存された結果はまだありません。収集開始後に確認してください。',parent=root)
    start_button=ttk.Button(buttons,text='収集開始',command=start); start_button.pack(side='left',padx=4)
    stop_button=ttk.Button(buttons,text='停止・保存',command=stop,state='disabled'); stop_button.pack(side='left',padx=4)
    ttk.Button(buttons,text='結果を見る',command=show_result).pack(side='left',padx=4)
    def poll():
        while not events.empty():
            event=events.get()
            if event.get('folder'): last_folder[0]=event['folder']
            if 'status' in event: status.set(event['status'])
            if 'detail_progress' in event:
                p=event['detail_progress']
                detail_status.set(f"個別記録：a {p['a']} / 500件・b {p['b']} / 500件"+('（完了）' if p['a']==p['b']==500 else ''))
            if 'counts' in event:
                c=event['counts']; m=metrics(c[:4])
                roles=role_metrics(c)
                detail=''
                if roles:
                    detail=f"\n攻撃側の突破 適用率：{percent(roles['attacker_breakthrough']['defense_coverage'])}\n防御側の防御 適用率：{percent(roles['defender_defense']['defense_coverage'])}"
                stats.set(f"攻撃判定：{m['attacks']:,}回{detail}\n計測異常：{c[8]:,}回")
            if event.get('done'):
                active[0]=None; start_button.config(state='normal'); stop_button.config(state='disabled')
                detail_check.config(state='normal')
                width40_check.config(state='normal')
                if event.get('error'): messagebox.showerror('収集を開始／継続できません',event['error'])
                if closing[0]: root.destroy(); return
        root.after(200,poll)
    def close():
        if active[0]: closing[0]=True; stop()
        else: root.destroy()
    root.protocol('WM_DELETE_WINDOW',close)
    root.after(200,poll)
    if smoke_test:
        root.withdraw()
        if last_folder[0]:
            result=show_report_window(root,last_folder[0])
            if result:result.withdraw()
        root.after(300,root.destroy)
    root.mainloop()

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--cli',action='store_true')
    parser.add_argument('--pid',type=int)
    parser.add_argument('--check',type=Path)
    parser.add_argument('--ui-check',action='store_true')
    parser.add_argument('--details',action='store_true',help='CLI: record first 500 source-target calls per side')
    parser.add_argument('--width40',action='store_true',help='Only battles with an active division of effective combat width 40')
    args=parser.parse_args()
    if args.check:
        print(json.dumps(profile_for(args.check),indent=2))
    elif args.cli:
        import signal
        recorder=Recorder(lambda event:print(json.dumps(event,ensure_ascii=False),flush=True))
        signal.signal(signal.SIGINT,lambda *a:recorder.stop_event.set())
        recorder.run(args.pid,details=args.details,width40=args.width40)
    else:
        gui(smoke_test=args.ui_check)
