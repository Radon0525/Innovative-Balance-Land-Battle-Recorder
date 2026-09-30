"""Bounded per-source/target attack traces, independent of cumulative checkpoints."""
import csv
import html
import io
import json
from pathlib import Path
from decimal import Decimal

HEADERS=['番号','発生順','攻撃する側','攻撃側SA','攻撃側HA','攻撃側突破',
         '防御側SA','防御側HA','防御側防御','受け手の装甲化率','攻撃配分率',
         '端数処理前の判定数','予定判定数','実施判定数','防御/突破枠（端数処理前）',
         '使用済み・前','使用済み・後','適用・不命中','適用・命中','超過・不命中','超過・命中',
         '確認','攻撃元ID','攻撃先ID','処理文脈ID','攻撃側の国','防御側の国','射撃方向']

def fixed(value):
    return format(Decimal(value)/100000,'f')

def trunc(value,denom=100000):
    return (1 if value>=0 else -1)*(abs(value)//denom)

def row_values(r,tags=None):
    r=list(map(int,r))
    attacker,defender=(r[8:13],r[13:18]) if r[3]==1 else (r[13:18],r[8:13])
    actual=sum(r[23:27])
    valid=r[27]==0 and r[28]==1 and r[30]==1 and actual<=r[18] and r[22]-r[21]==sum(r[23:25])
    status='正常' if valid and actual==r[18] else ('途中終了' if valid else '要確認')
    return [str(r[2])+('a' if r[3]==1 else 'b'),r[1],'攻撃側' if r[3]==1 else '防御側',
            *map(fixed,[attacker[0],attacker[1],attacker[4],defender[0],defender[1],defender[3],r[15],r[7]]),
            fixed(r[29]) if r[30] else '未観測',r[18] if r[28] else '未観測',actual,
            fixed(r[20]) if r[31] else '未観測',r[21],r[22],*r[23:27],status,
            hex(r[5]),hex(r[6]),hex(r[4]),*country_labels(r,tags)]

def country_labels(r,tags=None):
    from country_report import direction_labels
    return direction_labels(int(r[32]),int(r[33]),int(r[3]),tags)

def explanation(r,tags=None):
    r=list(map(int,r)); src=r[8:13]; dst=r[13:18]
    soft=trunc(trunc(src[0]*10000)*(100000-dst[2]))
    hard=trunc(trunc(src[1]*10000)*dst[2])
    base=soft+hard
    defense=dst[3] if r[3] else dst[4]
    threshold=trunc(trunc(defense*10000)*r[19])
    return (f'攻撃側 ⇔ 防御側：{country_labels(r,tags)[2]}\n攻撃元 {hex(r[5])} → 攻撃先 {hex(r[6])}\n'
      f'SA={fixed(src[0])}、HA={fixed(src[1])}、相手の装甲化率={fixed(dst[2])}。\n'
      f'基礎判定数 ≈ (SA × (1−装甲化率) + HA × 装甲化率) ÷ 10。'
      f'ゲームと同じ固定小数点の切り捨てを入れると {fixed(base)}。\n'
      f'攻撃配分率={fixed(r[7])}。配分・各種補正を適用した後にゲームから観測した値は '
      f'{fixed(r[29]) if r[30] else "未観測"}。各補正の個別内訳は未記録。\n'
      f'この値の整数部分に、端数から求めた確率で1を加える。予定判定数={r[18]}、実施={sum(r[23:27])}。\n'
      f'受け手の{"防御" if r[3] else "突破"}={fixed(defense)}、補正倍率={fixed(r[19])}。'
      f'値 ÷ 10 × 補正倍率（各段階を切り捨て）={fixed(threshold)}。'
      f'命中処理に渡された実測値={fixed(r[20]) if r[31] else "未観測"}。\n'
      '防御枠の端数判定は命中判定ごとに行われるため、小数部分を単純に四捨五入して枠数とはしない。\n'
      f'使用済み枠 {r[21]} → {r[22]}。適用中：不命中 {r[23]}／命中 {r[24]}、'
      f'超過後：不命中 {r[25]}／命中 {r[26]}。\n'
      'SA/HAはこの処理時点の能力値。全軍の合計や師団設計画面の値ではない。'
      'IDはこのセッション内のメモリアドレスで、師団名・永続IDではない。')

def ordered(data):
    return sorted(data['records'],key=lambda r:(int(r[2]),-int(r[3])))

def save_details(folder,data):
    from recorder import atomic_text
    from group_report import render_groups_html
    folder=Path(folder)
    records=ordered(data)
    limit=data.get('limit_per_side',500)
    counts={side:sum(int(r[3])==flag for r in records) for side,flag in [('a',1),('b',0)]}
    data=dict(data,format_version=1,completed=counts,limit_per_side=data.get('limit_per_side',500))
    atomic_text(folder/'details.json',json.dumps(data,ensure_ascii=False,indent=2)+'\n')
    stream=io.StringIO(newline='');writer=csv.writer(stream,lineterminator='\n');writer.writerow(HEADERS)
    writer.writerows(row_values(r,data.get('country_tags')) for r in records)
    atomic_text(folder/'details.csv','\ufeff'+stream.getvalue())
    rows=''.join('<tr class="'+('a' if int(r[3]) else 'b')+'">'+''.join('<td>'+html.escape(str(v))+'</td>' for v in row_values(r,data.get("country_tags")))+'</tr>' for r in records)
    notes=''.join('<details><summary>'+row_values(r)[0]+' の計算</summary><pre>'+html.escape(explanation(r,data.get("country_tags")))+'</pre></details>' for r in records)
    grouped_html=render_groups_html(data)
    atomic_text(folder/'details.html','''<!doctype html><meta charset="utf-8"><title>個別攻撃の記録</title>
<style>body{font:15px system-ui;margin:24px;background:#f3f6fa;color:#17263c}h1{font-size:24px}p{line-height:1.7}.sheet{overflow:auto;max-height:65vh;background:white;border:1px solid #b8c6d8}table{border-collapse:separate;border-spacing:0;white-space:nowrap;font-variant-numeric:tabular-nums}th,td{padding:9px 12px;border-right:1px solid #d6dfeb;border-bottom:1px solid #d6dfeb;text-align:right}th{position:sticky;top:0;background:#213e60;color:white;z-index:2}td:first-child{position:sticky;left:0;background:#e6edf6;font-weight:bold}.a{background:#edf6ff}.b{background:#fff6e8}pre{white-space:pre-wrap;line-height:1.7}details{background:white;padding:12px;margin:8px 0}</style>
<h1>個別攻撃の記録</h1>'''+f'<p>保存済み：a（攻撃側）{counts["a"]} / {limit}件、b（防御側）{counts["b"]} / {limit}件。</p>'+grouped_html+'<h2>個別処理の表</h2>'+'''
<p>1行＝1師団から1対象への攻撃処理。1行の中で複数回の命中判定が行われます。<br>
1aと1bはそれぞれの側の1件目で、同じ戦闘・時刻・師団同士の応酬を意味しません。実際の順番は「発生順」で確認できます。<br>
攻撃値はSA（対人）とHA（対戦車）を分けて表示。配分率と装甲化率は1＝100%。空欄の代わりに未観測を表示します。</p>
<label>表示する側 <select onchange="document.querySelectorAll('tbody tr').forEach(r=>r.hidden=this.value!=='all'&&!r.classList.contains(this.value))"><option value="all">両側</option><option value="a">a：攻撃側</option><option value="b">b：防御側</option></select></label>
<p><a href="details.csv">表をCSVで開く</a> ／ <a href="report.html">全体集計</a></p><div class="sheet"><table><thead><tr>'''+''.join('<th>'+html.escape(h)+'</th>' for h in HEADERS)+'</tr></thead><tbody>'+rows+'</tbody></table></div><h2>各行の計算</h2>'+notes)
    return counts

def show_details(root,folder,subset=None):
    import tkinter as tk
    from tkinter import ttk,messagebox
    try:data=json.loads((Path(folder)/'details.json').read_text(encoding='utf-8'))
    except (OSError,ValueError) as exc:
        messagebox.showinfo('個別攻撃の記録',f'個別記録はまだ保存されていません。\n{exc}',parent=root);return
    records=ordered(data)
    if subset is not None:records=[r for r in records if int(r[1]) in subset]
    w=tk.Toplevel(root);w.title('個別攻撃の記録');w.geometry('1250x720')
    ttk.Label(w,text=f'表示中 {len(records)}件'+('（選択した対象の処理）' if subset is not None else f" / 最大{data.get('limit_per_side',500)*2}件")+'。a・bは各側の発生順です。同じ番号でも同じ戦闘とは限りません。\n行を選ぶと計算の説明を表示します。横スクロールで内訳を確認できます。',padding=12).pack(anchor='w')
    from group_report import show_groups
    ttk.Button(w,text='攻撃先ごとのまとめ',command=lambda:show_groups(root,folder)).pack(anchor='w',padx=12,pady=(0,8))
    frame=ttk.Frame(w);frame.pack(fill='both',expand=True)
    tree=ttk.Treeview(frame,columns=list(range(len(HEADERS))),show='headings')
    for i,h in enumerate(HEADERS):tree.heading(i,text=h);tree.column(i,width=140,anchor='e',stretch=False)
    x=ttk.Scrollbar(frame,orient='horizontal',command=tree.xview);y=ttk.Scrollbar(frame,command=tree.yview)
    tree.configure(xscrollcommand=x.set,yscrollcommand=y.set)
    tree.grid(row=0,column=0,sticky='nsew');y.grid(row=0,column=1,sticky='ns');x.grid(row=1,column=0,sticky='ew')
    frame.rowconfigure(0,weight=1);frame.columnconfigure(0,weight=1)
    tree.tag_configure('a',background='#edf6ff');tree.tag_configure('b',background='#fff6e8')
    tree.configure(displaycolumns=[0,25,26,27,*range(1,25)])
    tree.column(27,width=350)
    for i,r in enumerate(records):tree.insert('','end',iid=str(i),values=row_values(r,data.get('country_tags')),tags=('a' if int(r[3]) else 'b',))
    text=tk.Text(w,height=13,wrap='word',font=('',10));text.pack(fill='x',padx=12,pady=12);text.configure(state='disabled')
    def select(event):
        if tree.selection():
            text.configure(state='normal');text.delete('1.0','end');text.insert('end',explanation(records[int(tree.selection()[0])],data.get('country_tags'))) ;text.configure(state='disabled')
    tree.bind('<<TreeviewSelect>>',select)
    ttk.Button(w,text='更新',command=lambda:(w.destroy(),show_details(root,folder,subset=subset))).pack(pady=6)
    return w
