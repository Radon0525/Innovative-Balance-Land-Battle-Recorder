"""Group observed records by target and context, never infer battle-hour boundaries."""
import html
import json
from pathlib import Path

NOTICE=('記録範囲全体のまとめです。ゲーム内の時間境界を記録していないため、複数時間の攻撃を含みます。'
        '「2体」は記録中に観測した攻撃元の種類数で、同時に2対1だったことの確定ではありません。'
        '保存された個別処理の抜粋で、戦闘全体の総数ではありません。')

def detail_scope(data):
    from recorder import filter_label
    scope='両陣営に30.00～50.00幅がいる戦闘の個別記録' if data.get('width_range_filter') else filter_label(data)
    if data.get('sample_interval_ms'):
        scope+='（実時間1秒に各側最大25件を抽出・無作為抽出ではありません）'
    return scope

def groups(data):
    records=sorted((list(map(int,r)) for r in data['records']),key=lambda r:r[1])
    names={}
    result={}
    for r in records:
        for address in (r[5],r[6]):
            if address not in names:names[address]=f'師団{len(names)+1}'
        key=(r[3],r[4],r[6])
        if key not in result:result[key]={'key':key,'records':[],'sources':{}}
        g=result[key];g['records'].append(r)
        g['sources'].setdefault(r[5],[]).append(r)
    return list(result.values()),names

def totals(records):
    counts=[sum(r[i] for r in records) for i in range(23,27)]
    actual=sum(counts);covered=sum(counts[:2])
    return [len(records),actual,counts[1]+counts[3],sum(counts[2:]),
            f'{covered/actual:.1%}' if actual else '—']

def defense_range(records):
    from detail_report import fixed
    values=[r[16] if r[3] else r[17] for r in records]
    low,high=min(values),max(values)
    return fixed(low) if low==high else f'{fixed(low)} ～ {fixed(high)}'

def attack_defense(records):
    """Convert observed pre-round pip values back to stat-scale units (x10)."""
    from detail_report import fixed
    missing_attack=sum(r[30]!=1 for r in records)
    missing_defense=sum(r[31]!=1 for r in records)
    attack=(f'未観測 {missing_attack}/{len(records)}処理' if missing_attack
            else fixed(sum(r[29] for r in records)*10))
    if missing_defense:
        defense=f'未観測 {missing_defense}/{len(records)}処理'
    else:
        values=[r[20]*10 for r in records]
        low,high=min(values),max(values)
        defense=fixed(low) if low==high else f'{fixed(low)} ～ {fixed(high)}'
    return [attack,defense]

def summary_values(records):
    return attack_defense(records)+totals(records)+[defense_range(records)]

def describe(group,names,records=None):
    from detail_report import row_values
    records=group['records'] if records is None else records
    role,context,target=group['key']
    sources=list(dict.fromkeys(r[5] for r in records))
    attack,defense=attack_defense(records)
    lines=[f'{" ＋ ".join(names[s] for s in sources)} → {names[target]}',
           f'攻撃合計（補正後）：{attack}　／　受け手の{"防御" if role else "突破"}（補正後）：{defense}',
           f'撃つ側：{"攻撃側（a）" if role else "防御側（b）"}　受け手の{"防御" if role else "突破"}：{defense_range(records)}',
           '師団の名前はこの表だけの仮名です。ゲーム内の師団名ではありません。',
           f'受け手ID：{hex(target)}　処理文脈ID：{hex(context)}',
           f'発生順：{min(r[1] for r in records)} ～ {max(r[1] for r in records)}（間に別対象の処理を含む場合があります）']
    for source in sources:
        rows=[r for r in records if r[5]==source]
        n,actual,hits,uncovered,rate=totals(rows)
        lines.append(f'{names[source]}：攻撃合計 {attack_defense(rows)[0]}、{n}処理、判定{actual}回、命中{hits}回、枠超過{uncovered}回、適用率{rate}／ID {hex(source)}')
    questionable=sum(row_values(r)[21]=='要確認' for r in records)
    partial=sum(row_values(r)[21]=='途中終了' for r in records)
    lines += [f'要確認の処理：{questionable}件 ／ 途中終了：{partial}件（どちらも集計に含む）',
              '攻撃合計＝各処理で観測した配分・補正後の端数処理前判定数の合計×10。防御／突破（補正後）＝実測した枠×10。同じ能力値の尺度へ換算しています。',
              '防御・突破は観測範囲の最小～最大で、足し合わせていません。攻撃合計は複数時間の累計を含むため、この2値の差を一回の戦闘の超過攻撃とは解釈しないでください。',NOTICE]
    return '\n'.join(lines)

def render_groups_html(data):
    grouped,names=groups(data)
    parts=['<h2>攻撃先ごとのまとめ</h2><p>記録対象：'+detail_scope(data)+'</p><p>'+html.escape(NOTICE)+'</p>',
           '<p>師団1・師団2…はこの表だけの仮名です。項目を開くと攻撃元別の内訳を読めます。</p>']
    for g in grouped:
        role,_,target=g['key'];n,actual,hits,uncovered,rate=totals(g['records'])
        attack,defense=attack_defense(g['records'])
        title=f'{names[target]} ← {len(g["sources"])}体から ／ {"a" if role else "b"} ／ 攻撃合計 {attack}・{"防御" if role else "突破"} {defense}（補正後） ／ 命中{hits}回'
        parts.append('<details><summary>'+html.escape(title)+'</summary><pre>'+html.escape(describe(g,names))+'</pre></details>')
    if not grouped:parts.append('<p>個別攻撃はまだ記録されていません。</p>')
    return ''.join(parts)

def show_groups(root,folder):
    import tkinter as tk
    from tkinter import ttk,messagebox
    from detail_report import show_details
    try:data=json.loads((Path(folder)/'details.json').read_text(encoding='utf-8'))
    except (OSError,ValueError) as exc:
        messagebox.showinfo('攻撃先ごとのまとめ',f'個別記録を読み込めません。\n{exc}',parent=root);return
    grouped,names=groups(data)
    w=tk.Toplevel(root);w.title('攻撃先ごとのまとめ');w.geometry('1180x750')
    ttk.Label(w,text='どの師団へ攻撃が集まったか',font=('',18,'bold'),padding=12).pack(anchor='w')
    ttk.Label(w,text=detail_scope(data)+'。'+NOTICE,wraplength=1100,padding=(12,0,12,12)).pack(anchor='w')
    frame=ttk.Frame(w);frame.pack(fill='both',expand=True,padx=12)
    headings=['攻撃合計（補正後）','防御/突破（補正後）','処理数','判定数','命中','枠超過','枠の適用率','防御/突破（能力値）']
    tree=ttk.Treeview(frame,columns=list(range(len(headings))),show='tree headings',selectmode='browse')
    tree.heading('#0',text='攻撃先 ← 攻撃元（展開で内訳）');tree.column('#0',width=280,minwidth=200)
    for i,label in enumerate(headings):
        tree.heading(i,text=label);tree.column(i,width=170 if i in (0,1,7) else 85,anchor='e',stretch=False)
    scroll=ttk.Scrollbar(frame,command=tree.yview);xscroll=ttk.Scrollbar(frame,orient='horizontal',command=tree.xview)
    tree.configure(yscrollcommand=scroll.set,xscrollcommand=xscroll.set)
    tree.grid(row=0,column=0,sticky='nsew');scroll.grid(row=0,column=1,sticky='ns');xscroll.grid(row=1,column=0,sticky='ew')
    frame.rowconfigure(0,weight=1);frame.columnconfigure(0,weight=1)
    tree.tag_configure('a',background='#edf6ff');tree.tag_configure('b',background='#fff6e8')
    selections={}
    for i,g in enumerate(grouped):
        role,_,target=g['key'];tag='a' if role else 'b';key=str(i)
        tree.insert('','end',iid=key,text=f'{names[target]} ← {len(g["sources"])}体（{tag}）',
                    values=summary_values(g['records']),tags=(tag,))
        selections[key]=(g,g['records'])
        for source,records in g['sources'].items():
            child=f'{i}/{source}';selections[child]=(g,records)
            tree.insert(key,'end',iid=child,text=f'{names[source]} → {names[target]}',
                        values=summary_values(records),tags=(tag,))
    text=tk.Text(w,height=13,wrap='word',font=('',10));text.pack(fill='x',padx=12,pady=12);text.configure(state='disabled')
    def selected(event=None):
        if tree.selection():
            g,records=selections[tree.selection()[0]]
            text.configure(state='normal');text.delete('1.0','end');text.insert('end',describe(g,names,records));text.configure(state='disabled')
    def drill():
        if tree.selection():
            _,records=selections[tree.selection()[0]]
            show_details(w,folder,subset={r[1] for r in records})
    tree.bind('<<TreeviewSelect>>',selected);tree.bind('<Double-1>',lambda e:drill())
    controls=ttk.Frame(w);controls.pack(pady=8)
    ttk.Button(controls,text='選択分の個別処理を見る',command=drill).pack(side='left',padx=6)
    ttk.Button(controls,text='更新',command=lambda:(w.destroy(),show_groups(root,folder))).pack(side='left',padx=6)
    if grouped:tree.selection_set('0');selected()
    return w
