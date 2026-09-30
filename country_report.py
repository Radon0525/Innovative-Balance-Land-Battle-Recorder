"""Attack/defence roles are battle roles, independent of the direction of each shot."""
from country_names import country_name

def direction_labels(source,target,role,tags=None):
    tags=tags or {}
    a,b=(source,target) if role==1 else (target,source)
    left=country_name(a,tags.get(str(a)));right=country_name(b,tags.get(str(b)))
    return left,right,f'{left} {"→" if role==1 else "←"} {right}'

def country_rows(data):
    result=[];tags=data.get('tags',{})
    for p in data.get('pairs',[]):
        a,b,label=direction_labels(p['source'],p['target'],p['role'],tags)
        c=list(map(int,p['counts']));n=sum(c);h=c[1]+c[3]
        result.append([a,b,label,'攻撃側から' if p['role']==1 else '防御側から',n,h,f'{h/n:.2%}' if n else '—',sum(c[:2]),sum(c[2:])])
    return sorted(result,key=lambda r:(r[0],r[1],r[3]))

class CountryTable:
    def __init__(self,parent,height=5):
        import tkinter as tk
        from tkinter import ttk
        self.frame=ttk.Frame(parent);self.frame.pack(fill='x',pady=6)
        self.text=tk.StringVar(value='国別・攻撃⇔防御：新しい記録で自動表示します。')
        ttk.Label(self.frame,textvariable=self.text,wraplength=800).pack(anchor='w')
        columns=[('a','攻撃側の国',150),('b','防御側の国',150),('direction','射撃の方向（攻撃側 ⇔ 防御側）',350),
                 ('role','撃つ側',100),('n','判定数',90),('h','命中',90),('rate','命中率',90),('covered','枠適用',90),('uncovered','枠超過',90)]
        body=ttk.Frame(self.frame);body.pack(fill='x');body.columnconfigure(0,weight=1)
        self.tree=ttk.Treeview(body,columns=[c[0] for c in columns],show='headings',height=height)
        for key,label,width in columns:self.tree.heading(key,text=label);self.tree.column(key,width=width,stretch=False)
        self.tree.grid(row=0,column=0,sticky='ew');y=ttk.Scrollbar(body,orient='vertical',command=self.tree.yview);y.grid(row=0,column=1,sticky='ns')
        x=ttk.Scrollbar(self.frame,orient='horizontal',command=self.tree.xview);x.pack(fill='x');self.tree.configure(xscrollcommand=x.set,yscrollcommand=y.set)
        nav=ttk.Frame(self.frame);nav.pack(fill='x');self.page=0;self.rows=[]
        ttk.Button(nav,text='前へ',command=lambda:self.move(-1)).pack(side='left')
        self.page_text=tk.StringVar();ttk.Label(nav,textvariable=self.page_text).pack(side='left',padx=8)
        ttk.Button(nav,text='次へ',command=lambda:self.move(1)).pack(side='left')
    def move(self,delta):self.page+=delta;self.draw()
    def update(self,data):
        data=data or {};self.rows=country_rows(data)
        self.text.set('全戦闘の国別累積：左が戦闘の攻撃側、右が防御側。矢印は射撃方向です。' if data.get('enabled') else 'この記録には国情報がありません。新しい記録で自動取得します。')
        if int(data.get('overflow',0)):self.text.set(self.text.get()+' 国の組合せ上限超過あり。')
        self.draw()
    def draw(self):
        self.page=max(0,min(self.page,max(0,(len(self.rows)-1)//50)))
        self.tree.delete(*self.tree.get_children())
        for row in self.rows[self.page*50:(self.page+1)*50]:self.tree.insert('','end',values=row)
        self.page_text.set(f'{self.page+1} / {max(1,(len(self.rows)+49)//50)} ページ · {len(self.rows)}件')
