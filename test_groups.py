import tempfile
import unittest
from pathlib import Path
from group_report import groups,totals,defense_range,render_groups_html,describe,attack_defense

def record(sequence,source,target=30,context=40,role=1):
    r=[0]*40
    r[0:7]=[1,sequence,sequence,role,context,source,target]
    r[16]=8000000;r[17]=12000000
    r[18]=10;r[23:27]=[4,1,3,2];r[28]=1;r[30]=1;r[22]=5
    return r

class GroupTests(unittest.TestCase):
    def test_effective_attack_sum_and_defense_share_units(self):
        a,b=record(1,10),record(2,10)
        a[29]=450000;b[29]=325000
        a[20]=b[20]=800000;a[31]=b[31]=1
        self.assertEqual(attack_defense([a,b]),['77.5','80'])
        b[20]=900000
        self.assertEqual(attack_defense([a,b]),['77.5','80 ～ 90'])
        b[30]=0
        self.assertEqual(attack_defense([a,b])[0],'未観測 1/2処理')
        a[31]=0
        self.assertEqual(attack_defense([a,b])[1],'未観測 1/2処理')
        a[29]=0;a[30]=1;a[31]=1
        self.assertEqual(attack_defense([a])[0],'0')

    def test_multiple_sources_and_repeated_source(self):
        data={'records':[record(3,10),record(1,10),record(2,20)]}
        grouped,names=groups(data)
        self.assertEqual(len(grouped),1)
        self.assertEqual(len(grouped[0]['sources']),2)
        self.assertEqual(totals(grouped[0]['records']),[3,30,9,15,'50.0%'])
        self.assertEqual(defense_range(grouped[0]['records']),'80')
        grouped[0]['records'][0][16]=9000000
        self.assertEqual(defense_range(grouped[0]['records']),'80 ～ 90')
        self.assertIn('複数時間',describe(grouped[0],names))
        self.assertIn('2体から',render_groups_html(data))

    def test_context_side_target_are_separate(self):
        rows=[record(1,10),record(2,10,context=41),record(3,10,role=0),record(4,10,target=31)]
        grouped,_=groups({'records':rows})
        self.assertEqual(len(grouped),4)
        self.assertEqual(defense_range(grouped[2]['records']),'120')
        self.assertEqual(groups({'records':[]}),([] ,{}))
        self.assertIn('まだ記録されていません',render_groups_html({'records':[]}))

    def test_summary_ui_expands_and_drills_to_original_rows(self):
        import os
        from recorder import BASE
        os.chdir(BASE)
        from recorder import configure_tk
        configure_tk()
        import tkinter as tk
        from tkinter import ttk
        from detail_report import save_details
        from group_report import show_groups
        root=tk.Tk();root.withdraw()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                save_details(tmp,{'records':[record(1,10),record(2,20),record(3,10,target=99)],'reserved':[0,3]})
                w=show_groups(root,tmp);root.update()
                frame=next(c for c in w.winfo_children() if isinstance(c,ttk.Frame))
                tree=next(c for c in frame.winfo_children() if isinstance(c,ttk.Treeview))
                self.assertEqual(len(tree.get_children()),2)
                self.assertEqual(len(tree.get_children('0')),2)
                tree.item('0',open=True);tree.selection_set('0/10');root.update()
                controls=[c for c in w.winfo_children() if isinstance(c,ttk.Frame)][-1]
                controls.winfo_children()[0].invoke();root.update()
                detail=next(c for c in w.winfo_children() if isinstance(c,tk.Toplevel))
                detailframe=next(c for c in detail.winfo_children() if isinstance(c,ttk.Frame))
                detailtree=next(c for c in detailframe.winfo_children() if isinstance(c,ttk.Treeview))
                self.assertEqual(len(detailtree.get_children()),1)
                self.assertEqual(detailtree.item('0')['values'][1],1)
                root.update()
                self.assertIn('攻撃先ごとのまとめ',(Path(tmp)/'details.html').read_text(encoding='utf-8'))
        finally:root.destroy()

if __name__=='__main__':unittest.main(verbosity=2)
