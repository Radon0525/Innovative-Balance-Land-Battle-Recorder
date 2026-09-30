import subprocess,sys,unittest
import frida
from recorder import source
from country_report import direction_labels,country_rows
from detail_report import row_values

class CountryTests(unittest.TestCase):
    def test_country_table_and_detail_country_columns(self):
        import os,tempfile,json
        from pathlib import Path
        from recorder import BASE,save_report,show_report_window
        os.chdir(BASE);from recorder import configure_tk;configure_tk()
        import tkinter as tk
        from tkinter import ttk
        root=tk.Tk();root.withdraw()
        def descendants(w):
            for child in w.winfo_children():yield child;yield from descendants(child)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                data=dict(enabled=True,tags={'1':'GER','2':'SOV'},pairs=[dict(source=1,target=2,role=1,counts=[1,1,1,1]),dict(source=2,target=1,role=0,counts=[2,2,2,2])])
                save_report(Path(tmp),[3]*4+[0]*5+[1]*8,dict(version='test',status='停止済み',started_at='test',countries=data))
                w=show_report_window(root,tmp);root.update()
                tree=next(x for x in descendants(w) if isinstance(x,ttk.Treeview) and 'direction' in x['columns'])
                self.assertEqual({tree.set(r,'direction') for r in tree.get_children()},{'ドイツ (GER) → ソ連 (SOV)','ドイツ (GER) ← ソ連 (SOV)'})
                self.assertTrue(tree.cget('yscrollcommand'));self.assertLessEqual(w.winfo_reqheight(),790)
        finally:root.destroy()
    def test_native_country_pairs_controller_and_roles(self):
        child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(90)'])
        session=frida.attach(child.pid);script=session.create_script(source({'test':True,'defense_offset':0}))
        try:
            script.load();data=script.exports_sync.countryfixture();pairs=data['countries']['pairs']
            self.assertEqual([(p['source'],p['target'],p['role']) for p in pairs],[(1,2,1),(2,1,0),(3,2,1),(4,2,1)])
            self.assertTrue(all(list(map(int,p['counts']))==[1,1,1,1] for p in pairs))
            self.assertEqual(data['countries']['tags']['1'],'GER');self.assertEqual(data['countries']['tags']['2'],'SOV')
            rows=data['details']['records'];self.assertEqual([(int(r[32]),int(r[33])) for r in rows],[(2,1),(1,2),(3,2),(4,2)])
            tags={'1':'GER','2':'SOV'};data['countries']['tags']=tags
            display=country_rows(data['countries'])
            self.assertTrue(any('ドイツ (GER) → ソ連 (SOV)'==r[2] for r in display))
            self.assertTrue(any('ドイツ (GER) ← ソ連 (SOV)'==r[2] for r in display))
            self.assertEqual(row_values(rows[0],tags)[-3:],['ドイツ (GER)','ソ連 (SOV)','ドイツ (GER) ← ソ連 (SOV)'])
            before=script.exports_sync.countries();script.exports_sync.stop();self.assertEqual(script.exports_sync.countries(),before)
        finally:script.unload();session.detach();child.terminate();child.wait(timeout=10)
    def test_unknown_country_is_not_assigned(self):
        self.assertEqual(direction_labels(0,0,1),('所属不明','所属不明','所属不明 → 所属不明'))

    def test_country_totals_continue_after_sample_limit(self):
        child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(90)'])
        session=frida.attach(child.pid);script=session.create_script(source({'test':True,'defense_offset':0}))
        try:
            script.load();data=script.exports_sync.countryfixture(300)
            self.assertEqual(len(data['details']['records']),500)
            self.assertEqual(list(map(int,data['countries']['pairs'][0]['counts'])),[300]*4)
            self.assertEqual(list(map(int,data['countries']['pairs'][1]['counts'])),[300]*4)
            self.assertEqual(len(data['countries']['pairs']),4)
            script.exports_sync.stop()
        finally:script.unload();session.detach();child.terminate();child.wait(timeout=10)

if __name__=='__main__':unittest.main()
