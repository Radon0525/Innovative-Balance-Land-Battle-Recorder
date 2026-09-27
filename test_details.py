import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import frida
from recorder import source
from detail_report import row_values,save_details,explanation

class DetailTests(unittest.TestCase):
    def test_table_can_open_and_select_a_row(self):
        import os
        from recorder import BASE
        from detail_report import show_details
        os.chdir(BASE)
        os.environ['TCL_LIBRARY']='.venv/tcl/tcl8.6'
        os.environ['TK_LIBRARY']='.venv/tcl/tk8.6'
        import tkinter as tk
        root=tk.Tk();root.withdraw()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                r=[0]*40;r[0]=1;r[2]=1;r[3]=1
                save_details(tmp,{'records':[r],'reserved':[0,1]})
                window=show_details(root,tmp)
                root.update()
                from tkinter import ttk
                frame=next(w for w in window.winfo_children() if isinstance(w,ttk.Frame))
                table=next(w for w in frame.winfo_children() if isinstance(w,ttk.Treeview))
                self.assertEqual(table.item('0')['values'][0],'1a')
                table.selection_set('0');root.update()
                explanation_widget=next(w for w in window.winfo_children() if isinstance(w,tk.Text))
                self.assertIn('未観測',explanation_widget.get('1.0','end'))
                window.destroy()
        finally:root.destroy()

    def test_real_callbacks_capture_and_cap_each_side(self):
        child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(120)'])
        session=None
        try:
            session=frida.attach(child.pid)
            script=session.create_script(source({'test':True,'defense_offset':0}))
            script.load()
            data=script.exports_sync.exercisedetails(1200)
            self.assertEqual(data['reserved'],['500','500'])
            records=[list(map(int,r)) for r in data['records']]
            self.assertEqual(len(records),1000)
            for r in records:
                self.assertEqual(r[7],50000) # Fifth argument is on the native stack.
                self.assertEqual(r[8],10000000)
                self.assertEqual(r[13],20000000)
                self.assertEqual(r[18:20],[4,100000])
                self.assertEqual(r[23:27],[1,1,1,1])
                self.assertEqual(r[22]-r[21],2)
                self.assertEqual(r[28:31],[1,450000,1])
                self.assertEqual(row_values(r)[21],'正常')
            self.assertEqual(row_values(records[0])[0],'1b')
            self.assertEqual(row_values(records[500])[0],'1a')
            # Source/target values reverse battle-side columns for b.
            self.assertEqual(row_values(records[0])[3],'200')
            self.assertEqual(row_values(records[500])[3],'100')
            script.exports_sync.stop()
            self.assertEqual(len(script.exports_sync.details()['records']),1000)
            with tempfile.TemporaryDirectory() as tmp:
                progress=save_details(Path(tmp),data)
                self.assertEqual(progress,{'a':500,'b':500})
                import csv
                with (Path(tmp)/'details.csv').open(encoding='utf-8-sig',newline='') as f:rows=list(csv.reader(f))
                self.assertEqual(len(rows),1001)
                self.assertEqual([r[0] for r in rows[1:5]],['1a','1b','2a','2b'])
                self.assertEqual(rows[-1][0],'500b')
                self.assertIn('個別攻撃',(Path(tmp)/'details.html').read_text(encoding='utf-8'))
                self.assertIn('各補正の個別内訳は未記録',explanation(records[0]))
            script.unload()
        finally:
            if session:session.detach()
            child.terminate();child.wait(timeout=10)

    def test_empty_missing_and_partial_are_not_fabricated(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(save_details(tmp,{'records':[],'reserved':[0,0]}),{'a':0,'b':0})
            r=[0]*40;r[0]=1;r[2]=1;r[3]=1
            self.assertEqual(row_values(r)[11],'未観測')
            self.assertEqual(row_values(r)[21],'要確認')
            r[18]=5;r[28]=1;r[30]=1;r[23]=2;r[22]=2
            self.assertEqual(row_values(r)[21],'途中終了')
            r[27]=1
            self.assertEqual(row_values(r)[21],'要確認')

if __name__=='__main__':unittest.main(verbosity=2)
