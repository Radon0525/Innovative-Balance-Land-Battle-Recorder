import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch
import frida
from recorder import source, metrics, save_report, profile_for, Recorder, latest_report, role_metrics

class RecorderTests(unittest.TestCase):
    def test_both_statistics_are_saved_separately(self):
        all_counts=[10,2,6,2,1,0,0,0,0]+[3]*8
        filtered=[3,1,1,1,0,0,0,0,0]+[1]*8
        with tempfile.TemporaryDirectory() as folder:
            save_report(Path(folder),all_counts+filtered,{'version':'test','status':'停止済み','started_at':'test','width_range_filter':True})
            saved=json.loads((Path(folder)/'summary.json').read_text(encoding='utf-8'))
            self.assertEqual(saved['counts'],all_counts)
            self.assertEqual(saved['ground']['attacks'],20)
            self.assertEqual(saved['filtered']['counts'],filtered)
            self.assertEqual(saved['filtered']['ground']['attacks'],6)
            self.assertIn('全戦闘と幅条件の比較',(Path(folder)/'report.html').read_text(encoding='utf-8'))

    def test_previous_session_report_is_found(self):
        import os
        with tempfile.TemporaryDirectory() as folder, patch('recorder.BASE',Path(folder)):
            self.assertIsNone(latest_report())
            for name,stamp in [('older',100),('newer',200)]:
                p=Path(folder)/'recordings'/name/'summary.json'
                p.parent.mkdir(parents=True);p.write_text('{}')
                os.utime(p,(stamp,stamp))
            self.assertEqual(latest_report().name,'newer')

    def test_collection_lifecycle_and_csv(self):
        with tempfile.TemporaryDirectory() as folder:
            device=Mock(); process=Mock(); process.name='hoi4.exe'; process.pid=123
            device.enumerate_processes.return_value=[process]
            session=device.attach.return_value
            script=session.create_script.return_value
            script.exports_sync.snapshot.return_value=['0']*17
            script.exports_sync.stop.return_value=['3','1','2','2','0','0','0','0','0','3','1','0','0','0','0','2','2']
            events=[]
            collector=Recorder(lambda e:(events.append(e),collector.stop_event.set()))
            with patch('frida.get_local_device',return_value=device), \
                 patch('recorder.BASE',Path(folder)), \
                 patch('recorder.process_path',return_value=Path('hoi4.exe')), \
                 patch('recorder.profile_for',return_value={'version':'test','sha256':'test'}), \
                 patch('recorder.source',return_value='test'):
                collector.run()
            self.assertIsNone(events[-1]['error'])
            summary=json.loads((collector.folder/'summary.json').read_text(encoding='utf-8'))
            self.assertEqual(summary['ground']['attacks'],8)
            self.assertEqual(summary['status'],'停止済み')
            import csv
            with (collector.folder/'checkpoints.csv').open(encoding='utf-8-sig',newline='') as f:
                rows=list(csv.reader(f))
            self.assertEqual(len(rows),3)
            self.assertEqual(rows[-1][2:6],['3','1','2','2'])
            script.unload.assert_called_once()
            session.detach.assert_called_once()

    def test_unsupported_build(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'hoi4.exe'; path.write_bytes(b'not the supported executable')
            with self.assertRaises(RuntimeError): profile_for(path)

    def test_roles_and_legacy(self):
        self.assertIsNone(role_metrics([0]*9))
        data=role_metrics([0]*9+[9,1,0,0,0,0,7,3])
        self.assertEqual(data['attacker_breakthrough']['defense_coverage'],1)
        self.assertEqual(data['attacker_breakthrough']['covered_avoid_rate'],.9)
        self.assertEqual(data['defender_defense']['defense_coverage'],0)
        self.assertIsNone(data['defender_defense']['covered_avoid_rate'])
        with tempfile.TemporaryDirectory() as folder:
            save_report(Path(folder),[9,1,7,3,0,0,0,0,0,9,1,0,0,0,0,7,3],
                        {'version':'test','status':'停止済み','started_at':'test'})
            saved=json.loads((Path(folder)/'summary.json').read_text(encoding='utf-8'))
            self.assertEqual(saved['roles']['attacker_breakthrough']['defended'],10)
            self.assertEqual(saved['roles']['defender_defense']['undefended'],10)

    def test_report_and_zero_denominator(self):
        self.assertIsNone(metrics([0,0,0,0])['defense_coverage'])
        with tempfile.TemporaryDirectory() as folder:
            save_report(Path(folder),[60,10,20,10,1,2,3,4,0],
                        {'version':'test','status':'停止済み','started_at':'test'})
            data=json.loads((Path(folder)/'summary.json').read_text(encoding='utf-8'))
            self.assertEqual(data['ground']['defense_coverage'],0.7)
            self.assertEqual(data['ground']['attacks'],100)

    def test_native_hooks(self):
        # A disposable child process, never HOI4. Exercise real Frida C callbacks.
        child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(120)'])
        session=None
        try:
            session=frida.attach(child.pid)
            script=session.create_script(source({'test':True,'defense_offset':0}))
            errors=[]
            script.on('message',lambda m,d:errors.append(m) if m['type']=='error' else None)
            script.load()
            self.assertEqual(script.exports_sync.exercise(10000),20001)
            self.assertEqual([int(x) for x in script.exports_sync.snapshot()],
                             [10000]*4+[1,0,0,1,0]+[5000]*8)
            self.assertEqual(script.exports_sync.exercise(17),35)
            self.assertEqual(script.exports_sync.parallel(1000,4),[2001]*4)
            expected=[14017]*4+[6,0,0,6,0]+[7009]*4+[7008]*4
            self.assertEqual([int(x) for x in script.exports_sync.stop()],expected)
            script.exports_sync.exercise(10)
            self.assertEqual([int(x) for x in script.exports_sync.snapshot()],expected)
            self.assertEqual(errors,[])
            script.unload()
        finally:
            if session: session.detach()
            child.terminate(); child.wait(timeout=10)

if __name__=='__main__': unittest.main(verbosity=2)
