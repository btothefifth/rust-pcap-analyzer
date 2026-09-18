import io
import unittest
from tools.product import tlv

class Short(io.BytesIO):
    def write(self,v):return super().write(v[:3])
class Stuck(io.BytesIO):
    def write(self,v):return 0

def rows():return [{'sequence':'1','run_id':'test','kind':'capture.start'},{'sequence':'2','run_id':'test','kind':'capture.complete'}]

class TlvIo(unittest.TestCase):
    def test_short_writes_completed(self):
        f=Short();tlv.write_events(f,rows());self.assertEqual(list(tlv.events(io.BytesIO(f.getvalue()))),rows())
    def test_no_progress_is_error(self):
        with self.assertRaises(OSError):tlv.write_events(Stuck(),rows())
    def test_aggregate_budget_before_join(self):
        with self.assertRaises(ValueError):tlv.encode(['a'*40]*30,limit=100)
    def test_mixed_run_not_accepted(self):
        values=rows();values[1]['run_id']='different';f=io.BytesIO();tlv.write_events(f,values)
        with self.assertRaises(ValueError):list(tlv.events(io.BytesIO(f.getvalue())))
    def test_records_after_abort_rejected(self):
        values=rows();values[1]['kind']='capture.aborted';values.append({'sequence':'3','run_id':'test','kind':'diagnostic'});f=io.BytesIO();tlv.write_events(f,values)
        with self.assertRaises(ValueError):list(tlv.events(io.BytesIO(f.getvalue()),require_complete=False))
    def test_invalid_limit(self):
        for n in [0,1,2,tlv.MAX_RECORD+1]:
            with self.assertRaises(ValueError):tlv.encode(None,limit=n)

if __name__=='__main__':unittest.main()
