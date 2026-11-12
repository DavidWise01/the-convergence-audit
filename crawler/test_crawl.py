import json
import tempfile
import unittest
from pathlib import Path
from crawl import Page, safe_url, scan

class ConvergenceScoutTests(unittest.TestCase):
    def test_allowlist_and_ports(self):
        hosts={"github.com"}
        self.assertIsNone(safe_url("http://127.0.0.1/",hosts))
        self.assertIsNone(safe_url("file:///etc/passwd",hosts))
        self.assertIsNone(safe_url("https://github.com:8000/",hosts))
        self.assertIsNone(safe_url("https://user:pass@github.com/x",hosts))
        self.assertIsNotNone(safe_url("https://github.com/topics/ai",hosts))
    def test_ignore_script(self):
        p=Page()
        p.feed("<p>source provenance</p><script>modeweaver</script>")
        self.assertIn("source provenance",p.text())
        self.assertNotIn("modeweaver",p.text())
    def test_append_only_candidate_and_dedup(self):
        cfg={"allowed_hosts":["example.org"],"seeds":["https://example.org/"],"patterns":["source provenance"],
            "max_pages":1,"max_depth":0,"host_delay_seconds":1}
        def sample(url,hosts,robots): return "<p>source provenance</p>",None
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"observations.jsonl"
            first=scan(cfg,path,reader=sample,sleeper=lambda n:None)
            self.assertEqual(first["added"],1)
            rec=json.loads(path.read_text().splitlines()[0])
            self.assertEqual(rec["ancestry"],"UNKNOWN")
            self.assertFalse(rec["copying_claim"])
            second=scan(cfg,path,reader=sample,sleeper=lambda n:None)
            self.assertEqual(second["added"],0)
            self.assertEqual(len(path.read_text().splitlines()),1)

if __name__=="__main__": unittest.main()
