import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import app
import db


class HelperTests(unittest.TestCase):
    def test_parse_query(self):
        path, params = app.parse_query("/search?q=milk&page=2")
        self.assertEqual(path, "/search")
        self.assertEqual(params, {"q": "milk", "page": "2"})

    def test_normalize_title(self):
        self.assertEqual(db.normalize_title("  a   b \n c "), "a b c")
        self.assertEqual(len(db.normalize_title("x" * 200)), 80)


if __name__ == "__main__":
    unittest.main()
