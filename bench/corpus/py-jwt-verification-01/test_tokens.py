import os
import unittest

os.environ.setdefault("TOKEN_SIGNING_KEY", "unit-test-only")

import tokens


class Base64Tests(unittest.TestCase):
    def test_round_trip(self):
        for raw in (b"", b"a", b"ab", b"abc", b"\x00\xff\x10"):
            self.assertEqual(tokens.b64decode(tokens.b64encode(raw)), raw)

    def test_no_padding(self):
        self.assertNotIn("=", tokens.b64encode(b"a"))


if __name__ == "__main__":
    unittest.main()
