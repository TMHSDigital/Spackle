import unittest

import app


class ClampLimitTests(unittest.TestCase):
    def test_defaults(self):
        self.assertEqual(app.clamp_limit(None), 25)
        self.assertEqual(app.clamp_limit("abc"), 25)
        self.assertEqual(app.clamp_limit("0"), 25)

    def test_bounds(self):
        self.assertEqual(app.clamp_limit("7"), 7)
        self.assertEqual(app.clamp_limit("5000"), 100)


if __name__ == "__main__":
    unittest.main()
