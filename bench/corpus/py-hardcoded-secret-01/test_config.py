import unittest

import config


class RetryDelayTests(unittest.TestCase):
    def test_exponential(self):
        self.assertEqual(config.retry_delays(4, 0.5), [0.5, 1.0, 2.0, 4.0])

    def test_empty(self):
        self.assertEqual(config.retry_delays(0), [])


if __name__ == "__main__":
    unittest.main()
