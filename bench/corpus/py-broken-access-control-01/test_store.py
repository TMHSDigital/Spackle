import unittest

import store


class StoreTests(unittest.TestCase):
    def test_format_amount(self):
        self.assertEqual(store.format_amount(12900), "129.00")
        self.assertEqual(store.format_amount(5), "0.05")

    def test_invoices_for_filters_by_owner(self):
        ids = sorted(inv.id for inv in store.invoices_for(2))
        self.assertEqual(ids, [1002, 1003])


if __name__ == "__main__":
    unittest.main()
