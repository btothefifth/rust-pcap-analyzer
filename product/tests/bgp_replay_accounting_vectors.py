"""Independent compact-JSON byte/work vectors, not execution of the Rust code."""
import json
import unittest


def compact(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def measured_length(value):
    """Independent size arithmetic; no serialized document used to measure it."""
    if value is None:
        return 4
    if isinstance(value, bool):
        return 4 if value else 5
    if isinstance(value, int):
        return len(str(value))
    if isinstance(value, str):
        lengths = {"\"": 2, "\\": 2, "\b": 2, "\f": 2, "\n": 2, "\r": 2, "\t": 2}
        return 2 + sum(lengths.get(c, 6 if ord(c) < 32 else len(c.encode("utf-8"))) for c in value)
    if isinstance(value, list):
        return 2 + max(0, len(value) - 1) + sum(map(measured_length, value))
    if isinstance(value, dict):
        return 2 + max(0, len(value) - 1) + sum(measured_length(k) + 1 + measured_length(v) for k, v in value.items())
    raise TypeError(type(value))


class AccountingVectors(unittest.TestCase):
    def test_scalar_exact_output_and_work(self):
        # Existing logical model: one node plus four units per output byte.
        self.assertEqual(compact(False), b"false")
        size = measured_length(False)
        self.assertEqual(size, 5)
        self.assertEqual(1 + 4 * size, 21)
        self.assertFalse(1 + 4 * size <= 20)
        self.assertFalse(size <= 4)

    def test_all_control_bytes_have_fixed_length(self):
        value = "".join(chr(n) for n in range(32))
        self.assertEqual(measured_length(value), 174)
        self.assertEqual(len(compact(value)), 174)

    def test_utf8_and_escapes_are_not_character_counts(self):
        for value, expected in [("é", 4), ("水", 5), ("😀", 6), ('"', 4), ("\\", 4), ("\0", 8), ("\n", 4)]:
            with self.subTest(value=value):
                self.assertEqual(measured_length(value), expected)
                self.assertEqual(len(compact(value)), expected)

    def test_nested_fixed_canonical_bytes(self):
        value = {"z": [None, True, False, 0, 18446744073709551615, '"\\\n\r\t\b\f\0é😀'], "a": {"b": [], "a": {}}}
        expected = r'{"a":{"a":{},"b":[]},"z":[null,true,false,0,18446744073709551615,"\"\\\n\r\t\b\f\u0000é😀"]}'.encode("utf-8")
        self.assertEqual(compact(value), expected)
        self.assertEqual(measured_length(value), len(expected))
        self.assertFalse(measured_length(value) <= len(expected) - 1)

    def test_decimal_boundaries(self):
        for power in range(1, 20):
            for value in (10 ** power - 1, 10 ** power):
                self.assertEqual(measured_length(value), len(compact(value)))
        self.assertEqual(measured_length(18446744073709551615), 20)

    def test_order_and_boolean_shapes(self):
        left = {"z": [False, None, {}], "a": {"z": 9, "a": 10}}
        right = {"a": {"a": 10, "z": 9}, "z": [False, None, {}]}
        self.assertEqual(compact(left), compact(right))
        self.assertNotEqual(compact(left), compact({"z": list(reversed(left["z"])), "a": left["a"]}))
        for value in ([], {}, [False], {"": None}, [[{}]]):
            self.assertEqual(measured_length(value), len(compact(value)))

    def test_budget_is_cumulative_not_refilled_by_phase(self):
        costs = [1 + 4 * 5, 1 + 4 * 5]
        self.assertEqual(sum(costs), 42)
        self.assertTrue(sum(costs) <= 42)
        self.assertFalse(sum(costs) <= 41)


if __name__ == "__main__":
    unittest.main()
