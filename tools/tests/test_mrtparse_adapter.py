"""Known wire answers and boundary checks for optional corpus tooling."""
import json
from pathlib import Path
import struct
import tempfile
import unittest

from tools.research import bgp_corpus as corpus, mrtparse_adapter as adapter
from tools.research.contract import InvalidResearch

FIXTURES = Path(__file__).parents[1] / "research/fixtures/bgp-corpus-known.json"


class AdapterTests(unittest.TestCase):
    def test_explicit_route_order_and_unknown_family(self):
        route = lambda address, length: {"prefix": address, "length": length}
        data = {"type": {16: "BGP4MP"}, "subtype": {4: "MESSAGE_AS4"}, "bgp_message": {
            "type": {2: "UPDATE"}, "withdrawn_routes": [route("192.0.2.0", 24)],
            "nlri": [route("198.51.100.0", 24)], "path_attributes": [
                {"type": {14: "MP_REACH_NLRI"}, "value": {"afi": {2: "IPv6"}, "safi": {1: "UNICAST"}, "nlri": [route("2001:db8::", 32)]}},
                {"type": {15: "MP_UNREACH_NLRI"}, "value": {"afi": {2: "IPv6"}, "safi": {1: "UNICAST"}, "withdrawn_routes": [route("2001:db9::", 32)]}}]}}
        _, actions, prefixes = adapter.fields(data)[0]
        self.assertEqual([a['action'] for a in actions], ['withdraw', 'withdraw', 'announce', 'announce'])
        self.assertEqual([p['prefix']['address'] for p in prefixes], ['192.0.2.0', '2001:db9::', '198.51.100.0', '2001:db8::'])
        original = data['bgp_message']['path_attributes'][0]['value']
        data['bgp_message']['path_attributes'][0]['value'] = {'next_hop_length': 255, 'next_hop': ['255.1.0.0']}
        self.assertEqual(adapter.fields(data), [(None, None, None)])
        data['bgp_message']['path_attributes'][0]['value'] = {'afi': {2: 'IPv6'}, 'safi': {1: 'UNICAST'}}
        self.assertEqual(adapter.fields(data), [(None, None, None)])
        data['bgp_message']['path_attributes'][0]['value'] = original
        data['bgp_message']['path_attributes'][0]['value']['afi'] = {25: 'L2VPN'}
        self.assertEqual(adapter.fields(data), [(None, None, None)])

    def test_rib_entries_preserve_path_ids(self):
        data = {'type': {13: 'TABLE_DUMP_V2'}, 'subtype': {10: 'RIB_IPV6_UNICAST_ADDPATH'},
                'prefix': '2001:db8::', 'length': 32, 'rib_entries': [{'path_id': 7}, {'path_id': 8}]}
        rows = adapter.fields(data)
        self.assertEqual([r[0] for r in rows], [0, 1])
        self.assertEqual([r[2][0]['path_id'] for r in rows], [7, 8])

    def test_pinned_wheel_required(self):
        with tempfile.TemporaryDirectory() as directory:
            wheel = Path(directory) / 'fake.whl'
            wheel.write_bytes(b'not executable')
            with self.assertRaises(InvalidResearch):
                adapter.load_decoder(wheel)

    def test_complete_record_selection_does_not_adopt_partial_tail(self):
        record = lambda kind, sub, body: struct.pack('!IHHI', 100, kind, sub, len(body)) + body
        raw = record(13, 1, b'peer') + record(13, 2, b'one') + record(13, 4, b'two')
        selected, ranges = corpus.select_records(raw + b'partial', 'bview')
        self.assertEqual(selected, raw)
        self.assertEqual(ranges[-1]['end'], len(raw))
        with self.assertRaises(InvalidResearch):
            corpus.select_records(raw[:-1], 'bview')
        with self.assertRaises(InvalidResearch):
            corpus.select_records(record(13, 2, b'bad'), 'bview')

    def test_fixture_records_are_complete_and_expected_anchors_exist(self):
        for fixture in json.loads(FIXTURES.read_text()):
            raw, at, offsets = bytes.fromhex(fixture['hex']), 0, []
            while at < len(raw):
                offsets.append(at)
                at += 12 + struct.unpack_from('!I', raw, at + 8)[0]
            self.assertEqual(at, len(raw))
            self.assertTrue(all(row['record_offset'] in offsets for row in fixture['expected']))


if __name__ == '__main__':
    unittest.main()
