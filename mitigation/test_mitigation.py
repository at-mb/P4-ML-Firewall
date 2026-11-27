"""Unit tests for mitigation.py (no switch needed). Usage: python3 test_mitigation.py <control-plane dir>"""
import sys
sys.path.insert(0, sys.argv.pop(1))
import unittest
import mitigation as m

class Fake:
    def __init__(s, size=99): s.e, s.n, s.size = {}, 0, size
    def add(s, t, f):
        k = (t, tuple(f))
        if k in s.e.values(): raise RuntimeError('DUPLICATE_ENTRY')
        if len(s.e) >= s.size: raise RuntimeError('TABLE_FULL')
        s.n += 1; s.e[s.n] = k; return s.n
    def delete(s, t, h): del s.e[h]
    def dropped(s, t, h): return 7

A, V = '172.16.0.5', '192.168.50.4'
F, B = (A, 1234, V, 80, 6), (V, 80, A, 1234, 6)

class T(unittest.TestCase):
    def mk(s, mode, protect=(), size=99):
        s.now = 0.0; s.f = Fake(size)
        return m.Mitigator(s.f, mode, 60, protect, None, lambda: s.now)
    def test_benign_not_blocked(s):
        x = s.mk('src'); x.update([F], [False]); s.assertEqual(s.f.e, {})
    def test_src_one_rule_no_duplicates(s):
        x = s.mk('src'); x.update([F, (A, 9, V, 80, 6)], [True, True]); x.update([F], [True])
        s.assertEqual(list(s.f.e.values()), [('MyIngress.blocked_src', (b'\xac\x10\x00\x05',))])
    def test_5tuple_encoding(s):
        x = s.mk('5tuple'); x.update([F], [True])
        s.assertEqual(list(s.f.e.values())[0][1], (b'\xac\x10\x00\x05', b'\x04\xd2', b'\xc0\xa8\x32\x04', b'\x00\x50', b'\x06'))
    def test_victim_seen_first_is_flipped(s):
        for mode in ('src', '5tuple'):
            x = s.mk(mode, ['192.168.50.0/24']); x.update([B], [True])
            s.assertEqual(list(s.f.e.values())[0][1][0], b'\xac\x10\x00\x05')
    def test_both_protected_ignored(s):
        x = s.mk('src', ['192.168.50.0/24', '172.16.0.0/16']); x.update([F], [True]); s.assertEqual(s.f.e, {})
    def test_timeout_then_reblock(s):
        x = s.mk('src'); x.update([F], [True]); s.now = 59; x.update(); s.assertEqual(len(s.f.e), 1)
        s.now = 60; x.update(); s.assertEqual(len(s.f.e), 0)
        x.update([F], [True]); s.assertEqual(len(s.f.e), 1)
    def test_table_full_does_not_crash(s):
        x = s.mk('5tuple', size=1); x.update([F, (A, 2, V, 3, 17)], [True, True]); s.assertEqual(len(s.f.e), 1)
    def test_attack_type_is_logged(s):
        import csv, os, tempfile
        path = os.path.join(tempfile.mkdtemp(), 'log.csv')
        s.now = 0.0; s.f = Fake()
        x = m.Mitigator(s.f, 'src', 60, (), path, lambda: s.now)
        x.update([F, B], [True, False], ['synflood', 'benign']); x.close()
        rows = list(csv.DictReader(open(path)))
        s.assertEqual([(r['event'], r['class'], r['dropped_packets']) for r in rows], [('block', 'synflood', '0'), ('close', 'synflood', '7')])
    def test_min_flows_per_source(s):
        s.now = 0.0; s.f = Fake()
        x = m.Mitigator(s.f, 'src', 60, (), None, lambda: s.now, min_flows=3)
        x.update([F, (A, 2, V, 3, 17), ('8.8.8.8', 53, V, 999, 17)], [True, True, True]); s.assertEqual(s.f.e, {})
        x.update([F, (A, 2, V, 3, 17), (A, 4, V, 5, 17)], [True, True, True]); s.assertEqual(len(s.f.e), 1)
    def test_close_removes_all(s):
        x = s.mk('5tuple'); x.update([F, (A, 2, V, 3, 17)], [True, True]); x.close(); s.assertEqual(s.f.e, {})

unittest.main()
