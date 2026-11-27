"""Python model of the patched p4_bloom_management.p4, exposed through the Thrift calls
that p4_util / mitigation use. Test harness only: it is not BMv2."""
import ipaddress, struct, threading, time, zlib

PACKETS, BLOOM, P = 16384, 32768, 4
FEATURES = ['time', 'packet_length', 'ip_flags', 'tcp_len', 'tcp_ack', 'tcp_flags', 'tcp_window_size',
            'udp_len', 'icmp_type', 'dst_port', 'src_port', 'dst_ip', 'src_ip', 'ip_upper_protocol']
WIDTH = {'time': 48, 'packet_length': 16, 'ip_flags': 16, 'tcp_len': 16, 'tcp_ack': 32, 'tcp_flags': 9,
         'tcp_window_size': 16, 'udp_len': 16, 'icmp_type': 8, 'dst_port': 16, 'src_port': 16, 'dst_ip': 32,
         'src_ip': 32, 'ip_upper_protocol': 8, 'flow_counter': 8, 'packet_counter': 14}

class Reg:
    def __init__(s, name, size): s.name, s.size = name, size

def h(x): return int(x, 16) if x else 0
def i(x): return int(x) if x else 0

def load(path):
    out = []
    for l in open(path):
        s, d, p, ln, fl, fo, tsp, tdp, tl, ack, tf, win, usp, udp_, ul, ic = l.rstrip('\n').split(',')
        p = int(p)
        sp, dp = (i(tsp), i(tdp)) if p == 6 else (i(usp), i(udp_)) if p == 17 else (0, 0)
        out.append(dict(src=s, dst=d, proto=p, sport=sp, dport=dp, len=i(ln),
                        ip_flags=((i(fo) // 8) << 3) | h(fl), tcp_len=i(tl) if p == 6 else 0,
                        ack=i(ack) if p == 6 else 0, tcp_flags=h(tf) & 0x1ff if p == 6 else 0,
                        win=i(win) if p == 6 else 0, udp_len=i(ul) if p == 17 else 0,
                        icmp=i(ic) if p == 1 else 0))
    return out

class FakeSwitch:
    def __init__(s):
        s.lock = threading.Lock(); s.t0 = time.time()
        s.r = {}
        for b in '01':
            for f in FEATURES: s.r[f + b] = [0] * PACKETS
            s.r['flow_counter' + b] = [0] * BLOOM
            for f in ('packet_counter', 'not_foldable_counter', 'process_in_memory', 'ignored_by_fulled_bloom'):
                s.r[f + b] = [0]
        for f in ('block_of_registers', 'sampling_counter', 'round_counter', 'num_packets'): s.r[f] = [0]
        s.r['sampling_treshold'] = [1]  # commands1.txt
        s.device_config = {'register': {n: Reg(n, len(v)) for n, v in s.r.items()}}
        s.tables = {'MyIngress.blocked_src': {}, 'MyIngress.blocked_flows': {}}
        s.handles, s.next = {}, 1
        s.delivered = {}

    # ---- Thrift API used by p4_util.RuntimeAPI and mitigation.SwitchTables ----
    def bm_register_read(s, cxt, name, index):
        with s.lock: return s.r[name][index]
    def bm_register_read_all(s, cxt, name):
        with s.lock: return list(s.r[name])
    def bm_register_write(s, cxt, name, index, value):
        with s.lock: s.r[name][index] = value
    def bm_register_reset(s, cxt, name):
        with s.lock: s.r[name] = [0] * len(s.r[name])
    def bm_mt_add_entry(s, cxt, table, match, action, data, opts):
        key = tuple(m.k['exact'].a[0] for m in match)
        with s.lock:
            if key in s.tables[table]: raise RuntimeError('DUPLICATE_ENTRY')
            hd = s.next; s.next += 1
            s.tables[table][key] = [hd, 0]; s.handles[hd] = (table, key)
            return hd
    def bm_mt_delete_entry(s, cxt, table, hd):
        with s.lock:
            t, key = s.handles.pop(hd); del s.tables[t][key]
    def bm_mt_read_counter(s, cxt, table, hd):
        with s.lock:
            t, key = s.handles[hd]
            return type('C', (), {'packets': s.tables[t][key][1], 'bytes': 0})()

    # ---- data plane ----
    def ingress(s, pkt, tag):
        src, dst = ipaddress.IPv4Address(pkt['src']).packed, ipaddress.IPv4Address(pkt['dst']).packed
        sp, dp, pr = struct.pack('!H', pkt['sport']), struct.pack('!H', pkt['dport']), bytes([pkt['proto']])
        with s.lock:
            s.r['num_packets'][0] += 1
            for t, key in (('MyIngress.blocked_src', (src,)), ('MyIngress.blocked_flows', (src, sp, dst, dp, pr))):
                e = s.tables[t].get(key)
                if e is not None:
                    e[1] += 1
                    return False
            s.delivered[tag] = s.delivered.get(tag, 0) + 1
            sc = (s.r['sampling_counter'][0] + 1) & 0xf
            s.r['sampling_counter'][0] = sc
            if sc != s.r['sampling_treshold'][0]:
                return True
            s.r['sampling_counter'][0] = 0
            b = str(s.r['block_of_registers'][0])
            idx = [zlib.crc32(x) % BLOOM for x in (src + sp + dst + dp + pr, dst + dp + src + sp + pr, src + sp + dst + dp, dst + dp + src + sp)]
            fc = s.r['flow_counter' + b]; c = [fc[j] for j in idx]
            if min(c) < P:
                pc = s.r['packet_counter' + b][0]
                s.r['packet_counter' + b][0] = (pc + 1) % PACKETS
                s.r['process_in_memory' + b][0] += 1
                vals = dict(time=int((time.time() - s.t0) * 1e6) & (2**48 - 1), packet_length=pkt['len'],
                            ip_flags=pkt['ip_flags'] & 0xffff, tcp_len=pkt['tcp_len'] & 0xffff, tcp_ack=pkt['ack'],
                            tcp_flags=pkt['tcp_flags'], tcp_window_size=pkt['win'], udp_len=pkt['udp_len'],
                            icmp_type=pkt['icmp'], dst_port=pkt['dport'], src_port=pkt['sport'],
                            dst_ip=int(ipaddress.IPv4Address(pkt['dst'])), src_ip=int(ipaddress.IPv4Address(pkt['src'])),
                            ip_upper_protocol=pkt['proto'])
                for f, v in vals.items(): s.r[f + b][pc] = v
            else:
                s.r['ignored_by_fulled_bloom' + b][0] += 1
            s.r['not_foldable_counter' + b][0] += 1
            for j, v in zip(idx, c): fc[j] = (v + 1) & 0xff
            return True
