"""Run the real lucid_cnn.py live loop against fakeswitch (no BMv2, no root), replaying like run_test.sh.
usage: PYTHONPATH=dev/stubs live_run.py <control-plane dir> <model.h5> <attack csv> <benign csv> <mode> <outdir> [attack_pps benign_pps duration]
mode: off | src | 5tuple; env MINF=N adds --min_flows N.
The csv files come from tshark, see README (dev/ section)."""
import os, sys, threading, time, _thread, json
cp, model, att, ben, mode, out = sys.argv[1:7]
apps, bpps, dur = (int(x) for x in (sys.argv[7:10] or (100, 50, 60)))
WARM, ATTACKER = 10, '172.16.0.5'
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, cp)
import fakeswitch
os.makedirs(out, exist_ok=True); os.chdir(out)
A = fakeswitch.load(att)[:apps * dur]; B = fakeswitch.load(ben)[:bpps * (dur + WARM)]
sw = fakeswitch.FakeSwitch()
import p4_util
p4_util.get_runtime_API = lambda host, port, pre, js: p4_util.RuntimeAPI(pre, sw, sw.device_config)
sys.argv = ['lucid_cnn.py', '--predict_live', 'localhost:22222', '--model', model, '--dataset_type', 'DOS2019_MC',
            '-r', '14', '-si', 'p4ddle', '--mitigate', mode, '--protect', '192.168.50.0/24'] + (['--min_flows', os.environ['MINF']] if os.environ.get('MINF') else [])
import lucid_cnn
stats = {}
def feeder():
    time.sleep(12)  # predictor start-up, as in run_test.sh
    ev = sorted([(n / bpps, 'benign', p) for n, p in enumerate(B)] + [(WARM + n / apps, 'attack', p) for n, p in enumerate(A)], key=lambda e: e[0])
    t0 = time.time(); stats['attack_start'] = t0 + WARM
    for t, tag, p in ev:
        d = t0 + t - time.time()
        if d > 0: time.sleep(d)
        k = 'attacker' if p['src'] == ATTACKER else ('victim' if tag == 'attack' else 'benign')
        stats[k + '_offered'] = stats.get(k + '_offered', 0) + 1
        sw.ingress(p, k)
    time.sleep(5); _thread.interrupt_main()
threading.Thread(target=feeder, daemon=True).start()
try:
    lucid_cnn.main(sys.argv[1:])
except SystemExit:
    pass
stats.update({k + '_received': v for k, v in sw.delivered.items()})
json.dump(stats, open('stats.json', 'w'))
print(json.dumps(stats))
