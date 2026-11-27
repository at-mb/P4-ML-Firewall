"""Score models on the held-out 30% (no balancing): uses the repo's own functions."""
import sys, pickle, numpy as np
sys.path.insert(0, sys.argv[1])
from lucid_cnn import *   # noqa: brings load_model, predict_classes, class_report, normalize_and_padding, ...
flows = pickle.load(open(sys.argv[2], 'rb'))
X, y, _ = dataset_to_list_of_fragments(flows); y = np.array(y)
names = ['benign', 'dns', 'synflood', 'udplag', 'webddos']
print("held-out samples per class:", dict(zip(names, np.bincount(y, minlength=5))))
for path in sys.argv[3:]:
    model = load_model(path)
    fs = 'rich' if model.input_shape[2] == RICH_FEATURES else 'lucid'
    mins, maxs = static_min_max(True, 2)
    Xn = np.expand_dims(np.array(normalize_and_padding(X, mins, maxs, 4, feature_set=fs, time_window=2)), 3)
    p = predict_classes(model, Xn)
    print("\n=====", path.split('/')[-1], "| features:", fs, "| outputs:", model.output_shape[-1])
    if model.output_shape[-1] > 1:
        print(class_report(y, p, model_classes(path, model)))
        print("macro-F1 %.4f" % f1_score(y, p, average='macro'))
    yb, pb = y > 0, p > 0
    print("attack-vs-benign: F1 %.4f  precision %.4f  benign FPR %.4f" % (f1_score(yb, pb), precision_score(yb, pb), pb[~yb].mean()))
    print("detection rate per true type:", {n: round(float(pb[y == i].mean()), 4) for i, n in enumerate(names)})
