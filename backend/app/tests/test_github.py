# one-off: הפקת רשימת הפיצ'רים המקורית של המודל
import pickle, pathlib, json
p = pathlib.Path(__file__).resolve().parent / 'curr_model' / 'model_every_valid_feature.pkl'
model = pickle.load(open(p, 'rb'))
feats = list(model.feature_names_in_)  # יש לרוב במודלים של sklearn 1.x
print(len(feats))
for f in feats: print(f)
# אופציונלי לשימוש נוח:
(p.parent / 'features.json').write_text(json.dumps(feats, ensure_ascii=False, indent=2), encoding='utf-8')
