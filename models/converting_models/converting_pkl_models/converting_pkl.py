import joblib
from sklearn_porter import Porter
import os

# טען את המודל המאומן
model_path = os.path.join(os.path.dirname(__file__), 'trained_model_random_forest.pkl')
model = joblib.load(model_path)

# המרת המודל ל-JavaScript
porter = Porter(model, language='js')

# הפלט כקוד JS
output_js = porter.export(class_name='PhishingModel', method_name='predict')

# שמור לקובץ JS
output_path = os.path.join(os.path.dirname(__file__), 'phishing_model.js')
with open(output_path, 'w', encoding='utf-8') as f:
    f.write(output_js)

print("[✅] המודל הומר ונשמר לקובץ phishing_model.js בהצלחה.")
