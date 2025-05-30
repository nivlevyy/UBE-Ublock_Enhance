import random
from os import getcwd
from tkinter import Tk, filedialog
import hashlib
import joblib

import numpy as np
import pandas as pd
from matplotlib import pyplot as plt
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from xgboost import XGBClassifier
import category_encoders as ce
from sklearn.feature_extraction import FeatureHasher
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
"""
check KNN model
"""

# FEATURES_HEADER = [
#     "URL Length", "Number of Subdomains", "Length of Hostname",
#     "Is IP Address", "Is URL Shortener", "Number of Hyphens",
#     "Number of @ signs", "Number of Query Parameters",
#     "Number of Directories", "Has Protocol", "Is Mail",
#     "Has Suspicious Chars", "Has Double Slash"
# ]
#
# FEATURES_HEADER = ['has_icon', 'favicon_diff_domain', 'favicon_invalid_ext', 'anchor_tags_present',
#                    'anchor_empty_href', 'anchor_diff_domain', 'anchor_diff_ratio', 'meta_external', 'meta_sus_words',
#                    'external_meta_ratio', 'script_external', 'script_sus_words', 'external_script_ratio', 'total_links',
#                    'external_link_count', 'ratio_extern_link', 'total_external', 'total_resources',
#                    'external_resources', 'external_request_ratio', 'sfh_total_forms', 'sfh_blank_action',
#                    'sfh_diff_domain', 'sfh_password_inputs', 'sfh_suspicious_inputs', 'iframe_src_count',
#                    'iframe_src_hidden', 'iframe_src_size', 'iframe_src_diff_domain', 'iframe_src_no_sandbox',
#                    'iframe_external_src_ratio', 'iframe_srcdoc_count', 'iframe_srcdoc_hidden', 'iframe_srcdoc_scripts',
#                    'iframe_srcdoc_sus_words', 'total_iframes', 'inline_scripts', 'high_risk_patterns',
#                    'medium_risk_patterns', 'low_risk_patterns', 'sus_js_diff_domain', 'sus_js_behave_ratio',
#                    'risk_patterns_ratio', 'nlp_suspicious_words', 'total_scripts', 'external_script',
#                    'meta_refresh_redirect', 'window_location_redirect', 'final_url_diff_domain', 'hidden_forms_count',
#                    'onmouseover_scripts', 'onmouseover_tags', 'right_click_scripts', 'right_click_tags']

FEATURES_HEADER = ['URL Length', 'Number of Subdomains', 'Length of Hostname', 'Is IP Address',
                   'Is URL Shortener', 'Number of Hyphens', 'Number of @ signs', 'Number of Query Parameters',
                   'Number of Directories', 'Has Protocol', 'Is Mail', 'Has Suspicious Chars', 'Has Double Slash',
                   'Has SSL', 'Valid SSL', 'SSL Issuer', 'Domain Age', 'Domain Expiration',
                   'Domain Registrar', 'VT Reputation', 'VT Malicious', 'VT Suspicious', 'VT Undetected', 'VT Harmless',
                   'has_icon', 'favicon_diff_domain', 'favicon_invalid_ext', 'anchor_tags_present', 'anchor_empty_href',
                   'anchor_diff_domain', 'anchor_diff_ratio', 'meta_external', 'meta_sus_words', 'external_meta_ratio',
                   'script_external', 'script_sus_words', 'external_script_ratio', 'total_links', 'external_link_count',
                   'ratio_extern_link', 'total_external', 'total_resources', 'external_resources',
                   'external_request_ratio', 'sfh_total_forms', 'sfh_blank_action', 'sfh_diff_domain',
                   'sfh_password_inputs', 'sfh_suspicious_inputs', 'iframe_src_count', 'iframe_src_hidden',
                   'iframe_src_size', 'iframe_src_diff_domain', 'iframe_src_no_sandbox', 'iframe_external_src_ratio',
                   'iframe_srcdoc_count', 'iframe_srcdoc_hidden', 'iframe_srcdoc_scripts', 'iframe_srcdoc_sus_words',
                   'total_iframes', 'inline_scripts', 'high_risk_patterns', 'medium_risk_patterns', 'low_risk_patterns',
                   'sus_js_diff_domain', 'sus_js_behave_ratio', 'risk_patterns_ratio', 'nlp_suspicious_words',
                   'onmouseover_scripts', 'onmouseover_tags', 'right_click_scripts', 'right_click_tags',
                   'Different Domains']
LABEL_HEADER = "validity"


def plot_features_weights(model, feature_cols: list):
    importances = model.feature_importances_
    feature_importance_df = pd.DataFrame({
        'Feature': feature_cols,
        'Importance': importances
    }).sort_values(by='Importance', ascending=False)

    print(feature_importance_df)

    plt.figure(figsize=(20, 20))
    plt.barh(feature_importance_df['Feature'], feature_importance_df['Importance'])
    plt.xlabel('Importance')
    plt.title('Feature Importances in Random Forest')
    plt.gca().invert_yaxis()
    plt.show()


def print_sample_output(x_test, model, validity_copy: pd.Series, df: pd.DataFrame, results_to_display: int):
    test_indices = x_test.index
    random_indices = random.sample(list(test_indices), results_to_display)
    classes = model.classes_

    print(f"\n🎯 Showing {results_to_display} random predictions:\n")

    for idx in random_indices:
        sample_df = x_test.loc[[idx]]
        url = df.loc[idx, "URL"]
        predicted_class = model.predict(sample_df)[0]
        probability = model.predict_proba(sample_df)[0]
        confidence = max(probability)
        real_validity = validity_copy.loc[idx]

        print(f"🧪 Sample index: {idx}")
        print(f"URL: {url}")
        print(f"Predicted class: {predicted_class} ({'Safe' if predicted_class == 1 else 'Malicious'})")
        print(f"Confidence: {confidence:.4f}")
        print(f"Real validity: {real_validity}")
        print("Class probabilities:")

        for cls, prob in zip(classes, probability):
            label = "Safe" if cls == 1 else "Malicious"
            print(f"  {label} ({cls}): {prob:.4f}")

        print("-" * 50)


def get_model(model_name: str, x_train, y_train):
    if model_name == "LogisticRegression":
        model = LogisticRegression(max_iter=1000)
        # model.fit(x_train, y_train)
    elif model_name == "RandomForestClassifier":
        model = RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=19)
        # model.fit(x_train, y_train)
    elif model_name == "XGBClassifier":
        model = XGBClassifier(scale_pos_weight=len(y_train[y_train == 0]) / len(y_train[y_train == 1]))
        # model.fit(x_train, y_train)
    else:
        model = RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=19)
        # model.fit(x_train, y_train)

    return model


def md5_hash_index(text, n_features=10):
    text = str(text) if text is not None else "nan"
    digest = hashlib.md5(text.encode()).digest()

    int_hash = int.from_bytes(digest[:4], "little", signed=False)

    index = int_hash % n_features
    sign = -1 if (int_hash & 1) else 1

    return index,sign

def custom_md5_hash_vector(parts, n_features=10):
    vec = np.zeros(n_features, dtype=np.float32)
    for raw in parts:
        index,sign = md5_hash_index(raw, n_features)
        vec[index] += sign
    return vec
def run_model(df: pd.DataFrame, model_name: str = "RandomForestClassifier", train_size: float = 0.05):
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report

    # עמודות קטגוריות
    categorical_cols = ['Final Domain', 'SSL Issuer', 'Domain Registrar']
    N_FEATURES = 10

    hashed_mat = np.vstack(
        df[categorical_cols]
        .astype(str)  # כל הערכים כ-string
        .apply(lambda r: custom_md5_hash_vector(r.values, n_features=N_FEATURES),axis=1)
        .to_numpy()
    )

    hashed_df = pd.DataFrame(hashed_mat,columns=[f'h{i}' for i in range(N_FEATURES)])

    # פירוק תכונות ומיזוג עם hash
    drop_cols = ['URL'] + categorical_cols + ['validity']
    X_numeric = df.drop(columns=drop_cols)
    X = pd.concat([X_numeric.reset_index(drop=True), hashed_df.reset_index(drop=True)], axis=1)

    y = df['validity'].map({'safe': 0, 'unsafe': 1})

    # פיצול לפי train_size
    x_train, x_test, y_train, y_test = train_test_split(X, y, train_size=train_size, stratify=y, random_state=42)

    # קבלת המודל מהפונקציה הדינמית
    model = get_model(model_name, x_train, y_train)
    model.fit(x_train, y_train)

    y_pred = model.predict(x_test)
    print(f"\n🔍 Evaluation for model: {model_name}")
    print(f"🧪 Train size: {train_size*100:.1f}%")
    print("\n📊 Classification Report:\n")
    print(classification_report(y_test, y_pred, zero_division=0))
    return model

##################################
# validity_copy = df["validity"].copy()
#
# categorical_columns = ['SSL Issuer', 'Domain Registrar']
#
# # Select feature and label columns
# x = df[FEATURES_HEADER]
# y = df[LABEL_HEADER].map({'safe': 1, 'unsafe': 0})
#
# # Apply HashingEncoder
# encoder = ce.HashingEncoder(cols=categorical_columns, n_components=16)  # You can adjust n_components
# x_encoded = encoder.fit_transform(x)
#
# # Train-test split
# x_train, x_test, y_train, y_test = train_test_split(x_encoded, y, test_size=0.15, random_state=17)
#
# model = get_model(model_name, x_train, y_train)
#
# # Make predictions
# y_pred = model.predict(x_test)
# accuracy = accuracy_score(y_test, y_pred)
# #classification = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
# classification = classification_report(y_test, y_pred, output_dict=False, zero_division=0)

# print("Accuracy:", accuracy)
# print("Classification Report:\n", classification)

# plot_features_weights(model, x_encoded.columns.tolist())  # pass encoded feature names
############################################################
# #print_sample_output(x_test, model, validity_copy, df, 50)
#
# all_probabilities = model.predict_proba(x)
#
# # Get predicted class (0 or 1) for each row
# predicted_classes = model.predict(x)
#
# # Get the confidence (i.e., the probability of the predicted class)
# confidences = all_probabilities[np.arange(len(predicted_classes)), predicted_classes]
#
# # Add confidence as a new column
# df["predicted"] = predicted_classes
# df["confidence"] = confidences

# df.to_csv(getcwd() + "\\stage2_output_with_confidence.csv", index=False)

# return classification


if __name__ == "__main__":
    root = Tk()
    root.withdraw()
    input_file = filedialog.askopenfilename(title="Select input CSV file", filetypes=[("CSV files", "*.csv")])

    if not input_file:
        print("No input file selected.")
        exit(1)

    df = pd.read_csv(input_file)


    my_train_model_RFC = run_model(df, "RandomForestClassifier", 0.25)
    my_train_model_LR = run_model(df, "LogisticRegression", 0.25)

    joblib.dump(my_train_model_RFC, "trained_models/trained_model_random_forest.pkl")
    joblib.dump(my_train_model_LR, "trained_models/trained_model_logistic.pkl")