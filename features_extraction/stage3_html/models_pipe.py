import pandas as pd
import numpy as np


from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier

from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix


stage1_df = pd.read_csv('stage1_features.csv')
stage2_df = pd.read_csv('stage2_features.csv')
stage3_df = pd.read_csv('stage3_features.csv')

