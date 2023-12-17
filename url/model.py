from subprocess import CalledProcessError
from sklearn.tree import export_graphviz
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
import IPython
import re
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import joblib
from lime.lime_tabular import LimeTabularExplainer

df = pd.read_csv("Backend/final.csv")
df = df.dropna()

df["url"] = df["Protocol"] + "://" + df["Domain"] + df["Path"]

df["age_domain"].value_counts()
df["statistical_report"].value_counts()
df["dns_record"].value_counts()


def slashes(url):
    # matched = re.search(dot_pattern, url)
    if len(url.split("/")) > 5:
        return 1
    else:
        return 0


df["slashes"] = df["url"].apply(lambda i: slashes(i))
df["slashes"].value_counts()


def dots(url):
    pattern = re.compile(r"\.")
    # matched = re.search(dot_pattern, url)
    if len(pattern.findall(url)) > 3:
        return 1
    else:
        return 0


df["dots"] = df["url"].apply(lambda i: dots(i))
df["dots"].value_counts()

y = df["label"]
# x = df.drop('Label', axis=1)
x = df.drop(
    [
        "Domain",
        "Path",
        "Protocol",
        "label",
        "Having_@_symbol",
        "Redirection_//_symbol",
        "Having_IP",
        "web_traffic",
        "url",
        "http_tokens",
    ],
    axis=1,
)
print(x.shape, y.shape)

print(x.columns)

x_train, x_test, y_train, y_test = train_test_split(
    x, y, test_size=0.2, random_state=42, shuffle=True
)
x_train.shape, y_train.shape, x_test.shape, y_test.shape


classfier = DecisionTreeClassifier(random_state=42)
classfier.fit(x_train, y_train)

# predicting the target value from the model for the samples with default values
y_test_tree = classfier.predict(x_test)
y_train_tree = classfier.predict(x_train)

acc_train_tree = accuracy_score(y_train, y_train_tree)
acc_test_tree = accuracy_score(y_test, y_test_tree)

print("Decision Tree: Accuracy on training Data: {:3f}".format(acc_train_tree))
print("Decision Tree: Accuracy on test Data: {:3f}".format(acc_test_tree))
print("Classification report - \n", classification_report(y_test, y_test_tree))
print(confusion_matrix(y_test, y_test_tree))


forest = RandomForestClassifier(max_depth=50, n_estimators=50)

# fit the model
forest.fit(x_train, y_train)
y_test_forest = forest.predict(x_test)
y_train_forest = forest.predict(x_train)

# computing the accuracy of the model performance
acc_train_forest = accuracy_score(y_train, y_train_forest)
acc_test_forest = accuracy_score(y_test, y_test_forest)

print("Random forest: Accuracy on training Data: {:.3f}".format(acc_train_forest))
print("Random forest: Accuracy on test Data: {:.3f}".format(acc_test_forest))
print("Classification report - \n", classification_report(y_test, y_test_forest))
print(confusion_matrix(y_test, y_test_forest))

import xgboost as xgb

xgb_model = xgb.XGBClassifier(learning_rate=0.3, n_estimators=100, max_depth=6)
xgb_model.fit(x_train, y_train)
y_test_xgb = xgb_model.predict(x_test)
y_train_xgb = xgb_model.predict(x_train)

# computing the accuracy of the model performance
acc_train_xgb = accuracy_score(y_train, y_train_xgb)
acc_test_xgb = accuracy_score(y_test, y_test_xgb)

print("XGB: Accuracy on training Data: {:.3f}".format(acc_train_xgb))
print("XGB: Accuracy on test Data: {:.3f}".format(acc_test_xgb))
print("Classification report - \n", classification_report(y_test, y_test_xgb))
print(confusion_matrix(y_test, y_test_xgb))

# class_names = ['original', 'phishing']
# feature_names = list(x_train.columns)

# explainer = LimeTabularExplainer(x_train.values, feature_names=feature_names, class_names=class_names, mode='classification')
# instance = x_test.iloc[5]
# Explain the model prediction for the instance
# explanation = explainer.explain_instance(instance, forest.predict_proba)
# explanation.show_in_notebook()

import pickle
# save the classifier
with open('model.pkl', 'wb') as fid:
    pickle.dump(xgb_model, fid)
