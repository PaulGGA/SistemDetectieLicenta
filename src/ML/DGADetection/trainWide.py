import pandas
import time
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns


# antrenare model Wide

csvPath = "data\\DGA\\dataset.csv"


def main():
    startT = time.time()

    data = pandas.read_csv(csvPath)

    y = data["Label"]

    x =data.drop(columns=["Domain", "Label"])


    names = x.columns.tolist()

    xTrain, xTest, yTrain, yTest = train_test_split(x,y, test_size= 0.2, train_size= 0.8, stratify= y)

    model = XGBClassifier(eta = 0.05, max_depth = 7, min_child_weight = 3, subsample = 0.7,
                            n_estimators = 500, colsample_bytree = 0.7, random_state = 10, tree_method = 'hist', 
                            reg_alpha = 0.1, reg_lambda = 1, n_jobs = -1 )

    model.fit(xTrain,yTrain)

    model.save_model("src\\ML\\models\\XgModelDGA.json")   

    yPred = model.predict(xTest)

    acc = accuracy_score(y_true= yTest, y_pred= yPred)

    print(f"Acuratete: {acc}")







