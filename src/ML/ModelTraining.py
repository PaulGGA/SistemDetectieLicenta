from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import pandas
from xgboost import XGBClassifier
import joblib
import numpy as np
import os
import sys
import shap

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))


from src.ML.DatasetBuilder import splitData, reorderData
import src.ML.models.customForest as CF

featureNames = [
    "EntropyTotal", "EntropyText", "EntropyData", "EntropyRsrc",
    "FileSize", "SectionsCnt", "ExecSections", "RWXSections",
    "ImportsCnt", "DllImportsCnt", "AddressOfEntryPoint",
    "SectionAlignment", "FileAlignment", "SizeOfImage",
    "SizeOfHeaders", "DllCharacteristics", "Characteristics"
]


featureExplanations = {
    "EntropyTotal":       ("high total file entropy", 
                           "low total entropy — clear structure"),
    "EntropyText":        ("highly obfuscated/packed code section", 
                           "normal entropy code section"),
    "EntropyData":        ("encrypted or compressed data section", 
                           "normal data section"),
    "EntropyRsrc":        ("unusually dense resources — possible hidden payload", 
                           "normal resources"),
    "FileSize":           ("unusual file size", 
                           "typical file size"),
    "SectionsCnt":        ("unusual number of PE sections", 
                           "normal number of sections"),
    "ExecSections":       ("multiple executable sections — possible packer", 
                           "normal number of executable sections"),
    "RWXSections":        ("Read-Write-Execute sections — highly suspicious behavior", 
                           "no RWX sections"),
    "ImportsCnt":         ("high number of imported functions", 
                           "few imports — possibly packed or statically linked"),
    "DllImportsCnt":      ("high number of imported DLLs", 
                           "normal number of DLLs"),
    "AddressOfEntryPoint":("entry point in an unusual location", 
                           "entry point in a typical location"),
    "SectionAlignment":   ("non-standard section alignment", 
                           "standard alignment"),
    "FileAlignment":      ("non-standard file alignment", 
                           "standard alignment"),
    "SizeOfImage":        ("unusual image size", 
                           "typical image size"),
    "SizeOfHeaders":      ("unusual header size", 
                           "standard header size"),
    "DllCharacteristics": ("suspicious DLL characteristics ", 
                           "normal DLL characteristics"),
    "Characteristics":    ("unusual PE flags", 
                           "normal PE flags"),
}



def explainPrediction(sample, featureNames = featureNames):
    try:
        explainer = joblib.load("src\\ML\\models\\XgExplainer.pkl")
        shapValuesRaw = explainer.shap_values(sample)
        if hasattr(shapValuesRaw, "ndim") and shapValuesRaw.ndim > 1:
            shapValues = shapValuesRaw[0]  
        elif isinstance(shapValuesRaw, list) and len(shapValuesRaw) > 0:
            shapValues = shapValuesRaw[1][0] if len(shapValuesRaw) > 1 else shapValuesRaw[0][0]
        else:
            shapValues = shapValuesRaw

        contributions = []

        for i in range(len(featureNames)):
            featureName = featureNames[i]
            val = float(shapValues[i]) 
            contributions.append((featureName, val))

        contributions.sort(key=lambda x: abs(x[1]),reverse= True)

        top5 = contributions[:5]

        explanations = []

        for feature, shapValue in top5:
            if abs(shapValue) < 0.01:
                continue

            direction = "malware" if shapValue > 0 else "benign"
            magnitude = abs(shapValue)

            if magnitude > 0.3:
                strength = "strong"
            elif magnitude > 0.1:
                strength = "medium"
            else:
                strength = "weak"
        
            pos_desc, neg_desc = featureExplanations.get(
                feature, (feature, feature)
            )
            description = pos_desc if shapValue > 0 else neg_desc

            explanations.append({
                "feature": feature,
                "shap_value": round(float(shapValue), 4),
                "direction": direction,
                "strength": strength,
                "description": description
            })

        return explanations

    except Exception as e:
        print(f"Eroare SHAP: {e}")
        return []



def normalizeData(xTrain, xTest):
    scaler = StandardScaler()

    scaler.fit(xTrain)

    xTrainScaled =  scaler.transform(xTrain)

    xTestScaled = scaler.transform(xTest)

    joblib.dump(scaler, "src\\ML\\models\\scaler.pkl")

    return xTrainScaled, xTestScaled, scaler


def trainForest(xTrain, yTrain):

    forestModel = CF.CustomRandomForest(nEstimators= 200, maxDepth= 20,
                                          minSamples = 2, nJobs = -1 )
    
    forestModel.fit(x= xTrain,labels = yTrain)

    joblib.dump(forestModel,"src\\ML\\models\\ForestModel.libjob" )
    
    return forestModel


def trainxG(xTrain, yTrain):

    xgModel = XGBClassifier(eta = 0.05, max_depth = 6, min_child_weight = 3, subsample = 0.7,
                            n_estimators = 400, colsample_bytree = 0.7, random_state = 10, tree_method = 'hist', 
                            reg_alpha = 0.1, reg_lambda = 1, )
    
    xgModel.fit(X = xTrain,y = yTrain)

    xgModel.save_model("src\\ML\\models\\XgModelStatic.json")    
    
    return xgModel


def predictUserFile(file):

    

    xgModel = XGBClassifier()
    xgModel.load_model("src\\ML\\models\\XgModelStatic.json")
    forestModel = joblib.load("src\\ML\\models\\ForestModel.libjob")
    scaler = joblib.load("src\\ML\\models\\scaler.pkl")
    df_features = pandas.DataFrame([file])

    df =  df_features.drop(['TimeDateStamp', 'ImageBase'], axis = 1)

    dfReordered = reorderData(df)

    date = scaler.transform(dfReordered)


    xgPreds = xgModel.predict_proba(date)[0]
    
    xgProbPred = max(xgPreds)

    mlExplanation = explainPrediction(date)

    

    if xgProbPred > 0.95:
        return int(xgModel.predict(date)[0]), float(xgProbPred), mlExplanation
    else:
        rfPreds = forestModel.probability(date)[0]

        predsFinal = (xgPreds * 2.0 + rfPreds)/3.0 

        predMax = float(max(predsFinal))

        index = int(np.argmax(predsFinal))
        return index, predMax, mlExplanation

