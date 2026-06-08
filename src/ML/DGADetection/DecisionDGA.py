import xgboost
import pandas
import numpy as np
import sys
import os
try:
    import importlib.util
    torch_spec = importlib.util.find_spec("torch")
    if torch_spec and torch_spec.origin:
        torch_lib = os.path.join(os.path.dirname(torch_spec.origin), "lib")
        if os.path.exists(torch_lib):
            os.add_dll_directory(torch_lib)
except Exception:
    pass
import torch

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

import ML.DGADetection.trainDeep as trainDeep
import src.ML.DGADetection.modelCombined as modelCombined
import src.ML.DGADetection.FeatureExtractionDGA as FeatureExtractionDGA



modelDeepPath = "src\\ML\\models\\model.pt"
modelWidePath = "src\\ML\\models\\XgModelDGA.json"

def getModels():

    try:
        modelDeep = modelCombined.CNNLSTM()
        modelDeep.load_state_dict(torch.load(modelDeepPath, weights_only=True, map_location=torch.device('cpu')))

        modelWide = xgboost.Booster()
        modelWide.load_model(modelWidePath)

        modelDeep.eval()


        return modelWide, modelDeep 

    except Exception as e:
        print(f"Eroare la incarcarea modelelor: {e}")
        return None, None


def featureExtractWide(listDomains):
    FeatureExtractionDGA.extractFeatures(listDomains, "", True)


def getDataLoader(csvPath = "src\\ML\\DGADetection\\file.csv"):
    
    try:
        data = pandas.read_csv(csvPath)
        
        return trainDeep.prepareDataFile(data)
        
    except Exception as e:
        print(f"Eroare la creeare DataLoader : {e}")
        return None
    
def testDomains(listDomains, prag = 0.7, csvPath = "src\\ML\\DGADetection\\file.csv"):

    modelWide, modelDeep = getModels()

    if modelWide is None or modelDeep is None:
        return {}
    
    featureExtractWide(listDomains)

    dataframe = pandas.read_csv(csvPath).drop(columns=['Domain'], errors='ignore')


    featuresWide = dataframe[modelWide.feature_names]

    featuresWide = featuresWide.apply(pandas.to_numeric, errors='coerce').fillna(0)

    featuresWide = featuresWide.astype(float)
    
    xgboostMatrix = xgboost.DMatrix(featuresWide.values, feature_names=modelWide.feature_names)

    probsWide = modelWide.predict(xgboostMatrix)


    dataloader = getDataLoader()

    if dataloader is None:
        return {}

    modelDeep.eval()
    probsDeep = []

    with torch.no_grad():
        for domains in dataloader:
            if isinstance(domains, (tuple, list)) and len(domains) == 2:
                elems, _ = domains
            else:
                elems = domains
                
            outputs = modelDeep(elems)
            

            probs_batch = outputs.squeeze().cpu().numpy().tolist()
            
            if isinstance(probs_batch, float):
                probsDeep.append(probs_batch)
            else:
                probsDeep.extend(probs_batch)
    
    finalProbs = []

    probsWideNp = np.array(probsWide)
    probsDeepNp = np.array(probsDeep)



    finalProbs = (probsDeepNp+probsWideNp)/2.0


    rez = {}

    for dom, p in zip(listDomains,finalProbs):
        finalDecision = bool(p > prag)
        rez[dom] = (finalDecision, p)


    return rez
