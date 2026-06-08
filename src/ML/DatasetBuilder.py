import os
import random
import pandas
import sys

from sklearn.model_selection import train_test_split

folderMalware = "C:\\licenta\\antibibus\\data\\malware\\unzip"
folderBenign = "C:\\licenta\\antibibus\\data\\benign"

outputCSV = "C:\\licenta\\antibibus\\data\\dataset_full.csv"

root_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if root_path not in sys.path:
    sys.path.append(root_path)


from src.Utils.VerificareFormat import verificaFormat
from src.ML.FeaturesExtraction import extractPE, getHash
def reorderData(data):
    ordine = [
        "EntropyTotal", "EntropyText", "EntropyData", "EntropyRsrc", 
        "FileSize", "SectionsCnt", "ExecSections", "RWXSections", 
        "ImportsCnt", "DllImportsCnt", "AddressOfEntryPoint", 
        "SectionAlignment", "FileAlignment", "SizeOfImage", 
        "SizeOfHeaders", "DllCharacteristics", "Characteristics"
        ]
    
    for col in ordine:
        if col not in data.columns:
            data[col] = 0.0
    
    return data[ordine]


def formatFile(filepath, label):

    try:
        if verificaFormat(filePath=filepath) != "PE":
            return None
        
        features = extractPE(file= filepath)


        hash = getHash(filepath,"sha256")

        features['hash'] = hash
        features['label'] = label
        features['filename'] = os.path.basename(filepath)

        return features
    except Exception as e:
        print(f"Eroare la fisierul {filepath}: {e}")
        return None
    

def buildDataSet(cntMalwareFiles, cntBenignFiles):
    malwareFiles = [os.path.join(folderMalware,file) for file in os.listdir(folderMalware)]
    benignFiles = [os.path.join(folderBenign,file) for file in os.listdir(folderBenign)]

    print(f"Disponibile: {len(malwareFiles)} malware, {len(benignFiles)} benign")


    random.seed(10)

    malwareSample = random.sample(malwareFiles, min(cntMalwareFiles, len(malwareFiles)))
    benignSample = random.sample(benignFiles,min(cntBenignFiles, len(benignFiles)))

    print(f"Selectate: {len(malwareSample)} malware, {len(benignSample)} benign")

    features = []

    for file in malwareSample:
        auxFeatuers = formatFile(file,1)
        if auxFeatuers != None:
            features.append(auxFeatuers)

    for file in benignSample:
        auxFeatuers = formatFile(file,0)
        if auxFeatuers != None:
            features.append(auxFeatuers)

    dataFrame = pandas.DataFrame(features)
    print(f"\nDataset final: {len(dataFrame)} samples")
    print(f"Malware: {len(dataFrame[dataFrame['label']==1])}")
    print(f"Benign: {len(dataFrame[dataFrame['label']==0])}")
    
    return dataFrame

def splitData():
    dataFrame = pandas.read_csv("data\\static\\dataset_full.csv")

    features =  dataFrame.drop(['label', 'hash', 'filename', 'TimeDateStamp', 'ImageBase', "Index"], axis = 1)

    features = reorderData(features)
    labels = dataFrame['label']

    xTrain, xTest, yTrain, yTest = train_test_split(
        features,
        labels,
        train_size= 0.8,
        test_size= 0.2,
        stratify= labels
    )


   
    
    return xTrain, xTest, yTrain, yTest



