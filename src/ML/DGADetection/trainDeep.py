import pandas
import torch
from torch.nn.utils.rnn import pad_sequence
import torch.optim
from sklearn.model_selection import train_test_split
from torch.utils.data import DataLoader
import zipfile
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

import src.ML.DGADetection.modelCombined as modelCombined
import ML.DGADetection.DatasetDeep as DatasetDeep


# antrenare model Deep

zipPath = "/content/dataset.zip"
csvPath = "/content/unzipped/dataset.csv"

# unzipped_folder = "unzipped"
# os.makedirs(unzipped_folder, exist_ok=True)

# with zipfile.ZipFile(zipPath, 'r') as zip_ref:
#     zip_ref.extractall(unzipped_folder)


dictionarValoriAlfabet ={
    'a': 2,  'b': 3,  'c': 4,  'd': 5,  'e': 6,  'f': 7,  'g': 8,  'h': 9,  'i': 10,'j': 11, 'k': 12, 'l': 13, 'm': 14, 'n': 15, 'o': 16, 'p': 17, 'q': 18, 'r': 19,
    's': 20, 't': 21, 'u': 22, 'v': 23, 'w': 24, 'x': 25, 'y': 26, 'z': 27,
    '0': 28, '1': 29, '2': 30, '3': 31, '4': 32, '5': 33, '6': 34, '7': 35, '8': 36, '9': 37, '-': 38, '.': 39, '_': 40, 'other': 1
}


def readDataFromCSV():
    data = pandas.read_csv(csvPath)

    data = data[["Domain", "Label"]]

    return data

def padding(data):
    x = [elem[0] for elem in data]
    y = [elem[1] for elem in data]

    xPadded = pad_sequence(x, True)

    yTensor = torch.stack(y)
    
    return xPadded, yTensor


def prepareData(data):

    x = data["Domain"]

    y = data["Label"]


    xTrain, xTest, yTrain,yTest  = train_test_split(x,y, shuffle= True, train_size= 0.8, test_size= 0.2)
    
    xTrain = xTrain.reset_index(drop=True)
    yTrain = yTrain.reset_index(drop=True)
    xTest = xTest.reset_index(drop=True)
    yTest = yTest.reset_index(drop=True)

    trainData = DatasetDeep.datasetLong(xTrain,yTrain,dictionarValoriAlfabet)

    dataLoaderTrain = DataLoader(trainData,128, shuffle= True, collate_fn= padding,num_workers= 4)

    testData = DatasetDeep.datasetLong(xTest,yTest,dictionarValoriAlfabet)

    dataLoaderTest = DataLoader(testData,128, shuffle= True, collate_fn= padding,num_workers= 4)


    return dataLoaderTrain,dataLoaderTest

def prepareDataFile(data):
    x = data["Domain"]
    dataset = DatasetDeep.datasetLong(x,None,dictionarValoriAlfabet)

    domainsDataLoader = DataLoader(dataset)

    return domainsDataLoader


def train(trainData):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    model = modelCombined.CNNLSTM().to(device)

    optimizer = torch.optim.Adam(model.parameters(), lr = 3e-4, weight_decay= 1e-4)

    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=30, eta_min=1e-6)

    criterion = torch.nn.BCELoss()

    nrEpoc = 20

    for epoch in range(1, nrEpoc +1):

        model.train()
        trainLoss = 0.0
        correct_preds = 0
        total_samples = 0
        for elems, labels in trainData:
            elems = elems.to(device)
            labels = labels.to(device)


            optimizer.zero_grad()

            outputs = model(elems)

            loss = criterion(outputs, labels)

            loss.backward()

            optimizer.step()

            trainLoss += loss.item() * elems.size(0)

            preds = (outputs >= 0.5).float()
            correct_preds += (preds == labels).sum().item()
            total_samples += labels.size(0)

        epochTrainLoss = trainLoss / len(trainData.dataset)

        epochAcc = (correct_preds / total_samples) * 100
        scheduler.step()

        print(f"Epoca {epoch:02d} | Train Loss = {epochTrainLoss:.4f} | Acuratețe Train = {epochAcc:.2f}%")
        
    return model

def test(model, testData, outputCSV = "output.csv"):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)
    model.eval()

    predictions = []
    ids = [id for (id, _) in testData]
    correct_preds = 0
    total_samples = 0

    with torch.no_grad():
        for elems, labels in testData:
            elems = elems.to(device)
            labels = labels.to(device)
            outputs = model(elems)
            preds = (outputs >= 0.5).float()
            
            correct_preds += (preds == labels).sum().item()
            total_samples += labels.size(0)
            
    testAcc = (correct_preds / total_samples) * 100
    print(f"Acuratete finala: {testAcc:.2f}%")

    # with open(outputCSV, 'w') as f:
    #     f.write("image_id,label\n")
    #     for elem, pred in zip(ids, predictions):
    #         f.write(f"{elem},{pred}\n")
    



# if __name__ == "__main__":
#     data = readDataFromCSV()
    
#     trainLoader, testLoader = prepareData(data)
    
#     trained_model = train(trainLoader)
    
#     test(trained_model, testLoader)

#     torch.save(trained_model.state_dict(),"model.pt")