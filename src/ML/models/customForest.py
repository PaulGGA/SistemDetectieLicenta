import sys
import os
import numpy as np
import pandas as pd
import time
from joblib import Parallel, delayed
import multiprocessing




current_dir = os.path.dirname(os.path.abspath(__file__))

root_path = os.path.abspath(os.path.join(current_dir, '..', '..', '..'))
sys.path.insert(0, root_path)


try:
    from entropyCalcC import lib as entropyLib
except ImportError:
    print("Eroare la incarcarea modulului de calculare a entropiei")
    entropyLib = None


def entropyNode(y):
    if len(y) == 0:
        return 0.0
    
    
    try:
        from entropyCalcC import lib as entropyLib
    except ImportError as e:
        print(f" Eroare la incărcarea modulului: {e}")
        print(f"[DEBUG] sys.path: {sys.path[:5]}")
        entropyLib = None
    
    if entropyLib:
        labelBytes = bytes(y.astype(np.uint8).tolist())
        return entropyLib.calcEntropie(labelBytes, len(labelBytes))
    else:
        hist = np.bincount(y)
        ps = hist / len(y)
        return -np.sum([p* np.log2(p) for p in ps if p >0])


def trainTree(data, labels, maxDepth, minSamples, cntFeatures):
    tree = DecisionTree(maxDepth= maxDepth, minSplitSamples= minSamples, cntFeatures= cntFeatures)

    cntSamples = data.shape[0]
    dataSubset = np.random.choice(a = cntSamples, size = cntSamples, replace = True )

    tree.fit(data[dataSubset],labels[dataSubset])

    return tree

class CustomRandomForest:
    def __init__(self, nEstimators = 100, maxDepth = 30, minSamples = 2, nJobs = -1):
        self.nEstimators = nEstimators
        self.maxDepth = maxDepth
        self.minSamples = minSamples
        self.nJobs = nJobs
        self.trees = []
        self.cntFeatures = None

    def fit(self,x, labels):
        dataNp = np.array(x)
        labelsNp = np.array(labels)

        nrSamples, nrFeatures = dataNp.shape

        self.cntFeatures = int(np.log2(nrFeatures))
  

        if self.nJobs == -1:
            cntCPU =     multiprocessing.cpu_count()
        else:
            cntCPU = self.nJobs

        print(f" Antrenare Custom Forest ({self.nEstimators} arbori) pe {cntCPU} nuclee...")

        self.trees = Parallel(n_jobs= cntCPU, verbose= 10)(
            delayed(trainTree)(
                dataNp, labelsNp, self.maxDepth, self.minSamples, self.cntFeatures) for _ in range(self.nEstimators)
            )
        
        print("Antrenament terminat")


    def predict(self, X):

        data = np.array(X)
        tree_preds = np.array([tree.predict(data) for tree in self.trees if tree !=None])
        
        tree_preds = np.swapaxes(tree_preds, 0, 1)
        
        y_pred = [self.majorityLabel(votes) for votes in tree_preds]

        return np.array(y_pred)

    def majorityLabel(self, y):
        if  len(y) - sum(y) > len(y)/2:
            return 0
        return 1

    def probability(self,X):
        data = X
        
        preds = np.array([tree.predict(data) for tree in self.trees if tree != None]).T

        probMalware = np.mean(preds[0])

        probBenign = 1.0 -probMalware

        return np.column_stack((probBenign, probMalware))        
         

        


class Node:
    def __init__(self, feature = None, treshold = None, left = None, right = None, value = None):
        self.feature = feature
        self.treshold = treshold
        self.left = left
        self.right = right
        self.value = value

    def isLeaf(self):
        return self.value is not None
    
class DecisionTree:
    def __init__(self, maxDepth = 30, minSplitSamples = 2, classWeight = None, cntFeatures = None):
        self.maxDepth = maxDepth
        self.minSplitSamples= minSplitSamples
        self.root = None
        self.classWeight = classWeight
        self.cntFeatures= cntFeatures

    def entropyGain(self, values, labels, threshold):
        currentEntropy = entropyNode(labels)

        results = values <= threshold

        leftNodeGroup = results
        rightNodeGroup = ~results

        if len(labels[leftNodeGroup]) == 0 or len(labels[rightNodeGroup]) == 0:
            return 0
        
        entropyChildL = entropyNode(labels[leftNodeGroup])
        entropyChildR = entropyNode(labels[rightNodeGroup])

        totalChildEntropy = entropyChildL * (len(labels[leftNodeGroup])/ len(labels)) + entropyChildR * (len(labels[rightNodeGroup])/len(labels))

        entropyDif =  currentEntropy - totalChildEntropy

        return entropyDif


    def fit(self, X,y):
        data = np.array(X)
        labels = np.array(y)

        self.nFeatures = data.shape[1]

        if self.cntFeatures is None:
            self.cntFeatures = self.nFeatures
        else:
            self.cntFeatures = min(self.cntFeatures, self.nFeatures)

        self.root = self.build(data,labels,depth= 0)


    def build(self, X, y, depth = 0):
        totalSamples, totalFeatures = X.shape
        totalClasses = len(np.unique(y))

        if depth >= self.maxDepth or totalClasses == 1 or totalSamples < self.minSplitSamples:
            leafValue = self.majorityLabel(y)
            return Node(value= leafValue)
        
        featureSubset = np.random.choice(a = totalFeatures, size = self.cntFeatures, replace = False )

        bestFeature, bestTreshold = self.bestSplit(X,y , featureSubset)

        if bestFeature is None:
            leafValue = self.majorityLabel(y)
            return Node( value= leafValue)
        
        leftNodeGroup = X[:,bestFeature] <= bestTreshold
        rightNodeGroup = ~leftNodeGroup

        subTreeL = self.build(X[leftNodeGroup], y[leftNodeGroup], depth + 1 )
        subTreeR = self.build(X[rightNodeGroup],y[rightNodeGroup],depth + 1)

        return Node(feature= bestFeature,treshold=bestTreshold, left= subTreeL, right= subTreeR)
    
    def majorityLabel(self, y):
        if  len(y) - sum(y) >= len(y)/2:
            return 0
        return 1              
    
    def bestSplit(self, X, y, features):
        maxGain = -np.inf
        bestFeature = None
        bestThreshold = None

        for feature in features:
            thresholds = np.unique(X[:, feature])

            for t in thresholds:
                gain = self.entropyGain(X[:, feature], y, t)

                if gain > maxGain:
                    maxGain = gain
                    bestFeature = feature
                    bestThreshold = t

        return bestFeature, bestThreshold
    
    def traverse(self, x, node):
        if node.isLeaf():
            return node.value
        
        if x[node.feature] <= node.treshold:
            return self.traverse(x, node.left)
        return self.traverse(x, node.right)
    
    def predict(self, X):
        return np.array([self.traverse(x,self.root) for x in X])




