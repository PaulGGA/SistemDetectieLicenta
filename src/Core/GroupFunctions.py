import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import Utils.VerificareFormat as vf
import ML.FeaturesExtraction as fe
import ML.ModelTraining as MT
import config.scanYara as yar
import Utils.DigitalCertificate as DC
import Sandbox.SandboxManagementClient as SC
import DynamicAnalysis.ReportsProcessing as RP
from concurrent.futures import ThreadPoolExecutor



def getFeatures(filePath):

    with ThreadPoolExecutor(max_workers=4) as th:

        hashFile = th.submit(fe.getHash, filePath)
        featuresML = th.submit(fe.extractPE,filePath)
        featuresYara = th.submit(yar.getYarafeatures, filePath)
        featuresCertificat = th.submit(DC.getCertificateFeatures,filePath)
    
    return hashFile.result(), featuresML.result(), featuresYara.result(), featuresCertificat.result()
    

def staticML(features):
    verdict, probability, mlExplanation = MT.predictUserFile(features)

    return verdict, probability, mlExplanation


   
    

    
