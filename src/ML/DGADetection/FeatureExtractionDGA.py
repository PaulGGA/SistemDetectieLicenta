import tldextract
import sys
import os
import math
import pandas

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..')))


tldList = ["is_biz","is_cc","is_cn","is_co.uk","is_com","is_de","is_eu","is_in","is_info","is_ir","is_kz","is_net","is_org","is_other","is_ru","is_top"]



try:
    from entropyCalcC import lib as entropyLib
except ImportError as e:
    print(f"Eroare la incarcarea modulului de calculare a entropiei {e}")
    entropyLib = None

def CalcEntropyOptim(data) -> float:
    if not data:
        return 0.0
    
    if type(data) != bytes:
        data = data.encode()
    
    dataBytes = data

    if entropyLib is None:
        return 0.0
    return entropyLib.calcEntropie(dataBytes,len(dataBytes))

def eVoc(c):
    if c in "aeiouAEIOU":
        return True
    return False

def maxConsSecv(text):
    
    secv = 0
    secvMax = 0
    for c in text:
        if eVoc(c) == False:
            secv += 1
        else:
            if secv > secvMax:
                secvMax = secv
            secv = 0
    if secv > secvMax:
        secvMax = secv
    
    return secvMax


def vowelRatio(text):

    cnt = 0

    for c in text:
        if eVoc(c):
            cnt +=1
    
    r = cnt/len(text)
    
    return r


def consRatio(text: str):

    cnt = 0

    for c in text:
        if eVoc(c) == False and c.isalpha():
            cnt +=1
    
    r = cnt/len(text)
    
    return r


def digitRatio(text: str):

    cnt = 0

    for c in text:
        if c.isdigit():
            cnt +=1
    
    r = cnt/len(text)
    
    return r


def uniqueRatio(text: str):
    if not text:
        return 0.0

    
    return len(set(text))/len(text) 



def specialRatio(text: str):

    cnt = 0

    for c in text:
        if not c.isalnum():
            cnt +=1
    
    r = cnt/len(text)
    
    return r

def vcRatio(text: str):
    cnt = 0

    ant = None
    for c in text:
        if ant != None:
            if c.isalpha() and ant.isalpha():
                if eVoc(c) ^ eVoc(ant):
                    cnt +=1
        ant = c
    
    r = cnt/len(text)
    
    return r


def createStringVCDS(text: str):
    newStr = ""

    for c in text:
        if eVoc(c):
            newStr +="V"
        elif c.isdigit():
            newStr += "D"
        elif c.isalpha():
            newStr += "C"
        else:
            newStr += "S"
    return newStr

def vcdsEntropy(text: str):
    
    newStr = createStringVCDS(text)
    

    entropie = CalcEntropyOptim(newStr.encode())

    return entropie
        

def vcdsEntropyCond(text):
    newStr = createStringVCDS(text)
    
    frecvPerechi = {}
    frecvPrima = {}

    for i in range(len(newStr) - 1):
        pereche = newStr[i:i+2]
        prima_litera = pereche[0]
        
        frecvPerechi[pereche] = frecvPerechi.get(pereche, 0) + 1
        frecvPrima[prima_litera] = frecvPrima.get(prima_litera, 0) + 1

    entropie = 0.0
    n = len(newStr) -1
    for k in ["C", "V", "D", "S"]:
        for l in ["C", "V", "D", "S"]:
            if k+l not in frecvPerechi or k not in frecvPrima:
                continue
            entropie -= frecvPerechi[k+l]/n * math.log2(frecvPerechi[k+l]/frecvPrima[k])

    return entropie

    
    
    

def length(text):

    return len(text)





def getSLD(domain : str):
    
    try:
        dom = str(domain).strip().lower() 
        obj = tldextract.extract(dom)
        
        return obj.domain
    except Exception as e:
        print(f"Eroare la extragerea SLD : {e}")
        return "error"

def getTLD(domain : str):
    try:
        dom = str(domain).strip().lower() 
        obj = tldextract.extract(dom)
        
        return obj.suffix
    except Exception as e:
        print(f"Eroare la extragerea TLD : {e}")
        return "error"


    

def tldEncoding(data: pandas.DataFrame):
    data["TLD"] = data["Domain"].apply(getTLD)
    data = data[data["TLD"] != "error"]

    topList = data["TLD"].value_counts().head(15).index.tolist()

    data["TLDaux"] = data["TLD"].apply(lambda x: x if x in topList else "other")

    data = pandas.get_dummies(data, columns= ["TLDaux"], prefix="is", dtype= int)

    for col in data.columns:
        if col.startswith("is_"):
            data[col] = data[col].astype(int)

    data = data.drop(columns="TLD")

    return data


def extractFeatures(listDomains = [], csvPath = "C:\\licenta\\data\\DGA\\dataset.csv", ok = False):
    if ok == False:
        data = pandas.read_csv(csvPath)
    else:
        data = pandas.DataFrame(listDomains, columns = ["Domain"])
        csvPath = "src\\ML\\DGADetection\\file.csv"
        
    
    data = tldEncoding(data)

    for tld in tldList:
        if tld not in data.columns:
            data[tld] = 0


    

    data["Domain"] = data["Domain"].apply(getSLD)

    data = data[data['Domain'] != "error"]
    data = data[data['Domain'].str.len() > 1]   

    data["Entropy"] = data["Domain"].apply(CalcEntropyOptim)

    data["SecvCons"] = data["Domain"].apply(maxConsSecv)

    data["RatioV"] = data["Domain"].apply(vowelRatio)

    data["RatioC"] = data["Domain"].apply(consRatio)

    data["RatioD"] = data["Domain"].apply(digitRatio)

    data["RatioS"] = data["Domain"].apply(specialRatio)

    data["RatioUnique"] = data["Domain"].apply(uniqueRatio)

    data["RatioVC"] = data["Domain"].apply(vcRatio)

    data["Length"] = data["Domain"].apply(length)

    data["EntropyVCDS"] = data["Domain"].apply(vcdsEntropy)

    data["EntropyCondVCDS"] = data["Domain"].apply(vcdsEntropyCond)


    data.to_csv(csvPath, index = False)


if __name__ == "__main__":
    extractFeatures()