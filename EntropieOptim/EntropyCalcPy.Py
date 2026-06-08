from entropyCalcC import lib
import os

def CalcEntropyOptim(data: bytes) -> float:
    if not data:
        return 0.0
    
    dataBytes = data

    return lib.calcEntropie(dataBytes,len(dataBytes))
