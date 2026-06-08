import pefile
import os
import sys
import hashlib


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))




try:
    from entropyCalcC import lib as entropyLib
except ImportError:
    print("Eroare la incarcarea modulului de calculare a entropiei")
    entropyLib = None


folderSafe = "C:\\licenta\\data\\benign"
folderUnsafe = "C:\\licenta\\antibibus\\data\\malware\\unzip"

def getHash(file,alg = 'sha256'):
    hashAlg = hashlib.new(alg)

    with open(file, 'rb') as f:
        while chunk := f.read(8192):
            hashAlg.update(chunk)
    
    return hashAlg.hexdigest()

def CalcEntropyOptim(data: bytes) -> float:
    if not data:
        return 0.0
    
    dataBytes = data

    if entropyLib is None:
        return 0.0
    return entropyLib.calcEntropie(dataBytes,len(dataBytes))




def extractPE(file):

    features = {
        "EntropyTotal":0.0,
        "EntropyText":0.0,
        "EntropyData":0.0,
        "EntropyRsrc":0.0,
        "FileSize": os.path.getsize(file),
        "SectionsCnt":0,
        "ImportsCnt":0,
        "DllImportsCnt":0,
        "ExecSections":0,
        "RWXSections":0,
        "AddressOfEntryPoint":0,
        "ImageBase":0,
        "SectionAlignment":0,
        "FileAlignment":0,
        "SizeOfImage":0,
        "SizeOfHeaders":0,
        "DllCharacteristics":0,
        "Characteristics":0,
        "TimeDateStamp":0,
    }

    with open(file, "rb") as f:
        data = f.read()

    features["EntropyTotal"] = CalcEntropyOptim(data)


    try:
        pe = pefile.PE(file)
        cntExecSections = 0
        cntRwxSections = 0
        for section in pe.sections:
            name = section.Name.decode(errors='ignore').strip('\x00')
            entropy = section.get_entropy()

            if name == ".text":
                features["EntropyText"] = entropy
            elif name == ".data":
                features["EntropyData"] = entropy
            elif name == ".rsrc":
                features["EntropyRsrc"] = entropy


            
            if section.Characteristics & 0x20000000:
                cntExecSections +=1

            # prezenta sectiunii read, write si execute
            RWX_MASK = 0x20000000 | 0x40000000 | 0x80000000
            if (section.Characteristics & RWX_MASK) == RWX_MASK:
                cntRwxSections += 1

        
        features["ExecSections"] = cntExecSections
        features["RWXSections"] = cntRwxSections
        
        features["SectionsCnt"] = len(pe.sections)
        
        cntFuncs = 0
        cntDll = 0

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            try:
                cntDll = len(pe.DIRECTORY_ENTRY_IMPORT) #type: ignore
                for entry in pe.DIRECTORY_ENTRY_IMPORT: # type: ignore
                    cntFuncs += len(entry.imports)
            except Exception as e:
                print("Fisierul nu are import table")
                pass

        features["ImportsCnt"] = cntFuncs
        features["DllImportsCnt"] = cntDll

        if hasattr(pe, "OPTIONAL_HEADER") and pe.OPTIONAL_HEADER is not None:
            features["AddressOfEntryPoint"] = pe.OPTIONAL_HEADER.AddressOfEntryPoint #type: ignore
            features["ImageBase"] = pe.OPTIONAL_HEADER.ImageBase #type: ignore
            features["SectionAlignment"] = pe.OPTIONAL_HEADER.SectionAlignment #type: ignore
            features["FileAlignment"] = pe.OPTIONAL_HEADER.FileAlignment #type: ignore
            features["SizeOfImage"] = pe.OPTIONAL_HEADER.SizeOfImage #type: ignore
            features["SizeOfHeaders"] = pe.OPTIONAL_HEADER.SizeOfHeaders #type: ignore
            features["DllCharacteristics"] = pe.OPTIONAL_HEADER.DllCharacteristics #type: ignore    

        if hasattr(pe,"FILE_HEADER") and pe.FILE_HEADER is not None:
            features["Characteristics"] = pe.FILE_HEADER.Characteristics #type: ignore
            features["TimeDateStamp"] = pe.FILE_HEADER.TimeDateStamp #type: ignore

    

    except Exception as e:
        print(f"eroare la PEfile parsing:{e}")

    return features




