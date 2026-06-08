import os
import shutil

from src.Utils.Database import db

key = 167

curentDir = os.path.dirname(os.path.abspath(__file__))

rootDir = os.path.abspath(os.path.join(curentDir, '..', '..'))

quarantyneDir = os.path.join(rootDir,"izolare")

os.makedirs(quarantyneDir, exist_ok= True)

def neuterFile(filepath):
    try:
        with open(filepath, "rb") as f:
            fileData = bytearray(f.read())
        
        for i in range(len(fileData)):
            fileData[i] = fileData[i] ^ key

        with open(filepath, "wb") as f:
            f.write(fileData)

        return True

    except Exception as e:
        print(f"Eroare la criptatea fisierului pt carantina: {e}")
        return False

def quarantineFile(filepath, fileHash, verdict):
    
    if not os.path.exists(filepath):
        print(f"Calea catre fisierul original e corupta : {filepath}")
        return False
    
    try:
        okFlag = neuterFile(filepath)

        if okFlag == False:
            raise Exception("Neutralizarea a esuat")
        hashFilename = f"{fileHash}.quar"

        quarantinePath = os.path.join(quarantyneDir, hashFilename)

        shutil.move(filepath, quarantinePath)

        db.addQuarantine(filepath,quarantinePath,fileHash, verdict)
        
        return True
    except Exception as e:
        print(f"Eroare la mutarea fisierului in carantina: {e}")
        return False

def restoreFile(fileHash, filePath, quarPath):
    if not os.path.exists(quarPath):
        print(f"Calea catre fisierul din carantina e corupta : {quarPath}")
        return False
    
    try:
        okFlag = neuterFile(quarPath)

        if okFlag == False:
            raise Exception("restaurarea a esuat")        

        shutil.move(quarPath,filePath)

        db.deleteQuarantine(fileHash)
        
        return True
    except Exception as e:
        print(f"Eroare la mutarea fisierului din carantina: {e}")
        return False

