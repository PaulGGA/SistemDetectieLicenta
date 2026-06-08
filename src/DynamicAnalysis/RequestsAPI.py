import boto3
import json
import os
from datetime import datetime
import time
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

# codul de pe server ce trimite fisierul catre masina virtuala pentru TI

def uploadFilesTI(ips, domains, filename, bucketName="licenta-sandbox-paul"):

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    uploadFilePath= f"files_{filename}_{timestamp}.json"
    
    path = os.path.join(r"C:\\licenta\\reports", uploadFilePath)
    os.makedirs(os.path.dirname(path), exist_ok=True)

    dictionar = {
        "ips": ips,
        "domains": domains,
    }
    
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(dictionar,f, indent= 4)
        
        print(f"Creat fisier json local cu adrese ip si domenii: {path}")

        conn = boto3.client("s3")
        s3_key = f"TI/IpsDomain/pending/{uploadFilePath}"
        
        conn.upload_file(path, bucketName, s3_key)
        
        print("Trimis cu succes")
        
        os.remove(path)
        
        return True, uploadFilePath

    except Exception as e:
        print(f" Eroare la trimiterea catre masina TI: {e}")
        return False, None




    

def sendHashReport(hashFile, bucketName="licenta-sandbox-paul"):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    uploadFilePath= f"files_{hashFile}_{timestamp}.json"
    
    path = os.path.join(r"C:\\licenta\\reports", uploadFilePath)
    os.makedirs(os.path.dirname(path), exist_ok=True)

    dictionar = {
        "hash": hashFile
    }
    
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(dictionar,f, indent= 4)
        
        print(f"Creat fisier json local cu hash: {path}")

        conn = boto3.client("s3")
        s3_key = f"TI/hash/pending/{uploadFilePath}"
        
        conn.upload_file(path, bucketName, s3_key)
        
        print("Trimis cu succes")
        
        os.remove(path)
        
        return True, uploadFilePath

    except Exception as e:
        print(f" Eroare la trimiterea catre masina TI: {e}")
        return False, None


def downloadHashReport(uploadFilePath, bucketName="licenta-sandbox-paul", maxWait=120):
    conn = boto3.client("s3")
    key = f"TI/hash/finished/{uploadFilePath}"
    
    reportsDir = "/tmp/ti_reports"
    os.makedirs(reportsDir, exist_ok=True)
    path = os.path.join(reportsDir, uploadFilePath)
    
    
    deadline = time.time() + maxWait 
    
    while time.time() < deadline:
        try:
            response = conn.list_objects_v2(Bucket=bucketName, Prefix="TI/hash/finished")
            files = [f for f in response.get("Contents", []) if not f["Key"].endswith("/")]

            for f in files:
                if uploadFilePath in f["Key"]:
                    conn.download_file(bucketName, key, path)
                    conn.delete_object(Bucket=bucketName, Key=key)
                    return path
        except Exception as e:
            print(f"Eroare polling hash: {e}")
        
        print("Nu a fost procesat fisierul inca")
        time.sleep(15)
    
    print(f"Timeout la downloadHashReport pentru {uploadFilePath}")
    return None 
    
def downloadNetworkReport(uploadFilePath, bucketName="licenta-sandbox-paul", maxWait=120):
    conn = boto3.client("s3")
    key = f"TI/IpsDomain/finished/{uploadFilePath}"

    reportsDir = "/tmp/ti_reports"
    os.makedirs(reportsDir, exist_ok=True)
    path = os.path.join(reportsDir, uploadFilePath)

    deadline = time.time() + maxWait 
    
    while time.time() < deadline:
        try:
            response = conn.list_objects_v2(Bucket=bucketName, Prefix="TI/IpsDomain/finished")
            files = [f for f in response.get("Contents", []) if not f["Key"].endswith("/")]

            for f in files:
                if uploadFilePath in f["Key"]:
                    conn.download_file(bucketName, key, path)
                    conn.delete_object(Bucket=bucketName, Key=key)
                    return path
        except Exception as e:
            print(f"Eroare polling hash: {e}")
        
        print("Nu a fost procesat fisierul inca")
        time.sleep(15)
    
    print(f"Timeout la downloadHashReport pentru {uploadFilePath}")
    return None
    
   
        
        
    
