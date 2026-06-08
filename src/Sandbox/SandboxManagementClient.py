import boto3
import os
from botocore.exceptions import ClientError
import pyzipper
import time
from ConfigData import REPORTS_TEMP_DIR


# script-ul pe partea clientului


password = b'infected'

Bucket = "licenta-sandbox-paul"
conn = boto3.client("s3")

currentDir = os.path.dirname(os.path.abspath(__file__))
root = os.path.abspath(os.path.join(currentDir, '..', '..'))
reportsDir = REPORTS_TEMP_DIR
os.makedirs(reportsDir, exist_ok=True)
localPath = os.path.join(reportsDir, "reports.zip")



def zipFile(file):
    try:
        with pyzipper.AESZipFile(file[:-4] + ".zip",
                                'w',
                                compression = pyzipper.ZIP_LZMA,
                                encryption = pyzipper.WZ_AES) as zf:
            zf.setpassword(password)
            zf.write(file,arcname= os.path.basename(file))
    except:
        print("Eroare")


def unzipReports(filename):
    path = None
    for root_dir, _, files in os.walk(reportsDir):
        for file in files:
            if filename in file and file.endswith(".zip"):
                path = os.path.join(root_dir, file)
                break
        break

    if path is None:
        print(f"Nu am gasit zip pentru: {filename} in {reportsDir}")
        return
    
    os.makedirs(reportsDir, exist_ok=True)
    try:
        with pyzipper.AESZipFile(path) as f:
            f.extractall(reportsDir)
        os.remove(path)
    except Exception as e:
        print(f"Eroare la dezarhivarea rapoartelor: {e}")


            