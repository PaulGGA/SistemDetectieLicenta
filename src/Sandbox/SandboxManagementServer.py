import boto3
import os
import pyzipper
import time
import ManageFakeNet as fn
import ManageProcMon as pm
import ManageTShark as ts
import RestoreNetwork as rn
import subprocess

# script-ul de pe sandbox


bucket = "licenta-sandbox-paul"
conn = boto3.client("s3")
ExtractPath = "C:\\licenta\\samples\\" 
ReportsPath = "C:\\licenta\\reports" 


def unzipFile(path):
    with pyzipper.AESZipFile(path) as f:
        try:
            f.setpassword(b'infected')

            f.extractall(ExtractPath)

            files = [os.path.join(ExtractPath, name) for name in f.namelist() if not name.endswith('/')]

            print("S-a terminat extragerea fiserului")
            os.remove(path=path)
            return files
        except Exception as e:
            print(f"Eroare la extragerea fisierului: {e}")
            return None


def getFile(files):
    print("Extragem fisierul")
    try:

        
        files.sort(key = lambda x: x["LastModified"])

        fisier = files[0]
        path = fisier['Key']
        name = path[path.rindex("/") + 1:]

        localPath = "C:\\licenta\\samples\\" + name

        conn.download_file(bucket,path,localPath)

        newPath = path.replace("pending","finished")

        
        conn.copy_object(
            Bucket = bucket,
            CopySource = {"Bucket" : bucket, 
                          "Key": path},
            Key = newPath
        )
        conn.delete_object(Bucket = bucket, Key = path)
        

        return name, localPath

    except Exception as e:
        print(f"Eroare la descarcarea fisierului : {e}")
        return None, None


def startScanning():
    try:

        while True:
            print("Scanam pentru fisiere noi")

            response = conn.list_objects_v2(
                Bucket =  bucket,
                Prefix = 'samples/pending/'
            )

            files = [f for f in response["Contents"] if not f["Key"].endswith('/') ]

            if not files:
                print("Nu exista fisiere inca")
                time.sleep(60)
                continue
                
            print("Am gasit fisiere")
        
            name, path = getFile(files)
            if name is None:
                continue
            
            startAnalyze(path,name)
            
            

            time.sleep(5)
    except Exception as e:
        print(f"Eroare {e}")



def zipReports():
        zipFile = ReportsPath + ".zip"
        try:
             with pyzipper.AESZipFile(zipFile, "w", compression = pyzipper.ZIP_LZMA) as f:
                for root, _, files in os.walk(ReportsPath):
                    for file in files:
                        file_path = os.path.join(root, file)

                        arcname = os.path.relpath(file_path, os.path.dirname(ReportsPath))
                        
                        f.write(file_path, arcname=arcname)
                        os.remove(file_path)
        except Exception as e:
            print(f"Eroare la arhivarea rapoartelor : {e} ")

def uploadReports(name):
    try:
        conn = boto3.client("s3")

        conn.upload_file(ReportsPath + ".zip",bucket, f"reports/{name}")
        print("Rapoarte uploadate cu succes")

        os.remove(ReportsPath + ".zip")
    except Exception as e:
        print(f"Eroare la uploadarea rapoartelor : {e}")


def startFile(path):

    try:    
        print("Unzip")

        files = unzipFile(path)

        if files is None:
            return
        
        file = files[0]

        print("Start rulare fisier")
        proces = subprocess.run([file],timeout = 120, capture_output=True)
        print(f"Fisier a rulat si a returnat codul: {proces.returncode}")

        if os.path.exists(file):
            os.remove(file)
    except subprocess.TimeoutExpired:
        print("Fisier oprit fortat")
    except Exception as e:
        print(f"Eroare: {e}")
            
def startAnalyze(file, name):
    print("Pornim ProcMon")
    okPM = pm.startProcMon()

    print("Pornim TShark")
    shark1, shark2 = ts.startShark(stopDuration= 30)

    print("Pornim FakeNet")
    net, fileFakeNet = fn.startFakeNet()

    if okPM and shark1 and shark2 and net and file:
        print("Sistemul de monitorizare a pornit cu succes")
    else:
        print("Eroare la pornirea sistemului de monitorizare")
        return None
    

    startFile(file)
    
    
    print("Oprim monitorizarea")
    
    print("Oprim procmon")
    outputPM = pm.stopProcmon()
    
    print("Oprim TSHARK")
    ts.stopShark(shark1,shark2)
    
    print("Oprim FakeNet")
    
    fn.stopFakeNet(net,file)
    
    print("Resetam Interfata Ethernet2")
    
    rn.restoreNetwork()
    
    os.remove("C:\\licenta\\reports\\procPML.pml")
    
    zipReports()
    
    uploadReports(name)
    
    os.remove("C:\\licenta\\reports.zip")



if __name__ == "__main__":
    startScanning()