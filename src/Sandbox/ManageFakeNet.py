import subprocess
import os

# caile hardcodate de pe Sandbox

FakeNetExe = "C:\\licenta\\Tools\\fakenet\\fakenet.exe"
FakeNetDir = "C:\\licenta\\Tools\\fakenet"
LogFilePath = "C:\\licenta\\reports\\fakenetLog.txt"

def startFakeNet():
    logFile = None
    try:
        os.makedirs(os.path.dirname(LogFilePath), exist_ok=True)

        logFile = open(LogFilePath,"w")

        fakenet = subprocess.Popen(args = FakeNetExe, cwd = FakeNetDir, creationflags= subprocess.CREATE_NO_WINDOW, stdout= logFile, stderr= subprocess.STDOUT)

        print("FakeNet pornit cu succes")
        return fakenet, logFile
    except Exception as e:
        print(f"Eroare la pornirea Fake Net : {e}")
        if logFile:
            logFile.close()
        return None, None

def stopFakeNet(net, file):
    try:
        if net:
            print("Oprim fake net")
            net.terminate()
            net.wait()
            subprocess.run("taskkill /f /im fakenet.exe", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if file:
            print("Inchidem fisierul de log")
            file.close()
    except Exception as e:
        print(f"Eroare la inchiderea fake net si a fisierului: {e}")


    
