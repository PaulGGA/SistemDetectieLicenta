import subprocess
import os
import time

# caile hardcodate de pe sandbox

ProcMonPath = "C:\\licenta\\Tools\\sysinternalssuite\\Procmon.exe"
OutputPathPml = "C:\\licenta\\reports\\procPML.pml"
OutputPathCsv = "C:\\licenta\\reports\\procCSV.csv"


def startProcMon():

    os.makedirs(os.path.dirname(OutputPathPml), exist_ok= True)

    if os.path.exists(OutputPathPml):
        try:
            os.remove(OutputPathPml)
        except:
            pass
    try:
        subprocess.Popen(
            args= [ProcMonPath,
                   "/BackingFile", OutputPathPml,
                   "/Quiet", "/Minimized"
                   ]
        )

        time.sleep(5)
        print("Pornit cu succes")
        return True
    
    except Exception as e:
        print(f"Eroare la pornirea ProcMon: {e}")
        return False

def stopProcmon():


    try:
        subprocess.run([ProcMonPath, "/Terminate"], check= True)

        time.sleep(5)
        
        if not os.path.exists(OutputPathPml):
            print("Nu a fost creat fisierul de output")
            return None
        
        subprocess.run(
            args= [ProcMonPath, 
                "/OpenLog", OutputPathPml,
                "/SaveAs", OutputPathCsv,
                ]
        )
        
        
        if os.path.exists(OutputPathCsv):
            print("Fisierul CSV creat cu succes")
            return OutputPathCsv
        else:
            print("Eroare la creearea fisierului CSV")
            return None
    except Exception as e:
        print(f"Eroare la oprirea Procmon : {e}")
        return None

