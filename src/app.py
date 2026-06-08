import os 
import json
import time
import uuid
import shutil
os.add_dll_directory("C:\\Windows\\System32")


try:
    import importlib.util
    torch_spec = importlib.util.find_spec("torch")
    if torch_spec and torch_spec.origin:
        torch_lib = os.path.join(os.path.dirname(torch_spec.origin), "lib")
        if os.path.exists(torch_lib):
            os.add_dll_directory(torch_lib)
except Exception:
    pass

import sys

import asyncio
import time
import concurrent.futures
import requests
import pyzipper
import traceback
import uuid

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

import Utils.VerificareFormat as vf
import ML.FeaturesExtraction as fe
import ML.ModelTraining as MT
import config.scanYara as yar
import Utils.DigitalCertificate as DC
import Sandbox.SandboxManagementClient as SC
import DynamicAnalysis.ReportsProcessing as RP
import Core.GroupFunctions as GF
import Core.DecisionLogic as DL
import Core.QuarantineManager as QM
from Utils.Database import db
from PyQt6.QtWidgets import (QApplication, QMainWindow, QPushButton, QLabel, 
                             QVBoxLayout, QHBoxLayout, QWidget, QFileDialog, QTextEdit,
                             QScrollArea, QFrame, QComboBox, QStackedWidget)
from PyQt6.QtCore import  QThread, pyqtSignal, Qt
from ConfigData import REPORTS_TEMP_DIR, ipServer

urlServer = ipServer
password = b'infected'
benignTresholdStatic = 35
susTresholdStatic = 50
malwareTresholdStatic = 70

def checkHashServer(hashFile):
    #hash Request
    try:
        response = requests.post(
            f"{urlServer}/check_hash",
            json={'hash': hashFile},
            timeout=180
        )
        if response.status_code == 200:
            return response.json()
        return None
    except Exception as e:
        print(f"Eroare check_hash: {e}")
        return None
 
 
def trimiteFlask(filePath):
    #sandbox Request

    zipPath = filePath[:-4] + ".zip"
    try:
        with pyzipper.AESZipFile(zipPath, 'w',
                                 compression=pyzipper.ZIP_DEFLATED,
                                 encryption=pyzipper.WZ_AES) as zf:
            zf.setpassword(password)
            zf.write(filePath, arcname=os.path.basename(filePath))
 
        with open(zipPath, 'rb') as f:
            response = requests.post(
                f"{urlServer}/analyze",
                files={'file': (os.path.basename(zipPath), f)},
                timeout=1000
            )
        return response
    except Exception as e:
        print(f"Eroare trimiteFlask: {e}")
        return None
    finally:
        if os.path.exists(zipPath):
            os.remove(zipPath)

def checkAlreadyScanned(hash):
    return db.getReportByHash(hash)


def earlyDecisionFunc(hashFile, filePath, rezSignal):
    hashTIRez = checkHashServer(hashFile)
    earlyDecision = DL.earlyHashDecision(RP.processHashTI(hashTIRez))
    if earlyDecision:
        db.saveReport(filePath, earlyDecision, 0, hashFile, "Hash TI", "static")
        rezSignal.emit({"Verdict": earlyDecision, "Score": 0, "Motives": ["Hash TI"]})
        return True
    return False


class WorkerThread(QThread):
    
    logSignal = pyqtSignal(str)
    endSignal = pyqtSignal()
    rezSignal = pyqtSignal(dict)
    savedSignal = pyqtSignal()


    def __init__(self, path, scanMode="static"):
        super().__init__()
        self.normalFilePath = path
        self.scanMode = scanMode
        self.uniqueFilePath = os.path.join(os.path.dirname(self.normalFilePath), str(uuid.uuid4()) + ".exe")
        shutil.copy(self.normalFilePath, self.uniqueFilePath)
   

    
    def run(self):
        if self.scanMode =="static":
            self.runStaticScan()
        else:
            self.runFullScan()

    def runStaticScan(self):
        try:
            self.logSignal.emit("Static Analysis Mode")
            
            self.logSignal.emit("Extracting static informations")
                

            self.logSignal.emit("Checking hash on Threat Intelligence")
            hashFile, featuresML, featuresYara, featuresCertificat = GF.getFeatures(self.normalFilePath)

            rezCheck = checkAlreadyScanned(hashFile)

            if rezCheck:
                self.logSignal.emit(f"File already scanned in {rezCheck[6]}")
                self.rezSignal.emit({"Verdict": rezCheck[2], "Score": rezCheck[3], "Motives": []})
                self.logSignal.emit("Finished")
                return

            if earlyDecisionFunc(hashFile, self.normalFilePath, self.rezSignal):
                return
            
            self.logSignal.emit(f"Getting the YARA + Certificate scores")

            ptsYara, listYara = DL.scorYara(featuresYara)
            
            ptsCert, rapCert = DL.scorCertificat(featuresCertificat)
            
            self.logSignal.emit(f"Using the static feature AI")
            verdictML, probML, mlExplanation = GF.staticML(featuresML)

            score, behaviourReport = DL.staticPointsDecision(ptsYara, ptsCert, verdictML, probML, listYara,rapCert,mlExplanation)


            if score > malwareTresholdStatic:
                verdict = "Malware"
            elif score > susTresholdStatic:
                verdict = "Suspicious"
            else:
                verdict = "Benign"
                
            motives = listYara or []
            detailsJson = json.dumps(behaviourReport, ensure_ascii=False)
            db.saveReport(self.normalFilePath, verdict, score, hashFile, detailsJson, "static")
            


            self.rezSignal.emit({"Verdict": verdict, "Score": score, "Motives": motives, "MLExplanation": mlExplanation})
            self.logSignal.emit("Finished")
            

            self.savedSignal.emit()

        except Exception as e:
            traceback.print_exc()
            print(e)    
            print("\nFATAL ERROR ! STOPPING THE SCAN")
            print("--------------------------------------\n")
            
            self.logSignal.emit(f"Error : {str(e)}, check terminal")
            self.rezSignal.emit({"Verdict": "Error", "Score": 0, "Motives": []})
        finally:
            os.remove(self.uniqueFilePath)
            self.endSignal.emit()


    def runFullScan(self):
        try:

            
            self.logSignal.emit(f"Analysis of file : {self.normalFilePath} started")


            hashFile, featuresML, featuresYara, featuresCertificat = GF.getFeatures(self.normalFilePath)
            
            rezCheck = checkAlreadyScanned(hashFile)

            if rezCheck:
                if rezCheck[6] == "full":
                    self.logSignal.emit(f"File already scanned with {rezCheck[6]} mode")
                    self.rezSignal.emit({"Verdict": rezCheck[2], "Score": rezCheck[3], "Motives": [], "MLExplanations": rezCheck[6]})
                    self.logSignal.emit("Finished")
                    return
                     


            with concurrent.futures.ThreadPoolExecutor() as sandboxThread:
                
                startAWS = sandboxThread.submit(trimiteFlask,self.uniqueFilePath)


                self.logSignal.emit("Extracting static informations")
                

                self.logSignal.emit("Checking hash on Threat Intelligence")
                hashTIRez =checkHashServer(hashFile)

                earlyDecision = DL.earlyHashDecision(RP.processHashTI(hashTIRez))



                if earlyDecision != None:
                    self.rezSignal.emit({
                    "Verdict": earlyDecision,
                    "Score": 0,
                    "Motives": ["Hash TI"]
    })
                    return
                ptsYara, listYara = DL.scorYara(featuresYara)

   
                
                ptsCert, rapCert = DL.scorCertificat(featuresCertificat)

  
            

                self.logSignal.emit(f"Using the static feature AI")
                verdictMLStatic, probMLStatic, mlExplanation = GF.staticML(featuresML)


                self.logSignal.emit("Waiting for AWS Sandbox reports")
                response = startAWS.result()    
        
            if response is None:
                raise Exception("Flask server error")

            if response.status_code != 200:
                raise Exception(f"Server error: {response.status_code}")

            self.logSignal.emit("Sandbox Succesfull")
            
            reportsZipPath = os.path.join(
                REPORTS_TEMP_DIR,
                f"{os.path.basename(self.uniqueFilePath)[:-4]}_reports.zip"
            )
            with open(reportsZipPath, 'wb') as f:
                f.write(response.content)

            self.logSignal.emit(f"Processing the reports")
            SC.unzipReports(os.path.basename(self.uniqueFilePath)[:-4])

            rezReports, dataTI = RP.funcProcess(self.uniqueFilePath, urlServer)


            if rezReports is None:
                score, behaviourReport = DL.staticPointsDecision(ptsYara, ptsCert, verdictMLStatic, probMLStatic, listYara,rapCert,mlExplanation,True)
                

                if score > malwareTresholdStatic - 15:
                    verdict = "Malware"
                elif score > susTresholdStatic - 10:
                    verdict = "Suspicious"
                else:
                    verdict = "Benign"
                
                motives = listYara or []

                detailsJson = json.dumps(behaviourReport, ensure_ascii=False)
                db.saveReport(self.normalFilePath, verdict, score, hashFile, detailsJson, "full")

                self.logSignal.emit("File couldn't execute in Sandbox, resorting to STATIC ANALYSIS")
                self.rezSignal.emit({"Verdict": verdict, "Score": score, "Motives": motives, "MLExplanation": mlExplanation})
                self.logSignal.emit("Finished")
                return



            rez, mitre, scor, behavioralDetails = DL.mainDecision(ptsYara,listYara,ptsCert,rapCert,verdictMLStatic,probMLStatic,rezReports, dataTI, hashFile, mlExplanation)



            detailsJson = json.dumps(behavioralDetails, ensure_ascii=False)
            db.saveReport(self.normalFilePath, rez, scor, hashFile, detailsJson, "full")

            raportFinal = {
                "Verdict":rez,
                "Score":scor,
                "Motives": mitre,
                "MLExplanation": mlExplanation
            }

            self.savedSignal.emit()
            self.rezSignal.emit(raportFinal)
            self.logSignal.emit("Finished")

            
        except Exception as e:
            traceback.print_exc()
            print("\n--- EROARE FATALA IN WORKER THREAD ---")
            print("--------------------------------------\n")
            
            self.logSignal.emit(f"Error : {str(e)}, check terminal")
            self.rezSignal.emit({"Verdict": "Error", "Score": 0, "Motives": {}})
        finally:
            os.remove(self.uniqueFilePath)
            self.endSignal.emit()



    



class MainWindowApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.filePath =  None
        self.fileHash = None
        self.verdict = "Benign"

        rezCntReports = self.getCntReportsApp()


        if rezCntReports is None:
            self.cntReports = 0
        else:
            self.cntReports = rezCntReports[0]

        rezCntQuarantine = self.getCntQuarantineApp()
        if rezCntQuarantine is None:
            self.cntQuarantines = 0
        else:
            self.cntQuarantines = rezCntQuarantine[0]

        self.setWindowTitle("Antivirus Main Page")
        self.resize(600, 450)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        layout = QHBoxLayout(central_widget)
        layout.setContentsMargins(0, 0, 0, 0) 
        layout.setSpacing(0)

        self.centralStack = QStackedWidget()


        self.centralPart = QWidget()
        centralLayout = QVBoxLayout(self.centralPart)
        centralLayout.setContentsMargins(10, 10, 10, 10)

        

        self.fileSelectButon = QPushButton("Select File for Analysis" )
        self.fileSelectButon.clicked.connect(self.selectFile)
        centralLayout.addWidget(self.fileSelectButon)
        

        self.scanButon = QPushButton("Scan File")
        self.scanButon.setStyleSheet("""
            background-color:transparent;
            border: 1px grey;
            color: rgba(128, 128, 128, 100);                 
                                     """)
        self.scanButon.clicked.connect(self.startScanFile)
        self.scanButon.setEnabled(False)
        centralLayout.addWidget(self.scanButon)

        self.resultText = QLabel("")
        self.resultText.setAlignment(Qt.AlignmentFlag.AlignCenter)
        centralLayout.addWidget(self.resultText)

        self.quarButton = QPushButton("Quarantine")
        self.quarButton.setStyleSheet("""
            background-color:red;
            border: 2px black;
            color: black;
""") 
        self.quarButton.clicked.connect(self.quarFile)
        self.quarButton.setVisible(False)
        centralLayout.addWidget(self.quarButton)
        

        self.logsText = QTextEdit()
        self.logsText.setReadOnly(True)
        self.logsText.setStyleSheet("background-color: #1e1e1e; color: #00FF00; font-family: Consolas;")
        self.logsText.append("Initialized, awaiting files")
        centralLayout.addWidget(self.logsText)


        bottomButtonsLayout = QHBoxLayout()
        bottomButtonsLayout.setSpacing(10) 
        self.showQuarantineButton = QPushButton("<- Quarantine")
        self.showQuarantineButton.setStyleSheet("background-color: #2d2d2d; color: white; padding: 5px;")
        self.showQuarantineButton.clicked.connect(self.toggleQuarantine)
        
        self.showReportsButton = QPushButton("Reports ->")
        self.showReportsButton.setStyleSheet("background-color: #2d2d2d; color: white; padding: 5px;")
        self.showReportsButton.clicked.connect(self.toggleReports)

        bottomButtonsLayout.addWidget(self.showQuarantineButton)
        bottomButtonsLayout.addWidget(self.showReportsButton)

        centralLayout.addLayout(bottomButtonsLayout)

        self.centralStack.addWidget(self.centralPart)    

        self.scanModeCombo = QComboBox()
        self.scanModeCombo.addItems(["Static Only (Fast)", "Full Scan (Static + Sandbox)" ])
        centralLayout.addWidget(self.scanModeCombo)


        self.reportDetailsPart = QWidget()
        detailsLayout = QVBoxLayout(self.reportDetailsPart)
        detailsLayout.setContentsMargins(10, 10, 10, 10)

        self.backToScannerButton = QPushButton("⬅ Back to Scan")
        self.backToScannerButton.setStyleSheet("background-color: #333; color: white; padding: 8px; border-radius: 4px;")
        self.backToScannerButton.clicked.connect(self.showScannerView)
        detailsLayout.addWidget(self.backToScannerButton)

        self.detailedReportText = QTextEdit()
        self.detailedReportText.setReadOnly(True)
        self.detailedReportText.setStyleSheet("background-color: #1e1e1e; color: #ffffff; font-size: 14px; border: none; padding: 10px;")
        detailsLayout.addWidget(self.detailedReportText)

        self.centralStack.addWidget(self.reportDetailsPart)

        layout.addWidget(self.centralStack)

        self.rightPart = QWidget()
        self.rightPart.setFixedWidth(300)
        self.rightPart.setStyleSheet("background-color: #252526; border-left: 2px solid #3c3c3c;")
        self.rightPart.setVisible(False)

     

        rightLayout = QVBoxLayout(self.rightPart)

        reportsTitle = QLabel("REPORTS")

        reportsTitle.setStyleSheet("color: white; font-size: 14px; font-weight: bold; border: none;")
        reportsTitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        rightLayout.addWidget(reportsTitle)

        self.reportsList = QScrollArea()
        self.reportsList.setWidgetResizable(True)
        self.reportsList.setStyleSheet("QScrollArea { border: none; background-color: #1e1e1e; }")

        self.reportsContainer = QWidget()
        self.reportsContainer.setStyleSheet("background-color: #1e1e1e;")
        self.reportsListLayout = QVBoxLayout(self.reportsContainer)
        self.reportsListLayout.setAlignment(Qt.AlignmentFlag.AlignTop)

        self.reportsList.setWidget(self.reportsContainer)
        rightLayout.addWidget(self.reportsList)

        self.indexPageReports = 0

        navPageReports = QHBoxLayout()

        self.previousPageReports = QPushButton("⬅")
        self.previousPageReports.setStyleSheet("background-color: #333; color: white; border: 1px solid #555;")
        self.previousPageReports.clicked.connect(self.goPreviousPageReports)



        self.nextPageReports = QPushButton("➡")
        self.nextPageReports.setStyleSheet("background-color: #333; color: white; border: 1px solid #555;")
        self.nextPageReports.clicked.connect(self.goNextPageReports)


        navPageReports.addWidget(self.previousPageReports)
        navPageReports.addWidget(self.nextPageReports)
        rightLayout.addLayout(navPageReports)


        layout.addWidget(self.rightPart)


        self.leftPart = QWidget()
        self.leftPart.setFixedWidth(300)
        self.leftPart.setStyleSheet("background-color: #252526; border-left: 2px solid #3c3c3c;")
        self.leftPart.setVisible(False)

        leftLayout = QVBoxLayout(self.leftPart)

        quarantineTitle = QLabel("Quarantined Files")

        quarantineTitle.setStyleSheet("color: white; font-size: 14px; font-weight: bold; border: none;")
        quarantineTitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        leftLayout.addWidget(quarantineTitle)

        self.quarantinesList = QScrollArea()
        self.quarantinesList.setWidgetResizable(True)
        self.quarantinesList.setStyleSheet("QScrollArea { border: none; background-color: #1e1e1e; }")

        self.quarContainer = QWidget()
        self.quarContainer.setStyleSheet("background-color: #1e1e1e;")
        self.quarantineListLayout = QVBoxLayout(self.quarContainer)
        self.quarantineListLayout.setAlignment(Qt.AlignmentFlag.AlignTop)

        self.quarantinesList.setWidget(self.quarContainer)

        leftLayout.addWidget(self.quarantinesList)

        self.indexPageQuarantine = 0

        navPageQuarantine = QHBoxLayout()

        self.previousPageQuarantine = QPushButton("⬅")
        self.previousPageQuarantine.setStyleSheet("background-color: #333; color: white; border: 1px solid #555;")
        self.previousPageQuarantine.clicked.connect(self.goPreviousPageQuarantines)



        self.nextPageQuarantine = QPushButton("➡")
        self.nextPageQuarantine.setStyleSheet("background-color: #333; color: white; border: 1px solid #555;")
        self.nextPageQuarantine.clicked.connect(self.goNextPageQuarantines)


        navPageQuarantine.addWidget(self.previousPageQuarantine)
        navPageQuarantine.addWidget(self.nextPageQuarantine)
        leftLayout.addLayout(navPageQuarantine)


        layout.insertWidget(0, self.leftPart)

    
    def quarFile(self):
        QM.quarantineFile(self.filePath,self.fileHash, self.verdict)
        self.quarButton.setVisible(False)


    def goPreviousPageReports(self):
        if self.indexPageReports >= 1:
            self.indexPageReports -= 1
            self.showReportPage(self.indexPageReports)

    def goNextPageReports(self):
        self.indexPageReports += 1
        self.showReportPage(self.indexPageReports)

    def goPreviousPageQuarantines(self):
        if self.indexPageQuarantine >= 1:
            self.indexPageQuarantine -= 1
            self.showQuarantinePage(self.indexPageQuarantine)

    def goNextPageQuarantines(self):
        self.indexPageQuarantine += 1
        self.showQuarantinePage(self.indexPageQuarantine)

    def clearReports(self):
        while self.reportsListLayout.count():
            item = self.reportsListLayout.takeAt(0)
            if item is not None:
                widget = item.widget()
                if widget is not None:
                    widget.deleteLater()

    def showReportPage(self, index):
        try:

            if index ==0:
                self.previousPageReports.setVisible(False)
            else:
                self.previousPageReports.setVisible(True)
            if index * 10 >= self.cntReports or self.cntReports <=10:
                self.nextPageReports.setVisible(False)
            else:
                self.nextPageReports.setVisible(True)
            reports = db.getReports(self.indexPageReports)
           
            self.clearReports()

            pageLabel = QLabel(f"--- PAGE {index + 1} ---")
            pageLabel.setStyleSheet("color: #cccccc; font-weight: bold;")
            pageLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.reportsListLayout.addWidget(pageLabel)

            if not reports:
                emptyLabel = QLabel("No scan history")
                emptyLabel.setStyleSheet("color: #cccccc;")
                self.reportsListLayout.addWidget(emptyLabel)
                self.previousPageReports.setVisible(False)
                self.nextPageReports.setVisible(False)
                return

            for rep in reports:
                filepath = os.path.basename(rep[0]) 
                scan_date = rep[1].split('.')[0]    
                verdict = rep[2]
                scor = rep[3]
                
                if verdict == "Malware":
                    color = "#ff4444"
                elif verdict == "Suspicious":
                    color = "#ffbb33"
                else:
                    color = "#00C851"

                card = QFrame()
                card.setStyleSheet("QFrame { background-color: #2d2d2d; border-radius: 5px; margin-bottom: 5px; padding: 5px; }")
                cardLayout = QVBoxLayout(card)
                cardLayout.setContentsMargins(5, 5, 5, 5)

                numeLabel = QLabel(f"<b style='color:{color}'>[{verdict}]</b> <b>{filepath}</b>")
                numeLabel.setStyleSheet("color: white;")
                numeLabel.setWordWrap(True)
                
                detaliiLabel = QLabel(f"<span style='font-size: 10px; color: #aaaaaa;'>Scor: {scor} | Data: {scan_date}</span>")
                
                viewBtn = QPushButton("See Details")
                viewBtn.setStyleSheet("background-color: #007ACC; color: white; border: none; padding: 5px; border-radius: 3px;")
                viewBtn.setCursor(Qt.CursorShape.PointingHandCursor)
                
                viewBtn.clicked.connect(lambda checked, r=rep: self.openDetailedReport(r))

                cardLayout.addWidget(numeLabel)
                cardLayout.addWidget(detaliiLabel)
                cardLayout.addWidget(viewBtn)

                self.reportsListLayout.addWidget(card)
        except Exception as e:
            print(f"Eroare la preluarea rapoartelor in aplicatie : {e}")
        
    def openDetailedReport(self, reportData):
    
        filepath = reportData[0]
        scan_date = reportData[1].split('.')[0]
        verdict = reportData[2]
        scor = reportData[3]
        hash_file = reportData[4]
        motive_text = reportData[5]
        scanMode = reportData[6]

        color = "#00C851" if verdict == "Benign" else ("#ffbb33" if verdict == "Suspicious" else "#ff4444")

        try:
            details = json.loads(motive_text)
            behavioral_html = ""
            for section_title, lines in details:
                behavioral_html += f"<h3 style='color:#aaaaaa; margin-top:15px;'>{section_title}</h3>"
                for line in lines:
                    behavioral_html += f"<p margin:3px 0;'>{line}</p>"
        except Exception:
            behavioral_html = f"<p style='color:#ffcccc;'>{motive_text.replace(', ', '<br>• ')}</p>"


        html_raport = f"""
            <h1 style='color:{color}; text-align:center;'>Verdict: {verdict}</h1>
            <h3 style='text-align:center; color:#aaaaaa;'>Static Score: {scor}/100</h3>
            <hr style='border:1px solid #444;'>
            <p><b>File:</b> {filepath}</p>
            <p><b>Scan Date:</b> {scan_date}</p>
            <p><b>Tipe of Scan:</b> {scanMode}</p>
            <p><b>Hash SHA256:</b> <span style='font-family:monospace; font-size:11px;'>{hash_file}</span></p>
            <hr style='border:1px solid #444;'>
            {behavioral_html}
            """

        self.detailedReportText.setHtml(html_raport)
        
        self.centralStack.setCurrentIndex(1)
        
        if self.rightPart.isVisible():
            self.toggleReports()

    def showScannerView(self):
        self.centralStack.setCurrentIndex(0)



    def getCntReportsApp(self):
        try:

            return db.getCntReports()
        except Exception as e:
            print(f"Eroare la preluarea numarului de rapoarte in aplicatie : {e}")
            return None
    
    def getCntQuarantineApp(self):
        try:

            return db.getCntQuarantine()
        except Exception as e:
            print(f"Eroare la preluarea numarului de fisier in carantina in aplicatie : {e}")
            return None



    def toggleReports(self):
        if self.rightPart.isVisible() == True:
            self.rightPart.setVisible(False)
            self.showReportsButton.setText("Reports ->")
            self.resize(600, self.height())
        else:
            self.showReportPage(self.indexPageReports)
            self.rightPart.setVisible(True)
            self.showReportsButton.setText("Hide Reports")
            self.resize(900, self.height())

    def toggleQuarantine(self):
        if self.leftPart.isVisible() == True:
            self.leftPart.setVisible(False)
            self.showQuarantineButton.setText("Quarantine <-")
            self.resize(600, self.height())
        else:
            self.showQuarantinePage(self.indexPageQuarantine)
            self.leftPart.setVisible(True)
            self.showQuarantineButton.setText("Hide Quarantine")
            self.resize(900, self.height())

    
    def clearQuar(self):
        while self.quarantineListLayout.count():
            item = self.quarantineListLayout.takeAt(0)
            if item is not None:
                widget = item.widget()
                if widget is not None:
                    widget.deleteLater()

   

    def showQuarantinePage(self, index):
        try:

            if index ==0:
                self.previousPageQuarantine.setVisible(False)
            else:
                self.previousPageQuarantine.setVisible(True)
            if index * 10 >= self.cntQuarantines or self.cntQuarantines <=10:
                self.nextPageQuarantine.setVisible(False)
            else:
                self.nextPageQuarantine.setVisible(True)

            self.clearQuar()
            quarantines = db.getQuarantine(self.indexPageQuarantine)

            pageLabel = QLabel(f"--- PAGE {index + 1} ---")
            pageLabel.setStyleSheet("color: #cccccc; font-weight: bold;")
            pageLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.quarantineListLayout.addWidget(pageLabel)
            
            if not quarantines:
                emptyLabel = QLabel("No files in Quarantine")
                emptyLabel.setStyleSheet("color: #cccccc;")
                self.quarantineListLayout.addWidget(emptyLabel)
                self.previousPageQuarantine.setVisible(False)
                self.nextPageQuarantine.setVisible(False)
                return

            for quar in quarantines:
                fileHash = quar[0]
                ogFilepath = quar[1] 
                quarPath = quar[2]
                scan_date = quar[3]
                

                card = QFrame()
                card.setStyleSheet("QFrame { background-color: #2d2d2d; border-radius: 5px; margin-bottom: 5px; padding: 5px; }")
                cardLayout = QVBoxLayout(card)
                cardLayout.setContentsMargins(5, 5, 5, 5)
                
                detaliiLabel = QLabel(f"<span style='font-size: 10px; color: #aaaaaa;'>{scan_date[:16]}</span>")
                
                restoreBtn = QPushButton("Restore File")
                restoreBtn.setStyleSheet("background-color: #4CAF50; color: white; border: none; padding: 5px; border-radius: 3px;")
                restoreBtn.setCursor(Qt.CursorShape.PointingHandCursor)
                
                restoreBtn.clicked.connect(lambda checked, h=fileHash, o=ogFilepath, q=quarPath: self.restoreCarantina(h, o, q))

                cardLayout.addWidget(detaliiLabel)
                cardLayout.addWidget(restoreBtn)

                self.quarantineListLayout.addWidget(card)
                
        except Exception as e:
            print(f"Eroare carantina : {e}")

    def restoreCarantina(self, fileHash, filePath, quarPath):
        ok = QM.restoreFile(fileHash, filePath, quarPath)
        
        if ok:
            self.cntQuarantines -= 1 
            self.showQuarantinePage(self.indexPageQuarantine)
            self.logsText.append(f"SUCCES! File was restored to {filePath}")
        else:
            self.logsText.append("ERROR! File was not restored")

    def selectFile(self):

        path, _ = QFileDialog.getOpenFileName(self, "Select File for Scan" , "" ,"(*.exe *.dll);;All Files (*.*)")

        if path != "":
            
            fileSize = os.path.getsize(path) / (1024 * 1024)
            limitSize = 100

            if fileSize > limitSize:
                self.logsText.append(f"File too large, please upload up to 100 MB")
                return


            if vf.verificaFormat(path) != "PE":
                self.logsText.append("File is not in PE ( executable) format, try again")
            else:
                self.filePath = path
                self.fileSelectButon.setText(os.path.basename(path))
                self.scanButon.setEnabled(True)
                self.scanButon.setStyleSheet("""
                background-color: light-blue;
                color: white; 
                border: none; 
                font-weight: bold;
                                        """)
                self.resultText.setText("")
                self.resultText.setVisible(False)
                self.quarButton.setVisible(False)
                self.fileHash = fe.getHash(path)


    def startScanFile(self):
        self.scanButon.setText("Analyzing")
        self.scanButon.setEnabled(False)

        self.fileSelectButon.setText("Select File for Analysis")
        self.fileSelectButon.setEnabled(False)

        if self.scanModeCombo.currentIndex() == 0:
            mode = "static"
        else:
            mode = "full"

        self.workerTH = WorkerThread(self.filePath, mode)

        self.workerTH.logSignal.connect(self.addLog)
        self.workerTH.rezSignal.connect(self.afiseazaVerdict)
        self.workerTH.endSignal.connect(self.endScanFile)
        self.workerTH.savedSignal.connect(lambda: setattr(self, 'cntReports', self.cntReports + 1))


        self.workerTH.start()
    
    def endScanFile(self):
        self.scanButon.setText("Scan File")
        self.fileSelectButon.setEnabled(True)
        
    
    def addLog(self, msj):
        self.logsText.append(msj)
    
    def afiseazaVerdict(self, raport_final):
        verdict1 = raport_final["Verdict"]
        self.quarButton.setVisible(verdict1 in ("Malware", "Suspicious"))
        self.verdict = verdict1
        scor = raport_final["Score"]
        motive = raport_final["Motives"]
        
        text_verdict = f"VERDICT: {verdict1}  |  STATIC SCORE: {scor}/100"
        self.resultText.setText(text_verdict)
        
        if verdict1 == "Malware":
            self.resultText.setStyleSheet("""
                background-color: #8b0000; 
                color: white;
                font-size: 24px;
                font-weight: bold;
                border: 2px solid #ff0000;
                border-radius: 5px;
                padding: 10px;
            """)
            
        elif verdict1 == "Benign":
            self.resultText.setStyleSheet("""
                background-color: #006400; 
                color: white;
                font-size: 24px;
                font-weight: bold;
                border: 2px solid #00ff00;
                border-radius: 5px;
                padding: 10px;
            """)
            
        elif verdict1 == "Suspicious":
            self.resultText.setStyleSheet("""
                background-color: #b8860b;
                color: white;
                font-size: 24px;
                font-weight: bold;
                border: 2px solid #ffd700;
                border-radius: 5px;
                padding: 10px;
            """)

        self.logsText.append("\n" + "="*50)
        self.logsText.append(f"SCAN FINISHED, SCORE : {scor}")
        listaTactici = raport_final.get("Tactici_Detectate", [])
        if listaTactici != []:
            self.logsText.append("MITRE ATT&CK tactics found:")
        
            for tactica in listaTactici:
                self.logsText.append(f"  -> {tactica}")

        if motive != []:
            self.logsText.append("\nMotives:")
            for motiv in motive:
                self.logsText.append(f"  * {motiv}")
            
        self.logsText.append("="*50 + "\n")
        self.resultText.setVisible(True)



if __name__ == "__main__":
    app = QApplication([])

    app.setStyle("Fusion") 

    fereastra = MainWindowApp()

    fereastra.show()

    sys.exit(app.exec())