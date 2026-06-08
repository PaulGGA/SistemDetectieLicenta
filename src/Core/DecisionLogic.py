
"""
Explicatie praguri

Pragurile de benign/suspicios/malitios difera in functie de mai multi factori precum:
tipul scanarii, alte operatiuni suspicioase si daca executabilul a rulat in sandbox


Pentru analiza completa, orice scor mai mare de 80 inseamna malware, iar mai mare ca 70 suspicios
In plus, mai sunt folosite pragurile de 30 si 50 pentru verdictul malware, in combinatie cu actiuni nelegitime detectate

Pentru scanarea statica sau lipsa activitatii in mediul izolat, sunt folosite praguri mai mici

"""



import re


def staticExplanations(listYara, rapCert, mlExplanation, probML, verdictML, staticDetails, sections):
    
    if rapCert:
        if "Trusted" in rapCert and "Valid" in rapCert:
            staticDetails.append("The file is digitally signed by a trusted publisher with a valid certificate.")
        elif "Trusted" in rapCert and "Expirat" in rapCert:
            staticDetails.append("The file is signed by a known publisher, but the digital certificate has expired.")
        elif "SelfSigned" in rapCert:
            staticDetails.append("The file has a self-signed digital certificate (T1553.002). This offers no real guarantees of authenticity.")
        elif "Modified" in rapCert:
            staticDetails.append("The digital signature was altered after signing (T1553.002) — the file was likely maliciously modified.")
        elif "NotSigned" in rapCert or "NoSignature" in rapCert:
            staticDetails.append("The file has no digital signature. Origin cannot be verified.")

        if "sha1" in rapCert or "md5" in rapCert:
            staticDetails.append("The certificate uses a deprecated and insecure signing algorithm (SHA-1/MD5).")

    if listYara:

        if "APIAntiDebugVMDetection" in listYara:
            staticDetails.append("Detection of analysis environment detected (T1497) — code contains instructions to bypass debuggers or VMs.")
        if "APIKeys" in listYara:
            staticDetails.append("Keyboard interception capability detected (T1056.001) — potential keylogging activity.")
        if "APIExfiltration" in listYara:
            staticDetails.append("Data exfiltration code detected (TA0010) — potential unauthorized transfer of information.")
        if "APIHooking" in listYara:
            staticDetails.append("Function hooking techniques detected (T1055) — used to intercept system calls and modify process behavior.")
        if "APICrypt" in listYara:
            staticDetails.append("Cryptographic capabilities present — can be used for data encryption (T1486 - Ransomware).")
        if "APIDownloads" in listYara:
            staticDetails.append("Ingress tool transfer capability (T1105) — code for downloading malicious content from the internet.")
        if "APIComunicate" in listYara:
            staticDetails.append("Application Layer Protocol detected (T1071) — file contains network communication code.")
        if "APIInstall" in listYara:
            staticDetails.append("Software installation patterns detected — may attempt to deploy additional components.")

    if staticDetails:
        sections.append(("Static Analysis", staticDetails))

    mlLines = []
    verdict_text = "MALWARE" if verdictML == 1 else "BENIGN"
    conf_pct = round(probML * 100, 1)
    
    mlLines.append(
        f"The ML model classified the file as <b>{verdict_text}</b> "
        f"with a confidence of <b>{conf_pct}%</b>."
    )
    
    mlLines.append("Key factors that influenced this decision:")
    
    if mlExplanation:
        for item in mlExplanation:
            mlLines.append(
                f"<b>{item['description']}</b> "
                f"— {item['strength']} contribution "
                f"({'towards malware' if item['direction'] == 'malware' else 'towards benign'})"
            )
    else:
        mlLines.append("ML explanation unavailable.")
        
    sections.append(("Static ML Analysis", mlLines))

    return sections


def buildStaticReport(listYara, rapCert, mlExplanation, probML, verdictML, noSandbox):
    
    sections = []
    staticDetails = []

    if noSandbox:
        staticDetails.append("""The file got sent to the sandbox and didn't run, either it got an error or it detected the virtual space.\n
                             The scan is done only using static methods.
                             """)
    

    staticExplanations(listYara, rapCert, mlExplanation, probML, verdictML, staticDetails, sections)
    
    return sections

def buildBehavioralReport(listYara, rapCert, rezReports, dataTI,
                           writeCnt, readCnt, c2Flag, dgaFlag,
                           persistenceFlag, sandboxEvasionFlag,
                           yaraEvasionFlag, logFlag, mitreTactics,
                           finalScore, staticScore, mlExplanation, probML, verdictML):
    
    sections = []

    staticDetails = []
    staticExplanations(listYara, rapCert, mlExplanation, probML, verdictML, staticDetails, sections)


    behaviorLines = []
    if writeCnt > 0:
        behaviorLines.append(f"The file wrote {writeCnt} executable files to disk (T1204.002).")
        if writeCnt > 10:
            behaviorLines.append("   -> High file creation rate suggests a Dropper or Ransomware (T1486).")
    
    if readCnt > 0:
        behaviorLines.append(f"The file accessed {readCnt} sensitive locations (T1005 - Data from Local System).")
        if readCnt > 5:
            behaviorLines.append(" Extensive access to credentials or SSH keys suggests Infostealer behavior (TA0009).")
    
    if persistenceFlag:
        behaviorLines.append("Boot or Logon Autostart Execution detected (T1547.001) — modified registry to ensure persistence.")
    
    if sandboxEvasionFlag:
        behaviorLines.append("Impair Defenses detected (T1562.001) — file attempted to disable Windows Defender or Firewall.")
    
    if mitreTactics.get("Process Injection -> T1055", 0) > 0:
        behaviorLines.append("Process Injection detected (T1055) — code was injected into other active processes to hide execution.")
    
    if mitreTactics.get("Command and Scripting Interpreter ->T1059", 0) > 0:
        behaviorLines.append("Command and Scripting Interpreter detected (T1059) — execution of hidden scripts via PowerShell/CMD.")
    
    if mitreTactics.get("Create or Modify System Process: Windows Service -> T1543.003", 0) > 0:
        behaviorLines.append("Create or Modify System Process (T1543.003) — advanced persistence via Windows Services.")
    
    if mitreTactics.get("IEFO -> T1546", 0) > 0:
        behaviorLines.append("Event Triggered Execution detected (T1546) — hijacked execution options for legitimate programs.")
    if mitreTactics.get( "Non-Standard Port -> T1571", 0) > 0:
        behaviorLines.append("Non-Standard Port detected (T1571) — used an atypical network port to bypass filtering and hide command and control traffic.")    
    if behaviorLines:
        sections.append(("Execution Behavior", behaviorLines))

    networkLines = []
    if c2Flag:
        networkLines.append("Command and Control communication detected (T1071) — connection to malicious external servers.")
    if dgaFlag:
        networkLines.append("Dynamic Resolution via DGA detected (T1568.002) — algorithmically generated domains to avoid blocklists.")
    malicious_http = rezReports.get("maliciousHttp", [])
    if malicious_http:
        networkLines.append(f"{len(malicious_http)} suspicious HTTP requests detected:")
        for req in malicious_http[:3]:
            networkLines.append(f"   -> {req.get('method','?')} {req.get('host','?')}{req.get('uri','')}")
            
    sure_domains = rezReports.get("sureDomains", [])
    if sure_domains:
        networkLines.append(f"Confirmed contacted domains ({len(sure_domains)}): {', '.join(sure_domains[:5])}")
        
    malicious_ips = [ip for ip in dataTI.get("ips", {}) if dataTI["ips"][ip].get("votesScor", 0) > 0.25]
    if malicious_ips:
        networkLines.append(f"Malicious IPs contacted: {', '.join(malicious_ips[:5])}")
        for ip in malicious_ips[:3]:
            owner = dataTI["ips"][ip].get("owner", ["","","","Unknown"])[3]
            country = dataTI["ips"][ip].get("owner", ["","","Unknown",""])[2]
            networkLines.append(f"   -> {ip} ({country}, {owner})")
            
    if networkLines:
        sections.append(("Network Activity", networkLines))

    conclusionLines = []
    conclusionLines.append(f"The final static score is {finalScore}/100, based on: ")
    conclusionLines.append(f"  * ML static analysis + heuristics: {staticScore}/100")
    conclusionLines.append(f"Dynamic analysis came back with these results: ")
    conclusionLines.append(f"  * Detected behavioral techniques: {sum(1 for v in mitreTactics.values() if v > 0)}")
    conclusionLines.append(f"  * Malicious network indicators: {'Yes' if c2Flag else 'No'}")
    
    sections.append(("Score Summary", conclusionLines))
    
    return sections    
    
scoresYara = {
    "APIInstall": 5,
    "APIKeys": 20,
    "APIDownloads":10,
    "APIComunicate":5,
    "APIExfiltration":20,
    "APIHooking": 25,
    "APIAntiDebugVMDetection":35,
    "APICrypt":15,
}



def scorYara(yaraFeatures):
    listYara = []
    listYara = [k for k in yaraFeatures if yaraFeatures[k]==1]

    if listYara == []:
        return 0, None
    else:
        scoreList = [scoresYara[k] for k in listYara]
        return sum(scoreList), listYara



def scorCertificat(certifFeatures):

    scor = 0

    raport = []

    if certifFeatures["IsSigned"] == 1:
        raport.append("Semnat")
        
        if certifFeatures["IsSelfSigned"] == 1:
            scor += 20
            raport.append("SelfSigned")
            
        if certifFeatures["Algorithm"] in ["sha1", "md5"]:
            scor += 5
            raport.append("Algoritm_Slab")

        if certifFeatures["ExpiredAtSigning"] == 1:
            scor += 25
            raport.append("Semnat_Dupa_Expirare")
            
        if certifFeatures["ValidCnt"] > 3650:
            scor += 5
            raport.append("Valabilitate_Anormala")

    status_id = certifFeatures.get("StatusId")

    if status_id == 1:
        if certifFeatures["TrustedIssuer"] == 1:
            raport.append("Trusted")
            if certifFeatures["Expired"] == 0:
                scor -= 50 
                raport.append("Valid")
            else:
                scor -= 15 
                raport.append("Expirat")

    elif status_id == 6:
       
        scor += 10
        raport.append("Untrusted_Root")

    elif status_id in [8, 10]:
        scor += 40
        raport.append("Modified")

    elif status_id == 2:
        scor += 10
        raport.append("NoSignature")
    else:
        scor += 5
        raport.append(f"Error_{status_id}")

   
    return scor, raport


def staticPointsDecision(ptsYara, ptsCert, verdictMLStatic, probMLStatic, listYara = None, rapCert = None, mlExplanation = None, noSandbox = False):
    if verdictMLStatic ==0:
        probMLStatic *= -1

    
    rawScore =  probMLStatic * 50 + ptsCert + ptsYara/4.0

    scaledScor = (rawScore + 100 ) /2.24

    behavioral_details = None

    behavioral_details = buildStaticReport(listYara, rapCert, mlExplanation, probMLStatic, verdictMLStatic, noSandbox)

    return max(0, min(100, round(scaledScor))), behavioral_details




def mainDecision(ptsYara, listYara,ptsCert, rapCert, verdictMLStatic, probMLStatic,  rezReports, dataTI, hashFile, mlExplanation):

    staticScore = staticPointsDecision(ptsYara,ptsCert,verdictMLStatic,probMLStatic)[0]

    evasionFlag = False
    persistenceFlag = False
    c2Flag = False
    logFlag = False
    writeCnt = 0
    readCnt = 0
    dgaFlag = False
    
    mitreTactics = {
        "Sandbox Evasion -> T1497": 0,
        "Subvert Trust Controls -> T1553.002": 0,
        "Registry Run Keys / Startup Folder -> T1547.001": 0,
        "Malicious File Dropper -> T1204.002": 0,
        "Data from Local System -> T1005": 0,
        "Keyloging -> T1056.001": 0,
        "Web Protocols -> T1071.001": 0,
        "Command and Scripting Interpreter ->T1059": 0,
        "Create or Modify System Process: Windows Service - > T1543.003": 0,
        "Process Injection -> T1055": 0,
        "Impair Defenses: Disable or Modify Tools -> T1562.001": 0,
        "Dynamic Resolution: Domain Generation Algorithms -> T1568.002": 0,
        "Data Encrypted for Impact > T1486":0,
        "IEFO -> T1546":0,
        "Non-Standard Port -> T1571": 0,
    }

    regPersistence = [r"currentversion\\run", r"winlogon\\userinit", r"winlogon\\shell",r"currentcontrolset\\services\\[^\\]+$",
                      r"start menu\\programs\\startup"]

    regEvasion = [r"policies\\system", r"windows defender\\exclusions", r"windows\\currentversion\\policies", r"safeboot\\minimal", r"windows firewall\\policies"]

    regPrivileges = [r"execution options", r"environment"]

    listYara = listYara or []

    yaraEvasionFlag = False

    if "APIAntiDebugVMDetection" in listYara:
        yaraEvasionFlag = True
        mitreTactics["Sandbox Evasion -> T1497"] +=1

    if "APIKeys" in listYara:
        logFlag = True
        mitreTactics["Keyloging -> T1056.001"] += 1

    if "SelfSigned" in rapCert or "Modified" in rapCert:
        evasionFlag = True
        mitreTactics["Subvert Trust Controls -> T1553.002"] += 1
    

    sandboxEvasionFlag = False

    for pid in rezReports["ProcActions"]:

        if rezReports["ProcActions"][pid]["FilesW"]:
            writeCnt += len(rezReports["ProcActions"][pid]["FilesW"])
            mitreTactics["Malicious File Dropper -> T1204.002"] +=1
        
        if rezReports["ProcActions"][pid]["FilesR"]:
            readCnt += len(rezReports["ProcActions"][pid]["FilesR"])
            mitreTactics["Data from Local System -> T1005"] +=1
        

        for regLine in rezReports["ProcActions"][pid]["Registers"]:
            line = regLine.lower()
            if any(re.search(elem,line) for  elem in regEvasion):
                sandboxEvasionFlag = True
                mitreTactics["Impair Defenses: Disable or Modify Tools -> T1562.001"] +=1
            if any(re.search(elem,line) for elem in regPersistence):
                persistenceFlag = True
                mitreTactics["Registry Run Keys / Startup Folder -> T1547.001"] +=1
            if any(re.search(elem,line) for elem in regPrivileges):
                mitreTactics["IEFO -> T1546"] +=1

    
    if rezReports["Injection"] == True:
        mitreTactics["Process Injection -> T1055"] +=1
    if rezReports["Scripting"] == True:
        mitreTactics["Command and Scripting Interpreter ->T1059"] +=1    

    if len(rezReports.get("maliciousHttp", [])) >0 :
        c2Flag = True
        mitreTactics["Web Protocols -> T1071.001"] +=1

    for ip in dataTI["ips"]:
        if dataTI["ips"][ip]["votesScor"] > 0.25:
            c2Flag = True

    for domain in dataTI["domains"]:
        if dataTI["domains"][domain]["DGA"] != None:
            dgaDecision, dgaProb = dataTI["domains"][domain]["DGA"]
            if dgaDecision == True:
                dgaFlag = True
                c2Flag = True
                mitreTactics["Dynamic Resolution: Domain Generation Algorithms -> T1568.002"] +=1
        elif dataTI["domains"][domain]["votesScor"] > 0.25:
            c2Flag = True

    if rezReports["UnusualPort"] == True:
        mitreTactics["Non-Standard Port -> T1571"] +=1
        c2Flag = True
    

    finalScore = staticScore


    FinalDecision = "Benign"

   

    # kill chain pentru ransomware
    if readCnt > 10 and writeCnt > 10 and ("APICrypt" in listYara or finalScore >50):
        FinalDecision = "Malware"
        mitreTactics["Data Encrypted for Impact > T1486"] +=1

    # keylogger si comunicare 
    elif logFlag and c2Flag:
        FinalDecision = "Malware"
    
    #infostealer
    elif readCnt > 5  and c2Flag and finalScore > 30:
        FinalDecision = "Malware" 

    # persistenta 
    elif persistenceFlag and finalScore > 30:
        FinalDecision = "Malware"
        
    elif finalScore < 30 and not c2Flag:
        FinalDecision = "Benign"
    else:
        tacticsTotal = sum(1 for tactic in mitreTactics.values() if tactic > 0)
        if tacticsTotal >3 or finalScore > 80:
            FinalDecision = "Malware"
        elif tacticsTotal > 0 or finalScore >70:
            FinalDecision = "Suspicious"
        else:
            FinalDecision = "Benign"
    
    
 

    trueTactics = [t for t in mitreTactics if mitreTactics[t]>0]

    behavioral_details = buildBehavioralReport(
        listYara, rapCert, rezReports, dataTI,
        writeCnt, readCnt, c2Flag, dgaFlag,
        persistenceFlag, sandboxEvasionFlag,
        yaraEvasionFlag, logFlag, mitreTactics,
        finalScore, staticScore, mlExplanation, probMLStatic, verdictMLStatic
    )

    
    if dgaFlag == True:
        return "Malware", trueTactics, finalScore, behavioral_details
    


    return FinalDecision, trueTactics, finalScore, behavioral_details



def earlyHashDecision(hashRez):

    if hashRez is None:
        return None

    voteHashScore = hashRez["votesScor"]
    repHashScore = hashRez["repScor"]

    if voteHashScore > 0.25 or (repHashScore < -20 and voteHashScore > 0.1):
        FinalDecision = "Malware"
    
    elif voteHashScore < 0.01 and repHashScore > 30:
        return "Benign"
    
    else:
        FinalDecision = None

    return FinalDecision
    

    



    
    







