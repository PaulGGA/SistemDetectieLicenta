import os
import src.DynamicAnalysis.WhitelistConfig as wc
import re
import pandas
import pyshark
import asyncio


from ConfigData import REPORTS_TEMP_DIR
reportsDir = os.path.join(REPORTS_TEMP_DIR, "reports\\")

RegexIP = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]{1,5})?\b"

import src.ML.FeaturesExtraction as FE
import ML.DGADetection.DecisionDGA as DF
import src.DynamicAnalysis.WhitelistConfig as WC




def processDiverterLine(line):
    i = line.index("Diverter")
    newLine = line[i + 9:].strip()
    parts = newLine.split(" ")
    ip = re.findall(RegexIP,line)
    if ip != []:
        ipSplit = ip[0].split(":")
    else:
        return None, None, None,None, None
    

    if parts[3] not in ["TCP", "UDP"]:
         return None, None, None,None, None
    #adresa IP, nume proc, id proc, protocol
    return ipSplit[0], ipSplit[1], parts[0], parts[1][1:-1], parts[3]

def processDnsLine(line):
    i = line.index("]")
    newLine = line[i+1:].strip()
    parts = newLine.split(" ")

    if parts[1] not in ["TCP", "UDP"]:
         return None, None, None,None
    #domeniu, numee proc, id proc, protocol
    return parts[5], parts[7], parts[8][1:-1], parts[1]

def ipFiltering(ip):
    # sunt excluse retele private, loopback, broadcast si fakenet
    parts = ip.split(".")

    nr1 = int(parts[0])
    nr2 = int(parts[1])
    nr3 = int(parts[2])

    #retele private
    if nr1 == 10:
        return False
    if nr1 == 172 and 16 <= nr2 < 32:
        return False
    if nr1 == 192 and nr2 == 168:
        return False
    
    #loopback si local
    if nr1 == 127 or (nr1 ==169 and nr2 == 254):
        return False
    
    #broadcast/ zero
    if ip == "255.255.255.255" or ip == "0.0.0.0": 
        return False

    #fakenet
    if nr1 == 192 and nr2 == 0 and nr3 == 2:
        return False

    return True
    
def processFNLog(treePID):
    with open(reportsDir + "\\fakenetLog.txt", "r") as f:
        lines = f.readlines()


    resultsDiverter = []
    resultsDNS = []
    ipsSeen = set()
    domainsSeen = set()
    suspectPortsFlag = False

    for line in lines:
        if "Diverter" in line and "requested" in line:
            IpAddr, Port, Pname, PID, Protocol = processDiverterLine(line)
            if IpAddr is None or Port is None:
                continue
            try:
                portInt = int(Port)
            except ValueError:
                portInt = -1
            if WC.verifWhitePort(portInt) == False:
               suspectPortsFlag = True 
            if ipFiltering(IpAddr) == False:
                continue
            if IpAddr not in ipsSeen:
                ipsSeen.add(IpAddr)
                resultsDiverter.append((IpAddr, Port, Pname, str(PID), Protocol))
            else:
                continue
        if "DNS Server" in line and "domain" in line:
            domain, PName, PID, Protocol = processDnsLine(line=line)
            if domain is None:
                continue
            if wc.verifDom(domain):
                continue
            if domain[1:-1] not in domainsSeen:
                resultsDNS.append((domain[1:-1],PName,str(PID), Protocol))


    return resultsDiverter, resultsDNS, suspectPortsFlag


def createDictProcessCreate(createList):
    dictProcess = {}
    for _, line in createList.iterrows():
        linePID = str(line["PID"])
        details = line["Detail"]
    

        
        match = re.search(r"PID:\s*(\d+)", details)
        if match:
            childPID = str(match.group(1))
            if linePID not in dictProcess:
                dictProcess[linePID] = []
            
            if childPID not in dictProcess[linePID]:
                dictProcess[linePID].append(childPID)

    return dictProcess

def findPIDAll(csvData, filename):
       

    potrivire = csvData[csvData["Process Name"].str.lower() == filename.lower()]


    if not potrivire.empty:

        target_PID = str(potrivire.iloc[0]["PID"])

        return target_PID

    return None

def processProcmon(filename):
    try:
        df = pandas.read_csv(reportsDir + "procCSV.csv")
    except Exception as e:
        print(f" Eroare la citirea fisierului CSV procmo : {e}")
        return None, None, None, None, [], False, False

    df.columns = df.columns.str.strip()

    procIgnore = ["Procmon64.exe","etwdump.exe","udpdump.exe", "Wireshark.exe", "tshark.exe", "Procmon.exe", "fakenet.exe"]

    df = df.query("`Process Name` not in @procIgnore")
    

    createList = df[df["Operation"] == "Process Create"]

    PID = findTargetPID(createList,filename=filename)

    if not PID:
        PID = findPIDAll(df, filename)
        
        if not PID:
            print(f"Fisierul {filename} nu a fost gasit in log-urile Procmon")
            return None, [pandas.DataFrame(), pandas.DataFrame()], pandas.DataFrame(), pandas.DataFrame(), [], False, False

    treePID = [PID]



    dictPro = createDictProcessCreate(createList)
    
    createMalwareTree(dictPro, PID, treePID)


    scriptsProc = ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"]

    isScripting = False
    for _, linie  in createList.iterrows():
        if str(linie["PID"]) not in treePID:
            continue
        for elem in scriptsProc:
            if elem in str(linie["Path"]).lower():
                isScripting = True
                break
        



    remoteThreads = df[(df["Operation"].str.contains("remote", case= False, na= False)) & (df["Operation"].str.contains("thread", case= False, na= False))].copy()

    isInjection = False
    if not remoteThreads.empty:
        createInjectionTree(remoteThreads, malwareTree= treePID)
        isInjection = True


    df = df.copy()
    df["PID"] = df["PID"].astype(str)

    treePID = [str(p) for p in treePID]
    

    dfFiltered = df[df["PID"].isin(treePID)]

    dfFiltered.to_csv(os.path.join(reportsDir, "procCSV.csv"))
    

    fileWriteList = dfFiltered[dfFiltered["Operation"] == "WriteFile"]

    extensions = (".exe" , ".dll", ".bat", ".vbs", ".ps1")
    finalWriteList = fileWriteList[fileWriteList["Path"].str.lower().str.endswith(extensions, na= False)]

    keywordsRead =  [ r"\\AppData\\.*\\(Login Data|logins\.json|key4\.db|cookies\.sqlite|wallet\.dat)", r"\\\.ssh\\(id_rsa|known_hosts|config)", r"\\AppData\\Local\\Google\\Chrome\\User Data",
                      r"\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles", r"\\AppData\\Local\\Microsoft\\Credentials", r"password|credential|keepass|lastpass",]
    keywordRegex = '|'.join(keywordsRead)

    fileReadList = dfFiltered[dfFiltered["Operation"] == "ReadFile"]

    readWhitelist = [r"\\font_index",r"\\iconcache", r"\\thumbcache", r"desktop\.ini",r"\\AppData\\Local\\Temp\\[^\\]+$"]

    readWhileRegex = "|".join(readWhitelist)

    finalReadList = fileReadList[fileReadList["Path"].str.contains(keywordRegex, case=False, regex= True, na=False)]

    finalReadList = finalReadList[~finalReadList["Path"].str.contains(readWhileRegex, case= False, regex= True, na=False)]

    keywordsRegistry = [r"currentVersion\\run", r"winlogon", r"services", r"start menu", r"startup", r"defender", r"policies\\system", r"firewall", r"security", r"safeboot", r"execution options", r"environment"]

    regex = '|'.join(keywordsRegistry)

    regList = dfFiltered[(dfFiltered["Operation"].isin(["RegSetValue", "RegCreateKey"])) & 
                 (dfFiltered["Path"].str.contains(regex, case= False, regex= True, na= False))]
    
    regWhitelist = [r"\\bam\\", r"\\AppCompatFlags\\", r"\\AppModel\\", r"\\TypedPaths\\", r"\\MuiCache\\", r"\\UserAssist\\", r"\\RecentDocs\\",r"\\ComDlg32\\"]   

    whitelistRegex = '|'.join(regWhitelist)

    regList = regList[~regList["Path"].str.contains(whitelistRegex, case=False, regex=True, na=False)] 
  
    
    
    networkList = dfFiltered[dfFiltered["Operation"].str.contains("TCP|UDP", case=False, na=False)]

    


    return createList, [finalReadList,finalWriteList], regList, networkList, treePID, isInjection, isScripting

def findTargetPID(createList, filename):
    details = None
    for _, line in createList.iterrows():
        val = str(line["Path"])
        if filename in val:
            details = line["Detail"]
            break
    
    if details is None:
        return details
    PID = 0
    match = re.search(r"PID:\s*(\d+)", details)

    if match:
        PID = str(match.group(1))
    else:
        return None
    


    return PID

def createMalwareTree(processDict, initialPID, rez):


    if initialPID in  processDict:
        copii = processDict[initialPID]

        for c in copii:
            if c not in rez:
                rez.append(c)
                createMalwareTree(processDict,c,rez)

def createInjectionTree(dfThreads, malwareTree):
    for _, line in dfThreads.iterrows():
        linePId = str(line["PID"])
        if linePId in malwareTree:
            match = re.search(r"PID:\s*(\d+)", line["Detail"])
            if match:
                malwareTree.append(str(match.group(1)))
            else:
                continue





def analyzePcap():

    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    results = {
            "queriesDNS": set(),
            "requestsHTTP": [],
            "tls": set(),
            "ports": set(),
        }

    try:
        f = pyshark.FileCapture(
            reportsDir + "report1.pcap",
            display_filter= "dns || http || ssl.handshake.type == 1 || tls.handshake.type == 1",
            keep_packets=False
        )

        for pachet in f :
            if hasattr(pachet, 'transport_layer') and pachet.transport_layer:
                transport = getattr(pachet, pachet.transport_layer.lower())
                if hasattr(transport, 'dstport'):
                    results["ports"].add(transport.dstport)

            if "DNS" in pachet:
                try:
                    query = pachet.dns.qry_name
                    results["queriesDNS"].add(query)
                except Exception as e:
                    print(f"Eroare la analiza pachet DNS : {e}")
                    pass
            if "HTTP" in pachet:
                try:
                    ipDST = "N/A"
                    if "IP" in pachet:
                        ip_dst = pachet.ip.dst
                    elif "IPV6" in pachet:
                        ip_dst = pachet.ipv6.dst
                    req_info = {
                        "method": getattr(pachet.http, 'request_method', 'N/A'),
                        "host": getattr(pachet.http, 'host', 'N/A'),
                        "uri": getattr(pachet.http, 'request_uri', 'N/A'),
                        "user_agent": getattr(pachet.http, 'user_agent', 'N/A'),
                        "ipDst": ipDST,
                    }
                    if req_info['host'] != 'N/A' or req_info['method'] != 'N/A':
                        results["requestsHTTP"].append(req_info)
                except Exception as e:
                    print(f"Eroare la analiza pachet HTTP : {e}")
                    pass
            if 'SSL' in pachet or 'TLS' in pachet:
                layer = pachet.tls if 'TLS' in pachet else pachet.ssl
                try:
                    if hasattr(layer, 'handshake_extensions_server_name'):
                        sni = layer.handshake_extensions_server_name
                        results["tls"].add(sni)
                except Exception as e:
                    print(f"Eroare la analiza pachet SSL/ TLS : {e}")
                    pass

        f.close()
    except Exception as e:
        print(f"Eroare la analiza fisierului pcap : {e}")

 
    results["queriesDNS"] = list(results["queriesDNS"])
    results["tls"] = list(results["tls"])
    results["ports"] = list(results["ports"])

    return results


def sendRequest(ips, domains, filename, urlServer):
    import requests as req

    try:
        response = req.post(
            f"{urlServer}/check_network",
            json={'ips': ips, 'domains': domains, 'filename':filename},
            timeout=300
        )
        if response.status_code != 200:
            print(f"Eroare server: {response.status_code}")
            return {"ips": {}, "domains": {}}
        
        data = response.json()

    except Exception as e:
        print(f"Eroare la request check_network: {e}")
        return {"ips": {}, "domains": {}}

    usefulData = {
        "ips": {},
        "domains": {},
    }
    for ip in ips:
        usefulData["ips"][ip] = []
    
        ipInfo = data.get("ThreatIntelligence", {}).get(ip, {})
        ipAttributes = ipInfo.get("data", {}).get("attributes", {})

        usefulData["ips"][ip].append(ipAttributes.get("last_analysis_stats", {"malicious":0,"suspicious":0,"undetected":0,"harmless":0}))
        usefulData["ips"][ip].append(ipAttributes.get("reputation", 0))
        usefulData["ips"][ip].append(ipAttributes.get("country", "Unknown"))
        usefulData["ips"][ip].append(ipAttributes.get("as_owner", "Unknown"))

    for domain in domains:
        usefulData["domains"][domain] = []
    

        domainInfo = data.get("ThreatIntelligence", {}).get(domain, {})
        domainAttributes = domainInfo.get("data", {}).get("attributes", {})


        usefulData["domains"][domain] = []
        usefulData["domains"][domain].append(domainAttributes.get("last_analysis_stats", {"malicious":0,"suspicious":0,"undetected":0,"harmless":0}))
        usefulData["domains"][domain].append(domainAttributes.get("reputation", 0))
        usefulData["domains"][domain].append(domainAttributes.get("categories", {}))

    return usefulData


def corellateRez(rezDiverter, rezDNS, rezProc, rezPcap, treePID, isInjection, isScripting, portFlag):
    _, finalFileList, regList, _ = rezProc

    readList = finalFileList[0]
    writeList = finalFileList[1]

    rez = {
        "IpProc": {},
        "sureDomains": [],
        "unsureDomains": [],
        "maliciousHttp": [], 
        "ProcActions": {},
        "Injection": False,
        "Scripting": False,
        "UnusualPort":False,   
    }

    ipsUnsafe = set()

    for ip, port, pName, PID, protocol in rezDiverter:
        k = ip + ":" + port
        if k not in rez["IpProc"]:
            rez["IpProc"][k] = []
        rez["IpProc"][k].append({"process":pName, "pid": PID, "protocol":protocol})
        ipsUnsafe.add(ip)


    domainsFakeNet = set(d for d, _ , _ ,_ in rezDNS)
    domainsPcap = set(rezPcap.get("queriesDNS",[]))


    rez["sureDomains"] = list(domainsFakeNet & domainsPcap)

    domainsTLS =  set(rezPcap.get("tls", []))

    rez["unsureDomains"] = list(domainsTLS - domainsPcap - domainsFakeNet)

    for PID in treePID:
        pidFiles1 = writeList[ PID ==writeList["PID"].astype(str)]
        pidFiles2 = readList[PID ==readList["PID"].astype(str)]
        pidRegisters = regList[ PID == regList["PID"].astype(str)]
        
        pidIps = []
        pidDns = []

        for domain, _, pid1, _ in rezDNS:
            if PID == str(pid1):
                pidDns.append(domain.strip())
        
        for ip, port, _, pidDiverter, _ in rezDiverter:
            if PID == str(pidDiverter):
                pidIps.append(ip.strip() + ":" + port.strip())

        if not pidFiles1.empty or not pidFiles2.empty or not pidRegisters.empty or pidIps or pidDns:
            rez["ProcActions"][PID] = {
                "FilesW": pidFiles1["Path"].unique().tolist(),
                "FilesR":pidFiles2["Path"].unique().tolist(),
                "Registers":pidRegisters["Path"].unique().tolist(),
                "Ips": list(set(pidIps)),
                "Dns":list(set(pidDns))
            }
        
    if "requestsHTTP" in rezPcap:
        for request in rezPcap["requestsHTTP"]:
            if request.get("dst_ip") in ipsUnsafe or request.get("host") in domainsFakeNet:
                rez["maliciousHttp"].append(request)

    
    rez["Injection"] = isInjection
    rez["Scripting"] = isScripting


    rez["sureDomains"] = [dom for dom in rez["sureDomains"] if not WC.verifDom(dom)]

    rez["unsureDomains"] = [dom for dom in rez["unsureDomains"] if not WC.verifDom(dom)]

    if portFlag == True:
        rez["UnusualPort"] = True

    return rez


def scorvotes(stats, hash = False):
    maliciousVts = stats["malicious"]

    if hash == True:
        if stats["harmless"] > 10 and maliciousVts < 3:
            return -1

    suspiciousVts = stats["suspicious"]
    total  = maliciousVts + suspiciousVts + stats["undetected"]

    if total !=0:
        scorVts = (maliciousVts + 0.5*suspiciousVts)/total
    else:
        scorVts = 0

    return scorVts


def processHashTI(hashDict):


    if hashDict:
        if "error" not in hashDict:
            tiDict = hashDict["ThreatIntelligence"]
            if tiDict:
                dateFaraHash = next(iter(tiDict.values()))
            
                if dateFaraHash and "data" in dateFaraHash:
                    votes = dateFaraHash["data"]["attributes"]["last_analysis_stats"]

                    scorVts = scorvotes(votes, hash= True)


                    scorRep =dateFaraHash["data"]["attributes"]["reputation"]


                    hashDict = {
                        "votesScor": scorVts,
                        "repScor": scorRep,
                    }
                else:
                    hashDict = {
                        "votesScor": 0,
                        "repScor": 0,
                    }
            else:
                hashDict = {"votesScor": 0, "repScor": 0}
    
    return hashDict

def processTiData(dictTI: dict):
    #votes

    data = {
        "ips": {},
        "domains": {},
    }

    for ip in dictTI["ips"]:
        stats = dictTI["ips"][ip][0]

        scorVts = scorvotes(stats)
        
        
        scorRep = dictTI["ips"][ip][1]
        data["ips"][ip] = {
            "votesScor": scorVts,
            "repScor": scorRep,
            "owner": dictTI["ips"][ip]
        }
    
    domains = []
    for dom in dictTI["domains"]:
        stats = dictTI["domains"][dom][0]
        
        scorVts = scorvotes(stats)

        scorRep = dictTI["domains"][dom][1]
        data["domains"][dom] = {
            "votesScor": scorVts,
            "repScor": scorRep,
            "category": dictTI["domains"][dom][2]
        }
        domains.append(dom)

    rezDGA = DF.testDomains(domains)
    
    if rezDGA != None:
        for dom in domains:
            data["domains"][dom]["DGA"] = rezDGA[dom]
    else:
        for dom in domains:
            data["domains"][dom]["DGA"] = None

   
    return data


def funcProcess(path, urlServer):

    fileName = os.path.basename(path)
    createList, finalFileList, regList, networkList, treePID, isInjection, isScripting = processProcmon(fileName)

    if createList is None:
        return None, None
        
    resultsDiverter, resultsDNS, portFlag = processFNLog(treePID)
    resultsPCAP = analyzePcap()


    rezFInal = corellateRez(resultsDiverter,resultsDNS,(createList, finalFileList, regList, networkList),resultsPCAP,treePID, isInjection, isScripting, portFlag) 

    ips = []
    for k in rezFInal["IpProc"]:
        ipsplit = k.split(":")
        ips.append(ipsplit[0])
   
    domains = rezFInal["sureDomains"]
    for dom in rezFInal["unsureDomains"]:
        domains.append(dom)

    dataTI = sendRequest(ips, domains,fileName, urlServer)

    finDataTi = processTiData(dataTI)

    return rezFInal, finDataTi



   


