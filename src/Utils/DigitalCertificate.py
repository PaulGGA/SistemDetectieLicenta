
from signify.authenticode import signed_file
from signify.pkcs7 import SignedData
from typing import Optional, Tuple
import datetime
import pandas as pd

# importarea listei de organizatii de incredere
try:
    trusted = pd.read_csv("src\\Utils\\trustedIssuers.csv")

    listTrusted = trusted['Keyword'].tolist()
except:
    print("Eroare la citirea organizatiilor de incredere, returnam o lista generala")
    listTrusted = ["microsoft", "google", "nvidia", "intel"]

# StatusId corespunde enum-ului AuthenticodeVerificationResult din signify:
# 1 = semnat
# 2 = nesemnat
# 6 = nu este semnat de o autoritae
# 8 = fisier modificat dupa semnare
# 10 = certificat expirat


def getBestSignature(signatures) -> Tuple[Optional[SignedData], Optional[str]]:
    bestSignature = None
    impMax = -1
    algBest = None
    for s in signatures:
        imp = 0
        if( hasattr(s, 'digest_algorithm')):
            alg = str(s.digest_algorithm).lower()
            if "sha256" in alg:
                impMax = 3
                bestSignature = s
                break
            elif "sha1" in alg:
                imp = 2
            else:
                imp = 1
        if imp > impMax:
            impMax = imp
            bestSignature = s

    match(impMax):
        case 2:
            algBest = "sha1"
        case 3:
            algBest = "sha256"
        case default:
            algBest = "other"

   
    return bestSignature, algBest
                
   
def getCertificateFeatures(filepath):
    features = {
        "StatusId": 2,             
        "IsSigned": 0,
        "Algorithm": "None",
        "SerialNumber": "0",
        "SignerName": "None",
        "Fingerprint": "0",
        "TrustedIssuer": 0,         
        "IsSelfSigned": 0,          
        "ValidCnt": 0,              
        "Expired": 0,             
        "HasTimestamp": 0,          
        "ExpiredAtSigning": 0
    }


   


    try:
        with open(filepath, "rb") as f:
            fisierParsat = signed_file.SignedPEFile(f)

            status, _ = fisierParsat.explain_verify()
            features["StatusId"] = status.value


            signatures = list(fisierParsat.signatures)

            if not signatures:
                return features
            
            features["IsSigned"] = 1

            bestSignature, alg = getBestSignature(signatures= signatures)

            features["Algorithm"] = alg

            if bestSignature is None:
                return features

                        
            certificates = list(bestSignature.certificates)

            leafCertificate = None
            
            for c in certificates:    

                subject = list(c.subject.get_components())
                issuer = list(c.issuer.get_components())
                if subject != issuer:
                    leafCertificate = c
                    break
            if leafCertificate is None and certificates:
                leafCertificate = certificates[0]

            if leafCertificate:
                for key, value in leafCertificate.subject.get_components():
                    if key == "CN":
                        features["SignerName"] = str(value)
                        for elem in listTrusted:
                            if elem in str(value).lower():
                                features["TrustedIssuer"] = 1
                                break
                            
                features["SerialNumber"] = str(leafCertificate.serial_number)
                features["Fingerprint"] = leafCertificate.sha1_fingerprint
                
                l1 = list(leafCertificate.subject.get_components())
                l2 = list(leafCertificate.issuer.get_components())

                if l1 == l2:
                    features["IsSelfSigned"] = 1
                else:
                    features["IsSelfSigned"] = 0


                features["ValidCnt"] = (leafCertificate.valid_to - leafCertificate.valid_from).days
                
                now = datetime.datetime.now(datetime.timezone.utc)

                if leafCertificate.valid_to < now:
                    features["Expired"] = 1
                else:
                    features["Expired"] = 0

                timestamp = bestSignature.signer_info.signing_time

                has_countersigner = hasattr(bestSignature.signer_info, 'countersigner') and bestSignature.signer_info.countersigner

                if timestamp or has_countersigner:
                    features["HasTimestamp"] = 1
                else:
                    features["HasTimestamp"] = 0

                if timestamp:
                    if leafCertificate.valid_from <= timestamp <= leafCertificate.valid_to:
                        features["ExpiredAtSigning"] = 0
                    else:
                        features["ExpiredAtSigning"] = 1
              

    except:
        print(f"Eroare la parsarea fisierului pentru a gasi certificatul digital")
        
    return features


