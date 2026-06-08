import yara

# pattern matching cu regulile YARA scrise
def getYarafeatures(file):

    yaraFile = "config\\YaraRules.yar"

    reguli = yara.compile(yaraFile)
    try:
        matches = reguli.match(file)
    except Exception as e:
        print(f"Eroare yara: {e}")
        return {}
    

    listaReguli = [
        "APIInstall",
        "APIKeys",
        "APIDownloads",
        "APIComunicate",
        "APIExfiltration",
        "APIHooking",
        "APIAntiDebugVMDetection",
        "APICrypt"
    ]

    features = {regula: 0 for regula in listaReguli}

    for i in matches:
        if i.rule in listaReguli:
            features[i.rule] = 1
    
    return features

