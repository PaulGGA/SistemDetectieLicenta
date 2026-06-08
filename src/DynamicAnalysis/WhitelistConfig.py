
SafeDomains = {
    "wpad.ec2.internal", 
    "wpad",
    "time.windows.com",
    "login.live.com",
    "login.microsoftonline.com",
    "settings-win.data.microsoft.com",
    "v10.events.data.microsoft.com",
    "ctldl.windowsupdate.com",
    "displaycatalog.mp.microsoft.com",
    "sls.update.microsoft.com",
    "fe3.delivery.mp.microsoft.com",
    "arc.msn.com",
    "edge.microsoft.com",
    "clients2.google.com",
    "update.googleapis.com",
    "events.data.microsoft.com"
}

SafeEnds = {
    ".microsoft.com",
    ".windows.com",
    ".aws.amazon.com",
    ".live.com"
}

SafePorts = {
    # web
    80, 443, 8080, 8443, 8008,   

    # DNS
    53,5353, 5355, 67, 68, 123,   

    # windows
    135, 137, 138, 139, 445, 3389, 5985, 5986,   

    # AWS
    2049, 9200
}



def verifDom(name):
    if name.lower() in SafeDomains:
        return True
    
    for s in SafeEnds:
        if name.lower().endswith(s):
            return True
    return False

def verifWhitePort(port):
    return port in SafePorts
