import os

def verificaFormat(filePath):

    # verificam daca fisierul exista
    if not os.path.exists(filePath):
            print("Path-ul specificat nu returneaza nimic")
            return 'Eroare'
    

    # verificam daca fisierul este in format PE
    try:
        with open(filePath, 'rb') as f:
            magicBytes = f.read(4)
        
        if magicBytes[:2] == b'MZ':    
            return "PE"

        if magicBytes == b'\x7fELF':
            return "ELF"
        
    except Exception as e:
           print(f"Eroare la citirea fisierului: {e}")
           return 'Eroare'

    return "Necunoscut"
