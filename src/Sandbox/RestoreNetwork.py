import subprocess
import time


# dupa inchiderea fakenet, setarile trebuie resetate pentru ca masina sa se conecteze inapoi la internet

def restoreNetwork():
    print("Incepem resetarea setarilor de retea")

    try:
        print("Resetam adresa IP si DGW la DHCP")
        
        cmd_dns = f'netsh interface ip set dns name="Ethernet 2" source=dhcp'
        subprocess.run(cmd_dns, shell=True, check=True, capture_output=True)

        subprocess.run('ipconfig /renew', shell=True, capture_output=True)
        subprocess.run('ipconfig /flushdns', shell=True, capture_output=True)

        print("Resetare reusita")
        return True
    except Exception as e:
        print(f"Eroare la resetare: {e}")
        return False

if __name__ == "__main__":
    restoreNetwork()