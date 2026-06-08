import subprocess
import os
import time

# caile hardcodate de pe Sandbox

SharkPath = "C:\\Program Files\\Wireshark\\tshark.exe"
OutputPath1 = "C:\\licenta\\reports\\report1.pcap"
OutputPath2 = "C:\\licenta\\reports\\report2.pcap"

def startShark(stopDuration):
    
    try:
        os.makedirs(os.path.dirname(OutputPath1), exist_ok=True)

        shark1 = subprocess.Popen(
            args= [SharkPath,
                   "-i", "Ethernet 2",
                   "-a", f"duration:{stopDuration}",
                   "-w", OutputPath1,
                   "-q"
                    ],
            stdout= subprocess.DEVNULL,
            stderr= subprocess.DEVNULL
        )


        shark2 = subprocess.Popen(
            args= [SharkPath,
                   "-i", "Adapter for loopback traffic capture",
                   "-a", f"duration:{stopDuration}",
                   "-w", OutputPath2,
                   "-q"
                    ],
            stdout= subprocess.DEVNULL,
            stderr= subprocess.DEVNULL
        )

        time.sleep(5)
        print("TSHark a pornit")
        return shark1, shark2
    except Exception as e:
        print(f"Eroare la pornirea WireShark : {e}")
        return None, None


def stopShark(s1, s2):
    if s1 and s1.poll() is None:
        print("Se opreste tshark")
        s1.terminate()
        try:
            s1.wait(timeout=5)
        except subprocess.TimeoutExpired:
            s1.kill()

    if s2 and s2.poll() is None:
        print("Se opreste tshark")
        s2.terminate()
        try:
            s2.wait(timeout=5)
        except subprocess.TimeoutExpired:
            s2.kill()
    
