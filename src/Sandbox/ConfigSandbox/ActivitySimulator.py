import time
import random
import threading
import requests
import ctypes


# script aflat in Sandbox pentru simularea activitatii


rotita = 0x0800
rotitaDelta = 120

class Simulator:
    def __init__(self):
        self.runFlag = False

        self.domains = [
            "https://www.google.com",
            "https://www.reddit.com",
            "https://www.instagram.com",
            "https://www.flashscore.com",
            "https://www.digisport.ro",
        ]

    
    def simulateMouse(self):

        width = ctypes.windll.user32.GetSystemMetrics(0)
        height = ctypes.windll.user32.GetSystemMetrics(1)


        while self.runFlag:
            x = random.randint(200, width - 200)
            y = random.randint(150, height - 150)

            ctypes.windll.user32.SetCursorPos(x,y)

            if random.random() < 0.2:
                dir = random.choice([-1,1])
                rotatieCnt = random.randint(2,5)

                rotation = dir *( rotitaDelta * rotatieCnt)

                ctypes.windll.user32.mouse_event(rotita,0,0,rotation,0)
        
            time.sleep(random.uniform(0.2,4.0))

    
    def simulateNetwork(self):
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }

        while self.runFlag:
            target = random.choice(self.domains)

            try:
                requests.get(url = target,headers= headers, timeout= 5)
            except Exception:
                pass
                
            time.sleep(random.uniform(6,12))

    def start(self):
        self.runFlag = True

        self.mouse_thread = threading.Thread(target=self.simulateMouse, daemon=True)
        self.mouse_thread.start()
        
        self.network_thread = threading.Thread(target=self.simulateNetwork, daemon=True)
        self.network_thread.start()

    def stop(self):
        self.runFlag = False
        