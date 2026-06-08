import sqlite3
import datetime

class Database:
    def __init__(self, name = "src\\Utils\\antivirus.db"):
        self.name = name
        
        with sqlite3.connect(self.name) as conexiune:
            cursor = conexiune.cursor()

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS Reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filepath TEXT,
                    scan_date DATETIME,
                    verdict TEXT,          
                    confidence REAL,      
                    fingerprint TEXT,
                    motives TEXT,
                    scan_type TEXT
                )
            ''')

            cursor.execute('''
            CREATE TABLE IF NOT EXISTS Quarantine(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hash TEXT,
                    ogFilepath TEXT,
                    quarFilepath TEXT,
                    verdict TEXT,
                    date DATETIME
                           )
            ''')

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_reports_date ON Reports(scan_date DESC)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_quarantine_hash ON Quarantine(hash)")

            conexiune.commit()

    
    def saveReport(self, filepath, verdict, confidence, fingerprint, motives, scanMode):
        try:
            with sqlite3.connect(self.name) as conexiune:
                cursor = conexiune.cursor()
                cursor.execute('''
                Insert or ignore into Reports(filepath, scan_date, verdict, confidence, fingerprint, motives, scan_type)
                               Values(?, ?, ?, ?, ?, ?, ?)
                               ''',(filepath, datetime.datetime.now().isoformat(), verdict, confidence, fingerprint, motives, scanMode))
                conexiune.commit()
        except Exception as e:
            print(f"eroare la adaugarea raportului : {e}")
    
    def getReports(self, pageCnt, itemsPerPage = 10  ):
        try:
            with sqlite3.connect(self.name) as conexiune:
                cursor = conexiune.cursor()


                cursor.execute(
                    '''
                    Select filepath, scan_date, verdict, confidence, fingerprint, motives, scan_type
                    From Reports
                    Order by scan_date Desc
                    Limit ? Offset ?
                    ''', (itemsPerPage, pageCnt * itemsPerPage)
                )

                return cursor.fetchall()
        except Exception as e:
            print(f"Eroare la returnarea rapoartelor : {e}")

    def getCntReports(self):
        try:
            with sqlite3.connect(self.name) as conexiune:
                cursor = conexiune.cursor()

                cursor.execute(
                    '''
                    Select count(*)
                    From Reports
                    '''
                )

                return cursor.fetchone()
        except Exception as e:
            print(f"Eroare la returnarea numarului rapoartelor : {e}")

    def addQuarantine(self,filePath, quarPath,hashFile, verdict):
        try:
            with sqlite3.connect(self.name) as conexiune:
                cursor = conexiune.cursor()

                cursor.execute(
                    '''
                    INSERT or IGNORE into Quarantine(hash, ogFilepath, quarFilepath, verdict, date)
                    Values(?, ?, ?, ?, ?)
                    ''', (hashFile,filePath, quarPath, verdict,datetime.datetime.now().isoformat())
                )

                conexiune.commit()
        except Exception as e:
            print(f"Eroare la inserarea in tabelul Quarantine: {e}")
    
    def deleteQuarantine(self, hashFile):
        try:
            with sqlite3.connect(self.name) as conexiune:
                cursor = conexiune.cursor()

                cursor.execute('''
                DELETE From Quarantine
                WHERE hash = ?
                               ''',(hashFile,))
                conexiune.commit()
        except Exception as e:
            print(f"Eroare la stergerea din tabelul Quarantyne :{e}")

    def getQuarantine(self, pageCnt, itemsPerPage = 10  ):
        try:
            with sqlite3.connect(self.name) as conexiune:
                cursor = conexiune.cursor()


                cursor.execute(
                    '''
                    Select hash, ogFilepath, quarFilepath, verdict, date
                    From Quarantine
                    Order by date Desc
                    Limit ? Offset ?
                    ''', (itemsPerPage, pageCnt * itemsPerPage)
                )

                return cursor.fetchall()
        except Exception as e:
            print(f"Eroare la returnarea fisierelor din carantina : {e}")

    def getCntQuarantine(self):
        try:
            with sqlite3.connect(self.name) as conexiune:
                cursor = conexiune.cursor()

                cursor.execute(
                    '''
                    Select count(*)
                    From Quarantine
                    '''
                )

                return cursor.fetchone()
        except Exception as e:
            print(f"Eroare la returnarea numarului de fisiere din carantina : {e}")
    
    def getQuarantineByFilePath(self,filepath):
        try:
            with sqlite3.connect(self.name) as conexiune:
                cursor = conexiune.cursor()

                cursor.execute(
                    '''
                    Select hash, ogFilepath, quarFilepath, verdict, date
                    From Quarantine
                    where ogFilepath = ?
                    ''',(filepath,)
                )

                return cursor.fetchone()
        except Exception as e:
            print(f"Eroare la returnarea unui fisier din carantina : {e}")
    
    def getReportByHash(self,hash):
        try:
            with sqlite3.connect(self.name) as conexiune:
                cursor = conexiune.cursor()

                cursor.execute(
                    '''
                    Select filepath, scan_date, verdict, confidence, fingerprint, motives, scan_type
                    FROM Reports
                    where fingerprint = ?
                ''',(hash,)
                )

                return cursor.fetchone()
        except Exception as e:
            print(f"Eroare la returnarea unui raport: {e}")
            return None

db = Database()