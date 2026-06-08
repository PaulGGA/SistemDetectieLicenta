# Sistem hibrid de analiza si izolare malware

Această aplicație este un motor euristic hibrid conceput pentru a analiza fișiere suspecte într-un mediu izolat. Sistemul combină analiza statică cu analiza dinamică a comportamentului pentru a oferi un verdict clar. De asemenea, amenințările identificate sunt mapate automat pe tacticile framework-ului de securitate MITRE ATT&CK.

**Structura Proiectului**
src/Core: Conține funcțiile principale care orchestrează fluxul aplicației și algoritmul de decizie finală.

src/DynamicAnalyzeData: Script-urile responsabile pentru procesarea datelor comportamentale.

src/ML: Fișierele dedicate analizei statice, incluzând script-urile de extragere a caracteristicilor și modelele pre-antrenate de Machine Learning.

src/Sandbox: Script-uri aflate în mediul izolat, ce se ocupă de funcționarea instrumentelor.

src/Utils: Fișiere inițiale pentru baza de date, certificatul digital și verificarea formatului.
