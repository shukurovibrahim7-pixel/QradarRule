import os
import requests
import urllib3

# SSL xəbərdarlıqlarını söndürmək üçün
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- KONFİQURASİYA (Mühit dəyişənlərindən oxunur) ---
GITHUB_TOKEN = os.getenv("MY_GITHUB_TOKEN")  # Terminalda təyin edilən dəyişən adı
QRADAR_SEC_TOKEN = os.getenv("MY_QRADAR_TOKEN")

REPO_OWNER = "shukurovibrahim7-pixel"
REPO_NAME = "QradarRule"
RULES_PATH = "Rules" 
QRADAR_IP = "51.21.74.45"
# ---------------------

headers = {}
if GITHUB_TOKEN:
    headers["Authorization"] = f"token {GITHUB_TOKEN}"

def get_github_files(owner, repo, path=""):
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    response = requests.get(url, headers=headers)
    
    if response.status_code != 200:
        print(f"[-] GitHub API Xətası: {response.status_code} - {response.text}")
        return []
    return response.json()

def download_file(download_url):
    res = requests.get(download_url, headers=headers)
    if res.status_code == 200:
        return res.text
    return None

def upload_to_qradar(rule_content, file_name):
    qradar_url = f"https://{QRADAR_IP}/api/content_management/staged_bundles"
    
    qradar_headers = {
        "SEC": f"{QRADAR_SEC_TOKEN}",
        "Accept": "application/json"
    }
    
    files = {'file': (file_name, rule_content, 'application/json')}
    
    try:
        response = requests.post(qradar_url, headers=qradar_headers, files=files, verify=False)
        if response.status_code in [200, 201]:
            print(f"[+] {file_name} uğurla QRadar-a göndərildi.")
        else:
            print(f"[-] QRadar import xətası ({file_name}): {response.status_code} - {response.text}")
    except Exception as e:
        print(f"[-] Bağlantı xətası: {str(e)}")

def main():
    if not QRADAR_SEC_TOKEN:
        print("[-] XƏTA: MY_QRADAR_TOKEN mühit dəyişəni təyin edilməyib!")
        return

    print("[*] GitHub-dan qayda faylları axtarılır...")
    files = get_github_files(REPO_OWNER, REPO_NAME, RULES_PATH)
    
    for file in files:
        if file['type'] == 'file' and (file['name'].endswith('.json') or file['name'].endswith('.xml')):
            print(f"[+] Tapıldı: {file['name']}. Endirilir...")
            rule_content = download_file(file['download_url'])
            
            if rule_content:
                # Düzəldilmiş şərt bloku: Token varsa birbaşa QRadar-a göndərir
                upload_to_qradar(rule_content, file["name"])

if __name__ == "__main__":
    main()
