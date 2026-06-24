import os
import requests
import urllib3

# SSL xəbərdarlıqlarını söndürmək üçün
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- KONFİQURASİYA ---
GITHUB_TOKEN = os.getenv("MY_GITHUB_TOKEN")  
QRADAR_SEC_TOKEN = os.getenv("MY_QRADAR_TOKEN")

REPO_OWNER = "shukurovibrahim7-pixel"
REPO_NAME = "QradarRule"
RULES_PATH = "Rules" 
QRADAR_IP = "51.21.74.45"
# ---------------------

headers = {
    "Accept": "application/vnd.github.v3+json"
}
if GITHUB_TOKEN:
    headers["Authorization"] = f"token {GITHUB_TOKEN}"

def get_github_files(owner, repo, path=""):
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    try:
        response = requests.get(url, headers=headers)
        
        if response.status_code != 200:
            print(f"[-] GitHub API Xətası: Status {response.status_code}")
            print(f"[-] Cavab: {response.text}")
            return []
        
        data = response.json()
        if isinstance(data, list):
            return data
        else:
            print("[-] Gözlənilməz API cavab formatı (Siyahı deyil).")
            return []
            
    except Exception as e:
        print(f"[-] GitHub bağlantı xətası: {str(e)}")
        return []

def download_file(download_url):
    try:
        res = requests.get(download_url, headers=headers)
        if res.status_code == 200:
            return res.text
        return None
    except Exception as e:
        print(f"[-] Fayl endirilərkən xəta: {str(e)}")
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
        print(f"[-] QRadar bağlantı xətası: {str(e)}")

def main():
    if not QRADAR_SEC_TOKEN:
        print("[-] XƏTA: MY_QRADAR_TOKEN mühit dəyişəni təyin edilməyib!")
        return

    print("[*] GitHub-dan qayda faylları axtarılır...")
    files = get_github_files(REPO_OWNER, REPO_NAME, RULES_PATH)
    
    if not files:
        print("[-] İşlənəcək fayl tapılmadı və ya API xətası baş verdi.")
        return
        
    for file in files:
        if isinstance(file, dict) and file.get('type') == 'file' and (file.get('name', '').endswith('.json') or file.get('name', '').endswith('.xml')):
            print(f"[+] Tapıldı: {file['name']}. Endirilir...")
            rule_content = download_file(file['download_url'])
            
            if rule_content:
                upload_to_qradar(rule_content, file["name"])

if __name__ == "__main__":
    main()
