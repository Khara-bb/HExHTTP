import requests
from utils.style import Colors

__version__ = "v2.0"

OWNER = "c0dejump"
REPO = "HExHTTP"

def get_latest_version():
    url = f"https://api.github.com/repos/{OWNER}/{REPO}/releases/latest"
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        latest_version = response.json().get("tag_name", "")
        return latest_version
    except requests.RequestException:
        return None

def check_for_update(version):
    latest_version = get_latest_version()
    if latest_version:
        if latest_version > version:
            print(f"{Colors.YELLOW}🚨 New version available: {latest_version} (current: {version}){Colors.RESET}")
        elif latest_version < version:
            print(f"{Colors.REDIR}🚧 You are using a beta version: {version} (latest version: {latest_version}){Colors.RESET}")
        else:
            print(f"{Colors.GREEN}✅ You are using the latest version {Colors.RESET}")

if __name__ == "__main__":
    check_for_update(__version__)
