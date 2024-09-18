import subprocess
import sys

# Gerekli kütüphaneleri kontrol edip yükleme fonksiyonu
def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# Gerekli kütüphaneler listesi
required_libraries = ['whois', 'requests', 'dns', 'colorama']

# Kütüphanelerin kurulu olup olmadığını kontrol et ve gerekirse yükle
for library in required_libraries:
    try:
        __import__(library)
    except ImportError:
        print(f"{library} kütüphanesi kurulu değil, kurulum yapılıyor...")
        install(library)

import whois
import socket
import ssl
import re
import dns.resolver
import requests
from datetime import datetime
from colorama import Fore, Style, init

# colorama başlatılır
init(autoreset=True)

# Çizgi fonksiyonu
def print_line():
    print(Fore.CYAN + "-" * 50)

# SSL Sertifikası kontrol fonksiyonu
def check_ssl(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return cert
    except:
        return None

# Whois bilgisine bakarak alan adı yaşı kontrolü
def check_whois(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):  # Eğer birden fazla tarih varsa ilkini al
            creation_date = creation_date[0]
        age = (datetime.now() - creation_date).days / 365
        return age > 1  # 1 yıldan kısa mı kontrol
    except Exception as e:
        return False  # Whois verisi alınamadıysa False döndür

# E-posta adresi ve domain belirli kelimeler içeriyor mu
def check_domain_keywords(email, domain):
    keywords = ['darkweb', 'hunting', 'intel', 'alumni', 'alumna', 'std', 'student', 'free', 'temp']
    for keyword in keywords:
        if keyword in email or keyword in domain:  # Hem e-posta hem domain içinde arıyoruz
            return True
    return False

# Argo kelimeleri dosyadan okuma fonksiyonu
def load_turkish_slang_words(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            slang_words = [line.strip() for line in file.readlines()]  # Her satırı al, trim et
        return slang_words
    except FileNotFoundError:
        print(Fore.RED + f"Argo kelime dosyası {file_path} bulunamadı.")
        return []

# Türkçe argo/küfür içerik kontrolü (kelimeleri dosyadan okuyoruz)
def check_turkish_slang(email, domain, slang_words):
    for slang in slang_words:
        if slang in email or slang in domain:
            return True
    return False

# Mail adresinde ve domaininde rakam kontrolü (360, 724, 247, 101 hariç)
def check_digit_count(email, domain):
    exempt_numbers = ['360', '724', '247', '101']
    
    # E-posta ve domain adında geçen sayıları bul
    email_digits = re.findall(r'\d+', email)
    domain_digits = re.findall(r'\d+', domain)
    
    def count_valid_digits(digits):
        # Geçerli sayı olmayanları say
        valid_digits = [d for d in digits if d not in exempt_numbers]
        return sum(len(d) for d in valid_digits)  # Rakamların toplam uzunluğunu hesapla
    
    email_digit_count = count_valid_digits(email_digits)
    domain_digit_count = count_valid_digits(domain_digits)
    
    # Eğer toplamda 2'den fazla rakam varsa fail vereceğiz
    return (email_digit_count > 2) or (domain_digit_count > 2)

# Varsayılan DNS kontrolü (A ve CNAME kayıtları)
def check_dns(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        return [answer.to_text() for answer in answers]
    except:
        return None

# Disposable email kontrol fonksiyonu
def check_disposable_email(email):
    api_urls = {
        "Kickbox": f"https://open.kickbox.com/v1/disposable/{email}",
        "MailCheck": f"https://api.mailcheck.ai/email/{email}",
        "IsItRealEmail": f"https://isitarealemail.com/api/email/validate?email={email}",
        "Disify": f"https://checkmail.disify.com/api/email/{email}",
        "ValidatorPizza": f"https://www.validator.pizza/email/{email}",
    }
    
    results = {}
    disposable_count = 0
    not_disposable_count = 0

    for api_name, url in api_urls.items():
        try:
            response = requests.get(url)
            data = response.json()
            if "disposable" in data:
                results[api_name] = data['disposable']
            elif "valid" in data:
                results[api_name] = not data['valid']
            elif "status" in data:
                results[api_name] = data["status"] == "invalid"
            elif "deliverable" in data:
                results[api_name] = not data['deliverable']
            else:
                results[api_name] = "unknown"

            if results[api_name]:
                disposable_count += 1
            else:
                not_disposable_count += 1
        except Exception as e:
            results[api_name] = f"Error: {str(e)}"
    
    return results, disposable_count, not_disposable_count

# E-posta formatı kontrolü
def validate_email_format(email):
    regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(regex, email) is not None

# Web sitesi boyutu kontrolü
def check_site_size(domain):
    try:
        url = f"http://{domain}"
        response = requests.get(url, timeout=10)
        
        # Content-Length başlığı varsa doğrudan al
        content_length = response.headers.get('Content-Length')
        if content_length:
            size_mb = int(content_length) / (1024 * 1024)  # Byte'ı MB'a çeviriyoruz
        else:
            # Content-Length yoksa body boyutunu al
            size_mb = len(response.content) / (1024 * 1024)
        
        return size_mb
    except requests.RequestException:
        return None

# "Coming Soon" veya "Under Maintenance" kontrolü
def check_coming_soon(domain):
    try:
        url = f"http://{domain}"
        response = requests.get(url, timeout=10)  # Web sayfasına istek gönder
        if response.status_code == 200:  # Sayfa bulunduysa
            content = response.text.lower()
            if "coming soon" in content or "under maintenance" in content or "bakımda" in content or "yakında gelecek" in content:
                return True  # Sayfa bakım modunda
        return False
    except requests.RequestException:
        return False  # İstek başarısız olduysa False döndür

# Puanlama Sistemi
def calculate_score(email, domain):
    score = 100

    # SSL Sertifikası Let’s Encrypt ise 15 puan kır
    cert = check_ssl(domain)
    if cert and 'Let\'s Encrypt' in cert['issuer'][0]:
        score -= 15

    # Rastgele karakterlerle oluşturulmuş mail adı kontrolü (örnek: dfkj38@gmail.com)
    local_part = email.split('@')[0]
    if re.match(r'^[a-zA-Z]+$', local_part) is None:
        score -= 20

    return score

# Kontrol ve Puanlama Sistemi
def evaluate_email(email):
    domain = email.split('@')[1]
    uyarilar = []  # Uyarıları toplayacağımız liste

    # Argo kelimeler dosyasının yolu
    slang_file_path = 'turkish_slang.txt'
    slang_words = load_turkish_slang_words(slang_file_path)

    # 1. Whois kontrolü
    print(Fore.BLUE + "Whois Kontrolü:")
    whois_check = check_whois(domain)
    if whois_check:
        print(Fore.GREEN + "Domain 1 yıldan fazla süredir aktif.")
    else:
        print(Fore.RED + "Domain 1 yıldan kısa süredir aktif veya bilgi alınamadı.")
        uyarilar.append("Whois kontrolünde sorun: Domain 1 yıldan kısa sürede aktif.")
    print_line()
    
    # 2. SSL kontrolü
    print(Fore.BLUE + "SSL Sertifikası Kontrolü:")
    ssl_check = check_ssl(domain)
    if ssl_check:
        print(Fore.GREEN + "Sertifika mevcut.")
    else:
        print(Fore.RED + "Sertifika yok.")
        uyarilar.append("SSL sertifikası yok.")
    print_line()

    # 3. Coming Soon veya Under Maintenance kontrolü
    print(Fore.BLUE + "Coming Soon / Under Maintenance Kontrolü:")
    maintenance_check = check_coming_soon(domain)
    if maintenance_check:
        print(Fore.RED + "Site 'Coming Soon' veya 'Under Maintenance' modunda.")
        uyarilar.append("Site 'Coming Soon' veya 'Under Maintenance' modunda.")
    else:
        print(Fore.GREEN + "Site aktif durumda.")
    print_line()

    # 4. Web Sitesi Boyutu Kontrolü:
    print(Fore.BLUE + "Web Sitesi Boyutu Kontrolü:")
    site_size = check_site_size(domain)
    if site_size:
        print(Fore.GREEN + f"Site boyutu: {site_size:.2f} MB.")
        if site_size < 1.0:
            print(Fore.RED + "Uyarı: Site boyutu 1MB'den küçük, Coming Soon olabilir.")
            uyarilar.append("Site boyutu 1MB'den küçük, Coming Soon olabilir.")
    else:
        print(Fore.RED + "Site boyutu alınamadı.")
        uyarilar.append("Site boyutu alınamadı.")
    print_line()

    # 5. DNS Kontrolü (Varsayılan DNS)
    print(Fore.BLUE + "DNS Kontrolü:")
    dns_check = check_dns(domain)
    if dns_check:
        print(Fore.GREEN + f"DNS kayıtları: {', '.join(dns_check)}")
    else:
        print(Fore.RED + "DNS veya subdomain kayıtları yok.")
        uyarilar.append("DNS veya subdomain kayıtları yok.")
    print_line()

    # 7. Anahtar Kelime Kontrolü:
    print(Fore.BLUE + "Anahtar Kelime Kontrolü:")
    keyword_check = check_domain_keywords(email, domain)
    if keyword_check:
        print(Fore.RED + "Yasaklı anahtar kelimeler içeriyor.")
        uyarilar.append("Yasaklı anahtar kelimeler içeriyor.")
    else:
        print(Fore.GREEN + "Yasaklı anahtar kelimeler yok.")
    print_line()

    # 8. Türkçe Argo/Küfür Kontrolü:
    print(Fore.BLUE + "Argo/Küfür Kontrolü:")
    slang_check = check_turkish_slang(email, domain, slang_words)
    if slang_check:
        print(Fore.RED + "Argo veya küfür içeriyor.")
        uyarilar.append("Argo veya küfür içeriyor.")
    else:
        print(Fore.GREEN + "Argo veya küfür yok.")
    print_line()

    # 9. Rakam Kontrolü:
    print(Fore.BLUE + "Rakam Kontrolü:")
    digit_check = check_digit_count(email, domain)
    if digit_check:
        print(Fore.RED + "E-posta adresi veya domain 2'den fazla rakam içeriyor.")
        uyarilar.append("E-posta adresi veya domain 2'den fazla rakam içeriyor.")
    else:
        print(Fore.GREEN + "2'den fazla rakam içermiyor.")
    print_line()

    # 10. E-posta Formatı Kontrolü:
    print(Fore.BLUE + "E-posta Formatı Kontrolü:")
    format_check = validate_email_format(email)
    if format_check:
        print(Fore.GREEN + "E-posta formatı uygun.")
    else:
        print(Fore.RED + "E-posta formatı yanlış.")
        uyarilar.append("E-posta formatı yanlış.")
    print_line()

    # 11. Disposable Email Kontrolü:
    print(Fore.BLUE + "Disposable Email Kontrolü:")
    disposable_results, disposable_count, not_disposable_count = check_disposable_email(email)
    for api_name, result in disposable_results.items():
        color = Fore.GREEN if not result else Fore.RED
        status = "Disposable" if result else "Not Disposable"
        print(f"{color}{api_name}: {status}")
    
    # Uyarılar kısmına yalnızca disposable ise ekleme yapıyoruz
    if disposable_count > not_disposable_count:
        uyarilar.append("E-posta adresi disposable görünüyor.")
    
    print_line()

    # Tüm sonuçları ekrana bastıktan sonra, uyarıları en sonda listele
    if uyarilar:
        print(Fore.RED + "\n--- Uyarılar ---")
        for uyarı in uyarilar:
            print(Fore.RED + uyarı)
    else:
        print(Fore.GREEN + "Her şey yolunda, herhangi bir uyarı yok.")

# E-posta al ve kontrolleri başlat
def main():
    email = input(Fore.YELLOW + "Lütfen bir e-posta adresi girin: ")
    print_line()
    evaluate_email(email)

# Programı başlat
if __name__ == "__main__":
    main()
