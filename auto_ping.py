import time
import requests

domain = "https://portfolio-website-okv1.onrender.com/"
interval = 120  # detik, artinya ping setiap 2 menit

while True:
    try:
        response = requests.get(domain, timeout=5)
        print(f"✅ {domain} HTTP Status: {response.status_code}")
    except requests.RequestException:
        print(f"❌ Tidak bisa mengakses {domain}")
    
    print(f"Menunggu {interval} detik sebelum ping lagi...\n")
    time.sleep(interval)
