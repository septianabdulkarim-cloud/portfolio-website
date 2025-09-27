import time
import socket
import requests
import dns.resolver

domain = "jaswebcom.my.id"
port_http = 80
port_https = 443
check_interval = 60  # detik, bisa diganti sesuai keinginan

def check_dns():
    try:
        answers = dns.resolver.resolve(domain, 'A')
        ip_list = [rdata.address for rdata in answers]
        print(f"✅ DNS resolve: {domain} -> {', '.join(ip_list)}")
        return True
    except Exception as e:
        print(f"❌ DNS error: {e}")
        return False

def check_port(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((domain, port))
        print(f"✅ Port {port} terbuka")
        return True
    except:
        print(f"❌ Port {port} tertutup")
        return False
    finally:
        sock.close()

def check_http(protocol="http"):
    try:
        r = requests.get(f"{protocol}://{domain}", timeout=5)
        print(f"✅ {protocol.upper()} Status: {r.status_code}")
        return True
    except:
        print(f"❌ {protocol.upper()} tidak bisa diakses")
        return False

print(f"Mulai memantau domain {domain} setiap {check_interval} detik...\n")

while True:
    dns_ok = check_dns()
    port_http_ok = check_port(port_http)
    port_https_ok = check_port(port_https)
    http_ok = check_http("http")
    https_ok = check_http("https")

    if dns_ok and (http_ok or https_ok) and (port_http_ok or port_https_ok):
        print(f"\n🎉 Domain {domain} kemungkinan sudah aktif!")
        break
    else:
        print("\nDomain belum aktif sepenuhnya, cek lagi nanti...\n")
        time.sleep(check_interval)
