import re
def analyze_nginx_config(nginx_config):
    if not nginx_config:
        raise ValueError("Parameter nginx_config musí byť neprázdny reťazec.")

    # Bad proxy
    insecure_proxy_settings = re.findall(r'proxy_set_header\s+(?!X-Real-IP|X-Forwarded-For|X-Forwarded-Proto)',
                                         nginx_config)

    # Forwarding error
    redirect_risk = re.search(r'return\s+302', nginx_config)

    # Kontrola HTTP TRACE
    trace_method_enabled = re.search(r'add_header\s+Allow\s+"TRACE"', nginx_config)

    # Kontrola SSL protokolov
    weak_ssl_protocols = re.findall(r'ssl_protocols\s+(SSLv2|SSLv3)', nginx_config)

    # Kontrola server info
    server_info_exposure = re.search(r'server_tokens\s+(on|build)', nginx_config)

    # Kontrola location
    insecure_path_traversal = re.findall(r'location\s+/\.\.', nginx_config)

    if insecure_proxy_settings:
        print("Upozornenie: Nezabezpečené proxy nastavenia môžu predstavovať riziko.")
    else:
        print("Proxy nastavenia sú zabezpečené.")

    if redirect_risk:
        print("Upozornenie: Existuje možnosť nezabezpečeného presmerovania.")
    else:
        print("Presmerovanie je zabezpečené.")

    if weak_ssl_protocols:
        print("Upozornenie: Používajú sa zastarané alebo slabé SSLv2/SSLv3/TLS protokoly.")
    else:
        print("SSL/TLS protokoly v poriadku.")

    if server_info_exposure:
        print("Upozornenie: Informácie o serveri sú exponované v HTTP hlavičkách.")
    else:
        print("Serverové hlavičky sú OK.")

    if insecure_path_traversal:
        print("Upozornenie: Nájdené sú nezabezpečené cesty na prechádzanie.")
    else:
        print("Cesty na prechádzanie sú zabezpečené.")

nginx_config = """upstream samplecluster {
    server localhost:8001;
    server localhost:8000;
}

server {
    listen 81;
    listen [::]:81;

    server_name example.ubuntu.com;

    root /var/www/tutorial;
    index index.html;

    location / {
        try_files $uri $uri/ =404;
    }

    location /sample {
        proxy_pass http://samplecluster/;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_next_upstream error timeout invalid_header http_500 http_502 http_503 http_504;
        proxy_set_header Host $host;
        proxy_redirect off;
        proxy_buffering off;
        proxy_cache off;
    }
}"""

# Spusti analýzu na zadanom konfiguračnom súbore
analyze_nginx_config(nginx_config)