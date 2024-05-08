import re

def check_http_methods(nginx_config):
    # put, delete, trace zakázané
    allowed_http_methods = ["GET", "HEAD", "POST", "CONNECT", "OPTIONS", "PATCH"]

    http_methods_pattern = r'allow\s+(.+?);'

    allowed_methods_match = re.findall(http_methods_pattern, nginx_config, re.DOTALL)
    if allowed_methods_match:
        for methods in allowed_methods_match:
            methods_list = re.split(r'\s*,\s*', methods.strip())
            for method in methods_list:
                if method.upper() not in allowed_http_methods:
                    print(f"Upozornenie: Nebezpečná metóda HTTP '{method}' je povolená.")
    else:
        print("Žiadne povolené metódy HTTP neboli nájdené.")

nginx_config = """
upstream samplecluster {
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
}
"""

# Spustenie kontroly na zadanom konfiguračnom súbore
check_http_methods(nginx_config)