import re

# http je aj samostatne
def check_http_methods(nginx_config):
    # Zoznam povolených metód HTTP
    allowed_http_methods = ["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"]

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

def analyze_nginx_config(config):
    config_dict = {}
    for line in config.splitlines():
        match = re.match(r'(\w+)\s+({.*})', line)
        if match:
            directive, value = match.groups()
            config_dict[directive] = value

    security_checks = [
        ('server_name', "Chýbajúci \"server_name\" pre identifikáciu virtuálneho hostiteľa"),
        ('listen', "Chýbajúci \"listen\" pre špecifikovanie počúvacích portov"),
        ('root', "Chýbajúci paramater \"root\" na špecifikovanie root adresára"),
        ('index', "Chýbajúci paramater \"index\" na špecifikovanie index súboru"),
        ('ssl_certificate', "Certifikát SSL nie je nakonfigurovaný (\"ssl_certificate\")"),
        ('ssl_certificate_key', "Klúč certifikátu SSL nie je nakonfigurovaný (\"ssl_certificate_key\")"),
        ('deny', "Chýbajúci prepínač \"deny\" na zamedzenie prístupu"),
        ('limit_conn', "Chýbajúci paramater \"limit_conn\" pre limitovanie pripojení"),
        ('limit_req', "Chýbajúci \"limit_req\" pre limitovanie požiadaviek"),
        ('worker_connections', "Chýba konfigurácia parametra \"worker_connections\"")
    ]

    efficiency_recommendations = [
        ('proxy_cache' not in config_dict.get('location /sample', ''),
         "Zvážte povolenie ukladania do vyrovnávacej pamäte pomocou \"proxy_cache\""),
        ('gzip' not in config_dict,
         "Zvážte povolenie \"gzip\" kompresie na zmešenie veľkosti odozvy"),
        ('keepalive_timeout' not in config_dict,
         "Zvážte nastavenie \"keepalive_timeout\" na udržiavanie HTTP spojení a redukciu latencie"),
        ('http2' not in config_dict,
         "Zvážte povolenie \"HTTP2\" protokolu pre zlepšenie výkonu"),
        ('expires' not in config_dict,
         "Zvážte povolenie \"expires\" na ukladanie statických prostriedkov na strane klienta"),
        ('client_max_body_size' not in config_dict,
         "Zvážte nastavenie \"client_max_body_size\" na limitovanie upload veľkosti")
    ]

    best_practices = [
        ('add_header' not in config,
         "Pridajte \"add_header\" bezpečtnostné hlavičky ako napríklad \n\"X-Content-Type-Options\", \"X-Frame-Options\",\"Content-Security-Policy\",...\n"),
        ('server_tokens' not in config,
         "Nastavte \"server_tokens off\" pre minimalizovanie úniku informácii\n"),
        ('access_log' not in config,
         "Konfigurujte \"access_log\" na ukladanie logov prístupu\n"),
        ('error_log' not in config,
         "Konfigurujte \"error_log\" na ukladanie error logov\n"),
        ('log_format' not in config,
         "Konfigurujte \"log_format\" na definovanie ukladania formátu logov\n"),
        ('content_security_policy' not in config,
         "Implementujte \"content_security_policy\" na obranu proti XSS útokom\n")
    ]

    output = ""
    for check in security_checks:
        if check[0] not in config:
            output += f"Bezpečnostné upozornenie: {check[1]}\n"
        elif check[0] == 'worker_connections':
            worker_connections_value = re.search(r'worker_connections\s+(\d+);', config)
            if worker_connections_value:
                connections = int(worker_connections_value.group(1))
                if connections < 1024:
                    output += "Bezpečnostné upozornenie: Hodnota \"worker_connections\" je nižšia ako 1024.\n"
            else:
                output += "Bezpečnostné upozornenie: Hodnota \"worker_connections\" nie je konfigurovaná.\n"

    for recommendation in efficiency_recommendations:
        if recommendation[0]:
            output += f"Odporúčania na zlepšenie výkonu: {recommendation[1]}\n"

    for practice in best_practices:
        if practice[0]:
            output += f"Bežná prax: {practice[1]}\n"

    fixed_config = config.strip()

    if 'server_name' not in config:
        fixed_config = fixed_config.replace('server {', 'server {\n    server_name example.com;')
    if 'listen' not in config:
        fixed_config = fixed_config.replace('server {', 'server {\n    listen 80;')
    if 'root' not in config:
        fixed_config = fixed_config.replace('server {', 'server {\n    root /var/www/html;')
    if 'index' not in config:
        fixed_config = fixed_config.replace('server {', 'server {\n    index index.html;')
    if 'ssl_certificate' not in config:
        fixed_config = fixed_config.replace('server {', 'server {\n    ssl_certificate /etc/nginx/ssl/certificate.crt;')
    if 'ssl_certificate_key' not in config:
        fixed_config = fixed_config.replace('server {', 'server {\n    ssl_certificate_key /etc/nginx/ssl/private.key;')
    if 'deny' not in config:
        fixed_config = fixed_config.replace('server {', 'server {\n    deny all;')
    if 'limit_conn' not in config:
        fixed_config = fixed_config.replace('server {',
                                            'server {\n    limit_conn_zone $binary_remote_addr zone=addr:10m;')
    if 'limit_req' not in config:
        fixed_config = fixed_config.replace('server {', 'server {\n    limit_req zone=reqs burst=10 nodelay;')

    print("~~~~~~~~~~~~~~~~~~~~~~~~")
    print("Čiastočne opravený config");
    print(fixed_config);
    print("~~~~~~~~~~~~~~~~~~~~~~~~")

    return output.strip()


# Example usage
nginx_config = """
upstream samplecluster {
    server localhost:8001;
    server localhost:8000;
}

events {
  worker_connections  512;
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

analysis_output = analyze_nginx_config(nginx_config)
print(analysis_output)
print("")
check_http_methods(nginx_config)
print("Čiastočne opravený konfig sa nachádza na začiatku výstupu.")