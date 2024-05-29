from flask import Flask, render_template, request
import whois
import socket
import dns.resolver
import requests

app = Flask(__name__)

# VirusTotal API Key
API_KEY = '7c7063a8507b02c5a285b6142e1e4e0ca56ee373607251c40e31a10be8bf18d2'

# IPInfo API Key
IPINFO_API_KEY = 'c0ec2816fd3065'

def get_domain_info(domain_name):
    domain_info = whois.whois(domain_name)
    extracted_info = {
        "domain_name": domain_info.domain_name,
        "registrar": domain_info.registrar,
        "registrar_url": domain_info.registrar_url,
        "registrar_iana": domain_info.registrar_iana,
        "updated_date": domain_info.updated_date,
        "creation_date": domain_info.creation_date.strftime('%a, %d %b %Y %H:%M:%S GMT') if domain_info.creation_date else None,
        "expiration_date": domain_info.expiration_date,
        "name_servers": domain_info.name_servers,
        "organization": domain_info.org,
        "state": domain_info.state,
        "status": domain_info.status,
        "emails": domain_info.emails,
        "country": domain_info.country,
        "dnssec": domain_info.dnssec,
    }
    try:
        ip_address = socket.gethostbyname(domain_name)
        extracted_info['ip_address'] = ip_address
    except socket.gaierror:
        extracted_info['ip_address'] = None

    try:
        dns_records = dns.resolver.resolve(domain_name, 'A')
        extracted_info['dns_records'] = [record.address for record in dns_records]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        extracted_info['dns_records'] = None

    return extracted_info

def get_location_and_virustotal_info(domain):
    result = {}
    try:
        ip_address = socket.gethostbyname(domain)
        ipinfo_url = f"http://ipinfo.io/{ip_address}/json?token={IPINFO_API_KEY}"
        response_ipinfo = requests.get(ipinfo_url)
        data_ipinfo = response_ipinfo.json()

        vt_url = f'https://www.virustotal.com/api/v3/domains/{domain}'
        headers = {'x-apikey': API_KEY}
        try:
            response_vt = requests.get(vt_url, headers=headers)
            response_vt.raise_for_status()
            data_vt = response_vt.json()
            vt_data = data_vt.get('data', {})
            vt_attributes = vt_data.get('attributes', {})
            result['virustotal_info'] = {
                "domain": vt_data.get("id"),
                "malicious": vt_attributes.get("last_analysis_stats", {}).get("malicious"),
                "suspicious": vt_attributes.get("last_analysis_stats", {}).get("suspicious"),
                "harmless": vt_attributes.get("last_analysis_stats", {}).get("harmless"),
                "undetected": vt_attributes.get("last_analysis_stats", {}).get("undetected"),
                "categories": vt_attributes.get("categories"),
            }
        except requests.RequestException as e:
            result['virustotal_error'] = str(e)

        if "error" in data_ipinfo:
            result['error'] = data_ipinfo['error']['message']
        else:
            result['domain_info'] = get_domain_info(domain)
            result['location_info'] = {
                "ip": data_ipinfo.get("ip"),
                "city": data_ipinfo.get("city"),
                "region": data_ipinfo.get("region"),
                "country": data_ipinfo.get("country"),
                "org": data_ipinfo.get("org"),
            }
    except (socket.gaierror, requests.exceptions.RequestException) as e:
        result['error'] = str(e)

    return result

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        domain = request.form['domain']
        data = get_location_and_virustotal_info(domain)
        return render_template('index.html', data=data, domain=domain)
    return render_template('index.html', data={}, domain=None)

if __name__ == '__main__':
    app.run(debug=True)