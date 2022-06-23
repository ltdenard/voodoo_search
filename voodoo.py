#!/home/ldenard/env/bin/python
import os
import re
import csv
import netaddr
import requests
import socket
import shodan
import validators

#TODOs
# migrate lambdas: 
# screenshot, sourcecode, tlsscan

class Voodoo:
    def __init__(self, **kwargs):
        self.column_width = 50
        self.hibp_key = ""
        if os.environ.get("HIBPKEY"):
            self.hibp_key = os.environ.get("HIBPKEY")
        elif kwargs.get("HIBPKEY"):
            self.hibp_key = kwargs.get("HIBPKEY")
        self.shodan_key = ""
        if os.environ.get("SHODANKEY"):
            self.shodan_key = os.environ.get("SHODANKEY")
        elif kwargs.get("SHODANKEY"):
            self.shodan_key = kwargs.get("SHODANKEY")
        self.securitytrails_key = ""
        if os.environ.get("SECURITYTRAILSKEY"):
            self.securitytrails_key = os.environ.get("SECURITYTRAILSKEY")
        elif kwargs.get("SECURITYTRAILSKEY"):
            self.securitytrails_key = kwargs.get("SECURITYTRAILSKEY")

    def ip_check(self, ip_addr):
        ip_match = re.compile(
            r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$')
        if ip_match.match(ip_addr):
            return True
        return False

    def private_ip_check(self, ip_addr):
        ip_match = re.compile(
            r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$')
        if ip_match.match(ip_addr):
            if netaddr.IPAddress(ip_addr).is_private(
            ) or netaddr.IPAddress(ip_addr).is_reserved():
                return True
        return False

    def cve_check(self, cve_num):
        cve_match = re.compile('^(CVE|cve)-[0-9]{4}-[0-9]{4,10}$')
        if cve_match.match(cve_num):
            return True
        return False

    def email_check(self, email_addr):
        try:
            user_regex = re.compile(
                # dot-atom
                r"(^[-!#$%&'*+/=?^_`{}|~0-9A-Z]+(\.[-!#$%&'*+/=?^_`{}|~0-9A-Z]+)*\Z"
                # quoted-string
                r'|^"([\001-\010\013\014\016-\037!#-\[\]-\177]|\\[\001-\011\013\014\016-\177])'
                r'*"\Z)',
                re.IGNORECASE,
            )
            domain_regex = re.compile(
                # max length for domain name labels is 63 characters per RFC 1034
                r"((?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+)(?:[A-Z0-9-]{2,63}(?<!-))\Z",
                re.IGNORECASE,
            )
            user_part, domain_part = email_addr.rsplit("@", 1)
            if user_regex.match(user_part) and domain_regex.match(domain_part):
                return True
        except:
            pass
        return False
    
    def domain_check(self, domain_name):
        if validators.domain(domain_name):
            return True
        return False

    def whois_request(self, ipaddr, server, port=43):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((server, port))
        ###############################################################
        # some whois servers need parameters that not part of the RFC #
        # de.whois-servers.net = '-T dn,ace domain.com'               #
        # jp.whois-servers.net = 'DOM domain.com/e'                   #
        ###############################################################
        if ipaddr.endswith('.de') and server == 'whois.denic.de':
            sock.send(("-T dn,ace {}\r\n".format(ipaddr)).encode("utf-8"))
        elif ipaddr.endswith('.jp') and server == 'whois.jprs.jp':
            sock.send(("DOM {}/e\r\n".format(ipaddr)).encode("utf-8"))
        elif server == 'whois.cymru.com':
            sock.send(("-v {}\r\n".format(ipaddr)).encode("utf-8"))
        elif server == 'whois.arin.net':
            sock.send(("+ {}\r\n".format(ipaddr)).encode("utf-8"))
        else:
            sock.send(("{}\r\n".format(ipaddr)).encode("utf-8"))
        buff = b""
        while True:
            data = sock.recv(1024)
            if len(data) == 0:
                break
            buff += data
        return buff.decode("utf-8")
    
    def generate_ascii_table(self, header_name, table_data):
        center_distance = int((self.column_width - len(header_name))/2)
        header = "="*self.column_width
        header += "\n"
        header += " "*center_distance
        header += header_name
        header += " "*center_distance
        header += "\n"
        header += "="*self.column_width
        header += "\n"
        header += table_data
        header += "\n"
        header += "="*self.column_width
        header += "\n"
        return header

    def get_whois(self, ip_addr):
        if self.domain_check(ip_addr) or (self.ip_check(ip_addr) and not self.private_ip_check(ip_addr)):
            try:
                iana_data = self.whois_request(ip_addr, 'whois.iana.org', 43)
                refer = [
                    l.split(':')[1].strip().replace(
                        'whois://',
                        '') for l in iana_data.splitlines() if l.startswith('refer:') or l.startswith('ReferralServer:')][0]
                whois_data = self.whois_request(ip_addr, refer, 43)
                if 'RIPE' in whois_data:
                    whois_data = self.whois_request(ip_addr, 'whois.ripe.net', 43)
                return whois_data
            except BaseException:
                return
        return
    
    def whois_table(self, search_term):
        whois_result = self.get_whois(search_term)
        if whois_result:
            stripped_data = [l for l in whois_result.splitlines() if ":" in l]
            header_name = "WHOIS"
            table_data = "\n".join(stripped_data)
            return self.generate_ascii_table(header_name, table_data)
        return "No Results."

    def get_asn(self, ip_addr):
        if self.ip_check(ip_addr) and not self.private_ip_check(ip_addr):
            asn_str = self.whois_request(ip_addr, 'whois.cymru.com')
            readerpipe = csv.DictReader(asn_str.split("\n"), delimiter='|')
            return_data = list(readerpipe)
            tmp_dict_list = []
            for d in return_data:
                tmp_dict = {}
                for k, v in d.items():
                    tmp_dict.update({
                        k.strip(): v.strip()
                    })
                tmp_dict_list.append(tmp_dict)
            if tmp_dict_list:
                return tmp_dict_list
        return
    
    def asn_table(self, search_term):
        asn_result = self.get_asn(search_term)
        if asn_result:
            formatted_data = []
            for asn_dict in asn_result:
                for k,v in asn_dict.items():
                    formatted_data.append("{}: {}".format(k,v))
            header_name = "ASN"
            table_data = "\n".join(formatted_data)
            return self.generate_ascii_table(header_name, table_data)
        return "No Results."

    def get_cve_data(self, cve_num):
        url = "https://cve.circl.lu/api/cve/"
        headers = {
            "Content-Type": "application/json"
        }
        if self.cve_check(cve_num):
            response = requests.get(
                "{}{}".format(
                    url, cve_num), headers=headers)
            if response.ok:
                response_data = response.json()
                return response_data
        return
    
    def cve_table(self, cve_num):
        cve_data = self.get_cve_data(cve_num)
        if cve_data:
            header_name = "CVE"
            stripped_data = [
                "CVSS: {}".format(cve_data.get("cvss")),
                "Published: {}".format(cve_data.get("Published")),
                "Modified: {}".format(cve_data.get("Modified")),
                "Summary: {}".format(cve_data.get("summary")),
                "Link: https://cve.circl.lu/cve/{}".format(cve_num.upper()),
            ]
            table_data = "\n".join(stripped_data)
            return self.generate_ascii_table(header_name, table_data)
        return "No Results."

    def get_greynoise(self, ip_addr):
        url = "https://api.greynoise.io/v3/community/"
        headers = {"Accept": "application/json"}
        if self.ip_check(ip_addr) and not self.private_ip_check(ip_addr):
            response = requests.get(
                "{}{}".format(
                    url, ip_addr), headers=headers)
            response_data = response.json()
            return response_data
        return
    
    def greynoise_table(self, ip_addr):
        greynoise_data = self.get_greynoise(ip_addr)
        if greynoise_data:
            header_name = "Greynoise"
            stripped_data = ["{}: {}".format(k,v) for k,v in greynoise_data.items()]
            table_data = "\n".join(stripped_data)
            return self.generate_ascii_table(header_name, table_data)
        return "No Results."

    def get_haveibeenpwned_result(self, email_addr):
        hibp_headers = {
            "Content-Type": "application/json",
            "hibp-api-key": self.hibp_key
        }
        if self.email_check(email_addr):
            response = requests.get(
                "https://haveibeenpwned.com/api/v3/breachedaccount/{}?truncateResponse=false".format(email_addr),
                headers=hibp_headers)
            if response.status_code == 200:
                return response.json()
        return
    
    def haveibeenpwned_table(self, email_addr):
        haveibeenpwned_data = self.get_haveibeenpwned_result(email_addr)
        if haveibeenpwned_data:
            header_name = "Have I Been Pwned"
            stripped_data = []
            for d in haveibeenpwned_data:
                tmp_list = []
                for k,v in d.items():
                    if k in [
                        "Title",
                        "Domain",
                        "BreachDate",
                        "PwnCount",
                        "DataClasses"
                    ]:
                        if isinstance(v, list):
                            tmp_list.append("{}: {}".format(k,",".join(v)))
                        else:
                            tmp_list.append("{}: {}".format(k,v))
                stripped_data.append(tmp_list)
            table_data = ("\n" + "-"*self.column_width + "\n").join(["\n".join(l) for l in stripped_data])
            return self.generate_ascii_table(header_name, table_data)
        return "No Results."


    def get_securitytails_pdns(self, ip_addr):
        url = "https://api.securitytrails.com/v1/domains/list"
        querystring = {"include_ips": "false", "scroll": "false"}
        headers = {
            "Content-Type": "application/json",
            "APIKEY": self.securitytrails_key
        }
        if self.ip_check(ip_addr) and not self.private_ip_check(ip_addr):
            payload = {"filter": {"ipv4": ip_addr}}
            response = requests.post(
                url,
                json=payload,
                headers=headers,
                params=querystring)
            if response.ok:
                response_data = response.json()
                return response_data
        return 
    
    def pdns_table(self, ip_addr):
        pdns_results = self.get_securitytails_pdns(ip_addr)
        if pdns_results:
            record_count = pdns_results.get("record_count")
            if record_count > 0:
                header_name = "Passive DNS"
                table_data = "Total Records: {}\n".format(record_count)
                stripped_data = [d.get("hostname") for d in pdns_results.get("records")[:10]]
                table_data += "Last 10:\n  "
                table_data += "\n  ".join(stripped_data)
                return self.generate_ascii_table(header_name, table_data)
        return "No Results."
    
    def get_shodan_data(self, ip_addr):
        api = shodan.Shodan(self.shodan_key)
        host_info = {}
        service_results = []
        if self.ip_check(ip_addr) and not self.private_ip_check(ip_addr):
            try:
                host = api.host(ip_addr)
            except shodan.exception.APIError:
                return None,None
            host_info = {
                    "IP": host.get('ip_str'),
                    "Organization": host.get('org', 'n/a'),
                    "Operating System": host.get('os', 'n/a')
                }
            for item in host['data']:
                service_dict = {
                    "Port": item.get('port'),
                    "Banner": item.get('data')
                }
                if service_dict:
                    service_results.append(service_dict)
        return host_info,service_results
    
    def shodan_table(self, ip_addr):
        host_info_dict, service_results_list = self.get_shodan_data(ip_addr)
        if host_info_dict:
            header_name = "Shodan"
            table_data = ""
            for k,v in host_info_dict.items():
                table_data += "{}: {}\n".format(k,v)
            if service_results_list:
                table_data += "Services: \n"
                for service_dict in service_results_list:
                    for k,v in service_dict.items():
                        tmp_value = str(v).strip().replace("\n", "\n          ")
                        table_data += "  {}: {}\n".format(k,tmp_value)
            return self.generate_ascii_table(header_name, table_data)
        return "No Results."

    def get_internetdb_result(self, ip_addr):
        if self.ip_check(ip_addr) and not self.private_ip_check(ip_addr):
            ip_addr_obj = netaddr.IPAddress(ip_addr)
            if ip_addr_obj.is_unicast() and not ip_addr_obj.is_private():
                response = requests.get(
                    "https://internetdb.shodan.io/{}".format(ip_addr))
                if response.status_code == 200:
                    return response.json()
        return
    
    def internetdb_table(self, ip_addr):
        host_info_dict = self.get_internetdb_result(ip_addr)
        if host_info_dict:
            header_name = "InternetDB"
            table_data = ""
            for k,v in host_info_dict.items():
                if isinstance(v, list):
                    tmp_values_list = list(map(str, v))
                    table_data += "{}: {}\n".format(k,"\n       ".join(tmp_values_list))
                else:
                    table_data += "{}: {}\n".format(k,v)
            return self.generate_ascii_table(header_name, table_data)
        return "No results."
    
    def ascii_results_table(self, search_value, short_version):
        results_list = []
        if self.cve_check(search_value):
            cve_result = self.cve_table(search_value)
            if cve_result:
                results_list.append(cve_result)
        if self.email_check(search_value):
            hibp_result = self.haveibeenpwned_table(search_value)
            if hibp_result:
                results_list.append(hibp_result)
        if self.ip_check(search_value) and not self.private_ip_check(search_value):
            asn_result = self.asn_table(search_value)
            if asn_result:
                results_list.append(asn_result)
            greynoise_result = self.greynoise_table(search_value)
            if greynoise_result:
                results_list.append(greynoise_result)
            internetdb_result = self.internetdb_table(search_value)
            if internetdb_result:
                results_list.append(internetdb_result)
            if not short_version:
                whois_result = self.whois_table(search_value)
                if whois_result:
                    results_list.append(whois_result)
                greynoise_result = self.greynoise_table(search_value)
                if greynoise_result:
                    results_list.append(greynoise_result)
                pdns_result = self.pdns_table(search_value)
                if pdns_result:
                    results_list.append(pdns_result)
                shodan_result = self.shodan_table(search_value)
                if shodan_result:
                    results_list.append(shodan_result)
        if self.private_ip_check(search_value):
            results_list.append("\nRFC1918 Address\n")
        if results_list:
            return "\n".join(results_list)
        






if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Voodoo Search')
    parser.add_argument('searchterm', help='input an IP, email address, or CVE to retrieve data on.')
    parser.add_argument('-s', action='store_true', help='short version of output for ASN, PDNS, InternetDB')
    args = parser.parse_args()
    search_term = args.searchterm
    short_version = args.s
    obj = Voodoo()
    print(obj.ascii_results_table(search_term, short_version))
