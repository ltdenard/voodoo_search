import unittest
import warnings
from voodoo import Voodoo
voodoo_obj = Voodoo()


class TestVoodoo(unittest.TestCase):
    
    def setUp(self):
        warnings.simplefilter("ignore", ResourceWarning)

    def tearDown(self):
        warnings.simplefilter("default", ResourceWarning)
    
    def test_get_whois_domain(self):
        whois_data = voodoo_obj.get_whois("cloudflare.com")
        return_status = False
        if "domain name: cloudflare.com" in whois_data.lower():
            return_status = True
        self.assertTrue(return_status)

    def test_get_whois(self):
        whois_data = voodoo_obj.get_whois("1.1.1.1")
        return_status = False
        if "cloudflare" in whois_data.lower():
            return_status = True
        self.assertTrue(return_status)

    def test_get_asn(self):
        asn_data = voodoo_obj.get_asn("1.1.1.1")
        return_status = False
        if asn_data[0].get("AS Name") == "CLOUDFLARENET, US":
            return_status = True
        self.assertTrue(return_status)

    def test_get_cve_data(self):
        cve_data = voodoo_obj.get_cve_data("cve-2021-44228").get("id")
        return_status = False
        if cve_data.lower() == 'cve-2021-44228':
            return_status = True
        self.assertTrue(return_status)

    def test_get_greynoise(self):
        greynoise_data = voodoo_obj.get_greynoise("1.1.1.1").get("name")
        return_status = False
        if greynoise_data.lower() == 'cloudflare public dns':
            return_status = True
        self.assertTrue(return_status)

    def test_get_haveibeenpwned(self):
        hibp_data = voodoo_obj.get_haveibeenpwned_result(
            "ltdenard@gmail.com")[0].get("Name")
        return_status = False
        if hibp_data.lower() == 'adobe':
            return_status = True
        self.assertTrue(return_status)

    def test_get_securitytails_pdns(self):
        pdns_data = voodoo_obj.get_securitytails_pdns("1.1.1.1").get("meta")
        return_status = False
        if pdns_data:
            return_status = True
        self.assertTrue(return_status)

    def test_get_shodan_data(self):
        shodan_host_data, shodan_service_data = voodoo_obj.get_shodan_data(
            "1.1.1.1")
        return_status = False
        if "cloudflare" in shodan_host_data.get("Organization").lower() and 53 in [
                d.get("Port") for d in shodan_service_data]:
            return_status = True
        self.assertTrue(return_status)

    def test_get_internetdb(self):
        internetdb_data = voodoo_obj.get_internetdb_result("1.1.1.1").get("ip")
        return_status = False
        if internetdb_data == "1.1.1.1":
            return_status = True
        self.assertTrue(return_status)


if __name__ == '__main__':
    unittest.main()
