from enum import IntEnum

server_port = 67
client_port = 68


class Mesaje(IntEnum):
    none = 0
    Discover = 1
    Offer = 2
    Request = 3
    Pack = 4
    Pnak = 5
    Decline = 6
    Release = 7
    Inform = 8


class Opcode(IntEnum):
    none = 0
    Request = 1
    Reply = 2


class Optiuni(IntEnum):
    PADDING = 0
    SUBNETMASK = 1
    ROUTER = 3
    SERVER_NAME = 5
    DNS = 6
    BROADCAST_ADDRESS = 28
    REQUESTED_IP = 50
    LEASE_TIME = 51
    MESSAGE_TYPE = 53
    PARAM_REQ_LIST = 55
    RENEWAL_TIME = 58
    REBINDING_TIME = 59
    CLIENT_ID = 61
    END = 255


class Pachete:
    def setare_masca_subretelei(self, masca_subretelei):
        try:
            int(masca_subretelei)
            import ipaddress
            net = ipaddress.ip_network('192.178.2.55/{}'.format(masca_subretelei), strict=False)
            self.masca_subretelei = str(net.netmask)
        except (ValueError, TypeError):
            self.masca_subretelei = masca_subretelei


class Server:
    def __init__(self, gui=None):
        self.ip = '0.0.0.0'
        self.destinatie = ('255.255.255.255', client_port)
        self.nume = None
        self.address_pool = {}
        self.ip_vechi = {}
        self.adresa_inceput = None
        self.masca_retelei = None
        self.adresa_difuzie = None
        self.lease_time = None
        self.timp_reinoire = None
        self.rebinding_time = None
        self.gui = gui

    def configurare_gama_adrese(self, adresa_ip, masca):
        self.adresa_inceput = adresa_ip
        self.masca_retelei = masca

    @staticmethod
    def update_ip(ip1, ip2, ip3, ip4, minim=0, maxim=256):
        ip4 += 1
        if ip4 == maxim:
            ip4 = minim
            ip3 += 1
        if ip3 == maxim:
            ip3 = minim
            ip2 += 1
        if ip2 == maxim:
            ip2 = minim
            ip1 += 1
        if ip1 == maxim:
            ip1 = minim
        return ip1, ip2, ip3, ip4

    def setare_lease_time(self, valoare):
        self.lease_time = valoare
        self.timp_reinoire = valoare//2
        self.rebinding_time = valoare*7//8

    def gama_adrese(self):
        self.address_pool, self.adresa_difuzie = self.calculare_adrese(self.adresa_inceput, self.masca_retelei)
        for ip in self.address_pool.keys():
            self.ip_vechi.update({ip: None})
        print(self.address_pool)

    @staticmethod
    def calculare_adrese(adresa_inceput, masca):
        gama_adrese = {}
        numar_adrese = 2 ** (32 - masca) - 2
        ip1, ip2, ip3, ip4 = [int(s) for s in adresa_inceput.split('.')]
        ip1, ip2, ip3, ip4 = Server.update_ip(ip1, ip2, ip3, ip4)
        for i in range(numar_adrese):
            gama_adrese.update({"{}.{}.{}.{}".format(ip1, ip2, ip3, ip4): {'mac': None, 'time': None}})
            ip1, ip2, ip3, ip4 = Server.update_ip(ip1, ip2, ip3, ip4)
        adresa_difuzie = "{}.{}.{}.{}".format(ip1, ip2, ip3, ip4)
        return gama_adrese, adresa_difuzie
