
# This is the part of "Domain Tracking Program"
# It is work to qeury the 'Whois' info from DNS and IP
# self.DBList is the result parsing Whois qeury
# But It is excluded the "Sub Domain List". if you need, Verify the code for free

### Here is the parsing Header
# "Domain" : "",
# "IP" : "",
# "SubDomainList" : [],
# "RegisterWhoisServer" : "",
# "RegisterEmail" : "",
# "AdminEmail" : "",
# "AdminPhone" : "",

### Here is the Key Result
# Ex)Naver.com

"""Registrar WHOIS Server : whois.gabia.com

Domain Name: naver.com
Registry Domain ID: 793803_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.gabia.com
Registrar URL: http://www.gabia.com
Updated Date: 2018-02-28T11:27:15Z
Creation Date: 1997-09-12T00:00:00Z
Registrar Registration Expiration Date: 2023-09-11T00:00:00Z
Registrar: Gabia, Inc.
Registrar IANA ID: 244
Reseller:
Domain Status: ok https://icann.org/epp#ok
Registry Registrant ID: Not Available From Registry
Registrant Name: NAVER Corp.
Registrant Organization: NAVER Corp.
Registrant Street: 6 Buljung-ro, Bundang-gu, Seongnam-si, Gyeonggi-do, 463-867, Korea
Registrant City: Gyeonggi
Registrant State/Province:
Registrant Postal Code: 463463
Registrant Country: KR
Registrant Phone: +82.215883829
Registrant Phone Ext:
Registrant Fax: +82.317841000
Registrant Fax Ext:
Registrant Email: white.4818(=)navercorp.com
Registry Admin ID: Not Available From Registry
Admin Name: NAVER Corp.
Admin Organization:
Admin Street: 6, Buljeong-ro, Bundang-gu, Seongnam-si, Gyeonggi-do
Admin City: Gyeonggi
Admin State/Province:
Admin Postal Code: 13561
Admin Country: KR
Admin Phone: +82.28293528
Admin Phone Ext:
Admin Fax:
Admin Fax Ext:
Admin Email: dl_ssl(=)navercorp.com
Registry Tech ID: Not Available From Registry
Tech Name: NAVER Corp.
Tech Organization:
Tech Street: 6, Buljeong-ro, Bundang-gu, Seongnam-si, Gyeonggi-do
Tech City: Gyeonggi
Tech State/Province:
Tech Postal Code: 13561
Tech Country: KR
Tech Phone: +82.28293528
Tech Phone Ext:
Tech Fax:
Tech Fax Ext:
Tech Email: dl_ssl(=)navercorp.com
Name Server: ns1.naver.com
Name Server: ns2.naver.com
DNSSEC: unsigned
Registrar Abuse Contact Email: abuse(=)gabia.com
Registrar Abuse Contact Phone: +82.8293543
URL of the ICANN WHOIS Data Problem Reporting System: http://wdprs.internic.net/
"""

## IP Query
"""inetnum:	210.89.160.0 - 210.89.191.255
netname:	NBP-NET
descr:	NBP
admin-c:	IM681-AP
tech-c:	IM681-AP
country:	KR
status:	ALLOCATED PORTABLE
mnt-by:	MNT-KRNIC-AP
mnt-irt:	IRT-KRNIC-KR
last-modified:	2018-04-13T06:52:58Z
source:	APNIC
irt:	IRT-KRNIC-KR
address:	Seocho-ro 398, Seocho-gu, Seoul, Korea
e-mail:	hostmaster@nic.or.kr
abuse-mailbox:	hostmaster@nic.or.kr
admin-c:	IM574-AP
tech-c:	IM574-AP
auth:	# Filtered
mnt-by:	MNT-KRNIC-AP
last-modified:	2017-10-19T07:36:36Z
source:	APNIC
Report invalid contact
person:	IP Manager
address:	Gyeonggi-do Bundang-gu, Seongnam-si Buljeong-ro 6
country:	KR
phone:	+82-31-1588-3820
e-mail:	dl_noc@navercorp.com
nic-hdl:	IM681-AP
mnt-by:	MNT-KRNIC-AP
last-modified:	2017-11-23T07:30:58Z
source:	APNIC
Report invalid contact
% Information related to '210.89.160.0 - 210.89.191.255'
inetnum:	210.89.160.0 - 210.89.191.255
netname:	NBP-NET-KR
descr:	NBP
country:	KR
admin-c:	TS411-KR
tech-c:	TS411-KR
status:	ALLOCATED PORTABLE
mnt-by:	MNT-KRNIC-AP
mnt-irt:	IRT-KRNIC-KR
remarks:	This information has been partially mirrored by APNIC from
remarks:	KRNIC. To obtain more specific information, please use the
remarks:	KRNIC whois server at whois.krnic.net.
changed:	hostmaster@nic.or.kr
source:	KRNIC
person:	IP Manager
address:	Gyeonggi-do Bundang-gu, Seongnam-si Buljeong-ro 6
address:	6
country:	KR
phone:	+82-31-1588-3820
e-mail:	dl_noc@navercorp.com
nic-hdl:	TS411-KR
mnt-by:	MNT-KRNIC-AP
changed:	hostmaster@nic.or.kr
source:	KRNIC
"""

# This is Whois Qeury Server List
#Server_List = ['whois.arin.net', 'whois.ripe.net', 'whois.apnic.net', 'whois.lacnic']
# Socket module import
import socket
# IP Query Class
class WhoIsQuery:
    def __init__(self,DNS):
        self.Host = DNS
        self.HostIP = socket.gethostbyname(self.Host)
        self.IPWhoIsQueryInfo()
        self.DNSWhoIsQueryInfo()

        self.DBList = []
        for IPQueryList in self.IPQueryList:
            self.Data = IPQueryList.strip()
            self.Data = self.Data.split("  ")
            self.Data = self.Data[0] + self.Data[-1]
            self.DBList.append(self.Data)
        for DnsQueryList in self.DnsQueryList:
            self.Data = DnsQueryList.strip()
            self.Data = self.Data.split("  ")
            self.Data = self.Data[0] + self.Data[-1]
            self.DBList.append(self.Data)


    # IP Whois Query
    def IPWhoIsQueryInfo(self):
        # Socket Settings and Query
        self.IPSocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        try:
            self.IPSocket.connect(("whois.apnic.net", 43))
        except ConnectionRefusedError as e:
            self.IPSocket.close()
            print(e)
        except TimeoutError as t:
            self.IPSocket.close()
            print(t)
        except socket.gaierror as sg:
            self.IPSocket.close()
            print(sg)
        else:
            self.sendIpData_And_getResponse()

    # Get Ip Query response
    def sendIpData_And_getResponse(self):
        self.IPSocket.send((self.HostIP + "\r\n").encode())
        self.Res = ""
        while True:
            self.Data = self.IPSocket.recv(2048)
            if self.Data:
                self.Res += self.Data.decode()
            else:
                break
        if "no entries found" in self.Res:
            print("ERROR: No Entries Found")
        elif "ERROR:101" in self.Res:
            print("ERROR: No Entries Found")
        else:
            self.IpData_Parsing()

    # Ip Response Parsing
    def IpData_Parsing(self):
        self.First_Filter = self.Res.split("\n\n")
        self.First_Filter.pop(0)
        self.First_Filter.pop(0)
        self.First_Filter.pop(0)
        self.First_Filter.pop(-1)
        self.First_Filter.pop(-1)
        self.temp = ""
        for i in self.First_Filter:
            self.temp += i
        self.IPQueryList = self.temp.split("\n")
        self.IPSocket.close()

    """
Dns_Server_List = [
"whois.verisign-grs.net","whois.markmonitor.com","whois.ibi.net","whois.krnic.net","whois.nic.co","whois.gabia.com"]
"""

    # DNS Whois Query
    def DNSWhoIsQueryInfo(self):
        self.DnsSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.DnsSocket.connect(("whois.gabia.com", 43))
        except ConnectionRefusedError as e:
            self.DnsSocket.close()
            print(e)
        except TimeoutError as t:
            self.DnsSocket.close()
            print(t)
        except socket.gaierror as sg:
            self.DnsSocket.close()
            print(sg)

        self.sendDnsData_And_getResponse()

    # Get Dns Response
    def sendDnsData_And_getResponse(self):
        self.DnsSocket.send((self.Host + "\r\n").encode())
        self.Res = ""
        while True:
            self.Data = self.DnsSocket.recv(2048)
            if self.Data:
                self.Res += self.Data.decode()
            else:
                break
            self.DnsData_Parsing()

    # Dns Response Parsing
    def DnsData_Parsing(self):
        self.temp = self.Res.split("\n")
        self.DnsQueryList = [i for i in self.temp if ": " in i]

    # Domain Name
    def Domain(self):
        return str(self.Host)
    # Domain IP
    def Ip(self):
        return str(self.HostIP)

    # Registrar WHOIS Server
    def RegisterWhoisServer(self):
        self.Value = [self.Findkey for self.Findkey in self.DBList if "Registrar WHOIS Server" in self.Findkey]
        return self.Value[0]

    # Registrant Email
    def RegistrantEmail(self):
        self.Value = [self.Findkey for self.Findkey in self.DBList if "Registrant Email" in self.Findkey]
        return self.Value[0]

    # Admin Email
    def AdminEmail(self):
        self.Value = [self.Findkey for self.Findkey in self.DBList if "Admin Email" in self.Findkey]
        return self.Value[0]

    # Admin Phone
    def AdminPhone(self):
        self.Value = [self.Findkey for self.Findkey in self.DBList if "Admin Phone" in self.Findkey]
        return self.Value[0]


