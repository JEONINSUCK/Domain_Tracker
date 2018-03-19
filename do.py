import socket, requests, os
from bs4 import BeautifulSoup

class domain_tracker():

    def __init__(self):
        self.index = 0
        self.data = {
            str(self.index):
                {
                    "is_kr": False,
                    "support_http": False,
                    "support_https": False,
                    "support_http_2": False,
                    "find_admin_url": False,
                    "http_res_code": 0,
                    "ip_address": "",
                    "domain": "",
                    "input_url": "",
                    "web_lang": "",
                    "db_lang": "",
                    "sub_urls": []
                }
             }


    def update(self, data, key=None):
        if key != None:
            self.data[key] = data
        else:
            self.index+=1
            self.data.update({"index":self.index, "data":data})

    def is_ip_or_domain(self, data):
        try:
            rs = [True, socket.inet_aton(data)]
        except socket.error:
            rs = [False, data]
        return rs

    def get_domain_inurl(self, url):
        spltAr = url.split("://");
        i = (0, 1)[len(spltAr) > 1];
        domain = spltAr[i].split("?")[0].split('/')[0].split(':')[0].lower();
        self.data[str(self.index)]["domain"] = domain
        return domain

    def get_whois_indomain(self, domain):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("whois.apnic.net", 43))
        s.send((bytes((socket.gethostbyname(domain) + "\r\n").encode())))

        response = ""
        while True:
            data = s.recv(4096)
            if not data:
                break
            else:
                response += data.decode()
        s.close()

        rs_ = ""
        for tmp in list(set(response.split("\n"))):
            if len(tmp.split(":")) > 1 and not ("%" in tmp):
                rs_ += tmp + "\n"

        return rs_

    def get_html(self, url):
       _html = ""
       resp = requests.get(url)
       if resp.status_code == 200:
          _html = resp.text
       return _html

    def get_links_inurl(self, url):
        self.get_domain_inurl(url)
        soup = BeautifulSoup(self.get_html(url), 'html.parser')
        soup.find_all('a')
        for link in soup.find_all('a'):
            url = self.make_full_url(link.get('href'))
            self.data[str(self.index)]['sub_urls'].append(url)
            print(url)

    def make_full_url(self, url):
        if url[0] == "/":
            url = self.domain + url
        if not ("http" in url[:5]):
            url = "http://" + url

        return url
url = "https://medium.com/@mjhans83/%ED%8C%8C%EC%9D%B4%EC%8D%AC%EC%9C%BC%EB%A1%9C-%ED%81%AC%EB%A1%A4%EB%A7%81-%ED%95%98%EA%B8%B0-908e78ee09e0"
sample = domain_tracker()
sample.get_links_inurl(url)