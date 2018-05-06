import requests
from bs4 import BeautifulSoup

class Shodan():
    shodanUrl = "https://shodan.io/host/"
    hosts = []
    webDicData =  {
        "City": "",
        "Country": "",
        "Orqanization": "",
        "ISP": "",
        "LastUpdate": "",
        "HostName": "",
        "OS": "",
        "WebServiceData": {
            "Port": 0,
            "Type": "",
            "Version": ""
        },
        "TunnelServiceData": {
            "Version": "",
            "Type": ""
        },
        "OthersServicePort" : []

    }


    def __int__(self):
        pass

    def setHostsList(self, hosts):
        self.hosts = hosts

    def setHostAppend(self, host):
        self.hosts.append(host)

    def moduleInfo(self):
        print("We do not use API")
        print("API is buy Promotion")
        print("You know this module to using crawling")

    def getHtml(self, ip):
        result = requests.get(self.shodanUrl+str(ip))
        if result.status_code == 200:
            return result.content
        else:
            return ""

    def paserHtml(self, ip):
        html = self.getHtml(ip)
        if html != "":
            soup = BeautifulSoup(html, 'html.parser')

            for line in soup.find_all(class_='service service-long'):
                try:
                    data = line.contents[2].text.split()

                    if data[2] == "http":
                        self.webDicData['WebServiceData']['Port'] = data[0]
                    elif data[2].find("telnet") >=0 or data[2].find("ssh") >= 0:
                        self.webDicData["TunnelServiceData"]["Type"] = data[2]
                        self.webDicData["TunnelServiceData"]["Version"] = line.contents[4].text.split()[0]
                    else:
                        self.webDicData['OthersServicePort'].append([data[2], data[0]])
                except:
                    print("is error")
            for line in soup.find_all(class_='service-main'):
                try:
                    data = line.contents[1].text.split(":")
                    for info in data:
                        if info.strip().find("http") >= 0:
                            if info.strip().find("Version") >= 0:
                                self.webDicData['WebServiceData']['Type'] = info.strip().replace("Version", "")
                            else:
                                self.webDicData['WebServiceData']['Type'] = info.strip()
                        if info.strip().find(".") >= 0:
                            self.webDicData['WebServiceData']['Version'] = info.strip()
                except:
                    print("is error")
            self.webDicData['WebServiceData']['Version'] = self.hasNumber(self.webDicData['WebServiceData']['Version'])
            # get default information
            for line in soup.find_all(class_='table'):
                try:
                    data = line.contents[1].text.split("\n\n\n")
                    for info in data:
                        info_list =  info.replace("\n\n", "").split("\n")
                        key = info_list[0].strip()
                        if key in self.webDicData:
                            self.webDicData[key] = info_list[1].strip()
                except:
                    print("error")
        else:
            print("Connection failed to host")

    def hasNumber(self, data):
        for N in range(0, 9):
            if str(N) in data:
                return data
        return ""

    def getResult(self):
        return self.webDicData

    def run(self):
        for host in self.hosts:
            self.paserHtml(host)

if __name__ == '__main__':
    shodan = Shodan()
    shodan.setHostAppend("52.79.56.52")
    shodan.setHostAppend("218.232.94.196")
    shodan.run()
    print(shodan.getResult())
