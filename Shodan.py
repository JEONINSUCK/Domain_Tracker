import requests

class Shodan():
    shodanUrl = "https://shodan.io/host/"
    hosts = []

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
            result.content
        else:



    def run(self):
        for host in self.hosts:
            # print(host)
            self.getHtml(host)


if __name__ == '__main__':
    shodan = Shodan()
    shodan.setHostAppend("52.79.56.52")
    shodan.run()
