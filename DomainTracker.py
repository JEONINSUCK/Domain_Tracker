#-*- coding: utf-8 -*-
import socket, sys, Shodan, WhoIsQueryInfo
from optparse import OptionParser

class DomainTracker():

    def __init__(self):
        self.struct = {
                "default" : {
                "IP": "",
                "SubDomainList": [],
                "RegisterWhoisServer": "",
                "RegisterEmail": "",
                "AdminEmail": "",
                "AdminPhone": "",
            },
            "UseShodanInfoData": {
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
                "OthersServicePort": [],
                "OthersDataList": []
            },
        }
        # self.whois_ = whoIs.WhoIsQuery()
        self.shodan = Shodan.Shodan()
        self.thread = 0
        self.fileName = ""
        self.searchDeepBool = False
        self.rs_get = ""
        self.data = {}
        self.init()

    def run(self):
        for Domain in self.data.keys():
            #get whois info



            #get shodan info
            print("[+]"+Domain)
            self.shodan.setHostAppend(socket.gethostbyname(Domain))
            self.shodan.run()
            self.data[Domain]["UseShodanInfoData"] = self.shodan.getResult()


    def updateIndex(self, key):
        self.data.update({key : self.struct})
        print("Domain item Create")

    def updateStruct(self, key, data=None):
        try:
            if key != None:
                self.data[key] = data
            else:
                print("Key is Null")
                raise
        except Exception as e:
            print(e)

    def ueage(self):
        if len(sys.argv) < 2:
            print("\n"+__file__+" -h or --help\nor\nExample : -D DomainTracker.py -google.com -t 2 -d\n")
            sys.exit(1)
        else:
            parser = OptionParser(usage="%prog Domain [OPTIONS]")
            parser.add_option("-d", "--deep", dest="setDeep", default=False,
            help=
                "Deep Search Using Searched Data, Is Advanced option But Find\n"\
                "Data is Everything, So We do not make sure Result from Deep Searched\n"\
                "This Option Do not support Multithread or Multiprocess if you want it\n"\
                "do will remake this module\n"
            , metavar="level")
            parser.add_option("-f", "--file", dest="setFile", default="",
            help=
                "Domain List File .txt, Format Is 1 Line 1 Domain, not use ','\n"\
                "And Do not Support Deep Search This Option"
            , metavar="list.txt")
            parser.add_option("-t", "--thread", dest="setThread", default=0, help="set Thread count", metavar="Num")
            parser.add_option("-D", "--Domain", dest="setDomain", default=0, help="set Domain", metavar="Domain")

            return parser.parse_args()

    def init(self):
        try:
            options, args = self.ueage()
            if options.setDomain:
                print("Set Domain is "+options.setDomain)
                self.updateIndex(options.setDomain)
            if options.setDeep:
                self.searchDeepBool = True
                print("Set-Option is deep : " + str(self.searchDeepBool))
            if int(options.setThread) > 0:
                self.thread = options.setThread
                print("set-Option : ", self.thread)
            if options.setFile != "":
                if self.fileName.find('"'):
                    self.fileName = options.setFile.replace('"', "")
                else:
                    self.fileName = options.setFile
                print("Set-Option is file : " + str(self.fileName))
        except Exception as err:
            print(str(err))
            sys.exit(1)

if __name__ == '__main__':
    process = DomainTracker()
    process.run()
    print(sys.argv[1])
