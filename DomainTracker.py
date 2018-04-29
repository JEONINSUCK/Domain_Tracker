import socket, requests, os, sys, getopt
from bs4 import BeautifulSoup

class DomainTracker():
    id = "0"
    thread = 0
    fileName = ""
    searchDeepBool = False
    struct = {
        str(id):
            {
                "Domain": "",
                "IP": "",
                "SubDomainList": [],
                "RegisterWhoisServer": "",
                "RegisterEmail": "",
                "AdminEmail": "",
                "AdminPhone": "",
                "Deep": True,
                "UseShodanInfo": True,
                "UseShodanInfoData": {
                    "City": "",
                    "Country": "",
                    "Orqanization": "",
                    "ISP": "",
                    "LastUpdate": "",
                    "HostName": "",
                    "OS": "",
                    "WebService": True,
                    "WebServiceData": {
                        "Port": 0,
                        "Type": "",
                        "Version": ""
                    },
                    "TunnelingService": True,
                    "TunnelServiceData": {
                        "Version": "",
                        "Type": ""
                    },
                    "OthersServicePort": [],
                    "OthersDataList": []
                },
            }
    }
    rs_get = ""
    def __init__(self):
        # self.id = "0"
        # self.thread = 0
        # self.fileName = ""
        # self.searchDeepBool = False
        # self.struct = {
        #     str(self.index):
        #         {
        #             "Domain": "",
        #             "IP": "",
        #             "SubDomainList": [],
        #             "RegisterWhoisServer": "",
        #             "RegisterEmail": "",
        #             "AdminEmail": "",
        #             "AdminPhone": "",
        #             "Deep": True,
        #             "UseShodanInfo": True,
        #             "UseShodanInfoData": {
        #                 "City": "",
        #                 "Country": "",
        #                 "Orqanization": "",
        #                 "ISP": "",
        #                 "LastUpdate": "",
        #                 "HostName": "",
        #                 "OS": "",
        #                 "WebService": True,
        #                 "WebServiceData": {
        #                     "Port": 0,
        #                     "Type": "",
        #                     "Version": ""
        #                 },
        #                 "TunnelingService": True,
        #                 "TunnelServiceData": {
        #                     "Version": "",
        #                     "Type": ""
        #                 },
        #                 "OthersServicePort": [],
        #                 "OthersDataList": []
        #             },
        #         }
        # }
        # self.rs_get = ""
        pass

    def runDetail(self, Domain):
        print(Domain)
        pass

    def updateIndex(self, index):
        self.id = str(int(self.id)+1)

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
        print("\nUsage\n")
        print('Usage: ' + sys.argv[0] + ' Domain [Options]')

        print("\nExample : DomainTracker.py google.com -T 2 -D\n")
        print("[Options]")
        print("  -f --file <Path&FileName>")
        print(
            "\tDomain List File .txt, Format Is 1 Line 1 Domain, not use ',' And Do not Support Deep Search This Option")
        print("  -t --thread <N>")
        print("\tUsing thread and Max Count is N")
        print("  -d --deep")
        print(
            "\tDeep Search Using Searched Data, Is Advanced option But Find\n"
            "\tData is Everything, So We do not make sure Result from Deep Searched\n"
            "\tThis Option Do not support Multithread or Multiprocess if you want it\n"
            "\tdo will remake this module\n"
        )
        sys.exit(1)


    def run(self):

        try:
            if len(sys.argv[1:]) <= 0:
                self.ueage()
            else:
                # input is char :
                # input is String =

                # opts, args = getopt.getopt(sys.argv[1:], "tdf:", ["Thread=", "THREAD=", "file=", "FILE=", "DEEP=", "deep=", "HELP", "help"])
                args = sys.argv

                index = 0
                for arg in sys.argv:
                    if arg.find(".") == -1:
                        arg = arg.upper()
                    else:
                        self.struct[self.id]["Domain"] = arg
                    if (arg == "-T" or (arg == "--THREAD")):
                        self.thread = sys.argv[index+1]
                        print("Set-Option is thread : " + str(self.thread))
                    elif (arg == "-F" or (arg == "--File")):
                        self.fileName = sys.argv[index+1]
                        if self.fileName.find('"'):
                            self.fileName = self.fileName.replace('"', "")
                        print("Set-Option is file : "+str(self.fileName))
                    elif (arg == "-D") or (arg == "--DEEP"):
                        self.searchDeepBool = True
                        print("Set-Option is deep : " + str(self.searchDeepBool))
                    index+=1
                self.runDetail(self.struct[self.id]["Domain"])
        except getopt.GetoptError as err:
            print(str(err))
            sys.exit(1)

if __name__ == '__main__':
    process = DomainTracker()
    process.run()




