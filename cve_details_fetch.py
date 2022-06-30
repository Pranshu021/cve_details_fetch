from bs4 import BeautifulSoup
import json, xlrd, nvdlib, sys, argparse, datetime
from lxml import etree
from xlwt import Workbook
(
# class CVE:
#     def __init__(self, cve_number='', cve_score=0, project_name=''):
#         self.cve_number = cve_number
#         self.cve_score = cve_score
#         self.project = project_name

#     def get_cve_details(self):
#         cve_data = nvdlib.getCVE(self.cve_number, key='88314ae5-519c-4fe6-ae64-80dda087c496')
#         return cve_data

#     def generate_cve_details(self, cve_data):
#         print("""
#         ================================
#         CVE: {}
#         Published Date: {}
#         V3Score: {}
#         Score: {}
#         Severity: {}
#         CWE: {}
#         References: 
#         1.{}
#         2.{}
#         3.{}
#         ================================
#         """.format(cve_data.id, cve_data.publishedDate, cve_data.v3score, cve_data.score, cve_data.v3severity, cve_data.cwe,  cve_data.cve.references.reference_data[0].url, cve_data.cve.references.reference_data[1].url, cve_data.cve.references.reference_data[2].url))

#     def generate_cve_report(self, cve_data):
#         print(cve_data)

#     def get_project_cve_details(self, **kwargs):
            
#         cve_list = nvdlib.searchCVE(keyword=self.project)
#         return cve_list

#     def generate_project_cve_details(self, cve_list):
#         for cve in cve_list:
#             print(cve.id)


# def main():
#     if len(sys.argv) < 2:
#         print("[-] No Arguments Passed. Use -h flag for help")
#         exit(1)
#     parser = argparse.ArgumentParser(description="Handle the info cve_datauirement flags")
#     subparser = parser.add_subparsers(dest='command')
#     cve_parser = subparser.add_parser('cve')
#     project_parser = subparser.add_parser('project')
#     cve_parser.add_argument('id', help='Fetch details of a specific cve id. Usage: cve --id CVE-2022-23306')
#     cve_parser.add_argument('--fullReport', help='Fetch A full json report of the given CVE. Usage: cve --fullReport CVE-2022-23307', action='store_true')
#     cve_parser.add_argument('--output', help="Export the result to the given output format. Choices are - csv, json", choices=['csv', 'json'])
#     project_parser.add_argument('--name', help='Fetch cve\'s for the mentioned affected package/product. Usage: --project-name Node')
#     project_parser.add_argument('--startDate', help='fetch all cve\'s published after the given date. Format: YYYY-MM-DD HH:mm Usage: --startDate 2021-06-21 00:00')
#     project_parser.add_argument('--endDate', help='fetch all cve\'s published before the given date. Format: YYYY-MM-DD HH:mm Usage: --startDate 2021-06-21 00:00')
#     project_parser.add_argument('--severity', default='False')

#     args = parser.parse_args()

#     if args.command == 'cve':
#         cve_obj = CVE(args.id)
#         cve_details = cve_obj.get_cve_details()

#         if args.fullReport:
#             cve_obj.generate_cve_report(cve_details)
#         else:
#             cve_obj.generate_cve_details(cve_details)

#     if args.command == 'project':
#         name = args.name
#         cve_obj = CVE(project_name=name)
#         cve_list = cve_obj.get_project_cve_details(pubStartDate=args.startDate, pubEndDate=args.endDate, cvssV3Severity=args.severity)
#         cve_obj.generate_project_cve_details(cve_list)
)

class CVE:
    def __init__(self, cve_number, key):
        self.cve_number = cve_number
        self.api_key = key


    def generate_details(self):
        data = self.fetch_data()
        self.display(data, "details")


    def generate_fullReport(self, output):
        data = self.fetch_data()
        if output:
            self.generate_output(data, "report")
        else:
            self.display(data, "report")


    def fetch_data(self):
        cve_data = nvdlib.getCVE(self.cve_number, key=self.api_key)
        return cve_data


    def generate_output(self, data, format):
        jsonFile = open(self.cve_number+"_"+format+".json", "w")
        if format == "report":
            json_data = str(data).replace('\'', '"').replace('True', '"True"').replace('False', '"False"')
            jsonFile.write(json_data)
        else:
            json_obj = json.dumps(self.__dict__)
            jsonFile.write(json_obj)

        jsonFile.close()


    def display(self, cve_data, format):
        if str(format) == "details":
            print("In details")
            print("""
            ================================
            CVE: {}
            Published Date: {}
            V3Score: {}
            Score: {}
            Severity: {}
            CWE: {}
            References: 
            1.{}
            2.{}
            3.{}
            ================================
            """.format(cve_data.id, cve_data.publishedDate, cve_data.v3score, cve_data.score, cve_data.v3severity, cve_data.cwe,  cve_data.cve.references.reference_data[0].url, cve_data.cve.references.reference_data[1].url, cve_data.cve.references.reference_data[2].url))

        if format == "report":
            print(cve_data)



def main():
    parser = argparse.ArgumentParser(description="Handle the info cve_datauirement flags")
    subparser = parser.add_subparsers(dest='command')
    cve_parser = subparser.add_parser('cve')
    cve_parser.add_argument('--id', required=True, help='Fetch details of a specific cve id. Usage: cve --id CVE-2022-23306')
    cve_parser.add_argument('--key', required=True, help="API key. To get your key, go to https://nvd.nist.gov/developers/cve_datauest-an-api-key")
    cve_parser.add_argument('--fullReport', help='Fetch A full json report of the given CVE. Usage: cve --fullReport CVE-2022-23307', action='store_true')
    cve_parser.add_argument('--json', help="Export the result to the json format.", action='store_true')
    

    args = parser.parse_args()
    cve_obj = CVE(args.id, args.key)

    if args.fullReport:
        cve_obj.generate_fullReport(args.json)
    else:
        cve_obj.generate_details()


if __name__ == "__main__":
    main()
    
# CVE-2022-23307

    # default=datetime.datetime.now().strftime("%Y-%m-%d %H:%M")