from bs4 import BeautifulSoup
import requests, json, xlrd, nvdlib, sys, argparse, datetime
from lxml import etree
from xlwt import Workbook

class CVE:
    def __init__(self, cve_number='', cve_score=0, project_name=''):
        self.cve_number = cve_number
        self.cve_score = cve_score
        self.project = project_name

    def get_cve_details(self):
        req = nvdlib.getCVE(self.cve_number, key='88314ae5-519c-4fe6-ae64-80dda087c496')
        return req

    def generate_cve_details(self, req):
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
        """.format(req.id, req.publishedDate, req.v3score, req.score, req.v3severity, req.cwe,  req.cve.references.reference_data[0].url, req.cve.references.reference_data[1].url, req.cve.references.reference_data[2].url))

    def generate_cve_report(self, req):
        print(req)

    def get_project_cve_details(self, startDate, endDate, severity):
        cve_list = nvdlib.searchCVE(keyword=self.project, pubStartDate=startDate, pubEndDate=endDate, cvssV3Severity=severity)
        return cve_list

    def generate_project_cve_details(self, cve_list):
        for cve in cve_list:
            print(cve.id)


def main():
    if len(sys.argv) < 2:
        print("[-] No Arguments Passed. Use -h flag for help")
        exit(1)
    parser = argparse.ArgumentParser(description="Handle the info requirement flags")
    subparser = parser.add_subparsers(dest='command')
    cve_parser = subparser.add_parser('cve')
    project_parser = subparser.add_parser('project')
    cve_parser.add_argument('id', help='Fetch details of a specific cve id. Usage: cve --id CVE-2022-23306')
    cve_parser.add_argument('--fullReport', help='Fetch A full json report of the given CVE. Usage: cve --fullReport CVE-2022-23307', action='store_true')
    cve_parser.add_argument('--output', help="Export the result to the given output format. Choices are - csv, json", choices=['csv', 'json'])
    project_parser.add_argument('--name', help='Fetch cve\'s for the mentioned affected package/product. Usage: --project-name Node')
    project_parser.add_argument('--startDate', help='fetch all cve\'s published after the given date. Format: YYYY-MM-DD HH:mm Usage: --startDate 2021-06-21 00:00')
    project_parser.add_argument('--endDate', help='fetch all cve\'s published before the given date. Format: YYYY-MM-DD HH:mm Usage: --startDate 2021-06-21 00:00')
    project_parser.add_argument('--severity', default='False')

    args = parser.parse_args()

    if args.command == 'cve':
        cve_obj = CVE(args.id)
        cve_details = cve_obj.get_cve_details()

        if args.fullReport:
            cve_obj.generate_cve_report(cve_details)
        else:
            cve_obj.generate_cve_details(cve_details)

    if args.command == 'project':
        name = args.name
        cve_obj = CVE(project_name=name)
        cve_list = cve_obj.get_project_cve_details(args.startDate+" 00:00", args.endDate+ " 00:00", args.severity)
        cve_obj.generate_project_cve_details(cve_list)

if __name__ == "__main__":
    main()
    


    # default=datetime.datetime.now().strftime("%Y-%m-%d %H:%M")