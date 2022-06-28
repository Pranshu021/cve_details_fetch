from xml import dom
from bs4 import BeautifulSoup
import requests
from lxml import etree
import json
import xlrd, xlwt
from xlwt import Workbook
from xlutils.copy import copy

cve_obj_list = []

class CVE:
    def __init__(self, product_type, product, vendor):
        self.product_type = product_type
        self.vendor = vendor
        self.product = product

def get_data_from_excel(file):
    file_location = (file)
    current_workbook = xlrd.open_workbook(file_location)
    current_sheet = current_workbook.sheet_by_index(0)
    cve_list = []

    for i in range(0, (current_sheet.ncols)):
        for j in range(1, (current_sheet.nrows)):
            cve_list.append(current_sheet.cell_value(j, i))
    
    return cve_list, current_workbook, current_sheet


def get_cve_project_data(url):
    req = requests.get(url)
    print(url, " Fetched ...")
    html_data = BeautifulSoup(req.content, 'html.parser')
    dom = etree.HTML(str(html_data))

    try:
        xpath_string = '//*[@id="vulnprodstable"]/tr[2]'
        td_xpath = dom.xpath(xpath_string)[0].getchildren()

        cve_obj = CVE(
            (str(td_xpath[1].text)).strip(), 
            (str(td_xpath[2].findtext('a'))).strip(), 
            (str(td_xpath[3].findtext('a'))).strip())

        cve_obj_list.append(cve_obj)
    except:
        cve_obj = CVE("None", "None", "None")
        cve_obj_list.append(cve_obj)


def export_to_csv(cve_obj_list):
    print("Exporting...")
    wb = Workbook()
    sheet1 = wb.add_sheet('Sheet 1')
    for i in range(0, len(cve_obj_list)):
        for j in range(0, 1):
            sheet1.write(i, j, cve_obj_list[i].product_type)
            sheet1.write(i, j+1, cve_obj_list[i].vendor)
            sheet1.write(i, j+2, cve_obj_list[i].product)

    wb.save('cve_project_data.xls')


cve_data, current_workbook, current_sheet = get_data_from_excel("./cve_data.xls")
cve_url = "https://www.cvedetails.com/cve/"
for cve in cve_data:
    get_cve_project_data("https://www.cvedetails.com/cve/"+cve)
export_to_csv(cve_obj_list)


# temp_obj = CVE("None", "None", "None")

# temp_obj_list=[]
# temp_obj_list.append(temp_obj)
# export_to_csv(temp_obj_list)







# get_cve_project_data(cve_data, "https://www.cvedetails.com/cve/CVE-2017-20049/")
# get_cve_project_data(cve_data, "https://www.cvedetails.com/cve/CVE-2015-20107/")

    





