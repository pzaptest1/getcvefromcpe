import openpyxl
import nvdlib
import re
import sys
import json
import requests

def get_epss_scores(cve):
    epss_scores = {}
    
    try:
        # Get the EPSS Score from the FIRST EPSS API
        response = requests.get('https://api.first.org/data/v1/epss/?cve=' + cve.strip())
        
        if response.status_code == 200:
            data = response.json()
            
            for item in data['data']:
                cve = item["cve"]
                epss = item["epss"]
                percentile = item["percentile"]
                
                epss_scores[cve] = {
                    'epss': epss,
                    'percentile': percentile
                }
                
                #print(f"CVE: {cve}, EPSS Score: {epss}, Percentile: {percentile} ")
        else:
            epss_scores[cve] = 'Error: Status code ' + str(response.status_code)
    except Exception as e:
        epss_scores[cve] = 'Error: ' + str(e)
    
    return epss_scores


def validate_input(input_str):
    # Regular expression to check for spaces or special characters
    pattern = re.compile(r'[\s!@#$%^&*()=_+[\]{}|;:",.<>?/\\]')

    # Check if the input contains spaces or special characters
    if pattern.search(input_str):
        # If spaces are encountered, ignore the rest of the input
        input_str = input_str.split()[0]

    return input_str


def process_nums(input_str):
    valid_input = []
    encountered_dot = False 
    for char in input_str:
        if char.isdigit() or char.isalpha():
            valid_input.append(char)
        elif char == '.' and not encountered_dot:
            valid_input.append(char)
            encountered_dot = True
        else:
            break
    return ''.join(valid_input)


def generate_cpe_string(package_name, vendor, package_version):
    cpe_version = "2.3"  # CPE version
    part = "a"  # Part is typically 'a' for applications
    product = package_name
    version = package_version
    update = "*"
    edition = "*"
    language = "*"
    sw_edition = "*"
    target_sw = "*"
    target_hw = "*"
    other = "*"

    cpe_string = f"cpe:{cpe_version}:{part}:{vendor}:{product}:{version}:{update}:{edition}:{language}:{sw_edition}:{target_sw}:{target_hw}:{other}"
    return cpe_string

def read_packages_from_excel(filename, sheet):
    package_data = []

    package_column = None
    vendor_column = None
    version_column = None
    
    try:
        workbook = openpyxl.load_workbook(filename)
      
        sheet = workbook[sheet]
        for row in sheet.iter_rows(min_row=1, max_row=1, values_only=True):
            for index, cell_value in enumerate(row):
                if cell_value == 'Package':
                    package_column = index + 1
                elif cell_value == 'Vendor':
                    vendor_column = index + 1
                elif cell_value == 'Version':
                    version_column = index + 1
                        
        if package_column is None or vendor_column is None or version_column is None:
            raise ValueError("Column headers 'Package', 'Vendor', and 'Version' not found.")
            
        for row in sheet.iter_rows(min_row=2, values_only=True):
            package_name = row[package_column - 1]
            package_name = validate_input(str(package_name))
            vendor = row[vendor_column - 1]
            if not vendor:
                vendor = package_name
            vendor = validate_input(str(vendor))
            package_version = row[version_column - 1]
            package_version = process_nums(str(package_version))
            cpe_string = generate_cpe_string(package_name, vendor, package_version)
            package_data.append(cpe_string)
                    
    except Exception as e:
        print(f"An error occurred: {e}")
        
    return package_data
 

if __name__ == "__main__":


    if len(sys.argv) == 1:

        excel_filename = "Book1.xlsx"

        """modify the list as appropriate"""
        #sheet_name = ['product1', 'product2', 'product3','product4','product5']
        sheet_name = ['product8']

        cve_list = []

   
        for sheet in sheet_name:
            print(sheet)
            cpe_strings = read_packages_from_excel(excel_filename, sheet)
            for cpe_string in cpe_strings:
                print(f"CPE String: {cpe_string}")
                r = nvdlib.searchCVE(cpeName = cpe_string)
                for eachCVE in r:
                    epss_scores = get_epss_scores(eachCVE.id)
                    print(eachCVE.id, eachCVE.score, epss_scores[eachCVE.id], eachCVE.url)
 
    else:
        arguments = sys.argv[1:]
        for arg in arguments:
            print ("command args:", arg) 
            r = nvdlib.searchCVE(arg)
            for eachCVE in r:
                print(eachCVE.id, eachCVE.score, eachCVE.url)
 
