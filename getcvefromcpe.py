import openpyxl
import nvdlib
import re
import time



def validate_input(input_str):
    # Regular expression to check for spaces or special characters
    pattern = re.compile(r'[\s!@#$%^&*()=_+[\]{}|;:",.<>?/\\]')

    # Check if the input contains spaces or special characters
    if pattern.search(input_str):
        # If spaces are encountered, ignore the rest of the input
        input_str = input_str.split()[0]

    return input_str



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
            package_name = validate_input(package_name)
            vendor = row[vendor_column - 1]
            if not vendor:
                vendor = package_name
            vendor = validate_input(vendor)
            package_version = row[version_column - 1]
            cpe_string = generate_cpe_string(package_name, vendor, package_version)
            package_data.append(cpe_string)
                    
    except Exception as e:
        print(f"An error occurred: {e}")
        
    return package_data

if __name__ == "__main__":
    excel_filename = "Book1.xlsx"
    sheet_name = ['test','product1','product2']

  
    for sheet in sheet_name:
        print(sheet)

        cpe_strings = read_packages_from_excel(excel_filename, sheet)
    
        for cpe_string in cpe_strings:
            print(f"CPE String: {cpe_string}")
            r = nvdlib.searchCVE(cpeName = cpe_string)
            for eachCVE in r:
                print(eachCVE.id, eachCVE.score, eachCVE.url)

 
