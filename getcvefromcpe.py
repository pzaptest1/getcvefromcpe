import openpyxl
import nvdlib

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

def read_packages_from_excel(filename):
    package_data = []
    
    try:
        workbook = openpyxl.load_workbook(filename)
        sheet = workbook.active
        
        package_column = None
        vendor_column = None
        version_column = None
        
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
            vendor = row[vendor_column - 1]
            package_version = row[version_column - 1]
            cpe_string = generate_cpe_string(package_name, vendor, package_version)
            package_data.append(cpe_string)
            
    except Exception as e:
        print(f"An error occurred: {e}")
    
    return package_data

if __name__ == "__main__":
    excel_filename = "Book1.xlsx"
    cpe_strings = read_packages_from_excel(excel_filename)
    
    for cpe_string in cpe_strings:
        print(f"CPE String: {cpe_string}")
        r = nvdlib.searchCVE(cpeName = cpe_string)
        for eachCVE in r:
           print(eachCVE.id, eachCVE.score, eachCVE.url)
