import os
import re
import json
import sys
from collections import defaultdict

# TODO :
# Fix the issue of sourced variables, example aports/main/java-gcj-compat/APKBUILD
# Fix the issue with ${var} types, example in aports/non-free/amd-ucode/APKBUILD

output_dir = 'output'
os.makedirs(output_dir, exist_ok=True)

PKGNAME_PATTERN = re.compile(r'pkgname=(.*)')
PKGVER_PATTERN = re.compile(r'pkgver=(.*)')
PKGREL_PATTERN = re.compile(r'pkgrel=(.*)')
SUBPACKAGES_PATTERN = re.compile(r'subpackages="(.*?)"', re.DOTALL)
ARCH_PATTERN = re.compile(r'arch=(.*)')
CVE_PATTERN = re.compile(r'cve-\d{4}-\d{4,}')
MAINTAINER_PATTERN = re.compile(r'^# Maintainer:\s*([^<]+)\s*<', re.MULTILINE)

def extract_cve_values(file_content):
    """Extract the CVE values from the given file content."""
    content = file_content.lower()
    cve_pattern = r'cve-\d{4}-\d{4,}'
    cve_matches = re.findall(cve_pattern, content)
    return list(set(cve_matches))

def extract_maintainer(file_content):
    """Extract the maintainer from the given file content."""
    match = MAINTAINER_PATTERN.search(file_content)
    if match:
        return match.group(1).strip()
    return None

def build_cpe_version(vendor, pkgname, pkgver):
    cpe_version = "cpe:2.3"
    vendor = vendor
    product_name = pkgname
    version = pkgver
    cpe = f"{cpe_version}:a:{vendor}:{product_name}:{version}:*:*:*:*:*:*:*"

    return cpe

def collect_shell_variables(content):
    """Collect all the variables from the given content into a dictionary."""
    variables = {}
    for line in content.splitlines():
        match = re.match(r"(\w+)=(.+)", line.strip())
        if match:
            key, value = match.groups()
            variables[key] = value.strip()
    return variables

def resolve_variable(value, variables):
    """Recursively resolves variables in a given value."""
    # no infinite loops
    visited = []
    if value.find(value) == -1:
        return "ERROR" # be explicit about the error, we deal with it later
    
    while "$" in value:
        match = re.search(r"\$(\w+)", value)
        if not match:
            break
        var_name = match.group(1)
        if var_name in variables:
            if var_name in visited:
                return "ERROR"
            value = value.replace(f"${var_name}", variables[var_name])
            visited.append(var_name)
        else:
            break
    return value

def find_apkbuilds(root_dir):
    """Search for all APKBUILD files in the given directory and its subdirectories."""
    apkbuild_files = []
    for root, dirs, files in os.walk(root_dir):
        if 'APKBUILD' in files:
            apkbuild_files.append(os.path.join(root, 'APKBUILD'))
    return apkbuild_files

def extract_variables(apkbuild_path):
    """Extract pkgname, pkgver, pkgrel, subpackages, and arch from an APKBUILD file."""
    variables = {
        'pkgname': None,
        'pkgver': None,
        'pkgrel': None,
        'arch': None,
        'sbom_ver' : None,
        'sbom_name' : None,
        'maintainer' : None,
        'secfixes': {},
        'subpackages': [],
        'patches': []
    }
    
    with open(apkbuild_path, 'r') as file:
        content = file.read()
        shell_vars = collect_shell_variables(content)
       
        pkgname_match = PKGNAME_PATTERN.search(content)
        if pkgname_match:
            variables['pkgname'] = pkgname_match.group(1).strip('"\'')
            if variables['pkgname'].find("$") != -1:
                variables['pkgname'] = resolve_variable(variables['pkgname'], shell_vars)

        pkgver_match = PKGVER_PATTERN.search(content)
        if pkgver_match:
            variables['pkgver'] = pkgver_match.group(1).strip('"\'')
            if variables['pkgver'].find("$") != -1:
                variables['pkgver'] = resolve_variable(variables['pkgver'], shell_vars)
        
        pkgrel_match = PKGREL_PATTERN.search(content)
        if pkgrel_match:
            variables['pkgrel'] = pkgrel_match.group(1).strip('"\'')
            if variables['pkgrel'].find("$") != -1:
                variables['pkgrel'] = resolve_variable(variables['pkgrel'], shell_vars)
        
        arch_match = ARCH_PATTERN.search(content)
        if arch_match:
            variables['arch'] = arch_match.group(1).strip('"\'')
        
        # subpackages
        subpackages_match = SUBPACKAGES_PATTERN.findall(content)
        for subpackages in subpackages_match:
            variables['subpackages'] += [pkg.strip() for pkg in subpackages.split()]

        filter_subpackages = []
        for subpackage in variables['subpackages']:
            if subpackage == "$subpackages":
                continue
            filter_subpackages.append(subpackage)
        
        variables['subpackages'] = [
                pkg.replace('$pkgname', variables['pkgname']).split(":")[0] for pkg in filter_subpackages
            ]
        
        variables['sbom_ver'] = variables['pkgver'] + "-r" + variables['pkgrel']
        variables['maintainer'] = extract_maintainer(content)
        variables['secfixes'] = extract_cve_values(content)

    return variables

def find_cve_patches(directory):
    """Find files in the directory that match the CVE pattern."""
    patches = []
    for filename in os.listdir(directory):
        filename = filename.lower()
        cve = CVE_PATTERN.search(filename)
        if cve:
            patches.append(cve.group(0).strip())
    return patches

def main(tag):
    """Main function to search for APKBUILD files, extract variables, and output to JSON."""
    root_dir = "aports/"
    print(f"Searching for APKBUILD files in: {root_dir}")
    
    apkbuild_files = find_apkbuilds(root_dir)
    
    if not apkbuild_files:
        print("No APKBUILD files found.")
        return
    
    results = []
    
    for apkbuild in apkbuild_files:
        print(f"Found APKBUILD: {apkbuild}")
        variables = extract_variables(apkbuild)
        
        apkbuild_dir = os.path.dirname(apkbuild)
        variables['patches'] = find_cve_patches(apkbuild_dir)
        
        # Create standalone subpackage entries
        subpackage_entries = []
        for subpackage in variables['subpackages']:
            subpackage_entry = {
                'apkbuild_path': apkbuild,
                'alpine_tag': tag,
                'pkgname': subpackage,
                'parent_pkgname': variables['pkgname'],
                'pkgver': variables['pkgver'],
                'pkgrel': variables['pkgrel'],
                'arch': variables['arch'],
                'patches': variables['patches'],
                'sbom_ver' : variables['sbom_ver'],
                'maintainer' : variables['maintainer'],
                'secfixes': variables['secfixes'],
                'cpe' : build_cpe_version(variables['pkgname'], subpackage, variables['sbom_ver'])
            }
            subpackage_entries.append(subpackage_entry)
        
        # Add the package to the list
        results.append({
            'apkbuild_path': apkbuild,
            'alpine_tag': tag,
            'pkgname': variables['pkgname'],
            'pkgver': variables['pkgver'],
            'pkgrel': variables['pkgrel'],
            'arch': variables['arch'],
            'patches': variables['patches'],
            'subpackages': variables['subpackages'],
            'sbom_ver' : variables['sbom_ver'],
            'maintainer' : variables['maintainer'],
            'secfixes': variables['secfixes'],
            'cpe' : build_cpe_version(variables['pkgname'], variables['pkgname'], variables['sbom_ver'])
        })

        for subpackage in subpackage_entries:
            results.append(subpackage)
    
    # Output results to JSON
    output_file = tag + '_packages.json'
    with open(os.path.join(output_dir, output_file), 'w') as json_file:
        json.dump(results, json_file, indent=4)
    
    print(f"Results saved to {output_file}")

if __name__ == "__main__":
    main(sys.argv[1])