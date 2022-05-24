# Author: Alex Tum

# import os
import subprocess
import json
import requests
import time
from packaging import version

# NOTE: May need to actually make the package class for easier processing of the nodes of the deptree

# Class Package contains dependencies of the package labeled by the class
class Package():
    """docstring for Package"""
    def __init__(self, name):
        # super(Package, self).__init__()
        self.package_name = name
        self.installed_version = None
        self.required_versions = []
        self.dependencies = []
        self.depth = 0
        self.vulns_for_installed_version = []
        self.is_parent_package = False
        self.all_package_vulns = []


    def __str__(self):
        packageString = 'package: ' + self.package_name + '| installed version: ' + self.installed_version + ' | dependencies: ['

        for i in range(len(self.dependencies)):
            if i == 0:
                packageString += '\n\t'
            packageString += str(self.dependencies[i]) 
            if i != len(self.dependencies)-1:
                packageString += ', '

        packageString += ']'
        return packageString 


# Function: Calls pipdeptree on the specified package
def retrieve_raw_package_dependencies(package):
    # package = "list"]
    cmd = ["pipdeptree", "-j", "-p"]

    # Add package to go through to the cmd list which will be passed to Popen
    # for package in packages:
    cmd.append(package)
    # print(cmd)

    pip_list = subprocess.Popen(cmd, stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.PIPE, text = True)
    output, errors = pip_list.communicate()     # Retrieve output and errors from Popen
    # output = pip_list.read()
    # errors = pip_list.stderr.read()

    # Wait till pip_list completes
    while pip_list.poll() == None:
        pip_list.wait()
    # print(output)
    print(errors)

    # The output returned by running pipdeptree -j is a JSON string that is a list of dictionaries of the package's dependencies 
    # pip_list.close()
    return output, errors


# Function: Currently parses the rawJSONString from pipdeptree into python dictionaries and retrieves the CVE Data for each.
# Returns a tuple of the dependency tree in a dictionary and the parent package object
def parse_Pipdeptree_JSON_For_NVD_CVEs(rawJSONString, parentName):
    jsonDeptree = json.loads(rawJSONString)

    # A dictionary containing package objects with key = packageNameString and value = package objects
    # {packageName: PackageObject}

    deptree = {}
    parentPackage = None
    # print(deptree[0]['package']['package_name'])
    # packageNames = []
    

    i = 0 # For testing only


    # deptree is a list of dictionaries that contain the packages and dependencies
    # This for loop fills the deptree with CVEs for each package
    for packageJSONEntry in jsonDeptree:
        packageName = packageJSONEntry['package']['key']
        # packageNames.append(packageName)

        #may need to check if package already exists in deptree before creating a new package object
        if ((packageName in deptree) and (packageName != parentName)) or ((parentName == packageName) and deptree[parentName]):
            packageObj = deptree[packageName]
        else:
            packageObj = Package(packageName)
            packageObj.installed_version = packageJSONEntry['package']['installed_version'] 
            deptree[packageName] = packageObj

        if packageObj.package_name == parentName:
            packageObj.is_parent_package = True
            parentPackage = packageObj


        # Add dependencies to packageObject
        # Check if the package has dependencies first
        if packageJSONEntry['dependencies']:
            for depJSONEntry in packageJSONEntry['dependencies']:
                # depJSONEntry is the list entry for each dependency package in the JSON

                # Check if the dependency object exists in the deptree. If not, then add it 
                if depJSONEntry['key'] in deptree:
                    # Check if the package contains all of its fields.
                    if not deptree[depJSONEntry['key']].installed_version:
                        deptree[depJSONEntry['key']].installed_version = depJSONEntry['installed_version']
                    if depJSONEntry['required_version'] not in deptree[depJSONEntry['key']].required_versions:
                        deptree[depJSONEntry['key']].required_versions.append(depJSONEntry['required_version'])
                    # if  
                else:
                    depObj = Package(depJSONEntry['key'])
                    depObj.installed_version = depJSONEntry['installed_version']
                    depObj.required_versions.append(depJSONEntry['required_version'])

                    # print('depJSONEntry[\'key\']: ' + depJSONEntry['key'] + ',\tdepObj.package_name: ' + depObj.package_name)
                    # print(depJSONEntry['key'] == depObj.package_name)
                    # print(depObj)

                    deptree[depJSONEntry['key']] = depObj

                packageObj.dependencies.append(deptree[depJSONEntry['key']])


        #Adding CVEs should only occur for each packageJSONEntry and not when every package is created.
        time.sleep(.1)
        cveResponse = getCVEData(["keyword"], [packageObj.package_name])
        cveParsed = parse_CVEs(cveResponse, packageObj)


        # TODO: Move CVEMatching to occur after filling up the data structures
        #       Conduct evaluation after filling up a dictionary of cpe's where the key = cpe and value = CVEs
        cveMatch = package_version_match_CVEs(depTree, packageObj)


        # print(packageArrayObject)

        # For testing, limits number of results
        i+=1
        if i>=4:
            break

    for packageKey in deptree:
        print(deptree[packageKey])
    return (deptree, parentPackage)


# Function: Sends an API request to the NVD's CVE database
# paramNames should be a list of parameters to search for on the NVD. Ex: "keyword"
# paramVals should be a list of values to search for, such as the package name. Ex: "Tensorflow" 
# Returns the JSON as indicated by the NVD API. The function already transforms it into a python dictionary
def getCVEData(paramNames, paramVals):
    queryParameters = {}
    if len(paramNames) == len(paramVals):
        for i in range(len(paramNames)):
            queryParameters[paramNames[i]] = paramVals[i]
    else:
        print("Error: Number of parameters passed must equal number of values passed.")

    r = requests.get("https://services.nvd.nist.gov/rest/json/cves/1.0/", params = queryParameters)
    returnJSON = r.json()
    # print(returnJSON)
    return returnJSON


# Function: Goes through the deptree and compare package version to CVE entry and version number
# NEWTODO: Do not optimize. Instead use it to evaluate the data after cpe's have been retrieved
#          Use what is currently in this function to fill the cpe's and do the version matching using different logic.
def package_version_match_CVEs(depTree):
    packageCVEMatch = False

    # Parse through the deptree and match CVEs and CPE's for the given package to decide if vulnerable.
    # May need to duplicate parts of parse_CVE_config_nodes() in order to evaluate the parent/child node relationships

    for package in dependencyTree:
        # If there are no CVE results then move on to next package
        pass


# Similar to parse_CVE_config_nodes()
# Will do the cpe matching
def package_match_configurations(packageObj):
    pass


# Function: Goes through the cve entries for a package and fills the cpe dictionary
# TODO: May be able to optimize by making this a callable function from the deptree parser
# NEWTODO: Have it add each possible vulnerability (this should be cveItem) to the packageObj
def parse_CVEs(cveReturn, packageObj)
    # for package in dependencyTree:
        # If there are no CVE results then move on to next package
    if cveReturn['resultsPerPage'] != 0:        
        for cveItem in cveReturn['result']['CVE_Items']:
            if 'configurations' in cveItem:
                if 'nodes' in cveItem['configurations']:
                    for node in cveItem['configurations']['nodes']:
                        packageCVEMatch = parse_CVE_config_nodes(node, cveItem, packageObj)

            # The below line should be good as of 24May
            packageObj.all_package_vulns.append(cveItem)

    return packageCVEMatch



# Helper function for package_version_match_CVE
# Uses recursion for the Configurations tree.
def parse_CVE_config_nodes(node, cveItem, packageObj, parentOperator=False):
    cpeMatch = False
    packageIsVulnerable = False
    print('node: ' + str(node))

    if node['children']:
        print('children' + str(node['children']))
        # if node['operator'].upper() == 'AND':
        for childNode in node['children']:
            if 'operator' in childNode:
                cpeMatch, packageIsVulnerable = parse_CVE_config_nodes(childNode, cveItem, packageObj, node['operator']) 
                if node['operator'].upper() == 'AND' and cpeMatch == False:
                    break
                elif node['operator'].upper() == 'OR' and cpeMatch == True:
                    break
            else:
                print('ERROR: No operator in node')

    elif node['cpe_match']:
        # May need to move all of the below branch code to a recursive function that allows us to take into account the operator for each cpe_match node.
        

        # print('cpe_match: ' + str(node['cpe_match']))
        for node_cpe_match_element in node['cpe_match']:
            UriList = node_cpe_match_element['cpe23Uri'].split(':')
            # print('UriList: ' + str(UriList))
            cpe_product = UriList[4]
            # print('node_cpe_match_element: ' + str(node_cpe_match_element))
            # cpeMatch = False

            # See if the cpe node is vulnerable
            # cpe_is_vulnerable = False
            # if node_cpe_match_element['vulnerable'] != True and cpe_product != packageObj.package_name:
            #     # cpe_is_vulnerable = True
            # # else:
            #     continue


            # TODO: Fix this as it does not cover the cases where there is no version end.
            #       Also move checking for package vulnerability status into different function
            #       Conduct evaluation after filling up a dictionary of cpe's where the key = cpe and value = CVEs
            # Retrieve range of vulnerable versions from configurations' node
            if 'versionEndIncluding' in node_cpe_match_element:
                latest_vuln_version_inclusive = version.parse(node_cpe_match_element['versionEndIncluding'])
                if version.parse(packageObj.installed_version) <= latest_vuln_version_inclusive:
                    if 'versionStartIncluding' in node_cpe_match_element:
                        earliest_vuln_version_inclusive = version.parse(node_cpe_match_element['versionStartIncluding'])
                        if version.parse(packageObj.installed_version) >= earliest_vuln_version_inclusive:
                            cpeMatch = True
                    elif 'versionStartExcluding' in node_cpe_match_element:
                        earliest_vuln_version_exclusive = version.parse(node_cpe_match_element['versionStartExcluding'])
                        if version.parse(packageObj.installed_version) > earliest_vuln_version_inclusive:
                            cpeMatch = True
                    else:
                        cpeMatch = True
                # else:
                    # print('got here ----------------------------------')
                # print(latest_vuln_version_inclusive)
            elif 'versionEndExcluding' in node_cpe_match_element:
                latest_vuln_version_exclusive = version.parse(node_cpe_match_element['versionEndExcluding'])
                if version.parse(packageObj.installed_version) < latest_vuln_version_exclusive:
                    if 'versionStartIncluding' in node_cpe_match_element:
                        earliest_vuln_version_inclusive = version.parse(node_cpe_match_element['versionStartIncluding'])
                        if version.parse(packageObj.installed_version) >= earliest_vuln_version_inclusive:
                            cpeMatch = True
                    elif 'versionStartExcluding' in node_cpe_match_element:
                        earliest_vuln_version_exclusive = version.parse(node_cpe_match_element['versionStartExcluding'])
                        if version.parse(packageObj.installed_version) > earliest_vuln_version_inclusive:
                            cpeMatch = True
                    else:
                        packageObj.vulns_for_installed_version.append(cveItem)
                # else:
                    # print('also got here -----------------------------')
                    # packageObj.all_package_vulns.append(cveItem)


            # Consider thinking about dealing with operators by creating a list/dictionary containing all of the cpe's and just searching through it later 
            # to match cpe's with operators. May need to do this in the node child logic branch 
            if cpeMatch:
                packageObj.vulns_for_installed_version.append(cveItem)
                packageIsVulnerable = True

            # TODO: add logic to deal with other CPE that are not our product
            #       may need to change the parser so that all cpe's for the dependency tree are loaded then go through the cpe's later.
            # elif not cpeMatch : and
            
            packageObj.all_package_vulns.append(cveItem)


    return (cpeMatch, packageIsVulnerable)

def main():
    packagesToCheck = ["tensorflow"]
    output, errors = retrieve_raw_package_dependencies( packagesToCheck[0] )
    f = open("pip_list_results.txt", "w")
    f.write(output)
    f.close()

    dTree = parse_Pipdeptree_JSON_For_NVD_CVEs(output, packagesToCheck[0])

    # print(pip_list.stdout)
    # print(" 'pip_list' ran with exit code %d" %pip_list.returncode)

if __name__ == '__main__':
    main()