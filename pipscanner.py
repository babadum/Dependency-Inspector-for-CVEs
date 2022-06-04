# Author: Alex Tum

# import os
import subprocess
import json
import requests
import time
from packaging import version
from packageClass import Package

# Globals
# deptree: A dictionary containing package objects with key = packageNameString and value = package objects
# {packageName: PackageObject}

parentPackage = None
deptree = {}

# cpeDict: A dictionary of cpe's where the key = cpe and value = [CVEs] 
cpeDict = {}
# print(deptree[0]['package']['package_name'])
jsonDeptree = []

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

    i = 0 # For testing only


    # deptree is a list of dictionaries that contain the packages and dependencies
    # This for loop fills the deptree with CVEs for each package
    for packageJSONEntry in jsonDeptree:
        packageName = packageJSONEntry['package']['key']
        # packageNames.append(packageName)

        #may need to check if package already exists in deptree before creating a new package object
        if ((packageName in deptree) and (packageName != parentName)) or ((parentName == packageName) and packageName in deptree):
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


        #Adding CVEs should only occur for each packageJSONEntry and not when every package or dependency is created.
        time.sleep(.05)
        # Tested getCVEData with a keyword search, may need to compare against a cpeMatchString search
        # cveResponse = getCVEData(["keyword"], [packageObj.package_name])

        cveResponse = getCVEData(["cpeMatchString"], ['cpe:/::' + packageObj.package_name])
        # print(cveResponse)
        parse_CVEs(cveResponse, packageObj, cpeDict)

    
        # print(packageArrayObject)

        # For testing, limits number of results
        # i+=1
        # if i>=20:
        #     break

    return (deptree, parentPackage, cpeDict)


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
# NEWTODO: Use to evaluate the data after cpe's have been retrieved
#          Use what is currently in this function to fill the cpe's and do the version matching using different logic.
def package_version_match_CVEs(dependencyTree, cpeDict):
    # packageCVEMatch = False
    # cpeMatch = False

    # Parse through the deptree and match CVEs and CPE's for the given package to decide if vulnerable.
    # May need to duplicate parts of parse_CVE_config_nodes() in order to evaluate the parent/child node relationships

    for package_key in dependencyTree:
        # cpeMatch = False
        package = dependencyTree[package_key]
        # If there are no CVE results then move on to next package
        if not package.all_package_vulns:
            continue
        else:
            for possibleCVE in package.all_package_vulns:
                packageCVEMatch = False
                if 'configurations' in possibleCVE:
                    if 'nodes' in possibleCVE['configurations']:
                        for node in possibleCVE['configurations']['nodes']:
                            # cpeDict =
                            cpeMatch = package_match_configurations(node, possibleCVE, package, cpeDict, dependencyTree)
                            if node['operator'].upper() == 'AND' and cpeMatch == False:
                                # packageCVEMatch = False
                                break
                            elif node['operator'].upper() == 'OR' and cpeMatch == True:
                                # packageCVEMatch = True
                                break
                        if cpeMatch == True:# node['operator'].upper() == 'AND' and packageCVEMatch == True:
                            packageCVEMatch = True
                if packageCVEMatch:# and (possibleCVE not in package.vulns_for_installed_version):
                    # print('packageCVEMatch: ' + str(packageCVEMatch) + ' cpeMatch: ' + str(cpeMatch))
                    package.vulns_for_installed_version.append(possibleCVE)
    return packageCVEMatch


# Similar to parse_CVE_config_nodes()
# Will do the cpe matching
def package_match_configurations(node, cve, packageObj, cpeDict, dependencyTree):
    cpeMatch = False
    # packageIsVulnerable = False
    # print('node: ' + str(node))

    

    if node['children']:
        # print('children' + str(node['children']))
        # if node['operator'].upper() == 'AND':
        for childNode in node['children']:
            if 'operator' in childNode:
                # print('childNode: ' + str(childNode))
                cpeMatch = package_match_configurations(childNode, cve, packageObj, cpeDict, dependencyTree) 
                if childNode['operator'].upper() == 'AND' and cpeMatch == False:
                    # packageIsVulnerable = False
                    break
                elif childNode['operator'].upper() == 'OR' and cpeMatch == True:
                    # packageIsVulnerable = True
                    break
                # if childNode['operator'].upper() == 'AND' and cpeMatch == False:
                #     packageIsVulnerable = False
                #May need to add branch to deal with negate operator
            else:
                print('ERROR: No operator in node')
        

    elif node['cpe_match']:
        # DONE May need to move all of the below branch code to a recursive function that allows us to take into account the operator for each cpe_match node.
        if node['operator'].upper() == 'AND':
            print('Found AND operator in cpe_match node')
        # print('cpe_match: ' + str(node['cpe_match']))
        for node_cpe_match_element in node['cpe_match']:
            UriList = node_cpe_match_element['cpe23Uri'].split(':')
            # # print('UriList: ' + str(UriList))
            cpe_product = UriList[4]
            cpe_product_version = UriList[5]
            # print('node_cpe_match_element: ' + str(node_cpe_match_element))
            # # cpeMatch = False
            cveID = cve['cve']['CVE_data_meta']['ID']
            # print("node_cpe_match_element_URI: " + node_cpe_match_element['cpe23Uri'])


            # See if the cpe node is vulnerable
            # cpe_is_vulnerable = False
            # if node_cpe_match_element['vulnerable'] != True and cpe_product != packageObj.package_name:
            #     # cpe_is_vulnerable = True
            # # else:
            #     continue

            cpePackageObj = packageObj
            # print('cpe_product: ' + cpe_product + ', packageObj.package_name: ' + packageObj.package_name + ', cpe_product != packageObj.package_name: ' + str(cpe_product != packageObj.package_name))
            # Retrieve the package that the cpe refers to if available
            if cpe_product != packageObj.package_name:
                if cpe_product not in dependencyTree:
                    continue
                else:
                    cpePackageObj = dependencyTree[cpe_product]


            # TODO: Fix this as it does not cover the cases where there is no version end.
            #           DONE Also move checking for package vulnerability status into different function
            #       Conduct evaluation after filling up a dictionary of cpe's where the key = cpe and value = [CVEs]
            #       May need to move this deeper after a check to see that the node element is applicable to the current package being assessed
            #       Also may be using the wrong packageObj to check installed versions as it should be checking for whichever package the cpe refers to
            #           Not the package that contains the cpe. 
            #       Need to add a check if there is no version range and instead a single version only appears in the cpe23Uri 
            # Retrieve range of vulnerable versions from configurations' node for the current package being evaluate
            cpe_package_installed_version = version.parse(cpePackageObj.installed_version)
            # print(cpe_product_version)
            if 'versionEndIncluding' in node_cpe_match_element:
                latest_vuln_version_inclusive = version.parse(node_cpe_match_element['versionEndIncluding'])
                if cpe_package_installed_version <= latest_vuln_version_inclusive:
                    if 'versionStartIncluding' in node_cpe_match_element:
                        earliest_vuln_version_inclusive = version.parse(node_cpe_match_element['versionStartIncluding'])
                        if cpe_package_installed_version >= earliest_vuln_version_inclusive:
                            cpeMatch = True
                    elif 'versionStartExcluding' in node_cpe_match_element:
                        earliest_vuln_version_exclusive = version.parse(node_cpe_match_element['versionStartExcluding'])
                        if cpe_package_installed_version > earliest_vuln_version_inclusive:
                            cpeMatch = True
                    else:
                        cpeMatch = True
                # else:

                # print('versionEndIncluding exists in the node_cpe_match_element ----------------------------------')
                # print('cpeMatch: ' + str(cpeMatch) + ' latest_vuln_version_inclusive: ' + str(latest_vuln_version_inclusive) + ' cpe_package_installed_version: ' + str(cpe_package_installed_version) + ' cpe_package_installed_version <= latest_vuln_version_inclusive: ' + str(cpe_package_installed_version <= latest_vuln_version_inclusive))
            elif 'versionEndExcluding' in node_cpe_match_element:
                latest_vuln_version_exclusive = version.parse(node_cpe_match_element['versionEndExcluding'])
                if cpe_package_installed_version < latest_vuln_version_exclusive:
                    if 'versionStartIncluding' in node_cpe_match_element:
                        earliest_vuln_version_inclusive = version.parse(node_cpe_match_element['versionStartIncluding'])
                        if cpe_package_installed_version >= earliest_vuln_version_inclusive:
                            cpeMatch = True
                    elif 'versionStartExcluding' in node_cpe_match_element:
                        earliest_vuln_version_exclusive = version.parse(node_cpe_match_element['versionStartExcluding'])
                        if cpe_package_installed_version > earliest_vuln_version_inclusive:
                            cpeMatch = True
                    else:
                        cpeMatch = True
                        # packageObj.vulns_for_installed_version.append(cveItem)
                # print('versionEndExcluding exists in the node_cpe_match_element ----------------------------------')
                # print('cpeMatch: ' + str(cpeMatch) + ' latest_vuln_version_exclusive: ' + str(latest_vuln_version_exclusive) + ' cpe_package_installed_version: ' + str(cpe_package_installed_version) + ' cpe_package_installed_version <= latest_vuln_version_exclusive: ' + str(cpe_package_installed_version < latest_vuln_version_exclusive))

            elif 'versionStartIncluding' in node_cpe_match_element:
                earliest_vuln_version_inclusive = version.parse(node_cpe_match_element['versionStartIncluding'])
                if cpe_package_installed_version >= earliest_vuln_version_inclusive:
                    cpeMatch = True
                # print('should not get here ----------------------------------')

            elif 'versionStartExcluding' in node_cpe_match_element:
                earliest_vuln_version_exclusive = version.parse(node_cpe_match_element['versionStartExcluding'])
                if cpe_package_installed_version > earliest_vuln_version_inclusive:
                    cpeMatch = True
            elif cpe_product_version != '*':
                # print('cpe_product_version: ' + cpe_product_version + ' cpe_package_installed_version == version.parse(cpe_product_version): ' + str(cpe_package_installed_version == version.parse(cpe_product_version)))
                if cpe_package_installed_version == version.parse(cpe_product_version):
                    cpeMatch = True
            elif cpe_product_version == '*' and cpeMatch == False:
                cpeMatch = True

                # else:
                    # print('also got here -----------------------------')
                    # packageObj.all_package_vulns.append(cveItem)


            if node['operator'].upper() == 'AND' and cpeMatch == False:
                break
            elif node['operator'].upper() == 'OR' and cpeMatch == True:
                break

    # TODO: May (weak maybe) need to add something to ensure that the final cpeMatch is correct and matches the operator.
    # if node['operator'].upper() == 'AND' and cpeMatch == False:

    # elif node['operator'].upper() == 'OR' and cpeMatch == True:
    #     break

    # May need to move the below if statement to right before the return
    # if cpeMatch == True: #node['operator'].upper() == 'AND' and packageIsVulnerable == True:
    #     packageIsVulnerable = True

    #print('cpeMatch: ' + str(cpeMatch))
    return cpeMatch #, packageIsVulnerable)


# Function: Goes through the cve entries for a package and fills the cpe dictionary
# NEWTODO: Have it add each possible vulnerability (this should be cveItem) to the packageObj COMPLETED
def parse_CVEs(cveReturn, packageObject, cpeDict):
    # for package in dependencyTree:
        # If there are no CVE results then move on to next package
    if cveReturn['resultsPerPage'] != 0:        
        for cveItem in cveReturn['result']['CVE_Items']:
            addCVE = False
            # print(cveItem)
            # print()
            if 'configurations' in cveItem:
                if 'nodes' in cveItem['configurations']:
                    #node is a list element
                    for node in cveItem['configurations']['nodes']:
                        # cpeDict =
                        addCVE = parse_CVE_config_nodes(node, cveItem, packageObject, cpeDict)
            # if addCVE:            
            packageObject.all_package_vulns.append(cveItem)

    # print( str(cpeDict))
    return 0

 

# Helper function for package_version_match_CVE
# Uses recursion for the Configurations tree.
def parse_CVE_config_nodes(node, cve, packageObj, cpeDict): #, parentOperator=False):
    # print('node: ' + str(node))

    if node['children']:
        # print('children' + str(node['children']))
        # if node['operator'].upper() == 'AND':
        for childNode in node['children']:
            parse_CVE_config_nodes(childNode, cve, packageObj, cpeDict) 

    elif node['cpe_match']:        
        # print('cpe_match: ' + str(node['cpe_match']))

        # node_cpe_match_element is a dictionary element in the node['cpe_match'] list
        for node_cpe_match_element in node['cpe_match']:    
            # print(node_cpe_match_element)
            UriList = node_cpe_match_element['cpe23Uri'].split(':')
            # print('UriList: ' + str(UriList))
            cpe_product = UriList[4]
            # print('node_cpe_match_element: ' + str(node_cpe_match_element))
            # cpeMatch = False

            if cpe_product != packageObj.package_name:
                #return false to indicate the cpe product does not apply to the selected package
                return 0

            # TODO: fill CPE dictionary
            cveID = cve['cve']['CVE_data_meta']['ID']
            if node_cpe_match_element['cpe23Uri'] not in cpeDict:
                cpeDict[node_cpe_match_element['cpe23Uri']] = {}

            if cveID not in cpeDict[node_cpe_match_element['cpe23Uri']]:
                cpeDict[node_cpe_match_element['cpe23Uri']][cveID] = cve
            
            
            # packageObj.all_package_vulns.append(cve)

    # Normal return
    return 1

# Traverses dTree and find out dependency depth
def Traverse_Tree_For_Dep_Depth(parentNodeObj, currentDepth):
    if parentNodeObj.depth == 0 or parentNodeObj.depth > currentDepth:
        parentNodeObj.depth = currentDepth
    if len(parentNodeObj.dependencies) > 0:
        for childNodeObj in parentNodeObj.dependencies:
            Traverse_Tree_For_Dep_Depth(childNodeObj, currentDepth + 1)
    return


# TODO: Build functionality that calculates the frequency of vulnerable dependencies at each depth of the deptree
def Calc_Num_of_Vulns_At_Dep_Depths(dependencyTree):
    # Dictionary where the key is each level of the dependency tree and the value is the number of vulnerabilities at each level
    vuln_count_depth_dict = {}

    for packageKey in dependencyTree:
        packageObj = dependencyTree[packageKey]
        # first check to see if the depth exists as a key in the dictionary
        if packageObj.depth in vuln_count_depth_dict:
            vuln_count_depth_dict[packageObj.depth] += len(packageObj.vulns_for_installed_version)



def main():
    packagesToCheck = ["numpy"] #tested with numpy and tensorboard packages.
    output, errors = retrieve_raw_package_dependencies( packagesToCheck[0] )
    f = open("pip_list_results.txt", "w")
    f.write(output)
    f.close()

    dTree, parentPackage, cpeDict = parse_Pipdeptree_JSON_For_NVD_CVEs(output, packagesToCheck[0])

    # TODO: Move CVEMatching to occur after filling up the data structures
    #       Conduct evaluation after filling up a dictionary of cpe's where the key = cpe and value = [CVEs]
    cveMatch = package_version_match_CVEs(dTree, cpeDict)


    Traverse_Tree_For_Dep_Depth(parentPackage, 0)

    for packageKey in dTree:
        print(dTree[packageKey])
        print()



    # print(cpeDict)

    # print(pip_list.stdout)
    # print(" 'pip_list' ran with exit code %d" %pip_list.returncode)

if __name__ == '__main__':
    main()