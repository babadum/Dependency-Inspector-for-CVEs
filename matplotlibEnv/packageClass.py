# Package class for easier processing of the nodes of the deptree

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
        packageString = 'package: ' + self.package_name + ' | depth: ' + str(self.depth) + ' | installed version: ' + self.installed_version

        if len(self.required_versions) > 0:
            packageString += ' \n\n\t required versions: ['

            for i in range(len(self.required_versions)):
                if i == 0:
                    packageString += '\n\t'
                packageString += str(self.required_versions[i]) 
                if i != len(self.required_versions)-1:
                    packageString += ', '

            packageString += '\n\t]\n'
        else:
            packageString += ' \n\t required versions: []'

        if len(self.dependencies) > 0:
            packageString += ' \n\n\t dependencies: ['

            for i in range(len(self.dependencies)):
                if i == 0:
                    packageString += '\n\t'
                packageString += str(self.dependencies[i]) 
                if i != len(self.dependencies)-1:
                    packageString += '\t '

            packageString += '\n\t]\n'
        else:
            packageString += ' \n\t dependencies: []'

        if len(self.vulns_for_installed_version) > 0:
            packageString += ' \n\t vulns for installed version: ['

            for i in range(len(self.vulns_for_installed_version)):
                if i == 0:
                    packageString += '\n\t'
                packageString += str(self.vulns_for_installed_version[i]['cve']['CVE_data_meta']['ID']) 
                if i != len(self.vulns_for_installed_version)-1:
                    packageString += ', '

            packageString += '\n\t]\n'
        else:
            packageString += ' \n\t vulns for installed version: []'

        if len(self.all_package_vulns) > 0:
            packageString += ' \n\t all vulns for any version: ['

            for i in range(len(self.all_package_vulns)):
                if i == 0:
                    packageString += '\n\t'
                packageString += str(self.all_package_vulns[i]['cve']['CVE_data_meta']['ID']) 
                if i != len(self.all_package_vulns)-1:
                    packageString += ', '

            packageString += '\n\t]\n'
        else:
            packageString += ' \n\t all vulns for any version: []'


        packageString += '\n'

        return packageString 
