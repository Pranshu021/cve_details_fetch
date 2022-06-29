#CVE_DETAILS_FETCH

A cve information fetcher utility.

Functionality :
- Search for a specific CVE details or generate a full Report in json format. Output contains information like - Severity, Project affected, References, Published Date etc.
- Search a list of cve's for a particular project. Optional Search Parameters - startDate, endDate, severity



USAGE:

- Fetch cve information and display on console : 
            cve_details_fetch.py cve --id CVE-2022-23307
- Generate a full json report for CVE : 
            cve_detauls_fetch.py cve --id CVE-2022-23307 --fullReport
- Generate a list of cve's for a particular project : 
            cve_details_fetch.py project --name Ansible
- Generate a list using additional parameters:
            cve_details_fetch.py project --name Ansible --startDate 2021-09-02 --endDate 2021-11-02 --severity HIGH
