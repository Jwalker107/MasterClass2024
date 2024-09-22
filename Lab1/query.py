### This is a simple REST script used to demonstrate using some VSCode Debugger.
### There are KNOWN errors in this script, and it is intended to be used to demonstrate debugging features.

import requests

bigfix_server="https://BESFNDWINROOT:52311"
bes_username="api-user"
bes_password=""


def test_login(bigfix_server, bes_username, bes_password, verify):
    response=requests.get(bigfix_server + "/api/login", auth=(bes_username, bes_password), verify=verify)
    if response.ok:
        print(f"Login succeeded with {response.status_code}, message {response.text}")
    else:
        raise ValueError(f"Login failed with {response.status_code}, message {response.text}, unable to continue")

def run_query(url, data, bes_username, bes_password, verify):
    response=requests.post(url=url, data=data, auth=(bes_username, bes_password), verify=verify)
    if response.ok:
        print(f"Query succeeded with {response.status_code}, message {response.text}")
    else:
        raise ValueError(f"Login failed with {response.status_code}, message {response.text}, unable to continue")
    return response

# Because we have not yet installed/configured a trusted certificate for the BigFix Root Server,
# we need to ignore certificate errors when connecting to it
verify=False
response=test_login(bigfix_server, bes_username, bes_password, verify=verify)


# Create a dictionary of the fields and values to POST to run the query.
# At minimum we need a 'relevance' field with the query to run
# Optionally we may also define a field 'output':'json' to get the results in JSON format rather than XML
data= {
    "relevance": """
(id of it, name of it | "no name", last report time of it) 
of bes computers
"""
}

url=bigfix_server + "api/query"
response=requests.post(url, data, bes_username, bes_password, verify)

print(response.text)