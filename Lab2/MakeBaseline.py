import datetime
import requests
from xml.etree import ElementTree

bigfix_server="https://bes-root.local:52311"
bes_username="mo"
bes_password="BES-Dev-1"
# Because we have not yet installed/configured a trusted certificate for the BigFix Root Server,
# we need to ignore certificate errors when connecting to it
verify=False
baseline_site="custom/Test"

baseline_template="""<?xml version="1.0" encoding="UTF-8"?>
<BES xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BES.xsd">
	<Baseline>
		<Title>My Baseline Title</Title>
		<Description>My Baseline Description</Description>
		<Relevance>true</Relevance>
		<Category>Custom Baseline Category</Category>
		<Source>Internal</Source>
		<SourceID></SourceID>
		<SourceReleaseDate>2021-07-15</SourceReleaseDate>
		<SourceSeverity>N/A</SourceSeverity>
		<CVENames></CVENames>
		<SANSID></SANSID>
		<MIMEField>
			<Name>x-fixlet-modification-time</Name>
			<Value>Thu, 15 Jul 2021 12:34:36 -0500</Value>
		</MIMEField>
		<Domain>BESC</Domain>
		<BaselineComponentCollection>
		</BaselineComponentCollection>
	</Baseline>
</BES>
"""


def to_bes_time(
    time=datetime.datetime.now(datetime.datetime.now().astimezone().tzinfo)
):
    """
    Given a datetime object with timezone(defaulting to current time and local time zone),
    return a BES formatted time string with zone offset
    Examples:
    to_bes_time() -> 'Sun, 22 Sep 2024 15:50:44 -0500'
    to_bes_time(datetime.datetime.now().astimezone(datetime.timezone.utc)) -> 'Sun, 22 Sep 2024 20:51:38 +0000'
    """
    return time.strftime("%a, %d %b %Y %H:%M:%S %z")

def to_bes_date(
    date=datetime.datetime.now(datetime.datetime.now().astimezone().tzinfo)
):
    """
    Given a datetime object with timezone(defaulting to current time and local time zone),
    return a BES formatted date string, i.e. '2024-04-23'
    """
    return date.strftime("%Y-%m-%d")

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
        raise ValueError(f"Query failed with {response.status_code}, message {response.text}, unable to continue")
    return response

def create_baseline_component( name, 
                               source_site_url, 
                               source_id, 
                               action_name, 
                               action_script, 
                               relevance, 
                               success_criteria="OriginalRelevance",
                               script_type="application/x-Fixlet-Windows-Shell", 
                               include_in_relevance="true"):
    """Creates a BaselineComponent from an existing Fixlet """
    
    # A BaselineComponent is an XML element with the following example structure:
    #
    # <BaselineComponent 
    #       Name="CustomFixlet1" 
    #       IncludeInRelevance="true" 
    #       SourceSiteURL="http://{root-server}:52311/cgi-bin/bfgather.exe/actionsite" 
    #       SourceID="40" 
    #       ActionName="Action1"
    #       >
    #    <ActionScript MIMEType="application/x-Fixlet-Windows-Shell">// Action Script </ActionScript>
    #    <SuccessCriteria Option="CustomRelevance">Relevance</SuccessCriteria>
    #    <Relevance>true</Relevance>
    # </BaselineComponent>

    # Create a new Element of type "BaselineComponent"
    component=ElementTree.Element("BaselineComponent")

    # TODO: Update the attributes and append the child elements for this fixlet

    # TODO: Create an Element of type "ActionScript", set attributes and values, and append it to the component    
    
    # TODO: Create an Element of type "SuccessCriteria", set attributes and values, and append it to the component

    # TODO: Create an Element of type "Relevance", set attributes and values, and append it to the component
    
    # Return the filled-out component
    return component


response=test_login(bigfix_server, bes_username, bes_password, verify=verify)

# Run a Session Relevance query that returns the fields we need to create a baseline from fixlets.
data = {
    "relevance": (
        """
(
    name of it
    , url of site of it
    , id of it
    , content id of (default action of it | action 0 of it)
    , script of (default action of it | action 0 of it)
    , relevance of it
    , (if (success on run to completion of (default action of it | action 0 of it)) then "RunToCompletion" else "OriginalRelevance") of it
    , script type of (default action of it | action 0 of it)
    , type of it
) of fixlets whose (
    fixlet flag of it
    and exists applicable computers of it 
    and exists default action of it
) of all bes sites whose (name of it = "Enterprise Security") 
"""
    ),
    "output": "json",
}

url=bigfix_server + "/api/query"
response=run_query(url, data, bes_username, bes_password, verify)
response_json=response.json()
fixlet_list=response_json["result"]

# Load the baseline XML template
baseline_xml=ElementTree.fromstring(baseline_template)

# Create  a BaselineComponentGroup element
component_group=ElementTree.Element("BaselineComponentGroup")
component_group.set("Name", "New Component Group")

# Loop through the fixlets retrieved by the query, and create a BaselineComponent for each.
for fixlet in fixlet_list:
    component=create_baseline_component( name=fixlet[0], 
                            source_site_url=fixlet[1], 
                            source_id=fixlet[2], 
                            action_name=fixlet[3], 
                            action_script=fixlet[4], 
                            relevance=fixlet[5], 
                            success_criteria=fixlet[6],
                            script_type=fixlet[7], 
                            include_in_relevance=("true" if fixlet[8]=="Fixlet" else "false")
                            )
    # TODO - append the new component to the component_group


# TODO - find the BaselineComponentCollection element in the baseline_xml and append the component_group to it

modification_time=baseline_xml.find(".//MIMEField[Name='x-fixlet-modification-time']/Value")
if modification_time is not None:
    modification_time.text=to_bes_time()

# TODO - find the SourceReleaseDate element in the baseline_xml and set it to the current date


response=requests.post(url=f'{bigfix_server}/api/baselines/{baseline_site}', data=ElementTree.tostring(baseline_xml), headers={'Content-Type': 'text/xml'}, auth=(bes_username, bes_password), verify=verify)
if response.ok:
    print(f"Baseline creation succeeded with {response.status_code}, message {response.text}")
else:
    raise ValueError(f"Baseline creation failed with {response.status_code}, message {response.text}, unable to continue")
