#Call Example
#python3 ./_vul.py --isAdmin=Y --org=4c503fed-f788-41f5-bdcb-55bb41188364 --issueId=SNYK-JAVA-C3P0-461017 --projectId=a78d9f03-8da4-4617-875d-d8e4fb90a504 --jiraProjectId=123 --jiraIssueType=1 --jiraSummary="description for jira"

#no expiration time for ignore
import argparse
import json
import re
import sys

import requests
import urllib3

from snyk import SnykClient
from utils import get_default_token_path, get_token


def parse_command_line_args():
    parser = argparse.ArgumentParser(description="Snyk API Examples")
    parser.add_argument("--isAdmin", type=str, help="Is the user admin", required=True)
    parser.add_argument("--orgId", type=str, help="The Snyk Organisation Id", required=True)
    parser.add_argument("--projectId", type=str, help="The project ID in Snyk", required=True)
    parser.add_argument("--issueId", type=str,help="The Snyk Issue Id", required=True)
    parser.add_argument("--jiraProjectId", type=int, help="The Jira Project ID", required=True)
    parser.add_argument("--jiraIssueType", type=int, help="The Jira issue type", required=True)
    parser.add_argument("--jiraSummary", type=str, help="The summary of the Jira issue", required=True)
    parser.add_argument("--reasonType", type=str, help="Ignore Reason Type", required=False)
    args = parser.parse_args()

    return args


snyk_token_path = get_default_token_path()
snyk_token = get_token(snyk_token_path)
args = parse_command_line_args()
org_id = args.orgId
project_id = args.projectId
issue_id = args.issueId
jira_project_id = args.jiraProjectId
jira_issue_type = args.jiraIssueType
jira_summary = args.jiraSummary
isAdmin = args.isAdmin
reason_type = args.reasonType
client = SnykClient(token=snyk_token)

if isAdmin in( "Y", "y"):
    is_admin = True
elif isAdmin in( "N", "n"):
    is_admin = False
else:
    print("Wrong value for admin")
    ys.exit()

if is_admin:
    values_object = {
        "ignorePath": "",
        "reasonType": reason_type,
        "disregardIfFixable": False,
        "reason": jira_summary
    }

    api_url = "org/" + org_id + "/project/" + project_id + "/ignore/" + issue_id
    print(api_url )
    #real Call
    #r2 = client.post(api_url, values_object)
else:
    print("create(" ,  str(issue_id) , "projectid" , str(jira_project_id) ," issuetype " , str(jira_issue_type) , " summary" , jira_summary)

    #project.jira_issues.create(issue_id, {"project": {"id": jira_project_id}, "issuetype": {"id": jira_issue_type}, "summary": "%s - %s" % (project.name, issue.title)})
