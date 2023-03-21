import requests
import json
import logging
import base64
import sys
import ssl
import subprocess
import os
import shutil
import time
import argparse


def configure_logging():
    logging.basicConfig(format="%(asctime)s - %(levelname)s - %(message)s", level=logging.INFO)


def _set_headers(creds):
    headers = {
        "Authorization": "Basic %s" % creds,
        "Content-Type": "application/json",
    }
    return headers


def encode_creds():
    creds = os.environ['SECURITY_USR'] + ':' + os.environ['SECURITY_PWD']
    return base64.b64encode(creds.encode("ascii")).decode("ascii")


def get_projects(creds, domain):
    response = requests.request("GET", f"{domain}/rest/api/1.0/projects", headers=_set_headers(creds), verify=True)

    if response.status_code == 401:
        logging.error(f"Failed to get projects for Domain {domain}. Jenkins user needs to be an admin of the domain or project")
        exit(1)
    elif response.status_code == 200:
        logging.info(f"Successfully found the projects for Domain: {domain}.")
        return response.json()
    else:
        logging.error(f"Failed to get projects for Domain: {domain} . Status Code: {response.status_code}")
        exit(1)


def get_slugs(creds, domain, project):
    response = requests.request("GET", f"{domain}/rest/api/1.0/projects/{project}/repos", headers=_set_headers(creds), verify=True)

    if response.status_code == 401:
        logging.error(f"Failed to get slugs for project {project}. Jenkins user needs to be an admin of the project or repo")
        exit(1)
    elif response.status_code == 200:
        return response.json()
    else:
        logging.error(f"Failed to get slugs for project {project}. Status Code: {response.status_code}")
        exit(1)


def get_report_status(creds, domain, project, slug):
    url = f"{domain}/rest/security/1.0/scan/{project}/repos/{slug}"

    response = requests.request("GET", url, headers=_set_headers(creds), verify=True)
    if response.status_code == 200:
        scanned = response.json()['scanned']
        logging.info(f"Project {project} has been scanned status equals {scanned}")
    elif response.status_code == 404:
        logging.error(f"Project {project} may not have a branch. Going to skip slug.")
        return False
    elif response.status_code == 500:
        logging.info(f"Failed to get slug status, triggering scan to resolve problem. Status Code: {response.status_code} Slug: {slug}")
        scanned = False
    else:
        logging.error(f"Failed to get slugs status. Status Code: {response.status_code} Reason: {response.reason} Slug: {slug} URL: {url}")
        exit(1)

    if scanned == False:
        response = requests.request("POST", url, headers=_set_headers(creds), verify=True)
        if response.status_code == 200:
            if response.json()['progress'] == 100:
                logging.info(f"Project {project} has been scanned status equals {response.json()['progress']}")
                return False
            else:
                logging.info(f"Project {project} has been scanned status equals {response.json()['progress']}")
                return True
        else:
            logging.error(f"Failed to scan slugs. Status Code: {response.status_code} URL: {url}")
            exit(1)
    else:
        return False


def get_scanresults(creds, domain, project, slug):
    payload = {
        # 'branch' : '',
        # 'ruleType' : '',
        # 'includeWhitelisted' : ''
    }
    response = requests.request("GET", f"{domain}/rest/security/1.0/export-report/{project}/repos/{slug}", headers=_set_headers(creds), data=payload, verify=True)

    if response.status_code == 401:
        logging.error("Failed to get scan results. Jenkins user needs to be an admin of the project or repo")
        exit(1)
    elif response.status_code == 404:
        return ""
    elif response.status_code == 200:
        return response.text
    else:
        logging.error(f"Failed to get scan results. Status Code: {response.status_code}")
        exit(1)


def main():
    creds = encode_creds()
    resultsfile = 'results.csv'
    bitbucket = os.environ['BITBUCKET']

    projects = get_projects(creds, bitbucket)
    if(projects == 'None'):
        exit(1)

    project_count = len(projects['values'])
    logging.info(f'Project Count: {project_count}')

    for proj in projects['values']:
        projectkey = proj['key']
        with open(resultsfile, 'a') as f:
            f.write(projectkey + "\n")

        repos = get_slugs(creds, bitbucket, projectkey)
        if (repos == 'None'):
            exit(1)

        repo_count = len(repos['values'])
        logging.info(f'Project: {projectkey} Repo Count: {repo_count}')

        for repo in repos['values']:
            with open(resultsfile, 'a') as f:
                f.write(repo['slug'] + "\n")

            while get_report_status(creds, bitbucket, projectkey, repo['slug']):
                time.sleep(30)
                logging.info("Waiting for report generation...")
            else:
                results = get_scanresults(creds, bitbucket, projectkey, repo['slug'])
                with open(resultsfile, 'a') as f:
                    f.write(results.replace(" ", "").replace("\n", ""))


if __name__ == '__main__':
    main()
