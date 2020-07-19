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


def _set_headers(username: str = None, api_key: str = None):
    headers = {'Content-Type': 'application/json'}
    if username:
        headers['Authorization'] = f'Basic {username}'
    if api_key:
        headers['Authorization'] = f'Bearer {api_key}'

    return headers


def process_api_request(url: str, verb: str, headers: dict, data: dict = None, params: dict = None):
    try:
        if data:
            r = getattr(requests, verb.lower())(url, headers=headers, data=json.dumps(data))
        elif params:
            r = getattr(requests, verb.lower())(url, headers=headers, params=json.dumps(params))
        else:
            r = getattr(requests, verb.lower())(url, headers=headers)

        r.raise_for_status()
    except Exception as e:
        logging.error(f'An error occured executing the API call: {e}')

    try:
        return r.json()
    except Exception as e:
        logging.error(f'An error occured loading the content: {e}')
        return None


def encode_creds():
    creds = os.environ['SECURITY_USR'] + ':' + os.environ['SECURITY_PWD']
    return base64.b64encode(creds.encode("ascii")).decode("ascii")


def get_project(creds, domain, project):
    headers = {
        "Authorization": "Basic %s" % creds,
        "Content-Type": "application/json",
    }
    response = requests.request("GET", f"{domain}/rest/api/1.0/projects/{project}", headers=headers, verify=False)

    if response.status_code == 200:
        logging.info(f"Successfully found the project {project}.")
        return response.json()
    else:
        logging.error(f"Failed to get project {project} . Status Code: {response.status_code}")
        exit(1)


def get_slugs(creds, domain, project):
    headers = {
        "Authorization": "Basic %s" % creds,
        "Content-Type": "application/json",
    }

    response = requests.request("GET", f"{domain}/rest/api/1.0/projects/{project}/repos", headers=headers, verify=False)

    if response.status_code == 401:
        logging.error(f"Failed to get slugs for project {project}. Jenkins user needs to be an admin of the project or repo")
        exit(1)
    elif response.status_code == 200:
        return response.json()
    else:
        logging.error(f"Failed to get slugs for project {project}. Status Code: {response.status_code}")
        exit(1)


def get_report_status(creds, domain, project, slug):
    headers = {
        "Authorization": "Basic %s" % creds,
        "Content-Type": "application/json",
    }

    url = f"{domain}/rest/security/1.0/scan/{project}/repos/{slug}"
    response = requests.request("GET", url, headers=headers, verify=False)
    if response.status_code == 200:
        scanned = response.json()['scanned']
        logging.info(f"Project {project} has been scanned status equals {scanned}")
    elif response.status_code == 404:
        logging.error(f"Project {project} may not have a branch. Going to skip slug.")
        return False
    elif response.status_code == 500:
        logging.error(f"Failed to get slug status, skipping slug. Status Code: {response.status_code} Slug: {slug} URL: {url}")
    else:
        logging.error(f"Failed to get slugs status. Status Code: {response.status_code} Reason: {response.reason} Slug: {slug} URL: {url}")
        exit(1)

    if scanned == False:
        response = requests.request("POST", url, headers=headers, verify=False)
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
    headers = {
        "Authorization": "Basic %s" % creds,
        "Content-Type": "application/json",
    }
    payload = {
        # 'branch' : '',
        # 'ruleType' : '',
        # 'includeWhitelisted' : ''
    }
    response = requests.request("GET", f"{domain}/rest/security/1.0/export-report/{project}/repos/{slug}", headers=headers, data=payload, verify=False)

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

    allrepos = os.environ['AllRepositoriesInProject']
    projectkey = os.environ['PROJECTKEY']
    bitbucket = os.environ['BITBUCKET']
    slug = os.environ['REPOSITORY']

    with open(resultsfile, 'a') as f:
        f.write(projectkey)

    if (allrepos == 'true'):
        repos = get_slugs(creds, bitbucket, projectkey)
        if (repos == 'None'):
            exit(1)

        for repo in repos['values']:
            with open(resultsfile, 'a') as f:
                f.write(repo['slug'])

            while get_report_status(creds, bitbucket, projectkey, repo['slug']):
                time.sleep(30)
                logging.info("Waiting for report generation...")
            else:
                results = get_scanresults(creds, bitbucket, projectkey, repo['slug'])
                open(resultsfile, 'a').write(results.replace(" ", "").replace("\n", ""))
    else:
        while get_report_status(creds, bitbucket, projectkey, slug):
            time.sleep(30)
            logging.info("Waiting for report generation...")
        else:
            results = get_scanresults(creds, bitbucket, projectkey, slug)
            open(resultsfile, 'a').write(results.replace(" ", "").replace("\n", ""))


if __name__ == '__main__':
    main()
