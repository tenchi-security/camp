#!/usr/bin/env python3
import os, os.path, logging, sys, json, multiprocessing, argparse
from datetime import datetime
import boto3
from cloudsplaining.command.scan_policy_file import scan_policy

# download policy files using boto3 IAM APIs
def download_policies(client, location: str, force: bool =False):
    logger = logging.getLogger("camp")
    num_policies = 0
    num_versions = 0
    num_skipped = 0
    for policy_page in client.get_paginator('list_policies').paginate(Scope='AWS'):
        for policy in policy_page['Policies']:
            policy_path = os.path.join(location, 'policies', policy['PolicyName'])
            metadata_fname = os.path.join(policy_path, 'metadata.json')
            os.makedirs(policy_path, exist_ok=True)

            # skip this if we have up-to-date information already
            if not force and os.path.isfile(metadata_fname):
                with open(metadata_fname, "r") as f:
                    existing = json.load(f)
                    if datetime.fromisoformat(existing['UpdateDate']) >= policy['UpdateDate']:
                        logger.debug(f"Skipping policy {policy['PolicyName']}")
                        num_skipped += 1
                        continue

            # check versions
            for version_page in client.get_paginator('list_policy_versions').paginate(PolicyArn=policy['Arn']):
                for version in version_page['Versions']:
                    version_path = os.path.join(policy_path, version['VersionId'])
                    logger.info(f"Saving policy {policy['PolicyName']} version at {version['VersionId']}")
                    os.makedirs(version_path, exist_ok=True)
                    version['CreateDate'] = version['CreateDate'].isoformat()
                    with open(os.path.join(version_path, "metadata.json"), "w") as f:
                        json.dump(version, f, indent=4)
                    document = client.get_policy_version(PolicyArn=policy['Arn'], VersionId=version['VersionId'])['PolicyVersion']['Document']
                    with open(os.path.join(version_path, "policy.json"), "w") as f:
                        json.dump(document, f, indent=4)
                    num_versions += 1

            # save metadata
            logger.info(f"Saving policy {policy['PolicyName']} metadata")
            policy['CreateDate'] = policy['CreateDate'].isoformat()
            policy['UpdateDate'] = policy['UpdateDate'].isoformat()
            with open(os.path.join(policy_path, "metadata.json"), "w") as f:
                json.dump(policy, f, indent=4)
            num_policies += 1
    logger.info(f'Downloaded {num_versions} versions of {num_policies} policies, skipped {num_skipped} existing downloaded policies.')

# generator of policy directory paths
def iter_policies(location: str) -> str:
    for policydir in os.scandir(os.path.join(location, 'policies')):
        if not policydir.is_dir():
            continue
        yield policydir.path

# generator of policy version paths from a policy directory
def iter_policy_versions(policydir: str) -> str:
    for versiondir in os.scandir(policydir):
        if not versiondir.is_dir():
            continue
        yield versiondir.path

# iterates through each policy version and runs CloudSplaining on the policy document
def scan_policies(location: str, force: bool =False):
    logger = logging.getLogger("camp")
    num_versions = 0
    num_skipped = 0
    pool = multiprocessing.Pool()

    for policy in iter_policies(location):
        for version in iter_policy_versions(policy):
            output_fname = os.path.join(version, 'cloudsplaining.json')
            if force or not os.path.exists(output_fname):
                input_fname = os.path.join(version, 'policy.json')
                pool.apply_async(run_cloudsplaining, [input_fname, output_fname],
                                 callback=lambda x: logger.info(f'Saved {x}'),
                                 error_callback=lambda x: logger.exception(x))
                num_versions += 1
            else:
                logger.debug(f"Skipping existing {output_fname}")
                num_skipped += 1
    pool.close()
    pool.join()
    logger.info(f"Scanned {num_versions} policy versions, skipped {num_skipped} policy versions with existing scan results.")

# helper function that runs CloudSplaining on a policy and saves it to a specific file
def run_cloudsplaining(input_fname: str, output_fname: str) -> str:
    with open(input_fname, 'r') as input_file:
        policy = json.load(input_file)
        results = scan_policy(policy)
        with open(output_fname, 'w') as output_file:
            json.dump(results, output_file, indent=4)
            return output_fname

# help function to execute a single CLI command
def handle_args(args):
    if args['command'] == 'download':
        client = boto3.Session(profile_name=args['profile']).client('iam')
        download_policies(client, args['location'], args['force'])
    elif args['command'] == 'scan':
        scan_policies(args['location'], args['force'])

# main code when executed as a CLI
if __name__ == "__main__":
    # set up logger
    logger = logging.getLogger("camp")
    logger.propagate = False
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # setup main argument parser
    parser = argparse.ArgumentParser(
        prog='camp',
        description='Command-line utility to download and analyze AWS IAM Managed Policies using CloudSplaining',
        epilog="Copyright 2020 Tenchi Security - All rights reserved")
    parser.add_argument("-l", "--location",
                        help="directory in which policy files will be stored",
                        required=False, type=str, default=os.getcwd())
    subparsers = parser.add_subparsers()

    # download sub-parser
    org_parser = subparsers.add_parser('download',
                                       help='download updated policies using AWS IAM API calls',
                                       description='download updated policies using AWS IAM API calls')
    parser.add_argument("-p", "--profile",
                        help="which profile to obtain AWS credentials for the Organization master account",
                        required=False, default=None)
    org_parser.add_argument("-f", "--force", help='re-download policies even if they are already on disk',
                            action='store_true')
    org_parser.set_defaults(command="download")

    # scan sub-parser
    org_parser = subparsers.add_parser('scan',
                                       help='process policies using CloudSplaining',
                                       description='process policies using CloudSplaining')
    org_parser.add_argument("-f", "--force", help='re-download policies even if they are already on disk',
                            action='store_true')
    org_parser.set_defaults(command="scan")

    # parse and start execution
    args = vars(parser.parse_args())
    if 'command' not in args:
        args['force'] = False
        for command in ('download', 'scan'):
            args['command'] = command
            handle_args(args)
    else:
        handle_args(args)
