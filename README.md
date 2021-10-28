# CloudSplaining on AWS Managed Policies (camp)

This is a tool that automatically downloads and keeps a local copy of all [AWS IAM Managed Policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html#aws-managed-policies), and also runs [Cloudsplaining](https://cloudsplaining.readthedocs.io/en/latest/) on each.

The code is written in Python 3. It was built to be executed regularly, and just download and analyze new policies and versions that are not in the local directory yet. The execution of Cloudsplaining is parallelized over downloaded policies.

## Installation
        $ make install

## Usage
This will run camp telling it to populate policies and Cloudsplaining output at `./policies`:

        $ make run

## Data
This repo uses GitHub actions to download and analyse any new policies and versions every 2 hours.

The directory structure is as follows:

Each policy gets a directory called `./policies/{policy name}`. Inside it there is a file called `metadata.json` with a structure similar to this:
```{json}
{
    "PolicyName": "AdministratorAccess",
    "PolicyId": "ANPAIWMBCKSKIEE64ZLYK",
    "Arn": "arn:aws:iam::aws:policy/AdministratorAccess",
    "Path": "/",
    "DefaultVersionId": "v1",
    "AttachmentCount": 5,
    "PermissionsBoundaryUsageCount": 0,
    "IsAttachable": true,
    "CreateDate": "2015-02-06T18:39:46+00:00",
    "UpdateDate": "2015-02-06T18:39:46+00:00"
}
```

Additionally, each policy version gets a directory called `./policies/{policy name}/{policy version}` with three files:
* `policy.json` which contains the actual IAM policy content.
* `metadata.json` with a structure similar to this:
```{json}
{
    "VersionId": "v1",
    "IsDefaultVersion": true,
    "CreateDate": "2015-02-06T18:39:46+00:00",
    "PolicyName": "AdministratorAccess"
}
```
* `cloudsplaining.json` with the output of Cloudsplaining processing.

On the root folder a CSV file called `versions_summary.csv` will also be created with a summary of findings, listing one policy version per row.

# Contributors
* Alexandre Sieira
* Victor Grenu

We want help! Two contributions that would be very much appreciated:
* Generating and keeping the HTML output of Cloudsplaining on the folders;
* Creation of a single page web application to interactively explore and visualize the summary and also the policy content.
