#!/usr/bin/env python3
"""
redlab attack #1 — make an S3 bucket public.

Generates two notable CloudTrail events:
  - PutBucketPublicAccessBlock  (disabling Block Public Access)
  - PutBucketPolicy             (attaching a public-read policy)

Usage:
  python attacks/s3_public_bucket.py            # perform the misconfiguration
  python attacks/s3_public_bucket.py --cleanup  # revert & delete the bucket
"""

import argparse
import json
import sys
import boto3
from botocore.exceptions import ClientError

PROFILE = "redlab"

# Derive account ID at runtime so nothing sensitive is hardcoded in the repo.
_sts = boto3.Session(profile_name=PROFILE).client("sts")
BUCKET = f"redlab-public-demo-{_sts.get_caller_identity()['Account']}"


def get_s3():
    session = boto3.Session(profile_name=PROFILE)
    return session.client("s3"), session.region_name


def attack():
    s3, region = get_s3()

    # 1. Create the bucket (us-east-1 must NOT send a LocationConstraint)
    try:
        if region == "us-east-1":
            s3.create_bucket(Bucket=BUCKET)
        else:
            s3.create_bucket(
                Bucket=BUCKET,
                CreateBucketConfiguration={"LocationConstraint": region},
            )
        print(f"[+] Created bucket: {BUCKET} ({region})")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
            print(f"[=] Bucket already exists: {BUCKET}")
        else:
            print(f"[!] create_bucket failed: {e}")
            sys.exit(1)

    # Tag it so it's clearly lab-created
    s3.put_bucket_tagging(
        Bucket=BUCKET,
        Tagging={"TagSet": [{"Key": "project", "Value": "redlab"},
                            {"Key": "purpose", "Value": "detection-test"}]},
    )

    # 2. THE MISCONFIG #1 — disable Block Public Access
    s3.put_public_access_block(
        Bucket=BUCKET,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    )
    print("[+] Disabled Block Public Access  -> CloudTrail: PutBucketPublicAccessBlock")

    # Harmless dummy object (so 'public read' is demonstrable, no real data)
    s3.put_object(Bucket=BUCKET, Key="hello.txt",
                  Body=b"this is a harmless redlab test object")

    # 3. THE MISCONFIG #2 — attach a public-read bucket policy
    public_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "PublicReadGetObject",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{BUCKET}/*",
        }],
    }
    s3.put_bucket_policy(Bucket=BUCKET, Policy=json.dumps(public_policy))
    print("[+] Attached public-read policy   -> CloudTrail: PutBucketPolicy")

    print(f"\n[✓] Done. Public object URL:\n    "
          f"https://{BUCKET}.s3.amazonaws.com/hello.txt")
    print("\nNow go look for PutBucketPublicAccessBlock and PutBucketPolicy "
          "in CloudTrail → Event history.")


def cleanup():
    s3, _ = get_s3()
    # Delete policy, then all objects, then the bucket itself.
    try:
        s3.delete_bucket_policy(Bucket=BUCKET)
        print("[-] Removed bucket policy")
    except ClientError as e:
        print(f"[=] bucket policy: {e.response['Error']['Code']}")

    try:
        objs = s3.list_objects_v2(Bucket=BUCKET).get("Contents", [])
        for o in objs:
            s3.delete_object(Bucket=BUCKET, Key=o["Key"])
            print(f"[-] Deleted object: {o['Key']}")
        s3.delete_bucket(Bucket=BUCKET)
        print(f"[-] Deleted bucket: {BUCKET}")
    except ClientError as e:
        print(f"[=] cleanup: {e.response['Error']['Code']}")

    print("\n[✓] Teardown complete.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cleanup", action="store_true",
                        help="Revert the misconfiguration and delete the bucket")
    args = parser.parse_args()
    cleanup() if args.cleanup else attack()