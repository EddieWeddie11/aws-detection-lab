# Cloud Misconfiguration Detection Lab

A hands-on lab that simulates common AWS misconfigurations (red team) and
detects them (blue team) — built to understand the full
**attack → signal → detection** loop from both sides.

## Why

I work as a SOC analyst analysing security signals. This project recreates the
attacker actions that *generate* those signals, so I can understand detections
from the inside out.

## Architecture

Attacker action (boto3)  ─►  CloudTrail event  ─►  S3 logs
                                                     │
                                                     ▼
                          Detection: prowler / checkov / Datadog Cloud SIEM

## Safety

- All actions run in an **isolated throwaway AWS sandbox account** with a budget alarm.
- A dedicated least-privilege `redlab-attacker` IAM identity performs the actions,
  so every event is clearly attributable in CloudTrail.
- Every attack script ships with a `--cleanup` teardown.

## Attacks implemented

| # | Attack | CloudTrail events | Detection |
|---|--------|-------------------|-----------|
| 1 | Public S3 bucket | `PutBucketPublicAccessBlock`, `PutBucketPolicy` | prowler `s3_bucket_public_access` |

## Usage

    python -m venv .venv && source .venv/bin/activate
    pip install -r requirements.txt
    python attacks/s3_public_bucket.py            # run attack
    python attacks/s3_public_bucket.py --cleanup  # tear down

## Roadmap

- [ ] IAM over-permissive policy
- [ ] Disable CloudTrail (defence evasion)
- [ ] Map each attack to a Sigma rule + Datadog detection

## What I learnt 

- Navigating AWS Portal and how configuration and attention to detail is very important 
- When creating a repo, having proper file structure is important and professional 
- Everything in the cloud is abstract in a way that, there are no visuals on what is happening unlike front-end development 
- Everything in the cloud is about proper configuration - one small misconfiguration can leave the door wide open
