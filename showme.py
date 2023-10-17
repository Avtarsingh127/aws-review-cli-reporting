# Code Snippet 20

# showreport.py

import argparse,pprint

import boto3
from utils.aws_utils import *

def main():
    parser = argparse.ArgumentParser(description="AWS EC2 instance report")
    
    parser.add_argument('--service', type=str, choices=['ec2', 'vpc'], required=True, help='AWS service to get report for')
    parser.add_argument('--region', type=str, default=None, help='AWS region (default: from AWS profile)')
    parser.add_argument('--output', type=str, choices=['s', 's2', 's3'], default='s', help='Report output format - s (short), s2 (more), s3 (with private IP)')
    parser.add_argument('--type', type=str, choices=['ec2','sub','vpce','rds','vpn','cvpn','sg','peer','nacl','route','eip','all'], help='Type of report when service is vpc - sub (subnets)')
    parser.add_argument('--stopped', action='store_true', help='Show only stopped instances')
    parser.add_argument('--vpcid', type=str, default=None, help='VPC ID to filter instances or show subnets')

    args = parser.parse_args()

    if args.service == 'ec2':
        if args.region == 'all':
            regions = [region['RegionName'] for region in boto3.client('ec2').describe_regions()['Regions']]
            data = []
            for region in regions:
                data.extend(get_ec2_instances(region=region,stopped=args.stopped,vpcid=args.vpcid))
        else:
            data = get_ec2_instances(region=args.region, stopped=args.stopped, vpcid=args.vpcid)
    elif args.service == 'vpc':
        data = get_vpc_resource(args.vpcid,args.region,args.type,args.output)
    
    

if __name__ == "__main__":
    main()
