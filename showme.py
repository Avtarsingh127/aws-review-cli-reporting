# Code Snippet 20

# showreport.py

import argparse,pprint
from prettytable import PrettyTable
import boto3
from utils.aws_utils import *

def main():
    parser = argparse.ArgumentParser(description="AWS EC2 instance report")
    
    parser.add_argument('--service', type=str, choices=['ec2', 'vpc'], required=True, help='AWS service to get report for')
    parser.add_argument('--region', type=str, default=None, help='AWS region (default: from AWS profile)')
    parser.add_argument('--output', type=str, choices=['s', 's2', 's3'], default='s', help='Report output format - s (short), s2 (more), s3 (with private IP)')
    parser.add_argument('--type', type=str, choices=['ec2','sub','vpce','rds','all'], help='Type of report when service is vpc - sub (subnets)')
    parser.add_argument('--stopped', action='store_true', help='Show only stopped instances')
    parser.add_argument('--vpcid', type=str, default=None, help='VPC ID to filter instances or show subnets')

    args = parser.parse_args()

    if args.service == 'ec2':
        if args.region == 'all':
            regions = [region['RegionName'] for region in boto3.client('ec2').describe_regions()['Regions']]
            data = []
            for region in regions:
                data.extend(get_ec2_instances(region, args.stopped, args.vpcid))
        else:
            data = get_ec2_instances(args.region, args.stopped, args.vpcid)
    elif args.service == 'vpc':
        data = get_vpc_resource(args.vpcid,args.region,args.type)
        
    keys_to_show = select_keys_to_show(args.service, args.region,args.type, args.output)

    data = sorted(data, key=lambda x: x.get('VPC ID', ''))

    table = PrettyTable()
    table.field_names = keys_to_show

    for d in data:
        row = [d.get(k, '') for k in keys_to_show]
        table.add_row(row)

    print(table)

if __name__ == "__main__":
    main()
