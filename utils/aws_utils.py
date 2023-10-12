# Code Snippet 11

# utils/aws_utils.py

import boto3

def get_ec2_instances(region=None, stopped=False, vpcid=None):
    if region is not None:
        session = boto3.Session(region_name=region)
    else:
        session = boto3.Session()

    ec2_resource = session.resource('ec2')
    ec2_client = session.client('ec2')
    
    instances = ec2_resource.instances.all()

    instance_data = []

    for instance in instances:
        if stopped and instance.state["Name"] != "stopped":
            continue
        if vpcid is not None and instance.vpc_id != vpcid:
            continue

        # Retrieve the instance name from the instance's tags
        instance_name = next((tag['Value'] for tag in instance.tags or [] if tag['Key'] == 'Name'), None)
        
        # Retrieve the VPC name from the VPC's tags
        vpc = ec2_resource.Vpc(instance.vpc_id)
        vpc_name = next((tag['Value'] for tag in vpc.tags or [] if tag['Key'] == 'Name'), None)
        
        instance_data.append({
            'Region': region,
            'Instance ID': instance.id, 
            'Instance Name': instance_name,
            'State': instance.state["Name"], 
            'Instance Type': instance.instance_type, 
            'VPC ID': instance.vpc_id,
            'VPC Name': vpc_name,
            'Subnet ID': instance.subnet_id,
            'Public IP': instance.public_ip_address, 
            'Private IP': instance.private_ip_address,
            'Launch Time': instance.launch_time
        })
    
    return instance_data

# Code Snippet 27

# utils/aws_utils.py

def select_keys_to_show(service, region, report_type,output):
    if service == 'ec2':
        if output == 's':
            keys_to_show = ['Instance ID', 'State', 'Instance Type', 'VPC ID', 'Subnet ID', 'Public IP', 'Launch Time']
        elif output == 's2':
            keys_to_show = ['Instance ID', 'State', 'Instance Type', 'Instance Name', 'VPC ID', 'VPC Name', 'Subnet ID', 'Public IP', 'Launch Time']
        elif report_type == 's3':
            output = ['Instance ID', 'State', 'Instance Type', 'VPC ID', 'Subnet ID', 'Public IP', 'Private IP', 'Launch Time']
    elif service == 'vpc':
        if report_type == 'sub' and output=='s':
            keys_to_show = ['Subnet ID', 'Subnet CIDR', 'Route Associations', 'Is Main']
        elif report_type == 'vpce' and output=='s':
            keys_to_show = ['VPC Endpoint ID', 'Service Name', 'VPC Endpoint Type', 'State', 'Route Tables']
        elif report_type == 'rds' and output=='s':
            keys_to_show = ['DBInstanceIdentifier','DBInstanceClass','Engine','DBInstanceStatus', 'MasterUsername', 'Endpoint','AllocatedStorage']
        else:
            keys_to_show = ['VPC ID', 'VPC Name', 'VPC CIDR', 'Subnets', 'Subnet CIDR', 'IsPublic', 'EC2 instance ID', 'Instance Name', 'Instance Public IP', 'Instance Private IP']
    return keys_to_show



# Code Snippet 15

# utils/aws_utils.py

def get_vpc_info(region=None):
    if region is not None:
        session = boto3.Session(region_name=region)
    else:
        session = boto3.Session()

    ec2_resource = session.resource('ec2')
    vpcs = ec2_resource.vpcs.all()

    vpc_data = []
    
    for vpc in vpcs:
        vpc_name = next((tag['Value'] for tag in vpc.tags or [] if tag['Key'] == 'Name'), None)
        subnets = list(vpc.subnets.all())
        
        for subnet in subnets:
            instances = list(subnet.instances.all())
            
            for instance in instances:
                instance_name = next((tag['Value'] for tag in instance.tags or [] if tag['Key'] == 'Name'), None)

                vpc_data.append({
                    'VPC ID': vpc.id,
                    'VPC Name': vpc_name,
                    'VPC CIDR': vpc.cidr_block,
                    'Subnet ID': subnet.id,
                    'Subnet CIDR': subnet.cidr_block,
                    'Is Public': subnet.map_public_ip_on_launch,
                    'Instance ID': instance.id,
                    'Instance Name': instance_name,
                    'Instance Public IP': instance.public_ip_address,
                    'Instance Private IP': instance.private_ip_address,
                    'Launch Time': instance.launch_time
                })
    
    return vpc_data

# Code Snippet 26

# utils/aws_utils.py

def get_subnet_info(vpc_id, region=None):
    if region is not None:
        session = boto3.Session(region_name=region)
    else:
        session = boto3.Session()

    ec2_client = session.client('ec2')
    route_tables = ec2_client.describe_route_tables(
        Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
    )['RouteTables']
    
    subnets = ec2_client.describe_subnets(
        Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
    )['Subnets']

    subnet_data = []

    for subnet in subnets:
        route_associations = []
        for route_table in route_tables:
            for association in route_table['Associations']:
                if association.get('SubnetId') == subnet['SubnetId']:
                    for route in route_table['Routes']:
                        destination = route.get('DestinationCidrBlock', 
                                                route.get('DestinationPrefixListId', 
                                                          route.get('DestinationIpv6CidrBlock', 
                                                                    route.get('DestinationVpcPeeringConnectionId', 
                                                                              'N/A'))))
                        target = route['GatewayId'] if 'GatewayId' in route else route.get('NatGatewayId')
                        route_associations.append(f"Destination: {destination}, Target: {target}")
        route_associations = "\n".join(route_associations)
        subnet_data.append({
            'Subnet ID': subnet['SubnetId'],
            'Subnet CIDR': subnet['CidrBlock'],
            'Route Associations': route_associations,
            'Is Main': association['Main']
        })

    return subnet_data


# Code Snippet 35
# aws_utils.py

def get_vpc_endpoints(vpc_id, region=None):
    if region is not None:
        session = boto3.Session(region_name=region)
    else:
        session = boto3.Session()

    ec2_client = session.client('ec2')
    
    response = ec2_client.describe_vpc_endpoints(
        Filters=[
            {
                'Name': 'vpc-id',
                'Values': [
                    vpc_id,
                ]
            },
        ],
    )
    
    vpc_endpoints = []
    for endpoint in response['VpcEndpoints']:
        vpc_endpoints.append({
            'VPC Endpoint ID': endpoint['VpcEndpointId'],
            'Service Name': endpoint['ServiceName'],
            'VPC Endpoint Type': endpoint['VpcEndpointType'],
            'State': endpoint['State'],
            'Route Tables': ', '.join(endpoint['RouteTableIds'])
        })
    
    return vpc_endpoints


def get_vpc_resource(vpc_id, region, resource_type):
    resource_data = {
        "ec2": get_ec2_instances,
        "sub": get_subnet_info,
        "rds": get_rds_instances,
        "vpce": get_vpc_endpoints
        # "vpn": get_vpn_connections
    }
    
    if resource_type == "all":
        all_resources = {}
        for key, function in resource_data.items():
            all_resources[key] = function(vpc_id, region)
        return all_resources
    
    else:
        function = resource_data.get(resource_type)
        if function:
            return function(vpc_id, region)
        else:
            raise ValueError(f"Invalid resource type: {resource_type}")

def get_rds_instances(vpc_id, region):
    rds = boto3.client('rds', region_name=region)
    response = rds.describe_db_instances()
    
    # Filtering instances in the provided VPC
    rds_instances_in_vpc = [db for db in response['DBInstances'] if db['DBSubnetGroup']['VpcId'] == vpc_id]
    
    # Extracting key details
    rds_details = []
    for instance in rds_instances_in_vpc:
        instance_details = {
            "DBInstanceIdentifier": instance['DBInstanceIdentifier'],
            "DBInstanceClass": instance['DBInstanceClass'],
            "Engine": instance['Engine'],
            "DBInstanceStatus": instance['DBInstanceStatus'],
            "MasterUsername": instance['MasterUsername'],
            "Endpoint": instance['Endpoint']['Address'],
            "AllocatedStorage": instance['AllocatedStorage']
        }
        rds_details.append(instance_details)
    return rds_details
