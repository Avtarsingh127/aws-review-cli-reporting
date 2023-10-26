from prettytable import PrettyTable

import boto3

# Code Snippet 27

# utils/aws_utils.py

def select_keys_to_show(service, region, report_type,output):
    # print("service: " + service)
    # print("region: " + region)
    # print("report_type: " + report_type)
    # print("output: " + output)
    if service == 'ec2':
        if output == 's':
            keys_to_show = ['Instance ID', 'State', 'Instance Type', 'VPC ID', 'Subnet ID', 'Public IP', 'Launch Time']
        elif output == 's2':
            keys_to_show = ['Instance ID', 'State', 'Instance Type', 'Instance Name', 'VPC ID', 'VPC Name', 'Subnet ID', 'Public IP', 'Launch Time']
        elif output == 's3':
            keys_to_show = ['Instance ID', 'State', 'Instance Type', 'VPC ID', 'Subnet ID', 'Public IP', 'Private IP', 'Launch Time']
    elif service == 'vpc':
        if report_type == 'sub' and output=='s':
            keys_to_show = ['Subnet ID', 'Subnet CIDR', 'Route Associations', 'Is Main']
        elif report_type == 'vpce' and output=='s':
            keys_to_show = ['VPC Endpoint ID', 'Service Name', 'VPC Endpoint Type', 'State', 'Route Tables']
        elif report_type == 'rds' and output=='s':
            keys_to_show = ['DBInstanceIdentifier','DBInstanceClass','Engine','DBInstanceStatus', 'MasterUsername', 'Endpoint','AllocatedStorage']
        elif report_type == 'ec2' and output=='s':
            keys_to_show = ['Instance ID', 'State', 'Instance Type', 'VPC ID', 'Subnet ID', 'Public IP', 'Launch Time']
        elif report_type == 'ec2' and output=='s2':
            keys_to_show = ['Instance ID', 'State', 'Instance Type', 'Instance Name', 'VPC ID', 'VPC Name', 'Subnet ID', 'Public IP', 'Launch Time']
        elif report_type == 'ec2' and output=='s3':
            keys_to_show = ['Instance ID', 'State', 'Instance Type', 'VPC ID', 'Subnet ID', 'Public IP', 'Private IP', 'Launch Time']
        elif report_type == 'vpn' and output=='s':
            keys_to_show = ['VPN Connection ID','VPC ID','Customer Gateway ID','VPN Gateway ID','State','Type','Creation Time','Option','Routes']
        elif report_type == 'cvpn' and output=='s':
            keys_to_show = ['Endpoint ID','Description','Status','Creation Time','VPN CIDR','VPC ID','DNS Name','Server Certificate ARN','Transport Protocol']
        elif report_type == 'sg' and output=='s':
            keys_to_show = ['SG ID','SG Name','Inbound Rules','Outbound Rules']
        elif report_type == 'sg' and output=='s2':
            keys_to_show = ['SG ID','SG Name','Description','VPC ID','Inbound Rules','Outbound Rules']
        elif report_type == 'peer' and output=='s':
            keys_to_show = ['Peering ID','Req VPC ID','Req VPC CIDR','Req Owner ID','Acc VPC ID','Acc VPC CIDR','Acc Owner ID','Status','Creation Time']
        elif report_type == 'nacl' and output=='s':
            keys_to_show = ['Net ACL ID','VPC ID','Is Default','Subnets Associated','Entries']
        elif report_type == 'route' and output=='s':
            keys_to_show = ['Route Table ID','VPC ID','Is Main','Routes','Associations']
        elif report_type == 'eip' and output=='s':
            keys_to_show = ['Public IP','Allocation ID','Instance ID','Network Interface ID','Private IP Address','VPC ID','Domain']
        elif report_type == 'nat' and output=='s':
            keys_to_show = ['NAT Gateway ID','VPC ID','State','Subnet ID','Private IP','Public IP','EIP Allocation ID','Creation Time']
        elif report_type == 'igw' and output=='s':
            keys_to_show = ['Internet Gateway ID','VPC ID','Attachment State']
        elif report_type == 'elb' and output=='s':
            keys_to_show = ['Type','Name','DNS Name','VPC ID','Availability Zones']
        elif report_type == 'lambda' and output=='s':
            keys_to_show = ['Function Name','Runtime','VPC ID','Subnet IDs','Security Group IDs']
        elif report_type == 'ecs' and output=='s':
            keys_to_show = ['ClusterName','Services','Tasks']
        elif report_type == 'eks' and output=='s':
            keys_to_show = ['ClusterName','Status','CreatedDate','VPC_ID','NodeGroups','KubernetesVersion']
        elif report_type == 'redshift' and output=='s':
            keys_to_show = ['ClusterIdentifier','NodeType','ClusterStatus','NumberOfNodes','DBName','VpcId','AvailabilityZone','ClusterCreateTime','ClusterParameterGroups','ClusterSecurityGroups','VpcSecurityGroups']
        elif report_type == 'ecache' and output=='s':
            keys_to_show = ['CacheClusterId','Engine','CacheNodeType','CacheClusterStatus','NumCacheNodes','VpcId','AvailabilityZones']
        elif report_type == 'api' and output=='s':
            keys_to_show = ['API Name','API ID','API Type','Description','CreatedDate','EndpointType']
        else:
            keys_to_show = ['VPC ID', 'VPC Name', 'VPC CIDR', 'Subnets', 'Subnet CIDR', 'IsPublic', 'EC2 instance ID', 'Instance Name', 'Instance Public IP', 'Instance Private IP']
    return keys_to_show



# Code Snippet 11

# utils/aws_utils.py

def get_ec2_instances(region=None, stopped=False, vpc_id=None):
    if region is not None:
        session = boto3.Session(region_name=region)
    else:
        session = boto3.Session()

    # print("Region: %s" % region)
    # print("vpc_id: %s" % vpc_id)
    # print("Stopped: %s" %stopped)
    ec2_resource = session.resource('ec2')
    ec2_client = session.client('ec2')
    
    filters = []
    if vpc_id is not None:
        filters.append({
            'Name': 'vpc-id',
            'Values': [vpc_id]
        })
    if stopped:
        filters.append({
            'Name': 'instance-state-name',
            'Values': ['stopped']
        })
    
    instances = ec2_resource.instances.filter(Filters=filters)

    instance_data = []
    
    for instance in instances:
        if stopped and instance.state["Name"] != "stopped":
            continue
        if vpc_id is not None and instance.vpc_id != vpc_id:
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

def get_vpn_connections(region=None, vpc_id=None):
    # Initialize session and client
    session = boto3.Session(region_name=region)
    ec2_client = session.client('ec2')
    
    # Define filters based on VPC ID if provided
    filters = []
    if vpc_id:
        filters.append({
            'Name': 'vpn-connection.vpc-id',
            'Values': [vpc_id]
        })

    # Fetch VPN connections using filters
    vpns = ec2_client.describe_vpn_connections(Filters=filters)
    
    vpn_data = []
    # Parse and append VPN details to vpn_data
    for vpn in vpns['VpnConnections']:
        vpn_data.append({
            'Region': region,
            'VPN Connection ID': vpn.get('VpnConnectionId', ''),
            'VPC ID': vpn.get('vpc_id', ''),
            'Customer Gateway ID': vpn.get('CustomerGatewayId', ''),
            'VPN Gateway ID': vpn.get('VpnGatewayId', ''),
            'State': vpn.get('State', ''),
            'Type': vpn.get('Type', ''),
            'Creation Time': vpn.get('CreationTime', ''),
            'Option': vpn.get('Options', {}).get('StaticRoutesOnly', ''),
            'Routes': ", ".join([route['DestinationCidrBlock'] for route in vpn.get('Routes', [])])
        })
    return vpn_data


import boto3

def get_client_vpn_endpoints(region=None, vpc_id=None):
    """
    Retrieve information about AWS Client VPN endpoints.

    :param region: AWS region name.
    :param vpc_id: VPC ID to filter the VPN endpoints (optional).
    :return: List of dictionaries containing VPN endpoint details.
    """
    # Initialize the session and client
    session = boto3.Session(region_name=region)
    ec2_client = session.client('ec2')

    # Define filters if VPC ID is provided
    
    # Fetch Client VPN endpoints data
    try:
        response = ec2_client.describe_client_vpn_endpoints()
    except Exception as e:
        print(f"Error fetching VPN endpoints: {str(e)}")
        return []

    # Extract and structure data
    vpn_data = []
    for endpoint in response.get('ClientVpnEndpoints', []):
        if vpc_id and endpoint.get('vpc_id') != vpc_id:
            continue
        
        vpn_data.append({
            'Endpoint ID': endpoint.get('ClientVpnEndpointId'),
            'Description': endpoint.get('Description'),
            'VPC ID': endpoint.get('VpcId'),
            'Status': endpoint.get('Status', {}).get('Code'),
            'Creation Time': endpoint.get('CreationTime'),
            'VPN CIDR': endpoint.get('ClientCidrBlock'),
            'DNS Name': endpoint.get('DnsName'),
            'Server Certificate ARN': endpoint.get('ServerCertificateArn'),
            'Transport Protocol': endpoint.get('TransportProtocol'),
        })
    
    return vpn_data


def get_security_groups(region=None, vpc_id=None):
    """
    Retrieve information about AWS security groups.

    :param region: AWS region name.
    :param vpc_id: VPC ID to filter the security groups (optional).
    :return: List of dictionaries containing security group details.
    """
    # Initialize the session and client
    session = boto3.Session(region_name=region)
    ec2_client = session.client('ec2')
    
    # Define a filter to obtain only security groups related to the provided VPC ID
    filters = []
    if vpc_id:
        filters.append({
            'Name': 'vpc-id',
            'Values': [vpc_id]
        })

    # Fetch Security Groups data
    try:
        response = ec2_client.describe_security_groups(Filters=filters)
    except Exception as e:
        print(f"Error fetching security groups: {str(e)}")
        return []

    # Extract and structure data
    sg_data = []
    for sg in response.get('SecurityGroups', []):
        # Extracting Inbound rules (permissions) as a string for simplicity
        inbound_rules = []
        for permission in sg.get('IpPermissions', []):
            from_port = permission.get('FromPort', '')
            to_port = permission.get('ToPort', '')
            ip_protocol = permission.get('IpProtocol', '')

            # Extract sources (CIDR, SG, Prefix list)
            sources = []
            for ip_range in permission.get('IpRanges', []):
                sources.append(ip_range.get('CidrIp', ''))
            for ipv6_range in permission.get('Ipv6Ranges', []):
                sources.append(ipv6_range.get('CidrIpv6', ''))
            for sg_range in permission.get('UserIdGroupPairs', []):
                sources.append(sg_range.get('GroupId', ''))
            for pl_range in permission.get('PrefixListIds', []):
                sources.append(pl_range.get('PrefixListId', ''))

            source_str = ", ".join(sources)
            inbound_rules.append(f"{ip_protocol}: {from_port}-{to_port} ({source_str})")
        
        inbound_rules_str = "\n".join(inbound_rules)
        
        # Extracting Outbound rules (permissions) with destination
        outbound_rules = []
        for permission in sg.get('IpPermissionsEgress', []):
            from_port = permission.get('FromPort', '')
            to_port = permission.get('ToPort', '')
            ip_protocol = permission.get('IpProtocol', '')

            # Extract destinations (CIDR, SG, Prefix list)
            destinations = []
            for ip_range in permission.get('IpRanges', []):
                destinations.append(ip_range.get('CidrIp', ''))
            for ipv6_range in permission.get('Ipv6Ranges', []):
                destinations.append(ipv6_range.get('CidrIpv6', ''))
            for sg_range in permission.get('UserIdGroupPairs', []):
                destinations.append(sg_range.get('GroupId', ''))
            for pl_range in permission.get('PrefixListIds', []):
                destinations.append(pl_range.get('PrefixListId', ''))

            destination_str = ", ".join(destinations)
            outbound_rules.append(f"{ip_protocol}: {from_port}-{to_port} ({destination_str})")
        
        outbound_rules_str = "\n".join(outbound_rules)

        sg_data.append({
            'SG ID': sg.get('GroupId'),
            'SG Name': sg.get('GroupName'),
            'Description': sg.get('Description'),
            'VPC ID': sg.get('VpcId'),
            'Inbound Rules': inbound_rules_str,
            'Outbound Rules': outbound_rules_str,
        })
    
    return sg_data


def get_vpc_peering_connections(region, vpc_id=None):
    """
    Get details about VPC peering connections in a specific region.
    Optionally filter for a specific VPC ID.
    
    Parameters:
        region (str): The AWS region to fetch VPC peering connections from.
        vpc_id (str, optional): A specific VPC ID to fetch peering connections for.
    
    Returns:
        list: A list of dictionaries, each containing details about a VPC peering connection.
    """
    session = boto3.Session(region_name=region)
    ec2_client = session.client('ec2')
    
    filters = []
    
    response = ec2_client.describe_vpc_peering_connections()
    
    peering_connections = []
    
    for connection in response.get('VpcPeeringConnections', []):
        if vpc_id is not None:
            requester_vpc_id = connection['RequesterVpcInfo'].get('VpcId')
            accepter_vpc_id = connection['AccepterVpcInfo'].get('VpcId')
            # Check if vpc_id is either requester or accepter
            if vpc_id != requester_vpc_id and vpc_id != accepter_vpc_id:
                continue
        peering_data = {
            'Peering ID': connection.get('VpcPeeringConnectionId'),
            'Req VPC ID': connection['RequesterVpcInfo'].get('VpcId'),
            'Req VPC CIDR': connection['RequesterVpcInfo'].get('CidrBlock'),
            'Req Owner ID': connection['RequesterVpcInfo'].get('OwnerId'),
            'Acc VPC ID': connection['AccepterVpcInfo'].get('VpcId'),
            'Acc VPC CIDR': connection['AccepterVpcInfo'].get('CidrBlock'),
            'Acc Owner ID': connection['AccepterVpcInfo'].get('OwnerId'),
            'Status': connection['Status'].get('Message'),
            'Creation Time': connection.get('CreationTimestamp')
        }
        peering_connections.append(peering_data)
    
    return peering_connections

def get_network_acls(region, vpc_id=None):
    session = boto3.Session(region_name=region)
    ec2_client = session.client('ec2')
    
    # If a VPC ID is specified, add it to the filter. Else, fetch all Network ACLs.
    filters = []
    if vpc_id:
        filters.append({
            'Name': 'vpc-id',
            'Values': [vpc_id]
        })
    
    response = ec2_client.describe_network_acls(Filters=filters)
    
    network_acls_data = []
    
    for acl in response.get('NetworkAcls', []):
        entries = []
        for entry in acl.get('Entries', []):
            entries.append({
                'Rule Number': entry.get('RuleNumber'),
                'Protocol': entry.get('Protocol'),
                'Rule Action': entry.get('RuleAction'),
                'Egress': entry.get('Egress'),
                'CIDR Block': entry.get('CidrBlock'),
                'Port Range': entry.get('PortRange')
            })
        
        acl_data = {
            'Net ACL ID': acl.get('NetworkAclId'),
            'VPC ID': acl.get('VpcId'),
            'Is Default': acl.get('IsDefault'),
            'Subnets Associated': [association.get('SubnetId') for association in acl.get('Associations', [])],
            'Entries': entries
        }
        network_acls_data.append(acl_data)
    
    return network_acls_data

def get_route_tables(region, vpc_id=None):
    # Create a session using the provided region
    session = boto3.Session(region_name=region)
    ec2_resource = session.resource('ec2')
    
    # If VPC ID is provided, filter by VPC ID
    filters = []
    if vpc_id:
        filters.append({
            'Name': 'vpc-id',
            'Values': [vpc_id]
        })
    
    route_tables = ec2_resource.route_tables.filter(Filters=filters)
    
    route_table_data = []

    for rt in route_tables:
        # Retrieving the main attribute
        is_main = any(attr.get('Key') == 'aws:cloudformation:stack-name' and attr.get('Value') == 'AWSServiceRoleForVPC' for attr in rt.tags or [])
        
        # Parsing each route in the route table
        routes_info = []
        for route in rt.routes:
            # Determine the target based on available attributes
            target = (route.gateway_id or route.instance_id or route.nat_gateway_id or 
                      route.transit_gateway_id or route.vpc_peering_connection_id or 
                      route.vpc_endpoint_id or route.destination_prefix_list_id)
            destination = route.destination_cidr_block or route.destination_prefix_list_id
            routes_info.append({
                'Destination': destination,
                'Target': target,
                'State': route.state
            })

        route_table_data.append({
            'Route Table ID': rt.id,
            'VPC ID': rt.vpc_id,
            'Is Main': is_main,
            'Routes': routes_info,
            'Associations': [assoc.subnet_id for assoc in rt.associations]
        })

    return route_table_data


def get_elastic_ips(region, vpc_id=None):
    session = boto3.Session(region_name=region)
    ec2_client = session.client('ec2')
    
    eips = ec2_client.describe_addresses()['Addresses']
    eip_data = []

    for eip in eips:
        associated_with_vpc = False

        if 'InstanceId' in eip:
            instance = ec2_client.describe_instances(InstanceIds=[eip['InstanceId']])
            if instance['Reservations'][0]['Instances'][0]['VpcId'] == vpc_id:
                associated_with_vpc = True

        elif 'NetworkInterfaceId' in eip:
            network_interface = ec2_client.describe_network_interfaces(NetworkInterfaceIds=[eip['NetworkInterfaceId']])
            if network_interface['NetworkInterfaces'][0]['VpcId'] == vpc_id:
                associated_with_vpc = True

        # Similarly, add more conditions here for other associations like NAT gateways, VPNs, etc. if necessary

        if vpc_id and not associated_with_vpc:
            continue

        eip_data.append({
            'Public IP': eip.get('PublicIp'),
            'Allocation ID': eip.get('AllocationId'),
            'Instance ID': eip.get('InstanceId'),
            'Network Interface ID': eip.get('NetworkInterfaceId'),
            'Private IP Address': eip.get('PrivateIpAddress'),
            'VPC ID': eip.get('VpcId'),
            'Domain': eip.get('Domain')
        })

    return eip_data

def get_nat_gateways(region, vpc_id=None):
    session = boto3.Session(region_name=region)
    ec2_client = session.client('ec2')
    
    filters = []
    if vpc_id:
        filters.append({
            'Name': 'vpc-id',
            'Values': [vpc_id]
        })

    nat_gateways = ec2_client.describe_nat_gateways(Filters=filters)['NatGateways']
    nat_data = []

    for nat in nat_gateways:
        nat_data.append({
            'NAT Gateway ID': nat.get('NatGatewayId'),
            'VPC ID': nat.get('VpcId'),
            'State': nat.get('State'),
            'Subnet ID': nat.get('SubnetId'),
            'Creation Time': nat.get('CreateTime'),
            'Private IP': nat['NatGatewayAddresses'][0].get('PrivateIp') if nat.get('NatGatewayAddresses') else None,
            'Public IP': nat['NatGatewayAddresses'][0].get('PublicIp') if nat.get('NatGatewayAddresses') else None,
            'EIP Allocation ID': nat['NatGatewayAddresses'][0].get('AllocationId') if nat.get('NatGatewayAddresses') else None
        })

    return nat_data

def get_internet_gateways(region, vpc_id=None):
    session = boto3.Session(region_name=region)
    ec2_client = session.client('ec2')
    
    filters = []
    if vpc_id:
        filters.append({
            'Name': 'attachment.vpc-id',
            'Values': [vpc_id]
        })

    internet_gateways = ec2_client.describe_internet_gateways(Filters=filters)['InternetGateways']
    igw_data = []

    for igw in internet_gateways:
        vpc_attachments = igw.get('Attachments', [])
        
        # Typically, an IGW is attached to one VPC. However, to handle any edge cases:
        attached_vpc_id = None
        attachment_state = None
        if vpc_attachments:
            attached_vpc_id = vpc_attachments[0].get('VpcId')
            attachment_state = vpc_attachments[0].get('State')
        
        igw_data.append({
            'Internet Gateway ID': igw.get('InternetGatewayId'),
            'VPC ID': attached_vpc_id,
            'Attachment State': attachment_state
        })

    return igw_data

def get_elastic_load_balancers(region, vpc_id=None):
    session = boto3.Session(region_name=region)
    
    # For Classic Load Balancers
    elb_client = session.client('elb')
    classic_load_balancers = elb_client.describe_load_balancers()['LoadBalancerDescriptions']
    classic_lb_data = []
    for clb in classic_load_balancers:
        if not vpc_id or (vpc_id and clb['VPCId'] == vpc_id):
            classic_lb_data.append({
                'Type': 'Classic',
                'Name': clb['LoadBalancerName'],
                'DNS Name': clb['DNSName'],
                'VPC ID': clb['VPCId'],
                'Availability Zones': ', '.join(clb['AvailabilityZones']),
            })

    # For Application and Network Load Balancers
    elbv2_client = session.client('elbv2')
    all_load_balancers = elbv2_client.describe_load_balancers()['LoadBalancers']
    app_net_lb_data = []
    for lb in all_load_balancers:
        if not vpc_id or (vpc_id and lb['VpcId'] == vpc_id):
            lb_type = lb['Type'].capitalize()
            app_net_lb_data.append({
                'Type': lb_type,
                'Name': lb['LoadBalancerName'],
                'DNS Name': lb['DNSName'],
                'VPC ID': lb['VpcId'],
                'Availability Zones': ', '.join([az['ZoneName'] for az in lb['AvailabilityZones']]),
            })

    # Combine and return both lists
    return classic_lb_data + app_net_lb_data

def get_lambda_functions(region, vpc_id=None):
    session = boto3.Session(region_name=region)
    lambda_client = session.client('lambda')

    # List all functions
    functions = lambda_client.list_functions()['Functions']

    lambda_data = []

    for func in functions:
        # Check if VPC is associated with the lambda function
        vpc_config = func.get('VpcConfig', {})
        func_vpc_id = vpc_config.get('VpcId', '')
        
        if not vpc_id or (vpc_id and func_vpc_id == vpc_id):
            lambda_data.append({
                'Function Name': func['FunctionName'],
                'Function ARN': func['FunctionArn'],
                'Runtime': func['Runtime'],
                'VPC ID': func_vpc_id,
                'Subnet IDs': ', '.join(vpc_config.get('SubnetIds', [])),
                'Security Group IDs': ', '.join(vpc_config.get('SecurityGroupIds', []))
            })

    return lambda_data

def get_ecs_info(region=None, vpc_id=None):
    session = boto3.Session(region_name=region)
    ecs_client = session.client('ecs')
    
    clusters_response = ecs_client.list_clusters()
    all_cluster_arns = clusters_response['clusterArns']

    ecs_info = []

    for cluster_arn in all_cluster_arns:
        cluster_name = cluster_arn.split('/')[-1]
        
        # Describing the cluster to get VPC information
        cluster_details = ecs_client.describe_clusters(clusters=[cluster_name])['clusters'][0]
        
        # Check if cluster belongs to the given VPC (if specified)
        if vpc_id and (cluster_details.get('vpcId') != vpc_id):
            continue

        services = ecs_client.list_services(cluster=cluster_name)['serviceArns']
        tasks = ecs_client.list_tasks(cluster=cluster_name)['taskArns']

        # Extracting service names from ARNs
        service_names = [service.split('/')[-1] for service in services]

        # Extracting task definition names from ARNs. It provides task definition versions as well. 
        # If you want just the task definition name without version, you'd need another step to parse that out.
        task_definitions = [task.split('/')[-1] for task in tasks]

        ecs_info.append({
            'ClusterName': cluster_name,
            'Services': ', '.join(service_names),
            'Tasks': ', '.join(task_definitions)
        })

    return ecs_info

def get_eks_info_with_nodegroups(region=None, vpc_id=None):
    session = boto3.Session(region_name=region)
    eks_client = session.client('eks')
    
    # Listing all EKS clusters in the region
    clusters_response = eks_client.list_clusters()
    all_cluster_names = clusters_response['clusters']

    eks_info = []

    for cluster_name in all_cluster_names:
        # Describing the cluster to get details
        cluster_details = eks_client.describe_cluster(name=cluster_name)['cluster']

        # Extract VPC information
        cluster_vpc_id = cluster_details.get('resourcesVpcConfig', {}).get('vpcId')

        # Check if cluster belongs to the given VPC (if specified)
        if vpc_id and (cluster_vpc_id != vpc_id):
            continue

        # Extracting node group details
        nodegroup_names = eks_client.list_nodegroups(clusterName=cluster_name)['nodegroups']
        nodegroups_info = []
        for nodegroup_name in nodegroup_names:
            nodegroup_details = eks_client.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)['nodegroup']
            
            nodegroups_info.append({
                'NodeGroupName': nodegroup_name,
                'Status': nodegroup_details['status'],
                # 'InstanceType': nodegroup_details['instanceType'],
                'NodeRole': nodegroup_details['nodeRole'],
                'DesiredSize': nodegroup_details['scalingConfig']['desiredSize'],
                # 'CurrentSize': len(nodegroup_details['instances'])
            })

        eks_info.append({
            'ClusterName': cluster_name,
            'Status': cluster_details['status'],
            'Endpoint': cluster_details['endpoint'],
            'CreatedDate': cluster_details['createdAt'],
            'VPC_ID': cluster_vpc_id,
            'NodeGroups': nodegroups_info,
            'KubernetesVersion': cluster_details['version'],
        })

    return eks_info


def get_redshift_clusters(vpc_id=None, region='us-west-2'):
    # Initialize the session
    session = boto3.Session(region_name=region)
    redshift_client = session.client('redshift')

    # Fetch Redshift clusters
    clusters = redshift_client.describe_clusters()['Clusters']

    cluster_data = []

    for cluster in clusters:
        # Check if we are filtering by VPC and if this cluster belongs to the given VPC
        if vpc_id and cluster['VpcId'] != vpc_id:
            continue

        cluster_info = {
            'ClusterIdentifier': cluster['ClusterIdentifier'],
            'NodeType': cluster['NodeType'],
            'ClusterStatus': cluster['ClusterStatus'],
            'NumberOfNodes': cluster['NumberOfNodes'],
            'MasterUsername': cluster['MasterUsername'],
            'DBName': cluster['DBName'],
            'Endpoint': f"{cluster['Endpoint']['Address']}:{cluster['Endpoint']['Port']}",
            'VpcId': cluster['VpcId'],
            'AvailabilityZone': cluster['AvailabilityZone'],
            'ClusterCreateTime': cluster['ClusterCreateTime'],
            'ClusterParameterGroups': ", ".join([group['ParameterGroupName'] for group in cluster['ClusterParameterGroups']]),
            'ClusterSecurityGroups': ", ".join(cluster['ClusterSecurityGroups']),
            'VpcSecurityGroups': ", ".join([group['VpcSecurityGroupId'] for group in cluster['VpcSecurityGroups']])
        }

        cluster_data.append(cluster_info)

    return cluster_data


def get_elasticache_info(vpc_id=None, region='us-east-1'):
    # Initialize the session
    session = boto3.Session(region_name=region)
    elasticache_client = session.client('elasticache')

    # Fetch Elasticache clusters
    clusters = elasticache_client.describe_cache_clusters(ShowCacheNodeInfo=True)['CacheClusters']

    cache_data = []

    for cluster in clusters:
        # Check if we are filtering by VPC and if this cluster belongs to the given VPC
        subnet_group = elasticache_client.describe_cache_subnet_groups(CacheSubnetGroupName=cluster['CacheSubnetGroupName'])['CacheSubnetGroups'][0]
        
        if vpc_id and subnet_group['VpcId'] != vpc_id:
            continue

        # Extract node details
        node_details = []
        if 'CacheNodes' in cluster:
            for node in cluster['CacheNodes']:
                node_details.append({
                    'CacheNodeID': node['CacheNodeId'],
                    'Status': node['CacheNodeStatus'],
                    'Endpoint': f"{node['Endpoint']['Address']}:{node['Endpoint']['Port']}"
                })

        cluster_info = {
            'CacheClusterId': cluster['CacheClusterId'],  # This is the cluster name
            'Engine': cluster['Engine'],
            'CacheNodeType': cluster['CacheNodeType'],
            'CacheClusterStatus': cluster['CacheClusterStatus'],
            'NumCacheNodes': cluster.get('NumCacheNodes', None),
            'Nodes': node_details,
            'VpcId': subnet_group['VpcId'],
            'AvailabilityZone': cluster.get('PreferredAvailabilityZone', None)
        }

        cache_data.append(cluster_info)
    print('NOTE: CacheClusterId shows the nodes in the cluster')
    return cache_data

# Code Snippet 81
def get_api_gateways(vpc_id=None, region='us-east-1'):
    session = boto3.Session(region_name=region)
    client_rest = session.client('apigateway')
    client_ws = session.client('apigatewayv2')

    all_apis = []
    
    # Get REST APIs
    rest_apis = client_rest.get_rest_apis().get('items', [])
    for api in rest_apis:
        # If we need to filter by VPC and this API is not private, skip it
        if vpc_id and api['endpointConfiguration']['types'][0] != "PRIVATE":
            continue
        # If we're filtering by VPC and the VPC ID doesn't match, skip it
        if vpc_id and api.get('vpcEndpointIds', [None])[0] != vpc_id:
            continue
        all_apis.append({
            'API ID': api['id'],
            'API Name': api['name'],
            'API Type': 'REST',
            'EndpointType': api['endpointConfiguration']['types'][0],
            'Description': api.get('description', ''),
            'CreatedDate': api['createdDate']
        })

    # Get Websocket APIs
    websocket_apis = client_ws.get_apis().get('items', [])
    for api in websocket_apis:
        # If we need to filter by VPC and this API is not private, skip it
        if vpc_id and api['protocolType'] != "WEBSOCKET":
            continue
        # If we're filtering by VPC and the VPC ID doesn't match, skip it
        # Note: As of my last update, vpcEndpoint configuration is not available for WebSocket APIs. 
        # This may change in future AWS SDK updates. 
        all_apis.append({
            'API ID': api['apiId'],
            'API Name': api['name'],
            'API Type': 'WEBSOCKET',
            'EndpointType': api.get('protocolType', 'WEBSOCKET'),
            'Description': api.get('description', ''),
            'CreatedDate': api['createdDate']
        })

    # You can also add other API types (like HTTP APIs) in a similar fashion if you are using them.

    return all_apis


def get_vpc_resource(vpc_id, region, resource_type,output_type,output_file,format):
    resource_data = {
        "ec2": get_ec2_instances,
        "sub": get_subnet_info,
        "rds": get_rds_instances,
        "vpce": get_vpc_endpoints,
        "vpn": get_vpn_connections,
        "cvpn": get_client_vpn_endpoints,
        "sg" : get_security_groups,
        "peer": get_vpc_peering_connections,
        "nacl": get_network_acls,
        "route": get_route_tables,
        "eip": get_elastic_ips,
        "nat": get_nat_gateways,
        "igw": get_internet_gateways,
        "elb": get_elastic_load_balancers,
        "lambda": get_lambda_functions,
        "ecs": get_ecs_info,
        "eks": get_eks_info_with_nodegroups,
        "redshift": get_redshift_clusters,
        "ecache": get_elasticache_info,
        "api": get_api_gateways

    }
    data = []
    if resource_type == "all":
        all_resources = {}
        for key, function in resource_data.items():
            print('Executing: %s' % function)
            data = function(vpc_id=vpc_id, region=region)
            print('==============================' + key + '============================')
            show_output(data=data,service='vpc',region=region,report_type=key,output=output_type,output_file=output_file,format=format)
            print('================================================================')
        
    else:
        function = resource_data.get(resource_type)
        if function:
            data = function(vpc_id=vpc_id, region=region)
            show_output(data=data,service='vpc',region=region,report_type=resource_type,output=output_type,output_file=output_file,format=format) 
        else:
            raise ValueError(f"Invalid resource type: {resource_type}")

def show_output(data, service, region, report_type, output, output_file='', format='table'):
    keys_to_show = select_keys_to_show(service=service, region=region, report_type=report_type, output=output)
    output_data = ""

    if format == 'table':
        table = PrettyTable()
        table.align = 'l'
        table.field_names = keys_to_show

        for d in data:
            row = [str(d.get(k, '')) for k in keys_to_show]
            table.add_row(row)
        output_data = str(table)

    elif format == 'csv':
        # Form the header row
        output_data = ','.join(keys_to_show) + '\n'
        for d in data:
            row = [str(d.get(k, '')) for k in keys_to_show]
            output_data += ','.join(row) + '\n'

    if output_file:
        write_to_file(report_type, output_data, filename=output_file)
    else:
        print(output_data)

def write_to_file(type, table_data, filename='output.txt'):
    with open(filename, 'a') as f:
        f.write(table_data)
        f.write("\n\n")  # Add a couple of newline characters for better separation between entries



# def show_output(data,service,region,report_type,output):
#     keys_to_show = select_keys_to_show(service=service, region=region,report_type=report_type, output=output)

#     # data = sorted(data, key=lambda x: x.get('VPC ID', ''))

#     table = PrettyTable()
#     table.align = 'l'
#     table.field_names = keys_to_show

#     for d in data:
#         row = [d.get(k, '') for k in keys_to_show]
#         table.add_row(row)
#     write_to_file(type=report_type,table_data=str(table))
#     # print(table)

# def show_output_csv(data, service, region, report_type, output):
#     keys_to_show = select_keys_to_show(service=service, region=region, report_type=report_type, output=output)
    
#     # Print the header row
#     print(','.join(keys_to_show))
#     header = ','.join(keys_to_show) + '\n'
#     write_to_file(type=report_type,table_data=header)
    
#     for d in data:
#         row = [str(d.get(k, '')) for k in keys_to_show]
#         line =','.join(row)
#         write_to_file(type=report_type,table_data=line)

# def write_to_file(type,table_data, filename='output.txt'):
#     """
#     Appends the table data to the given filename.

#     Parameters:
#         - table_data (str): The table data in string format.
#         - filename (str, optional): The name of the file to append to. Defaults to 'output.txt'.

#     Returns:
#         None
#     """
#     with open(filename, 'a') as f:
        
#         f.write(table_data)
#         f.write("\n\n")  # Add a couple of newline characters for better separation between entries
