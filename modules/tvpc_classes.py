# -*- coding: utf-8 -*-
"""

Copyright (c) 2019 Cisco and/or its affiliates.

This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at

               https://developer.cisco.com/docs/licenses

All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.

"""
__author__ = "Steven Mosher <stmosher@cisco.com>"
__copyright__ = "Copyright (c) 2019 Cisco and/or its affiliates."
__license__ = "Cisco Sample Code License, Version 1.1"

from jinja2 import Environment
from jinja2 import BaseLoader
import boto3
import paramiko
from config import Settings
import ipaddress
import logging
import re
import time


class Vgw:
    def __init__(self, vgw):
        self.tvpc_program_key = Settings.tvpc_program_key
        self.cluster_value = vgw['Tags'].get(self.tvpc_program_key, '')
        self.bandwidth = vgw['Tags'].get('tvpc_bandwidth', '10')
        self.Region = vgw['Region']
        self.VpnGatewayId = vgw['VpnGatewayId']


class Vpn:
    def __init__(self, vpn, cgws):
        self.VpnConnectionId = vpn['VpnConnectionId']
        self.VpnGatewayId = vpn['VpnGatewayId']
        self.CustomerGatewayId = vpn['CustomerGatewayId']
        self.Region = vpn['Region']
        self.status_aws = vpn['State']
        self.PublicIp = self.set_public_ip(cgws)

        self.tvpc_program_key = Settings.tvpc_program_key
        self.cluster_value = vpn['Tags'].get(self.tvpc_program_key, '')
        self.bandwidth_mbps = vpn['Tags'].get('tvpc_bandwidth_mbps', '')
        self.TunnelInsideCidr1 = vpn['Tags'].get('tvpc_TunnelInsideCidr1', '')
        self.TunnelInsideCidr2 = vpn['Tags'].get('tvpc_TunnelInsideCidr2', '')
        self.TunnelIntNumber1 = vpn['Tags'].get('tvpc_TunnelIntNumber1', '')
        self.TunnelIntNumber2 = vpn['Tags'].get('tvpc_TunnelIntNumber2', '')
        self.Neighbor1 = vpn['Tags'].get('tvpc_Neighbor1', '')
        self.Neighbor2 = vpn['Tags'].get('tvpc_Neighbor2', '')
        self.NeighborASN = vpn['Tags'].get('tvpc_NeighborASN', '')

    def set_public_ip(self, cgws):
        for o in cgws:
            if o['CustomerGatewayId'] == self.CustomerGatewayId:
                return o['IpAddress']

    def remove_vpn(self):
        logger = logging.getLogger(__name__)
        try:
            client = boto_client_for_methods(self.Region)
            client.delete_vpn_connection(
                VpnConnectionId=self.VpnConnectionId
            )
            logger.info('VPN %s successfully deleted', self.VpnConnectionId)
            return 'success'
        except Exception as e:
            logger.error("Exception occurred while trying to delete vpn %s", self.VpnConnectionId, exc_info=True)
            return 'fail'


class Router:
    def __init__(self, description, cgws, eips):
        self.InstanceId = description['InstanceId']
        self.InstanceType = description['InstanceType']
        self.AmiId = description['ImageId']
        self.KeyName = description['KeyName']
        self.status = description['State']['Name']
        self.VpcId = description['VpcId']
        self.PublicIp = description['PublicIpAddress']
        self.AvailabilityZone = description['Placement']['AvailabilityZone']
        self.Region = description['Region']

        self.tvpc_program_key = Settings.tvpc_program_key
        self.max_bandwidth = Settings.instance_types[self.InstanceType]
        self.DmvpnCidr = Settings.dmvpn_address_space
        self.DmvpnNetmask = ipaddress.ip_network(Settings.dmvpn_address_space).netmask

        self.cluster_value = description['Tags'].get(self.tvpc_program_key, '')
        self.hub = description['Tags'].get('tvpc_hub', '')
        self.region_extension = description['Tags'].get('tvpc_region_extension', '')
        self.eligible = description['Tags'].get('tvpc_eligible', '')
        self.asn = description['Tags'].get('tvpc_asn', '')
        self.available_bandwidth = description['Tags'].get('tvpc_available_bandwidth', '')
        self.DmvpnAddress = description['Tags'].get('tvpc_DmvpnAddress', '')
        self.vpc_cidr = description['Tags'].get('tvpc_vpc_cidr', '')

        self.CustomerGatewayId = self.set_cid(cgws)
        self.eip_AllocationId = self.set_eip_allo(eips)
        self.eip_AssociationId = self.set_eip_asso(eips)

        self.remove_records = []
        self.add_records = []
        self.reachability = self.set_reachability_and_get_available_tunnel_interfaces_and_cidrs()
        self.configure_vpn_ssh = """{% for i in records %}
crypto ikev2 profile {{ i.VpnConnectionId }}-{{ i.TunnelIntNumber1  }}
 match address local interface GigabitEthernet1
 match identity remote address {{ i.t0_vpn_gateway_tunnel_outside_address }}
 authentication remote pre-share key {{ i.t0_ike_pre_shared_key }}
 authentication local pre-share key {{ i.t0_ike_pre_shared_key }}
!
crypto ipsec profile {{ i.VpnConnectionId }}-{{ i.TunnelIntNumber1  }}
 set transform-set AES256/SHA256/TUNNEL
 set ikev2-profile {{ i.VpnConnectionId }}-{{ i.TunnelIntNumber1  }}
 set pfs group14
 set security-association lifetime seconds 3600
 set security-association replay window-size 128
!
interface Tunnel{{ i.TunnelIntNumber1 }}
 description {{ i.VpnConnectionId }} from {{ i.VpnGatewayId }} to {{ i.CustomerGatewayId }}
 vrf forwarding internal
 ip address {{ i.t0_customer_gateway_tunnel_inside_address }} 255.255.255.252
 ip virtual-reassembly
 tunnel source GigabitEthernet1
 tunnel destination {{ i.t0_vpn_gateway_tunnel_outside_address }}
 tunnel mode ipsec ipv4
 tunnel protection ipsec profile {{ i.VpnConnectionId }}-{{ i.TunnelIntNumber1 }}
 ip tcp adjust-mss 1379
 no shutdown
!
crypto ikev2 profile {{ i.VpnConnectionId }}-{{ i.TunnelIntNumber2  }}
 match address local interface GigabitEthernet1
 match identity remote address {{ i.t1_vpn_gateway_tunnel_outside_address }}
 authentication remote pre-share key {{ i.t1_ike_pre_shared_key }}
 authentication local pre-share key {{ i.t1_ike_pre_shared_key }}
!
crypto ipsec profile {{ i.VpnConnectionId }}-{{ i.TunnelIntNumber2  }}
 set transform-set AES256/SHA256/TUNNEL
 set ikev2-profile {{ i.VpnConnectionId }}-{{ i.TunnelIntNumber2  }}
 set pfs group14
 set security-association lifetime seconds 3600
 set security-association replay window-size 128
!
interface Tunnel{{ i.TunnelIntNumber2}}
 description {{ i.VpnConnectionId }} from {{ i.VpnGatewayId }} to {{ i.CustomerGatewayId }}
 vrf forwarding internal
 ip address {{ i.t1_customer_gateway_tunnel_inside_address }} 255.255.255.252
 ip virtual-reassembly
 tunnel source GigabitEthernet1
 tunnel destination {{ i.t1_vpn_gateway_tunnel_outside_address }}
 tunnel mode ipsec ipv4
 tunnel protection ipsec profile {{ i.VpnConnectionId }}-{{ i.TunnelIntNumber2 }}
 ip tcp adjust-mss 1379
 no shutdown
{% endfor %}
router bgp {{ asn }}
 address-family ipv4 vrf internal
{% for i in records %}
 neighbor {{ i.Neighbor1 }} remote-as {{ i.NeighborASN }}
 neighbor {{ i.Neighbor1 }} peer-group VGWSPOKES
 neighbor {{ i.Neighbor2 }} remote-as {{ i.NeighborASN }}
 neighbor {{ i.Neighbor2 }} peer-group VGWSPOKES
{% endfor %}
"""
        self.unconfigure_vpn_ssh = """router bgp {{ asn }}
 address-family ipv4 vrf internal
{% for i in records %}
  no neighbor {{ i.Neighbor1 }}
  no neighbor {{ i.Neighbor2 }}
{% endfor %}
!
{% for i in records %}
interface Tunnel{{ i.TunnelIntNumber1 }}
 shutdown
!
no interface Tunnel{{ i.TunnelIntNumber1 }}
!
interface Tunnel{{ i.TunnelIntNumber2 }}
 shutdown
!
no interface Tunnel{{ i.TunnelIntNumber2 }}
{% endfor %}
!
{% for i in records %}
no crypto ipsec profile {{ i.VpnConnectionId }}-{{ i.TunnelIntNumber1 }}
no crypto ipsec profile {{ i.VpnConnectionId }}-{{ i.TunnelIntNumber2 }}
WAIT
WAIT
no crypto ikev2 profile {{ i.VpnConnectionId }}-{{ i.TunnelIntNumber1 }}
no crypto ikev2 profile {{ i.VpnConnectionId }}-{{ i.TunnelIntNumber2 }}
{% endfor %}
"""

    def set_cid(self, cgws):
        for o in cgws:
            if o['IpAddress'] == self.PublicIp:
                return o['CustomerGatewayId']

    def set_eip_allo(self, eips):
        for e in eips:
            if e['PublicIp'] == self.PublicIp:
                return e['AllocationId']

    def set_eip_asso(self, eips):
        for e in eips:
            if e['PublicIp'] == self.PublicIp:
                return e['AssociationId']

    def update_available_bandwidth_tag(self):
        logger = logging.getLogger(__name__)
        client = boto_client_for_methods(self.Region)
        try:
            client.create_tags(
                Resources=[
                    self.InstanceId
                ],
                Tags=[
                    {
                        'Key': 'tvpc_available_bandwidth',
                        'Value': self.available_bandwidth
                    }
                ]
            )
            return 'success'
        except Exception as e:
            logger.error("Exception while trying to update router %s tvpc_available_bandwidth tag", self.PublicIp,
                         exc_info=True)
            return 'fail'

    def update_eligible_tag(self):
        logger = logging.getLogger(__name__)
        client = boto_client_for_methods(self.Region)
        try:
            client.create_tags(
                Resources=[
                    self.InstanceId
                ],
                Tags=[
                    {
                        'Key': 'tvpc_eligible',
                        'Value': self.eligible
                    }
                ]
            )
            return 'success'
        except Exception as e:
            logger.error("Exception while trying to update router %s tvpc_available_bandwidth tag", self.PublicIp,
                         exc_info=True)
            return 'fail'

    def set_reachability_and_get_available_tunnel_interfaces_and_cidrs(self):
        """ This will check paramiko response
        If successful, will set self.reachability to True
        If successful, will populate self.available_interface_numbers
        If successful, will populate self.available_vpn_cidrs"""
        logger = logging.getLogger(__name__)
        if self.status != 'running':
            return False
        try:
            c = paramiko.SSHClient()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            c.connect(self.PublicIp, username='ec2-user', key_filename=f'keys/{self.KeyName}.pem', timeout=5.0)
            ssh = c.invoke_shell()
            self.prompt(ssh)
            ssh.send('show interface stats | i Tunnel\n')
            response_show_int = self.prompt(ssh)
            ssh.send('show ip interface | i Internet address\n')
            response_show_address = self.prompt(ssh)
            ssh.close()

            response_show_int = response_show_int.splitlines()
            used_interfaces_tunnel = list()
            for i in response_show_int:
                if re.search(r'^Tunnel', i):
                    inter = i.lstrip('Tunnel')
                    used_interfaces_tunnel.append(inter)

            # Create available tunnel interfaces list
            available_interface_numbers = []
            for i in range(Settings.vpn_interface_range['start'], Settings.vpn_interface_range['end']):
                if i not in used_interfaces_tunnel:
                    available_interface_numbers.append(i)
            available_interface_numbers.reverse()
            self.available_interface_numbers = available_interface_numbers

            response_show_address = response_show_address.splitlines()
            cidr = list()
            for i in response_show_address:
                if re.search(r'  Internet address', i):
                    n = i.lstrip('  Internet address is ')
                    cidr.append(n)

            ipaddr_int_objects = list()
            for i in cidr:
                ipaddr_int_objects.append(ipaddress.IPv4Interface(i))

            # Create list of used network cidrs from host ip and prefix
            used_cidrs = list()
            for int_o in ipaddr_int_objects:
                used_cidrs.append(str(int_o.network))

            # Create an available CIDR list
            aws_vpn_space = Settings.aws_vpn_space
            aws_reserved_space = Settings.aws_reserved_vpn_space
            if used_cidrs:
                for c in used_cidrs:
                    aws_reserved_space.append(c)

            # chop into /30 subnets
            nl = list(ipaddress.ip_network(aws_vpn_space).subnets(new_prefix=30))
            nl_string = []
            for i in nl:
                nl_string.append(str(i))
            available_cidr_list = []
            for i in nl_string:
                if i not in aws_reserved_space:
                    available_cidr_list.append(i)

            self.available_vpn_cidrs = available_cidr_list
            return True
        except Exception as e:
            logger.error("Router %s unreachable", self.PublicIp, exc_info=True)
            return False

    def prompt(self, chan):
        buff = ''
        while not buff.endswith('#'):
            resp = chan.recv(9999)
            resp1 = resp.decode('utf-8')
            buff += resp1
        return buff

    def check_responsive(self):
        logger = logging.getLogger(__name__)
        counter = 0
        while counter < 3:
            try:
                c = paramiko.SSHClient()
                c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                c.connect(self.PublicIp, username='ec2-user', key_filename=f'keys/{self.KeyName}.pem', timeout=5.0)
                ssh = c.invoke_shell()
                ssh.send('show version\n')
                self.prompt(ssh)
                ssh.close()
                return 'success'
            except:
                if counter < 3:
                    time.sleep(1)
                    counter += 1
                else:
                    logger.warning('Exception driven Responsive test failed for {}'.format(self.PublicIp))
                    return 'fail'
        logger.warning('Responsive test failed for {}'.format(self.PublicIp))
        return 'fail'

    def remove_router_vpc_etc(self):
        logger = logging.getLogger(__name__)
        try:
            client = boto_client_for_methods(self.Region)
            if self.eip_AssociationId:
                try:
                    client.disassociate_address(
                        AssociationId=self.eip_AssociationId
                    )
                except Exception as e:
                    logger.error("Exception occurred", exc_info=True)

            if self.eip_AllocationId:
                try:
                    client.release_address(
                        AllocationId=self.eip_AllocationId
                    )
                except Exception as e:
                    logger.error("Exception occurred", exc_info=True)

            ec2 = boto_resource_for_methods(self.Region)
            ec2client = ec2.meta.client
            if self.VpcId:
                try:
                    vpc = ec2.Vpc(self.VpcId)
                    for subnet in vpc.subnets.all():
                        for instance in subnet.instances.all():
                            instance.terminate()
                            instance.wait_until_terminated()
                    for gw in vpc.internet_gateways.all():
                        vpc.detach_internet_gateway(InternetGatewayId=gw.id)
                        gw.delete()
                    for subnet in vpc.subnets.all():
                        subnet.delete()
                    for rt in vpc.route_tables.all():
                        if not rt.associations:
                            rt.delete()
                    for sg in vpc.security_groups.all():
                        if sg.group_name != 'default':
                            sg.delete()
                    ec2client.delete_vpc(VpcId=self.VpcId)
                except Exception as e:
                    logger.error("Exception occurred", exc_info=True)

            if self.CustomerGatewayId:
                try:
                    client.delete_customer_gateway(CustomerGatewayId=self.CustomerGatewayId)
                except Exception as e:
                    logger.error("Exception occurred", exc_info=True)
        except Exception as e:
            logger.error("Exception occurred", exc_info=True)


def boto_client_for_methods(region):
    return boto3.client('ec2', region_name=region)


def boto_resource_for_methods(region):
    return boto3.resource('ec2', region_name=region)


class BotoClient:
    def __init__(self, region):
        self.region = region
        self.client = boto3.client('ec2', region_name=self.region)
        self.ec2 = boto3.resource('ec2', region_name=self.region)

    def get_vgws(self):
        results = self.client.describe_vpn_gateways()
        vgws = list()
        for item in results['VpnGateways']:
            tags_dict = self.get_tags(item['Tags'])
            if tags_dict.get(Settings.tvpc_program_key):
                item['Tags'] = tags_dict
                item['Region'] = self.region
                vgws.append(item)
        return vgws

    def get_cgws(self):
        results = self.client.describe_customer_gateways()
        cgws = list()
        for item in results['CustomerGateways']:
            tags_dict = self.get_tags(item['Tags'])
            if tags_dict.get(Settings.tvpc_program_key):
                item['Tags'] = tags_dict
                item['Region'] = self.region
                cgws.append(item)
        return cgws

    def get_eips(self):
        results = self.client.describe_addresses()
        eips = list()
        for item in results['Addresses']:
            if item.get('Tags', False):
                tags_dict = self.get_tags(item['Tags'])
                if tags_dict.get(Settings.tvpc_program_key):
                    item['Tags'] = tags_dict
                    item['Region'] = self.region
                    eips.append(item)
        return eips

    def get_routers(self):
        results = self.client.describe_instances()
        routers = list()
        for item in results['Reservations']:
            if item['Instances'][0]['State']['Name'] == 'terminated':
                continue
            elif item['Instances'][0]['State']['Name'] == 'shutting-down':
                continue
            else:
                tags_dict = self.get_tags(item['Instances'][0]['Tags'])
                if tags_dict.get(Settings.tvpc_program_key):
                    item['Instances'][0]['Tags'] = tags_dict
                    item['Instances'][0]['Region'] = self.region
                    routers.append(item['Instances'][0])
        return routers

    def get_vpns(self):
        results = self.client.describe_vpn_connections()
        vpns = list()
        for item in results['VpnConnections']:
            tags_dict = self.get_tags(item['Tags'])
            if tags_dict.get(Settings.tvpc_program_key):
                item['Tags'] = tags_dict
                item['Region'] = self.region
                vpns.append(item)
        return vpns

    @staticmethod
    def get_tags(i):
        tags = {}
        for t in i:
            tags[t['Key']] = t['Value']
        return tags
