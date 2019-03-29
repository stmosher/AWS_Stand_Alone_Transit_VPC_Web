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

from multiprocessing import Process
from multiprocessing import Queue
from queue import Empty
from config import Settings
from jinja2 import Template
import time
import logging
import boto3
import paramiko


def clean_up(cgw):
    logger = logging.getLogger(__name__)
    client = boto3.client('ec2', region_name=cgw.Region)
    if cgw.eip_AssociationId:
        try:
            client.disassociate_address(
                AssociationId=cgw.eip_AssociationId
            )
        except Exception as e:
            logger.error("Exception occurred", exc_info=True)

    if cgw.eip_AllocationId:
        try:
            client.release_address(
                AllocationId=cgw.eip_AllocationId
            )
        except Exception as e:
            logger.error("Exception occurred", exc_info=True)

    ec2 = boto3.resource('ec2', region_name=cgw.Region)
    ec2client = ec2.meta.client
    if cgw.VpcId:
        try:
            vpc = ec2.Vpc(cgw.VpcId)
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
            ec2client.delete_vpc(VpcId=cgw.VpcId)
        except Exception as e:
            logger.error("Exception occurred", exc_info=True)

    if cgw.CustomerGatewayId:
        try:
            client.delete_customer_gateway(
                CustomerGatewayId=cgw.CustomerGatewayId
            )
        except Exception as e:
            logger.error("Exception occurred", exc_info=True)

    logger.warning('Previous Error - Successfully executed clean_up function ')


def build_main(results_queue, cgw):
    logger = logging.getLogger(__name__)
    settings = Settings()
    try:
        ec2 = boto3.resource('ec2', region_name=cgw.Region)

        client = boto3.client('ec2', region_name=cgw.Region)

        response = client.allocate_address(
            Domain='vpc'
        )
        cgw.eip_AllocationId = response['AllocationId']
        cgw.PublicIp = response['PublicIp']

        vpc = ec2.create_vpc(CidrBlock='192.168.66.0/28')
        cgw.VpcId = vpc.id
        vpc.create_tags(Tags=[{"Key": "Name", "Value": "transit_vpc"}, {"Key": settings.tvpc_program_key,
                                                                        "Value": cgw.cluster_value}])
        vpc.wait_until_available()

        ig = ec2.create_internet_gateway()
        vpc.attach_internet_gateway(InternetGatewayId=ig.id)

        # create a route table and route to igw
        route_table = vpc.create_route_table()
        route_table.create_route(
            DestinationCidrBlock='0.0.0.0/0',
            GatewayId=ig.id
        )

        subnet_1 = ec2.create_subnet(AvailabilityZone=cgw.AvailabilityZone, CidrBlock='192.168.66.0/28', VpcId=vpc.id)
        route_table.associate_with_subnet(SubnetId=subnet_1.id)

        sec_group = ec2.create_security_group(
            GroupName='tvpc security group', Description='tvpc ipsec', VpcId=vpc.id)

        sec_group.authorize_ingress(IpPermissions=[
            {'FromPort': 4500, 'IpProtocol': 'udp', 'IpRanges': [{'CidrIp': '0.0.0.0/0'}], 'ToPort': 4500},
            {'FromPort': 0, 'IpProtocol': '50', 'IpRanges': [{'CidrIp': '0.0.0.0/0'}], 'ToPort': 0},
            {'FromPort': 500, 'IpProtocol': 'udp', 'IpRanges': [{'CidrIp': '0.0.0.0/0'}], 'ToPort': 500},
            {'FromPort': 22, 'IpProtocol': 'tcp', 'IpRanges': [{'CidrIp': '0.0.0.0/0'}], 'ToPort': 22}
        ]
        )

        instance_1 = ec2.create_instances(
            ImageId=cgw.AmiId, InstanceType=cgw.InstanceType, MaxCount=1, MinCount=1, KeyName=cgw.KeyName,
            NetworkInterfaces=[{'SubnetId': subnet_1.id, 'DeviceIndex': 0, 'AssociatePublicIpAddress': True,
                                'Groups': [sec_group.group_id]}],
            TagSpecifications=[{'ResourceType': 'instance', 'Tags': [{'Key': settings.tvpc_program_key,
                                                                      'Value': cgw.cluster_value}]}]
        )
        instance_1[0].wait_until_running()

        cgw.InstanceId = instance_1[0].id

        response = client.associate_address(
            AllocationId=cgw.eip_AllocationId,
            InstanceId=instance_1[0].id,
        )
        cgw.eip_AssociationId = response['AssociationId']

        ec2.create_tags(
            Resources=[
                instance_1[0].id,
                ig.id,
                route_table.id,
                subnet_1.id,
                sec_group.id,
                cgw.eip_AllocationId
            ],
            Tags=[
                {
                    'Key': 'Name',
                    'Value': cgw.PublicIp
                },
                {
                    'Key': settings.tvpc_program_key,
                    'Value': cgw.cluster_value
                },
                {
                    'Key': 'tvpc_hub',
                    'Value': str(cgw.hub)
                },
                {
                    'Key': 'tvpc_region_extension',
                    'Value': str(cgw.region_extension)
                },
                {
                    'Key': 'tvpc_eligible',
                    'Value': 'False'
                },
                {
                    'Key': 'tvpc_asn',
                    'Value': str(cgw.asn)
                },
                {
                    'Key': 'tvpc_available_bandwidth',
                    'Value': str(cgw.available_bandwidth)
                },
                {
                    'Key': 'tvpc_DmvpnAddress',
                    'Value': cgw.DmvpnAddress
                },
            ]
        )
        response = client.create_customer_gateway(
            BgpAsn=cgw.asn,
            PublicIp=cgw.PublicIp,
            Type='ipsec.1'
        )
        cgw.CustomerGatewayId = response['CustomerGateway']['CustomerGatewayId']
        ec2.create_tags(
            Resources=[
                cgw.CustomerGatewayId,
            ],
            Tags=[
                {
                    'Key': 'Name',
                    'Value': cgw.PublicIp
                },
                {
                    'Key': settings.tvpc_program_key,
                    'Value': cgw.cluster_value
                },
                {
                    'Key': 'InstanceId',
                    'Value': cgw.InstanceId
                },
            ]
        )
        result = {'success': cgw}
        results_queue.put(result)
        logger.info('Successfully built capacity add VPC %s', vpc.id)
    except Exception as e:
        logger.error("Exception occurred", exc_info=True)
        clean_up(cgw)
        result = {'fail': cgw}
        results_queue.put(result)


def check_responsive(cgw):
    logger = logging.getLogger(__name__)
    settings = Settings()
    keyfile = settings.regions[cgw.Region]['key']
    counter = 0
    while counter < 90:
        try:
            print(str(counter))
            c = paramiko.SSHClient()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            c.connect(cgw.PublicIp, username='ec2-user', key_filename=f'keys/{keyfile}.pem', timeout=5.0)
            ssh = c.invoke_shell()
            ssh.send('show version\n')
            prompt(ssh)
            ssh.close()
            return 'success'
        except:
            if counter < 90:
                time.sleep(5)
                counter += 1
            else:
                logger.warning('Exception driven Responsive test failed for %s ', cgw.CustomerGatewayId)
                return 'fail'
    logger.warning('Responsive test failed for %s ', cgw.CustomerGatewayId)
    return 'fail'


def prompt(chan):
    buff = ''
    while not buff.endswith('#'):
        resp = chan.recv(9999)
        resp1 = str(resp, 'utf-8')
        buff += resp1
    return buff


def configure_main(config_results_queue, cgw):
    logger = logging.getLogger(__name__)
    settings = Settings()
    keyfile = settings.regions[cgw.Region]['key']
    result = check_responsive(cgw)
    if result == 'fail':
        result = {'fail': cgw}
        clean_up(cgw)
        config_results_queue.put(result)

    else:
        try:
            hub_routers = {'h1_public': cgw.h1_public, 'h1_private': cgw.h1_private,
                           'h2_public': cgw.h2_public, 'h2_private': cgw.h2_private}
            with open('templates/cgw_spoke_base.j2', 'r') as t:
                template_data = t.readlines()

            configuration = list()
            conf_vars_dict = dict()
            conf_vars_dict['hub_routers'] = hub_routers
            conf_vars_dict['cgw'] = cgw.__dict__
            conf_vars_dict['settings'] = dict()
            conf_vars_dict['settings']['dmvpn_password'] = settings.dmvpn_password

            for line in template_data:
                line = line.rstrip('\n')
                t = Template(line)
                new_line = t.render(conf_vars_dict)
                configuration.append(new_line)

            c = paramiko.SSHClient()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            c.connect(cgw.PublicIp, username='ec2-user', key_filename=f'keys/{keyfile}.pem', timeout=15.0)
            ssh = c.invoke_shell()
            ssh.send('config t\n')
            prompt(ssh)

            for line in configuration:
                ssh.send(line + '\n')
                prompt(ssh)

            ssh.send('end\n')
            prompt(ssh)
            ssh.send('event manager run 10interface\n')
            prompt(ssh)
            ssh.send('wr mem\n')
            prompt(ssh)
            ssh.close()
            cgw.eligible = 'True'
            cgw.update_eligible_tag()
            result = {'success': cgw}
            config_results_queue.put(result)
        except Exception as e:
            logger.error("Exception occurred", exc_info=True)
            clean_up(cgw)
            result = {'fail': cgw}
            config_results_queue.put(result)


def create_tasks(req_queue, num_processes, routers):
    """
         The request_queue is populated the router objects
    """
    for i in routers:
        req_queue.put(i)
    for i in range(num_processes):
        req_queue.put('DONE')


def work(req_queue, results_queue):
    """
        This is the target function for each process.  It repeatedly grabs from the request_queue until it grabs the
        value "DONE" and then it terminates the work loop.
    """
    while True:
        try:
            val = req_queue.get(timeout=300)
            if val == 'DONE':
                break
            else:
                results_queue.put(build_main(results_queue, val))
        except TimeoutError:
            break


def work_configure(req_queue, results_queue):
    """
        This is the target function for each process.  It repeatedly grabs from the request_queue until it grabs the
        value "DONE" and then it terminates the work loop.
    """
    while True:
        try:
            val = req_queue.get(timeout=300)
            if val == 'DONE':
                break
            else:
                results_queue.put(configure_main(results_queue, val))
        except TimeoutError:
            break


def collect_results(results_queue):
    results = []
    while True:
        try:
            results_element = results_queue.get(block=False)
            if results_element is not None:
                results.append(results_element)
        except Empty:
            break
    return results


def main(list_router_objects):
    logger = logging.getLogger(__name__)
    config_results = None
    req_queue = Queue()
    results_queue = Queue()
    num_processes = len(list_router_objects)
    processes = []

    create_tasks(req_queue, num_processes, list_router_objects)

    for i in range(num_processes):
        p = Process(target=work, args=(req_queue, results_queue))
        p.start()
        processes.append(p)

    for p in processes:
        p.join()

    build_results = collect_results(results_queue)

    to_configure_list = list()
    for i in build_results:
        if i.get('success', False):
            to_configure_list.append(i['success'])

    if to_configure_list:
        req_queue_c = Queue()
        results_queue_c = Queue()
        num_processes = len(list_router_objects)
        processes = []

        create_tasks(req_queue_c, num_processes, to_configure_list)

        for i in range(num_processes):
            p = Process(target=work_configure, args=(req_queue_c, results_queue_c))
            p.start()
            processes.append(p)

        for p in processes:
            p.join()

        config_results = collect_results(results_queue_c)

    flag = False
    if config_results:
        for i in config_results:
            if i.get('success', False):
                logger.info('Router %s in cluster %s deployed in region %s!', i['success'].PublicIp,
                            i['success'].cluster_value, i['success'].Region)
                flag = True

    return flag
