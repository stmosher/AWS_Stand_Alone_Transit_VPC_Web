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

# import boto3
# from web_app.models import Cgw
# from multiprocessing import Process, Queue
import logging
from modules.tvpc_classes import BotoClient
from modules.tvpc_classes import Router
from modules.tvpc_classes import Vpn
from modules.tvpc_classes import Vgw
from config import Settings
#
# def remove_cgw(cgw):
#     logger = logging.getLogger(__name__)
#     try:
#         client = boto3.client('ec2', region_name=cgw.Region)
#         if cgw.eip_AssociationId:
#             try:
#                 client.disassociate_address(
#                     AssociationId=cgw.eip_AssociationId
#                 )
#             except Exception as e:
#                 logger.error("Exception occurred", exc_info=True)
#         if cgw.eip_AllocationId:
#             try:
#                 client.release_address(
#                     AllocationId=cgw.eip_AllocationId
#                 )
#             except Exception as e:
#                 logger.error("Exception occurred", exc_info=True)
#
#         ec2 = boto3.resource('ec2', region_name=cgw.Region)
#         ec2client = ec2.meta.client
#         if cgw.VpcId:
#             try:
#                 vpc = ec2.Vpc(cgw.VpcId)
#                 for subnet in vpc.subnets.all():
#                     for instance in subnet.instances.all():
#                         instance.terminate()
#                         instance.wait_until_terminated()
#                 for gw in vpc.internet_gateways.all():
#                     vpc.detach_internet_gateway(InternetGatewayId=gw.id)
#                     gw.delete()
#                 for subnet in vpc.subnets.all():
#                     subnet.delete()
#                 for rt in vpc.route_tables.all():
#                     if not rt.associations:
#                         rt.delete()
#                 for sg in vpc.security_groups.all():
#                     if sg.group_name != 'default':
#                         sg.delete()
#                 ec2client.delete_vpc(VpcId=cgw.VpcId)
#             except Exception as e:
#                 logger.error("Exception occurred", exc_info=True)
#
#         if cgw.CustomerGatewayId:
#             try:
#                 client.delete_customer_gateway(CustomerGatewayId=cgw.CustomerGatewayId)
#             except Exception as e:
#                 logger.error("Exception occurred", exc_info=True)
#     except Exception as e:
#         logger.error("Exception occurred", exc_info=True)
#
#
# def work(req_queue):
#     while True:
#         try:
#             val = req_queue.get(timeout=300)
#             if val == 'DONE':
#                 break
#             else:
#                 remove_cgw(val)
#         except TimeoutError:
#             break
#
#
# def create_tasks(req_queue, num_processes, cgws):
#     for i in cgws:
#         req_queue.put(i)
#     for i in range(num_processes):
#         req_queue.put('DONE')
#
#
# def remove_vpn(vpn):
#     client = boto3.client('ec2', region_name=vpn.Region)
#     try:
#         client.delete_vpn_connection(
#             VpnConnectionId=vpn.VpnConnectionId
#         )
#     except:
#         pass
#
#
# def work_vpn(req_queue):
#     while True:
#         try:
#             val = req_queue.get(timeout=300)
#             if val == 'DONE':
#                 break
#             else:
#                 remove_vpn(val)
#         except TimeoutError:
#             break
#
#
# def create_tasks_vpn(req_queue, num_processes, vpns):
#     for i in vpns:
#         req_queue.put(i)
#     for i in range(num_processes):
#         req_queue.put('DONE')
#
#
# def main(cluster, region):
#     logger = logging.getLogger(__name__)
#     """
#     This will remove all VPNs, VGW records, CGWs in a region other than cluster
#     """
#     try:
#         # Delete all vgw records referencing init_value
#         vgws = Vgw.query.filter_by(init_tag_key=cluster, Region=region).all()
#         if vgws:
#             for vgw in vgws:
#                 db.session.delete(vgw)
#         db.session.commit()
#         # Delete all VPNs
#         vpns = []
#         cgws = Cgw.query.filter_by(init_tag_key=cluster, Region=region).all()
#         for c in cgws:
#             vpns.extend(Vpn.query.filter_by(CustomerGatewayId=c.CustomerGatewayId).all())
#         if vpns:
#             processes = []
#             req_queue = Queue()
#             num_processes = 10
#
#             for i in range(num_processes):
#                 p = Process(target=work_vpn, args=(req_queue,))
#                 p.start()
#                 processes.append(p)
#
#             create_tasks_vpn(req_queue, num_processes, vpns)
#
#             for p in processes:
#                 p.join()
#
#         # Delete all AWS CGW VPC
#         processes = []
#         req_queue = Queue()
#         num_processes = len(cgws)
#
#         for i in range(num_processes):
#             p = Process(target=work, args=(req_queue, ))
#             p.start()
#             processes.append(p)
#
#         create_tasks(req_queue, num_processes, cgws)
#
#         for p in processes:
#             p.join()
#
#         # Remove cluster associated records from DB
#         del_TunnelInsideCidr = []
#         del_TunnelInsideInterfaceNumber = []
#         del_Vpn = []
#         for c in cgws:
#             # Delete all TunnelInsideCidr who's CustomerGatewayId is a removed cgw
#             del_TunnelInsideCidr.extend(TunnelInsideCidr.query.filter_by(CustomerGatewayId=c.CustomerGatewayId).all())
#             # Delete all TunnelInsideInterfaceNumber who's CustomerGatewayId is a removed cgw
#             del_TunnelInsideInterfaceNumber.extend(TunnelInsideInterfaceNumber.query.filter_by(CustomerGatewayId=c.CustomerGatewayId).all())
#             # Delete all VPNs who's CustomerGatewayId is a removed cgw
#             del_Vpn.extend(Vpn.query.filter_by(CustomerGatewayId=c.CustomerGatewayId).all())
#             db.session.delete(c)
#             db.session.commit()
#         for tc in del_TunnelInsideCidr:
#             db.session.delete(tc)
#             db.session.commit()
#         for ti in del_TunnelInsideInterfaceNumber:
#             db.session.delete(ti)
#             db.session.commit()
#         for vp in del_Vpn:
#             db.session.delete(vp)
#             db.session.commit()
#     except Exception as e:
#         logger.error("Exception occurred", exc_info=True)
#     logger.info('Cluster %s removed from region %s successfully!', cluster, region)


def create_aws_objects(eip, vgw, cgw, rou, vpn):
    region_routers_candidate_d = list()
    region_vgws_candidate_d = list()
    region_vpns_candidate_d = list()
    for vg in vgw:
        region_vgws_candidate_d.append(Vgw(vg))
    for r in rou:
        if r['State']['Name'] == 'terminated':
            continue
        elif r['State']['Name'] == 'shutting-down':
            continue
        else:
            region_routers_candidate_d.append(Router(r, cgw, eip))
    for vp in vpn:
        region_vpns_candidate_d.append(Vpn(vp, cgw))
    return region_routers_candidate_d, region_vgws_candidate_d, region_vpns_candidate_d


def get_available_clusters(ro):
    ac = list()
    for r in ro:
        if r.cluster_value not in ac:
            ac.append(r.cluster_value)
    unique = list(set(ac))
    return unique


def get_aws_information(reg):
    ec2_client = BotoClient(reg)
    ei = ec2_client.get_eips()
    vg = ec2_client.get_vgws()
    cg = ec2_client.get_cgws()
    ro = ec2_client.get_routers()
    vp = ec2_client.get_vpns()
    return ei, vg, cg, ro, vp


def get_cluster_data(region):
    # get aws info
    ei, vg, cg, ro, vp = get_aws_information(region)
    region_routers_candidate, region_vgws_candidate, region_vpns_candidate = create_aws_objects(ei, vg, cg, ro, vp)

    # create available cluster list
    available_clusters = get_available_clusters(region_routers_candidate)
    return region_routers_candidate, region_vpns_candidate, available_clusters


def main(cluster, region):
    logger = logging.getLogger(__name__)
    region_routers_candidate, region_vpns_candidate, available_clusters = get_cluster_data(region)

    for router in region_routers_candidate:
        if router.cluster_value == cluster:
            router.eligible = 'False'
            router.update_eligible_tag()
    for vpn in region_vpns_candidate:
        if vpn.cluster_value == cluster:
            vpn.remove_vpn()
    for router in region_vpns_candidate:
        if router.cluster_value == cluster:
            router.remove_router_vpc_etc()
