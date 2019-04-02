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
from modules.tvpc_classes import BotoClient
from modules.tvpc_classes import Router
from modules.tvpc_classes import Vpn
from modules.tvpc_classes import Vgw


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
    available_clusters = get_available_clusters(region_routers_candidate)
    return region_routers_candidate, region_vpns_candidate, available_clusters


def main(cluster, region):
    region_routers_candidate, region_vpns_candidate, available_clusters = get_cluster_data(region)
    for router in region_routers_candidate:
        if router.cluster_value == cluster:
            router.eligible = 'False'
            router.update_eligible_tag()
    for vpn in region_vpns_candidate:
        if vpn.cluster_value == cluster:
            vpn.remove_vpn()
    routers_to_remove = list()
    for router in region_routers_candidate:
        if router.cluster_value == cluster:
            routers_to_remove.append(router)
    if routers_to_remove:
        processes = list()
        for router in routers_to_remove:
            p = Process(target=remove_router, args=(router,))
            p.start()
            processes.append(p)
        for p in processes:
            p.join()


def remove_router(router):
    router.remove_router_vpc_etc()
