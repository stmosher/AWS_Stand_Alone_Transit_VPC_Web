#!/usr/bin/env python3
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

from flask import render_template
from flask import flash
from flask import redirect
from flask import url_for
from web_app import app
from flask_login import login_user
from flask_login import logout_user
from flask_login import current_user
from flask_login import login_required
from web_app.user import User
from web_app.forms import CsrEnable
from web_app.forms import CsrDisable
from web_app.forms import RemoveCapacity
from web_app.forms import ContractCluster
from web_app.forms import AddCapacity
from web_app.forms import RemoveCluster
from web_app.forms import ExtendCluster
from web_app.forms import LoginForm
from web_app.forms import AddCluster
from web_app.forms import CsrRedeploy
from modules import setup_add_cluster
from modules import setup_extend_cluster
from modules import setup_remove_cluster
from modules import setup_contract_cluster
from modules import setup_capacity_add
from modules import setup_redeploy_csr
import boto3
from config import Settings
import ipaddress
import logging
from copy import deepcopy
import os
from modules.tvpc_classes import BotoClient
from modules.tvpc_classes import Router
from modules.tvpc_classes import Vpn
from modules.tvpc_classes import Vgw
from modules.tvpc_classes import Tgw
from modules.tvpc_classes import LicenseHelper


@app.route('/')
@app.route('/index')
@login_required
def index():
    return render_template('index.html', title='Home')


@app.route('/login', methods=['GET', 'POST'])
def login():
    logger = logging.getLogger(__name__)
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User(username=os.environ.get('web_username'), password=os.environ.get('web_password'))
        user_test = User(username=form.username.data, password=form.password.data)
        if user_test.username != user.username or user_test.password != user.password:
            flash('Invalid username or password')
            logger.info("Invalid username or password. User %s attempted login", form.username.data)
            return redirect(url_for('login'))
        logger.info("User %s logged in", form.username.data)
        login_user(user_test, remember=form.remember_me.data)
        return redirect(url_for('index'))
    return render_template('login.html', title='Sign In', form=form)


@app.route('/logout')
def logout():
    logger = logging.getLogger(__name__)
    logger.info("User logged out")
    logout_user()
    return redirect(url_for('index'))


@app.route('/add_cluster', methods=['GET', 'POST'])
@login_required
def add_cluster():
    logger = logging.getLogger(__name__)
    settings = Settings()
    form = AddCluster()
    form.Region.choices = settings.get_regions_tuples()
    form.InstanceType.choices = settings.get_instances_tuples()

    if form.validate_on_submit():
        region_routers_candidate, region_vgws_candidate, region_vpns_candidate, available_clusters, region_tgws_candidate = get_cluster_data(form.Region.data)
        if form.cluster_value.data in available_clusters:
            flash("Cluster name '{}' has already been deployed in '{}'".format(form.cluster_value.data,
                                                                               form.Region.data))
            return redirect(url_for('add_cluster'))

        if form.InstanceType.data not in settings.get_region_supported_instances(form.Region.data):
            flash("Instance type '{}' is not available in '{}'".format(form.InstanceType.data, form.Region.data))
            return redirect(url_for('add_cluster'))

        az_names = get_availability_zones_available(form.Region.data)
        all_routers = get_all_routers()
        available_dmvpn_addresses = get_available_dmvpn_addresses_hub(all_routers, form.cluster_value.data, 2)
        available_subnets = get_available_vpc_cidr_space(all_routers, form.cluster_value.data, 2)

        router1 = Cgw(Region=form.Region.data, hub=True, region_extension=False, AvailabilityZone=az_names[0],
                      InstanceType=form.InstanceType.data, asn=form.asn.data, cluster_value=form.cluster_value.data,
                      available_bandwidth=Settings.instance_types[form.InstanceType.data],
                      AmiId=Settings.regions[form.Region.data]['ami'],
                      max_bandwidth=Settings.instance_types[form.InstanceType.data],
                      KeyName=Settings.regions[form.Region.data]['key'],
                      DmvpnAddress=available_dmvpn_addresses[0],
                      DmvpnNetmask=str(ipaddress.ip_network(Settings.dmvpn_address_space).netmask),
                      eligible='False', DmvpnCidr=Settings.dmvpn_address_space, vpc_cidr=available_subnets[0])
        router2 = Cgw(Region=form.Region.data, hub=True, region_extension=False, AvailabilityZone=az_names[1],
                      InstanceType=form.InstanceType.data, asn=form.asn.data, cluster_value=form.cluster_value.data,
                      available_bandwidth=Settings.instance_types[form.InstanceType.data],
                      AmiId=Settings.regions[form.Region.data]['ami'],
                      max_bandwidth=Settings.instance_types[form.InstanceType.data],
                      KeyName=Settings.regions[form.Region.data]['key'],
                      DmvpnAddress=available_dmvpn_addresses[1],
                      DmvpnNetmask=str(ipaddress.ip_network(Settings.dmvpn_address_space).netmask),
                      eligible='False', DmvpnCidr=Settings.dmvpn_address_space, vpc_cidr=available_subnets[1])

        r1, r2 = setup_add_cluster.main(router1, router2)
        if r1 == 'fail':
            flash("Cluster '{}' deployment and configuration failed".format(form.cluster_value.data))
            logger.warning("Cluster %s deployment and configuration failed", form.cluster_value.data)
        elif r1.registration_failed or r2.registration_failed:
            if r1.registration_failed:
                flash("Router '{}' failed to register with Cisco Smart Licensing".format(r1.PublicIp))
            if r2.registration_failed:
                flash("Router '{}' failed to register with Cisco Smart Licensing".format(r2.PublicIp))
        else:
            flash("Cluster '{}' deployed successfully!".format(r1.cluster_value))
            logger.info("Cluster %s deployed successfully!", r1.cluster_value)

        return redirect(url_for('add_cluster'))
    return render_template('add_cluster.html', title='Add Cluster', form=form)


@app.route('/extend_cluster', methods=['GET', 'POST'])
@login_required
def extend_cluster():
    logger = logging.getLogger(__name__)
    settings = Settings()
    all_routers = get_all_routers()
    form = ExtendCluster()
    form.Region.choices = settings.get_regions_tuples()
    form.InstanceType.choices = settings.get_instances_tuples()

    unique_clusters = get_available_clusters(all_routers)
    cluster_list = []
    for i in unique_clusters:
        cluster_list.append((i, i))
    cluster_list.sort()
    form.cluster_value.choices = cluster_list

    if form.validate_on_submit():
        if form.InstanceType.data not in settings.get_region_supported_instances(form.Region.data):
            flash("Instance type '{}' is not available in '{}'".format(form.InstanceType.data, form.Region.data))
            return redirect(url_for('extend_cluster'))

        cluster_already_there_result = check_router_in_region(all_routers, form.cluster_value.data, form.Region.data)
        if cluster_already_there_result:
            flash("Region '{}' already has cluster '{}'. Maybe you want to + capacity.".format(form.Region.data,
                  form.cluster_value.data))
            return redirect(url_for('extend_cluster'))

        available_dmvpn_addresses = get_available_dmvpn_addresses(all_routers, form.cluster_value.data, 2)
        available_subnets = get_available_vpc_cidr_space(all_routers, form.cluster_value.data, 2)
        az_names = get_availability_zones_available(form.Region.data)

        hubs = list()
        for rou in all_routers:
            if (rou.cluster_value == form.cluster_value.data) and (rou.hub == 'True'):
                hubs.append(rou)
        cgw_template = hubs[0]
        list_router_objects = list()
        for i in range(2):
            list_router_objects.append(
                Cgw(Region=form.Region.data,
                    hub=False,
                    region_extension=True,
                    AvailabilityZone=az_names.pop(0),
                    InstanceType=form.InstanceType.data,
                    asn=int(cgw_template.asn),
                    cluster_value=form.cluster_value.data,
                    available_bandwidth=Settings.instance_types[form.InstanceType.data],
                    AmiId=Settings.regions[form.Region.data]['ami'],
                    max_bandwidth=Settings.instance_types[form.InstanceType.data],
                    KeyName=Settings.regions[form.Region.data]['key'],
                    DmvpnAddress=available_dmvpn_addresses.pop(0),
                    DmvpnNetmask=str(ipaddress.ip_network(Settings.dmvpn_address_space).netmask),
                    eligible='False',
                    DmvpnCidr=Settings.dmvpn_address_space,
                    h1_public=hubs[0].PublicIp,
                    h1_private=hubs[0].DmvpnAddress,
                    h2_public=hubs[1].PublicIp,
                    h2_private=hubs[1].DmvpnAddress,
                    vpc_cidr=available_subnets.pop(0))
                )
        results_list = setup_extend_cluster.main(list_router_objects)
        if not results_list:
            flash("Cluster Extension failed")
            logger.warning("Cluster Extension failed")
        else:
            for i in results_list:
                if i.get('success', False):
                    flash("Router '{}' successfully deployed".format(i['success'].PublicIp))
                    logger.info("Router %s deployed successfully!", i['success'].PublicIp)
                    if i['success'].registration_failed:
                        flash("Router '{}' failed to register with Cisco Smart Licensing".format(i['success'].PublicIp))
                        logger.info("Router %s failed to register with Cisco Smart Licensing", i['success'].PublicIp)

        return redirect(url_for('extend_cluster'))
    return render_template('extend_cluster.html', title='Extend Cluster', form=form)


@app.route('/capacity_add', methods=['GET', 'POST'])
@login_required
def capacity_add():
    logger = logging.getLogger(__name__)
    settings = Settings()
    all_routers = get_all_routers()
    form = AddCapacity()

    form.Region.choices = settings.get_regions_tuples()
    form.InstanceType.choices = settings.get_instances_tuples()
    form.instance_number.choices = (('1', '1'), ('2', '2'), ('3', '3'), ('4', '4'), ('5', '5'), ('6', '6'))
    unique_clusters = get_available_clusters(all_routers)
    cluster_list = []
    for i in unique_clusters:
        cluster_list.append((i, i))
    cluster_list.sort()
    form.cluster_value.choices = cluster_list

    if form.validate_on_submit():
        if form.InstanceType.data not in settings.get_region_supported_instances(form.Region.data):
            flash("Instance type '{}' is not available in '{}'".format(form.InstanceType.data, form.Region.data))
            return redirect(url_for('capacity_add'))

        cluster_already_there_result = check_router_in_region(all_routers, form.cluster_value.data, form.Region.data)
        if not cluster_already_there_result:
            flash("Region '{region}' does not yet contain cluster '{cluster}'."
                  " Maybe you want to extend cluster '{cluster}' into region.".format(region=form.Region.data,
                                                                                      cluster=form.cluster_value.data))
            return redirect(url_for('capacity_add'))

        available_dmvpn_addresses = get_available_dmvpn_addresses(all_routers, form.cluster_value.data,
                                                                  int(form.instance_number.data))
        available_subnets = get_available_vpc_cidr_space(all_routers, form.cluster_value.data,
                                                         int(form.instance_number.data))
        az_list = get_best_az(all_routers, form.Region.data, form.cluster_value.data, int(form.instance_number.data))

        hubs = list()
        for rou in all_routers:
            if (rou.cluster_value == form.cluster_value.data) and (rou.hub == 'True'):
                hubs.append(rou)
        cgw_template = hubs[0]
        list_router_objects = list()
        for i in range(int(form.instance_number.data)):
            list_router_objects.append(
                Cgw(Region=form.Region.data,
                    hub=False,
                    region_extension=False,
                    AvailabilityZone=az_list.pop(-1),
                    InstanceType=form.InstanceType.data,
                    asn=int(cgw_template.asn),
                    cluster_value=form.cluster_value.data,
                    available_bandwidth=Settings.instance_types[form.InstanceType.data],
                    AmiId=Settings.regions[form.Region.data]['ami'],
                    max_bandwidth=Settings.instance_types[form.InstanceType.data],
                    KeyName=Settings.regions[form.Region.data]['key'],
                    DmvpnAddress=available_dmvpn_addresses.pop(0),
                    DmvpnNetmask=str(ipaddress.ip_network(Settings.dmvpn_address_space).netmask),
                    eligible='False',
                    DmvpnCidr=Settings.dmvpn_address_space,
                    h1_public=hubs[0].PublicIp,
                    h1_private=hubs[0].DmvpnAddress,
                    h2_public=hubs[1].PublicIp,
                    h2_private=hubs[1].DmvpnAddress,
                    vpc_cidr=available_subnets.pop(0))
                )
        results_list = setup_capacity_add.main(list_router_objects)

        if not results_list:
            flash("Capacity add failed")
            logger.warning("Capacity add failed")
        else:
            for i in results_list:
                if i.get('success', False):
                    flash("Router '{}' successfully deployed".format(i['success'].PublicIp))
                    logger.info("Router %s deployed successfully!", i['success'].PublicIp)
                    if i['success'].registration_failed:
                        flash("Router '{}' failed to register with Cisco Smart Licensing".format(i['success'].PublicIp))
                        logger.info("Router %s failed to register with Cisco Smart Licensing", i['success'].PublicIp)
                else:
                    flash("Router '{}' failed to deploy".format(i['fail'].PublicIp))
                    logger.warning("Router %s deployment and configuration failed", i['fail'].PublicIp)

        return redirect(url_for('capacity_add'))
    return render_template('capacity_add.html', title='Add Capacity', form=form)


@app.route('/remove_cluster', methods=['GET', 'POST'])
@login_required
def remove_cluster():
    logger = logging.getLogger(__name__)
    form = RemoveCluster()
    all_routers = get_all_routers()
    unique_clusters = get_available_clusters(all_routers)

    cluster_list = []
    for i in unique_clusters:
        cluster_list.append((i, i))
    cluster_list.sort()
    form.cluster.choices = cluster_list

    if form.validate_on_submit():
        setup_remove_cluster.main(form.cluster.data)
        flash('Cluster Destroyed')
        logger.info('Cluster %s Destroyed', form.cluster.data)
        return redirect(url_for('remove_cluster'))
    return render_template('remove_cluster.html', title='Remove Cluster', form=form)


@app.route('/contract_cluster', methods=['GET', 'POST'])
@login_required
def contract_cluster():
    logger = logging.getLogger(__name__)
    form = ContractCluster()
    all_routers = get_all_routers()

    temp_list = []
    for i in all_routers:
        cluster_region = i.cluster_value + "/" + i.Region
        temp_list.append(cluster_region)
    unique = list(set(temp_list))
    temp_list = []
    for i in unique:
        temp_list.append((i, i))
    temp_list.sort()
    form.cluster_region.choices = temp_list

    if form.validate_on_submit():
        cluster_region_list = form.cluster_region.data.split('/')
        flag = True
        for i in all_routers:
            if (i.cluster_value == cluster_region_list[0]) and (i.Region == cluster_region_list[1]) and (i.hub == 'True'):
                flag = False
        if not flag:
            flash('You can not contract cluster from DMVPN hub region')
            return redirect(url_for('contract_cluster'))
        else:
            setup_contract_cluster.main(cluster_region_list[0], cluster_region_list[1])
            flash('Cluster Removed from Region')
            logger.info('Cluster %s removed from region %s', cluster_region_list[0], cluster_region_list[1])

        return redirect(url_for('contract_cluster'))
    return render_template('contract_cluster.html', title='Contract Cluster', form=form)


@app.route('/csr_redeploy', methods=['GET', 'POST'])
@login_required
def csr_redeploy():
    logger = logging.getLogger(__name__)
    all_routers = get_all_routers()
    settings = Settings()
    form = CsrRedeploy()
    form.InstanceType.choices = settings.get_instances_tuples()

    candidates = list()
    for router in all_routers:
        if router.eligible == 'False':
            candidates.append(router)

    candidates = sorted(candidates, key=lambda k: k.cluster_value, reverse=False)

    csr_t = list()
    for i in candidates:
        csr_t.append((i.PublicIp, i.PublicIp))
    form.csr.choices = csr_t

    if form.validate_on_submit():

        csr_ip = form.csr.data
        for router in candidates:
            if router.PublicIp == csr_ip:
                old_cgw = router

        if form.InstanceType.data not in settings.get_region_supported_instances(old_cgw.Region):
            flash("Instance type '{}' is not available in '{}'".format(form.InstanceType.data, old_cgw.Region))
            return redirect(url_for('csr_redeploy'))

        hubs = list()
        for rou in all_routers:
            if (rou.cluster_value == old_cgw.cluster_value) and (rou.hub == 'True'):
                hubs.append(rou)

        if old_cgw.hub == 'False':
            available_dmvpn_addresses = get_available_dmvpn_addresses(all_routers, old_cgw.cluster_value, 1)
            DmvpnAddress = available_dmvpn_addresses.pop(0)
        else:
            DmvpnAddress = old_cgw.DmvpnAddress
        available_subnets = get_available_vpc_cidr_space(all_routers, old_cgw.cluster_value, 1)
        new_cgw = Cgw(Region=old_cgw.Region,
                      AvailabilityZone=old_cgw.AvailabilityZone,
                      hub=old_cgw.hub,
                      region_extension=old_cgw.region_extension,
                      InstanceType=form.InstanceType.data,
                      asn=old_cgw.asn,
                      cluster_value=old_cgw.cluster_value,
                      available_bandwidth=settings.instance_types[form.InstanceType.data],
                      AmiId=Settings.regions[old_cgw.Region]['ami'],
                      max_bandwidth=Settings.instance_types[form.InstanceType.data],
                      KeyName=Settings.regions[old_cgw.Region]['key'],
                      DmvpnAddress=DmvpnAddress,
                      DmvpnNetmask=old_cgw.DmvpnNetmask,
                      DmvpnCidr=old_cgw.DmvpnCidr,
                      eligible='False',
                      h1_public=hubs[0].PublicIp,
                      h1_private=hubs[0].DmvpnAddress,
                      h2_public=hubs[1].PublicIp,
                      h2_private=hubs[1].DmvpnAddress,
                      vpc_cidr=available_subnets.pop(0)
                      )

        result = setup_redeploy_csr.main(old_cgw, new_cgw)
        # result = False or cgw object
        if not result:
            flash("Redeploy Failed")
            logger.warning("Redeploy Failed")
        else:
            if result.registration_failed:
                    flash("Router '{}' failed to register with Cisco Smart Licensing".format(result.PublicIp))
                    logger.info("Router %s failed to register with Cisco Smart Licensing", result.PublicIp)
            flash('The redeploy completed!')
            logger.info('The redeploy of router %s successfully completed!', old_cgw.PublicIp)

        return redirect(url_for('csr_redeploy'))
    return render_template('csr_redeploy.html', title='CSR Redeploy', form=form, cgws=candidates)


@app.route('/capacity_remove', methods=['GET', 'POST'])
@login_required
def capacity_remove():
    logger = logging.getLogger(__name__)
    all_routers = get_all_routers()
    all_vpns = get_all_vpns()
    candidates = list()
    for router in all_routers:
        if (router.hub == 'False') and (router.region_extension == 'False') and (router.eligible == 'False'):
            flag = 'none'
            for vpn in all_vpns:
                if vpn.CustomerGatewayId == router.CustomerGatewayId:
                    flag = 'used'
                    break
            if flag == 'none':
                candidates.append(router)

    form = RemoveCapacity()
    tl = []
    for i in candidates:
        tl.append(str(i.PublicIp) + "/" + i.cluster_value + "/" + i.Region)

    temp_list = []
    for i in tl:
        temp_list.append((i, i))
    temp_list.sort()

    form.csr_cluster_region.choices = temp_list

    if form.validate_on_submit():
        csr_cluster_region_list = form.csr_cluster_region.data.split('/')
        for router in candidates:
            if router.PublicIp == csr_cluster_region_list[0]:

                settings = Settings()
                logger = logging.getLogger(__name__)
                if settings.regions[router.Region]['smart_licensing'] == 'True':
                    sl_helper = LicenseHelper(router)
                    result = sl_helper.deregister()
                    if not result:
                        logger.warning('Smart Licensing DeRegistration failed for router %s', router.PublicIp)
                        flash('Smart Licensing DeRegistration failed for router %s', router.PublicIp)

                router.remove_router_vpc_etc()
                flash('CGW removed')
                logger.info('CGW %s removed', router.PublicIp)

        return redirect(url_for('capacity_remove'))
    return render_template('capacity_remove.html', title='Remove Capacity', form=form)


@app.route('/csr_disable', methods=['GET', 'POST'])
@login_required
def csr_disable():
    logger = logging.getLogger(__name__)
    form = CsrDisable()
    all_routers = get_all_routers()
    all_routers = sorted(all_routers, key=lambda k: k.cluster_value, reverse=False)

    routers = list()
    for i in all_routers:
        if i.eligible == 'True':
            routers.append((i.PublicIp, i.PublicIp))
    form.csr_public_ip.choices = routers

    if form.validate_on_submit():
        for router in all_routers:
            if router.PublicIp == form.csr_public_ip.data:
                router.eligible = 'False'
                router.update_eligible_tag()

        flash("CSR1000v '{}' has been set to inactive".format(form.csr_public_ip.data))
        flash('The next poller process will move associated VPNs to another router')
        logger.info('CSR1000v %s successfully disabled', form.csr_public_ip.data)
        return redirect(url_for('csr_disable'))
    return render_template('csr_disable.html', title='CSR Disable', form=form, cgws=all_routers)


@app.route('/csr_enable', methods=['GET', 'POST'])
@login_required
def csr_enable():
    logger = logging.getLogger(__name__)
    form = CsrEnable()
    all_routers = get_all_routers()
    all_routers = sorted(all_routers, key=lambda k: k.cluster_value, reverse=False)

    routers = list()
    for i in all_routers:
        if i.eligible == 'False':
            routers.append((i.PublicIp, i.PublicIp))
    form.csr_public_ip.choices = routers

    if form.validate_on_submit():
        for router in all_routers:
            if router.PublicIp == form.csr_public_ip.data:
                router.eligible = 'True'
                router.update_eligible_tag()

        flash("CSR1000v '{}' has been enabled!".format(form.csr_public_ip.data))
        logger.info('CSR1000v %s successfully enabled!', form.csr_public_ip.data)
        return redirect(url_for('csr_enable'))
    return render_template('csr_enable.html', title='CSR Enable', form=form, cgws=all_routers)


@app.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    settings = Settings()
    regions = settings.get_regions()
    regions.sort()
    results_cgws = []
    results_vgws = []
    results_vpns = []
    results_tgws = []
    for region in regions:
        region_routers_candidate, region_vgws_candidate, region_vpns_candidate, available_clusters, region_tgws_candidate = get_cluster_data(
            region)
        r = list()
        for i in region_routers_candidate:
            if (i.hub == 'True') and (i.region_extension == 'False'):
                r.append(i)
        if r:
            r = sorted(r, key=lambda k: k.cluster_value, reverse=False)
            results_cgws.extend(r)
        r = list()
        for i in region_routers_candidate:
            if (i.hub == 'False') and (i.region_extension == 'True'):
                r.append(i)
        if r:
            r = sorted(r, key=lambda k: k.cluster_value, reverse=False)
            results_cgws.extend(r)
        r = list()
        for i in region_routers_candidate:
            if (i.hub == 'False') and (i.region_extension == 'False'):
                r.append(i)
        if r:
            r = sorted(r, key=lambda k: k.cluster_value, reverse=False)
            results_cgws.extend(r)

        region_vgws_candidate = sorted(region_vgws_candidate, key=lambda k: k.cluster_value, reverse=False)
        results_vgws.extend(region_vgws_candidate)

        region_vpns_candidate = sorted(region_vpns_candidate, key=lambda k: k.cluster_value, reverse=False)
        results_vpns.extend(region_vpns_candidate)

        region_tgws_candidate = sorted(region_tgws_candidate, key=lambda k: k.cluster_value, reverse=False)
        results_tgws.extend(region_tgws_candidate)

    return render_template('dashboard.html', title='Dashboard', cgws=results_cgws, vgws=results_vgws, vpns=results_vpns, tgws=results_tgws)


def get_availability_zones_available(region):
    client = boto3.client('ec2', region_name=region)
    response = client.describe_availability_zones()
    az_names = []
    for i in response['AvailabilityZones']:
        if i['State'] == 'available':
            az_names.append(i['ZoneName'])
    return az_names


def get_best_az(routers, region, cluster, instance_number):
    client = boto3.client('ec2', region_name=region)
    response = client.describe_availability_zones()
    result_list_temp = list()
    result_list_final = list()
    az_dict = {}
    for i in response['AvailabilityZones']:
        if i['State'] == 'available':
            az_dict[i['ZoneName']] = 0
    az_list = list()

    for r in routers:
        if r.Region == region and r.cluster_value == cluster:
            az_dict[r.AvailabilityZone] += 1

    for k, v in az_dict.items():
        az_list.append({'name': k, 'number': v})

    az_list = sorted(az_list, key=lambda a: a['number'], reverse=False)
    for i in range(instance_number):
        result_list_temp.append(deepcopy(az_list[0]))
        az_list[0]['number'] += 1
        az_list = sorted(az_list, key=lambda a: a['number'], reverse=False)
    for i in result_list_temp:
        # for k in i.keys():
        result_list_final.append(i['name'])
    return result_list_final


def get_aws_information(reg):
    ec2_client = BotoClient(reg)
    ei = ec2_client.get_eips()
    vg = ec2_client.get_vgws()
    cg = ec2_client.get_cgws()
    ro = ec2_client.get_routers()
    vp = ec2_client.get_vpns()
    try:
        tg = ec2_client.get_tgws()
    except:
        tg = []
    return ei, vg, cg, ro, vp, tg


def create_aws_objects(eip, vgw, cgw, rou, vpn, tgw):
    region_routers_candidate_d = list()
    region_vgws_candidate_d = list()
    region_vpns_candidate_d = list()
    region_tgws_candidate_d = list()
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
    for tg in tgw:
        region_tgws_candidate_d.append(Tgw(tg))
    return region_routers_candidate_d, region_vgws_candidate_d, region_vpns_candidate_d, region_tgws_candidate_d


def get_available_clusters(ro):
    ac = list()
    for r in ro:
        if r.cluster_value not in ac:
            ac.append(r.cluster_value)
    unique = list(set(ac))
    return unique


def get_cluster_data(region):
    # get aws info
    ei, vg, cg, ro, vp, tg = get_aws_information(region)
    # create objects from aws info
    region_routers_candidate, region_vgws_candidate, region_vpns_candidate, region_tgws_candidate = create_aws_objects(ei, vg, cg, ro, vp, tg)
    # create available cluster list
    available_clusters = get_available_clusters(region_routers_candidate)
    return region_routers_candidate, region_vgws_candidate, region_vpns_candidate, available_clusters, region_tgws_candidate


def get_available_vpc_cidr_space(routers, cluster, number=2):
    available_subnets = list()
    used_subnets = list()
    for r in routers:
        if r.cluster_value == cluster:
            used_subnets.append(r.vpc_cidr)
    all_subnets = list(ipaddress.ip_network(Settings.vpc_cidr_address_space).subnets(new_prefix=28))
    for i in all_subnets:
        i = str(i)
        if i not in used_subnets:
            available_subnets.append(i)
            if len(available_subnets) == number:
                break
    return available_subnets


def get_available_dmvpn_addresses(routers, cluster, number=2):
    available_add = list()
    used_add = list()
    for r in routers:
        if r.cluster_value == cluster:
            used_add.append(r.DmvpnAddress)
    all_addresses = list(ipaddress.ip_network(Settings.dmvpn_address_space).hosts())
    for i in all_addresses:
        i = str(i)
        if i not in used_add:
            available_add.append(i)
            if len(available_add) == number:
                break
    return available_add


def get_available_dmvpn_addresses_hub(routers, cluster, number=2):
    available_add = list()
    used_add = list()
    for r in routers:
        if r.cluster_value == cluster:
            used_add.append(r.DmvpnAddress)
    all_addresses = list(ipaddress.ip_network(Settings.dmvpn_address_space).hosts())
    all_addresses.reverse()
    for i in all_addresses:
        i = str(i)
        if i not in used_add:
            available_add.append(i)
            if len(available_add) == number:
                break
    return available_add


def get_all_routers():
    router_objects = list()
    for reg in Settings.regions:
        eips, vgws, cgws, routers, vpns, tgws = get_aws_information(reg)
        region_routers_candidate, region_vgws_candidate, region_vpns_candidate, region_tgws_candidate = create_aws_objects(eips, vgws, cgws, routers, vpns, tgws)
        router_objects.extend(region_routers_candidate)
    return router_objects


def get_all_vpns():
    vpn_objects = list()
    for reg in Settings.regions:
        eips, vgws, cgws, routers, vpns, tgws = get_aws_information(reg)
        region_routers_candidate, region_vgws_candidate, region_vpns_candidate, region_tgws_candidate = create_aws_objects(eips, vgws, cgws, routers, vpns, tgws)
        vpn_objects.extend(region_vpns_candidate)
    return vpn_objects


def check_router_in_region(all_rout, cluster_value, region):
    for i in all_rout:
        if (i.Region == region) and (i.cluster_value == cluster_value):
            return True
    return False


class Cgw:
    def __init__(self, hub, region_extension, eligible, cluster_value, Region, AvailabilityZone, asn, InstanceType,
                 max_bandwidth, available_bandwidth, AmiId, KeyName, DmvpnAddress, DmvpnNetmask, DmvpnCidr,
                 vpc_cidr, h1_public=None, h1_private=None, h2_public=None, h2_private=None):
        self.hub = hub
        self.region_extension = region_extension
        self.eligible = eligible
        self.cluster_value = cluster_value
        self.Region = Region
        self.AvailabilityZone = AvailabilityZone
        self.asn = asn
        self.InstanceType = InstanceType
        self.max_bandwidth = max_bandwidth
        self.available_bandwidth = available_bandwidth
        self.AmiId = AmiId
        self.KeyName = KeyName
        self.DmvpnAddress = DmvpnAddress
        self.DmvpnNetmask = DmvpnNetmask
        self.DmvpnCidr = DmvpnCidr
        self.h1_public = h1_public
        self.h1_private = h1_private
        self.h2_public = h2_public
        self.h2_private = h2_private
        self.vpc_cidr = vpc_cidr

    def update_eligible_tag(self):
        logger = logging.getLogger(__name__)
        client = boto3.client('ec2', region_name=self.Region)
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

    def update_available_bandwidth_tag(self):
        logger = logging.getLogger(__name__)
        client = boto3.client('ec2', region_name=self.Region)
        try:
            client.create_tags(
                Resources=[
                    self.InstanceId
                ],
                Tags=[
                    {
                        'Key': 'tvpc_available_bandwidth',
                        'Value': str(self.available_bandwidth)
                    }
                ]
            )
            return 'success'
        except:
            logger.error("Exception while trying to update router %s tvpc_available_bandwidth tag", self.PublicIp,
                         exc_info=True)
            return 'fail'
