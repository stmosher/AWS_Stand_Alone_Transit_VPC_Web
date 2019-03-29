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

import os


class Config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'MyTestSecretKEy'


class Settings:
    regions = {
        'us-gov-west-1': {
            'ami': 'ami-19630c78',
            'key': 'CSR_500'
        }
        # 'us-gov-east-1': {
        #     'ami': 'xxxx',
        #     'key': 'CSR_600'
        # },
        # 'us-east-1': {
        #     'ami': 'ami-0d8a2f539abbd5763',
        #     'key': 'CSR_100'
        # },
        # 'us-east-2': {
        #     'ami': 'ami-07f8094154b663213',
        #     'key': 'CSR300'
        # },
        # 'us-west-1': {
        #     'ami': 'ami-0cf71f2688b924e36',
        #     'key': 'CSR_400'
        # },
        # 'us-west-2': {
        #     'ami': 'ami-01d5fc08abef26bc5',
        #     'key': 'CSR_200'
        # }
    }
    instance_types = {
        'c4.large': 500,
        'c4.xlarge': 1000,
        'c4.2xlarge': 2000,
        'c4.4xlarge': 4500
    }
    tvpc_program_key = 'auto_tvpc_cluster_member'
    dmvpn_address_space = "192.168.254.0/23"
    dmvpn_password = os.environ.get('dmvpn_password')
    users = [{'id': '1', 'username': 'admin', 'password': 'cisco'}]
    aws_vpn_space = '169.254.0.0/16'
    aws_reserved_vpn_space = ['169.254.0.0/30',
                              '169.254.1.0/30',
                              '169.254.2.0/30',
                              '169.254.3.0/30',
                              '169.254.4.0/30',
                              '169.254.5.0/30',
                              '169.254.169.252/30',
                              '169.254.255.252/30']
    vpn_interface_range = {'start': 5000, 'end': 5999}

    def get_instances_tuples(self):
        types = []
        for k in self.instance_types:
            types.append((k, k))
        return types

    def get_regions_tuples(self):
        regions = []
        for k in self.regions:
            regions.append((k, k))
        return regions

    def get_regions(self):
        regions = []
        for k in self.regions:
            regions.append(k)
        return regions
