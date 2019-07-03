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
    SECRET_KEY = os.environ.get('SECRET_KEY')


class Settings:
    # regions added to the below will be considered for IPSEC overlay participation
    regions = {
        # 'us-gov-west-1': {
        #     'ami': 'ami-ce6617af',
        #     'key': 'CSR_500',
        #     'eligible_default': 'False',
        #     'smart_licensing': 'True',
        #     'instance_types': {
        #         't2.medium': 250,
        #         'c5.large': 2000,
        #         'c5.xlarge': 2500,
        #         'c5.2xlarge': 6000,
        #         'c5.4xlarge': 8000,
        #         'c5.9xlarge': 8900
        #     }
        # },
        # 'us-gov-east-1': {
        #     'ami': 'ami-025da1276d2b0b0ae',
        #     'key': 'CSR_600.pem',
        #     'eligible_default': 'False',
        #     'smart_licensing': 'True',
        #     'instance_types': {
        #         'c5.large': 2000,
        #         'c5.xlarge': 2500,
        #         'c5.2xlarge': 6000,
        #         'c5.4xlarge': 8000,
        #         'c5.9xlarge': 8900
        #     }
        # },
        'us-east-1': {
            'ami': 'ami-0d8a2f539abbd5763',
            'key': 'Virginia',
            'eligible_default': 'True',
            'smart_licensing': 'True',
            'instance_types': {
                't2.medium': 250,
                'c4.large': 500,
                'c4.xlarge': 1000,
                'c4.2xlarge': 2000,
                'c4.4xlarge': 4500,
                'c5.large': 2000,
                'c5.xlarge': 2500,
                'c5.2xlarge': 6000,
                'c5.4xlarge': 8000,
                'c5.9xlarge': 8900
            }
        },
        'us-east-2': {
            'ami': 'ami-07f8094154b663213',
            'key': 'Ohio',
            'eligible_default': 'True',
            'smart_licensing': 'True',
            'instance_types': {
                't2.medium': 250,
                'c4.large': 500,
                'c4.xlarge': 1000,
                'c4.2xlarge': 2000,
                'c4.4xlarge': 4500,
                'c5.large': 2000,
                'c5.xlarge': 2500,
                'c5.2xlarge': 6000,
                'c5.4xlarge': 8000,
                'c5.9xlarge': 8900
            }
        },
        # 'us-west-1': {
        #     'ami': 'ami-0cf71f2688b924e36',
        #     'key': 'CSR_400',
        #     'eligible_default': 'False',
        #     'smart_licensing': 'True',
        #     'instance_types': {
        #         't2.medium': 250,
        #         'c4.large': 500,
        #         'c4.xlarge': 1000,
        #         'c4.2xlarge': 2000,
        #         'c4.4xlarge': 4500,
        #         'c5.large': 2000,
        #         'c5.xlarge': 2500,
        #         'c5.2xlarge': 6000,
        #         'c5.4xlarge': 8000,
        #         'c5.9xlarge': 8900
        #     }
        # },
        # 'us-west-2': {
        #     'ami': 'ami-01d5fc08abef26bc5',
        #     'key': 'CSR_200',
        #     'eligible_default': 'False',
        #     'smart_licensing': 'True',
        #     'instance_types': {
        #         't2.medium': 250,
        #         'c4.large': 500,
        #         'c4.xlarge': 1000,
        #         'c4.2xlarge': 2000,
        #         'c4.4xlarge': 4500,
        #         'c5.large': 2000,
        #         'c5.xlarge': 2500,
        #         'c5.2xlarge': 6000,
        #         'c5.4xlarge': 8000,
        #         'c5.9xlarge': 8900
        #     }
        # }
    }
    # Possible instance types and max IPSEC performance for router deployment options
    instance_types = {
        't2.medium': 250,
        'c4.large': 500,
        'c4.xlarge': 1000,
        'c4.2xlarge': 2000,
        'c4.4xlarge': 4500,
        'c5.large': 2000,
        'c5.xlarge': 2500,
        'c5.2xlarge': 6000,
        'c5.4xlarge': 8000,
        'c5.9xlarge': 8900
    }

    # Smart Licensing Information
    licenses = [
        {'license_token': '',
         'license_feature_set': 'ax',
         'license_throughput': 5000
         }
    ]
    dns_server = '8.8.8.8'
    email_address = 'stmosher@cisco.com'
    smart_licensing_server = 'https://tools.cisco.com/its/service/oddce/services/DDCEService'

    # Items with below key in AWS TAG will be considered participating in program
    tvpc_program_key = 'auto_tvpc_cluster_member'
    # Router VPC CIDR blocks are taken from the address space below
    vpc_cidr_address_space = '10.255.0.0/23'
    # Router DMVPN Tunnel addresses are from the address space below
    dmvpn_address_space = '192.168.254.0/23'
    dmvpn_password = os.environ.get('dmvpn_password')
    # AWS VPN tunnels are created using the address space below - Defined by AWS
    aws_vpn_space = '169.254.0.0/16'
    aws_reserved_vpn_space = ['169.254.0.0/30',
                              '169.254.1.0/30',
                              '169.254.2.0/30',
                              '169.254.3.0/30',
                              '169.254.4.0/30',
                              '169.254.5.0/30',
                              '169.254.169.252/30',
                              '169.254.255.252/30']
    # Tunnels created for router to vGW connectivity use the interface ranges specified below
    vpn_interface_range = {'start': 5000, 'end': 5999}

    def get_instances_tuples(self):
        types = []
        for k in self.instance_types:
            types.append((k, k))
        return types

    def get_region_supported_instances(self, region):
        types = []
        for k in self.regions[region]['instance_types']:
            types.append(k)
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
