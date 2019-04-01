# AWS Stand Alone Cloud Transit VPC Solution
## Description
Summary: This program automates the lifecycle of Cisco CSR1000v routers for use with the stand-alone transit VPC 
solution.

IT operations must ensure enterprise IT policies are followed. These include:
* Security
* Routing
* QoS

Application owners and developers desire rapid on-demand provisioning of their applications.

This program enables IT operations to rapidly provision a scalable and secure IPSEC overlay network for interVPC cloud routing.
IT operations will provide application owners and developers a KEY/VALUE pair for access to the appropriate routing cluster.
Once the application owners and/or developers tag their VPC connected AWS virtual private gateway (vGW) with the KEY/VALUE pair, 
redundant VPN tunnels will be provisioned automatically.

This program also allows application owners and developers to request bandwidth from the network. This allows the
program to select the best suited router pair for the requested service. Bandwidth requests are configured  by the application
owners and/or developers by adding a KEY='bandwidth', VALUE='$integter for Mbps' tag to the vGW.

## Installation

1. Clone the repository from GitHub
    - ````````git clone https://wwwin-github.cisco.com/stmosher/GovCloud_Web_Interface.git````````
2. Create a virtual environment
    - `````` python3 venv venv ``````
3. Activate virtual environment
    - ```````` source venv/bin/activate```````` 
5. Edit set_env_vars_empty.sh with your appropriate DMVPN, AWS, and Web App access credentials. See example below:
    - ````````#!/usr/bin/env bash ````````
    - ````````export SECRET_KEY='key123'````````
    - ````````export FLASK_APP=web_app.py````````
    - ````````export dmvpn_password='HardPasswordToGuess'````````
    - ````````export AWS_ACCESS_KEY_ID='1111111111111'````````
    - ````````export AWS_SECRET_ACCESS_KEY='123451234512345'````````
    - ````````export export web_username='Administrator'````````
    - ````````export web_password='Password123'````````
6. Run script to set environment variables:
    - ````````source ./set_env_vars_empty.sh````````
7. Install application requirements:
    - ````````pip install -r requirements.txt````````
8. Add Regions, per region CSR1000v AMIs, and per regions keys to config.py
9. Copy your applicable AWS keys to directory "keys"
10. Start web server
    - ````````flask run -h 0.0.0.0 -p 8080 ````````
11. Log into web-server environment variable set username and password
12. Install and run the TVPC Poller app found at https://wwwin-github.cisco.com/stmosher/GovCloud_Poller_Program.git

## Webserver
![alt-test](./README/dashboard.png "dashboard")

Web-server tabs:
- Dashboard
    - Displays information about CSRs, vGWs, and deployed VPNs
- +Cluster
    - Deploys initial CSR1000v pair (cluster)
        - Choose region
        - Choose Instance Type
        - Create cluster name
        - Define cluster ASN
    - Cluster routers are deployed in different availability zones
- +Region
    - Extends cluster into a new region
        - Choose cluster to extend
        - Choose new region in which to deploy redundant CSR1000v pair
        - Choose instance types for regional CSR1000v anchor routers
- +Capacity
    - Adds another CSR1000v(s) to the region of your choosing
- Disable CSR
    - Marks a CSR1000v router ineligible
        - This causes the next scheduler cycle to move associated vGW connectivity to another, least loaded, regional router,
         or drop VPN's if another fully functioning router isn't available in region and different region AZ.
- Redeploy CSR
    - Prerequisite is the CSR must have been previously disabled
    - Allows redeploy with new CSR1000v image
    - Allows redeploy with higher or lower capacity AWS instance type
    - A new CSR1000v is deployed, the old CSR1000v EIP is transferred, the old CSR1000v is destroyed
- Enable CSR
    - If CSR was disabled, use this to re-enable
        - Enabled routers will be eligible for VPNs
- -Capacity
    - Prerequisite is the CSR1000v must have been disabled
    - Removes a previously added capacity router
- -Region
    - All chosen cluster/region CSR1000vs will be destroyed and associated VPNs deleted
- -Cluster
    - All CSR1000vs in the cluster will be destroyed and associated VPNs deleted

## Logging
All logs associated with web_app.py (Web Server) are found in log_web_app.log

### Notes
Tested with Python 3.7.2

Cisco IOS-XE 16.10.1b


