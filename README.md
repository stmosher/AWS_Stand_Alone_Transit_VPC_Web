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
    - ````````git clone https://wwwin-github.cisco.com/stmosher/Transit_AWS_stand_alone.git````````
2. Create a virtual environment
    - `````` python3 venv venv ``````
3. Activate virtual environment
    - ```````` source venv/bin/activate```````` 
5. Edit set_env_vars_empty.sh with your appropriate database, DMVPN, Netconf, and AWS credentials. See example below:
    - ````````#!/usr/bin/env bash ````````
    - ````````export SECRET_KEY='key123'````````
    - ````````export FLASK_APP=web_app.py````````
    - ````````export dmvpn_password='HardPasswordToGuess'````````
    - ````````export AWS_ACCESS_KEY_ID='1111111111111'````````
    - ````````export AWS_SECRET_ACCESS_KEY='123451234512345'````````

6. Run script to set environment variables:
    - ````````source ./set_env_vars_empty.sh````````
7. Install application requirements:
    - ````````pip install -r requirements.txt````````
8. Create tables in your database:
    - ````````flask migrate init````````
    - ````````flask db migrate -m "init"````````
    - ````````flask db upgrade````````
9. Create a username and password in the "user" table:
    - ````````INSERT INTO user (username, password) VALUES ('schmuckatelli', '12345');````````
10. Add Regions, per region CSR1000v AMIs, and per regions keys to config.py
11. Copy your applicable AWS keys to directory "keys"
12. Start web server
    - ````````flask run -h 0.0.0.0 -p 8080 ````````
13. From virtual environment, with "source ./set_env_vars_empty.sh" configured:
    - ````````python scheduler_main.py````````
14. Log into web-server with previously added username and password

## Webserver
![alt-test](./README/dashboard.png "dashboard")

Web-server tabs:
- Dashboard
    - Displays information about CSRs, vGWs, and deployed VPNs
- +Cluster
    - Deploys initial CSR1000v pair (cluster)
        - Choose region
        - Choose Instance Type
        - Create cluster KEY/VALUE pair for users
        - Define cluster ASN
    - Cluster routers are deployed in different availability zones
- +Region
    - Extends cluster into a new region
        - Choose cluster to extend
        - Choose new region in which to deploy redundant CSR1000v pair
        - Choose instance types for regional CSR1000v pair
- +Capacity
    - Adds another CSR1000v pair to the region of your choosing
- Disable CSR
    - Marks CSR1000v routers an ineligible
        - This causes the next scheduler cycle to move associated vGW connectivity to another, least loaded, regional router pair,
         or drop VPN's if another fully functioning pair isn't available in region
- Redeploy CSR
    - Prerequisite is the pair must have been previously disabled
    - Allows redeploy with new CSR1000v image
    - Allows redeploy with higher or lower capacity AWS instance type
    - A new CSR1000v is deployed, an old CSR1000v pair EIP is transferred, old CSR1000v is destroyed, and again for 2nd old CSR1000v
- Enable CSR
    - If CSR was disabled, use this to re-enable
        - Enabled routers will be eligible for VPNs
- -Capacity
    - Prerequisite is the CSR1000v pair must have been disabled
    - Removes previously added capacity pairs
- -Region
    - All chosen cluster/region CSR1000vs will be destroyed and associated VPNs deleted
- -Cluster
    - All CSR1000vs in the cluster will be destroyed and associated VPNs deleted

## Fault Tolerance
Scheduler function performs a health check. If a CSR1000v router's AWS status is not "available", it will mark the router as disabled.
If both routers, become disabled, if will VPN connect the vGWs to another pair. If there's no pair available, the VPNS will be removed. 
New VPNs will be created when an cluster pair becomes available.

If a CSR1000v goes down, if it comes back up, you must manually "Enable CSR" to make it eligible to receive VPNs.

In the case of a VPN removal where the terminating CSR1000v is unconfigurable, the AWS VPN will be deleted.
This could cause an issue is the router comes back up and a new VPN is to be configured using the same subnet (address conflict).

Therefore to mitigate, upon VPN deletion where the router was not configurable, the program will mark the subnet as a ZOMBIE.
It you find a ZOMBIE in the logs or database, you can remove configurations from the conflicted routers, or even simpler,
you can blow away and redeploy the router through redeploy or -Capacity/+Capacity. 

## Logging
All logs associated with scheduler.py (vpn build/remove function) are found in "log_poller.log".

All logs associated with web_app.py (Web Server) are found in log_web_app.log

### Notes
Tested with Python 3.7.2

Cisco IOS-XE 16.10.1b


