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

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField, IntegerField
from wtforms.validators import ValidationError, DataRequired, EqualTo, NumberRange
# from web_app.models import User


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Log In')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Request Password Reset')


class AddCluster(FlaskForm):
    Region = SelectField('Region')
    InstanceType = SelectField('Instance Type')
    asn = IntegerField('ASN (65413 - 65535)', validators=[DataRequired(), NumberRange(65413, 65535)])
    cluster_value = StringField('Cluster Name, e.g., development', validators=[DataRequired()])

    submit = SubmitField('Submit')


class ExtendCluster(FlaskForm):
    cluster_value = SelectField('Which Cluster would you like to extend: ')
    Region = SelectField('Into which region would you like to extend?: ')
    InstanceType = SelectField('Which instance type for the initial routers: ')
    submit = SubmitField('Submit')


class AddCapacity(FlaskForm):
    cluster_value = SelectField('To which Cluster would you like to add capacity: ')
    Region = SelectField('To which region would you like to add capacity: ')
    InstanceType = SelectField('Instance Type: ')
    instance_number = SelectField('How many instances would you like to deploy: ')
    submit = SubmitField('Submit')


class RemoveCluster(FlaskForm):
    cluster = SelectField('Which Cluster would you like to disappear: ')
    submit = SubmitField('Submit')


class ContractCluster(FlaskForm):
    cluster_region = SelectField('Which Extended Cluster/Region would you like to remove: ')
    submit = SubmitField('Submit')


class CsrRedeploy(FlaskForm):
    csr = SelectField('Which Csr1000v would you like to redeploy: ')
    InstanceType = SelectField('Which instance Type: ')
    submit = SubmitField('Submit')


class RemoveCapacity(FlaskForm):
    csr_cluster_region = SelectField('Which CSR1000v/Cluster/Region would you like to remove: ')
    submit = SubmitField('Submit')


class CsrDisable(FlaskForm):
    csr_public_ip = SelectField('Which CSR1000v would you like to disable: ')
    submit = SubmitField('Submit')


class CsrEnable(FlaskForm):
    csr_public_ip = SelectField('Which CSR1000v would you like to enable: ')
    submit = SubmitField('Submit')
