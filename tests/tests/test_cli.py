#!/usr/bin/python
# Copyright 2017 Mender Software AS
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        https://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
from common import cli, api_client_mgmt, mongo, clean_db, \
    make_auth, explode_jwt
import bravado
import pytest
import tenantadm


class TestCli:
    def test_create_user(self, api_client_mgmt, cli, clean_db):
        cli.create_user('foo@bar.com', '1234youseeme')
        users = api_client_mgmt.get_users()
        assert [user for user in users if user.email == 'foo@bar.com']

    def test_create_user_login(self, api_client_mgmt, cli, clean_db):
        email = 'foo@bar.com'
        password = '1234youseeme'
        cli.create_user(email, password)
        _, r = api_client_mgmt.login(email, password)
        assert r.status_code == 200

        token = r.text
        assert token

    def test_create_user_with_id(self, api_client_mgmt, cli, clean_db):
        cli.create_user('foo@bar.com', '1234youseeme', user_id='123456')
        users = api_client_mgmt.get_users()
        assert [user for user in users \
                if user.email == 'foo@bar.com' and user.id == '123456']


class TestCliMultitenant:
    def test_create_user(self, api_client_mgmt, cli):
        cli.create_user('foo-tenant1id@bar.com', '1234youseeme',
                        tenant_id='tenant1id')

        users = api_client_mgmt.get_users(make_auth('foo', tenant='tenant1id'))
        assert [user for user in users if user.email == 'foo-tenant1id@bar.com']

        other_tenant_users = api_client_mgmt.get_users(make_auth('foo',
                                                                 tenant='tenant2id'))
        assert not other_tenant_users

    def test_create_user_login(self, api_client_mgmt, cli, clean_db):
        email = 'foo@bar.com'
        password = '1234youseeme'
        tenant = 'tenant1id'

        users_db = {tenant: [email]}

        cli.create_user(email, password, tenant_id=tenant)

        with tenantadm.run_fake_user_tenants(users_db):
            _, r = api_client_mgmt.login(email, password)
            assert r.status_code == 200

            token = r.text
            assert token
            _, claims, _ = explode_jwt(token)
            assert claims['mender.tenant'] == tenant
