#!/usr/bin/python
# Copyright 2021 Northern.tech AS
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
import json
import pytest
import uuid
from datetime import datetime, timedelta
from pymongo import MongoClient
from base64 import urlsafe_b64encode, urlsafe_b64decode
from client import CliClient, ManagementApiClient, InternalApiClient


def make_auth(sub, tenant=None):
    """
        Prepare an almost-valid JWT token header, suitable for consumption by our identity middleware (needs sub and optionally mender.tenant claims).

        The token contains valid base64-encoded payload, but the header/signature are bogus.
        This is enough for the identity middleware to interpret the identity
        and select the correct db; note that there is no gateway in the test setup, so the signature
        is never verified.

        If 'tenant' is specified, the 'mender.tenant' claim is added.
    """
    try:
        sub_id = uuid.UUID(sub)
    except ValueError:
        sub_id = uuid.uuid5(uuid.NAMESPACE_OID, sub)

    payload = {
        "jti": str(uuid.uuid4()),
        "sub": str(sub_id),
        "iss": "Mender",
        "exp": int((datetime.now() + timedelta(days=7)).timestamp()),
    }
    if tenant is not None:
        payload["mender.tenant"] = tenant
    payload = json.dumps(payload)
    payloadb64 = urlsafe_b64encode(payload.encode("utf-8"))

    jwt = "bogus_header." + payloadb64.decode().strip("=") + ".bogus_sign"

    return {"Authorization": "Bearer " + jwt}


def make_basic_auth(username, password):
    """
    Creates an auth header suitable for user /login.
    """
    hdr = "{}:{}".format(username, password)
    hdr = urlsafe_b64encode(hdr.encode("utf-8"))
    return "Basic " + hdr.decode()


@pytest.fixture(scope="session")
def mongo():
    return MongoClient("mender-mongo:27017")


def mongo_cleanup(mongo):
    dbs = mongo.database_names()
    dbs = [d for d in dbs if d not in ["local", "admin", "config"]]
    for d in dbs:
        mongo.drop_database(d)


@pytest.fixture(scope="session")
def cli():
    return CliClient()


@pytest.fixture(scope="session")
def api_client_mgmt():
    return ManagementApiClient()


@pytest.fixture(scope="session")
def api_client_int():
    return InternalApiClient()


@pytest.yield_fixture(scope="class")
def init_users(cli, api_client_mgmt, mongo):
    for i in range(5):
        cli.create_user("user-{}@foo.com".format(i), "correcthorsebatterystaple")

    yield api_client_mgmt.get_users()
    mongo_cleanup(mongo)


@pytest.yield_fixture(scope="function")
def init_users_f(cli, api_client_mgmt, mongo):
    """
    Function-scoped version of 'init_users'.
    """
    for i in range(5):
        cli.create_user("user-{}@foo.com".format(i), "correcthorsebatterystaple")

    yield api_client_mgmt.get_users()
    mongo_cleanup(mongo)


@pytest.yield_fixture(scope="class")
def init_users_mt(cli, api_client_mgmt, mongo):
    tenant_users = {"tenant1id": [], "tenant2id": []}
    for t in tenant_users:
        for i in range(5):
            cli.create_user(
                "user-{}-{}@foo.com".format(i, t), "correcthorsebatterystaple", None, t,
            )
        tenant_users[t] = api_client_mgmt.get_users(make_auth("foo", t))
    yield tenant_users
    mongo_cleanup(mongo)


@pytest.yield_fixture(scope="function")
def init_users_mt_f(cli, api_client_mgmt, mongo):
    """
    Function-scoped version of 'init_users_mt'.
    """
    tenant_users = {"tenant1id": [], "tenant2id": []}
    for t in tenant_users:
        for i in range(5):
            cli.create_user(
                "user-{}-{}@foo.com".format(i, t), "correcthorsebatterystaple", None, t,
            )
            tenant_users[t] = api_client_mgmt.get_users(make_auth("foo", t))
    yield tenant_users
    mongo_cleanup(mongo)


@pytest.yield_fixture(scope="class")
def user_tokens(init_users, api_client_mgmt):
    tokens = []
    for user in init_users:
        _, r = api_client_mgmt.login(user.email, "correcthorsebatterystaple")
        tokens.append(r.text)

    yield tokens


@pytest.yield_fixture(scope="function")
def clean_db(mongo):
    mongo_cleanup(mongo)
    yield mongo
    mongo_cleanup(mongo)


def b64pad(b64data):
    """Pad base64 string with '=' to achieve a length that is a multiple of 4
    """
    return b64data + "=" * (4 - (len(b64data) % 4))


def explode_jwt(token):
    parts = token.split(".")
    assert len(parts) == 3

    # JWT fields are passed in a header and use URL safe encoding, which
    # substitutes - instead of + and _ instead of /
    hdr_raw = urlsafe_b64decode(b64pad(parts[0]))
    claims_raw = urlsafe_b64decode(b64pad(parts[1]))
    sign = urlsafe_b64decode(b64pad(parts[2]))

    # unpack json data
    hdr = json.loads(hdr_raw.decode())
    claims = json.loads(claims_raw.decode())

    return hdr, claims, sign
