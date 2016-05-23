# Copyright 2016 Nexenta Systems, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
"""
:mod:`nexenta.jsonrpc` -- Nexenta-specific JSON RPC client
=====================================================================

.. automodule:: nexenta.jsonrpc
"""

import base64
import json
import requests
import time

from oslo_log import log as logging
from oslo_serialization import jsonutils

from manila.exception import NexentaException

LOG = logging.getLogger(__name__)


class NexentaJSONProxy(object):
    def __init__(self, scheme, host, port, user,
                 password, auto=False, method=None):
        self.scheme = scheme
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.auto = True
        self.method = method

    @property
    def url(self):
        return '%s://%s:%s/' % (self.scheme, self.host, self.port)

    def __getattr__(self, method=None):
        if method:
            return NexentaJSONProxy(
                self.scheme, self.host, self.port,
                self.user, self.password, self.auto, method)

    def __hash__(self):
        return self.url.__hash__()

    def __repr__(self):
        return 'NEF proxy: %s' % self.url

    def __call__(self, path, data=None):
        auth = base64.b64encode(
            ('%s:%s' % (self.user, self.password)).encode('utf-8'))
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Basic %s' % auth
        }
        url = self.url + path

        if data:
            data = jsonutils.dumps(data)

        LOG.debug('Sending JSON to url: %s, data: %s, method: %s',
                  path, data, self.method)

        response = getattr(requests, self.method)(
            url, data=data, headers=headers)
        self.check_error(response)
        content = json.loads(response.content) if response.content else None
        LOG.debug("Got response: %s %s %s",
                  response.status_code, response.reason, content)
        response.close()

        if response.status_code == 202 and content:
            url = self.url + content['links'][0]['href']
            keep_going = True
            while keep_going:
                time.sleep(1)
                response = requests.get(url)
                self.check_error(response)
                LOG.debug("Got response: %s %s", response.status_code,
                          response.reason)
                content = json.loads(
                    response.content) if response.content else None
                keep_going = response.status_code == 202
                response.close()
        return content

    def check_error(self, response):
        code = response.status_code
        if code not in (200, 201, 202):
            reason = response.reason
            content = json.loads(
                response.content) if response.content else None
            response.close()
            if content and 'code' in content:
                message = content.get(
                    'message', 'Message is not specified by Nexenta REST')
                raise NexentaException(message, code=content['code'])
            raise NexentaException(
                'Got bad response: {} {} {}'.format(code, reason, content))
