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

import mock
from mock import patch

from manila import context
from manila import exception
from manila.share import configuration as conf
from manila.share.drivers.nexenta.ns5.nexenta_nas import NexentaNasDriver
from manila.share.drivers.nexenta.ns5.nexenta_nas import PATH_DELIMITER
from manila import test
from oslo_utils import units

PATH_TO_RPC = 'manila.share.drivers.nexenta.ns5.jsonrpc.NexentaJSONProxy'


class TestNexentaNasDriver(test.TestCase):

    def setUp(self):
        def _safe_get(opt):
            return getattr(self.cfg, opt)
        super(TestNexentaNasDriver, self).setUp()
        self.ctx = context.get_admin_context()
        self.cfg = mock.Mock(spec=conf.Configuration)
        self.cfg.safe_get = mock.Mock(side_effect=_safe_get)
        self.cfg.nexenta_host = '1.1.1.1'
        self.cfg.nexenta_rest_port = 8080
        self.cfg.nexenta_rest_protocol = 'auto'
        self.cfg.nexenta_pool = 'pool1'
        self.cfg.nexenta_nfs_share = 'nfs_share'
        self.cfg.nexenta_user = 'user'
        self.cfg.nexenta_password = 'password'
        self.cfg.nexenta_thin_provisioning = False
        self.cfg.enabled_share_protocols = 'NFS'
        self.cfg.nexenta_mount_point_base = '$state_path/mnt'
        self.cfg.nexenta_dataset_compression = 'on'

        self.cfg.network_config_group = 'DEFAULT'
        self.cfg.admin_network_config_group = (
            'fake_admin_network_config_group')
        self.cfg.driver_handles_share_servers = False

        self.drv = NexentaNasDriver(configuration=self.cfg)
        self.drv.do_setup(self.ctx)

        self.pool_name = self.cfg.nexenta_pool
        self.fs_prefix = self.cfg.nexenta_nfs_share

    @patch(PATH_TO_RPC)
    def test_check_for_setup_error(self, m):
        m.get.return_value = {'data': []}
        self.assertRaises(LookupError, self.drv.check_for_setup_error)

    @patch(PATH_TO_RPC)
    def test_create_share(self, m):
        share = {'name': 'share', 'size': 1}
        self.assertEqual('{}:/{}/{}/{}'.format(
            self.cfg.nexenta_host, self.pool_name,
            self.fs_prefix, share['name']),
            self.drv.create_share(self.ctx, share))

    @patch('manila.share.drivers.nexenta.ns5.nexenta_nas.NexentaNasDriver.'
           '_add_permission')
    @patch(PATH_TO_RPC)
    def test_create_share__error_on_add_permission(
            self, m, add_permission_mock):
        share = {'name': 'share', 'size': 1}
        add_permission_mock.side_effect = exception.NexentaException(
            'An error occurred while adding permission')
        self.assertRaises(
            exception.NexentaException, self.drv.create_share, self.ctx, share)
        url = 'storage/pools/pool1/filesystems/nfs_share%2Fshare'
        self.drv.nef.delete.assert_called_with(url)
        url = 'storage/pools/{}/filesystems/{}'.format(
            self.pool_name, '%2F'.join([self.fs_prefix, share['name']]))
        self.drv.nef.delete.assert_called_with(url)

    @patch(PATH_TO_RPC)
    def test_create_share_from_snapshot(self, m):
        share = {'name': 'share'}
        snapshot = {'name': 'share@first', 'share_name': 'share'}
        self.assertEqual('{}:/{}/{}/{}'.format(
            self.cfg.nexenta_host, self.pool_name,
            self.fs_prefix, share['name']),
            self.drv.create_share_from_snapshot(self.ctx, share, snapshot))

        url = ('storage/pools/%(pool)s/'
               'filesystems/%(fs)s/snapshots/%(snap)s/clone') % {
            'pool': self.pool_name,
            'fs': PATH_DELIMITER.join(
                [self.fs_prefix, snapshot['share_name']]),
            'snap': snapshot['name']}
        path = '/'.join([self.pool_name, self.fs_prefix, share['name']])
        data = {'targetPath': path}
        self.drv.nef.post.assert_any_call(url, data)

    @patch('manila.share.drivers.nexenta.ns5.nexenta_nas.NexentaNasDriver.'
           '_add_permission')
    @patch(PATH_TO_RPC)
    def test_create_share_from_snapshot__add_permission_error(
            self, m, add_permission_mock):
        share = {'name': 'share'}
        snapshot = {'share_name': 'share', 'name': 'share@first'}
        add_permission_mock.side_effect = exception.NexentaException(
            'Some exception')
        self.assertRaises(
            exception.NexentaException, self.drv.create_share_from_snapshot,
            self.ctx, share, snapshot)

        url = ('storage/pools/%(pool)s/filesystems/%(fs)s') % {
            'pool': self.pool_name,
            'fs': PATH_DELIMITER.join(
                (self.fs_prefix, share['name']))}
        self.drv.nef.delete.assert_any_call(url)

    @patch('manila.share.drivers.nexenta.ns5.nexenta_nas.NexentaNasDriver.'
           '_add_permission')
    @patch(PATH_TO_RPC)
    def test_create_share_from_snapshot__add_permission_error_error(
            self, m, add_permission_mock):
        share = {'name': 'share'}
        snapshot = {'share_name': 'share', 'name': 'share@first'}
        add_permission_mock.side_effect = exception.NexentaException(
            'Some exception')
        self.drv.nef.delete.side_effect = exception.NexentaException(
            'Some exception 2')
        self.assertRaises(
            exception.NexentaException, self.drv.create_share_from_snapshot,
            self.ctx, share, snapshot)

    @patch(PATH_TO_RPC)
    def test_delete_share(self, m):
        share = {'name': 'share'}
        self.drv.delete_share(self.ctx, share)
        url = 'storage/pools/%(pool)s/filesystems/%(fs)s' % {
            'pool': self.pool_name,
            'fs': PATH_DELIMITER.join([self.fs_prefix, share['name']])
        }
        url += '?snapshots=true'
        self.drv.nef.delete.assert_called_with(url)

    @patch(PATH_TO_RPC)
    def test_extend_share(self, m):
        share = {'name': 'share'}
        new_size = 1
        self.drv.extend_share(share, new_size)
        quota = new_size * units.Gi
        data = {
            'reservationSize': quota
        }
        url = 'storage/pools/{}/filesystems/{}%2F{}'.format(
            self.pool_name, self.fs_prefix, share['name'])
        self.drv.nef.post.assert_called_with(url, data)

    @patch(PATH_TO_RPC)
    def test_shrink_share(self, m):
        share = {'name': 'share'}
        new_size = 5
        self.drv.extend_share(share, new_size)
        quota = new_size * units.Gi
        data = {
            'reservationSize': quota
        }
        url = 'storage/pools/{}/filesystems/{}%2F{}'.format(
            self.pool_name, self.fs_prefix, share['name'])
        self.drv.nef.post.assert_called_with(url, data)

    @patch(PATH_TO_RPC)
    def test_create_snapshot(self, m):
        snapshot = {'share_name': 'share', 'name': 'share@first'}
        self.drv.create_snapshot(self.ctx, snapshot)
        url = 'storage/pools/%(pool)s/filesystems/%(fs)s/snapshots' % {
            'pool': self.pool_name,
            'fs': PATH_DELIMITER.join([self.fs_prefix, snapshot['share_name']])
        }
        data = {'name': snapshot['name']}
        self.drv.nef.post.assert_called_with(url, data)

    @patch(PATH_TO_RPC)
    def test_delete_snapshot(self, m):
        snapshot = {'share_name': 'share', 'name': 'share@first'}
        self.drv.delete_snapshot(self.ctx, snapshot)
        url = ('storage/pools/%(pool)s/'
               'filesystems/%(fs)s/snapshots/%(snap)s') % {
            'pool': self.pool_name,
            'fs': PATH_DELIMITER.join(
                [self.fs_prefix, snapshot['share_name']]),
            'snap': snapshot['name']
        }
        self.drv.nef.delete.assert_called_with(url)

    def build_access_security_context(self, level, ip, mask=None):
        ls = [{"allow": True, "etype": "network", "entity": ip}]
        if mask is not None:
            ls[0]['mask'] = mask
        new_sc = {
            "securityModes": ["sys"],
        }
        if level == 'rw':
            new_sc['readWriteList'] = ls
        elif level == 'ro':
            new_sc['readOnlyList'] = ls
        else:
            raise exception.ManilaException('Wrong access level')
        return new_sc

    @patch(PATH_TO_RPC)
    def test_update_access__unsupported_access_type(self, m):
        share = {'name': 'share'}
        access = {
            'access_type': 'group',
            'access_to': 'ordinary_users',
            'access_level': 'rw'
        }
        self.assertRaises(exception.InvalidShareAccess, self.drv.update_access,
                          self.ctx, share, [access], None, None)

    @patch(PATH_TO_RPC)
    def test_update_access__cidr(self, m):
        share = {'name': 'share'}
        access = {
            'access_type': 'ip',
            'access_to': '1.1.1.1/24',
            'access_level': 'rw'
        }
        url = 'nas/nfs/' + PATH_DELIMITER.join(
            (self.pool_name, self.fs_prefix, share['name']))
        self.drv.nef.get.return_value = {}
        self.drv.update_access(self.ctx, share, [access], None, None)
        self.drv.nef.put.assert_called_with(
            url, {'securityContexts': [
                self.build_access_security_context('rw', '1.1.1.1', 24)]})

    @patch(PATH_TO_RPC)
    def test_update_access__cidr_wrong_mask(self, m):
        share = {'name': 'share'}
        access = {
            'access_type': 'ip',
            'access_to': '1.1.1.1/aa',
            'access_level': 'rw'
        }
        self.drv.nef.get.return_value = {}
        self.assertRaises(exception.InvalidInput, self.drv.update_access,
                          self.ctx, share, [access], None, None)

    @patch(PATH_TO_RPC)
    def test_update_access__one_ip_ro_add_rule_to_existing(self, m):
        share = {'name': 'share'}
        access = [{'access_type': 'ip',
                   'access_to': '5.5.5.5',
                   'access_level': 'ro'},
                  {'access_type': 'ip',
                   'access_to': '1.1.1.1/24',
                   'access_level': 'rw'}]
        url = 'nas/nfs/' + PATH_DELIMITER.join(
            (self.pool_name, self.fs_prefix, share['name']))
        sc = self.build_access_security_context('rw', '1.1.1.1', 24)
        self.drv.nef.get.return_value = {'securityContexts': [sc]}
        self.drv.update_access(self.ctx, share, access, None, None)
        self.drv.nef.put.assert_called_with(
            url, {'securityContexts': [
                sc, self.build_access_security_context('ro', '5.5.5.5')]})
