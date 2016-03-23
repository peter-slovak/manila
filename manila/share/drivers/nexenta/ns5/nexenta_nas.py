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

import netaddr
from oslo_log import log

from manila import exception
from manila.i18n import _, _LI, _LW
from manila.share import driver
from manila.share.drivers.nexenta import options
from manila.share.drivers.nexenta import utils
from manila.share.drivers.nexenta.ns5 import jsonrpc

PATH_DELIMITER = '%2F'
VERSION = '1.0'
LOG = log.getLogger(__name__)


class NexentaNasDriver(driver.ShareDriver):
    """Nexenta Share Driver.
    Executes commands relating to Shares.
    API version history:

        1.0 - Initial version.
    """

    driver_prefix = 'nexenta'

    def __init__(self, *args, **kwargs):
        """Do initialization."""
        LOG.debug('Initializing Nexenta driver.')
        super(NexentaNasDriver, self).__init__(False, *args, **kwargs)
        self.configuration = kwargs.get('configuration', None)
        if self.configuration:
            self.configuration.append_config_values(
                options.NEXENTA_CONNECTION_OPTS)
            self.configuration.append_config_values(
                options.NEXENTA_NFS_OPTS)
            self.configuration.append_config_values(
                options.NEXENTA_DATASET_OPTS)
        else:
            raise exception.InvalidShare(_('Nexenta configuration missing.'))

        self.nef = None
        self.nef_protocol = self.configuration.nexenta_rest_protocol
        self.nef_host = self.configuration.nexenta_host
        self.nef_port = self.configuration.nexenta_rest_port
        self.nef_user = self.configuration.nexenta_user
        self.nef_password = self.configuration.nexenta_password

        self.pool_name = self.configuration.nexenta_volume
        self.fs_prefix = self.configuration.nexenta_nfs_share

        self.storage_protocol = 'NFS'
        self.nfs_mount_point_base = self.configuration.nexenta_mount_point_base
        self.dataset_compression = self.configuration.nexenta_dataset_compression

    @property
    def backend_name(self):
        backend_name = None
        if self.configuration:
            backend_name = self.configuration.safe_get('share_backend_name')
        if not backend_name:
            backend_name = self.__class__.__name__
        return backend_name

    def do_setup(self, context):
        """Any initialization the nexenta nas driver does while starting."""
        if self.nef_protocol == 'auto':
            protocol, auto = 'http', True
        else:
            protocol, auto = self.nef_protocol, False
        self.nef = jsonrpc.NexentaJSONProxy(
            protocol, self.nef_host, self.nef_port, self.nef_user,
            self.nef_password, auto=auto)

    def check_for_setup_error(self):
        """Verify that the volume for our folder exists.

        :raise: :py:exc:`LookupError`
        """
        url = 'storage/pools/{}'.format(self.pool_name)
        if not self.nef.get(url):
            raise LookupError(_("Pool {} does not exist in Nexenta Store appliance").format(self.pool_name))
        url = 'storage/pools/{}/filesystems/{}'.format(self.pool_name, self.fs_prefix)
        if not self.nef.get(url):
            raise LookupError(_("filesystem {} does not exist in Nexenta Store appliance").format(self.fs_prefix))

        path = '/'.join((self.pool_name, self.fs_prefix))
        shared = False
        response = self.nef.get('nas/nfs')
        for share in response['data']:
            if share.get('filesystem') == path:
                shared = True
                break
        if not shared:
            raise LookupError(_("Dataset {} is not shared in Nexenta Store appliance").format(path))

    def create_share(self, context, share, share_server=None):
        """Create a share."""
        LOG.debug('Creating share: %s.' % share['name'])
        data = {
            'recordSize': 4 * 1024,
            'compressionMode': self.dataset_compression,
            'name': '/'.join((self.fs_prefix, share['name']))
        }
        if not self.configuration.nexenta_thin_provisioning:
            data['reservationSize'] = int(share['size']) * 1024*1024*1024

        url = 'storage/pools/{}/filesystems'.format(self.pool_name)
        self.nef.post(url, data)
        location = '{}:/{}/{}/{}'.format(self.nef_host, self.pool_name, self.fs_prefix, share['name'])

        try:
            self._add_permission(share['name'])
        except:
            try:
                url = 'storage/pools/{}/filesystems/{}'.format(
                    self.pool_name, PATH_DELIMITER.join([self.fs_prefix, share['name']]))
                self.nef.delete(url)
            except:
                LOG.warning(_LW("Cannot destroy created filesystem: %(vol)s/%(folder)s"),
                            {'vol': self.pool_name, 'folder': '/'.join([self.fs_prefix, share['name']])})
            raise
        return location

    def create_share_from_snapshot(
            self,
            context,
            share,
            snapshot,
            share_server=None):
        """Is called to create share from snapshot."""
        LOG.debug('Creating share from snapshot %s', snapshot['name'])

        #dataset_path = '%s/%s/%s' % (self.nef_pool, self.nef_fs, share['name'])
        url = ('storage/pools/%(pool)s/'
               'filesystems/%(fs)s/snapshots/%(snap)s/clone') % {
            'pool': self.pool_name,
            'fs': PATH_DELIMITER.join([self.fs_prefix, snapshot['share_name']]),
            'snap': snapshot['name']
        }
        location = '{}:/{}/{}/{}'.format(self.nef_host, self.pool_name, self.fs_prefix, share['name'])
        path = '/'.join([self.pool_name, self.fs_prefix, share['name']])
        data = {'targetPath': path}
        self.nef.post(url, data)

        url = 'storage/filesystems/{}/promote'.format(path.replace('/', PATH_DELIMITER))
        self.nef.post(url)

        try:
            self._add_permission(share['name'])
        except exception.NexentaException:
            try:
                url = ('storage/pools/%(pool)s/'
                       'filesystems/%(fs)s') % {
                    'pool': self.pool_name,
                    'fs': PATH_DELIMITER.join((self.fs_prefix, share['name']))
                }
                self.nef.delete(url)
            except exception.NexentaException:
                LOG.warning(_LW("Cannot destroy cloned filesystem: "
                                "%(vol)s/%(filesystem)s"),
                            {'vol': self.pool_name,
                            'filesystem': '/'.join((self.fs_prefix, share['name']))})
            raise

        return location

    def delete_share(self, context, share, share_server=None):
        """Delete a share."""
        LOG.debug('Deleting share: %s.' % share['name'])

        url = ('storage/pools/%(pool)s/filesystems/%(fs)s') % {
            'pool': self.pool_name,
            'fs': PATH_DELIMITER.join([self.fs_prefix, share['name']])
        }
        #origin = self.nef.get(url).get('originalSnapshot')
        url += '?snapshots=true'
        try:
            self.nef.delete(url)
        except exception.NexentaException as exc:
            if 'Failed to destroy snapshot' in exc.args[0]:
                LOG.debug('Snapshot has dependent clones, skipping')
            else:
                raise
        '''
        try:
            if origin and self._is_clone_snapshot_name(origin):
                path, snap = origin.split('@')
                pool, fs = path.split('/', 1)
                snap_url = ('storage/pools/%(pool)s/'
                            'filesystems/%(fs)s/snapshots/%(snap)s') % {
                    'pool': pool,
                    'fs': fs,
                    'snap': snap
                }
                self.nef.delete(snap_url)
        except exception.NexentaException as exc:
            if 'does not exist' in exc.args[0]:
                LOG.debug(
                    'Volume %s does not exist on appliance', '/'.join(
                        [self.nef_pool, self.nef_fs]))'''

    def extend_share(self, share, new_size, share_server=None):
        """Extends a share."""
        LOG.debug('Extending share: %s to %sG.' % (share['name'], new_size))
        self._set_quota(share['name'], new_size)

    def shrink_share(self, share, new_size, share_server=None):
        """Shrinks size of existing share."""
        LOG.debug('Shrinking share: %s to %sG.' % (share['name'], new_size))
        self._set_quota(share['name'], new_size)

    def create_snapshot(self, context, snapshot, share_server=None):
        """Create a snapshot."""
        LOG.debug('Creating a snapshot of share: %s.' % snapshot['share_name'])

        url = 'storage/pools/%(pool)s/filesystems/%(fs)s/snapshots' % {
            'pool': self.pool_name,
            'fs': PATH_DELIMITER.join([self.fs_prefix, snapshot['share_name']]),
        }
        data = {'name': snapshot['name']}
        self.nef.post(url, data)

    def delete_snapshot(self, context, snapshot, share_server=None):
        """Delete a snapshot."""
        LOG.debug('Deleting a snapshot: %s.' % '@'.join(
            [snapshot['share_name'], snapshot['name']]))

        url = ('storage/pools/%(pool)s/'
               'filesystems/%(fs)s/snapshots/%(snap)s') % {
            'pool': self.pool_name,
            'fs': PATH_DELIMITER.join([self.fs_prefix, snapshot['share_name']]),
            'snap': snapshot['name']
        }
        self.nef.delete(url)
        LOG.info(_LI('Deleted snapshot %s.'), '@'.join(
            [snapshot['share_name'], snapshot['name']]))

    def allow_access(self, context, share, access, share_server=None):
        """Allow access to the share."""
        LOG.debug("Allow access.")

        access_type = access['access_type'].strip()
        if access_type != 'ip':
            err_msg = 'Access type <{}> not allowed. Allowed type is <ip>'.format(access_type)
            raise exception.InvalidInput(err_msg)

        address_mask = access['access_to'].strip().split('/', 1)
        address = address_mask[0]
        ls = [{"allow": True, "etype": "network", "entity": address}]
        if len(address_mask) == 2:
            try:
                mask = int(address_mask[1])
                if mask != 32:
                    ls[0]['mask'] = mask
            except:
                raise exception.InvalidInput('<{}> is not a valid access parameter'.format(access['access_to']))

        url = 'nas/nfs/' + PATH_DELIMITER.join((self.pool_name, self.fs_prefix, share['name']))
        res = self.nef.get(url)

        security_contexts = res.get('securityContexts', [])

        new_sc = {
            "root": ls,
            "securityModes": ["sys"]
        }

        access_level = access['access_level'].strip()
        if access_level == 'rw':
            new_sc['readWriteList'] = ls
        elif access_level == 'ro':
            new_sc['readOnlyList'] = ls
        else:
            raise exception.InvalidInput(_(
                            'Access level %s is not allowed in '
                            'Nexenta Store appliance'), access_level)
        security_contexts.append(new_sc)
        data = {"securityContexts": security_contexts}
        self.nef.put(url, data)

    def deny_access(self, context, share, access, share_server=None):
        """Deny access to the share."""
        LOG.debug("Deny access.")

        address_mask = access['access_to'].strip().split('/')
        address = address_mask[0]
        mask = int(address_mask[1]) if len(address_mask) > 1 else None
        if mask == 32: mask = None

        url = 'nas/nfs/' + PATH_DELIMITER.join((self.pool_name, self.fs_prefix, share['name']))
        res = self.nef.get(url)
        security_contexts = res.get('securityContexts', [])
        for i in xrange(len(security_contexts)):
            address_ = security_contexts[i]['root'][0]['entity']
            mask_ = security_contexts[i]['root'][0].get('mask')
            if address == address_ and mask == mask_:
                del security_contexts[i]
                break
        data = {"securityContexts": security_contexts}
        self.nef.put(url, data)

        '''
        access_type = access['access_type'].strip()
        access_to = access['access_to'].strip()
        access_to = ':'.join((access_type, access_to))

        main_url = 'storage/pools/{pool}/filesystems/{dataset}/acl'.format(
            pool=self.nef_pool, dataset=PATH_DELIMITER.join((self.nef_fs, share['name'])))
        # Get ACL to find out ACE index we need.
        query = {'fields': 'index', 'type': 'allow', 'principal': access_to}
        data = self.nef.get("{}?{}".format(main_url, '&'.join([key + '=' + query[key] for key in query.keys()])))['data']
        # Delete all allow ACE in list for specified principal
        for ace in data:
            url = '{}/{}'.format(main_url, ace['index'])
            self.nef.delete(url)'''

    def _set_quota(self, share_name, new_size):
        if self.configuration.nexenta_thin_provisioning:
            return
        if isinstance(new_size, basestring):
            new_size = int(new_size)
        quota = new_size * 1024*1024*1024
        data = {
            #'quotaSize': quota,
            'reservationSize': quota
        }
        url = 'storage/pools/{}/filesystems/{}%2F{}'.format(self.pool_name, self.fs_prefix, share_name)
        self.nef.put(url, data)

    def _update_share_stats(self, data=None):
        super(NexentaNasDriver, self)._update_share_stats()
        share = ':/'.join([self.nef_host, self.fs_prefix])
        total, free, allocated = self._get_capacity_info(share)
        total_space = utils.str2gib_size(total)
        free_space = utils.str2gib_size(free)

        data = dict(
            vendor_name='Nexenta',
            storage_protocol=self.storage_protocol,
            total_capacity_gb=total_space,
            free_capacity_gb=free_space,
            reserved_percentage=self.configuration.reserved_share_percentage,
            nfs_mount_point_base=self.nfs_mount_point_base,
            thin_provisioning=self.configuration.nexenta_thin_provisioning,
            driver_version=VERSION
        )
        self._stats.update(data)

    def _get_capacity_info(self, path):
        """Calculate available space on the NFS share.

        :param path: example pool/nfs
        """
        url = 'storage/pools/{}/filesystems/{}'.format(self.pool_name, self.fs_prefix)
        data = self.nef.get(url)
        total = utils.str2size(data['bytesAvailable'])
        allocated = utils.str2size(data['bytesUsed'])
        free = total - allocated
        return total, free, allocated

    def _manage_share_access(self, share_name, access, type_):
        access_type = access['access_type'].strip()
        if access_type != 'ip':
            err_msg = (_('Access type %s is not allowed in Nexenta Store appliance'), access_type)
            raise exception.InvalidInput(err_msg)

        access_to = access['access_to'].strip()
        ls = [{"allow": True,
          "etype": "network",
          "entity": access_to}]
        data = {
            "securityContexts": [
                {
                    "root": ls,
                    "securityModes": ["sys"]
                }
            ]
        }

        access_level = access['access_level'].strip()
        if access_level == 'rw':
            data['securityContexts'][0]['readWriteList'] = ls
        elif access_level == 'ro':
            data['securityContexts'][0]['readOnlyList'] = ls
        else:
            raise exception.InvalidInput(_(
                            'Access level  %s is not allowed in '
                            'Nexenta Store appliance'), access_level)
        url = 'nas/nfs/' + PATH_DELIMITER.join((self.pool_name, self.fs_prefix, share_name))
        self.nef.put(url, data)

    def _add_permission(self, share_name):
        """Share NFS filesystem on NexentaStor Appliance.

        :param share_name: relative filesystem name to be shared
        """
        LOG.debug('Creating RW ACE for filesystem everyone on Nexenta Store for <%s> filesystem', share_name)
        url = 'storage/pools/{}/filesystems/{}/acl'.format(self.pool_name, PATH_DELIMITER.join((self.fs_prefix, share_name)))
        data = {
            "type": "allow",
            "principal": "everyone@",
            "permissions": [
                "list_directory",
                "read_data",
                "add_file",
                "write_data",
                "add_subdirectory",
                "append_data",
                "read_xattr",
                "write_xattr",
                "execute",
                "delete_child",
                "read_attributes",
                "write_attributes",
                "delete",
                "read_acl",
                "write_acl",
                "write_owner",
                "synchronize"
            ],
            "flags": [
                "file_inherit",
                "dir_inherit"
            ]
        }
        self.nef.post(url, data)

        LOG.debug('RW ACE for filesystem <%s> on Nexenta Store has been successfully created', share_name)