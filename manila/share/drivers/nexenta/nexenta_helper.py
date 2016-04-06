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

from manila import exception
from manila.i18n import _, _LI
from manila.share.drivers.nexenta import jsonrpc
from manila.share.drivers.nexenta import utils
from oslo_log import log

LOG = log.getLogger(__name__)


class RestHelper(object):

    def __init__(self, configuration):
        self.configuration = configuration
        self.url = None
        self.headers = {
            "Connection": "keep-alive",
            "Content-Type": "application/json",
            'Authorization': 'Basic %s' % 'admin:nexenta'.encode('base64')[:-1]
        }
        self.nfs_mount_point_base = (
            self.configuration.nexenta_mount_point_base)
        self.dataset_compression = (
            self.configuration.nexenta_dataset_compression)
        self.dataset_deduplication = self.configuration.nexenta_dataset_dedup
        self.nms = None
        self.nms_protocol = self.configuration.nexenta_rest_protocol
        self.nms_host = self.configuration.nexenta_host
        self.volume = self.configuration.nexenta_volume
        self.share = self.configuration.nexenta_nfs_share
        self.nms_port = self.configuration.nexenta_rest_port
        self.nms_user = self.configuration.nexenta_user
        self.nms_password = self.configuration.nexenta_password
        self.storage_protocol = 'NFS'

    def _check_service(self):
        LOG.debug('Check service is not implemented')

    @property
    def backend_name(self):
        backend_name = None
        if self.configuration:
            backend_name = self.configuration.safe_get('volume_backend_name')
        if not backend_name:
            backend_name = self.__class__.__name__
        return backend_name

    def do_setup(self):
        if self.nms_protocol == 'auto':
            protocol, auto = 'http', True
        else:
            protocol, auto = self.nms_protocol, False
        path = '/rest/nms/'
        self.nms = jsonrpc.NexentaJSONProxy(
            protocol, self.nms_host, self.nms_port, path, self.nms_user,
            self.nms_password, auto=auto)

    def check_for_setup_error(self):
        if not self.nms.volume.object_exists(self.volume):
            raise LookupError(_("Volume %s does not exist in Nexenta"
                                "Stor appliance"), self.volume)
        folder = '%s/%s' % (self.volume, self.share)
        create_folder_props = {'recordsize': '4K',
                               'quota': 'none',
                               'compression': self.dataset_compression,
                               'sharesmb': self.configuration.nexenta_smb,
                               'sharenfs': self.configuration.nexenta_nfs,
                               }
        if not self.nms.folder.object_exists(folder):
            self.nms.folder.create_with_props(
                self.volume, self.share, create_folder_props)
            path = '%s/%s' % (self.volume, self.share)
            self._share_folder(path)

    def _get_cifs_service_status(self):
        LOG.debug("Check CIFS Service status - NOT YET IMPLEMENTED.")

    def _start_cifs_service_status(self):
        LOG.debug("Start CIFS Service - NOT YET IMPLEMENTED.")

    def _create_filesystem(self, share):
        """Create file system."""
        if self.configuration.nexenta_thin_provisioning:
            quota = 'none'
        else:
            quota = '%sG' % share['size']
        create_folder_props = {'recordsize': '4K',
                               'quota': quota,
                               'reservation': quota,
                               'compression': self.dataset_compression,
                               'sharesmb': self.configuration.nexenta_smb,
                               'sharenfs': self.configuration.nexenta_nfs,
                               }

        parent_path = '%s/%s' % (self.volume, self.share)
        self.nms.folder.create_with_props(
            parent_path, share['name'], create_folder_props)

        path = self._get_share_path(share['name'])
        return self._get_location_path(path, share['share_proto'])

    def _share_folder(self, path):
        share_opts = {
            'read_write': '*',
            'read_only': '',
            'root': 'nobody',
            'extra_options': 'anon=0',
            'recursive': 'true',
            'anonymous_rw': 'true',
        }
        LOG.debug('Sharing folder on Nexenta Store')
        self.nms.netstorsvc.share_folder('svc:/network/nfs/server:default',
                                         path, share_opts)

    def _set_quota(self, share_name, new_size):
        if self.configuration.nexenta_thin_provisioning:
            quota = '%sG' % new_size
            self.nms.folder.set_child_prop(
                self._get_share_path(share_name), 'quota', quota)

    def _get_location_path(self, path, protocol):
        location = None
        if protocol == 'NFS':
            location = '%s:/volumes/%s' % (self.nms_host, path)
        else:
            raise exception.InvalidShare(
                reason=(_('Invalid NAS protocol supplied: %s.')
                        % protocol))
        return location

    def _delete_share(self, share_name, share_proto):
        """Delete share."""
        folder = self._get_share_path(share_name)
        # Destroy a child object.
        try:
            self.nms.folder.destroy(folder.strip(), '-r')
        except exception.NexentaException as exc:
            if 'does not exist' in exc.args[0]:
                LOG.info(_LI('Folder %s does not exist, it was '
                             'already deleted.'), folder)
                return
            raise

    def _get_share_path(self, share_name):
        return '%s/%s/%s' % (self.volume, self.share, share_name)

    def _get_snapshot_name(self, snapshot_name):
        return 'snapshot-%s' % snapshot_name

    def _create_snapshot(self, share_name, snapshot_name):
        """Create a snapshot."""
        folder = self._get_share_path(share_name)
        self.nms.folder.create_snapshot(folder, snapshot_name, '-r')
        return '%s@%s' % (folder, snapshot_name)

    def _delete_snapshot(self, share_name, snapshot_name):
        """Deletes snapshot."""
        try:
            self.nms.snapshot.destroy('%s@%s' % (
                self._get_share_path(share_name), snapshot_name), '')
        except exception.NexentaException as exc:
            if 'does not exist' in exc.args[0]:
                LOG.info(_LI('Snapshot %(folder)s@%(snapshot)s does not '
                             'exist, it was already deleted.'),
                         {
                             'folder': share_name,
                             'snapshot': snapshot_name,
                })
            elif 'has dependent clones' in exc.args[0]:
                LOG.info(_LI('Snapshot %(folder)s@%(snapshot)s has dependent '
                             'clones, it will be deleted later.'),
                         {
                             'folder': share_name,
                             'snapshot': snapshot_name,
                })

    def _create_share_from_snapshot(self, share, snapshot):
        snapshot_name = '%s/%s/%s@%s' % (
            self.volume, self.share, snapshot['share_name'], snapshot['name'])
        self.nms.folder.clone(
            snapshot_name,
            '%s/%s/%s' % (self.volume, self.share, share['name']))
        path = self._get_share_path(share['name'])
        self._share_folder(path)
        return self._get_location_path(path, share['share_proto'])

    def _allow_access(self, share_name, access, share_proto):
        """Allow access to the share."""
        access_to = access['access_to'].strip()
        access_type = access['access_type'].strip()

        if access_type == 'ip':
            opts = self.nms.netstorsvc.get_shareopts(
                'svc:/network/nfs/server:default',
                self._get_share_path(share_name))
            rw_list = opts['read_write']
            if rw_list and rw_list != '*':
                rw_list += '%s:' % access_to
            else:
                rw_list = '%s:' % access_to

            share_opts = {
                'auth_type': 'none',
                'read_write': rw_list,
                'recursive': 'true',
                'anonymous_rw': 'true',
                'anonymous': 'true',
                'extra_options': 'anon=0',
            }
            result = self.nms.netstorsvc.share_folder(
                'svc:/network/nfs/server:default',
                self._get_share_path(share_name), share_opts)
            return result
        raise exception.InvalidInput(
            'Unsupported access type: %s' % access_type)

    def _deny_access(self, share_name, access, share_proto):
        """Deny access to share."""
        access_type = access['access_type'].strip()
        access_to = access['access_to'].strip()
        LOG.debug('Deny access to share %s for user %s' % (
            share_name, access_type))

        if access_type == 'ip':
            opts = self.nms.netstorsvc.get_shareopts(
                'svc:/network/nfs/server:default',
                self._get_share_path(share_name))
            rw_list = opts['read_write']
            if rw_list and (access_to in rw_list):
                rw_list = rw_list.replace(('%s:' % access_to), '')
                share_opts = {
                    'Auth_Type': 'Auth_sys',
                    'read_write': rw_list,
                    'recursive': 'true',
                    'anonymous_rw': 'true',
                    'anonymous': 'true',
                    'extra_options': 'anon=0'
                }
                result = self.nms.netstorsvc.share_folder(
                    'svc:/network/nfs/server:default',
                    self._get_share_path(share_name),
                    share_opts)
                return result
            return
        raise exception.InvalidInput('Only IP-based access is allowed')

    def _get_capacity_info(self, nfs_share):
        """Calculate available space on the NFS share.

        :param nfs_share: example 172.18.194.100:/var/nfs
        """
        folder_props = self.nms.folder.get_child_props(
            '%s/%s' % (self.volume, self.share), 'used|available')
        free = utils.str2gib_size(folder_props['available'])
        allocated = utils.str2gib_size(folder_props['used'])
        return free + allocated, free, allocated

    def _update_volume_stats(self):
        total, free, allocated = self._get_capacity_info(self.share)
        return dict(
            vendor_name='Nexenta',
            storage_protocol=self.storage_protocol,
            total_capacity_gb=total,
            free_capacity_gb=free,
            reserved_percentage=self.configuration.reserved_share_percentage,
            nfs_mount_point_base=self.nfs_mount_point_base,
            thin_provisioning=self.configuration.nexenta_thin_provisioning
        )
