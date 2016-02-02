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

from oslo_log import log
from manila import exception
from manila.i18n import _, _LI
from manila.share.drivers.nexenta import jsonrpc
import utils


LOG = log.getLogger(__name__)


class RestHelper():

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
        self.share = self.configuration.nexenta_share
        self.nms_port = self.configuration.nexenta_rest_port
        self.nms_user = self.configuration.nexenta_user
        self.nms_password = self.configuration.nexenta_password
        self.storage_protocol = 'NFS'

    def _check_service(self):
        LOG.debug('Check service is not implemented')
        # TODO : To be completed.
        # running_status = self._get_cifs_service_status()
        # if running_status != constants.STATUS_SERVICE_RUNNING:
        #    self._start_cifs_service_status()

        # service = self._get_nfs_service_status()
        # if ((service['RUNNINGSTATUS'] != constants.STATUS_SERVICE_RUNNING) or
        #    (service['SUPPORTV3'] == 'false') or
        #    (service['SUPPORTV4'] == 'false')):
        #    self._start_nfs_service_status()

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
        if not self.nms.folder.object_exists(folder):
            raise LookupError(_("Folder %s does not exist in Nexenta"
                                "Stor appliance"), folder)

    def _get_cifs_service_status(self):
        LOG.debug("Check CIFS Service status - NOT YET IMPLEMENED.")

    def _start_cifs_service_status(self):
        LOG.debug("Start CIFS Service - NOT YET IMPLEMENED.")

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
        self._share_folder(path)
        return self._get_location_path(path, share['share_proto'])

    def _share_folder(self, path):
        share_opts = {
            'Auth_Type': 'Auth_sys',
            'read_write': '*',
            'recursive': 'true',
            'anonymous_rw': 'true',
            'anonymous': 'true',
            'extra_options': 'anon=0',
        }
        LOG.debug('Sharing folder on Nexenta Store')
        self.nms.netstorsvc.share_folder(
            'svc:/network/nfs/server:default', path, share_opts)        

    def _get_location_path(self, path, protocol):
        location = None
        if protocol == 'NFS':
            # /volumes/DemoVol1/share_16a6d104_3e56_4c04_b2fc_5fa3ed3c9d5d
            # 10.141.67.225:/volumes/DemoVol1/share_16a6d104_3e56_4c04_b2fc_5fa3ed3c9d5d
            # path = path.replace("-", "_")
            location = '%s:/volumes/%s' % (self.nms_host, path)
        elif protocol == 'CIFS':
            # CIFS location needed is
            # \\10.141.67.225\demovol1_share_712d7b3a_420a_4ebd_8e42_f97e42b712e3
            # complete share name is -
            # DemoVol1/share_712d7b3a_420a_4ebd_8e42_f97e42b712e3@ \
            # share_snapshot_f502ba94_e880_4c04_85b8_53cc5cc3e663
            path = path.replace("-", "_")
            path = path.replace("/", "_")
            location = '\\\\%s\\%s' % (self.nms_host, path)
        else:
            raise exception.InvalidShare(
                reason=(_('Invalid NAS protocol supplied: %s.')
                        % protocol))
        return location

        # fmri.append('svc:/network/smb/server:default')  # CIFS
        # fmri.append('svc:/network/nfs/server:default')  # NFS
        # nms.netstorsvc.get_shared_folders(f, '')

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
                return
            elif 'has dependent clones' in exc.args[0]:
                LOG.info(_LI('Snapshot %(folder)s@%(snapshot)s has dependent '
                             'clones, it will be deleted later.'),
                         {
                             'folder': share_name,
                             'snapshot': snapshot_name,
                })
                return

    def _create_share_from_snapshot(self, share, snapshot):
        snapshot_name = '%s/%s/%s@%s' % (self.volume,
            self.share, snapshot['share_name'], snapshot['name'])
        self.nms.folder.clone(snapshot_name, '%s/%s/%s' % (
            self.volume, self.share, share['name']))
        path = self._get_share_path(share['name'])
        self._share_folder(path)
        return self._get_location_path(path, share['share_proto'])

    def _allow_access(self, share_name, access, share_proto):
        """Allow access to the share."""
        LOG.debug('Access data obtained is %s', access)
        access_type = access['access_type'].strip()

        if access_type != 'user' and access_type != 'group':
            err_msg = (
                _('Access type  %s is '
                  'not allowed in Nexenta Store appliance'), access_type)
            raise exception.InvalidInput(err_msg)

        access_to = access['access_to'].strip()
        access_level = access['access_level'].strip()
        LOG.debug('Access level %s is to be given to %s', (
            access_level, access_to))

        if access_level == 'rw':
            permission_arr = {'allow': ['list_directory',
                                        'read_data',
                                        'write_data',
                                        'add_file',
                                        'add_subdirectory',
                                        'append_data',
                                        'read_xattr',
                                        'write_xattr',
                                        'execute',
                                        'delete_child',
                                        'read_attributes',
                                        'write_attributes',
                                        'delete',
                                        'read_acl',
                                        'write_acl',
                                        'write_owner',
                                        'synchronize',
                                        ]
                              }
        elif access_level == 'ro':
            permission_arr = {'allow': ['list_directory',
                                        'read_data',
                                        'read_xattr',
                                        'read_attributes',
                                        'read_acl',
                                        ]
                              }
        else:
            raise exception.InvalidInput(_(
                            'Access level  %s is not allowed in '
                            'Nexenta Store appliance'), access_level)

        result = self.nms.folder.set_user_acl(
            self._get_share_path(share_name), access_to, permission_arr)
        return result

    def _deny_access(self, share_name, access, share_proto):
        """Deny access to share."""
        LOG.debug('DENY ACL for share ', share_name)
        LOG.debug('Access data obtained is ', access)
        access_type = access['access_type'].strip()

        if access_type != 'user' and access_type != 'group':
            raise exception.InvalidInput(_(
                'Access type %s is not allowed '
                'in NexentaStore appliance'), access_type)

        access_to = access['access_to'].strip()
        permission_arr = {'deny': ['list_directory',
                                    'read_data',
                                    'write_data',
                                    'add_file',
                                    'add_subdirectory',
                                    'append_data',
                                    'read_xattr',
                                    'write_xattr',
                                    'execute',
                                    'delete_child',
                                    'read_attributes',
                                    'write_attributes',
                                    'delete',
                                    'read_acl',
                                    'write_acl',
                                    'write_owner',
                                    'synchronize',
                                    ]}

        result = self.nms.folder.set_user_acl(
            self._get_share_path(share_name), access_to, permission_arr)
        return result

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
