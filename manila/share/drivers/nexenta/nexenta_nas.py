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
from manila.share import driver
from manila.share.drivers.nexenta import nexenta_helper
from manila.share.drivers.nexenta import options


VERSION = '1.0'
LOG = log.getLogger(__name__)


class NexentaNasDriver(driver.ShareDriver):
    """Nexenta Share Driver.

    Executes commands relating to Shares.
    API version history:
        1.0 - Initial version.
    """

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
            self.helper = nexenta_helper.RestHelper(self.configuration)
        else:
            raise exception.InvalidShare(_('Nexenta configuration missing.'))

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
        LOG.debug("Do setup the plugin.")
        return self.helper.do_setup()

    def check_for_setup_error(self):
        """Returns an error if prerequisites aren't met."""
        self.helper.check_for_setup_error()
        self.helper._check_service()

    def create_share(self, context, share, share_server=None):
        """Create a share."""
        LOG.debug('Creating share: %s.' % share['name'])
        return self.helper._create_filesystem(share)

    def create_share_from_snapshot(
            self,
            context,
            share,
            snapshot,
            share_server=None):
        """Is called to create share from snapshot."""
        LOG.debug('Creating share from snapshot %s', snapshot['name'])
        return self.helper._create_share_from_snapshot(share, snapshot)

    def delete_share(self, context, share, share_server=None):
        """Delete a share."""
        LOG.debug('Deleting share: %s.' % share['name'])
        self.helper._delete_share(share['name'], share['share_proto'])

    def extend_share(self, share, new_size, share_server=None):
        """Extends a share."""
        LOG.debug('Extending share: %s to %sG.' % (share['name'], new_size))
        self.helper._set_quota(share['name'], new_size)

    def shrink_share(self, share, new_size, share_server=None):
        """Shrinks size of existing share."""
        LOG.debug('Shrinking share: %s to %sG.' % (share['name'], new_size))
        self.helper._set_quota(share['name'], new_size)

    def create_snapshot(self, context, snapshot, share_server=None):
        """Create a snapshot."""
        LOG.debug('Creating a snapshot of share: %s.' % snapshot['share_name'])

        snap_id = self.helper._create_snapshot(
            snapshot['share_name'], snapshot['name'])
        LOG.info(_LI('Created snapshot id %s.'), snap_id)

    def delete_snapshot(self, context, snapshot, share_server=None):
        """Delete a snapshot."""
        LOG.debug('Deleting a snapshot: %s.' % '@'.join(
            [snapshot['share_name'], snapshot['name']]))

        self.helper._delete_snapshot(snapshot['share_name'], snapshot['name'])
        LOG.info(_LI('Deleted snapshot %s.'), '@'.join(
            [snapshot['share_name'], snapshot['name']]))

    def allow_access(self, context, share, access, share_server=None):
        """Allow access to the share."""
        LOG.debug("Allow access.")
        self.helper._allow_access(share['name'], access, share['share_proto'])

    def deny_access(self, context, share, access, share_server=None):
        """Deny access to the share."""
        LOG.debug("Deny access.")
        self.helper._deny_access(share['name'], access, share['share_proto'])

    def _update_share_stats(self, data=None):
        super(NexentaNasDriver, self)._update_share_stats()
        data = self.helper._update_volume_stats()
        data['driver_version'] = VERSION
        self._stats.update(data)
