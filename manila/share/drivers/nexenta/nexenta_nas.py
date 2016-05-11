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
                options.nexenta_connection_opts)
            self.configuration.append_config_values(
                options.nexenta_nfs_opts)
            self.configuration.append_config_values(
                options.nexenta_dataset_opts)
            self.helper = nexenta_helper.RestHelper(self.configuration)
        else:
            raise exception.BadConfigurationException(
                _('Nexenta configuration missing.'))

    @property
    def share_backend_name(self):
        share_backend_name = None
        if self.configuration:
            share_backend_name = self.configuration.safe_get(
                'share_backend_name')
        if not share_backend_name:
            share_backend_name = 'NexentaStor4'
        return share_backend_name

    def do_setup(self, context):
        """Any initialization the nexenta nas driver does while starting."""
        LOG.debug('Setting up the plugin.')
        return self.helper.do_setup()

    def check_for_setup_error(self):
        """Returns an error if prerequisites aren't met."""
        self.helper.check_for_setup_error()

    def create_share(self, context, share, share_server=None):
        """Create a share."""
        LOG.debug('Creating share %s.' % share['name'])
        return self.helper._create_filesystem(share)

    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None):
        """Is called to create share from snapshot."""
        LOG.debug('Creating share from snapshot %s.', snapshot['name'])
        return self.helper._create_share_from_snapshot(share, snapshot)

    def delete_share(self, context, share, share_server=None):
        """Delete a share."""
        LOG.debug('Deleting share %s.' % share['name'])
        self.helper._delete_share(share['name'])

    def extend_share(self, share, new_size, share_server=None):
        """Extends a share."""
        LOG.debug('Extending share %s to %sG.' % (share['name'], new_size))
        self.helper._set_quota(share['name'], new_size)

    def create_snapshot(self, context, snapshot, share_server=None):
        """Create a snapshot."""
        LOG.debug('Creating a snapshot of share %s.' % snapshot['share_name'])
        snap_id = self.helper._create_snapshot(
            snapshot['share_name'], snapshot['name'])
        LOG.info(_LI('Created snapshot %s.'), snap_id)

    def delete_snapshot(self, context, snapshot, share_server=None):
        """Delete a snapshot."""
        LOG.debug('Deleting snapshot %s@%s.' % (
            snapshot['share_name'], snapshot['name']))
        self.helper._delete_snapshot(snapshot['share_name'], snapshot['name'])

    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        """Update access rules for given share.

        :param context: The `context.RequestContext` object for the request
        :param share: Share that will have its access rules updated.
        :param access_rules: All access rules for given share. This list
        is enough to update the access rules for given share.
        :param add_rules: Empty List or List of access rules which should be
        added. access_rules already contains these rules. Not used by this
        driver.
        :param delete_rules: Empty List or List of access rules which should be
        removed. access_rules doesn't contain these rules. Not used by
        this driver.
        :param share_server: Data structure with share server information.
        Not used by this driver.
        """
        self.helper._update_access(share['name'], access_rules)

    def _update_share_stats(self, data=None):
        super(NexentaNasDriver, self)._update_share_stats()
        data = self.helper._update_share_stats()
        data['driver_version'] = VERSION
        data['share_backend_name'] = self.share_backend_name
        self._stats.update(data)
