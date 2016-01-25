# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2015 Wipro Technologies.
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

import time

from oslo_config import cfg
from oslo_log import log
from oslo_utils import excutils
from oslo_utils import units

from manila import exception
from manila.i18n import _, _LI, _LW
from manila.share import driver
from manila.share.drivers.Nexenta_Wipro import constants
from manila.share.drivers.Nexenta_Wipro import nexenta_helper


nexenta_opts = [
    cfg.StrOpt(
        'manila_nexenta_conf_file',
        default='/etc/manila/manila_nexenta_conf.xml',
        help='This is configuration file for the Manila Nexenta driver.')]

CONF = cfg.CONF
CONF.register_opts(nexenta_opts)
LOG = log.getLogger(__name__)


class NexentaNasDriver(driver.ShareDriver):
    # class NexentaNasDriver(object):
    """Nexenta Share Driver.
    Executes commands relating to Shares.
    API version history:

        1.0 - Initial version.
    """

    def __init__(self, *args, **kwargs):
        """Do initialization."""
        LOG.debug("Nexenta_Wipro: Entered into init function.")
        super(NexentaNasDriver, self).__init__(False, *args, **kwargs)
        self.configuration = kwargs.get('configuration', None)
        if self.configuration:
            self.configuration.append_config_values(nexenta_opts)
            self.helper = nexenta_helper.RestHelper(self.configuration)
        else:
            raise exception.InvalidShare(_("Nexenta configuration missing."))

        pools = self.pools
        print"NEXENTA_WIPRO pools are", pools

    def check_for_setup_error(self):
        """Returns an error if prerequisites aren't met."""
        self.helper._check_conf_file()
        self.helper._check_service()

    def do_setup(self, context):
        """Any initialization the nexenta nas driver does while starting."""
        LOG.debug("Do setup the plugin.")
        return self.helper.login()

    def create_share(self, context, share, share_server=None):
        """Create a share."""

        LOG.debug("Create a share.")

        share_name = share['name']
        share_proto = share['share_proto']

        # size by default is in G - converting size in bytes.
        size = share['size'] * units.Gi

        print"NEXENTA_WIPRO units Gi is", units.Gi
        print"NEXENTA_WIPRO share_name %s, share_proto %s, size in bytes%s",\
            share_name, share_proto, size

        # We sleep here to ensure the newly created filesystem can be read.
        # NEXENTA_WIPRO get wait interval from xml config file-
        # <WaitInterval>3</WaitInterval>

        complete_share_name = self.helper.allocate_container(
            share_name, size, share_proto)
        location = self.helper._get_location_path(
            complete_share_name, share_proto)
        print"NEXENTA_WIPRO: location is ", location
        return location

    def create_share_from_snapshot(
            self,
            context,
            share,
            snapshot,
            share_server=None):
        """Is called to create share from snapshot."""
        LOG.debug("Create share from snapshot.")
        raise NotImplementedError()

    # delete a share
    def delete_share(self, context, share, share_server=None):
        """Delete a share."""
        print"NEXENTA_WIPRO deleting a share name and protocol ",\
            share['name'], share['share_proto']
        LOG.debug("Delete a share.")
        self.helper._delete_share(share['name'], share['share_proto'])

    def create_snapshot(self, context, snapshot, share_server=None):
        """Create a snapshot."""
        LOG.debug("Create a snapshot.")
        snap_name = snapshot['id']
        # share_proto = snapshot['share_proto']
        # share_type = self.helper._get_share_type(share_proto.strip())
        share_name = snapshot['share_name']

        # print"NEXENTA_WIPRO snap name %s share_proto %s  share_name",\
        #   snap_name, share_proto, share_name

        # NEXENTA_WIPRO snapshot name %s
        # share_snapshot_06b0463b-9bed-4fb6-8f49-0ddf560e08a3
        snapshot_name = "share_snapshot_" + snap_name
        print"NEXENTA_WIPRO snapshot name %s ", snapshot_name

        snap_id = self.helper._create_snapshot(
            share_name, snapshot_name)
        LOG.info(_LI('Created snapshot id %s.'), snap_id)

    def delete_snapshot(self, context, snapshot, share_server=None):
        """Delete a snapshot."""
        LOG.debug("Delete a snapshot.")
        snap_name = snapshot['id']
        # share_proto = snapshot['share_proto']
        share_name = snapshot['share_id']

        # print"NEXENTA_WIPRO snap name %s share_proto %s share_name",\
        #    snap_name, share_proto, share_name

        snapshot_name = "share_snapshot_" + snap_name
        print"NEXENTA_WIPRO snapshot name %s ", snapshot_name

        self.helper._delete_snapshot(share_name, snapshot_name)
        LOG.info(_LI('Deleted snapshot %s.'), snap_name)

    def ensure_share(self, context, share, share_server=None):
        """Ensure that storages are mounted and exported."""
        LOG.debug("Ensure share.")

    #  *************************************************************************
    #  *************************************************************************
    #  *********************ALLOW / DENY ACCESS ACL
    #  *************************************************************************
    #  *************************************************************************

    def allow_access(self, context, share, access, share_server=None):
        """Allow access to the share."""
        LOG.debug("Allow access.")
        self.helper._allow_access(share['name'], access, share['share_proto'])

    def deny_access(self, context, share, access, share_server=None):
        """Deny access to the share."""
        LOG.debug("Deny access.")
        self.helper._deny_access(share['name'], access, share['share_proto'])

    def get_network_allocations_number(self):
        """Get number of network interfaces to be created."""
        LOG.debug("Get network allocations number.")
        return constants.IP_ALLOCATIONS
