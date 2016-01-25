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

import urllib2 as urlreq
import json
import jsonrpc

import urlparse
import base64
from xml.etree import ElementTree as ET
from oslo_log import log
from oslo_serialization import jsonutils
from oslo_utils import units
from manila import exception
from manila.i18n import _, _LE, _LW
from manila.share.drivers.Nexenta_Wipro import constants
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
        self.shares = {}
        self.share2nms = ''
        self.shareinfo = {}

    def _read_xml(self):
        """Open xml file and parse the content."""
        # default='/etc/manila/manila_nexenta_conf.xml',
        filename = self.configuration.manila_nexenta_conf_file
        print "NEXENTA_WIPRO:- conf filename", filename
        try:
            tree = ET.parse(filename)
            root = tree.getroot()
        except Exception as err:
            LOG.error(_LE('Read Nexenta config file(%(filename)s)'
                          ' for Manila error: %(err)s') %
                      {'filename': filename,
                       'err': err})
            raise err
        return root

    def _check_conf_file(self):
        """Check the config file, make sure the essential items are set """
        root = self._read_xml()

        # <RestURL>http://10.141.67.41:8457/rest/nms</RestURL>
        resturl = root.findtext('Storage/RestURL')
        print"NEXENTA_WIPRO: resturl", resturl

        # <Product>NEXENTASTOR</Product>
        product = root.findtext('Storage/Product')
        print"NEXENTA_WIPRO: product", product

        # VOL_52 - Volume Name
        # pool_node = root.findall('Filesystem/StoragePool')
        pool_node = root.findtext('Filesystem/StoragePool')
        print"NEXENTA_WIPRO: pool_node", pool_node

        if product != "NEXENTASTOR":
            err_msg = (_(
                '_check_conf_file: Config file invalid. '
                'Product must be set to NEXENTASTOR.'))
            LOG.error(err_msg)
            raise exception.InvalidInput(err_msg)

        if (not resturl):
            err_msg = (_(
                '_check_conf_file: Config file invalid. RestURL '
                'must be set'))
            LOG.error(err_msg)
            raise exception.InvalidInput(err_msg)

        if (not pool_node):
            err_msg = (_(
                '_check_conf_file: Config file invalid. '
                'StoragePool must be set.'))
            LOG.error(err_msg)
            raise exception.InvalidInput(err_msg)

    def _check_service(self):
        # NEXENTA_WIPRO: Assume that Service is running for now.
        print "NOT IMPLEMENETED"
        # NEXENTA_WIPRO: TODO : To be completed.
        # running_status = self._get_cifs_service_status()
        # if running_status != constants.STATUS_SERVICE_RUNNING:
        #    self._start_cifs_service_status()

        # service = self._get_nfs_service_status()
        # if ((service['RUNNINGSTATUS'] != constants.STATUS_SERVICE_RUNNING) or
        #    (service['SUPPORTV3'] == 'false') or
        #    (service['SUPPORTV4'] == 'false')):
        #    self._start_nfs_service_status()

    def _get_login_info(self):
        """NEXENTA_WIPRO: Get login IP from config file."""
        logininfo = {}
        filename = self.configuration.manila_nexenta_conf_file
        print"NEXENTA_WIPRO: conf filename ", filename

        tree = ET.parse(filename)
        root = tree.getroot()

        RestURL = root.findtext('Storage/RestURL')
        logininfo['RestURL'] = RestURL.strip()
        print"NEXENTA_WIPRO: rest url obtained is %s ", RestURL
        return logininfo

    def login(self):
        """Log in Nexenta array."""
        login_info = self._get_login_info()
        # url should be 'http://192.168.199.128:8457/rest/nms'
        url = login_info['RestURL']
        print"NEXENTA_WIPRO:- url is ", url

        # NEXENTA_WIPRO: First Command Get the NexentaStor Version,
        # just for testing the communication
        self.url = login_info['RestURL']
        root = self._read_xml()

        # <connection_url>http://admin:nexenta@10.141.67.41:8457</connection_url>
        nms_url = root.findtext('Filesystem/connection_url').strip()
        print"NEXENTA_WIPRO: : nms_url : ", nms_url
        # nms_url should be http://10.141.67.41:8457/rest/nms
        self.share2nms = self._get_nms_for_url(nms_url)
        nms = self.share2nms
        res = (nms.appliance.get_prop('nms_version'))
        if not (res):
            err_msg = (
                _("NEXENTA_WIPRO:_ERR: Could not login in"
                  "Nexenta Store appliance"))
            LOG.error(err_msg)
            raise exception.InvalidInput(err_msg)

        print "NEXENTA_WIPRO: res is ", res
        nms_version = res
        # <share_name>manila_folder</share_name>
        # share_name  = root.findtext('Filesystem/share_name').
        # strip().decode('unicode_escape')
        # print"NEXENTA_WIPRO:200 : share_address : ", share_address
        return nms_version

    def _get_nms_for_url(self, nms_url):

        # o = urlparse('http://www.cwi.nl:80/%7Eguido/Python.html') ->
        # NEXENTA_WIPRO: BREAK INTO 6 parts
        # ParseResult(scheme='http', netloc='www.cwi.nl:80',
        # path='/%7Eguido/Python.html',
        # params='', query='', fragment='')

        parts = urlparse.urlparse(nms_url)
        scheme = parts.scheme
        print"NEXENTA_WIPRO: scheme is ", scheme

        user = 'admin'
        password = 'nexenta'

        # NEXENTA_WIPRO: if username and password not given in url
        # http://admin:nexenta@10.141.67.41:8457
        if '@' not in parts.netloc:
            host_and_port = parts.netloc  # 10.141.67.41:8457
        else:
            user_and_password, host_and_port = parts.netloc.split(
                '@', 1)  # admin:nexenta@10.141.67.41:8457
            if ':' in user_and_password:
                user, password = user_and_password.split(':')  # admin:nexenta
            else:
                user = user_and_password

        if ':' in host_and_port:
            host, port = host_and_port.split(':', 1)  # 10.141.67.41:8457
        else:
            host, port = host_and_port, '2000'

        # http,10.141.67.41,8457
        url = '%s://%s:%s/rest/nms/' % (scheme, host, port)
        print"NEXENTA_WIPRO: url is ", url
        # url should be http://10.141.67.41:8457/rest/nms

        return jsonrpc.NexentaJSONProxy(url, user, password)

    def _get_cifs_service_status(self):
        LOG.debug("Check CIFS Service status- NOT YET IMPLEMENED.")

    def _start_cifs_service_status(self):
        LOG.debug("Start CIFS Service - NOT YET IMPLEMENED.")

    def _find_pool_info(self):
        root = self._read_xml()
        pool_name = root.findtext('Filesystem/StoragePool').strip()
        print"NEXENTA_WIPRO: pool_name : ", pool_name

        if not pool_name:
            err_msg = (_("Invalid resource pool: %s.") % pool_name)
            LOG.error(err_msg)
            raise exception.InvalidInput(err_msg)

        nms = self.share2nms
        if not nms.volume.object_exists(pool_name):
            err_msg = (
                _("NEXENTA_WIPRO:_ERR: Volume %s does not"
                  "exist in Nexenta Store appliance") %
                pool_name)
            LOG.error(err_msg)
            raise exception.InvalidInput(err_msg)

        # Check the Available storage space on the volume.

        # TODO confirm why the free and available have "ulta pulta" values
        volume_props = nms.volume.get_child_props(pool_name, '')
        print"NEXENTA_WIPRO: volume props ", volume_props

        # Used storage space, the size of storage within the volume occupied by
        # data
        print volume_props['allocated']
        # free : Available storage space within the volume. Or, same: amount of
        # storage that can be  used
        print volume_props['free']

        allocated = utils.str2size(volume_props['allocated'])
        free = utils.str2size(volume_props['free'])

        poolinfo = {}
        poolinfo['NAME'] = pool_name
        poolinfo['ALLOCATED'] = allocated
        poolinfo['FREE_CAPACITY'] = free

        print"NEXENTA_WIPRO: poolinfo is ", poolinfo
        return poolinfo

    def _get_share_type(self, share_proto):
        share_type = None
        if share_proto == 'NFS':
            share_type = "NFSHARE"
        elif share_proto == 'CIFS':
            share_type = "CIFSHARE"
        else:
            raise exception.InvalidShare(
                reason=(_('Invalid NAS protocol supplied: %s.')
                        % share_proto))
        return share_type

    def _init_filesys_para(self, share_name, size, share_proto):
        """Init basic filesystem parameters."""
        poolinfo = self._find_pool_info()

        print("NEXENTA_WIPRO: pool free capacity in bytes is",
              poolinfo['FREE_CAPACITY'])
        print("NEXENTA_WIPRO: required size in bytes is ", size)

        if poolinfo['FREE_CAPACITY'] < size:
            err_msg = (
                _("NEXENTA_WIPRO:_ERR: Volume %s doesnt"
                  "have enough free space") %
                poolinfo['NAME'])
            LOG.error(err_msg)
            raise exception.InvalidInput(err_msg)

        # convert size to Gigabytes - a string is to be sent to nexenta.
        size = '%sG' % (size / units.Gi)

        # TODO: confirm size unit
        nexenta_folderparam = {
            "NAME": share_name.replace("-", "_"),
            "PARENT_NAME": poolinfo['NAME'],  # Volume Name
            "POOLINFO": poolinfo,
            "DESCRIPTION": "Manilla Nexenta Folder smb shared",
            "QUOTA": size,  # size in bytes
            "RECORDSIZE": '4k',
            "COMPRESSION": 'on',
            "SHARESMB": 'off',
            "SHARENFS": 'off',
            "SIZE": size,
            "SHARE_PROTO": share_proto.strip(),
        }

        if share_proto == "CIFS":
            nexenta_folderparam['SHARESMB'] = 'on'
            nexenta_folderparam['SHARENFS'] = 'off'
        elif share_proto == "NFS":
            nexenta_folderparam['SHARESMB'] = 'off'
            nexenta_folderparam['SHARENFS'] = 'on'
        else:
            print"Wrong share protocol"
            err_msg = (
                _("NEXENTA_WIPRO:_ERR: Wrong Value of share protocol"))
            LOG.error(err_msg)
            raise exception.InvalidInput(err_msg)

        print("NEXENTA_WIPRO: Check sharesmb and sharenfs option",
              nexenta_folderparam)
        return nexenta_folderparam

    def allocate_container(self, share_name, size, share_proto):
        """Creates filesystem associated to share by name."""
        print"NEXENTA_WIPRO: share_name in creation is", share_name
        # share_name in creation is share-15dee8f7-49bc-4833-8499-4116418b740d
        nexenta_folderparam = self._init_filesys_para(
            share_name, size, share_proto)
        complete_share_name = self._create_filesystem(nexenta_folderparam)
        return complete_share_name

    def _create_filesystem(self, folder_param):
        """Create file system."""
        # TODO: size and quota has to be related

        nms = self.share2nms

        if folder_param['SHARESMB'] == "on":
            create_folder_props = {'quota': folder_param['QUOTA'],
                                   'recordsize': folder_param['RECORDSIZE'],
                                   'compression': folder_param['COMPRESSION'],
                                   'sharesmb': folder_param['SHARESMB'],
                                   }
        elif (folder_param['SHARESMB'] == "off" and
              folder_param['SHARENFS'] == "on"):
            create_folder_props = {'quota': folder_param['QUOTA'],
                                   'recordsize': folder_param['RECORDSIZE'],
                                   'compression': folder_param['COMPRESSION'],
                                   'sharenfs': folder_param['SHARENFS'],
                                   }

        print "NEXENTA_WIPRO: create-folder_props are ", create_folder_props

        if not nms.folder.create_with_props(
                folder_param['PARENT_NAME'],
                folder_param['NAME'],
                create_folder_props):
            err_msg = (
                _('NEXENTA_WIPRO:_ERR: Folder %(folder) could'
                  'not be created on Volume %(volume)') % {
                    'folder': folder_param['NAME'],
                    'volume': folder_param['PARENT_NAME']})
            LOG.error(err_msg)
            raise exception.InvalidShare(reason=err_msg)

        # FOLDER IS CREATED

        if folder_param['SHARESMB'] == "on":
            fmri = 'svc:/network/smb/server:default'
        elif (folder_param['SHARESMB'] == "off" and
              folder_param['SHARENFS'] == "on"):
            fmri = 'svc:/network/nfs/server:default'
        else:
            print"Could Not set fmri"
            err_msg = (_('NEXENTA_WIPRO:_ERR: Could Not set FMRI'))
            LOG.error(err_msg)
            raise exception.InvalidInput(reason=err_msg)
        print "NEXENTA_WIPRO: fmri used is", fmri

        path = '%s/%s' % (folder_param['PARENT_NAME'].strip(),
                          folder_param['NAME'].strip())
        print "folder path is ", path

        # share_opts = {
        #            'read_write': '*',
        #            'read_only': '',
        # 'root': 'nobody',
        #            'extra_options': 'anon=0',
        #            'recursive': 'true',
        #            'anonymous_rw': 'true',
        #            }
        share_opts = {
            'Auth_Type': 'Auth_sys',
            'read_write': '*',
            'recursive': 'true',
            'anonymous_rw': 'true',
            'anonymous': 'true',
            'extra_options': 'anon=0',
        }
        LOG.debug('Sharing folder on Nexenta Store')

        print"NEXENTA_WIPRO: share opts are ", share_opts
        try:
            result = nms.netstorsvc.share_folder(fmri, path, share_opts)
        except Exception as err:
            LOG.error(
                _LE('NEXENTA_WIPRO:_ERR: Folder %(share_name)'
                    'could not be shared, error:') % {
                    'share_name': folder_param['NAME']})
            raise err

        # Get all folders that are shared using the specified storage
        # access protocol and match the specified pattern
        # Pattern to select a subset of folders.
        # An empty string matches all folders
        # Returns : List of shared folders according to specified parameters
        share_folders = []
        share_folders = nms.netstorsvc.get_shared_folders(fmri, '')
        print"list of share folders", share_folders

        complete_share_name = ''
        for index in range(len(share_folders)):
            print "shared folders is ", share_folders[index]
            print"folder_name is", path
            if folder_param['NAME'] in share_folders[index]:
                complete_share_name = share_folders[index]
                print("NEXENTA_WIPRO: Folder %s created & shared"
                      " successfully", complete_share_name)
                break

        self.shareinfo[folder_param['NAME']] = folder_param
        print "NEXENTA_WIPRO: FOLDER Completed Successfully!!"
        return complete_share_name

    def _get_location_path(self, complete_share_name, share_proto):
        root = self._read_xml()
        target_ip = root.findtext('Storage/LogicalPortIP').strip()
        print"NEXENTA_WIPRO: Target ip is %s", target_ip

        location = None
        if share_proto == 'NFS':
            # /volumes/DemoVol1/share_16a6d104_3e56_4c04_b2fc_5fa3ed3c9d5d
            # 10.141.67.225:/volumes/DemoVol1/share_16a6d104_3e56_4c04_b2fc_5fa3ed3c9d5d
            complete_share_name = complete_share_name.replace("-", "_")
            location = '%s:/volumes/%s' % (target_ip,
                                           complete_share_name)
        elif share_proto == 'CIFS':
            # CIFS location needed is
            # \\10.141.67.225\demovol1_share_712d7b3a_420a_4ebd_8e42_f97e42b712e3
            # complete share name is -
            # DemoVol1/share_712d7b3a_420a_4ebd_8e42_f97e42b712e3@ \
            # share_snapshot_f502ba94_e880_4c04_85b8_53cc5cc3e663
            complete_share_name = complete_share_name.replace("-", "_")
            complete_share_name = complete_share_name.replace("/", "_")
            print("NEXENTA_WIPRO: complete_share_name for CIFS is ",
                  complete_share_name)
            location = '\\\\%s\\%s' % (target_ip,
                                       complete_share_name)
        else:
            raise exception.InvalidShare(
                reason=(_('Invalid NAS protocol supplied: %s.')
                        % share_proto))
        print"NEXENTA_WIPRO: folder location is ", location
        return location

    # =========================================================================
    # =========================================================================
    # *****************************CREATE SHARE FUNCTIONS COMPLETE*************
    # =========================================================================
    # =========================================================================

    def _get_share_by_name(self, share_name):

        share_name = share_name.strip()  # remove white space
        share_name = share_name.replace("-", "_")
        nms = self.share2nms

        fmri = []
        fmri.append('svc:/network/smb/server:default')  # CIFS
        fmri.append('svc:/network/nfs/server:default')  # NFS

#        if share_proto.strip() == "cifs" or share_proto.strip() == "CIFS":
#            fmri = 'svc:/network/smb/server:default'
#        elif share_proto.strip() == "nfs" or share_proto.strip() == "NFS":
#            fmri = 'svc:/network/nfs/server:default'
#        else:
#            print"Could Not set fmri"
#            err_msg = (_('NEXENTA_WIPRO:_ERR207: Could Not set FMRI'))
#            LOG.error(err_msg)
#            raise exception.InvalidInput(reason=err_msg)
#        print "NEXENTA_WIPRO: fmri used is", fmri

        # Get all folders that are shared using the specified storage
        # access protocol and match the specified pattern
        # Pattern to select a subset of folders.
        # An empty string matches all folders
        # Returns : List of shared folders according to specified parameters
        share_folders = []
        for f in fmri:
            shared_folders_get = nms.netstorsvc.get_shared_folders(f, '')
            share_folders.extend(shared_folders_get)

        found = 0
        complete_share_name = ''

        for index in range(len(share_folders)):
            if share_name in share_folders[index]:
                vol_name, folder_name = share_folders[
                    index].decode("utf-8").split('/', 1)
                print("NEXENTA_WIPRO: volname and folder name is ",
                      vol_name, folder_name)
                complete_share_name = share_folders[index]
                found = 1
                break

        if found == 1:
            share_name = complete_share_name
        else:
            err_msg = (
                _("NEXENTA_WIPRO: Folder %s does not "
                  "exist in Nexenta Store appliance") %
                share_name)
            LOG.error(err_msg)
            raise exception.InvalidInput(err_msg)
            return

        if not nms.folder.object_exists(complete_share_name):
            err_msg = (
                _("NEXENTA_WIPRO: Folder %s does not"
                  "exist in Nexenta Store appliance") %
                complete_share_name)
            LOG.error(err_msg)
            raise exception.InvalidInput(err_msg)
            return

        share_props = nms.folder.get_child_props(complete_share_name, '')
        print "NEXENTA_WIPRO: folder props ", share_props
        return share_props, complete_share_name

    def _delete_share(self, share_name, share_proto):
        # called as self.helper._delete_share(share['name'],
        # share['share_proto'])
        """Delete share."""

        share_props, complete_share_name = self._get_share_by_name(
            share_name)
        print"NEXENTA_WIPRO: share_props are", share_props
        print"NEXENTA_WIPRO: share_name is are", complete_share_name

        nms = self.share2nms

        # Destroy a child object.
        try:
            result = nms.folder.destroy(complete_share_name.strip(), '')
        except Exception as err:
            LOG.error(_LE('Folder (%(folder_name))'
                          ' Could not be deleted, error: %(err)s') %
                      {'folder_name': complete_share_name,
                       'err': err})
            raise err

        return result

    # CREATE SNAPSHOT
    def _create_snapshot(self, share_name, snapshot_name):
        """Create a snapshot."""

        share_name = share_name.strip().replace("-", "_")
        snapshot_name = snapshot_name.strip()
        snapshot_name = snapshot_name.replace("-", "_")

        # share_name share_712d7b3a_420a_4ebd_8e42_f97e42b712e3
        # snapshot_name share_snapshot_f81d925c_b282_4317_9426_4059aa415de0
        print"NEXENTA_WIPRO: share_name is ", share_name
        print"NEXENTA_WIPRO: snapshot_name is ", snapshot_name

        share_props, share_name = self._get_share_by_name(
            share_name)
        print"NEXENTA_WIPRO: share_props are", share_props
        print"NEXENTA_WIPRO: share_name is are", share_name

        nms = self.share2nms

        if not nms.folder.object_exists(share_name):
            err_msg = (
                _("NEXENTA_WIPRO: Folder %s does "
                  "not exist in Nexenta Store appliance") %
                share_name)
            LOG.error(err_msg)
            raise exception.InvalidInput(err_msg)

        try:
            result = nms.folder.create_snapshot(
                share_name, snapshot_name, "-r")
        except Exception as err:
            LOG.error(_LE('Snapshot (%(snapshot_name))'
                          ' Could not be created, error: %(err)s') %
                      {'snapshot_name': snapshot_name,
                       'err': err})
            raise err

        print "NEXENTA_WIPRO: create snapshot result is ", result
        # TODO confirm what needs to return from here
        return result

    # DELETE SNAPSHOT START
    def _delete_snapshot(self, share_name, snapshot_name):
        """Deletes snapshot."""
        # NEXENTA_WIPRO: snapshot name is 11
        # share_snapshot_cddfd4e6-defb-4c84-b26c-fdd20b7605ec
        print"NEXENTA_WIPRO: snapshot name is 11", snapshot_name

        share_name = share_name.strip().replace("-", "_")
        snapshot_name = snapshot_name.strip()
        snapshot_name = snapshot_name.replace("-", "_")

        print"NEXENTA_WIPRO: share_name is are", share_name
        print"NEXENTA_WIPRO: snapshot_name is are", snapshot_name

        share_props, complete_share_name = self._get_share_by_name(
            share_name)
        print"NEXENTA_WIPRO: share_props are", share_props
        print"NEXENTA_WIPRO: share_name is are", complete_share_name
        print"NEXENTA_WIPRO: snapshot_name is are", snapshot_name

        nms = self.share2nms

        snapshot_name = complete_share_name + '@' + snapshot_name
        # DemoVol1/share_712d7b3a_420a_4ebd_8e42_f97e42b712e3@share_snapshot_f502ba94_e880_4c04_85b8_53cc5cc3e663
        print"NEXENTA_WIPRO: complete snapshot_name is ", snapshot_name

        if not nms.snapshot.object_exists(snapshot_name):
            err_msg = (
                _("NEXENTA_WIPRO: Snapshot %s does not"
                  "exist in Nexenta Store appliance") %
                snapshot_name)
            LOG.error(err_msg)
            raise exception.InvalidInput(err_msg)

        try:
            result = nms.snapshot.destroy(snapshot_name, '')
        except Exception as err:
            LOG.error(_LE('Snapshot (%(snapshot_name))'
                          ' Could not be destroyed, error: %(err)s') %
                      {'snaoshot_name': snapshot_name,
                       'err': err})
            raise err

        print "NEXENTA_WIPRO: delete snapshot result is ", result
        # TODO confirm what needs to return from here
        return result

    def _allow_access(self, share_name, access, share_proto):
        """Allow access to the share."""
        print"NEXENTA_WIPRO: Changing ACL for share ", share_name
        share_props, complete_share_name = self._get_share_by_name(
            share_name)
        print"NEXENTA_WIPRO: share_props are", share_props
        print"NEXENTA_WIPRO: share_name is are", complete_share_name

        nms = self.share2nms

        print"NEXENTA_WIPRO: access data obtained is ", access
        access_type = access['access_type'].strip()
        print"NEXENTA_WIPRO: access type obtained is ", access_type

        if access_type != "user" and access_type != "group":
            err_msg = (
                _("NEXENTA_WIPRO: access type  %s is "
                  "not allowed in Nexenta Store appliance") %
                access_type)
            LOG.error(err_msg)
            raise exception.InvalidInput(err_msg)

        access_to = access['access_to'].strip()
        print"NEXENTA_WIPRO: access is to be given to ", access_to

        access_level = access['access_level'].strip()
        print"NEXENTA_WIPRO: access level is to be given to ", access_level

        # list_directory, read_data, add_file, write_data, add_subdirectory,
        # append_data, read_xattr, write_xattr, execute, delete_child,
        # read_attributes, write_attributes, read_acl, write_acl,
        # write_owner, synchronize
        if access_level == "rw":
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
        elif access_level == "ro":
            permission_arr = {'allow': ['list_directory',
                                        'read_data',
                                        'read_xattr',
                                        'read_attributes',
                                        'read_acl',
                                        ]
                              }
        else:
            err_msg = _("NEXENTA_WIPRO: access level  %s \
                         is not allowed in Nexenta Store appliance") \
                % access_level
            LOG.error(err_msg)
            raise exception.InvalidInput(err_msg)

        # set_user_acl('vol1/a', 'mikec', { 'allow' => ['read_data'], 'deny' =>
        # ['write_data'] } )
        try:
            result = nms.folder.set_user_acl(
                complete_share_name, access_to, permission_arr)
        except Exception as err:
            LOG.error(_LE('User ACL for user (%(user_name))'
                          ' Could not be set, error: %(err)s') %
                      {'user_name': access_to,
                       'err': err})
            raise err
        print "NEXENTA_WIPRO: ACL set for user"
        return result

    def _deny_access(self, share_name, access, share_proto):
        """Deny access to share."""
        print"NEXENTA_WIPRO: DENY ACL for share ", share_name
        share_props, complete_share_name = self._get_share_by_name(
            share_name)
        print"NEXENTA_WIPRO: share_props are", share_props
        print"NEXENTA_WIPRO: share_name is are", complete_share_name

        nms = self.share2nms
        print"NEXENTA_WIPRO: access data obtained is ", access
        access_type = access['access_type'].strip()
        print"NEXENTA_WIPRO: access type obtained is ", access_type

        if access_type != "user" and access_type != "group":
            err_msg = (
                (_("NEXENTA_WIPRO: access type  %s is",
                   "not allowed in Nexenta Store appliance")) %
                access_type)
            LOG.error(err_msg)
            raise exception.InvalidInput(err_msg)

        access_to = access['access_to'].strip()
        print"NEXENTA_WIPRO: access is to be given to ", access_to

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
                                    ]}

        try:
            result = nms.folder.set_user_acl(
                complete_share_name,
                access_to,
                permission_arr)
        except Exception as err:
            LOG.error(_LE('User ACL for user (%(user_name))'
                          ' Could not be set, error: %(err)s') %
                      {'user_name': access_to,
                       'err': err})
            raise err
        print "NEXENTA_WIPRO: ACL denied for user"
        return result
