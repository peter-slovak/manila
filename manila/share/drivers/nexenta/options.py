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
:mod:`nexenta.options` -- Contains configuration options for Nexenta drivers.
=============================================================================

.. automodule:: nexenta.options
"""

from oslo_config import cfg

NEXENTA_CONNECTION_OPTS = [
    cfg.StrOpt('nexenta_host',
               default='',
               help='IP address of Nexenta SA'),
    cfg.IntOpt('nexenta_rest_port',
               default=8457,
               help='HTTP port to connect to Nexenta REST API server'),
    cfg.StrOpt('nexenta_rest_protocol',
               default='auto',
               choices=['http', 'https', 'auto'],
               help='Use http or https for REST connection (default auto)'),
    cfg.StrOpt('nexenta_user',
               default='admin',
               help='User name to connect to Nexenta SA'),
    cfg.StrOpt('nexenta_password',
               default='nexenta',
               help='Password to connect to Nexenta SA',
               secret=True),
    cfg.StrOpt('nexenta_volume',
               default='volume1',
               help='volume name on NexentaStor'),
    cfg.StrOpt('nexenta_nfs',
                default='on',
                help=('on if share over NFS is enabled')),
    cfg.StrOpt('nexenta_smb',
                default='off',
                help=('on if share over SMB is enabled'))
]

NEXENTA_NFS_OPTS = [
    cfg.StrOpt('nexenta_mount_point_base',
               default='$state_path/mnt',
               help='Base directory that contains NFS share mount points'),
    cfg.BoolOpt('nexenta_nms_cache_volroot',
                default=True,
                help=('If set True cache NexentaStor appliance volroot option '
                      'value.'))
]

NEXENTA_DATASET_OPTS = [
    cfg.StrOpt('nexenta_share',
               default='nfs_share',
               help='NFS share on NexentaStor'),
    cfg.StrOpt('nexenta_dataset_compression',
               default='on',
               choices=['on', 'off', 'gzip', 'gzip-1', 'gzip-2', 'gzip-3',
                        'gzip-4', 'gzip-5', 'gzip-6', 'gzip-7', 'gzip-8',
                        'gzip-9', 'lzjb', 'zle', 'lz4'],
               help='Compression value for new ZFS folders.'),
    cfg.StrOpt('nexenta_dataset_dedup',
               default='off',
               choices=['on', 'off', 'sha256', 'verify', 'sha256, verify'],
               help='Deduplication value for new ZFS folders.'),
    cfg.BoolOpt('nexenta_thin_provisioning',
                default=True,
                help=('If True shares will not be space guaranteed and '
                      'overprovisioning will be enabled.')),
]

CONF = cfg.CONF
CONF.register_opts(NEXENTA_CONNECTION_OPTS)
CONF.register_opts(NEXENTA_DATASET_OPTS)
CONF.register_opts(NEXENTA_NFS_OPTS)
