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

from oslo_utils import units

from manila import utils


def str2gib_size(s):
    """Covert size-string to size in gigabytes."""
    size_in_bytes = utils.translate_string_size_to_float(s)
    return size_in_bytes // units.Gi


def bytes_to_gb(size):
    return int(size) / (1024 * 1024 * 1024)
