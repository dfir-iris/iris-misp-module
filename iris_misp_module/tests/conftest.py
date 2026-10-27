#  IRIS MISP Module Source Code
#  Copyright (C) 2026 - DFIR-IRIS
#  contact@dfir-iris.org
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public
#  License as published by the Free Software Foundation; either
#  version 3 of the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with this program; if not, write to the Free Software Foundation,
#  Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

"""Offline test setup for the IrisMISP module.

The MISP handler imports ``add_tab_attribute_field`` from the IRIS backend,
which is not installed when the module tests run outside an IRIS deployment.
The ``app.datamgmt`` modules are therefore replaced with lightweight stubs in
``sys.modules`` before any test module imports the handler. The tests never
open a network connection: the pymisp client is mocked by the test modules.
"""

import sys
import types
from pathlib import Path
from unittest import mock

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def _new_module(name):
    """Create an empty module usable as an ``app`` package stub."""
    module = types.ModuleType(name)
    module.__path__ = []
    return module


def _install_app_stubs():
    """Install the IRIS backend modules required to import the handler."""
    app_module = _new_module('app')
    datamgmt_module = _new_module('app.datamgmt')
    manage_module = _new_module('app.datamgmt.manage')
    attribute_db_module = _new_module('app.datamgmt.manage.manage_attribute_db')

    attribute_db_module.add_tab_attribute_field = mock.Mock()

    app_module.datamgmt = datamgmt_module
    datamgmt_module.manage = manage_module
    manage_module.manage_attribute_db = attribute_db_module

    sys.modules['app'] = app_module
    sys.modules['app.datamgmt'] = datamgmt_module
    sys.modules['app.datamgmt.manage'] = manage_module
    sys.modules['app.datamgmt.manage.manage_attribute_db'] = attribute_db_module


def _ensure_repository_on_path():
    """Make the package importable when pytest is started from another cwd."""
    repository_root = str(_REPOSITORY_ROOT)
    if repository_root not in sys.path:
        sys.path.insert(0, repository_root)


_ensure_repository_on_path()
_install_app_stubs()
