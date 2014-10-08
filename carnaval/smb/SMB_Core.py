# ============================================================================ #
#                                  SMB_Core.py
#
# Copyright:
#   Copyright (C) 2014 by Christopher R. Hertel
#
# $Id: SMB_Core.py; 2014-10-08 02:19:20 -0500; Christopher R. Hertel$
#
# ---------------------------------------------------------------------------- #
#
# Description:
#   SMB1/2/3 Network File Protocols: Core components.
#
# ---------------------------------------------------------------------------- #
#
# License:
#
#   This library is free software; you can redistribute it and/or
#   modify it under the terms of the GNU Lesser General Public
#   License as published by the Free Software Foundation; either
#   version 3.0 of the License, or (at your option) any later version.
#
#   This library is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#   Lesser General Public License for more details.
#
#   You should have received a copy of the GNU Lesser General Public License
#   along with this library.  If not, see <http://www.gnu.org/licenses/>.
#
# See Also:
#   The 0.README file included with the distribution.
#
# ---------------------------------------------------------------------------- #
#              This code was developed in participation with the
#                   Protocol Freedom Information Foundation.
#                          <www.protocolfreedom.org>
# ---------------------------------------------------------------------------- #
#
# ToDo:
#
# ============================================================================ #
#
"""SMB1/2/3 Network File Protocols: Core components

Classes, functions, and other objects used throughout this SMB protocol
implementation.  Fundamental stuff.

REFERENCES:
  [MS-CIFS] Microsoft Corporation, "Common Internet File System (CIFS)
            Protocol Specification"
            http://msdn.microsoft.com/en-us/library/ee442092.aspx

  [MS-SMB]  Microsoft Corporation, "Server Message Block (SMB) Protocol
            Specification"
            http://msdn.microsoft.com/en-us/library/cc246231.aspx

  [MS-SMB2] Microsoft Corporation, "Server Message Block (SMB) Protocol
            Versions 2 and 3",
            http://msdn.microsoft.com/en-us/library/cc246482.aspx
"""

# Imports -------------------------------------------------------------------- #
#
#   ErrorCodeExceptions - Provides the CodedError() class, upon which the
#                         SMBerror class is built.
#

from common.ErrorCodeExceptions import CodedError


# Classes -------------------------------------------------------------------- #
#

class SMBerror( CodedError ):
  """SMB1/2/3 exceptions.

  An exception class with an associated set of error codes, defined by
  numbers (starting at 1001).  The error codes are specific to this
  exception class.

  Class Attributes:
    error_dict  - A dictionary that maps error codes to descriptive
                  names.  This dictionary defines the set of valid
                  SMBerror error codes.

  Error Codes:
    1001  - SMB Semantic Error encountered.
    1002  - SMB Syntax Error encountered.
    1003  - SMB Protocol mismatch ("<FF>SMB" not found).

  See Also: common.ErrorCodeExceptions.CodedError

  Doctest:
    >>> print SMBerror.errStr( 1002 )
    SMB Syntax Error
    >>> a, b = SMBerror.errRange()
    >>> a < b
    True
    >>> SMBerror()
    Traceback (most recent call last):
      ...
    ValueError: Undefined error code: None.
    >>> s = 'Die Flipperwaldt gersput'
    >>> print SMBerror( 1003, s )
    1003: SMB Protocol Mismatch; Die Flipperwaldt gersput.
  """
  # This one assignment is all that's needed to create the class:
  error_dict = {
    1001 : "SMB Semantic Error",
    1002 : "SMB Syntax Error",
    1003 : "SMB Protocol Mismatch"
    }

# ============================================================================ #
