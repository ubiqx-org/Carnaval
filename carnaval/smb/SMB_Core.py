# -*- coding: utf-8 -*-
# ============================================================================ #
#                                  SMB_Core.py
#
# Copyright:
#   Copyright (C) 2014 by Christopher R. Hertel
#
# $Id: SMB_Core.py; 2016-08-14 14:06:40 -0500; Christopher R. Hertel$
#
# ---------------------------------------------------------------------------- #
#
# Description:
#   Carnaval Toolkit: Core components.
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
# References:
#   [MS-CIFS] Microsoft Corporation, "Common Internet File System (CIFS)
#             Protocol Specification"
#             http://msdn.microsoft.com/en-us/library/ee442092.aspx
#
#   [MS-SMB]  Microsoft Corporation, "Server Message Block (SMB) Protocol
#             Specification"
#             http://msdn.microsoft.com/en-us/library/cc246231.aspx
#
#   [MS-SMB2] Microsoft Corporation, "Server Message Block (SMB) Protocol
#             Versions 2 and 3"
#             http://msdn.microsoft.com/en-us/library/cc246482.aspx
#
# ============================================================================ #
#
"""Carnaval Toolkit: Core components

Classes, functions, and other objects used throughout this SMB protocol
implementation.  Fundamental stuff.
"""

# Imports -------------------------------------------------------------------- #
#
#   time.time()         - Get the current system time.
#   ErrorCodeExceptions - Provides the CodedError() class, upon which the
#                         SMBerror class is built.
#

from time import time
from common.ErrorCodeExceptions import CodedError


# Classes -------------------------------------------------------------------- #
#

class SMBerror( CodedError ):
  """SMB2/3 exceptions.

  An exception class with an associated set of error codes, defined by
  numbers (starting at 1000).  The error codes are specific to this
  exception class.

  Class Attributes:
    error_dict  - A dictionary that maps error codes to descriptive
                  names.  This dictionary defines the set of valid
                  SMBerror error codes.

  Error Codes:
    1000  - Warning message (operation succeded with caveats).
    1001  - SMB Syntax Error encountered.
    1002  - SMB Semantic Error encountered.
    1003  - SMB Protocol mismatch ([<FF>|<FE>]+"SMB" not found).

  See Also: common.ErrorCodeExceptions.CodedError

  Doctest:
    >>> print SMBerror.errStr( 1002 )
    SMB Semantic Error
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
  # This assignment is all that's needed to create the class:
  error_dict = {
    1000 : "Warning",
    1001 : "SMB Syntax Error",
    1002 : "SMB Semantic Error",
    1003 : "SMB Protocol Mismatch"
    }

class SMB_FileTime( object ):
  """FILETIME format time value handling.

  FILETIME values are given in bozoseconds since the Windows Epoch.  The
  Windows Epoch is UTC midnight on 1-Jan-1601, and a bozosecond is equal
  to 100 nanoseconds (or 1/10th of a microsecond, or 10^-7 seconds).
  There is no "official" prefix for 10^-7, so use of the term
  "bozosecond" is on your own recognizance.

  FILETIME values are 64-bit unsigned integers, supporting a date range
  from the Windows Epoch to 28-May-60056.
  """
  # References:
  #   Implementing CIFS: The Common Internet File System
  #       Section 2.6.3.1 under "SystemTimeLow and SystemTimeHigh"
  #       http://ubiqx.org/cifs/SMB.html#SMB.6.3.1
  #   [MS-DTYP;2.3.3]
  #       Microsoft Corporation, "Windows Data Types", section 2.3.3
  #       https://msdn.microsoft.com/en-us/library/cc230324.aspx
  #   Wikipedia: 1601
  #       https://en.wikipedia.org/wiki/1601
  #   Wikipedia: NTFS
  #       https://en.wikipedia.org/wiki/NTFS
  #
  # Class Values:
  #   _EPOCH_DELTA_SECS - The number of seconds between the Windows Epoch
  #                       and the Unix/POSIX/Linux/BSD/etc. Epoch.
  _EPOCH_DELTA_SECS = 11644473600

  @classmethod
  def utcNow( cls ):
    """Return the current UTC time as a FILETIME value.

    Output: An unsigned long integer representing the current time in
            FILETIME format.
    """
    return( long( round( time(), 7 ) * 10000000 ) + cls._EPOCH_DELTA_SECS )


# Functions ------------------------------------------------------------------ #
#

def SMB_Pad8( msglen=0 ):
  """Return the number of padding octets needed for 8-octet alignment.

  Input:  msglen  - The length of the bytestream that may need to be
                    padded.  It is assumed that this bytestream starts
                    on an 8-octet boundary (otherwise, the results are
                    somewhat meaningless).

  Output: The number of octets required in order to pad to a multiple
          of 8 octets.  This, of course, will be in the range 0..7.

  Doctest:
  >>> for i in [-9, -2, 0, 3, 8, 9]:
  ...   print "%2d ==> %d" % (i, SMB_Pad8( i ))
  -9 ==> 1
  -2 ==> 2
   0 ==> 0
   3 ==> 5
   8 ==> 0
   9 ==> 7
  """
  return( (8 - (msglen % 8)) & 0x7 )    # 9% code, 91% documentation.


# ============================================================================ #
# Sean sat despondently on the edge of the Wankel rotary engine, as the
# two manicurists crafted a transistor radio using parts from a discarded
# Velociraptor.
# ============================================================================ #
