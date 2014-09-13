# ============================================================================ #
#                                  SMB_Core.py
#
# Copyright:
#   Copyright (C) 2014 by Christopher R. Hertel
#
# $Id: SMB_Core.py; 2014-09-12 21:52:46 -0500; Christopher R. Hertel$
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
#   - The SMBerror class is almost identical to the NBTerror class in
#     ../nbt/NBT_Core.  It should be a fairly simple task to create a
#     base class somewhere in ../common.
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

# Classes -------------------------------------------------------------------- #
#

class SMBerror( Exception ):
  """SMB1/2/3 exceptions.

  An exception class with an associated set of error codes, defined by
  numbers (starting at 1001).  The error codes are specific to this
  exception class.

  Class Attributes:
    error_dict  - A dictionary that maps error codes to descriptive
                  names.  This dictionary defines the set of valid
                  SMBerror error codes.

  Instance Attributes:
    eCode   - The error code number that was used to raise the
              exception.
    message - A(n optional) descriptive string to help the user
              interpret a particular instance of SMBerror.
    value   - A(n optional) value of almost any type.  If <value> is
              not None, it must be convertable into a string so that
              it can be printed when the error message is displayed.
              The interpretation of this value depends upon the error
              message.

  Error Codes:
    1001  - SMB Semantic Error encountered.
    1002  - SMB Syntax Error encountered.
    1003  - SMB Protocol mismatch ("<FF>SMB" not found).
  """
  error_dict = {
    1001 : "SMB Semantic Error",
    1002 : "SMB Syntax Error",
    1003 : "SMB Protocol Mismatch"
    }

  @classmethod
  def errStr( cls, eCode=None ):
    """Return the description associated with an SMBerror error code.

    Input:  eCode - An SMBerror error code.

    Output: A string, which is the text associated with the given
            error code, or None if the error code is not defined.

    Doctest:
      >>> print SMBerror.errStr( 1002 )
      SMB Syntax Error
    """
    if( eCode ):
      eCode = int( eCode )
      if( eCode in cls.error_dict ):
        return( cls.error_dict[ eCode ] )
    return( None )

  @classmethod
  def errRange( cls ):
    """Return the minimum and maximum error code values as a tuple.

    Output: A tuple containing the minimum and maximum values of the
            SMBerror error codes that are defined.

    Notes:  Error codes should be defined in sequential order with no
            gaps, but don't take that as a promise.

    Doctest:
      >>> a, b = SMBerror.errRange()
      >>> a < b
      True
    """
    return( min( cls.error_dict ), max( cls.error_dict ) )

  def __init__( self, eCode=None, message=None, value=None ):
    """Create an SMBerror instance.

    Input:
      eCode   - An SMBerror error code.  The available error codes are
                given in the <error_dict> class attribute.  Any other
                code will generate a ValueError exception.
      message - An optional string used to explain the circumstances
                under which the exception was raised.
      value   - An optional value of any type, to be interpreted based
                upon the eCode value and the method called.  See the
                documentation for each method.

    Errors: ValueError  - Thrown if the given error code is not a
                          defined SMBerror error code.

    Doctest:
    >>> SMBerror()
    Traceback (most recent call last):
      ...
    ValueError: Unknown error code: None.
    """
    if( eCode not in self.error_dict ):
      raise ValueError( "Unknown error code: %s." % str( eCode ) )
    self.eCode   = eCode
    self.message = message
    self.value   = value

  def __str__( self ):
    """Formatted error message.

    Output:
      A string, the format of which is:
        <nnnn> ': ' <Description> ['; ' <Message>][' (' <Value> ')'] '.'
      where:
        <nnnn>        is the error code, or "????" if the error code
                      was incorrectly specified.
        <Description> is the general description assigned to the error
                      code.
        <Message>     is the (optional) instance-specific message given
                      when the exception is raised.
        <Value>       is the (optional) instance-specific value given
                      when the exception is raised.

    Doctest:
      >>> s = 'Die Flipperwaldt gersput'
      >>> print SMBerror( 1003, s )
      1003: SMB Protocol Mismatch; Die Flipperwaldt gersput.
    """
    if self.eCode in self.error_dict:
      tup  = (str( self.eCode ).zfill( 4 ), self.error_dict[ self.eCode ] )
      msg  = "%s: %s" % tup
      if self.message:
        msg += ("; " + self.message)
      if self.value:
        msg += (" (%s)" % str( self.value ) )
      return( msg + '.' )
    return( "????: NBT Error; Unkown NBT exception raised." )

# ============================================================================ #
