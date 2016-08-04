# ============================================================================ #
#                            ErrorCodeExceptions.py
#
# Copyright:
#   Copyright (C) 2014 by Christopher R. Hertel
#
# $Id: ErrorCodeExceptions.py; 2016-08-04 13:37:38 -0500; Christopher R. Hertel$
#
# ---------------------------------------------------------------------------- #
#
# Description:
#   Provides an interface class for creating error-code based exceptions.
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
#
# Notes:
#
#   It is expected that descendant classes will be created from the
#   CodedError class.  The only thing that needs to be done to create a new,
#   working class is to assign a dictionary to the error_dict class variable.
#   The dictionary should map error codes (integer or long values) to short
#   strings, which are typically the names associated with the errors.
#   For example:
#     { 0: 'SUCCESS',
#       1: 'ANNOYANCE',
#       2: 'DISTURBANCE',
#       3: "UTTER_FAILURE" }
#
# ============================================================================ #
#
"""Carnaval Toolkit:  Exceptions based on Error Codes.

This module provides a framework for creating exception classes that
indicate a particular error based upon an error code.
"""

# Classes -------------------------------------------------------------------- #
#

class CodedError( Exception ):
  """Error code interface class.

  This is an interface (incomplete) class that serves as a framework for
  building exception classes that are based on error codes.  Each
  descendant class is defined with its own set of error codes, which
  are mapped to descriptive names.

  Class Attributes:
    error_dict  - A dictionary that maps error codes to descriptive
                  names.  This dictionary defines the set of valid
                  error codes.

  Instance Attributes:
    eCode   - The error code number that was used to raise the
              exception.
    message - A(n optional) descriptive string to help the user
              interpret a particular instance.
    value   - A(n optional) value of almost any type.  If <value> is
              not None, it should be convertable into a string so that
              it can be printed when the error message is displayed.
              The interpretation of this value may be different for
              each class and each error code defined within the class.
  """
  error_dict = None

  @classmethod
  def errStr( cls, eCode=None ):
    """Return the description associated with the given error code.

    Input:  eCode - An error code.

    Output: A string, which is the text associated with the given
            error code, or None if the error code is not defined.

    Notes:  CodedError() descendant classes can be created simply by
            assigning a dictionary of number/string pairs to the
            <error_dict> class attribute.
    """
    if( eCode ):
      eCode = long( eCode )
      if( eCode in cls.error_dict ):
        return( cls.error_dict[ eCode ] )
    return( None )

  @classmethod
  def errRange( cls ):
    """Return the minimum and maximum error code values as a tuple.

    Output: A tuple containing the minimum and maximum values of the
            error codes that are defined.
    """
    return( min( cls.error_dict ), max( cls.error_dict ) )

  def __init__( self, eCode=None, message=None, value=None ):
    """Create a CodedError() instance.

    Input:
      eCode   - An error code.  The available error codes are defined
                within the descendant type as keys in the <error_dict>
                class attribute.  Any undefined code will generate a
                ValueError exception.
      message - An optional string used to explain the circumstances
                under which the exception was raised.
      value   - An optional value of any type, to be interpreted based
                upon the eCode value and the method called.

    Errors:
      NotImplementedError - Raised if the <error_dict> class attribute
                            is None.
      ValueError          - Raised if the given error code is not a
                            defined error code.
    """
    if( self.error_dict is None ):
      raise NotImplementedError()
    if( eCode not in self.error_dict ):
      raise ValueError( "Undefined error code: %s." % str( eCode ) )
    # ...else, we're in good shape.
    self.eCode   = eCode
    self.message = message
    self.value   = value

  def __str__( self ):
    """Formatted error message.

    Output:
      A string, the format of which is:
        <nnnn> ': ' <Name> ['; ' <Message>][' (' <Value> ')']'.'
      where:
        <nnnn>    is the error code.
        <Name>    is the descriptive name assigned to the error code.
        <Message> is the (optional) instance-specific message given
                  when the exception is raised.
        <Value>   is the (optional) instance-specific value given
                  when the exception is raised.

    Notes:  Override this method if your descendant type needs a
            different message format.
    """
    msg = str( self.eCode ).zfill( 4 ) + ': ' + self.error_dict[ self.eCode ]
    if( self.message ):
      msg += "; " + self.message
    if( self.value ):
      msg += " (%s)" % str( self.value )
    return( msg + '.' )

# ============================================================================ #
