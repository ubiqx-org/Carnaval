# ============================================================================ #
#                                  NBT_Core.py
#
# Copyright:
#   Copyright (C) 2014 by Christopher R. Hertel
#
# $Id: NBT_Core.py; 2014-09-11 16:12:35 -0500; Christopher R. Hertel$
#
# ---------------------------------------------------------------------------- #
#
# Description:
#   NetBIOS over TCP/IP (IETF STD19) implementation: Core components.
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
# Notes:
#
#   The NBT transport protocol is a virtual LAN protocol.  It is used to
#   emulate the behavior of the old IBM PC Network and NetBIOS Frame (NBF)
#   protocol networks.  Note that NetBIOS and NetBEUI are APIs, not network
#   protocols.  NBT provides a mechanism by which the NetBIOS and NetBEUI
#   APIs can be mapped to TCP/UDP.  For more detailed information, see the
#   references given in the docstring below.
#
#   On a DOS, OS/2, or Windows platform, various transport layers are
#   available that support the NetBIOS/NetBEUI API.  Of these, NBT has
#   emerged as the most popular and most commonly used.
#
#   - The modules in the NBT suite are written to run under Python v2.7.
#     Some attempts have been made to provide compatibility with older
#     versions, but little or no testing has been done.  Patches are
#     welcome, but see the 0.Readme.txt file for notes on submissions.
#     No attempt at all has been made at Python 3 compatability.
#
#   - This module makes use of class methods, which seem to confuse a
#     lot of people (including yours truly).  This write-up was quite
#     useful:
# http://julien.danjou.info/blog/2013/guide-python-static-class-abstract-methods
#
# ============================================================================ #
#
"""NetBIOS over TCP/UDP (NBT) protocol: Core Components

Classes, functions, and other objects used throughout this NBT Transport
implementation.  Fundamental stuff.

The NBT transport protocol is made of of three services:
  NBT Name Service     - Maps NetBIOS endpoint names to IPv4 addresses.
  NBT Datagram Service - NetBIOS datagram distribution over UDP.
  NBT Session Service  - NetBIOS sessions over TCP.

NBT is defined in IETF RFCs 1001 and 1002, collectively known as IETF
Standard 19 (STD19).  A detailed implementer's guide to NBT can be
found on the web at:
  http://www.ubiqx.org/cifs/NetBIOS.html

References:
  Implementing CIFS: The Common Internet File System
    http://www.ubiqx.orc/cifs/
  RFC 1001: PROTOCOL STANDARD FOR A NetBIOS SERVICE ON A TCP/UDP
            TRANSPORT: CONCEPTS AND METHODS
    http://www.rfc-editor.org/rfc/rfc1001.txt
  RFC 1002: PROTOCOL STANDARD FOR A NetBIOS SERVICE ON A TCP/UDP
            TRANSPORT: DETAILED SPECIFICATIONS
    http://www.rfc-editor.org/rfc/rfc1002.txt
  [MS-NBTE]: NetBIOS over TCP (NBT) Extensions
    http://msdn.microsoft.com/en-us/library/dd891412.aspx
"""

# Classes -------------------------------------------------------------------- #
#

class NBTerror( Exception ):
  """NBT errors.

  A set of error codes, defined by numbers (starting with 1001)
  specific to the NBT transport implementation.

  Class Attributes:
    error_dict  - A dictionary that maps error codes to descriptive
                  names.  This dictionary defines the set of valid
                  NBTerror error codes.

  Instance Attributes:
    eCode   - The error code number that was used to raise the
              exception.
    message - A(n optional) descriptive string to help the user
              interpret a particular instance of an NBTerror.
    value   - A(n optional) value of almost any type.  If <value> is
              not None, it must be convertable into a string so that
              it can be printed when the error message is displayed.
              The interpretation of this value depends upon the error
              message.

  Error Codes:
    1001  - NBT Semantic Error encountered.
    1002  - NBT Syntax Error encountered.
    1003  - RFC883 Label String Pointer (LSP) encountered.
    1004  - An LSP was expected, but not found.
    1005  - NBT message could not be parsed.
  """
  error_dict = {
    1001 : "NBT Semantic Error",
    1002 : "NBT Syntax Error",
    1003 : "Label String Pointer",
    1004 : "No Label String Pointer",
    1005 : "Malformed Message"
    }

  @classmethod
  def errStr( cls, eCode=None ):
    """Return the description associated with an NBTerror error code.

    Input:  eCode - An NBTerror error code.

    Output: A string, which is the text associated with the given
            error code, or None if the error code is not defined.

    Doctest:
      >>> print NBTerror.errStr( 1002 )
      NBT Syntax Error
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
            NBTerror error codes that are defined.

    Notes:  Error codes should be defined in sequential order with no
            gaps, but don't take that as a promise.

    Doctest:
      >>> a, b = NBTerror.errRange()
      >>> a < b
      True
    """
    return( min( cls.error_dict ), max( cls.error_dict ) )

  def __init__( self, eCode=None, message=None, value=None ):
    """Create an NBTerror instance.

    Input:
      eCode   - An NBTerror error code.  The available error codes are
                given in the <error_dict> class attribute.  Any other
                code will generate a ValueError exception.
      message - An optional string used to explain the circumstances
                under which the exception was raised.
      value   - An optional value of any type, to be interpreted based
                upon the eCode value and the method called.  See the
                documentation for each method.

    Errors: ValueError  - Thrown if the given error code is not a
                          defined NBTerror error code.

    Doctest:
    >>> NBTerror()
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
      >>> s = 'Mein Luftkissenfahrzeug ist voller Aale'
      >>> print NBTerror( 1005, s )
      1005: Malformed Message; Mein Luftkissenfahrzeug ist voller Aale.
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


class dLinkedList( object ):
  """
  Doubly-linked list.

  A simple implementation of a doubly-linked list.

  This implementation is intentionally simple.  It is missing a few
  conveniences, such as a count of the nodes in the list, and it does
  no error checking.  Be careful.

  Instance Attributes:
    Head  - The first node in the list.
    Tail  - The last node in the list.

  If the list is empty, both <Head> and <Tail> will be None.

  Doctest:
    >>> lst = dLinkedList()
    >>> [ d for d in lst.elements() ]
    []
    >>> for i in range( 1, 6 ):
    ...   lst.insert( dLinkedList.Node( "node0"+str(i) ) )
    >>> lst.remove( lst.Head )
    >>> lst.remove( lst.Tail )
    >>> n = lst.Head.Next.Next
    >>> n.Data
    'node02'
    >>> lst.remove( n )
    >>> [ d for d in lst.elements() ]
    ['node04', 'node03']
  """
  class Node( object ):
    """A node in the doubly-linked list.

    Instance Attributes:
      Next  - The next node in the linked list, or None to indicate the
              end of the list.
      Prev  - The previous node in the linked list, or None to indicate
              that the current node is the first node in the list.
      Data  - The payload of the node.  That is, whatever it is that
              the user is storing within the node.

    Note: The attribute names all begin with an upper case letter
          because "next" is the name of a Python built-in function (see
          https://docs.python.org/2/library/functions.html#next).
    """
    def __init__( self, Data=None ):
      """Create and initialize a <dLinkedList> node.

      Input:
        Data  - Node payload; the data being stored within the linked
                list node.
      """
      self.Next = self.Prev = None
      self.Data = Data

  def __init__( self ):
    """Create and initialize a <dLinkedList> list.
    """
    self.Head = None
    self.Tail = None

  def insert( self, newNode=None, after=None ):
    """Add a <dLinkedList.Node()> object to an existing list.

    Input:
      newNode - The new <dLinkedList.Node()> object to be inserted.
      after   - An optional node, that is already included in the list,
                after which the new node is to be inserted.  If this is
                None, the new node will be inserted at the head of the
                list.
    """
    if( after ):
      newNode.Next = after.Next
      after.Next   = newNode
    else:
      newNode.Next = self.Head
      self.Head    = newNode
    newNode.Prev = after
    if( newNode.Next ):
      newNode.Next.Prev = newNode
    else:
      self.Tail = newNode

  def remove( self, oldNode ):
    """Remove a node from the list.

    Input:
      oldNode - The node to be removed from the list.
    """
    if( oldNode.Prev is None ):
      self.Head = oldNode.Next
    else:
      oldNode.Prev.Next = oldNode.Next

    if( oldNode.Next is None ):
      self.Tail = oldNode.Prev
    else:
      oldNode.Next.Prev = oldNode.Prev

  def elements( self ):
    """A generator that iterates the Data fields from within the list.
    """
    n = self.Head
    while( n is not None ):
      yield n.Data
      n = n.Next

# ============================================================================ #
