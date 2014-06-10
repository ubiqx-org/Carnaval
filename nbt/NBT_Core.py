# ============================================================================ #
#                                  NBT_Core.py
#
# Copyright:
#   Copyright (C) 2014 by Christopher R. Hertel
#
# $Id: NBT_Core.py; 2014-06-10 13:27:30 -0500; Christopher R. Hertel$
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

# Constants ------------------------------------------------------------------ #
#
#   _NBT_HEX_XLATE  - String used to convert a nibble into a hex digit
#                     character.  Used in hexbyte() and hexstr().
#                     You've seen this a million times, no?
#

_NBT_HEX_XLATE = "0123456789ABCDEF"


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
                code will generate a malformed
      message - An optional string used to explain the circumstances
                under which the exception was raised.
      value   - An optional value of any type, to be interpreted based
                upon the eCode value and the method called.  See the
                documentation for each method.
    """
    self.eCode, self.message = ( -1, None )
    if eCode in self.error_dict:
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

# Functions ------------------------------------------------------------------ #
#

def hexbyte( data=None ):
  """Convert bytes into two-character hex strings.

  Input:  data  - A string, the first byte of which will be used to
                  generate the output.  This must be readable as type
                  str.

  Output: A two-byte string representing the hex value of first byte
          of the input.  For example: '\\t' --> '09'.

  Errors: ValueError  - Raised if the input is not of type str or the
                        input string is empty.  We need at least (and
                        will use at most) one byte.

  Notes:  This function converts the input byte into a two-character
          hex string, whether or not the input byte is a printable
          character.  The output is always a two hex-digit pair, and
          never an escape sequence (e.g., never '\\t' for TAB).

  Doctest:
    >>> print "<%s>" % hexbyte( "\\b" )
    <08>
  """
  # Check for garblage.
  if not isinstance( data, str ):
    s = type( data ).__name__
    raise ValueError( "Expected a string of 1 or more bytes, got a %s." % s  )
  if len( data ) < 1:
    raise ValueError( "Cannot hexlify the empty string." )

  # Compose the two-byte hex string.
  b = ord( data[0] )
  return( _NBT_HEX_XLATE[ (b >> 4) ] + _NBT_HEX_XLATE[ (b & 0x0f) ] )


def hexstr( data=None ):
  """Convert non-printing bytes in a string of bytes to hex escapes.

  Input:  data  - The string of bytes to convert.  The input must be of
                  type str.  The empty string is acceptable.

  Output: A string in which nonprinting characters in the original
          string will be represented using '\\xXX' notation.

  Errors: ValueError  - Raised if the input is not of type str.

  Notes:  This is similar to the standard binascii.b2a_hex() function,
          except that it doesn't produce escape sequences (e.g., "\\t").

          This function operates on octet strings only.  NetBIOS does
          not understand Unicode.  Sorry.
          See:  http://blogs.msdn.com/b/larryosterman/archive/2007/07/
                11/how-do-i-compare-two-different-netbios-names.aspx

  Doctest:
    >>> print hexstr( "\\tOcelot\\nBanana" )
    \\x09Ocelot\\x0ABanana
  """
  # Check for garblage.
  if not isinstance( data, str ):
    s = type( data ).__name__
    raise ValueError( "Expected a string of bytes, got a %s." % s  )

  s = ''
  for b in [ ord( x ) for x in data ]:
    if (b < 0x20) or (b > 0x7F):
      s += "\\x" + _NBT_HEX_XLATE[ (b >> 4) ] + _NBT_HEX_XLATE[ (b & 0x0f) ]
    else:
      s += chr( b )
  return( s )


def hexdumpln( offset=0, data=None ):
  """Return a hex-dumped string representing up to 16 bytes.

  Input:  offset  - The offset within <data> at which to find the 16
                    or less bytes that are to be dumped.
          data    - The string of bytes, including the bytes to be
                    dumped.  Must be of type str.

  Errors: ValueError  - Raised if the input is not of type str.

  Output: If <data> is None, None will be returned.  If the range of
          bytes indicated by the input is empty, the empty string is
          returned.  Otherwise, the output is a string representing
          up to 16 bytes of input, in fairly traditional hexdump
          format.

  Notes:  This implementation uses a unicode-encoded hollow bullet
          to represent non-printing characters.

  Doctest:
  >>> print hexdumpln( 8, _NBT_HEX_XLATE + "Hello, Whirled" )
  000008:  38 39 41 42 43 44 45 46  48 65 6c 6c 6f 2c 20 57  |89ABCDEFHello, W|
  """
  # Reality check.
  if( data is None ):
    return( None )
  # Check for garblage.
  if not isinstance( data, str ):
    s = type( data ).__name__
    raise ValueError( "Expected a string of bytes, not a(n) %s." % s  )

  # Do the work.
  line = data[offset:][:16]
  if( not line ):
    return( "" )
  hx = ""   # String of hex digits.
  ch = ""   # Character representation.
  for c in line:
    b   = ord( c )
    hx += "%02x " % b
    ch += c if( (0x20 <= b) and (b < 0x7F) ) else u'\u25E6'
  # Pad each section.
  hx = (hx + (48 * ' '))[:48]
  ch = (ch + (16 * ' '))[:16]
  return( "%06X:  %s %s |%s|" % (offset, hx[:24], hx[24:][:24], ch) )


def hexdump( data=None ):
  """Print a hex dump so that packets can be visually inspected.

  Input:  data  - The string of bytes to to be dumped.  The input must
                  be of type str.

  Output: None; the dump is printed to stdout.

  Errors: ValueError  - Raised if the input is not of type str.

  Doctest:
  >>> hexdump( _NBT_HEX_XLATE + "Hello, Whirled" )
  000000:  30 31 32 33 34 35 36 37  38 39 41 42 43 44 45 46  |0123456789ABCDEF|
  000010:  48 65 6c 6c 6f 2c 20 57  68 69 72 6c 65 64        |Hello, Whirled  |
  """
  # This forces the sanity checks in hexdumpln() to be run.
  s = hexdumpln( 0, data )
  if( not s ):
    return
  print s
  # It's now safe to dump the rest of <data>.
  for offset in range( 16, len( data ), 16 ):
    print hexdumpln( offset, data )

# ============================================================================ #
