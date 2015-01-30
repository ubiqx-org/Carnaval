# ============================================================================ #
#                             NBT_SessionService.py
#
# Copyright:
#   Copyright (C) 2014 by Christopher R. Hertel
#
# $Id: NBT_SessionService.py; 2015-01-29 21:23:17 -0600; Christopher R. Hertel$
#
# ---------------------------------------------------------------------------- #
#
# Description:
#   NetBIOS over TCP/IP (IETF STD19) implementation: NBT Session Service.
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
#   - A subset of the NBT Session Service is maintained as an artifact in
#     SMB Naked TCP transport (what Microsoft calls "TCP Direct") over
#     port 445.  Specifically, Naked TCP transport uses a four-byte header
#     per-message to identify the length of the following message.  The
#     difference is that in NBT 17 bits are used for the length, whereas
#     24 bits are available (until/unless Microsoft changes the rules) in
#     naked TCP.
#
# ToDo:
#
#   - Write a genereric dump() function that parses an array of 4 bytes (or
#     allows for 10 in the case of the Redirect Response) and pretty-prints
#     the parsed output.
#
#   - More doctests?
#
# ============================================================================ #
#
"""NetBIOS over TCP/UDP (NBT) protocol: Session Service

NBT is defined in IETF RFCs 1001 and 1002, collectively known as IETF
Standard 19 (STD19).  A detailed implementer's guide to NBT can be found
on the web at:
  http://www.ubiqx.org/cifs/NetBIOS.html#NBT.6

The NBT Session Service is probably the simplest aspect of the NBT
transport suite.  It consists of only six possible messages, half of which
fit compactly in only 4 bytes:

    * Session Message
    * Session Request
    * Positive Session Response
    * Negative Session Response
    * Retarget Session Response
    * Session Keepalive

The Session Message is a header used to identify the length of a subsequent
message (e.g., an SMB message, though NBT can be a transport for lots of
things).  The remaining messages are complete unto themselves and interact
only minimally with next layer protocols (such as SMB).

The NBT Session Service is simple enough that it is implemented here as a
set of functions, not classes.  In some cases, the functions just retrn a
constant value.

CONSTANTS:

  Protocol Details:
    SS_PORT = 139   : The default NBT Session Service TCP listener port.

  Message Types:
    SS_SESSION_MESSAGE    : A four-byte header indicating the length, in
                            bytes, of the message (belonging to another
                            protocol) that follows.
    SS_SESSION_REQUEST    : Sent from the client (calling node) to a
                            server (called node) over an existing TCP
                            session to request the start of a NetBIOS
                            session.
    SS_POSITIVE_RESPONSE  : Response from the called node back to the
                            calling node to indicate that a Session
                            Request was granted.
    SS_NEGATIVE_RESPONSE  : Indicates that a Session Request was denied.
    SS_RETARGET_RESPONSE  : A rarely-used message that instructs the
                            to retry the connection using a new IP
                            address and/or port number.
    SS_SESSION_KEEPALIVE  : The pig in the pipeline.

  Error codes:
    SS_ERR_NOT_LISTENING  : Not Listening On Called Name
                            The name is registered, but no application
                            or service is listening for session
                            connection requests on that name.
    SS_ERR_NOT_ANSWERING  : Not Listening For Calling Name
                            The name is registered, and the service is
                            listening for connections, but it doesn't
                            want to talk to you.  It is probably
                            expecting a call from some other node.
    SS_ERR_NOT_PRESENT    : Called Name Not Present
                            The remote node has not even registered the
                            CALLED NAME.
    SS_ERR_INSUFFICIENT   : Insufficient Resources
                            The remote node is busy and cannot take your
                            call at this time.
    SS_ERR_UNSPECIFIED    : Unspecified Error
                            Something is wrong on the far end, but we
                            are not quite sure what the problem is.
"""

# Imports -------------------------------------------------------------------- #
#
#   struct          - Binary data packing and parsing tools.
#   NBT_Core        - Objects common to all NBT transport services.
#   common.HexDump  - Output formatting functions.
#

import struct       # Binary data handling.

from NBT_Core       import NBTerror # NBT exception class.
from common.HexDump import hexstr   # Hexify binary values.


# Constants ------------------------------------------------------------------ #
#

# Protocol Details
SS_PORT = 139         # The default NBT Session Service TCP listener port.

# Message Types
SS_SESSION_MESSAGE    = 0x00  # Payload follows.
SS_SESSION_REQUEST    = 0x81  # Request creation of a NetBIOS session.
SS_POSITIVE_RESPONSE  = 0x82  # NetBIOS session accepted.
SS_NEGATIVE_RESPONSE  = 0x83  # NetBIOS session denied.
SS_RETARGET_RESPONSE  = 0x84  # NetBIOS session redirected.
SS_SESSION_KEEPALIVE  = 0x85  # NBT session keep-alive.

# Error Codes
SS_ERR_NOT_LISTENING  = 0x80  # Not Listening _On Called_ Name
SS_ERR_NOT_ANSWERING  = 0x81  # Not Listening _For Calling_ Name
SS_ERR_NOT_PRESENT    = 0x82  # Called Name Not Present
SS_ERR_INSUFFICIENT   = 0x83  # Insufficient Resources
SS_ERR_UNSPECIFIED    = 0x8F  # Unspecified Error


# Globals -------------------------------------------------------------------- #
#
#   _formatLong   - Convert an integer value (assumed to be unsigned) to/from
#                   four octets in network byte order.  This is primarily
#                   used for [en|de]coding the length field of a Session
#                   Message.
#   _formatIPPort - Convert an IPv4 address (expressed as a string of octets)
#                   and a port number (as a unsigned short) into a six-byte
#                   string of octets.  ...and back again.
#

_formatLong   = struct.Struct( "!L" )
_formatIPPort = struct.Struct( "!4sH" )


# Functions ------------------------------------------------------------------ #
#

def _L1Okay( name ):
  # Ensure that we have a correctly encoded NBT name.
  if( (34 != len( name )) or ('\x20' != name[0]) or ('\0' != name[33]) ):
    return( False )
  return( all( c in "ABCDEFGHIJKLMNOP" for c in name[1:33] ) )

def SessionMessage( mLen ):
  """Create the four-byte message frame of a session message.

  Input:  mLen  - The length, in bytes, of the message to be transmitted.

  Errors: AssertionError  - Raised if the length exceeds the 17-bit
                            maximum value imposed by NBT.

  Output: <mLen> formatted as four bytes in network byte order.

  Doctest:
    >>> print ParseMsg( SessionMessage( 1978 ) )
    (0, 1978)
  """
  assert( mLen < 0x20000 ), \
    "Session Message length exceeds the 17-bit maximum imposed by NBT."
  return( _formatLong.pack( mLen & 0x0001FFFF ) )

def SessionRequest( CalledName, CallingName ):
  """Create an NBT Session Service Session Request message.

  Input:
    CalledName  - The name of the NBT service to which the message is
                  addressed.  There may be several named NBT services
                  listening on a given server.
    CallingName - The name of the NBT service or application that is
                  sending the session request.

  Errors: ValueError  - Thrown if either of the input paramaters does
                        not match the required format.  See the Notes.

  Output: A byte string.  The first four bytes are always
          [0x81, 0, 0, 0x44].  The remaining 68 bytes are the Called and
          Calling names provided.  The total length of the output will
          always be 72 bytes.

  Notes:  This function is mostly a set of sanity checks.

          The input parameters must each be L2-encoded NBT names *without
          NBT scope*.  This is an odditiy of the session service.  The NBT
          scope must not be used.  The resulting encoded name will always
          be 34 bytes in length.  The first byte will always be 0x20 and
          the last byte will always be 0x00.

  Doctest:
    >>> called = ' EHEPFCEHEPEOFKEPEMEBCACACACACACA\\x00'
    >>> calling = ' EMEJENECFFFCEHEFFCFKCACACACACACA\\x00'
    >>> req = SessionRequest( called, calling )
    >>> print "0x%02X" % ParseMsg( req )
    0x81
    >>> print "Called.: [%s]\\nCalling: [%s]" % ParseCNames( req[4:] )
    Called.: [ EHEPFCEHEPEOFKEPEMEBCACACACACACA\0]
    Calling: [ EMEJENECFFFCEHEFFCFKCACACACACACA\0]
  """
  # Check both names.
  if( not _L1Okay( CalledName ) ):
    raise ValueError( "Malformed Called Name: %s." % hexstr( CalledName ) )
  if( not _L1Okay( CallingName ) ):
    raise ValueError( "Malformed Calling Name: %s." % hexstr( CallingName ) )
  # Return the composed message.
  return( "\x81\0\0\x44" + CalledName + CallingName )

def PositiveResponse():
  """Return a Positive Session Response message.

  Output: Always "\\x82\\0\\0\\0".
          Think of this function as a "getter".

  Doctest:
    >>> print "0x%02X" % ParseMsg( PositiveResponse() )[0]
    0x82
  """
  return( "\x82\0\0\0" )

def NegativeResponse( errCode=0 ):
  """Return a Negative Session Response message.

  Input:  errCode - The NBT Session Service error code to be sent.

  Output: The first four bytes are always "\\x83\\0\\0\\0x01".
          The fifth byte is the <errCode> value being sent.

  Doctest:
    >>> nr = NegativeResponse( SS_ERR_UNSPECIFIED )
    >>> print hexstr( nr )
    \\x83\\x00\\x00\\x01\\x8F
    >>> print "0x%02X" % ParseErrCode( nr[4] )
    0x8F
  """
  assert( errCode in [ 0x80, 0x81, 0x82, 0x83, 0x8F ] ), \
      "Invalid error code 0x%02X" % errCode
  return( "\x83\0\0\x01" + chr( errCode )  )

def RetargetResponse( rdrIP=None, rdrPort=0 ):
  """Create a Retarget Response message.

  Input:
    rdrIP   - The IPv4 address of the server to which the client is
              being redirected, given as a four byte string (type
              <str>).  See the notes, below.
    rdrPort - The port number to which the client is being redirected,
              given as an integer.  This value will be silently
              truncated to a 16-bit unsigned value.

  Output: A composed Retarget Response message.

  Notes:  Client implementations generally ignore Retarget Response
          messages, which is a pity.  Per the RFCs, upon receiving one of
          these, the client is supposed to close the current TCP session
          and retry using the IP address and port number provided.  There
          are, of course, some really bad things that can happen (think of
          two servers that point to one another), so a client that
          respects the Retarget Response will also need to have some
          safeguards.

  Doctest:
    >>> ip = chr( 172 ) + chr( 23 ) + chr( 255 ) + chr( 12 )
    >>> rr = RetargetResponse( ip, 8139 )
    >>> print hexstr( rr )
    \\x84\\x00\\x00\\x06\\xAC\\x17\\xFF\\x0C\\x1F\\xCB
    >>> print ParseRetarget( rr[4:] )
    ('\\xac\\x17\\xff\\x0c', 8139)
  """
  ip   = (rdrIP[:4] if( rdrIP ) else (4 * '\0'))
  port = (rdrPort & 0xFFFF)
  return( "\x84\0\0\x06" + _formatIPPort.pack( ip, port ) )

def Keepalive():
  """Return a Session Keepalive message.

  Output: Always "\\x85\\0\\0\\0".

  Doctest:
    >>> ka = Keepalive()
    >>> print hexstr( ka )
    \\x85\\x00\\x00\\x00
    >>> print "0x%02X" % ParseMsg( ka )
    0x85
  """
  return( "\x85\0\0\0" )

def ParseMsg( msg=None ):
  """Parse the leading 4 bytes of a Session Service message.

  Input:  msg - At least 4 bytes, received from the wire.

  Errors: NBTerror( 1002 )  - Session message length exceeds maximum.
          NBTerror( 1005 )  - Invalid session service message type.
          ValueError        - Missing or incomplete message.  Four bytes
                              are expected.

  Output: A tuple.
          The first element of the tuple will be the message type. If the
          message type is SS_SESSION_MESSAGE, then there will be a second
          element, which is the length of the message that follows.  In
          all other cases, there will be no additional elements in the
          tuple.

  Notes:  By returning a tuple, we hope to make it easy to handle the
          return value in a simple and consistent way.

          This function parses exactly 4 bytes.  Additional parsing is
          required if the return value is one of the following:
          * (SS_SESSION_REQUEST,)
            ParseCNames() should be called to retrieve the Called and
            Calling names.
          * (SS_NEGATIVE_RESPONSE,)
            ParseErrCode() should be called to retrive the error code.
          * (SS_RETARGET_RESPONSE,)
            ParseRetarget() should be called to read the IPv4 address
            and port number.
  """
  if( (msg is None) or (len(msg) < 4) ):
    raise ValueError( "Missing or short message." )

  mType = ord( msg[0] )
  if( mType in [SS_SESSION_KEEPALIVE, SS_SESSION_REQUEST, SS_POSITIVE_RESPONSE,
                SS_NEGATIVE_RESPONSE, SS_RETARGET_RESPONSE] ):
    return( (mType,) )
  elif( SS_SESSION_MESSAGE == mType ):
    mLen = _formatLong.unpack( msg[:4] )[0]
    if( 0x20000 <= mLen ):
      s = "Session Message length exceeds the 17-bit maximum imposed by NBT %d."
      raise NBTerror( 1002, s, mLen )
    return( (SS_SESSION_MESSAGE, mLen) )

  raise NBTerror( 1005, "Unknown Session Service message code", mType )

def ParseCNames( msg=None ):
  """Return the Session Request Called and Calling names.

  Input:  msg - A byte string, at least 68 bytes in length.  This must
                be the 68 bytes immediately following the 4 bytes of the
                message header.

  Errors: NBTerror( 1001 )  - Thrown if either the called or calling name
                              is not a valid NBT name.
          ValueError        - Missing or incomplete message.  Sixty-eight
                              bytes are expected.

  Output: A tuple, containing the called and calling names (in that
          order).
  """
  if( (not msg) or (len( msg ) < 68) ):
    raise ValueError( "Missing or short message." )
  called = msg[:34]
  if( not _L1Okay( called ) ):
    raise NBTerror( 1001, "Malformed Called name in Session Request" )
  calling = msg[34:68]
  if( not _L1Okay( calling ) ):
    raise NBTerror( 1001, "Malformed Calling name in Session Request" )
  return( (called, calling) )

def ParseErrCode( msg=None ):
  """Retrieve the (one byte) error code from input stream.

  Input:  msg - A byte string containing at least one byte.  This must be
                the byte immediately following the four bytes of the
                message header.

  Errors: NBTerror( 1005 )  - The error code was parsed, but not
                              recognized as a valid error code.
          ValueError        - The input did not contain the minimum
                              single byte.

  Output: The Session Service error code (as an integer).  This will
          be one of the SS_ERR_* error code values.
  """
  if( not msg ):
    raise ValueError( "Missing or short message." )
  errCode = ord( msg[0] )
  if( errCode not in [ 0x80, 0x81, 0x82, 0x83, 0x8F ] ):
    raise NBTerror( 1005, "Unknown error code in Negative Session Response" )
  return( errCode )

def ParseRetarget( msg=None ):
  """Retrieve the redirection IPv4 address and port number.

  Input:  msg - A byte string containing at least 6 bytes.  This
                must be the six bytes immediately following the four
                bytes of the message header.

  Errors: ValueError  - The input was less than 6 bytes in length.

  Output: A tuple containing the IPv4 address (as an byte string) and
          port to which the client is being redirected.
  """
  if( (not msg) or (len( msg ) < 6) ):
    raise ValueError( "Missing or short message." )
  return( _formatIPPort.unpack( msg[:6] ) )

# ============================================================================ #
