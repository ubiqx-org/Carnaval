# ============================================================================ #
#                             NBT_SessionService.py
#
# Copyright:
#   Copyright (C) 2014 by Christopher R. Hertel
#
# $Id: NBT_SessionService.py; 2016-12-11 00:23:22 -0600; Christopher R. Hertel$
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
#   - More doctests.
#
# ============================================================================ #
#
"""NetBIOS over TCP/UDP (NBT) protocol: Session Service

NBT is defined in IETF RFCs 1001 and 1002, collectively known as IETF
Standard 19 (STD19).  A detailed implementer's guide to NBT can be found
on the web at:
  http://www.ubiqx.org/cifs/NetBIOS.html#NBT.6

The NBT Session Service is probably the simplest aspect of the NBT
transport suite.  It consists of only six possible messages, all but one
of which have a fixed length and format:

    * Session Message
    * Session Request
    * Positive Session Response
    * Negative Session Response
    * Retarget Session Response
    * Session Keepalive

The Session Message is a header used to identify the length of a subsequent
message (e.g., an SMB message, though NBT can be a transport for lots of
things).  The remaining messages are complete unto themselves and do not
interact with next layer protocols (such as SMB).

The NBT Session Service is simple.  It is implemented here as a set of
functions.  In some cases, the functions do nothing more than return a
constant value.

CONSTANTS:

  Protocol Details:
    SS_PORT = 139   : The default NBT Session Service TCP listener port.

  Message Types (single octet type codes):
    SS_SESSION_MESSAGE    : A four-byte header indicating the length, in
                            bytes, of the message (belonging to another
                            protocol) that follows.
    SS_SESSION_REQUEST    : Sent from the client (calling node) to a
                            server (called node) over an existing TCP
                            session to request the start of an NBT
                            session.
    SS_POSITIVE_RESPONSE  : Response from the called node back to the
                            calling node to indicate that a Session
                            Request was granted.
    SS_NEGATIVE_RESPONSE  : Indicates that a Session Request was denied.
                            An error code is included in the response.
    SS_RETARGET_RESPONSE  : A rarely-used message that instructs the
                            calling node to retry the connection using a
                            new IP address and/or port number.
    SS_SESSION_KEEPALIVE  : The pig in the pipeline.

  Error codes (single octet values returned in the Negative Response):
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

from NBT_Core             import NBTerror # NBT exception class.
from common.HexDump       import hexstr   # Hexify binary values.
from nbt.NBT_NameService  import Name     # Encode/decode NetBIOS names.


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
#   _msgLenDict   - Used to validate Session Service messages by mapping
#                   message types to the fixed value of their own length
#                   subfields.
#   _msgTypeDict  - A mapping from NBT Session Service message type codes to
#                   descriptive strings.
#   _errCodeDict  - A mapping from Negative Session Response error codes to
#                   descriptive strings.
#

_formatLong   = struct.Struct( "!L" )
_formatIPPort = struct.Struct( "!4sH" )

_msgLenDict   = { SS_SESSION_REQUEST  : 68,
                  SS_POSITIVE_RESPONSE: 0,
                  SS_NEGATIVE_RESPONSE: 1,
                  SS_RETARGET_RESPONSE: 6,
                  SS_SESSION_KEEPALIVE: 0 }

_msgTypeDict  = { SS_SESSION_MESSAGE  : "Session Message",
                  SS_SESSION_REQUEST  : "Session Request",
                  SS_POSITIVE_RESPONSE: "Positive Session Response",
                  SS_NEGATIVE_RESPONSE: "Negative Session Response",
                  SS_RETARGET_RESPONSE: "Retarget Session Response",
                  SS_SESSION_KEEPALIVE: "Session Keepalive" }

_errCodeDict  = { SS_ERR_NOT_LISTENING: "Not Listening on Called Name",
                  SS_ERR_NOT_ANSWERING: "Not Listening for Calling Name",
                  SS_ERR_NOT_PRESENT  : "Called Name Not Present",
                  SS_ERR_INSUFFICIENT : "Insufficient Resources",
                  SS_ERR_UNSPECIFIED  : "Unspecified Error" }


# Functions ------------------------------------------------------------------ #
#

def MsgTypeStr( mType=-1 ):
  """Given an NBT Session Service message type, return the description.

  Input:  mType - The one-octet message type code.

  Output: A string giving a brief description of the NBT Session Service
          message type.  If the code is unrecognized, the string will be
          "<Undefined>".

  Doctest:
  >>> print MsgTypeStr( SS_SESSION_KEEPALIVE )
  Session Keepalive
  >>> print MsgTypeStr( "Frog" )
  <Undefined>
  """
  if( mType in _msgTypeDict ):
    return( _msgTypeDict[ mType ] )
  return( "<Undefined>" )

def ErrCodeStr( eCode=-1 ):
  """Given a NBT Session Service Negative Response error code, return
     the error description.

  Input:  eCode - The one-octet error code.

  Output: A string giving a brief description of the Negative Session
          Response error code.  If the code is unrecognized, the string
          will be "<Undefined>".

  Doctest:
  >>> print ErrCodeStr( SS_ERR_NOT_PRESENT )
  Called Name Not Present
  """
  if( eCode in _errCodeDict ):
    return( _errCodeDict[ eCode ] )
  return( "<Undefined>" )

def _L2Okay( name ):
  # Test whether we have a correctly L2-encoded NBT name (with no Scope).
  #   name  - A string of octets, presumably extracted from a Session
  #           Request message.  This will either be the Called or the
  #           Calling name.
  # Output: If the string conforms to the expected format then True is
  #         returned, else False.
  #
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
  assert( 0 <= mLen ), "Negative length (%d) not supported." % mLen
  assert( mLen < 0x20000 ), \
    "Session Message length exceeds the 17-bit maximum imposed by NBT."
  # The mask is used because the assert()s may be compiled out.
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
    >>> called = ' EHEPFCEHEPEOFKEPEMEBCACACACACACA\\0'
    >>> calling = ' EMEJENECFFFCEHEFFCFKCACACACACACA\\0'
    >>> req = SessionRequest( called, calling )
    >>> print "0x%02X" % ParseMsg( req )[0]
    0x81
    >>> called, calling = map( hexstr, ParseCNames( req[4:] ) )
    >>> print "Called.: [%s]\\nCalling: [%s]" % (called, calling)
    Called.: [ EHEPFCEHEPEOFKEPEMEBCACACACACACA\\x00]
    Calling: [ EMEJENECFFFCEHEFFCFKCACACACACACA\\x00]
  """
  # Check both names.
  if( not _L2Okay( CalledName ) ):
    raise ValueError( "Malformed Called Name: %s." % hexstr( CalledName ) )
  if( not _L2Okay( CallingName ) ):
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
          are, of course, some really bad things that can happen (think
          of two servers that point to one another), so a client that
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
    >>> print "0x%02X" % ParseMsg( ka )[0]
    0x85
  """
  return( "\x85\0\0\0" )

def ParseMsg( msg=None ):
  """Parse the leading 4 bytes of a Session Service message.

  Input:  msg - At least 4 bytes, received from the wire.

  Errors: NBTerror( 1002 )  - An invalid value was encountered when
                              parsing the message header.  Possible
                              causes:
                              * A non-zero FLAGS subfield.
                              * A length value that does not match the
                                fixed length of a given message type.
          NBTerror( 1005 )  - Invalid session service message type.
          ValueError        - Missing or incomplete message.  Four bytes
                              (minimum) are expected.

  Output: A 2-tuple: (<message type>, <message length>).

  Notes:  This function parses exactly 4 bytes.  Additional parsing is
          required if the message type is one of the following:
          * SS_SESSION_MESSAGE:
            The returned length value gives the number of octets of
            payload that follow the message header.  The payload is
            a message belonging to a higher level protocol.
          * SS_SESSION_REQUEST:
            ParseCNames() should be called to retrieve the Called and
            Calling names.
          * SS_NEGATIVE_RESPONSE:
            ParseErrCode() should be called to retrive the error code.
          * SS_RETARGET_RESPONSE:
            ParseRetarget() should be called to read the IPv4 address
            and port number.

          The LENGTH subfield is viewed as being 17 bits long.  This
          interpretation differs from the RFC, which specifies a
          16 bit field plus a one bit Length Extension in the FLAGS
          field.  Ugh.  Our interpretation is simpler and works just
          fine.  Besides, no other FLAGS values have ever been
          defined.

  Doctest:
  >>> ParseMsg( RetargetResponse( "\\xc0\\xa8\\x0a\\x7a", 8139 ) )
  (132, 6)
  """
  # Is it all there?
  if( (msg is None) or (len(msg) < 4) ):
    raise ValueError( "Missing or short message." )

  # Parse it.
  mType  = ord( msg[0] )
  mFlags = (ord( msg[1] ) >> 1)
  mLen   = _formatLong.unpack( msg[:4] )[0] & 0x0001FFFF

  # Check for an obvious error.
  if( mFlags ):
    raise NBTerror( 1002, "Malformed Session Service message (non-zero FLAGS)" )

  # Get this one out the door quickly.
  if( SS_SESSION_MESSAGE == mType ):
    return( mType, mLen )

  # The first 90% of the job takes 90% of the work.
  # The remaining 10% of the job takes an additional 90% of the work.
  #
  # Check for a valid message type.
  if( mType not in _msgLenDict ):
    s = "Unknown Session Service message code: [0x%02x]" % mType
    raise NBTerror( 1005, s )

  # Check for an incorrect message length.
  if( mLen != _msgLenDict[mType] ):
    s = "Malformed %s " % MsgTypeStr( mType )
    if( _msgLenDict[mType] ):
      s += "(length (%d) != %d)" % (mLen, _msgLenDict[mType])
    else:
      s += "message (non-zero length)"
    raise NBTerror( 1002, s )

  # Done.
  return( (mType, mLen) )

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
  if( not _L2Okay( called ) ):
    raise NBTerror( 1001, "Malformed Called name in Session Request" )
  calling = msg[34:68]
  if( not _L2Okay( calling ) ):
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

def dump( msg=None, indent=0 ):
  """Parse and pretty print an NBT Session Service message.

  Input:  msg     - The (packed) NBT Session Service message.
          indent  - The number of spaces to indent the formatted output.

  Output: A string containing the formatted NBT message.  If the input
          is empty or None, the empty string is returned.

  Notes:  This function does its own parsing, and does not throw any
          exceptions if it finds a parsing error.  Instead, it just
          adds the error information to the output.

          If the message is a Session Message, this function does not
          dump the payload.  That should be handled by the higher
          level protocol stack.

  Doctest:
  >>> print dump( SessionMessage( 1234 ) + "Extra Junk" )
  Message Type: 0x00 [Session Message]
  Flags.......: 0x00
  Length......: 1234
  >>> called, calling = map( Name, ("CALLED", "CALLING") )
  >>> print dump( SessionRequest( called.L2name, calling.L2name ) )
  Message Type: 0x81 [Session Request]
  Flags.......: 0x00
  Length......: 68
  Called Name.: [ EDEBEMEMEFEECACACACACACACACACACA\\x00]
                CALLED<20>
  Calling Name: [ EDEBEMEMEJEOEHCACACACACACACACACA\\x00]
                CALLING<20>
  >>> print dump( PositiveResponse() )
  Message Type: 0x82 [Positive Session Response]
  Flags.......: 0x00
  Length......: 0
  """
  def _decodeL2( nom=None ):
    # Small sub-function to decode L2 NBT names.
    if( _L2Okay( nom ) ):
      n = Name()
      n.setL2name( nom )
      return( str( n ) )
    return( "<Cannot Decode>" )

  # Prepare your spells.
  ind   = ' ' * indent    # The correct number of spaces for indentation.
  inLen = len( msg )      # Length of the input, in bytes.

  # Check for secret doors and traps.
  if( not msg ):
    return( "" )
  if( inLen < 4 ):
    return( ind + "Short input: %s" % hexstr( msg ) )

  # Enter the dungeon.
  mType  = ord( msg[0] )
  mFlags = (ord( msg[1] ) >> 1)
  mLen   = _formatLong.unpack( msg[:4] )[0] & 0x0001FFFF

  # Loot the room.
  s = "{0:s}Message Type: 0x{1:02X} [{2:s}]\n" \
      "{0:s}Flags.......: 0x{3:02X}{4:s}\n"    \
      "{0:s}Length......: {5:d}{6:s}"

  # Go looking for trouble.
  fstr = "" if not mFlags else " <Invalid Flags>"
  validstr = ""
  if( (mType in _msgLenDict) and (mLen != _msgLenDict[mType]) ):
    validstr = " <Invalid Length>"
  s = s.format( ind, mType, MsgTypeStr( mType ), mFlags, fstr, mLen, validstr )

  # Deal with the monsters.
  if( (mType in _msgLenDict) and (inLen < (4 + _msgLenDict[mType])) ):
    s += "\n%sShort input.: %s" % (ind, hexstr( msg[4:] ))
  elif( mType == SS_SESSION_REQUEST ):
    called, calling = (msg[4:38], msg[38:72])
    s += "\n%sCalled Name.: [%s]" % (ind, hexstr( called ))
    s += "\n%s              %s" % (ind, _decodeL2( called ))
    s += "\n%sCalling Name: [%s]" % (ind, hexstr( calling ))
    s += "\n%s              %s" % (ind, _decodeL2( calling ))
  elif( mType == SS_NEGATIVE_RESPONSE ):
    eCode = ord(msg[4])
    s += "\n%sError Code..: 0x%02X (%s)" % (ind, eCode, ErrCodeStr( eCode ))
  elif( mType == SS_RETARGET_RESPONSE ):
    ip, port = _formatIPPort.unpack( msg[4:10] )
    s += "\n%sIPv4 Address: %d.%d.%d.%d" % (ind, ip[0], ip[1], ip[2], ip[3])
    s += "\n%sPort Number.: %d" % (ind, port)

  # Face the Gazebo Alone.
  return( s )


# ============================================================================ #
# "...and then", said the long nose weevil, "Glenda the Gladiator landed her
# fighter jet on the deck of a suburban shopping mall and became Secretary of
# Defense".
# ============================================================================ #
