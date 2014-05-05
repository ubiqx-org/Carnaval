# ============================================================================ #
#                            NBT_DatagramService.py
#
# Copyright:
#   Copyright (C) 2014 by Christopher R. Hertel
#
# $Id: NBT_DatagramService.py; 2014-05-05 15:33:44 -0500; Christopher R. Hertel$
#
# ---------------------------------------------------------------------------- #
#
# Description:
#   NetBIOS over TCP/IP (IETF STD19) implementation: NBT Datagram Service.
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
#   - The NBT Datagram Service has rarely, if ever, been implemented
#     correctly, a point that is repeatedly regurgitated throughout the
#     comments in this module.
#
#     http://www.ubiqx.org/cifs/NetBIOS.html lays out both the design flaws
#     in STD19, as well as the implementation flaws that have plagued this
#     important piece of the NBT suite for years.
#
#   - This implementation includes support for creating an NBT Datagram
#     Distribution Server (NBDD), something which is almost never done
#     (probably for good reason).
#
# ToDo:
#
#   - Write a fragment reassembly class.
#   - Write more doctests.
#
# ============================================================================ #
#
"""NetBIOS over TCP/UDP (NBT) protocol: Datagram Service

NBT is defined in IETF RFCs 1001 and 1002, collectively known as IETF
Standard 19 (STD19).  A detailed implementer's guide to NBT can be
found on the web at:  http://www.ubiqx.org/cifs/NetBIOS.html

For details on implementing the Datagram Service in particular, see
section 1.5:  http://www.ubiqx.org/cifs/NetBIOS.html#NBT.5

Let's repeat this until it sinks in:  NetBIOS is an API, not a network
protocol.  It was originally a chunk of code loaded into DOS memory that
presented an API, but the original code is never (well, maybe rarely)
used any more.  A remarkably useful guide to the NetBIOS API can be
found here:  http://www.netbiosguide.com/

The NBT Datagram Service is rarely implemented as it was designed.  This
module provides the tools needed for creating either an "RFC-correct"
implementation, or the more common "do what Windows does" variety.

One of the goals of this project is that the modules should make it easy
to create correctly formatted messages, but also possible to place all
sorts of correctly formatted evilnastiness onto the wire...for testing
purposes only, of course.  In addition, when parsing a received message
the code tries to be reasonably forgiving.

CONSTANTS:

  Protocol Details:
    DS_PORT = 138   : The default NBT Datagram Service UDP listener port.

  Datagram Service Header:
    Header.MSG_TYPE; Message Types:
    DS_DGM_UNIQUE   : Direct Unique (unicast) datagram.
    DS_DGM_GROUP    : Direct Group (multicast) datagram.
    DS_DGM_BCAST    : Broadcast datagram.
    DS_DGM_ERROR    : Error message.
    DS_DGM_QUERY    : Query the NBDD regarding service.
    DS_DGM_POSRESP  : NBDD reports it can provide service.
    DS_DGM_NEGRESP  : NBDD reports that it cannot provide service.
    DS_DGM_MSGMASK  : MSG_TYPE subfield mask.

    Header.FLAGS mask:
    DS_FLAGS_MASK   : Bitmask for the Flags field.

    Header.FLAGS.SNT (Sending Node Type):
    DS_SNT_B        : Sending node is in B mode.
    DS_SNT_P        : P node.
    DS_SNT_M        : M node.
    DS_SNT_H        : H node (Microsoft extension).
    DS_SNT_NBDD     : Sent by NBT Datagram Distribution Server (not used).
    DS_SNT_MASK     : SNT subfield mask.

    Header.FLAGS.First and .More bits:
    DS_FIRST_FLAG   : 'F'irst flag.
    DS_MORE_FLAG    : 'M'ore flag.
    DS_FM_MASK      : Mask for First and More bits.

    Datagram error codes (ERROR_CODE):
    DS_ERR_NONAME   : Destination Name Not Present
    DS_ERR_SRCNAME  : Malformed Source Name
    DS_ERR_DSTNAME  : Malformed Destination Name
"""

# Imports -------------------------------------------------------------------- #
#
#   struct                - Binary data packing and parsing tools.
#   NBT_NameService.Name  - NBT Name object, for handling L2-encoded names.
#   NBT_Core.hexstr()     - Utility to convert binary strings into human-
#                           readable format, more or less.
#

import struct                         # Binary data handling.
from NBT_NameService import Name      # NBT Name class.
from NBT_Core        import hexstr    # Hexify binary values.


# Constants ------------------------------------------------------------------ #
#

# Protocol Details
DS_PORT = 138   # The default NBT Datagram Service UDP listener port.

# Header.MSG_TYPE
DS_DGM_UNIQUE   = 0x10    # Unicast datagram.
DS_DGM_GROUP    = 0x11    # Multicast datagram.
DS_DGM_BCAST    = 0x12    # Broadcast datagram.
DS_DGM_ERROR    = 0x13    # Datagram error.
DS_DGM_QUERY    = 0x14    # NBDD service query.
DS_DGM_POSRESP  = 0x15    # NBDD positive response.
DS_DGM_NEGRESP  = 0x16    # NBDD negative response.
DS_DGM_MSGMASK  = 0x17    # MSG_TYPE subfield mask.

# Header.FLAGS mask:
DS_FLAGS_MASK = 0x0F      # Bitmask for the Flags field.

# Header.FLAGS.SNT (Sending Node Type)
DS_SNT_B      = 0x00      # B node.
DS_SNT_P      = 0x04      # P node.
DS_SNT_M      = 0x08      # M node.
DS_SNT_H      = 0x0C      # H node (Microsoft extension).
DS_SNT_NBDD   = DS_SNT_H  # Message sent by NBT Datagram Distribution Server.
DS_SNT_MASK   = DS_SNT_H  # SNT subfield mask.

# Header.FLAGS First and More bits.
DS_FIRST_FLAG = 0x02      # 'F'irst flag.
DS_MORE_FLAG  = 0x01      # 'M'ore flag.
DS_FM_MASK    = 0x03      # Mask for First and More bits.

# Datagram error codes (ERROR_CODE).
DS_ERR_NONAME  = 0x82     # Destination Name Not Present (-126)
DS_ERR_SRCNAME = 0x83     # Malformed Source Name (-125)
DS_ERR_DSTNAME = 0x84     # Malformed Destination Name (-124)


# Globals -------------------------------------------------------------------- #
#
#   _format_DS_hdr  - A Struct object used to parse and pack NBT Datagram
#                     Service header fields, excluding the DGM_LEN and
#                     PACKET_OFFSET fields (which, in my not so humble
#                     opinion, are not actually part of the header since
#                     they are only used for Message messages).
#   _format_LenOff  - Used to pack and parse the NBT Datagram Service
#                     Header.DGM_LEN and Header.PACKET_OFFSET fields.
#

# Structure formats.
_format_DS_hdr = struct.Struct( "!BBH4sH" )
_format_LenOff = struct.Struct( "!HH" )


# Classes -------------------------------------------------------------------- #
#

class DSHeader( object ):
  """NBT Datagram Service Header base class.

  As shown in RFC1002, there is a common header for all Datagram Service
  messages.  This DSHeader class is made up of the following fields,
  which map to the header fields described in the RFC.

    Attribute   RFC1002 name
    ---------   ------------
    msgType   - MSG_TYPE
    hdrSNT    - FLAGS.SNT
    dgmId     - DGM_ID
    srcIP     - SOURCE_IP
    srcPort   - SOURCE_PORT

  Despite what the RFCs say, the Header.DGM_LEN and Header.PACKET_OFFSET
  fields aren't really part of the header.  Those fields are only used
  when sending a unique, multicast, or broadcast datagram and never used
  for any of the NBDD messages.  In this implementation, they are
  typically calculated when the datagram message is composed.
  See the <DSMessage> and <DSFragment> classes.

  Also note that only the SNT (Source Node Type) bits of the FLAGS field
  are exposed here.  By default, this class initializes the F & M bits
  to indicate an unfragmented message (0x02).  The F and M bits are
  exposed in descendant classes that actually handle message
  fragmentation.

  See:  http://tools.ietf.org/html/rfc1002#section-4.4
        http://ubiqx.org/cifs/NetBIOS.html#NBT.5.3
  """
  def __init__( self, msgType = 0,
                      hdrSNT  = 0,
                      dgmId   = 0,
                      srcIP   = None,
                      srcPort = 0 ):
    """Create a datagram header instance.

    Input:
      msgType - One of the DS_DGM_* message type values, representing
                one of the valid Datagram Service message formats.
      hdrSNT  - Sender Node Type, one of the DS_SNT_* values.
      dgmId   - A two-byte identifier used to map responses to requests.
      srcIP   - The IP address of the originating interface.  See the
                notes, below.
      srcPort - The originating port number.

    Notes:  In the original design of the NBT Datagram Service, there
            was a relay node known as the NetBIOS Datagram Distribution
            Server (NBDD).  To send a multicast (group) message to all
            group members in a routed IP network (M, P, or H mode), an
            end-node would send the message (unicast) to the NBDD.  The
            NBDD would then look up the IP addresses of all members, and
            relay the datagram message.

            As a result of this design, the IPv4 address and port of the
            originating node had to be maintained within the message
            header so that nodes that received messages via the relay
            would know where to send the reply.

            Unfortunately, the Windows NBT implementation has completely
            munged[1] the datagram service; there are no NBDD at all
            and datagrams are instead broadcast to the local IP subnet,
            rather than being relayed to all members of the group.  This
            is clearly incorrect behavior per the RFCs.

            [1] http://en.wikipedia.org/wiki/Mung_(computer_term)
                Also, from the TECO manual:
                  Mung: A recursive acronym for "Mung Until No Good"; an
                        act applied by novice TECO users to their source
                        files.
              See also: http://en.wikipedia.org/wiki/TECO_(text_editor)
    """
    self._msgType   = (msgType & DS_DGM_MSGMASK)
    self._hdrFlags  = (hdrSNT & DS_SNT_MASK) | DS_FIRST_FLAG
    self._dgmId     = (dgmId & 0xFFFF)
    self._srcIP     = (srcIP[:4] if( srcIP ) else (4 * '\0'))
    self._srcPort   = (srcPort & 0xFFFF)

  def __msgType( self, msgType=None ):
    # Get/set the Header.MSG_TYPE value.
    if( msgType is None ):
      return( self._msgType )
    self._msgType = (msgType & DS_DGM_MSGMASK)

  def __hdrSNT( self, hdrSNT=None ):
    # Get/set the Sender Node Type in the Header.FLAGS field.
    if( hdrSNT is None ):
      return( DS_SNT_MASK & self._hdrFlags )
    self._hdrFlags = (self._hdrFlags & ~DS_SNT_MASK) | (DS_SNT_MASK & hdrSNT)

  def __dgmId( self, dgmId=None ):
    # Get/set the Message ID (Header.DGM_ID).
    if( dgmId is None ):
      return( self._dgmId )
    self._dgmId = (0xFFFF & int( dgmId ))

  def __srcIP( self, srcIP=None ):
    # Get/set the Header.SOURCE_IP address of the message.
    if( srcIP is None ):
      return( self._srcIP )
    self._srcIP = (srcIP[:4] if( srcIP ) else (4 * '\0'))

  def __srcPort( self, srcPort=None ):
    # Get/set the Header.SOURCE_PORT value.
    if( srcPort is None ):
      return( self._srcPort )
    self._srcPort = (0xFFFF & int( srcPort ))

  def dump( self, indent=0 ):
    """Produce a formatted representation of the Datagram Service Header.

    Input:  indent  - Number of spaces to indent the output.

    Output: The header, formatted for display, returned as a string.
    """

    def _FmtMsgType():
      # Format and return a description of the message type.
      xlate = { DS_DGM_UNIQUE : "Direct Unique (unicast) datagram",
                DS_DGM_GROUP  : "Direct Group (multicast) datagram",
                DS_DGM_BCAST  : "Broadcast datagram",
                DS_DGM_ERROR  : "Error message",
                DS_DGM_QUERY  : "Query the NBDD regarding service",
                DS_DGM_POSRESP: "NBDD reports it can provide service",
                DS_DGM_NEGRESP: "NBDD reports that it cannot provide service" }
      s = xlate[self.msgType] if( self.msgType in xlate ) else '<unknown>'
      return( "0x%02X = %s" % (self.msgType, s) )

    def _FmtSNT():
      # Format and return a SenderNodeType description as a string.
      xlate = { DS_SNT_B: "B node",
                DS_SNT_P: "P node",
                DS_SNT_M: "M node",
                DS_SNT_H: "H node or NBDD" }
      s = xlate[self.hdrSNT] if( self.hdrSNT in xlate ) else "<impossible>"
      return( "0b{:02b} = ".format( self.hdrSNT >> 2 ) + s )

    def _FmtFragType():
      # Format and return the fragmentation status as a string.
      xlate = {          0x00: "Last Fragment",
                 DS_MORE_FLAG: "Middle Fragment",
                DS_FIRST_FLAG: "Unfragmented",
                         0x03: "First Fragment" }
      fm = (self._hdrFlags & DS_FM_MASK)
      s  = xlate[fm] if( fm in xlate ) else "<impossible>"
      return( "0b{:02b} = ".format( fm ) + s )

    ipv4 = tuple( ord( octet ) for octet in tuple( self.srcIP ) )
    ind = ' ' * indent
    s  = ind + "Header:\n"
    s += ind + "  Msg_Type....: %s\n" % _FmtMsgType()
    s += ind + "  Flags.......: 0x%02X\n" % self._hdrFlags
    s += ind + "    SNT.........: %s\n" % _FmtSNT()
    s += ind + "    FM..........: %s\n" % _FmtFragType()
    s += ind + "  DatagramID..: 0x%04X (%d)\n" % (self.dgmId, self.dgmId)
    s += ind + "  Source IP...: %u.%u.%u.%u\n" % ipv4
    s += ind + "  Source Port.: %u\n" % self.srcPort
    return( s )

  def compose( self, dgmId=None ):
    """Compose an NBT datagram header.

    Input:  dgmId - If not None, the given value will be used to set the
                    datagram ID (DGM_ID).
    Output: A string of bytes; the formatted header.
    """
    # (Optionally) update the message ID.
    if( dgmId is not None ):
      self._dgmId = (0xFFFF & int( dgmId ))
    # Compose and return.
    return( _format_DS_hdr.pack( self._msgType,
                                 self._hdrFlags,
                                 self._dgmId,
                                 self._srcIP,
                                 self._srcPort ) )

  # Properties.
  msgType   = property( __msgType,  __msgType,  doc="Message Type; MSG_TYPE" )
  hdrSNT    = property( __hdrSNT,   __hdrSNT,   doc="Sender Node Type; SNT" )
  dgmId     = property( __dgmId,    __dgmId,    doc="Datagram ID; DGM_ID" )
  srcIP     = property( __srcIP,    __srcIP,    doc="Source IPv4 address" )
  srcPort   = property( __srcPort,  __srcPort,  doc="Header.SOURCE_PORT" )


class DSMessage( DSHeader ):
  """NBT Datagram Service generic Message class.

  This class implements NBT unicast, multicast, and broadcast messages,
  which all have the same structure.  They differ in the value of the
  MSG_TYPE and, of course, the kind of destination name (unique,
  group, broadcast).

  This class represents an "idealized" datagram message.  Think of it as
  "pre-fragmented".  Even if the payload is too large to be sent as a
  single unfragmented datagram, it is represented as a single message.
  The exception is the composeList() method, which does the work of
  converting the idealized datagram into wire-format byte strings that
  are ready for transmission, fragmenting the payload as needed.

  The DSFragment class handles fragmented messages that are to be
  reconstituted.

  NetBIOS sets a payload limit of 512 bytes per datagram message, so you
  should never be sending more than that in a single message.  That
  upper limit can, of course, be broken for testing.  Here's how:

    Setting the <usrData> attribute to a payload greater than 512 bytes
    in length, either via the __init__() method or via the <usrData>
    property, will cause a ValueError() exception to be thrown.  The
    attribute will, however, have been set to the new value.  For
    testing, the ValueError() exception can be caught and ignored.
    Another option is to set the <_usrData> attribute directly, thus
    bypassing the length check performed when the <usrData> (no '_')
    property is set.

  Separate from the 512 byte NetBIOS limit, RFC1001/1002 provides
  a mechanism for fragmenting the NetBIOS message so that the payload
  is spread across multiple UDP datagrams.  It is not clear why this
  feature was considered necessary, since UDP datagrams also support
  fragmentation.

  The <maxData> attribute sets the maximum number of payload bytes to
  be sent per UDP message.  If the size of <usrData> exceeds this limit,
  the composeList() method will fragment the payload.  The default value
  of <maxData> is 512 (to match the NetBIOS limit).  For testing,
  <maxData> can be set to a lower number to force NBT fragmentation, or
  a higher value to avoid it.  To set <maxData> to a value greater than
  512, set the <_maxData> attribute directly (bypassing the <maxData>
  property).

  See:  http://tools.ietf.org/html/rfc1002#section-4.4
        http://ubiqx.org/cifs/NetBIOS.html#NBT.5.3
  """
  def __init__( self, msgType = 0,
                      hdrSNT  = 0,
                      dgmId   = 0,
                      srcIP   = None,
                      srcPort = 0,
                      srcName = None,
                      dstName = None,
                      usrData = None ):
    """Create a datagram message instance.

    Input:
      msgType - One of the DS_DGM_* message type values:
                  DS_DGM_UNIQUE, DS_DGM_GROUP, or DS_DGM_BCAST.
      hdrSNT  - Sending Node Type value (one of the DS_SNT_* values).
      dgmId   - A 16-bit message ID, used to match responses to
                requests.
      srcIP   - The sending node's IPv4 address.  This is the address
                of the interface on which the message was sent,
                presented as a string of four octets.
      srcPort - The source UDP port.
      srcName - The L2-encoded fully-qualified name of the NetBIOS
                service that is sending the message.
      dstName - The L2-encoded name of the NetBIOS service that is to
                receive the message.  This may be the wildcard name,
                but must always be fully qualified (must include the
                scope).
      usrData - The message content.  NetBIOS itself sets a limit of
                512 bytes for the datagram content.

    Errors:
      AssertionError  - Raised if either <srcName> or <dstName> are not
                        of type <str>.
      TypeError       - <usrData> is not of type <str>.
      ValueError      - <usrData> exceeds the 512 byte limit imposed by
                        NetBIOS.  See the notes in the object
                        description, above.

    Notes:  The NBT names are strings, not NBT_NameService.Name
            objects (but correct L2-encoded names are easy to generate
            using the NBT_NameService.Name class).

            Minimal validation is done to ensure that the <srcName> and
            <dstName> parameters are correct.  There is, in fact, only
            an assert statement to check that the values are of the
            correct type.  This is by design.  Validate your input.
    """
    super( DSMessage, self ).__init__( msgType = msgType,
                                       hdrSNT  = hdrSNT,
                                       dgmId   = dgmId,
                                       srcIP   = srcIP,
                                       srcPort = srcPort )

    # Do a minor amount of cleanup before storing the values.
    self.__srcName( '' if( srcName is None ) else srcName )
    self.__dstName( '' if( dstName is None ) else dstName )
    self.__usrData( '' if( usrData is None ) else usrData )

    # Packet offset.  Will be zero in un- or pre-fragmented messages.
    self._pktOffset = 0

    # By definition, the maximum payload size of a NetBIOS datagram message
    # is 512 bytes.  This tuneable value sets the maximum payload of the
    # NBT Datagram.  NBT (as opposed to NetBIOS) allows for fragmenting of
    # the NetBIOS payload.  This attribute sets the number of bytes beyond
    # which fragmentation will occur.  It *should* be in the rage 1..512,
    # though anything less than 256 is probably a very bad idea.
    self._maxData  = 512

  def __srcName( self, srcName=None ):
    # Get/set the source (calling) name.
    if( srcName is None ):
      return( self._srcName )
    assert isinstance( srcName, str ), "srcName is not of type str."
    self._srcName = srcName

  def __dstName( self, dstName=None ):
    # Get/set the destination (called) name.
    if( dstName is None ):
      return( self._dstName )
    assert isinstance( dstName, str ), "dstName is not of type str."
    self._dstName = dstName

  def __usrData( self, usrData=None ):
    # Get/set the message Data portion of the datagram; USER_DATA.
    #
    # Errors: TypeError   - The input is not of type <str>.
    #         ValueError  - The input exceeds the 512 byte limit
    #                       imposed by NetBIOS.
    #
    # Notes:  If, for testing purposes or due to temporary insanity,
    #         you want to try sending a payload larger than the 512
    #         byte limit, you can catch and ignore the ValueError
    #         exception.
    #
    if( usrData is None ):
      return( self._usrData )
    if( not isinstance( usrData, str ) ):
      s = type( usrData ).__name__
      raise TypeError( "User_Data must be of type str, not %s." % s )
    self._usrData = usrData
    if( len( usrData ) > 512 ):
      raise ValueError( "Message data exceeds NetBIOS maximum size." )

  def __maxData( self, maxData=None ):
    # Get/set the maximum datagram payload size.
    #
    # Input:
    #   maxData - The maximum size (in bytes) of the payload of the
    #             NBT datagram.  If the data exceeds this size, it
    #             will be fragmented and sent in multiple datagrams.
    #
    # Output: If the input is None, this function will return the
    #         current maxData value.  Otherwise, no value (None) is
    #         returned.
    #
    # Notes:  This method will silently enforce a data fragment size in
    #         the range 1..512.  You can assign a value above 512 by
    #         setting the <_maxData> attribute directly.  Values above
    #         512 should only be used for testing.  Smaller values can
    #         be used to force NBT datagram fragmentation, also for
    #         testing.
    #
    if( maxData is None ):
      return( self._maxData )
    self._maxData = max( 1, min( 512, maxData ) )

  def dump( self, indent=0 ):
    """Create a presentable representation of an NBT Datagram Message.

    Input:  indent  - Number of spaces to indent the formatted output.

    Notes:  The returned layout represents an idealized view of the
            message.  Fragmentation is not shown, for example, and
            the PACKET_OFFSET is always given as zero.
    """
    n = Name()
    ind = ' ' * indent
    pOff = self._pktOffset
    dLen = len( self.srcName ) + len( self.dstName ) + len( self.usrData )

    s  = super( DSMessage, self ).dump( indent )
    s += ind + "Message:\n"
    s += ind + "  Dgm_Length....: 0x%04X (%u)\n" % (dLen, dLen)
    s += ind + "  Packet_Offset.: 0x%04X (%u)\n" % (pOff, pOff)
    n.setL2name( self.srcName )
    s += ind + "  Source_Name...: %s\n" % hexstr( self.srcName )
    s += ind + "               => %s\n" % str( n )
    n.setL2name( self.dstName )
    s += ind + "  Dest_Name.....: %s\n" % hexstr( self.dstName )
    s += ind + "               => %s\n" % str( n )
    s += ind + "  User_Data.....: %s\n" % hexstr( self.usrData )
    return( s )

  def composeList( self, dgmId=None ):
    """Pack the message parameters into a list of strings of octets.

    Input:
      dgmID - Either None, or a 16-bit number used to map responses to
              requests.  If None, the current value will be used.

    Output: A list containing one or more composed messages.  Each
            element in the list is a string of bytes--the wire format
            of the message to be transmitted.

    Notes:  Because of the possibility of NBT Datagram fragmentation,
            this method returns a list of messages.  Typically, there
            will only be one message in the list...but check.
    """
    # (Optionally) update the message ID.
    if( dgmId is not None ):
      self._dgmId = (0xFFFF & int( dgmId ))

    # Grab some important values.
    noms   = self._srcName + self._dstName    # Put the names together and
    nomLen = len( noms )                      # store the combined length.
    flags  = (self._hdrFlags & ~DS_FM_MASK)   # Clear the FM bits.

    # Fragment the payload.
    u = self._usrData
    m = self._maxData
    if( len( u ) < m ):
      # The simple, and most common case.
      fragList    = [ u ]
      fragListLen = 1
    else:
      # Actually fragment the list.
      fragList    = [ u[i:i+m] for i in xrange( 0, len( u ), m ) ]
      fragListLen = len( fragList )

    # Initialize some values.
    msgList = []
    offset  = 0
    flagsFM = DS_FIRST_FLAG
    # Build the message list.
    for i in xrange( fragListLen ):
      # Calculate per-iteration values.
      if( i < (fragListLen - 1) ):
        flagsFM |= DS_MORE_FLAG
      fragLen = len( fragList[i] )
      # Create the UDP message content.
      hdr = _format_DS_hdr.pack( self._msgType,
                                 (flags | flagsFM),
                                 self._dgmId,
                                 self._srcIP,
                                 self._srcPort )
      lenOff = _format_LenOff.pack( (nomLen + fragLen), offset )
      msgList.append( hdr + lenOff + noms + fragList[i] )
      # Prep for the next iteration (if any).
      offset += fragLen
      flagsFM = 0x0000

    # Return the list of composed messages.
    return( msgList )

  # Properties.
  srcName = property( __srcName, __srcName, doc="Source NBT Name" )
  dstName = property( __dstName, __dstName, doc="Destination NBT Name" )
  usrData = property( __usrData, __usrData, doc="Message Payload" )
  maxData = property( __maxData, __maxData, doc="Fragmentation Threshold" )


class DSFragment( DSMessage ):
  """Datagram Message Fragment class.

  A special case of the DSMessage class, used for handling message
  fragments.

  A fragment can be a part of a Unique, Group, or Broadcast message.
  The specific message type should be determined as the original
  message is being reconstituted.

  Only the datagram service datagram messages are ever fragmented.
  Datagram service error messages and NBDD message are never fragmented.

  Doctest:
    >>> ip = chr( 192 ) + chr( 168 ) + chr( 0 ) + chr( 1 )
    >>> sn = Name( "MOONBEAM" ).getL2name()
    >>> dn = Name( "KAPOOR" ).getL2name()
    >>> ud = (8 * "Asynchonous double buffer.  " ).rstrip()
    >>> DUD = DirectUniqueDatagram( DS_SNT_B, 2, ip, DS_PORT, sn, dn, ud )
    >>> DUD.maxData = 196
    >>> DgmList = DUD.composeList()
    >>> len( DgmList )
    2
    >>> print ParseDgm( DgmList[1] ).dump()
    Header:
      Msg_Type....: 0x10 = Direct Unique (unicast) datagram
      Flags.......: 0x00
        SNT.........: 0b00 = B node
        FM..........: 0b00 = Last Fragment
      DatagramID..: 0x0002 (2)
      Source IP...: 192.168.0.1
      Source Port.: 138
    Message:
      Dgm_Length....: 0x005E (94)
      Packet_Offset.: 0x00C4 (196)
      Source_Name...:  ENEPEPEOECEFEBENCACACACACACACACA\\x00
                   => MOONBEAM<20>
      Dest_Name.....:  ELEBFAEPEPFCCACACACACACACACACACA\\x00
                   => KAPOOR<20>
      User_Data.....: Asynchonous double buffer.
    <BLANKLINE>
  """
  def __init__( self, msgType   = 0,
                      hdrFlags  = 0,
                      dgmId     = 0,
                      srcIP     = None,
                      srcPort   = 0,
                      pktOffset = 0,
                      srcName   = None,
                      dstName   = None,
                      usrData   = None ):
    """Create a Datagram Message fragment instance.

    Input:
      msgType   - One of the DS_DGM_* message type values:
                  DS_DGM_UNIQUE, DS_DGM_GROUP, or DS_DGM_BCAST.
      hdrFlags  - The Sender Node Type OR'ed with the F and M flag bits
                  (that is, all Flags subfields).
      dgmId     - A 16-bit message ID, used to match responses to
                  requests.
      srcIP     - The sending node's IPv4 address.  This is the address
                  of the interface on which the message was sent,
                  presented as a string of four octets.
      srcPort   - The source UDP port.
      pktOffset - The offset of the <usrData> of this fragment, relative
                  to the whole of the original payload.
      srcName   - The fully-qualified and L2-encoded name of the NetBIOS
                  service that sent the message.
      dstName   - The L2-encoded name of the NetBIOS service that is to
                  receive the message.  This may be the wildcard name,
                  but must always be fully qualified (must include the
                  scope).
      usrData   - The message payload fragment.
    """
    super( DSFragment, self ).__init__( msgType = msgType,
                                        dgmId   = dgmId,
                                        srcIP   = srcIP,
                                        srcPort = srcPort,
                                        srcName = srcName,
                                        dstName = dstName,
                                        usrData = usrData )
    self._hdrFlags  = (DS_FLAGS_MASK & hdrFlags)
    self._pktOffset = pktOffset

  def __hdrFM( self, hdrFM=None ):
    # Get/set the [F]irst and [M]ore bits in the Header.FLAGS field.
    if( hdrFM is None ):
      return( DS_FM_MASK & self._hdrFlags )
    self._hdrFlags = (self._hdrFlags & ~DS_FM_MASK) | (DS_FM_MASK & hdrFM)

  def __pktOffsest( self, pktOffset=None ):
    # Get/set the packet offset of the payload of this message, relative to
    # the original payload.
    if( pktOffset is None ):
      return( self._pktOffset )
    self._pktOffset = pktOffset

  def compose( self ):
    """Create a wire-form bytes tring of the fragment.

    Output: A byte string; the composed NBT fragment.
    """
    hdr    = _format_DS_hdr.pack( self._msgType,
                                  self._hdrFlags,
                                  self._dgmId,
                                  self._srcIP,
                                  self._srcPort )
    body   = self._srcName + self._dstName + self._usrData
    lenOff = _format_LenOff.pack( len( body ), self._pktOffset )
    return( hdr + lenOff + body )

  # Properties.
  hdrFM     = property( __hdrFM,      __hdrFM,      doc="First and More bits" )
  pktOffset = property( __pktOffsest, __pktOffsest, doc="Packet offset" )


class DirectUniqueDatagram( DSMessage ):
  """Direct Unique (unicast) datagram class.

  Doctest:
    >>> ip = chr( 10 ) + chr( 11 ) + chr( 12 ) + chr( 13 )
    >>> sn = Name( "Fooberry", scope="cheese" ).getL2name()
    >>> dn = Name( "Vorplzoo" ).getL2name()
    >>> ud = "We are the android sisters."
    >>> DUD = DirectUniqueDatagram( DS_SNT_B, 7, ip, DS_PORT, sn, dn, ud )
    >>> DgmList = DUD.composeList()
    >>> len( DgmList )
    1
    >>> print ParseDgm( DgmList[0] ).dump()
    Header:
      Msg_Type....: 0x10 = Direct Unique (unicast) datagram
      Flags.......: 0x02
        SNT.........: 0b00 = B node
        FM..........: 0b10 = Unfragmented
      DatagramID..: 0x0007 (7)
      Source IP...: 10.11.12.13
      Source Port.: 138
    Message:
      Dgm_Length....: 0x0066 (102)
      Packet_Offset.: 0x0000 (0)
      Source_Name...:  EGGPGPGCGFHCHCHJCACACACACACACACA\\x06cheese\\x00
                   => Fooberry<20>.cheese
      Dest_Name.....:  FGGPHCHAGMHKGPGPCACACACACACACACA\\x00
                   => Vorplzoo<20>
      User_Data.....: We are the android sisters.
    <BLANKLINE>
  """
  def __init__( self, hdrSNT  = 0,
                      dgmId   = 0,
                      srcIP   = None,
                      srcPort = 0,
                      srcName = None,
                      dstName = None,
                      usrData = None ):
    """Create a Direct Unique Datagram message instance.

    Input:
      hdrSNT  - Sending Node Type value (one of the DS_SNT_* values).
      dgmId   - A 16-bit message ID, used to match responses to
                requests.
      srcIP   - Sending node's IPv4 address.  This is the address of the
                interface on which the message was sent, presented as a
                string of four octets.
      srcPort - The source UDP port.
      srcName - The L2-encoded fully-qualified name of the NetBIOS
                service that is sending the message.
      dstName - The L2-encoded name of the NetBIOS service that is to
                receive the message.  This must be a Unique name.
      usrData - The message content.  NetBIOS itself sets a limit of
                512 bytes for the datagram content.

    Errors:
      AssertionError  - Raised if either <srcName> or <dstName> are not
                        of type <str>.
      TypeError       - <usrData> is not of type <str>.
      ValueError      - <usrData> exceeds the 512 byte limit imposed by
                        NetBIOS.

    Notes:  This is a direct descendent of the <DSMessage> class, with
            a fixed message type (<msgType>) of <DS_DGM_UNIQUE>.
    """
    super( DirectUniqueDatagram, self ).__init__( msgType = DS_DGM_UNIQUE,
                                                  hdrSNT  = hdrSNT,
                                                  dgmId   = dgmId,
                                                  srcIP   = srcIP,
                                                  srcPort = srcPort,
                                                  srcName = srcName,
                                                  dstName = dstName,
                                                  usrData = usrData )

  # ToDo: Figure out a better way to remove the getter from the
  #       inherited properties.
  def __msgType( self ):
    return( DS_DGM_UNIQUE )
  msgType = property( __msgType, doc="Message Type; MSG_TYPE" )


class DirectGroupDatagram( DSMessage ):
  """Direct Group (multicast) datagram class.

  Doctest:
    >>> ip = chr( 10 ) + chr( 12 ) + chr( 14 ) + chr( 18 )
    >>> sn = Name( "ONOFFON", suffix='\x37' ).getL2name()
    >>> dn = Name( "OFFONOFF", suffix='\x42' ).getL2name()
    >>> ud = "Last night, I had a digital dream."
    >>> DGD = DirectGroupDatagram( DS_SNT_P, 21, ip, DS_PORT, sn, dn, ud )
    >>> DgmList = DGD.composeList()
    >>> len( DgmList )
    1
    >>> print ParseDgm( DgmList[0] ).dump()
    Header:
      Msg_Type....: 0x11 = Direct Group (multicast) datagram
      Flags.......: 0x06
        SNT.........: 0b01 = P node
        FM..........: 0b10 = Unfragmented
      DatagramID..: 0x0015 (21)
      Source IP...: 10.12.14.18
      Source Port.: 138
    Message:
      Dgm_Length....: 0x0066 (102)
      Packet_Offset.: 0x0000 (0)
      Source_Name...:  EPEOEPEGEGEPEOCACACACACACACACADH\\x00
                   => ONOFFON<37>
      Dest_Name.....:  EPEGEGEPEOEPEGEGCACACACACACACAEC\\x00
                   => OFFONOFF<42>
      User_Data.....: Last night, I had a digital dream.
    <BLANKLINE>
  """
  def __init__( self, hdrSNT  = 0,
                      dgmId   = 0,
                      srcIP   = None,
                      srcPort = 0,
                      srcName = None,
                      dstName = None,
                      usrData = None ):
    """Create a Direct Group Datagram message instance.

    Input:
      hdrSNT  - Sending Node Type value (one of the DS_SNT_* values).
      dgmId   - A 16-bit message ID, used to match responses to
                requests.
      srcIP   - Sending node's IPv4 address.  This is the address of the
                interface on which the message was sent, presented as a
                string of four octets.
      srcPort - The source UDP port.
      srcName - The L2-encoded fully-qualified name of the NetBIOS
                service that is sending the message.
      dstName - The L2-encoded name of the NetBIOS service that is to
                receive the message.  This must be a Group name.
      usrData - The message content.  NetBIOS itself sets a limit of
                512 bytes for the datagram content.

    Errors:
      AssertionError  - Raised if either <srcName> or <dstName> are not
                        of type <str>.
      TypeError       - <usrData> is not of type <str>.
      ValueError      - <usrData> exceeds the 512 byte limit imposed by
                        NetBIOS.

    Notes:  This is a direct descendant of the <DSMessage> class, with
            a fixed message type (<msgType>) of <DS_DGM_GROUP>.
    """
    super( DirectGroupDatagram, self ).__init__( msgType = DS_DGM_GROUP,
                                                 hdrSNT  = hdrSNT,
                                                 dgmId   = dgmId,
                                                 srcIP   = srcIP,
                                                 srcPort = srcPort,
                                                 srcName = srcName,
                                                 dstName = dstName,
                                                 usrData = usrData )

  def __msgType( self ):
    return( DS_DGM_GROUP )
  msgType = property( __msgType, doc="Message Type; MSG_TYPE" )


class BroadcastDatagram( DSMessage ):
  """Broadcast datagram class.

  Doctest:
    >>> ip = chr( 10 ) + chr( 1 ) + chr( 2 ) + chr( 3 )
    >>> sn = Name( "Andor", suffix='\x37', scope='digital' ).getL2name()
    >>> dn = Name( '*', scope="circus" ).getL2name()
    >>> ud = "A zen country singer?"
    >>> BD = BroadcastDatagram( DS_SNT_M, 2010, ip, DS_PORT, sn, dn, ud )
    >>> DgmList = BD.composeList()
    >>> len( DgmList )
    1
    >>> print ParseDgm( DgmList[0] ).dump()
    Header:
      Msg_Type....: 0x12 = Broadcast datagram
      Flags.......: 0x0A
        SNT.........: 0b10 = M node
        FM..........: 0b10 = Unfragmented
      DatagramID..: 0x07DA (2010)
      Source IP...: 10.1.2.3
      Source Port.: 138
    Message:
      Dgm_Length....: 0x0068 (104)
      Packet_Offset.: 0x0000 (0)
      Source_Name...:  EBGOGEGPHCCACACACACACACACACACADH\\x07digital\\x00
                   => Andor<37>.digital
      Dest_Name.....:  CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\\x06circus\\x00
                   => *<00>.circus
      User_Data.....: A zen country singer?
    <BLANKLINE>
  """
  def __init__( self, hdrSNT  = 0,
                      dgmId   = 0,
                      srcIP   = None,
                      srcPort = 0,
                      srcName = None,
                      dstName = None,
                      usrData = None ):
    """Create a Broadcast Datagram message instance.

    Input:
      hdrSNT  - Sending Node Type value (one of the DS_SNT_* values).
      dgmId   - A 16-bit message ID, used to match responses to
                requests.
      srcIP   - Sending node's IPv4 address.  This is the address of the
                interface on which the message was sent, presented as a
                string of four octets.
      srcPort - The source UDP port.
      srcName - The L2-encoded fully-qualified name of the NetBIOS
                service that is sending the message.
      dstName - The L2-encoded wildcard name.  See the notes below.
      usrData - The message content.  NetBIOS itself sets a limit of
                512 bytes for the datagram content.

    Errors:
      AssertionError  - The first label portion of the L2-encoded
                        destination name was not the wildcard name.
      AssertionError  - Raised if either <srcName> or <dstName> are not
                        of type <str>.
      TypeError       - <usrData> is not of type <str>.
      ValueError      - <usrData> exceeds the 512 byte limit imposed by
                        NetBIOS.

    Notes:  This is a direct descendant of the <DSMessage> class, with
            a fixed message type (<msgType>) of DS_DGM_BCAST.

            The destination name (<dstName>) *must* be the wildcard name
            with the scope appended, encoded in L2 format.  The simplest
            form of the wildcard name is:
              ' CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0'
            ...which is the wildcard name with the empty scope.

            The destination name is passed in as a parameter so that the
            correct scope can be included, in encoded format.
    """
    # Ensure that we were given the wildcard name.
    assert (' CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' != dstName[:34]), \
      "Invalid destination name (must be '*')."
    # Call the super method.
    super( BroadcastDatagram, self ).__init__( msgType = DS_DGM_BCAST,
                                               hdrSNT  = hdrSNT,
                                               dgmId   = dgmId,
                                               srcIP   = srcIP,
                                               srcPort = srcPort,
                                               srcName = srcName,
                                               dstName = dstName,
                                               usrData = usrData )

  def __msgType( self ):
    return( DS_DGM_BCAST )
  msgType = property( __msgType, doc="Message Type; MSG_TYPE" )


class ErrorDatagram( DSHeader ):
  """Datagram Error Response message.

  Doctest:
    >>> ip = chr( 10 ) + chr( 100 ) + chr( 102 ) + chr( 103 )
    >>> ED = ErrorDatagram( DS_SNT_P, 2525, ip, DS_PORT, DS_ERR_NONAME )
    >>> print ParseDgm( ED.compose() ).dump()
    Header:
      Msg_Type....: 0x13 = Error message
      Flags.......: 0x06
        SNT.........: 0b01 = P node
        FM..........: 0b10 = Unfragmented
      DatagramID..: 0x09DD (2525)
      Source IP...: 10.100.102.103
      Source Port.: 138
    Error.....: 0x82 = Destination Name Not Present
    <BLANKLINE>
  """
  def __init__( self, hdrSNT  = 0,
                      dgmId   = 0,
                      srcIP   = None,
                      srcPort = 0,
                      errCode = 0 ):
    """Create an Error Datagram message instance.

    Input:
      hdrSNT  - Sending Node Type value (one of the DS_SNT_* values).
      dgmId   - A 16-bit message ID, used to match responses to
                requests.
      srcIP   - Sending node's IPv4 address.  This is the address of the
                interface on which the message was sent, presented as a
                string of four octets.
      srcPort - The source UDP port.
      errCode - The NBT Datagram Service error code, which should be one
                of the single-byte DS_ERR_* values.

    Errors:
      ValueError  - Raised if the error code is not one of the values
                    defined in RFC1002.
    """
    super( ErrorDatagram, self ).__init__( msgType = DS_DGM_ERROR,
                                           hdrSNT  = hdrSNT,
                                           dgmId   = dgmId,
                                           srcIP   = srcIP,
                                           srcPort = srcPort )
    self.__errCode( errCode )

  def __errCode( self, errCode=None ):
    # Get/set the ERROR_CODE value.
    #
    # Throws a ValueError if the error code is outside of the defined range.
    if( errCode is None ):
      return( self._errCode )
    # Set the error code.
    ec = (0xFF & int( errCode ))  # Minor cleanup.
    if( ec not in [DS_ERR_NONAME, DS_ERR_SRCNAME, DS_ERR_DSTNAME] ):
      raise ValueError( "Unknown error code: 0x%02X." % ec )
    self._errCode = ec

  def __msgType( self ):
    # Getter only.
    return( DS_DGM_ERROR )

  def dump( self, indent=0 ):
    """Produce a formatted representation of the Error message.

    Input:  indent  - Number of spaces to indent the formatted output.

    Output: The Error message, formatted for display, as a string.
    """
    xlate = { DS_ERR_NONAME : "Destination Name Not Present",
              DS_ERR_SRCNAME: "Malformed Source Name",
              DS_ERR_DSTNAME: "Malformed Destination Name" }
    estr = xlate[self.errCode] if( self.errCode in xlate ) else '<unknown>'
    s  = super( ErrorDatagram, self ).dump( indent )
    s += (' ' * indent) + "Error.....: 0x%02X = %s\n" % (self._errCode, estr)
    return( s )

  def compose( self, dgmId=None ):
    """Create the Datagram Error Response message from parts.

    Input:
      dgmID - Either None, or a 16-bit identifier used to map the
              error response to the originating request.  If None, the
              current value will be used.

    Output: A string of bytes which are the formatted Datagram Error
            Response message.
    """
    # (Optionally) update the message ID.
    if( dgmId is not None ):
      self._dgmId = (0xFFFF & int( dgmId ))
    hdr = _format_DS_hdr.pack( self._msgType,
                               self._hdrFlags,
                               self._dgmId,
                               self._srcIP,
                               self._srcPort )
    return( hdr + chr( self._errCode ) )

  # Properties.
  errCode = property( __errCode, __errCode, doc="Error Code" )
  msgType = property( __msgType,            doc="Message Type; MSG_TYPE" )


class DSQuery( DSHeader ):
  """NBDD Query message.

  This is the generic query class, used to create NBDD Query Requests
  and Responses.

  NBDD Query messages are used to ask the NBDD whether or not it can
  service a multicast or broadcast relay request.  This message type
  is almost never used, however, because there are few if any extant
  implementations of the NBDD.  Pooh.

  The query/response protocol is described in RFC1001 section 17.3, and
  briefly section 5.3.2 of RFC1002.
  """
  def __init__( self, msgType = 0,
                      hdrSNT  = 0,
                      dgmId   = 0,
                      srcIP   = None,
                      srcPort = 0,
                      qryName = None ):
    """Create an NBDD Query message.

    Input:
      msgType - One of DS_DGM_QUERY, DS_DGM_POSRESP, DS_DGM_NEGRESP.
                The query request and response messages have identical
                formats.
      hdrSNT  - Sending Node Type value (one of the DS_SNT_* values).
      dgmId   - A 16-bit message ID, used to match responses to
                requests.
      srcIP   - Sending node's IPv4 address.  This is the address of the
                interface on which the message was sent, presented as a
                string of four octets.
      srcPort - The source UDP port.
      qryName - The fully qualified NBT name (in L2-encoded format)
                being queried.

    Errors:
      AssertionError  - Raised if <qryName> is not of type <str>.
      ValueError      - Raised if the given <msgType> is not one of
                        the query message types.
    """
    if( msgType not in [ DS_DGM_QUERY, DS_DGM_POSRESP, DS_DGM_NEGRESP ] ):
      raise ValueError( "Invalid query message type (0x%02X)." % msgType )
    super( DSQuery, self ).__init__( msgType = msgType,
                                     hdrSNT  = hdrSNT,
                                     dgmId   = dgmId,
                                     srcIP   = srcIP,
                                     srcPort = srcPort )
    self.__qryName( '' if( qryName is None ) else qryName )

  def __qryName( self, qryName=None ):
    # Get/set the query name.
    if( qryName is None ):
      return( self._qryName )
    assert isinstance( qryName, str ), "Query Name is not of type str."
    self._qryName = qryName

  def __msgType( self, msgType=None ):
    # Get/set the message type.
    if( msgType is None ):
      return( DS_DGM_ERROR )
    if( msgType not in [ DS_DGM_QUERY, DS_DGM_POSRESP, DS_DGM_NEGRESP ] ):
      raise ValueError( "Invalid query message type (0x%02X)." % msgType )
    self._msgType = (msgType & DS_DGM_MSGMASK)

  def dump( self, indent=0 ):
    """Produce a formatted representation of an NBDD query message.

    Input:  indent  - Number of spaces to indent the formatted output.

    Output: The NBDD message, formatted for display, as a string.
    """
    n = Name()
    n.setL2name( self.qryName )
    ind = ' ' * indent
    s  = super( DSQuery, self ).dump( indent )
    s += ind + "QueryName.: %s\n" % hexstr( self.qryName )
    s += ind + "         => %s\n" % str( n )
    return( s )

  def compose( self, dgmId=None ):
    """Create the wire-format NBDD query message.

    Input:
      dgmID - Either None, or a 16-bit message identifier.  If None, the
              current value will be used.

    Output: A string of bytes which are the formatted NBDD query
            message.
    """
    # (Optionally) update the message ID.
    if( dgmId is not None ):
      self._dgmId = (0xFFFF & int( dgmId ))
    # Format the message.
    hdr = _format_DS_hdr.pack( self._msgType,
                               self._hdrFlags,
                               self._dgmId,
                               self._srcIP,
                               self._srcPort )
    return( hdr + self._qryName )

  # Properties.
  qryName = property( __qryName, __qryName, doc="Query name; DESTINATION_NAME" )
  msgType = property( __msgType, __msgType, doc="Message Type; MSG_TYPE" )


class QueryNBDD( DSQuery ):
  """NBDD Query Request message.

  Doctest:
    >>> ip    = chr( 10 ) + chr( 0 ) + chr( 37 ) + chr( 42 )
    >>> qName = Name( "Tookah" ).getL2name()
    >>> QN    = QueryNBDD( DS_SNT_P, 7890, ip, DS_PORT, qName )
    >>> print ParseDgm( QN.compose() ).dump()
    Header:
      Msg_Type....: 0x14 = Query the NBDD regarding service
      Flags.......: 0x06
        SNT.........: 0b01 = P node
        FM..........: 0b10 = Unfragmented
      DatagramID..: 0x1ED2 (7890)
      Source IP...: 10.0.37.42
      Source Port.: 138
    QueryName.:  FEGPGPGLGBGICACACACACACACACACACA\\x00
             => Tookah<20>
    <BLANKLINE>
  """
  def __init__( self, hdrSNT  = 0,
                      dgmId   = 0,
                      srcIP   = None,
                      srcPort = 0,
                      qryName = None ):
    """Create an NBDD Query Request message.

    Input:
      hdrSNT  - Sending Node Type value (one of the DS_SNT_* values).
      dgmId   - A 16-bit message ID, used to match responses to
                requests.
      srcIP   - Sending node's IPv4 address.  This is the address of the
                interface on which the message was sent, presented as a
                string of four octets.
      srcPort - The source UDP port.
      qryName - The fully qualified NBT name (in L2-encoded format)
                to be queried.

    Errors:
      AssertionError  - Raised if <qryName> is not of type <str>.
      ValueError      - Raised if the given <msgType> is not one of
                        the query message types.
    """
    super( QueryNBDD, self ).__init__( msgType = DS_DGM_QUERY,
                                       hdrSNT  = hdrSNT,
                                       dgmId   = dgmId,
                                       srcIP   = srcIP,
                                       srcPort = srcPort,
                                       qryName = qryName )

  def __msgType( self ):
    return( DS_DGM_QUERY )
  msgType = property( __msgType, doc="Message Type; MSG_TYPE" )


class PositiveResponseNBDD( DSQuery ):
  """NBDD Positive Query Response message.

  Doctest:
    >>> ip    = chr( 10 ) + chr( 10 ) + chr( 99 ) + chr( 88 )
    >>> qName = Name( "Teru" ).getL2name()
    >>> pNBDD = PositiveResponseNBDD( 1978, ip, DS_PORT, qName )
    >>> print ParseDgm( pNBDD.compose() ).dump()
    Header:
      Msg_Type....: 0x15 = NBDD reports it can provide service
      Flags.......: 0x0E
        SNT.........: 0b11 = H node or NBDD
        FM..........: 0b10 = Unfragmented
      DatagramID..: 0x07BA (1978)
      Source IP...: 10.10.99.88
      Source Port.: 138
    QueryName.:  FEGFHCHFCACACACACACACACACACACACA\\x00
             => Teru<20>
    <BLANKLINE>
  """
  def __init__( self, dgmId   = 0,
                      srcIP   = None,
                      srcPort = 0,
                      qryName = None ):
    """Create an NBDD Positive Query Response message.

    Input:
      dgmId   - The message ID copied from the query request.
      srcIP   - The IPv4 address of the NBDD.
      srcPort - The NBDD's UDP port (should always be 138).
      qryName - The name that was queried, copied from the request.

    Errors:
      AssertionError  - Raised if <qryName> is not of type <str>.
    """
    super( PositiveResponseNBDD, self ).__init__( msgType = DS_DGM_POSRESP,
                                                  hdrSNT  = DS_SNT_NBDD,
                                                  dgmId   = dgmId,
                                                  srcIP   = srcIP,
                                                  srcPort = srcPort,
                                                  qryName = qryName )

  def __msgType( self ):
    return( DS_DGM_POSRESP )
  msgType = property( __msgType, doc="Message Type; MSG_TYPE" )


class NegativeResponseNBDD( DSQuery ):
  """NBDD Negative Query Response message.

    >>> ip    = chr( 10 ) + chr( 10 ) + chr( 44 ) + chr( 66 )
    >>> qName = Name( "Ruby" ).getL2name()
    >>> nNBDD = NegativeResponseNBDD( 7654, ip, DS_PORT, qName )
    >>> print ParseDgm( nNBDD.compose() ).dump()
    Header:
      Msg_Type....: 0x16 = NBDD reports that it cannot provide service
      Flags.......: 0x0E
        SNT.........: 0b11 = H node or NBDD
        FM..........: 0b10 = Unfragmented
      DatagramID..: 0x1DE6 (7654)
      Source IP...: 10.10.44.66
      Source Port.: 138
    QueryName.:  FCHFGCHJCACACACACACACACACACACACA\\x00
             => Ruby<20>
    <BLANKLINE>
  """
  def __init__( self, dgmId   = 0,
                      srcIP   = None,
                      srcPort = 0,
                      qryName = None ):
    """Create an NBDD Negative Query Response message.

    Input:
      dgmId   - The message ID copied from the query request.
      srcIP   - The IPv4 address of the NBDD.
      srcPort - The NBDD's UDP port (should always be 138).
      qryName - The name that was queried, copied from the request.

    Errors:
      AssertionError  - Raised if <qryName> is not of type <str>.
    """
    super( NegativeResponseNBDD, self ).__init__( msgType = DS_DGM_NEGRESP,
                                                  hdrSNT  = DS_SNT_NBDD,
                                                  dgmId   = dgmId,
                                                  srcIP   = srcIP,
                                                  srcPort = srcPort,
                                                  qryName = qryName )

  def __msgType( self ):
    return( DS_DGM_NEGRESP )
  msgType = property( __msgType, doc="Message Type; MSG_TYPE" )


# Functions ------------------------------------------------------------------ #
#

def ParseDgm( msg=None ):
  """Parse an NBT Datagram Service message.

  Input:
    msg - A byte string (type str) received from the network.

  Errors: TypeError   - Raised if the input is not a of type str.
          ValueError  - Raised if the input is None, the empty string,
                        or is too short to be parsed correctly.

  Output: An NBT Datagram Service message object, which will be one of
          the following:
            DSFragment            - The message is a fragmented message
                                    message.
            DirectUniqueDatagram  - A unicast datagram message message.
            DirectGroupDatagram   - A multicast datagram 2*message.
            BroadcastDatagram     - A broadcast datagram 2*message.
            ErrorDatagram         - An error message.
            QueryNBDD             - An NBDD query request message.
            NegativeResponseNBDD  - A negative query response message.
            PositiveResponseNBDD  - A positive query response message.

  Notes:  This function will parse the given message and either return
          an object of the correct type or throw an exception if the
          message could not be parsed.

          The goal is to correctly and forgivingly parse the incoming
          message, throwing an exception only when something is deeply
          wrong in a truly meaningful way.
  """
  def _DGmsg():
    # Parse a message message.
    #
    # Errors: ValueError        - Raised if the input parameter fails
    #                             basic sanity checks.
    #         NBTerror( 1003 )  - A Label String Pointer was encountered.
    #                             This should never happen.
    #
    # Output: One of the three datagram message types, or a DSFragment
    #         if the message being parsed is a fragment.
    #
    dgmLen, pktOffset = _format_LenOff.unpack( msg[10:14] )
    if( len( msg ) != (dgmLen + 14) ):
      s = "less than" if( len( msg ) < (dgmLen + 14) ) else "greater than"
      s = "The actual message length is %s the reported message length." % s
      raise ValueError( s )
    n       = Name()
    pos     = 14
    pos    += n.setL2name( msg[pos:] )
    srcName = n.getL2name()
    pos    += n.setL2name( msg[pos:] )
    dstName = n.getL2name()
    usrData = msg[pos:]

    if( DS_FIRST_FLAG != (hdrFlags & DS_FM_MASK) ):
      # If the FIRST flag is not set or if MORE is set, we have a fragment.
      return( DSFragment( msgType   = msgType,
                          hdrFlags  = hdrFlags,
                          dgmId     = dgmId,
                          srcIP     = srcIP,
                          srcPort   = srcPort,
                          pktOffset = pktOffset,
                          srcName   = srcName,
                          dstName   = dstName,
                          usrData   = usrData ) )
    if( DS_DGM_UNIQUE == msgType ):
      return( DirectUniqueDatagram( hdrSNT  = hdrFlags,
                                    dgmId   = dgmId,
                                    srcIP   = srcIP,
                                    srcPort = srcPort,
                                    srcName = srcName,
                                    dstName = dstName,
                                    usrData = usrData ) )
    elif( DS_DGM_GROUP == msgType ):
      return( DirectGroupDatagram( hdrSNT  = hdrFlags,
                                   dgmId   = dgmId,
                                   srcIP   = srcIP,
                                   srcPort = srcPort,
                                   srcName = srcName,
                                   dstName = dstName,
                                   usrData = usrData ) )
    else:
      return( BroadcastDatagram( hdrSNT  = hdrFlags,
                                 dgmId   = dgmId,
                                 srcIP   = srcIP,
                                 srcPort = srcPort,
                                 srcName = srcName,
                                 dstName = dstName,
                                 usrData = usrData ) )

  # ==== Start ParseDgm() function ==== #

  # Sanity checks.
  if( not isinstance( msg, str ) ):
      s = type( msg ).__name__
      raise TypeError( "An NBT packet must be of type str, not %s." % s )
  if( (not msg) or (len( msg ) < 11) ):
    raise ValueError( "NBT message short or empty." )

  # Parse the header portion into five fields.
  msgType, hdrFlags, dgmId, srcIP, srcPort = _format_DS_hdr.unpack( msg[:10] )

  # We should now have enough information to determine the packet type.
  if( msgType in [ DS_DGM_UNIQUE, DS_DGM_GROUP, DS_DGM_BCAST ] ):
    return( _DGmsg() )
  elif( DS_DGM_ERROR == msgType ):
    return( ErrorDatagram( hdrFlags, dgmId, srcIP, srcPort, ord( msg[10] ) ) )
  elif( DS_DGM_QUERY == msgType ):
    return(  QueryNBDD( hdrFlags, dgmId, srcIP, srcPort, msg[10:] ) )
  elif( DS_DGM_POSRESP == msgType ):
    return( PositiveResponseNBDD( dgmId, srcIP, srcPort, msg[10:] ) )
  elif( DS_DGM_NEGRESP == msgType ):
    return( NegativeResponseNBDD( dgmId, srcIP, srcPort, msg[10:] ) )

  # Ooops.
  s = "Parsing failed, unknown message type: 0x%02X" % msgType
  raise NBTerror( 1005, s )

# ============================================================================ #
