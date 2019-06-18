# -*- coding: utf-8 -*-
# ============================================================================ #
#                                SMB2_Header.py
#
# Copyright:
#   Copyright (C) 2016 by Christopher R. Hertel
#
# $Id: SMB2_Header.py; 2019-06-18 17:56:20 -0500; crh$
#
# ---------------------------------------------------------------------------- #
#
# Description:
#   Carnaval Toolkit: SMB2+ message header parsing and composition.
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
#   - This module provides the basic tools used to compose and decompose
#     SMB2/3 message headers. This module can be used by both client and
#     server implementations.
#
#   - The specific dialects considered by this module are:
#         Common Name | Official Name | Dialect ID
#         ============|===============|===========
#          SMB2.0     | SMB 2.0.2     | 0x0202
#          SMB2.1     | SMB 2.1       | 0x0210
#          SMB3.0     | SMB 3.0       | 0x0300
#          SMB3.02    | SMB 3.0.2     | 0x0302
#          SMB3.11    | SMB 3.1.1     | 0x0311
#
#     Others can be added as they are conjured up from the underworld.
#
#   - The Python <int> type is "at least" 32 bits, but it's signed, so to
#     be safe we use the <long> type to handle ULONG field values.  That
#     ensures that unsigned 32-bit field values are handled correctly.
#     The <long> type can be used to store UINT32 and UINT64 values, as
#     well as shorter integer types.
#     See: https://docs.python.org/2/library/stdtypes.html#typesnumeric
#
#   - This project, overall, is designed to protect against sending invalid
#     field values.  It also, to some extent, protects against invalid values
#     in received messages.  However, to make it easy to do protocol testing,
#     these protections can be easily bypassed.
#
# References:
#
#   [MS-SMB2]   Microsoft Corporation, "Server Message Block (SMB)
#               Protocol Versions 2 and 3",
#               http://msdn.microsoft.com/en-us/library/cc246482.aspx
#
# ToDo:
#   - Add more unit tests.
#   - Add support for "related commands" (NextCommand chaining).
#   - Add support for transform headers (\xfdSMB).
#   - Extend the context information to include more connection-related
#     data, including GUID, flags, etc.
#   - Check the assert() calls in setters when decomposing a message header.
#     We want consistent error handling, and asserts() can be compiled out.
#   - Allow (and keep) invalid values where docs say "must ignore".
#
# FIX:
#   - Use exceptions from SMB_Core.
#
# Moose:
#
#   \_\_    _/_/
#       \__/
#       (oo)
#       (..)
#        --
#
# ============================================================================ #
#
"""Carnaval Toolkit: SMB2+ message header packing and parsing.

Common classes, functions, etc., for packing and unpacking SMB2+ Headers.
This module deals with structures common to both the client and server.

CONSTANTS:

  Protocol constants:
    SMB2_MSG_PROTOCOL : \\xFESMB; SMB2 message prefix (protocol ID).
                        4 bytes.
    SMB2_HDR_SIZE     : The fixed length of an SMB2+ message header
                        (64 bytes).

  Supported SMB2+ dialect revision codes:
    SMB2_DIALECT_202  : SMB 2.0.2 dialect revision (Vista, W2K8 Server)
    SMB2_DIALECT_210  : SMB 2.1   dialect revision (Win7, W2K8r2 Server)
    SMB2_DIALECT_300  : SMB 3.0   dialect revision (Win8, W2K12 Server)
    SMB2_DIALECT_302  : SMB 3.0.2 dialect revision (Win8.1, W2K12r2 Server)
    SMB2_DIALECT_311  : SMB 3.1.1 dialect revision (Win10, 2016 Server)
    SMB2_DIALECT_LIST : A list of all supported dialects, ordered from
                        lowest to highest.
    SMB2_DIALECT_MIN  : The lowest supported dialect.
    SMB2_DIALECT_MAX  : The highest supported dialect.

  SMB2+ command codes:
    SMB2_COM_NEGOTIATE        : Dialect and feature support negotiation.
    SMB2_COM_SESSION_SETUP    : Authentication and session establishment.
    SMB2_COM_LOGOFF           : Close a session; log out.
    SMB2_COM_TREE_CONNECT     : Connect to a remote share; mount.
    SMB2_COM_TREE_DISCONNECT  : Disconnect a connected share; umount.
    SMB2_COM_CREATE           : Create/open a filesystem object (file).
    SMB2_COM_CLOSE            : Close a previously opened handle.
    SMB2_COM_FLUSH            : Push data to disk (or thereabouts).
    SMB2_COM_READ             : Get some data.
    SMB2_COM_WRITE            : Put some data.
    SMB2_COM_LOCK             : Byte-range locks.
    SMB2_COM_IOCTL            : Do fiddly stuff.
    SMB2_COM_CANCEL           : Don't do whatever you're waiting to do.
    SMB2_COM_ECHO             : Ping!
    SMB2_COM_QUERY_DIRECTORY  : Find things in the Object Store.
    SMB2_COM_CHANGE_NOTIFY    : Let me know if something happens.
    SMB2_COM_QUERY_INFO       : Get some metadata.
    SMB2_COM_SET_INFO         : Put some metadata.
    SMB2_COM_OPLOCK_BREAK     : Server->client lease/oplock break.

  SMB2+ header flags:
    SMB2_FLAGS_SERVER_TO_REDIR    : Response
    SMB2_FLAGS_ASYNC_COMMAND      : Async
    SMB2_FLAGS_RELATED_OPERATIONS : Chained command
    SMB2_FLAGS_SIGNED             : Signed packet
    SMB2_FLAGS_DFS_OPERATIONS     : Distributed File System
    SMB2_FLAGS_REPLAY_OPERATION   : SMB3 Replay
    SMB2_FLAGS_MASK               : Flags Bitmask
"""

# Imports -------------------------------------------------------------------- #
#

import struct       # Binary data handling.

from SMB_Status     import *          # Windows NT Status Codes.
from common.HexDump import hexstr     # Convert binary data to readable output.
from common.HexDump import hexstrchop # Ditto, but with linewrap.
from common.HexDump import hexdump    # Formatted hex dump à la hexdump(1).


# Constants ------------------------------------------------------------------ #
#

# Protocol constants
SMB2_MSG_PROTOCOL  = '\xFESMB'  # Standard SMB2 message prefix (protocol ID).
SMB2_HDR_SIZE      = 64         # Fixed SMB2+ header size.

# Known SMB2+ dialect revision codes.
# An unknown or undefined dialect is indicated using <None>.
SMB2_DIALECT_202 = 0x0202  # SMB 2.0.2 dialect revision (Vista/W2K8 Server)
SMB2_DIALECT_210 = 0x0210  # SMB 2.1   dialect revision (Win7/W2K8r2 Server)
SMB2_DIALECT_300 = 0x0300  # SMB 3.0   dialect revision (Win8/W2K12 Server)
SMB2_DIALECT_302 = 0x0302  # SMB 3.0.2 dialect revision (Win8.1/W2K12r2 Server)
SMB2_DIALECT_311 = 0x0311  # SMB 3.1.1 dialect revision (Win10/W2K16 Server)
# List of supported dialects, in order from oldest to newest.
SMB2_DIALECT_LIST = [ SMB2_DIALECT_202,
                      SMB2_DIALECT_210,
                      SMB2_DIALECT_300,
                      SMB2_DIALECT_302,
                      SMB2_DIALECT_311 ]
SMB2_DIALECT_MIN  = SMB2_DIALECT_LIST[0]    # Oldest supported revision.
SMB2_DIALECT_MAX  = SMB2_DIALECT_LIST[-1]   # Newest supported revision.

# SMB2/3 command codes (there are, currently, 19 SMB2+ command codes).
SMB2_COM_NEGOTIATE        = 0x0000  #  0
SMB2_COM_SESSION_SETUP    = 0x0001  #  1
SMB2_COM_LOGOFF           = 0x0002  #  2
SMB2_COM_TREE_CONNECT     = 0x0003  #  3
SMB2_COM_TREE_DISCONNECT  = 0x0004  #  4
SMB2_COM_CREATE           = 0x0005  #  5
SMB2_COM_CLOSE            = 0x0006  #  6
SMB2_COM_FLUSH            = 0x0007  #  7
SMB2_COM_READ             = 0x0008  #  8
SMB2_COM_WRITE            = 0x0009  #  9
SMB2_COM_LOCK             = 0x000A  # 10
SMB2_COM_IOCTL            = 0x000B  # 11
SMB2_COM_CANCEL           = 0x000C  # 12
SMB2_COM_ECHO             = 0x000D  # 13
SMB2_COM_QUERY_DIRECTORY  = 0x000E  # 14
SMB2_COM_CHANGE_NOTIFY    = 0x000F  # 15
SMB2_COM_QUERY_INFO       = 0x0010  # 16
SMB2_COM_SET_INFO         = 0x0011  # 17
SMB2_COM_OPLOCK_BREAK     = 0x0012  # 18

# SMB2/3 header flags
SMB2_FLAGS_SERVER_TO_REDIR    = 0x00000001  # Response
SMB2_FLAGS_ASYNC_COMMAND      = 0x00000002  # Async
SMB2_FLAGS_RELATED_OPERATIONS = 0x00000004  # ANDX
SMB2_FLAGS_SIGNED             = 0x00000008  # Signed packet
SMB2_FLAGS_DFS_OPERATIONS     = 0x10000000  # Distributed File System (DFS)
SMB2_FLAGS_REPLAY_OPERATION   = 0x20000000  # SMB3 Replay
SMB2_FLAGS_PRIORITY_MASK      = 0x00000070  # SMB311 priority bits
SMB2_FLAGS_MASK               = 0x3000007F  # Bitmask

# Max Size values
_UCHAR_MAX  = 0xFF        # Bitmask for Unsigned 8-bit (UCHAR) values.
_USHORT_MAX = 0xFFFF      # Bitmask for Unsigned 16-bit (USHORT) values.
_ULONG_MAX  = 0xFFFFFFFF  # Bitmask for Unsigned 32-bit (ULONG) values.
_UINT64_MAX = (2**64) - 1 # Bitmask for Unsigned 64-bit (UINT64) values.


# Classes -------------------------------------------------------------------- #
#

class _SMB2_Header( object ):
  # SMB2/SMB3 Message Header; [MS-SMB; 2.2.1].
  #
  # This class is used to format both Sync and Async SMB2 headers.
  #
  # Reminder: SMB2 and SMB3 are names for different sets of dialects of the
  #           same protocol; SMB3.0 was originally SMB2.2.  Can you say
  #           "Marketing Upgrade"?
  #
  # Class values:
  # Values instanciated once for the class (so that all instances can use them).
  #
  #   These represent the four possible header formats defined for the
  #   supported SMB2 dialects.  It's basically a 2x2 matrix.
  #
  #   _format_SMB2_StatAsync  - Async header, with <status> and <asyncId>.
  #   _format_SMB2_StatTreeId - Sync header,  with <status> and <treeId>.
  #   _format_SMB2_cSeqAsync  - Async header, with <channelSeq> and <asyncId>.
  #   _format_SMB2_cSeqTreeId - Sync header,  with <channelSeq> and <treeId>.
  #
  #   In general, Async headers are sent in server responses that are used to
  #   tell the client to wait for a pending operation to complete.  That is,
  #   they are "hang on a bit" messages, telling the client not to time out.
  #
  #   A client uses an async header when it is sending a CANCEL request for
  #   a command for which the server has already sent an Async response.
  #   That is:
  #     Command -->           (sync)
  #     <-- Hang on a bit     (async)
  #     Nevermind -->         (async)
  #     <-- Command canceled  (sync)
  #   The middle two are sent using Async headers.
  #
  #   These two additional patterns are used for decoding header variants.
  #   _format_2H  - Two unsigned 16-bit integers.
  #   _format_Q   - One unsigned 64-bit integer.
  #
  #   [MS-SMB2; 2.2.1] also mystically says that the Async header "MAY be used
  #   for any request", but doesn't explain when or why a client would do such
  #   a confusing thing.
  #
  #   _cmd_LookupDict - A dictionary that maps command codes to strings.
  #                     This is used for composing error messages, and when
  #                     providing a header dump.
  #
  _format_SMB2_StatAsync  = struct.Struct( '<4s H H L   H H L L Q Q   Q 16s' )
  _format_SMB2_StatTreeId = struct.Struct( '<4s H H L   H H L L Q L L Q 16s' )
  _format_SMB2_cSeqAsync  = struct.Struct( '<4s H H H H H H L L Q Q   Q 16s' )
  _format_SMB2_cSeqTreeId = struct.Struct( '<4s H H H H H H L L Q L L Q 16s' )

  _format_2H = struct.Struct( "<H H" )
  _format_Q  = struct.Struct( "<Q" )

  _cmd_LookupDict = \
    {
    SMB2_COM_NEGOTIATE      : "NEGOTIATE",
    SMB2_COM_SESSION_SETUP  : "SESSION_SETUP",
    SMB2_COM_LOGOFF         : "LOGOFF",
    SMB2_COM_TREE_CONNECT   : "TREE_CONNECT",
    SMB2_COM_TREE_DISCONNECT: "TREE_DISCONNECT",
    SMB2_COM_CREATE         : "CREATE",
    SMB2_COM_CLOSE          : "CLOSE",
    SMB2_COM_FLUSH          : "FLUSH",
    SMB2_COM_READ           : "READ",
    SMB2_COM_WRITE          : "WRITE",
    SMB2_COM_LOCK           : "LOCK",
    SMB2_COM_IOCTL          : "IOCTL",
    SMB2_COM_CANCEL         : "CANCEL",
    SMB2_COM_ECHO           : "ECHO",
    SMB2_COM_QUERY_DIRECTORY: "QUERY_DIRECTORY",
    SMB2_COM_CHANGE_NOTIFY  : "CHANGE_NOTIFY",
    SMB2_COM_QUERY_INFO     : "QUERY_INFO",
    SMB2_COM_SET_INFO       : "SET_INFO",
    SMB2_COM_OPLOCK_BREAK   : "OPLOCK_BREAK"
    }

  # _SMB2_Header class methods:
  #
  @classmethod
  def parseMsg( cls, msgBlob=None, dialect=SMB2_DIALECT_MIN ):
    """Decompose wire data and return an _SMB2_Header object.

    Input:
      cls     - This class.
      msgBlob - An array of at least 64 bytes, representing an SMB2+
                message in wire format.
      dialect - The minimum dialect under which to parse the header.

    Output:
      An <_SMB2_Header> object.

    Errors:
      AssertionError  - Thrown if:
                        + The length of <msgBlob> is less than the
                          minimum of 64 bytes.
                        + The command code parsed from the message is
                          not a valid command code.
                        + The given dialect is not known.
      ValueError      - Thrown if the packet cannot possibly contain a
                        valid SMB2+ message header.  This exception is
                        raised if either the ProtocolId field doesn't
                        contain the correct string, or if the
                        StructureSize value is incorrect.

    Notes:
      - This function does not parse SMB3 Transform Headers.  An SMB3
        Transform header will be rejected with a ValueError.
      - Beyond the basics of verifying that ProtocolId and StructureSize
        are correct, this function does _no_ validation of the input.
    """
    # Fundamental sanity check.
    assert( SMB2_HDR_SIZE <= len( msgBlob ) ), "Incomplete message header."

    # Parse it.  Use the simple sync response format.
    tup = cls._format_SMB2_StatTreeId.unpack( msgBlob[:SMB2_HDR_SIZE] )

    # Look for trouble.
    if( SMB2_MSG_PROTOCOL != tup[0] ):
      raise ValueError( "Malformed SMB2 ProtocolId: [%s]." % repr( tup[0] ) )
    elif( SMB2_HDR_SIZE != tup[1] ):
      s = "The SMB2 Header StructureSize must be 64, not %d." % tup[1]
      raise ValueError( s )

    # Create and populate a header record instance.
    hdr = cls( tup[4], dialect )
    hdr._creditCharge  = tup[2]
    # 3: Status/ChannelSeq/Reserved1; see below
    hdr.command        = tup[4]
    hdr._creditReqResp = tup[5]
    hdr._flags         = tup[6]
    hdr._nextCommand   = tup[7]
    hdr._messageId     = tup[8]
    # 9, 10: Reserved2/TreeId/AsyncId; see below
    hdr._sessionId     = tup[11]
    hdr._signature     = tup[12]

    # Handle the overloaded fields.
    if( hdr.flagReply or (dialect < SMB2_DIALECT_300) ):
      hdr._status = tup[3]
    else:
      hdr._channelSeq, hdr._reserved1 = cls._format_2H.unpack( msgBlob[8:12] )

    if( hdr.flagAsync ):
      hdr._asyncId = cls._format_Q.unpack( msgBlob[32:40] )
    else:
      hdr._reserved2 = tup[9]
      hdr._treeId    = tup[10]

    # All done.
    return( hdr )

  @classmethod
  def commandName( self, CmdId=0xFF ):
    """Given an SMB2 command code, return the name of the command.

    Input:
      CmdId - An SMB2/3 command code.

    Output: A string.
            If <CmdId> is a known SMB2/3 command code, the string
            will be the command name.  Otherwise, the empty string
            is returned.
    """
    if( CmdId in self._cmd_LookupDict ):
      return( self._cmd_LookupDict[CmdId] )
    return( '' )

  def __init__( self, command=None, dialect=SMB2_DIALECT_MIN ):
    # Create an SMB2 message header object.
    #
    # Input:
    #   command - The command code; one of the SMB2_COM_* values.
    #   dialect - The dialect version under which this header is being
    #             created.  This is contextual information; in future
    #             revisions we may need to expand the context data to
    #             include things like negotiated flag settings, etc.
    # Errors:
    #   AssertionError  - Thrown if the given command code is not a
    #                     known code, or if the given dialect is not
    #                     in the list of supported dialects.
    #   [ TypeError,    - Either of these may be thrown if an input value
    #     ValueError ]    cannot be converted into the expected type.
    #
    # Notes:
    #   Several SMB2 Header fields are overloaded.  For example, the
    #   <Status> field is a four byte field at offset 8.
    #     * In the 2.0 and 2.1 dialects, this field MUST be zero in
    #       Request messages.
    #     * In the 3.x dalects, in a request message only, the same
    #       bytes are used for a 2-byte <ChannelSequence> field,
    #       followed by a 2-byte Reserved-must-be-zero field.
    #     * In SMB2/3 Response messages, the field is always the 4-byte
    #       <Status> field.
    #
    #   Similarly, in an Async header the 8 bytes at offset 32 are used
    #   for the <AsyncId>.  In a Sync header, the first four bytes are
    #   Reserved-must-be-zero, and the next four bytes are the TreeID.
    #
    self._protocolId    = SMB2_MSG_PROTOCOL     #  4 bytes
    self._headerSize    = SMB2_HDR_SIZE         #  2 bytes
    self._creditCharge  = 0                     #  2 bytes
    self._status        = 0                     #  4 bytes -- <status> --
    self._channelSeq    = 0                     #  2 bytes \ Same bytes
    self._reserved1     = 0                     #  2 bytes / as <status>
    self.command        = command               #  2 bytes
    self._creditReqResp = 0                     #  2 bytes
    self._flags         = 0                     #  4 bytes
    self._nextCommand   = 0                     #  4 bytes
    self._messageId     = 0                     #  8 bytes
    self._reserved2     = 0                     #  4 bytes \ Same bytes
    self._treeId        = 0                     #  4 bytes / as <asyncId>
    self._asyncId       = 0                     #  8 bytes -- <asyncId> --
    self._sessionId     = 0                     #  8 bytes
    self._signature     = (16 * '\0')           # 16 bytes
                                                # 64 bytes total.
    # Context information:
    #
    assert( dialect in SMB2_DIALECT_LIST ), "Unknown Dialect: %0x04X" % dialect
    self._dialect = int( dialect )

  @property
  def creditCharge( self ):
    """Get/set the SMB2_Header.CreditCharge field value (USHORT).

    Errors:
      AssertionError  - Thrown if the assigned value (after conversion
                        to an <int>) is either negative or greater
                        than 0xFFFF.
                      - Thrown if the assigned value is non-zero and
                        the current dialect is SMBv2.0.2.
      [ TypeError,    - Either of these may be thrown if the assigned
        ValueError ]    value cannot be converted into an <int>.

    Notes:
      It is out of character to throw an exception based on the given
      dialect level.  This layer does minimal enforcement of
      per-dialect syntax rules, generally allowing the caller to make
      their own mess.  You can, of course, still bypass the assertion
      by setting <instance>._creditCharge directly.
    """
    return( self._creditCharge )
  @creditCharge.setter
  def creditCharge( self, cc ):
    cc = int( cc )
    assert( 0 <= cc <= _USHORT_MAX ), "Assigned value (%d) out of range." % cc
    assert( (cc == 0) or (self._dialect > SMB2_DIALECT_202) ), \
      "Reserved; Value must be zero in SMBv2.0.2."
    self._creditCharge = cc

  @property
  def status( self ):
    """Get/set the SMB2_Header.status field (ULONG).

    Errors:
      AssertionError  - Thrown if the assigned value (after conversion
                        to a <long>) is either negative or greater
                        than 0xFFFFFFFF.
      [ TypeError,    - Either of these may be thrown if the assigned
        ValueError ]    value cannot be converted into a <long>.

    Notes:
      This field should only be set in response messages, and should
      be considered "reserved; must be zero" in all requests.

      Starting with SMBv3.0.0, this field is superceeded in request
      messages by the 16-bit ChannelSequence field (plus an additional
      16-bit Reserved field).

      It is probably easiest to think of it this way:
      - There is no <Status> field in request messages; it only exists
        in response messages.
      - If the dialect is less than 0x0300, then there is a 32-bit
        "Reserved Must Be Zero" field where the <Status> field might
        otherwise exist.
      - If the dialect is 0x0300 or greater, then there is a 16-bit
        <ChannelSequence> field followed by a 16-bit "Reserved Must Be
        Zero" field where the <Status> might otherwise exist.
    """
    return( self._status )
  @status.setter
  def status( self, st ):
    st = 0L if( not st ) else long( st )
    assert( 0 <= st <= _ULONG_MAX ), \
      "Assigned value (0x%08X) out of range." % st
    self._status = st

  @property
  def channelSeq( self ):
    """Get/set the Channel Sequence value (USHORT).

      AssertionError  - Thrown if the assigned value (after conversion
                        to an <int>) is either negative or greater
                        than 0xFFFF.
      [ TypeError,    - Either of these may be thrown if the assigned
        ValueError ]    value cannot be converted into an <int>.

    Notes:
      The ChannelSequence value is only recognized in request messages,
      and only if the dialect is 0x0300 or greater.  That is, this
      field does not not exist in SMB2.x, only in SMB3.x.  In all
      responses, and in dialcts prior to 0x0300, the bytes of this
      field are always seen as part of the Status field.
    """
    return( self._channelSeq )
  @channelSeq.setter
  def channelSeq( self, cs ):
    cs = int( cs )
    assert( 0 <= cs <= _USHORT_MAX ), "Assigned value (%d) out of range." % cs
    self._channelSeq = cs

  @property
  def command( self ):
    """Get/set the SMB2_Header.Command (UCHAR).

    Errors: [ AssertionError, TypeError, ValueError ]
      Thrown if the assigned value cannot be converted into a valid
      SMB2 command code.
    """
    return( self._command )
  @command.setter
  def command( self, cmd ):
    cmd = int( cmd )
    assert( 0 <= cmd <= 0x12 ), "Unknown command code: 0x%04X." % cmd
    self._command = cmd

  @property
  def creditReqResp( self ):
    """Get/set the Credit Request / Credit Response value (USHORT).

    Errors:
      AssertionError  - Thrown if the assigned value (after conversion
                        to an <int>) is either negative or greater
                        than 0xFFFF.
      [ TypeError,    - Either of these may be thrown if the assigned
        ValueError ]    value cannot be converted into an <int>.

    ToDo: Document how and when this is used; references.
          The credit management subsystem needs study.
    """
    return( self._creditReqResp )
  @creditReqResp.setter
  def creditReqResp( self, crr ):
    crr = int( crr )
    assert( 0 <= crr <= _USHORT_MAX ), \
      "Assigned value (%d) out of range." % crr
    self._creditReqResp = crr

  @property
  def flags( self ):
    """Get/set the Flags field (ULONG).

    Errors:
      AssertionError  - Thrown if the assigned value (after conversion
                        to a <long>) has bits that are set which do not
                        represent a known SMB2+ flag.
      [ TypeError,    - Either of these may be thrown if the assigned
        ValueError ]    value cannot be converted into a <long>.
    """
    return( self._flags )
  @flags.setter
  def flags( self, flags ):
    flgs = long( flags )
    assert( flgs == (flgs & SMB2_FLAGS_MASK) ), "Unrecognized flag bit(s)."
    self._flags = flgs
  # Note: See below for per-flag get/set properties.

  @property
  def nextCommand( self ):
    """Get/set the Next Command offset value (ULONG).

    Errors:
      AssertionError  - Thrown if the assigned value (after conversion
                        to a <long>) is either negative, or greater
                        than (2^32)-1.
      [ TypeError,    - Either of these may be thrown if the assigned
        ValueError ]    value cannot be converted into a <long>.
    """
    return( self._nextCommand )
  @nextCommand.setter
  def nextCommand( self, nextOffset ):
    nc = long( nextOffset )
    assert( 0 <= nc <= _ULONG_MAX ), \
      "Invalid Related Command Offset: %d." % nc
    self._nextCommand = nc

  @property
  def messageId( self ):
    """Get/set the Message ID value (UINT64).

    Errors:
      AssertionError  - Thrown if the assigned value (after conversion
                        to a <long>) is either negative, or greater
                        than (2^64)-1.
      [ TypeError,    - Either of these may be thrown if the assigned
        ValueError ]    value cannot be converted into a <long>.
    """
    return( self._messageId )
  @messageId.setter
  def messageId( self, messageId ):
    mi = long( messageId )
    assert( 0 <= mi <= _UINT64_MAX ), \
      "Assigned value (%d) out of range." % mi
    self._messageId = mi

  @property
  def treeId( self ):
    """Get/set the Tree Connect ID (ULONG).

    Errors:
      AssertionError  - Thrown if the assigned value (after conversion
                        to a <long>) is either negative or greater
                        than 0xFFFFFFFF.
      [ TypeError,    - Either of these may be thrown if the assigned
        ValueError ]    value cannot be converted into a <long>.
    """
    return( self._treeId )
  @treeId.setter
  def treeId( self, treeId ):
    tid = long( treeId )
    assert( 0 <= tid <= _ULONG_MAX ), \
      "Assigned value (%d) out of range." % tid
    self._treeId    = tid

  @property
  def asyncId( self ):
    """Get/set the Async Id (UINT64).

    Errors:
      AssertionError  - Thrown if the assigned value (after conversion
                        to a <long>) is either negative or greater
                        than (2^64)-1.
      [ TypeError,    - Either of these may be thrown if the assigned
        ValueError ]    value cannot be converted into a <long>.
    """
    return( self._asyncId )
  @asyncId.setter
  def asyncId( selfd, asyncId ):
    ai = long( asyncId )
    assert( 0 <= ai <= _UINT64_MAX ), \
      "Assigned value (%d) out of range." % ai
    self._asyncId = ai

  @property
  def sessionId( self ):
    """Get/set the Session Id (UINT64).

    Errors:
      AssertionError  - Thrown if the assigned value (after conversion
                        to a <long>) is either negative or greater
                        than (2^64)-1.
      [ TypeError,    - Either of these may be thrown if the assigned
        ValueError ]    value cannot be converted into a <long>.
    """
    return( self._sessionId )
  @sessionId.setter
  def sessionId( self, sessionId ):
    si = long( sessionId )
    assert( 0 <= si <= _UINT64_MAX ), \
      "Assigned value (%d) out of range." % si
    self._sessionId = si

  @property
  def signature( self ):
    """Get/set the packet signature.

    Errors:
      AssertionError  - Thrown if the string representation of the
                        assigned value is not exactly 16 bytes.
      SyntaxError     - Thrown if the assigned value is not of type
                        <str> and cannot be converted to type <str>.
    """
    return( self._signature )
  @signature.setter
  def signature( self, signature ):
    sig = str( signature )
    assert( 16 == len( sig ) ), "Exactly 16 bytes required."
    self._signature = sig

  # Flag bitfield properties.
  #   _flag[S|G]et() generically handles getting and setting of
  #   individual flag bits.
  def _flagGet( self, flag ):
    return( bool( flag & self._flags ) )

  def _flagSet( self, flag, bitState ):
    if( bitState ):
      self._flags |= flag
    else:
      self._flags &= ~flag

  @property
  def flagReply( self ):
    """Get/set the SMB2_FLAGS_SERVER_TO_REDIR (Reply) bit.
    The assigned value is evaluated as a boolean:
      True = set the bit; False = clear it.
    """
    return( self._flagGet( SMB2_FLAGS_SERVER_TO_REDIR ) )
  @flagReply.setter
  def flagReply( self, bitState ):
    self._flagSet( SMB2_FLAGS_SERVER_TO_REDIR, bitState )

  @property
  def flagAsync( self ):
    """Get/set the SMB2_FLAGS_ASYNC_COMMAND (Async) bit.
    The assigned value is evaluated as a boolean:
      True = set the bit; False = clear it.
    """
    return( self._flagGet( SMB2_FLAGS_ASYNC_COMMAND ) )
  @flagAsync.setter
  def flagAsync( self, bitState ):
    self._flagSet( SMB2_FLAGS_ASYNC_COMMAND, bitState )

  @property
  def flagNext( self ):
    """Get/set the SMB2_FLAGS_RELATED_OPERATIONS (Next) bit.
    The assigned value is evaluated as a boolean:
      True = set the bit; False = clear it.
    """
    return( self._flagGet( SMB2_FLAGS_RELATED_OPERATIONS ) )
  @flagNext.setter
  def flagNext( self, bitState ):
    self._flagSet( SMB2_FLAGS_RELATED_OPERATIONS, bitState )

  @property
  def flagSigned( self ):
    """Get/set the SMB2_FLAGS_SIGNED (Signed) bit.
    The assigned value is evaluated as a boolean:
      True = set the bit; False = clear it.
    """
    return( self._flagGet( SMB2_FLAGS_SIGNED ) )
  @flagSigned.setter
  def flagSigned( self, bitState ):
    self._flagSet( SMB2_FLAGS_SIGNED, bitState )

  @property
  def flagDFS( self ):
    """Get/set the SMB2_FLAGS_DFS_OPERATIONS (DFS) bit.
    The assigned value is evaluated as a boolean:
      True = set the bit; False = clear it.
    """
    return( self._flagGet( SMB2_FLAGS_DFS_OPERATIONS ) )
  @flagDFS.setter
  def flagDFS( self, bitState ):
    self._flagSet( SMB2_FLAGS_DFS_OPERATIONS, bitState )

  @property
  def flagReplay( self ):
    """Get/set the SMB2_FLAGS_REPLAY_OPERATION (Replay) bit.
    The assigned value is evaluated as a boolean:
      True = set the bit; False = clear it.
    """
    return( self._flagGet( SMB2_FLAGS_REPLAY_OPERATION ) )
  @flagReplay.setter
  def flagReplay( self, bitState ):
    self._flagSet( SMB2_FLAGS_REPLAY_OPERATION, bitState )

  @property
  def flagPriority( self ):
    """Get/set the SMBv3.1.1+ Priority subfield.
    This value is actually a 3-bit integer (in the range 0..7).
    Errors:
      ValueError  - Thrown if the assigned value is outside of the
                    valid range.
    """
    return( (self._flags & SMB2_FLAGS_PRIORITY_MASK) >> 4 )
  @flagPriority.setter
  def flagPriority( self, prioVal ):
    if( prioVal not in range( 8 ) ):
      raise ValueError( "Assigned value (%d) out of range." % prioVal )
    self._flags &= ~SMB2_FLAGS_PRIORITY_MASK
    self._flags |= (prioVal << 4)

  def dump( self, indent=0 ):
    # Produce a nicely formatted dump of the SMB2 header.
    #
    # Input:
    #   indent  - Number of spaces to indent the formatted output.
    #
    # Output: A string, presentng the formatted SMB2 header fields.
    #
    # Notes:  If the message is a request and the dialect is at least
    #         0x0300, the ChannelSequence (and a Reserved field) will
    #         replace the Status field (which would otherwise go unused
    #         in a request).  This is a protocol modification introduced
    #         with the 3.0 dialect.
    #
    ind = ' ' * indent
    cmdName  = self.commandName( self._command )
    cmdName  = "<unknown>" if( not cmdName ) else cmdName
    statName = NTStatus( self._status )
    statName = "\n" if( statName is None ) else " [%s]\n" % statName.name

    # Stuff...
    s  = ind + "ProtocolId...: %s\n" % hexstr( self._protocolId[:4] )
    s += ind + "StructureSize: 0x{0:04X} ({0:d})\n".format( self._headerSize )
    s += ind + "CreditCharge.: 0x{0:04X} ({0:d})\n".format( self._creditCharge )
    # Status/Reserved1
    if( self.flagReply or self._dialect < SMB2_DIALECT_300 ):
      s += ind + "Status.......: 0x{0:08X}".format( self._status ) + statName
    else:
      s += ind + "ChannelSeq...: 0x{0:04X} ({0:d})\n".format( self._channelSeq )
      s += ind + "Reserved1....: 0x{0:04X} ({0:d})\n".format( self._reserved1 )
    # More stuff...
    s += ind + "Command......: 0x{0:02X} ({0:d})".format( self._command ) \
             + " [{0:s}]\n".format( self.commandName( self._command ) )
    s += ind + "CreditReqResp: 0x{0:04X} ({0:d})\n".format( self.creditReqResp )
    s += ind + "Flags........: 0x{0:08X} ({0:d})\n".format( self._flags )
    # Flag subfields.
    s += ind + "  Response.....: %s\n" % self.flagReply
    s += ind + "  Async........: %s\n" % self.flagAsync
    s += ind + "  Related Op...: %s\n" % self.flagNext
    s += ind + "  Signed.......: %s\n" % self.flagSigned
    if( self._dialect >= SMB2_DIALECT_311 ):
      s += ind + "  Priority.....: {0:d}\n".format( self.flagPriority )
    s += ind + "  DFS Operation: %s\n" % self.flagDFS
    s += ind + "  SMB3.x Replay: %s\n" % self.flagReplay
    # Yet more stuff...
    s += ind + "NextCommand..: 0x{0:08X} ({0:d})\n".format( self._nextCommand )
    s += ind + "MessageId....: 0x{0:016X} ({0:d})\n".format( self._messageId )
    # AsyncId/Reserved2+TreeId
    if( self.flagAsync ):
      s += ind + "AsyncId......: 0x{0:016X} ({0:d})\n".format( self._asyncId )
    else:
      s += ind + "Reserved2....: 0x{0:08X} ({0:d})\n".format( self._reserved2 )
      s += ind + "TreeId.......: 0x{0:08X} ({0:d})\n".format( self._treeId )
    # SessionId and Signature
    s += ind + "SessionId....: 0x{0:016X} ({0:d})\n".format( self._sessionId )
    s += ind + "Signature....: ["
    tmp = (16 + indent)
    s += ('\n' + (' ' * tmp)).join( hexstrchop( self._signature, 32 ) ) + "]\n"
    return( s )

  def compose( self ):
    # Marshall the SMB2 header fields into a stream of bytes.
    #
    # Output: A string of bytes; the wire format of the SMB2 header.
    #
    # Notes:  It's probably okay if the dialect version isn't
    #         specified.  The default values of <channelSeq> and
    #         <reserved1> are zero, so the encoded format would be
    #         zero for either interpretation.
    #
    if( self.flagReply or (self._dialect < 0x0300) ):
      # Bytes 8..11 are <status>
      if( self.flagAsync ):
        # Bytes 32..39 are <async>
        msg = self._format_SMB2_StatAsync.pack( self._protocolId,
                                                self._headerSize,
                                                self._creditCharge,
                                                self._status,
                                                self._command,
                                                self._creditReqResp,
                                                self._flags,
                                                self._nextCommand,
                                                self._messageId,
                                                self._asyncId,
                                                self._sessionId,
                                                self._signature )
      else:
        # Bytes 32..39 are <reserved2>/<treeId>
        msg = self._format_SMB2_StatTreeId.pack( self._protocolId,
                                                 self._headerSize,
                                                 self._creditCharge,
                                                 self._status,
                                                 self._command,
                                                 self._creditReqResp,
                                                 self._flags,
                                                 self._nextCommand,
                                                 self._messageId,
                                                 self._reserved2,
                                                 self._treeId,
                                                 self._sessionId,
                                                 self._signature )
    else:
      # Bytes 8..11 are <channelSeq>/<reserved1>
      if( self.flagAsync ):
        # Bytes 32..39 are <async>
        msg = self._format_SMB2_cSeqAsync.pack( self._protocolId,
                                                self._headerSize,
                                                self._creditCharge,
                                                self._channelSeq,
                                                self._reserved1,
                                                self._command,
                                                self._creditReqResp,
                                                self._flags,
                                                self._nextCommand,
                                                self._messageId,
                                                self._asyncId,
                                                self._sessionId,
                                                self._signature )
      else:
        # Bytes 32..39 are <reserved2>/<treeId>
        msg = self._format_SMB2_cSeqTreeId.pack( self._protocolId,
                                                 self._headerSize,
                                                 self._creditCharge,
                                                 self._channelSeq,
                                                 self._reserved1,
                                                 self._command,
                                                 self._creditReqResp,
                                                 self._flags,
                                                 self._nextCommand,
                                                 self._messageId,
                                                 self._reserved2,
                                                 self._treeId,
                                                 self._sessionId,
                                                 self._signature )
    return( msg )


# Unit Tests ----------------------------------------------------------------- #
#

def _unit_test():
  # Module unit tests.
  #
  """
  Doctest:
    >>> _unit_test()
    Success
  """
  if( __debug__ ):
    # 1.Baseline test.
    #   Just verify that we can store and retrieve the basic attributes
    #   of an _SMB2_Header object.
    #
    hdr = _SMB2_Header( SMB2_COM_LOGOFF, SMB2_DIALECT_302 )
    hdr.creditCharge  = 213
    hdr.channelSeq    = 42607
    hdr.creditReqResp = 42
    hdr.flagReply     = False
    hdr.flagAsync     = False
    hdr.flagNext      = False
    hdr.flagSigned    = False
    hdr.flagPriority  = 5
    hdr.flagDFS       = True
    hdr.flagReplay    = False
    hdr.nextCommand   = 0x87654321
    hdr.messageId     = _SMB2_Header._format_Q.unpack( "Fooberry" )[0]
    hdr.treeId        = 0xBEADED
    hdr.sessionId     = _SMB2_Header._format_Q.unpack( "Icecream" )[0]
    hdr.signature     = "Reginald".center( 16 )
    # Create a header dump, compose a message, then parse the message.
    dmp0 = hdr.dump()
    msg  = hdr.compose()
    hdr = _SMB2_Header.parseMsg( msg, SMB2_DIALECT_302 )
    # Dump the newly reparsed header, and compare against the original.
    dmp1 = hdr.dump()
    if( dmp0 != dmp1 ):
      print "Failure: Reparsing a composed header resulted in differences."
      print "As composed:\n", dmp0
      print "As parsed:\n", dmp1
      return

    # 2.Add additional tests hereafter.

  # Bottom line.
  print "Success"


# ============================================================================ #
# Reginald fidgeted uneasily in his seat. "I realize", he said, pensively,
# "that I do have unusually large dorsal fins, for a carrot".
# ============================================================================ #
