# -*- coding: utf-8 -*-
# ============================================================================ #
#                               SMB1_Messages.py
#
# Copyright:
#   Copyright (C) 2014, 2015 by Christopher R. Hertel
#
# $Id: SMB1_Messages.py; 2018-02-21 06:29:52 -0600; Christopher R. Hertel$
#
# ---------------------------------------------------------------------------- #
#
# Description:
#   Carnaval Toolkit: SMB1 message parsing and composition.
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
#   - This module currently contains only enough code to handle the SMB1
#     protocol negotiation (NegProt) and echo exchanges.
#
#     There are no immediate plans to implement anything beyond those two
#     since, as of this writing (Jan, 2015), the only supported version
#     of Windows that does not include SMB2 is W2k3...and that is scheduled
#     to go out of support in mid-July, 2015.
#
#     The Linux CIFS kernel client now also supports SMB2, as does Samba.
#
#     The SMB1 protocol can (and should) now retire quietly, saying only
#     "Chaos, panic and disorder...my work here is done".
#
# ToDo:
#   - The _SMB1_Echo._dump() method should itemize the Flags and Flags2
#     bitfield values, a. la. Wireshark.
#   - Several methods are missing Doctests.
#   - Several setter methods do not assert that the assigned value is
#     within the valid range for the type (e.g., 0..255 for UCHAR).
#   - The ParseSMB1 function could be tightened up a bit.  Too much
#     redundant code.
#
# References:
#
#   [IMPCIFS] Hertel, Christopher R., "Implementing CIFS - The Common
#             Internet File System", Prentice Hall, August 2003
#             ISBN:013047116X
#             http://www.ubiqx.org/cifs/
#
#   [MS-CIFS] Microsoft Corporation, "Common Internet File System (CIFS)
#             Protocol Specification"
#             http://msdn.microsoft.com/en-us/library/ee442092.aspx
#
#   [MS-SMB]  Microsoft Corporation, "Server Message Block (SMB) Protocol
#             Specification"
#             http://msdn.microsoft.com/en-us/library/cc246231.aspx
#
#   [SMBDEAD] Jose Barreto, Microsoft, "The Deprecation of SMB1 – You
#             should be planning to get rid of this old SMB dialect"
#             https://blogs.technet.microsoft.com/josebda/2015/04/21/\
#             the-deprecation-of-smb1-you-should-be-planning-to-get-\
#             rid-of-this-old-smb-dialect/
#
# ============================================================================ #
#
"""Carnaval Toolkit: SMB1 message parsing and composition.

"SMB1" is a new name for an old protocol.

"SMB" stands for "Server Message Block".  The original SMB protocol was
developed by IBM in the early 1980's.  It was later extended and enhanced
by 3Com, IBM, Intel, and Microsoft, resulting in several dialects that
were produced for PC-DOS, MS-DOS, and OS/2.  The most recent dialect of
the original SMB protocol is known as the NT LAN Manager dialect
("NT LM 0.12").  It was created (quite a long time ago) for Windows NT.

The new "SMB1" name generally refers to the NT LAN Manager dialect. The
Windows NT SMB stack, however, is backward-compatible with older dialects
so "SMB1" can also refer to the original SMB protocol as a whole.

With Windows Vista, Microsft introduced a completely new (but strangely
familiar) protocol known as SMB2.  Since then, Microsoft has downgraded
SMB1 to the point that it is now officially deprecated.  There are plans
to remove SMB1 from future versions of Windows.

This module currently implements only three SMB1 protocol commands:
  * SMB_COM_NEGOTIATE
    SMB1 protocol negotiation can be used as an initial step toward
    SMB2/3 protocol negotiation.  That's why we bother.
  * SMB_COM_ECHO
    This is the SMB1 equivalent of a "ping".  It is typically used as a
    keepalive, or to test an established SMB connection.  It may be
    sent following an SMB_COM_NEGOTIATE if an SMB1 dialect has been
    negotiated.  It is possible that this will never be used.
  * SMB_COM_INVALID
    This is the designated bogus command.  It generates error
    response messages.

The SMB1 protocol is specified in [MS-CIFS] and [MS-SMB].  [IMPCIFS]
provides a guide to SMB1 and related protocols, and their implementation.

CONSTANTS:

  Protocol Constants:
    SMB_MSG_PROTOCOL  : \\xFFSMB; SMB message prefix (protocol ID).

  Supported SMB1 Commands:
    SMB_COM_ECHO      : SMB echo request.
    SMB_COM_NEGOTIATE : Protocol dialect negotiation.
    SMB_COM_INVALID   : Designated invalid command.

  SMB1_Header.Flags:
  (This list is incomplete.  See [MS-CIFS; 2.2.3.1] for more.)
    SMB_FLAGS_CASE_INSENSITIVE    : Obsolete; Ignore pathname case.
                                    Windows sets this to 1.
    SMB_FLAGS_CANONICALIZED_PATHS : Obsolete; DOS pathnames.
                                    Windows sets this to 1.
    SMB_FLAGS_REPLY               : Request/Reply (0/1) flag.
    SMB_FLAGS_MASK                : Bitmask of all valid Flags bits.

  SMB1_Header.Flags2:
  (This list is incomplete.  See [MS-CIFS; 2.2.3.1] and [MS-SMB; 2.2.3.1].)
    SMB_FLAGS2_LONG_NAMES         : Long name support.
    SMB_FLAGS2_EAS                : Support for OS/2 Extended Attributes.
    SMB_FLAGS2_SIGNATURE_REQUIRED : Client requires message signing.
    SMB_FLAGS2_EXTENDED_SECURITY  : Extended Security support.
    SMB_FLAGS2_NT_STATUS          : Use NT status codes (0=use DOS).
    SMB_FLAGS2_UNICODE            : Unicode support.
    SMB_FLAGS2_MASK               : Bitmask of all valid Flags2 bits.

  Other Values:
    SMB_NO_DIALECT    : Used in the SMB1 NegProt response to indicate
                        that none of the dialects offered were accepted.
    SMB_TID_INVALID   : Used as a Treeconnect ID (TID) in SMB_COM_ECHO
                        when no Tree Connect has been made.
"""

# Imports -------------------------------------------------------------------- #
#
#   struct    - Binary data packing and parsing tools.
#
#   os        - We require getpid() to provide the ProcessID.
#   random    - Used to generate the Multiplex ID values.
#   binascii  - A cheap crc32 can be used to validate SMB_Echo payloads.
#   SMB_Core  - SMB exception class.
#   HexDump   - Local collection of binary to hex-string utilities.
#

import struct       # Byte-wise data handling.

from os             import getpid     # Get the current process ID.
from random         import randint    # Generate a random integer.
from binascii       import crc32      # Simple 32-bit checksum.
from SMB_Core       import SMBerror   # SMBerror exception class.
from common.HexDump import hexstr     # Produce readable output.
from common.HexDump import hexstrchop # Ditto, but with linewrap.


# Constants ------------------------------------------------------------------ #
#

# Protocol constants
SMB_MSG_PROTOCOL  = '\xFFSMB' # Standard SMB message prefix (protocol ID).

# Supported SMB1 Commands
SMB_COM_ECHO      = 0x2B      # Echo (ping).
SMB_COM_NEGOTIATE = 0x72      # Protocol Negotiation.
SMB_COM_INVALID   = 0xFE      # Officially invalid command code.

# SMB1 Header Flags bits (incomplete list; see [MS-CIFS;2.2.3.1])
SMB_FLAGS_CASE_INSENSITIVE    = 0x08  # 1=Case insensitive pathnames.
SMB_FLAGS_CANONICALIZED_PATHS = 0x10  # 1=Path in DOS format.
SMB_FLAGS_REPLY               = 0x80  # 0=Request, 1=Reply.
SMB_FLAGS_MASK                = 0xFB  # ALL defined SMB1.Flags bits.

# SMB1 Header Flags2 bits (incomplete list; see [MS-CIFS;2.2.3.1]
#                                           and [MS-SMB;2.2.3.1])
SMB_FLAGS2_LONG_NAMES         = 0x0001  # 1=Long names allowed.
SMB_FLAGS2_EAS                = 0x0002  # 1=Extended Attributes supported.
SMB_FLAGS2_SIGNATURE_REQUIRED = 0x0010  # 1=Client requires signing.
SMB_FLAGS2_EXTENDED_SECURITY  = 0x0800  # 1=Extended Security supported.
SMB_FLAGS2_NT_STATUS          = 0x4000  # 1=Use NT Status codes (not DOS).
SMB_FLAGS2_UNICODE            = 0x8000  # 1=Strings are Unicode.
SMB_FLAGS2_MASK               = 0xFC5F  # ALL defined SMB1.Flags2 bits.

# SMB1 Special Values.
#
_USHORT_MAX     = 0xFFFF      # Bitmask for Unsigned Short (USHORT) values.
SMB_NO_DIALECT  = _USHORT_MAX # Used in SMB_COM_NEGOTIATE to indicate that
                              # none of the dialects offered by the client
                              # were acceptable to the server.
                              # See [MS-CIFS; 2.2.4.52.2].
SMB_TID_INVALID = _USHORT_MAX # "No TID" TreeID value used in SMB_COM_ECHO.
                              # See [MS-CIFS; 3.2.4.1].


# Globals -------------------------------------------------------------------- #
#
#   _format_SMB1hdr     - The layout of an SMB1 header as a Python Struct
#                         object.  Note that the '<' character indicates
#                         little-endian encoding, which is the standard
#                         for SMB.  See the _SMB1_Header.compose() method
#                         or [MS-CIFS; 2.2.3.1] for the full layout.
#   _format_SMB1BH      - Typically used when the WordCount is zero, this
#                         structure maps to the WordCount (a byte) followed
#                         immediately by the ByteCount (two bytes).  Any
#                         data would follow the ByteCount.
#   _format_SMB1BHH     - Maps to a byte (WordCount) followed by two shorts.
#                         Used, for example, when creating a CORE protocol
#                         NegProt Response such as the "no dialect selected"
#                         message.
#   _format_SMB1H       - Extract an unsigned short, converting it from
#                         SMB byte order.
#
#   _DEF_FLAGS_REQ      - Default Flags value to use in a request.
#   _DEF_FLAGS_RSP      - Default Flags value to use in a response.
#   _DEF_FLAGS2         - Default Flags2 value for requests and responses.
#

_format_SMB1hdr = struct.Struct( '<4s B L B H H 8s H H H H H' )
_format_SMB1BH  = struct.Struct( '<B H' )
_format_SMB1BHH = struct.Struct( '<B H H' )
_format_SMB1H   = struct.Struct( '<H' )

_DEF_FLAGS_REQ  = SMB_FLAGS_CASE_INSENSITIVE | SMB_FLAGS_CANONICALIZED_PATHS
_DEF_FLAGS_RSP  = SMB_FLAGS_REPLY | _DEF_FLAGS_REQ
_DEF_FLAGS2     = SMB_FLAGS2_LONG_NAMES | SMB_FLAGS2_NT_STATUS \
                | SMB_FLAGS2_UNICODE


# Classes -------------------------------------------------------------------- #
#

class _SMB1_Header( object ):
  # SMBv1 Message Header.
  #
  def __init__( self,
                command     = SMB_COM_INVALID,# Command code.
                status      = 0L,             # NT Error code (0 == success).
                flags       = 0,              # LANMAN1.0 Flags field.
                flags2      = 0,              # LANMAN1.2 Flags2 field.
                pid         = 0L,             # Process ID (32 bits).
                tid         = 0,              # Tree Connect ID.
                uid         = 0,              # (Virtual) User ID.
                mid         = 0 ):            # Multiplex ID.
    # Create an SMB1 message header object.
    #
    # Input:
    #   command     - The SMB1 command code to be used.
    #                 Default: The designated invalid SMB1 command code.
    #   status      - 32-bit NT status code.  Always zero for requests.
    #                 If None, zero (success) is used.
    #   flags       - Flags.
    #                 If None, _DEF_FLAGS_REQ is used.
    #   flags2      - More flags.
    #                 If None, _DEF_FLAGS2 is used.
    #   pid         - 32-bit process ID.
    #                 If None, the current process ID is used.
    #   tid         - 16-bit Tree ID.
    #                 If None, SMB_TID_INVALID is used used.
    #   uid         - 16-bit user authentication ID.
    #                 If None, zero (0) is used.  See [MS-CIFS; 3.2.4.1].
    #   mid         - 16-bit Multiplex ID.
    #                 If None, a pseudo-random number is used.
    #
    # Notes:
    #   The default command value is SMB_COM_INVALID, which was reserved
    #   in OS/2 LAN Manager documentation as an officially non-existant
    #   command.  This default must be overridden.
    #
    #   Other than the command code, all fields default to zero, including
    #   the flags fields.  Passing None for a given field will override the
    #   zero default and assign an alternative value, as described above.
    #
    #   There are a handful of header field attributes that are not exposed
    #   through this initialization method:
    #   * _protocol     - This is always "\xFFSMB", so there is no reason
    #                     to make it available as a parameter.
    #   * _secFeatures  - This is generally used for message signing,
    #                     although it can also be used for other purposes
    #                     when SMB is being carried over a connectionless
    #                     transport (see [MS-CIFS; 2.2.3.1]).  For signing,
    #                     it must be all zeros when the signature is
    #                     calculated over the completed (unsigned) message.
    #                     The signature is written to the header afterward.
    #   * _reserved     - This is a 2-byte reserved field that must be set
    #                     to zero.
    #   As is common in this collection of modules, the rules can be
    #   broken by directly setting the attribute to the desired value.
    #
    self._protocol    = SMB_MSG_PROTOCOL
    self.command      = SMB_COM_INVALID if( command is None ) else command
    self.status       = 0               if( status  is None ) else status
    self.flags        = _DEF_FLAGS_REQ  if( flags   is None ) else flags
    self.flags2       = _DEF_FLAGS2     if( flags2  is None ) else flags2
    self._secFeatures = (8 * '\0')
    self._reserved    = 0
    self.pid          = getpid()        if( pid is None ) else pid
    self.tid          = SMB_TID_INVALID if( tid is None ) else tid
    self.uid          = 0               if( uid is None ) else uid
    self.mid          = randint( 16, 64000 ) if( mid is None ) else mid

  @property
  def command( self ):
    """SMB1 Command code; unsigned 8-bit integer.
    Errors:
      AssertionError  - Thrown if the assigned value is either negative
                        or greater than 255 (i.e., is not an unsigned
                        8-bit integer value).
      TypeError       - Thrown if the assigned value is of a type that
                        cannot be converted to an integer.
      ValueError      - Thrown if the assigned value is a convertable
                        type (e.g., <str>), but still cannot be
                        converted to an integer.
    """
    return( self._command )
  @command.setter
  def command( self, command=None ):
    command = int( command )
    assert( (0xFF & command) == command ), \
      "Command code %s out of range." % hexnum2str( command )
    self._command = command

  @property
  def status( self ):
    """NT Status code; unsigned 32-bit integer.
    Errors:
      AssertionError  - Thrown if the assigned value, interpreted as an
                        integer, does not fit into a 32-bit unsigned
                        integer.
      TypeError       - Thrown if the assigned value is of a type that
                        cannot be converted to an integer.
      ValueError      - Thrown if the assigned value is a convertable
                        type (e.g., <str>), but still cannot be
                        converted to an integer (e.g.,
                        int( "feldspar" )).
    """
    return( self._status )
  @status.setter
  def status( self, status=None ):
    status = long( status )
    assert( (0xFFFFFFFF & status) == status ), \
      "Status code %s out of range." % hexnum2str( status )
    self._status = status

  @property
  def flags( self ):
    """LANMAN1.0 Flags field; unsigned 8-bit integer.
    Errors:
      TypeError   - Thrown if the assigned value is of a type that
                    cannot be converted to an integer.
      ValueError  - Thrown if the assigned value is a convertable
                    type (e.g., <str>), but still cannot be converted
                    to an integer.
    """
    return( self._flags )
  @flags.setter
  def flags( self, flags=None ):
    self._flags = ( SMB_FLAGS_MASK & int( flags ) )

  @property
  def flags2( self, flags2=None ):
    """LANMAN1.2 Flags2 field; unsigned 16-bit integer.
    Errors:
      TypeError   - Thrown if the assigned value is of a type that
                    cannot be converted to an integer.
      ValueError  - Thrown if the assigned value is a convertable
                    type (e.g., <str>), but still cannot be converted
                    to an integer.
    """
    return( self._flags2 )
  @flags2.setter
  def flags2( self, flags2=None ):
    self._flags2 = ( SMB_FLAGS2_MASK & int( flags2 ) )

  @property
  def pid( self ):
    """Client process ID; unsigned 32-bit integer.
    Errors:
      AssertionError  - Thrown if the given PID value is negative.
      TypeError       - Thrown if the assigned value is of a type that
                        cannot be converted to an integer.
      ValueError      - Thrown if the assigned value is a convertable
                        type (e.g., <str>), but still cannot be
                        converted to an integer.
    """
    return( self._pidHigh << 16 | self._pidLow )
  @pid.setter
  def pid( self, pid=None ):
    pid = long( pid )
    assert ( pid >= 0 ), "PID must be a positive value."
    self._pidLow  = int( _USHORT_MAX & pid )
    self._pidHigh = int( (pid >> 16) & _USHORT_MAX )

  @property
  def tid( self ):
    """TreeConnect ID; unsigned 16-bit integer.
    Errors:
      TypeError   - Thrown if the assigned value is of a type that
                    cannot be converted to an integer.
      ValueError  - Thrown if the assigned value is a convertable
                    type (e.g., <str>), but still cannot be converted
                    to an integer.
    """
    return( self._tid )
  @tid.setter
  def tid( self, tid=None ):
    self._tid = ( _USHORT_MAX & int( tid ) )

  @property
  def uid( self ):
    """[Virtual] User ID: unsigned 16-bit integer.
    Errors:
      TypeError   - Thrown if the assigned value is of a type that
                    cannot be converted to an integer.
      ValueError  - Thrown if the assigned value is a convertable
                    type (e.g., <str>), but still cannot be converted
                    to an integer.
    """
    return( self._uid )
  @uid.setter
  def uid( self, uid=None ):
    self._uid = ( _USHORT_MAX & int( uid ) )

  @property
  def mid( self ):
    """Multiplex ID: unsigned 16-bit integer.
    Errors:
      TypeError   - Thrown if the assigned value is of a type that
                    cannot be converted to an integer.
      ValueError  - Thrown if the assigned value is a convertable
                    type (e.g., <str>), but still cannot be converted
                    to an integer.
    """
    return( self._mid )
  @mid.setter
  def mid( self, mid=None ):
    self._mid = ( _USHORT_MAX & int( mid ) )

  def dump( self, indent=0 ):
    # Produce a pretty-printed representation of the SMB1 header.
    #
    # Input:  indent  - Number of spaces to indent the formatted output.
    #
    # Output: A string, containing the formatted SMB1 header fields.
    #
    # ToDo:   Print Flags and Flags2 bitfields that are set.
    #
    ind = ' ' * indent
    sig = ''.join( '{0:02x}'.format( ord( b ) ) for b in self._secFeatures )
    s = ind + "Protocol..: %s\n"     % hexstr( self._protocol[:4] ) \
      + ind + "Command...: 0x%02X\n" % self._command                \
      + ind + "NT Status.: 0x%08X\n" % self._status                 \
      + ind + "Flags.....: 0b{0:08b}\n".format( self._flags )       \
      + ind + "Flags2....: 0b{0:016b}\n".format( self._flags2 )     \
      + ind + "PIDHigh...: 0x%04X\n" % self._pidHigh                \
      + ind + "Signature.: 0x%s\n"   % sig                          \
      + ind + "Reserved..: 0x%04X\n" % self._reserved               \
      + ind + "TID.......: 0x%04X\n" % self._tid                    \
      + ind + "PIDLow....: 0x%04X\n" % self._pidLow                 \
      + ind + "    PID ==> 0x{0:08X} ({0:d})\n".format( self.pid )  \
      + ind + "UID.......: 0x%04X\n" % self._uid                    \
      + ind + "MID.......: 0x%04X\n" % self._mid
    return( s )

  def compose( self ):
    # Marshall the SMB1 header fields into a stream of bytes.
    #
    return( _format_SMB1hdr.pack( self._protocol[:4],   # 4s; Protocol prefix.
                                  self._command,        # B;  Command code.
                                  self._status,         # L;  Error codes.
                                  self._flags,          # B;  LANMAN 1.0 flags.
                                  self._flags2,         # H;  LANMAN 1.2 flags.
                                  self._pidHigh,        # H;  Upper PID bytes.
                                  self._secFeatures,    # 8s; Signature field.
                                  self._reserved,       # H;  Must Be Zero.
                                  self._tid,            # H;  TreeConnectId.
                                  self._pidLow,         # H;  Lower PID bytes.
                                  self._uid,            # H;  aUthId.
                                  self._mid ) )         # H;  MultiplexId.


class SMB1_NegProt_Request( _SMB1_Header ):
  """SMBv1 Negotiate Protocol Request message.

  The Negotiate Protocol (or NegProt) request is used by SMB clients when
  connecting to SMB servers.  It is used to determine the greatest common
  protocol and dialect between the two, and also allows the server to
  indicate a set of supported features.
  """
  def __init__( self,
                dialects = [ "2.002", "2.???" ],
                flags    = _DEF_FLAGS_REQ,
                flags2   = _DEF_FLAGS2,
                pid      = None,
                mid      = None ):
    """Create an SMB1 NegProt request that negotiates SMB2.0 or above.

    Input:
      dialects  - A list of SMB dialect strings to be included (in
                  the presented order) in the request.  By default,
                  the list will be ["2.002", "2.???"].  These are the
                  two strings that may be used to negotiate the SMB2+
                  protocol from an SMB NegProt.
      flags     - An unsigned 8-bit field made up of LANMAN1.0 Flags
                  bits.  If not given, default values will be used.
      flags2    - An unsigned 16 bit field made up of LANMAN1.2 Flags2
                  bits.  If not given, default values will be used.
      pid       - The value to be sent as the process ID.  If not
                  given (None), the actual process ID will be used.
      mid       - The value to be sent as the Multiplex ID (MID).
                  If not given, a pseudo-random number will be used.

    Notes:  The "2.002" dialect string asks the server whether it
            specifically supports the SMB2.0 dialect (aka. 2.002).
            The "2.???" dialect string was introduced with SMB2.1.
            It asks whether the server supports any SMB2+ dialect.
            Some Windows SMB2.0 servers only recognize the "2.002"
            string, while others recognize both.

            It is completely safe and normal for the client to send
            both dialect strings.  The client may send only "2.002" if
            it will only support the 2.0 dialect.  If "2.???" is sent,
            the server will expect the client to continue negotiations
            by sending an SMB2 NegProt after receiving the server's
            initial response.
    """
    # Initialize the object.
    self.dialects = dialects
    super( SMB1_NegProt_Request, self ).__init__( command = SMB_COM_NEGOTIATE,
                                                  flags   = flags,
                                                  flags2  = flags2,
                                                  pid     = pid,
                                                  mid     = mid )

  @property
  def dialects( self ):
    """The list of available dialects.
    Errors:
      AssertionError  - Thrown if a value in the list being assigned is
                        not of type string (<str>).
    """
    return( self._dialects )
  @dialects.setter
  def dialects( self, dialects=None ):
    dbytes = ''
    for dialect in dialects:
      # Check each element in the list, and also compose an SMB1 data blob.
      assert isinstance( dialect, str ), \
        "SMB1 protocol dialect identifiers must be strings."
      dbytes += '\x02%s\0' % dialect  # Build the SMB_Data block.
    # Now that the input has been checked, update the attributes.
    self._dialects = dialects
    self._smbData  = dbytes

  def dump( self, indent=0 ):
    """Produce a formatted representation of the SMB1 NegProt request.

    Input:  indent  - The number of spaces to indent the formatted
                      output.

    Output: The SMB1 NegProt request message, formatted for display and
            returned as a string.

    Doctest:
      >>> print SMB1_NegProt_Request( pid=987654321, mid=0x8899 ).dump()
      NegProt Request
      Header:
        Protocol..: \\xFFSMB
        Command...: 0x72
        NT Status.: 0x00000000
        Flags.....: 0b00011000
        Flags2....: 0b1100000000000001
        PIDHigh...: 0x3ADE
        Signature.: 0x0000000000000000
        Reserved..: 0x0000
        TID.......: 0x0000
        PIDLow....: 0x68B1
            PID ==> 0x3ADE68B1 (987654321)
        UID.......: 0x0000
        MID.......: 0x8899
      SMB_Parameters:
        WordCount.: 0x00 (0)
      SMB_Data:
        ByteCount.: 0x000E (14)
        ..........: <02>2.002\\0
        ..........: <02>2.???\\0
      <BLANKLINE>
    """
    ind = ' ' * indent
    s  = ind + "NegProt Request\nHeader:\n"
    s += super( SMB1_NegProt_Request, self ).dump( indent + 2 )
    s += ind + "SMB_Parameters:\n"
    s += ind + "  WordCount.: 0x00 (0)\n"
    s += ind + "SMB_Data:\n" + ind
    s += "  ByteCount.: 0x{0:04X} ({0:d})\n".format( len( self._smbData ) )

    # Split the message payload using the string terminator as the delimiter.
    for d in self._smbData.split( '\0' ):
      if( d ):
        # Each dialect string should be preceeded by 0x02.
        if( '\x02' == d[0] ):
          s += "  ..........: <02>%s\\0\n" % hexstr( d[1:] )
        else:
          s += "  ..........: %s\\0\n" % hexstr( d )
    return( s )

  def compose( self ):
    """Compose an SMB1 Negotiate Protocol Request.

    Output: A string of bytes, which are (should be) the wire format of
            an SMB1 Negotiate Protocol Request.

    Doctest:
      >>> len( SMB1_NegProt_Request().compose() )
      49
    """
    s  = super( SMB1_NegProt_Request, self ).compose()
    s += _format_SMB1BH.pack( 0, len( self._smbData ) )
    return( s + self._smbData )


class SMB1_NegProt_Response( _SMB1_Header ):
  """SMBv1 Negotiate Protocol Response message.

  When using an SMB1 NegProt to negotiate an SMB2 dialect, there are four
  possible responses from the server:

  1)  If the client sends and the server accepts the "2.???" dialect
      string, then the server should send an SMB2_Negotiate response
      indicating that the 0x02FF dialect has been selected.  0x02FF
      indicates that further processing is required, and the client
      must send a subsequent SMB2_Negotiate request.

  2)  If the client sends and the server accepts the "2.002" dialect
      string, then the server should send an SMB2_Negotiate response
      with the 0x0202 dialect selected.  0x0202 indicates that the
      "2.002" dialect has been successfully negotiated.

  In cases 1 and 2, the server should respond with an SMB2 (not SMB1)
  Negotiate Response message.

  3)  If the server supports SMB1 or earlier SMB dialect:
      If the client didn't send either SMB2 dialect string, or if the
      server doesn't support SMB2, then the server should complete SMB
      protocol negotiation.  This means that the server should either
      select one of the SMB dialects presented by the client, or return
      an index value of 0xFFFF to indicate that no suitable dialect was
      offered.

  4)  If the server does not support SMB:
      If the client did not offer any acceptable SMB2 dialect strings,
      the server should drop the connection.

  So, the server will only return an SMB NegProt response if it actually
  supports the legacy SMB protocol (SMB1 or earlier).

  As currently implemented, this class is really only suited for sending
  an 0xFFFF response to indicate that no SMB dialect was selected.  Note,
  however, that doing so will (falsely?) indicate to the client that the
  responding node does support some dialect of the original SMB protocol.

  So, in reality, SMB2 servers based upon this module should never send
  an SMB1 Negprot response.  SMB2 clients based on this module may
  receive an SMB1 NegProt response with an index value of 0xFFFF.
  """
  def __init__( self,
                dIndex = SMB_NO_DIALECT,
                flags  = _DEF_FLAGS_RSP,
                flags2 = _DEF_FLAGS2,
                pid    = 0,
                mid    = 0 ):
    """Create an SMB1 NegProt response message.

    Input:
      flags   - An unsigned 8-bit field made up of LANMAN1.0 Flags
                bits.  If not given, default values will be used.
      flags2  - An unsigned 16 bit field made up of LANMAN1.2 Flags2
                bits.  If not given, default values will be used.
      pid     - The value to be sent as the process ID.  The PID in
                the response must match the request PID.
      mid     - The value to be sent as the Multiplex ID (MID).
                The response MID must match the request MID.
      dIndex  - The index of the selected dialect.  Index values start
                at zero.  0xFFFF (-1, the default) indicates that no
                dialect was selected.
    """
    # Initialize the object.
    self.dIndex = dIndex
    super( SMB1_NegProt_Response, self ).__init__( command = SMB_COM_NEGOTIATE,
                                                   flags   = flags,
                                                   flags2  = flags2,
                                                   pid     = pid,
                                                   mid     = mid )
  @property
  def dIndex( self ):
    """The dialect index; an unsigned 16-bit integer.
    Errors:
      TypeError   - Thrown if the assigned value is of a type that
                    cannot be converted to an integer.
      ValueError  - Thrown if the assigned value is a convertable
                    type (e.g., <str>), but still cannot be converted
                    to an integer (e.g., int( "spoo" )).
    Notes:  If a negative value is assigned, it will be converted to
            the designated 'no match' value: 0xFFFF.  0xFFFF is also
            ((uint16_t)-1).  The wire format of the Dialect Index is
            an unsigned 16-bit integer.
    """
    return( self._dIndex )
  @dIndex.setter
  def dIndex( self, dIndex=None ):
    dIndex = int( dIndex )
    if( dIndex < 0 ):
      self._dIndex = SMB_NO_DIALECT
    else:
      self._dIndex = ( _USHORT_MAX & dIndex )

  def dump( self, indent=0 ):
    """Produce a formatted representation of the SMB NegProt response.

    Input:  indent  - The number of spaces to indent the formatted
                      output.

    Output: The SMB NegProt response message, formatted for display and
            returned as a string.

    Doctest:
      >>> s1npr = SMB1_NegProt_Response( pid=987654321, mid=0x8899 )
      >>> s1npr.dIndex = -15
      >>> print s1npr.dump()
      NegProt Response
      Header:
        Protocol..: \\xFFSMB
        Command...: 0x72
        NT Status.: 0x00000000
        Flags.....: 0b10011000
        Flags2....: 0b1100000000000001
        PIDHigh...: 0x3ADE
        Signature.: 0x0000000000000000
        Reserved..: 0x0000
        TID.......: 0x0000
        PIDLow....: 0x68B1
            PID ==> 0x3ADE68B1 (987654321)
        UID.......: 0x0000
        MID.......: 0x8899
      SMB_Parameters:
        WordCount.....: 0x01 (1)
        Dialect Index.: 0xFFFF (65535)
      SMB_Data:
        ByteCount.....: 0x0000 (0)
      <BLANKLINE>
    """
    ind = ' ' * indent
    # Compose the dump.
    s  = ind + "NegProt Response\n"
    s += ind + "Header:\n"
    s += super( SMB1_NegProt_Response, self ).dump( indent + 2 )
    s += ind + "SMB_Parameters:\n"
    s += ind + "  WordCount.....: 0x01 (1)\n"
    s += ind + "  Dialect Index.: 0x{0:04X} ({0:d})\n".format( self._dIndex )
    s += ind + "SMB_Data:\n"
    s += ind + "  ByteCount.....: 0x0000 (0)\n"
    return( s )

  def compose( self ):
    """Compose an SMB1 Negotiate Protocol Response.

    Output: A string of bytes, which are (should be) the wire format of
            an SMB1 Negotiate Protocol Response.

    Notes:  Technically, the SMB Negprot Response message composed here
            matches the Core Protocol dialect format.  That's okay for
            an incomplete SMB implementation, particularly since the
            only response we anticipate creating is the "no dialect
            selected" response.  ...or maybe an error response (which
            shouldn't happen).

    Doctest:
      >>> foo = SMB1_NegProt_Response().compose()
      >>> print '\\n'.join( hexstrchop( foo, 48 ) )
      \\xFFSMBr\\x00\\x00\\x00\\x00\\x98\\x01\\xC0\\x00\\x00\\x00
      \\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00
      \\x00\\x00\\x00\\x00\\x00\\x01\\xFF\\xFF\\x00\\x00
    """
    s = super( SMB1_NegProt_Response, self ).compose()
    return( s + _format_SMB1BHH.pack( 1, self._dIndex, 0 ) )


class _SMB1_Echo( _SMB1_Header ):
  # Generic SMB1 echo message.
  #
  # There are two differences between the request and response messages.
  # * In the request, the SMB_FLAGS_REPLY bit is clear.  It is set in the
  #   response.
  # * In the request, the first parameter word is the EchoCount.
  #   In the response, the same offset hods the SequenceNumber.
  #
  def __init__( self,
                paramWord0= 1,
                payload   = '',
                flags     = _DEF_FLAGS_REQ,
                flags2    = _DEF_FLAGS2,
                pid       = None,
                mid       = None,
                tid       = SMB_TID_INVALID ):
    # Create an SMB1 Echo Message.
    #
    # Input:
    #   paramWord0  - The first (zeroth) parameter word in the
    #                 SMB_Parameters.Words array (see [MS-CIFS;2.2.3.2]).
    #   payload     - The contents of the SMB_Parameters.Bytes portion
    #                 of the message.  This is just a bunch of bytes that
    #                 get sent along in the Echo message.
    #   flags       - LANMAN1.0 Flags field.
    #   flags2      - LANMAN1.2 Flags2 field.
    #   pid         - Process ID.
    #   mid         - Multiplex ID.
    #   tid         - TreeConnect ID.  This defaults to 0xFFFF, which is
    #                 the designated "I have no TID" value.
    #
    super( _SMB1_Echo, self ).__init__( command = SMB_COM_ECHO,
                                        flags   = flags,
                                        flags2  = flags2,
                                        pid     = pid,
                                        mid     = mid,
                                        tid     = tid )
    self._setParamWord0( paramWord0 )
    self.payload = payload

  def _setParamWord0( self, paramWord0=1 ):
    # Setter function for the parameter word (echoCount|seqNumber).
    paramWord0 = int( paramWord0 )
    assert( (0 <= paramWord0 <= _USHORT_MAX) ), \
      "Value out of range: %d." % paramWord0
    self._paramWord0 = paramWord0

  @property
  def payload( self ):
    """Echo message payload; A string of bytes.

    Errors:
      AssertionError  - Thrown if the input could not be converted
                        into a string, or if the length of the
                        payload exceeds the maximum payload size.

    Notes:  The payload is the string of bytes sent along with the
            echo messages.  The payload may be given as one of the
            following:
              None          - The empty string will be used.
              <str>         - The given string will be used as-is.
              <bytearray>   - Will be converted to type <str>.
              <unicode>     - Unicode strings are converted to type
                              <str> using "utf_8" encoding.
    """
    return( self._payload )
  @payload.setter
  def payload( self, payload='' ):
    # Validate and/or massage the input.
    pl_type = type( payload )
    if( pl_type is str ):
      pass
    elif( payload is None ):
      payload = ''
    elif( pl_type is bytearray ):
      payload = str( payload )
    elif( pl_type is unicode ):
      payload = payload.encode( "utf_8" )
    else:
      assert( True ), \
        "Unwilling to convert <%s> input to <str> type." % pl_type.__name__
    # Survived the input type tests; make sure we don't exceed the limit.
    assert( len( payload ) <= _USHORT_MAX ), \
        "Payload length (%d) exceeds the 65535-byte maximum." % len( payload )
    # All good.
    self._payload = payload
    self._cksum   = None

  @property
  def cksum( self ):
    """Calculate and return a crc32 checksum over the payload.
    Notes:  The checksum is cached internally.  If it already present,
            the cached value is returned.  Otherwise, it is calculated,
            stored, and returned.
            So... if you choose to bypass the <.payload> property and
            set the <._payload> attribute directly, it is important
            to also clear the <._cksum> attribute (set it to None).
    Doctest:
      >>> cs = SMB1_Echo_Request( 0, "Vroo!" ).cksum
      >>> print "0x{0:8X}".format( cs )
      0x5DC04E4A
    """
    if( not self._cksum ):
      self._cksum = ( crc32( self._payload ) & 0xffffffff )
    return( self._cksum )

  def _dump( self, indent=0 ):
    # Internal method used to dump both request and response Echos.
    #
    assert( self._flags is not None ), "Internal error; _dump( flags=None )"

    # Set up the strings for request vs. response.
    if( 0 == (self._flags & SMB_FLAGS_REPLY) ):
      paramName = "EchoCount....."
      direction = "Request"
    else:
      paramName = "SequenceNumber"
      direction = "Response"

    # Fairly normal message dump...
    ind  = ' ' * indent
    pw0  = self._paramWord0
    plen = len( self._payload )
    # Compose the dump.
    s  = ind + "Echo %s\n" % direction
    s += ind + "Header:\n"
    s += super( _SMB1_Echo, self ).dump( indent + 2 )
    s += ind + "SMB_Parameters:\n"
    s += ind + "  WordCount.....: 0x01 (1)\n"
    s += ind + "    {0:}: 0x{1:04X} ({1:d})\n".format( paramName, pw0 )
    s += ind + "SMB_Data:\n"
    s += ind + "  ByteCount.....: 0x{0:04X} ({0:d})\n".format( plen )
    s += ind + "    Data..........:"
    hexlines = hexstrchop( self._payload, 66 )
    if( not hexlines ):
      s += '\n'
    elif( (len( hexlines ) == 1) and (len( hexlines[0] ) <= 52) ):
      s += ' ' + hexlines[0] + '\n'
    else:
      prefix = '\n' + (' ' * (indent+6))
      s += prefix + prefix.join( hexlines ) + '\n'
    s += ind + "      (Checksum) => 0x{0:08X}\n".format( self.cksum )
    return( s )

  def compose( self ):
    """Compose an SMB1 Echo message.

    Output: A string of bytes, which are (should be) the wire format
            of an SMB1 Echo message.

    Doctest:
      >>> er = SMB1_Echo_Request( pid=165449, mid=64128 )
      >>> print '\\n'.join( hexstrchop( er.compose(), 48 ) )
      \\xFFSMB+\\x00\\x00\\x00\\x00\\x18\\x01\\xC0\\x02\\x00\\x00
      \\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\xFF\\xFFI
      \\x86\\x00\\x00\\x80\\xFA\\x01\\x01\\x00\\x00\\x00
    """
    s  = super( _SMB1_Echo, self ).compose()
    s += _format_SMB1BHH.pack( 1, self._paramWord0, len( self._payload ) )
    return( s + self._payload )


class SMB1_Echo_Request( _SMB1_Echo ):
  """SMBv1 Echo Request message.

  A valid SMB_COM_NEGOTIATE exchange must occur before an SMB_COM_ECHO
  request may be sent to the server.  This requirement comes from the
  fact that the SMB Echo was introduced with the LAN Manager 1.0
  dialect of SMB, which means that the original CORE protocol did not
  support SMB Echo.  Until the NegProt is complete, you can't really
  know whether the request is allowed.

  The SMB_COM_ECHO can, however, be sent before a valid SMB session has
  been created.  That is, before an SMB_COM_SESSION_SETUP_ANDX exchange
  has occurred.  No authentication necessary.  This may (correctly) be
  seen as a security flaw in SMB1 since it allows any node out there to
  send echo requests, possibly with a large <echoCount> value.  SMB2
  does, in fact, require authentication before an SMB2 Echo can occur.
  """

  def __init__( self,
                echoCount = 1,
                payload   = '',
                flags     = _DEF_FLAGS_REQ,
                flags2    = _DEF_FLAGS2,
                pid       = None,
                mid       = None,
                tid       = SMB_TID_INVALID ):
    """Create an SMB1 Echo request message.

    Input:
      echoCount - An unsigned short integer value (an integer in the
                  range 0..65535) indicating the number of response
                  messages that the server should send.  The default
                  is one (1).  See the notes, below.
      payload   - The byte stream to be sent to and echoed back by the
                  SMB server.  The default value is the empty string
                  (zero bytes).
      flags     - This is the SMB1 Header Flags field.  If not given,
                  a default value will be used.
      flags2    - The SMB1 Header Flags2 field.  If not given, a
                  default value will be used.
      pid       - The process ID.  If not given, getpid() will be used
                  to retrieve the current process ID.  The pid value is
                  limited to 32 bits.
      mid       - Multiplex ID.  If not given, a pseudo-random value
                  will be used.
      tid       - TreeConnect ID.  If not given, the Invalid TID value
                  will be used.  This is typically the best choice.

    Notes:  SMB_COM_ECHO is an oddity of the SMB1 protocol.  A single
            request can, in theory, generate 64K (minus one) responses.
            In practice, servers typically limit the number of actual
            replies that they will send.  Some set the limit at about
            100, others allow only one.

            If the type of <payload> is <unicode>, it will be converted
            to a <str> using "utf_8" encoding.  If the input type is a
            <bytearray>, it will also be converted to a <str>.  All of
            the compose() methods return type <str>.

    Doctest:
      >>> len( SMB1_Echo_Request( payload="Weaslebreath" ).compose() )
      49
    """
    super( SMB1_Echo_Request, self ).__init__( flags = flags,
                                               flags2= flags2,
                                               pid   = pid,
                                               mid   = mid,
                                               tid   = tid )
    self.echoCount = echoCount
    self.payload   = payload

  @property
  def echoCount( self ):
    """SMB1 EchoCount value; unsigned 16-bit integer.
    Errors:
      AssertionError  - Thrown if <echoCount> is negative or greater
                        than 0xFFFF (i.e., does not fit into a USHORT).
      TypeError       - Thrown if the assigned value is of a type that
                        cannot be converted to an integer.
      ValueError      - Thrown if the assigned value is a convertable
                        type (e.g., <str>), but still cannot be
                        converted to an integer.
    Notes:  The echo count indicates the number of replies that the
            client expects from a single request.
    """
    return( self._paramWord0 )
  @echoCount.setter
  def echoCount( self, echoCount=1 ):
    self._setParamWord0( echoCount )

  def dump( self, indent=0 ):
    """Produce a formatted representation of the SMB1 Echo Request.

    Input:  indent  - The number of spaces to indent the formatted
                      output.

    Output: The SMB1 Echo Request message, formatted for display and
            returned as a string.

    Note:   If <indent> is zero (the default) the output lines should
            not exceed 72 characters in width.

    Doctest:
      >>> er = SMB1_Echo_Request( 2, "Fooberry\\nBeast" )
      >>> er.pid = 1026
      >>> er.mid = 9767
      >>> print er.dump()
      Echo Request
      Header:
        Protocol..: \\xFFSMB
        Command...: 0x2B
        NT Status.: 0x00000000
        Flags.....: 0b00011000
        Flags2....: 0b1100000000000001
        PIDHigh...: 0x0000
        Signature.: 0x0000000000000000
        Reserved..: 0x0000
        TID.......: 0xFFFF
        PIDLow....: 0x0402
            PID ==> 0x00000402 (1026)
        UID.......: 0x0000
        MID.......: 0x2627
      SMB_Parameters:
        WordCount.....: 0x01 (1)
          EchoCount.....: 0x0002 (2)
      SMB_Data:
        ByteCount.....: 0x000E (14)
          Data..........: Fooberry\\x0ABeast
            (Checksum) => 0xF81C2060
      <BLANKLINE>
    """
    return( self._dump( indent ) )


class SMB1_Echo_Response( _SMB1_Echo ):
  """SMBv1 Echo Response message.

  The Echo Response contains two key fields:
    * SMB_Parameters.SequenceNumber is incremented for each Response to
      the same Request.  The first response has a SequenceNumber of 1.
    * SMB_Data.Data is a copy of the payload received in the Request.
  """

  def __init__( self,
                seqNumber = 1,
                payload   = '',
                flags     = _DEF_FLAGS_RSP,
                flags2    = _DEF_FLAGS2,
                pid       = None,
                mid       = None,
                tid       = SMB_TID_INVALID ):
    """Create an SMB1 Echo Response message.

    Input:
      seqNumber - The sequence number, which should range from 1 to
                  <echoCount>, where <echoCount> is the value of the
                  same name received in the Echo Request.  The protocol
                  requires that at least one response is sent.
      payload   - The byte stream received in the Echo Request.
      flags     - This is the SMB1 Header Flags field.  If not given,
                  a default value will be used.
      flags2    - The SMB1 Header Flags2 field.  If not given, a default
                  value will be used.
      pid       - The process ID.  This must be the same as the <pid>
                  received in the request.
      mid       - Multiplex ID.  This must be the same as the <mid>
                  received in the request.
      tid       - TreeConnect ID.  If not given, the Invalid TID value
                  will be used.
    """
    super( SMB1_Echo_Response, self ).__init__( flags = flags,
                                                flags2= flags2,
                                                pid   = pid,
                                                mid   = mid,
                                                tid   = tid )
    self.seqNumber = seqNumber
    self.payload   = payload

  @property
  def seqNumber( self ):
    """SMB1 SequenceNumber value; unsigned 16-bit integer.
    Errors:
      TypeError       - Thrown if the assigned value is of a type that
                        cannot be converted to an integer.
      ValueError      - Thrown if the assigned value is a convertable
                        type (e.g., <str>), but still cannot be
                        converted to an integer.
      AssertionError  - Thrown if <seqNumber> is less than one or
                        greater than 0xFFFF.
    Notes:  The sequence number of the echo response.
    """
    return( self._paramWord0 )
  @seqNumber.setter
  def seqNumber( self, seqNumber=1 ):
    self._setParamWord0( seqNumber )

  def dump( self, indent=0 ):
    """Produce a formatted representation of the SMB1 Echo Response.

    Input:  indent  - The number of spaces to indent the formatted
                      output.

    Output: The SMB1 Echo Response message, formatted for display and
            returned as a string.

    Note:   If <indent> is zero (the default) the output lines should
            not exceed 72 characters in width.

    Doctest:
      >>> print SMB1_Echo_Response( pid=198, mid=123 ).dump()
      Echo Response
      Header:
        Protocol..: \\xFFSMB
        Command...: 0x2B
        NT Status.: 0x00000000
        Flags.....: 0b10011000
        Flags2....: 0b1100000000000001
        PIDHigh...: 0x0000
        Signature.: 0x0000000000000000
        Reserved..: 0x0000
        TID.......: 0xFFFF
        PIDLow....: 0x00C6
            PID ==> 0x000000C6 (198)
        UID.......: 0x0000
        MID.......: 0x007B
      SMB_Parameters:
        WordCount.....: 0x01 (1)
          SequenceNumber: 0x0001 (1)
      SMB_Data:
        ByteCount.....: 0x0000 (0)
          Data..........:
            (Checksum) => 0x00000000
      <BLANKLINE>
    """
    return( self._dump( indent ) )


# Functions ------------------------------------------------------------------ #
#

def ParseSMB1( msg=None ):
  """Decompose an SMB1 message to create a message object.

  Input:  msg - A stream of bytes, which presumably is an SMB message.

  Output: If no exception is generated, this function will return one of
          the supported SMB message objects, which are:
            SMB1_NegProt_Request
            SMB1_NegProt_Response
            SMB1_Echo_Request
            SMB1_Echo_Response

  Errors:
    ValueError        - Thrown if the input message is too small to be a
                        complete SMB message.
    SMBerror( 1001 )  - SMB Syntax Error; the dialect list in an SMB1
                        NegProt request is not formatted correctly.
    SMBerror( 1002 )  - SMB Semantic Error; thrown if:
                        1) The command code in the message does not
                           represent one of the supported commands.
                        2) The message is an SMB NegProt request with
                           no dialects listed.
                        3) The message is an SMB Echo with an incorrect
                           WordCount or ByteCount.
    SMBerror( 1003 )  - SMB Protocol Mismatch; thrown if the first four
                        bytes of the message are not "<FF>SMB".

  Notes:  SMB and SMB2 messages are typically prefaced by a four-byte
          length field.  The length is considered to be part of the
          transport, and should not be included in the input to this
          function.

  Doctest:
    >>> npr = SMB1_NegProt_Request( pid=5, mid=7 )
    >>> print ParseSMB1( npr.compose() ).dump()
    NegProt Request
    Header:
      Protocol..: \\xFFSMB
      Command...: 0x72
      NT Status.: 0x00000000
      Flags.....: 0b00011000
      Flags2....: 0b1100000000000001
      PIDHigh...: 0x0000
      Signature.: 0x0000000000000000
      Reserved..: 0x0000
      TID.......: 0x0000
      PIDLow....: 0x0005
          PID ==> 0x00000005 (5)
      UID.......: 0x0000
      MID.......: 0x0007
    SMB_Parameters:
      WordCount.: 0x00 (0)
    SMB_Data:
      ByteCount.: 0x000E (14)
      ..........: <02>2.002\\0
      ..........: <02>2.???\\0
    <BLANKLINE>
  """
  def _Echo():
    # Subfunction to parse SMB_COM_ECHO messages.
    #
    if( wCount != 1 ):
      raise SMBerror( 1002, "Incorrect WordCount in SMB_Echo.", wCount )

    # Extract the ByteCount and Bytes.
    byteCount = _format_SMB1H.unpack( msg[35:37] )
    payload   = msg[37:]
    if( byteCount != len( payload ) ):
      s = "ByteCount does not match extracted payload length (%d != %d)"
      s = s % (byteCount, len( payload ))
      raise SMBerror( 1002, s )

    # Compose the Echo object.
    if( 0 == (SMB_FLAGS_REPLY & flags) ):
      er = SMB1_Echo_Request( echoCount = byteCount,
                              payload   = payload,
                              flags     = flags,
                              flags2    = flags2,
                              pid       = 0,
                              mid       = mid,
                              tid       = tid )
    else:
      er = SMB1_Echo_Response( seqNumber = byteCount,
                               payload   = payload,
                               flags     = flags,
                               flags2    = flags2,
                               pid       = 0,
                               mid       = mid,
                               tid       = tid )

    # Fill in the remaining fields.
    er.status       = ntErr
    er._pidHigh     = pidH
    er._secFeatures = secSig
    er._reserved    = rsvd
    er._pidLow      = pidL
    er.uid          = uid
    return( er )

  # ==== Start ParseSMB1() function ==== #

  # Check that there's enough of a message to handle.
  if( (not msg) or (len( msg ) < 35) ):
    # 35 bytes == len( Header ) + len( WordCount ) + len( ByteCount ).
    #   That's the absolute minimum size of an SMB message, even an
    #   Error Response message.
    raise ValueError( "SMB message short or empty." )
  # Is it an SMB/SMB1 message?
  if( SMB_MSG_PROTOCOL != msg[:4] ):
    raise SMBerror( 1003, "Not an SMB1 message" )

  # It looks like it's an SMB1 message.  Pull it apart.
  pcol, cmd, ntErr, flags, flags2, pidH, secSig, rsvd, tid, pidL, uid, mid = \
    _format_SMB1hdr.unpack( msg[:32] )

  # Make sure that we can handle the command we've received.
  if( cmd not in [ SMB_COM_NEGOTIATE, SMB_COM_ECHO ] ):
    s = "Unknown or Unsupported SMB Command Code <{0:02X}>".format( cmd )
    raise SMBerror( 1002, s )

  # Grab the next two fields.
  #   The first is the SMB_Parameters.WordCount field.  If it's zero,
  #   then the second value will be the SMB_Data.ByteCount field.
  #   If WordCount is not zero, then the second value will be the
  #   SMB_Parameters.Words[0] field.
  wCount, uShort = _format_SMB1BH.unpack( msg[32:35] )

  # Preliminaries complete.  Create an object from the parsed input.
  if( cmd == SMB_COM_ECHO ):
    # Call the Echo message parser subfunction thingy stuff.
    return( _Echo() )

  # Handle NegProt messages.
  if( 0 == (SMB_FLAGS_REPLY & flags) ):
    # It's a request message.  Validate the dialect list.
    bCount = uShort
    if( bCount < 3 ):
      raise SMBerror( 1002, "Empty SMB1 NegProt dialect list" )
    if( ('\x02' != msg[35]) or ('\0' != msg[-1]) ):
      raise SMBerror( 1001, "Malformed SMB1 NegProt dialect list" )
    # Extract the dialect strings.
    dialects = msg[36:-1].split( "\0\x02" )
    # Create and update the object.
    npr = SMB1_NegProt_Request( flags    = flags,
                                flags2   = flags2,
                                pid      = 0,
                                mid      = mid,
                                dialects = dialects )
  else:
    # If'n it's not a request, then it's a response.
    dIndex = uShort if( wCount ) else None
    npr = SMB1_NegProt_Response( flags  = flags,
                                 flags2 = flags2,
                                 pid    = 0,
                                 mid    = mid,
                                 dIndex = dIndex )

  # Fill in the remaining fields.
  npr.status       = ntErr
  npr._pidHigh     = pidH
  npr._secFeatures = secSig
  npr._reserved    = rsvd
  npr.tid          = tid
  npr._pidLow      = pidL
  npr.uid          = uid
  return( npr )

# ============================================================================ #
# Susan placed the large plate of cheese rinds onto a doily on the table next
# to the bucket of tractor engine parts.  She sprayed the arrangement with
# vegetable oil and then stepped back to review her handiwork.  "You know",
# she said aloud, "what this needs is a mallard".
# ============================================================================ #
