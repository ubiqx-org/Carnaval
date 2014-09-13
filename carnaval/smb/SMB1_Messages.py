# ============================================================================ #
#                               SMB1_Messages.py
#
# Copyright:
#   Copyright (C) 2014 by Christopher R. Hertel
#
# $Id: SMB1_Messages.py; 2014-09-13 09:46:50 -0500; Christopher R. Hertel$
#
# ---------------------------------------------------------------------------- #
#
# Description:
#   SMB1/2/3 Network File Protocols: SMB1 message parsing and composition.
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
#   - This module currently only contains enough code to handle the SMB1
#     protocol negotiation exchange (NegProt).
#
#     There are no immediate plans to implement anything beyond protocol
#     negotiation since, as of this writing (Aug, 2014), the only supported
#     version of Windows that does not include SMB2 is W2k3.  The Linux
#     CIFS kernel client now also supports SMB2, as does Samba.  The SMB1
#     protocol can (and should) now retire quietly saying "My work here is
#     done".
#
# ============================================================================ #
#
"""SMB1/2/3 Network File Protocols: SMB1 message parsing and composition.

SMB1 is the most recent dialect of the venerable Server Message Block (SMB)
network file protocol.  It is also probably the last such dialect, since
SMB has been replaced by a newer protocol known as SMB2.  SMB2 really is a
completely different protocol, not just another dialect.

The original SMB protocol was developed by IBM in the early 1980's.
It was later extended and enhanced by 3Com, IBM, Intel, and Micrsoft.
Several versions of SMB were produced for PC-DOS, MS-DOS, and OS/2.

SMB1, originally known as the NT LAN Manager 0.12 ("NT LM 0.12") dialect,
was created for Windows NT.  Other than security enhancements and minor
feature upgrades, it hasn't changed much since then and is still supported
in current Windows versions.  However, since the release of Vista, Windows
has also included support for the SMB2 protocol.  Original SMB is on the
road to retirement.

This module implements only SMB1 protocol negotiation, which can be used
as an initial step toward SMB2 protocol negotiation.

SMB1 is specified in [MS-CIFS] and [MS-SMB].  [IMPCIFS] provides a guide
to the protocol and its implementation.

CONSTANTS:

  Protocol Constants:
    SMB_MSG_PROTOCOL  : \\xFFSMB; SMB message prefix (protocol ID).

  Supported SMB1 Commands:
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

REFERENCES:

  [IMPCIFS] Hertel, Christopher R., "Implementing CIFS - The Common
            Internet File System", Prentice Hall, August 2003
            ISBN:013047116X
            http://www.ubiqx.org/cifs/

  [MS-CIFS] Microsoft Corporation, "Common Internet File System (CIFS)
            Protocol Specification"
            http://msdn.microsoft.com/en-us/library/ee442092.aspx

  [MS-SMB]  Microsoft Corporation, "Server Message Block (SMB) Protocol
            Specification"
            http://msdn.microsoft.com/en-us/library/cc246231.aspx
"""

# Imports -------------------------------------------------------------------- #
#
#   struct    - Binary data packing and parsing tools.
#
#   os        - We require getpid() to provide the ProcessID.
#   random    - Used to generate the Multiplex ID values.
#   HexDump   - Local collection of binary to hex-string utilities.
#

import struct                       # Binary data handling.

from os             import getpid   # Get the current process ID.
from random         import randint  # Generate a random integer.
from SMB_Core       import SMBerror # SMBerror exception class.
from common.HexDump import hexstr   # Produce readable output.


# Constants ------------------------------------------------------------------ #
#

# Protocol constants
SMB_MSG_PROTOCOL  = '\xFFSMB' # Standard SMB message prefix (protocol ID).

# Supported SMB1 Commands
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


# Globals -------------------------------------------------------------------- #
#
#   _format_SMB1hdr     - The layout of an SMB1 header as a Python Struct
#                         object.  Note that the '<' character indicates
#                         little-endian encoding, which is the standard
#                         for SMB.  See the _SMB1_Header.compose() method
#                         or [MS-CIFS;2.2.3.1] for the full layout.
#   _format_SMB1BH      - Typically used when the WordCount is zero, this
#                         structure maps to the WordCount (a byte) followed
#                         immediately by the ByteCount (two bytes).  Any
#                         data would follow the ByteCount.
#   _format_SMB1BHH     - Maps to a byte (WordCount) followed by two shorts.
#                         Used, for example, when creating a CORE protocol
#                         NegProt Response such as the "no dialect selected"
#                         message.
#
#   _DEF_FLAGS_REQ      - Default Flags value to use in a request.
#   _DEF_FLAGS_RSP      - Default Flags value to use in a response.
#   _DEF_FLAGS2         - Default Flags2 value for requests and responses.
#

_format_SMB1hdr = struct.Struct( '<4s B L B H H 8s H H H H H' )
_format_SMB1BH  = struct.Struct( '<B H' )
_format_SMB1BHH = struct.Struct( '<B H H' )

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
                command     = SMB_COM_INVALID,# Designated invalid SMB1 command.
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
    #   status      - 32-bit NT status code.  Always zero for requests.
    #   flags       - Flags.
    #   flags2      - More flags.
    #   pid         - 32-bit process ID.
    #   tid         - 16-bit Tree ID.
    #   uid         - 16-bit user authentication ID.
    #   mid         - 16-bit Multiplex ID.
    #
    # Notes:
    #   The default command value is SMB_COM_INVALID, which was reserved
    #   in OS/2 LAN Manager documentation as an officially non-existant
    #   command.
    #
    #   Other than the command code, all fields default to zero.
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
    self.command      = command
    self.status       = status
    self.flags        = flags
    self.flags2       = flags2
    self._secFeatures = (8 * '\0')
    self._reserved    = 0
    self.pid          = pid
    self.tid          = tid
    self.uid          = uid
    self.mid          = mid

  def __command( self, command=None ):
    # Get/set command code.
    if( command is None ):
      return( self._command )
    assert isinstance( command, int ), "Command code is not an integer."
    self._command = ( 0xFF & command )

  def __status( self, status=None ):
    # Get/set status code.
    if( status is None ):
      return( self._status )
    assert isinstance( status, (int, long) ), "Status code is not an integer."
    self._status = status

  def __flags( self, flags=None ):
    if( flags is None ):
      return( self._flags )
    assert isinstance( flags, int ), "Flags is not an integer."
    self._flags = (flags & SMB_FLAGS_MASK)

  def __flags2( self, flags2=None ):
    if( flags2 is None ):
      return( self._flags2 )
    assert isinstance( flags2, int ), "Flags2 is not an integer."
    self._flags2 = (flags2 & SMB_FLAGS2_MASK )

  def __pid( self, pid=None ):
    # Get/set Process ID value.
    if( pid is None ):
      return( long( self._pidHigh << 16 ) | self._pidLow )
    assert isinstance( pid, (int, long) ), "Given PID value is not an integer."
    assert ( pid >= 0 ), "PID must be a positive value."
    self._pidLow  = int( 0xFFFF & pid )
    self._pidHigh = int( (pid >> 16) & 0xFFFF )

  def __tid( self, tid=None ):
    # Get/set Treeconnect ID.
    if( tid is None ):
      return( self._tid )
    self._tid = (0xFFFF & tid)

  def __uid( self, uid=None ):
    # Get/set authenticated user ID.
    if( uid is None ):
      return( self._uid )
    self._uid = (0xFFFF & uid)

  def __mid( self, mid=None ):
    # Get/set Multiplex ID.
    if( mid is None ):
      return( self._mid )
    self._mid = (0xFFFF & mid)

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
    s  = ind + "Protocol..: %s\n"     % hexstr( self._protocol[:4] )
    s += ind + "Command...: 0x%02X\n" % self._command
    s += ind + "NT Status.: 0x%08X\n" % self._status
    s += ind + "Flags.....: 0b{0:08b}\n".format( self._flags )
    s += ind + "Flags2....: 0b{0:016b}\n".format( self._flags2 )
    s += ind + "PIDHigh...: 0x%04X\n" % self._pidHigh
    s += ind + "Signature.: 0x%s\n"   % sig
    s += ind + "Reserved..: 0x%04X\n" % self._reserved
    s += ind + "TID.......: 0x%04X\n" % self._tid
    s += ind + "PIDLow....: 0x%04X\n" % self._pidLow
    s += ind + "    PID ==> 0x{0:08X} ({0:d})\n".format( self.pid )
    s += ind + "UID.......: 0x%04X\n" % self._uid
    s += ind + "MID.......: 0x%04X\n" % self._mid
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

  # Properties.
  command = property( __command, __command, doc="SMB1 Command code" )
  status  = property( __status,  __status,  doc="NT Status code" )
  flags   = property( __flags,   __flags,   doc="LANMAN1.0 Flags field" )
  flags2  = property( __flags2,  __flags2,  doc="LANMAN1.2 Flags2 field" )
  pid     = property( __pid,     __pid,     doc="32-bit Process ID" )
  tid     = property( __tid,     __tid,     doc="16-bit TreeConnect ID" )
  uid     = property( __uid,     __uid,     doc="16-bit User ID" )
  mid     = property( __mid,     __mid,     doc="16-bit Multiplex ID" )


class SMB1_NegProt_Request( _SMB1_Header ):
  """SMBv1 Negotiate Protocol Request message.

  The Negotiate Protocol (or NegProt) request is used by SMB clients when
  connecting to SMB servers.  It is used to determine the greatest common
  protocol and dialect between the two, and also allows the server to
  indicate a set of supported features.
  """
  def __init__( self,
                flags    = _DEF_FLAGS_REQ,
                flags2   = _DEF_FLAGS2,
                pid      = getpid(),
                mid      = randint( 16, 64000 ),
                dialects = [ "2.002", "2.???" ] ):
    """Create an SMB1 NegProt request that negotiates SMB2.0 or above.

    Input:
      flags     - An unsigned 8-bit field made up of LANMAN1.0 Flags
                  bits.  If not given, default values will be used.
      flags2    - An unsigned 16 bit field made up of LANMAN1.2 Flags2
                  bits.  If not given, default values will be used.
      pid       - The value to be sent as the process ID.  If not
                  given, the actual process ID will be used.
      mid       - The value to be sent as the Multiplex ID (MID).
                  If not given, a pseudo-random number will be used.
      dialects  - A list of SMB dialect strings to be included (in
                  the presented order) in the request.  By default,
                  the list will be ["2.002", "2.???"].  These are the
                  two strings that may be used to negotiate the SMB2+
                  protocol from an SMB NegProt.

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
    self.__dialects( dialects )
    super( SMB1_NegProt_Request, self ).__init__( command = SMB_COM_NEGOTIATE,
                                                  flags   = flags,
                                                  flags2  = flags2,
                                                  pid     = pid,
                                                  mid     = mid )

  def __dialects( self, dialects=None ):
    # Get/set the list of dialects.
    if( dialects is None ):
      return( self._dialects )
    self._dialects = []
    self._smbData  = ''
    for dialect in dialects:
      assert isinstance( dialect, str ), "Protocol dialects must be strings."
      self._dialects.append( dialect )        # Yes, we're copying the list.
      self._smbData += '\x02%s\0' % dialect   # Build the SMB Data block.

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

  # Properties.
  dialect = property( __dialects, __dialects, doc="List of available dialects" )


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

  In cases 1 and 2, the server will respond with an SMB2 (not SMB1)
  message.

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
  supports the legacy SMB protocol.

  As currently implemented, this class is really only suited for sending
  an 0xFFFF response to indicate that no SMB dialect was selected.  Note,
  however, that doing so will (falsely) indicate to the client that the
  responding node does support some dialect of the original SMB protocol.
  """
  def __init__( self,
                flags    = _DEF_FLAGS_RSP,
                flags2   = _DEF_FLAGS2,
                pid      = 0,
                mid      = 0,
                dIndex   = 0xFFFF ):
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
    self.__setdIndex( dIndex )
    super( SMB1_NegProt_Response, self ).__init__( command = SMB_COM_NEGOTIATE,
                                                   flags   = flags,
                                                   flags2  = flags2,
                                                   pid     = pid,
                                                   mid     = mid )

  def __getdIndex( self ):
    # Get the dialect index, which may be None.
    return( self._dIndex )

  def __setdIndex( self, dIndex=None ):
    # Set the dialect index.  None is a valid value.
    if( dIndex is None ):
      self._dIndex    = None
    else:
      assert isinstance( dIndex, int ), \
             "Dialect index must be an integer or None."
      if( dIndex < 0 ):
        self._dIndex = 0xFFFF
      else:
        self._dIndex = (0xFFFF & dIndex)

  def dump( self, indent=0 ):
    """Produce a formatted representation of the SMB NegProt response.

    Input:  indent  - The number of spaces to indent the formatted
                      output.

    Output: The SMB NegProt response message, formatted for display and
            returned as a string.

    Doctest:
    >>> s1npr = SMB1_NegProt_Response( pid=987654321, mid=0x8899 )
    >>> s1npr.dIndex = None
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
      WordCount.....: 0x00 (0)
    SMB_Data:
      ByteCount.....: 0x0000 (0)
    <BLANKLINE>
    """
    ind = ' ' * indent
    wc  = 0
    di  = ''

    # If the index is given as non-None, prepare an additional line.
    if( self._dIndex is not None ):
      wc = 1
      di = ind + "  Dialect Index.: 0x{0:04X} ({0:d})\n".format( self._dIndex )

    # Compose the dump.
    s  = ind + "NegProt Response\n"
    s += ind + "Header:\n"
    s += super( SMB1_NegProt_Response, self ).dump( indent + 2 )
    s += ind + "SMB_Parameters:\n"
    s += ind + "  WordCount.....: 0x{0:02X} ({0:d})\n".format( wc ) + di
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
    >>> print hexstr( foo[:15] )
    \\xFFSMBr\\x00\\x00\\x00\\x00\\x98\\x01\\xC0\\x00\\x00\\x00
    >>> print hexstr( foo[15:26] )
    \\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00
    >>> print hexstr( foo[26:] )
    \\x00\\x00\\x00\\x00\\x00\\x00\\x01\\xFF\\xFF\\x00\\x00
    """
    s  = super( SMB1_NegProt_Response, self ).compose()
    if( self._dIndex is None ):
      s += _format_SMB1BH.pack( 0, 0 )
    else:
      s += _format_SMB1BHH.pack( 1, self._dIndex, 0 )
    return( s )

  # Properties
  dIndex = property( __getdIndex, __setdIndex, doc="Selected dialect index" )


# Functions ------------------------------------------------------------------ #
#

def ParseSMB1( msg=None ):
  """Decompose an SMB1 message to create a message object.

  Input:  msg - A stream of bytes, which presumably is an SMB message.

  Output: If no exception is generated, this function will return one of
          the supported SMB message objects, which are:
            SMB1_NegProt_Request
            SMB1_NegProt_Response

  Errors:
    ValueError        - Thrown if the input message is too small to be a
                        complete SMB message.
    SMBerror( 1001 )  - SMB Semantic Error; thrown if:
                        1) The command code in the message is not
                           SMB_COM_NEGOTIATE (that is, not a supported
                           command).
                        2) The message is an SMB1 NegProt request with
                           no dialects listed.
    SMBerror( 1002 )  - SMB Syntax Error; the dialect list in an SMB1
                        NegProt request is not formatted correctly.

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
  # Check that there's enough of a message to handle.
  if( (not msg) or (len( msg ) < 35) ):
    # 35 bytes == len( Header ) + len( WordCount ) + len( ByteCount ).
    #   That's the absolute minimum size of an SMB message.
    raise ValueError( "SMB message short or empty." )
  # Is it an SMB/SMB1 message?
  if( SMB_MSG_PROTOCOL != msg[:4] ):
    raise SMBerror( 1003, "Not an SMB1 message" )

  # It looks like it's an SMB1 message.  Pull it apart.
  pcol, cmd, ntErr, flags, flags2, pidH, secSig, rsvd, tid, pidL, uid, mid = \
    _format_SMB1hdr.unpack( msg[:32] )

  # Make sure that we can handle the command we've received.
  if( SMB_COM_NEGOTIATE != cmd ):
    s = "Unknown or Unsupported SMB Command Code <{0:02X}>".format( cmd )
    raise SMBerror( 1001, s )

  # Grab the next two fields.
  wCount, uShort = _format_SMB1BH.unpack( msg[32:35] )

  # Create and return the message object.
  if( 0 == (SMB_FLAGS_REPLY & flags) ):
    # It's a request message.  Validate the dialect list.
    bCount = uShort
    if( bCount < 3 ):
      raise SMBerror( 1001, "Empty SMB1 NegProt dialect list" )
    if( ('\x02' != msg[35]) or ('\0' != msg[-1]) ):
      raise SMBerror( 1002, "Malformed SMB1 NegProt dialect list" )
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
