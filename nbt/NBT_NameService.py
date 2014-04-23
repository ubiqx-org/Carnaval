# ============================================================================ #
#                              NBT_NameService.py
#
# Copyright:
#   Copyright (C) 2014 by Christopher R. Hertel
#
# $Id: NBT_NameService.py; 2014-04-23 10:34:14 -0500; Christopher R. Hertel$
#
# ---------------------------------------------------------------------------- #
#
# Description:
#   NetBIOS over TCP/IP (IETF STD19) implementation: NBT Name Service.
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
# ---------------------------------------------------------------------------- #
#
# Notes:
#   - One of the design goals of this module is to make it very easy to
#     create correct messages, but to also allow the caller to purposefully
#     mess things up if they so choose.  The idea is to allow the caller to
#     create (with a bit of effort) invalid messages for pernicious testing.
#     This is a design goal acheived in most cases by allowing the caller to
#     modify values within a message after they have already created the
#     message object.
#
#   - This module make some use of doctest strings within docstrings.
#     More should be added.  A lot more.
#     See: http://docs.python.org/2/library/doctest.html
#
# RFC Errata:
#   - With regard to IMP_ERR, RFC 1002 says:
#       "Allowable only for challenging NBNS when gets an Update type
#       registration request."
#     See: http://www.ubiqx.org/cifs/NetBIOS.html#NBT.4.3.1.2
#   - "NAME UPDATE REQUEST" and "NAME OVERWRITE REQUEST & DEMAND" need
#     to be clarified.  See the Alert box in #NBT.4.3.1.2.
#   - The 0x8/0x9 Name Refresh OPcode confusion.
#   - The RedirectNameQueryResponse in RFC1002 could use some
#     clarification.
#
# ToDo:
#   - Write more doctests.
#
#   - Consider which fields in a from-the-wire message should be copied
#     verbatim into the object created by ParseMsg().  Once we know what
#     kind of message we have, we can forgive several types of errors in
#     the message itself, including reserved bits that should be clear,
#     or fields (like the TTL field) that should be zero in some cases.
#     Why keep the wire values?  Only for testing and disgnostics.  What
#     mistakes do other implementations make?
#
# ============================================================================ #
#
"""NetBIOS over TCP/UDP (NBT) protocol: NBT Name Service

The NBT Name Service provides a mechanism for mapping NetBIOS names to
IPv4 addresses in an IP network.  This module is a toolkit for
implementing the NBT Name Service protocol.

NBT is defined in IETF RFCs 1001 and 1002, collectively known as IETF
Standard 19 (STD19).  A detailed implementer's guide to NBT can be
found on the web at:  http://www.ubiqx.org/cifs/NetBIOS.html

CONSTANTS:

  Protocol Details:
    NS_PORT = 137         # The default NBT Name Service listener port.

  Name Service Header:
    Header.FLAGS.R_BIT; 'R'esponse bit.
    NS_R_BIT  = 0x8000    # True (1) in response messages, else 0.

    Header.FLAGS.OPCODE; Name service OPcodes.
    NS_OPCODE_MASK        = 0x7800          # Mask         = 0x0F
    NS_OPCODE_QUERY       = 0x0000          # Query        = 0x00
    NS_OPCODE_REGISTER    = 0x2800          # Registration = 0x05
    NS_OPCODE_RELEASE     = 0x3000          # Release      = 0x06
    NS_OPCODE_WACK        = 0x3800          # WACK         = 0x07
    NS_OPCODE_REFRESH     = 0x4000          # Refresh      = 0x08
    NS_OPCODE_ALTREFRESH  = 0x4800          # Refresh      = 0x09
    NS_OPCODE_MULTIHOMED  = NS_OPCODE_MASK  # Multi-homed  = 0x0F

    Header.FLAGS.NM_FLAGS; See RFC 883 for history.
    NS_NM_FLAGS_MASK  = 0x0790  # Mask
    NS_NM_AA_BIT      = 0x0400  # Authoritative Answer
    NS_NM_TC_BIT      = 0x0200  # TrunCation flag
    NS_NM_RD_BIT      = 0x0100  # Recursion Desired
    NS_NM_RA_BIT      = 0x0080  # Recursion Available
    NS_NM_B_BIT       = 0x0010  # Broadcast flag

    Header.FLAGS.RCODE; Result Code.
    NS_RCODE_MASK     = 0x0007        # Subfield mask
    NS_RCODE_POS_RSP  = 0x0000        # Positive Response
    NS_RCODE_FMT_ERR  = 0x0001        # Format Error
    NS_RCODE_SRV_ERR  = 0x0002        # Server failure
    NS_RCODE_NAM_ERR  = 0x0003        # Name Error
    NS_RCODE_IMP_ERR  = 0x0004        # Unsupported request
    NS_RCODE_RFS_ERR  = 0x0005        # Refused
    NS_RCODE_ACT_ERR  = 0x0006        # Active error
    NS_RCODE_CFT_ERR  = NS_RCODE_MASK # Name in conflict

    Header.FLAGS; All possible Header.FLAGS bits.
    NS_HEADER_FLAGS_MASK = 0xFF97     # Full HEADER.FLAGS mask

  Resource Records:
    ResourceRecord.RR_TYPE;  Resource Record types.
    NS_RR_TYPE_A      = 0x0001  # Not used in practice,
    NS_RR_TYPE_NS     = 0x0002  # not used in practice.
    NS_RR_TYPE_NULL   = 0x000A  # In RFC1002; typically not used.
    NS_RR_TYPE_NB     = 0x0020  # NetBIOS Name record.
    NS_RR_TYPE_NBSTAT = 0x0021  # Node (Adapter) Status request/response.

    ResourceRecord.RR_CLASS; Resource Record class.
    NS_RR_CLASS_IN    = 0x0001  # Internet Class; NBT uses only this class.

    ResourceRecord.RR_NAME; Label String Pointer.
    NS_RR_LSP = "\xC0\x0C"        # The only Label String Pointer used in NBT.

  Question Records:
    QuestionRecord.Q_TYPE; Question Record types.
    NS_Q_TYPE_NB      = NS_RR_TYPE_NB     # Name Query.
    NS_Q_TYPE_NBSTAT  = NS_RR_TYPE_NBSTAT # Node Status Query.

    QuestionRecord.Q_CLASS; Question Record class.
    NS_Q_CLASS_IN     = NS_RR_CLASS_IN    # Same as the RR IN class.

  RData:
    RDATA.NB_FLAGS values; Owner Node Type and type of name (group/unique).
    NS_NBFLAG_MASK = 0xE000     # NBFlag mask.
    NS_ONT_B       = 0x0000     # Owner Node Type is B (B-mode).
    NS_ONT_P       = 0x2000     # Owner Node Type is P (P-mode).
    NS_ONT_M       = 0x4000     # Owner Node Type is M (M-mode).
    NS_ONT_H       = 0x6000     # Owner Node Type is H (H-mode).
    NS_ONT_MASK    = NS_ONT_H   # Owner Node Type (ONT) mask.
    NS_GROUP_BIT   = 0x8000     # If set, the name is a NetBIOS group name.

    RDATA.NODE_NAME.NAME_FLAGS (in a Node Status Reply).
    NS_NAMEFLAG_MASK = 0xFE00   # (NS_NBFLAG_MASK | NS_STATE_MASK).
    NS_STATE_MASK    = 0x1E00   # Mask for (DRG | CNF | ACT | PRM).
    NS_DRG           = 0x1000   # If set, name is being released.
    NS_CNF           = 0x0800   # If set, name is in conflict.
    NS_ACT           = 0x0400   # Always set.  Name is active.
    NS_PRM           = 0x0200   # Machine's permanent name.  Not used.
"""

# Imports -------------------------------------------------------------------- #
#
#   struct    - Binary data packing and parsing tools.
#   NBT_Core  - Objects common to all NBT transport services.
#

import struct                         # Binary data handling.

from NBT_Core import NBTerror         # NBT exception class.
from NBT_Core import hexbyte, hexstr  # Byte to hex string conversion.
from NBT_Core import hexdump          # Hexdump raw blocks of data.


# Constants ------------------------------------------------------------------ #
#

# Protocol Details
NS_PORT = 137           # The standard NBT Name Service listener port.

# Header.FLAGS.R_BIT
# 'R'esponse bit.
NS_R_BIT  = 0x8000  # True (1) in response messages, else 0.

# Header.FLAGS.OPCODE
# Name service OPcodes.  (Offset to match their bit positions in the header.)
NS_OPCODE_MASK        = 0x7800          # Mask         = 0x0F
NS_OPCODE_QUERY       = 0x0000          # Query        = 0x00
NS_OPCODE_REGISTER    = 0x2800          # Registration = 0x05
NS_OPCODE_RELEASE     = 0x3000          # Release      = 0x06
NS_OPCODE_WACK        = 0x3800          # WACK         = 0x07
NS_OPCODE_REFRESH     = 0x4000          # Refresh      = 0x08
NS_OPCODE_ALTREFRESH  = 0x4800          # Refresh      = 0x09
NS_OPCODE_MULTIHOMED  = NS_OPCODE_MASK  # Multi-homed  = 0x0F

# Header.FLAGS.NM_FLAGS
NS_NM_FLAGS_MASK  = 0x0790  # Mask
NS_NM_AA_BIT      = 0x0400  # Authoritative Answer
NS_NM_TC_BIT      = 0x0200  # TrunCation flag
NS_NM_RD_BIT      = 0x0100  # Recursion Desired
NS_NM_RA_BIT      = 0x0080  # Recursion Available
NS_NM_B_BIT       = 0x0010  # Broadcast flag

# Header.FLAGS.RCODE
NS_RCODE_MASK     = 0x0007        # Subfield mask
NS_RCODE_POS_RSP  = 0x0000        # Positive Response
NS_RCODE_FMT_ERR  = 0x0001        # Format Error
NS_RCODE_SRV_ERR  = 0x0002        # Server failure
NS_RCODE_NAM_ERR  = 0x0003        # Name Error
NS_RCODE_IMP_ERR  = 0x0004        # Unsupported request
NS_RCODE_RFS_ERR  = 0x0005        # Refused
NS_RCODE_ACT_ERR  = 0x0006        # Active error
NS_RCODE_CFT_ERR  = NS_RCODE_MASK # Name in conflict

# Header.FLAGS; All possible Header.FLAGS bits.
NS_HEADER_FLAGS_MASK  = 0xFF97    # Full HEADER.FLAGS mask

# RR.RR_TYPE;  Resource Record types.
NS_RR_TYPE_A      = 0x0001  # Not used in practice,
NS_RR_TYPE_NS     = 0x0002  # not used in practice,
NS_RR_TYPE_NULL   = 0x000A  # not used in practice.
NS_RR_TYPE_NB     = 0x0020  # Name Query response, Registration Request, etc.
NS_RR_TYPE_NBSTAT = 0x0021  # Node (Adapter) Status Query request/response.

# RR.RR_CLASS; Resource Record class.
NS_RR_CLASS_IN    = 0x0001  # Internet Class; NBT uses only this class.

# RR.RR_NAME; Label String Pointer.
NS_RR_LSP = "\xC0\x0C"      # The only Label String Pointer used in NBT.

# Q_TYPE; Question Record types.
NS_Q_TYPE_NB      = NS_RR_TYPE_NB     # Name Query.
NS_Q_TYPE_NBSTAT  = NS_RR_TYPE_NBSTAT # Node Status Query.

# Q_CLASS; Question Record class.
NS_Q_CLASS_IN     = NS_RR_CLASS_IN    # Same as the RR IN class.

# RDATA.NB_FLAGS values.
NS_NBFLAG_MASK = 0xE000     # NBFlag mask.
NS_ONT_B       = 0x0000     # Owner Node Type is B (B-mode).
NS_ONT_P       = 0x2000     # Owner Node Type is P (P-mode).
NS_ONT_M       = 0x4000     # Owner Node Type is M (M-mode).
NS_ONT_H       = 0x6000     # Owner Node Type is H (H-mode).
NS_ONT_MASK    = NS_ONT_H   # Owner Node Type (ONT) mask.
NS_GROUP_BIT   = 0x8000     # If set, the name is a NetBIOS group name.

# RDATA.NODE_NAME.NAME_FLAGS (in a Node Status Reply).
NS_NAMEFLAG_MASK = 0xFE00   # (NS_NBFLAG_MASK | NS_STATE_MASK).
NS_STATE_MASK    = 0x1E00   # Mask used for (DRG | CNF | ACT | PRM).
NS_DRG           = 0x1000   # If set, name is being released.
NS_CNF           = 0x0800   # If set, name is in conflict.
NS_ACT           = 0x0400   # Always set.  Name is active.
NS_PRM           = 0x0200   # Indicates machine's permanent name.  Not used.


# Globals -------------------------------------------------------------------- #
#
#   _format_NS_hdr    - A Struct object used to parse NBT Name Service
#                       headers.
#   _format_QR        - A pair of 16-bit uints, as in a question record
#                       following the query name.
#   _format_RR        - Two 16-bit uints, followed by a 32-bit uint, followed
#                       by another 16-bit uint.  These represent the 4 fields
#                       that always follow the RR_NAME in a Resource Record
#                       structure:  RR_TYPE, RR_CLASS, TTL, and RDLENGTH.
#   _format_Short     - A single short uint; Typically a Flags field.
#   _format_MacAddr   - A string of 6 octets, typically a MAC address.
#   _format_AddrEntry - A short followed by four unsigned bytes.  This maps
#                       to the ADDR_ENTRY field of an Address Record.
#
#   _OPcodeDict       - Map OPcode values to descriptive text.
#   _ontDict          - Maps Owner Node Type values to descriptive text.
#   _nameFlagDict     - Maps NAME_FLAG values to descriptive text.
#

# Structure formats
_format_NS_hdr    = struct.Struct( "!6H" )
_format_QR        = struct.Struct( "!2H" )
_format_RR        = struct.Struct( "!HHLH" )
_format_Short     = struct.Struct( "!H" )
_format_MacAddr   = struct.Struct( "!6B" )
_format_AddrEntry = struct.Struct( "!H4s" )

# Quick lookup dictionaries
_OPcodeDict = { NS_OPCODE_REGISTER  : 'registration',
                NS_OPCODE_REFRESH   : 'refresh',
                NS_OPCODE_ALTREFRESH: 'refresh',
                NS_OPCODE_RELEASE   : 'release',
                NS_OPCODE_MULTIHOMED: 'multi-homed registration' }

_ontDict  = { NS_ONT_B: "B node",
              NS_ONT_P: "P node",
              NS_ONT_M: "M node",
              NS_ONT_H: "H node" }

_nameFlagDict = { NS_DRG: "Deregister",
                  NS_CNF: "Conflict",
                  NS_ACT: "Active",
                  NS_PRM: "Permanent" }


# Classes -------------------------------------------------------------------- #
#

class Name( object ):
  """NBT Name encoding and decoding.

  NetBIOS names identify communications endpoints, not nodes.  A single
  node may have multiple NetBIOS names registered, just as it may have
  multiple TCP or UDP ports actively sending and receiving messages.

  In NBT, the NetBIOS name is encoded before it is used on the wire.
  The fully encoded (wire) format of the name is known as an NBT name.

  The encoded format can be used for sorting and comparing names.  The
  only reason to decode the name is for display purposes, which is not as
  speed-critical as, say, data transfer.  So, within this class, the NBT
  name is stored fully encoded and is decoded upon request.

  The encoding of NBT names is complicated by the use of Label String
  Pointers.  Normally, a level 2 encoded NBT name is composed of labels,
  each of which is preceded by a one byte length.  The highest order two
  bits are always zero, so the maximum label length is 63 bytes.  If,
  however, the upper two bytes are both 1 (0xC0) then the field is not a
  length byte at all, but a two-byte Label String Pointer.  The
  lower-order 14 bits represent an offset into an NBT message at which
  the rest of the encoded name is to be found.

  Doctext:
    >>> name = "fooberry".upper()
    >>> name = Name( name )
    >>> newname = Name()
    >>> newname.setNetBIOSname( name.getNetBIOSname(), ' ', '\x1E', 'scope' )
    >>> str( newname )
    'FOOBERRY<1E>.scope'
  """
  def __init__( self, name=None, pad=None, suffix=None, scope=None, lsp=None ):
    """Initialize an NBT Name.

    Input:
      name    - If given, this must be a NetBIOS name (15 bytes, max).
      pad     - Padding byte.
      suffix  - Suffix byte.
      scope   - The NBT scope identifier.
      lsp     - Either None, or an offset value (0..16383) to be
                encoded as a label string pointer.

    Output: None

    Errors: TypeError   - Raised if any of the input parameters are not
                          None and are not of type <str>.
            ValueError  - If any of the name segments, or the name
                          composed from those segments, do not conform
                          to the syntax prescribed in the RFCs.

    Notes:  More details are provided in the description of
            <setNetBIOSname()>, below.

            By default, the NBT Name is initialized with an empty value,
            (None) which must be set before the name can be used.  If
            the <name> parameter is something other than None, the
            NBT Name will be filled in by calling the setNetBIOSname()
            method with the supplied parameters.
    """
    self.reset()
    if( name is not None ):
      self._name = self.setNetBIOSname( name, pad, suffix, scope, lsp )
    return

  def __str__( self ):
    """Informal string presentation of the wire-format NBT name.

    Notes:  The output might not include the padding bytes.

            Padding bytes are problematic.  By definition, only space
            ('\\x20') and NUL ('\\0') can be used as padding, and NUL is
            reserved for the wildcard name.  The decoding done in this
            module is based on those rules.  If the remote node used
            some other padding, that padding will appear as part of the
            name.  From experience, it does seem that padding rules are
            not strictly observed by all implementations.

            If, however, the name being printed was created from its
            component parts and a non-standard pad-byte was given, then
            the pad byte will be known and recognized as a pad byte.
            ...and that's why the doctest output shown below is correct.

    Doctest:
      >>> name = Name( "ZNORFGASSER", pad='x', suffix=' ' )
      >>> str( name )
      'ZNORFGASSER<20>'
      >>> name.setL2name( name.getL2name() )
      34
      >>> str( name )
      'ZNORFGASSERxxxx<20>'
      >>> str( Name( "*" ) )
      '*<00>'
    """
    # Ensure that the name is fully decoded, or is empty.
    self._decodeAll()
    if( self._NBname is None ):
      return( '' )

    # Present the user-readable format in a pretty-printed way.
    s  = self._NBname if self._NBname else "''"
    s += ("<%s>" % hexbyte( self._Suffix ))
    if( self._Scope ):
      s += '.' + self._Scope
    if( self._LSP is not None ):
      s += "[%s]" % str( self._LSP )
    return( hexstr( s ) )

  def __repr__( self ):
    """String representation of the NBT Name object instance.

    Notes:  See the python documentation for clarification.
            http://docs.python.org/2/reference/datamodel.html#object.__repr__

    Doctest:
    >>> print Name( "MITSCHLAG", scope="Himmelschpitz.org" ).__repr__()
    Name( 'MITSCHLAG', '\\x20', '\\x20', 'Himmelschpitz.org', None )
    """
    # Ensure that the name is fully decoded, or is empty.
    self._decodeAll()
    if( self._NBname is None ):
      return( "Name()" )

    # Format the output.
    n   = self._NBname.encode( 'string_escape' )
    p   = "None"
    s   = "None"
    sc  = "None"
    lsp = "None"
    if( self._Pad is not None ):
      p = "'\\x" + hexbyte( self._Pad ) + "'"
    if( self._Suffix is not None ):
      s = "'\\x" + hexbyte( self._Suffix ) + "'"
    if( self._Scope is not None ):
      sc = "'" + self._Scope.encode( 'string_escape' ) + "'"
    if( self._LSP is not None ):
      lsp = self._LSP
    return( "Name( '%s', %s, %s, %s, %s )" % (n, p, s, sc, lsp) )

  @staticmethod
  def L1decode( L1name ):
    """Undo the half-ascii encoding of an L1-encoded name.

    Input:
      L1name  - A level-1 encoded NetBIOS name, which must be 32 octets
                in length.

    Errors: ValueError  - Raised if the input just isn't right somehow.

    Output: A 16-octet string made up of the original NetBIOS name,
            any padding bytes, and the suffix byte.
    """
    if( 32 != len( L1name ) ):
      s = "Incorrect length (%d) for an L1 encoded NetBIOS name" % len( L1name )
      raise ValueError( s )

    tmpnam = ''
    for i in range(32)[::2]:
      if( L1name[i] not in "ABCDEFGHIJKLMNOP" ):
        s = "Invalid character '%s' in L1 encoded name" % L1name[i]
        raise ValueError( s )
      hi = ((ord( L1name[i] ) - 0x41) << 4) & 0xF0
      lo = (ord( L1name[i+1] ) - 0x41) & 0x0F
      tmpnam += chr( hi + lo )
    return( tmpnam )

  def _L1_decode( self ):
    # Private method to populate the _NBname, _Pad, and _Suffix attributes
    # by decoding the L1-encoded name.
    #
    if( self._L1name is None ):
      return

    # Decode the L1 encoded name.
    tmpnam = Name.L1decode( self._L1name )

    # Attempt to parse the decoded name (find the Pad and Suffix bytes).
    self._Suffix = tmpnam[15]
    tmpnam = tmpnam[:15]
    # Only space and NUL are valid padding bytes, and space is the specified
    # default.  We will stick with the rules here and not try to guess any
    # other padding values that someone may have (mis)used.
    self._Pad = ' '
    if( '*' == tmpnam[0] and ('\0' == tmpnam[1] == self._Suffix) ):
      # NUL padding is (supposed to be) used for the wildcard name only.
      self._Pad = '\0'
    tmpnam = tmpnam.rstrip( self._Pad )
    self._NBname = tmpnam

  def _L2_decode( self ):
    # Private method to populate the _L1name, _Scope, and _LSP attributes
    # by decoding the L2-encoded name.
    #
    if( self._L2name is None ):
      # All empty.
      self.reset()
      return

    # Parse the segments into a list of strings.
    lsp    = None
    parts  = []
    chomp  = self._L2name
    seglen = ord( chomp[0] )
    while (seglen > 0) and (lsp is None):
      if( seglen & 0xC0 ):
        # Label string pointer.
        lsp = ((seglen & ~0xC0) << 8) + ord( chomp[1] )
      else:
        # Normal length field.
        parts += [ chomp[1:seglen+1] ]
        chomp  = chomp[1+seglen:]
        seglen = ord( chomp[0] )

    # Store the pieces.
    self._L1name = parts[0]
    self._Scope  = '.'.join( parts[1:] )
    self._LSP    = lsp

  def _decodeAll( self ):
    # Decode available encoded names.
    #   If the name exists in some encoded form, decode it to the
    #   user-readable format.
    #
    if( not self._NBname ):
      if( not self._L1name ):
        self._L2_decode()
      self._L1_decode()

  def reset( self ):
    """Reset the NBT Name to None.
    """
    self._L2name = None
    self._L1name = None
    self._NBname = None
    self._Pad    = None
    self._Suffix = None
    self._Scope  = None
    self._LSP    = None

  def setNetBIOSname( self, name  = None,
                            pad   = None,
                            suffix= None,
                            scope = None,
                            lsp   = None ):
    """Encode and store a NetBIOS name (and scope).

    Input:
      name    - The NetBIOS name (maximum 15 bytes) to be encoded.
                If <name> is None, or exceeds the maximum length, an
                exception will be thrown.  That means we are allowing
                the empty string as a NetBIOS name.
      pad     - Padding byte.  If not specified (given as None), a
                default padding value will be used.  The default is NUL
                (0x00) if the given <name> is '*' (the wildcard name),
                otherwise the default padding byte is a space (0x20).
      suffix  - By convention, the 16th byte of a NetBIOS name is
                reserved for a "type" value, known as the "suffix byte".
                There are several known suffix values (also defined by
                convention).  If <suffix> is given as None, a space is
                used by default, unless the padding byte is NUL in
                which case NUL is also used for the suffix.
                See: http://www.ubiqx.org/cifs/Appendix-C.html
      scope   - The NBT scope identifier.  See notes below.
      lsp     - Either None, or a Label String Pointer offset in the
                range 0..0x3FFF (14 bits).

    Output: None

    Errors: TypeError   - Raised if any of the input parameters are not
                          of the correct type.
            ValueError  - Raised if <name> is None.
            ValueError  - Raised if <name> exceeds 15 bytes in length.
            ValueError  - Raised if <lsp> is not in the permitted range.
            ValueError  - Raised if the encoded L2 name exceeds the 255
                          byte length limit.

    Notes:  All input value must be of the correct type.
            - <name> must be of type <str>.
            - <lsp> must be None or of type <int>.
            - All other input values must be None or of type <str>.

            The 255 overall length limit is specified in [RFC1002],
            section 4.1.
              See: http://www.rfc-editor.org/rfc/rfc1002.txt

            By convention, the name should be given in upper case. This
            method does not convert the name to upper case, nor does it
            check that the name is in upper case.  There are some (rare)
            programs out there that do somehow manage to create NBT
            names from mixed-case input, so we must also allow it.

            Some old documentation claims that the NUL byte (0x00) is an
            illegal character in a NetBIOS name.  The use of Unicode in
            Windows has caused this rule to be broken, so the Name class
            must accommodate names that contain NUL bytes.  Windows uses
            UCS-2LE or UTF-16LE encoding.

            The NBT scope is poorly understood by most implementers.
            Think of it as a virtual LAN identifier.  The default scope
            is the empty string, and that is the one that is most
            commonly used.
            See: http://www.ubiqx.org/cifs/NetBIOS.html#NBT.2.2

            Label String Pointers (LSPs) are used to reduce the amount
            of space used to store L2-encoded names in NBT packets.  If
            given, the <lsp> value will be encoded and used to terminate
            composed L2-encoded name.
            See: http://ubiqx.org/cifs/NetBIOS.html#NBT.4.1.3

            The NetBIOS name and NBT scope are defined, in the RFCs, as
            strings of octets, not characters.  See:
            http://blogs.msdn.com/b/larryosterman/archive/2007/07/11/
            how-do-i-compare-two-different-netbios-names.aspx
    """
    # Validate the name.
    if( name is None ):
      raise ValueError( "No NetBIOS name given." )
    elif( not isinstance( name, str ) ):
      s = type( name ).__name__
      raise TypeError( "NetBIOS name must be of type str, not %s." % s )
    elif( len( name ) > 15 ):
      raise ValueError( "NetBIOS name exceeds the maximum length." )

    # Validate the pad byte.
    if( pad is None ):
      pad = '\0' if '*' == name else ' '
    elif( not isinstance( pad, str ) ):
      s = type( pad ).__name__
      raise TypeError( "Padding byte must be of type str, not %s." % s )
    else:
      pad = pad[0]

    # Validate the suffix byte.
    if( suffix is None ):
      suffix = '\0' if pad == '\0' else ' '
    elif( not isinstance( suffix, str ) ):
      s = type( suffix ).__name__
      raise TypeError( "Suffix byte must be of type str, not %s." % s )
    else:
      suffix = suffix[0]

    # Validate and clean up the scope string, if any.
    if( scope is None ):
      scope = ''
    elif( not isinstance( scope, str ) ):
      s = type( scope ).__name__
      raise TypeError( "NetBIOS scope must be of type str, not %s." % s )
    else:
      scope = scope.strip( " ." )

    # Validate the LSP, if present.
    if( lsp is not None ):
      if( not isinstance( lsp, int ) ):
        s = type( scope ).__name__
        raise TypeError( "Label String Pointer must be an int, not %s." %s )
      elif( (lsp < 0) or (lsp > 0x3FFF) ):
        raise ValueError( "Label String Pointer out of range: %d." % lsp )

    # L1 encode the NetBIOS name.
    s = (name + (16 * pad))[:15] + suffix
    self._L1name = ''
    for c in s:
      self._L1name += chr( ((ord( c ) >> 4) & 0xFF) + 0x41 )  # High nibble.
      self._L1name += chr( (ord( c ) & 0x0f) + 0x41 )         # Low nibble.

    # L2 encode the NetBIOS name and scope.
    self._L2name = ''
    for s in [self._L1name] + [x for x in scope.split( '.' ) if( x )]:
      self._L2name += chr( len( s ) ) + s

    # If there's no LSP terminate with an empty label length, else the lsp.
    if( lsp is None ):
      self._L2name += '\0'
    else:
      # Encode and store the lsp.
      self._L2name += chr( ((lsp >> 8) & 0xFF) | 0xC0 )       # High byte.
      self._L2name += chr( lsp & 0xFF )                       # Low byte.

    # Is the name too long?
    if( len( self._L2name ) > 0xFF ):
      raise ValueError( "Encoded L2 name exceeds 255 byte maximum length." )

    # Keep track of the validated and cleaned-up input values.
    self._NBname = name
    self._Pad    = pad
    self._Suffix = suffix
    self._Scope  = scope
    self._LSP    = lsp
    return

  def _parseL2name( self, l2name ):
    # Internal method to validate the format of a level 2 encoded NBT name.
    #
    # Input:
    #   l2name  - The L2 encoded NBT name to be validated.
    #
    # Output: A tuple contaning the validated name and Label String Pointer
    #         (LSP) offset.  If the latter is None, then the input name is
    #         terminated with a label length of zero (the normal case).
    #
    # Errors: ValueError  - Raised if the L2 name fails basic sanity checks,
    #                       including:
    #                       + A label length points to a position beyond the
    #                         end of the input string.
    #                       + The second byte of an LSP is beyond the end of
    #                         the input string.
    #                       + A reserved flag combination was found in the
    #                         upper two bits of a label length.
    #
    posn   = 0
    namlen = len( l2name )
    lablen = ord( l2name[0] )
    # Read through the label lengths to ensure correct syntax and total length.
    while( lablen > 0 ):
      if( lablen < 0x40 ):
        # Upper two bits are 00; should be a normal label length.
        posn += 1 + lablen
        if( posn >= namlen ):
          # Must've had invalid length bytes.
          raise ValueError( "Malformed NBT name; label length incorrect." )
        lablen = ord( l2name[posn] )
      elif( 0xC0 == (lablen & 0xC0) ):
        # Upper bits are 11; it's a label string pointer (2 bytes long).
        if( (posn + 1) >= namlen ):
          raise ValueError( "Malformed NBT name; corrupt label pointer." )
        # Trim and return the L2 name, and the LSP.
        lsp = ((lablen & ~0xC0) << 8) + ord( l2name[posn+1] )
        return( (l2name[:posn+2], lsp ) )
      else:
        # Neither a valid length nor a valid label string pointer.
        raise ValueError( "Malformed NBT name; reserved bit pattern used." )
    # Validated, zero-terminated, L2 name.
    return( (l2name[:posn+1], None) )

  def setL2name( self, nbtname=None ):
    """Assign an L2 (wire) format name to the NBT Name object.

    Input:
      nbtname - A fully encoded wire-format NBT name.  This name will
                overwrite the existing name, in all it's forms.

    Output: The length, in bytes, of the L2-encoded NBT name.  This is
            useful for parsing packets, as it indicates the location of
            the data following the L2-encoded name.

    Errors: ValueError        - Raised if the input parameter fails
                                basic sanity checks.
            NBTerror( 1003 )  - A Label String Pointer was encountered.
                                See notes below.

    Notes:  This method always starts by clearing the current name
            stored in the instance.

            If ValueError is raised the NBT Name instance will be empty.

            If an NBTerror (with an eCode of 1003) is raised, the
            instance will contain the portion of the name that was
            provided, terminated with the label string pointer that was
            discovered.  In addition, NBTerror.value will be set to the
            offset extracted from the LSP.

            Use appendL2name() to combine name segments and create a
            single L2 encoded name.

            In practice, the only label string pointer ever used in
            NBT is 0xC00C, which points to an offset of 12.  The
            NBT Name class, and this method, are painfully excessive
            in supporting input of any LSP.  "It should never happen."

            See: http://ubiqx.org/cifs/NetBIOS.html#NBT.4.1.3
            and "Domain name representation and compression" (page 31)
            in [RFC883] for more details on label string pointers.
    """
    # Clear the current name.
    self.reset()

    # Check for empty name.
    if( not nbtname ):
      raise ValueError( "Invalid NBT name (Empty or None)." )
    # Sanity check the initial label length.
    if( ('\x20' != nbtname[0]) and (ord(nbtname[0]) < 0x40) ):
      raise ValueError( "Malformed NBT name; invalid initial name length." )

    # Parse the name, to validate it and to look for a Label String Pointer.
    nbtname, lsp = self._parseL2name( nbtname )

    # Does the name exceed the maximum length?
    namLen = len( nbtname )
    if( namLen > 255 ):
      raise ValueError( "NBT name length exceeds 255 byte maximum." )

    # A correctly formed NBT name.
    self._L2name = nbtname
    # If there's an LSP, we raise an exception.
    if( lsp is not None ):
      self._LSP = lsp
      m = "Info: The given name is terminated by a Label String Pointer:"
      raise NBTerror( 1003, m, lsp )
    return namLen

  def appendL2name( self, nbtname=None ):
    """Concatenate one L2name to another.

    Input:
      nbtname - An L2 encoded NBT name, or portion thereof, presented
                as type 'str'.

    Output: Total length of the recomposed L2-encoded name.

    Errors: ValueError        - Raised if the input parameter fails
                                basic sanity checks.
            NBTerror( 1003 )  - Yet another Label String Pointer was
                                encountered.  See notes below.
            NBTerror( 1004 )  - The L2 name fragment already stored
                                in the instance is not terminated by
                                an LSP.  Appending another segment is
                                not supported.

    Notes:  This method is intended to be called after setL2name() has
            been used to set the initial portion of an L2 name that is
            split using a Label String Pointer (LSP).

            In theory, it's possible that a second segment would also
            contain an LSP.  In practice, it should never, ever happen.
            NBT is a simple protocol, and though LSPs are general in
            design they are only used in one way within NBT:  If two
            names in a packet are the same, the second instance will
            be a pointer to the first.

            The cases in which two names are the same in NBT messages
            always occur in the NBT Name Service, and the offset of the
            first name is always 12 bytes, so the LSP in the second
            position is always 0xC00C.

            This method does not modify the current value of the NBT
            Name instance until the new name segment has been validated.
            If a ValueError or NBTerror( 1004 ) is raised, the initial
            value of the instance will be intact.  If NBTerror( 1003 )
            is raised, the instance will contain the concatenated name,
            terminated with the new LSP and the LSP offset will be
            returned in NBTerror.value.
    """
    # Check that the current L2name really terminates on an LSP.
    L2name = self._L2name
    if( (not L2name) or (len( L2name ) < 2) \
        or (0xC0 != (0xC0 & ord( L2name[-2] ))) ):
      m = "Cannot append to an empty or fully qualified NBT name"
      raise NBTerror( 1004, message=m )

    # Parse the new sequence.
    nbtname, lsp = self._parseL2name( nbtname )
    # Compose and check the new name.
    L2name = L2name[:-2] + nbtname
    if( len( L2name ) > 255 ):
      raise ValueError( "NBT name length exceeds 255 byte maximum." )

    # Valid name.
    self.reset()
    self._L2name = L2name
    if( lsp is not None ):
      self._LSP = lsp
      m = "Info: The given name is terminated by a Label String Pointer:"
      raise NBTerror( 1003, m, lsp )
    return( len( self._L2name ) )

  def getNetBIOSname( self ):
    """Return the NetBIOS name from the NBT Name.

    Output: The decoded NetBIOS name, or None if the object is empty.
    """
    if( self._NBname is None ):
      self._decodeAll()
    return( self._NBname )

  def getLANAname( self ):
    """Return the 16-octet formatted version of the NetBIOS name.

    Output: The decoded, padded, and suffixed NetBIOS name, or None if
            the object is empty.

    Notes:  This is similar to the getNetBIOSname() method, but the
            padding and suffix bytes are included in the result.  The
            output will be a string of 16 octets or None.  The scope
            is not included in the result.

            The LANA name is the 16-byte name as it would have been
            registered on the original LAN Adapter hardware in the
            1980's.
    """
    return( (self.getNetBIOSname() + (15 * self._Pad))[:15] + self._Suffix )

  def getScope( self ):
    """Return the NBT scope string.

    Output: The unencoded scope string, or None if the object is empty.
    """
    if( self._Scope is None ):
      self._decodeAll()
    return( self._Scope )

  def getPadSuffix( self ):
    """Return a tuple containing the padding byte and the suffix byte.

    Output: Either None, or a two-element tuple.  The first element will
            be the padding byte and the second will be the suffix byte.

    Notes:  If the name has not been set, then the padding and suffix
            bytes will be unknown.  That is the only case in which the
            return value will be None.
    """
    if( (self._Pad is None) or (self._Suffix is None) ):
      self._decodeAll()
    if( (self._Pad is None) or (self._Suffix is None) ):
      return( None )
    return( (self._Pad, self._Suffix) )

  def __getPad( self ):
    # "Getter" method for the padding byte value.
    tup = self.getPadSuffix()
    return( tup[0] if( tup ) else None )

  def __getSuffix( self ):
    # "Getter" method for the suffix byte value.
    tup = self.getPadSuffix()
    return( tup[1] if( tup ) else None )

  def getLSP( self ):
    """If the name is terminated by an LSP, return the offset value.

    Output: None, if there is no label string pointer (LSP) in the L2
            name, or an integer in the range 0..0x3FFF representing the
            offset (relative to the start of a given NBT packet) at
            which the remainder of the L2 encoded name can be found.

    Notes:  Once again, in practice the NBT protocol only ever uses
            0xC00C as an L2 name with an LSP.  This code is excessively
            pedantic in its implementation of LSP support.
    """
    if( self._LSP is None ):
      self._decodeAll()
    return( self._LSP )

  def getL1name( self ):
    """Return the L1 encoded version of the NBT name.

    Output: None, if the NBT Name is empty, else the L1 encoded string
            format of the NBT name.

    Notes:  Some systems allow the user to set a scope string that
            contains non-printing characters.  Rare, but possible.
    """
    if( (self._L1name is None) and (self._L2name is not None) ):
      self._L2_decode()
    return( self._L1name )

  def getL2name( self ):
    """Return the fully encoded (wire format) version of the NBT name.

    Output: None, if the NBT Name is empty.  Otherwise, the L2 encoded
            format of the name is returned.
    """
    return( self._L2name )

  # Name object properties.
  NBname = property( getNetBIOSname, doc="Retrieve the NetBIOS name" )
  Pad    = property( __getPad,    doc="Retrieve the Padding byte" )
  Suffix = property( __getSuffix, doc="Retrieve the Suffix byte" )
  Scope  = property( getScope,    doc="Retrieve the Scope string" )
  L1name = property( getL1name,   doc="Retrieve the L1 encoded NBT name" )
  L2name = property( getL2name,   doc="Retrieve the L2 encoded NBT name" )
  LSP    = property( getLSP, doc="Retrieve the Label String Pointer, if any" )


class NSHeader( object ):
  """NBT Name Service Message Header base class.

  All of the Name Service messages start with a set of six 2-octet
  fields.  The format of the Name Service header is derived from the
  DNS system; the NBT RFCs make several references to RFC 883.

  See:  http://www.ubiqx.org/cifs/NetBIOS.html#NBT.4.2
  """
  def __init__( self, TrnId=0, Flags=0, Counts=(0, 0, 0, 0) ):
    """Create an NBT Name Service message.

    Input:
      TrnId   - The Transaction Id.
      Flags   - The message header FLAGS field.
      Counts  - The record counts (QD, AN, NS, AR) as shown in:
                http://www.ubiqx.org/cifs/NetBIOS.html#NBT.4.2.1

    Notes:  All inputs default to zero, which does not map to any
            valid message.

            No comprehensive sanity checks are performed on the input
            parameters.  It is assumed that those checks have already
            been done.
    """
    self._TrnId = (0xFFFF & int( TrnId ))
    self._Flags = (0xFFFF & int( Flags ))
    self._QDcount = 0x0001 if Counts[0] else 0x0000
    self._ANcount = 0x0001 if Counts[1] else 0x0000
    self._NScount = 0x0001 if Counts[2] else 0x0000
    self._ARcount = 0x0001 if Counts[3] else 0x0000

  def __TrnId( self, TrnId=None ):
    # Get/set the Transaction ID (HEADER.NAME_TRN_ID).
    if( TrnId is None ):
      return( self._TrnId )   # Return the current Transaction Id value.
    self._TrnId = (0xFFFF & int( TrnId ))   # Set the NAME_TRN_ID value.

  def __Flags( self, Flags=None ):
    # Get/set the 2-octet HEADER.FLAGS field.
    if( Flags is None ):
      return( self._Flags )   # Return the current HEADER.FLAGS value.
    self._Flags  = (0xFFFF & int( Flags ))    # Set the HEADER.FLAGS value.

  def __Rbit( self, R=None ):
    # Get/set the state of the HEADER.FLAGS.R(esponse) bit.
    if( R is None ):
      return( bool( self._Flags & NS_R_BIT ) )
    if( R ):
      self._Flags |= NS_R_BIT
    else:
      self._Flags &= ~NS_R_BIT

  def __OPcode( self, OPcode=None ):
    # Get/set the HEADER.FLAGS.OPCODE subfield value.
    if( OPcode is None ):
      return( self._Flags & NS_OPCODE_MASK )
    self._Flags = (self._Flags & ~NS_OPCODE_MASK) | (OPcode & NS_OPCODE_MASK)

  def __NMflags( self, NMflags=None ):
    # Get/set the HEADER.FLAGS.NMFLAGS subfield.
    if( NMflags is None ):
      return( self._Flags & NS_NM_FLAGS_MASK )
    self._Flags &= ~NS_NM_FLAGS_MASK
    self._Flags |= (NMflags & NS_NM_FLAGS_MASK)

  def __AAbit( self, AA=None ):
    # Get/set the NM_FLAGS.AA (Authoritative Answer) bit state.
    if( AA is None ):
      return( bool( self._Flags & NS_NM_AA_BIT ) )
    if( AA ):
      self._Flags |= NS_NM_AA_BIT
    else:
      self._Flags &= ~NS_NM_AA_BIT

  def __TCbit( self, TC=None ):
    # Get/set the NM_FLAGS.TC (TrunCation) bit state.
    if( TC is None ):
      return( bool( self._Flags & NS_NM_TC_BIT ) )
    if( TC ):
      self._Flags |= NS_NM_TC_BIT
    else:
      self._Flags &= ~NS_NM_TC_BIT

  def __RDbit( self, RD=None ):
    # Get/set the NM_FLAGS.RD (Recursion Desired) bit state.
    if( RD is None ):
      return( bool( self._Flags & NS_NM_RD_BIT ) )
    if( RD ):
      self._Flags |= NS_NM_RD_BIT
    else:
      self._Flags &= ~NS_NM_RD_BIT

  def __RAbit( self, RA=None ):
    # Get/set the state of the NM_FLAGS.RA (Recursion Available) bit.
    if( RA is None ):
      return( bool( self._Flags & NS_NM_RA_BIT ) )
    if( RA ):
      self._Flags |= NS_NM_RA_BIT
    else:
      self._Flags &= ~NS_NM_RA_BIT

  def __Bbit( self, B=None ):
    # Get/set the state of the Broadcast bit (NM_FLAGS.B).
    if( B is None ):
      return( bool( self._Flags & NS_NM_B_BIT ) )
    if( B ):
      self._Flags |= NS_NM_B_BIT
    else:
      self._Flags &= ~NS_NM_B_BIT

  def __Rcode( self, Rcode=None ):
    # Get/set the message Result Code (NM_FLAGS.RCODE).
    if( Rcode is None ):
      return( self._Flags & NS_RCODE_MASK )
    self._Flags = (self._Flags & ~NS_RCODE_MASK) | (Rcode & NS_RCODE_MASK)

  def __QDcount( self, QDcount=None ):
    # Get/set the number of Question Records included in the message.
    if( QDcount is None ):
      return( self._QDcount )
    # The QDcount must be 0 or 1.
    self._QDcount = 0x0001 if QDcount else 0x0000

  def __ANcount( self, ANcount=None ):
    # Get/set the number of Answer Records included in the message.
    if( ANcount is None ):
      return( self._ANcount )
    # The ANcount must be 0 or 1.
    self._ANcount = 0x0001 if ANcount else 0x0000

  def __NScount( self, NScount=None ):
    # Get/set the number of Name Service Authority records.
    if( NScount is None ):
      return( self._NScount )
    # The NScount must be 0 or 1.
    self._NScount = 0x0001 if NScount else 0x0000

  def __ARcount( self, ARcount=None ):
    # Get/set the number of Additional Records in the message.
    if( ARcount is None ):
      return( self._ARcount )
    # As above, the only valid values are 0 and 1.
    self._ARcount = 0x0001 if ARcount else 0x0000

  def dump( self, indent=0 ):
    """Produce a formatted representation of the Name Service Header.

    Input:
      indent  - Number of spaces to indent the output.

    Ouput:  The header, formatted for display, returned as a string.
    """
    def _TupOPcode():
      # Return a tuple containing the opcode and its string representation.
      xlate = { NS_OPCODE_QUERY:      "Query",
                NS_OPCODE_REGISTER:   "Registration",
                NS_OPCODE_RELEASE:    "Release",
                NS_OPCODE_WACK:       "WACK",
                NS_OPCODE_REFRESH:    "Refresh",
                NS_OPCODE_ALTREFRESH: "AltRefresh",
                NS_OPCODE_MULTIHOMED: "Multi-homed Reg." }
      OPcode = self.__OPcode()
      s = xlate[OPcode] if( OPcode in xlate ) else '<unknown>'
      return( (OPcode, s) )

    def _TupRcode():
      # Return a tuple containing the Rcode and its string representation.
      xlate = { NS_RCODE_POS_RSP: "Positive Response",
                NS_RCODE_FMT_ERR: "Format Error",
                NS_RCODE_SRV_ERR: "Server failure",
                NS_RCODE_NAM_ERR: "Name Error",
                NS_RCODE_IMP_ERR: "Unsupported request",
                NS_RCODE_RFS_ERR: "Refused",
                NS_RCODE_ACT_ERR: "Active error",
                NS_RCODE_CFT_ERR: "Name in conflict" }
      Rcode = self.__Rcode()
      s = xlate[Rcode] if( Rcode in xlate ) else '<unknown>'
      return( (Rcode, s) )

    ind = ' ' * indent
    s  = ind + "Header:\n"
    s += ind + "  Name_Trn_Id.: 0x%04X\n" % self.__TrnId()
    s += ind + "  Flags.......: 0x%04X\n" % self.__Flags()
    s += ind + "        Reply...: %s\n"   % self.__Rbit()
    s += ind + "        OPcode..: 0x%X = %s\n"  % _TupOPcode()
    s += ind + "        NMflags.: 0x%03X\n" % self.__NMflags()
    s += ind + "                AA: %s\n" % self.__AAbit()
    s += ind + "                TC: %s\n" % self.__TCbit()
    s += ind + "                RD: %s\n" % self.__RDbit()
    s += ind + "                RA: %s\n" % self.__RAbit()
    s += ind + "                B.: %s\n" % self.__Bbit()
    s += ind + "        Rcode...: 0x%X = %s\n" % _TupRcode()
    s += ind + "  QDcount....: 0x%04X\n" % self.__QDcount()
    s += ind + "  ANcount....: 0x%04X\n" % self.__ANcount()
    s += ind + "  NScount....: 0x%04X\n" % self.__NScount()
    s += ind + "  ARcount....: 0x%04X\n" % self.__ARcount()
    return( s )

  def compose( self, TrnId=None ):
    """Create the message header.

    Output: The wire format of the NBT Name Service message header,
            presented as a string of 12 octets.
    """
    if( TrnId is not None ):
      self._TrnId = (0xFFFF & int( TrnId ))
    return( _format_NS_hdr.pack( self._TrnId,
                                 self._Flags,
                                 self._QDcount,
                                 self._ANcount,
                                 self._NScount,
                                 self._ARcount ) )

  # Turn the majority of the methods into properties.
  TrnId   = property( __TrnId,   __TrnId,   doc="Transaction ID; NAME_TRN_ID" )
  Flags   = property( __Flags,   __Flags,   doc="Header Flags; HEADER.FLAGS" )
  Rbit    = property( __Rbit,    __Rbit,    doc="Response Flag; R" )
  OPcode  = property( __OPcode,  __OPcode,  doc="Operation Code; OPCODE" )
  NMflags = property( __NMflags, __NMflags, doc="Name Flags: FLAGS.NM_FLAGS" )
  AAbit   = property( __AAbit,   __AAbit,   doc="Authoritative Answer bit; AA" )
  TCbit   = property( __TCbit,   __TCbit,   doc="TrunCation bit; TC" )
  RDbit   = property( __RDbit,   __RDbit,   doc="Recursion Desired bit; RD" )
  RAbit   = property( __RAbit,   __RAbit,   doc="Recursion Available bit; RA" )
  Bbit    = property( __Bbit,    __Bbit,    doc="Broadcast bit; B" )
  Rcode   = property( __Rcode,   __Rcode,   doc="Return Code; RCODE" )
  QDcount = property( __QDcount, __QDcount, doc="Question Records; QDCOUNT" )
  ANcount = property( __ANcount, __ANcount, doc="Answer Records; ANCOUNT" )
  NScount = property( __NScount, __NScount, doc="Authority Records; NSCOUNT" )
  ARcount = property( __ARcount, __ARcount, doc="Additional Records; ARCOUNT" )


class QuestionRecord( object ):
  """NBT Name Service Question Record.

  The Question Record is a basic building block of the NBT Name Service.

  It consists of an encoded NBT name, a question type, and a question
  class.  The question type depends upon the question question being
  asked or answered.  The question class is always NS_Q_CLASS_IN.

  See:  http://www.ubiqx.org/cifs/NetBIOS.html#NBT.4.2.2
  """
  def __init__( self, Qname=None, Qtype=None ):
    """Create an NBT Name Service Question Record.

    Input:
      Qname - An L2-encoded NBT name.
      Qtype - A Question Type value.
              The valid values are NS_Q_TYPE_NB and NS_Q_TYPE_NBSTAT.

    Notes:  The NBT Name Service always uses the Question Class
            NS_Q_CLASS_IN.  There is no reason (other than perverse
            testing) to ever override this value.
    """
    self._Qname  = Qname
    self._Qtype  = Qtype
    self._Qclass = NS_Q_CLASS_IN

  def __Qname( self, Qname=None ):
    # Get/set the encoded NBT Question Name.
    if( Qname is None ):
      return( self._Qname )
    self._Qname = Qname

  def __Qtype( self, Qtype=None ):
    # Get/set the Question Type.
    if( Qtype is None ):
      return( self._Qtype )
    self._Qtype = (0xFFFF & Qtype)

  def __Qclass( self, Qclass=None ):
    # Get/set the Question Class.
    if( Qclass is None ):
      return( self._Qclass )
    self._Qclass = (0xFFFF & Qclass)

  def dump( self, indent=0 ):
    """Produce a formatted representation of the Question Record.

    Input:
      indent  - Number of spaces to indent the output.

    Ouput:  The question record, formatted for display, returned as a
            string.
    """
    def _TupQtype():
      # Return the Qtype and its description as a tuple.
      xlate = { NS_Q_TYPE_NB:     "Name Query",
                NS_Q_TYPE_NBSTAT: "Node Status Query" }
      s = xlate[self._Qtype] if( self._Qtype in xlate ) else '<unknown>'
      return( (self._Qtype, s) )

    def _TupQclass():
      # Return the Qclass and its description as a tuple.
      s = "Internet Class" if( self._Qclass == NS_Q_CLASS_IN ) else '<unknown>'
      return( (self._Qclass, s) )

    n = Name()
    n.setL2name( self._Qname )
    ind = ' ' * indent
    s  = ind + "Question Record:\n"
    s += ind + "  Qname.: %s\n" % hexstr( self._Qname )
    s += ind + "       => %s\n" % str( n )
    s += ind + "  Qtype.: 0x%04X = %s\n" % _TupQtype()
    s += ind + "  Qclass: 0x%04X = %s\n" % _TupQclass()
    return( s )

  def compose( self ):
    """Create the Question Record portion of the message.

    Output: A string of octets that are the wire format of the Question
            Record.
    """
    return( self._Qname + _format_QR.pack( self._Qtype, self._Qclass ) )

  # Create properties.
  Qname  = property( __Qname,  __Qname,  doc="NBT Encoded Name; QUESTION_NAME" )
  Qtype  = property( __Qtype,  __Qtype,  doc="Question Type; QUESTION_TYPE" )
  Qclass = property( __Qclass, __Qclass, doc="Question Class; QUESTION_CLASS" )


class ResourceRecord( object ):
  """NBT Name Service Resource Record.

  The Resource Record is made of three parts:
    * The Name section (which is identical to a Question Record).
    * The TTL (Time To Live) field.  Seconds, given as a 32-bit uint.
    * The Resource Data section, which varies depending upon the
      message type, but always starts with a 2-octet length field.

  See:  http://www.ubiqx.org/cifs/NetBIOS.html#NBT.4.2.3
  """
  def __init__( self, RRname=None, RRtype=None, TTL=None, RDlen=None ):
    """Create an NBT Name Service Resource Record.

    Input:
      RRname  - An L2-encoded NBT name.
                See: http://www.ubiqx.org/cifs/NetBIOS.html#NBT.4.2.3
      RRtype  - A Resource Record Type value.  The valid values are
                NS_RR_TYPE_NB, NS_RR_TYPE_NBSTAT, and possibly
                NS_RR_TYPE_NULL.  The latter is given in the RFCs but
                not used by Windows, though Samba now uses it.  Other
                possible values are NS_RR_TYPE_A and NS_RR_TYPE_NS,
                but these are not used by NBT.
      TTL     - A 32-bit Time to Live value, in seconds.  The default
                TTL is typically around 3 days.
                See: http://www.ubiqx.org/cifs/NetBIOS.html#foot15
      RDlen   - The length of the RDATA section that follows.

    Notes:  The NBT Name Service always uses the Resource Record Class
            NS_RR_CLASS_IN.  There is no reason (other than perverse
            testing) to ever override this value.
    """
    self._RRname  = RRname
    self._RRtype  = (0xFFFF & RRtype)
    self._RRclass = NS_RR_CLASS_IN
    self._TTL     = 0x00000000 if( not TTL ) else (0xFFFFFFFF & int( TTL ))
    self._RDlen   = 0x0000 if( not RDlen ) else (0xFFFF & int( RDlen ))

  def __RRname( self, RRname=None ):
    # Get/set the encoded NBT Resource Record Name.
    if( RRname is None ):
      return( self._RRname )
    self._RRname = RRname

  def __RRtype( self, RRtype=None ):
    # Get/set the Resource Record Type.
    if( RRtype is None ):
      return( self._RRtype )
    self._RRtype = (0xFFFF & RRtype)

  def __RRclass( self, RRclass=None ):
    # Get/set the Resource Record Class.
    if( RRclass is None ):
      return( self._RRclass )
    self._RRclass = (0xFFFF & RRclass)

  def __TTL( self, TTL=None ):
    # Get/set the Time to Live value.
    if( TTL is None ):
      return( self._TTL )
    self._TTL = (0xFFFFFFFF & int( TTL ))

  def __RDlen( self, RDlen=None ):
    # Get/set the RDLENGTH field of the Resource Record.
    if( RDlen is None ):
      return( self._RDlen )
    self._RDlen = (0xFFFF & int( RDlen ))

  def dump( self, indent=0 ):
    """Produce a formatted representation of the Resource Record.

    Input:
      indent  - Number of spaces to indent the output.

    Ouput:  The resource record, formatted for display, returned as a
            string.
    """
    def _TupRRname():
      # Return a tuple contaning two strings:
      # The first is either the empty string or the hexified L2 name.
      # The second is either the string representation of the decoded
      # format of the input string, or an error message.
      try:
        n = Name()
        n.setL2name( self._RRname )
      except NBTerror as nbte:
        if( 1003 == nbte.eCode ):
          s = "LSP offset: %d" % nbte.value
        else:
          # No NBT errors other than 1003 are defined for Name.setL2name().
          s = "NBT Error: %s" % str( nbte )
      except Exception as e:
        s = "Error: %s" % str( e )
      else:
        s = str( n )
      x = '' if( self._RRname is None ) else hexstr( self._RRname )
      return( (x, s) )

    def _TupRRtype():
      # Return the RRtype and its description as a tuple.
      xlate = { NS_RR_TYPE_A:      "Host Address; not used in NBT",
                NS_RR_TYPE_NS:     "Name Server; not used in NBT",
                NS_RR_TYPE_NULL:   "Name lookup failure",
                NS_RR_TYPE_NB:     "Name Query",
                NS_RR_TYPE_NBSTAT: "Node Status" }
      s = xlate[self._RRtype] if( self._RRtype in xlate ) else '<unknown>'
      return( (self._RRtype, s) )

    def _TupRRclass():
      # Return the RRclass and its description as a tuple.
      s = "Internet Class"
      if( self._RRclass != NS_RR_CLASS_IN ):
        s = '<unknown>'
      return( (self._RRclass, s) )

    l2nam, nbnam = _TupRRname()
    ind = ' ' * indent
    s  = ind + "Resource Record:\n"
    s += ind + "  RRname..: %s\n" % l2nam
    s += ind + "         => %s\n" % nbnam
    s += ind + "  RRtype..: 0x%04X = %s\n" % _TupRRtype()
    s += ind + "  RRclass.: 0x%04X = %s\n" % _TupRRclass()
    s += ind + "  TTL.....: %d seconds\n"  % self.__TTL()
    s += ind + "  RDlength: %d bytes\n"    % self.__RDlen()
    return( s )

  def compose( self ):
    """Create the Resource Record portion of the message.

    Output: A string of octets that are the wire format of a Resource
            Record (excluding the RDATA).
    """
    s = _format_RR.pack( self._RRtype, self._RRclass, self._TTL, self._RDlen )
    return( self._RRname + s )

  # Create properties.
  RRname = property( __RRname,  __RRname,  doc="Resource Record Name; RR_NAME" )
  RRtype = property( __RRtype,  __RRtype,  doc="Resource Record Type; RR_TYPE" )
  RRclass= property( __RRclass, __RRclass, doc="Resource Record Type; RR_TYPE" )
  TTL    = property( __TTL,     __TTL,     doc="Time To Live; TTL" )
  RDlen  = property( __RDlen,   __RDlen,   doc="RDATA Length; RDLENGTH" )


class AddressRecord( object ):
  """NBT Name Service Address Record.

  Several messages in the NBT Name Service use the following RDATA
  format:
    RDATA
      {
      NB_FLAGS
        {
        G   = <TRUE for a group name, FALSE for a unique name>
        ONT = <Owner type>
        }
      NB_ADDRESS = <Requesting node's IP address>
      }

  This class implements that structure.  We're calling it an Address
  Record for lack of a better name.

  For an example, see http://www.ubiqx.org/cifs/NetBIOS.html#NBT.4.3.1

  Doctext:
  >>> ip = chr( 10 ) + chr( 64 ) + chr( 109 ) + chr( 73 )
  >>> hexstr( AddressRecord( True, NS_ONT_H, ip ).compose() )
  '\\\\xE0\\\\x00\\\\x0A@mI'
  """
  def __init__( self, G=False, ONT=NS_ONT_B, IP=None ):
    """Create an Address Record.

    Input:
      G       - Boolean; True if the associated name is a Group name,
                else False.
      ONT     - Owner Node Type.
                  NS_ONT_B == B node
                  NS_ONT_P == P node
                  NS_ONT_M == M node
                  NS_ONT_H == H node (Microsoft extension to STD 19)
      IP      - IPv4 address.
    """
    self._NBaddr  = (IP[:4] if( IP ) else (4 * '\0'))
    self._NBflags = (ONT & NS_ONT_MASK)
    if( G ):
      self._NBflags |= NS_GROUP_BIT

  def __Gbit( self, G=None ):
    # Get/set the Group (G) bit in the NB_FLAGS field.
    if( G is None ):
      return( bool( NS_GROUP_BIT & self._NBflags ) )
    if( G ):
      self._NBflags |= NS_GROUP_BIT
    else:
      self._NBflags &= ~NS_GROUP_BIT

  def __ONT( self, ONT=None ):
    # Get/set the Owner Node Type in the RDATA.NB_FLAGS.
    if( ONT is None ):
      return( NS_ONT_MASK & self._NBflags )
    self._NBflags = (self._NBflags & ~NS_ONT_MASK) | (NS_ONT_MASK & ONT)

  def __NBaddr( self, NBaddr=None ):
    # Get/set the RDATA.NB_ADDRESS of the message.
    if( NBaddr is None ):
      return( self._NBaddr )
    self._NBaddr = (NBaddr[:4] if( NBaddr ) else (4 * '\0'))

  def __NBflags( self, NBflags=None ):
    # Get/set the RDATA.NB_FLAGS field as a whole.
    if( NBflags is None ):
      return( self._NBflags )
    self._NBflags = (NBflags & NS_NBFLAG_MASK)

  def dump( self, indent ):
    """Produce a formatted representation of the Address Record.

    Input:
      indent  - Number of spaces to indent the output.

    Ouput:  The address record, formatted for display, returned as a
            string.
    """
    def _TupONT():
      # Return the string representation of the Owner Node Type value.
      ont = self.__ONT()
      return( (ont, (_ontDict[ont] if( ont in _ontDict ) else '<unknown>')) )

    ipv4 = tuple( ord( octet ) for octet in tuple( self.__NBaddr() ) )
    ind = ' ' * indent
    s  = ind + "RDATA (Address Record):\n"
    s += ind + "  NBflags.: 0x%04x\n"   % self.__NBflags()
    s += ind + "          G...: %s\n"         % self.__Gbit()
    s += ind + "          ONT.: 0x%X = %s\n"  % _TupONT()
    s += ind + "  NBaddr..: %u.%u.%u.%u" % ipv4
    return( s )

  def compose( self ):
    """Create the wire-format representation of the Address Record.

    Output: A byte stream.
    """
    return( _format_Short.pack( self._NBflags ) + self._NBaddr )

  # Properties.
  Gbit    = property( __Gbit,    __Gbit,    doc="Group bit; RDATA.NB_FLAGS.G" )
  ONT     = property( __ONT,     __ONT,     doc="Owner Node Type; NB_FLAGS.ONT")
  NBaddr  = property( __NBaddr,  __NBaddr,  doc="IPv4 address; NB_ADDRESS" )
  NBflags = property( __NBflags, __NBflags, doc="Name flags; NB_FLAGS" )


class NodeStatusRequest( NSHeader, QuestionRecord ):
  """NBT Node Status Query Request.

  The Node Status Request (aka. Adapter Status Query) was originally
  used to request the status of the LAN Adapter (LANA) cards used in
  the original PC Network system.  In modern usage, the Node Status
  Request asks for the receiver's name table.

  See:  http://www.ubiqx.org/cifs/NetBIOS.html#NBT.4.3.5
  """
  def __init__( self, TrnId=0, L2name=None ):
    """Create an NBT Node Status Request.

    Input:
      TrnId   - Transaction Id.
      L2name  - The name to be queried.

    Notes:  The <TrnId> may be left zero, and filled in when the
            message is composed.
    """
    NSHeader.__init__( self, TrnId, NS_OPCODE_QUERY, (1, 0, 0, 0) )
    QuestionRecord.__init__( self, L2name, NS_Q_TYPE_NBSTAT )

  def dump( self, indent=0 ):
    """Dump a Node Status Request message in printable format.

    Input:
      indent  - Number of spaces to indent the output.

    Ouput:  The Node Status Request message, formatted for display and
            returned as a string.
    """
    return( NSHeader.dump( self, indent ) +
            QuestionRecord.dump( self, indent ) )

  def compose( self, TrnId=None ):
    """Create the message packet from the available parts.

    Input:
      TrnId - Transaction Id.  If not None, the given value will
              overwrite any previously provided value.

    Output: A byte string.
            This is the formatted node status request message, ready
            to be sent via UDP.
    """
    if( TrnId is not None ):
      self._TrnId = (0xFFFF & int( TrnId ))
    return( NSHeader.compose( self ) + QuestionRecord.compose( self ) )


class NodeStatusResponse( NSHeader, ResourceRecord ):
  """NBT Node Status Response.

  The Node Status Response includes a statistics section, the format of
  which tends to vary from implementation to implementation.  The
  record layout returned from Windows systems differs from the layout
  specified by the RFCs.  Under NBT, however, there is agreement on
  the first six bytes, which should contain the MAC address of the
  interface on which the names are registered (or all zeros).

  See:  http://www.ubiqx.org/cifs/NetBIOS.html#NBT.4.3.5.1
  """
  def __init__( self, TrnId=0, L2name=None, NameList=[], MAC=None ):
    """Create an NBT Node Status Response.

    Input:
      TrnId     - Transaction Id.
      L2name    - The queried name, copied from the request.
      NameList  - A list of tuples.  Each tuple contains two elements:
                  NetBIOSname - An unencoded NetBIOS name, totaling 16
                                bytes in length.  The name must include
                                the suffix byte and any padding.
                  NameFlags   - The Group bit, the owner node type
                                bits, and four name status bits, all
                                packed into a 16-byte integer.
      MAC       - An optional MAC address, presented as a string of 6
                  bytes.  If None, the MAC field will be filled with
                  zeros (which is what Samba does).
    """
    # Header
    flags = ( NS_R_BIT | NS_OPCODE_QUERY | NS_NM_AA_BIT )
    NSHeader.__init__( self, TrnId, flags, (0, 1, 0, 0) )
    # Node Status RDATA
    self._NameList = NameList[:255] if( NameList ) else []
    self._MAC   = MAC[:6] if( MAC ) else (6 * '\0')
    # Resource Record
    rdlen = 7 + (18 * (len( self._NameList ) & 0xFF ))
    ResourceRecord.__init__( self, L2name, NS_RR_TYPE_NBSTAT, 0, rdlen )

  def __NameList( self, NameList=None ):
    # Get/set the list of names in the response.
    if( NameList is None ):
      return( self._NameList )
    self._NameList = NameList[:255] if( NameList ) else []
    self._RDlen = 7 + (18 * (len( self._NameList ) & 0xFF ))

  def __MAC( self, MAC=None ):
    # Get/set the MAC address value.
    if( MAC is None ):
      return( self._MAC )
    self._MAC = (MAC + (6 * '\0'))[:6] if( MAC ) else (6 * '\0')

  def dump( self, indent=0 ):
    """Dump a Node Status Request message in printable format.

    Input:
      indent  - Number of spaces to indent the output.

    Ouput:  The Node Status Request message, formatted for display and
            returned as a string.
    """
    ind = ' ' * indent
    s = NSHeader.dump( self, indent ) + ResourceRecord.dump( self, indent )
    s += ind + "  RDATA (Address Record):\n"
    s += ind + "    Num_Names:  %d\n" % len( self._NameList )
    for NetBIOSname, NameFlags in self._NameList:
      flgstr  = _ontDict[ (NS_ONT_MASK & NameFlags) ]
      flgstr += ", " + (" Group" if( NS_GROUP_BIT & NameFlags ) else "Unique")
      for nf in [ NS_ACT, NS_CNF, NS_DRG, NS_PRM ]:
        if( (NameFlags & nf) == nf ):
          flgstr += ", " + _nameFlagDict[ nf ]
      s += ind + "    %s" % hexstr( NetBIOSname[:15] )
      s += ind + "<%s> [%s]\n" % (hexbyte( NetBIOSname[15] ), flgstr)
    return( s )

  def compose( self, TrnId=None ):
    """Create an NBT Node Status Response message.

    Input:
      TrnId - Transaction Id.  If not None, the given value will
              overwrite any previously provided value.

    Output: A byte string.
            This is the formatted node status response message, ready
            to be sent via UDP.

    Note:   Currently, we only handle a 6-byte statistics section in
            the response format.  This is smaller than Windows or the
            RFCs prescribe.  It should be okay, but if it's not we can
            add padding bytes (NULs) to fill in the missing space.
    """
    if( TrnId is not None ):
      self._TrnId = (0xFFFF & int( TrnId ))
    # Header
    s = NSHeader.compose( self, self._TrnId )
    # Resource Record
    s += ResourceRecord.compose( self )
    # Quantify the name list; The name list size is given as a single byte.
    s += chr( (len( self._NameList ) & 0xFF ) )
    # Node_Name entries; The names should be 16 octets long already, but...
    for nam, flg in self._NameList:
      s += (nam + (16 * '\0'))[:16]   # ...pad and trim them, just to be sure.
      s += _format_Short.pack( NS_NAMEFLAG_MASK & flg )
    # MAC address
    s += self._MAC
    return( s )

  # Create properties.
  NameList = property( __NameList, __NameList, doc="List of registered names." )
  MAC      = property( __MAC,      __MAC,      doc="Interface MAC address." )


class NameQueryRequest( NSHeader, QuestionRecord ):
  """NBT Name Query Request.

  There are three kinds of Name Query Requests.

  Broadcast Name Queries are used for name resolution only.  They must
  have the B bit set.  In addition, the RD bit should (by convention)
  be set, but must be ignored by the receiving nodes.  The RD bit has
  no actual meaning in a broadcast query.

  Unicast Name Resolution Queries are sent to the NetBIOS Name Server
  (NBNS).  These must have the B bit clear and the RD bit set.  RD, in
  this case, means that if the query could not be resolved from the
  local name table, it should be resolved from the NBNS database.

  Unicast Name Verification Queries have both the B and RD bits clear.
  These queries are sent directly to a node to verify that the node
  still claims ownership of the queried name.  The answer must come
  from the local name table.

  See:  http://www.ubiqx.org/cifs/NetBIOS.html#NBT.4.3.2
  """
  def __init__( self, TrnId=0, B=True, RD=True, L2name=None ):
    """Create an NBT Name Query Request.

    Input:
      TrnId   - The Transaction Id.  This defaults to zero when
                instantiating a NameQueryRequest, but may be given when
                composing the wire format message using the compose()
                method.
      B       - Boolean.  If True, the B (Broadcast) bit will be set in
                the query.  Otherwise the B bit will be clear (0).
      RD      - Boolean.  If True, the RD (Recursion Desired) bit will
                be set in the query.  Otherwise the RD bit will be clear
                (0).
      L2name  - The L2 encoded query name.

    Notes:  No comprehensive sanity checks are performed on the input.
            It is assumed that those checks have already been done.
    """
    NSHeader.__init__( self, TrnId, NS_OPCODE_QUERY, (1, 0, 0, 0) )
    QuestionRecord.__init__( self, L2name, NS_Q_TYPE_NB )
    self.Bbit  = B
    self.RDbit = RD

  def dump( self, indent=0 ):
    """Dump a Name Query Request message in printable format.

    Input:
      indent  - Number of spaces to indent the output.

    Ouput:  The Name Query Request message, formatted for display and
            returned as a string.
    """
    return( NSHeader.dump( self, indent ) +
            QuestionRecord.dump( self, indent ) )

  def compose( self, TrnId=None ):
    """Create the message packet from the available parts.

    Input:
      TrnId - Transaction Id.  If not None, the given value will
              overwrite any previously provided value.

    Output: A byte string.
            This is the formatted name query request message, ready
            to be sent via UDP.
    """
    if( TrnId is not None ):
      self._TrnId = (0xFFFF & int( TrnId ))
    return( NSHeader.compose( self ) + QuestionRecord.compose( self ) )


class NameQueryResponse( NSHeader, ResourceRecord ):
  """NBT Name Query Response message.

  The name query response may be positive or negative.  The negative
  response will have an error code in the FLAGS.RCODE field, and the
  Answer Record will be minimally populated.

  See:  http://www.ubiqx.org/cifs/NetBIOS.html#NBT.4.3.2.1
        http://www.ubiqx.org/cifs/NetBIOS.html#NBT.4.3.2.2
  """
  def __init__( self, TrnId   = 0,
                      RD      = True,
                      RA      = True,
                      Rcode   = NS_RCODE_POS_RSP,
                      L2name  = None,
                      TTL     = 0,
                      AddrList= [] ):
    """Create an NBT Name Query Response.

    Input:
      TrnId     - Transaction Id.
      RD        - Should match the value received in the request.
      RA        - True if the reply is from the NBNS, else False.
      Rcode     - Error code, if any.
      L2name    - The query name.
      TTL       - TTL (always zero in negative responses).
      AddrList  - A list of AddressRecord objects.

    Notes:  When the message is instantiated, the <RRtype> value is
            filled in based upon the values of <Rcode> and <AddrList>.
            If <Rcode> is non-zero and the <AddrList> is empty, then
            <RRtype> is set to NS_RR_TYPE_NULL.  Otherwise, it is set
            to NS_RR_TYPE_NB.

            Subsequent changes to <AddrList> and/or <Rcode> will not
            change the value of <RRtype>.  That's the responsibility
            of the calling code.  Once again, this approach is taken
            to make it easy to create correct messages, and possible
            to create incorrect messages for evil testing purposes.
    """
    flags = ( NS_R_BIT | NS_OPCODE_QUERY | NS_NM_AA_BIT )
    NSHeader.__init__( self, TrnId, flags, (0, 1, 0, 0) )
    ResourceRecord.__init__( self, L2name, NS_RR_TYPE_NB, 0, 0 )
    # Set any additional HEADER.FLAG fields.
    self.RDbit = RD
    self.RAbit = RA
    self.Rcode = Rcode
    # If it's a negative response, set the RRtype to NULL.
    #   Note: From this point out, the caller can manually override the
    #         Rcode, AddrList, and RRtype.
    if( Rcode and not AddrList ):
      self.RRtype = NS_RR_TYPE_NULL
    # TTL.
    self.TTL   = TTL
    # ...and set the address list by calling the __AddrList() method.
    self.__AddrList( aList if( aList ) else [] )

  def __AddrList( self, AddrList=None ):
    # Set the address list for the NBT Name Query Response.
    if( AddrList is None ):
      return( self._AddrList )
    if( not isinstance( msg, list ) ):
      raise TypeError( "The Address List must be a list, or None." )
    self._AddrList = AddrList
    self.RDlen = 6 * len( AddrList )

  def dump( self, indent=0 ):
    """Dump a Name Query Response message in printable format.

    Input:
      indent  - Number of spaces to indent the output.

    Ouput:  The Name Query Response message, formatted for display and
            returned as a string.
    """
    return( NSHeader.dump( self, indent )+ResourceRecord.dump( self, indent ) )

  def compose( self, TrnId=None ):
    """Create an NBT Name Query Response message.

    Input:
      TrnId - Transaction Id.  If not None, the given value will
              overwrite any previously provided value.

    Output: A byte string.
            This is the formatted name query response message, ready
            to be sent via UDP.
    """
    if( TrnId is not None ):
      self._TrnId = (0xFFFF & int( TrnId ))
    # Header
    s = NSHeader.compose( self, self._TrnId )
    # Resource Record
    s += ResourceRecord.compose( self )
    # RData; the address list.
    for AddrEntry in self._AddrList:
      s += AddrEntry.compose()
    return( s )

  AddrList = property( __AddrList, __AddrList,
                       doc="Name Query Answers; ADDR_ENTRY[]" )


class NameRegistrationRequest( NSHeader, QuestionRecord,
                               ResourceRecord, AddressRecord ):
  """NBT Name Registration Request.

  The NBT Name Service requires that names be registered before they
  may be used.  This message is used to perform the registration
  (unless the host is a multi-homed host...there's a different message
  for that).

  Name registrations may be sent as a broadcast message to the local
  LAN, or unicast to the NetBIOS Name Server (NBNS).

  The Name Registration Request is made up of four components:
  - The header.
  - A Question Record.
  - A Resource Record.  The RR_NAME field contains a label string
    pointer to the QUESTION_NAME in the previous section.
  - An Address Record.

  See:  http://www.ubiqx.org/cifs/NetBIOS.html#NBT.4.3.1
  """
  def __init__( self, TrnId = 0,
                      B     = True,
                      L2name= None,
                      TTL   = 0,
                      G     = False,
                      ONT   = NS_ONT_B,
                      IP    = None ):
    """Create a Name Registration Request message.

    Input:
      TrnId   - Transaction Id.
      B       - Boolean; the value of the B (Broadcast) bit.  Should be
                True for broadcast registrations.
      L2name  - The name to be registered, fully encoded.
      TTL     - This value should be zero for broadcast registrations,
                and should be roughly 3 days for point-to-point (NBNS)
                registrations.  The exact value is implementation-
                specific.
      G       - Boolean; set to True if the name is being registered
                as a Group name, else False.
      ONT     - Owner Node Type.
                  NS_ONT_B == B node
                  NS_ONT_P == P node
                  NS_ONT_M == M node
                  NS_ONT_H == H node (Microsoft extension to STD 19)
      IP      - IPv4 address of the requesting node.  This, of course,
                is the IP of the interface on which the NBT Name
                Service is running.  It should be given as a string of
                four octets.

    Notes:  In response to a unicast registration request, the NBNS may
            return a different (lesser) TTL value in the response. That
            value becomes authoritative.

            To register a multi-homed host with the NBNS, you need a
            MultiHomedRegRequest message.
    """
    flags = NS_OPCODE_REGISTER | NS_NM_RD_BIT
    NSHeader.__init__( self, TrnId, flags, (1, 0, 0, 1) )
    QuestionRecord.__init__( self, L2name, NS_Q_TYPE_NB )
    ResourceRecord.__init__( self, NS_RR_LSP, NS_RR_TYPE_NB, TTL, 6 )
    AddressRecord.__init__( self, G, ONT, IP )
    # Set additional header flags.
    self.Bbit  = B

  def dump( self, indent=0 ):
    """Dump a Name Registration Request message in printable format.

    Input:
      indent  - Number of spaces to indent the output.

    Ouput:  The Name Registration Request message, formatted for display
            and returned as a string.
    """
    return( NSHeader.dump( self, indent ) +
            QuestionRecord.dump( self, indent ) +
            ResourceRecord.dump( self, indent ) +
            AddressRecord.dump( self, indent+2 ) )

  def compose( self, TrnId=None ):
    """Create an NBT Name Registration Request message.

    Input:
      TrnId - Transaction Id.  If not None, the given value will
              overwrite any previously provided value.

    Output: A byte string.
            This is the formatted name registration request, ready
            to be sent via UDP.
    """
    if( TrnId is not None ):
      self._TrnId = (0xFFFF & int( TrnId ))
    return( NSHeader.compose( self ) +
            QuestionRecord.compose( self ) +
            ResourceRecord.compose( self ) +
            AddressRecord.compose( self ) )


class NameRegistrationResponse( NSHeader, ResourceRecord, AddressRecord ):
  """NBT Name Registration Response.

  A node sending a broadcast Name Registration Request (the requester)
  may receive unicast Negative Name Registration Responses from one or
  more nodes that already claim ownership of the name (the owners).  A
  unicast Negative Name Registration Response is the only valid message
  that can be received in response to a broadcast registration.

  Things are more complicated for the requester when the request is
  sent to an NBNS.  The NBNS may respond with:
  * A Positive Name Registration Response
  * A Negative Name Registration Response
  * One or more WACK responses, followed by one of the above.
  * An End Node Challenge Name Response, which is (in theory) sent by
    some NBNS implementations.

  Note:  If the NBNS sends back a Positive Response, the client must
         use the TTL value in the response (instead of the one that it
         sent in the request) as the registration timeout.

  See:  http://www.ubiqx.org/cifs/NetBIOS.html#NBT.4.3.1.1
  """
  def __init__( self, TrnId = 0,
                      Rcode = NS_RCODE_POS_RSP,
                      L2name= None,
                      TTL   = 0,
                      G     = False,
                      ONT   = NS_ONT_B,
                      IP    = None ):
    """Create an NBT Name Service Name Registration Response message.

    Input:
      TrnId   - Transaction Id.
      Rcode   - Error code, if any.
      L2name  - The query name.
      TTL     - Time to live.  See the notes, below.
      G       - Boolean; True if the registered name is a Group name,
                else False.
      ONT     - Owner Node Type.
                  NS_ONT_B == B node
                  NS_ONT_P == P node
                  NS_ONT_M == M node
                  NS_ONT_H == H node (Microsoft extension to STD 19)
      IP      - IPv4 address of the registered node.  In a positive
                response, this will be the same as the IP given in
                the request.  In a negative response, however, the
                RDATA values are those of the owner.

    Notes:  As mentioned, the TTL given in a Positive response is
            assigned by the server.  It may be less than or equal to
            the requested TTL.  The TTL value in a Negative response
            isn't particularly interesting, and should be set to zero.
    """
    flags  = NS_R_BIT | NS_OPCODE_REGISTER | \
             NS_NM_AA_BIT | NS_NM_RD_BIT | NS_NM_RA_BIT
    NSHeader.__init__( self, TrnId, flags, (0, 1, 0, 0) )
    ResourceRecord.__init__( self, L2name, NS_RR_TYPE_NB, TTL, 6 )
    AddressRecord.__init__( self, G, ONT, IP )
    self.Rcode = Rcode

  def dump( self, indent=0 ):
    """Dump a Name Registration Response message in printable format.

    Input:
      indent  - Number of spaces to indent the output.

    Ouput:  The Name Registration Response message, formatted for
            display and returned as a string.
    """
    return( NSHeader.dump( self, indent ) +
            ResourceRecord.dump( self, indent ) +
            AddressRecord.dump( self, indent ) )

  def compose( self, TrnId=None ):
    """Create an NBT Name Registration Response message.

    Input:
      TrnId - Transaction Id.  If not None, the given value will
              overwrite any previously provided value.

    Output: A byte string.
            This is the formatted name registration response, ready
            to be sent via UDP.
    """
    if( TrnId is not None ):
      self._TrnId = (0xFFFF & int( TrnId ))
    return( NSHeader.compose( self ) +
            ResourceRecord.compose( self ) +
            AddressRecord.compose( self ) )


class ChallengeNameRegistrationResponse( NameRegistrationResponse ):
  """End-Node Challenge Name Registration Response

  This is an awkward message.  It is almost identical to a Positive
  Name Registration Response.  The key difference is that the Recursion
  Available (RA) bit is clear (0) instead of set (1).  That one subtle
  difference means a great deal.

  An NBNS *may* send an End-Node Challenge Name Registration Response
  if it detects a name collision.  This message instructs the client
  (the original requester) that it must check with the name owner to
  determine whether or not the name is in use.  If the name owner is
  no longer using the name, the requester may claim it using a Name
  Update Request.

  This is a terrible way to do business.

  See:  http://www.ubiqx.org/cifs/NetBIOS.html#NBT.4.3.1.2
  """
  def __init__( self, TrnId = 0,
                      L2name= None,
                      G     = False,
                      ONT   = NS_ONT_B,
                      IP    = None ):
    """Instantiate an End-Node Challenge Name Registration message.

      TrnId   - Transaction Id.
      L2name  - The query name.
      G       - Group (True) or Unique (False) name.
      ONT     - Owner Node Type.
      IP      - IPv4 address of the registered node.

    Notes:  <G>, <ONT>, and <IP> must be retrieved from the NBNS
            database.  The IP address is the address of the owner
            node.
    """
    # Rcode is zero, as required for an End-Node Challenge message.
    # TTL is also given as zero, since it has no real purpose here.
    super( ChallengeNameRegistrationResponse, self
         ).__init__( TrnId, 0, L2name, 0, G, ONT, IP )
    self.RA = False


class WaitForAcknowledgementResponse( NSHeader, ResourceRecord ):
  """WACK; Wait for Acknowledgement Response

  The Wait for Acknowledgement Response is only ever sent by the NBNS
  in response to a name registration requests--regular or Multi-Homed.
  The WACK is typically used instead of sending an End-Node Challenge
  Name Registration Response, because it allows the NBNS, rather than
  the requesting client, to decide whether or not an existing name is
  still in use by the current owner.

  The WACK basically allows the NBNS to tell the requester to hang on
  for a few seconds while the NBNS figures out the actual state of a
  currently registered name.

  See:  http://www.ubiqx.org/cifs/NetBIOS.html#NBT.4.3.1.2
  """
  def __init__( self, TrnId=0, L2name=None, TTL=0, RDflags=None ):
    """Create a WACK message object.

    Input:
      TrnId   - The NAME_TRN_ID (Transaction Id) copied from the
                original request.
      L2name  - The RR_NAME copied from the original request.
      TTL     - The number of seconds that the NBNS is requesting that
                the client wait for a response before the client either
                retries its request or gives up.
      RDflags - The HEADER.FLAGS field copied from the original request.
    """
    flags = NS_R_BIT | NS_OPCODE_WACK | NS_NM_AA_BIT
    NSHeader.__init__( self, TrnId, flags, (0, 1, 0, 0) )
    ResourceRecord.__init__( self, L2name, NS_RR_TYPE_NB, TTL, 2)
    self._RDflags = (NS_HEADER_FLAGS_MASK & (0 if( not RDflags ) else RDflags))

  def dump( self, indent=0 ):
    """Dump a WACK.

    Input:
      indent  - Number of spaces to indent the output.

    Ouput:  The Wait For Acknowledgement Response message, formatted for
            display and returned as a string.
    """
    return( NSHeader.dump( self, indent )+ResourceRecord.dump( self, indent ) )

  def compose( self, TrnId=None ):
    """Create the wire-format WACK message.

    Input:
      TrnId - Transaction Id.  If not None, the given value will
              overwrite any previously provided value.

    Output: A byte string.
            This is the formatted name WACK response, ready to be sent
            via UDP.
    """
    if( TrnId is not None ):
      self._TrnId = (0xFFFF & int( TrnId ))
    # Header
    s = NSHeader.compose( self )
    # Resource Record
    s += ResourceRecord.compose( self )
    # RData
    return( s + _format_Short.pack( self._RDflags ))


class MultiHomedNameRegistrationRequest( NameRegistrationRequest ):
  """Multi-Homed Host Name Registration Request message.

  This message is an extension to the protocol as specified in the RFCs.
  It may have been added by IBM, or possibly by Microsoft, to handle the
  problem

  See:  http://www.ubiqx.org/cifs/NetBIOS.html#NBT.4.3.1.4
  """
  def __init__( self, TrnId = 0,
                      L2name= None,
                      TTL   = 0,
                      ONT   = NS_ONT_P,
                      IP    = None ):
    """Create a Multi-Homed Name Registration Request message.

    Input:
      TrnId   - Transaction Id.
      L2name  - The name to be registered, fully encoded.
      TTL     - The Time To Live should be set to roughly 3 days.
                Multi-homed registrations are always sent to the NBNS
                and are never broadcast.
      ONT     - Owner Node Type.  Cannot be a B node.
                  NS_ONT_P == P node
                  NS_ONT_M == M node
                  NS_ONT_H == H node (Microsoft extension to STD 19)
      IP      - IPv4 address of the requesting node.

    Notes:  The IP address, of course, will depend upon the interface
            from which the Multi-Homed Name Registration Request is
            sent.  On a multi-homed host, each such request will be sent
            from a different interface, and will have a different IP
            address (and different Transaction ID).

            Multi-homed registrations are only ever sent as unicast to
            the NBNS.  In addition, only unique names are registered
            this way.  Group names can be associated with multiple IP
            addresses, so there is no reason to use a multi-homed
            registration.
    """
    # The B and G bits are left clear (0).
    super( MultiHomedNameRegistrationRequest, self
         ).__init__( TrnId, False, L2name, TTL, False, ONT, IP )
    self.OPcode = NS_OPCODE_MULTIHOMED


class NameRefreshRequest( NameRegistrationRequest ):
  """Name Refresh Request message.

  The Name Refresh Request message is sent to the NBNS as a way of
  saying "I'm still here", and resetting the TTL timer.  Name Refresh
  Request messages are never broadcast.

  See:  http://www.ubiqx.org/cifs/NetBIOS.html#NBT.4.3.3
  """
  def __init__( self, TrnId = 0,
                      L2name= None,
                      TTL   = 0,
                      G     = False,
                      ONT   = NS_ONT_P,
                      IP    = None ):
    """Create a Name Refresh Request.

    Input:
      TrnId   - Transaction Id.
      L2name  - The name to be refreshed, fully encoded.
      TTL     - The Time To Live.
      G       - Boolean; set to True if the name is being registered
                as a Group name, else False.
      ONT     - Owner Node Type.  (Cannot be a B node.)
                  NS_ONT_P == P node
                  NS_ONT_M == M node
                  NS_ONT_H == H node (Microsoft extension to STD 19)
      IP      - IPv4 address of the requesting node.

    Notes:  The L2name and the Address Entry (RDATA.ADDR_ENTRY) must
            match what was sent in the original request.  If these
            fields do not match, the NameRefresh is handled like a
            Name Registration Request.  Also, if a Name Registration
            Request is sent to the NBNS for a name that already exists
            then the Registration is handled as if it were a Refresh.
            There's not much point in having a separate message type.
    """
    # Leave the B bit clear (0).
    super( NameRegistrationRequest, self
         ).__init__( TrnId, False, L2name, TTL, G, ONT, IP )
    # These 2 changes differentiate this message from a Unicast registration.
    self.OPcode = NS_OPCODE_REFRESH
    self.RDbit  = False


class NameReleaseRequestandDemand( NameRegistrationRequest ):
  """Name Release Request or Name Release Demand message.

  A Name Release sent in B mode is a Name Release Demand; no response is
  expected.  Any node receiving the Name Release Demand message should
  flush the released name from its local cache (if it has one).

  When unicast to an NBNS, this message is a Name Release Request.  The
  NBNS should remove the matching entry from its database and reply with
  a Name Release Response.

  The Name Release Demand may also be unicast to an end node.  This may
  be done if a name conflict is detected on the network.  The receiving
  node is supposed to give up ownership of the offending name, but most
  NBT end-nodes ignore the Name Release Demand.

  See:  http://www.ubiqx.org/cifs/NetBIOS.html#NBT.4.3.4
        http://www.ubiqx.org/cifs/NetBIOS.html#NBT.4.3.6.1
  """
  def __init__( self, TrnId = 0,
                      B     = True,
                      L2name= None,
                      G     = False,
                      ONT   = NS_ONT_P,
                      IP    = None ):
    """Create a Name Release Request or Demand.

    Input:
      TrnId   - Transaction Id.
      B       - Boolean; the value of the B (Broadcast) bit.  Should be
                True for Broadcast Name Release Demand messages, and
                False for unicast Request and Demand messages.
      L2name  - The name to be released, fully encoded.
      G       - Boolean; should match the already registered name.
      ONT     - Owner Node Type.
                  NS_ONT_B == B node
                  NS_ONT_P == P node
                  NS_ONT_M == M node
                  NS_ONT_H == H node (Microsoft extension to STD 19)
      IP      - IPv4 address of the registered name.

    Notes:  The name, Group bit, Owner Node Type and IP address in the
            message need to match the name to be released.
    """
    # TTL is Zero.
    super( NameReleaseRequestAndDemand, self
         ).__init__( TrnId, B, L2name, 0, G, ONT, IP )
    self.OPcode = NS_OPCODE_RELEASE


class NameReleaseResponse( NameRegistrationResponse ):
  """NBNS Name Release Response message.

  This message is sent by the NBNS in response to a Name Release
  Request.

  This message is identical to the Name Registration Response,
  except that it has a different OPcode and the RD and RA bits are
  clear (0).

  See:  http://www.ubiqx.org/cifs/NetBIOS.html#NBT.4.3.4.1
  """
  def __init__( self, TrnId = 0,
                      Rcode = NS_RCODE_POS_RSP,
                      L2name= None,
                      G     = False,
                      ONT   = NS_ONT_B,
                      IP    = None ):
    """Create an NBT Name Service Name Release Response message.

    Input:
      TrnId   - Transaction Id.
      Rcode   - Error code, if any.
      L2name  - The query name.
      G       - Boolean; True if the registered name is a Group name,
                else False.
      ONT     - Owner Node Type.  (Cannot be a B node.)
                  NS_ONT_P == P node
                  NS_ONT_M == M node
                  NS_ONT_H == H node (Microsoft extension to STD 19)
      IP      - IPv4 address of the released name to IP mapping.

    Notes:  The RData should be copied from the request.
    """
    flags  = NS_R_BIT | NS_OPCODE_RELEASE | NS_NM_AA_BIT
    NSHeader.__init__( self, TrnId, flags, (0, 1, 0, 0) )
    ResourceRecord.__init__( self, L2name, NS_RR_TYPE_NB, TTL, 6 )
    AddressRecord.__init__( self, G, ONT, IP )
    self.Rcode = Rcode


class NameUpdateRequestAndOverwriteDemand( NameRegistrationRequest ):
  """Name Update Request and Name Overwrite Demand message.

  The Name Update Request message is a unicast message sent to the NBNS
  to claim ownership of a name that has been abandoned by another node.
  The Update Request may only be sent if the client received an End-Node
  Challenge Name Registration Response from the NBNS.  The NBNS will
  respond to the Name Update Request by sending a Name Registration
  Response.

  The Name Overwrite Demand message is identical to the Name Update
  Request, except that the B bit is set (1), and the message is sent
  as a broadcast.  The Name Overwrite Demand is sent to conclude the
  broadcast name registration process.

  The Update Request is identical to a Name Registration Request, except
  that the RD bit is clear (0).

  See:  http://www.ubiqx.org/cifs/NetBIOS.html#NBT.4.3.1.1
        http://www.ubiqx.org/cifs/NetBIOS.html#NBT.4.3.1.2
  """
  def __init__( self, TrnId = 0,
                      B     = True,
                      L2name= None,
                      TTL   = 0,
                      G     = False,
                      ONT   = NS_ONT_B,
                      IP    = None ):
    """Create a Name Update Request or Name Overwrite Demand message.

    Input:
      TrnId   - Transaction Id.
      B       - Boolean; the value of the B (Broadcast) bit.  Should be
                True for the Overwrite Demand, False for the Update
                Request.
      L2name  - The name to be registered, fully encoded.
      TTL     - This value should be zero for the Overwrite Demand, and
                roughly 3 days for the Update Request.
      G       - Boolean; set to True if the name is being registered
                as a Group name, else False.
      ONT     - Owner Node Type.
                  NS_ONT_B == B node
                  NS_ONT_P == P node
                  NS_ONT_M == M node
                  NS_ONT_H == H node (Microsoft extension to STD 19)
      IP      - IPv4 address of the requesting node.  This, of course,
                is the IP of the interface on which the NBT Name
                Service is running.  It should be given as a string of
                four octets.

    Notes:  When creating one of these messages, the easiest thing to
            do is to recycle the Registration Request by clearing the
            RD bit.
    """
    super( NameUpdateRequestAndOverwriteDemand, self
         ).__init__( TrnId, B, L2name, TTL, G, ONT, IP )
    self.RDbit = False


class NameConflictDemand( NameRegistrationResponse ):
  """Name Conflict Demand message.

  The Name Conflict Demand is similar to the Name Release Demand in
  behavior.  When this message is sent to an end-node, the end-node is
  supposed to give up ownership of the name in question.  Why the RFCs
  defined two messages that have the same intended purpose is a unknown.

  The Name Conflict Demand is basically a Negative Name Registration
  Response with an Rcode of NS_RCODE_CFT_ERR.

  Most NBT end-nodes ignore this message.

  See:  http://www.ubiqx.org/cifs/NetBIOS.html#NBT.4.3.6
  """
  def __init__( self, TrnId = 0,
                      L2name= None,
                      G     = False,
                      ONT   = NS_ONT_B,
                      IP    = None ):
    """Create an NBT Name Service Name Registration Response message.

    Input:
      TrnId   - Transaction Id.
      L2name  - The conflicted name.
      G       - Boolean; True if the registered name is a Group name,
                else False.
      ONT     - Owner Node Type.
                  NS_ONT_B == B node
                  NS_ONT_P == P node
                  NS_ONT_M == M node
                  NS_ONT_H == H node (Microsoft extension to STD 19)
      IP      - IPv4 address of the registered node.  In a positive
                response, this will be the same as the IP given in
                the request.  In a negative response, however, the
                RDATA values are those of the owner.
    """
    super( NameConflictDemand, self ).__init__( TrnId,
                                                Rcode=NS_RCODE_CFT_ERR,
                                                L2name=L2name,
                                                TTL=0,
                                                G=G, ONT=ONT, IP=IP )


# class RedirectNameQueryResponse():
#   Unimplemented... though it could be quite interesting to write this
#   up and test it.
#   See:  http://www.ubiqx.org/cifs/NetBIOS.html#NBT.4.3.2.3


class LocalNameTable( object ):
  """Maintain a list of locally registered NBT names.

  The local Name Table is a simple database that is intended for keeping
  track of locally registered names (per end-node).  An instance of the
  Local Name Table keeps track of the Scope identifier for the list, an
  Interface identifier (IPv4 address), and the list of registered names
  themselves.  The list of names is used to answer Name and Node Status
  queries from remote nodes, and also to defend registered names.

  The list of names contains the first component of the L1-encoded NetBIOS
  name (which is used as a lookup key), the name type (Group vs. Unique)
  and the name status.  As an extension to normal STD19 behavior, there is
  also a "Hidden" flag, which can be used to fake-register hidden names,
  such as the "*SMBSERVER" name used in some versions of Windows and in
  Samba.
  """
  def __init__( self, IP=None, scope='', ONT=NS_ONT_B, NameList=[] ):
    """Create a local name table.

    Input:
      IP        - The (optional) interface ID.  This is not used for any
                  particular purpose within the table.  It's just stored
                  for reference.  It must be None, or a string of four
                  octets.
      scope     - Used for lookups that are done based on the fully
                  qualified L2 name received on the wire.  If the scope
                  does not match, the name is not in the list.  The
                  scope should be provided unencoded (it will be stored
                  in L2 encoded format internally).  If no scope is
                  given, the empty scope ('') will be used as the
                  default.
      ONT       - Owner Node Type.  One of:
                    [ NS_ONT_B, NS_ONT_P, NS_ONT_M, NS_ONT_H ]
      NameList  - Either None, or a list of tuples each containing the
                  following:
                    L1name  - The L1-encoded NetBIOS name.
                    Hidden  - Boolean; True for hidden names.  This
                              should be used rarely and only for certain
                              names.
                    Nflags  - A 16-bit field made up of the following:
                              Group bit:  Either 0x0000 or NS_GROUP_BIT.
                              Name Status bits; one or more of:
                                 [ NS_DRG, NS_CNF, NS_ACT, NS_PRM ]
                  The NameList is typically generated internally by
                  calls to the addEntry() method, but the list can be
                  pre-loaded via the nameList parameter.

    Errors: TypeError   - The value of an input parameter was of the
                          wrong type.
            ValueError  - An input parameter did not match the required
                          format.
    """
    # Sanity Checks.
    if( IP is not None ):
      if( not isinstance( IP, str ) ):
        s = type( IP ).__name__
        raise TypeError( "IP address must be of type str, not %s." % s )
      elif( 4 != len( IP ) ):
        s = "Interface IP must be a 4-octet IPv4 address or None"
        raise ValueError( s )
    if( not isinstance( scope, str ) ):
      s = type( scope ).__name__
      raise TypeError( "Scope must be of type str, not %s." % s )

    # Go ahead...
    self._IPaddr   = IP
    self._ONT      = (ONT & NS_ONT_MASK)
    self._scope    = (Name( 'nada', scope=scope ).getL2name())[33:]
    self._nameDict = {}
    if( NameList ):
      for L1name, Hidden, Nflags in NameList:
        if( not isinstance( L1name, str ) ):
          s = type( L1name ).__name__
          raise TypeError( "The NBT name must be of type str, not %s." % s )
        if( 32 != len( L1name ) ):
          raise ValueError( "Malformed L1-encoded NBT name [%s]" % L1name )
        # Name_Flags are stored internally without the Owner Node Type (ONT).
        Nflags = (Nflags & (NS_GROUP_BIT | NS_STATE_MASK))
        self._nameDict[ L1name ] = (bool(Hidden), Nflags)

  def updateEntry( self, L1name=None,
                         Hidden=False,
                         Group=False,
                         Status=NS_ACT ):
    """Add/overwrite a name entry in the name list.

    Input:
      L1name  - An NBT name in L1 encoded format.
      Hidden  - Boolean; True for hidden names.  This should be used
                rarely, and only for certain names (like "*SMBSERVER").
      Group   - Boolean; True if the name is a Group name (not Unique).
      Status  - Name status.
                One or more of:  [ NS_DRG, NS_CNF, NS_ACT, NS_PRM ]
    """
    # Sanity Checks (sometimes bounce).
    if( not isinstance( L1name, str ) ):
      s = type( L1name ).__name__
      raise TypeError( "The NBT name must be of type str, not %s." % s )
    if( 32 != len( L1name ) ):
      raise ValueError( "Malformed L1-encoded NBT name [%s]" % L1name )
    # Add the entry.  Name_Flags are stored internally without Owner Node Type.
    Name_Flags  = (NS_GROUP_BIT if( Group ) else 0x0000)
    Name_Flags |= (NS_STATE_MASK & Status)
    self._nameDict[ L1name ] = (bool(Hidden), Name_Flags)

  def delEntry( self, L1name=None ):
    """Remove a name from the name list.

    Input:
      L1name  - The NBT name of the entry to be removed.

    Output: Boolean; True if the entry was removed from the list.
            False if the entry was not found (and, therefore, not
            removed).
    """
    if( L1name in self._nameDict ):
      del self._nameDict[ L1name ]
      return( True )
    return( False )

  def findEntry( self, nom=None, showHidden=False ):
    """
    Input:
      nom         - A fully-qualified L2 name, including scope (even if
                    it is the empty scope), or the unqualified (no
                    scope) L1-encoded name.  If the latter, no check is
                    performed against the scope (which is bad, so be
                    sure that you know what you're doing).
      showHidden  - Pass True to allow lookup of hidden names.

    Errors: ValueError  - Raised if <nom> was not formatted as expected.

    Output: Either None, indicating that the name was not found in the
            internal list, or a tuple containing:
              Hidden    - Boolean; True for hidden names, else False.
                          Can only be True if <showHidden> was True.
              Group     - True for a Group name, else False.
              NameFlags - A 16-bit value containing the name state bits;
                          one or more of:
                            [NS_DRG, NS_CNF, NS_ACT, NS_PRM]
    """
    if( len( nom ) >= 34 ):     # An L2 encoded name with scope.
      if( nom[:33].lower() != self._scope.lower() ):
        return( None )
      nom = nom[1:][:32]
    elif( 32 != len( nom ) ):   # Not an L1, unscoped name.
      raise ValueError( "Invalid name in query: %s" % hexstr( nom ) )

    if( nom in self._nameDict ):
      Hidden, Flags = self._nameDict[nom]
      if( showHidden or not Hidden ):
        return( (Hidden, bool(NS_GROUP_BIT & Flags), (NS_STATE_MASK & Flags)) )
    return( None )

  def statusList( self ):
    """Return a list of registered names.

    Output: A list of zero or more tuples, formatted for use in creating
            a NodeStatusResponse message.  Each tuple contains two
            elements:
              NetBIOSname - An unencoded NetBIOS name, totaling 16 bytes
                            in length.  The name will include the suffix
                            byte and any padding.
              NameFlags   - The Group bit, the owner node type bits, and
                            four name status bits, all packed into a
                            16-byte integer.

    Notes:  The resulting list will not contain any hidden names.  By
            definition, hidden names are not registered and are not
            visible to other nodes in the NBT virtual LAN.

    Doctext:
    >>> lnt = LocalNameTable()
    >>> lnt.updateEntry( "EGFCEFEMECCACACACACACACACACACAAA",
    ... Status=(NS_ACT|NS_PRM) )
    >>> lnt.updateEntry( "EGFCEFEMECCACACACACACACACACACACA" )
    >>> lnt.updateEntry( "EOEFFCEEEMEJEOEHEFFCCACACACACACA", Group=True )
    >>> lnt.updateEntry( "EOEFFCEEEMEJEOEHEFFCCACACACACABN", Group=True )
    >>> lnt.updateEntry( "CKFDENECFDEFFCFGEFFCCACACACACACA", Hidden=True )
    >>> for n, f in lnt.statusList():
    ...   s = hexstr( n[:15] )
    ...   print "%s<%02X> [0x%04x]" % (s, ord( n[15] ), f)
    FRELB          <00> [0x0600]
    FRELB          <20> [0x0400]
    NERDLINGER     <1D> [0x8400]
    NERDLINGER     <20> [0x8400]
    """
    tmplst = []
    for nom in self._nameDict:
      Hidden, Flags = self._nameDict[nom]
      if( not Hidden ):
        tmplst.append( (Name.L1decode( nom ), (Flags | self._ONT)) )
    tmplst.sort( key=lambda x: ((NS_GROUP_BIT & x[1]), x[0]) )
    return( tmplst )


# Functions ------------------------------------------------------------------ #
#

def ParseMsg( msg=None ):
  """Parse an NBT Name Service message.

  Input:
    msg - A byte string (type str) received from the network.

  Errors: NBTerror( 1003 )  - A Label String Pointer was encountered
                              where a full name was expected.
          NBTerror( 1005 )  - Parsing failure.
          ValueError        - Invalid L2 name.

  Output: An NBT Name Service message object.

  Notes:  This function will parse the given message and either return
          an object of the correct type or throw an exception if the
          message could not be parsed.

          The goal is to correctly and forgivingly parse the incoming
          message, throwing an exception only when something is really
          and truly wrong.
  """
  # NBT message types:
  #
  # NS_OPCODE_QUERY
  # - Name Query Request
  # - Node Status Request
  # - Positive Name Query Response
  # - Negative Name Query Response
  # - Redirect Name Query Response (Unused/Unimplemented)
  # - Node Status Response
  #
  # NS_OPCODE_REGISTER
  # - Name Registration Request
  # - Name Update (Overwrite) Request
  # - Name Overwrite Demand
  # - Positive Name Registration Response
  # - Negative Name Registration Response
  # - Challenge Name Registration Response
  # - Name Conflict Demand
  #
  # NS_OPCODE_RELEASE
  # - Name Release Request
  # - Name Release Demand
  # - Positive Name Release Response
  # - Negative Name Release Response
  #
  # NS_OPCODE_WACK
  # - Wait for Acknowledgement Response
  #
  # NS_OPCODE_REFRESH
  # NS_OPCODE_ALTREFRESH
  # - Name Refresh Request
  #
  # NS_OPCODE_MULTIHOMED
  # - Multi-Homed Name Registration Request
  #

  def _readName( offset ):
    # Parse out the L2 name from a message.
    #
    # Input:  offset  - The position within <msg> at which to find the
    #                   name to be read.  Note that the scope of <msg>
    #                   is the entire ParseMsg() function.
    #
    # Errors: NBTerror( 1005 )  - Parsing failure.
    #         ValueError        - Invalid L2 name.
    #
    # Output: A tuple consisting of the offset of the byte immediately
    #         following the parsed L2 name and the L2 name itself, as
    #         in: (offset, L2name).
    #
    # Notes:  An offset of 12 is significant.  All of the Name Service
    #         messages, even the unused Redirect Name Query Response
    #         message, place the primary L2-encoded name at offset 12,
    #         immediately following the header.
    #
    n = Name()
    try:
      offset += n.setL2name( msg[offset:] )
    except NBTerror as nbte:
      if( 1003 == nbte.eCode ):
        if( 12 == offset ):
          raise NBTerror( 1005, "Misplaced Label String Pointer" )
        if( 12 == nbte.value ):
          raise NBTerror( 1005, "Misdirected Label String Pointer" )
        offset += n.setL2name( msg[12] )
      else:
        raise
    return( (offset, n.getL2name()) )

  def _readQueRec():
    # Parse a Question Record from a message.
    #
    # Errors: NBTerror( 1005 )  - Parsing failure.
    #         ValueError        - Invalid L2 name in the Question Record.
    #
    # Output: A tuple consisting of:
    #         - The offset of the byte immediately following the parsed
    #           Question Record.
    #         - The Question Type (Qtype).
    #         - The Question Name (Qname).
    #
    # Notes:  NBT Question Records always start at offset 12.  No other
    #         starting offset is valid.
    #
    offset, Qname = _readName( 12 )
    Qtype, Qclass = _format_QR.unpack( msg[offset:][:4] )
    if( Qtype not in [ NS_Q_TYPE_NB, NS_Q_TYPE_NBSTAT ] ):
      raise NBTerror( 1005, "Unexpected question type: 0x%04X" % Qtype )
    if( NS_Q_CLASS_IN != Qclass ):
      raise NBTerror( 1005, "Unknown question class: 0x%04X" % Qclass )
    return( (4+offset, Qtype, Qname) )

  def _readResRec( offset ):
    # Parse a Resource Record from a message.
    #
    # Input:  offset  - The position within <msg> at which to find the
    #                   Resource Record to be read.
    #
    # Errors: NBTerror( 1005 )  - Parsing failure.
    #         ValueError        - Invalid L2 name in the Resource Record.
    #
    # Output: A tuple consisting of:
    #         - The offset of the byte immediately following the parsed
    #           Resource Record (offset).
    #         - The RR Type (RRtype).
    #         - The TTL value (TTL).
    #         - The RData length (RDlen).
    #         - The RR name (RRname).
    #
    offset, RRname = _readName( offset )
    RRtype, RRclass, TTL, RDlen = _format_RR.unpack( msg[offset:][:10] )
    if( RRtype not in [ NS_RR_TYPE_NB, NS_RR_TYPE_NBSTAT, NS_RR_TYPE_NULL ] ):
      raise NBTerror( 1005, "Unexpected Resource Record type: 0x%04X" % RRtype )
    if( NS_RR_CLASS_IN != RRclass ):
      raise NBTerror( 1005, "Unknown Resource Record class: 0x%04X" % RRclass )
    return( offset+10, RRtype, TTL, RDlen, RRname )

  def _query_request():
    # Parse a node status or name query request message.
    #
    # Errors: NBTerror( 1005 )  - Parsing failure.
    #         ValueError        - Invalid L2 name.
    #
    # Output: NameQueryRequest or NodeStatusRequest.
    #
    if( (1, 0, 0, 0 ) != Counts ):
      raise NBTerror( 1005, "Invalid record count in query request" )
    # Parse the Question Record.
    offset, Qtype, Qname = _readQueRec()
    if( NS_Q_TYPE_NBSTAT == Qtype ):
      # Node Status Request.
      Req = NodeStatusRequest( TrnId, Qname )
    else:
      # Name Query Request (NS_Q_TYPE_NB).
      B   = bool( NMflags & NS_NM_B_BIT )
      RD  = bool( NMflags & NS_NM_RD_BIT )
      Req = NameQueryRequest( TrnId, B, RD, Qname )
    Req.NMflags = NMflags
    return( Req )

  def _query_response():
    # Parse a node status or name query response message.
    #
    # Errors: NBTerror( 1003 )  - A Label String Pointer was encountered.
    #                             A Query Request should not contain an LSP.
    #         NBTerror( 1005 )  - Parsing failure.
    #         ValueError        - Invalid L2 name.
    #
    # Output: NameQueryResponse or NodeStatusResponse.
    #
    if( (0, 1, 0, 0) != Counts ):
      raise NBTerror( 1005, "Invalid record count in query response" )
    # Parse the Answer Record.
    offset, RRtype, TTL, RDlen, RRname = _readResRec( 12 )
    # RDATA parsing differs depending upon the RR_TYPE.
    if( NS_RR_TYPE_NBSTAT == RRtype ):
      # Node Status response (always positive).
      num_names = ord( msg[offset] )
      offset += 1
      NameList = []
      for i in range( num_names ):
        # Unpack the name records.
        NB_name  = msg[offset:][:16]
        NBflags, = _format_Short.unpack( msg[(16+offset):][:2] )
        NameList.append( (NB_name, NBflags) )
        offset += 18
      # Unpack the MAC and create the Node Status Response object.
      MAC  = _format_MacAddr.unpack( msg[offset:][:6] )
      Resp = NodeStatusResponse( TrnId, RRname, NameList, MAC )
    else:
      # Name Query response (positive/negative).
      RD = bool( NMflags & NS_NM_RD_BIT )
      RA = bool( NMflags & NS_NM_RA_BIT )
      aL = []
      if( 0 == Rcode ):
        # The response is positive, so collect the name records.
        for i in range( RDlen/6 ):
          aL.append( _format_AddrEntry.unpack( msg[offset:][:6] ) )
          offset += 6
      Resp = NameQueryResponse( TrnId, RD, RA, Rcode, RRname, TTL, aL )
    Resp.NMflags = NMflags
    return( Resp )

  def _rrr_request():
    # Parse a Registration, Refresh, or Release Request message.
    #
    # Errors: NBTerror( 1005 )  - Parsing failure.
    #         ValueError        - Invalid L2 name (RRName).
    #
    # Output: Several message types have the same format.  This function will
    #         return one of the following:
    #         - NameRegistrationRequest,
    #         - NameUpdateRequestAndOverwriteDemand,
    #         - NameRefreshRequest,
    #         - NameReleaseRequestandDemand,
    #         - MultiHomedNameRegistrationRequest.
    #
    if( (1, 0, 0, 1) != Counts ):
      s = "Invalid record count in %s request" % _OPcodeDict[ OPcode ]
      raise NBTerror( 1005, s )
    # Parse the Question and Resource Records.
    offset, Qtype, Qname = _readQueRec()
    offset, RRtype, TTL, RDlen, RRname = _readResRec( 12 )
    # Rdata
    NBflags, IP = _format_AddrEntry.unpack( msg[offset:][:6] )
    # Now figure out what type of request it really is.
    RD = bool( NMflags & NS_NM_RD_BIT )
    B  = bool( NMflags & NS_NM_B_BIT )
    # Build the message object.
    if( OPcode in [ NS_OPCODE_REFRESH, NS_OPCODE_ALTREFRESH ] ):
      Req = NameRefreshRequest( TrnId, RRname, TTL, G, ONT, IP )
    elif( NS_OPCODE_RELEASE == OPcode ):
      Req = NameReleaseRequestandDemand( TrnId, B, RRname, G, ONT, IP )
    elif( NS_OPCODE_MULTIHOMED == OPcode ):
      Req = MultiHomedNameRegistrationRequest( TrnId, RRname, TTL, ONT, IP )
    elif( RD ):
      Req = NameRegistrationRequest( TrnId, B, RRname, TTL )
    else:
      Req = NameUpdateRequestAndOverwriteDemand( TrnId, B, RRname, TTL )
    Req.NMflags = NMflags
    return( Req )

  def _reg_response():
    # Parse a Name Registration or Release Response message.
    #
    # Errors: NBTerror( 1005 )  - Parsing failure.
    #         ValueError        - Invalid L2 name (RRName).
    #
    # Output: An object of one of the following classes:
    #         - Positive or Negative Name Registration Response,
    #         - Challenge Name Registration Response (NS_OPCODE_REGISTER)
    #         - Name Conflict Demand (NS_OPCODE_REGISTER)
    #         - Name Release Response (NS_OPCODE_RELEASE)
    #
    if( (0, 1, 0, 0) != Counts ):
      s = "release" if( NS_OPCODE_RELEASE == OPcode ) else "registration"
      raise NBTerror( 1005, "Invalid record count in %s response" % s )
    offset, RRtype, TTL, RDlen, RRname = _readResRec( 12 )
    NBflags, IP = _format_AddrEntry.unpack( msg[offset:][6] )
    B   = bool( NMflags & NS_NM_B_BIT )
    RD  = bool( NMflags & NS_NM_RD_BIT )
    G   = bool( NBflags & NS_GROUP_BIT )
    ONT = (NBflags & NS_ONT_MASK)
    if( NS_OPCODE_RELEASE == OPcode ):
      Resp = NameReleaseResponse( TrnId, Rcode, RRname, G, ONT, IP )
    elif( NS_RCODE_CFT_ERR == Rcode ):
      Resp = NameConflictDemand( TrnId, RRname, G, ONT, IP )
    elif( RD or Rcode ):
      # Pos/Neg Name Reg Response
      Resp = NameRegistrationResponse( TrnId, Rcode, RRname, TTL, G, ONT, IP )
    else:
      Resp = ChallengeNameRegistrationResponse( TrnId, RRname, G, ONT, IP )
    Resp.NMflags = NMflags
    return( Resp )

  def _wack_response():
    # Parse a WACK message.
    #
    # Errors: NBTerror( 1005 )  - Parsing Failure.
    #         ValueError        - Invalid L2 name (RRName).
    #
    # Output: A WACK Response object.
    #
    if( (0, 1, 0, 0) != Counts ):
      raise NBTerror( 1005, "Invalid record count in WACK response" )
    offset, RRtype, TTL, RDlen, RRname = _readResRec( 12 )
    RDflags = _format_Short.unpack( msg[offset:][2] )
    Resp = WaitForAcknowledgementResponse( TranId, RRname, TTL, RDflags )
    Resp.NMflags = NMflags
    return( Resp )

  # ==== Start ParseMsg() function ==== #

  # Sanity checks.
  if( not msg ):
    raise ValueError( "Empty NBT message in ParseMsg()." )
  if( not isinstance( msg, str ) ):
      s = type( msg ).__name__
      raise TypeError( "NBT packet must be of type str, not %s." % s )

  # Parse the header into six two-byte fields.
  TrnId, Flags, QDcnt, ANcnt, NScnt, ARcnt = _format_NS_hdr.unpack( msg[:12] )
  # Further parse the flags field.
  Rbit    = bool( Flags & NS_R_BIT )
  OPcode  = (Flags & NS_OPCODE_MASK)
  NMflags = (Flags & NS_NM_FLAGS_MASK)
  Rcode   = (Flags & NS_RCODE_MASK)
  Counts  = (QDcnt, ANcnt, NScnt, ARcnt)

  # Parse Messages.
  if( not Rbit ): # Requests
    if( NS_OPCODE_QUERY == OPcode ):
      return( _query_request() )
    elif( OPcode in _OPcodeDict ):
      return( _rrr_request() )
  else: # Responses
    if( NS_OPCODE_QUERY == OPcode ):
      return( _query_response() )
    elif( OPcode in [ NS_OPCODE_REGISTER, NS_OPCODE_RELEASE] ):
      return( _reg_response() )
    elif( NS_OPCODE_WACK == OPcode ):
      return( _wack_response() )

  # Ooops.
  s = "response" if( Rbit ) else "request"
  s = "Parsing failed, unhandled %s OPcode: 0x%X." % (s, (OPcode >> 11))
  raise NBTerror( 1005, s )

# ============================================================================ #
