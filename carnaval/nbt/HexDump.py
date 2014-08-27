# ============================================================================ #
#                                  HexDump.py
#
# Copyright:
#   Copyright (C) 2014 by Christopher R. Hertel
#
# $Id: HexDump.py; 2014-08-26 20:38:46 -0500; Christopher R. Hertel$
#
# ---------------------------------------------------------------------------- #
#
# Description:
#   Convert binary values into formatted hex string representation.
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
#   - This module expands the set of available Python tools that convert
#     binary values into hex strings, adding new formatting options and
#     providing improved control over the output.  That's what the label
#     says.
#
# ============================================================================ #
#
"""Carnaval Toolkit:  Binary to Hex-string utilities.

A set of functions that provide byte-to-hex-string conversions to print
binary data in a more human-readable form.
"""

# Constants ------------------------------------------------------------------ #
#
#   _HEX_XLATE  - String used to convert a nibble into a hex digit character.
#                 Used in hexbyte() and hexstr().  You've seen this a million
#                 times, no?
#

_HEX_XLATE = "0123456789ABCDEF"


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
  if( not isinstance( data, str ) ):
    s = type( data ).__name__
    raise ValueError( "Expected a string of 1 or more bytes, got a %s." % s  )
  if( len( data ) < 1 ):
    raise ValueError( "Cannot hexlify the empty string." )

  # Compose the two-byte hex string.
  b = ord( data[0] )
  return( _HEX_XLATE[ (b >> 4) ] + _HEX_XLATE[ (b & 0x0f) ] )


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
  if( not isinstance( data, str ) ):
    s = type( data ).__name__
    raise ValueError( "Expected a string of bytes, got '%s'." % s  )

  s = ''
  for b in [ ord( x ) for x in data ]:
    if( (b < 0x20) or (b > 0x7F) ):
      s += "\\x" + _HEX_XLATE[ (b >> 4) ] + _HEX_XLATE[ (b & 0x0f) ]
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
  >>> print hexdumpln( 8, _HEX_XLATE + "Hello, Whirled" )
  000008:  38 39 41 42 43 44 45 46  48 65 6c 6c 6f 2c 20 57  |89ABCDEFHello, W|
  """
  # Reality check.
  if( data is None ):
    return( None )
  # Check for garblage.
  if( not isinstance( data, str ) ):
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
  >>> hexdump( _HEX_XLATE + "Hello, Whirled" )
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
