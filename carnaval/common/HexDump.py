# ============================================================================ #
#                                  HexDump.py
#
# Copyright:
#   Copyright (C) 2014,2015 by Christopher R. Hertel
#
# $Id: HexDump.py; 2015-09-21 22:31:58 -0500; Christopher R. Hertel$
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

def hexnum2str( numbr=None, width=0 ):
  """Format an integer value as a string in hexadecimal notation.

  Input:  numbr - The number to be formatted as a string.
          width - The minimum width of the formatted portion of the
                  resulting string.

  Output: A string in the form [-]0xX..., where "[-]" is an optional
          minus sign that will be present if <numbr> is negative, and
          "X..." is the formatted portion of the resulting string,
          which is the hexadecimal representation of abs( <numbr> ).

  Doctest:
    >>> print hexnum2str( -0xABCDEF, 8 )
    -0x00ABCDEF
    >>> print hexnum2str( 12345 )
    0x3039
  """
  prefix = "-0x" if( numbr < 0 ) else "0x"
  if( not width ):
    width = 0
  return( prefix + ("{0:0>{1}X}".format( abs( numbr ), width )) )


def hexbyte( data=None ):
  """Convert bytes into two-character hex strings.

  Input:  data  - A string, the first byte of which will be used to
                  generate the output.  This must be readable as type
                  str.

  Output: A two-byte string representing the hex value of first byte
          of the input.  For example: '\\t' --> '09'.

  Errors:
    AssertionError  - Raised if the input is not of type <str>.
    ValueError      - Raised if the input string is empty.  We need at
                      least (and will use at most) one byte.

  Notes:  This function converts the input byte into a two-character
          hex string, whether or not the input byte is a printable
          character.  The output is always a two hex-digit pair, and
          never an escape sequence (e.g., never '\\t' for TAB).

  Doctest:
    >>> print "<%s>" % hexbyte( "\\b" )
    <08>
  """
  # Check for garblage.
  assert( isinstance( data, str ) ), \
    "Expected type <str>, got <%s>." % type( data ).__name__
  if( len( data ) < 1 ):
    raise ValueError( "Cannot hexlify the empty string." )

  # Compose the two-byte hex string.
  b = ord( data[0] )
  return( _HEX_XLATE[ (b >> 4) ] + _HEX_XLATE[ (b & 0x0f) ] )


def hexstr( data=None ):
  """Convert non-printing bytes in a string of bytes to hex escapes.

  Input:  data  - The string of bytes to convert.  The input must be of
                  type <str>.  The empty string is acceptable.

  Output: A string in which nonprinting characters in the original
          string will be represented using "\\xXX" notation.

  Errors:
    AssertionError  - Raised if the input is not of type str.

  Notes:  This is similar to the standard binascii.b2a_hex() function,
          except that it doesn't produce single-character escape
          sequences (e.g., "\\t").  All of the escapes are in the
          "\\xXX" format.

          This function operates on octet strings only.  NetBIOS does
          not understand Unicode.  Sorry.
          See:  http://blogs.msdn.com/b/larryosterman/archive/2007/07/
                11/how-do-i-compare-two-different-netbios-names.aspx

          You can convert Unicode strings to the <str> format using the
          .encode() method and your preferred encoding scheme.

  Doctest:
    >>> print hexstr( "\\tOcelot\\nBanana" )
    \\x09Ocelot\\x0ABanana
  """
  # Check for garblage.
  assert( isinstance( data, str ) ), \
    "Expected type <str>, got <%s>." % type( data ).__name__

  s = ''
  for b in [ ord( x ) for x in data ]:
    if( (b < 0x20) or (b > 0x7F) ):
      s += "\\x" + _HEX_XLATE[ (b >> 4) ] + _HEX_XLATE[ (b & 0x0f) ]
    else:
      s += chr( b )
  return( s )


def hexstrchop( data=None, linemax=72 ):
  """Chop the the output of HexDump.hexstr() into smaller chunks.

  Input:  data    - The string of bytes to convert.  The input must be
                    of type <str>.  The empty string is acceptable.
                    This is the same as the input to <hexstr()>.
          linemax - Maximum length of the resulting chunks.  This value
                    must be at least 4.  The default is 72.

  Output: A list of strings, none of which are more than <linemax>
          bytes in length.  Any given string may be up to three bytes
          less than <linemax>, because the lines will be broken on a
          "\\xXX" escape sequence.

  Errors: AssertionError  - Raised if the input is not of type str, or
                            if <linemax> is less than 4.

  Notes:  This function was written to make it easier to handle chunks
          of text (or binary data) in DocString output.

  Doctest:
    >>> s  = '"Tofu donkey." said the caterpillar, but Nesbit '
    >>> s += 'disagreed.  "You can\\'t have pickled cheese", she said.'
    >>> print '\\n'.join( hexstrchop( s, 62 ) )
    "Tofu donkey." said the caterpillar, but Nesbit disagreed.  "Y
    ou can't have pickled cheese", she said.
    >>> print '\\n'.join( hexstrchop( "\\t\\t\\t\\t", 9 ) )
    \\x09\\x09
    \\x09\\x09
    >>> print '\\n'.join( hexstrchop( "Z\\n\\n", 4 ) )
    Z
    \\x0A
    \\x0A
    >>> for ln in hexstrchop( "gooberry", 4 ):
    ...   print ln
    goob
    erry
  """
  # Check input.
  assert( linemax >= 4 ), \
    "Cannot wrap to less than 4 columns."

  # Generate the hexified string.
  hstr = hexstr( data )
  # Parse it and wrap it.
  llen, hslen, llist = (0, len(hstr), [])
  while( hslen > linemax ):
    loc = hstr[(linemax-3):(linemax+1)].find( "\\x" )
    if( loc < 0 ):
      loc = linemax
    else:
      loc = linemax + (loc - 3)
    llist.append( hstr[:loc] )
    hstr = hstr[loc:]
    hslen = len( hstr )

  # Add in the remainder, if any, and return the result.
  if( hstr ):
    llist.append( hstr )
  return( llist )


def hexdumpln( data=None, offset=0 ):
  """Return a hex-dumped string representing up to 16 bytes.

  Input:  data    - The string of bytes, including the bytes to be
                    dumped.  Must be of type str.
          offset  - The offset within <data> at which to find the 16
                    or less bytes that are to be dumped.

  Errors:
    AssertionError  - Raised if the input is not of type str.

  Output: If <data> is None, None will be returned.
          If the range of bytes indicated by the input is empty, the
          empty string is returned.  Otherwise, the output is a string
          representing up to 16 bytes of input, in fairly traditional
          hexdump format. The line is NOT terminated with a newline.

  Notes:  This implementation uses a unicode-encoded hollow bullet
          to represent non-printing characters.

  Doctest:
  >>> print hexdumpln( _HEX_XLATE + "Hello, Whirled", 8 )
  000008:  38 39 41 42 43 44 45 46  48 65 6c 6c 6f 2c 20 57  |89ABCDEFHello, W|
  """
  # Reality check.
  if( data is None ):
    return( None )
  # Check for garblage.
  assert( isinstance( data, str ) ), \
    "Expected type <str>, got <%s>." % type( data ).__name__

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
  """Produce a hex dump so that packets can be visually inspected.

  Input:  data  - The string of bytes to to be dumped.  The input must
                  be of type str.

  Output: A string, formatted as a hex dump.  Each line is terminated
          with a newline character.  The empty string is returned if
          <data> is the empty string or None.

  Errors:
    AssertionError  - Raised if the input is not of type str.

  Doctest:
  >>> print hexdump( _HEX_XLATE + "Hello, Whirled" )
  000000:  30 31 32 33 34 35 36 37  38 39 41 42 43 44 45 46  |0123456789ABCDEF|
  000010:  48 65 6c 6c 6f 2c 20 57  68 69 72 6c 65 64        |Hello, Whirled  |
  <BLANKLINE>
  """
  # Reality check.
  if( not data ):
    return( '' )
  # Check for garblage.
  assert( isinstance( data, str ) ), \
    "Expected type <str>, got <%s>." % type( data ).__name__

  # Quick 'n easy...
  s = ''
  for offset in range( 0, len( data ), 16 ):
    s += hexdumpln( data, offset ) + '\n'
  return( s )

# ============================================================================ #
