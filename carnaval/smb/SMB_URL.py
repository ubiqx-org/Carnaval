# -*- coding: utf-8 -*-
# ============================================================================ #
#                                  SMB_URL.py
#
# Copyright:
#   Copyright (C) 2015 by Christopher R. Hertel
#
# $Id: SMB_URL.py; 2018-10-02 18:22:51 -0500; Christopher R. Hertel$
#
# ---------------------------------------------------------------------------- #
#
# Description:
#   SMB URL composition and parsing.
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
#   - The first attempt at writing this module failed because it relied on
#     Python urlparse.urlsplit() function, which had a known bug.  See:
#       http://bugs.python.org/issue9374
#     Essentially, when dealing with an unrecognized URI scheme, the
#     urlparse functions would fail to parse the query and fragment parts,
#     leaving them as part of the path.  This bug existed in Python 2.7.3,
#     but was fixed some time before the release of 2.7.5.  It just seemed
#     easier to do the parsing by hand.
#
#   - The SMB URL specification has never moved beyond the draft stage
#     (despite a great deal of effort).  As of January 2015, the most recent
#     attempt is still draft-crhertel-smb-url-12.txt, which expired in mid
#     2007.
#
#     Although there is no official standard, there are several SMB client
#     implementations that do support some variant of the SMB URL.  Most of
#     these vary slightly (and differently) from the draft specification.
#
#   - The original author of this SMB URL parsing implementation is also the
#     author of the SMB URL draft specifications.  So there.
#
#   - One thing potentially missing from the SMB URL draft specification is
#     the ability, within the URL string, to specify an offset/length pair.
#     This would be useful for reading chunks of a given file.  I do not
#     know whether a similar feature exists in other URL formats.
#
# ============================================================================ #
#
"""Carnaval Toolkit: SMB URL format parsing and packing.

  The SMB URL is (was) a proposed URL format for use in identifying SMB
  shares, folders, and files within SMB shares.  Basically, anything
  within the namespace of an SMB share, including the share itself.  The
  SMB URL can also be used to access the (now deprecated) Browse Service
  (A.K.A. the "Network Neighborhood").  Several SMB client
  implementations support the SMB URL.

  This module provides the smb_url() class, which can parse, modify, and
  compose SMB URL strings.

References:

  [SMBURL]
    Draft SMB URL specification (expired):
      http://www.ietf.org/archive/id/draft-crhertel-smb-url-12.txt
  [IMPCIFS]
    SMB URL description:
      http://www.ubiqx.org/cifs/Appendix-D.html
  [PYURLPARSE]
    Python urlparse module documentation:
      SMBhttps://docs.python.org/2/library/urlparse.html
  [RFC2732]
    Format for Literal IPv6 Addresses in URL's:
      https://www.ietf.org/rfc/rfc2732.txt
"""


# Imports -------------------------------------------------------------------- #
#
#   SMB_Core  - We use the SMBerror exception class.
#

from SMB_Core import SMBerror


# Functions ------------------------------------------------------------------ #

def parseContext( context="" ):
  """Parse an SMB URL formatted NBT context into key/value tuples.

  Input:
    context - A string of key/value pairs.  The pairs are separated
              from one another by either the '&' or the ';' character.
              The keys are separated from their respective values by an
              equal sign ('=').

  Output: A list of tuples, or None.
          None is returned if the input generated an empty list.
          If a list of tuples is returned, each tuple will contain one
          (key, value) pair.

  Doctest:
    >>> print parseContext( "? a=1;&b=2; c =3; &" )
    [('a', '1'), ('b', '2'), ('c', '3')]
  """
  if( not context ):
    return( None )

  # This code is too forgiving.
  #   It does a lot of cleanup as it parses the input string
  #   and formats the resulting tuples.
  context = context.lstrip( " ?&;" ).rstrip( "&;" )
  ctxlist = []
  for y in [ x.split( '&' ) for x in context.split( ';' ) ]:
    for pair in y:
      if( pair.strip() ):
        key, value = pair.split( '=', 1 )
        key = key.strip()
        if( key ):
          ctxlist.append( (key, value) )
  return( ctxlist if( ctxlist ) else None )

def composeContext( contextList=[] ):
  """Create an NBT context string from a list of key/value pairs.

  Input:
    contextList - A list of key/value tuples, such as might be produced
                  by calling parseContext().

  Output: A string, or None.
          None is returned if the the context string would have been
          empty, otherwise a formatted context string is returned.  The
          string will not include a leading question mark ('?').

  Errors:
    AssertionError  - Thrown if the input is neither None nor a list.

    Other exceptions may be thrown if the contents of the <contextList>
    cannot be parsed properly by Python.

  Doctest:
    >>> clst = [('a', '1'), ('b', '2'), ('c', '3')]
    >>> print composeContext( clst )
    a=1;b=2;c=3
    >>> print composeContext( [] )
    None
  """
  if( not contextList ):
    return( None )
  assert( type( contextList ) is list ), \
    "Expected a list of tuples, not a(n) %s" % type( contextList ).__name__
  ctx = ''
  for tup in contextList:
    ctx += ( ";%s=%s" % tup )
  return( ctx[1:] if( ctx ) else None )


# Classes -------------------------------------------------------------------- #
#

class smb_url( object ):
  """Compose and decompose SMB URL strings.

  The SMB URL has the following syntax:
    smb://[[[authdomain;]username@]hostname[:port][/pathname]][?context]

    The SMB URL format is semantically overloaded.  Many strings that
    match the format shown above may represent either an object in the
    SMB file system or a query to be passed to the NetBIOS-based Browse
    Service.

  Class Properties:

    scheme      This is the scheme identifier.  When read, it always
                returns the string "smb".  The value cannot be changed.
                Note that the draft specifications allow either "smb" or
                "cifs" as a scheme identifier.  The CIFS name is being
                retired, however, so this module only recognizes "smb".
    authdomain  The authentication domain.  This is a string value.
    username    The username for authentication; a string.
    password    It is generally considered to be unwise to include a
                password in a visible URL string, and supporting parsing
                of the password may be considered enablement, but this
                usage is fairly common.  The password is generally
                parsed as a subfield of the username, delimited by a
                colon (':').
    hostname    This may be either a name or an IP address.  An IPv6
                address must match the syntax given in RFC 2732.  A name
                may be either an SMB server or workgroup identifier.
    port        Port number.  The standard ports for SMB are 139 (for
                SMB over NBT Session Service) and 445 (for SMB over
                Naked TCP transport).  This property is an integer type,
                all of the others are strings.
    path        The pathname.  The first component of the pathname, if
                it exists, is the share name.  The object identified by
                a pathname may be a share, a file, a directory, or some
                other SMB filesystem object such as a device or a link.
    context     A set of key/value pairs, used to provide NBT context.
                Keys and values are separated by equal signs ('=').
                Key/value pairs are separated by semicolons (or by
                ampersands).  Eg.: "Key1=ValueA;key2=valueB;fred=ethel"
    url         The complete URL string.  Reading this property causes
                the URL to be composed from the other fields.  Setting
                this value causes all of the other fields to be reset
                and then filled in by parsing the URL.

    Except for the scheme name, any of the above can be set to None to
    clear the value.

  Errors:
    AssertionError  - Values assigned to properties may be tested to
                      ensure that they meet type or value requirements.
                      If a value is found to be wanting, we'll let you
                      know.
    AttributeError  - Thrown if an attempt is made to assign a value to
                      the <scheme> property, which is read-only.
    ValueError      - Thrown by Python if it detects bogus input that
                      was otherwise missed.  For instance, if an attempt
                      is made to assign a non-numeric string to the
                      <port> property, which stores an integer value.

  Notes:
    It is completely possible to generate a bogus SMB URL string using
    this class.  The initial parsing is somewhat picky (yet also
    somewhat forgiving) about correct syntax.  Several of the property
    assignments also perform syntax checks.  You can bypass the syntax
    checks by assigning the _<field> attributes directly.  There are,
    however, a few additional checks performed when the resulting URL
    is composed.

  Doctest:
    >>> x = smb_url( "smb://fooberry" )
    >>> x.url
    'smb://fooberry'
    >>> x.path = "/"
    >>> x.url
    'smb://fooberry/'
    >>> x.context = " ? Froo=froo; groo=Groo "
    >>> x.path    = "/Foo hammer/gizmogram/peas.pie"
    >>> x.url
    'smb://fooberry/Foo hammer/gizmogram/peas.pie?Froo=froo;groo=Groo '
    >>> x.username = "chesspieceface"
    >>> x.context  = "calling=me&called=you"
    >>> x.path     = "/hamster"
    >>> print x.url
    smb://chesspieceface@fooberry/hamster?calling=me;called=you
  """

  def __init__( self, url=None ):
    """Create an SMB_url() object.

    Input:
      url - An SMB URL string, or None.
            None is equivalent to "smb://", which represents a local
            Browse Service (Network Neighborhood) query.

    Errors: See the parse() method.
    """
    self.parse( url )

  def reset( self ):
    """Clear the URL, retaining only the scheme (which is assumed).

    Doctest:
      >>> x = smb_url( "//hello/whirld" )
      >>> x.authdomain = "ploobis"
      >>> x.url
      'smb://ploobis;hello/whirld'
      >>> x.reset()
      >>> x.url
      'smb://'
    """
    self._authdomain = None
    self._username   = None
    self._password   = None
    self._hostname   = None
    self._port       = None
    self._path       = None
    self._context    = None
    self._url        = None

  def parse( self, url=None ):
    """Parse an SMB URL into its component parts.

    Input:
      url - An SMB URL string, or None.
            None is equivalent to "smb://", which represents a
            local Browse Service (Network Neighborhood) query.

    Errors:
      SMBerror( 1000 )  - Warning.
                          This warning is thrown if, for example, the
                          input contains a URL fragment (which is not
                          a supported field in the SMB URL format).

                          A warning can be safely ignored.  Warnings
                          are not thrown until the URL string has been
                          successfully parsed, and all attributes
                          assigned.

      SMBerror( 1001 )  - A syntax error was encountered while parsing
                          the given URL string.  The <value> attribute
                          of the exception will contain the offset
                          within the URL string at which the error was
                          detected.
      ValueError        - Thrown if the port number field could not be
                          interpreted as an integer.

    Notes:  This method resets the contents of the object to the empty
            state before parsing the new URL string.  All previous
            state is cleared.  It's a do-over.

    Doctest:
      >>> x = smb_url( "smb://ad;un:pw@host/share/path/file.ext" )
      >>> x.context = "nbns=172.28.42.88&nodetype=H;scope=gorch;"
      >>> print x.path
      /share/path/file.ext
      >>> x.path = ''
      >>> print x.url
      smb://ad;un:pw@host?nbns=172.28.42.88;nodetype=H;scope=gorch
      >>> x.authdomain = None
      >>> print smb_url( x.url ).url
      smb://un:pw@host?nbns=172.28.42.88;nodetype=H;scope=gorch
      >>> try:
      ...   smb_url( "smb://#NoGood" )
      ... except SMBerror, e:
      ...   tup = (e.eCode, e.errStr( e.eCode ), e.value)
      ...   print "%d; %s (%d)" % tup
      1000; Warning (6)
    """
    # Reset the attributes, and clean up the input a bit.
    self.reset()
    if( not url ):
      return
    tmp = url.lstrip()      # Clean up the url string.
    pos = url.find( tmp )   # How much padding did we remove?

    # Brute-force parsing.  Split off the "smb://" part.
    scheme, delim, tmp = tmp.partition( "//" )
    if( not delim ):
      raise SMBerror( 1001, "Missing initial double slash ('//')", pos )
    if( scheme ):
      pos += len( scheme )
      if( scheme.lower() not in [ "smb", "smb:" ] ):
        raise SMBerror( 1001, "Invalid scheme: '%s'" % scheme, pos )

    # Trim off the fragment, if one exists.  (Throw an exception later.)
    tmp, x, fragment = tmp.partition( '#' )
    # Trim off the context (query) portion, if it's there.
    tmp, x, context  = tmp.partition( '?' )
    # Now we can split the hierarchical portion into netloc and path.
    netloc, x, path  = tmp.partition( '/' )
    # Further parse the netloc portion.
    username,   x, hostname = netloc.rpartition( '@' )
    authdomain, x, username = username.rpartition( ';' )
    username,   x, password = username.partition( ':' )
    hostname,   x, port     = hostname.partition( ':' )

    # Should have everything.  Check for bugs.
    if( path and not hostname ):
      pos = 2 + url.find( "//" )
      raise SMBerror( 1001, "Path provided, but no hostname given", pos )

    # Further error checking is done by the property assignment methods.
    self.port       = port
    self.hostname   = hostname
    self.password   = password
    self.path       = path
    self.context    = context
    self.username   = username
    self.authdomain = authdomain

    # Now that everything has been parsed and assigned,
    #   see if we need to throw any warnings.
    if( fragment ):
      s = "Fragments have no meaning in the SMB URL format"
      raise SMBerror( 1000, s, url.rfind( '#' ) )

  def compose( self ):
    """Create an SMB URL string from the component parts.

    Output: An SMB URI string, built from the available attributes.
    """
    # Validate.
    if( self._path and not self._hostname ):
      raise SMBerror( 1001, "Pathname given, but no hostname specified" )

    ad = "" if( not self._authdomain ) else (self._authdomain + ';')
    pw = "" if( not self._password   ) else (':' + self._password)
    un = "" if( not self._username   ) else ("%s%s@" % (self._username, pw))
    hn = "" if( not self._hostname   ) else self._hostname
    po = "" if( not self._port       ) else (":%d" % self._port)
    pa = "" if( not self._path       ) else self._path
    cx = "" if( not self._context    ) else ('?' + self._context)
    self._url = "smb://%s%s%s%s%s%s" % (ad, un, hn, po, pa, cx)
    return( self._url )

  def dump( self, indent=0 ):
    """Return a printable string listing the URL field contents.

    Input:  indent  - Number of spaces to indent the formatted output.

    Output: A string with a user-readable list of property contents.

    Doctest:
      >>> s ="//ad;un:pw@hn:139/share/path/file.ext?SCOPE=scope.id"
      >>> print smb_url( s ).dump()
      Scheme...............: "smb"
      Authentication Domain: "ad"
      Username.............: "un"
      Password.............: "pw"
      Hostname.............: "hn"
      Port Number..........: 139
      Share Path...........: "/share/path/file.ext"
      Context..............: "SCOPE=scope.id"
      <BLANKLINE>
    """
    def fmat( val=None ):
      # Output prettying function thingy.
      if( val is None ):
        return( "" )
      if( str == type( val ) ):
        return( '"%s"' % val )
      return( str( val ) )

    ind = ' ' * indent
    s  = ind + 'Scheme...............: "%s"\n' % self.scheme
    s += ind + "Authentication Domain: %s\n" % fmat( self._authdomain )
    s += ind + "Username.............: %s\n" % fmat( self._username )
    s += ind + "Password.............: %s\n" % fmat( self._password )
    s += ind + "Hostname.............: %s\n" % fmat( self._hostname )
    s += ind + "Port Number..........: %s\n" % fmat( self._port )
    s += ind + "Share Path...........: %s\n" % fmat( self._path )
    s += ind + "Context..............: %s\n" % fmat( self._context )
    return( s )

  def _cleanStrField( self, fld ):
    # Validate the input string.
    #
    # Input:  fld - Either None, or a string representing a field within
    #               an SMB URL.
    #
    # Output: If <fld> is None or the empty string, this method will
    #         return None.  Otherwise, if no errors are detected, this
    #         method just returns the input string.
    #
    # Errors: AssertionError  - Thrown if the input is neither a string
    #                           nor None.
    #
    # Notes:  This method was originally intended to do all sorts of
    #         string cleanup before returning the input value.  It was
    #         decided, however, that it was better to let higher-level
    #         processing catch any syntactic or semantic errors in the
    #         input values.
    #
    assert( (fld is None) or isinstance( fld, str ) ), \
      "Expected a string, not a(n) %s" % type( fld ).__name__
    return( fld if( fld ) else None )

  @property
  def scheme( self ):
    """Always returns "smb".
    """
    return( "smb" )     # Self-conscious little waste of code...

  @property
  def authdomain( self ):
    """Get/set the Authentication Domain; string
    """
    return( self._authdomain )
  @authdomain.setter
  def authdomain( self, ad=None ):
    self._authdomain = self._cleanStrField( ad )

  @property
  def username( self ):
    """Get/set the Username; string
    """
    return( self._username )
  @username.setter
  def username( self, un=None ):
    self._username = self._cleanStrField( un )

  @property
  def password( self ):
    """Get/set the (optional and discouraged) password; string

    Notes:  The password field a subfield of username.  Use with
            caution; don't expose passwords.
    """
    return( self._password )
  @password.setter
  def password( self, pw=None ):
    self._password = self._cleanStrField( pw )

  @property
  def hostname( self ):
    """Get/set the Hostname (server identifier or workgroup name); string
    """
    return( self._hostname )
  @hostname.setter
  def hostname( self, hn=None ):
    self._hostname = self._cleanStrField( hn )

  @property
  def port( self ):
    """Get/set the port number; integer

    Errors:
      ValueError      - Thrown if the input is not None and cannot be
                        converted to an integer.  The port number can
                        be set to None.
      AssertionError  - Thrown if the input, converted to an integer,
                        is outside of the range of an unsigned short.
                        (uint16_t).
    """
    return( self._port )
  @port.setter
  def port( self, po=None ):
    if( (not po) and (type( po ) is not int) ):
      self._port = None
    else:
      ponum = int( po )
      assert( (0 <= ponum) and (ponum <= 0xFFFF) ), \
        "The given port number is outside the valid range (0..65535)."
      self._port = int( po )

  @property
  def path( self ):
    """Get/set the path; string
    """
    return( self._path )
  @path.setter
  def path( self, pa=None ):
    if( not pa.strip() ):
      self._path = None
    else:
      assert( isinstance( pa, str ) ), \
        "Expected a pathname string, not a(n) %s" % type( pa ).__name__
      self._path = '/' + pa.lstrip( '/' )

  @property
  def context( self ):
    """Get/set the NBT context key/value pairs; string

    See Also: <parseContext>, <composeContext>
    """
    return( self._context )
  @context.setter
  def context( self, cx=None ):
    assert( (cx is None) or isinstance( cx, str ) ), \
      "Expected a context string, not a(n) %s" % type( cx ).__name__
    self._context = composeContext( parseContext( cx ) )

  @property
  def url( self ):
    """Get/set the SMB URL; string

    Notes:  Reading the url forcess it to be composed from the available
            fields (thus ensuring that it is up to date).
    """
    return( self.compose() )
  @url.setter
  def url( self, url=None ):
    self.parse( url )

# ============================================================================ #
#                    Dreams, spread upon the gravel driveway like carrot juice #
#                      in the morning fog of a bright new day.  "Except", said #
#                           Candice, "that Harold is lactose intolerant, so he #
#                            could not have taken the catamaran to Cleveland". #
# ============================================================================ #
