# ============================================================================ #
#                            $Name: git_utils.py$
#
# Copyright (C) 2012 Jose A. Rivera <jarrpa@redhat.com>
# Copyright (C) 2017 Christopher R. Hertel <crh@ubiqx.org>
#
# $Date: 2018-02-21 06:29:07 -0600$
#
# ---------------------------------------------------------------------------- #
#
# Description: Mostly-git-related utility functions.
#
# ---------------------------------------------------------------------------- #
#
# License:
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# ---------------------------------------------------------------------------- #
#
# Notes:
#
# ToDo:
#   - This module does its job, but it could sure use some cleanup.
#
# ============================================================================ #

# ---------------------------------------------------------------------------- #
# Imports
#

import sys
import re
import os
import subprocess
import time as _time
from datetime import datetime, timedelta, tzinfo


# ---------------------------------------------------------------------------- #
# Functions
#

def git( args, interactive=False, ginput=None, cwd=None ):
  """Execute a git command via a subprocess.
  """
  if( type(args) == str ):
    tmp = args.split('"')
    tmp2 = []
    for i in range( len(tmp) ):
      if( i % 2 ):
        tmp2.append( tmp[i] )
      else:
        tmp2 += tmp[i].split()
    args = tmp2
  args  = ['git'] + args
  out   = None if( interactive ) else subprocess.PIPE
  inp   = None if( interactive ) else subprocess.PIPE
  gitsp = subprocess.Popen( args, cwd=cwd,
                            stdout=out, stdin=inp, stderr=subprocess.STDOUT )
  if( not interactive ):
    details = gitsp.communicate( ginput )[0]
    details = details.strip()
  else:
    gitsp.wait()
    details = None
  return( details )

def git_config( key ):
  """Git config.
  """
  # FIX:  Please document what this function is meant to do and why.
  details = git( ['config', '%s' % (key)] )
  if( details ):
    return( details )
  else:
    return( None )

def git_repo_name():
  """Attempt to determine the repository name from the current path.

  Notes:  I'm not actually clear on what this function is intended to do.
  """
  # FIX:  Please document what this function is meant to do and why.
  if git( ['rev-parse', '--is-bare-repository'] ) == 'true':
    return( os.path.basename( os.getcwd() ) )
  else:
    return( os.path.basename( os.path.dirname( os.getcwd() ) ) )

def git_parse_date( datestr, fmt=False ):
  """Parse a given date string into a Python datetime object.

  Formats allowed for the date string are the same as those outlined in
  'git help commit' under DATE FORMATS.

  datestr - A properly formatted date string.
  fmt     - A boolean to indicate if the discovered format of the string
            should also be returned.  See the Output section.

  Output: If fmt is False, return a Python datetime object. If fmt is True,
          return a tuple (<date>, <format>) where <date> is a datetime object
          and <format> is a format string indicating the discovered format of
          datestr. If datestr can not me parsed, return either None (if
          fmt=False) or a tuple of (None,'') (if fmt=True).
  """
  # FIX:  This function does not appear to do anything worth-while.
  #       It returns either None or the tuple ( None, '' ).
  #       Is it just incomplete?

  # Define acceptable formats.
  fmtstrs = { 'gittime'  : '%s %z', # NOTE: %s may not be cross-platform.
              'rfc2822'  : '%a, %d %b %Y %H:%M:%S %z',
              'isodate1' : '%Y-%m-%d',
              'isodate2' : '%Y.%m.%d',
              'isodate3' : '%m/%d/%Y',
              'isodate4' : '%d.%m.%Y',
              'isosep1'  : 'T',
              'isosep2'  : ' ',
              'isotime'  : '%H:%M:%S',
            }

  dtm    = None
  fmtstr = ''

  # Done. Return results.
  if fmt == False:
    results = dtm
  else:
    results = ( dtm, fmtstr )
  return( results )


# ---------------------------------------------------------------------------- #
# A class capturing the platform's idea of local time.
# Taken from https://docs.python.org/2/library/datetime.html#tzinfo-objects
# on 2017-08-30.

STDOFFSET = timedelta( seconds = -_time.timezone )
if( _time.daylight ):
  DSTOFFSET = timedelta( seconds = -_time.altzone )
else:
  DSTOFFSET = STDOFFSET
DSTDIFF = DSTOFFSET - STDOFFSET

class LocalTimezone( tzinfo ):
  """Provide local timezone information.
  """
  def _isdst( self, dt ):
    """Undocumented.
    """
    tt = ( dt.year, dt.month, dt.day,
           dt.hour, dt.minute, dt.second,
           dt.weekday(), 0, 0 )
    stamp = _time.mktime( tt )
    tt = _time.localtime( stamp )
    return( tt.tm_isdst > 0 )

  def utcoffset( self, dt ):
    """Undocumented.
    """
    if( self._isdst( dt ) ):
      return( DSTOFFSET )
    else:
      return( STDOFFSET )

  def dst( self, dt ):
    """Undocumented.
    """
    if( self._isdst( dt ) ):
      return( DSTDIFF )
    else:
      return( timedelta( 0 ) )

  def tzname( self, dt ):
    """Undocumented.
    """
    return( _time.tzname[self._isdst( dt )] )


# ---------------------------------------------------------------------------- #
# Mainline...

LocalTZ = LocalTimezone()

# ============================================================================ #
