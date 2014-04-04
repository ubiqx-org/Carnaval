#!/usr/bin/env python
# ============================================================================ #
#                          $Name: git_keywords.py$
#
# Copyright (C) 2012 Jose A. Rivera <jarrpa@redhat.com>
#
# $Date: 2014-04-03 23:31:49 -0500$
#
# ---------------------------------------------------------------------------- #
#
# Description: Keyword-substitution git pre-commit hook.
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
# ============================================================================ #
#
"""Git pre-commit variable substitution script.

This script is a git pre-commit hook.  It looks for altered text files in
the index, scans them for keywords, and inserts relevant keyword information
for each keyword found.  The keyword is retained, but the associated value
is either added or updated.

Currently, the following keywords are supported:
  * Name      - The name of the file.
  * Copyright - A string indicating who holds copyright to the file and when.
                Taken as the author of the commit.
  * Date      - A date and time stamp of when the file was last committed.
  * Id        - A string giving the file name, author date, and author name.
  * Author    - A string giving the author name and author e-mail address.
  * AName     - The file author's name.
  * AEmail    - The file author's e-mail address.
  * ADate     - The file author's date of authorship.
  * Committer - A string giving the committer name and author e-mail address.
  * CName     - The file committer's name.
  * CEmail    - The file committer's e-mail address
  * CDate     - The file committer's date of commit. An alias for Date.

In addition, this script requires the use of the following custom git
attributes:
  * kwsub - If True, the file will be marked for keyword substitution.  If
            False or unspecified, the file will be ignored.
See 'git help attributes' for more information on git attributes.
"""

# ---------------------------------------------------------------------------- #
# Imports
#

import sys
import re
import os
import mimetypes
from git_utils import git, git_config, git_parse_date, LocalTZ
from getpass  import getuser
from socket   import getfqdn
from datetime import datetime


# ---------------------------------------------------------------------------- #
# Functions
#

def getenv( key ):
  """Return the value of the given environmental variable.

  key - The name of the environmental variable.

  Output: The value assigned to the given variable, or the empty string if
          no such name exists in the environment.
  """
  return( os.environ[key] if( key in os.environ ) else '' )

def kwsub( filepath ):
  """Scan through the given file line-by-line looking for matching keywords.
  Substitute appropriate values if keywords are found.

  filepath  - Path to the file to be scanned.
  """
  tmppath = filepath + '.tmp'
  # Try to open files. rfile is the reading file, wfile is the temp writing
  # file. If this fails, abort commit.
  try:
    rfile = open( filepath, 'r' )
    wfile = open( tmppath, 'w' )
    # Copy over stat modes (rwx) from the original file. Important for scripts!
    os.chmod( tmppath, os.stat( filepath ).st_mode )
  except Exception as e:
    os.remove( tmppath )
    sys.exit( e )

  # Gather system information.
  user      = getuser()
  git_user  = git_config( 'user.name' )
  git_email = git_config( 'user.email' )
  fqdn      = getfqdn()
  an = getenv('GIT_AUTHOR_NAME') or git_user or user
  ae = getenv('GIT_AUTHOR_EMAIL') or git_email or (user + '@' + fqdn)
  cn = getenv('GIT_COMMITTER_NAME') or git_user or user
  ce = getenv('GIT_COMMITTER_EMAIL') or git_email or (user + '@' + fqdn)
  author = an + ' <' + ae + '>'
  committer = cn + ' <' + ce + '>'
  dt = datetime.now().replace( tzinfo=LocalTZ )
  dfmt = '%Y-%m-%d %H:%M:%S'
  ad = git_parse_date( getenv( 'GIT_AUTHOR_DATE' ) ) or dt
  adate = ad.strftime( dfmt + ' %z' )
  cd = git_parse_date( getenv( 'GIT_COMMITTER_DATE' ) ) or dt
  cdate = cd.strftime( dfmt + ' %z' )
  name = os.path.basename( filepath )

  # Set the keywords and their substitutions.
  kw = { 'Name'     : 'Name: ' + name,
         'Copyright': 'Copyright (C) ' + str(ad.year) + ' ' + author,
         'Date'     : 'Date: ' + cdate,
         'Id'       : 'Id: ' + name + ' ' + cdate + ' ' + cn,
         'Author'   : 'Author: ' + author,
         'AName'    : 'AName: ' + an,
         'AEmail'   : 'AEmail: ' + ae,
         'ADate'    : 'ADate: ' + adate,
         'Committer': 'Committer: ' + committer,
         'CName'    : 'CName: ' + cn,
         'CEmail'   : 'CEmail: ' + ce,
         'CDate'    : 'CDate: ' + cdate,
       }

  # Begin substitution.
  subbed = False
  for line in rfile:
    for key in kw:
      for m in re.finditer( r'\$(' + key + ')([^$]*)\$', line ):
        line = line[:m.start()] + '$' + kw[key] + '$' + line[m.end():]
        subbed = True
        # Debug line.
        #print filepath + ': ' + line
    wfile.write( line )

  rfile.close()
  wfile.close()

  if( subbed ):
    os.remove( filepath )
    os.rename( tmppath, filepath )
    git( 'add ' + filepath )
  else:
    os.remove( tmppath )

  # Set environment variables so git metadata matches in-file metadata.
  os.environ[ 'GIT_AUTHOR_NAME' ]  = an
  os.environ[ 'GIT_AUTHOR_EMAIL' ] = ae
  os.environ[ 'GIT_AUTHOR_DATE' ]  = ad.strftime( dfmt )
  os.environ[ 'GIT_COMMITTER_NAME' ]  = cn
  os.environ[ 'GIT_COMMITTER_EMAIL' ] = ce
  os.environ[ 'GIT_COMMITTER_DATE' ]  = cd.strftime( dfmt )

  # Done.
  return


# ---------------------------------------------------------------------------- #
# Mainline
#
def main():
  """Mainline.

  Check for modified files in the index, try to determine whether or not
  they are text files, and then determine whether or not they are marked
  for keyword substitution.
  """
  for file in git( 'diff-index --cached --diff-filter=ACMRTUX ' + \
                   '--name-only HEAD' ).split('\n'):
    if( file ):
      mime = mimetypes.guess_type( file )
      if( (mime[0] is None or 'text' in mime[0]) and \
          ('true' == git('check-attr kwsub ' + file).split(': ')[2]) ):
        kwsub( file )
  sys.exit( 0 )

if __name__ == '__main__':
  main()

# ============================================================================ #
