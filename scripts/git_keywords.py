#!/usr/bin/env python
# ============================================================================ #
#                          $Name: git_keywords.py$
#
# Copyright (C) 2012 Jose A. Rivera <jarrpa@redhat.com>
# Copyright (C) 2017 Christopher R. Hertel <crh@ubiqx.org>
#
# $Date: 2017-03-10 15:58:23 -0600$
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
  * Copyright - A string indicating who holds copyright to the file and
                when.  Taken as the author of the commit.  This should only
                be used when a single author holds copyright.
  * Date      - A date and time stamp of when the file was last committed.
  * Id        - A string giving the file name, author date, and author name.
  * Author    - A string giving the author name and author e-mail address.
  * AName     - The file author's name.
  * AEmail    - The file author's e-mail address.
  * ADate     - The file author's date of authorship.
  * Committer - A string giving the committer name and e-mail address.
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
  """Perform keyword substitution on the given file.

  filepath  - The pathname of the file to be operated upon.

  Notes:  This function scans through the given file line-by-line
          looking for keywords.  It then expands those keywords by
          adding or replacing the associated value string.  The changes,
          if any, are written to a temporary file.  If the process
          completes successfully, the temporary file replaces the
          original and 'git add' is called to add the updated version to
          the repositiory.

          If there is an error opening either the source or temporary
          file used by this function, sys.exit() will be called, which
          will abort the commit that caused this pre-commit hook script
          to be called.
  """
  # FIX:  Creating a temporary file by simply adding '.tmp' to the pathname
  #       could (in theory) lead to overwriting of some existing file that
  #       the user actually wanted.  It'd be better to use something like
  #       mkstemp(3).  Fortunately, Python has such magic:
  #         https://docs.python.org/2/library/tempfile.html
  #
  #     - It would be nice if this function could be run stand-alone, so
  #       that it could be used in more situations than just a pre-commit
  #       script.  It does nice stuff.
  #       Suggestion:  Move the calls to sys.exit() and 'git add' out of the
  #       function and let the function return true/false or some other
  #       status indication.  On success, do the 'git add'.  On failure
  #       exit the program.
  #
  #     - Delete this FIX block.  ;)
  # /FIX

  # Try to open files.
  #   rfile is the file to be read (source file)
  #   wfile is the temporary file that will be written
  # If opening the files or copying permissions fails, then bail out.
  tmppath = filepath + '.tmp'
  try:
    rfile = open( filepath, 'r' )
    wfile = open( tmppath,  'w' )
    # Copy over stat modes (rwx) from the original file.  Important for scripts!
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
         'Date'     : 'Date: '   + cdate,
         'Id'       : 'Id: ' + name + '; ' + cdate + '; ' + cn,
         'Author'   : 'Author: ' + author,
         'AName'    : 'AName: '  + an,
         'AEmail'   : 'AEmail: ' + ae,
         'ADate'    : 'ADate: '  + adate,
         'Committer': 'Committer: ' + committer,
         'CName'    : 'CName: '  + cn,
         'CEmail'   : 'CEmail: ' + ce,
         'CDate'    : 'CDate: '  + cdate,
       }

  # Begin substitution.
  subbed = False
  for line in rfile:
    if '$' in line:
      for key in kw:
        for m in re.finditer( r'\$(' + key + ')([^$]*)\$', line ):
          line = line[:m.start()] + '$' + kw[key] + '$' + line[m.end():]
          subbed = True
          # DEBUG: print filepath + ': ' + line
    wfile.write( line )

  # Close 'em.
  rfile.close()
  wfile.close()

  # Update the files.
  if( subbed ):
    # Replace the original file with the new one.
    os.remove( filepath )
    os.rename( tmppath, filepath )
    git( 'add ' + filepath )
  else:
    # ...or just remove the tmpfile if no changes were made.
    os.remove( tmppath )

  # Set environment variables so that git metadata matches in-file metadata.
  os.environ[ 'GIT_AUTHOR_NAME'     ] = an
  os.environ[ 'GIT_AUTHOR_EMAIL'    ] = ae
  os.environ[ 'GIT_AUTHOR_DATE'     ] = ad.strftime( dfmt )
  os.environ[ 'GIT_COMMITTER_NAME'  ] = cn
  os.environ[ 'GIT_COMMITTER_EMAIL' ] = ce
  os.environ[ 'GIT_COMMITTER_DATE'  ] = cd.strftime( dfmt )

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
  gcmd = 'diff-index --cached --diff-filter=ACMRTUX --name-only HEAD'
  for fname in [ fnam for fnam in git( gcmd ).split('\n') if fnam ]:
    # Try to determine the mime type of the file.
    mime = mimetypes.guess_type( fname )
    if( (mime[0] is None) or ('text' in mime[0]) ):
      # Good chance it's a text file.  See if we're allowed to work on it.
      if( 'true' == git( 'check-attr kwsub ' + fname ).split(': ')[2] ):
        # Perform keyword substitution.
        kwsub( fname )

  # All done.
  sys.exit( 0 )

# You know what this is.  You know what it does.
#
if __name__ == '__main__':
  main()

# ============================================================================ #
