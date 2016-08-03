# -*- coding: utf-8 -*-
# ============================================================================ #
#                                 SMB_Status.py
#
# Copyright:
#   Copyright (C) 2016 by Christopher R. Hertel
#
# $Id: SMB_Status.py; 2016-08-03 11:12:56 -0500; Christopher R. Hertel$
#
# ---------------------------------------------------------------------------- #
#
# Description:
#   Carnaval Toolkit: SMB NTSTATUS codes (error codes).
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
# References:
#   [MS-ERREF]  Microsoft Corporation, "Windows Error Codes"
#               https://msdn.microsoft.com/en-us/library/cc231196.aspx
#
# ============================================================================ #
#
"""Carnaval Toolkit: SMB NTSTATUS codes (error codes).

This module encapsulates the Windows NT return codes, aka., NTSTATUS
codes, that are used by SMB.  It provides methods for looking up
NTSTATUS values by name or code number, and for parsing out NTSTATUS
code subfields.

Notes:
  Early (pre-NT) versions of SMB used a different (now deprecated)
  error code format.
"""

# Internal Data -------------------------------------------------------------- #
#
#   _init_dict      - Maps NTSTATUS codes to their associated names and
#                     descriptions.  This is the "user friendly"
#                     representation.  The goal is to make it easy to
#                     read, add, and update entries.  The <_init_dict>
#                     dictionary is only used at start-up, and is deleted
#                     as soon as <_ntstatus_dict> has been generated.
#   _ntstatus_dict  - Maps NTSTATUS codes *and names* to a tuple that
#                     includes the code, name, and description.  This is
#                     the dictionary that is actually used at run-time.
_init_dict = \
  {
  0x00000000: ("STATUS_SUCCESS", "The operation completed successfully."),
  0x00000103: ("STATUS_PENDING",
    "The operation that was requested is pending completion."),
  0x00000104: ("STATUS_REPARSE",
    "A reparse should be performed by the Object Manager because the name " +
    "of the file resulted in a symbolic link."),
  0x0000010B: ("STATUS_NOTIFY_CLEANUP",
    "Indicates that a notify change request has been completed due to " +
    "closing the handle that made the notify change request."),
  0x0000010C: ("STATUS_NOTIFY_ENUM_DIR",
    "Indicates that a notify change request is being completed and that the " +
    "information is not being returned in the caller's buffer. The caller " +
    "now needs to enumerate the files to find the changes."),
  0xC0000467: ("STATUS_FILE_NOT_AVAILABLE",
    "The file is temporarily unavailable."),
  0x80000005: ("STATUS_BUFFER_OVERFLOW",
    "Buffer Overflow; The data was too large to fit into the specified " +
    "buffer."),
  0x80000006: ("STATUS_NO_MORE_FILES",
    "No more files were found which match the file specification."),
  0x80000014: ("STATUS_EA_LIST_INCONSISTENT",
    "The extended attribute (EA) list is inconsistent."),
  0x8000001A: ("STATUS_NO_MORE_ENTRIES",
    "No more entries are available from an enumeration operation."),
  0x8000002D: ("STATUS_STOPPED_ON_SYMLINK",
    "The create operation stopped after reaching a symbolic link."),
  0xC0000001: ("STATUS_UNSUCCESSFUL",
    "Operation Failed; The requested operation was unsuccessful."),
  0xC0000003: ("STATUS_INVALID_INFO_CLASS",
    "Invalid Parameter; The specified information class is not a valid " +
    "information class for the specified object."),
  0xC0000004: ("STATUS_INFO_LENGTH_MISMATCH",
    "The specified information record length does not match the length that " +
    "is required for the specified information class."),
  0xC0000008: ("STATUS_INVALID_HANDLE", "An invalid HANDLE was specified."),
  0xC000000D: ("STATUS_INVALID_PARAMETER",
    "An invalid parameter was passed to a service or function."),
  0xC000000F: ("STATUS_NO_SUCH_FILE",
    "File Not Found; The file does not exist."),
  0xC0000010: ("STATUS_INVALID_DEVICE_REQUEST",
    "The specified request is not a valid operation for the target device."),
  0xC0000011: ("STATUS_END_OF_FILE",
    "The end-of-file marker has been reached. There is no valid data in the " +
    "file beyond this marker."),
  0xC0000016: ("STATUS_MORE_PROCESSING_REQUIRED",
    "Still Busy; The specified I/O request packet (IRP) cannot be disposed " +
    "of because the I/O operation is not complete."),
  0xC0000017: ("STATUS_NO_MEMORY",
    "Insufficient Quota; Not enough virtual memory or paging file quota is " +
    "available to complete the specified operation."),
  0xC0000022: ( "STATUS_ACCESS_DENIED",
    "A process has requested access to an object but has not been granted " +
    "those access rights." ),
  0xC0000023: ("STATUS_BUFFER_TOO_SMALL",
    "The buffer is too small to contain the entry.  No information has been " +
    "written to the buffer."),
  0xC0000033: ("STATUS_OBJECT_NAME_INVALID", "The object name is invalid."),
  0xC0000034: ("STATUS_OBJECT_NAME_NOT_FOUND", "The object name is not found."),
  0xC0000035: ("STATUS_OBJECT_NAME_COLLISION",
    "The object name already exists."),
  0xC000004F: ("STATUS_EAS_NOT_SUPPORTED",
    "An operation involving EAs failed because the file system does not " +
    "support EAs."),
  0xC0000051: ("STATUS_NONEXISTENT_EA_ENTRY",
    "An EA operation failed because the name or EA index is invalid."),
  0xC0000054: ("STATUS_FILE_LOCK_CONFLICT",
    "A requested read/write cannot be granted due to a conflicting file lock."),
  0xC0000055: ("STATUS_LOCK_NOT_GRANTED",
    "A requested file lock cannot be granted due to other existing locks."),
  0xC000005F: ("STATUS_NO_SUCH_LOGON_SESSION",
    "A specified logon session does not exist. It may already have been " +
    "terminated."),
  0xC0000064: ("STATUS_NO_SUCH_USER", "The specified account does not exist."),
  0xC000006A: ("STATUS_WRONG_PASSWORD",
    "When trying to update a password, this return status indicates that the " +
    "value provided as the current password is not correct."),
  0xC000006C: ("STATUS_PASSWORD_RESTRICTION",
    "When trying to update a password, this status indicates that some " +
    "password update rule has been violated.  For example, the password may " +
    "not meet length criteria."),
  0xC000006D: ("STATUS_LOGON_FAILURE",
    "The attempted logon is invalid.  This is either due to a bad username " +
    "or authentication information."),
  0xC000006F: ("STATUS_INVALID_LOGON_HOURS",
    "The user account has time restrictions and may not be logged onto at " +
    "this time."),
  0xC0000070: ("STATUS_INVALID_WORKSTATION",
    "The user account is restricted so that it may not be used to log on " +
    "from the source workstation."),
  0xC0000071: ("STATUS_PASSWORD_EXPIRED",
    "The user account password has expired."),
  0xC0000073: ("STATUS_NONE_MAPPED",
    "None of the information to be translated has been translated."),
  0xC000007C: ("STATUS_NO_TOKEN",
    "An attempt was made to reference a token that does not exist.  This is " +
    "typically done by referencing the token that is associated with a " +
    "thread when the thread is not impersonating a client."),
  0xC000007E: ("STATUS_RANGE_NOT_LOCKED",
    "The range specified in NtUnlockFile was not locked."),
  0xC000007F: ("STATUS_DISK_FULL",
    "An operation failed because the disk was full."),
  0xC000009A: ("STATUS_INSUFFICIENT_RESOURCES",
    "Insufficient system resources exist to complete the API."),
  0xC00000B5: ("STATUS_IO_TIMEOUT",
    "Device Timeout; The specified I/O operation was not completed " +
    "before the time-out period expired."),
  0xC00000B6: ("STATUS_FILE_FORCED_CLOSED",
    "The specified file has been closed by another process."),
  0xC00000BA: ("STATUS_FILE_IS_A_DIRECTORY",
    "The file that was specified as a target is a directory, and the caller " +
    "specified that it could be anything but a directory."),
  0xC00000BB: ("STATUS_NOT_SUPPORTED", "The request is not supported."),
  0xC00000C3: ("STATUS_INVALID_NETWORK_RESPONSE",
    "The network responded incorrectly."),
  0xC00000C9: ("STATUS_NETWORK_NAME_DELETED", "The network name was deleted."),
  0xC00000D0: ("STATUS_REQUEST_NOT_ACCEPTED",
    "No more connections can be made to this remote computer at this time " +
    "because the computer has already accepted the maximum number of " +
    "connections."),
  0xC00000DF: ("STATUS_NO_SUCH_DOMAIN", "The specified domain did not exist."),
  0xC00000E3: ("STATUS_INVALID_OPLOCK_PROTOCOL",
    "An error status returned when an invalid opportunistic lock (oplock) " +
    "acknowledgment is received by a file system."),
  0xC00000E5: ("STATUS_INTERNAL_ERROR", "An internal error occurred."),
  0xC0000102: ("STATUS_FILE_CORRUPT_ERROR",
    "Corrupt File; The file or directory is corrupt and unreadable."),
  0xC0000103: ("STATUS_NOT_A_DIRECTORY",
    "A requested opened file is not a directory."),
  0xC0000120: ("STATUS_CANCELLED", "The I/O request was canceled."),
  0xC0000128: ("STATUS_FILE_CLOSED",
    "An I/O request other than close and several other special case " +
    "operations was attempted using a file object that had already been " +
    "closed."),
  0xC000014B: ("STATUS_PIPE_BROKEN",
    "The pipe operation has failed because the other end of the pipe has " +
    "been closed."),
  0xC000015B: ("STATUS_LOGON_TYPE_NOT_GRANTED",
    "A user has requested a type of logon (for example, interactive or " +
    "network) that has not been granted. An administrator has control over " +
    "who may logon interactively and through the network."),
  0xC0000184: ("STATUS_INVALID_DEVICE_STATE",
    "The device is not in a valid state to perform this request."),
  0xC000018D: ("STATUS_TRUSTED_RELATIONSHIP_FAILURE",
    "The logon request failed because the trust relationship between this " +
    "workstation and the primary domain failed."),
  0xC0000190: ("STATUS_TRUST_FAILURE",
    "The network logon failed. This may be because the validation authority " +
    "cannot be reached."),
  0xC0000192: ("STATUS_NETLOGON_NOT_STARTED",
    "An attempt was made to logon, but the NetLogon service was not started."),
  0xC000019C: ("STATUS_FS_DRIVER_REQUIRED",
    "A volume has been accessed for which a file system driver is required " +
    "that has not yet been loaded."),
  0xC0000203: ("STATUS_USER_SESSION_DELETED",
    "The remote user session has been deleted."),
  0xC000020C: ("STATUS_CONNECTION_DISCONNECTED",
    "The transport connection is now disconnected."),
  0xC0000224: ("STATUS_PASSWORD_MUST_CHANGE",
    "The user password must be changed before logging on the first time."),
  0xC000022A: ("STATUS_DUPLICATE_OBJECTID",
    "The attempt to insert the ID in the index failed because the ID is " +
    "already in the index."),
  0xC0000233: ("STATUS_DOMAIN_CONTROLLER_NOT_FOUND",
    "A domain controller for this domain was not found."),
  0xC000023C: ("STATUS_NETWORK_UNREACHABLE",
    "The remote network is not reachable by the transport."),
  0xC000026E: ("STATUS_VOLUME_DISMOUNTED",
    "An operation was attempted to a volume after it was dismounted."),
  0xC00002F9: ("STATUS_PKINIT_NAME_MISMATCH",
    "The client certificate does not contain a valid UPN, or does not " +
    "match the client name in the logon request."),
  0xC0000320: ("STATUS_PKINIT_FAILURE",
    "The Kerberos protocol encountered an error while validating the KDC " +
    "certificate during smart card logon. There is more information in the " +
    "system event log."),
  0xC000035C: ("STATUS_NETWORK_SESSION_EXPIRED",
    "The client session has expired; The client must re-authenticate to " +
    "continue accessing the remote resources."),
  0xC0000380: ("STATUS_SMARTCARD_WRONG_PIN",
    "An incorrect PIN was presented to the smart card."),
  0xC0000381: ("STATUS_SMARTCARD_CARD_BLOCKED", "The smart card is blocked."),
  0xC0000383: ("STATUS_SMARTCARD_NO_CARD", "No smart card is available."),
  0xC0000388: ("STATUS_DOWNGRADE_DETECTED",
    "The system detected a possible attempt to compromise security.  " +
    "Ensure that you can contact the server that authenticated you."),
  0xC000038C: ("STATUS_PKINIT_CLIENT_FAILURE",
    "The smart card certificate used for authentication was not trusted.  " +
    "Contact your system administrator."),
  0xC000038F: ("STATUS_SMARTCARD_SILENT_CONTEXT",
    "The smart card provider could not perform the action because the " +
    "context was acquired as silent."),
  0xC0000466: ("STATUS_SERVER_UNAVAILABLE",
    "The file server is temporarily unavailable."),
  0xC000A100: ("STATUS_HASH_NOT_SUPPORTED",
    "Hash generation for the specified version and hash type is not enabled " +
    "on server."),
  0xC000A101: ("STATUS_HASH_NOT_PRESENT",
    "The hash requests is not present or not up to date with the current " +
    "file contents.")
  }
# Build the "real" dictionary from the initial one.
_ntstatus_dict = {}
for code in _init_dict:
  name, desc = _init_dict[code]
  _ntstatus_dict[ code ] = (code, name.upper(), desc)
  _ntstatus_dict[ name ] = _ntstatus_dict[ code ]
# Clean up.
del _init_dict, code, name, desc

# Functions ------------------------------------------------------------------ #
#

def getTuple( key=None ):
  """Given an NTSTATUS code or name, retrieve an NTSTATUS three-tuple.

  Input:  key - A name or number that uniquely identifies an NTSTATUS
                value.
  Output: This method returns None if the given <key> is not defined.
          Otherwise, a three-tuple is returned.  The fields are:
            [0] - The NTSTATUS code value, an unsigned integer
                  (typically a <long>, but it may be an <int>).
            [1] - The name of the NTSTATUS value, as a string.  This
                  should always be in all-caps and prefixed with
                  "STATUS_".
            [2] - The error message associated with the NTSTATUS.

  Errors:
    AssertionError  - The given <key> was neither a string nor an
                      integer type.  That's just wrong.

  Doctest:
    >>> print getTuple( 0xF0000001 )
    None
    >>> print getTuple( 0 )
    (0, 'STATUS_SUCCESS', 'The operation completed successfully.')
  """
  t = type( key )
  assert( t in [str, int, long] ), \
    "The NTSTATUS <key> must be a string or an integer."
  if( str == t ):
    key = key.upper()
  try:
    return( _ntstatus_dict[key] )
  except KeyError:
    return( None )

def getCode( key=None ):
  """Given an NTSTATUS code or name, retrieve just the NTSTATUS code.

  Input:  key - The name or number of the NTSTATUS value.
                (Typically, this will be the name, since it's
                pointless to look up the code using the code.)

  Output: The NTSTATUS code, as an integer, or None if <key> is not
          defined.

  Errors:
    AssertionError  - The given <key> was neither a string nor an
                      integer type (<long> or <int>).

  Doctest:
    >>> print getCode( 0xF0000001 )
    None
    >>> print "0x%08X" % getCode( 0xC000007C )
    0xC000007C
    >>> print getCode()
    Traceback (most recent call last):
    ...
    AssertionError: The NTSTATUS <key> must be a string or an integer.
  """
  entry = getTuple( key )
  return( None if( entry is None ) else entry[0] )

def getName( key=None ):
  """Given an NTSTATUS code or name, retrieve just the name.

  Input:  key - The name or number of the NTSTATUS value.
                (Typically, this will be the code, since it's
                pointless to look up the name using the name.)

  Output: The NTSTATUS name, as a string, or None if <key> is
          not defined.

  Errors:
    AssertionError  - The given <key> was neither a string nor an
                      integer type (<long> or <int>).
  Doctest:
    >>> print getName( 0xF0000001 )
    None
    >>> print getName( 0 )
    STATUS_SUCCESS
    >>> print getName( 0xC00000BB )
    STATUS_NOT_SUPPORTED
  """
  entry = getTuple( key )
  return( None if( entry is None ) else entry[1] )

def getDesc( key=None ):
  """Given an NTSTATUS code or name, retrieve just the description.

  Input:  key - The name or number of the NTSTATUS value.

  Output: The NTSTATUS description, as a string, or None if <key>
          is not defined.

  Errors:
    AssertionError  - The given <key> was neither a string nor an
                      integer type.

  Doctest:
    >>> print getDesc( 0xF0000001 )
    None
    >>> print getDesc( "STATUS_SUCCESS" )
    The operation completed successfully.
  """
  entry = getTuple( key )
  return( None if( entry is None ) else entry[2] )

def parseCode( code=None ):
  """Parse an NTSTATUS code into its various subcomponents.

  Input:  code  - The NTSTATUS code to be parsed.

  Output: A 5-tuple containing the following fields:
            Sev       - Message severity, as a number.
                        0 == Success  1 == Information
                        2 == Warning  3 == Error
            C         - Customer bit.  This should always be clear
                        (0) in NTSTATUS code values returned from
                        an SMB server.
            N         - Reserved; should always be clear (0).
            Facility  - A 12-bit Facility code, indicating the
                        subsystem that generated the NTSTATUS code.
            SubCode   - The remainder of the error code.

  Errors:
    AssertionError  - Thrown if the input is not an integer value.

  Notes:  This method provides access to archane information of
          academic or alchemic interest...but here it is anyway.
          [MS-ERREF; 2.3] provides more information about each of
          the returned subfields.

          The Facility codes are, of course, defined with respect
          to Windows subsystems.  See [MS-ERREF; 5] for a table of
          Windows Facility codes and their meanings.

  Doctest:
    >>> parseCode( 0xC0000467 )
    (3, 0, 0, 0, 1127)
    >>> parseCode( 0xC0130003 )
    (3, 0, 0, 19, 3)
    >>> parseCode( 0x60123456 )
    (1, 1, 0, 18, 13398)
    >>> parseCode( 0xFFFFFFFF )
    (3, 1, 1, 4095, 65535)
  """
  assert( type( code ) in [int, long] ), "Expected an integer value."
  code      = long( code ) & 0xFFFFFFFF
  sev       = int( code >> 30 )
  Customer  = 1 if( code & 0x20000000 ) else 0
  Nreserved = 1 if( code & 0x10000000 ) else 0
  facility  = int( (code & 0x0FFF0000) >> 16 )
  subCode   = int( code & 0x0000FFFF )
  return( (sev, Customer, Nreserved, facility, subCode) )

def severityName( sev ):
  """Return the textual representation of the severity of an NTSTATUS code.

  Input:  sev - The severity value, as an integer in the range 0..3.

  Output: One of the following strings:
            ["Success", "Info", "Warning", "Error"]

  Errors:
    AssertionError  - Thrown if the input is a negative integer.
    IndexError      - Thrown if the input is greater than three (3).
    TypeError       - Thrown if the input is not an integer at all.

  Notes:
    The severity level can be calculated either by calling parseCode(),
    or as (0x3 & (NTSTATUS >> 30)).

  Doctest:
    >>> severityName( 0 )
    'Success'
    >>> severityName( "Feldspar Omnibus Noodle" )
    Traceback (most recent call last):
    ...
    TypeError: list indices must be integers, not str
  """
  assert( sev >= 0 ), "Expecting an integer value in the range 0..3."
  return( ["Success", "Info", "Warning", "Error"][sev] )

# ============================================================================ #
