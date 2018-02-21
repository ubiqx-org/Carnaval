# -*- coding: utf-8 -*-
# ============================================================================ #
#                                 SMB_Status.py
#
# Copyright:
#   Copyright (C) 2016 by Christopher R. Hertel
#
# $Id: SMB_Status.py; 2018-02-21 06:29:07 -0600; Christopher R. Hertel$
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
NTSTATUS values by code number, and for parsing out NTSTATUS
code subfields.

Notes:
  * [MS-ERREF] provides a list of Windows NTSTATUS codes, their
    standard names, and their associated messages (in English).
  * Pre-NT versions of SMB used the SMB_ERROR error code format.
    SMB_ERROR codes are 4 octets in length, just like NTSTATUS codes,
    but the two are composed differently.  SMB_ERROR codes are
    deprecated, and are not used in SMB2/3.  See [MS-CIFS; 2.2.1.5].
"""


# Classes -------------------------------------------------------------------- #
#

class NTStatus( long ):
  """The NTStatus class is used to generate a global set of NTSTATUS
  codes.  It also provides the basic utility methods needed to manage
  and use those codes.

  Here's how it works:

    from SMB_Status import *

  Now you have access to a bunch of NTSTATUS codes, such as
  STATUS_NO_SUCH_FILE, which represents the error code returned by
  Windows if it cannot find the file you requested.  The value of
  STATUS_NO_SUCH_FILE turns out to be 0xC000000F.

  The NTSTATUS codes are given as python long integers, but they are
  actually stored as instances of the NTStatus class, which is a
  descendant of the built-in <long> type.  In addition to the error
  code, NTStatus objects also store the name and message text of the
  error.  (See the examples, below.)

  All of the NTSTATUS codes provided by this module are also kept
  in an internal dictionary, which provides a mechanism for reverse
  lookup.  Passing the status code to the NTStatus() constructor
  returns the alread-existing NTStatus object found in the internal
  dictionary, or <None> if the code was not found.

  Windows has a lot of error codes.  This module provides definitions
  for only those codes that are known to be used in SMB2.  As testing
  uncovers additional error codes that are passed over the wire, those
  codes can be easily added.

  New NTStatus codes are automatically added to the global list when
  they are instantiated.  For example:
    MY_STATUS_CODE = NTStatus( 0xA00001FF, "MY_STATUS_CODE",
                               "Something annoying happened." )
  ...does the following:
    - Creates an NTStatus code instance with a value of 0xA00001FF,
    - Adds the new instance to the internal dictionary in the class,
    - Returns a reference to the new instance and stores it in
      MY_STATUS_CODE.

  The Constructor
  === ===========

  The NTStatus() constructor is purposefully overloaded.
    - If you pass in only the code value (as an integer), NTStatus()
      will perform a lookup in the internal dictionary.  If a matching
      entry is found, a reference to the NTStatus object is returned.
      Otherwise, <None> is returned.
    - If you pass in the code, name, and error message, a new NTStatus
      object instance will be created, and a reference to the new
      instance will be added to the internal dictionary.
    - Other combinations should cause an exception to be thrown.

  Doctest:
    >>> print "0x%08X" % STATUS_NO_SUCH_FILE
    0xC000000F
    >>> print "[%s]" % STATUS_NO_SUCH_FILE.name
    [STATUS_NO_SUCH_FILE]
    >>> print STATUS_NO_SUCH_FILE.message
    File Not Found; The file does not exist.
    >>> status = NTStatus( 0xC000000F )
    >>> print "{0:s} == 0x{1:08X}".format( status.name, status )
    STATUS_NO_SUCH_FILE == 0xC000000F
    >>> #
    >>> # Using the NTStatus() Constructor:
    >>> MY_STATUS_CODE = NTStatus( 0xA00001FF, "MY_STATUS_CODE",
    ...                            "Something annoying happened." )
    >>> MyStat = NTStatus( MY_STATUS_CODE )
    >>> print MyStat.name, MyStat.message
    MY_STATUS_CODE Something annoying happened.
    >>> MyStat.remove()
    >>> del MyStat
    >>> print NTStatus( 0xA00001FF )
    None
    >>> print "0x%08X" % MY_STATUS_CODE
    0xA00001FF
    >>> del MY_STATUS_CODE
  """
  # Class attributes
  #
  #   _ntstatus_dict  - Maps NTStatus code values to NTStatus objects.
  #                     This is used to allow lookup of NTStatus objects
  #                     based on the status code.  The retrieved object,
  #                     if there is one, will include the code, name, and
  #                     description of the NTStatus.  This dictionary is
  #                     populated automagically as the NTStatus values are
  #                     instantiated.
  _ntstatus_dict = {}

  def __new__( cls, code=None, name=None, message=None ):
    # We're doing two things here:
    #   1) We are adding a some interesting attributes to the <long>
    #      built-in class, as well as a handful of useful methods.
    #      Creating a subclass of <long> lets us do this without losing
    #      the basic characteristics of the <long> class itself.
    #
    #   2) We're overloading <__new__()> in a quirky, but utilitarian, way.
    #      If we get only the <code> argument, then instead of creating a
    #      new instance we perform a lookup in the class lookup table:
    #      <_ntstatus_dict>.  If the entry is found, return it, otherwise
    #      return <None>.
    #
    # The parent class of this class must be <long> (instead of <int>)
    # because the <int> class may be a signed 32-bit value on some platforms.
    # NTStatus codes are unsigned 32-bit values by definition.

    # Validate the status code.
    if( not (isinstance( code, int ) or isinstance( code, long )) ):
      s = "The <code> argument must be of type <int> or <long>, not %s."
      raise TypeError( s % type( code ) )
    code = (long( code ) & 0xFFFFFFFF)

    # If we only received one argument, assume it's an NTStatus code and
    # look for the corresponding NTStatus object in the dictionary.  This
    # is a quirky overloading of <__new__()>, used to find an existing
    # instance rather than creating a new instance.
    #
    if( (name is None) and (message is None) ):
      if( code in cls._ntstatus_dict ):
        return( cls._ntstatus_dict[ code ] )
      return( None )

    # Validate the two string parameters.
    if( not isinstance( name, str ) ):
      s = "The <name> argument must be of type <str>, not %s."
      raise TypeError( s % type( name ) )
    if( not isinstance( message, str ) ):
      s = "The <message> argument must be of type <str>, not %s."
      raise TypeError( s % type( message ) )

    # Create the instance, fill in the attributes, and return it.
    inst = super( NTStatus, cls ).__new__( cls, code )
    inst._name = name
    inst._mesg = message
    cls._ntstatus_dict[ code ] = inst  # Add it to the lookup table.
    return( inst )

  def remove( self ):
    """Remove this instance from the internal class dictionary.

    This method is provided for completeness.  There is no reason to
    use it.

    If the NTStatus code of the calling instance exists in the class
    lookup dictionary (<NTStatus._ntstatus_dict>), then that entry is
    deleted.  This is only really useful when the NTStatus instance
    itself is about to be deleted, and there is no reason (that I can
    foresee) to delete an NTStatus instance.

    Note that it doesn't work to put this funtionality into a
    <__del__()> method since the reference in the internal dictionary
    will prevent the <__del__()> method from being called.  Checkmate.

    Doctest:
      >>> Foo = NTStatus( 0xA0000099, "Foo", "This is the Foo!" )
      >>> print NTStatus( 0xA0000099 )
      2684354713
      >>> Foo.remove()
      >>> print NTStatus( 0xA0000099 )
      None
      >>> del Foo
    """
    if( self in self._ntstatus_dict ):
      del self._ntstatus_dict[ self ]

  @property
  def name( self ):
    """Get the name of the NTStatus code, returned as a string.

    Doctest:
      >>> STATUS_PENDING.name
      'STATUS_PENDING'
      >>> STATUS_PENDING == NTStatus( eval( STATUS_PENDING.name ) )
      True
    """
    return( self._name )

  @property
  def message( self ):
    """Get the error message string associated with the error code.

    Doctest:
      >>> eval( "STATUS_NO_SUCH_FILE" ).message
      'File Not Found; The file does not exist.'
    """
    return( self._mesg )

  @property
  def getTuple( self ):
    """Get the NTStatus code, name, and error message as a tuple.

    Doctest:
      >>> NTStatus( 0 ).getTuple
      (0L, 'STATUS_SUCCESS', 'The operation completed successfully.')
    """
    return( (self, self._name, self._mesg) )

  @property
  def subCodes( self ):
    """Get the subcomponents of an NTStatus code.

    Output: A 5-tuple containing the following fields:
              Severity  - Message severity, as an integer.
                          0 == Success  1 == Information
                          2 == Warning  3 == Error
              C         - Customer bit.  This should always be clear
                          (0) in NTStatus code values returned from
                          an SMB server.
              N         - Reserved; should always be clear (0).
              Facility  - A 12-bit Facility code, indicating the
                          subsystem that generated the NTStatus code.
              SubCode   - The remainder of the error code.
            All subfields are returned as integer values.

    Notes:  This method provides access to archane information of
            academic or alchemic interest...but here it is anyway.
            [MS-ERREF; 2.3] provides more information about each of
            the returned subfields.

            The Facility codes are, of course, defined with respect
            to Windows subsystems.  See [MS-ERREF; 5] for a table of
            Windows Facility codes and their meanings.

    Doctest:
      >>> STATUS_FILE_NOT_AVAILABLE.subCodes
      (3, 0, 0, 0, 1127)
    """
    sev       = int( 0x03 & (self >> 30) )
    Customer  = 1 if( self & 0x20000000 ) else 0
    Nreserved = 1 if( self & 0x10000000 ) else 0
    facility  = int( 0x0FFF & (self >> 16) )
    subCode   = int( 0xFFFF & self )
    return( (sev, Customer, Nreserved, facility, subCode) )

  @property
  def severityName( self ):
    """Get the string representation of the severity of the NTStatus code.

    Output: One of the following strings:
              ["Success", "Info", "Warning", "Error"]
    Doctest:
      >>> print STATUS_STOPPED_ON_SYMLINK.severityName
      Warning
    """
    sev = (0x03 & (self >> 30))
    return( ["Success", "Info", "Warning", "Error"][sev] )


# Initialization ------------------------------------------------------------- #
#
# _init_dict  - A dictionary mapping NTStatus codes to the standard names
#               for those codes, plus descriptive error messages explaining
#               what each code means.  This dictionary is used to generate
#               a set of NTStatus objects.  The <_init_dict> dictionary
#               will be deleted once the set of NTStatus objects have been
#               instantiated.
#
#               So, anyway, if you need to permenently add a Windows NT
#               Status Code to the list, this is the easiest place to do it.
#               You only need to add one entry, and the module will take
#               care of the rest.  The format of an entry is:
#                 <ntstatus_code>: ("<constant_name>", "<error_message>"),
#
#               For testing purposes, it is best to set the Customer Bit in
#               the NTSTATUS code, to ensure that your code does not
#               conflict with any other code.
#

_init_dict = \
  {
  0x00000000: ("STATUS_SUCCESS", "The operation completed successfully."),
  0x00000103: ("STATUS_PENDING",
    "The operation that was requested is pending completion."),
  0x00000104: ("STATUS_REPARSE", "A reparse should be performed by the " \
    "Object Manager because the name of the file resulted in a symbolic link."),
  0x0000010B: ("STATUS_NOTIFY_CLEANUP",
    "Indicates that a notify change request has been completed due to " \
    "closing the handle that made the notify change request."),
  0x0000010C: ("STATUS_NOTIFY_ENUM_DIR",
    "Indicates that a notify change request is being completed and that the " \
    "information is not being returned in the caller's buffer. The caller " \
    "now needs to enumerate the files to find the changes."),
  0x80000005: ("STATUS_BUFFER_OVERFLOW", "Buffer Overflow; The data was too " \
    "large to fit into the specified buffer."),
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
    "Invalid Parameter; The specified information class is not a valid " \
    "information class for the specified object."),
  0xC0000004: ("STATUS_INFO_LENGTH_MISMATCH",
    "The specified information record length does not match the length that " \
    "is required for the specified information class."),
  0xC0000008: ("STATUS_INVALID_HANDLE", "An invalid HANDLE was specified."),
  0xC000000D: ("STATUS_INVALID_PARAMETER",
    "An invalid parameter was passed to a service or function."),
  0xC000000F: ("STATUS_NO_SUCH_FILE",
    "File Not Found; The file does not exist."),
  0xC0000010: ("STATUS_INVALID_DEVICE_REQUEST",
    "The specified request is not a valid operation for the target device."),
  0xC0000011: ("STATUS_END_OF_FILE", "The end-of-file marker has been " \
    "reached. There is no valid data in the file beyond this marker."),
  0xC0000016: ("STATUS_MORE_PROCESSING_REQUIRED",
    "Still Busy; The specified I/O request packet (IRP) cannot be disposed " \
    "of because the I/O operation is not complete."),
  0xC0000017: ("STATUS_NO_MEMORY",
    "Insufficient Quota; Not enough virtual memory or paging file quota is " \
    "available to complete the specified operation."),
  0xC0000022: ( "STATUS_ACCESS_DENIED",
    "A process has requested access to an object but has not been granted " \
    "those access rights." ),
  0xC0000023: ("STATUS_BUFFER_TOO_SMALL",
    "The buffer is too small to contain the entry.  No information has been " \
    "written to the buffer."),
  0xC0000033: ("STATUS_OBJECT_NAME_INVALID", "The object name is invalid."),
  0xC0000034: ("STATUS_OBJECT_NAME_NOT_FOUND", "The object name is not found."),
  0xC0000035: ("STATUS_OBJECT_NAME_COLLISION",
    "The object name already exists."),
  0xC000004F: ("STATUS_EAS_NOT_SUPPORTED", "An operation involving EAs " \
    "failed because the file system does not support EAs."),
  0xC0000051: ("STATUS_NONEXISTENT_EA_ENTRY",
    "An EA operation failed because the name or EA index is invalid."),
  0xC0000054: ("STATUS_FILE_LOCK_CONFLICT",
    "A requested read/write cannot be granted due to a conflicting file lock."),
  0xC0000055: ("STATUS_LOCK_NOT_GRANTED",
    "A requested file lock cannot be granted due to other existing locks."),
  0xC000005F: ("STATUS_NO_SUCH_LOGON_SESSION", "A specified logon session " \
    "does not exist. It may already have been terminated."),
  0xC0000064: ("STATUS_NO_SUCH_USER", "The specified account does not exist."),
  0xC000006A: ("STATUS_WRONG_PASSWORD",
    "When trying to update a password, this return status indicates that the " \
    "value provided as the current password is not correct."),
  0xC000006C: ("STATUS_PASSWORD_RESTRICTION",
    "When trying to update a password, this status indicates that some " \
    "password update rule has been violated.  For example, the password may " \
    "not meet length criteria."),
  0xC000006D: ("STATUS_LOGON_FAILURE",
    "The attempted logon is invalid.  This is either due to a bad username " \
    "or authentication information."),
  0xC000006F: ("STATUS_INVALID_LOGON_HOURS",
    "The user account has time restrictions and may not be logged onto at " \
    "this time."),
  0xC0000070: ("STATUS_INVALID_WORKSTATION",
    "The user account is restricted so that it may not be used to log on " \
    "from the source workstation."),
  0xC0000071: ("STATUS_PASSWORD_EXPIRED",
    "The user account password has expired."),
  0xC0000073: ("STATUS_NONE_MAPPED",
    "None of the information to be translated has been translated."),
  0xC000007C: ("STATUS_NO_TOKEN",
    "An attempt was made to reference a token that does not exist.  This is " \
    "typically done by referencing the token that is associated with a " \
    "thread when the thread is not impersonating a client."),
  0xC000007E: ("STATUS_RANGE_NOT_LOCKED",
    "The range specified in NtUnlockFile was not locked."),
  0xC000007F: ("STATUS_DISK_FULL",
    "An operation failed because the disk was full."),
  0xC000009A: ("STATUS_INSUFFICIENT_RESOURCES",
    "Insufficient system resources exist to complete the API."),
  0xC00000B5: ("STATUS_IO_TIMEOUT",
    "Device Timeout; The specified I/O operation was not completed " \
    "before the time-out period expired."),
  0xC00000B6: ("STATUS_FILE_FORCED_CLOSED",
    "The specified file has been closed by another process."),
  0xC00000BA: ("STATUS_FILE_IS_A_DIRECTORY",
    "The file that was specified as a target is a directory, and the caller " \
    "specified that it could be anything but a directory."),
  0xC00000BB: ("STATUS_NOT_SUPPORTED", "The request is not supported."),
  0xC00000C3: ("STATUS_INVALID_NETWORK_RESPONSE",
    "The network responded incorrectly."),
  0xC00000C9: ("STATUS_NETWORK_NAME_DELETED", "The network name was deleted."),
  0xC00000D0: ("STATUS_REQUEST_NOT_ACCEPTED", "No more connections can be " \
    "made to this remote computer at this time because the computer has " \
    "already accepted the maximum number of connections."),
  0xC00000DF: ("STATUS_NO_SUCH_DOMAIN", "The specified domain did not exist."),
  0xC00000E3: ("STATUS_INVALID_OPLOCK_PROTOCOL",
    "An error status returned when an invalid opportunistic lock (oplock) " \
    "acknowledgment is received by a file system."),
  0xC00000E5: ("STATUS_INTERNAL_ERROR", "An internal error occurred."),
  0xC0000102: ("STATUS_FILE_CORRUPT_ERROR",
    "Corrupt File; The file or directory is corrupt and unreadable."),
  0xC0000103: ("STATUS_NOT_A_DIRECTORY",
    "A requested opened file is not a directory."),
  0xC0000120: ("STATUS_CANCELLED", "The I/O request was canceled."),
  0xC0000128: ("STATUS_FILE_CLOSED", "An I/O request other than close and " \
    "several other special case operations was attempted using a file object " \
    "that had already been closed."),
  0xC000014B: ("STATUS_PIPE_BROKEN", "The pipe operation has failed because " \
    "the other end of the pipe has been closed."),
  0xC000015B: ("STATUS_LOGON_TYPE_NOT_GRANTED",
    "A user has requested a type of logon (for example, interactive or " \
    "network) that has not been granted. An administrator has control over " \
    "who may logon interactively and through the network."),
  0xC0000184: ("STATUS_INVALID_DEVICE_STATE",
    "The device is not in a valid state to perform this request."),
  0xC000018D: ("STATUS_TRUSTED_RELATIONSHIP_FAILURE",
    "The logon request failed because the trust relationship between this " \
    "workstation and the primary domain failed."),
  0xC0000190: ("STATUS_TRUST_FAILURE", "The network logon failed.  " \
    "This may be because the validation authority cannot be reached."),
  0xC0000192: ("STATUS_NETLOGON_NOT_STARTED",
    "An attempt was made to logon, but the NetLogon service was not started."),
  0xC000019C: ("STATUS_FS_DRIVER_REQUIRED", "A volume has been accessed for " \
    "which a file system driver is required that has not yet been loaded."),
  0xC0000203: ("STATUS_USER_SESSION_DELETED",
    "The remote user session has been deleted."),
  0xC000020C: ("STATUS_CONNECTION_DISCONNECTED",
    "The transport connection is now disconnected."),
  0xC0000224: ("STATUS_PASSWORD_MUST_CHANGE",
    "The user password must be changed before logging on the first time."),
  0xC000022A: ("STATUS_DUPLICATE_OBJECTID", "The attempt to insert the ID " \
    "in the index failed because the ID is already in the index."),
  0xC0000233: ("STATUS_DOMAIN_CONTROLLER_NOT_FOUND",
    "A domain controller for this domain was not found."),
  0xC000023C: ("STATUS_NETWORK_UNREACHABLE",
    "The remote network is not reachable by the transport."),
  0xC000026E: ("STATUS_VOLUME_DISMOUNTED",
    "An operation was attempted to a volume after it was dismounted."),
  0xC00002F9: ("STATUS_PKINIT_NAME_MISMATCH",
    "The client certificate does not contain a valid UPN, or does not " \
    "match the client name in the logon request."),
  0xC0000320: ("STATUS_PKINIT_FAILURE", "The Kerberos protocol encountered " \
    "an error while validating the KDC certificate during smart card logon."),
  0xC000035C: ("STATUS_NETWORK_SESSION_EXPIRED",
    "The client session has expired; The client must re-authenticate to " \
    "continue accessing the remote resources."),
  0xC0000380: ("STATUS_SMARTCARD_WRONG_PIN",
    "An incorrect PIN was presented to the smart card."),
  0xC0000381: ("STATUS_SMARTCARD_CARD_BLOCKED", "The smart card is blocked."),
  0xC0000383: ("STATUS_SMARTCARD_NO_CARD", "No smart card is available."),
  0xC0000388: ("STATUS_DOWNGRADE_DETECTED",
    "The system detected a possible attempt to compromise security.  " \
    "Ensure that you can contact the server that authenticated you."),
  0xC000038C: ("STATUS_PKINIT_CLIENT_FAILURE",
    "The smart card certificate used for authentication was not trusted.  " \
    "Contact your system administrator."),
  0xC000038F: ("STATUS_SMARTCARD_SILENT_CONTEXT",
    "The smart card provider could not perform the action because the " \
    "context was acquired as silent."),
  0xC0000466: ("STATUS_SERVER_UNAVAILABLE",
    "The file server is temporarily unavailable."),
  0xC0000467: ("STATUS_FILE_NOT_AVAILABLE",
    "The file is temporarily unavailable."),
  0xC000A100: ("STATUS_HASH_NOT_SUPPORTED", "Hash generation for the " \
    "specified version and hash type is not enabled on server."),
  0xC000A101: ("STATUS_HASH_NOT_PRESENT", "The hash requests is not present " \
    "or not up to date with the current file contents.")
  }

# Use <_init_dict> to generate the set of NTStatus objects,
# then discard <_init_dict>, as it is no longer needed.
for key in _init_dict:
  name, mesg = _init_dict[ key ]
  exec( "%s = NTStatus( %d, \"%s\", \"%s\" )" % ( name, key, name, mesg ) )
del key, name, mesg, _init_dict

# ============================================================================ #
# I don't know when you're done with the butter in line for a karaoke party,
# but the dogs smell like a good meeting with the picture of three months
# worth of unusual ice.
# ============================================================================ #
