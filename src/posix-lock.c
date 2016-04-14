#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include "posix-lock.h"
#include "logger.h"

/* 
  Lock a file or die, to provide assurance that a 'scan manager' won't 
  melt your LAN

  Here, 'scan manager' means some automated script or application that 
  invokes masscan infinitely in a serial fashion, rather than using the
  masscan infinite flag. 

  This feature is designed to prevent a buggy or broken scan manager from 
  invoking the same masscan instance more than once. This can happen if it 
  fails (i.e. crashes) and doesn't clean up the child masscan process, and
  doesn't go through all the trouble of checking the process list to try
  and find the process. Relying on a PID file isn't always reliable when
  things crash.

  Yes, fix the scan manager so that it doesn't crash, or makes sure its
  children are cleaned up somehow, but for networks that can't handle certain 
  packet rates, this is a failsafe to prevent the possibility of affecting 
  production networks/systems that can't handle multiple scans at once. 
  This is really only a concern on a LAN, I think.

  Because the purpose of this feature is to prevent mistakes, O_CREAT is not 
  used. If the lock file doesn't already exist, it's possible the scan manager
  is broken and trying to run wild. It is up to the scan manager to manage the
  creation and deletion of the lock file and not the responsibility of masscan.

  Exit if the lock file couldn't be opened
  Exit if the fctnl(F_SETLK) failed

  Return 0 if the lock was successful, application should continue

  There is no unlock, we just let the lock die at process termination for 
  simplicity. Note this short-circuits command line parsing.
*/

int
acquire_posix_lock (const char *filename)
{
  struct flock fl = { F_WRLCK, SEEK_SET, 0, 0, 0 };
  int fd;
  int result = 0;

  fl.l_pid = getpid ();

  if ((fd = open (filename, O_RDWR)) == -1)
    {
      LOG(0,"FAIL: lock file can't be opened with errno message %s\n",strerror(errno));
      exit(1);
    }

  if ((result = fcntl (fd, F_SETLK, &fl)) == -1)
    {
      if (errno == EAGAIN)
	     {
	       LOG (0, "FAIL: lock file %s is already locked by another process\n",filename);
	     }
      else
	     { /* I don't know why this would ever happen unless some other application is messing with our lock */
	       LOG (0, "FAIL: failed to acquire lock on file %s with errno message %s\n", filename,
	       strerror (errno));
	     }
      exit(1);
    }

  return result;
}
