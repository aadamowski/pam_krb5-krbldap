
#include <unistd.h>

#ifndef LOCK_SH
#define LOCK_SH 1
#endif
#ifndef LOCK_EX
#define LOCK_EX 2
#endif
#ifndef LOCK_NB
#define LOCK_NB 4
#endif
#ifndef LOCK_UN
#define LOCK_UN 8
#endif

#include <errno.h>

   int flock (int fd, int operation)
   {
      int i;

      switch (operation) {

      /* LOCK_SH - get a shared lock */
           case LOCK_SH:
      /* LOCK_EX - get an exclusive lock */
           case LOCK_EX:
              i = lockf (fd, F_LOCK, 0);
              break;

      /* LOCK_SH|LOCK_NB - get a non-blocking shared lock */
           case LOCK_SH|LOCK_NB:
      /* LOCK_EX|LOCK_NB - get a non-blocking exclusive lock */
           case LOCK_EX|LOCK_NB:
              i = lockf (fd, F_TLOCK, 0);
              if (i == -1)
              if ((errno == EAGAIN) || (errno == EACCES))
                      errno = EWOULDBLOCK;
           break;
      /* LOCK_UN - unlock */
           case LOCK_UN:
              i = lockf (fd, F_ULOCK, 0);
              break;

      /* Default - can't decipher operation */
           default:
              i = -1;
              errno = EINVAL;
              break;
      }
      return (i); 
   }
