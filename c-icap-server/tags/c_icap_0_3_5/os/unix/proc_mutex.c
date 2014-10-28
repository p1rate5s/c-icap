/*
 *  Copyright (C) 2004-2008 Christos Tsantilas
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA.
 */

#include "common.h"
#include "c-icap.h"
#include <errno.h>
#include "debug.h"
#include "proc_mutex.h"




#if defined(USE_SYSV_IPC_MUTEX)

#define  SEMKEY 888888L         /*A key but what key;The IPC_PRIVATE must used instead ..... */
#define  PERMS 0600
/*static int current_semkey=SEMKEY; */

static struct sembuf op_lock[2] = {
     {0, 0, 0},                 /*wait for sem to become 0 */
     {0, 1, SEM_UNDO}           /*then increment sem by 1  */
};

static struct sembuf op_unlock[1] = {
     {0, -1, (IPC_NOWAIT | SEM_UNDO)}   /*decrement sem by 1   */
};

#ifndef HAVE_UNION_SEMUN
union semun {
     int val;                   /* Value for SETVAL */
     struct semid_ds *buf;      /* Buffer for IPC_STAT, IPC_SET */
     unsigned short *array;     /* Array for GETALL, SETALL */
     struct seminfo *__buf;     /* Buffer for IPC_INFO
                                   (Linux specific) */
};
#endif

int ci_proc_mutex_init(ci_proc_mutex_t * mutex)
{
     union semun arg;
     if ((*mutex = semget(IPC_PRIVATE, 1, IPC_CREAT | PERMS)) < 0) {
          ci_debug_printf(1, "Error creating mutex\n");
          return 0;
     }
     arg.val = 0;
     if ((semctl(*mutex, 0, SETVAL, arg)) < 0) {
          ci_debug_printf(1, "Error setting default value for mutex, errno:%d\n",
                          errno);
          return 0;
     }
     return 1;
}

int ci_proc_mutex_destroy(ci_proc_mutex_t * mutex)
{
     if (semctl(*mutex, 0, IPC_RMID, 0) < 0) {
          ci_debug_printf(1, "Error removing mutex\n");
          return 0;
     }
     return 1;
}

int ci_proc_mutex_lock(ci_proc_mutex_t * mutex)
{
     if (semop(*mutex, (struct sembuf *) &op_lock, 2) < 0) {
          return 0;
     }
     return 1;
}

int ci_proc_mutex_unlock(ci_proc_mutex_t * mutex)
{
     if (semop(*mutex, (struct sembuf *) &op_unlock, 1) < 0) {
          return 0;
     }
     return 1;
}

#elif defined (USE_POSIX_SEMAPHORES)
#include <fcntl.h>           /* For O_* constants */
#include <sys/stat.h> 


int ci_proc_mutex_init(ci_proc_mutex_t * mutex)
{
    int i = 0;
    mutex->sem = SEM_FAILED;
    for(i = 0; i < 1024; ++i) {
        errno = 0;
        snprintf(mutex->name, CI_PROC_MUTEX_NAME_SIZE, "%s%d", CI_PROC_MUTEX_NAME_TMPL, i);
        if ((mutex->sem = sem_open(mutex->name, O_CREAT|O_EXCL, S_IREAD|S_IWRITE|S_IRGRP, 1)) != SEM_FAILED) {
            return 1;
        }
        if (errno != EEXIST)
            break;
    }
    if (errno == EEXIST) {
        ci_debug_printf(1, "Error allocation posix proc mutex, to many c-icap mutexes are open!\n");
    } else {
        ci_debug_printf(1, "Error allocation posix proc mutex, errno: %d\n", errno);
    }
    return 0;
}

int ci_proc_mutex_destroy(ci_proc_mutex_t * mutex)
{
     if (sem_unlink(mutex->name) < 0) {
          return 0;
     }
     return 1;
}

int ci_proc_mutex_lock(ci_proc_mutex_t * mutex)
{
     if (sem_wait(mutex->sem)) {
         ci_debug_printf(1, "Failed to get lock of posix mutex\n");
         return 0;
     }
     return 1;
}

int ci_proc_mutex_unlock(ci_proc_mutex_t * mutex)
{
     if (sem_post(mutex->sem)) {
         ci_debug_printf(1, "Failed to unlock of posix mutex\n");
         return 0;
     }
     return 1;
}

#elif defined (USE_POSIX_FILE_LOCK)

/*NOTE: mkstemp does not exists for some platforms */

int ci_proc_mutex_init(ci_proc_mutex_t * mutex)
{
     strcpy(mutex->filename, FILE_LOCK_TEMPLATE);
     if ((mutex->fd = mkstemp(mutex->filename)) < 0)
          return 0;

     return 1;
}

int ci_proc_mutex_destroy(ci_proc_mutex_t * mutex)
{
     close(mutex->fd);
     if (unlink(mutex->filename) != 0)
          return 0;
     return 1;
}

int ci_proc_mutex_lock(ci_proc_mutex_t * mutex)
{
     struct flock fl;
     fl.l_type = F_WRLCK;
     fl.l_whence = SEEK_SET;
     fl.l_start = 0;
     fl.l_len = 0;

     if (fcntl(mutex->fd, F_SETLKW, &fl) < 0)
          return 0;
     return 1;
}

int ci_proc_mutex_unlock(ci_proc_mutex_t * mutex)
{
     struct flock fl;
     fl.l_type = F_UNLCK;
     fl.l_whence = SEEK_SET;
     fl.l_start = 0;
     fl.l_len = 0;
     if (fcntl(mutex->fd, F_SETLK, &fl) < 0)
          return 0;
     return 1;
}


#endif
