#include <config.h>
#include "ucarp.h"
#include "spawn.h"
#ifdef HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif
#include "log.h"

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

int spawn_handler(const int dev_desc_fd, const char * const script)
{
    pid_t pid;
    const char *addr_arg;
    const char *af_param;

    if (script == NULL || *script == 0) {
        return 0;
    }
    
    /* Choose the appropriate address argument and family based on address family */
#ifdef INET6
    if (address_family == AF_INET6) {
        addr_arg = vaddr6_arg;
        af_param = "6";
    } else {
        addr_arg = vaddr_arg;
        af_param = "4";
    }
#else
    addr_arg = vaddr_arg;
    af_param = "4";
#endif

    pid = fork();
    if (pid == (pid_t) 0) {
        (void) close(dev_desc_fd);
        execl(script, script, interface, addr_arg, af_param, xparam, (char *) NULL);
        logfile(LOG_ERR, _("Unable to exec %s %s %s %s%s%s: %s"),
                script, interface, addr_arg, af_param,
                (xparam ? " " : ""), (xparam ? xparam : ""),
                strerror(errno));
        _exit(EXIT_FAILURE);
    } else if (pid != (pid_t) -1) {
        logfile(LOG_WARNING, _("Spawning [%s %s %s %s%s%s]"),
                script, interface, addr_arg, af_param,
                (xparam ? " " : ""), (xparam ? xparam : ""));
#ifdef HAVE_WAITPID
        {
            while (waitpid(pid, NULL, 0) == (pid_t) -1 && errno == EINTR);
        }
#else
        {
            pid_t foundpid;

            do {
                foundpid = wait3(NULL, 0, NULL);
                if (foundpid == (pid_t) -1 && errno == EINTR) {
                    continue;
                }
            } while (foundpid != (pid_t) -1 && foundpid != pid);
        }
#endif
    } else {
        logfile(LOG_ERR, _("Unable to spawn the script: %s"),
                strerror(errno));
        return -1;
    }
    return 0;
}
