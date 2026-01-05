#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <dlfcn.h>
#include <fcntl.h>

pid_t find_pid(const char* name) {
    DIR* d = opendir("/proc");
    if (!d) return -1;
    struct dirent* e;
    while ((e = readdir(d))) {
        if (e->d_type != DT_DIR) continue;
        pid_t pid = atoi(e->d_name);
        if (pid <= 0) continue;
        char path[PATH_MAX], exe[PATH_MAX];
        snprintf(path, sizeof(path), "/proc/%d/exe", pid);
        ssize_t len = readlink(path, exe, sizeof(exe) - 1);
        if (len != -1) {
            exe[len] = '\0';
            if (strstr(exe, name)) {
                closedir(d);
                return pid;
            }
        }
    }
    closedir(d);
    return -1;
}

int is_ptraced(pid_t pid) {
    char path[64], line[256];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 1; 
    read(fd, line, sizeof(line));
    close(fd);
    char *tracer = strstr(line, "TracerPid:");
    if (tracer && atoi(tracer + 10) != 0) return 1;
    return 0;
}

unsigned long get_module_base(pid_t pid, const char *name) {
    char path[64], line[512];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    unsigned long addr = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, name)) {
            addr = strtoul(line, NULL, 16);
            break;
        }
    }
    fclose(f);
    return addr;
}

unsigned long get_offset(const char *lib, const char *sym) {
    void *h = dlopen(lib, RTLD_LAZY);
    if (!h) return 0;
    unsigned long o = (unsigned long)dlsym(h, sym) - get_module_base(getpid(), lib);
    dlclose(h);
    return o;
}

void inject(pid_t pid, const char *lib_path) {
    if (is_ptraced(pid)) exit(EXIT_FAILURE);

    struct user_regs_struct old, regs;
    unsigned long target_dlopen;
    int status;

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) exit(EXIT_FAILURE);
    waitpid(pid, &status, 0);
    ptrace(PTRACE_GETREGS, pid, NULL, &old);
    memcpy(&regs, &old, sizeof(regs));

    unsigned long libc = get_module_base(pid, "libc.so.6");
    unsigned long libdl = get_module_base(pid, "libdl.so.2");
    
    target_dlopen = libdl ? (libdl + get_offset("libdl.so.2", "dlopen")) : 
                            (libc + get_offset("libc.so.6", "dlopen"));

    if (!target_dlopen) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        exit(EXIT_FAILURE);
    }

    regs.rsp -= 0x100;
    size_t len = strlen(lib_path) + 1;
    for (size_t i = 0; i < len; i += sizeof(long)) {
        long word = 0;
        memcpy(&word, lib_path + i, (len - i < sizeof(long)) ? len - i : sizeof(long));
        ptrace(PTRACE_POKEDATA, pid, regs.rsp + i, word);
    }

    regs.rdi = regs.rsp;
    regs.rsi = RTLD_NOW;
    regs.rip = target_dlopen;
    regs.rsp -= 8;
    
    ptrace(PTRACE_POKEDATA, pid, regs.rsp, 0);

    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    waitpid(pid, &status, 0);

    ptrace(PTRACE_SETREGS, pid, NULL, &old);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
}

int main(int argc, char **argv) {
    const char *target_proc = "sober";
    const char *lib = (argc > 1) ? argv[1] : "./atingle.so";

    pid_t pid = find_pid(target_proc);
    if (pid == -1) exit(EXIT_FAILURE);

    inject(pid, lib);
    return EXIT_SUCCESS;
}
