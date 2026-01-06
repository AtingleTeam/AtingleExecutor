#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <errno.h>

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
    struct user_regs_struct old, regs;
    unsigned long target_dlopen;
    int status;

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        perror("ERR_ATTACH");
        exit(EXIT_FAILURE);
    }
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

void patch(pid_t pid) {
    unsigned char pattern[] = "Java_com_roblox_protocols_localstor";
    size_t p_len = sizeof(pattern) - 1;
    unsigned long start = 0x700000000000UL, end = 0x800000000000UL, c_size = 0x100000;
    unsigned char *buf = malloc(c_size);
    if (!buf) return;

    for (unsigned long addr = start; addr < end; addr += c_size) {
        struct iovec local = {buf, c_size}, remote = {(void*)addr, c_size};
        if (process_vm_readv(pid, &local, 1, &remote, 1, 0) > 0) {
            for (size_t i = 0; i <= c_size - p_len; i++) {
                if (memcmp(buf + i, pattern, p_len) == 0) {
                    unsigned long base = (addr + i) - 0x1000d;
                    unsigned char patch[] = {0x90, 0x90};
                    struct iovec pl = {patch, 2}, pr = {(void*)(base + 0x0), 2};
                    process_vm_writev(pid, &pl, 1, &pr, 1, 0);
                    free(buf);
                    return;
                }
            }
        }
    }
    free(buf);
}

int main(int argc, char **argv) {
    pid_t pid = find_pid("sober");
    if (pid == -1) return EXIT_FAILURE;
    inject(pid, (argc > 1) ? argv[1] : "./atingle.so");
    patch(pid);
    return EXIT_SUCCESS;
}
