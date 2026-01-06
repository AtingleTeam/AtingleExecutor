#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>

typedef void (*GameSendChatFunc)(const char* msg, int type);

#define GAME_SEND_CHAT_MESSAGE_FUNCTION_OFFSET 0x0

unsigned long get_lib_base(const char* name) {
    char line[512];
    FILE* f = fopen("/proc/self/maps", "r");
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

void print_str(const char* message) {
    unsigned long base = get_lib_base("libroblox.so");
    if (base == 0) return;

    unsigned long chat_func_addr = base + GAME_SEND_CHAT_MESSAGE_FUNCTION_OFFSET;
    GameSendChatFunc send_chat_func = (GameSendChatFunc)chat_func_addr;

    if (send_chat_func) {
        send_chat_func(message, 0);
    }
}

__attribute__((constructor))
void init_lib() {
    print_str("Atingle loaded!");
}
