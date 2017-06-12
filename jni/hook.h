#include <stdio.h>
#include <stdlib.h>
#include <asm/user.h>
#include <asm/ptrace.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <android/log.h>

#define LOG_TAG "MY_HOOK"
#define LOGD(fmt, args...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, fmt, ##args)


struct hook_t {
    unsigned int jump[7];
    unsigned int store[9];
    unsigned char jumpt[22];
    unsigned char storet[38];
    unsigned int orig;
    unsigned int patch;
    unsigned char thumb;
    unsigned int module_base;
    void *data;
};

void get_module_range(pid_t pid, const char* module_name, long* start_addr, long* end_addr);

int hook_by_addr(struct hook_t *h, char* module_name, unsigned int addr, void *hook_thumb, void*hook_arm);
int hook_by_name(struct hook_t *h, char* module_name, unsigned char* func_name, void *hook_thumb, void *hook_arm);

static int _hook(struct hook_t *h, unsigned int addr, void *hook_thumb, void *hook_arm);

void inline hook_cacheflush(unsigned int begin, unsigned int end);

void hook_unset_jump(struct hook_t *h);
void hook_set_jump(struct hook_t *h);

