/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 Kdufse. All Rights Reserved.
 * Kernel Version Modification Module
 * Single-file version for APatch KPM
 */

#include <hook.h>
#include <kpmodule.h>
#include <ksyms.h>
#include <linux.h>
#include <uapi.h>

#define KPM_NAME "kernel_version_mod"
#define KPM_VERSION "1.0.0"
#define KPM_AUTHOR "Kdufse"
#define KPM_DESCRIPTION "Modify kernel version string"

#define VERSION_MAX_LEN 256
#define MAX_SYM_COUNT 20

// 全局变量
static char custom_version[VERSION_MAX_LEN] = {0};
static char original_version[VERSION_MAX_LEN] = {0};
static char *version_ptr = NULL;
static bool is_modified = false;

// 日志函数
static void log_info(const char *fmt, ...)
{
    char buf[256];
    va_list args;
    
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    
    printk(KPM_NAME ": %s\n", buf);
}

// 查找版本字符串
static int find_version_string(void)
{
    // 常见的版本字符串符号
    const char *sym_names[] = {
        "linux_banner",
        "linux_proc_banner", 
        "linux_version_string",
        "init_uts_ns",
        NULL
    };
    
    for (int i = 0; sym_names[i] != NULL; i++) {
        void *addr = kallsyms_lookup_name(sym_names[i]);
        if (addr) {
            char *str = (char *)addr;
            // 检查是否看起来像版本字符串
            if (str && str[0] && strstr(str, "Linux")) {
                version_ptr = str;
                strlcpy(original_version, str, sizeof(original_version));
                log_info("Found version at %s: %pK", sym_names[i], addr);
                log_info("Original: %s", original_version);
                return 0;
            }
        }
    }
    
    log_info("Warning: Could not find version string via symbols");
    return -1;
}

// 修改版本
static int modify_version(const char *new_ver)
{
    if (!version_ptr) {
        log_info("No version pointer available");
        return -1;
    }
    
    if (!new_ver || strlen(new_ver) == 0) {
        log_info("Invalid version string");
        return -2;
    }
    
    size_t new_len = strlen(new_ver);
    size_t old_len = strlen(version_ptr);
    
    if (new_len >= old_len) {
        log_info("New version too long, may cause overflow");
    }
    
    // 尝试修改
    for (size_t i = 0; i < new_len && i < old_len; i++) {
        version_ptr[i] = new_ver[i];
    }
    
    // 如果新版本较短，需要截断
    if (new_len < old_len) {
        version_ptr[new_len] = '\0';
    }
    
    strlcpy(custom_version, new_ver, sizeof(custom_version));
    is_modified = true;
    
    log_info("Version modified to: %s", version_ptr);
    return 0;
}

// 恢复版本
static void restore_version(void)
{
    if (version_ptr && original_version[0]) {
        strlcpy(version_ptr, original_version, strlen(version_ptr) + 1);
        is_modified = false;
        custom_version[0] = '\0';
        log_info("Version restored to: %s", version_ptr);
    }
}

// 模块初始化
static long mod_init(const char *args, const char *event, void *__user reserved)
{
    log_info("Initializing " KPM_NAME " v" KPM_VERSION);
    
    // 查找版本字符串
    find_version_string();
    
    // 如果有启动参数，设置版本
    if (args && strlen(args) > 0) {
        log_info("Setting initial version: %s", args);
        modify_version(args);
    }
    
    return 0;
}

// 模块退出
static long mod_exit(void *__user reserved)
{
    log_info("Exiting " KPM_NAME);
    
    // 恢复原始版本
    restore_version();
    
    return 0;
}

// 控制函数
static long mod_control0(const char *args, char *__user out_msg, int outlen)
{
    char msg[512];
    
    if (!args || strlen(args) == 0) {
        snprintf(msg, sizeof(msg),
            "=== " KPM_NAME " ===\n"
            "Author: " KPM_AUTHOR "\n"
            "Version: " KPM_VERSION "\n\n"
            "Commands:\n"
            "  get           - Show current version\n"
            "  set <ver>     - Set new version\n"
            "  reset         - Restore original\n"
            "  status        - Show status\n");
    } else if (strcmp(args, "get") == 0) {
        snprintf(msg, sizeof(msg),
            "Current: %s\n"
            "Original: %s\n"
            "Modified: %s",
            version_ptr ? version_ptr : "Unknown",
            original_version,
            is_modified ? "Yes" : "No");
    } else if (strncmp(args, "set ", 4) == 0) {
        const char *new_ver = args + 4;
        int ret = modify_version(new_ver);
        if (ret == 0) {
            snprintf(msg, sizeof(msg), "Success: %s", version_ptr ? version_ptr : "Unknown");
        } else {
            snprintf(msg, sizeof(msg), "Error: %d", ret);
        }
    } else if (strcmp(args, "reset") == 0) {
        restore_version();
        snprintf(msg, sizeof(msg), "Reset to: %s", version_ptr ? version_ptr : "Unknown");
    } else if (strcmp(args, "status") == 0) {
        snprintf(msg, sizeof(msg),
            "Status: %s\n"
            "Pointer: %pK\n"
            "Custom: %s\n"
            "Original: %s",
            is_modified ? "MODIFIED" : "ORIGINAL",
            version_ptr,
            custom_version,
            original_version);
    } else {
        snprintf(msg, sizeof(msg), "Unknown command: %s", args);
    }
    
    if (out_msg && outlen > 0) {
        size_t len = strlen(msg);
        if (len >= outlen) len = outlen - 1;
        compat_copy_to_user(out_msg, msg, len);
        compat_copy_to_user(out_msg + len, "\0", 1);
    }
    
    return 0;
}

// KPM宏
KPM_NAME(KPM_NAME);
KPM_VERSION(KPM_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR(KPM_AUTHOR);
KPM_DESCRIPTION(KPM_DESCRIPTION);

KPM_INIT(mod_init);
KPM_EXIT(mod_exit);
KPM_CTL0(mod_control0);