/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 Kdufse. All Rights Reserved.
 * Kernel Version Modification Module
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/version.h>
#include "kernel_version.h"

KPM_NAME("kernel_version_mod");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Kdufse");
KPM_DESCRIPTION("Kernel Version Modification Module");

// 全局变量
struct version_info ver_info;
char custom_version[KERNEL_VERSION_MAX_LEN] = {0};
bool version_modified = false;

// 内核版本符号
char *linux_banner = NULL;
char linux_proc_banner[] = "%s version %s (%s)\n";
int kernel_version = 0;
unsigned int kernel_version_code = 0;

// Hook函数指针
static int (*orig_utsname_release)(struct kobject *kobj, struct kobj_uevent_env *env);
static void *(*orig_utsname_show)(struct kobject *kobj, struct kobj_attribute *attr, char *buf);

// 需要修改的版本字符串列表
static const char *version_strings[] = {
    "linux_banner",
    "linux_proc_banner",
    "init_uts_ns",
    NULL
};

// 查找版本字符串函数
static int find_version_strings(void)
{
    // 查找 linux_banner
    lookup_name(linux_banner);
    
    if (!linux_banner) {
        // 尝试其他可能的符号
        linux_banner = (char *)kallsyms_lookup_name("linux_banner_ptr");
        if (!linux_banner) {
            linux_banner = (char *)kallsyms_lookup_name("linux_version_string");
        }
    }
    
    if (!linux_banner) {
        logk_err("Failed to find linux_banner\n");
        return -ENOENT;
    }
    
    logk_info("Found linux_banner at %pK: %s\n", linux_banner, linux_banner);
    
    // 分配内存保存原始版本
    size_t len = strlen(linux_banner) + 1;
    ver_info.original_version = kmalloc(len, GFP_KERNEL);
    if (!ver_info.original_version) {
        logk_err("Failed to allocate memory for original version\n");
        return -ENOMEM;
    }
    
    strncpy(ver_info.original_version, linux_banner, len);
    ver_info.version_str = linux_banner;
    ver_info.max_len = len;
    ver_info.is_hooked = false;
    ver_info.is_modified = false;
    
    logk_info("Original kernel version: %s\n", ver_info.original_version);
    
    return 0;
}

// Hook处理函数
static int utsname_release_before(hook_fargs2_t *args, void *udata)
{
    // 如果已经修改了版本，返回自定义版本
    if (version_modified && strlen(custom_version) > 0) {
        // 这里可以修改uts相关的数据结构
        logk_info("utsname_release called, version modified\n");
    }
    return 0;
}

static void *utsname_show_before(hook_fargs3_t *args, void *udata)
{
    // 如果已经修改了版本，显示自定义版本
    if (version_modified && strlen(custom_version) > 0) {
        char *buf = (char *)args->arg2;
        struct kobject *kobj = (struct kobject *)args->arg0;
        
        if (kobj && buf) {
            // 修改显示的版本字符串
            int len = snprintf(buf, PAGE_SIZE, "%s", custom_version);
            args->ret = (void *)(long)len;
            args->skip_origin = true;
            logk_info("Showing custom version: %s\n", custom_version);
        }
    }
    return 0;
}

// 初始化版本字符串
int init_version_strings(void)
{
    int ret;
    
    // 查找内核版本字符串
    ret = find_version_strings();
    if (ret < 0) {
        logk_err("Failed to find version strings\n");
        return ret;
    }
    
    // 查找需要hook的函数
    orig_utsname_release = (void *)kallsyms_lookup_name("utsname_release");
    orig_utsname_show = (void *)kallsyms_lookup_name("utsname_show");
    
    if (!orig_utsname_release && !orig_utsname_show) {
        logk_info("utsname functions not found, using direct modification\n");
    } else {
        logk_info("Found utsname functions\n");
    }
    
    return 0;
}

// 清理版本字符串
void cleanup_version_strings(void)
{
    if (ver_info.original_version) {
        kfree(ver_info.original_version);
        ver_info.original_version = NULL;
    }
    
    ver_info.version_str = NULL;
    ver_info.max_len = 0;
    ver_info.is_hooked = false;
    ver_info.is_modified = false;
}

// Hook版本相关函数
int hook_version_functions(void)
{
    int ret = 0;
    
    if (orig_utsname_release) {
        hook_func(orig_utsname_release, 2, utsname_release_before, NULL, NULL);
    }
    
    if (orig_utsname_show) {
        hook_func(orig_utsname_show, 3, utsname_show_before, NULL, NULL);
    }
    
    ver_info.is_hooked = (orig_utsname_release != NULL || orig_utsname_show != NULL);
    
    return ret;
}

// 取消Hook
void unhook_version_functions(void)
{
    if (ver_info.is_hooked) {
        unhook_func(orig_utsname_release);
        unhook_func(orig_utsname_show);
    }
    
    ver_info.is_hooked = false;
}

// 设置内核版本
int set_kernel_version(const char *new_version)
{
    if (!new_version || strlen(new_version) == 0) {
        logk_err("Invalid version string\n");
        return -EINVAL;
    }
    
    if (strlen(new_version) >= KERNEL_VERSION_MAX_LEN) {
        logk_err("Version string too long\n");
        return -EINVAL;
    }
    
    // 保存自定义版本
    strncpy(custom_version, new_version, KERNEL_VERSION_MAX_LEN - 1);
    custom_version[KERNEL_VERSION_MAX_LEN - 1] = '\0';
    
    // 直接修改内核版本字符串
    if (ver_info.version_str && ver_info.max_len > 0) {
        size_t len = strlen(new_version);
        
        if (len < ver_info.max_len) {
            // 备份当前版本（如果是第一次修改）
            if (!ver_info.is_modified) {
                // 已经备份了原始版本，无需再次备份
                ver_info.is_modified = true;
            }
            
            // 修改版本字符串
            memset(ver_info.version_str, 0, ver_info.max_len);
            strncpy(ver_info.version_str, new_version, ver_info.max_len - 1);
            version_modified = true;
            
            logk_info("Kernel version changed to: %s\n", ver_info.version_str);
            
            // 尝试修改其他相关的版本字符串
            const char **vs = version_strings;
            while (*vs) {
                char *ptr = (char *)kallsyms_lookup_name(*vs);
                if (ptr) {
                    // 尝试修改，但不保证成功
                    size_t ptr_len = strlen(ptr);
                    if (strstr(ptr, ver_info.original_version)) {
                        // 这是一个包含版本字符串的指针
                        logk_info("Found version string at %s\n", *vs);
                    }
                }
                vs++;
            }
            
            return 0;
        } else {
            logk_err("New version too long for buffer\n");
            return -ENOSPC;
        }
    } else {
        logk_err("No version string found to modify\n");
        return -ENOENT;
    }
}

// 恢复原始版本
void restore_original_version(void)
{
    if (ver_info.version_str && ver_info.original_version && ver_info.max_len > 0) {
        if (ver_info.is_modified) {
            memset(ver_info.version_str, 0, ver_info.max_len);
            strncpy(ver_info.version_str, ver_info.original_version, ver_info.max_len - 1);
            version_modified = false;
            ver_info.is_modified = false;
            memset(custom_version, 0, sizeof(custom_version));
            
            logk_info("Restored original kernel version: %s\n", ver_info.version_str);
        }
    }
}

// 模块初始化函数
static long kernel_version_init(const char *args, const char *event, void *__user reserved)
{
    int ret;
    
    logk_info("Initializing Kernel Version Modification Module\n");
    
    // 初始化版本字符串
    ret = init_version_strings();
    if (ret < 0) {
        logk_err("Failed to initialize version strings\n");
        return ret;
    }
    
    // Hook相关函数
    ret = hook_version_functions();
    if (ret < 0) {
        logk_err("Failed to hook version functions\n");
        cleanup_version_strings();
        return ret;
    }
    
    // 如果启动时有参数，设置版本
    if (args && strlen(args) > 0) {
        ret = set_kernel_version(args);
        if (ret < 0) {
            logk_info("Failed to set initial version, continuing anyway\n");
        }
    }
    
    logk_info("Module initialized successfully\n");
    return 0;
}

// 模块退出函数
static long kernel_version_exit(void *__user reserved)
{
    logk_info("Exiting Kernel Version Modification Module\n");
    
    // 恢复原始版本
    restore_original_version();
    
    // 取消Hook
    unhook_version_functions();
    
    // 清理资源
    cleanup_version_strings();
    
    logk_info("Module exited successfully\n");
    return 0;
}

KPM_INIT(kernel_version_init);
KPM_EXIT(kernel_version_exit);