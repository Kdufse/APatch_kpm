/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 Kdufse. All Rights Reserved.
 * Kernel Version Modification Module
 */

#ifndef __KERNEL_VERSION_MOD_H
#define __KERNEL_VERSION_MOD_H

#include <hook.h>
#include <kpmodule.h>
#include <ksyms.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#define KERNEL_VERSION_MAX_LEN 128
#define KERNEL_VERSION_BUF_SIZE 256

// 内核版本字符串结构
struct version_info {
    char *version_str;          // 指向内核版本字符串的指针
    char *original_version;     // 保存原始版本字符串的备份
    size_t max_len;             // 缓冲区最大长度
    bool is_hooked;             // 是否已经hook
    bool is_modified;           // 是否已经修改
};

// 日志宏
#define logkm(fmt, ...) printk("kernel_version_mod: " fmt, ##__VA_ARGS__)
#define logk_info(fmt, ...) pr_info("kernel_version_mod: " fmt, ##__VA_ARGS__)
#define logk_err(fmt, ...) pr_err("kernel_version_mod: " fmt, ##__VA_ARGS__)

// 查找内核函数宏
#define lookup_name(func)                                  \
    func = 0;                                              \
    func = (typeof(func))kallsyms_lookup_name(#func);      \
    if (func) {                                            \
        logk_info("found %s at %pK\n", #func, func);       \
    } else {                                               \
        logk_err("failed to find %s\n", #func);            \
    }

// Hook相关宏
#define hook_func(func, argc, before, after, udata)        \
    if (!func) {                                           \
        return -ENOENT;                                    \
    }                                                      \
    hook_err_t hook_err = hook_wrap(func, argc, before, after, udata); \
    if (hook_err) {                                        \
        logk_err("hook %s error: %d\n", #func, hook_err);  \
        return -EINVAL;                                    \
    } else {                                               \
        logk_info("hook %s success\n", #func);             \
    }

#define unhook_func(func)                                  \
    if (func && !is_bad_address(func)) {                   \
        unhook(func);                                      \
        logk_info("unhook %s success\n", #func);           \
    }

// 内核版本相关函数声明
extern char *linux_banner;
extern char linux_proc_banner[];
extern int kernel_version;
extern unsigned int kernel_version_code;

// 模块全局变量
extern struct version_info ver_info;
extern char custom_version[KERNEL_VERSION_MAX_LEN];
extern bool version_modified;

// 函数声明
int init_version_strings(void);
void cleanup_version_strings(void);
int hook_version_functions(void);
void unhook_version_functions(void);
int set_kernel_version(const char *new_version);
void restore_original_version(void);

#endif /* __KERNEL_VERSION_MOD_H */