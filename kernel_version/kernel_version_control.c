/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 Kdufse. All Rights Reserved.
 * Kernel Version Control Interface
 */

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <kputils.h>
#include "kernel_version.h"

// 控制命令枚举
enum {
    CMD_GET_VERSION = 0,
    CMD_SET_VERSION = 1,
    CMD_RESET_VERSION = 2,
    CMD_GET_STATUS = 3
};

// 控制函数0：主要控制接口
static long kernel_version_control0(const char *ctl_args, char *__user out_msg, int outlen)
{
    char msg[KERNEL_VERSION_BUF_SIZE];
    char *token;
    int cmd = -1;
    char new_version[KERNEL_VERSION_MAX_LEN] = {0};
    int ret = 0;
    
    logk_info("Control0 called with args: %s\n", ctl_args ? ctl_args : "NULL");
    
    // 解析控制参数
    if (ctl_args) {
        // 复制参数到内核空间
        char *args = kstrdup(ctl_args, GFP_KERNEL);
        if (!args) {
            snprintf(msg, sizeof(msg), "Error: Failed to allocate memory");
            goto copy_out;
        }
        
        // 解析命令
        token = strsep(&args, ":");
        if (token) {
            if (kstrtoint(token, 10, &cmd) < 0) {
                cmd = -1;
            }
        }
        
        // 解析版本字符串（如果有）
        if (args && cmd == CMD_SET_VERSION) {
            strncpy(new_version, args, KERNEL_VERSION_MAX_LEN - 1);
            new_version[KERNEL_VERSION_MAX_LEN - 1] = '\0';
        }
        
        kfree(args);
    }
    
    // 执行命令
    switch (cmd) {
        case CMD_GET_VERSION:
            if (version_modified && strlen(custom_version) > 0) {
                snprintf(msg, sizeof(msg), 
                    "Current: %s\nOriginal: %s\nStatus: Modified",
                    custom_version, 
                    ver_info.original_version ? ver_info.original_version : "Unknown");
            } else {
                snprintf(msg, sizeof(msg),
                    "Current: %s\nOriginal: %s\nStatus: Original",
                    ver_info.version_str ? ver_info.version_str : "Unknown",
                    ver_info.original_version ? ver_info.original_version : "Unknown");
            }
            break;
            
        case CMD_SET_VERSION:
            if (strlen(new_version) > 0) {
                ret = set_kernel_version(new_version);
                if (ret == 0) {
                    snprintf(msg, sizeof(msg), "Success: Version changed to %s", new_version);
                } else {
                    snprintf(msg, sizeof(msg), "Error: Failed to change version (err=%d)", ret);
                }
            } else {
                snprintf(msg, sizeof(msg), "Error: No version string provided");
            }
            break;
            
        case CMD_RESET_VERSION:
            restore_original_version();
            snprintf(msg, sizeof(msg), "Success: Version restored to original");
            break;
            
        case CMD_GET_STATUS:
            snprintf(msg, sizeof(msg),
                "Module: kernel_version_mod\n"
                "Author: Kdufse\n"
                "Status: %s\n"
                "Original Version: %s\n"
                "Custom Version: %s\n"
                "Hooked: %s",
                version_modified ? "Modified" : "Original",
                ver_info.original_version ? ver_info.original_version : "Unknown",
                strlen(custom_version) > 0 ? custom_version : "Not set",
                ver_info.is_hooked ? "Yes" : "No");
            break;
            
        default:
            snprintf(msg, sizeof(msg),
                "Kernel Version Mod Control Interface\n"
                "Commands:\n"
                "  0 - Get current version info\n"
                "  1:version - Set new version (e.g., 1:Linux 6.1.0-custom)\n"
                "  2 - Reset to original version\n"
                "  3 - Get module status\n"
                "\n"
                "Current: %s\n"
                "Modified: %s",
                ver_info.version_str ? ver_info.version_str : "Unknown",
                version_modified ? "Yes" : "No");
            break;
    }
    
copy_out:
    // 复制结果到用户空间
    compat_copy_to_user(out_msg, msg, strlen(msg) + 1);
    
    return ret;
}

// 控制函数1：简单设置接口
static long kernel_version_control1(const char *ctl_args, char *__user out_msg, int outlen)
{
    char msg[256];
    
    logk_info("Control1 called with args: %s\n", ctl_args ? ctl_args : "NULL");
    
    if (ctl_args && strlen(ctl_args) > 0) {
        // 直接设置版本
        int ret = set_kernel_version(ctl_args);
        if (ret == 0) {
            snprintf(msg, sizeof(msg), "Version set to: %s", ctl_args);
        } else {
            snprintf(msg, sizeof(msg), "Error: Failed to set version (err=%d)", ret);
        }
    } else {
        // 获取当前状态
        snprintf(msg, sizeof(msg),
            "Kernel Version: %s\n"
            "Modified: %s\n"
            "Use: Provide version string to set",
            ver_info.version_str ? ver_info.version_str : "Unknown",
            version_modified ? "Yes" : "No");
    }
    
    compat_copy_to_user(out_msg, msg, strlen(msg) + 1);
    return 0;
}

// 控制函数2：重启生效的持久化设置
static long kernel_version_control2(const char *ctl_args, char *__user out_msg, int outlen)
{
    char msg[512];
    char persist_file[64];
    char *persist_path = "/data/local/tmp/kernel_version_persist.txt";
    
    logk_info("Control2 called (persistent settings)\n");
    
    if (ctl_args && strlen(ctl_args) > 0) {
        // 保存到文件（重启后生效）
        struct file *fp = filp_open(persist_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (IS_ERR(fp)) {
            snprintf(msg, sizeof(msg), "Error: Cannot create persist file");
        } else {
            kernel_write(fp, ctl_args, strlen(ctl_args), &fp->f_pos);
            filp_close(fp, NULL);
            
            snprintf(msg, sizeof(msg), 
                "Persistent setting saved: %s\n"
                "Will take effect after reboot\n"
                "File: %s",
                ctl_args, persist_path);
        }
    } else {
        // 检查是否存在持久化文件
        struct file *fp = filp_open(persist_path, O_RDONLY, 0);
        if (IS_ERR(fp)) {
            snprintf(msg, sizeof(msg),
                "No persistent settings found\n"
                "Use: Provide version string to save persistent setting");
        } else {
            char buffer[KERNEL_VERSION_MAX_LEN];
            loff_t pos = 0;
            ssize_t len = kernel_read(fp, buffer, sizeof(buffer) - 1, &pos);
            filp_close(fp, NULL);
            
            if (len > 0) {
                buffer[len] = '\0';
                snprintf(msg, sizeof(msg),
                    "Persistent setting: %s\n"
                    "File: %s\n"
                    "Apply now? Use control1 with this version",
                    buffer, persist_path);
            } else {
                snprintf(msg, sizeof(msg), "Persistent file empty");
            }
        }
    }
    
    compat_copy_to_user(out_msg, msg, strlen(msg) + 1);
    return 0;
}

KPM_CTL0(kernel_version_control0);
KPM_CTL1(kernel_version_control1);
KPM_CTL2(kernel_version_control2);