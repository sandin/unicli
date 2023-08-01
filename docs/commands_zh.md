# Unicli使用说明

Unicli 为所有 Unicorn API 都提供了命令支持，并额外的还提供了一些非常实用的其他命令。

​                   

## 通用

| 命令                   | 说明                                                   |
| ---------------------- | ------------------------------------------------------ |
| `script <filename>`    | 加载一个init_script脚本                                |
| `set <name> <value>`   | 设置一个本地变量                                       |
| `unset <name>`         | 删除一个本地变量                                       |
| `print <name>`         | 打印一个本地变量                                       |
| `set_base <addr>`      | 设置一个base address，后续所有地址参数都基于这个基地址 |
| `disasm <addr> <size>` | 反汇编一段代码                                         |
| `run <expr>`           | 直接运行任何一条Python指令                             |
| `help`                 | 打印完整命令帮助信息                                   |
| `exit`                 | 退出程序                                               |

​                     

## 加载

| 命令                  | 说明                                         |
| --------------------- | -------------------------------------------- |
| `load <filename>`     | 加载一个文件，将其按照文件格式映射到虚拟内存 |
| `[--format <format>]` | 文件格式：`elf`, `pe`, `macho`, `raw`        |
| `[--arch <arch>]`     | CPU架构：`arm`, `arm64`, `x86`, `x86_64`     |
| `[--base <address>]`  | 加载的基地址                                 |
| `[--offset <offset>]` | 偏移地址（仅用于 `raw` 格式的文件）          |
| `unload <filename>`   | 卸载一个文件                                 |
| `load_list`           | 打印所有已经加载的文件列表                   |

​           

## 内存

| 命令                             | 说明                   |
| -------------------------------- | ---------------------- |
| `mem_map <addr> <size> [<port>]` | 映射虚拟内存           |
| `mem_write <addr> <data>`        | 写内存                 |
| `mem_read <addr> <size>`         | 读内存                 |
| `mem_list`                       | 打印已映射内存区间列表 |

​              

## 寄存器

| 命令                           | 说明     |
| ------------------------------ | -------- |
| `reg_write <reg_name> <value>` | 写寄存器 |
| `reg_read <reg_name>`          | 读寄存器 |

​               

## Hook

| 命令                      | 说明                                               |
| ------------------------- | -------------------------------------------------- |
| `hook_block <subcommand>` | Hook block，在执行该地址的block之前先执行子命令    |
| `hook_code <subcommand>`  | Hook block，在执行该地址的汇编指令之前先执行子命令 |

​            

## 执行

| 命令                                | 说明         |
| ----------------------------------- | ------------ |
| `emu_start <start_addr> <end_addr>` | 开始模拟执行 |
| `emu_stop`                          | 停止模拟执行 |

​           

## 步进

| 命令             | 说明              |
| ---------------- | ----------------- |
| `step_inst`      | 步进到下一条指令  |
| `step_block`     | 步进到下一个Block |
| `step_to <addr>` | 步进到指定地址    |

​          

## Context

| 命令                   | 说明           |
| ---------------------- | -------------- |
| `ctx_save [<name>]`    | 保存当前上下文 |
| `ctx_restore [<name>]` | 恢复指定上下文 |
| `ctx_del [<name>]`     | 删除指定上下文 |

