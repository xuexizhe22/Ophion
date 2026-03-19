# Ophion / SimpleVMM 修复说明（2026-03-20）

## 1. 这次最终是怎么修好的

### 最终根因

这次真正导致蓝屏 / 卡死 / KD 断连的问题，不是单一某个 `RDMSR` handler 写错了，而是**环境假设冲突**：

- Guest Windows 跑在 **VMware 外层 hypervisor** 里启动，系统已经接受了“自己在 hypervisor 里”的事实，并会使用 Hyper-V enlightenment / synthetic MSR。
- 但 L1 里的 Ophion 代码又试图把 Guest 继续伪装成“裸机”：
  - `CPUID` 隐藏 hypervisor bit
  - 对 `0x40000000+` synthetic MSR 做截获 / 注入 `#GP` / 特殊模拟
  - 对 Hyper-V guest idle / crash enlightenment 路径进行人为干预

结果就是 Guest 看到的 CPU/Hypervisor 行为前后不一致，尤其在空闲路径和崩溃上报路径上会出问题。

### 最终有效修复思路

最终稳定版本采用的是：

**只要检测到外层 hypervisor 存在，就自动切换到 nested compatibility mode。**

这个模式下的核心原则是：

1. **不再试图把 Guest 伪装成 bare metal**
2. **不再隐藏 hypervisor 存在**
3. **不再在 nested 环境里启用 MSR bitmap 去拦截 synthetic MSR**

也就是说，最终真正让系统稳定下来的不是“把 `0x400000F0` 模拟得更像”，而是：

- **承认当前是 nested virtualization**
- **停止对 Guest 已经依赖的 hypervisor 语义做篡改**

### 为什么这次修复有效

因为它把 Guest 的观察结果重新变得一致：

- 如果系统从开机开始就在 hypervisor 里，那么 `CPUID` 就继续表现成“在 hypervisor 里”
- synthetic MSR 不再被我们反复拦截 / 注入 / 模拟
- Guest idle、crash enlightenment、SynIC 等路径不再被 L1 破坏

结论可以概括成一句话：

> **在 VMware 的 nested VT-x 场景里，Ophion 必须优先做“兼容型 VMM”，而不是“隐身型 VMM”。**

---

## 2. 从头到尾都改了哪些代码

说明：

- 下面这份清单是根据两部分整理出来的：
  - 之前对话导出的上下文备份
  - 当前工程源码的实际状态
- 也就是说，这份文档既包含早期已经做过的修复，也包含这次最终让 nested 环境稳定下来的修复。

---

## 3. 第一阶段：构建 / 头文件 / 工程修复

### 3.1 WDK / 头文件修复

#### 文件

- `Y:\xiazai\Ophion-master (1)\Ophion-master\include\hv.h`
- `Y:\xiazai\Ophion-master (1)\Ophion-master\src\driver.c`

#### 修改内容

- 把 `hv.h` 的头文件依赖从 `ntddk.h` 改成了 `ntifs.h`
- 在 `driver.c` 顶部补了 `#include <ntifs.h>`

#### 解决的问题

- `KAPC_STATE` 未定义
- `PsLookupProcessByProcessId` 未定义
- `KeStackAttachProcess` 未定义
- `KeUnstackDetachProcess` 未定义

---

### 3.2 VS / WDK 签名工程修复

#### 文件

- `Y:\xiazai\Ophion-master (1)\Ophion-master\Ophion.vcxproj`
- `Y:\xiazai\Ophion-master (1)\Ophion-master\Ophion.vcxproj.user`

#### 修改内容

- 把 `Debug|x64` / `Release|x64` 的 `SignMode` 改成 `Off`
- 不再依赖 WDK 内置 `SIGNTASK`
- 改成 `PostBuildEvent` 手动调用 `signtool.exe`
- 使用本地 PFX：
  - `Y:\xiazai\Ophion-master (1)\Ophion-master\build\OphionTestCert.pfx`

#### 解决的问题

- `TestCertificate` 属性无效
- `No certificates were found that met all the given criteria`
- `Invalid certificate or password`

---

### 3.3 用户态测试程序修复

#### 文件

- `Y:\xiazai\Ophion-master (1)\ConsoleApplication1\ConsoleApplication1.cpp`

#### 修改内容

- 程序结束前暂停，避免窗口一闪而过
- 失败路径打印 `GetLastError()`

#### 目的

- 提高测试时的可观察性

---

## 4. 第二阶段：VMX 生命周期稳定性修复

这部分的目标是：先让驱动能更保守地启动 / 卸载 / 退出 VMX，避免还没进主问题之前就炸掉。

### 4.1 关闭 private host CR3

#### 文件

- `Y:\xiazai\Ophion-master (1)\Ophion-master\include\stealth.h`

#### 修改内容

- `USE_PRIVATE_HOST_CR3` 从 `1` 改成 `0`

#### 目的

- 先避免 host CR3 深拷贝页表带来的额外复杂性
- 让 nested 环境的基础 VMX 路径先稳定

---

### 4.2 为 VCPU 状态增加 `vmx_active`

#### 文件

- `Y:\xiazai\Ophion-master (1)\Ophion-master\include\hv_types.h`

#### 修改内容

- 在 `VIRTUAL_MACHINE_STATE` 中新增：
  - `BOOLEAN vmx_active;`

#### 目的

- 区分：
  - 已经 `VMXON` 但还没 `VMLAUNCH`
  - 已经 launch
  - 已经 `VMXOFF`

---

### 4.3 `vmx_init()` 失败回滚路径修复

#### 文件

- `Y:\xiazai\Ophion-master (1)\Ophion-master\src\driver.c`

#### 修改内容

- `vmx_init()` 失败时，不再直接 `vmx_terminate()`
- 改为：
  - 先 `broadcast_terminate_all()`
  - 再 `vmx_terminate()`

#### 目的

- 确保所有已进入 VMX 的核心先统一退场

---

### 4.4 `broadcast_terminate_all()` 卸载路径修复

#### 文件

- `Y:\xiazai\Ophion-master (1)\Ophion-master\src\broadcast.c`

#### 修改内容

- 以前是对所有 CPU 无条件做 `VMCALL(VMXOFF)`
- 现在改成：
  - 如果 `vcpu->launched == TRUE`：
    - 走 `asm_vmx_vmcall(VMCALL_VMXOFF, ...)`
  - 如果 `vcpu->vmx_active == TRUE` 但还没 launch：
    - 直接本核 `__vmx_off()`

#### 目的

- 避免在不合适的阶段强行执行 `VMCALL(VMXOFF)`

---

### 4.5 `vmx_virtualize_cpu()` 状态管理修复

#### 文件

- `Y:\xiazai\Ophion-master (1)\Ophion-master\src\vmx.c`

#### 修改内容

- 初始化：
  - `vmx_active`
  - `launched`
  - `vmxoff.executed`
- `VMXON` 成功后设置：
  - `vmx_active = TRUE`
- `vmclear / vmptrld / vmlaunch` 失败路径补齐：
  - `__vmx_off()`
  - 清理 `CR4.VMXE`
  - 恢复状态变量

#### 目的

- 防止 VMX 失败后留下半初始化状态

---

### 4.6 `VMCALL_VMXOFF` 状态收尾修复

#### 文件

- `Y:\xiazai\Ophion-master (1)\Ophion-master\src\vmexit.c`

#### 修改内容

- 在 `VMCALL_VMXOFF` 路径中，`__vmx_off()` 前设置：
  - `vcpu->vmxoff.executed = TRUE`
  - `vcpu->launched = FALSE`
  - `vcpu->vmx_active = FALSE`

#### 目的

- 避免 VMXOFF 之后还被后续逻辑当成“仍在 VMX”处理

---

## 5. 第三阶段：MSR / nested virtualization 相关修复

这一阶段是本次问题的核心。

### 5.1 最初观察到的故障

Guest 在：

- `nt!PpmIdleGuestExecute`

执行：

- `rdmsr`

时崩溃。

日志指向的是：

- `0x400000F0`

这个 MSR 实际上是：

- `HV_X64_MSR_GUEST_IDLE`

之后又观察到：

- `0x40000104`

这个是：

- `HV_X64_MSR_CRASH_P4`

说明 Guest 还会进入 Hyper-V crash enlightenment 路径。

---

### 5.2 中间尝试过的兼容补丁

这些补丁部分保留在代码里，但**它们不是最终稳定的根修复**。

#### 文件

- `Y:\xiazai\Ophion-master (1)\Ophion-master\src\vmexit.c`

#### 中间改动包括

- 增加 synthetic MSR 安全读写包装：
  - `vmexit_try_read_msr()`
  - `vmexit_try_write_msr()`
- 增加 synthetic MSR 调试日志：
  - `vmexit_log_synthetic_msr()`
- 增加 `HV_X64_MSR_GUEST_IDLE (0x400000F0)` 特殊处理：
  - `vmexit_emulate_guest_idle()`
- 增加 crash enlightenment MSR 特殊处理：
  - `HV_X64_MSR_CRASH_P0` ~ `HV_X64_MSR_CRASH_CTL`
  - `vmexit_handle_crash_msr_read()`
  - `vmexit_handle_crash_msr_write()`

#### 这些补丁的作用

- 帮助定位问题
- 在某些阶段避免更早的蓝屏
- 为后续 nested 兼容模式保留保护性 fallback

#### 但为什么它们不是最终答案

因为只要 Guest 还被我们伪装成“裸机”，就仍然会和外层 hypervisor 的实际行为冲突。

---

## 6. 第四阶段：最终稳定修复（真正解决问题的部分）

这是这次成功的关键。

### 6.1 检测外层 hypervisor，并自动关闭 stealth

#### 文件

- `Y:\xiazai\Ophion-master (1)\Ophion-master\include\stealth.h`
- `Y:\xiazai\Ophion-master (1)\Ophion-master\src\stealth.c`

#### 修改内容

在 `STEALTH_CPUID_CACHE` 中新增：

- `outer_hypervisor_present`
- `hypervisor_max_leaf`
- `hypervisor_vendor[3]`

在 `stealth_init_cpuid_cache()` 中新增：

- 用 `CPUID(1)` 检查 `ECX[31]` 是否已置位
- 如果已存在外层 hypervisor：
  - 读取 `CPUID(0x40000000)` 的 vendor / max leaf
  - 自动执行：
    - `g_stealth_enabled = FALSE`

新增日志：

- `Outer hypervisor detected: ...`
- `Nested compatibility mode enabled: stealth CPUID/MSR masking disabled`

#### 这一步的意义

这是最终修复的总开关。

它的语义是：

> 如果 Guest 本来就运行在 hypervisor 里，那么 Ophion 不再继续隐身。

---

### 6.2 nested 环境下禁用 MSR bitmap

#### 文件

- `Y:\xiazai\Ophion-master (1)\Ophion-master\src\vmx.c`

#### 修改内容

在 `vmx_setup_vmcs()` 中，把 primary processor controls 的请求拆开了：

- 默认保留：
  - `CPU_BASED_VM_EXEC_CTRL_USE_TSC_OFFSETTING`
  - `CPU_BASED_VM_EXEC_CTRL_USE_IO_BITMAPS`
  - `CPU_BASED_VM_EXEC_CTRL_ACTIVATE_SECONDARY_CONTROLS`
- 只有在**没有外层 hypervisor**时，才额外启用：
  - `CPU_BASED_VM_EXEC_CTRL_USE_MSR_BITMAPS`

日志也扩展成显示：

- `MSRBitmap=0/1`

#### 这一步的意义

这是最终真正避免 `0x400000F0`、crash MSR、SynIC 等 synthetic MSR 被我们反复截获的关键。

一旦 `MSRBitmap=0`：

- Guest 对大部分 MSR 的访问就不会再频繁 VM-exit 到我们的 handler
- `guest idle` 不再被我们反复截获
- `crash enlightenment` 不再被我们截断 / 透传 / 伪造

---

### 6.3 nested 场景下不再隐藏 CPUID hypervisor bit

#### 文件

- `Y:\xiazai\Ophion-master (1)\Ophion-master\src\vmexit.c`

#### 修改内容

`vmexit_handle_cpuid()` 原本会在 `leaf == 1` 时清掉：

- `ECX[31]` hypervisor present bit

但现在由于：

- `g_stealth_enabled = FALSE`

所以这一行为在 nested 模式下自动关闭。

#### 这一步的意义

让 Guest 继续看到“自己确实运行在 hypervisor 里”，避免和 synthetic MSR / enlightenments 逻辑打架。

---

## 7. 这次最终真正有效的最小结论

最终真正起决定性作用的代码，不是单独某个 `RDMSR` handler 的花式模拟，而是这两件事：

1. **检测到外层 hypervisor 后，自动关闭 stealth**
2. **检测到外层 hypervisor 后，不再启用 MSR bitmap**

换句话说：

> **最终修复 = nested compatibility mode**

它的本质是：

- 不再把 nested guest 伪装成裸机
- 不再拦截已经由外层 hypervisor 支持的 synthetic MSR 行为

---

## 8. 当前版本里仍然保留但不再是主路径的代码

这些代码还在，但在当前稳定方案下已经不是主要依赖：

### 文件

- `Y:\xiazai\Ophion-master (1)\Ophion-master\src\vmexit.c`

### 保留内容

- `HV_X64_MSR_GUEST_IDLE` 兼容返回
- crash MSR 本地缓存 / 拦截
- synthetic MSR 安全透传包装

### 为什么还保留

- 作为保护性 fallback
- 以后如果重新启用 MSR bitmap，这些逻辑还能继续保护系统

### 但请注意

**当前稳定版本并不是依赖这些 handler 频繁工作才稳定的。**

当前稳定版本主要是因为：

- nested 模式下根本就不再大量拦截这些 MSR 了

---

## 9. 给其他 AI / 二次编译者的结论

如果要让其他 AI 继续接手，请明确告诉它：

### 必须保留的核心原则

1. **在 VMware nested VT-x 环境里，不要试图对 Guest 隐藏 hypervisor**
2. **如果外层 hypervisor 已存在，必须关闭 stealth CPUID/MSR masking**
3. **如果外层 hypervisor 已存在，必须关闭 `USE_MSR_BITMAPS`**
4. **不要再把 `HV_X64_MSR_GUEST_IDLE` 当成普通 `RDMSR` 去 root-mode 透传**
5. **不要把 Hyper-V crash MSR 直接 pass-through 给外层 hypervisor**

### 可以继续做的事

- 基于当前稳定版继续验证：
  - 加载
  - 卸载
  - `VMCALL`
  - EPT 基础能力
- 后续如果要重新做 stealth，必须先区分：
  - bare metal 模式
  - nested compatibility 模式

### 不要立刻做的事

- 不要在当前 nested 环境里重新打开：
  - hypervisor bit 隐藏
  - synthetic MSR 一刀切 `#GP`
  - guest idle “架构上更真实”的 HLT 模拟

---

## 10. 当前构建方式

### 工程

- `Y:\xiazai\Ophion-master (1)\Ophion-master\Ophion.vcxproj`

### 构建命令

```powershell
& 'Y:\VS2022\MSBuild\Current\Bin\MSBuild.exe' `
  'Y:\xiazai\Ophion-master (1)\Ophion-master\Ophion.vcxproj' `
  /p:Configuration=Debug `
  /p:Platform=x64 `
  /m
```

### 当前成功生成的驱动

- `Y:\xiazai\Ophion-master (1)\Ophion-master\build\bin\Debug\Ophion.sys`

### 当前可观察到的成功标志

日志中应看到类似：

- `Outer hypervisor detected: ...`
- `Nested compatibility mode enabled: stealth CPUID/MSR masking disabled`
- `Primary proc controls: ... MSRBitmap=0`

---

## 11. 一句话总结

这次不是把某一个 `RDMSR` handler 写对了，而是把整个 VMM 的运行模式从：

- **“我假设 Guest 在裸机上”**

改成了：

- **“我承认 Guest 在外层 hypervisor 上，我先做 nested 兼容”**

这就是这次稳定下来的根本原因。
