## 介绍

本程序可以自动发包shnu*体锻打卡*小程序（仅支持奉贤校区），自动跑步打卡，一天内可以打卡多次(但不建议)。

## 依赖安装

请确保有python 3.8以及以上python环境，系统环境为windows。

在终端使用如下命令安装依赖

```
pip install -r requirements.txt
```

## 使用教程

### 初次使用流程

1. **启动程序**：双击运行 `shnuruning.py` 或在终端中执行 `python shnuruning.py`。程序会自动请求管理员权限（用于系统代理设置和证书安装）。

2. **证书安装**：初次使用时，程序会自动检测证书是否安装，若未安装会提示安装证书。证书安装是必要的，用于抓取用户ID信息。

3. **获取用户ID**：
   - 在主界面选择"获取用户ID"
   - 确认关闭所有VPN/代理软件
   - 按照提示打开微信小程序"体锻打卡"
   - 等待程序自动抓取用户ID（过程中不要关闭程序）
   - 获取成功后会显示用户信息

4. **开始跑步**：
   - 在主界面选择"开始跑步"
   - 若有多个用户，会显示用户选择界面
   - 输入跑步时间（分钟）和距离（公里）
   - 选择跑步模式（模拟真实跑步或快速完成）
   - 按照程序提示完成跑步打卡

### 详细功能说明

#### 证书安装

程序会自动检测是否已安装 mitmproxy 证书。如果未安装，会引导您完成安装过程：

1. 程序会先检查是否已安装 mitmproxy
2. 如未安装，会自动下载并安装
3. 启动mitmproxy并打开浏览器引导您访问http://mitm.it/进行证书安装
4. 在浏览器中，点击对应您操作系统的图标下载证书
5. 双击下载的证书文件，按照系统提示安装（Windows系统需要选择"将所有证书放入下列存储"，然后选择"受信任的根证书颁发机构"）
6. 验证证书是否安装成功

**注意**：证书安装需要管理员权限，程序会自动请求。安装证书后，系统可能会弹出安全提示，请选择"是"。

#### 获取用户ID

用户ID是体锻打卡必须的参数，程序通过以下方式获取：

1. 设置系统代理（127.0.0.1:8080）
2. 启动 mitmproxy 代理服务
3. 当您打开微信小程序时，程序会自动捕获用户ID和相关信息
4. 获取到的信息会保存到 `userInfo.json` 文件中
5. 完成后自动关闭代理并恢复系统设置

**支持多用户**：每次获取到的新用户会被添加到用户列表中，不会覆盖现有用户。

#### 跑步打卡

跑步打卡是程序的核心功能，使用步骤：

1. 选择要使用的用户（若有多个）
2. 输入跑步参数：
   - 时间：1-25分钟（建议不超过25分钟）
   - 距离：2公里以上（建议2-5公里）
3. 选择跑步模式：
   - **模拟真实跑步**：等待所设定的时间后才上报完成
   - **快速完成**：立即上报完成结果，无需等待

**注意**：每天第一次跑步前，请先在微信小程序内点击"开始跑步"，然后直接点击"结束跑步"，以获取有效的跑步路线。然后再使用本程序进行跑步。

#### 多用户管理

程序支持多个用户同时管理：

1. 用户信息保存在 `userInfo.json` 文件中
2. 每次获取新用户ID时，会自动添加到列表中
3. 如获取到已存在的用户ID，会更新该用户信息
4. 跑步时可从列表中选择要使用的用户账号

## 程序实现原理

### 证书生成与安装

程序使用 mitmproxy 工具生成和管理证书：

1. 使用 Python 的 `subprocess` 模块运行 mitmproxy 生成证书
2. 证书默认保存在 `~/.mitmproxy/` 目录下
3. 使用 PowerShell 命令将证书导入到系统证书存储区
4. 通过 `certutil` 命令验证证书是否成功安装

### 网络代理与数据抓取

程序使用 mitmproxy 作为中间人代理：

1. 设置系统代理指向本地 mitmproxy 服务
2. 通过 mitmproxy 的 Addon 机制捕获特定 URL 的请求和响应
3. 从响应数据中提取用户ID、姓名、学号等信息
4. 使用 JSON 格式保存用户信息到本地文件

### 跑步模拟实现

程序通过模拟位置点上报和时间控制实现跑步打卡：

1. 发送开始跑步请求，获取 `runningRecord`
2. 按照预设路线发送位置点信息
3. 模拟真实跑步模式下，使用倒计时显示进度条
4. 跑步完成后，上报完成信息，包括时间、距离等参数

### 错误处理与恢复

程序实现了完善的错误处理机制：

1. 每个关键操作都有异常捕获和日志记录
2. 系统代理设置失败时，会尝试自动杀死可能冲突的进程
3. 用户ID获取超时时，提供重试选项
4. 跑步过程中用户可随时取消（按'N'键）

### 代码架构

程序采用模块化设计：

1. `Addon.py` - 负责网络请求拦截和用户信息提取
2. `shnuruning.py` - 主程序，包含用户界面和核心逻辑
3. 使用全局变量管理用户信息和跑步状态
4. 采用函数式编程风格，每个功能封装为独立函数

## 更新日志

### 2025.03.09 更新
1. 改进了证书生成和安装流程，现在可以自动验证证书是否正确安装
2. 添加了日志记录功能，问题排查更加方便
3. 证书路径更新为标准路径，提高兼容性
4. 增加了证书格式转换功能，支持 pem 格式
5. 添加了自动检测和安装 mitmproxy 的功能
6. 修复了中文引号导致的语法错误
7. 修复了 mitmproxy 安装成功但无法在路径中找到的问题，使用模块方式直接运行 mitmproxy
8. 新增多用户管理功能，支持同时存储多个用户的信息并在运行时选择
9. 修复了获取用户ID后程序闪退的问题
10. 改进了用户ID获取流程的稳定性，增加了超时处理和错误捕获
11. 新增快速完成功能，用户可选择跳过等待时间直接上报完成（存在被系统检测的风险）

### 2025.03.24 更新
1. 改进了证书安装流程，现在不再自动生成和安装证书，而是启动mitmproxy并用浏览器引导用户访问http://mitm.it/手动安装证书
2. 修复了证书安装失败的问题
3. 增加了详细的证书安装指导步骤
4. 修复了多线程运行mitmproxy导致的"signal only works in main thread"错误，现在使用多进程方式运行mitmproxy
5. 修复了浏览器访问mitm.it时显示"traffic is not passing through mitmproxy"的问题，确保在访问证书安装页面前正确设置系统代理

## 功能特点

1. 自动获取用户ID并存储
2. 多用户管理，可以为多个用户打卡
3. 自动模拟跑步路线和位置点上报
4. 自动安装和管理证书
5. 支持自定义跑步时间和距离
6. 详细的日志记录，便于故障排查
7. 支持模拟真实跑步或快速完成模式

## 故障排查

如果遇到问题，可以查看 `shnuruning.log` 日志文件，其中包含详细的运行信息和错误报告。

证书安装失败的常见原因：
1. 缺少管理员权限 - 尝试以管理员身份运行程序
2. OpenSSL 未安装 - 需要安装 OpenSSL
3. 之前的 mitmproxy 进程未正确关闭 - 重启计算机后重试
4. mitmproxy 未正确安装 - 程序将尝试自动安装，或者可以手动执行 `pip install mitmproxy`
5. ~~安装后 mitmproxy 不在系统路径中 - 重启计算机后再试~~ (已解决，现在使用模块直接导入)
6. 证书安装失败 - 现在程序会引导您通过浏览器手动安装证书，按照屏幕提示操作
7. "signal only works in main thread"错误 - 已修复，改用多进程方式运行mitmproxy
8. 浏览器显示"traffic is not passing through mitmproxy" - 表示浏览器没有使用mitmproxy代理，已修复系统代理设置流程

如果遇到 "The system cannot find the file specified" 错误，通常是因为 mitmproxy 未安装或不在系统路径中，请尝试以下步骤：
1. 确保程序使用的是最新版本，已修复此问题
2. 如果问题仍然存在，尝试手动安装 mitmproxy: `pip install mitmproxy`

## 多用户管理

程序现在支持同时为多个用户存储信息和打卡：

1. 每次获取用户ID时，新用户会被添加到用户列表中，而不会覆盖现有用户
2. 如果获取到的用户ID已存在，会更新该用户的信息
3. 运行跑步功能时，如果有多个用户，会显示用户选择界面
4. 选择用户后，可以使用该用户的信息进行跑步打卡

## 跑步模式

程序提供两种跑步模式：

1. **模拟真实跑步**：等待设定的时间后才上报跑步完成结果，更接近真实跑步体验
2. **快速完成**：立即上报跑步完成结果，无需等待，但可能被后台系统检测到异常

⚠️ **风险警告**：使用快速完成模式可能会被后台系统识别为异常行为，导致跑步记录被清除或账号被标记。请自行承担使用风险。

已知问题与解决方案：
1. 中文引号导致的语法错误 - 已修复，如果仍遇到相关问题请提交反馈
2. mitmproxy 安装成功但无法在路径中找到 - 已修复，现在使用 Python 模块方式直接调用 mitmproxy
3. 获取用户ID后程序闪退 - 已修复，优化了进程管理逻辑，防止重复关闭同一进程
4. 用户ID获取超时 - 已添加60秒超时处理，超时后可选择重试或返回

