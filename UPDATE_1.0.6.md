# v1.0.6 更新流程（10 台测试服务器）

> 原因：10 台测试服务器还停留在 v1.0.3，**1.0.3 没有云更新功能**（v1.0.4 才引入），
> 必须手动用快速上线命令更新一次。更新完成后即具备云端一键更新能力，以后无需逐台操作。

## 前置确认

- [ ] 管理端 Controller 已更新到 v1.0.6（已完成）
- [ ] v1.0.6 Release 已编译完成（已确认：2026-08-08 10:17 发布，二进制就绪）

## 操作步骤

### 第 1 步：停止 10 台的旧 systemd 服务

每台服务器执行：

```bash
sudo systemctl stop nettool-worker
```

> 必须停止旧 worker：1.0.3 旧进程不会自动退出，不停的话新 worker 注册会被分配 node2/node3，
> 节点列表出现重复机器。

### 第 2 步：管理端 Dashboard 生成更新命令

1. 登录管理端 Dashboard（v1.0.6）
2. 进入「快速上线」面板
3. 存储 URL 填：

```
https://cf.liuass.eu.org/ghproxy/https://github.com/2476818641/newtool/releases/download/v1.0.6/worker-linux-amd64
```

4. 勾选：
   - [x] `-proxy`（拉取 L7 代理）
   - [x] `-install`（安装 systemd 服务）—— **不要勾 `-daemon`**
5. 点保存 → 生成命令 → 复制

> ⚠️ 关键：这 10 台原来是 systemd（-install）部署的，更新命令也必须勾 `-install`。
> 新版本的 `-install` 会自动：写 systemd 服务 → daemon-reload → **立即 start（节点立刻上线）**。
> 若误勾 `-daemon`：worker 会以前台方式跑，但旧 systemd 服务文件还在（只是 stop 了），
> 开机会被 systemd 拉起来，造成混乱。

### 第 3 步：每台执行生成的命令

生成的命令形如：

```bash
sudo bash -c "curl -fsSL \"https://cf.liuass.eu.org/ghproxy/.../worker-linux-amd64\" -o worker && chmod +x worker && ./worker -c <controller>:<port> -token <token> -http-port <port> -proxy -install"
```

### 第 4 步：验证

- [ ] 管理端节点列表显示 10 台 v1.0.6 上线（无 1.0.3 重复节点）
- [ ] 每台 `systemctl status nettool-worker` 显示 active (running)
- [ ] 节点状态 READY

## 手动命令备用（方式二）

若不想用 Web UI，手动执行：

```bash
# 停旧
sudo systemctl stop nettool-worker

# 下载 v1.0.6 并安装
curl -fsSL "https://cf.liuass.eu.org/ghproxy/https://github.com/2476818641/newtool/releases/download/v1.0.6/worker-linux-amd64" -o worker && chmod +x worker && sudo ./worker -c <controller-ip>:<grpc端口> -token <worker-token> -http-port <http端口> -proxy -install
```

> token/端口用 Controller 的实际值（`data/auth/worker.token`）。

## 更新完成后的日常更新流程（v1.0.6+）

以后每次更新只需在管理服务器 Dashboard：

1. 「检查更新」→ 看版本对比 + 更新说明（Release 链接）
2. 「更新 Controller」→ 自动下载校验替换重启
3. 「更新 Workers」→ 所有 Worker 约 60s 内自动下载（经 ghproxy）→ 校验 → 替换 → 重启

**无需再逐台登录服务器。**
