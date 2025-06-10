# JumpTiger: 安全与隐蔽性兼备的代理程序

![JumpTiger Logo](https://img.shields.io/badge/Status-Active-brightgreen)
![Python Version](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

## 目录
- [项目简介](#项目简介)
- [核心特性](#核心特性)
- [系统架构](#系统架构)
- [快速开始](#快速开始)
  - [先决条件](#先决条件)
  - [服务器端部署](#服务器端部署)
  - [客户端配置与运行](#客户端配置与运行)
  - [Web 监控界面](#web-监控界面)
- [项目结构](#项目结构)
- [开发与测试](#开发与测试)
- [未来展望](#未来展望)
- [贡献](#贡献)
- [许可证](#许可证)
- [致谢](#致谢)

---

## 项目简介

**JumpTiger** 是一个为应对复杂网络环境而设计的高效、安全且具备出色隐蔽性的代理程序。它通过**自主实现的 Shadowsocks 协议核心**，并结合 **v2ray-plugin 的 WebSocket (WS) + TLS 混淆**和 **Nginx 的 HTTPS 伪装**，构建了一个多层防御体系，旨在帮助用户突破网络限制，实现自由、安全的网络访问。

本项目不仅深入探讨了网络代理协议的底层原理，更通过创新的技术组合，有效提升了代理的抗审查能力，并提供了直观的实时监控界面，方便用户管理和查看代理服务状态。

---

## 核心特性

-   **自主 Shadowsocks 实现**：不依赖于现有的 Shadowsocks 库，从零开始实现 Shadowsocks 客户端与服务器端的 SOCKS5 协议握手、数据封装、加密/解密及转发逻辑，深入理解协议细节。
-   **多层隐蔽性设计**：
    -   **Shadowsocks 加密**：确保数据内容安全。
    -   **v2ray-plugin WS + TLS 混淆**：将 Shadowsocks 流量伪装成标准 HTTPS WebSocket 流量，有效绕过深度包检测（DPI）。
    -   **Nginx HTTPS 伪装**：在 443 端口提供合法网站内容，进一步增强服务器隐蔽性，使其看起来像普通 Web 服务器。
-   **支持多种加密算法**：内置支持 **AES-256-CFB** 和 **ChaCha20** 两种主流、安全的流式加密算法。
-   **SOCKS5 协议全面支持**：作为本地代理，可用于代理各类支持 SOCKS5 协议的应用程序流量。
-   **实时可视化监控**：集成 Flask Web 框架和 Chart.js，提供一个轻量级 Web 界面，实时展示连接日志、活跃连接数及流量统计。

---

## 系统架构

**JumpTiger** 采用客户端-服务器架构，并引入 v2ray-plugin 和 Nginx 构成多层代理链路，其工作流程如下图所示：

![JumpTiger System Architecture](docs/system_architecture.png)
*图1：JumpTiger 系统架构示意图*

1.  **本地应用** (如浏览器、Telegram) 通过 **SOCKS5 协议**连接到本地 `Shadowsocks 客户端`。
2.  `Shadowsocks 客户端` 对应用数据进行**加密**，并将加密数据转发给本地 `v2ray-plugin 客户端`。
3.  `v2ray-plugin 客户端` 将加密数据进行 **WebSocket (WS) + TLS 混淆**，通过 443 端口连接到远程 `Nginx 服务器`。
4.  远程 `Nginx 服务器` 根据配置路径 (如 `/ws`) 将混淆流量**反向代理**给本地 `v2ray-plugin 服务器`；非代理请求则返回伪装的网站内容。
5.  `v2ray-plugin 服务器` **解混淆**接收到的流量，还原出 Shadowsocks 加密数据，并转发给本地 `Shadowsocks 服务器`。
6.  `Shadowsocks 服务器` **解密**数据，解析出目标地址，并建立连接到**目标网站/服务**，实现双向数据转发。
7.  `Shadowsocks 服务器` 记录连接日志，供 `Web 监控界面` 实时展示。

---

## 快速开始

### 先决条件

在部署 **JumpTiger** 之前，请确保您的服务器和本地环境满足以下条件：

**服务器端**：
-   **操作系统**: Ubuntu 20.04 LTS 或更高版本 (推荐)
-   **Python**: Python 3.8+
-   **pip**: Python 包管理器
-   **Nginx**: 1.18+ (用于 HTTPS 伪装和反向代理)
-   **v2ray-plugin**: 从 [V2Ray 官方发布页](https://github.com/v2fly/v2ray-plugin/releases) 下载最新版本，并确保可执行权限。
-   **公网 IP** 和 **域名** (推荐，用于 Nginx HTTPS)

**客户端**：
-   **操作系统**: Windows 10+, macOS Ventura+, Ubuntu 22.04+
-   **Python**: Python 3.8+
-   **pip**: Python 包管理器
-   **v2ray-plugin**: 从 [V2Ray 官方发布页](https://github.com/v2fly/v2ray-plugin/releases) 下载最新版本，并确保可执行权限。
-   **支持 SOCKS5 代理的应用程序** (如 Chrome 配置 SwitchyOmega 扩展, Telegram Desktop, Proxyfier 等)。

### 服务器端部署

1.  **克隆项目仓库**：
    ```bash
    git clone [https://github.com/YourUsername/JumpTiger.git](https://github.com/YourUsername/JumpTiger.git)
    cd JumpTiger
    ```

2.  **安装 Python 依赖**：
    ```bash
    pip install -r requirements.txt
    ```

3.  **配置 `server_config.json`**：
    在 `server/` 目录下创建 `server_config.json` 文件。
    ```json
    {
        "host": "127.0.0.1",
        "port": 8000,
        "password": "your_strong_password",
        "method": "aes-256-cfb",
        "log_file": "../../web_monitor/data/ss_connections.log"
    }
    ```
    **注意：请确保 `password` 和 `method` 与客户端配置一致。`host` 和 `port` 是 Shadowsocks 服务器监听 v2ray-plugin 的地址和端口。`log_file` 指向监控日志路径。**

4.  **配置 Nginx**：
    安装 Nginx：
    ```bash
    sudo apt update
    sudo apt install nginx
    ```
    将 `server/nginx/nginx.conf` 复制到 Nginx 配置目录（通常是 `/etc/nginx/sites-available/default` 或 `/etc/nginx/conf.d/your_domain.conf`）。请替换 `your_domain.com` 为您的域名，并配置 SSL 证书 (例如使用 Let's Encrypt)：

    ```nginx
    server {
        listen 443 ssl;
        listen [::]:443 ssl;
        server_name your_domain.com; # 替换为你的域名
    
        ssl_certificate /etc/letsencrypt/live/your_[domain.com/fullchain.pem](https://domain.com/fullchain.pem); # 你的证书路径
        ssl_certificate_key /etc/letsencrypt/live/your_[domain.com/privkey.pem](https://domain.com/privkey.pem); # 你的密钥路径
        ssl_session_cache shared:SSL:1m;
        ssl_session_timeout 5m;
        ssl_ciphers HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers on;
    
        # 伪装网站内容（可选，但强烈推荐）
        root /var/www/html; # 假设你的伪装网站文件在这里
        index index.html index.htm;
    
        location / {
            try_files $uri $uri/ =404; # 提供伪装网站内容
        }
    
        # v2ray-plugin 反向代理路径
        location /ws { # 这个路径需要与v2ray-plugin配置中的path一致
            proxy_redirect off;
            proxy_pass [http://127.0.0.1:10000](http://127.0.0.1:10000); # v2ray-plugin 服务器监听的端口
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
    }
    
    server {
        listen 80;
        listen [::]:80;
        server_name your_domain.com;
        return 301 https://$host$request_uri; # 将HTTP请求重定向到HTTPS
    }
    ```
    保存配置并测试 Nginx 配置：
    ```bash
    sudo nginx -t
    sudo systemctl reload nginx
    ```

5.  **运行 v2ray-plugin 服务器**：
    在https://github.com/shadowsocks/v2ray-plugin/releases下载v2ray-plugin
    将下载的 `v2ray-plugin` 可执行文件放到一个方便的目录，例如 `server/v2ray-plugin/v2ray-plugin`。
    启动 v2ray-plugin 服务器端，监听 `10000` 端口，并连接到 Shadowsocks 服务器的 `8000` 端口（此端口由您的 `shadowsocks_core/server.py` 监听）。
    ```bash
    # 进入 server/v2ray-plugin/ 目录
    cd server/v2ray-plugin/
    ./v2ray-plugin_linux_amd64 -server -mode websocket -path /ws -host 127.0.0.1:8000 -loglevel none &
    # & 用于后台运行
    cd ../../
    ```
    **注意**：`v2ray-plugin` 的具体命令和参数可能因版本而异，请查阅其官方文档。`-path /ws` 需与 Nginx 配置中的 `location /ws` 匹配。

6.  **运行 Shadowsocks 服务器**：
    使用提供的启动脚本。
    ```bash
    # 进入 server/ 目录
    cd server/
    chmod +x run_server.sh
    ./run_server.sh &
    # & 用于后台运行
    cd ../
    ```
    `run_server.sh` 脚本内容：
    ```bash
    #!/bin/bash
    # 确保在项目根目录运行
    SCRIPT_DIR=$(dirname "$0")
    cd "$SCRIPT_DIR"
    
    # 启动 Shadowsocks 服务器
    python shadowsocks_core/server.py
    ```

### 客户端配置与运行

1.  **克隆项目仓库**：
    在您的本地机器上：
    ```bash
    git clone [https://github.com/YourUsername/JumpTiger.git](https://github.com/YourUsername/JumpTiger.git)
    cd JumpTiger
    ```

2.  **安装 Python 依赖**：
    ```bash
    pip install -r requirements.txt
    ```

3.  **配置 `client_config.json`**：
    在 `client/` 目录下创建 `client_config.json` 文件。
    确保 `password` 和 `method` 与服务器端配置一致。
    `remote_host` 应该是您服务器的**域名**（或公网 IP），`remote_port` 应该是 `443`（Nginx HTTPS 端口）。
    ```json
    {
        "local_host": "127.0.0.1",
        "local_port": 1080,
        "remote_host": "your_domain.com", # 替换为你的服务器域名或公网IP
        "remote_port": 443,              # Nginx HTTPS 端口
        "password": "your_strong_password",
        "method": "aes-256-cfb"
    }
    ```

4.  **运行 v2ray-plugin 客户端**：
    将下载的 `v2ray-plugin` 可执行文件放到一个方便的目录，例如 `client/v2ray-plugin/v2ray-plugin`。
    启动 v2ray-plugin 客户端，监听 `10800` 端口（此端口由您的 `shadowsocks_core/client.py` 连接），并将其流量转发到您的服务器域名 `your_domain.com:443`。
    ```bash
    # 进入 client/v2ray-plugin/ 目录
    cd client/v2ray-plugin/
    ./v2ray-plugin_windows_amd64.exe -client -mode websocket -path /ws -tls -host your_domain.com -loglevel none &
    # 或 Linux/macOS: ./v2ray-plugin_linux_amd64 -client -mode websocket -path /ws -tls -host your_domain.com -loglevel none &
    cd ../../
    ```
    **注意**：`-tls` 表示使用 TLS 加密，`-path /ws` 需与服务器端 Nginx 配置中的 `location /ws` 匹配，`-host your_domain.com` 替换为您的服务器域名。

5.  **运行 Shadowsocks 客户端**：
    使用提供的启动脚本。
    ```bash
    # 进入 client/ 目录
    cd client/
    chmod +x run_client.sh # Linux/macOS
    ./run_client.sh &
    # & 用于后台运行
    cd ../
    ```
    `run_client.sh` 脚本内容：
    ```bash
    #!/bin/bash
    # 确保在项目根目录运行
    SCRIPT_DIR=$(dirname "$0")
    cd "$SCRIPT_DIR"
    
    # 启动 Shadowsocks 客户端
    python shadowsocks_core/client.py
    ```

6.  **配置本地应用**：
    将您的浏览器（如 Chrome 配合 SwitchyOmega 扩展）或其他应用程序的代理设置为 **SOCKS5 代理**，地址为 `127.0.0.1`，端口为 `1080`。

### Web 监控界面

1.  **确保 Shadowsocks 服务器正在运行**：监控界面会读取服务器的日志文件。
2.  **运行 Web 监控 Flask 应用**：
    ```bash
    # 进入 web_monitor/ 目录
    cd web_monitor/
    python app.py &
    # & 用于后台运行
    cd ../
    ```
    默认会运行在 `http://0.0.0.0:5000`。您可以通过浏览器访问 `http://服务器IP:5000` 来查看监控界面。

## 项目结构

```plain 
JumpTiger/
├── client/
│   ├── client_config.json             # 客户端的配置，包括本地监听地址、远程服务器地址、密码和加密方法
│   ├── run_client.sh                  # 启动 Shadowsocks 客户端的脚本（Linux/macOS）
│   └── shadowsocks_core/
│       ├── __init__.py                # Python 包标识文件
│       ├── client.py                  # Shadowsocks 客户端的核心逻辑实现
│       └── cipher.py                  # 加密/解密算法的实现（与服务端共享）
│   └── v2ray-plugin/                  # 存放 v2ray-plugin 客户端可执行文件，根据操作系统选择对应版本
│       └── v2ray-plugin_windows_amd64.exe  # 示例：Windows 版可执行文件
│       └── v2ray-plugin_linux_amd64      # 示例：Linux 版可执行文件
├── docs/
│   └── system_architecture.png        # 项目系统架构图，可视化代理链路
├── server/
│   ├── nginx/
│   │   └── nginx.conf                 # Nginx 服务器的配置文件示例，用于 HTTPS 伪装和 WebSocket 反向代理
│   ├── run_server.sh                  # 启动 Shadowsocks 服务器的脚本（Linux/macOS）
│   ├── server_config.json             # 服务器端的配置，包括监听地址、密码和加密方法
│   └── shadowsocks_core/
│       ├── __init__.py                # Python 包标识文件
│       ├── server.py                  # Shadowsocks 服务器的核心逻辑实现
│       └── cipher.py                  # 加密/解密算法的实现（与客户端共享）
│   └── v2ray-plugin/                  # 存放 v2ray-plugin 服务器端可执行文件，根据操作系统选择对应版本
│       └── v2ray-plugin_linux_amd64      # 示例：Linux 版可执行文件
├── web_monitor/
│   ├── app.py                         # Flask Web 应用的主文件，负责数据接口和页面渲染
│   ├── data/
│   │   └── ss_connections.log         # 由 Shadowsocks 服务器写入的连接日志文件，Web 监控读取此文件
│   ├── static/
│   │   ├── script.js                  # 用于 Web 监控界面的前端 JavaScript 逻辑
│   │   └── style.css                  # 用于 Web 监控界面的前端 CSS 样式
│   └── templates/
│       └── index.html                 # Web 监控界面的 HTML 模板文件
├── .gitignore                         # Git 忽略文件，用于指定哪些文件不应被版本控制
├── LICENSE                            # 项目许可证文件 (MIT License)
├── requirements.txt                   # Python 项目依赖列表
└── README.md                          # 项目的详细说明文档
```





## 开发与测试

本项目使用 **Python 3.8+** 进行开发，并依赖 `cryptography` 和 `Flask` 等库。
我们进行了详细的功能性测试，确保代理的基本功能、加密算法、混淆伪装以及监控界面都能正常工作。性能与稳定性测试也初步验证了程序在并发和大流量场景下的表现。

有关详细的测试方案、环境搭建、预期结果和结果分析，请参阅[项目设计报告](#)。

---

## 未来展望

**JumpTiger** 将持续迭代和改进，未来计划包括：

-   **更强大的密钥派生函数**：引入 PBKDF2/scrypt 增强密钥安全性。
-   **细粒度流量管理**：实现按用户或时间段的流量统计和限额。
-   **自动化部署与管理工具**：开发一键部署脚本、Docker 容器化和命令行管理工具。
-   **更强的鲁棒性**：优化错误处理和连接重试机制。
-   **集成更多高级混淆协议**：如 Trojan、VMess over gRPC/HTTP/TCP。
-   **跨平台客户端开发**：提供更友好的图形用户界面。
-   **智能路由与分流**：根据目标自动选择代理策略。

---

## 贡献

我们欢迎所有对 **JumpTiger** 项目感兴趣的开发者贡献代码、提出建议或报告 Bug。请遵循以下步骤：

1.  Fork 本仓库。
2.  创建您的功能分支 (`git checkout -b feature/AmazingFeature`)。
3.  提交您的修改 (`git commit -m 'Add some AmazingFeature'`)。
4.  推送到分支 (`git push origin feature/AmazingFeature`)。
5.  打开一个 Pull Request。

---

## 许可证

本项目基于 MIT 许可证发布。详情请查阅 [LICENSE](LICENSE) 文件