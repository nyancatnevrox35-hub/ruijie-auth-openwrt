# Ruijie 802.1X 认证客户端 —— OpenWrt/ImmortalWrt 软件包(含 LuCI Web 界面)

基于逆向重写的 `ruijie_auth.c` 打包,适用于校园网锐捷 802.1X EAP-MD5 认证。
包含两个包:

| 包 | 内容 | 架构 |
|---|---|---|
| `ruijie-auth` | 主程序 + procd init 脚本 + UCI 配置 | 架构相关(随设备) |
| `luci-app-ruijie-auth` | LuCI Web 图形界面(菜单 网络 → Ruijie 802.1X) | 全架构(all) |

## 0. 前提与术语

1. **路由器必须已运行 OpenWrt/ImmortalWrt**(官方 CudyOS 不行)。确认方法:
   SSH 登录执行 `cat /etc/openwrt_release` 与 `uname -m`。
2. 包格式:OpenWrt/ImmortalWrt **23.05 / 24.10 稳定版用 `.ipk`(opkg)**;
   只有 OpenWrt **main/SNAPSHOT**(2024 年末起迁移到 apk 包管理器)才产出 `.apk`。
   本仓库同一套源码,用什么 SDK 编译就得到什么格式。
3. Cudy TR3000 若为 MT7981B(Filogic 820)平台,对应的 OpenWrt 目标为
   `mediatek/filogic`、包架构 `aarch64_cortex-a53`。**以 `uname -m` 实际输出为准。**

## 1. 目录结构

    package/
      ruijie-auth/
        Makefile                  # 二进制包定义
        src/ruijie_auth.c         # 主程序(自包含,已修复审查发现的问题)
        files/ruijie-auth.init    # procd init 脚本
        files/ruijie-auth.config  # UCI 默认配置
      luci-app-ruijie-auth/
        Makefile
        htdocs/luci-static/resources/view/ruijie-auth.js   # LuCI JS 视图
        root/usr/share/luci/menu.d/luci-app-ruijie-auth.json   # 菜单项
        root/usr/share/rpcd/acl.d/luci-app-ruijie-auth.json    # rpcd ACL

## 2. 用 SDK 编译(产出 .ipk)

**SDK 版本必须与路由器固件版本一致**(23.05 对 23.05,24.10 对 24.10)。
示例(以 ImmortalWrt 23.05、MT7981 为例,替换为你实际下载的 SDK 文件名):

    # 1) 下载对应 SDK 并解压
    #    ImmortalWrt: https://downloads.immortalwrt.org/releases/<ver>/targets/mediatek/filogic/
    #    文件名形如: immortalwrt-sdk-23.05.x-mediatek-filogic_*.tar.xz
    tar xf immortalwrt-sdk-*.tar.xz && cd immortalwrt-sdk-*

    # 2) 更新并安装 luci feed(SDK 自带 feeds.conf.default 含 luci)
    ./scripts/feeds update luci
    ./scripts/feeds install -p luci -a

    # 3) 把本仓库的两个包目录复制进 SDK
    mkdir -p package
    cp -r <本仓库>/package/ruijie-auth <本仓库>/package/luci-app-ruijie-auth package/

    # 4) 生成默认配置(首次必需:否则 make 会尝试启动交互式 menuconfig,
    #    无终端环境直接报 "Error opening terminal")
    make defconfig

    # 5) 编译
    make package/ruijie-auth/compile V=s
    make package/luci-app-ruijie-auth/compile V=s

    # 6) 产物位置(apk 固件为 .apk,opkg 固件为 .ipk)
    #    bin/packages/<arch>/base/ruijie-auth_1.0.0-1_<arch>.apk
    #    bin/packages/<arch>/luci/luci-app-ruijie-auth_1.0.0-1_all.apk

## 3. 安装与使用

    # 上传两个 ipk 到路由器后:
    opkg install ./ruijie-auth_*.ipk
    opkg install ./luci-app-ruijie-auth_*.ipk

    # 或命令行配置(UCI):
    uci set ruijie.main.enabled=1
    uci set ruijie.main.interface=wan          # 上联口
    uci set ruijie.main.username=学号
    uci set ruijie.main.password=密码
    uci commit ruijie
    /etc/init.d/ruijie-auth restart

然后浏览器打开 LuCI → 网络 → **Ruijie 802.1X** 填写并启用。
界面会实时显示认证状态(读取 `/var/run/ruijie-auth.status`,认证成功后由守护进程写入)。

## 4. 设计要点 / 安全

- 密码不经过命令行(避免 `ps` 泄露):init 脚本把密码写入
  `/var/run/ruijie-auth.pass`(0600,仅 root 可读),守护进程经 `--password-file` 读取。
  UCI 配置 `/etc/config/ruijie` 以 0600 安装。
- 认证状态文件 `/var/run/ruijie-auth.status` 内容为成功时间戳(epoch 秒),
  LuCI 通过 rpcd 的 file 插件读取(ACL 已随包安装)。
- 守护进程 stdout/stderr 由 procd 接入 logd,`logread -e ruijie-auth` 可查日志。
- procd `respawn 3600 5 5`:进程异常退出自动拉起。

## 5. 高级选项(默认未在界面暴露)

程序还支持 `--no-start-trailer` / `--no-private-trailer`(调试用)、
`--success-file`(自定义状态路径)。如需在界面暴露,在
`ruijie-auth.js` 与 `ruijie-auth.init` 中对应添加字段即可。

## 6. 常见问题

- **架构不匹配 / 依赖报错**:确认 SDK 目标与 `uname -m` 一致。
- **认证失败**:先开 `debug` 开关,然后 `logread -e ruijie-auth` 查看十六进制帧;
  校园网若绑定 MAC,在 `mac` 栏填原认证设备的 MAC。
- **TR3000 尚无 OpenWrt 固件**:需要先解决固件移植(查 OpenWrt ToH / 论坛是否有
  MT7981 板型支持),本包不解决刷机问题。

## 7. 免本地环境:GitHub Actions 云编译(推荐)

本仓库自带 `.github/workflows/build.yml`，会并行构建两套官方 SDK:

- `ImmortalWrt-25.12.1` (官方 releases SDK)
- `OpenWrt-snapshot` (官方 snapshots SDK)

每套构建都会先下载官方 `sha256sums` 并校验 SDK 压缩包完整性，然后再编译。只要:

1. 把整个目录推到 GitHub 仓库;
2. 打开 Actions 页面,选 "Build ruijie-auth packages" → **Run workflow**;
3. 等约 10~20 分钟,从该次运行页分别下载:
   - `ruijie-auth-packages-immortalwrt`
   - `ruijie-auth-packages-openwrt`

附件内除 `.apk/.ipk` 外，还包含:

- `SHA256SUMS` (产物哈希)
- `build-info.txt` (SDK 来源与校验值)
- `file-types.txt` (产物文件类型检查)

工作流会在云端自动完成 SDK 下载、官方校验、feeds 安装与编译,无需本地 Linux 环境。
