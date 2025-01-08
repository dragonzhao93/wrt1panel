<p align="center"><a href="https://1panel.cn"><img src="http://1panel.oss-cn-hangzhou.aliyuncs.com/img/1panel-logo.png" alt="1Panel" width="300" /></a></p>
<p align="center"><b>现代化、开源的 Linux 服务器运维管理面板</b></p>
<p align="center">
  <a href="https://www.gnu.org/licenses/gpl-3.0.html"><img src="https://shields.io/github/license/1Panel-dev/1Panel?color=%231890FF" alt="License: GPL v3"></a>
  <a href="https://app.codacy.com/gh/1Panel-dev/1Panel?utm_source=github.com&utm_medium=referral&utm_content=1Panel-dev/1Panel&utm_campaign=Badge_Grade_Dashboard"><img src="https://app.codacy.com/project/badge/Grade/da67574fd82b473992781d1386b937ef" alt="Codacy"></a>
  <a href="https://github.com/1Panel-dev/1Panel/releases"><img src="https://img.shields.io/github/v/release/1Panel-dev/1Panel" alt="GitHub release"></a>
  <a href="https://github.com/1Panel-dev/1Panel"><img src="https://img.shields.io/github/stars/1Panel-dev/1Panel?color=%231890FF&style=flat-square" alt="Stars"></a>
  <a href="https://app.fossa.com/projects/git%2Bgithub.com%2F1Panel-dev%2F1Panel?ref=badge_shield"><img src="https://app.fossa.com/api/projects/git%2Bgithub.com%2F1Panel-dev%2F1Panel.svg?type=shield" alt="FOSSA Status"></a><br>
  [<a href="docs/README_TW.md">中文(繁體)</a>] | [<a href="docs/README_EN.md">English</a>] | [<a href="docs/README_JP.md">日本語</a>]
</p>

------------------------------

1Panel 是新一代的 Linux 服务器运维管理面板。
本仓库中的代码基于1panel-V1.10.1-lts 修改，为适配openwrt环境中运行1panel而创建，CENTOS、Ubuntu、Debian、Raspbian等系统请到1panel官方仓库查看或自行尝试能否使用。

- **高效管理**：用户可以通过 Web 图形界面轻松管理 Linux 服务器，实现主机监控、文件管理、数据库管理、容器管理等功能；
- **快速建站**：深度集成开源建站软件 WordPress 和 [Halo](https://github.com/halo-dev/halo/)，域名绑定、SSL 证书配置等操作一键搞定；
- **应用商店**：精选上架各类高质量的开源工具和应用软件，协助用户轻松安装并升级；
- **安全可靠**：基于容器管理并部署应用，实现最小的漏洞暴露面，同时提供防火墙和日志审计等功能；
- **一键备份**：支持一键备份和恢复，用户可以将数据备份到各类云端存储介质，永不丢失。

## UI 展示

![UI展示](https://resource.fit2cloud.com/1panel/img/overview.png)

## 快速开始

**在线体验**

- 环境地址：<https://demo.1panel.cn/>
- 用户名：demo
- 密码：1panel

**一键安装**

在 Linux 终端 执行如下官方命令一键安装原版1Panel（请注意，该方式在openwrt中不能正常安装）:

```sh
curl -sSL https://resource.fit2cloud.com/1panel/package/quick_start.sh -o quick_start.sh && sudo bash quick_start.sh
```
在 openwrt 终端 执行如下命令在openwrt中一键安装wrt1panel或官方1Panel :

```sh
curl -sSL https://raw.githubusercontent.com/dragonzhao93/wrt_installer/wrt_1panel/quick_start.sh -o quick_start.sh && bash quick_start.sh
```
本仓库ACTIONS编译的二进制文件及压缩包，请到[releases](https://github.com/dragonzhao93/wrt1panel/releases)查看、下载。

### 安装过程中遇到问题
一些常见的安装问题及解决办法，请到[wrt_installer](https://github.com/dragonzhao93/wrt_installer)查看。


## License

Copyright (c) 2014-2024 [FIT2CLOUD 飞致云](https://fit2cloud.com/), All rights reserved.

Licensed under The GNU General Public License version 3 (GPLv3)  (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

<https://www.gnu.org/licenses/gpl-3.0.html>

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
