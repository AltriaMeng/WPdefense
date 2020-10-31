==快速==

贡献者：杨炳汉，杨超宇，于津鉴，袁疆域

标题：快速，性能，测试

Stable tag: trunk

许可证：MIT License

目标用户：本产品插件主要面向的对象为：使用WordPress且对WordPress友好，没有恶意的用户。

这是WordPress的非官方插件。

这插件的官方代码储存库位置于：
https://github.com/AltriaMeng/WPdefense/


==描述==

此插件为私人团队开发的一个插件，该插件实现的主要功能为防止恶意用户暴力登入以及对恶意登入者进行功能性限制，防止其对博客进行修改以及对账户进行恶意操作。


==说明==

配置：
  WordPressify需要Node v7.5 +。這是唯一的一系列擴展。您需要下載Node。
    Node.js是基於Chrome的V8 JavaScript引擎創建的JavaScript運行時。Node.js使用事件驅動的非模塊I / O模型，從而實現輕巧高效。Node.js的生態系統npm是世界上最大的開源庫生態系統。

安裝：
  從儲存庫安裝WordPressify：
    要安裝WordPressify，您需要從GitHub克隆存儲庫：
    git clone https://github.com/AltriaMeng/WPdefense
    這將在本地計算機上克隆存儲庫。導航到新創建的文件夾。


==更新日志==

V0.1_alpha

  📦 NEW：查阅源码。
  
  📦 NEW：基本功能实现。
  
  🐛 FIX：bug修复。
  
  👌 iMPROVE:性能增强
  
  🚀 RELEASE：备份所有 defense 文件上传的构建文件
  

==后续开发计划==

此次发布版本为WPdefense0.1_alpha：

  之后的版本发布分为四个周期，每个周期的更新迭代预计时间为2-3周

WPdefense0.2：

  对于本插件进一步的可行性分析，确定其主要方向。

WPdefense0.5：

  解决其架构核心内容，确定其整体结构。

WPdefense0.9：

  完整核心功能，对结构进行优化调整，并对于项目进行常规Debug，解决大框架中的常识性问题。

WPdefense1.0：

  发布项目，并加入用户反馈内容，宏观调控项目。


==常见问题==

从储存库安装WPdefense:
  要安装WPdefense,需从GitHub克隆储存库：
  git clone https://github.com/AltriaMeng/WPdefense/new/main
  
 Windows用戶:
  如果您正在使用Windows,只需要配置和安装JavaScript.
  
自签名不安全的证书：
  如果您想连接到具有自签名证书（不安全）的HTTPS WordPress安裝，则需要在wp链接之前放置以下行来强制连接。
    var  apiPromise  =  WPAPI 。發現（ 'http://my-site.com'  ）;
  
稳定性不足：
  等待后续版本更新。
  

==许可证信息==

  许可证：
  MIT License

  Copyright (c) 2020 ChaoYuYang

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:
  
  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
