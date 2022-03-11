# device_soc_winnermicro

#### 介绍

##### 目录

```
device/soc/
├── wm800                                 # 芯片SOC名称
├── ...                                   # 芯片SOC名称
|
├── hals                                  # hals适配目录
│   └── console                           # 连接类接口适配目录
├── Kconfig.liteos_m.defconfig            # kconfig 默认宏配置
├── Kconfig.liteos_m.series               # W800系列soc配置宏
└── Kconfig.liteos_m.soc                  # soc kconfig配置宏
```

仓库包含编译构建脚本和打包镜像工具。

系统要求： Ubuntu18.04 64位系统版本。

编译环境搭建包含如下几步：

1. 获取源码
2. 安装的库和工具
3. 安装python3
4. 安装hb
5. 安装csky-abiv2-elf-gcc
6. 编译流程
7. 烧录打印

## 获取源码

```shell
mkdir openharmony_winnermicro

cd openharmony_winnermicro

repo init -u git@gitee.com:openharmony/manifest.git -b OpenHarmony-3.1-Beta --no-repo-verify

repo sync -c

repo forall -c 'git lfs pull'
```

## 安装的库和工具

> - 通常系统默认安装samba、vim等常用软件。

> - 使用如下apt-get命令安装下面的库和工具：

```
sudo apt-get install build-essential gcc g++ make zlib* libffi-dev e2fsprogs pkg-config flex bison perl bc openssl libssl-dev libelf-dev libc6-dev-amd64 binutils binutils-dev libdwarf-dev u-boot-tools mtd-utils gcc-arm-linux-gnueabi
```

## 安装Python3

1. 打开Linux编译服务器终端。
2. 输入如下命令，查看python版本号：

   ```
   python3 --version
   ```
   1. 运行如下命令，查看Ubuntu版本：

   ```
   cat /etc/issue
   ```

   2. ubuntu 18安装python。
   ```
   sudo apt-get install python3.8
   ```

3. 设置python和python3软链接为python3.8。

   ```
   sudo update-alternatives --install /usr/bin/python python /usr/bin/python3.8 1
   sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.8 1
   ```
4. 安装并升级Python包管理工具（pip3），任选如下一种方式。

   - **命令行方式：**

     ```
     sudo apt-get install python3-setuptools python3-pip -y
     sudo pip3 install --upgrade pip
     ```
   - **安装包方式：**

     ```
     curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
     python get-pip.py
     ```

## 安装hb
### 安装方法

1. 运行如下命令安装hb

   ```
   pip3 uninstall ohos-build # 如果安装了hb,先卸载
   pip3 install build/lite
   ```
2. 设置环境变量

   ```
   vim ~/.bashrc
   ```

   将以下命令拷贝到.bashrc文件的最后一行，保存并退出。

   ```
   export PATH=~/.local/bin:$PATH
   ```

   执行如下命令更新环境变量。

   ```
   source ~/.bashrc
   ```
3. 执行"hb -h"，有打印以下信息即表示安装成功：

   ```
   usage: hb
   
   OHOS build system
   
   positional arguments:
     {build,set,env,clean}
       build               Build source code
       set                 OHOS build settings
       env                 Show OHOS build env
       clean               Clean output
   
   optional arguments:
     -h, --help            show this help message and exit
   ```

## 安装csky-abiv2-elf-gcc

1. 打开Linux编译服务器终端。
2. 下载[csky-abiv2-elf-gcc 编译工具下载](https://occ.t-head.cn/community/download?id=3885366095506644992)
	选择下载 csky-elfabiv2-tools-x86_64-minilibc-20210423.tar。
3. 解压 csky-elfabiv2-tools-x86_64-minilibc-20210423.tar 安装包至\~/toolchain/路径下，并将解压生成的bin目录名修改为csky-elfabiv2-bin。

   ```shell
   cd toolchain
   tar zxvf csky-elfabiv2-tools-x86_64-minilibc-20210423.tar
   mv bin csky-elfabiv2-bin
   ```
4. 设置环境变量。

   ```
   vim ~/.bashrc
   ```

   将以下命令拷贝到.bashrc文件的最后一行，保存并退出。

   ```
   export PATH=~/toolchain/csky-elfabiv2-bin:$PATH
   ```
5. 生效环境变量。

   ```
   source ~/.bashrc
   ```

## 编译流程

[编译构建使用指南](https://gitee.com/openharmony/docs/blob/master/zh-cn/device-dev/subsystems/subsys-build-mini-lite.md)

```shell
hb set

hihope
 > neptune100

选择neptune100

hb build -f
```

## 烧录打印

windows下：
1. 下载PC端固件烧录工具并安装(HW Upgrade Tools) [w800串口烧录工具](https://www.winnermicro.com/html/1/156/158/558.html)。
2. 在代码根目录下执行脚本 ./device/soc/winnermicro/tools/aft_build_project.sh,会在out目录下生成 .fls文件。
3. 通过USB转接线连接PC和w800开发板,在PC的设备管理器中确认与w800连接所用的COM口。
4. 打开烧录工具(HW Upgrade Tools)，选定COM口并选择打开串口,选择固件为out目录下生成的 OHOS_Image.fls文件，勾选擦除Flash(波特率:115200,型号:W80X)。
5. 点击下载键等待烧录。
6. 烧录成功图形界面会显示 file success以及烧录成功之后的启动log,反之显示fail。
7. 打开烧录工具(HW Upgrade Tools),选择复位，可在图形界面看到板子启动log;或打开串口调试工具,RST按键启动板子,查看log。

# 相关仓

* [device/soc/winnermicro](https://gitee.com/openharmony/device_soc_winnermicro)