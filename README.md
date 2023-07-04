# RustyRcs
A Demo App for rust-rcs-client library.

See:

https://github.com/Hirohumi/rust-rcs-client

## Prerequisite 前置条件

For this demo App to function properly, you will need system privilege. Normally it is done through privapp-permissions.xml while compiling the system image. But you can also use a rooted device and install the app under /system/priv-app/.

因为 AKA 鉴权需要使用 SIM 芯片通道，你必须要给这个 App 提供对应的系统权限，否则无法登录。一般来说都是厂商自己去改 permissions 白名单，但用 root 过的机器，把应用 push 到 /system/priv-app/ 底下让它自动安装也行。

## How to use 如何使用

You will need to compile rust-rcs-client and copy the result .so libs into the corresponding folder.

编译 rust-rcs-client，把结果拷贝到对应目录。

You also need to write your own values.xml for the SIM card info you are using.

编写一个 values.xml，手机上用哪张 SIM 卡就写哪张的信息。App 初始化的时候会用到。

## Contact

If you have any doubt, contact lydian.ever@gmail.com or QQ:364123445

如有疑问，欢迎联系
