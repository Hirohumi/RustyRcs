# RustyRcs
A Demo App for rust-rcs-client library.

See:

https://github.com/Hirohumi/rust-rcs-client

## Prerequisite 前置条件

For this demo App to function properly, you will need system privilege. Normally it is done through privapp-permissions.xml while compiling the system image. But you can also use a rooted device and install the app under /system/priv-app/.

因为 AKA 鉴权需要使用 SIM 芯片通道，你必须要给这个 App 提供对应的系统权限，否则无法登录。一般来说都是厂商自己去改 permissions 白名单，但用 root 过的机器，把应用 push 到 /system/priv-app/ 底下让它自动安装也行。

## How to use 如何使用

You will need to compile rust-rcs-client and copy the result librust_rcs_client.so into the corresponding folder.

编译 rust-rcs-client，把结果拷贝到对应目录。

For arm64 Android, the path is

arm64 的库放到

```
app/src/main/cpp/libs/arm64-v8a/rust_rcs/lib/
```

For armeabi-v7 Android, the path is

armeabi 的库放到

```
app/src/main/cpp/libs/armeabi-v7a/rust_rcs/lib/
```

You also need to write a values xml for the SIM card info you are using. Like this:

另外再编写一个 values xml，手机上用哪张 SIM 卡就写哪张的信息。类似这样：

```
<resources>
    <integer name="mcc">your country code</integer>
    <integer name="mnc">your network code</integer>
    <string name="imsi" translatable="false">your imsi</string>
    <string name="imei" translatable="false">your imei</string>
    <string name="msisdn" translatable="false">your msisdn (with the plus sign)</string>
    <string name="to_msisdn" translatable="false">peer msisdn (with the plus sign)</string>
</resources>
```

Put it in

把它放在

```
app/src/main/res/values/
```

Normally a real RCS client would be reading these info out of TelephonyManager, but this is a Demo App after all.

一般来说真正的 RCS 客户端是直接从 TelephonyManager 读这些信息的，不过这里就懒一点好了。

## How does it work 它是如何工作的

An RCS subscription have a lifecycle like this:

RCS 订阅服务的生命周期基本上是这样的

```
INIT -> CONFIGED -> CONNECTED -> CONFIGED -> DISPOSED
```

Press the Init button and the RCS client will start its auto-config process, normally it would take a while for first time configuration.

点击 UI 上的 Init 按钮客户端就会开始自动配置流程，首次配置会花点时间因为涉及到收取 Otp 短信之类的。

When you see the following log, that means the RCS client is successfully configured.

如果看到下面的日志，证明自动配置成功了。

```
onConfigResult:0
```

Then press the Connect button and the client will connect itself to the RCS network, look for the following log to indicate successful registration.

然后再点击 Connect 按钮进行注册，看到以下日志证明注册成功：

```
onStateChange:1
```

Then you can send messages, search for chatbots and do whatever you want. See logs for operation detail.

然后你就可以正常发消息，上传文件，查找 Chatbot 之类的了。具体运行结果看日志。

## Contact

If you have any doubt, contact lydian.ever@gmail.com or QQ:364123445

如有疑问，欢迎联系
