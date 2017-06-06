# AOSHook

A hook framework based on [Libiegou](https://github.com/zhengmin1989/TheSevenWeapons/tree/master/LiBieGou) and [adbi](https://github.com/crmulliner/adbi).

What I have modifed is written in [this blog](https://www.nevermoe.com/?p=854#more-854).


# Usage

1. modify the jni/inject.c file. You can hook functions both by address or by the function's name:

```
    hook_by_addr(&eph1, "libc.so", 0x2ca43c, hook_thumb1, hook_arm1);
    
    hook_by_name(&eph_sendto, "libc.so", "sendto", sendto_thumb, sendto_arm);
```
    
2. ndk-build

3. push the `stalker` and `libinject.so` file to your android (e.g. push to /data/local/tmp)

4. On android, type `./stalker [pid]`.
