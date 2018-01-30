# AOSHook

A hook framework based on [Libiegou](https://github.com/zhengmin1989/TheSevenWeapons/tree/master/LiBieGou), [adbi](https://github.com/crmulliner/adbi) and [Android-Inline-Hook](https://github.com/ele7enxxh/Android-Inline-Hook).

What I have modifed is written in [this blog](https://www.nevermoe.com/?p=854#more-854).


# Usage

1. modify the jni/inject.c file. You can hook functions both by address or by the function's name:

```
    static struct hook_t eph1;
    static struct hook_t eph_sendto;
    ...
    ...
    
    hook_by_addr(&eph1, "libc.so", target_addr, hook_func1);
    
    hook_by_name(&eph_sendto, "libc.so", "sendto", hook_sendto);
```
    
2. ndk-build

3. push the `stalker` and `libinject.so` file to your android (please push to /data/local/tmp)

4. On android, type `./stalker [pid]`.
