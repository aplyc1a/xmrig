# XMRig

Forked from https://github.com/xmrig/xmrig 增强了一定的隐身性。

编译：

```shell
find ./ -type f -exec sed -i "s/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/自己的钱包地址/g" {} \;
```

mkdir -p xmrig/build && cd xmrig/build

cmake ..; make
