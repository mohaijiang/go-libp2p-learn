# p2p ssh app with libp2p 

This program demonstrates a simple p2p chat application. You will learn how to discover a peer in the network, connect to it and open a tcp stream.

## Build

From the `01p2pssh` directory run the following:

```
> cd 01p2pssh/
> go build -o p2pssh
```

## Usage

Use two different terminal windows to run

参数说明

```
## 参数说明；
##   -l 本地p2p端口
##   -L 本地端口提供映射
##   -d 链接到的relay节点
##   -p relay 节点的peerId
##   -F 映射到本地的端口
##   -P circuit 代理的peerId, 即需要转发的节点的peerid 

## 启动nat 代理节点
./p2pssh -l 10000
## 启动端口提供节点 
./p2pssh -l 10001 -L 1022 -d /ip4/127.0.0.1/tcp/10000 -p QmfBiPjVZ2FGaU33Nw134VJtruAq8X3hAjGc3f8uGif3Y3
## 启动端口转发本地服务
./p2pssh -l 10002 -F 9000 -P QmeSLxtLXp3sLXWLDHnPGDX9atergzof8mTM3ZnFATwafm -d /ip4/127.0.0.1/tcp/10000 -p QmfBiPjVZ2FGaU33Nw134VJtruAq8X3hAjGc3f8uGif3Y3