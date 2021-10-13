## ipfs 端口转发 https://github.com/ipfs/go-ipfs/blob/master/docs/experimental-features.md#ipfs-p2p

```shell
## 1.启动ipfs守护进程
ipfs daemon

## 2. 启动ipfs 体验特效 p2p 
ipfs config --json Experimental.Libp2pStreamMounting true

## 3. 在一个内网的server 节点启动ssh 22端口监听
ipfs p2p listen /x/ssh /ip4/127.0.0.1/tcp/22

## 4. 在需要进行ssh 链接的客户端节点，将远程的端口映射到本地
ipfs p2p forward /x/ssh /ip4/127.0.0.1/tcp/2222 /p2p/$SERVER_ID

## 5. 本地使用 ssh进行连接测试
ssh root@127.0.0.1 -p 2222

```
