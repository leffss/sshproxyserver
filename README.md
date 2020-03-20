### 说明
go 语言使用 `golang.org/x/crypto/ssh` 实现的 sshproxyserver。数据流向：客户端 ----> sshproxyserver ----> 后端真实 ssh 服务器。

在此基础上可以干的事情：
- 集成到堡垒机系统中
- 实现命令审计、记录
- 其他

### MIT License
```
Copyright (c) 2020 leffss
```