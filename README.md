# tc redirect

支持将指定pid的udp rtps报文通过ringbuf送到用户态处理, 用户态修改报文payload后, 重新发送给目的ip/端口
```shell
$ cd tc-redirect/
$ make
$ ./udp_server
$ ./udp_client
$ sudo ./tc_redirect `pgrep udp_client`
```
