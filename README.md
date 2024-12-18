# 计网编程：实现Tracert程序

## 要求
- 采用C语言，调用ws2 32.lib
- 最好能增加一个原来没有的功能

## 参考实现
- https://blog.csdn.net/wangjiannuaa/article/details/6105678
- https://blog.csdn.net/chenpuo/article/details/118254016

## 运行
- 编译[*(参考)*](#compile-error)
    ```shell
    gcc .\mytracert.c -o mytrace.exe -l ws2_32
    ```
- 运行
    ```shell
    ./mytrace.exe <ip or domain name>
    ```
- 如果出现超时（所有尝试均为`*`），解决方案见[*防火墙超时问题*](#timeout)

## 可能出现的问题

- **编译时报错**<a id='compile-error'></a>
    代码中本应当使用`#pragma comment(lib, "ws2_32.lib")`进行库链接，但由于笔者环境，编译时报错。因此这里使用手动链接
    ```shell
    gcc .\mytracert.c -o mytrace.exe -l ws2_32
    ```

- **防火墙超时问题**<a id='timeout'></a>
    运行时可能出现超时：
    ```shell
    PS D:...\MyTracert> .\mytrace.exe baidu.com
    Tracing route to baidu.com(39.156.66.10) [max 30 hops]:
    1      *       *       *       Request timed out
    ...
    17      *       *       *       Request timed out
    18      < 1 ms  16 ms   < 1 ms  11001   39.156.66.10    [unknown]
    Trace Route Complete!
    ```
    由于原始套接字被防火墙限制，因此会出现超时。
    
    参考[博客](https://candinya.com/posts/write-a-route-tracing-tool-on-windows/#%E8%A7%A3%E5%86%B3%E5%8C%85%E8%B6%85%E6%97%B6%E9%97%AE%E9%A2%98)以及[Readme](https://crates.io/crates/tracert)，通过以下方案解决：

    使用管理员权限打开命令提示符(cmd)，输入以下命令允许`ICMPv4`或`ICMPv6`：
    ```shell
    # 允许ICMPv4
    netsh advfirewall firewall add rule name="All ICMP v4" dir=in action=allow protocol=icmpv4:any,any
    # 删除规则
    netsh advfirewall firewall delete rule name="All ICMP v4"

    # 允许ICMPv6
    netsh advfirewall firewall add rule name="All ICMP v6" dir=in action=allow protocol=icmpv6:any,any
    # 删除规则
    netsh advfirewall firewall delete rule name="All ICMP v6"
    ```

- **接收回复包长度参数问题**
    代码中使用`recv_size = recvfrom(sockfd, recv_data, MAX_PACKET_SIZE, 0, (struct sockaddr*)from_addr, &addr_len);`进行接收。其中最后一个参数`int *fromlen`注意是指针，需要使用`&addr_len`。

    注意这里不能使用`sizeof(from_addr)`或`sizeof(struct sockaddr)`，否则`recvfrom`会报错，`WSAGetLastError() == 10014`。

    参考：https://stackoverflow.com/questions/26418115/c-udp-recvfrom-wsagetlasterror-10014

- **回复包解析问题**
    注意在进行回复包解析时，需要跳过`IP`头部，只需要解析`ICMP`头部即可。
    ```c
    unsigned short ip_header_len = (recv_buf[0] & 0x0f) * 4;
    recv_data = (ICMP_DATA*)(recv_buf + ip_header_len);
    ```



