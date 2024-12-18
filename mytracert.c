#define WIN32_LEAN_AND_MEAN

#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#define RET_CODE int
#define CORRECT_CODE 0
#define ERROR_CODE -1
#define TIME_OUT_CODE -2
#define COMPLETE_CODE 1
#define HOSTNAME_ERROR_CODE -3

#define MAX_HOP 30 // 最大跳数
#define MAX_TRY 3  // 最大尝试次数

#define MAGIC_LEN 10
#define MAX_PACKET_SIZE 1024 // Max ICMP packet size

#define ICMP_ECHO_TYPE 8 // ICMP Echo报文类型
#define ICMP_ECHO_CODE 0 // ICMP Echo报文代码
#define ICMP_TIMEOUT 11  // ICMP Timeout报文类型
#define ICMP_ECHOREPLY 0 // ICMP Echo Reply报文类型
#define ICMP_UNREACH 3   // ICMP Unreachable报文类型

// #pragma comment(lib, "ws2_32.lib")
// 环境问题，编译时显式链接
// gcc .\mytracert.c -o mytrace.exe -l ws2_32

typedef struct icmp_data {
    // header
    BYTE type;
    BYTE code;
    WORD checksum; // 校验和
    WORD id;       // 标识符
    WORD seq;      // 序列号

    // data
    char magic_str[MAGIC_LEN]; // 任意数据
} ICMP_DATA;

// 校验和计算函数
unsigned short calculate_checksum(unsigned short* buf, int size) {
    unsigned long sum = 0; // 可能进位，使用long类型，防止溢出
    while (size > 1) {
        sum += *buf;
        buf++;
        size -= sizeof(unsigned short);
    }
    if (size == 1) { // 最后一个字节单独处理
        sum += *(unsigned char*)buf;
    }
    // 计算可能的进位
    unsigned long carry = sum >> 16;
    while (carry) {
        sum = (sum & 0xffff) + carry;
        carry = sum >> 16;
    }
    return (~sum) & 0xffff;
}

RET_CODE resolve_host(struct sockaddr_in* dest_addr, char* ip, char* hostname, char* input_param) {
    struct addrinfo hints, *res;
    int ret_code;

    memset(dest_addr, 0, sizeof(struct sockaddr_in));
    dest_addr->sin_family = AF_INET;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;       // 只支持 IPv4 地址
    hints.ai_socktype = SOCK_STREAM; // TCP 套接字类型

    // 解析主机名
    ret_code = getaddrinfo(input_param, NULL, &hints, &res);
    if (ret_code != 0) {
        printf("getaddrinfo failed: %s\n", gai_strerror(ret_code));
        return ERROR_CODE;
    }

    // 遍历 addrinfo 链表，获取第一个有效的 IPv4 地址
    struct sockaddr_in* sockaddr_ipv4 = (struct sockaddr_in*)res->ai_addr;
    dest_addr->sin_addr = sockaddr_ipv4->sin_addr;

    // 获取字符串形式的 IP 地址
    if (inet_ntop(AF_INET, &dest_addr->sin_addr, ip, INET_ADDRSTRLEN) == NULL) {
        printf("\rinet_ntop() failed\n");
        freeaddrinfo(res);
        return ERROR_CODE;
    }
    freeaddrinfo(res);

    // 获取主机名
    ret_code = getnameinfo((struct sockaddr*)dest_addr, sizeof(*dest_addr), hostname, NI_MAXHOST, NULL, 0, NI_NAMEREQD);
    if (ret_code != 0) {
        printf("Hostname resolution failed: %d\n", ret_code);
        return HOSTNAME_ERROR_CODE;
    }
    return CORRECT_CODE;
}

// 创建套接字函数
SOCKET create_socket() {
    int ret_code;

    SOCKET sockfd = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (sockfd == INVALID_SOCKET) {
        printf("WSASocket() failed: %d\n", WSAGetLastError());
        return INVALID_SOCKET;
    }

    int timeout = 1000; // 超时时间
    ret_code = setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    if (ret_code == SOCKET_ERROR) {
        printf("setsockopt(SO_RCVTIMEO) failed: %d\n", WSAGetLastError());
        return INVALID_SOCKET;
    }
    ret_code = setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
    if (ret_code == SOCKET_ERROR) {
        printf("setsockopt(SO_SNDTIMEO) failed: %d\n", WSAGetLastError());
        return INVALID_SOCKET;
    }

    return sockfd;
}

// 发送ICMP请求包函数
RET_CODE send_recv_icmp(SOCKET sockfd, int seq, struct sockaddr_in* dest_addr, int ttl, char* recv_data, struct sockaddr_in* from_addr, DWORD* send_timestamp, DWORD* recv_timestamp) {
    int ret_code;
    int addr_len = sizeof(struct sockaddr_in); // 见README.md

    ret_code = setsockopt(sockfd, IPPROTO_IP, IP_TTL, (char*)&ttl, sizeof(ttl));
    if (ret_code == SOCKET_ERROR) {
        printf("\rsetsockopt(IP_TTL) failed: %d\n", WSAGetLastError());
        return ERROR_CODE;
    }

    // 创建ICMP数据包
    char* icmp_buf = (char*)malloc(sizeof(ICMP_DATA));
    if (icmp_buf == NULL) {
        printf("\rmalloc(ICMP_DATA) failed\n");
        return ERROR_CODE;
    }
    ICMP_DATA* icmp_data = (ICMP_DATA*)icmp_buf;
    icmp_data->type = ICMP_ECHO_TYPE;             // ICMP echo request
    icmp_data->code = ICMP_ECHO_CODE;             // ICMP echo request code
    icmp_data->checksum = 0;                      // 后续计算
    icmp_data->id = GetCurrentProcessId();        // 标识符
    icmp_data->seq = seq;                         // 序列号
    memset(icmp_data->magic_str, 'A', MAGIC_LEN); // 任意数据
    icmp_data->checksum = calculate_checksum((unsigned short*)icmp_data, sizeof(ICMP_DATA));

    // 发送ICMP数据包
    int send_size, recv_size;
    *send_timestamp = GetTickCount(); // 发送包的起始时间
    send_size = sendto(sockfd, icmp_buf, sizeof(ICMP_DATA), 0, (struct sockaddr*)dest_addr, sizeof(struct sockaddr_in));
    if (send_size == SOCKET_ERROR) {
        if (WSAGetLastError() == WSAETIMEDOUT) {
            return TIME_OUT_CODE;
        }
        printf("\rsendto() failed: %d\n", WSAGetLastError());
        return ERROR_CODE;
    }
    if (send_size < sizeof(ICMP_DATA)) {
        printf("\rsendto() sent only %d bytes\n", send_size);
        return ERROR_CODE;
    }
    // 接收ICMP数据包
    recv_size = recvfrom(sockfd, recv_data, MAX_PACKET_SIZE, 0, (struct sockaddr*)from_addr, &addr_len);
    *recv_timestamp = GetTickCount();
    if (recv_size == SOCKET_ERROR) {
        if (WSAGetLastError() == WSAETIMEDOUT) {
            return TIME_OUT_CODE;
        }
        printf("\rrecvfrom() failed: %d\n", WSAGetLastError());
        return ERROR_CODE;
    }
    return CORRECT_CODE;
}

// 打印结果
void display_time(DWORD time) {
    if (time < 1) {
        printf("< 1");
    } else {
        printf("%d", time);
    }
    printf(" ms\t");
}
RET_CODE display_ip_hostname(struct sockaddr_in* from_addr) {
    char ip_str[INET_ADDRSTRLEN];
    char hostname[NI_MAXHOST];
    int ret_code;

    if (inet_ntop(AF_INET, &from_addr->sin_addr, ip_str, sizeof(ip_str)) == NULL) {
        printf("\rinet_ntop failed\n");
        return ERROR_CODE;
    }
    ret_code = getnameinfo((struct sockaddr*)from_addr, sizeof(*from_addr), hostname, sizeof(hostname), NULL, 0, NI_NAMEREQD);
    if (ret_code == 0) {
        printf("%s\t%s\n", ip_str, hostname);
    } else {
        printf("%s\t[unknown]\n", ip_str);
    }
    return CORRECT_CODE;
}

RET_CODE display_one_hop(SOCKET sockfd, int* seq, struct sockaddr_in* dest_addr, int ttl) {
    printf("%2d\t", ttl);

    DWORD send_timestamp, recv_timestamp;
    struct sockaddr_in from_addr;
    char recv_buf[MAX_PACKET_SIZE];
    ICMP_DATA* recv_data;
    int ret_code;
    int success_count = 0;
    int complete_count = 0;

    for (int i = 0; i < MAX_TRY; i++) {
        send_timestamp = 0;
        recv_timestamp = 0;
        *seq = *seq + 1;
        ret_code = send_recv_icmp(sockfd, *seq, dest_addr, ttl, recv_buf, &from_addr, &send_timestamp, &recv_timestamp);
        if (ret_code == TIME_OUT_CODE) {
            printf("*\t");
            continue;
        } else if (ret_code == ERROR_CODE) {
            return ERROR_CODE;
        } else { // ret_code == CORRECT_CODE
            unsigned short ip_header_len = (recv_buf[0] & 0x0f) * 4;
            recv_data = (ICMP_DATA*)(recv_buf + ip_header_len);
            success_count++;
            if (recv_data->type == ICMP_ECHOREPLY && recv_data->id == GetCurrentProcessId()) {
                complete_count = 1;
                display_time(recv_timestamp - send_timestamp);
            } else if (recv_data->type == ICMP_TIMEOUT) {
                if (recv_data->code == 0) {
                    display_time(recv_timestamp - send_timestamp);
                } else if (recv_data->code == 1) {
                    printf("\ricmp timeout with type %d, code %d(TTL equals 0 during reassembly)\n", recv_data->type, recv_data->code);
                    return ERROR_CODE;
                }
            } else if (recv_data->type == ICMP_UNREACH) {
                printf("\rDestination host is unreachable!\n");
                return ERROR_CODE;
            } else {
                printf("\ricmp packet with type %d, code %d received.\n", recv_data->type, recv_data->code);
                return ERROR_CODE;
            }
        }
        Sleep(1000); // 等待1秒
    }
    if (success_count == 0) {
        printf("Request timed out\n");
    } else {
        ret_code = display_ip_hostname(&from_addr);
        if (ret_code == ERROR_CODE) {
            return ERROR_CODE;
        }
    }
    if (complete_count == 1) {
        printf("Trace Route Complete!\n");
        return COMPLETE_CODE;
    }
    return CORRECT_CODE;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s <ip or hostname>\n", argv[0]);
        return -1;
    }
    int ret_code;

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup() failed:%d\n", GetLastError());
        return -1;
    }

    char* input_param = argv[1];
    char ip_str[INET_ADDRSTRLEN];
    char hostname[NI_MAXHOST];
    struct sockaddr_in dest_addr;
    ret_code = resolve_host(&dest_addr, &ip_str, &hostname, input_param);
    if (ret_code != CORRECT_CODE) {
        if (ret_code == HOSTNAME_ERROR_CODE) {
            snprintf(hostname, NI_MAXHOST, "%s", input_param);
        } else {
            printf("Error: resolve_host() failed\n");
            return -1;
        }
    }

    printf("Tracing route to %s(%s) [max %d hops]:\n", hostname, ip_str, MAX_HOP);

    SOCKET sockfd = INVALID_SOCKET;
    sockfd = create_socket();
    if (sockfd == INVALID_SOCKET) {
        printf("create_socket() failed\n");
        return -1;
    }

    int seq = 0;
    int ttl = 1;
    while (ttl <= MAX_HOP) {
        int ret_code = display_one_hop(sockfd, &seq, &dest_addr, ttl);
        if (ret_code == ERROR_CODE) {
            return -1;
        } else if (ret_code == COMPLETE_CODE) {
            break;
        } else { // ret_code == CORRECT_CODE
            ;
        }
        ttl++;
    }
    if (ttl > MAX_HOP) {
        printf("Too many hops, trace route failed.\n");
    }
    closesocket(sockfd);
    WSACleanup();
    return 0;
}