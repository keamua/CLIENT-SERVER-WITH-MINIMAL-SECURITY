# CLIENT-SERVER-WITH-MINIMAL-SECURITY
NKU2021春季算法安全协议第三次作业  
客户端-服务器 微型安全协议
FEATURES 
特性
Server – Client application: 
服务器-客户端 应用
You will implement a simple UDP client – server application, where a server transmits a file to a client after the client successfully logs in by using a password. 
完成一个简单的UDP客户端-服务器应用，用服务器来给成功输入密码登录的客户端传输文件。
Requirements: 
要求
There are two pieces of code you have to implement in two different files – a client and a server. Below is the protocol specification which will give you the details you need to implement these two programs. Also, we are giving you the packet format, which specifies the content of the messages the client and server will exchange. Your implementation must work correctly even when the client and server run on architectures with different endian formats. 
必须在两个不同的文件中实现两段代码—客户端和服务器。下面是协议规范，提供了实现这两个程序所需的详细信息。此外，还有提供了数据包格式，指定了客户端和服务器将交换的消息的内容。即使客户机和服务器在具有不同endian格式的体系结构上运行，实现也必须正常工作。

Protocol Specification: 
协议规范

a. The client sends a JOIN_REQ packet to initiate communication with the server. 
b. The server responds with a PASS_REQ packet, which is a password request to the user. 
c. The client will send a PASS_RESP packet to the server which includes the password 
d. The server will verify the password and in case the password is correct, the server will send a PASS_ACCEPT packet to the client. 
e. In case the password is incorrect, the server sends a PASS_REQ packet again to the client. The PASS_REQ packet will be retransmitted at most three times. After the third time, the server sends a REJECT message to the client. The client closes the session, and the server exits as well. 
f. Once the server transmits the PASS_ACCEPT packet to the client, the server begins transmitting the file using DATA packets. The file is broken into several segments (depending on the size of the file), and each segment is transmitted using a DATA packet. 
g. When the server completes sending the file, it will transmit a TERMINATE packet which marks the end of the file download. Included in this packet, there is a file digest (SHA1 digest) that the client will use to verify the integrity of the received file. 
a客户端发送一个JOIN_REQ数据包来启动与服务器的通信。
b服务器用PASS_REQ数据包响应，这是对用户要求密码输入。
c客户端将向服务器发送PASS_RESP数据包，其中包括密码
d服务器将验证密码，如果密码正确，服务器将向客户端发送PASS_ACCEPT数据包。
e如果密码不正确，服务器会再次向客户。PASS_REQ数据包最多重传三次。之后第三次，服务器向客户端发送拒绝消息。客户端关闭会话，服务器也会退出。
f一旦服务器将PASS_ACCEPT数据包传输到客户机，服务器就开始了使用数据包传输文件。文件被分成几个部分（取决于文件的大小），并且每个段都使用数据包。
g当服务器发送完文件后，它将发送一个终止包，这标志着文件下载的结束。在这个包中，有一个文件摘要（SHA1 digest）客户端将用来验证所接收文件的完整性。
 

Assumptions 
假设
You may make the following assumptions to simplify the design: 
你可以用下面这些假设来简化设计
a. The server handles only one client at a time. There is no need to address issues associated with supporting multiple simultaneous clients. You will not need to use select/threads in this assignment. 
b. Dealing with losses: We are using UDP-based data communication. While packet losses are possible with UDP, they are rare in a LAN environment such as the one where your code will be running on, and you will in all likelihood not encounter packet loss. There is no need for your code to implement any mechanism such as ACK/retransmission for reliable data delivery. However, in the event that a packet loss does occur, this will lead to gaps in data sequence numbers, or unexpected packets being received. In such cases, your code should exit gracefully.
a服务器一次只能处理一个客户端。不需要解决与支持多个同时客户端相关的问题。您不需要在此任务中使用线程。
b处理丢失：我们使用基于UDP的数据通信。虽然UDP可能会导致数据包丢失，但在局域网环境（例如代码将在其上运行的环境）中，这种情况很少见，而且您很可能不会遇到数据包丢失。您的代码不需要实现任何机制（如ACK/重传）来实现可靠的数据传递。然而，在发生数据包丢失的情况下，这将导致数据序列号中的间隔，或者接收到意外的数据包。在这种情况下，您的代码应该正确地退出。

Packet Formats 
包的格式
The picture shows the formats of the various packets. Some notes: 
这个图片展示了各种包的格式，一些概念
a. All packets have a 2 byte packet type, and 4 byte payload length. 
b. The packet types are as follows: JOIN_REQ: 1, PASS_REQ: 2, PASS_RESP: 3, PASS_ACCEPT: 4, DATA: 5, TERMINATE: 6, REJECT: 7 
c. For the JOIN_REQ, PASS_REQ, PASS_ACCEPT and REJECT messages, the payload length is 0. For the PASS_RESP message, the payload length is the length of the password, for the TERMINATE message, the payload length is the length of the SHA digest, and for the DATA packet, the payload length is the number of bytes of the data segment you are transmitting. 
d. Note that the payload length of DATA does not include the packet ID. 
a 所有的包用两个字节来表示类型，4个字节表示负载长度
b 有下面的这些类型JOIN_REQ: 1, PASS_REQ: 2, PASS_RESP: 3, PASS_ACCEPT: 4, DATA: 5, TERMINATE: 6, REJECT: 7 
c 对于JOIN_REQ, PASS_REQ, PASS_ACCEPT 和REJECT这四种包，负载长度为0，对于PASS_RESP包，负载长度是密码的长度，对于TERMINATE包是SHA摘要的长度，对于DATA包，负载长度是正在传输的数据段的字节数
d 注意DATA类型的包的负载长度不包括包的id。
 
Command Line Arguments:
命令行参数

Your server and client code must be executed from the command line as follows: 
设计的服务器端和客户端代码必须能够按照下面的命令行进行执行
./server <server port> <password> <input file> 

The password corresponds to the correct password the client has to transmit in order for the server to consider a valid login. The input file is the path to the file that the server will send to the client. 
密码对应于客户端必须传输的正确密码，以便服务器考虑有效登录。输入文件是服务器将发送到客户端的文件的路径。

./client <server name> <server port> <clientpwd1> <clientpwd2> <clientpwd3> <output file> 

The three passwords correspond to the passwords used in each of the three attempts the client uses to login. Note that once a correct password is transmitted, no further login attempts are needed and the remaining password entries are ignored. The output file argument is the file name to assign to the file the server will send to the client. 
这三个密码对应于客户端三次登录尝试中每次使用的密码。请注意，一旦传输了正确的密码，就不需要再次尝试登录，其余的密码条目将被忽略。output file参数是要分配给服务器将发送给客户端的文件的文件名。

Output messages: 
输出信息

You must print to the screen (STDOUT) the messages “OK” or “ABORT” depending on whether your application finishes correctly or terminate unexpectedly. Note that this information must be printed by both the client and the server programs. 
a. Print the message “OK” in case your application finishes correctly. This is the case when the server is able to completely send the file to the client and the digest sent by the server matches the digest of the file received by the client. 
b. Print the message “ABORT” in case an error occurs. Two examples of erroneous situations are:
(i) the digest of the file the client receives differs from the digest sent by the server; 
(ii) the client or server receives an unexpected packet
您必须在屏幕（STDOUT）上打印消息“OK”或“ABORT”，这取决于您的应用程序是正确完成还是意外终止。请注意，此信息必须由客户端和服务器程序打印。
a如果应用程序正确完成，请打印消息“确定”。当服务器能够将文件完全发送到客户机，并且服务器发送的摘要与客户机接收的文件摘要相匹配时，就是这种情况。
b如果发生错误，打印消息“ABORT”。错误情况的两个例子是：
（i） 客户端接收的文件摘要与服务器发送的文件摘要不同；
（ii）客户端或服务器接收到意外数据包
