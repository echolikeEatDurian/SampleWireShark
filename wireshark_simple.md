





<div align="center"><font size="40px">wireshark_simple</font></div>





# shark.Pro

``` cpp
INCLUDEPATH += D:/download/WpdPack/Include
LIBS += D:/download/WpdPack/Lib/x64/wpcap.lib  libws2_32
# 这行代码将指定的目录（D:/download/WpdPack/Include）添加到包含路径中。它允许编译器在构建项目时找到该目录中的头文件。
# 这行代码将两个库添加到项目中。D:/download/WpdPack/Lib/x64/wpcap.lib 是一个库文件，将在编译过程中链接，为项目提供额外的功能。libws2_32 是另一个库，可能用于网络相关的操作。
    
RESOURCES += \
    src.qrc
# 这行代码将指定的资源文件（src.qrc）添加到项目中。资源文件通常包含应用程序使用的非代码资源，如图像、图标或其他数据文件。
    
```

# Headers

## format.h

``` cpp
#ifndef FORMAT_H
#define FORMAT_H

/*
   @ This head file is used to define format of packages
   @ auther DJH-sudo
   @ if you have any question,pls contact me at djh113@126.com
*/

// define some types and macro defination
typedef unsigned char u_char;     // 1 byte
typedef unsigned short u_short;   // 2 byte
typedef unsigned int u_int;       // 4 byte
typedef unsigned long u_long;     // 4 byte

#define ARP  "ARP"                 //
#define TCP  "TCP"                 //
#define UDP  "UDP"                 //
#define ICMP "ICMP"                //
#define DNS  "DNS"                 //
#define TLS  "TLS"                 //
#define SSL  "SSL"                 //
// Ethernet protocol format
/*
+-------------------+-----------------+------+
|       6 byte      |     6 byte      |2 byte|
+-------------------+-----------------+------+
|destination address|  source address | type |
+-------------------+-----------------+------+
*/
typedef struct ether_header{       // 以太网帧头部，14 字节
    u_char ether_des_host[6];      // 目标 MAC 地址，6 字节
    u_char ether_src_host[6];      // 源 MAC 地址，6 字节
    u_short ether_type;            // 类型，2 字节
} ETHER_HEADER;

// Ipv4 header
/*
+-------+-----------+---------------+-------------------------+
| 4 bit |   4 bit   |    8 bit      |          16 bit         |
+-------+-----------+---------------+-------------------------+
|version|head length|  TOS/DS_byte  |        total length     |
+-------------------+--+---+---+----+-+-+-+-------------------+
|          identification           |R|D|M|    offset         |
+-------------------+---------------+-+-+-+-------------------+
|       ttl         |     protocal  |         checksum        |
+-------------------+---------------+-------------------------+
|                   source ip address                         |
+-------------------------------------------------------------+
|                 destination ip address                      |
+-------------------------------------------------------------+
*/
typedef struct ip_header{           // IP 头部结构体，20 字节
    u_char versiosn_head_length;    // 版本号和头部长度，各占 4 位
    u_char TOS;                     // TOS/DS 字节，1 字节
    u_short total_length;           // IP 数据包总长度，2 字节
    u_short identification;         // 标识，2 字节
    u_short flag_offset;            // 标志和片偏移，标志占 3 位，偏移占 13 位
    u_char ttl;                     // 生存时间（TTL），1 字节
    u_char protocol;                // 协议，1 字节
    u_short checksum;               // 校验和，2 字节
    u_int src_addr;                 // 源 IP 地址，4 字节
    u_int des_addr;                 // 目标 IP 地址，4 字节
} IP_HEADER;


// Tcp header
/*
+----------------------+---------------------+
|         16 bit       |       16 bit        |
+----------------------+---------------------+
|      source port     |  destination port   |
+----------------------+---------------------+
|              sequence number               |
+----------------------+---------------------+
|                 ack number                 |
+----+---------+-------+---------------------+
|head| reserve | flags |     window size     |
+----+---------+-------+---------------------+
|     checksum         |   urgent pointer    |
+----------------------+---------------------+
*/
typedef struct tcp_header{    // TCP 头部结构体，20 字节
    u_short src_port;         // 源端口号，2 字节
    u_short des_port;         // 目标端口号，2 字节
    u_int sequence;           // 序列号，4 字节
    u_int ack;                // 确认序列号，4 字节
    u_char header_length;     // 头部长度，占 4 位
    u_char flags;             // 标志位，占 6 位
    u_short window_size;      // 窗口大小，2 字节
    u_short checksum;         // 校验和，2 字节
    u_short urgent;           // 紧急指针，2 字节
} TCP_HEADER;

// Udp header
/*
+---------------------+---------------------+
|        16 bit       |        16 bit       |
+---------------------+---------------------+
|    source port      |   destination port  |
+---------------------+---------------------+
| data package length |       checksum      |
+---------------------+---------------------+
*/
typedef struct udp_header{ // UDP 头部结构体，8 字节
    u_short src_port;      // 源端口号，2 字节
    u_short des_port;      // 目标端口号，2 字节
    u_short data_length;   // 数据长度，2 字节
    u_short checksum;      // 校验和，2 字节

} UDP_HEADER;
// Icmp header
/*
+---------------------+---------------------+
|  1 byte  |  1 byte  |        2 byte       |
+---------------------+---------------------+
|   type   |   code   |       checksum      |
+---------------------+---------------------+
|    identification   |       sequence      |
+---------------------+---------------------+
|                  option                   |
+-------------------------------------------+
*/
typedef struct icmp_header{         // ICMP 头部结构体，至少 8 字节
    u_char type;                    // 类型，1 字节
    u_char code;                    // 代码，1 字节
    u_short checksum;               // 校验和，2 字节
    u_short identification;         // 标识符，2 字节
    u_short sequence;               // 序列号，2 字节
} ICMP_HEADER;

//Arp
/*
|<--------  ARP header  ------------>|
+------+--------+-----+------+-------+----------+---------+---------------+--------------+
|2 byte| 2 byte |1byte| 1byte|2 byte |  6 byte  | 4 byte  |     6 byte    |     4 byte   |
+------+--------+-----+------+-------+----------+---------+---------------+--------------+
| type |protocol|e_len|ip_len|op_type|source mac|source ip|destination mac|destination ip|
+------+--------+-----+------+-------+----------+---------+---------------+--------------+
*/
typedef struct arp_header{   // ARP 头部结构体，28 字节
    u_short hardware_type;   // 硬件类型，2 字节
    u_short protocol_type;   // 协议类型，2 字节
    u_char mac_length;       // MAC地址长度，1 字节
    u_char ip_length;        // IP地址长度，1 字节
    u_short op_code;         // 操作码，2 字节

    u_char src_eth_addr[6];  // 源以太网地址，6 字节
    u_char src_ip_addr[4];   // 源IP地址，4 字节
    u_char des_eth_addr[6];  // 目标以太网地址，6 字节
    u_char des_ip_addr[4];   // 目标IP地址，4 字节

} ARP_HEADER;
// dns
/*
+--------------------------+---------------------------+
|           16 bit         |1b|4bit|1b|1b|1b|1b|3b|4bit|
+--------------------------+--+----+--+--+--+--+--+----+
|      identification      |QR| OP |AA|TC|RD|RA|..|Resp|
+--------------------------+--+----+--+--+--+--+--+----+
|         Question         |       Answer RRs          |
+--------------------------+---------------------------+
|     Authority RRs        |      Additional RRs       |
+--------------------------+---------------------------+
*/
typedef struct dns_header{  // DNS 头部结构体，12 字节
    u_short identification; // 标识，2 字节
    u_short flags;          // 标志位，总共 2 字节
    u_short question;       // 问题数，2 字节
    u_short answer;         // 回答资源记录数，2 字节
    u_short authority;      // 授权资源记录数，2 字节
    u_short additional;     // 附加资源记录数，2 字节
} DNS_HEADER;

// dns question
typedef struct dns_question {
    // char* name;          // 非固定长度
    u_short query_type;     // 查询类型，2 字节
    u_short query_class;    // 查询类，2 字节
} DNS_QUESTION;

typedef struct dns_answer {
    // char* name;           // 非固定长度
    u_short answer_type;    // 回答类型，2 字节
    u_short answer_class;   // 回答类，2 字节
    u_int TTL;              // 生存时间，4 字节
    u_short dataLength;     // 数据长度，2 字节
    // char* name;           // 非固定长度
} DNS_ANSWER;

#endif // FORMAT_H



```





## capture.h

``` cpp
#ifndef CAPTURE_H
#define CAPTURE_H

#include <QThread>          // 包含QThread库，用于多线程操作
#include <Format.h>         // 包含Format.h头文件
#include <QQueue>           // 包含QQueue库，用于队列操作
#include "pcap.h"           // 包含pcap库，用于抓包操作
#include <QString>          // 包含QString库，用于处理字符串
#include "winsock2.h"       // 包含winsock2库，用于网络编程
#include "datapackage.h"    // 包含datapackage.h头文件

class Capture : public QThread
{
     Q_OBJECT                 // 宏，用于支持信号和槽机制
public:
    Capture();               // 构造函数
    bool setPointer(pcap_t *pointer);  // 设置指针
    void setFlag();          // 设置标志
    void resetFlag();        // 重置标志
    int ethernetPackageHandle(const u_char *pkt_content, QString &info);  
    // 处理以太网数据包
    int ipPackageHandle(const u_char *pkt_content, int &ipPackage);        
    // 处理IP数据包
    QString arpPackageHandle(const u_char *pkt_content);                  
    // 处理ARP数据包
    QString icmpPackageHandle(const u_char *pkt_content);                  
    // 处理ICMP数据包
    int tcpPackageHandle(const u_char *pkt_content, QString &info, int ipPackage);  // 处理TCP数据包
    int udpPackageHandle(const u_char *pkt_content, QString &info);        
    // 处理UDP数据包
    QString dnsPackageHandle(const u_char *pkt_content);                  
    // 处理DNS数据包
protected:
    static QString byteToHex(u_char *str, int size);                       
    // 将字节数组转换为十六进制字符串
    void run();                                                            
    // 重写run函数，用于多线程运行

signals:
    void send(DataPackage data);                                           
    // 发送信号，传递DataPackage对象

private:
    pcap_t *pointer;                                                      
    // pcap指针
    struct pcap_pkthdr *header;                                           
    // 抓包的包头
    const u_char *pkt_data;                                               
    // 抓到的数据包内容
    time_t local_time_version_sec;                                         
    // 本地时间秒
    struct tm local_time;                                                 
    // 本地时间结构
    char timeString[16];                                                   
    // 时间字符串
    volatile bool isDone;                                                  
    // 完成标志
};
#endif // CAPTURE_H
```



## data_package.h

``` cpp
#ifndef DATAPACKAGE_H
#define DATAPACKAGE_H

#include <QString>
#include "Format.h"


/*
 * This class is describe the data package infomation
 * +-----+------------+
 * | type| infomation |
 * +-----+------------+
 * |  1  |    arp     |
 * +-----+------------+
 * |  2  |    icmp    |
 * +-----+------------+
 * |  3  |    tcp     |
 * +-----+------------+
 * |  4  |    udp     |
 * +-----+------------+
 * |  5  |    dns     |
 * +-----+------------+
 * |  6  |    tls     |
 * +-----+------------+
 * |  7  |    ssl     |
 * +-----+------------+
*/
class DataPackage
{
private:
    u_int data_length; // data pakage length
    QString timeStamp; // timestamp of package
    QString info;      // a breif introduction of package
    int packageType;   // type

public:
    const u_char *pkt_content; // root pointer of package data

protected:
    /*
     * turn the byteArray to QString
    */
    static QString byteToHex(u_char*str,int size);
public:
    // Construction and destruction
    DataPackage();
    ~DataPackage() = default;

    // set the var
    void setDataLength(unsigned int length);                    // set the package length
    void setTimeStamp(QString timeStamp);                       // set timestamp
    void setPackageType(int type);                              // set package type
    void setPackagePointer(const u_char *pkt_content,int size); // set package pointer
    void setPackageInfo(QString info);                          // set package information

    // get the var
    QString getDataLength();                  // get package length
    QString getTimeStamp();                   // get timestamp
    QString getPackageType();                 // get package type
    QString getInfo();                        // get a breif package information
    QString getSource();                      // get the source address of package
    QString getDestination();                 // get the destination address of package

    // get the mac info
    QString getDesMacAddr();                  // get the destination MAC address
    QString getSrcMacAddr();                  // get the source MAC address
    QString getMacType();                     // get the type of MAC address

    // get the ip info
    QString getDesIpAddr();                   // get the destination ip address
    QString getSrcIpAddr();                   // get the source ip address
    QString getIpVersion();                   // get the ip version
    QString getIpHeaderLength();              // get the ip head length
    QString getIpTos();                       // get the ip tos
    QString getIpTotalLength();               // get the ip total package length
    QString getIpIdentification();            // get the ip identification
    QString getIpFlag();                      // get the ip flag
    QString getIpReservedBit();               // the reserved bit
    QString getIpDF();                        // Don't fragment
    QString getIpMF();                        // More fragment
    QString getIpFragmentOffset();            // get the offset of package
    QString getIpTTL();                       // get ip ttl [time to live]
    QString getIpProtocol();                  // get the ip protocol
    QString getIpCheckSum();                  // get the checksum

    // get the icmp info
    QString getIcmpType();                    // get the icmp type
    QString getIcmpCode();                    // get the icmp code
    QString getIcmpCheckSum();                // get the icmp checksum
    QString getIcmpIdentification();          // get the icmp identification
    QString getIcmpSequeue();                 // get the icmp sequence
    QString getIcmpData(int size);            // get the icmp data

    // get the arp info
    QString getArpHardwareType();             // get arp hardware type
    QString getArpProtocolType();             // get arp protocol type
    QString getArpHardwareLength();           // get arp hardware length
    QString getArpProtocolLength();           // get arp protocol length
    QString getArpOperationCode();            // get arp operation code
    QString getArpSourceEtherAddr();          // get arp source ethernet address
    QString getArpSourceIpAddr();             // get arp souce ip address
    QString getArpDestinationEtherAddr();     // get arp destination ethernet address
    QString getArpDestinationIpAddr();        // get arp destination ip address

    // get the tcp info
    QString getTcpSourcePort();               // get tcp source port
    QString getTcpDestinationPort();          // get tcp destination port
    QString getTcpSequence();                 // get tcp sequence
    QString getTcpAcknowledgment();           // get acknowlegment
    QString getTcpHeaderLength();             // get tcp head length
    QString getTcpRawHeaderLength();          // get tcp raw head length [default is 0x05]
    QString getTcpFlags();                    // get tcp flags
    QString getTcpPSH();                      // PSH flag
    QString getTcpACK();                      // ACK flag
    QString getTcpSYN();                      // SYN flag
    QString getTcpURG();                      // URG flag
    QString getTcpFIN();                      // FIN flag
    QString getTcpRST();                      // RST flag
    QString getTcpWindowSize();               // get tcp window size
    QString getTcpCheckSum();                 // get tcp checksum
    QString getTcpUrgentPointer();            // get tcp urgent pointer
    QString getTcpOperationKind(int kind);    // get tcp option kind
    int getTcpOperationRawKind(int offset);   // get tcp raw option kind

    /*
     * tcp optional parts
    */
    bool getTcpOperationMSS(int offset,u_short& mss);                          // kind = 2
    bool getTcpOperationWSOPT(int offset,u_char&shit);                         // kind = 3
    bool getTcpOperationSACKP(int offset);                                     // kind = 4
    bool getTcpOperationSACK(int offset,u_char&length,QVector<u_int>&edge);    // kind = 5
    bool getTcpOperationTSPOT(int offset,u_int& value,u_int&reply);            // kind = 8

    // get the udp info
    QString getUdpSourcePort();               // get udp source port
    QString getUdpDestinationPort();          // get udp destination port
    QString getUdpDataLength();               // get udp data length
    QString getUdpCheckSum();                 // get udp checksum

    // get the dns info
    QString getDnsTransactionId();            // get dns transaction id
    QString getDnsFlags();                    // get dns flags
    QString getDnsFlagsQR();                  // get dns flag QR
    QString getDnsFlagsOpcode();              // get dns flag operation code
    QString getDnsFlagsAA();                  // get dns flag AA
    QString getDnsFlagsTC();                  // get dns flag TC
    QString getDnsFlagsRD();                  // get dns flag RD
    QString getDnsFlagsRA();                  // get dns flag RA
    QString getDnsFlagsZ();                   // get dns flag Z [reserved]
    QString getDnsFlagsRcode();               // get dns flag Rcode
    QString getDnsQuestionNumber();           // get dns question number
    QString getDnsAnswerNumber();             // get dns answer number
    QString getDnsAuthorityNumber();          // get dns authority number
    QString getDnsAdditionalNumber();         // get dns addition number
    void getDnsQueriesDomain(QString&name,int&Type,int&Class);
    QString getDnsDomainType(int type);
    QString getDnsDomainName(int offset);
    int getDnsAnswersDomain(int offset,QString&name1,u_short&Type,u_short& Class,u_int&ttl,u_short&dataLength,QString& name2);

    // get the tls info
    bool getisTlsProtocol(int offset);
    void getTlsBasicInfo(int offset,u_char&contentType,u_short&version,u_short&length);
    void getTlsClientHelloInfo(int offset,u_char&handShakeType,int& length,u_short&version,QString&random,u_char&sessionIdLength,QString&sessionId,u_short&cipherLength,QVector<u_short>&cipherSuit,u_char& cmLength,QVector<u_char>&CompressionMethod,u_short&extensionLength);
    void getTlsServerHelloInfo(int offset,u_char&handShakeType,int&length,u_short&version,QString& random,u_char&sessionIdLength,QString&sessionId,u_short&cipherSuit,u_char&compressionMethod,u_short&extensionLength);
    void getTlsServerKeyExchange(int offset,u_char&handShakeType,int&length,u_char&curveType,u_short&curveName,u_char&pubLength,QString&pubKey,u_short&sigAlgorithm,u_short&sigLength,QString&sig);
    u_short getTlsExtensionType(int offset);
    void getTlsHandshakeType(int offset,u_char&type);

    /*
     * these functions are used to parse the extension parts
     * extension parts are common in handshake parts (client hello,server hello ...)
     * there are some extension types are not included in, maybe you should refer the official API
    */
    void getTlsExtensionServerName(int offset,u_short&type,u_short&length,u_short&listLength,u_char&nameType,u_short&nameLength,QString& name);
    void getTlsExtensionSignatureAlgorithms(int offset,u_short&type,u_short&length,u_short&algorithmLength,QVector<u_short>&signatureAlgorithm);
    void getTlsExtensionSupportGroups(int offset,u_short&type,u_short&length,u_short&groupListLength,QVector<u_short>&group);
    void getTlsExtensionEcPointFormats(int offset,u_short&type,u_short&length,u_char& ecLength,QVector<u_char>&EC);
    void getTlsExtensionSessionTicket(int offset,u_short&type,u_short&length);
    void getTlsExtensionEncryptThenMac(int offset,u_short&type,u_short&length);
    void getTlsExtensionSupportVersions(int offset,u_short&type,u_short&length,u_char&supportLength,QVector<u_short>&supportVersion);
    void getTlsExtensionPskKeyExchangeModes(int offset,u_short&type,u_short&length,u_char&modeLength,QVector<u_char>&mode);
    void getTlsExtensionKeyShare(int offset,u_short&type,u_short&length,u_short&shareLength,u_short&group,u_short&exchangeLength,QString& exchange);
    void getTlsExtensionOther(int offset,u_short&type,u_short&length,QString& data);
    void getTlsExtensionExtendMasterSecret(int offset,u_short&type,u_short&length);
    void getTlsExtensionPadding(int offset,u_short&type,u_short&length,QString&data);

    /*
     * when transfer data,some types will be encoded,like using 0x01 to represent the MD5 in extension hash part
     * to visual display these types,we need to decode and analysis
     * this functions are used to do these analisis
     * however,some types may be the custom types, so we can't decode
     * also,there are some rules not be included, maybe you should refer the official API
    */
    // Parsing the encode data
    static QString getTlsHandshakeType(int type);                          // Parsing TLS handshake type
    static QString getTlsContentType(int type);                            // Parsing TLS content type
    static QString getTlsVersion(int version);                             // Parsing TLS version
    static QString getTlsHandshakeCipherSuites(u_short code);              // Parsing TLS cipher suite
    static QString getTlsHandshakeCompression(u_char code);                // Parsing TLS compression
    static QString getTlsHandshakeExtension(u_short type);                 // Parsing TLS extension
    static QString getTlsHandshakeExtensionECPointFormat(u_char type);     // Parsing TLS EC point format
    static QString getTlsHandshakeExtensionSupportGroup(u_short type);     // Parsing TLS support group
    static QString getTlsHadshakeExtensionSignature(u_char type);          // Parsing TLS signature
    static QString getTlsHadshakeExtensionHash(u_char type);               // Parsing TLS hash

};

#endif // DATAPACKAGE_H

```



## mainwindow.h

``` cpp
#ifndef MAINWINDOW_H
#define MAINWINDOW_H



#include <QMainWindow>
#include "pcap.h"
#include "capture.h"
#include "readonlydelegate.h"
#include <QVector>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    // construction and destruction
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    // show network card
    void showNetworkCard();
    // capture the data package
    int capture();

private slots:
    void on_comboBox_currentIndexChanged(int index);
    void on_tableWidget_cellClicked(int row, int column);
    void on_lineEdit_returnPressed();
    void on_lineEdit_textChanged(const QString &arg1);
    void on_tableWidget_currentCellChanged(int currentRow, int currentColumn, int previousRow, int previousColumn);
public slots:
    void handleMessage(DataPackage data);
private:
    Ui::MainWindow *ui;
    pcap_if_t *all_devices;                 // all adapter device
    pcap_if_t *device;                      // An adapter
    pcap_t *pointer;                        // data package pointer
    ReadOnlyDelegate* readOnlyDelegate;     // readonly detegate
    int countNumber;                        // countNumber
    int rowNumber;                          // rowNumber
    QVector<DataPackage>data;               // store data
    char errbuf[PCAP_ERRBUF_SIZE];          // error buffer
    bool isStart;                           // the thread is start or not
};
#endif // MAINWINDOW_H
```



## readonlydelegate.h

``` cpp
#ifndef READONLYDELEGATE_H
#define READONLYDELEGATE_H

#include<QWidget>
#include<QItemDelegate>
#include<QStyleOptionViewItem>
class ReadOnlyDelegate: public QItemDelegate
{
public:
    ReadOnlyDelegate(QWidget *parent = NULL):QItemDelegate(parent)
    {}

    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option,
const QModelIndex &index) const override //final
    {
        Q_UNUSED(parent)
        Q_UNUSED(option)
        Q_UNUSED(index)
        return NULL;
    }
};

#endif // READONLYDELEGATE_H

```









# sources

## capture.cpp

``` cpp
#include "capture.h"
#include <QDebug>
#include <QString>

Capture::Capture(){
    this->isDone = false;
    this->pointer = nullptr;
    this->header = nullptr;
    this->pkt_data = nullptr;
}
bool Capture::setPointer(pcap_t *pointer){
    this->pointer = pointer;
    if(pointer)
        return true;
    else return false;
}

void Capture::setFlag(){
    this->isDone = true;
}

void Capture::resetFlag(){
    this->isDone = false;
}

QString Capture::byteToHex(u_char *str, int size){
    QString res = "";
    for(int i = 0;i < size;i++){
        char one = str[i] >> 4;
        if(one >= 0x0A)
            one = one + 0x41 - 0x0A;
        else one = one + 0x30;
        char two = str[i] & 0xF;
        if(two >= 0x0A)
            two = two  + 0x41 - 0x0A;
        else two = two + 0x30;
        res.append(one);
        res.append(two);
    }
    return res;
}

void Capture::run(){
    unsigned int number_package = 0;
    while(true){
        if(isDone)
            break;
         // 添加的

        //添加的
        int res = pcap_next_ex(pointer,&header,&pkt_data);
        if(res == 0)
            continue;
        local_time_version_sec = header->ts.tv_sec;
        localtime_s(&local_time,&local_time_version_sec);
        strftime(timeString,sizeof(timeString),"%H:%M:%S",&local_time);
        QString info = "";
        int type = ethernetPackageHandle(pkt_data,info);
        if(type){
            DataPackage data;
            int len = header->len;
            data.setPackageType(type);
            data.setTimeStamp(QString(timeString));
            data.setDataLength(len);
            data.setPackagePointer(pkt_data,len);
            data.setPackageInfo(info);
            if(data.pkt_content != nullptr){
                emit send(data);
                number_package++;
            }else continue;
        }
        else continue;
    }
    return;
}

int Capture::ethernetPackageHandle(const u_char *pkt_content,QString& info){
    ETHER_HEADER* ethernet;
    u_short ethernet_type;
    ethernet = (ETHER_HEADER*)pkt_content;
    ethernet_type = ntohs(ethernet->ether_type);

    switch(ethernet_type){
    case 0x0800:{// ip package
        int dataPackage = 0;
        int res = ipPackageHandle(pkt_content,dataPackage);
        switch (res) {
        case 1:{// icmp package
            info = icmpPackageHandle(pkt_content);
            return 2;
        }
        case 6:{// tcp package
            return tcpPackageHandle(pkt_content,info,dataPackage);

        }
        case 17:{ // udp package
            int type = udpPackageHandle(pkt_content,info);
            return type;
        }
        default:break;
        }
        break;
    }
    case 0x0806:{// arp package
        info = arpPackageHandle(pkt_content);
        return 1;
    }
    default:{// undefined package
        break;
    }
    }
    return 0;
}
// ip package
int Capture::ipPackageHandle(const u_char *pkt_content,int& ipPackage){
    /*
+------+-----+-----+
|   1  |  6  |  17 |
+------+-----+-----+
| ICMP | TCP | UDP |
+------+-----+-----+
*/
    IP_HEADER* ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    int protocol = ip->protocol;
    ipPackage = (htons(ip->total_length) - (ip->versiosn_head_length & 0x0F) * 4);
    return protocol;
}
// icmp package
/*
 * part of the protocol of type and code
 * if you need detail information, pls check the official documents
+------+------+------------------------------------------------+
| type | code |                   information                  |
+------+------+------------------------------------------------+
|  0   |   0  |     Echo response (ping command response)      |
+------+------+------------------------------------------------+
|      |   0  |             Network unreachable                |
+      +------+------------------------------------------------+
|      |   1  |             Host unreachable                   |
+      +------+------------------------------------------------+
|      |   2  |              Protocol unreachable              |
+      +------+------------------------------------------------+
|   3  |   3  |              Port unreachable                  |
+      +------+------------------------------------------------+
|      |   4  |    Fragmentation is required, but DF is set    |
+      +------+------------------------------------------------+
|      |   5  |        Source route selection failed           |
+      +------+------------------------------------------------+
|      |   6  |            Unknown target network              |
+------+------+------------------------------------------------+
|   4  |   0  | Source station suppression [congestion control]|
+------+------+------------------------------------------------+
|   5  |  any |                  Relocation                    |
+------+------+------------------------------------------------+
|  8   |   0  |       Echo request (ping command request)      |
+------+------+------------------------------------------------+
......

*/
QString Capture::icmpPackageHandle(const u_char *pkt_content){
    ICMP_HEADER*icmp;
    icmp = (ICMP_HEADER*)(pkt_content + 20 + 14);
    u_char type = icmp->type;
    u_char code = icmp->code;
    QString result = "";
    switch (type) {
    case 0:{
        if(!code)
            result = "Echo response (ping)";
        break;
    }
    case 3:{
        switch (code) {
        case 0:{
            result = "Network unreachable";
            break;
        }
        case 1:{
            result = "Host unreachable";
            break;
        }
        case 2:{
            result = "Protocol unreachable";
            break;
        }
        case 3:{
            result = "Port unreachable";
            break;
        }
        case 4:{
            result = "Fragmentation is required, but DF is set";
            break;
        }
        case 5:{
            result = "Source route selection failed";
            break;
        }
        case 6:{
            result = "Unknown target network";
            break;
        }
        default:break;
        }
        break;
    }
    case 4:{
        result = "Source station suppression [congestion control]";
        break;
    }
    case 5:{
        result = "Relocation";
        break;
    }
    case 8:{
        if(!code)
            result = "Echo request (ping)";
        break;
    }
    default:break;
    }
    return result;
}

int Capture::tcpPackageHandle(const u_char *pkt_content,QString &info,int ipPackage){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    u_short src = ntohs(tcp->src_port);
    u_short des = ntohs(tcp->des_port);
    QString proSend = "";
    QString proRecv = "";
    int type = 3;
    int delta = (tcp->header_length >> 4) * 4;
    int tcpPayLoad = ipPackage - delta;
    if((src == 443 || des == 443) && (tcpPayLoad > 0)){
        if(src == 443)
            proSend = "(https)";
        else proRecv = "(https)";
        u_char *ssl;
        ssl = (u_char*)(pkt_content + 14 + 20 + delta);
        u_char isTls = *(ssl);
        ssl++;
        u_short*pointer = (u_short*)(ssl);
        u_short version = ntohs(*pointer);
        if(isTls >= 20 && isTls <= 23 && version >= 0x0301 && version <= 0x0304){
            type = 6;
            switch(isTls){
            case 20:{
                info = "Change Cipher Spec";
                break;
            }
            case 21:{
                info = "Alert";
                break;
            }
            case 22:{
                info = "Handshake";
                ssl += 4;
                u_char type = (*ssl);
                switch (type) {
                case 1: {
                    info += " Client Hello";
                    break;
                }
                case 2: {
                    info += " Server hello";
                    break;
                }
                case 4: {
                    info += " New Session Ticket";
                    break;
                }
                case 11:{
                    info += " Certificate";
                    break;
                }
                case 16:{
                    info += " Client Key Exchange";
                    break;
                }
                case 12:{
                    info += " Server Key Exchange";
                    break;
                }
                case 14:{
                    info += " Server Hello Done";
                    break;
                }
                default:break;
                }
                break;
            }
            case 23:{
                info = "Application Data";
                break;
            }
            default:{
                break;
            }
            }
            return type;
        }else type = 7;
    }

    if(type == 7){
        info = "Continuation Data";
    }
    else{
        info += QString::number(src) + proSend+ "->" + QString::number(des) + proRecv;
        QString flag = "";
        if(tcp->flags & 0x08) flag += "PSH,";
        if(tcp->flags & 0x10) flag += "ACK,";
        if(tcp->flags & 0x02) flag += "SYN,";
        if(tcp->flags & 0x20) flag += "URG,";
        if(tcp->flags & 0x01) flag += "FIN,";
        if(tcp->flags & 0x04) flag += "RST,";
        if(flag != ""){
            flag = flag.left(flag.length()-1);
            info += " [" + flag + "]";
        }
        u_int sequeue = ntohl(tcp->sequence);
        u_int ack = ntohl(tcp->ack);
        u_short window = ntohs(tcp->window_size);
        info += " Seq=" + QString::number(sequeue) + " Ack=" + QString::number(ack) + " win=" + QString::number(window) + " Len=" + QString::number(tcpPayLoad);
    }
    return type;
}

int Capture::udpPackageHandle(const u_char *pkt_content,QString&info){
    UDP_HEADER * udp;
    udp = (UDP_HEADER*)(pkt_content + 14 + 20);
    u_short desPort = ntohs(udp->des_port);
    u_short srcPort = ntohs(udp->src_port);
    if(desPort == 53){ // dns query
        info =  dnsPackageHandle(pkt_content);
        return 5;
    }
    else if(srcPort == 53){// dns reply
        info =  dnsPackageHandle(pkt_content);
        return 5;
    }
    else{
        QString res = QString::number(srcPort) + "->" + QString::number(desPort);
        res += " len=" + QString::number(ntohs(udp->data_length));
        info = res;
        return 4;
    }
}

QString Capture::arpPackageHandle(const u_char *pkt_content){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    u_short op = ntohs(arp->op_code);
    QString res = "";
    u_char*addr = arp->des_ip_addr;

    QString desIp = QString::number(*addr) + "."
            + QString::number(*(addr+1)) + "."
            + QString::number(*(addr+2)) + "."
            + QString::number(*(addr+3));

    addr = arp->src_ip_addr;
    QString srcIp = QString::number(*addr) + "."
            + QString::number(*(addr+1)) + "."
            + QString::number(*(addr+2)) + "."
            + QString::number(*(addr+3));

    u_char* srcEthTemp = arp->src_eth_addr;
    QString srcEth = byteToHex(srcEthTemp,1) + ":"
            + byteToHex((srcEthTemp+1),1) + ":"
            + byteToHex((srcEthTemp+2),1) + ":"
            + byteToHex((srcEthTemp+3),1) + ":"
            + byteToHex((srcEthTemp+4),1) + ":"
            + byteToHex((srcEthTemp+5),1);

    switch (op){
    case 1:{
        res  = "Who has " + desIp + "? Tell " + srcIp;
        break;
    }
    case 2:{
        res = srcIp + " is at " + srcEth;
        break;
    }
    default:break;
    }
    return res;
}

QString Capture::dnsPackageHandle(const u_char *pkt_content){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    u_short identification = ntohs(dns->identification);
    u_short type = ntohs(dns->flags);
    QString info = "";
    if((type & 0xf800) == 0x0000){
        info = "Standard query ";
    }
    else if((type & 0xf800) == 0x8000){
        info = "Standard query response ";
    }
    QString name = "";
    char*domain = (char*)(pkt_content + 14 + 20 + 8 + 12);
    while(*domain != 0x00){
        if(domain && (*domain) <= 64){
            int length = *domain;
            domain++;
            for(int k = 0;k < length;k++){
                name += (*domain);
                domain++;
            }
            name += ".";
        }else break;
    }
    // DNS_QUESITON *qus = (DNS_QUESITON*)(pkt_content + 14 + 20 + 8 + 12 + stringLength);
    // qDebug()<<ntohs(qus->query_type);
    // qDebug()<<ntohs(qus->query_class);
    name = name.left(name.length()-1);
    return info + "0x" + QString::number(identification,16) + " " + name;
}

```





## datapackage.cpp

``` cpp
#include "datapackage.h"
#include <QMetaType>
#include "winsock.h"
#include <QVector>

DataPackage::DataPackage()
{
    // register the DataPackage type then
    qRegisterMetaType<DataPackage>("DataPackage");
    this->timeStamp = "";
    this->data_length = 0;
    this->packageType = 0;
    this->pkt_content = nullptr;
}

void DataPackage::setDataLength(unsigned int length){
    this->data_length = length;
}

void DataPackage::setTimeStamp(QString timeStamp){
    this->timeStamp = timeStamp;
}

void DataPackage::setPackageType(int type){
    this->packageType = type;
}

void DataPackage::setPackagePointer(const u_char *pkt_content,int size){
    this->pkt_content = (u_char*)malloc(size);
    if(this->pkt_content != nullptr)
        memcpy((char*)(this->pkt_content),pkt_content,size);
    else this->pkt_content = nullptr;
    //  Do not use  `this->pkt_content = pkt_content;`
}
void DataPackage::setPackageInfo(QString info){
    this->info = info;
}
QString DataPackage::byteToHex(u_char *str, int size){
    QString res = "";
    for(int i = 0;i < size;i++){
        char one = str[i] >> 4;
        if(one >= 0x0A)
            one = one + 0x41 - 0x0A;
        else one = one + 0x30;
        char two = str[i] & 0xF;
        if(two >= 0x0A)
            two = two  + 0x41 - 0x0A;
        else two = two + 0x30;
        res.append(one);
        res.append(two);
    }
    return res;
}

QString DataPackage::getTimeStamp(){
    return this->timeStamp;
}

QString DataPackage::getDataLength(){
    return QString::number(this->data_length);
}

QString DataPackage::getPackageType(){
    switch (this->packageType) {
    case 1:return ARP;
    case 2:return ICMP;
    case 3:return TCP;
    case 4:return UDP;
    case 5:return DNS;
    case 6:return TLS;
    case 7:return SSL;
    // TODU ...more protocol you can add
    default:{
        return "";
    }
    }
}

QString DataPackage::getInfo(){
    return info;
}

QString DataPackage::getSource(){
    if(this->packageType == 1)
        return getArpSourceIpAddr();
    else return getSrcIpAddr();
}
QString DataPackage::getDestination(){
    if(this->packageType == 1)
        return getArpDestinationIpAddr();
    else return getDesIpAddr();
}
/* Ether */
/********************** get destination ethenet address **********************/
QString DataPackage::getDesMacAddr(){
    ETHER_HEADER*ethernet;
    ethernet = (ETHER_HEADER*)pkt_content;
    u_char*addr;
    if(ethernet){
        addr = ethernet->ether_des_host;
        if(addr){
            QString res = byteToHex(addr,1) + ":"
                    + byteToHex((addr+1),1) + ":"
                    + byteToHex((addr+2),1) + ":"
                    + byteToHex((addr+3),1) + ":"
                    + byteToHex((addr+4),1) + ":"
                    + byteToHex((addr+5),1);
            if(res == "FF:FF:FF:FF:FF:FF") return "FF:FF:FF:FF:FF:FF(Broadcast)";
            else return res;
        }
    }
    return "";
}
/********************** get source ethenet address **********************/
QString DataPackage::getSrcMacAddr(){
    ETHER_HEADER*ethernet;
    ethernet = (ETHER_HEADER*)pkt_content;
    u_char*addr;
    if(ethernet){
        addr = ethernet->ether_src_host;
        if(addr){
            QString res = byteToHex(addr,1) + ":"
                    + byteToHex((addr+1),1) + ":"
                    + byteToHex((addr+2),1) + ":"
                    + byteToHex((addr+3),1) + ":"
                    + byteToHex((addr+4),1) + ":"
                    + byteToHex((addr+5),1);
            if(res == "FF:FF:FF:FF:FF:FF") return "FF:FF:FF:FF:FF:FF(Broadcast)";
            else return res;
        }
    }
    return "";
}
/********************** get ethenet type **********************/
QString DataPackage::getMacType(){
    ETHER_HEADER*ethernet;
    ethernet = (ETHER_HEADER*)pkt_content;
    u_short ethernet_type = ntohs(ethernet->ether_type);
    switch (ethernet_type) {
    case 0x0800: return "IPv4(0x800)";
    case 0x0806:return "ARP(0x0806)";
    default:{
        return "";
    }
    }
}

/* ip */
/********************** get destination ip address **********************/
QString DataPackage::getDesIpAddr(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    sockaddr_in desAddr;
    desAddr.sin_addr.s_addr = ip->des_addr;
    return QString(inet_ntoa(desAddr.sin_addr));
}
/********************** get source ip address **********************/
QString DataPackage::getSrcIpAddr(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    sockaddr_in srcAddr;
    srcAddr.sin_addr.s_addr = ip->src_addr;
    return QString(inet_ntoa(srcAddr.sin_addr));
}
/********************** get ip version **********************/
QString DataPackage::getIpVersion(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number(ip->versiosn_head_length >> 4);
}
/********************** get ip header length **********************/
QString DataPackage::getIpHeaderLength(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    QString res = "";
    int length = ip->versiosn_head_length & 0x0F;
    if(length == 5) res = "20 bytes (5)";
    else res = QString::number(length*5) + "bytes (" + QString::number(length) + ")";
    return res;
}

/********************** get ip TOS **********************/
QString DataPackage::getIpTos(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number(ntohs(ip->TOS));
}
/********************** get ip total length **********************/
QString DataPackage::getIpTotalLength(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number(ntohs(ip->total_length));
}
/********************** get ip indentification **********************/
QString DataPackage::getIpIdentification(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number(ntohs(ip->identification),16);
}
/********************** get ip flag **********************/
QString DataPackage::getIpFlag(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number((ntohs(ip->flag_offset)& 0xe000) >> 8,16);
}
/********************** get ip reverse bit **********************/
QString DataPackage::getIpReservedBit(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    int bit = (ntohs(ip->flag_offset) & 0x8000) >> 15;
    return QString::number(bit);
}
/********************** get ip DF flag[Don't Fragment] **********************/
QString DataPackage::getIpDF(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number((ntohs(ip->flag_offset) & 0x4000) >> 14);
}
/********************** get ip MF flag[More Fragment] **********************/
QString DataPackage::getIpMF(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number((ntohs(ip->flag_offset) & 0x2000) >> 13);
}
/********************** get ip Fragment Offset **********************/
QString DataPackage::getIpFragmentOffset(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number(ntohs(ip->flag_offset) & 0x1FFF);
}
/********************** get ip TTL **********************/
QString DataPackage::getIpTTL(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number(ip->ttl);
}
/********************** get ip protocol **********************/
QString DataPackage::getIpProtocol(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    int protocol = ip->protocol;
    switch (protocol) {
    case 1:return "ICMP (1)";
    case 6:return "TCP (6)";
    case 17:return "UDP (17)";
    default:{
        return "";
    }
    }
}
/********************** get ip checksum **********************/
QString DataPackage::getIpCheckSum(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number(ntohs(ip->checksum),16);
}

/* icmp */
/********************** get icmp type **********************/
QString DataPackage::getIcmpType(){
    ICMP_HEADER*icmp;
    icmp = (ICMP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohs(icmp->type));
}
/********************** get icmp code **********************/
QString DataPackage::getIcmpCode(){
    ICMP_HEADER*icmp;
    icmp = (ICMP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohs(icmp->code));

}
/********************** get icmp checksum **********************/
QString DataPackage::getIcmpCheckSum(){
    ICMP_HEADER*icmp;
    icmp = (ICMP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohs(icmp->checksum),16);
}
/********************** get icmp identification **********************/
QString DataPackage::getIcmpIdentification(){
    ICMP_HEADER*icmp;
    icmp = (ICMP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohs(icmp->identification));
}
/********************** get icmp sequence **********************/
QString DataPackage::getIcmpSequeue(){
    ICMP_HEADER*icmp;
    icmp = (ICMP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohs(icmp->sequence));
}
QString DataPackage::getIcmpData(int size){
    char*icmp;
    icmp = (char*)(pkt_content + 14 + 20 + 8);
    QString res= "";
    for(int i = 0;i < size;i++){
        res += (*icmp);
        icmp++;
    }
    return res;
}
/* arp info */
QString DataPackage::getArpHardwareType(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    int type = ntohs(arp->hardware_type);
    QString res = "";
    if(type == 0x0001) res = "Ethernet(1)";
    else res = QString::number(type);
    return res;
}
/********************** get arp protocol type **********************/
QString DataPackage::getArpProtocolType(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    int type = ntohs(arp->protocol_type);
    QString res = "";
    if(type == 0x0800) res = "IPv4(0x0800)";
    else res = QString::number(type);
    return res;
}
/********************** get hardware length **********************/
QString DataPackage::getArpHardwareLength(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    return QString::number(arp->mac_length);
}
/********************** get arp protocol length **********************/
QString DataPackage::getArpProtocolLength(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    return QString::number(arp->ip_length);
}
/********************** get arp operator code **********************/
QString DataPackage::getArpOperationCode(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    int code = ntohs(arp->op_code);
    QString res = "";
    if(code == 1) res  = "request(1)";
    else if(code == 2) res = "reply(2)";
    return res;
}
/********************** get arp source ethernet address **********************/
QString DataPackage::getArpSourceEtherAddr(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    u_char*addr;
    if(arp){
        addr = arp->src_eth_addr;
        if(addr){
            QString res = byteToHex(addr,1) + ":"
                    + byteToHex((addr+1),1) + ":"
                    + byteToHex((addr+2),1) + ":"
                    + byteToHex((addr+3),1) + ":"
                    + byteToHex((addr+4),1) + ":"
                    + byteToHex((addr+5),1);
            return res;
        }
    }
    return "";
}
/********************** get arp destination ethernet address **********************/
QString DataPackage::getArpDestinationEtherAddr(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    u_char*addr;
    if(arp){
        addr = arp->des_eth_addr;
        if(addr){
            QString res = byteToHex(addr,1) + ":"
                    + byteToHex((addr+1),1) + ":"
                    + byteToHex((addr+2),1) + ":"
                    + byteToHex((addr+3),1) + ":"
                    + byteToHex((addr+4),1) + ":"
                    + byteToHex((addr+5),1);
            return res;
        }
    }
    return "";
}
/********************** get arp source ip address **********************/
QString DataPackage::getArpSourceIpAddr(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    if(arp){
        u_char*addr = arp->src_ip_addr;
        QString srcIp = QString::number(*addr) + "."
                + QString::number(*(addr+1)) + "."
                + QString::number(*(addr+2)) + "."
                + QString::number(*(addr+3));
        return srcIp;
    }
    return "";
}
/********************** get arp destination ip address **********************/
QString DataPackage::getArpDestinationIpAddr(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    if(arp){
        u_char*addr = arp->des_ip_addr;
        QString desIp = QString::number(*addr) + "."
                + QString::number(*(addr+1)) + "."
                + QString::number(*(addr+2)) + "."
                + QString::number(*(addr+3));
        return desIp;
    }
    return "";
}

/* tcp */
/********************** get tcp source port **********************/
QString DataPackage::getTcpSourcePort(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    int port = ntohs(tcp->src_port);
    if(port == 443) return "https(443)";
    return QString::number(port);
}
/********************** get tcp destination port **********************/
QString DataPackage::getTcpDestinationPort(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    int port = ntohs(tcp->des_port);
    if(port == 443) return "https(443)";
    return QString::number(port);
}
/********************** get tcp sequence **********************/
QString DataPackage::getTcpSequence(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohl(tcp->sequence));
}
/********************** get tcp acknowledgment **********************/
QString DataPackage::getTcpAcknowledgment(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohl(tcp->ack));
}
/********************** get tcp header length **********************/
QString DataPackage::getTcpHeaderLength(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    int length = (tcp->header_length >> 4);
    if(length == 5) return "20 bytes (5)";
    else return QString::number(length*4) + " bytes (" + QString::number(length) + ")";
}
QString DataPackage::getTcpRawHeaderLength(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(tcp->header_length >> 4);
}

/********************** get tcp flags **********************/
QString DataPackage::getTcpFlags(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(tcp->flags,16);
}

/********************** get tcp PSH **********************/
QString DataPackage::getTcpPSH(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(((tcp->flags) & 0x08) >> 3);
}
/********************** get tcp ACK **********************/
QString DataPackage::getTcpACK(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(((tcp->flags) & 0x10) >> 4);
}
/********************** get tcp SYN **********************/
QString DataPackage::getTcpSYN(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(((tcp->flags) & 0x02) >> 1);
}
/********************** get tcp UGR **********************/
QString DataPackage::getTcpURG(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(((tcp->flags) & 0x20) >> 5);
}
/********************** get tcp FIN **********************/
QString DataPackage::getTcpFIN(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number((tcp->flags) & 0x01);
}
/********************** get tcp RST **********************/
QString DataPackage::getTcpRST(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(((tcp->flags) & 0x04) >> 2);
}
/********************** get tcp window size **********************/
QString DataPackage::getTcpWindowSize(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohs(tcp->window_size));
}
/********************** get tcp checksum **********************/
QString DataPackage::getTcpCheckSum(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohs(tcp->checksum),16);
}
/********************** get tcp urgent pointer **********************/
QString DataPackage::getTcpUrgentPointer(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohs(tcp->urgent));
}

QString DataPackage::getTcpOperationKind(int kind){
    switch(kind){
    case 0:return "EOL";              // end of list
    case 1:return "NOP";              // no operation
    case 2:return "MSS";              // max segment
    case 3:return "WSOPT";            // window scaling factor
    case 4:return "SACK-Premitted";   // support SACK
    case 5:return "SACK";             // SACK Block
    case 8:return "TSPOT";            // Timestamps
    case 19:return "TCP-MD5";         // MD5
    case 28:return "UTP";             // User Timeout
    case 29:return "TCP-AO";          // authenticated
    }
}
int DataPackage::getTcpOperationRawKind(int offset){
    u_char*tcp;
    tcp = (u_char*)(pkt_content + 14 + 20 + offset + 20);
    return *tcp;
}
bool DataPackage::getTcpOperationSACK(int offset,u_char&length,QVector<u_int>&edge){
    u_char*tcp;
    tcp = (u_char*)(pkt_content + 14 + 20 + offset + 20);
    if(*tcp == 5){
        tcp++;
        length = *tcp;
        tcp++;
        u_int* pointer = (u_int*)tcp;
        for(int i = 0;i < (length - 2)/4;i++){
            u_int temp = htonl(*pointer);
            edge.push_back(temp);
            pointer++;
        }
        return true;
    }else return false;
}
bool DataPackage::getTcpOperationMSS(int offset, u_short &mss){
    u_char *tcp;
    tcp = (u_char*)(pkt_content + 14 + 20 + offset + 20);
    if(*tcp == 2){
        tcp++;
        if(*tcp == 4){
            tcp++;
            u_short* Mss = (u_short*)tcp;
            mss = ntohs(*Mss);
            return true;
        }
        else return false;
    }
    return false;
}
bool DataPackage::getTcpOperationSACKP(int offset){
    u_char *tcp;
    tcp = (u_char*)(pkt_content + 14 + 20 + offset + 20);
    if(*tcp == 4)
        return true;
    else return false;
}
bool DataPackage::getTcpOperationWSOPT(int offset, u_char &shit){
    u_char *tcp;
    tcp = (u_char*)(pkt_content + 14 + 20 + offset + 20);
    if(*tcp == 3){
        tcp++;
        if(*tcp == 3){
            tcp++;
            shit = *tcp;
        }else return false;
    }else return false;
}

bool DataPackage::getTcpOperationTSPOT(int offset, u_int &value, u_int &reply){
    u_char *tcp;
    tcp = (u_char*)(pkt_content + 14 + 20 + offset + 20);
    if(*tcp == 8){
        tcp++;
        if(*tcp == 10){
            tcp++;
            u_int *pointer = (u_int*)(tcp);
            value = ntohl(*pointer);
            pointer++;
            reply = ntohl(*pointer);
            return true;
        }else return false;
    }else return false;
}
/* udp */
/********************** get udp source port **********************/
QString DataPackage::getUdpSourcePort(){
    UDP_HEADER*udp;
    udp = (UDP_HEADER*)(pkt_content + 20 + 14);
    int port = ntohs(udp->src_port);
    if(port == 53) return "domain(53)";
    else return QString::number(port);
}
/********************** get udp destination port **********************/
QString DataPackage::getUdpDestinationPort(){
    UDP_HEADER*udp;
    udp = (UDP_HEADER*)(pkt_content + 20 + 14);
    int port = ntohs(udp->des_port);
    if(port == 53) return "domain(53)";
    else return QString::number(port);
}
/********************** get udp data length **********************/
QString DataPackage::getUdpDataLength(){
    UDP_HEADER*udp;
    udp = (UDP_HEADER*)(pkt_content + 20 + 14);
    return QString::number(ntohs(udp->data_length));

}
/********************** get udp checksum **********************/
QString DataPackage::getUdpCheckSum(){
    UDP_HEADER*udp;
    udp = (UDP_HEADER*)(pkt_content + 20 + 14);
    return QString::number(ntohs(udp->checksum),16);
}

/* dns */
/********************** get dns transaction **********************/
QString DataPackage::getDnsTransactionId(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number(ntohs(dns->identification),16);
}
/********************** get dns flag **********************/
QString DataPackage::getDnsFlags(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    int type = ntohs(dns->flags);
    QString info = "";
    if((type & 0xf800) == 0x0000){
        info = "(Standard query)";
    }
    else if((type & 0xf800) == 0x8000){
        info = "(Standard query response)";
    }
    return QString::number(type,16) + info;
}
/********************** get dns QR **********************/
QString DataPackage::getDnsFlagsQR(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number((ntohs(dns->flags) & 0x8000) >> 15);
}
/********************** get dns Operation code **********************/
QString DataPackage::getDnsFlagsOpcode(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number((ntohs(dns->flags) & 0x7800) >> 11);
}
/********************** get dns AA **********************/
QString DataPackage::getDnsFlagsAA(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number((ntohs(dns->flags) & 0x0400) >> 10);
}
/********************** get dns TC **********************/
QString DataPackage::getDnsFlagsTC(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number((ntohs(dns->flags) & 0x0200) >> 9);
}
/********************** get dns RD **********************/
QString DataPackage::getDnsFlagsRD(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number((ntohs(dns->flags) & 0x0100) >> 8);
}
/********************** get dns RA **********************/
QString DataPackage::getDnsFlagsRA(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number((ntohs(dns->flags) & 0x0080) >> 7);
}
/********************** get dns Z(reserved) **********************/
QString DataPackage::getDnsFlagsZ(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number((ntohs(dns->flags) & 0x0070) >> 4);
}
/********************** get dns Response code **********************/
QString DataPackage::getDnsFlagsRcode(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number((ntohs(dns->flags) & 0x000f));
}
/********************** get dns Question number **********************/
QString DataPackage::getDnsQuestionNumber(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number(ntohs(dns->question));
}
/********************** get dns Answer number **********************/
QString DataPackage::getDnsAnswerNumber(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number(ntohs(dns->answer));
}
/********************** get dns Authority number **********************/
QString DataPackage::getDnsAuthorityNumber(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number(ntohs(dns->authority));
}
/********************** get dns Additional number **********************/
QString DataPackage::getDnsAdditionalNumber(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number(ntohs(dns->additional));
}
/********************** get dns query result **********************/
void DataPackage::getDnsQueriesDomain(QString&name,int&Type,int&Class){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    char*domain = (char*)(pkt_content + 14 + 20 + 8 + 12);
    while(*domain != 0x00){
        if(domain && (*domain) <= 64){
            int length = *domain;
            domain++;
            for(int k = 0;k < length;k++){
                name += (*domain);
                domain++;
            }
            name += ".";
        }else break;
    }
    domain++;
    name = name.left(name.length() - 1);
    DNS_QUESITON *qus = (DNS_QUESITON*)(domain);
    Type = ntohs(qus->query_type);
    Class = ntohs(qus->query_class);
}
/********************** get dns domian name **********************/
QString DataPackage::getDnsDomainName(int offset){
    char*dns;
    dns = (char*)(pkt_content + 14 + 20 + 8 + offset);
    QString name = "";
    while(dns && *dns != 0x00){
        if((unsigned char)(*dns) <= 64){
            int length = *dns;
            dns++;
            for(int k = 0;k<length;k++){
                name += (*dns);
                dns++;
            }
            name += ".";
        }else if(((*dns) & 0xc0) == 0xc0){
            int accOffset = (((*dns) & 0x3f) << 8);
            dns++;
            accOffset += (unsigned char)(*dns);
            name += getDnsDomainName(accOffset) + ".";
            dns++;
            break;
        }
    }
    name = name.left(name.length() - 1);
    return name;
}
/********************** get dns answer result **********************/
int DataPackage::getDnsAnswersDomain(int offset, QString &name1, u_short &Type, u_short &Class, u_int &ttl, u_short &dataLength,QString&name2){
    char*dns = (char*)(pkt_content + 14 + 20 + 8 + 12 + offset);
    if(((*dns) & 0xc0) == 0xc0){
        int accOffset = (((*dns) & 0x3f) << 8);
        dns++; //
        accOffset += (*dns);
        name1 = getDnsDomainName(accOffset);
        dns++; //
        DNS_ANSWER*answer = (DNS_ANSWER*)(dns);
        Type = ntohs(answer->answer_type);
        Class = ntohs(answer->answer_class);
        ttl = ntohl(answer->TTL);
        dataLength = ntohs(answer->dataLength);
        dns += (2 + 2 + 4 + 2);
        if(dataLength == 4){
            for(int i = 0;i < 4;i++){
                name2 += QString::number((unsigned char)(*dns));
                name2 += ".";
                dns++;
            }
        }else{
            for(int k = 0;k<dataLength;k++){
                if((unsigned char)(*dns) <= 64){
                    int length = *dns;
                    dns++;
                    k++;
                    for(int j = 0;j < length;j++){
                        name2 += *dns;
                        dns++;
                        k++;
                    }
                    name2 += ".";
                }else if(((*dns) & 0xc0) == 0xc0){
                    int accOffset = (((*dns) & 0x3f) << 8);
                    dns++;
                    k++;
                    accOffset += (unsigned char)(*dns);
                    name2 += getDnsDomainName(accOffset) + ".";
                    dns++;
                    k++;
                }
            }
        }
        name2 = name2.left(name2.length() - 1);
        return dataLength + 2 + 2 + 2 + 4 + 2;

    }else{
        name1 = getDnsDomainName(offset + 12);
        DNS_ANSWER*answer = (DNS_ANSWER*)(dns + name1.size() + 2);
        Type = ntohs(answer->answer_type);
        Class = ntohs(answer->answer_class);
        ttl = ntohl(answer->TTL);
        dataLength = ntohs(answer->dataLength);
        if(dataLength == 4){
            dns += (2 + 2 + 4 + 2 + name1.size() + 1);
            for(int i = 0;i < 4;i++){
                name2 += (unsigned char)(*dns);
                dns++;
            }
        }else{
            for(int k = 0;k<dataLength;k++){
                if((unsigned char)(*dns) <= 64){
                    int length = *dns;
                    dns++;
                    k++;
                    for(int j = 0;j < length;j++){
                        name2 += *dns;
                        dns++;
                        k++;
                    }
                    name2 += ".";
                }else if(((*dns) & 0xc0) == 0xc0){
                    int accOffset = (((*dns) & 0x3f) << 8);
                    dns++;
                    k++;
                    accOffset += (*dns);
                    name2 += getDnsDomainName(accOffset);
                    dns++;
                    k++;
                }
            }
        }
        name2 = name2.left(name2.length() - 1);
        return dataLength + 2 + 2 + 2 + 4 + 2 + name1.size() + 2;
    }
}
/********************** get dns domain type **********************/
QString DataPackage::getDnsDomainType(int type){
    switch (type) {
    case 1: return "A (Host Address)";
    case 2:return "NS";
    case 5:return "CNAME (Canonical NAME for an alias)";
    case 6:return "SOA";
    case 11:return "WSK";
    case 12:return "PTR";
    case 13:return "HINFO";
    case 15:return "MX";
    case 28:return "AAAA";
    case 252:return "AXFR";
    case 255:return "ANY";
    default:return "";
    }
}

// tls
/********************** get tls protocol to check the data is meet this format or not **********************/
bool DataPackage::getisTlsProtocol(int offset){
    char*ssl;
    ssl = (char*)(pkt_content + 14 + 20 + 20 + offset);
    u_char type = (u_char)(*ssl);
    if(type >= 20 && type <= 23){
        u_short *point = (u_short*)(ssl+1);
        int version = ntohs(*point);
        if(version >= 0x0301 && version <= 0x0304)
            return true;
        else return false;
    }
    else return false;
}
/********************** get tls basic information **********************/
void DataPackage::getTlsBasicInfo(int offset, u_char &contentType, u_short &version, u_short &length){
    u_char*ssl;
    ssl = (u_char*)(pkt_content + 14 + 20 + offset);
    contentType = *ssl;
    ssl++;
    u_short* pointer = (u_short*)(ssl);
    version = ntohs(*pointer);
    pointer++;
    length = ntohs(*(pointer));
}

/********************** get tls handshake type **********************/
void DataPackage::getTlsHandshakeType(int offset, u_char &type){
    u_char*ssl;
    ssl = (u_char*)(pkt_content + 14 + 20 + offset);
    type = *ssl;
}
/********************** get tls client hello information **********************/
void DataPackage::getTlsClientHelloInfo(int offset, u_char &handShakeType, int &length, u_short &version, QString &random, u_char &sessionIdLength, QString &sessionId,u_short&cipherLength,QVector<u_short> &cipherSuit,u_char& cmLength,QVector<u_char>&CompressionMethod,u_short&extensionLength){
    u_char*ssl;
    ssl = (u_char*)(pkt_content + 14 + 20 + offset);
    handShakeType = *ssl;
    ssl++;
    length = (*ssl) * 4096 + (*(ssl+1)) * 256 + *(ssl + 2);
    ssl += 3;
    u_short* ver = (u_short*)(ssl);
    version = ntohs(*ver);
    ver++;
    ssl += 2;
    for(int i = 0;i < 32;i++){
        random += QString::number(*ssl,16);
        ssl++;
    }
    sessionIdLength = *ssl;
    ssl++;
    for(int k = 0;k < sessionIdLength;k++){
        sessionId += QString::number(*ssl,16);
        ssl++;
    }
    u_short* clen = (u_short*)(ssl);
    cipherLength = ntohs(*clen);
    clen++;
    for(int k = 0;k < cipherLength/2;k++){
        cipherSuit.push_back(ntohs(*clen));
        clen++;
    }
    ssl += (2 + cipherLength);
    cmLength = *ssl;
    ssl++;
    for(int k = 0;k<cmLength;k++){
        CompressionMethod.push_back(*ssl);
        ssl++;
    }
    extensionLength = (*(ssl)) * 256 + *(ssl + 1);
}

void DataPackage::getTlsServerHelloInfo(int offset, u_char &handShakeType, int &length, u_short &version, QString& random, u_char &sessionIdLength, QString &sessionId, u_short &cipherSuit, u_char &compressionMethod, u_short &extensionLength){
    u_char*ssl;
    ssl = (u_char*)(pkt_content + 14 + 20 + offset);
    handShakeType = *ssl;
    ssl++;
    length = (*ssl) * 4096 + (*(ssl + 1)) * 256 + *(ssl + 2);
    ssl += 3;
    u_short* ver = (u_short*)(ssl);
    version = ntohs(*ver);
    ver++;
    ssl += 2;
    for(int i = 0;i < 32;i++){
        random += QString::number(*ssl,16);
        ssl++;
    }
    sessionIdLength = *ssl;
    ssl++;
    for(int k = 0;k < sessionIdLength;k++){
        sessionId += QString::number(*ssl,16);
        ssl++;
    }
    u_short*point = (u_short*)(ssl);
    cipherSuit = ntohs(*point);
    ssl += 2;
    compressionMethod = *ssl;
    ssl++;
    extensionLength = (*ssl) * 256 + (*(ssl + 1));
}
void DataPackage::getTlsServerKeyExchange(int offset, u_char &handShakeType, int &length, u_char &curveType, u_short &curveName, u_char &pubLength, QString &pubKey, u_short &sigAlgorithm, u_short &sigLength, QString &sig){
    u_char*ssl;
    ssl = (u_char*)(pkt_content + 14 + 20 + offset);
    handShakeType = *ssl;
    ssl++;
    length = (*ssl) * 4096 + (*(ssl + 1)) * 256 + *(ssl + 2);
    ssl += 3;
    curveType = (*ssl);
    ssl++;
    u_short*point = (u_short*)(ssl);
    curveName = ntohs(*point);
    ssl += 2;
    pubLength = (*ssl);
    ssl++;
    for(int i = 0;i < pubLength;i++){
        pubKey += QString::number(*ssl,16);
        ssl++;
    }
    point = (u_short*)(ssl);
    sigAlgorithm = ntohs(*point);
    point++;
    sigLength = ntohs(*point);
    ssl += 4;
    for(int i = 0;i < sigLength;i++){
        sig += QString::number(*ssl,16);
        ssl++;
    }
}
/********************** get tls handshake type **********************/
QString DataPackage::getTlsHandshakeType(int type){
    switch (type) {
    case 1:return "Client Hello";
    case 2:return "Server hello";
    case 11:return "Certificate";
    case 16:return "Client Key Exchange";
    case 4:return "New Session Ticket";
    case 12:return "Server Key Exchange";
    case 14:return "Server Hello Done";

    default:return "";
    }
}
/********************** get tls content type **********************/
QString DataPackage::getTlsContentType(int type){
    switch (type) {
    case 20: return "Change Cipher Spec";
    case 21:return "Alert";
    case 22:return "Handshake";
    case 23:return "Application Data";
    default:return "";
    }
}
/********************** get tls version **********************/
QString DataPackage::getTlsVersion(int version){
    switch (version) {
    case 0x0300:return "SSL 3.0";
    case 0x0301:return "TLS 1.0";
    case 0x0302:return "TLS 1.1";
    case 0x0303:return "TLS 1.2";
    case 0x0304:return "TLS 1.3";
    default:return "Unkonwn";
    }
}
/********************** get tls handshake cipher suites **********************/
QString DataPackage::getTlsHandshakeCipherSuites(u_short code){
    switch (code) {
    case 0x00ff: return "TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0x00ff)";
    case 0xc02c: return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xc02c)";
    case 0xc030: return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)";
    case 0x009f: return "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 (0x009f)";
    case 0xc0ad: return "TLS_ECDHE_ECDSA_WITH_AES_256_CCM (0xc0ad)";
    case 0xc09f: return "TLS_DHE_RSA_WITH_AES_256_CCM (0xc09f)";
    case 0xc024: return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 (0xc024)";
    case 0xc028: return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 (0xc028)";
    case 0x006b: return "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 (0x006b)";
    case 0xc00a: return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0xc00a)";
    case 0xc014: return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014)";
    case 0x0039: return "TLS_DHE_RSA_WITH_AES_256_CBC_SHA (0x0039)";
    case 0xc0af: return "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 (0xc0af)";
    case 0xc0a3: return "TLS_DHE_RSA_WITH_AES_256_CCM_8 (0xc0a3)";
    case 0xc087: return "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 (0xc087)";
    case 0xc08b: return "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 (0xc08b)";
    case 0xc07d: return "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 (0xc07d)";
    case 0xc073: return "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 (0xc073)";
    case 0xc077: return "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 (0xc077)";
    case 0x00c4: return "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 (0x00c4)";
    case 0x0088: return "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA (0x0088)";
    case 0xc02b: return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b)";
    case 0xc02f: return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)";
    case 0x009e: return "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 (0x009e)";
    case 0xc0ac: return "TLS_ECDHE_ECDSA_WITH_AES_128_CCM (0xc0ac)";
    case 0xc09e: return "TLS_DHE_RSA_WITH_AES_128_CCM (0xc09e)";
    case 0xc023: return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 (0xc023)";
    case 0xc027: return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (0xc027)";
    case 0x0067: return "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 (0x0067)";
    case 0xc009: return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0xc009)";
    case 0xc013: return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013)";
    case 0x0033: return "TLS_DHE_RSA_WITH_AES_128_CBC_SHA (0x0033)";
    case 0xc0ae: return "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 (0xc0ae)";
    case 0xc0a2: return "TLS_DHE_RSA_WITH_AES_128_CCM_8 (0xc0a2)";
    case 0xc086: return "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 (0xc086)";
    case 0xc08a: return "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 (0xc08a)";
    case 0xc07c: return "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 (0xc07c)";
    case 0xc072: return "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 (0xc072)";
    case 0xc076: return "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 (0xc076)";
    case 0x00be: return "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 (0x00be)";
    case 0x0045: return "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA (0x0045)";
    case 0xc008: return "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA (0xc008)";
    case 0xc012: return "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA (0xc012)";
    case 0x0016: return "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA (0x0016)";
    case 0x00ab: return "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 (0x00ab)";
    case 0xc0a7: return "TLS_DHE_PSK_WITH_AES_256_CCM (0xc0a7)";
    case 0xc038: return "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 (0xc038)";
    case 0x00b3: return "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 (0x00b3)";
    case 0xc036: return "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA (0xc036) ";
    case 0x0091: return "TLS_DHE_PSK_WITH_AES_256_CBC_SHA (0x0091)";
    case 0xc091: return "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 (0xc091)";
    case 0xc09b: return "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 (0xc09b)";
    case 0xc097: return "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 (0xc097)";
    case 0xc0ab: return "TLS_PSK_DHE_WITH_AES_256_CCM_8 (0xc0ab)";
    case 0x00aa: return "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 (0x00aa)";
    case 0xc0a6: return "TLS_DHE_PSK_WITH_AES_128_CCM (0xc0a6)";
    case 0xc037: return "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 (0xc037)";
    case 0x00b2: return "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 (0x00b2)";
    case 0xc035: return "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA (0xc035)";
    case 0x0090: return "TLS_DHE_PSK_WITH_AES_128_CBC_SHA (0x0090)";
    case 0xc090: return "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 (0xc090)";
    case 0xc096: return "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 (0xc096)";
    case 0xc09a: return "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 (0xc09a)";
    case 0xc0aa: return "TLS_PSK_DHE_WITH_AES_128_CCM_8 (0xc0aa)";
    case 0xc034: return "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA (0xc034)";
    case 0x008f: return "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA (0x008f)";
    case 0x009d: return "TLS_RSA_WITH_AES_256_GCM_SHA384 (0x009d)";
    case 0xc09d: return "TLS_RSA_WITH_AES_256_CCM (0xc09d)";
    case 0x003d: return "TLS_RSA_WITH_AES_256_CBC_SHA256 (0x003d)";
    case 0x0035: return "TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)";
    case 0xc032: return "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 (0xc032)";
    case 0xc02a: return "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 (0xc02a)";
    case 0xc00f: return "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA (0xc00f)";
    case 0xc02e: return "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 (0xc02e)";
    case 0xc026: return "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 (0xc026)";
    case 0xc005: return "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA (0xc005)";
    case 0xc0a1: return "TLS_RSA_WITH_AES_256_CCM_8 (0xc0a1)";
    case 0xc07b: return "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 (0xc07b)";
    case 0x00c0: return "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 (0x00c0)";
    case 0x0084: return "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA (0x0084)";
    case 0xc08d: return "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 (0xc08d)  ";
    case 0xc079: return "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 (0xc079)  ";
    case 0xc089: return "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 (0xc089)";
    case 0xc075: return "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 (0xc075)";
    case 0x009c: return "TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009c)";
    case 0xc09c: return "TLS_RSA_WITH_AES_128_CCM (0xc09c)";
    case 0x003c: return "TLS_RSA_WITH_AES_128_CBC_SHA256 (0x003c)";
    case 0x002f: return "TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)";
    case 0xc031: return "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 (0xc031)";
    case 0xc029: return "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 (0xc029)";
    case 0xc00e: return "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA (0xc00e)";
    case 0xc02d: return "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02d)";
    case 0xc025: return "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 (0xc025)";
    case 0xc004: return "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA (0xc004)";
    case 0xc0a0: return "TLS_RSA_WITH_AES_128_CCM_8 (0xc0a0)";
    case 0xc07a: return "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 (0xc07a)";
    case 0x00ba: return "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 (0x00ba)";
    case 0x0041: return "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA (0x0041)";
    case 0xc08c: return "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 (0xc08c)";
    case 0xc078: return "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 (0xc078)";
    case 0xc088: return "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 (0xc088)";
    case 0xc074: return "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 (0xc074)";
    case 0x000a: return "TLS_RSA_WITH_3DES_EDE_CBC_SHA (0x000a)";
    case 0xc00d: return "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA (0xc00d)  ";
    case 0xc003: return "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA (0xc003)";
    case 0x00ad: return "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 (0x00ad)";
    case 0x00b7: return "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 (0x00b7)";
    case 0x0095: return "TLS_RSA_PSK_WITH_AES_256_CBC_SHA (0x0095)";
    case 0xc093: return "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 (0xc093)";
    case 0xc099: return "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 (0xc099)";
    case 0x00ac: return "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 (0x00ac)";
    case 0x00b6: return "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 (0x00b6)";
    case 0x0094: return "TLS_RSA_PSK_WITH_AES_128_CBC_SHA (0x0094)";
    case 0xc092: return "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 (0xc092)";
    case 0xc098: return "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 (0xc098)";
    case 0x0093: return "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA (0x0093)";
    case 0x00a9: return "TLS_PSK_WITH_AES_256_GCM_SHA384 (0x00a9)";
    case 0xc0a5: return "TLS_PSK_WITH_AES_256_CCM (0xc0a5)";
    case 0x00af: return "TLS_PSK_WITH_AES_256_CBC_SHA384 (0x00af)";
    case 0x008d: return "TLS_PSK_WITH_AES_256_CBC_SHA (0x008d)";
    case 0xc08f: return "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 (0xc08f)";
    case 0xc095: return "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 (0xc095)";
    case 0xc0a9: return "TLS_PSK_WITH_AES_256_CCM_8 (0xc0a9)";
    case 0x00a8: return "TLS_PSK_WITH_AES_128_GCM_SHA256 (0x00a8)";
    case 0xc0a4: return "TLS_PSK_WITH_AES_128_CCM (0xc0a4)";
    case 0x00ae: return "TLS_PSK_WITH_AES_128_CBC_SHA256 (0x00ae)";
    case 0x008c: return "TLS_PSK_WITH_AES_128_CBC_SHA (0x008c)";
    case 0xc08e: return "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 (0xc08e)";
    case 0xc094: return "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 (0xc094)";
    case 0xc0a8: return "TLS_PSK_WITH_AES_128_CCM_8 (0xc0a8)";
    case 0x008b: return "TLS_PSK_WITH_3DES_EDE_CBC_SHA (0x008b)";
    case 0xc007: return "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA (0xc007)";
    case 0xc011: return "TLS_ECDHE_RSA_WITH_RC4_128_SHA (0xc011)";
    case 0xc033: return "TLS_ECDHE_PSK_WITH_RC4_128_SHA (0xc033)";
    case 0x008e: return "TLS_DHE_PSK_WITH_RC4_128_SHA (0x008e) ";
    case 0x0005: return "TLS_RSA_WITH_RC4_128_SHA (0x0005)";
    case 0x0004: return "TLS_RSA_WITH_RC4_128_MD5 (0x0004)";
    case 0xc00c: return "TLS_ECDH_RSA_WITH_RC4_128_SHA (0xc00c)";
    case 0xc002: return "TLS_ECDH_ECDSA_WITH_RC4_128_SHA (0xc002) ";
    case 0x0092: return "TLS_RSA_PSK_WITH_RC4_128_SHA (0x0092)";
    case 0x008a: return "TLS_PSK_WITH_RC4_128_SHA (0x008a)";
    case 0x1302: return "TLS_AES_256_GCM_SHA384 (0x1302)";
    case 0x1303: return "TLS_CHACHA20_POLY1305_SHA256 (0x1303)";
    case 0x1301: return "TLS_AES_128_GCM_SHA256 (0x1301)";
    case 0xcca9: return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca9)";
    case 0xcca8: return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca8)";
    case 0xccaa: return "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xccaa)";
    default:return "0x" + QString::number(code,16);
    }
}
/********************** get tls handshake compression **********************/
QString DataPackage::getTlsHandshakeCompression(u_char code){
    switch (code) {
    case 0:return "null";
    default:return "";
    }
}

QString DataPackage::getTlsHandshakeExtension(u_short type){
    switch (type) {
    case 0: return "server_name";
    case 5: return "status_request";
    case 11:return "ec_point_format";
    case 10:return "supported_groups";
    case 35:return "session_ticket";
    case 22:return "encrypt_then_mac";
    case 23:return "extended_master_secret";
    case 13:return "signature_algorithms";
    case 43:return "supported_versions";
    case 45:return "psk_key_exchange_modes";
    case 51:return "key_share";
    case 21:return "padding";
    case 18:return "signed_certificate_timestamp";
    case 39578:return "Reserved (GREASE) (39578)";
    default:return "Unknown type";
    }
}

QString DataPackage::getTlsHandshakeExtensionECPointFormat(u_char type){
    switch (type) {
    case 0:return "EC point format: uncompressed (0)";
    case 1:return "EC point format: ansiX962_compressed_prime (1)";
    case 2:return "EC point format: ansiX962_compressed_char2 (2)";
    default:return QString::number(type);
    }
}

QString DataPackage::getTlsHandshakeExtensionSupportGroup(u_short type){
    switch (type) {
    case 0x001d:return "x25519 (0x001d)";
    case 0x0017:return "secp256r1 (0x0017)";
    case 0x001e:return "x448 (0x001e)";
    case 0x0019:return "secp521r1 (0x0019)";
    case 0x0018:return "secp384r1 (0x0018)";
    case 0x001c:return "brainpoolP512r1 (0x001c)";
    case 0x001b:return "brainpoolP384r1 (0x001b)";
    case 0x0016:return "secp256k1 (0x0016)";
    case 0x001a:return "brainpoolP256r1 (0x001a)";
    case 0x0015:return "secp224r1 (0x0015)";
    case 0x0014:return "secp224k1 (0x0014)";
    case 0x0013:return "secp192r1 (0x0013)";
    case 0x0012:return "secp192k1 (0x0012)";
    default:return "0x" + QString::number(type,16);
    }
}

QString DataPackage::getTlsHadshakeExtensionHash(u_char type){
    switch (type) {
    case 4:return "SHA256";
    case 5:return "SHA384";
    case 6:return "SHA512";
    case 2:return "SHA1";
    case 3:return "SHA224";
    case 1:return "MD5";
    default:return "Unknown";
    }
}
QString DataPackage::getTlsHadshakeExtensionSignature(u_char type){
    switch (type) {
    case 1:return "RSA";
    case 2:return "DSA";
    case 3:return "ECDSA";
    default:return "Unknown";
    }
}
u_short DataPackage::getTlsExtensionType(int offset){
    u_short*ssl;
    ssl = (u_short*)(pkt_content + 14 + 20 + offset);
    return ntohs(*ssl);
}

void DataPackage::getTlsExtensionServerName(int offset, u_short &type, u_short &length, u_short &listLength, u_char &nameType, u_short &nameLength, QString &name){
    u_short*ssl;
    ssl = (u_short*)(pkt_content + 14 + 20 + offset);
    type = ntohs(*ssl);
    ssl++;
    length = ntohs(*ssl);
    ssl++;
    listLength = ntohs(*ssl);
    ssl++;
    u_char*p = (u_char*)ssl;
    nameType = *p;
    p++;
    nameLength = (*p) * 16 + *(p+1);
    p += 2;
    for(int i = 0;i < nameLength;i++){
        name += (*p);
        p++;
    }
    return;
}

void DataPackage::getTlsExtensionKeyShare(int offset, u_short &type, u_short &length, u_short &shareLength, u_short &group, u_short &exchangeLength,QString &exchange){
    u_short*ssl;
    ssl = (u_short*)(pkt_content + 14 + 20 + offset);
    type = ntohs(*ssl);
    ssl++;
    length = ntohs(*ssl);
    ssl++;
    shareLength = ntohs(*ssl);
    ssl++;
    group = ntohs(*ssl);
    ssl++;
    exchangeLength = ntohs(*ssl);
    ssl++;
    u_char*point = (u_char*)(ssl);
    for(int i = 0;i < exchangeLength;i++){
        exchange += QString::number(*point,16);
        point++;
    }
}

void DataPackage::getTlsExtensionEcPointFormats(int offset, u_short &type, u_short &length,u_char& ecLength,QVector<u_char> &EC){
    u_short*ssl;
    ssl = (u_short*)(pkt_content + 14 + 20 + offset);
    type = ntohs(*ssl);
    ssl++;
    length = ntohs(*ssl);
    ssl++;
    u_char* point = (u_char*)(ssl);
    ecLength = *point;
    point++;
    for(int i = 0;i < ecLength;i++){
        EC.push_back(*point);
        point++;
    }
}

void DataPackage::getTlsExtensionOther(int offset, u_short &type, u_short &length,QString&data){
    u_short*ssl;
    ssl = (u_short*)(pkt_content + 14 + 20 + offset);
    type = ntohs(*ssl);
    ssl++;
    length = ntohs(*ssl);
    ssl++;
    u_char*point = (u_char*)(ssl);
    for(int i = 0;i < length;i++){
        data += QString::number(*point,16);
        point++;
    }
}

void DataPackage::getTlsExtensionSupportGroups(int offset, u_short &type, u_short &length, u_short &groupListLength, QVector<u_short> &group){
    u_short*ssl;
    ssl = (u_short*)(pkt_content + 14 + 20 + offset);
    type = ntohs(*ssl);
    ssl++;
    length = ntohs(*ssl);
    ssl++;
    groupListLength = ntohs(*ssl);
    ssl++;
    for(int i = 0;i < groupListLength/2;i++){
        group.push_back(ntohs(*ssl));
        ssl++;
    }
}

void DataPackage::getTlsExtensionSessionTicket(int offset, u_short &type, u_short &length){
    u_short*ssl;
    ssl = (u_short*)(pkt_content + 14 + 20 + offset);
    type = ntohs(*ssl);
    ssl++;
    length = ntohs(*ssl);
    ssl++;
}

void DataPackage::getTlsExtensionEncryptThenMac(int offset, u_short &type, u_short &length){
    u_short*ssl;
    ssl = (u_short*)(pkt_content + 14 + 20 + offset);
    type = ntohs(*ssl);
    ssl++;
    length = ntohs(*ssl);
}

void DataPackage::getTlsExtensionExtendMasterSecret(int offset, u_short &type, u_short &length){
    u_short*ssl;
    ssl = (u_short*)(pkt_content + 14 + 20 + offset);
    type = ntohs(*ssl);
    ssl++;
    length = ntohs(*ssl);
}

void DataPackage::getTlsExtensionSignatureAlgorithms(int offset, u_short &type, u_short &length, u_short &algorithmLength, QVector<u_short> &signatureAlgorithm){
    u_short*ssl;
    ssl = (u_short*)(pkt_content + 14 + 20 + offset);
    type = ntohs(*ssl);
    ssl++;
    length = ntohs(*ssl);
    ssl++;
    algorithmLength = ntohs(*ssl);
    ssl++;
    for(int i = 0;i < algorithmLength/2;i++){
        signatureAlgorithm.push_back(ntohs(*ssl));
        ssl++;
    }
}

void DataPackage::getTlsExtensionSupportVersions(int offset, u_short &type, u_short &length, u_char &supportLength, QVector<u_short> &supportVersion){
    u_short*ssl;
    ssl = (u_short*)(pkt_content + 14 + 20 + offset);
    type = ntohs(*ssl);
    ssl++;
    length = ntohs(*ssl);
    ssl++;
    u_char*point = (u_char*)(ssl);
    supportLength = *point;
    point++;
    ssl = (u_short*)(point);
    for(int i = 0;i < supportLength;i++){
        supportVersion.push_back(ntohs(*ssl));
        ssl++;
    }
}
void DataPackage::getTlsExtensionPadding(int offset, u_short &type, u_short &length,QString& data){
    u_short*ssl;
    ssl = (u_short*)(pkt_content + 14 + 20 + offset);
    type = ntohs(*ssl);
    ssl++;
    length = ntohs(*ssl);
    ssl++;
    u_char*point = (u_char*)(ssl);
    for(int i = 0;i < length;i++){
        data += QString::number(*point,16);
        point++;
    }
}

```



## mainwindow.cpp









# UML类图

## Caputure代码解释

![image-20230615143920935](C:\Users\echo\AppData\Roaming\Typora\typora-user-images\image-20230615143920935.png)

``` plantUML
@startuml

class Capture {
  - pointer: pcap_t*
  - header: pcap_pkthdr*
  - pkt_data: const u_char*
  - local_time_version_sec: time_t
  - local_time: tm
  - timeString: char[16]
  - isDone: volatile bool
  - filterStr: QString

  + Capture(filterStr: QString)
  + setPointer(pointer: pcap_t*): bool
  + setFlag(): void
  + resetFlag(): void
  + ethernetPackageHandle(pkt_content: const u_char*, info: QString&): int
  + ipPackageHandle(pkt_content: const u_char*, ipPackage: int&): int
  + arpPackageHandle(pkt_content: const u_char*): QString
  + icmpPackageHandle(pkt_content: const u_char*): QString
  + tcpPackageHandle(pkt_content: const u_char*, info: QString&, ipPackage: int): int
  + udpPackageHandle(pkt_content: const u_char*, info: QString&): int
  + dnsPackageHandle(pkt_content: const u_char*): QString
  + setFilterStr(filterstr: QString): void
  + getFilterStr(): QString
  + run(): void
  + send(data: DataPackage): void
}

Capture "1" -- "1" QThread

@enduml
```

## datapackage

![XLR1Kjim4Btp5JfrJA4_aEbqe52Q3D2uaGlJ4oEaZQE9BRdIcfHs-kzLb9WgwIfSFB3lxTjzQwsZCu_2OTysHx8HthDBWQ8KSYbgOB-F67l7L8WyD61gN8nO_w0DnZ3g5ZYAjXknhnoTDdKCQpEtkv5kerOzTp1Yc-mJrYtnGLg3O734mXyUWxHS2FSsvZm-8rHs33yBZsuqGAVCwry](D:\StudyNotes\课程笔记\大三下\数字取证\XLR1Kjim4Btp5JfrJA4_aEbqe52Q3D2uaGlJ4oEaZQE9BRdIcfHs-kzLb9WgwIfSFB3lxTjzQwsZCu_2OTysHx8HthDBWQ8KSYbgOB-F67l7L8WyD61gN8nO_w0DnZ3g5ZYAjXknhnoTDdKCQpEtkv5kerOzTp1Yc-mJrYtnGLg3O734mXyUWxHS2FSsvZm-8rHs33yBZsuqGAVCwry.png)

``` cpp
#ifndef DATAPACKAGE_H
#define DATAPACKAGE_H

#include <QString>
#include "Format.h"


/*
 * This class is describe the data package infomation
 * +-----+------------+
 * | type| infomation |
 * +-----+------------+
 * |  1  |    arp     |
 * +-----+------------+
 * |  2  |    icmp    |
 * +-----+------------+
 * |  3  |    tcp     |
 * +-----+------------+
 * |  4  |    udp     |
 * +-----+------------+
 * |  5  |    dns     |
 * +-----+------------+
 * |  6  |    tls     |
 * +-----+------------+
 * |  7  |    ssl     |
 * +-----+------------+
*/
class DataPackage
{
private:
    u_int data_length; // data pakage length
    QString timeStamp; // timestamp of package
    QString info;      // a breif introduction of package
    int packageType;   // type

public:
    const u_char *pkt_content; // root pointer of package data

protected:
    /*
     * turn the byteArray to QString
     * "OX9011CD" -> "0XABCDEF"
    */
    static QString byteToHex(u_char*str,int size);
public:
    // Construction and destruction
    DataPackage();
    ~DataPackage() = default;

    // set the var
    void setDataLength(unsigned int length);                    // set the package length
    void setTimeStamp(QString timeStamp);                       // set timestamp
    void setPackageType(int type);                              // set package type
    void setPackagePointer(const u_char *pkt_content,int size); // set package pointer
    void setPackageInfo(QString info);                          // set package information

    // get the var
    QString getDataLength();                  // get package length
    QString getTimeStamp();                   // get timestamp
    QString getPackageType();                 // get package type
    QString getInfo();                        // get a breif package information
    QString getSource();                      // get the source address of package
    QString getDestination();                 // get the destination address of package

    // get the mac info
    QString getDesMacAddr();                  // get the destination MAC address
    QString getSrcMacAddr();                  // get the source MAC address
    QString getMacType();                     // get the type of MAC address

    // get the ip info
    QString getDesIpAddr();                   // get the destination ip address
    QString getSrcIpAddr();                   // get the source ip address
    QString getIpVersion();                   // get the ip version
    QString getIpHeaderLength();              // get the ip head length
    QString getIpTos();                       // get the ip tos
    QString getIpTotalLength();               // get the ip total package length
    QString getIpIdentification();            // get the ip identification
    QString getIpFlag();                      // get the ip flag
    QString getIpReservedBit();               // the reserved bit
    QString getIpDF();                        // Don't fragment
    QString getIpMF();                        // More fragment
    QString getIpFragmentOffset();            // get the offset of package
    QString getIpTTL();                       // get ip ttl [time to live]
    QString getIpProtocol();                  // get the ip protocol
    QString getIpCheckSum();                  // get the checksum

    // get the icmp info
    QString getIcmpType();                    // get the icmp type
    QString getIcmpCode();                    // get the icmp code
    QString getIcmpCheckSum();                // get the icmp checksum
    QString getIcmpIdentification();          // get the icmp identification
    QString getIcmpSequeue();                 // get the icmp sequence
    QString getIcmpData(int size);            // get the icmp data

    // get the arp info
    QString getArpHardwareType();             // get arp hardware type
    QString getArpProtocolType();             // get arp protocol type
    QString getArpHardwareLength();           // get arp hardware length
    QString getArpProtocolLength();           // get arp protocol length
    QString getArpOperationCode();            // get arp operation code
    QString getArpSourceEtherAddr();          // get arp source ethernet address
    QString getArpSourceIpAddr();             // get arp souce ip address
    QString getArpDestinationEtherAddr();     // get arp destination ethernet address
    QString getArpDestinationIpAddr();        // get arp destination ip address

    // get the tcp info
    QString getTcpSourcePort();               // get tcp source port
    QString getTcpDestinationPort();          // get tcp destination port
    QString getTcpSequence();                 // get tcp sequence
    QString getTcpAcknowledgment();           // get acknowlegment
    QString getTcpHeaderLength();             // get tcp head length
    QString getTcpRawHeaderLength();          // get tcp raw head length [default is 0x05]
    QString getTcpFlags();                    // get tcp flags
    QString getTcpPSH();                      // PSH flag
    QString getTcpACK();                      // ACK flag
    QString getTcpSYN();                      // SYN flag
    QString getTcpURG();                      // URG flag
    QString getTcpFIN();                      // FIN flag
    QString getTcpRST();                      // RST flag
    QString getTcpWindowSize();               // get tcp window size
    QString getTcpCheckSum();                 // get tcp checksum
    QString getTcpUrgentPointer();            // get tcp urgent pointer
    QString getTcpOperationKind(int kind);    // get tcp option kind
    int getTcpOperationRawKind(int offset);   // get tcp raw option kind

    /*
     * tcp optional parts
    */
    bool getTcpOperationMSS(int offset,u_short& mss);                          // kind = 2
    bool getTcpOperationWSOPT(int offset,u_char&shit);                         // kind = 3
    bool getTcpOperationSACKP(int offset);                                     // kind = 4
    bool getTcpOperationSACK(int offset,u_char&length,QVector<u_int>&edge);    // kind = 5
    bool getTcpOperationTSPOT(int offset,u_int& value,u_int&reply);            // kind = 8

    // get the udp info
    QString getUdpSourcePort();               // get udp source port
    QString getUdpDestinationPort();          // get udp destination port
    QString getUdpDataLength();               // get udp data length
    QString getUdpCheckSum();                 // get udp checksum

    // get the dns info
    QString getDnsTransactionId();            // get dns transaction id
    QString getDnsFlags();                    // get dns flags
    QString getDnsFlagsQR();                  // get dns flag QR
    QString getDnsFlagsOpcode();              // get dns flag operation code
    QString getDnsFlagsAA();                  // get dns flag AA
    QString getDnsFlagsTC();                  // get dns flag TC
    QString getDnsFlagsRD();                  // get dns flag RD
    QString getDnsFlagsRA();                  // get dns flag RA
    QString getDnsFlagsZ();                   // get dns flag Z [reserved]
    QString getDnsFlagsRcode();               // get dns flag Rcode
    QString getDnsQuestionNumber();           // get dns question number
    QString getDnsAnswerNumber();             // get dns answer number
    QString getDnsAuthorityNumber();          // get dns authority number
    QString getDnsAdditionalNumber();         // get dns addition number
    void getDnsQueriesDomain(QString&name,int&Type,int&Class);
    QString getDnsDomainType(int type);
    QString getDnsDomainName(int offset);
    int getDnsAnswersDomain(int offset,QString&name1,u_short&Type,u_short& Class,u_int&ttl,u_short&dataLength,QString& name2);

    // get the tls info
    bool getisTlsProtocol(int offset);
    void getTlsBasicInfo(int offset,u_char&contentType,u_short&version,u_short&length);
    void getTlsClientHelloInfo(int offset,u_char&handShakeType,int& length,u_short&version,QString&random,u_char&sessionIdLength,QString&sessionId,u_short&cipherLength,QVector<u_short>&cipherSuit,u_char& cmLength,QVector<u_char>&CompressionMethod,u_short&extensionLength);
    void getTlsServerHelloInfo(int offset,u_char&handShakeType,int&length,u_short&version,QString& random,u_char&sessionIdLength,QString&sessionId,u_short&cipherSuit,u_char&compressionMethod,u_short&extensionLength);
    void getTlsServerKeyExchange(int offset,u_char&handShakeType,int&length,u_char&curveType,u_short&curveName,u_char&pubLength,QString&pubKey,u_short&sigAlgorithm,u_short&sigLength,QString&sig);
    u_short getTlsExtensionType(int offset);
    void getTlsHandshakeType(int offset,u_char&type);

    /*
     * these functions are used to parse the extension parts
     * extension parts are common in handshake parts (client hello,server hello ...)
     * there are some extension types are not included in, maybe you should refer the official API
    */
    void getTlsExtensionServerName(int offset,u_short&type,u_short&length,u_short&listLength,u_char&nameType,u_short&nameLength,QString& name);
    void getTlsExtensionSignatureAlgorithms(int offset,u_short&type,u_short&length,u_short&algorithmLength,QVector<u_short>&signatureAlgorithm);
    void getTlsExtensionSupportGroups(int offset,u_short&type,u_short&length,u_short&groupListLength,QVector<u_short>&group);
    void getTlsExtensionEcPointFormats(int offset,u_short&type,u_short&length,u_char& ecLength,QVector<u_char>&EC);
    void getTlsExtensionSessionTicket(int offset,u_short&type,u_short&length);
    void getTlsExtensionEncryptThenMac(int offset,u_short&type,u_short&length);
    void getTlsExtensionSupportVersions(int offset,u_short&type,u_short&length,u_char&supportLength,QVector<u_short>&supportVersion);
    void getTlsExtensionPskKeyExchangeModes(int offset,u_short&type,u_short&length,u_char&modeLength,QVector<u_char>&mode);
    void getTlsExtensionKeyShare(int offset,u_short&type,u_short&length,u_short&shareLength,u_short&group,u_short&exchangeLength,QString& exchange);
    void getTlsExtensionOther(int offset,u_short&type,u_short&length,QString& data);
    void getTlsExtensionExtendMasterSecret(int offset,u_short&type,u_short&length);
    void getTlsExtensionPadding(int offset,u_short&type,u_short&length,QString&data);

    /*
     * when transfer data,some types will be encoded,like using 0x01 to represent the MD5 in extension hash part
     * to visual display these types,we need to decode and analysis
     * this functions are used to do these analisis
     * however,some types may be the custom types, so we can't decode
     * also,there are some rules not be included, maybe you should refer the official API
    */
    // Parsing the encode data
};

#endif // DATAPACKAGE_H

```



## Format类 

``` cpp
```





