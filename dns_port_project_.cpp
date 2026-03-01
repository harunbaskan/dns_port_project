

#include <iostream> // cout, cin icin  kullanıyor
#include <string>// string veri tipi için
#include <cstring> // strcpy, strcat, memset için (C tarzı string işlemleri)
#include <winsock2.h>   // Windows soket fonksiyonları (socket, sendto, recvfrom)
#include <ws2tcpip.h> // IP adresi dönüşüm fonksiyonları (inet_pton, inet_addr)

#pragma comment(lib, "ws2_32.lib") // Derleyiciye: ws2_32.lib kütüphanesini bağla

using namespace std; // std:: yazmamak için (cout yerine std::cout yazmaya gerek yok)

// dns sunucusu ayarlari
#define DNS_SERVER_IP "8.8.8.8" // Google'ın DNS sunucusu googleın herkese açık dns sunucusu 
#define DNS_SERVER_PORT 53    // DNS standart portu  dns protokolü için kabul edilmiş standart port

// taranacak portlar
int port_list[] = {22, 80, 443};
string service_names[] = {"SSH", "HTTP", "HTTPS"};
int total_ports = 3;  // Kaç port tarayacağız

// tarama sonuclari
string scan_results[3];


// dns header yapisi (12 byte)
#pragma pack(push, 1) // Derleyiciye: boşluk bırakma, sıkıştır
struct DnsHeader {
    unsigned short id;
    unsigned short flags;                      //DNS paketi tam 12 byte olmalı.
    unsigned short question_count;
    unsigned short answer_count;
    unsigned short authority_count;
    unsigned short additional_count;
};

struct DnsQuestion {
    unsigned short qtype;
    unsigned short qclass;
};
#pragma pack(pop) // Sıkıştırmayı kapat, normale dön


// winsock baslatma cunku windowsta  udp ve tcp kullanabilmek için
bool init_winsock() { // Winsock bilgilerini tutacak yapı

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { //Winsock 2.2 sürümünü açıyorum, soket altyapısını hazırla
        cout << "Winsock hatasi!" << endl;
        return false;
    }
    return true;
}

void cleanup_winsock() {
    WSACleanup();
}


/*
    Alan adini DNS formatina cevir
    ornek: "google.com" -> "\x06google\x03com\x00"
*/
void encode_domain(const char* domain, unsigned char* output) {
    int lock_pos = 0;
    char temp[256];
    
    strcpy(temp, domain);
    strcat(temp, ".");
    
    for (int i = 0; i < (int)strlen(temp); i++) {
        if (temp[i] == '.') {
            *output++ = i - lock_pos;
            for (; lock_pos < i; lock_pos++) {
                *output++ = temp[lock_pos];
            }
            lock_pos++;
        }
    }
    *output = 0;
}


/*
    DNS yanitindaki ismi atla
*/
int skip_name(unsigned char* buffer, int pos) {
    unsigned char len = buffer[pos];
    
    while (len != 0) {
        if ((len & 0xC0) == 0xC0) {
            return pos + 2;
        }
        pos += len + 1;
        len = buffer[pos];
    }
    return pos + 1;
}


/*
    DNS Cozumleme Fonksiyonu
    
    Adimlar:
    1. UDP soketi olustur
    2. DNS paketi hazirla
    3. 8.8.8.8 adresine gonder
    4. Cevabi al ve IP bul
*/
string resolve_domain(const char* domain) {
    
    SOCKET udp_sock;
    struct sockaddr_in server_addr;
    unsigned char request[512];
    unsigned char response[512];
    int request_size = 0;
    
    cout << "[*] DNS sorgusu hazirlaniyor..." << endl;
    
    // soket olustur
    udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_sock == INVALID_SOCKET) {
        cout << "Soket hatasi!" << endl;
        return "";
    }
    
    // timeout
    int timeout_ms = 3000;
    setsockopt(udp_sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout_ms, sizeof(timeout_ms));
    
    // sunucu adresi
    server_addr.sin_family = AF_INET; //IPv4 kullanıcaz
    server_addr.sin_port = htons(DNS_SERVER_PORT); // portu ağ formatına çevirir.
    server_addr.sin_addr.s_addr = inet_addr(DNS_SERVER_IP); //IP adresini string’ten IPv4 sayısına çevirir. kaynagı winsock
    
    // paketi temizle
    memset(request, 0, 512);
    
    // header doldur
    struct DnsHeader* header = (struct DnsHeader*)request;
    header->id = htons(1234);
    header->flags = htons(0x0100);  // RD=1 (recursion desired) DNS sunucusu benim adıma çözümleme yapsın
    header->question_count = htons(1);//1 soru sorduk
    header->answer_count = 0;
    header->authority_count = 0;
    header->additional_count = 0;
    
    request_size = sizeof(struct DnsHeader);
    
    // domain ekle
    unsigned char* qname = request + request_size;
    encode_domain(domain, qname);//headerdan sonra domain adinida pakete ekleme
    request_size += strlen((char*)qname) + 1;
    
    // soru tipi ekle
    struct DnsQuestion* question = (struct DnsQuestion*)(request + request_size);
    question->qtype = htons(1);     // A kaydi
    question->qclass = htons(1);    // Internet
    request_size += sizeof(struct DnsQuestion);
    
    cout << "[*] Paket gonderiliyor -> " << DNS_SERVER_IP << ":" << DNS_SERVER_PORT << endl;
    
    // gonder
    if (sendto(udp_sock, (char*)request, request_size, 0,
               (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        cout << "Gonderme hatasi!" << endl;
        closesocket(udp_sock);
        return "";
    }
    
    // cevap al
    int addr_len = sizeof(server_addr);
    int received = recvfrom(udp_sock, (char*)response, 512, 0,
                            (struct sockaddr*)&server_addr, &addr_len);
    
    if (received < 0) {
        cout << "Timeout! Cevap alinamadi." << endl;
        closesocket(udp_sock);
        return "";
    }
    
    cout << "[*] Cevap alindi (" << received << " byte)" << endl;
    
    // cevabi isle
    struct DnsHeader* resp_header = (struct DnsHeader*)response;
    int num_answers = ntohs(resp_header->answer_count);
    
    if (num_answers == 0) {
        cout << "Sonuc bulunamadi!" << endl;
        closesocket(udp_sock);
        return "";
    }
    
    // soru kismini atla
    int pos = sizeof(struct DnsHeader);
    pos = skip_name(response, pos);
    pos += sizeof(struct DnsQuestion);
    
    // cevaplari oku
    for (int i = 0; i < num_answers; i++) {
        
        pos = skip_name(response, pos);
        
        unsigned short type = ntohs(*(unsigned short*)(response + pos));
        pos += 2;
        pos += 2;  // class
        pos += 4;  // ttl
        
        unsigned short data_len = ntohs(*(unsigned short*)(response + pos));
        pos += 2;
        
        // A kaydi mi? (type=1, len=4)
        if (type == 1 && data_len == 4) {
            unsigned char* ip = response + pos;
            
            char ip_string[16];
            sprintf(ip_string, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
            
            closesocket(udp_sock);
            return string(ip_string);
        }
        
        pos += data_len;
    }
    
    closesocket(udp_sock);
    return "";
}


/*
    TCP Port Tarama
    

*/
string scan_port(string target_ip, int port) {
    
    SOCKET tcp_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    
    if (tcp_sock == INVALID_SOCKET) {
        return "ERROR";
    }
    
    // timeout
    int timeout_ms = 2000;
    setsockopt(tcp_sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout_ms, sizeof(timeout_ms));
    setsockopt(tcp_sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout_ms, sizeof(timeout_ms));
    
    // hedef
    struct sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    inet_pton(AF_INET, target_ip.c_str(), &target.sin_addr);
    
    // baglan
    int result = connect(tcp_sock, (struct sockaddr*)&target, sizeof(target));// three handshake burda connect ile otomatik olarak os arka planda yapti
    
    closesocket(tcp_sock);
    
    if (result == 0) {
        return "OPEN";
    }
    
    int err = WSAGetLastError();
    if (err == WSAECONNREFUSED) {
        return "CLOSED";
    }
    
    return "FILTERED";
}


int main() {
    
    string input_domain;
    string resolved_ip;
    
    cout << endl;
    cout << "========================================" << endl;
    cout << "         AG TANILAMA ARACI             " << endl;
    cout << "   Manuel DNS + TCP Port Tarama        " << endl;
    cout << "========================================" << endl;
    cout << endl;
    
    if (!init_winsock()) {
        return 1;
    }
    
    // kullanicidan al
    cout << "Alan adi girin: ";
    cin >> input_domain;
    cout << endl;
    
    // dns cozumle
    resolved_ip = resolve_domain(input_domain.c_str());
    
    if (resolved_ip.empty()) {
        cout << "[!] DNS basarisiz!" << endl;
        cleanup_winsock();
        return 1;
    }
    
    cout << "[+] IP Adresi: " << resolved_ip << endl;
    cout << endl;
    
    // port tara
    cout << "[*] Port taramasi basliyor..." << endl;
    cout << endl;
    
    for (int i = 0; i < total_ports; i++) {
        cout << "    " << port_list[i] << "/" << service_names[i] << " -> ";
        scan_results[i] = scan_port(resolved_ip, port_list[i]);
        cout << scan_results[i] << endl;
    }
    
    // sonuclar
    cout << endl;
    cout << "========================================" << endl;
    cout << "              SONUCLAR                 " << endl;
    cout << "========================================" << endl;
    cout << "Domain: " << input_domain << endl;
    cout << "IP: " << resolved_ip << endl;
    cout << "DNS Server: " << DNS_SERVER_IP << endl;
    cout << "----------------------------------------" << endl;
    cout << "PORT    SERVICE   STATUS" << endl;
    cout << "----------------------------------------" << endl;
    
    for (int i = 0; i < total_ports; i++) {
        cout << port_list[i] << "     " << service_names[i];
        
        if (service_names[i].length() < 5) cout << "      ";
        else cout << "     ";
        
        cout << scan_results[i] << endl;
    }
    
    cout << "----------------------------------------" << endl;
    cout << endl;
    cout << "[+] Tarama tamamlandi." << endl;
    
    cleanup_winsock();
    
    return 0;
}