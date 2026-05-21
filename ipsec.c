#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <openssl/evp.h>

#define BUFFER_SIZE 65536
#define ESP_PROTO 50

typedef struct esp_header {
    uint32_t spi;
    uint32_t seq;
} ESPHeader;

unsigned char aes_key[32] = {
    0x11,0x11,0x11,0x11,
    0x11,0x11,0x11,0x11,
    0x11,0x11,0x11,0x11,
    0x11,0x11,0x11,0x11,
    0x22,0x22,0x22,0x22,
    0x22,0x22,0x22,0x22,
    0x22,0x22,0x22,0x22,
    0x22,0x22,0x22,0x22
};

unsigned char iv[16] = {
    0x00,0x01,0x02,0x03,
    0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,
    0x0c,0x0d,0x0e,0x0f
};

int encrypt_payload(unsigned char *plaintext,
                    int plaintext_len,
                    unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    ctx = EVP_CIPHER_CTX_new();

    EVP_EncryptInit_ex(ctx,
                       EVP_aes_256_cbc(),
                       NULL,
                       aes_key,
                       iv);

    EVP_EncryptUpdate(ctx,
                      ciphertext,
                      &len,
                      plaintext,
                      plaintext_len);

    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx,
                        ciphertext + len,
                        &len);

    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int main()
{
    int sockfd;
    char buffer[BUFFER_SIZE];

    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    printf("Listening for packets...\n");

    while (1) {

        struct sockaddr saddr;
        socklen_t saddr_len = sizeof(saddr);

        int data_size = recvfrom(sockfd,
                                 buffer,
                                 BUFFER_SIZE,
                                 0,
                                 &saddr,
                                 &saddr_len);

        if (data_size < 0) {
            perror("recvfrom");
            break;
        }

        struct iphdr *ip = (struct iphdr *)buffer;

        printf("Captured Packet: %s -> ",
               inet_ntoa(*(struct in_addr *)&ip->saddr));

        printf("%s\n",
               inet_ntoa(*(struct in_addr *)&ip->daddr));

        unsigned char encrypted[BUFFER_SIZE];

        int iphdrlen = ip->ihl * 4;

        unsigned char *payload =
            (unsigned char *)(buffer + iphdrlen);

        int payload_len = data_size - iphdrlen;

        int encrypted_len =
            encrypt_payload(payload,
                            payload_len,
                            encrypted);

        ESPHeader esp;

        esp.spi = htonl(0x12345678);
        esp.seq = htonl(1);

        unsigned char outpacket[BUFFER_SIZE];

        memcpy(outpacket,
               buffer,
               iphdrlen);

        memcpy(outpacket + iphdrlen,
               &esp,
               sizeof(ESPHeader));

        memcpy(outpacket + iphdrlen + sizeof(ESPHeader),
               encrypted,
               encrypted_len);

        struct iphdr *newip =
            (struct iphdr *)outpacket;

        newip->protocol = ESP_PROTO;

        int total_len =
            iphdrlen +
            sizeof(ESPHeader) +
            encrypted_len;

        newip->tot_len = htons(total_len);

        int send_sock =
            socket(AF_INET,
                   SOCK_RAW,
                   IPPROTO_RAW);

        if (send_sock < 0) {
            perror("send socket");
            continue;
        }

        int one = 1;

        setsockopt(send_sock,
                   IPPROTO_IP,
                   IP_HDRINCL,
                   &one,
                   sizeof(one));

        struct sockaddr_in dest;

        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = ip->daddr;

        if (sendto(send_sock,
                   outpacket,
                   total_len,
                   0,
                   (struct sockaddr *)&dest,
                   sizeof(dest)) < 0) {

            perror("sendto");
        }
        else {
            printf("ESP packet sent\n");
        }

        close(send_sock);
    }

    close(sockfd);

    return 0;
}
