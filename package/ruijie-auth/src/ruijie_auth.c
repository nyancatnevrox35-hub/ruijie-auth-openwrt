/*
 * ruijie_auth.c - OpenWrt Ruijie 802.1X EAP-MD5 认证客户端(逆向重写版)
 *
 * 本实现不依赖抓包中的具体设备数据:设备信息在运行时从路由器动态采集,
 * 无法采集的字段按官方客户端算法随机生成或使用逆向得到的常量。
 *
 * 逆向依据:
 *   - ruijie_auth.pcapng          认证流程与 trailer 帧结构
 *   - 8021x_decompiled.c          官方 8021x.exe 6.84 反编译(字段生成算法)
 *
 * 认证流程(与官方客户端一致):
 *   EAPOL-Start -> Request/Identity -> Response/Identity(+trailer)
 *   -> Request/MD5-Challenge -> Response/MD5(+trailer) -> Success
 *
 * 私有 trailer(585 字节)由官方函数 EncapRGVerdorSegForPeap 生成,
 * TLV 格式: [1a][total_len][00 00 13 11][tag][lenfield][value]
 *           total_len = 8 + value_len, lenfield = 2 + value_len
 *
 * 关键字段来源(逆向结论):
 *   0x02  客户端版本(常量)
 *   0x17  会话串:官方超时路径用 rand() 随机生成,服务器必须容忍随机值
 *   0x18  固定 00 00 00 01
 *   0x2d  本机 MAC(动态采集;服务端设备绑定锚点)
 *   0x2f  16 字节随机数据
 *   0x35  DHCP 认证阶段(常量)
 *   0x36  链路本地 IPv6(由 MAC 推导 EUI-64)
 *   0x38  临时 IPv6(随机 64 位后缀)
 *   0x4e  全局 IPv6(动态采集,无则全零)
 *   0x4d  128 字节环境指纹(官方含 PID+随机数,不用于设备绑定;随机填充)
 *   0x39  固定 d0a3cde2 + 零
 *   0x54  Static:AB45A862 + 零填充(常量)
 *   0x62/0x6b/0x70/0x6f/0x79  固定小字段(常量)
 *   0x7e  固定 00 00 01 00 00 0c 00 00(常量)
 *   0x76  认证服务器列表 "202.199.30.31;202.199.29.94"(常量)
 *
 * EAP-MD5 挑战响应用标准 RFC 3748:MD5(EAP_id || password || challenge)。
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <limits.h>
#include <math.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <getopt.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/sockios.h>
#include <arpa/inet.h>

#ifndef ETH_P_EAPOL
#define ETH_P_EAPOL 0x888E
#endif

#define EAPOL_VERSION 1
#define EAPOL_EAP_PACKET 0
#define EAPOL_START 1
#define EAPOL_LOGOFF 2

#define EAP_REQUEST 1
#define EAP_RESPONSE 2
#define EAP_SUCCESS 3
#define EAP_FAILURE 4

#define EAP_TYPE_IDENTITY 1
#define EAP_TYPE_MD5 4

#define DEFAULT_INTERFACE "eth0"
#define DEFAULT_TIMEOUT 3.0
#define DEFAULT_RETRY_DELAY 3.0
#define DEFAULT_START_BURST 2
#define DEFAULT_AUTH_SERVERS "202.199.30.31;202.199.29.94"

#define MAX_USERNAME_LEN 64
#define MAX_PASSWORD_LEN 64

/* ---------------- 逆向得到的常量 ---------------- */

static const uint8_t RUIJIE_PAE_GROUP[6] = {0x01, 0xd0, 0xf8, 0x00, 0x00, 0x03};
static const uint8_t BROADCAST[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

/* trailer 固定头(23 字节,逆向常量) */
static const uint8_t TRAILER_HEADER[23] = {
    0xff, 0xff, 0x37, 0x77, 0x7f, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
    0xfc, 0xff, 0xca, 0xe7, 0xff, 0x7f, 0xac, 0x1c, 0x27, 0x07, 0x06, 0xfd
};

/* TLV 魔数 */
static const uint8_t TLV_MAGIC[4] = {0x00, 0x00, 0x13, 0x11};

/* 设备段进程名 "8021x.exe"(官方常量) */
static const uint8_t CLIENT_EXE_NAME[9] = {
    '8', '0', '2', '1', 'x', '.', 'e', 'x', 'e'
};

/* 0x54 值:Static 标志(逆向常量) */
static const char STATIC_MARKER[] = "Static:AB45A862";

/* ---------------- MD5 (RFC 1321, 自包含) ---------------- */

typedef struct {
    uint32_t state[4];
    uint32_t count[2];
    uint8_t buffer[64];
} md5_ctx_t;

#define MD5_F(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define MD5_G(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define MD5_H(x, y, z) ((x) ^ (y) ^ (z))
#define MD5_I(x, y, z) ((y) ^ ((x) | ~(z)))
#define MD5_ROTLEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define MD5_FF(a, b, c, d, x, s, ac) \
    { (a) += MD5_F((b), (c), (d)) + (x) + (ac); \
      (a) = MD5_ROTLEFT((a), (s)); \
      (a) += (b); }
#define MD5_GG(a, b, c, d, x, s, ac) \
    { (a) += MD5_G((b), (c), (d)) + (x) + (ac); \
      (a) = MD5_ROTLEFT((a), (s)); \
      (a) += (b); }
#define MD5_HH(a, b, c, d, x, s, ac) \
    { (a) += MD5_H((b), (c), (d)) + (x) + (ac); \
      (a) = MD5_ROTLEFT((a), (s)); \
      (a) += (b); }
#define MD5_II(a, b, c, d, x, s, ac) \
    { (a) += MD5_I((b), (c), (d)) + (x) + (ac); \
      (a) = MD5_ROTLEFT((a), (s)); \
      (a) += (b); }

static void md5_decode(uint32_t *out, const uint8_t *in, size_t len) {
    for (size_t i = 0, j = 0; j < len; i++, j += 4) {
        out[i] = ((uint32_t)in[j]) | (((uint32_t)in[j + 1]) << 8) |
                 (((uint32_t)in[j + 2]) << 16) | (((uint32_t)in[j + 3]) << 24);
    }
}

static void md5_encode(uint8_t *out, const uint32_t *in, size_t len) {
    for (size_t i = 0, j = 0; j < len; i++, j += 4) {
        out[j] = (uint8_t)(in[i] & 0xff);
        out[j + 1] = (uint8_t)((in[i] >> 8) & 0xff);
        out[j + 2] = (uint8_t)((in[i] >> 16) & 0xff);
        out[j + 3] = (uint8_t)((in[i] >> 24) & 0xff);
    }
}

static void md5_transform(uint32_t state[4], const uint8_t block[64]) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t x[16];
    md5_decode(x, block, 64);

    MD5_FF(a, b, c, d, x[0], 7, 0xd76aa478);
    MD5_FF(d, a, b, c, x[1], 12, 0xe8c7b756);
    MD5_FF(c, d, a, b, x[2], 17, 0x242070db);
    MD5_FF(b, c, d, a, x[3], 22, 0xc1bdceee);
    MD5_FF(a, b, c, d, x[4], 7, 0xf57c0faf);
    MD5_FF(d, a, b, c, x[5], 12, 0x4787c62a);
    MD5_FF(c, d, a, b, x[6], 17, 0xa8304613);
    MD5_FF(b, c, d, a, x[7], 22, 0xfd469501);
    MD5_FF(a, b, c, d, x[8], 7, 0x698098d8);
    MD5_FF(d, a, b, c, x[9], 12, 0x8b44f7af);
    MD5_FF(c, d, a, b, x[10], 17, 0xffff5bb1);
    MD5_FF(b, c, d, a, x[11], 22, 0x895cd7be);
    MD5_FF(a, b, c, d, x[12], 7, 0x6b901122);
    MD5_FF(d, a, b, c, x[13], 12, 0xfd987193);
    MD5_FF(c, d, a, b, x[14], 17, 0xa679438e);
    MD5_FF(b, c, d, a, x[15], 22, 0x49b40821);

    MD5_GG(a, b, c, d, x[1], 5, 0xf61e2562);
    MD5_GG(d, a, b, c, x[6], 9, 0xc040b340);
    MD5_GG(c, d, a, b, x[11], 14, 0x265e5a51);
    MD5_GG(b, c, d, a, x[0], 20, 0xe9b6c7aa);
    MD5_GG(a, b, c, d, x[5], 5, 0xd62f105d);
    MD5_GG(d, a, b, c, x[10], 9, 0x02441453);
    MD5_GG(c, d, a, b, x[15], 14, 0xd8a1e681);
    MD5_GG(b, c, d, a, x[4], 20, 0xe7d3fbc8);
    MD5_GG(a, b, c, d, x[9], 5, 0x21e1cde6);
    MD5_GG(d, a, b, c, x[14], 9, 0xc33707d6);
    MD5_GG(c, d, a, b, x[3], 14, 0xf4d50d87);
    MD5_GG(b, c, d, a, x[8], 20, 0x455a14ed);
    MD5_GG(a, b, c, d, x[13], 5, 0xa9e3e905);
    MD5_GG(d, a, b, c, x[2], 9, 0xfcefa3f8);
    MD5_GG(c, d, a, b, x[7], 14, 0x676f02d9);
    MD5_GG(b, c, d, a, x[12], 20, 0x8d2a4c8a);

    MD5_HH(a, b, c, d, x[5], 4, 0xfffa3942);
    MD5_HH(d, a, b, c, x[8], 11, 0x8771f681);
    MD5_HH(c, d, a, b, x[11], 16, 0x6d9d6122);
    MD5_HH(b, c, d, a, x[14], 23, 0xfde5380c);
    MD5_HH(a, b, c, d, x[1], 4, 0xa4beea44);
    MD5_HH(d, a, b, c, x[4], 11, 0x4bdecfa9);
    MD5_HH(c, d, a, b, x[7], 16, 0xf6bb4b60);
    MD5_HH(b, c, d, a, x[10], 23, 0xbebfbc70);
    MD5_HH(a, b, c, d, x[13], 4, 0x289b7ec6);
    MD5_HH(d, a, b, c, x[0], 11, 0xeaa127fa);
    MD5_HH(c, d, a, b, x[3], 16, 0xd4ef3085);
    MD5_HH(b, c, d, a, x[6], 23, 0x04881d05);
    MD5_HH(a, b, c, d, x[9], 4, 0xd9d4d039);
    MD5_HH(d, a, b, c, x[12], 11, 0xe6db99e5);
    MD5_HH(c, d, a, b, x[15], 16, 0x1fa27cf8);
    MD5_HH(b, c, d, a, x[2], 23, 0xc4ac5665);

    MD5_II(a, b, c, d, x[0], 6, 0xf4292244);
    MD5_II(d, a, b, c, x[7], 10, 0x432aff97);
    MD5_II(c, d, a, b, x[14], 15, 0xab9423a7);
    MD5_II(b, c, d, a, x[5], 21, 0xfc93a039);
    MD5_II(a, b, c, d, x[12], 6, 0x655b59c3);
    MD5_II(d, a, b, c, x[3], 10, 0x8f0ccc92);
    MD5_II(c, d, a, b, x[10], 15, 0xffeff47d);
    MD5_II(b, c, d, a, x[1], 21, 0x85845dd1);
    MD5_II(a, b, c, d, x[8], 6, 0x6fa87e4f);
    MD5_II(d, a, b, c, x[15], 10, 0xfe2ce6e0);
    MD5_II(c, d, a, b, x[6], 15, 0xa3014314);
    MD5_II(b, c, d, a, x[13], 21, 0x4e0811a1);
    MD5_II(a, b, c, d, x[4], 6, 0xf7537e82);
    MD5_II(d, a, b, c, x[11], 10, 0xbd3af235);
    MD5_II(c, d, a, b, x[2], 15, 0x2ad7d2bb);
    MD5_II(b, c, d, a, x[9], 21, 0xeb86d391);

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;

    memset(x, 0, sizeof(x));
}

static void md5_init(md5_ctx_t *ctx) {
    ctx->count[0] = 0;
    ctx->count[1] = 0;
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
}

static void md5_update(md5_ctx_t *ctx, const uint8_t *input, size_t input_len) {
    size_t i, index, part_len;
    index = (size_t)((ctx->count[0] >> 3) & 0x3f);
    ctx->count[0] += (uint32_t)(input_len << 3);
    if (ctx->count[0] < (uint32_t)(input_len << 3)) ctx->count[1]++;
    ctx->count[1] += (uint32_t)(input_len >> 29);

    part_len = 64 - index;
    if (input_len >= part_len) {
        memcpy(&ctx->buffer[index], input, part_len);
        md5_transform(ctx->state, ctx->buffer);
        for (i = part_len; i + 63 < input_len; i += 64) {
            md5_transform(ctx->state, &input[i]);
        }
        index = 0;
    } else {
        i = 0;
    }
    memcpy(&ctx->buffer[index], &input[i], input_len - i);
}

static void md5_final(md5_ctx_t *ctx, uint8_t digest[16]) {
    uint8_t bits[8];
    size_t index, pad_len;
    uint8_t padding[64];
    memset(padding, 0, sizeof(padding));
    padding[0] = 0x80;

    md5_encode(bits, ctx->count, 8);
    index = (size_t)((ctx->count[0] >> 3) & 0x3f);
    pad_len = (index < 56) ? (56 - index) : (120 - index);
    md5_update(ctx, padding, pad_len);
    md5_update(ctx, bits, 8);
    md5_encode(digest, ctx->state, 16);
    memset(ctx, 0, sizeof(*ctx));
}

/* ---------------- 日志 ---------------- */

static int g_debug = 0;
static volatile sig_atomic_t g_running = 1;

static void log_ts(void) {
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm);
    printf("%s ", buf);
}

static void log_info(const char *fmt, ...) {
    log_ts();
    printf("INFO ");
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    putchar('\n');
}

static void log_warn(const char *fmt, ...) {
    log_ts();
    printf("WARNING ");
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    putchar('\n');
}

static void log_error(const char *fmt, ...) {
    log_ts();
    printf("ERROR ");
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    putchar('\n');
}

static void log_debug(const char *fmt, ...) {
    if (!g_debug) return;
    log_ts();
    printf("DEBUG ");
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    putchar('\n');
}

/* ---------------- 工具函数 ---------------- */

static void format_mac(const uint8_t mac[6], char out[18]) {
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             (unsigned)mac[0], (unsigned)mac[1], (unsigned)mac[2],
             (unsigned)mac[3], (unsigned)mac[4], (unsigned)mac[5]);
}

static int parse_mac(const char *text, uint8_t mac[6]) {
    char clean[13];
    size_t j = 0;
    for (size_t i = 0; text[i]; i++) {
        char c = text[i];
        if (c == ':' || c == '-' || c == '.') continue;
        if (!isxdigit((unsigned char)c)) return -1;
        if (j >= 12) return -1; /* 超过 12 个 hex 字符:拒绝而非截断 */
        clean[j++] = c;
    }
    clean[j] = '\0';
    if (j != 12) return -1;
    for (int i = 0; i < 6; i++) {
        char buf[3] = {clean[i * 2], clean[i * 2 + 1], 0};
        char *end = NULL;
        long v = strtol(buf, &end, 16);
        if (!end || *end != '\0' || v < 0 || v > 255) return -1;
        mac[i] = (uint8_t)v;
    }
    return 0;
}

static int get_interface_mac(const char *ifname, uint8_t mac[6]) {
    char path[128];
    snprintf(path, sizeof(path), "/sys/class/net/%s/address", ifname);
    FILE *f = fopen(path, "r");
    if (f) {
        char buf[32];
        if (fgets(buf, sizeof(buf), f)) {
            fclose(f);
            /* sysfs 文件末尾必带 '\n',必须先剥掉;解析失败则落到 ioctl 回退 */
            size_t len = strlen(buf);
            while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r' ||
                               buf[len - 1] == ' ' || buf[len - 1] == '\t')) {
                buf[--len] = '\0';
            }
            if (parse_mac(buf, mac) == 0) return 0;
        } else {
            fclose(f);
        }
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    int rc = ioctl(sock, SIOCGIFHWADDR, &ifr);
    close(sock);
    if (rc < 0) return -1;
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    return 0;
}

static double env_float(const char *name, double def) {
    const char *v = getenv(name);
    if (!v || !*v) return def;
    char *end = NULL;
    double r = strtod(v, &end);
    if (!end || *end != '\0' || !isfinite(r)) return def;
    return r;
}

static int env_int(const char *name, int def) {
    const char *v = getenv(name);
    if (!v || !*v) return def;
    char *end = NULL;
    long r = strtol(v, &end, 10);
    if (!end || *end != '\0' || r > INT_MAX || r < INT_MIN) return def;
    return (int)r;
}

/* 解析命令行 double 参数:必须完整消费且为有限值 */
static int parse_double_arg(const char *text, double *out) {
    char *end = NULL;
    double v = strtod(text, &end);
    if (!end || end == text || *end != '\0' || !isfinite(v)) return -1;
    *out = v;
    return 0;
}

/* 解析命令行 long 参数:必须完整消费 */
static int parse_long_arg(const char *text, long *out) {
    char *end = NULL;
    long v = strtol(text, &end, 10);
    if (!end || end == text || *end != '\0') return -1;
    *out = v;
    return 0;
}

/* 读取文件第一行(去掉末尾 \r\n);path 为 "-" 时读 stdin */
static int read_first_line(const char *path, char *out, size_t out_size) {
    FILE *f = (strcmp(path, "-") == 0) ? stdin : fopen(path, "r");
    if (!f) return -1;
    if (!fgets(out, (int)out_size, f)) {
        if (f != stdin) fclose(f);
        return -1;
    }
    if (f != stdin) fclose(f);
    size_t len = strlen(out);
    while (len > 0 && (out[len - 1] == '\n' || out[len - 1] == '\r')) {
        out[--len] = '\0';
    }
    return 0;
}

/* 毫秒级睡眠(替代已废弃的 usleep,可被信号中断) */
static void sleep_ms(long ms) {
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    while (nanosleep(&ts, &ts) < 0 && errno == EINTR) {
        /* 被信号打断则继续睡完剩余时间 */
    }
}

static void hexdump(const uint8_t *data, size_t len) {
    for (size_t offset = 0; offset < len; offset += 16) {
        printf("%04zx  ", offset);
        size_t chunk = len - offset;
        if (chunk > 16) chunk = 16;
        for (size_t i = 0; i < 16; i++) {
            if (i < chunk) printf("%02x ", (unsigned)data[offset + i]);
            else printf("   ");
            if (i == 7) printf(" ");
        }
        printf(" ");
        for (size_t i = 0; i < chunk; i++) {
            uint8_t b = data[offset + i];
            putchar(b >= 32 && b <= 126 ? (char)b : '.');
        }
        putchar('\n');
    }
}

static const char *eap_code_name(uint8_t code) {
    switch (code) {
        case EAP_REQUEST: return "Request";
        case EAP_RESPONSE: return "Response";
        case EAP_SUCCESS: return "Success";
        case EAP_FAILURE: return "Failure";
        default: return "code-?";
    }
}

static const char *eap_type_name(uint8_t eap_type) {
    switch (eap_type) {
        case EAP_TYPE_IDENTITY: return "Identity";
        case EAP_TYPE_MD5: return "MD5-Challenge";
        default: return "type-?";
    }
}

static const char *eapol_type_name(uint8_t eapol_type) {
    switch (eapol_type) {
        case EAPOL_EAP_PACKET: return "EAP-Packet";
        case EAPOL_START: return "Start";
        case EAPOL_LOGOFF: return "Logoff";
        default: return "type-?";
    }
}

/* ---------------- 随机数(设备无关的动态数据) ---------------- */

static int random_bytes(uint8_t *buf, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, buf + got, len - got);
        if (n <= 0) break;
        got += (size_t)n;
    }
    close(fd);
    if (got < len) return -1;
    return 0;
}

/* 生成 hex 字符随机串(官方 0x17/0x4d 字段即为此形态) */
static void random_hex_string(uint8_t *out, size_t hex_len, int uppercase) {
    uint8_t rb[128];
    static const char lower[] = "0123456789abcdef";
    static const char upper[] = "0123456789ABCDEF";
    const char *table = uppercase ? upper : lower;
    for (size_t i = 0; i < hex_len; ) {
        size_t want = (hex_len - i + 1) / 2;
        if (want > sizeof(rb)) want = sizeof(rb);
        if (random_bytes(rb, want) != 0) {
            for (size_t j = 0; j < want; j++) rb[j] = (uint8_t)rand();
        }
        for (size_t j = 0; j < want && i < hex_len; j++) {
            out[i++] = (uint8_t)table[rb[j] >> 4];
            if (i < hex_len) out[i++] = (uint8_t)table[rb[j] & 0xf];
        }
    }
}

/* ---------------- trailer 动态构建(逆向重写核心) ---------------- */

#define TRAILER_LEN 585

struct trailer_builder {
    uint8_t buf[1024];
    size_t len;
    int overflow; /* 写入超界标记:任何字段追加越界立即中止 */
};

static void tb_put(struct trailer_builder *tb, const void *data, size_t len) {
    if (tb->overflow) return;
    if (len > sizeof(tb->buf) - tb->len) {
        tb->overflow = 1;
        return;
    }
    memcpy(tb->buf + tb->len, data, len);
    tb->len += len;
}

/* 追加 1a 包装的 TLV */
static void tb_tlv(struct trailer_builder *tb, uint8_t tag,
                   const uint8_t *value, size_t value_len) {
    uint8_t hdr[8];
    hdr[0] = 0x1a;
    hdr[1] = (uint8_t)(8 + value_len);
    memcpy(hdr + 2, TLV_MAGIC, 4);
    hdr[6] = tag;
    hdr[7] = (uint8_t)(2 + value_len);
    tb_put(tb, hdr, 8);
    tb_put(tb, value, value_len);
}

/* 追加紧凑 TLV(0x02 用,无 1a 包装,无 value;逆向常量 lenfield=03) */
static void tb_tlv_compact(struct trailer_builder *tb, uint8_t tag) {
    uint8_t hdr[6];
    memcpy(hdr, TLV_MAGIC, 4);
    hdr[4] = tag;
    hdr[5] = 0x03; /* 官方固定值 */
    tb_put(tb, hdr, 6);
}

/* 由 MAC 推导 EUI-64 链路本地 IPv6(fe80::xxxx:xxff:fexx:xxxx) */
static void make_link_local_ipv6(const uint8_t mac[6], uint8_t ipv6[16]) {
    memset(ipv6, 0, 16);
    ipv6[0] = 0xfe;
    ipv6[1] = 0x80;
    ipv6[8] = mac[0] ^ 0x02;
    ipv6[9] = mac[1];
    ipv6[10] = mac[2];
    ipv6[11] = 0xff;
    ipv6[12] = 0xfe;
    ipv6[13] = mac[3];
    ipv6[14] = mac[4];
    ipv6[15] = mac[5];
}

/*
 * 从 /proc/net/if_inet6 采集指定 scope 的第 nth 个(从 0 起)IPv6 地址。
 * scope: 0x00=global(0x4e 用), 0x20=link-local(0x36/0x38 用)。
 * 采集失败返回 -1(调用方回退到推导/随机/全零)。
 */
static int get_ipv6_by_scope(const char *ifname, unsigned int want_scope,
                             int nth, uint8_t ipv6[16]) {
    memset(ipv6, 0, 16);
    FILE *f = fopen("/proc/net/if_inet6", "r");
    if (!f) return -1;
    char line[256];
    int found = -1;
    int seen = 0;
    while (fgets(line, sizeof(line), f)) {
        char addr[33], dev[64];
        unsigned int idx, plen, scope, flags;
        if (sscanf(line, "%32s %x %x %x %x %63s",
                   addr, &idx, &plen, &scope, &flags, dev) == 6) {
            if (strcmp(dev, ifname) != 0) continue;
            if (scope != want_scope) continue;
            if (seen < nth) {
                seen++;
                continue;
            }
            for (int i = 0; i < 16; i++) {
                unsigned int byte;
                sscanf(addr + i * 2, "%2x", &byte);
                ipv6[i] = (uint8_t)byte;
            }
            found = 0;
            break;
        }
    }
    fclose(f);
    return found;
}

/*
 * 构建完整 trailer。kind: 0=Start, 1=Identity, 2=MD5
 * 动态字段:MAC(0x2d)、IPv6(0x36/0x38/0x4e)
 * 随机字段:0x17、0x2f、0x4d(官方即含随机成分)
 * 常量字段:版本、Static 标志、服务器列表等
 */
static size_t build_trailer(uint8_t *out, size_t cap, int kind,
                            const uint8_t *local_mac, const char *ifname,
                            const char *auth_servers) {
    struct trailer_builder tb;
    tb.len = 0;
    tb.overflow = 0;

    /* 固定头 */
    tb_put(&tb, TRAILER_HEADER, sizeof(TRAILER_HEADER));

    /* 设备段:魔数 + "8021x.exe" + 零填充 + 版本 + 0x02 TLV */
    uint8_t zeros[23];
    memset(zeros, 0, sizeof(zeros));
    tb_put(&tb, TLV_MAGIC, 4);
    tb_put(&tb, CLIENT_EXE_NAME, sizeof(CLIENT_EXE_NAME));
    tb_put(&tb, zeros, sizeof(zeros));
    {
        /* 版本 5 字节:06=主版本 6, 54=84(即 6.84),末三字节 0
         * 已用抓包三个帧(Start/Identity/MD5)逐一验证,均为 06 54 00 00 00 */
        uint8_t ver[5] = {0x06, 0x54, 0x00, 0x00, 0x00};
        tb_put(&tb, ver, 5);
    }
    {
        /* 0x02 紧凑 TLV(逆向常量:魔数+02+03,无 value) */
        tb_tlv_compact(&tb, 0x02);
    }

    /* 0x17:随机会话串(官方超时路径即 rand(),服务器必须容忍) */
    {
        uint8_t val[32];
        random_hex_string(val, 32, 1); /* 大写 hex,与官方 %X 一致 */
        tb_tlv(&tb, 0x17, val, 32);
    }

    /* 0x18:固定 00 00 00 01 */
    {
        uint8_t val[4] = {0x00, 0x00, 0x00, 0x01};
        tb_tlv(&tb, 0x18, val, 4);
    }

    /* 0x2d:本机 MAC(动态,设备绑定锚点) */
    tb_tlv(&tb, 0x2d, local_mac, 6);

    /* 0x2f:16 字节随机(二进制,官方亦为动态) */
    {
        uint8_t val[16];
        if (random_bytes(val, 16) != 0) {
            for (int i = 0; i < 16; i++) val[i] = (uint8_t)rand();
        }
        tb_tlv(&tb, 0x2f, val, 16);
    }

    /* 0x35:DHCP 认证阶段(常量 03) */
    {
        uint8_t val = 0x03;
        tb_tlv(&tb, 0x35, &val, 1);
    }

    /* 0x36:链路本地 IPv6(优先采集系统真实地址,采不到回退 MAC 推导 EUI-64) */
    {
        uint8_t val[16];
        if (get_ipv6_by_scope(ifname, 0x20, 0, val) != 0) {
            make_link_local_ipv6(local_mac, val);
        }
        tb_tlv(&tb, 0x36, val, 16);
    }

    /* 0x38:临时 IPv6(采集系统 link-local 第二个地址;无则 fe80:: + 随机 64 位) */
    {
        uint8_t val[16];
        if (get_ipv6_by_scope(ifname, 0x20, 1, val) != 0) {
            memset(val, 0, 16);
            val[0] = 0xfe;
            val[1] = 0x80;
            if (random_bytes(val + 8, 8) != 0) {
                for (int i = 0; i < 8; i++) val[8 + i] = (uint8_t)rand();
            }
        }
        tb_tlv(&tb, 0x38, val, 16);
    }

    /* 0x4e:全局 IPv6(动态采集,无则全零) */
    {
        uint8_t val[16];
        get_ipv6_by_scope(ifname, 0x00, 0, val);
        tb_tlv(&tb, 0x4e, val, 16);
    }

    /* 0x4d:128 字节环境指纹(官方含 PID+随机数,不用于设备绑定) */
    {
        uint8_t val[128];
        if (kind == 0) {
            /* Start 帧官方此段全零 */
            memset(val, 0, 128);
        } else {
            /* Identity/MD5 帧:随机 hex 串(官方为运行时生成) */
            random_hex_string(val, 128, 0);
        }
        tb_tlv(&tb, 0x4d, val, 128);
    }

    /* 0x39:固定 d0a3cde2 + 28 字节零(逆向常量) */
    {
        uint8_t val[32];
        memset(val, 0, sizeof(val));
        val[0] = 0xd0; val[1] = 0xa3; val[2] = 0xcd; val[3] = 0xe2;
        tb_tlv(&tb, 0x39, val, 32);
    }

    /* 0x54:Static:AB45A862 + 零填充(64 字节) */
    {
        uint8_t val[64];
        memset(val, 0, sizeof(val));
        memcpy(val, STATIC_MARKER, strlen(STATIC_MARKER));
        tb_tlv(&tb, 0x54, val, 64);
    }

    /* 0x62 / 0x6b / 0x7e / 0x70 / 0x6f / 0x79:固定小字段 */
    {
        uint8_t v = 0x00;
        tb_tlv(&tb, 0x62, &v, 1);
        tb_tlv(&tb, 0x6b, &v, 1);
    }
    {
        uint8_t val[8] = {0x00, 0x00, 0x01, 0x00, 0x00, 0x0c, 0x00, 0x00};
        tb_tlv(&tb, 0x7e, val, 8);
    }
    {
        uint8_t v1 = 0x40;
        tb_tlv(&tb, 0x70, &v1, 1);
        uint8_t v2 = 0x00;
        tb_tlv(&tb, 0x6f, &v2, 1);
        uint8_t v3 = 0x02;
        tb_tlv(&tb, 0x79, &v3, 1);
    }

    /* 0x76:认证服务器列表(动态可配置,非空时追加) */
    if (auth_servers && *auth_servers) {
        tb_tlv(&tb, 0x76, (const uint8_t *)auth_servers, strlen(auth_servers));
    }

    if (tb.overflow || tb.len > cap) return 0;
    memcpy(out, tb.buf, tb.len);
    return tb.len;
}

/* ---------------- EAPOL 帧构建 ---------------- */

static size_t build_eap(uint8_t *buf, size_t buf_size, uint8_t code, uint8_t eap_id,
                        int eap_type, const uint8_t *data, size_t data_len) {
    size_t off = 0;
    if (5 + data_len > buf_size) return 0;
    uint16_t eap_len = (uint16_t)(5 + data_len);
    buf[off++] = code;
    buf[off++] = eap_id;
    buf[off++] = (eap_len >> 8) & 0xff;
    buf[off++] = eap_len & 0xff;
    buf[off++] = (uint8_t)eap_type;
    memcpy(buf + off, data, data_len);
    off += data_len;
    return off;
}

static size_t build_ethernet(uint8_t *buf, const uint8_t src[6], const uint8_t dst[6]) {
    memcpy(buf, dst, 6);
    memcpy(buf + 6, src, 6);
    buf[12] = (ETH_P_EAPOL >> 8) & 0xff;
    buf[13] = ETH_P_EAPOL & 0xff;
    return 14;
}

static size_t build_eapol_frame(uint8_t *buf, size_t buf_size,
                                const uint8_t src[6], const uint8_t dst[6],
                                uint8_t eapol_type, const uint8_t *body,
                                size_t body_len, const uint8_t *trailer,
                                size_t trailer_len) {
    size_t total = 14 + 4 + body_len + trailer_len;
    if (total > buf_size) return 0;
    size_t off = build_ethernet(buf, src, dst);
    buf[off++] = EAPOL_VERSION;
    buf[off++] = eapol_type;
    buf[off++] = (body_len >> 8) & 0xff;
    buf[off++] = body_len & 0xff;
    if (body_len > 0) {
        memcpy(buf + off, body, body_len);
        off += body_len;
    }
    if (trailer_len > 0) {
        memcpy(buf + off, trailer, trailer_len);
        off += trailer_len;
    }
    return off;
}

static void compute_md5_response(uint8_t eap_id, const char *password,
                                 const uint8_t *challenge, size_t challenge_len,
                                 uint8_t digest[16]) {
    md5_ctx_t ctx;
    md5_init(&ctx);
    md5_update(&ctx, &eap_id, 1);
    md5_update(&ctx, (const uint8_t *)password, strlen(password));
    md5_update(&ctx, challenge, challenge_len);
    md5_final(&ctx, digest);
}

/* ---------------- 帧解析 ---------------- */

typedef struct {
    const uint8_t *raw;
    size_t raw_len;
    uint8_t src[6];
    uint8_t dst[6];
    int has_vlan;
    uint16_t vlan_tci;
    size_t eapol_offset;
    uint8_t eapol_version;
    uint8_t eapol_type;
    uint16_t eapol_len;
    const uint8_t *trailer;
    size_t trailer_len;
    int has_eap;
    uint8_t eap_code;
    uint8_t eap_id;
    uint16_t eap_len;
    int has_eap_type;
    uint8_t eap_type;
    const uint8_t *eap_data;
    size_t eap_data_len;
} eapol_frame_t;

static int parse_eapol(const uint8_t *packet, size_t len, eapol_frame_t *frame) {
    memset(frame, 0, sizeof(*frame));
    frame->raw = packet;
    frame->raw_len = len;
    if (len < 18) return -1;

    memcpy(frame->dst, packet, 6);
    memcpy(frame->src, packet + 6, 6);
    uint16_t eth_type = ((uint16_t)packet[12] << 8) | packet[13];
    size_t offset = 14;
    frame->has_vlan = 0;

    /* 支持多层 VLAN 标签(802.1Q / 802.1ad,Q-in-Q) */
    while (eth_type == 0x8100 || eth_type == 0x88A8) {
        if (len < offset + 4) return -1;
        if (!frame->has_vlan) {
            frame->has_vlan = 1;
            frame->vlan_tci = ((uint16_t)packet[offset] << 8) | packet[offset + 1];
        }
        eth_type = ((uint16_t)packet[offset + 2] << 8) | packet[offset + 3];
        offset += 4;
    }

    if (eth_type != ETH_P_EAPOL || len < offset + 4) return -1;

    frame->eapol_offset = offset;
    frame->eapol_version = packet[offset];
    frame->eapol_type = packet[offset + 1];
    frame->eapol_len = ((uint16_t)packet[offset + 2] << 8) | packet[offset + 3];

    size_t body_off = offset + 4;
    size_t declared_end = body_off + frame->eapol_len;
    if (len < declared_end) return -1;

    frame->trailer = packet + declared_end;
    frame->trailer_len = len - declared_end;

    if (frame->eapol_type != EAPOL_EAP_PACKET || frame->eapol_len < 4) {
        return 0;
    }

    frame->has_eap = 1;
    frame->eap_code = packet[body_off];
    frame->eap_id = packet[body_off + 1];
    frame->eap_len = ((uint16_t)packet[body_off + 2] << 8) | packet[body_off + 3];
    /* eap_len < 4 的畸形帧会让后续 eap_len - 4 下溢(越界读),直接丢弃 */
    if (frame->eap_len < 4 || frame->eap_len > frame->eapol_len) return -1;

    if (frame->eap_code == EAP_REQUEST || frame->eap_code == EAP_RESPONSE) {
        if (frame->eap_len >= 5) {
            frame->has_eap_type = 1;
            frame->eap_type = packet[body_off + 4];
            frame->eap_data = packet + body_off + 5;
            frame->eap_data_len = frame->eap_len - 5;
        }
    } else {
        frame->eap_data = packet + body_off + 4;
        frame->eap_data_len = frame->eap_len - 4;
    }
    return 0;
}

static void printable_reason(const uint8_t *data, size_t len, char *out, size_t out_len) {
    size_t j = 0;
    for (size_t i = 0; i < len && j + 1 < out_len; i++) {
        uint8_t b = data[i];
        /* 允许标准 ASCII 可见字符及多字节编码 (b >= 128 已含在 b >= 32 分支中) */
        if (b >= 32 && b != 127) {
            out[j++] = (char)b;
        } else {
            out[j++] = ' ';
        }
    }
    out[j] = '\0';
    /* 清理尾部多余空白与换行 */
    while (j > 0 && (out[j - 1] == ' ' || out[j - 1] == '\r' || out[j - 1] == '\n' || out[j - 1] == '.')) {
        out[--j] = '\0';
    }
}

/* ---------------- 客户端状态机 ---------------- */

typedef struct {
    const char *ifname;
    const char *username;
    const char *password;
    const char *auth_servers;
    uint8_t local_mac[6];
    double timeout;
    double retry_delay;
    int start_burst;
    int private_trailer;
    int start_trailer_enabled;
    const char *success_file;

    int sock;
    int sock_error;
    int sock_errno;
    uint8_t server_mac[6];
    uint8_t rx_packet[2048];
    eapol_frame_t rx_frame;
} ruijie_client_t;

static void client_init(ruijie_client_t *c) {
    memset(c, 0, sizeof(*c));
    c->sock = -1;
    memcpy(c->server_mac, RUIJIE_PAE_GROUP, 6);
}

static void client_close(ruijie_client_t *c) {
    if (c->sock >= 0) {
        close(c->sock);
        c->sock = -1;
    }
}

static int client_setup(ruijie_client_t *c) {
    char mac_str[18];

    /* 先清掉旧的成功标记,避免建连失败时残留过期的 success 文件 */
    if (c->success_file) {
        unlink(c->success_file);
    }

    c->sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_EAPOL));
    if (c->sock < 0) return -1;

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = (int)if_nametoindex(c->ifname);
    sll.sll_protocol = htons(ETH_P_EAPOL);
    if (sll.sll_ifindex == 0) {
        client_close(c);
        errno = ENOENT; /* 必须在 close 之后设置,避免被覆盖 */
        return -1;
    }
    if (bind(c->sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        int e = errno; /* close 可能改动 errno,先保存再恢复 */
        client_close(c);
        errno = e;
        return -1;
    }

    format_mac(c->local_mac, mac_str);
    log_info("interface=%s local_mac=%s username=%s",
             c->ifname, mac_str, c->username);
    return 0;
}

static void send_frame(ruijie_client_t *c, const char *description,
                       const uint8_t *frame, size_t frame_len) {
    char src_str[18], dst_str[18];
    if (send(c->sock, frame, frame_len, 0) < 0) {
        c->sock_errno = errno;
        c->sock_error = 1;
        log_warn("send failed: %s", strerror(errno));
        return;
    }
    format_mac(frame + 6, src_str);
    format_mac(frame, dst_str);
    log_info("TX %-26s len=%zu src=%s dst=%s", description, frame_len, src_str, dst_str);
    if (g_debug) {
        log_debug("TX hex");
        hexdump(frame, frame_len);
    }
}

/* 按 kind 构建 trailer 并发送 EAPOL 帧 */
static void send_with_trailer(ruijie_client_t *c, int kind, uint8_t eapol_type,
                              const uint8_t *body, size_t body_len,
                              const char *description, int use_trailer) {
    uint8_t frame[2048];
    uint8_t trailer[TRAILER_LEN];
    size_t trailer_len = 0;
    if (use_trailer) {
        trailer_len = build_trailer(trailer, sizeof(trailer), kind,
                                    c->local_mac, c->ifname, c->auth_servers);
        if (trailer_len == 0) {
            log_error("trailer build failed (auth server list too long? max 27 bytes)");
            return;
        }
    }
    size_t frame_len = build_eapol_frame(frame, sizeof(frame), c->local_mac,
                                         c->server_mac, eapol_type,
                                         body, body_len, trailer, trailer_len);
    if (frame_len == 0) { log_error("frame too large"); return; }
    send_frame(c, description, frame, frame_len);
}

static void send_start(ruijie_client_t *c) {
    send_with_trailer(c, 0, EAPOL_START, NULL, 0, "EAPOL-Start",
                      c->start_trailer_enabled);
}

static void send_start_burst(ruijie_client_t *c) {
    memcpy(c->server_mac, RUIJIE_PAE_GROUP, 6);
    int count = c->start_burst > 0 ? c->start_burst : 1;
    for (int i = 0; i < count; i++) {
        send_start(c);
        if (i + 1 < count) sleep_ms(100);
    }
}

static void send_identity(ruijie_client_t *c, uint8_t eap_id) {
    uint8_t eap_buf[256];
    size_t user_len = strlen(c->username);
    size_t eap_len = build_eap(eap_buf, sizeof(eap_buf), EAP_RESPONSE, eap_id,
                               EAP_TYPE_IDENTITY,
                               (const uint8_t *)c->username, user_len);
    if (eap_len == 0) {
        log_error("identity frame too large (username_len=%zu)", user_len);
        return;
    }
    char desc[64];
    snprintf(desc, sizeof(desc), "Response/Identity id=%u", (unsigned)eap_id);
    send_with_trailer(c, 1, EAPOL_EAP_PACKET, eap_buf, eap_len, desc,
                      c->private_trailer);
}

static void send_md5(ruijie_client_t *c, uint8_t eap_id, const uint8_t *challenge,
                     size_t challenge_len) {
    uint8_t digest[16];
    uint8_t md5_data[256];
    uint8_t eap_buf[256];

    compute_md5_response(eap_id, c->password, challenge, challenge_len, digest);

    size_t user_len = strlen(c->username);
    md5_data[0] = 16; /* value-size */
    memcpy(md5_data + 1, digest, 16);
    memcpy(md5_data + 17, c->username, user_len);
    size_t md5_data_len = 1 + 16 + user_len;
    size_t eap_len = build_eap(eap_buf, sizeof(eap_buf), EAP_RESPONSE, eap_id,
                               EAP_TYPE_MD5, md5_data, md5_data_len);
    if (eap_len == 0) {
        log_error("md5 frame too large (username_len=%zu)", user_len);
        return;
    }
    char desc[64];
    snprintf(desc, sizeof(desc), "Response/MD5 id=%u", (unsigned)eap_id);
    send_with_trailer(c, 2, EAPOL_EAP_PACKET, eap_buf, eap_len, desc,
                      c->private_trailer);
}

static void send_logoff(ruijie_client_t *c) {
    uint8_t frame[64];
    size_t frame_len = build_eapol_frame(frame, sizeof(frame), c->local_mac,
                                         c->server_mac, EAPOL_LOGOFF,
                                         NULL, 0, NULL, 0);
    send_frame(c, "EAPOL-Logoff", frame, frame_len);
}

static void log_rx_frame(const eapol_frame_t *frame) {
    char src_str[18], dst_str[18];
    format_mac(frame->src, src_str);
    format_mac(frame->dst, dst_str);

    char label[64];
    if (!frame->has_eap) {
        snprintf(label, sizeof(label), "%s", eapol_type_name(frame->eapol_type));
    } else {
        snprintf(label, sizeof(label), "%s/%s",
                 eap_code_name(frame->eap_code),
                 frame->has_eap_type ? eap_type_name(frame->eap_type) : "-");
    }

    char id_str[8];
    if (frame->has_eap) snprintf(id_str, sizeof(id_str), "%u", (unsigned)frame->eap_id);
    else strcpy(id_str, "-");

    char eap_len_str[8];
    if (frame->has_eap) snprintf(eap_len_str, sizeof(eap_len_str), "%u", (unsigned)frame->eap_len);
    else strcpy(eap_len_str, "-");

    log_info("RX %-26s id=%s frame_len=%zu eapol_len=%u eap_len=%s trailer_or_pad=%zu src=%s dst=%s",
             label, id_str, frame->raw_len, (unsigned)frame->eapol_len, eap_len_str,
             frame->trailer_len, src_str, dst_str);
    if (g_debug) {
        log_debug("RX hex");
        hexdump(frame->raw, frame->raw_len);
    }
}

/* returns 1 on frame, 0 on timeout/shutdown, -1 on socket error */
static int recv_frame(ruijie_client_t *c, double timeout, eapol_frame_t **out) {
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    double end_at = start.tv_sec + start.tv_nsec / 1e9 + timeout;

    while (g_running) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        double remaining = end_at - (now.tv_sec + now.tv_nsec / 1e9);
        if (remaining <= 0) return 0;

        /* 先夹到 [1,1000] 再转 int,避免超大 timeout 时浮点转整型溢出 */
        int ms = (remaining >= 1.0) ? 1000 : (int)(remaining * 1000) + 1;

        struct pollfd pfd = { .fd = c->sock, .events = POLLIN };
        int rc = poll(&pfd, 1, ms);
        if (rc < 0) {
            if (errno == EINTR) continue;
            c->sock_errno = errno;
            c->sock_error = 1;
            return -1;
        }
        if (rc == 0) continue;

        ssize_t n = recv(c->sock, c->rx_packet, sizeof(c->rx_packet), 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            c->sock_errno = errno;
            c->sock_error = 1;
            return -1;
        }

        if (parse_eapol(c->rx_packet, (size_t)n, &c->rx_frame) < 0) continue;
        if (memcmp(c->rx_frame.src, c->local_mac, 6) == 0) continue;
        if (memcmp(c->rx_frame.dst, c->local_mac, 6) != 0 &&
            memcmp(c->rx_frame.dst, RUIJIE_PAE_GROUP, 6) != 0 &&
            memcmp(c->rx_frame.dst, BROADCAST, 6) != 0) continue;

        log_rx_frame(&c->rx_frame);
        if (memcmp(c->rx_frame.src, RUIJIE_PAE_GROUP, 6) != 0 &&
            memcmp(c->server_mac, c->rx_frame.src, 6) != 0) {
            char mac_str[18];
            format_mac(c->rx_frame.src, mac_str);
            log_info("learned server MAC %s", mac_str);
            memcpy(c->server_mac, c->rx_frame.src, 6);
        }
        *out = &c->rx_frame;
        return 1;
    }
    return 0;
}

static void log_failure(ruijie_client_t *c, const eapol_frame_t *frame) {
    char reason[256];
    printable_reason(frame->eap_data, frame->eap_data_len, reason, sizeof(reason));
    time_t t = time(NULL) + (time_t)c->retry_delay;
    struct tm *tm = localtime(&t);
    char next_time[32];
    strftime(next_time, sizeof(next_time), "%Y-%m-%d %H:%M:%S", tm);
    if (reason[0]) {
        log_warn("EAP-Failure: %s; retry at %s", reason, next_time);
    } else {
        log_warn("EAP-Failure; retry at %s", next_time);
    }
}

static void mark_success(const char *path) {
    if (!path) return;
    size_t path_len = strlen(path);
    if (path_len >= 240) {
        log_warn("success file path too long (%zu bytes)", path_len);
        return;
    }
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);

    /* 防符号链接攻击:先清残留,再以 O_EXCL 独占创建,绝不跟随已存在的链接 */
    unlink(tmp);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd < 0) {
        log_warn("could not write success file %s: %s", tmp, strerror(errno));
        return;
    }
    char stamp[32];
    int n = snprintf(stamp, sizeof(stamp), "%ld\n", (long)time(NULL));
    if (n < 0 || write(fd, stamp, (size_t)n) != n) {
        log_warn("could not write success file %s: %s", tmp, strerror(errno));
        close(fd);
        unlink(tmp);
        return;
    }
    close(fd);
    if (rename(tmp, path) < 0) {
        log_warn("could not rename success file %s: %s", path, strerror(errno));
        unlink(tmp);
    }
}

static const char *handle_request(ruijie_client_t *c, const eapol_frame_t *frame) {
    if (frame->eap_type == EAP_TYPE_IDENTITY) {
        send_identity(c, frame->eap_id);
        return "identity";
    }
    if (frame->eap_type == EAP_TYPE_MD5) {
        if (frame->eap_data_len < 1) {
            log_warn("invalid MD5 challenge: missing value-size");
            return "bad";
        }
        size_t value_size = frame->eap_data[0];
        if (frame->eap_data_len < 1 + value_size) {
            log_warn("invalid MD5 challenge: value-size=%zu data_len=%zu",
                     value_size, frame->eap_data_len);
            return "bad";
        }
        const uint8_t *challenge = frame->eap_data + 1;
        if (g_debug) {
            char ch_hex[64];
            size_t n = value_size > 31 ? 31 : value_size;
            for (size_t i = 0; i < n; i++)
                snprintf(ch_hex + i * 2, 3, "%02x", (unsigned)challenge[i]);
            ch_hex[n * 2] = '\0';
            log_debug("challenge=%s", ch_hex);
        }
        send_md5(c, frame->eap_id, challenge, value_size);
        return "md5";
    }
    log_warn("unsupported EAP request type=%u", (unsigned)frame->eap_type);
    return "unsupported";
}

static int authenticate_once(ruijie_client_t *c) {
    log_info("starting authentication");
    send_start_burst(c);
    const char *state = "identity";

    while (g_running) {
        if (c->sock_error) break;
        eapol_frame_t *frame = NULL;
        int rc = recv_frame(c, c->timeout, &frame);
        if (rc < 0) break;
        if (rc == 0) {
            log_warn("timeout in state=%s; sending EAPOL-Start again", state);
            state = "identity";
            send_start_burst(c);
            continue;
        }

        if (!frame->has_eap) continue;

        if (frame->eap_code == EAP_FAILURE) {
            log_failure(c, frame);
            return 0;
        }
        if (frame->eap_code == EAP_SUCCESS) {
            log_info("authentication success");
            mark_success(c->success_file);
            return 1;
        }
        if (frame->eap_code != EAP_REQUEST) continue;

        const char *handled = handle_request(c, frame);
        if (strcmp(handled, "identity") == 0) state = "md5";
        else if (strcmp(handled, "md5") == 0) state = "result";
    }
    return 0;
}

static int monitor_session(ruijie_client_t *c) {
    log_info("entering session monitor");
    while (g_running) {
        if (c->sock_error) return -1;
        eapol_frame_t *frame = NULL;
        int rc = recv_frame(c, 30.0, &frame);
        if (rc < 0) return -1;
        if (rc == 0) continue;
        if (!frame->has_eap) continue;

        if (frame->eap_code == EAP_SUCCESS) {
            log_info("received repeated Success");
            continue;
        }
        if (frame->eap_code == EAP_FAILURE) {
            log_failure(c, frame);
            return 0;
        }
        if (frame->eap_code == EAP_REQUEST) {
            handle_request(c, frame);
        }
    }
    return 1;
}

static int run_forever(ruijie_client_t *c) {
    if (client_setup(c) < 0) {
        int e = errno; /* 先保存 errno:日志函数内部可能改动它 */
        c->sock_error = 1;
        c->sock_errno = e;
        log_warn("initial setup error: %s; will retry in %.1f seconds",
                 strerror(e), c->retry_delay);
    }

    while (g_running) {
        if (!c->sock_error) {
            if (authenticate_once(c)) {
                monitor_session(c);
            }
        }
        if (!g_running) break;

        struct timespec ts;
        ts.tv_sec = (time_t)c->retry_delay;
        ts.tv_nsec = (long)((c->retry_delay - ts.tv_sec) * 1e9);

        if (c->sock_error) {
            log_warn("network/socket error: %s; reinitializing in %.1f seconds",
                     strerror(c->sock_errno), c->retry_delay);
            if (nanosleep(&ts, NULL) < 0 && errno == EINTR) {
                if (!g_running) break;
            }
            client_close(c);
            if (client_setup(c) < 0) {
                c->sock_error = 1;
                c->sock_errno = errno;
                log_warn("reinitialization failed: %s; will retry later", strerror(errno));
                continue;
            }
            c->sock_error = 0;
        } else {
            log_info("retrying in %.1f seconds", c->retry_delay);
            if (nanosleep(&ts, NULL) < 0 && errno == EINTR) {
                if (!g_running) break;
            }
        }
    }
    if (c->sock >= 0) {
        send_logoff(c);
    }
    client_close(c);
    return 0;
}

/* ---------------- 参数解析与入口 ---------------- */

typedef struct {
    const char *ifname;
    const char *username;
    const char *password;
    const char *password_file;
    int password_given; /* -p 是否显式给出:给出时密码文件不覆盖 */
    const char *auth_servers;
    const char *mac;
    double timeout;
    double retry_delay;
    int start_burst;
    int no_start_trailer;
    int no_private_trailer;
    int debug;
    const char *success_file;
} options_t;

static void print_usage(const char *prog) {
    printf("Usage: %s [options]\n", prog);
    printf("\n");
    printf("Ruijie 802.1X EAP-MD5 client for OpenWrt/ImmortalWrt (reverse-engineered).\n");
    printf("\n");
    printf("Options:\n");
    printf("  -i, --interface IF          network interface (default: %s or RUIJIE_INTERFACE)\n", DEFAULT_INTERFACE);
    printf("  -u, --username USER         802.1X username [required, or RUIJIE_USERNAME]\n");
    printf("  -p, --password PASS         802.1X password (visible in 'ps'; prefer --password-file)\n");
    printf("      --password-file PATH     read password from file, '-' for stdin (or RUIJIE_PASSWORD_FILE)\n");
    printf("      --auth-servers SERVERS  auth server IP list (default: %s or RUIJIE_AUTH_SERVERS)\n", DEFAULT_AUTH_SERVERS);
    printf("  -m, --mac MAC               optional source MAC (or RUIJIE_MAC)\n");
    printf("      --timeout SEC           receive timeout (default %.1f or RUIJIE_TIMEOUT)\n", DEFAULT_TIMEOUT);
    printf("      --retry-delay SEC       delay after failure (default %.1f or RUIJIE_RETRY_DELAY)\n", DEFAULT_RETRY_DELAY);
    printf("      --start-burst N         EAPOL-Start frames per attempt (default %d or RUIJIE_START_BURST)\n", DEFAULT_START_BURST);
    printf("      --no-start-trailer      send bare EAPOL-Start without trailer\n");
    printf("      --no-private-trailer    debug: standard EAP-MD5 without Ruijie trailer\n");
    printf("      --debug                 enable hex dumps\n");
    printf("      --success-file PATH     write this file after EAP Success (or RUIJIE_SUCCESS_FILE)\n");
    printf("  -h, --help                  show this help\n");
}

static int parse_args(int argc, char *argv[], options_t *opts) {
    opts->ifname = getenv("RUIJIE_INTERFACE");
    if (!opts->ifname) opts->ifname = DEFAULT_INTERFACE;
    opts->username = getenv("RUIJIE_USERNAME");
    opts->password = getenv("RUIJIE_PASSWORD");
    opts->password_file = getenv("RUIJIE_PASSWORD_FILE");
    opts->password_given = 0;
    opts->auth_servers = getenv("RUIJIE_AUTH_SERVERS");
    if (!opts->auth_servers) opts->auth_servers = DEFAULT_AUTH_SERVERS;
    opts->mac = getenv("RUIJIE_MAC");
    opts->timeout = env_float("RUIJIE_TIMEOUT", DEFAULT_TIMEOUT);
    opts->retry_delay = env_float("RUIJIE_RETRY_DELAY", DEFAULT_RETRY_DELAY);
    opts->start_burst = env_int("RUIJIE_START_BURST", DEFAULT_START_BURST);
    opts->no_start_trailer = 0;
    opts->no_private_trailer = 0;
    opts->debug = 0;
    opts->success_file = getenv("RUIJIE_SUCCESS_FILE");

    static struct option long_options[] = {
        {"interface", required_argument, 0, 'i'},
        {"username", required_argument, 0, 'u'},
        {"password", required_argument, 0, 'p'},
        {"password-file", required_argument, 0, 0},
        {"auth-servers", required_argument, 0, 0},
        {"mac", required_argument, 0, 'm'},
        {"timeout", required_argument, 0, 0},
        {"retry-delay", required_argument, 0, 0},
        {"start-burst", required_argument, 0, 0},
        {"no-start-trailer", no_argument, 0, 0},
        {"no-private-trailer", no_argument, 0, 0},
        {"debug", no_argument, 0, 0},
        {"success-file", required_argument, 0, 0},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int option_index = 0;
    int c;
    while ((c = getopt_long(argc, argv, "hi:u:p:m:", long_options, &option_index)) != -1) {
        switch (c) {
            case 'h':
                print_usage(argv[0]);
                exit(0);
            case 'i':
                opts->ifname = optarg;
                break;
            case 'u':
                opts->username = optarg;
                break;
            case 'p':
                opts->password = optarg;
                opts->password_given = 1;
                break;
            case 'm':
                opts->mac = optarg;
                break;
            case 0: {
                const char *name = long_options[option_index].name;
                if (strcmp(name, "timeout") == 0) {
                    double v;
                    if (parse_double_arg(optarg, &v) != 0) {
                        log_error("invalid --timeout value: %s", optarg);
                        return -1;
                    }
                    opts->timeout = v;
                } else if (strcmp(name, "retry-delay") == 0) {
                    double v;
                    if (parse_double_arg(optarg, &v) != 0) {
                        log_error("invalid --retry-delay value: %s", optarg);
                        return -1;
                    }
                    opts->retry_delay = v;
                } else if (strcmp(name, "start-burst") == 0) {
                    long v;
                    if (parse_long_arg(optarg, &v) != 0 || v < 1 || v > INT_MAX) {
                        log_error("invalid --start-burst value: %s", optarg);
                        return -1;
                    }
                    opts->start_burst = (int)v;
                } else if (strcmp(name, "password-file") == 0) {
                    opts->password_file = optarg;
                } else if (strcmp(name, "auth-servers") == 0) {
                    opts->auth_servers = optarg;
                } else if (strcmp(name, "no-start-trailer") == 0) {
                    opts->no_start_trailer = 1;
                } else if (strcmp(name, "no-private-trailer") == 0) {
                    opts->no_private_trailer = 1;
                } else if (strcmp(name, "debug") == 0) {
                    opts->debug = 1;
                } else if (strcmp(name, "success-file") == 0) {
                    opts->success_file = optarg;
                }
                break;
            }
            default:
                return -1;
        }
    }
    return 0;
}

static void handle_signal(int sig) {
    (void)sig;
    g_running = 0;
}

int main(int argc, char *argv[]) {
    options_t opts;
    if (parse_args(argc, argv, &opts) < 0) {
        print_usage(argv[0]);
        return 1;
    }

    g_debug = opts.debug;
    srand((unsigned)time(NULL) ^ (unsigned)getpid());

    if (!opts.username || !opts.username[0]) {
        log_error("missing username: use -u/--username or RUIJIE_USERNAME");
        return 1;
    }
    char password_file_buf[MAX_PASSWORD_LEN + 2];
    char password_cli_buf[MAX_PASSWORD_LEN + 2];
    if (opts.password_file && !opts.password_given) {
        if (read_first_line(opts.password_file, password_file_buf,
                            sizeof(password_file_buf)) < 0) {
            log_error("could not read password from %s: %s",
                      opts.password_file, strerror(errno));
            return 1;
        }
        opts.password = password_file_buf;
    }
    if (!opts.password || !opts.password[0]) {
        log_error("missing password: use -p/--password, --password-file "
                  "or RUIJIE_PASSWORD");
        return 1;
    }
    if (strlen(opts.username) > MAX_USERNAME_LEN) {
        log_error("username too long (max %d bytes)", MAX_USERNAME_LEN);
        return 1;
    }
    if (strlen(opts.password) > MAX_PASSWORD_LEN) {
        log_error("password too long (max %d bytes)", MAX_PASSWORD_LEN);
        return 1;
    }

    /* 复制密码并抹除命令行参数中的明文,降低 ps 泄露风险 */
    if (opts.password_given) {
        strncpy(password_cli_buf, opts.password, sizeof(password_cli_buf) - 1);
        password_cli_buf[sizeof(password_cli_buf) - 1] = '\0';
        opts.password = password_cli_buf;
        for (int i = 1; i < argc; i++) {
            if ((strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--password") == 0) &&
                i + 1 < argc) {
                memset(argv[i + 1], 'x', strlen(argv[i + 1]));
            } else if (strncmp(argv[i], "--password=", 11) == 0) {
                memset(argv[i] + 11, 'x', strlen(argv[i] + 11));
            }
        }
    }

    if (opts.timeout <= 0) {
        log_error("--timeout must be positive");
        return 1;
    }
    if (opts.retry_delay < 0) {
        log_error("--retry-delay must be non-negative");
        return 1;
    }
    if (opts.start_burst < 1) {
        log_error("--start-burst (or RUIJIE_START_BURST) must be at least 1");
        return 1;
    }
    /* trailer 固定部分 550 字节 + 0x76 TLV(8 + 服务器串)必须不超过 585 */
    if (strlen(opts.auth_servers) > 27) {
        log_error("--auth-servers list too long (max 27 bytes, got %zu)",
                  strlen(opts.auth_servers));
        return 1;
    }

    ruijie_client_t client;
    client_init(&client);
    client.ifname = opts.ifname;
    client.username = opts.username;
    client.password = opts.password;
    client.auth_servers = opts.auth_servers;
    client.timeout = opts.timeout;
    client.retry_delay = opts.retry_delay;
    client.start_burst = opts.start_burst;
    client.private_trailer = !opts.no_private_trailer;
    client.start_trailer_enabled = (!opts.no_start_trailer && !opts.no_private_trailer);
    client.success_file = opts.success_file;

    if (opts.mac) {
        if (parse_mac(opts.mac, client.local_mac) < 0) {
            log_error("invalid MAC address: %s", opts.mac);
            return 1;
        }
    } else {
        if (get_interface_mac(client.ifname, client.local_mac) < 0) {
            log_error("could not get MAC address for %s: %s", client.ifname, strerror(errno));
            return 1;
        }
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    return run_forever(&client) < 0 ? 1 : 0;
}
