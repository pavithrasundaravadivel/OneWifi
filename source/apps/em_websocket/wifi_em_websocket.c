#define EM_WEBSOCKET_PUSH 1

#ifdef EM_WEBSOCKET_PUSH
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <stdbool.h>
#include <cjson/cJSON.h>
#include "wifi_apps_mgr.h"
#include "wifi_events.h"
#include "wifi_util.h"
/* ================================================================
 * EasyMesh topology streaming over VB-SB WebSocket (wss://)
 * ================================================================ */

#define EM_TOPO_STREAM_URL_SIZE    4096
#define EM_TOPO_STREAM_TOKEN_KEY   "token="
#define EM_TOPO_STREAM_SAT_URL     "https://devprimary.vbautobot.comcast.com:6002/get_sat"
#define EM_TOPO_STREAM_TOKEN_SIZE  4096
#define EM_TOPO_GATEWAY_MAC_SIZE   18
#define EM_TOPO_SSL_KEYLOG_FILE    "/tmp/em_topo_ssl_keys.log"
#define EM_TOPOLOGY_EVENT_NAME     "Device.WiFi.DataElements.Network.Topology"
#define EM_TOPOLOGY_SUBSCRIBE_RETRY_SEC 1

typedef struct wifi_app wifi_app_t;

/* Default base URL — SAT token is appended as ?token=<JWT> after fetch */
static char g_em_topo_stream_url[EM_TOPO_STREAM_URL_SIZE] =
    "wss://vb-streamer-api.vb.comcast.com:6100/ws/topology/xb";

static int                g_em_topo_socket_fd     = -1;
static SSL_CTX           *g_em_topo_ssl_ctx       = NULL;
static SSL               *g_em_topo_ssl           = NULL;
static unsigned long long g_em_topo_order_id      = 0;
static char              g_em_topo_gateway_mac[EM_TOPO_GATEWAY_MAC_SIZE] = {0};

/* All SSL reads and writes must be serialized across the sender and ping listener. */
static pthread_mutex_t    g_em_topo_sock_mtx    = PTHREAD_MUTEX_INITIALIZER;
static pthread_t          g_em_topo_ping_tid     = 0;
static volatile int       g_em_topo_listen_stop  = 0;
static volatile int       g_em_topo_ws_ready     = 0;
static pthread_t          g_em_topo_subscribe_tid = 0;
static volatile int       g_em_topo_subscribe_stop = 0;
static volatile int       g_em_topo_subscribed = 0;

typedef struct {
    bool     use_tls;
    char     host[128];
    uint16_t port;
    char     path_query[1024];
} em_topo_url_info_t;

static void em_topo_close(void);
static bus_error_t get_topology_handler(char *event_name,
                                        bus_data_prop_t *p_data,
                                        void *user_data);

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
static void em_topo_ssl_keylog_cb(const SSL *ssl, const char *line)
{
    FILE *fp;

    (void)ssl;
    fp = fopen(EM_TOPO_SSL_KEYLOG_FILE, "a");
    if (fp == NULL) {
        wifi_util_dbg_print(WIFI_APPS,
            "[TOPO-WS] keylog: fopen(%s) failed: %s",
            EM_TOPO_SSL_KEYLOG_FILE, strerror(errno));
        return;
    }
    fprintf(fp, "%s\n", line);
    fflush(fp);
    fclose(fp);
    wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] keylog: %s", line);
}
#endif

/* --- URL parsing (same logic as parse_csi_stream_url in websocket.c) --- */
static bool em_topo_parse_url(em_topo_url_info_t *info)
{
    const char *url       = g_em_topo_stream_url;
    const char *scheme    = strstr(url, "://");
    const char *host_start, *host_end, *path_start;
    long parsed_port = 6100;

    if (!info) return false;
    memset(info, 0, sizeof(*info));

    if (scheme) {
        info->use_tls = ((size_t)(scheme - url) == 3 && strncmp(url, "wss", 3) == 0);
        host_start = scheme + 3;
    } else {
        info->use_tls  = true;
        host_start = url;
    }

    host_end = host_start;
    while (*host_end && *host_end != ':' && *host_end != '/' && *host_end != '?')
        host_end++;

    {
        size_t hlen = (size_t)(host_end - host_start);
        if (hlen > 0 && hlen < sizeof(info->host)) {
            memcpy(info->host, host_start, hlen);
            info->host[hlen] = '\0';
        }
    }

    if (*host_end == ':') {
        char *ep = NULL;
        long p = strtol(host_end + 1, &ep, 10);
        if (ep != host_end + 1 && p > 0 && p <= 65535) parsed_port = p;
    }
    info->port = (uint16_t)parsed_port;

    path_start = host_end;
    if (*path_start == ':')
        while (*path_start && *path_start != '/' && *path_start != '?')
            path_start++;
    snprintf(info->path_query, sizeof(info->path_query), "%s",
        *path_start ? path_start : "/");
    return (info->host[0] != '\0');
}

static int em_topo_build_url_with_token(const char *token)
{
    char updated[EM_TOPO_STREAM_URL_SIZE] = {0};
    const char *cur = g_em_topo_stream_url;
    const char *tp  = strstr(cur, EM_TOPO_STREAM_TOKEN_KEY);
    int written;

    if (!token || !token[0]) return -1;
    if (tp) {
        size_t prefix_len = (size_t)(tp - cur) + strlen(EM_TOPO_STREAM_TOKEN_KEY);
        const char *suffix = strchr(tp, '&');
        written = snprintf(updated, sizeof(updated), "%.*s%s%s",
            (int)prefix_len, cur, token, suffix ? suffix : "");
    } else {
        const char *sep = strchr(cur, '?') ? "&" : "?";
        written = snprintf(updated, sizeof(updated), "%s%s%s%s",
            cur, sep, EM_TOPO_STREAM_TOKEN_KEY, token);
    }
    if (written <= 0 || (size_t)written >= sizeof(updated)) return -1;
    snprintf(g_em_topo_stream_url, sizeof(g_em_topo_stream_url), "%s", updated);
    return 0;
}

/* --- SAT token fetch via MTLS (same pattern as fetch_latest_csi_stream_token) --- */
static int em_topo_fetch_sat_token(char *token_out, size_t token_out_len)
{
    static char password[256] = {0};
    char curl_cmd[1024] = {0};
    char curl_output[EM_TOPO_STREAM_TOKEN_SIZE] = {0};
    int  curl_exit_code = -1;
    FILE *fp = NULL;
    char line_buf[256] = {0};
    size_t used = 0;

    if (token_out == NULL || token_out_len == 0) {
        wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] em_topo_fetch_sat_token: invalid args (token_out=%p len=%zu)", token_out, token_out_len);
        return -1;
    }

    if (!password[0]) {
        wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] No cached password, running GetConfigFile /tmp/.cfgDynamicSExpki");
        if (system("GetConfigFile /tmp/.cfgDynamicSExpki") != 0) {
            wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] GetConfigFile failed");
            return -1;
        }
        wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] GetConfigFile OK, reading password");
        fp = popen("cat /tmp/.cfgDynamicSExpki", "r");
        if (fp == NULL) {
            wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] popen(cat /tmp/.cfgDynamicSExpki) failed");
            return -1;
        }
        if (!fgets(password, sizeof(password), fp)) {
            wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] fgets password failed");
            pclose(fp);
            return -1;
        }
        pclose(fp); fp = NULL;
        password[strcspn(password, "\r\n")] = '\0';
        wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] Password read OK (len=%zu)", strlen(password));
    } else {
        wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] Using cached password (len=%zu)", strlen(password));
    }

    for (int attempt = 0; attempt < 2; attempt++) {
        int status;
        const char *cert = "/nvram/certs/devicecert_2.pk12";
        snprintf(curl_cmd, sizeof(curl_cmd),
            "curl -s --cert-type P12 --cert %s:%s %s",
            cert, password, EM_TOPO_STREAM_SAT_URL);

        wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] SAT attempt %d: running curl for %s", attempt + 1, EM_TOPO_STREAM_SAT_URL);
        fp = popen(curl_cmd, "r");
        if (fp == NULL) {
            wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] popen(curl) failed: %s", strerror(errno));
            return -1;
        }
        used = 0;
        while (fgets(line_buf, sizeof(line_buf), fp)) {
            size_t ll = strlen(line_buf);
            if (used + ll >= sizeof(curl_output) - 1) break;
            memcpy(curl_output + used, line_buf, ll); used += ll;
        }
        curl_output[used] = '\0';
        status = pclose(fp); fp = NULL;
        curl_exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] curl exit_code=%d output_len=%zu", curl_exit_code, used);

        if (curl_exit_code == 0 && used > 0) {
            while (used > 0 && (curl_output[used-1] == '\n' ||
                                curl_output[used-1] == '\r' ||
                                curl_output[used-1] == ' '))
                curl_output[--used] = '\0';
            if (used > 0 && curl_output[0] == '<') {
                wifi_util_dbg_print(WIFI_APPS,
                    "[TOPO-WS] SAT endpoint returned HTML error page, treating as failure");
                break;
            }
            if (used >= 2 && curl_output[0] == '"' &&
                curl_output[used - 1] == '"') {
                memmove(curl_output, curl_output + 1, used - 2);
                used -= 2;
                curl_output[used] = '\0';
                wifi_util_dbg_print(WIFI_APPS,
                    "[TOPO-WS] Stripped surrounding quotes from token (new len=%zu)",
                    used);
            }
            if (used > 0 && used < token_out_len) {
                memcpy(token_out, curl_output, used + 1);
                wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] SAT token fetched OK (len=%zu)", used);
                return 0;
            }
            wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] curl output empty or too large (used=%zu max=%zu)", used, token_out_len);
        } else {
            wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] curl failed or empty response (exit_code=%d used=%zu)", curl_exit_code, used);
        }

        if (curl_exit_code == 58 && attempt == 0) {
            wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] PKCS12 password stale (curl error 58), refreshing and retrying");
            memset(password, 0, sizeof(password));
            if (system("GetConfigFile /tmp/.cfgDynamicSExpki") != 0) {
                wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] GetConfigFile retry failed");
                return -1;
            }
            fp = popen("cat /tmp/.cfgDynamicSExpki", "r");
            if (fp == NULL || !fgets(password, sizeof(password), fp)) {
                wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] Password retry read failed");
                if (fp) pclose(fp);
                return -1;
            }
            pclose(fp); fp = NULL;
            password[strcspn(password, "\r\n")] = '\0';
            wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] Password refreshed OK, retrying curl");
            continue;
        }
        break;
    }
    wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] SAT token fetch failed after all attempts");
    return -1;
}

static int em_topo_peer_closed(void)
{
    int fd = g_em_topo_ssl ? SSL_get_fd(g_em_topo_ssl) : g_em_topo_socket_fd;
    char peek;
    ssize_t n;

    if (fd < 0) {
        return 1;
    }

    n = recv(fd, &peek, 1, MSG_PEEK | MSG_DONTWAIT);
    if (n == 0) {
        wifi_util_dbg_print(WIFI_APPS,
            "[TOPO-WS] peer_closed: peer sent FIN, connection gone");
        return 1;
    }
    if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        wifi_util_dbg_print(WIFI_APPS,
            "[TOPO-WS] peer_closed: socket error errno=%d (%s)",
            errno, strerror(errno));
        return 1;
    }
    return 0;
}

static int em_topo_send_all(const unsigned char *buf, size_t len)
{
    size_t sent = 0;
    int flags = 0;

    if (em_topo_peer_closed()) {
        wifi_util_dbg_print(WIFI_APPS,
            "[TOPO-WS] em_topo_send_all: peer closed before write");
        return -1;
    }

#ifdef MSG_NOSIGNAL
    flags = MSG_NOSIGNAL;
#endif

    while (sent < len) {
        int n = g_em_topo_ssl
            ? SSL_write(g_em_topo_ssl, buf + sent, (int)(len - sent))
            : (int)send(g_em_topo_socket_fd, buf + sent, len - sent, flags);
        if (n <= 0) {
            return -1;
        }
        sent += (size_t)n;
    }
    return 0;
}

/* Send a masked client-to-server text frame (RFC 6455 section 5.3). */
static int ws_send_frame(const char *payload, size_t payload_len)
{
    unsigned char header[14];
    size_t header_len = 0;
    unsigned char mask[4];
    unsigned char *masked = NULL;
    int ret = -1;

    if (payload == NULL || payload_len == 0) {
        return -1;
    }

    if (RAND_bytes(mask, sizeof(mask)) != 1) {
        wifi_util_dbg_print(WIFI_APPS,
            "[TOPO-WS] ws_send_frame: RAND_bytes failed");
        return -1;
    }

    header[0] = 0x81;
    if (payload_len <= 125) {
        header[1] = 0x80 | (unsigned char)payload_len;
        header_len = 2;
    } else if (payload_len <= 65535) {
        header[1] = 0x80 | 126;
        header[2] = (unsigned char)((payload_len >> 8) & 0xFF);
        header[3] = (unsigned char)(payload_len & 0xFF);
        header_len = 4;
    } else {
        header[1] = 0x80 | 127;
        header[2] = 0;
        header[3] = 0;
        header[4] = 0;
        header[5] = 0;
        header[6] = (unsigned char)((payload_len >> 24) & 0xFF);
        header[7] = (unsigned char)((payload_len >> 16) & 0xFF);
        header[8] = (unsigned char)((payload_len >> 8) & 0xFF);
        header[9] = (unsigned char)(payload_len & 0xFF);
        header_len = 10;
    }

    memcpy(header + header_len, mask, sizeof(mask));
    header_len += sizeof(mask);

    masked = malloc(payload_len);
    if (masked == NULL) {
        wifi_util_dbg_print(WIFI_APPS,
            "[TOPO-WS] ws_send_frame: malloc failed (%zu bytes)",
            payload_len);
        return -1;
    }
    for (size_t i = 0; i < payload_len; i++) {
        masked[i] = ((const unsigned char *)payload)[i] ^ mask[i & 3];
    }

    if (em_topo_send_all(header, header_len) != 0 ||
        em_topo_send_all(masked, payload_len) != 0) {
        wifi_util_dbg_print(WIFI_APPS,
            "[TOPO-WS] ws_send_frame: frame write failed");
        goto cleanup;
    }
    ret = 0;

cleanup:
    free(masked);
    return ret;
}

static int em_topo_read(char *buf, size_t len)
{
    if (g_em_topo_ssl) {
        return SSL_read(g_em_topo_ssl, buf, (int)len);
    }
    return (int)recv(g_em_topo_socket_fd, buf, len, 0);
}

static int em_topo_read_exact(unsigned char *buf, size_t len)
{
    size_t used = 0;

    while (used < len) {
        int n = em_topo_read((char *)buf + used, len - used);
        if (n <= 0) {
            wifi_util_dbg_print(WIFI_APPS,
                "[TOPO-WS] read_exact failed: got %d after %zu/%zu bytes (errno=%d %s)",
                n, used, len, errno, strerror(errno));
            return -1;
        }
        used += (size_t)n;
    }
    return 0;
}

/* Send a masked WebSocket control frame. */
static int em_topo_send_ws_control_frame(unsigned char opcode,
    const unsigned char *payload, size_t payload_len)
{
    unsigned char header[6] = {0};
    unsigned char mask[4] = {0};
    unsigned char *masked = NULL;
    size_t header_len = 2;
    int rc = -1;

    if ((opcode & 0x08) == 0 || payload_len > 125) {
        return -1;
    }

    header[0] = (unsigned char)(0x80 | (opcode & 0x0F));
    header[1] = (unsigned char)(0x80 | payload_len);

    wifi_util_dbg_print(WIFI_APPS,
        "[TOPO-WS] sending control frame opcode=0x%X payload_len=%zu",
        (unsigned int)(opcode & 0x0F), payload_len);

    if (RAND_bytes(mask, sizeof(mask)) != 1) {
        wifi_util_dbg_print(WIFI_APPS,
            "[TOPO-WS] control frame RAND_bytes failed");
        return -1;
    }
    memcpy(header + header_len, mask, sizeof(mask));
    header_len += sizeof(mask);

    if (payload_len > 0) {
        masked = malloc(payload_len);
        if (masked == NULL) {
            return -1;
        }
        for (size_t i = 0; i < payload_len; i++) {
            masked[i] = payload[i] ^ mask[i % 4];
        }
    }

    if (em_topo_send_all(header, header_len) != 0) {
        goto cleanup;
    }
    if (payload_len > 0 && em_topo_send_all(masked, payload_len) != 0) {
        goto cleanup;
    }
    rc = 0;

cleanup:
    free(masked);
    return rc;
}

static void *em_topo_ping_listener_thread(void *arg)
{
    (void)arg;
    wifi_util_dbg_print(WIFI_APPS,
        "[TOPO-WS] ping-listener thread started (tid=%lu)",
        (unsigned long)pthread_self());

    while (!g_em_topo_listen_stop) {
        int fd = g_em_topo_socket_fd;
        fd_set rfds;
        struct timeval tv;
        int rc;

        if (fd < 0 || !g_em_topo_ws_ready) {
            usleep(200000);
            continue;
        }

        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        rc = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            wifi_util_dbg_print(WIFI_APPS,
                "[TOPO-WS] ping-listener select error %d (%s), waiting for reconnect",
                errno, strerror(errno));
            usleep(200000);
            continue;
        }
        if (rc == 0) {
            continue;
        }

        pthread_mutex_lock(&g_em_topo_sock_mtx);
        if (g_em_topo_socket_fd < 0) {
            pthread_mutex_unlock(&g_em_topo_sock_mtx);
            continue;
        }
        if (g_em_topo_listen_stop) {
            pthread_mutex_unlock(&g_em_topo_sock_mtx);
            break;
        }

        {
            unsigned char hdr[2] = {0};
            unsigned char opcode;
            unsigned char mask[4] = {0};
            unsigned char *payload = NULL;
            size_t payload_len;
            int is_masked;
            int close_received = 0;

            if (em_topo_read_exact(hdr, sizeof(hdr)) != 0) {
                g_em_topo_ws_ready = 0;
                pthread_mutex_unlock(&g_em_topo_sock_mtx);
                continue;
            }

            opcode = (unsigned char)(hdr[0] & 0x0F);
            is_masked = ((hdr[1] & 0x80) != 0);
            payload_len = (size_t)(hdr[1] & 0x7F);
            wifi_util_info_print(WIFI_APPS,
                "[TOPO-WS] ping-listener: frame opcode=0x%X payload_len=%zu\n",
                (unsigned int)opcode, payload_len);

            if ((opcode & 0x08) && payload_len > 125) {
                wifi_util_dbg_print(WIFI_APPS,
                    "[TOPO-WS] ping-listener oversized control frame");
                g_em_topo_ws_ready = 0;
                pthread_mutex_unlock(&g_em_topo_sock_mtx);
                continue;
            }

            if (payload_len == 126) {
                unsigned char ext[2] = {0};
                if (em_topo_read_exact(ext, sizeof(ext)) != 0) {
                    g_em_topo_ws_ready = 0;
                    pthread_mutex_unlock(&g_em_topo_sock_mtx);
                    continue;
                }
                payload_len = ((size_t)ext[0] << 8) | (size_t)ext[1];
            } else if (payload_len == 127) {
                unsigned char ext[8] = {0};
                if (em_topo_read_exact(ext, sizeof(ext)) != 0) {
                    g_em_topo_ws_ready = 0;
                    pthread_mutex_unlock(&g_em_topo_sock_mtx);
                    continue;
                }
                if (ext[0] || ext[1] || ext[2] || ext[3]) {
                    g_em_topo_ws_ready = 0;
                    pthread_mutex_unlock(&g_em_topo_sock_mtx);
                    continue;
                }
                payload_len = ((size_t)ext[4] << 24) |
                              ((size_t)ext[5] << 16) |
                              ((size_t)ext[6] << 8) |
                              (size_t)ext[7];
            }

            if (is_masked &&
                em_topo_read_exact(mask, sizeof(mask)) != 0) {
                g_em_topo_ws_ready = 0;
                pthread_mutex_unlock(&g_em_topo_sock_mtx);
                continue;
            }

            if (payload_len > 0) {
                payload = malloc(payload_len + 1);
                if (payload == NULL ||
                    em_topo_read_exact(payload, payload_len) != 0) {
                    free(payload);
                    g_em_topo_ws_ready = 0;
                    pthread_mutex_unlock(&g_em_topo_sock_mtx);
                    continue;
                }
                if (is_masked) {
                    for (size_t i = 0; i < payload_len; i++) {
                        payload[i] ^= mask[i % 4];
                    }
                }
            }

            if (opcode == 0x9) {
                wifi_util_info_print(WIFI_APPS,
                    "[TOPO-WS] ping-listener: PING received (len=%zu), "
                    "sending PONG\n",
                    payload_len);
                if (em_topo_send_ws_control_frame(0xA, payload,
                        payload_len) != 0) {
                    free(payload);
                    g_em_topo_ws_ready = 0;
                    pthread_mutex_unlock(&g_em_topo_sock_mtx);
                    continue;
                }
                wifi_util_info_print(WIFI_APPS,
                    "[TOPO-WS] ping-listener: PONG sent (len=%zu)\n",
                    payload_len);
            } else if (opcode == 0xA) {
                wifi_util_dbg_print(WIFI_APPS,
                    "[TOPO-WS] PONG received (len=%zu)", payload_len);
            } else if (opcode == 0x8) {
                wifi_util_dbg_print(WIFI_APPS,
                    "[TOPO-WS] websocket close frame received");
                free(payload);
                g_em_topo_ws_ready = 0;
                close_received = 1;
            } else {
                wifi_util_dbg_print(WIFI_APPS,
                    "[TOPO-WS] application frame received "
                    "(opcode=0x%X len=%zu)",
                    (unsigned int)opcode, payload_len);
            }

            if (!close_received) {
                free(payload);
            }
            pthread_mutex_unlock(&g_em_topo_sock_mtx);

            if (close_received) {
                em_topo_close();
            }
        }
    }

    wifi_util_dbg_print(WIFI_APPS,
        "[TOPO-WS] ping-listener thread exiting (tid=%lu)",
        (unsigned long)pthread_self());
    return NULL;
}

static void em_topo_start_ping_listener(void)
{
    int rc;

    if (g_em_topo_ping_tid != 0) {
        return;
    }

    g_em_topo_listen_stop = 0;
    rc = pthread_create(&g_em_topo_ping_tid, NULL,
        em_topo_ping_listener_thread, NULL);
    if (rc != 0) {
        g_em_topo_ping_tid = 0;
        wifi_util_dbg_print(WIFI_APPS,
            "[TOPO-WS] failed to create ping-listener thread: %s",
            strerror(rc));
    } else {
        wifi_util_dbg_print(WIFI_APPS,
            "[TOPO-WS] ping-listener thread created (tid=%lu)",
            (unsigned long)g_em_topo_ping_tid);
    }
}

static void em_topo_stop_ping_listener(void)
{
    int fd;

    if (g_em_topo_ping_tid == 0) {
        return;
    }

    g_em_topo_listen_stop = 1;
    fd = g_em_topo_socket_fd;
    if (fd >= 0) {
        shutdown(fd, SHUT_RDWR);
    }
    pthread_join(g_em_topo_ping_tid, NULL);
    g_em_topo_ping_tid = 0;
}

static void em_topo_close(void)
{
    wifi_util_dbg_print(WIFI_APPS,
        "[TOPO-WS] Closing connection (fd=%d ssl=%p)",
        g_em_topo_socket_fd, (void *)g_em_topo_ssl);

    g_em_topo_ws_ready = 0;
    pthread_mutex_lock(&g_em_topo_sock_mtx);

    if (g_em_topo_ssl) {
        int fd = SSL_get_fd(g_em_topo_ssl);
        int flags;

        wifi_util_dbg_print(WIFI_APPS,
            "[TOPO-WS] SSL_shutdown + SSL_free");
        flags = fd >= 0 ? fcntl(fd, F_GETFL, 0) : -1;
        if (flags >= 0) {
            (void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        }
        SSL_shutdown(g_em_topo_ssl);
        SSL_free(g_em_topo_ssl);
        g_em_topo_ssl = NULL;
    }
    if (g_em_topo_ssl_ctx) {
        wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] SSL_CTX_free");
        SSL_CTX_free(g_em_topo_ssl_ctx);
        g_em_topo_ssl_ctx = NULL;
    }
    if (g_em_topo_socket_fd >= 0) {
        wifi_util_dbg_print(WIFI_APPS,
            "[TOPO-WS] closing socket fd=%d", g_em_topo_socket_fd);
        close(g_em_topo_socket_fd);
        g_em_topo_socket_fd = -1;
    }

    pthread_mutex_unlock(&g_em_topo_sock_mtx);
    wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] Connection closed");
}

static void em_topo_load_gateway_mac(void)
{
    char mac[32] = {0};
    FILE *fp;

    fp = popen("deviceinfo.sh -cmac 2>/dev/null || "
               "cat /sys/class/net/brlan0/address 2>/dev/null || "
               "cat /sys/class/net/erouter0/address 2>/dev/null", "r");
    if (fp != NULL) {
        if (fgets(mac, sizeof(mac), fp) != NULL) {
            mac[strcspn(mac, "\r\n")] = '\0';
        }
        pclose(fp);
    }

    if (mac[0] == '\0') {
        snprintf(mac, sizeof(mac), "unknown");
    }
    snprintf(g_em_topo_gateway_mac, sizeof(g_em_topo_gateway_mac), "%s", mac);
    wifi_util_dbg_print(WIFI_APPS,
        "[TOPO-WS] Gateway CM-MAC fetched at runtime: %s",
        g_em_topo_gateway_mac);
}

static void *em_topo_subscription_thread(void *arg)
{
    wifi_app_t *app = (wifi_app_t *)arg;
    unsigned int subscribe_attempt = 0;
    bus_error_t rc;

    while (!g_em_topo_subscribe_stop) {
        rc = get_bus_descriptor()->bus_event_subs_fn(
            &app->handle, EM_TOPOLOGY_EVENT_NAME, get_topology_handler, NULL, 1000);
        if (rc == bus_error_success) {
            g_em_topo_subscribed = 1;
            em_topo_load_gateway_mac();
            em_topo_start_ping_listener();
            wifi_util_info_print(WIFI_APPS,
                "%s:%d: RBUS model registered; topology subscription succeeded\n",
                __func__, __LINE__);
            return NULL;
        }

        subscribe_attempt++;
        if (subscribe_attempt == 1 ||
            (subscribe_attempt % 10) == 0) {
            wifi_util_error_print(WIFI_APPS,
                "%s:%d waiting for RBUS model %s (attempt:%u rc:%d)\n",
                __func__, __LINE__, EM_TOPOLOGY_EVENT_NAME,
                subscribe_attempt, rc);
        }
        sleep(EM_TOPOLOGY_SUBSCRIBE_RETRY_SEC);
    }

    return NULL;
}

/* --- Entry point: called from the Network Topology event handler --- */
static void em_topo_stream_send_topology(const char *topology_json)
{
    char *envelope_str = NULL;
    char id_buf[32] = {0};
    char ts_buf[32] = {0};
    struct timeval tv_now = {0};
    struct tm tm_now;
    cJSON *envelope;

    if (topology_json == NULL) {
        wifi_util_dbg_print(WIFI_APPS,
            "[TOPO-WS] topology_json is NULL, skipping");
        return;
    }

    g_em_topo_order_id++;
    gettimeofday(&tv_now, NULL);
    localtime_r(&tv_now.tv_sec, &tm_now);
    strftime(ts_buf, sizeof(ts_buf), "%m%d%y%H%M%S", &tm_now);
    snprintf(id_buf, sizeof(id_buf), "%llu", g_em_topo_order_id);

    envelope = cJSON_CreateObject();
    if (envelope == NULL) {
        wifi_util_dbg_print(WIFI_APPS,
            "[TOPO-WS] cJSON_CreateObject failed");
        return;
    }

    cJSON_AddStringToObject(envelope, "cm_mac", g_em_topo_gateway_mac);
    cJSON_AddStringToObject(envelope, "ordering_id", id_buf);
    cJSON_AddStringToObject(envelope, "app_type", "easyMesh");
    cJSON_AddStringToObject(envelope, "timestamp", ts_buf);
    {
        cJSON *payload_obj = cJSON_Parse(topology_json);
        if (payload_obj != NULL) {
            cJSON_AddItemToObject(envelope, "payload", payload_obj);
        } else {
            cJSON_AddStringToObject(envelope, "payload", topology_json);
        }
    }

    envelope_str = cJSON_PrintUnformatted(envelope);
    cJSON_Delete(envelope);
    if (envelope_str == NULL) {
        wifi_util_dbg_print(WIFI_APPS,
            "[TOPO-WS] cJSON_PrintUnformatted failed");
        return;
    }

    wifi_util_dbg_print(WIFI_APPS,
        "[TOPO-WS] Sending topology #%llu ts=%s mac=%s",
        g_em_topo_order_id, ts_buf, g_em_topo_gateway_mac);

    for (int send_attempt = 0; send_attempt < 5; send_attempt++) {
        if (g_em_topo_socket_fd < 0 || !g_em_topo_ws_ready) {
            em_topo_close();
            wifi_util_dbg_print(WIFI_APPS,
                "[TOPO-WS] No active connection, starting connect sequence");
            wifi_util_dbg_print(WIFI_APPS,
                "[TOPO-WS] Target URL: %s", g_em_topo_stream_url);

            {
                char token[EM_TOPO_STREAM_TOKEN_SIZE] = {0};
                wifi_util_dbg_print(WIFI_APPS,
                    "[TOPO-WS] Fetching SAT token from %s",
                    EM_TOPO_STREAM_SAT_URL);
                if (em_topo_fetch_sat_token(token, sizeof(token)) == 0) {
                    wifi_util_dbg_print(WIFI_APPS,
                        "[TOPO-WS] SAT token fetched OK (len=%zu)",
                        strlen(token));
                    if (em_topo_build_url_with_token(token) == 0) {
                        wifi_util_dbg_print(WIFI_APPS,
                            "[TOPO-WS] URL updated with token: %s",
                            g_em_topo_stream_url);
                    }
                } else {
                    wifi_util_dbg_print(WIFI_APPS,
                        "[TOPO-WS] SAT token fetch failed, proceeding without token");
                }
            }

            {
                em_topo_url_info_t info;
                char port_str[8] = {0};
                struct addrinfo hints = {0};
                struct addrinfo *result = NULL;
                int gai_rc;

                wifi_util_dbg_print(WIFI_APPS,
                    "[TOPO-WS] Parsing URL: %s", g_em_topo_stream_url);
                if (!em_topo_parse_url(&info)) {
                    wifi_util_dbg_print(WIFI_APPS,
                        "[TOPO-WS] URL parse failed");
                    em_topo_close();
                    continue;
                }
                snprintf(port_str, sizeof(port_str), "%u",
                    (unsigned int)info.port);
                wifi_util_dbg_print(WIFI_APPS,
                    "[TOPO-WS] Parsed - host=%s port=%s path=%s tls=%d",
                    info.host, port_str, info.path_query, info.use_tls);

                hints.ai_family = AF_UNSPEC;
                hints.ai_socktype = SOCK_STREAM;
                gai_rc = getaddrinfo(info.host, port_str, &hints, &result);
                if (gai_rc != 0 || result == NULL) {
                    wifi_util_dbg_print(WIFI_APPS,
                        "[TOPO-WS] DNS lookup failed for %s", info.host);
                    em_topo_close();
                    continue;
                }

                wifi_util_dbg_print(WIFI_APPS,
                    "[TOPO-WS] DNS resolved OK, attempting TCP connect to %s:%s",
                    info.host, port_str);
                for (struct addrinfo *rp = result; rp != NULL; rp = rp->ai_next) {
                    int fd = socket(rp->ai_family, rp->ai_socktype,
                        rp->ai_protocol);
                    if (fd < 0) {
                        wifi_util_dbg_print(WIFI_APPS,
                            "[TOPO-WS] socket() failed: %s", strerror(errno));
                        continue;
                    }
                    if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
                        g_em_topo_socket_fd = fd;
                        break;
                    }
                    wifi_util_dbg_print(WIFI_APPS,
                        "[TOPO-WS] connect() failed: %s", strerror(errno));
                    close(fd);
                }
                freeaddrinfo(result);

                if (g_em_topo_socket_fd < 0) {
                    wifi_util_dbg_print(WIFI_APPS,
                        "[TOPO-WS] TCP connect to %s:%s failed",
                        info.host, port_str);
                    em_topo_close();
                    continue;
                }
                wifi_util_dbg_print(WIFI_APPS,
                    "[TOPO-WS] TCP connected to %s:%s (fd=%d)",
                    info.host, port_str, g_em_topo_socket_fd);

                if (info.use_tls) {
                    wifi_util_dbg_print(WIFI_APPS,
                        "[TOPO-WS] Starting TLS setup");
                    SSL_library_init();
                    g_em_topo_ssl_ctx = SSL_CTX_new(TLS_client_method());
                    if (g_em_topo_ssl_ctx == NULL) {
                        wifi_util_dbg_print(WIFI_APPS,
                            "[TOPO-WS] SSL_CTX_new failed");
                        em_topo_close();
                        continue;
                    }
                    wifi_util_dbg_print(WIFI_APPS,
                        "[TOPO-WS] SSL_CTX created OK");
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
                    SSL_CTX_set_keylog_callback(g_em_topo_ssl_ctx,
                        em_topo_ssl_keylog_cb);
                    wifi_util_dbg_print(WIFI_APPS,
                        "[TOPO-WS] SSL key logging enabled -> %s",
                        EM_TOPO_SSL_KEYLOG_FILE);
#endif

                    g_em_topo_ssl = SSL_new(g_em_topo_ssl_ctx);
                    if (g_em_topo_ssl == NULL) {
                        wifi_util_dbg_print(WIFI_APPS,
                            "[TOPO-WS] SSL_new failed");
                        em_topo_close();
                        continue;
                    }
                    SSL_set_tlsext_host_name(g_em_topo_ssl, info.host);
                    SSL_set_fd(g_em_topo_ssl, g_em_topo_socket_fd);
                    wifi_util_dbg_print(WIFI_APPS,
                        "[TOPO-WS] Calling SSL_connect to %s", info.host);
                    if (SSL_connect(g_em_topo_ssl) != 1) {
                        wifi_util_dbg_print(WIFI_APPS,
                            "[TOPO-WS] SSL_connect failed (SSL error=%d)",
                            SSL_get_error(g_em_topo_ssl, -1));
                        em_topo_close();
                        continue;
                    }
                    wifi_util_dbg_print(WIFI_APPS,
                        "[TOPO-WS] TLS handshake OK - cipher=%s",
                        SSL_get_cipher(g_em_topo_ssl));
                }

                {
                    char req[2048] = {0};
                    char resp[1024] = {0};
                    unsigned char ws_key_bytes[16];
                    char ws_key_b64[25] = {0};
                    int w;
                    int r;

                    if (RAND_bytes(ws_key_bytes, sizeof(ws_key_bytes)) != 1 ||
                        EVP_EncodeBlock((unsigned char *)ws_key_b64,
                            ws_key_bytes, sizeof(ws_key_bytes)) <= 0) {
                        wifi_util_dbg_print(WIFI_APPS,
                            "[TOPO-WS] failed to generate WebSocket key");
                        em_topo_close();
                        continue;
                    }
                    snprintf(req, sizeof(req),
                        "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\n"
                        "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
                        "Sec-WebSocket-Version: 13\r\n\r\n",
                        info.path_query, info.host, ws_key_b64);
                    wifi_util_dbg_print(WIFI_APPS,
                        "[TOPO-WS] Sending WS upgrade request (%zu bytes)",
                        strlen(req));

                    w = g_em_topo_ssl
                        ? SSL_write(g_em_topo_ssl, req, (int)strlen(req))
                        : (int)send(g_em_topo_socket_fd, req, strlen(req), 0);
                    if (w <= 0) {
                        wifi_util_dbg_print(WIFI_APPS,
                            "[TOPO-WS] WS upgrade write failed");
                        em_topo_close();
                        continue;
                    }

                    r = g_em_topo_ssl
                        ? SSL_read(g_em_topo_ssl, resp, (int)sizeof(resp) - 1)
                        : (int)recv(g_em_topo_socket_fd, resp,
                            sizeof(resp) - 1, 0);
                    if (r <= 0) {
                        wifi_util_dbg_print(WIFI_APPS,
                            "[TOPO-WS] WS upgrade read failed");
                        em_topo_close();
                        continue;
                    }
                    resp[r] = '\0';
                    wifi_util_dbg_print(WIFI_APPS,
                        "[TOPO-WS] WS upgrade response: %.120s", resp);
                    if (!strstr(resp, "101")) {
                        wifi_util_dbg_print(WIFI_APPS,
                            "[TOPO-WS] WS upgrade rejected - no 101 in response");
                        em_topo_close();
                        continue;
                    }
                }

                wifi_util_dbg_print(WIFI_APPS,
                    "[TOPO-WS] WS upgrade OK - connected to %s:%s%s",
                    info.host, port_str, info.path_query);
                g_em_topo_ws_ready = 1;
            }
        } else {
            wifi_util_dbg_print(WIFI_APPS,
                "[TOPO-WS] Reusing existing connection (fd=%d)",
                g_em_topo_socket_fd);
        }

        {
            size_t jlen = strlen(envelope_str);
            int n;

            wifi_util_dbg_print(WIFI_APPS,
                "[TOPO-WS] Sending DataFrame #%llu len=%zu",
                g_em_topo_order_id, jlen);
            pthread_mutex_lock(&g_em_topo_sock_mtx);
            n = ws_send_frame(envelope_str, jlen);
            pthread_mutex_unlock(&g_em_topo_sock_mtx);
            if (n == 0) {
                wifi_util_dbg_print(WIFI_APPS,
                    "[TOPO-WS] DataFrame sent successfully #%llu len=%zu",
                    g_em_topo_order_id, jlen);
                break;
            }

            wifi_util_dbg_print(WIFI_APPS,
                "[TOPO-WS] Send failed #%llu - closing connection",
                g_em_topo_order_id);
            em_topo_close();
        }
    }

    free(envelope_str);
}

#endif /* EM_WEBSOCKET_PUSH */

static bus_error_t get_topology_handler(char *event_name, bus_data_prop_t *p_data,
                                        void *user_data)
{
    char *raw_data = NULL;
    size_t raw_data_len;

    (void)user_data;

    if (event_name == NULL || p_data == NULL ||
        strcmp(event_name, EM_TOPOLOGY_EVENT_NAME) != 0) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: Invalid topology event\n", __func__, __LINE__);
        return bus_error_invalid_input;
    }

    raw_data_len = p_data->value.raw_data_len;
    if (p_data->value.raw_data.bytes == NULL || raw_data_len == 0) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: Empty topology payload\n", __func__, __LINE__);
        return bus_error_invalid_input;
    }

    raw_data = malloc(raw_data_len + 1);
    if (raw_data == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: Memory allocation failed for raw_data\n", __func__, __LINE__);
        return bus_error_out_of_resources;
    }
    memcpy(raw_data, p_data->value.raw_data.bytes, raw_data_len);
    raw_data[raw_data_len] = '\0';
    wifi_util_info_print(WIFI_APPS, "%s:%d: Received topology event, payload is %s\n", __func__, __LINE__, raw_data);

    em_topo_stream_send_topology(raw_data);
    free(raw_data);
    return bus_error_success;
}

int em_websocket_init(wifi_app_t *app, unsigned int create_flag)
{
    int rc = RETURN_OK;
    char *component_name = "WifiEMWebsocket";

    rc = get_bus_descriptor()->bus_open_fn(&app->handle, component_name);
    if (rc != bus_error_success) {
	    wifi_util_error_print(WIFI_APPS,
	        "%s:%d bus: bus_open_fn open failed for component:%s, rc:%d\n",
	        __func__, __LINE__, component_name, rc);
	    return RETURN_ERR;
    }

    signal(SIGPIPE, SIG_IGN);
    g_em_topo_subscribe_stop = 0;
    g_em_topo_subscribed = 0;
    rc = pthread_create(&g_em_topo_subscribe_tid, NULL,
        em_topo_subscription_thread, app);
    if (rc != 0) {
        wifi_util_error_print(WIFI_APPS,
            "%s:%d: failed to create RBUS subscription thread, rc:%d\n",
            __func__, __LINE__, rc);
        g_em_topo_subscribe_tid = 0;
        get_bus_descriptor()->bus_close_fn(&app->handle);
        return RETURN_ERR;
    }

    wifi_util_info_print(WIFI_APPS, "%s:%d: Init em websocket app %s\n", __func__, __LINE__,
		    rc ? "failure" : "success");
    return RETURN_OK;
}

int em_websocket_event(wifi_app_t *app, wifi_event_t *event)
{
    return RETURN_OK;
}

int em_websocket_deinit(wifi_app_t *app)
{
    if (app != NULL) {
        g_em_topo_subscribe_stop = 1;
        if (g_em_topo_subscribe_tid != 0) {
            pthread_join(g_em_topo_subscribe_tid, NULL);
            g_em_topo_subscribe_tid = 0;
        }
        em_topo_stop_ping_listener();
        em_topo_close();
        if (g_em_topo_subscribed) {
            get_bus_descriptor()->bus_event_unsubs_fn(
                &app->handle, EM_TOPOLOGY_EVENT_NAME);
            g_em_topo_subscribed = 0;
        }
        get_bus_descriptor()->bus_close_fn(&app->handle);
    }
    return RETURN_OK;
}
