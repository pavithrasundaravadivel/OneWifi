#define EM_WEBSOCKET_PUSH 1

#ifdef EM_WEBSOCKET_PUSH
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <time.h>
#include <signal.h>
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

typedef struct wifi_app wifi_app_t;

/* Default base URL — SAT token is appended as ?token=<JWT> after fetch */
static char g_em_topo_stream_url[EM_TOPO_STREAM_URL_SIZE] =
    "wss://vb-streamer-api.vb.comcast.com:6100/ws/receive_data";

static int                g_em_topo_socket_fd     = -1;
static SSL_CTX           *g_em_topo_ssl_ctx       = NULL;
static SSL               *g_em_topo_ssl           = NULL;
static unsigned long long g_em_topo_order_id      = 0;

typedef struct {
    bool     use_tls;
    char     host[128];
    uint16_t port;
    char     path_query[1024];
} em_topo_url_info_t;

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

static void em_topo_close(void)
{
    wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] Closing connection (fd=%d ssl=%p)", g_em_topo_socket_fd, (void *)g_em_topo_ssl);
    if (g_em_topo_ssl) {
        wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] SSL_shutdown + SSL_free");
        SSL_shutdown(g_em_topo_ssl);
        SSL_free(g_em_topo_ssl);
        g_em_topo_ssl = NULL;
    }
    if (g_em_topo_ssl_ctx) {
        wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] SSL_CTX_free");
        SSL_CTX_free(g_em_topo_ssl_ctx);
        g_em_topo_ssl_ctx = NULL;
    }
    if (g_em_topo_socket_fd >= 0) {
        wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] closing socket fd=%d", g_em_topo_socket_fd);
        close(g_em_topo_socket_fd);
        g_em_topo_socket_fd = -1;
    }
    wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] Connection closed");
}

/* --- Entry point: called from publish_network_topology() --- */
static void em_topo_stream_send_topology(const char *topology_json)
{
    char          *envelope_str = NULL;
    char           id_buf[32]   = {0};
    char           ts_buf[32]   = {0};
    struct timeval tv_now       = {0};
    struct tm      tm_now;

    if (topology_json == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] topology_json is NULL, skipping");
        return;
    }

    g_em_topo_order_id++;
    gettimeofday(&tv_now, NULL);
    localtime_r(&tv_now.tv_sec, &tm_now);
    strftime(ts_buf, sizeof(ts_buf), "%m%d%y%H%M%S", &tm_now);
    snprintf(id_buf, sizeof(id_buf), "%llu", g_em_topo_order_id);

    cJSON *envelope = cJSON_CreateObject();
    if (envelope == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] cJSON_CreateObject failed");
        return;
    }
    cJSON_AddStringToObject(envelope, "start_id",    id_buf);
    cJSON_AddStringToObject(envelope, "ordering_id", id_buf);
    cJSON_AddStringToObject(envelope, "app_type",    "easyMesh");
    cJSON_AddStringToObject(envelope, "timestamp",   ts_buf);
    cJSON_AddStringToObject(envelope, "payload",     topology_json);
    cJSON_AddStringToObject(envelope, "end_id",      id_buf);
    envelope_str = cJSON_PrintUnformatted(envelope);
    cJSON_Delete(envelope);
    if (envelope_str == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] cJSON_PrintUnformatted failed");
        return;
    }

    wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] Sending topology ordering_id=%s ts=%s", id_buf, ts_buf);

    /* ---- Connect (only if not already up) ---- */
    if (g_em_topo_socket_fd < 0) {
        wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] No active connection, starting connect sequence");
        wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] Target URL: %s", g_em_topo_stream_url);

        char token[EM_TOPO_STREAM_TOKEN_SIZE] = {0};
        wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] Fetching SAT token from %s", EM_TOPO_STREAM_SAT_URL);
        if (em_topo_fetch_sat_token(token, sizeof(token)) == 0) {
            wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] SAT token fetched OK (len=%zu)", strlen(token));
            em_topo_build_url_with_token(token);
            wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] URL updated with token: %s", g_em_topo_stream_url);
        } else {
            wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] SAT token fetch failed, proceeding without token");
        }

        em_topo_url_info_t info;
        char port_str[8] = {0};
        struct addrinfo hints = {}, *result = NULL;

        wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] Parsing URL: %s", g_em_topo_stream_url);
        if (!em_topo_parse_url(&info)) {
            wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] URL parse failed");
            goto cleanup;
        }
        snprintf(port_str, sizeof(port_str), "%u", (unsigned int)info.port);
        wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] Parsed — host=%s port=%s path=%s tls=%d",
            info.host, port_str, info.path_query, info.use_tls);

        wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] Resolving DNS for %s", info.host);
        hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(info.host, port_str, &hints, &result) != 0 || !result) {
            wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] DNS lookup failed for %s", info.host);
            goto cleanup;
        }
        wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] DNS resolved OK, attempting TCP connect to %s:%s", info.host, port_str);

        for (struct addrinfo *rp = result; rp; rp = rp->ai_next) {
            int fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (fd < 0) {
                wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] socket() failed: %s", strerror(errno));
                continue;
            }
            if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
                g_em_topo_socket_fd = fd;
                break;
            }
            wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] connect() failed: %s", strerror(errno));
            close(fd);
        }
        freeaddrinfo(result);

        if (g_em_topo_socket_fd < 0) {
            wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] TCP connect to %s:%s failed", info.host, port_str);
            goto cleanup;
        }
        wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] TCP connected to %s:%s (fd=%d)", info.host, port_str, g_em_topo_socket_fd);

        if (info.use_tls) {
            wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] Starting TLS setup");
            SSL_library_init();
            g_em_topo_ssl_ctx = SSL_CTX_new(TLS_client_method());
            if (g_em_topo_ssl_ctx == NULL) {
                wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] SSL_CTX_new failed");
                em_topo_close(); goto cleanup;
            }
            wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] SSL_CTX created OK");

            g_em_topo_ssl = SSL_new(g_em_topo_ssl_ctx);
            if (g_em_topo_ssl == NULL) {
                wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] SSL_new failed");
                em_topo_close(); goto cleanup;
            }
            wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] SSL object created OK");

            SSL_set_tlsext_host_name(g_em_topo_ssl, info.host);
            SSL_set_fd(g_em_topo_ssl, g_em_topo_socket_fd);
            wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] Calling SSL_connect to %s", info.host);
            if (SSL_connect(g_em_topo_ssl) != 1) {
                wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] SSL_connect failed (SSL error=%d)", SSL_get_error(g_em_topo_ssl, -1));
                em_topo_close(); goto cleanup;
            }
            wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] TLS handshake OK — cipher=%s", SSL_get_cipher(g_em_topo_ssl));
        }

        char req[2048] = {0}, resp[1024] = {0};
        snprintf(req, sizeof(req),
            "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\n"
            "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n",
            info.path_query, info.host);
        wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] Sending WS upgrade request (%zu bytes)", strlen(req));

        int w = g_em_topo_ssl ? SSL_write(g_em_topo_ssl, req, (int)strlen(req))
                               : (int)send(g_em_topo_socket_fd, req, strlen(req), 0);
        wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] WS upgrade write returned %d (expected %zu)", w, strlen(req));
        if (w <= 0) {
            wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] WS upgrade write failed");
            em_topo_close(); goto cleanup;
        }

        int r = g_em_topo_ssl ? SSL_read(g_em_topo_ssl, resp, (int)sizeof(resp) - 1)
                               : (int)recv(g_em_topo_socket_fd, resp, sizeof(resp) - 1, 0);
        wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] WS upgrade read returned %d bytes", r);
        if (r <= 0) {
            wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] WS upgrade read failed");
            em_topo_close(); goto cleanup;
        }
        resp[r] = '\0';
        wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] WS upgrade response: %.120s", resp);

        if (!strstr(resp, "101")) {
            wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] WS upgrade rejected — no 101 in response");
            em_topo_close(); goto cleanup;
        }
        wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] WS upgrade OK — connected to %s:%s%s", info.host, port_str, info.path_query);
    } else {
        wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] Reusing existing connection (fd=%d)", g_em_topo_socket_fd);
    }

    /* ---- Send ---- */
    {
        size_t jlen = strlen(envelope_str);
        wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] Sending DataFrame ordering_id=%s len=%zu", id_buf, jlen);
        int n = g_em_topo_ssl ? SSL_write(g_em_topo_ssl, envelope_str, (int)jlen)
                              : (int)send(g_em_topo_socket_fd, envelope_str, jlen, MSG_NOSIGNAL);
        if (n > 0) {
            wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] DataFrame sent successfully ordering_id=%s len=%zu sent=%d", id_buf, jlen, n);
        } else {
            wifi_util_dbg_print(WIFI_APPS,"[TOPO-WS] Send failed ordering_id=%s (ret=%d) — closing connection", id_buf, n);
            em_topo_close();
        }
    }

cleanup:
    free(envelope_str);
}

#endif /* EM_WEBSOCKET_PUSH */

static void get_topology_handler(char *event_name, bus_data_prop_t *p_data)
{
    char *raw_data = NULL;
    size_t raw_data_len;

    if (event_name == NULL || p_data == NULL ||
        strcmp(event_name, "Device.WiFi.DataElements.Network.Topology") != 0) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: Invalid topology event\n", __func__, __LINE__);
        return;
    }

    raw_data_len = p_data->value.raw_data_len;
    if (p_data->value.raw_data.bytes == NULL || raw_data_len == 0) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: Empty topology payload\n", __func__, __LINE__);
        return;
    }

    raw_data = malloc(raw_data_len + 1);
    if (raw_data == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: Memory allocation failed for raw_data\n", __func__, __LINE__);
        return;
    }
    memcpy(raw_data, p_data->value.raw_data.bytes, raw_data_len);
    raw_data[raw_data_len] = '\0';
    wifi_util_info_print(WIFI_APPS, "%s:%d: Received topology event, payload is %s\n", __func__, __LINE__, raw_data);

    em_topo_stream_send_topology(raw_data);
    free(raw_data);
}
int em_websocket_init(wifi_app_t *app, unsigned int create_flag)
{
    int rc = RETURN_OK;
    char *component_name = "WifiEMWebsocket";

    rc = get_bus_descriptor()->bus_event_subs_fn(&app->handle, "Device.WiFi.DataElements.Network.Topology", get_topology_handler, NULL, 0);
    if (rc != bus_error_success) {
	    wifi_util_error_print(WIFI_APPS,
			   "%s:%d bus: bus_subscribe_fn failed for component:%s, rc:%d\n", __func__, __LINE__,
			    component_name, rc);
	    return RETURN_ERR;
    }

    wifi_util_info_print(WIFI_APPS, "%s:%d: Init em websocket app %s\n", __func__, __LINE__,
		    rc ? "failure" : "success");
    return rc;
}

int em_websocket_event(wifi_app_t *app, wifi_event_t *event)
{
    return RETURN_OK;
}

int em_websocket_deinit(wifi_app_t *app)
{
    return RETURN_OK;
}
