/* Integration tests for WN_TRANSPORT_WEBSOCKET: real client + server over
 * loopback TCP, HTTP upgrade (RFC6455), then the normal encrypted weft-net
 * handshake and delivery modes inside binary WebSocket frames. */
#include "../test_framework.h"
#include "../../include/weft_net.h"
#include "../../src/websocket.h"
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <poll.h>
#include <pthread.h>
#include <time.h>
#include <fcntl.h>

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

/* Bind a TCP socket to port 0, read the kernel-assigned port back, and
 * release it. The port is free again as soon as close() returns; the test
 * binds it again immediately, so a racing process grabbing it in between
 * is unlikely. */
static uint16_t free_port(void) {
    int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = inet_addr("127.0.0.1");
    bind(s, (struct sockaddr *)&a, sizeof(a));
    socklen_t len = sizeof(a);
    getsockname(s, (struct sockaddr *)&a, &len);
    uint16_t p = (uint16_t)ntohs(a.sin_port);
    close(s);
    return p;
}

static bool write_all(int fd, const uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t w = send(fd, buf + off, len - off, MSG_NOSIGNAL);
        if (w > 0) { off += (size_t)w; continue; }
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return false;
        if (w < 0) return false;
        if (w == 0) return false;
    }
    return true;
}

static ssize_t read_before(int fd, void *buf, size_t len, uint64_t deadline) {
    for (;;) {
        uint64_t now = now_ms();
        if (now >= deadline) return -1;
        struct pollfd p = { .fd = fd, .events = POLLIN };
        int ready = poll(&p, 1, (int)(deadline - now));
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0) return -1;
        ssize_t n = recv(fd, buf, len, 0);
        if (n < 0 && errno == EINTR) continue;
        return n;
    }
}

static bool read_upgrade(int fd, const char key[25]) {
    char resp[512];
    uint64_t deadline = now_ms() + 2000;
    /* Stop at the header boundary so bytes from a following frame are
     * still available even if TCP delivered them in the same segment. */
    for (size_t i = 0; i < sizeof(resp); i++) {
        if (read_before(fd, &resp[i], 1, deadline) != 1) return false;
        if (wn_ws_http_header_complete(resp, i + 1, NULL))
            return wn_ws_check_server_response(resp, i + 1, key);
    }
    return false;
}

static bool read_exact(int fd, uint8_t *buf, size_t len) {
    uint64_t deadline = now_ms() + 2000;
    size_t off = 0;
    while (off < len) {
        ssize_t n = read_before(fd, buf + off, len - off, deadline);
        if (n <= 0) return false;
        off += (size_t)n;
    }
    return true;
}

static bool wait_for_event(wn_endpoint_t *ep, wn_event_type_t type, wn_event_t *out, int timeout_ms) {
    uint64_t iterations = (uint64_t)timeout_ms / 50 + 1;
    for (uint64_t i = 0; i < iterations; i++) {
        if (wn_poll_event(ep, out, 50)) {
            if (out->event_type == type) return true;
        }
    }
    return false;
}

static wn_address_t addr(const char *host, uint16_t port) {
    wn_address_t a; memset(&a, 0, sizeof(a));
    strncpy(a.host, host, sizeof(a.host) - 1);
    a.port = port;
    a.family = WN_AF_UNSPEC;
    return a;
}

static void ws_config(wn_config_t *cfg) {
    wn_config_default(cfg);
    cfg->transport = WN_TRANSPORT_WEBSOCKET;
}

TEST(test_ws_upgrade_precedes_pipelined_pong_and_close_is_echoed) {
    wn_config_t cfg; ws_config(&cfg);
    wn_endpoint_t *server = NULL;
    uint16_t port = free_port();
    wn_address_t bind_addr = addr("127.0.0.1", port);
    ASSERT_EQ(wn_server_create(&bind_addr, &cfg, &server), WN_OK);

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(port) };
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd < 0 || connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        if (fd >= 0) close(fd);
        wn_endpoint_destroy(server);
        WN_FAIL("%s", "could not connect raw WebSocket peer");
        return;
    }

    char req[512], key[25];
    size_t req_len = 0;
    const uint8_t ping[] = { 0x00, 0xAB, 0xFF };
    uint8_t pong[2 + sizeof(ping)];
    bool built = wn_ws_build_client_request("127.0.0.1", port, "/", req,
                                          sizeof(req), &req_len, key);
    size_t ping_len = built ? wn_ws_encode(WN_WS_OPCODE_PING, ping, sizeof(ping), true,
                                         (uint8_t *)req + req_len, sizeof(req) - req_len) : 0;
    /* Submit HTTP and the first frame together: the raw 101 response
     * must precede the queued pong on the wire. */
    bool sent = ping_len > 0 && write_all(fd, (const uint8_t *)req, req_len + ping_len);
    bool upgraded = sent && read_upgrade(fd, key);
    bool got_pong = upgraded && read_exact(fd, pong, sizeof(pong));
    CHECK_TRUE(upgraded);
    CHECK_TRUE(got_pong);
    if (got_pong) {
        CHECK_EQ(pong[0], 0x80 | WN_WS_OPCODE_PONG);
        CHECK_EQ(pong[1], sizeof(ping)); /* server reply must be unmasked */
        CHECK_MEM_EQ(pong + 2, ping, sizeof(ping));

        const uint8_t code[] = { 0x03, 0xE8 }; /* normal closure (1000) */
        uint8_t close_frame[2 + 4 + sizeof(code)], echo[2 + sizeof(code)];
        size_t n = wn_ws_encode(WN_WS_OPCODE_CLOSE, code, sizeof(code), true,
                                close_frame, sizeof(close_frame));
        bool got_echo = n > 0 && write_all(fd, close_frame, n) &&
                        read_exact(fd, echo, sizeof(echo));
        CHECK_TRUE(got_echo);
        if (got_echo) {
            CHECK_EQ(echo[0], 0x80 | WN_WS_OPCODE_CLOSE);
            CHECK_EQ(echo[1], sizeof(code));
            CHECK_MEM_EQ(echo + 2, code, sizeof(code));
            uint8_t extra;
            ssize_t end = read_before(fd, &extra, sizeof(extra), now_ms() + 2000);
            CHECK_EQ(end, 0);
        }
    }
    close(fd);
    wn_endpoint_destroy(server);
}

TEST(test_ws_connect_and_reliable_echo) {
    wn_config_t cfg; ws_config(&cfg);
    wn_endpoint_t *server = NULL, *client = NULL;
    wn_address_t bind_addr = addr("127.0.0.1", 34751);
    ASSERT_EQ(wn_server_create(&bind_addr, &cfg, &server), WN_OK);
    ASSERT_EQ(wn_client_create(&cfg, &client), WN_OK);

    wn_peer_id_t client_peer;
    ASSERT_EQ(wn_connect(client, &bind_addr, &client_peer), WN_OK);

    wn_event_t ev;
    ASSERT_TRUE(wait_for_event(client, WN_EVENT_CONNECTED, &ev, 5000));
    ASSERT_TRUE(wait_for_event(server, WN_EVENT_CONNECTED, &ev, 5000));
    wn_peer_id_t server_peer = ev.peer;

    const char *msg = "websocket hello";
    ASSERT_EQ(wn_send(client, client_peer, 0, WN_RELIABLE_ORDERED,
                      (const uint8_t *)msg, strlen(msg)), WN_OK);
    ASSERT_TRUE(wait_for_event(server, WN_EVENT_DATA, &ev, 5000));
    ASSERT_EQ(ev.data_len, strlen(msg));
    ASSERT_MEM_EQ(ev.data, msg, strlen(msg));

    const char *reply = "echo from ws server";
    ASSERT_EQ(wn_send(server, server_peer, 0, WN_RELIABLE_ORDERED,
                      (const uint8_t *)reply, strlen(reply)), WN_OK);
    ASSERT_TRUE(wait_for_event(client, WN_EVENT_DATA, &ev, 5000));
    ASSERT_EQ(ev.data_len, strlen(reply));
    ASSERT_MEM_EQ(ev.data, reply, strlen(reply));

    wn_endpoint_destroy(client);
    wn_endpoint_destroy(server);
}

TEST(test_ws_unreliable_delivery) {
    wn_config_t cfg; ws_config(&cfg);
    wn_endpoint_t *server = NULL, *client = NULL;
    wn_address_t bind_addr = addr("127.0.0.1", 34752);
    ASSERT_EQ(wn_server_create(&bind_addr, &cfg, &server), WN_OK);
    ASSERT_EQ(wn_client_create(&cfg, &client), WN_OK);

    wn_peer_id_t client_peer;
    ASSERT_EQ(wn_connect(client, &bind_addr, &client_peer), WN_OK);
    wn_event_t ev;
    ASSERT_TRUE(wait_for_event(client, WN_EVENT_CONNECTED, &ev, 5000));
    ASSERT_TRUE(wait_for_event(server, WN_EVENT_CONNECTED, &ev, 5000));

    const uint8_t payload[] = { 1, 2, 3, 4, 5 };
    ASSERT_EQ(wn_send(client, client_peer, 2, WN_UNRELIABLE, payload, sizeof(payload)), WN_OK);
    ASSERT_TRUE(wait_for_event(server, WN_EVENT_DATA, &ev, 5000));
    ASSERT_EQ(ev.channel, 2);
    ASSERT_EQ(ev.data_len, sizeof(payload));
    ASSERT_MEM_EQ(ev.data, payload, sizeof(payload));

    wn_endpoint_destroy(client);
    wn_endpoint_destroy(server);
}

TEST(test_ws_fragmented_large_message) {
    wn_config_t cfg; ws_config(&cfg);
    wn_endpoint_t *server = NULL, *client = NULL;
    wn_address_t bind_addr = addr("127.0.0.1", 34753);
    ASSERT_EQ(wn_server_create(&bind_addr, &cfg, &server), WN_OK);
    ASSERT_EQ(wn_client_create(&cfg, &client), WN_OK);

    wn_peer_id_t client_peer;
    ASSERT_EQ(wn_connect(client, &bind_addr, &client_peer), WN_OK);
    wn_event_t ev;
    ASSERT_TRUE(wait_for_event(client, WN_EVENT_CONNECTED, &ev, 5000));
    ASSERT_TRUE(wait_for_event(server, WN_EVENT_CONNECTED, &ev, 5000));

    size_t big_len = 5000;
    uint8_t *big = (uint8_t *)malloc(big_len);
    ASSERT_TRUE(big != NULL);
    for (size_t i = 0; i < big_len; i++) big[i] = (uint8_t)((i * 13 + 7) & 0xFF);

    ASSERT_EQ(wn_send(client, client_peer, 0, WN_RELIABLE_ORDERED, big, big_len), WN_OK);
    ASSERT_TRUE(wait_for_event(server, WN_EVENT_DATA, &ev, 10000));
    ASSERT_EQ(ev.data_len, big_len);
    ASSERT_MEM_EQ(ev.data, big, big_len);

    free(big);
    wn_endpoint_destroy(client);
    wn_endpoint_destroy(server);
}

TEST(test_ws_discovery_unsupported) {
    wn_config_t cfg; ws_config(&cfg);
    wn_endpoint_t *server = NULL;
    wn_address_t bind_addr = addr("127.0.0.1", 34754);
    ASSERT_EQ(wn_server_create(&bind_addr, &cfg, &server), WN_OK);
    ASSERT_EQ(wn_discovery_enable(server, 34999), WN_ERR_UNSUPPORTED);
    wn_endpoint_destroy(server);

    wn_endpoint_t *client = NULL;
    ASSERT_EQ(wn_client_create(&cfg, &client), WN_OK);
    ASSERT_EQ(wn_discovery_probe(client, 34999, 100), WN_ERR_UNSUPPORTED);
    wn_endpoint_destroy(client);
}

TEST(test_ws_rejects_cleartext_config) {
    wn_config_t cfg; ws_config(&cfg);
    cfg.encryption_enabled = false;
    wn_endpoint_t *ep = NULL;
    wn_address_t bind_addr = addr("127.0.0.1", 34755);
    ASSERT_EQ(wn_server_create(&bind_addr, &cfg, &ep), WN_ERR_UNSUPPORTED);
    ASSERT_EQ(wn_client_create(&cfg, &ep), WN_ERR_UNSUPPORTED);
}

/* Test-only helpers from endpoint.c, declared in tests/test_helpers.h. */
#include "../test_helpers.h"

/* Regression (P1-4): the WebSocket immediate-connect path (nonblocking
 * connect() succeeding synchronously on loopback) leaked its pending entry
 * when ws_client_finish_connect failed -- no release, so the slot stayed
 * in_use until the 5s expiry. A synchronously-failed wn_connect must leave
 * no pending entry behind (checked here via the async-failure shape, which
 * exercises the same release accounting; the immediate path is covered by
 * the release_pending_by_connid call in wn_connect). */
TEST(test_ws_failed_connect_does_not_leak_pending) {
    wn_config_t cfg; ws_config(&cfg);
    wn_endpoint_t *client = NULL;
    ASSERT_EQ(wn_client_create(&cfg, &client), WN_OK);
    ASSERT_EQ(wn_endpoint_pending_used_for_test(client), 0);
    wn_event_t ev;

    /* Phase 1: closed port (dial refused). Synchronous refusal: no entry
     * may leak. */
    wn_address_t closed = addr("127.0.0.1", 34760);
    wn_peer_id_t peer = 0;
    wn_result_t r = wn_connect(client, &closed, &peer);
    if (r != WN_OK) {
        /* Synchronous refusal (e.g. immediate RST): no entry may leak. */
        ASSERT_EQ(wn_endpoint_pending_used_for_test(client), 0);
        wn_endpoint_destroy(client);
        return;
    }
    /* Async path: one entry in flight. */
    ASSERT_EQ(wn_endpoint_pending_used_for_test(client), 1);
    bool failed = wait_for_event(client, WN_EVENT_CONNECT_FAILED, &ev, 6000);
    /* Either CONNECT_FAILED (pending released via drop_peer_state) or a
     * 5s expiry (pending released via expire_pending): both must drain. */
    if (failed) {
        ASSERT_EQ(wn_endpoint_pending_used_for_test(client), 0);
    } else {
        /* No event yet: expiry hasn't fired; at most the one entry remains. */
        ASSERT_TRUE(wn_endpoint_pending_used_for_test(client) <= 1);
        /* Wait for the 5s pending timeout to reclaim it. */
        ASSERT_TRUE(wait_for_event(client, WN_EVENT_CONNECT_FAILED, &ev, 6000));
        ASSERT_EQ(wn_endpoint_pending_used_for_test(client), 0);
    }
    wn_endpoint_destroy(client);
}

/* R3 follow-up to the above: an accept-then-RST listener. The listener
 * accepts the TCP connection and immediately closes it with SO_LINGER
 * zero, so the client's poll cycle sees POLLOUT (or POLLERR) and
 * ws_client_finish_connect must fail through getsockopt/send -- the real
 * socket-path failure branch behind the pending-leak fix (the
 * release_pending_by_connid fallback in wn_connect, and
 * ws_link_drop_peer_state's release). Assert the pending entry drains
 * and a CONNECT_FAILED event is actually delivered. */
TEST(test_ws_rst_listener_leaks_nothing) {
    wn_config_t cfg; ws_config(&cfg);
    wn_endpoint_t *client = NULL;
    ASSERT_EQ(wn_client_create(&cfg, &client), WN_OK);
    ASSERT_EQ(wn_endpoint_pending_used_for_test(client), 0);

    int lst = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ASSERT_TRUE(lst >= 0);
    int one = 1;
    setsockopt(lst, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(34776);
    sa.sin_addr.s_addr = inet_addr("127.0.0.1");
    ASSERT_EQ(bind(lst, (struct sockaddr *)&sa, sizeof(sa)), 0);
    ASSERT_EQ(listen(lst, 4), 0);

    wn_address_t rst_addr = addr("127.0.0.1", 34776);
    wn_peer_id_t peer = 0;
    wn_result_t r = wn_connect(client, &rst_addr, &peer);
    ASSERT_EQ(r, WN_OK); /* dial-out is always synchronous-OK (async TCP) */
    ASSERT_EQ(wn_endpoint_pending_used_for_test(client), 1);

    /* Accept whatever lands and close with zero linger: RST to the
     * client. Accepts can lag the kernel handshake by a poll cycle. */
    for (long long t = 0; t < 3000; t += 20) {
        struct pollfd pf = { .fd = lst, .events = POLLIN, .revents = 0 };
        if (poll(&pf, 1, 20) > 0 && (pf.revents & POLLIN)) {
            struct sockaddr_storage peer_sa; socklen_t plen = sizeof(peer_sa);
            int c = accept(lst, (struct sockaddr *)&peer_sa, &plen);
            ASSERT_TRUE(c >= 0);
            struct linger lg = { .l_onoff = 1, .l_linger = 0 };
            setsockopt(c, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
            close(c);
            wn_event_t ev;
            bool failed = wait_for_event(client, WN_EVENT_CONNECT_FAILED, &ev, 6000);
            CHECK_TRUE(failed); /* surface the failure, not just expiry */
            ASSERT_EQ(wn_endpoint_pending_used_for_test(client), 0);
            close(lst);
            wn_endpoint_destroy(client);
            return; /* success */
        }
    }
    close(lst);
    wn_endpoint_destroy(client);
    WN_FAIL("%s", "listener never saw the dial-out connection");
}

/* M2 (the ws-link reap sweep in endpoint.c): raw TCP "peers" that land on
 * a WebSocket server port but never complete the HTTP upgrade previously
 * held their socket + decoder memory for as long as the TCP connection
 * lived (nothing else releases such links). After the fix the IO thread
 * closes any link that has not upgraded within WN_WS_CONNECT_TIMEOUT_MS
 * (10s). */
TEST(test_ws_reaps_pre_upgrade_links) {
    wn_config_t cfg; ws_config(&cfg);
    wn_endpoint_t *server = NULL;
    wn_address_t bind_addr = addr("127.0.0.1", 34975);
    ASSERT_EQ(wn_server_create(&bind_addr, &cfg, &server), WN_OK);
    ASSERT_TRUE(wn_endpoint_ws_links_used_for_test(server) == 0);

    /* Three raw TCP sockets that connect and then say nothing at all: no
     * HTTP request, no WebSocket frames, nothing to release them on the
     * old code. */
    int socks[3];
    for (int i = 0; i < 3; i++) {
        socks[i] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        ASSERT_TRUE(socks[i] >= 0);
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons(bind_addr.port);
        sa.sin_addr.s_addr = inet_addr("127.0.0.1");
        ASSERT_EQ(connect(socks[i], (struct sockaddr *)&sa, sizeof(sa)), 0);
    }

    /* Accepted links appear; nothing else may kick them off. */
    for (long long t = 0; t < 3000; t += 50) {
        if (wn_endpoint_ws_links_used_for_test(server) == 3) break;
        usleep(50 * 1000);
    }
    ASSERT_TRUE(wn_endpoint_ws_links_used_for_test(server) == 3);

    /* The reap sweep must close them past WN_WS_CONNECT_TIMEOUT_MS. */
    for (long long t = 0; t < 12000; t += 200) {
        if (wn_endpoint_ws_links_used_for_test(server) == 0) break;
        usleep(200 * 1000);
    }
    ASSERT_TRUE(wn_endpoint_ws_links_used_for_test(server) == 0);

    for (int i = 0; i < 3; i++) close(socks[i]);
    wn_endpoint_destroy(server);
}

/* The legitimate client dials the same server while the attacker is still
 * flooding. It must complete the TCP upgrade and the encrypted handshake
 * inside the two-second budget. */
typedef struct {
    wn_endpoint_t *client;
    wn_address_t addr;
    bool connected;
    uint64_t elapsed_ms;
} legit_ctx_t;

static void *legit_connect_thread(void *arg) {
    legit_ctx_t *c = (legit_ctx_t *)arg;
    wn_peer_id_t peer;
    uint64_t start = now_ms();
    wn_event_t ev;
    memset(&ev, 0, sizeof(ev));
    if (wn_connect(c->client, &c->addr, &peer) == WN_OK) {
        c->connected = wait_for_event(c->client, WN_EVENT_CONNECTED, &ev, 2000);
    }
    c->elapsed_ms = now_ms() - start;
    return NULL;
}

static void send_ping_batch_until(int fd, const uint8_t *batch, size_t len,
                                  size_t *off, uint64_t deadline) {
    while (now_ms() < deadline) {
        ssize_t n = send(fd, batch + *off, len - *off, MSG_NOSIGNAL);
        if (n > 0) {
            /* Resume a short write at the same byte, including across
             * phases. A corrupt ping stream could close the link for a
             * protocol error and give a false pass for the stall check. */
            *off = (*off + (size_t)n) % len;
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) return;
        struct pollfd p = { .fd = fd, .events = POLLOUT };
        poll(&p, 1, 10);
    }
}

/* A peer that sends pings and never reads used to stall the single I/O
 * thread inside sock_write_all (poll(POLLOUT) for up to a second, while
 * holding the connection and WebSocket link locks), so an unrelated
 * legitimate client could not complete its handshake. The fix queues
 * whole frames on a bounded per-link buffer and flushes them on POLLOUT,
 * so the I/O thread never waits on a stuck peer. */
TEST(test_ws_peer_ping_flood_does_not_block_other_clients) {
    uint16_t port = free_port();
    wn_config_t cfg; ws_config(&cfg);
    wn_endpoint_t *server = NULL;
    wn_address_t bind_addr = addr("127.0.0.1", port);
    ASSERT_EQ(wn_server_create(&bind_addr, &cfg, &server), WN_OK);

    /* Attacker: raw TCP client, complete just the HTTP upgrade, then flood
     * masked pings and never read the pongs. The tiny receive buffer makes
     * the server's send buffer fill after a few hundred pongs, and the
     * socket goes nonblocking below so a stalled server cannot wedge this
     * thread (the deadline still gets checked). */
    int atk = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ASSERT_TRUE(atk >= 0);
    int rcvbuf = 4096;
    int option_result = setsockopt(atk, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    ASSERT_EQ(option_result, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = inet_addr("127.0.0.1");
    ASSERT_EQ(connect(atk, (struct sockaddr *)&sa, sizeof(sa)), 0);

    char req[512];
    size_t req_len = 0;
    char key[25];
    ASSERT_TRUE(wn_ws_build_client_request("127.0.0.1", port, "/", req, sizeof(req),
                                            &req_len, key));
    ASSERT_TRUE(write_all(atk, (const uint8_t *)req, req_len));

    ASSERT_TRUE(read_upgrade(atk, key));
    ASSERT_EQ(wn_endpoint_ws_links_used_for_test(server), 1);

    int fl = fcntl(atk, F_GETFL, 0);
    ASSERT_TRUE(fl >= 0);
    ASSERT_EQ(fcntl(atk, F_SETFL, fl | O_NONBLOCK), 0);

    /* Warm the flood up first: the old code only wedges once the server's
     * send buffer for this link is full. Starting the legitimate client
     * afterwards means its two-second budget overlaps the stalled window
     * instead of racing the first few pings. */
    uint8_t payload[100];
    memset(payload, 0xAB, sizeof(payload));
    uint8_t frame[2 + 4 + sizeof(payload)];
    uint8_t batch[64 * sizeof(frame)];
    for (size_t i = 0; i < sizeof(batch); i += sizeof(frame)) {
        size_t n = wn_ws_encode(WN_WS_OPCODE_PING, payload, sizeof(payload), true,
                                batch + i, sizeof(frame));
        ASSERT_EQ(n, sizeof(frame));
    }
    size_t off = 0;
    send_ping_batch_until(atk, batch, sizeof(batch), &off, now_ms() + 1500);
    CHECK_EQ(wn_endpoint_ws_links_used_for_test(server), 1);

    /* Legitimate client starts now, while the flood is in progress. */
    legit_ctx_t legit;
    memset(&legit, 0, sizeof(legit));
    legit.addr = bind_addr;
    ASSERT_EQ(wn_client_create(&cfg, &legit.client), WN_OK);
    pthread_t tid;
    ASSERT_EQ(pthread_create(&tid, NULL, legit_connect_thread, &legit), 0);

    /* Keep flooding without reading. The write itself starts failing once
     * the attacker's own send buffer fills, which is fine: by then the
     * server's send buffer for this link is already full. The ping is
     * 100 bytes so the pong fits the server's existing control-frame
     * buffer: this test is about the write path, not control-frame
     * sizing (which has its own conformance tests). */
    send_ping_batch_until(atk, batch, sizeof(batch), &off, now_ms() + 5000);

    pthread_join(tid, NULL);

    /* The legitimate client must have completed, and quickly: the old
     * code leaves it starved while the I/O thread waits on the attacker. */
    CHECK_TRUE(legit.connected);
    CHECK_TRUE(legit.elapsed_ms < 2000);
    if (legit.connected) {
        wn_event_t ev;
        bool server_connected = wait_for_event(server, WN_EVENT_CONNECTED, &ev, 2000);
        CHECK_TRUE(server_connected);
        /* The raw peer is still open and has sent only valid frames.
         * Only the healthy link should remain after the write timeout. */
        CHECK_EQ(wn_endpoint_ws_links_used_for_test(server), 1);
        if (server_connected) {
            const uint8_t msg[] = { 1, 2, 3 };
            wn_result_t sent = wn_send(server, ev.peer, 0, WN_RELIABLE_ORDERED,
                                       msg, sizeof(msg));
            CHECK_EQ(sent, WN_OK);
            bool received = sent == WN_OK && wait_for_event(legit.client, WN_EVENT_DATA, &ev, 2000);
            CHECK_TRUE(received);
            if (received) {
                CHECK_EQ(ev.data_len, sizeof(msg));
                if (ev.data_len == sizeof(msg)) CHECK_MEM_EQ(ev.data, msg, sizeof(msg));
            }
        }
    }

    close(atk);
    wn_endpoint_destroy(legit.client);
    wn_endpoint_destroy(server);
}

int main(void) {
    printf("websocket integration tests\n");
    RUN_TEST(test_ws_upgrade_precedes_pipelined_pong_and_close_is_echoed);
    RUN_TEST(test_ws_connect_and_reliable_echo);
    RUN_TEST(test_ws_unreliable_delivery);
    RUN_TEST(test_ws_fragmented_large_message);
    RUN_TEST(test_ws_discovery_unsupported);
    RUN_TEST(test_ws_rejects_cleartext_config);
    RUN_TEST(test_ws_failed_connect_does_not_leak_pending);
    RUN_TEST(test_ws_rst_listener_leaks_nothing);
    RUN_TEST(test_ws_reaps_pre_upgrade_links);
    RUN_TEST(test_ws_peer_ping_flood_does_not_block_other_clients);
    TEST_SUMMARY();
}
