/* Connection migration over real UDP sockets.
 *
 * The client talks to a relay on loopback, and the relay talks to the
 * server. Partway through the session the relay closes its upstream socket
 * and opens a new one on a different port, the way a NAT rebinding does. The
 * server then sees the client at a new source address. Packets still sent to
 * the old port are lost, as they would be on a real network. */
#include "../test_framework.h"
#include "../../include/weft_net.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>

typedef struct {
    int front;                 /* client talks to this socket */
    int up;                    /* socket toward the server; replaced on rebind */
    struct sockaddr_in server;
    struct sockaddr_in client; /* learned from the client's first packet */
    bool have_client;
    uint16_t front_port;
    uint16_t up_port;
    atomic_int rebind_req;
    atomic_int rebound;
    atomic_int stop;
} relay_t;

static int open_loopback_udp(uint16_t *out_port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0) { close(fd); return -1; }
    socklen_t len = sizeof(a);
    getsockname(fd, (struct sockaddr *)&a, &len);
    *out_port = ntohs(a.sin_port);
    return fd;
}

static void *relay_thread(void *arg) {
    relay_t *r = (relay_t *)arg;
    uint8_t buf[2048];
    while (!atomic_load(&r->stop)) {
        if (atomic_exchange(&r->rebind_req, 0)) {
            /* Bind the replacement while the old socket is still open, so the
             * kernel cannot hand back the same port. */
            uint16_t new_port = 0;
            int fresh = open_loopback_udp(&new_port);
            if (fresh >= 0) {
                close(r->up);
                r->up = fresh;
                r->up_port = new_port;
                atomic_store(&r->rebound, 1);
            }
        }
        struct pollfd fds[2];
        fds[0].fd = r->front; fds[0].events = POLLIN; fds[0].revents = 0;
        fds[1].fd = r->up;    fds[1].events = POLLIN; fds[1].revents = 0;
        if (poll(fds, 2, 10) <= 0) continue;

        if (fds[0].revents & POLLIN) {
            struct sockaddr_in from;
            socklen_t flen = sizeof(from);
            ssize_t n = recvfrom(r->front, buf, sizeof(buf), 0, (struct sockaddr *)&from, &flen);
            if (n > 0) {
                r->client = from;
                r->have_client = true;
                sendto(r->up, buf, (size_t)n, 0, (struct sockaddr *)&r->server, sizeof(r->server));
            }
        }
        if (fds[1].revents & POLLIN) {
            struct sockaddr_in from;
            socklen_t flen = sizeof(from);
            ssize_t n = recvfrom(r->up, buf, sizeof(buf), 0, (struct sockaddr *)&from, &flen);
            if (n > 0 && r->have_client) {
                sendto(r->front, buf, (size_t)n, 0, (struct sockaddr *)&r->client, sizeof(r->client));
            }
        }
    }
    return NULL;
}

static bool relay_start(relay_t *r, uint16_t server_port, pthread_t *tid) {
    memset(r, 0, sizeof(*r));
    r->front = open_loopback_udp(&r->front_port);
    r->up = open_loopback_udp(&r->up_port);
    if (r->front < 0 || r->up < 0) return false;
    r->server.sin_family = AF_INET;
    r->server.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    r->server.sin_port = htons(server_port);
    return pthread_create(tid, NULL, relay_thread, r) == 0;
}

static void relay_stop(relay_t *r, pthread_t tid) {
    atomic_store(&r->stop, 1);
    pthread_join(tid, NULL);
    close(r->front);
    close(r->up);
}

static wn_address_t make_addr(const char *host, uint16_t port) {
    wn_address_t a;
    memset(&a, 0, sizeof(a));
    strncpy(a.host, host, sizeof(a.host) - 1);
    a.port = port;
    a.family = WN_AF_UNSPEC;
    return a;
}

static bool wait_for_event(wn_endpoint_t *ep, wn_event_type_t type, wn_event_t *out, int timeout_ms) {
    uint64_t iterations = (uint64_t)timeout_ms / 50 + 1;
    for (uint64_t i = 0; i < iterations; i++) {
        if (wn_poll_event(ep, out, 50) && out->event_type == type) return true;
    }
    return false;
}

/* Connect a client through a relay, rebind the relay, and check whether the
 * server's reply still reaches the client. Returns true if it did. */
static bool run_rebind_scenario(uint16_t server_port, bool server_migrates) {
    wn_config_t server_cfg, client_cfg;
    wn_config_default(&server_cfg);
    wn_config_default(&client_cfg);
    if (!server_migrates) server_cfg.capabilities &= ~WN_CAP_MIGRATION;

    wn_endpoint_t *server = NULL, *client = NULL;
    wn_address_t bind_addr = make_addr("127.0.0.1", server_port);
    ASSERT_EQ(wn_server_create(&bind_addr, &server_cfg, &server), WN_OK);

    relay_t relay;
    pthread_t tid;
    ASSERT_TRUE(relay_start(&relay, server_port, &tid));

    ASSERT_EQ(wn_client_create(&client_cfg, &client), WN_OK);
    wn_address_t relay_addr = make_addr("127.0.0.1", relay.front_port);
    wn_peer_id_t client_peer;
    ASSERT_EQ(wn_connect(client, &relay_addr, &client_peer), WN_OK);

    wn_event_t ev;
    ASSERT_TRUE(wait_for_event(client, WN_EVENT_CONNECTED, &ev, 3000));
    ASSERT_TRUE(wait_for_event(server, WN_EVENT_CONNECTED, &ev, 3000));
    wn_peer_id_t server_peer = ev.peer;

    const char *before = "before rebind";
    ASSERT_EQ(wn_send(client, client_peer, 0, WN_RELIABLE_ORDERED,
                      (const uint8_t *)before, strlen(before)), WN_OK);
    ASSERT_TRUE(wait_for_event(server, WN_EVENT_DATA, &ev, 3000));
    ASSERT_MEM_EQ(ev.data, before, strlen(before));

    /* Rebind: the server now sees the client from a new port. */
    atomic_store(&relay.rebind_req, 1);
    for (int i = 0; i < 300 && !atomic_load(&relay.rebound); i++) usleep(10000);
    ASSERT_TRUE(atomic_load(&relay.rebound));

    const char *after = "after rebind";
    ASSERT_EQ(wn_send(client, client_peer, 0, WN_RELIABLE_ORDERED,
                      (const uint8_t *)after, strlen(after)), WN_OK);
    ASSERT_TRUE(wait_for_event(server, WN_EVENT_DATA, &ev, 3000));
    ASSERT_MEM_EQ(ev.data, after, strlen(after));

    /* Server-to-client traffic. With migration it must reach the client on
     * the new port; without it, it keeps going to the lost old port. */
    const char *reply = "reply after rebind";
    ASSERT_EQ(wn_send(server, server_peer, 0, WN_RELIABLE_ORDERED,
                      (const uint8_t *)reply, strlen(reply)), WN_OK);
    bool got_reply = wait_for_event(client, WN_EVENT_DATA, &ev, 3000);
    if (got_reply) ASSERT_MEM_EQ(ev.data, reply, strlen(reply));

    relay_stop(&relay, tid);
    wn_endpoint_destroy(client);
    wn_endpoint_destroy(server);
    return got_reply;
}

TEST(test_server_reply_reaches_rebound_client_when_migration_on) {
    ASSERT_TRUE(run_rebind_scenario(34761, true));
}

TEST(test_server_reply_lost_after_rebind_when_migration_off) {
    /* Opt-out check: with migration disabled on the server, the connection
     * keeps sending to the old address, so the reply never arrives. */
    ASSERT_FALSE(run_rebind_scenario(34762, false));
}

int main(void) {
    printf("=== migration integration tests ===\n");
    RUN_TEST(test_server_reply_reaches_rebound_client_when_migration_on);
    RUN_TEST(test_server_reply_lost_after_rebind_when_migration_off);
    TEST_SUMMARY();
    return 0;
}
