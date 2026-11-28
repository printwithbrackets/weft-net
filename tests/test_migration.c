#include "test_framework.h"
#include "../src/connection.h"
#include "../src/protocol.h"
#include "../src/byteorder.h"
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

/* Connection migration tests. Each side has an outbox instead of a socket:
 * sends are queued with their destination address, and a test delivers them
 * explicitly. A packet is only delivered when its destination equals the
 * receiving side's current address, so a packet sent to an old address after
 * the peer has moved is lost, the same as on a real network. The source
 * address passed to the receiver is the sender's address at delivery time. */

#define MAX_OUT 64
#define MAX_PKT 2048

typedef struct {
    uint8_t           pkt[MAX_PKT];
    size_t            len;
    struct sockaddr_storage dest;
    socklen_t         dest_len;
} outmsg_t;

typedef struct side {
    wn_connection_t  *conn;
    struct sockaddr_storage own; /* address this side currently sends from */
    socklen_t         own_len;
    outmsg_t          out[MAX_OUT];
    int               out_count;
    int               out_overflow;
    int               data_count;
    uint8_t           last_data[64];
    uint32_t          last_data_len;
    wn_conn_callbacks_t cb;
} side_t;

typedef struct {
    side_t client;
    side_t server;
    uint64_t now;
} pair_t;

static void addr4(struct sockaddr_storage *s, socklen_t *len, uint16_t port) {
    memset(s, 0, sizeof(*s));
    struct sockaddr_in *a = (struct sockaddr_in *)s;
    a->sin_family = AF_INET;
    a->sin_port = htons(port);
    a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    *len = sizeof(*a);
}

static bool addr_is(const struct sockaddr_storage *s, uint16_t port) {
    const struct sockaddr_in *a = (const struct sockaddr_in *)s;
    return a->sin_family == AF_INET && ntohs(a->sin_port) == port;
}

/* Callbacks run with the connection lock held, so they must not assert. */
static void queue_out(side_t *s, const uint8_t *packet, size_t len,
                      const struct sockaddr_storage *dest, socklen_t dest_len) {
    if (s->out_count >= MAX_OUT || len > MAX_PKT) {
        s->out_overflow++;
        return;
    }
    outmsg_t *m = &s->out[s->out_count++];
    memcpy(m->pkt, packet, len);
    m->len = len;
    memcpy(&m->dest, dest, dest_len);
    m->dest_len = dest_len;
}

static void cb_send_wire(void *ctx, wn_peer_id_t peer, const uint8_t *packet, size_t len) {
    (void)peer;
    side_t *s = (side_t *)ctx;
    queue_out(s, packet, len, &s->conn->addr, s->conn->addr_len);
}

static void cb_send_wire_to(void *ctx, wn_peer_id_t peer, const struct sockaddr_storage *addr,
                            socklen_t addr_len, const uint8_t *packet, size_t len) {
    (void)peer;
    side_t *s = (side_t *)ctx;
    queue_out(s, packet, len, addr, addr_len);
}

static bool cb_on_data(void *ctx, wn_peer_id_t peer, uint8_t channel, wn_delivery_t delivery,
                       const uint8_t *data, uint32_t len) {
    (void)peer; (void)channel; (void)delivery;
    side_t *s = (side_t *)ctx;
    s->data_count++;
    s->last_data_len = len < sizeof(s->last_data) ? len : (uint32_t)sizeof(s->last_data);
    memcpy(s->last_data, data, s->last_data_len);
    return true;
}

static void cb_on_disconnected(void *ctx, wn_peer_id_t peer, wn_result_t reason) {
    (void)ctx; (void)peer; (void)reason;
}

static bool cb_can_accept(void *ctx, uint32_t len) {
    (void)ctx; (void)len;
    return true;
}

static void side_init(side_t *s, wn_connection_t *conn, uint16_t port) {
    memset(s, 0, sizeof(*s));
    s->conn = conn;
    addr4(&s->own, &s->own_len, port);
    s->cb.on_data = cb_on_data;
    s->cb.on_disconnected = cb_on_disconnected;
    s->cb.send_wire = cb_send_wire;
    s->cb.send_wire_to = cb_send_wire_to;
    s->cb.can_accept = cb_can_accept;
    s->cb.on_connected = NULL;
    s->cb.ctx = s;
}

/* Client at 127.0.0.1:5001, server at 127.0.0.1:6000, both with migration
 * negotiated (the handshake sets this bit in production, so tests set it
 * directly). */
static void pair_init(pair_t *p) {
    memset(p, 0, sizeof(*p));
    uint8_t c2s_key[32], s2c_key[32];
    uint8_t c2s_salt[12] = {1}, s2c_salt[12] = {2};
    for (int i = 0; i < 32; i++) {
        c2s_key[i] = (uint8_t)(i + 1);
        s2c_key[i] = (uint8_t)(0xA0 + i);
    }

    struct sockaddr_storage a_client, a_server;
    socklen_t l_client, l_server;
    addr4(&a_client, &l_client, 5001);
    addr4(&a_server, &l_server, 6000);

    wn_connection_t *cc = wn_connection_create(1001, &a_server, l_server, true, 4,
                                               c2s_key, s2c_key, c2s_salt, s2c_salt,
                                               10000, 1000, 0);
    wn_connection_t *sc = wn_connection_create(1001, &a_client, l_client, false, 4,
                                               s2c_key, c2s_key, s2c_salt, c2s_salt,
                                               10000, 1000, 0);
    ASSERT_TRUE(cc != NULL);
    ASSERT_TRUE(sc != NULL);
    cc->capabilities = WN_CAP_DEFAULT;
    sc->capabilities = WN_CAP_DEFAULT;

    side_init(&p->client, cc, 5001);
    side_init(&p->server, sc, 6000);
    p->now = 1000;
}

static void pair_free(pair_t *p) {
    wn_connection_destroy(p->client.conn);
    wn_connection_destroy(p->server.conn);
}

/* Deliver one queued packet to `to` if it was addressed to `to`'s current
 * address. The source address is the sender's own address right now. */
static bool deliver_one(side_t *from, int idx, side_t *to, uint64_t now) {
    outmsg_t *m = &from->out[idx];
    if (m->dest_len != to->own_len || memcmp(&m->dest, &to->own, to->own_len) != 0) {
        return false;
    }
    wn_connection_on_packet_from(to->conn, m->pkt[0], m->pkt + 1, m->len - 1, now, &to->cb,
                                 &from->own, from->own_len);
    return true;
}

/* Deliver everything `from` queued to `to`, then clear the outbox. */
static int pump(side_t *from, side_t *to, uint64_t now) {
    int delivered = 0;
    int n = from->out_count;
    for (int i = 0; i < n; i++) {
        if (deliver_one(from, i, to, now)) delivered++;
    }
    from->out_count = 0;
    return delivered;
}

/* Deliver in both directions until nothing more moves. */
static void settle(pair_t *p) {
    for (int i = 0; i < 20; i++) {
        int a = pump(&p->client, &p->server, p->now);
        int b = pump(&p->server, &p->client, p->now);
        if (a == 0 && b == 0) break;
    }
}

/* Index of the first queued packet of `type` addressed to `port`, or -1. */
static int find_out(side_t *s, uint8_t type, uint16_t port) {
    for (int i = 0; i < s->out_count; i++) {
        if (s->out[i].pkt[0] == type && addr_is(&s->out[i].dest, port)) return i;
    }
    return -1;
}

static void send_data(pair_t *p, side_t *from, const char *text) {
    wn_result_t r = wn_connection_send(from->conn, 0, WN_RELIABLE_ORDERED,
                                       (const uint8_t *)text, strlen(text), 0, p->now,
                                       &from->cb);
    ASSERT_EQ(r, WN_OK);
}

/* Client sends one message from its original address, then moves to port
 * 5002 (a NAT rebinding, for example) and sends again. The server sees an
 * authenticated packet from the new address. */
static void client_moves_and_sends(pair_t *p) {
    send_data(p, &p->client, "before move");
    settle(p);
    addr4(&p->client.own, &p->client.own_len, 5002);
    send_data(p, &p->client, "after move");
    pump(&p->client, &p->server, p->now);
}

static void addr6_scoped(struct sockaddr_storage *s, socklen_t *len, uint16_t port, uint32_t scope) {
    memset(s, 0, sizeof(*s));
    struct sockaddr_in6 *a = (struct sockaddr_in6 *)s;
    a->sin6_family = AF_INET6;
    a->sin6_port = htons(port);
    a->sin6_addr.s6_addr[0] = 0xfe;
    a->sin6_addr.s6_addr[1] = 0x80;
    a->sin6_addr.s6_addr[15] = 1;
    a->sin6_scope_id = scope;
    *len = sizeof(*a);
}

TEST(test_migration_capability_is_on_by_default) {
    ASSERT_EQ(WN_CAP_MIGRATION, 0x00000008u);
    ASSERT_TRUE((WN_CAP_DEFAULT & WN_CAP_MIGRATION) != 0);
}

TEST(test_authentic_packet_from_new_address_is_delivered_and_challenged) {
    pair_t p;
    pair_init(&p);

    client_moves_and_sends(&p);

    /* The authenticated data is still delivered. */
    ASSERT_EQ(p.server.data_count, 2);
    /* Sends are not redirected until the new address proves it can receive. */
    ASSERT_TRUE(addr_is(&p.server.conn->addr, 5001));
    ASSERT_TRUE(p.server.conn->path_pending);
    ASSERT_TRUE(addr_is(&p.server.conn->path_addr, 5002));
    /* The challenge goes to the new address. */
    ASSERT_TRUE(find_out(&p.server, WN_PKT_PATH_CHALLENGE, 5002) >= 0);
    pair_free(&p);
}

TEST(test_path_response_moves_connection_and_later_sends_follow) {
    pair_t p;
    pair_init(&p);

    client_moves_and_sends(&p);
    settle(&p);

    ASSERT_TRUE(addr_is(&p.server.conn->addr, 5002));
    ASSERT_FALSE(p.server.conn->path_pending);

    /* Server-to-client data now goes to the new address and arrives there. */
    send_data(&p, &p.server, "reply on new path");
    settle(&p);
    ASSERT_EQ(p.client.data_count, 1);
    ASSERT_MEM_EQ(p.client.last_data, "reply on new path", p.client.last_data_len);
    pair_free(&p);
}

TEST(test_data_keeps_going_to_old_address_during_validation) {
    pair_t p;
    pair_init(&p);

    client_moves_and_sends(&p);
    /* Server still has an unvalidated new path. Its data must go to the old
     * address, not the one that has not yet been validated. */
    send_data(&p, &p.server, "mid validation");
    ASSERT_TRUE(find_out(&p.server, WN_PKT_DATA, 5001) >= 0);
    ASSERT_TRUE(find_out(&p.server, WN_PKT_DATA, 5002) < 0);
    pair_free(&p);
}

TEST(test_path_response_with_wrong_token_is_ignored) {
    pair_t p;
    pair_init(&p);

    client_moves_and_sends(&p);
    /* Corrupt the server's stored token so the client's (authentic) response
     * no longer matches. */
    p.server.conn->path_token[0] ^= 0x01;
    settle(&p);

    ASSERT_TRUE(addr_is(&p.server.conn->addr, 5001));
    ASSERT_TRUE(p.server.conn->path_pending);
    pair_free(&p);
}

TEST(test_path_response_from_unexpected_address_is_ignored) {
    pair_t p;
    pair_init(&p);

    client_moves_and_sends(&p);
    /* The server sends its challenge to 5002. Deliver it, then move the
     * client to 5003 before its response goes out. The response comes from
     * an address the server never challenged. */
    pump(&p.server, &p.client, p.now);
    addr4(&p.client.own, &p.client.own_len, 5003);
    pump(&p.client, &p.server, p.now);

    ASSERT_TRUE(addr_is(&p.server.conn->addr, 5001));
    ASSERT_TRUE(p.server.conn->path_pending);
    ASSERT_TRUE(addr_is(&p.server.conn->path_addr, 5002));
    pair_free(&p);
}

TEST(test_unauthenticated_packet_from_new_address_triggers_nothing) {
    pair_t p;
    pair_init(&p);

    send_data(&p, &p.client, "tampered");
    ASSERT_EQ(p.client.out_count, 1);
    /* Flip one bit of the GCM tag so the packet fails authentication. */
    p.client.out[0].pkt[p.client.out[0].len - 1] ^= 0x01;
    addr4(&p.client.own, &p.client.own_len, 5002);
    pump(&p.client, &p.server, p.now);

    ASSERT_EQ(p.server.data_count, 0);
    ASSERT_FALSE(p.server.conn->path_pending);
    ASSERT_TRUE(find_out(&p.server, WN_PKT_PATH_CHALLENGE, 5002) < 0);
    pair_free(&p);
}

TEST(test_migration_disabled_when_capability_not_negotiated) {
    pair_t p;
    pair_init(&p);
    p.server.conn->capabilities &= ~WN_CAP_MIGRATION;

    client_moves_and_sends(&p);
    settle(&p);

    ASSERT_TRUE(addr_is(&p.server.conn->addr, 5001));
    ASSERT_FALSE(p.server.conn->path_pending);
    ASSERT_TRUE(find_out(&p.server, WN_PKT_PATH_CHALLENGE, 5002) < 0);
    pair_free(&p);
}

TEST(test_packets_without_udp_source_cannot_migrate) {
    pair_t p;
    pair_init(&p);

    send_data(&p, &p.client, "data without a UDP source");
    ASSERT_EQ(p.client.out_count, 1);
    const outmsg_t *data = &p.client.out[0];
    ASSERT_EQ(wn_connection_on_packet(p.server.conn, data->pkt[0], data->pkt + 1,
                                     data->len - 1, p.now, &p.server.cb), WN_OK);
    p.client.out_count = 0;
    ASSERT_EQ(p.server.data_count, 1);
    ASSERT_FALSE(p.server.conn->path_pending);

    client_moves_and_sends(&p);
    pump(&p.server, &p.client, p.now);
    int idx = find_out(&p.client, WN_PKT_PATH_RESPONSE, 6000);
    ASSERT_TRUE(idx >= 0);
    const outmsg_t *response = &p.client.out[idx];
    ASSERT_EQ(wn_connection_on_packet(p.server.conn, response->pkt[0], response->pkt + 1,
                                     response->len - 1, p.now, &p.server.cb),
              WN_ERR_PROTOCOL_MISMATCH);
    ASSERT_TRUE(p.server.conn->path_pending);
    ASSERT_TRUE(addr_is(&p.server.conn->addr, 5001));
    pair_free(&p);
}

TEST(test_challenge_is_rejected_without_negotiated_migration) {
    pair_t p;
    pair_init(&p);
    client_moves_and_sends(&p);

    int idx = find_out(&p.server, WN_PKT_PATH_CHALLENGE, 5002);
    ASSERT_TRUE(idx >= 0);
    const outmsg_t *challenge = &p.server.out[idx];
    p.client.conn->capabilities &= ~WN_CAP_MIGRATION;
    ASSERT_EQ(wn_connection_on_packet_from(p.client.conn, challenge->pkt[0], challenge->pkt + 1,
                                          challenge->len - 1, p.now, &p.client.cb,
                                          &p.server.own, p.server.own_len),
              WN_ERR_PROTOCOL_MISMATCH);
    ASSERT_EQ(p.client.out_count, 0);
    ASSERT_FALSE(p.client.conn->path_pending);
    pair_free(&p);
}

TEST(test_lost_challenge_can_be_retried_and_validate_the_path) {
    pair_t p;
    pair_init(&p);
    client_moves_and_sends(&p);
    ASSERT_TRUE(find_out(&p.server, WN_PKT_PATH_CHALLENGE, 5002) >= 0);
    p.server.out_count = 0; /* Drop the first challenge. */

    wn_connection_tick(p.server.conn, p.now + 499, &p.server.cb);
    ASSERT_TRUE(find_out(&p.server, WN_PKT_PATH_CHALLENGE, 5002) < 0);
    p.now += 500;
    wn_connection_tick(p.server.conn, p.now, &p.server.cb);
    ASSERT_TRUE(find_out(&p.server, WN_PKT_PATH_CHALLENGE, 5002) >= 0);
    ASSERT_TRUE(addr_is(&p.server.conn->addr, 5001));

    settle(&p);
    ASSERT_FALSE(p.server.conn->path_pending);
    ASSERT_TRUE(addr_is(&p.server.conn->addr, 5002));
    pair_free(&p);
}

TEST(test_ipv6_address_change_without_port_change_validates) {
    pair_t p;
    pair_init(&p);

    /* Give the client an IPv6 source address known to the server, then change
     * only the IP. The simulated link does not need IPv6 socket support. */
    struct sockaddr_in6 *client_addr = (struct sockaddr_in6 *)&p.client.own;
    memset(&p.client.own, 0, sizeof(p.client.own));
    client_addr->sin6_family = AF_INET6;
    client_addr->sin6_port = htons(5001);
    ASSERT_EQ(inet_pton(AF_INET6, "2001:db8::1", &client_addr->sin6_addr), 1);
    p.client.own_len = sizeof(*client_addr);
    p.server.conn->addr = p.client.own;
    p.server.conn->addr_len = p.client.own_len;

    send_data(&p, &p.client, "original IPv6 address");
    settle(&p);
    ASSERT_FALSE(p.server.conn->path_pending);

    ASSERT_EQ(inet_pton(AF_INET6, "2001:db8::2", &client_addr->sin6_addr), 1);
    send_data(&p, &p.client, "new IPv6 address");
    ASSERT_EQ(pump(&p.client, &p.server, p.now), 1);
    ASSERT_TRUE(p.server.conn->path_pending);
    settle(&p);
    ASSERT_FALSE(p.server.conn->path_pending);

    const char reply[] = "reply to new IPv6 address";
    send_data(&p, &p.server, reply);
    settle(&p);
    ASSERT_EQ(p.client.data_count, 1);
    ASSERT_EQ(p.client.last_data_len, sizeof(reply) - 1);
    ASSERT_MEM_EQ(p.client.last_data, reply, sizeof(reply) - 1);
    pair_free(&p);
}

static size_t bytes_to_port(const side_t *side, uint16_t port) {
    size_t total = 0;
    for (int i = 0; i < side->out_count; i++) {
        if (addr_is(&side->out[i].dest, port)) total += side->out[i].len;
    }
    return total;
}

TEST(test_amplification_budget_limits_bytes_to_unvalidated_address) {
    pair_t p;
    pair_init(&p);

    addr4(&p.client.own, &p.client.own_len, 5002);
    send_data(&p, &p.client, "probe trigger");
    ASSERT_EQ(p.client.out_count, 1);
    size_t received = p.client.out[0].len;
    ASSERT_EQ(pump(&p.client, &p.server, p.now), 1);
    size_t sent = bytes_to_port(&p.server, 5002);
    ASSERT_TRUE(sent > 0);
    p.server.out_count = 0;

    /* The client never answers. Keep ticking the server for longer than the
     * retransmit interval, discarding everything it sends. */
    for (int i = 0; i < 40; i++) {
        p.now += 100;
        wn_connection_tick(p.server.conn, p.now, &p.server.cb);
        sent += bytes_to_port(&p.server, 5002);
        p.server.out_count = 0;
    }

    ASSERT_TRUE(p.server.conn->path_pending);
    ASSERT_TRUE(sent <= 3 * received);
    ASSERT_EQ(p.server.out_overflow, 0);

    /* Fresh traffic on the candidate path gives the server room to retry. */
    send_data(&p, &p.client, "fresh traffic");
    ASSERT_EQ(p.client.out_count, 1);
    received += p.client.out[0].len;
    ASSERT_EQ(pump(&p.client, &p.server, p.now), 1);
    ASSERT_TRUE(find_out(&p.server, WN_PKT_PATH_CHALLENGE, 5002) >= 0);
    ASSERT_TRUE(sent + bytes_to_port(&p.server, 5002) <= 3 * received);
    pair_free(&p);
}

TEST(test_response_arriving_after_validation_timeout_cannot_move_connection) {
    pair_t p;
    pair_init(&p);

    client_moves_and_sends(&p);
    pump(&p.server, &p.client, p.now); /* Hold the genuine response in flight. */
    int idx = find_out(&p.client, WN_PKT_PATH_RESPONSE, 6000);
    ASSERT_TRUE(idx >= 0);
    const outmsg_t *response = &p.client.out[idx];

    wn_connection_tick(p.server.conn, p.now + 4999, &p.server.cb);
    ASSERT_TRUE(p.server.conn->path_pending);
    p.now += 5000;
    wn_connection_tick(p.server.conn, p.now, &p.server.cb);
    ASSERT_FALSE(p.server.conn->path_pending);

    ASSERT_EQ(wn_connection_on_packet_from(p.server.conn, response->pkt[0], response->pkt + 1,
                                          response->len - 1, p.now, &p.server.cb,
                                          &p.client.own, p.client.own_len), WN_OK);
    ASSERT_FALSE(p.server.conn->path_pending);
    ASSERT_TRUE(addr_is(&p.server.conn->addr, 5001));
    pair_free(&p);
}

TEST(test_reliable_messages_arrive_in_order_across_migration) {
    pair_t p;
    pair_init(&p);

    send_data(&p, &p.client, "one");
    settle(&p);
    addr4(&p.client.own, &p.client.own_len, 5002);
    send_data(&p, &p.client, "two");
    send_data(&p, &p.client, "three");
    settle(&p);

    ASSERT_EQ(p.server.data_count, 3);
    ASSERT_TRUE(addr_is(&p.server.conn->addr, 5002));
    ASSERT_MEM_EQ(p.server.last_data, "three", p.server.last_data_len);
    pair_free(&p);
}

/* Regression: the same link-local address on a different interface (scope)
 * is a different path and must start validation. */
TEST(test_same_address_different_ipv6_scope_starts_validation) {
    pair_t p;
    pair_init(&p);
    addr6_scoped(&p.client.own, &p.client.own_len, 5001, 2);
    p.server.conn->addr = p.client.own;
    p.server.conn->addr_len = p.client.own_len;

    send_data(&p, &p.client, "scope two");
    pump(&p.client, &p.server, p.now);
    ASSERT_FALSE(p.server.conn->path_pending);

    addr6_scoped(&p.client.own, &p.client.own_len, 5001, 3);
    send_data(&p, &p.client, "scope three");
    pump(&p.client, &p.server, p.now);
    ASSERT_TRUE(p.server.conn->path_pending);
    pair_free(&p);
}

/* Regression: an authenticated challenge on a side without send_wire_to
 * must not call a NULL function pointer. */
TEST(test_challenge_without_send_wire_to_is_ignored) {
    pair_t p;
    pair_init(&p);
    p.server.cb.send_wire_to = NULL;

    p.client.conn->path_pending = true;
    p.client.conn->path_addr = p.server.own;
    p.client.conn->path_addr_len = p.server.own_len;
    p.client.conn->path_started_ms = p.now;
    p.client.conn->path_next_challenge_ms = 0;
    p.client.conn->path_bytes_received = 1000;
    wn_connection_tick(p.client.conn, p.now, &p.client.cb);
    ASSERT_TRUE(find_out(&p.client, WN_PKT_PATH_CHALLENGE, 6000) >= 0);

    pump(&p.client, &p.server, p.now);
    ASSERT_EQ(find_out(&p.server, WN_PKT_PATH_RESPONSE, 5001), -1);
    ASSERT_TRUE(addr_is(&p.server.conn->addr, 5001));
    pair_free(&p);
}

/* Regression: a response arriving after the validation deadline must not
 * commit the move, even if the periodic tick has not yet cleared the state. */
TEST(test_response_after_validation_deadline_does_not_commit) {
    pair_t p;
    pair_init(&p);
    client_moves_and_sends(&p);
    pump(&p.server, &p.client, p.now); /* client receives the challenge and queues its response */
    p.now += 5000;                     /* deadline is WN_PATH_TIMEOUT_MS, 5000 ms */
    pump(&p.client, &p.server, p.now); /* the response arrives after the deadline */

    ASSERT_TRUE(addr_is(&p.server.conn->addr, 5001));
    pair_free(&p);
}

int main(void) {
    printf("=== migration tests ===\n");
    RUN_TEST(test_migration_capability_is_on_by_default);
    RUN_TEST(test_authentic_packet_from_new_address_is_delivered_and_challenged);
    RUN_TEST(test_path_response_moves_connection_and_later_sends_follow);
    RUN_TEST(test_data_keeps_going_to_old_address_during_validation);
    RUN_TEST(test_path_response_with_wrong_token_is_ignored);
    RUN_TEST(test_path_response_from_unexpected_address_is_ignored);
    RUN_TEST(test_unauthenticated_packet_from_new_address_triggers_nothing);
    RUN_TEST(test_migration_disabled_when_capability_not_negotiated);
    RUN_TEST(test_packets_without_udp_source_cannot_migrate);
    RUN_TEST(test_challenge_is_rejected_without_negotiated_migration);
    RUN_TEST(test_lost_challenge_can_be_retried_and_validate_the_path);
    RUN_TEST(test_ipv6_address_change_without_port_change_validates);
    RUN_TEST(test_amplification_budget_limits_bytes_to_unvalidated_address);
    RUN_TEST(test_response_arriving_after_validation_timeout_cannot_move_connection);
    RUN_TEST(test_reliable_messages_arrive_in_order_across_migration);
    RUN_TEST(test_same_address_different_ipv6_scope_starts_validation);
    RUN_TEST(test_challenge_without_send_wire_to_is_ignored);
    RUN_TEST(test_response_after_validation_deadline_does_not_commit);
    TEST_SUMMARY();
    return 0;
}
