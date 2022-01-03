#include "utp-react-native.h"
#include "utp.h"
#include "uv.h"
#include <stdlib.h>
#include <string.h>
#include <jsi/jsi.h>

using namespace facebook::jsi;
using namespace std;

typedef struct {
    unsigned char * data;
    size_t byteLength;
} Uint8Array_t;

Uint8Array_t get_buffer(Runtime &runtime, const Value &arg, string name) {
    string msg = "Argument \"" + name + "\" must be of type Uint8Array";
    if (!arg.isObject()) {
        throw JSError(runtime, msg);
    }
    auto obj = arg.getObject(runtime);
    if (!obj.hasProperty(runtime, "buffer")) {
        throw JSError(runtime, msg);
    }
    auto buf = obj.getPropertyAsObject(runtime, "buffer");
    if (!buf.isArrayBuffer(runtime)) {
        throw JSError(runtime, msg);
    }
    auto arr = buf.getArrayBuffer(runtime);
    auto byteLength = obj.getProperty(runtime, "byteLength");
    auto byteOffset = obj.getProperty(runtime, "byteOffset");
    if (!byteLength.isNumber() || !byteOffset.isNumber()) {
        throw JSError(runtime, msg);
    }
    Uint8Array_t arr8;
    arr8.data = arr.data(runtime) + (size_t) byteOffset.getNumber();
    arr8.byteLength = (size_t) byteLength.getNumber();
    return arr8;
}

Function get_function(Runtime &runtime, const Value &arg, string name) {
    string msg = "Argument \"" + name + "\" must be of type Function";
    if (!arg.isObject()) {
        throw JSError(runtime, msg);
    }
    auto obj = arg.getObject(runtime);
    if (!obj.isFunction(runtime)) {
        throw JSError(runtime, msg);
    }
    return obj.getFunction(runtime);
}

namespace utp_react_native {

#define UTP_RN_TIMEOUT_INTERVAL 20

typedef struct {
    uint32_t min_recv_packet_size;
    uint32_t recv_packet_size;

    struct utp_iovec send_buffer[256];
    struct utp_iovec *send_buffer_next;
    uint32_t send_buffer_missing;

    utp_socket *socket;
    Runtime *runtime;
    Object ctx;
    uv_buf_t buf;
    Function on_read;
    Function on_drain;
    Function on_end;
    Function on_error;
    Function on_close;
    Function on_connect;
    Function realloc;
} utp_rn_connection_t;

typedef struct {
    uv_udp_t handle;
    utp_context *utp;
    uint32_t accept_connections;
    utp_rn_connection_t *next_connection;
    uv_timer_t timer;
    Runtime *runtime;
    Object ctx;
    uv_buf_t buf;
    Function on_message;
    Function on_send;
    Function on_connection;
    Function on_close;
    Function realloc;
    int pending_close;
    int closing;
} utp_rn_t;

typedef struct {
    uv_udp_send_t req;
    Object ctx;
} utp_rn_send_request_t;

typedef struct {
    Runtime *runtime;
    Function cb;
    uv_getaddrinfo_t *req;
} utp_rn_dns_request_t;

inline static void utp_rn_parse_address(struct sockaddr *name, char *ip, int *port) {
    struct sockaddr_in *name_in = (struct sockaddr_in *) name;
    *port = ntohs(name_in->sin_port);
    uv_ip4_name(name_in, ip, 17);
}

static int utp_rn_connection_drain(utp_rn_connection_t *self) {
    struct utp_iovec *next = self->send_buffer_next;
    uint32_t missing = self->send_buffer_missing;

    if (!missing) return 1;

    int sent_bytes = utp_writev(self->socket, next, missing);
    if (sent_bytes < 0) {
        self->on_error.callWithThis(*self->runtime, self->ctx, sent_bytes);
        return 0;
    }

    size_t bytes = sent_bytes;

    while (bytes > 0) {
        if (next->iov_len <= bytes) {
            bytes -= next->iov_len;
            next++;
            missing--;
        } else {
            next->iov_len -= bytes;
            next->iov_base = ((char *) next->iov_base) + bytes;
            break;
        }
    }

    self->send_buffer_missing = missing;
    self->send_buffer_next = next;

    return missing ? 0 : 1;
}

inline static void utp_rn_connection_destroy(utp_rn_connection_t *self) {
    self->on_close.callWithThis(*self->runtime, self->ctx);

    self->buf.base = NULL;
    self->buf.len = 0;
}

static void on_sendto_free(uv_udp_send_t *req, int status) {
    free(req);
}

static void on_uv_close(uv_handle_t *handle) {
    utp_rn_t *self = (utp_rn_t *) handle->data;

    self->pending_close--;
    if (self->pending_close > 0) return;

    self->on_close.callWithThis(*self->runtime, self->ctx);
}

static void on_uv_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    utp_rn_t *self = (utp_rn_t *) handle->data;
    *buf = self->buf;
}

static void on_uv_read(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags) {
    utp_rn_t *self = (utp_rn_t *) handle->data;

    utp_check_timeouts(self->utp);
    if (self->closing) return;

    if (nread == 0) {
        utp_issue_deferred_acks(self->utp);
        return;
    }

    if (nread > 0) {
        const unsigned char *base = (const unsigned char *) buf->base;
        if (utp_process_udp(self->utp, base, nread, addr, sizeof(struct sockaddr))) return;
    }

    int port;
    char ip[17];
    utp_rn_parse_address((struct sockaddr *) addr, ip, &port);

    auto ret = self->on_message.callWithThis(*self->runtime, self->ctx, (int) nread, port, String::createFromUtf8(*self->runtime, ip));
    Uint8Array_t rbuf = get_buffer(*self->runtime, ret, "on_message ret");
    if (rbuf.byteLength == 0) {
        size_t size = nread <= 0 ? 0 : nread;
        self->buf.base += size;
        self->buf.len -= size;
    } else {
        self->buf.base = (char *) rbuf.data;
        self->buf.len = rbuf.byteLength;
    }
}

static void on_uv_send(uv_udp_send_t *req, int status) {
    uv_udp_t *handle = req->handle;
    utp_rn_t *self = (utp_rn_t *) handle->data;
    utp_rn_send_request_t *send = (utp_rn_send_request_t *) req->data;

    self->on_send.callWithThis(*self->runtime, self->ctx, send->ctx, status);
}

static uint64 on_utp_state_change(utp_callback_arguments *a) {
    utp_rn_connection_t *self = (utp_rn_connection_t *) utp_get_userdata(a->socket);
    self->runtime->global().getPropertyAsObject(*self->runtime, "console").getPropertyAsFunction(*self->runtime, "log").call(*self->runtime, String::createFromUtf8(*self->runtime, "STATE"), a->state);

    switch (a->state) {
        case UTP_STATE_CONNECT: {
            self->on_connect.callWithThis(*self->runtime, self->ctx);
            break;
        }

        case UTP_STATE_WRITABLE: {
            if (utp_rn_connection_drain(self)) {
                self->on_drain.callWithThis(*self->runtime, self->ctx);
            }
            break;
        }

        case UTP_STATE_EOF: {
            if (self->recv_packet_size) {
                auto ret = self->on_read.callWithThis(*self->runtime, self->ctx, (int) self->recv_packet_size);
                Uint8Array_t buf = get_buffer(*self->runtime, ret, "on_read ret");
                if (buf.byteLength == 0) {
                    size_t size = self->recv_packet_size <= 0 ? 0 : self->recv_packet_size;
                    self->buf.base += size;
                    self->buf.len -= size;
                } else {
                    self->buf.base = (char *) buf.data;
                    self->buf.len = buf.byteLength;
                }
                self->recv_packet_size = 0;
            }
            self->on_end.callWithThis(*self->runtime, self->ctx);
            break;
        }

        case UTP_STATE_DESTROYING: {
            utp_rn_connection_destroy(self);
            break;
        }

        default: {
            self->runtime->global().getPropertyAsObject(*self->runtime, "console").getPropertyAsFunction(*self->runtime, "warn").call(*self->runtime, String::createFromUtf8(*self->runtime, "on_utp_statechange: unknown state"), a->state);
            break;
        }
    }

    return 0;
}

static uint64 on_utp_read(utp_callback_arguments *a) {
    utp_rn_connection_t *self = (utp_rn_connection_t *) utp_get_userdata(a->socket);

    memcpy(self->buf.base + self->recv_packet_size, a->buf, a->len);
    self->recv_packet_size += a->len;

    if (self->recv_packet_size < self->min_recv_packet_size) {
        return 0;
    }

    auto ret = self->on_read.callWithThis(*self->runtime, self->ctx, (int) self->recv_packet_size);
    Uint8Array_t buf = get_buffer(*self->runtime, ret, "on_read ret");
    if (buf.byteLength == 0) {
        size_t size = self->recv_packet_size <= 0 ? 0 : self->recv_packet_size;
        self->buf.base += size;
        self->buf.len -= size;
    } else {
        self->buf.base = (char *) buf.data;
        self->buf.len = buf.byteLength;
    }
    self->recv_packet_size = 0;
    return 0;
}

static uint64 on_utp_firewall(utp_callback_arguments *a) {
    utp_rn_t *self = (utp_rn_t *) utp_context_get_userdata(a->context);
    return self->accept_connections ? 0 : 1;
}

static uint64 on_utp_accept(utp_callback_arguments *a) {
    utp_rn_t *self = (utp_rn_t *) utp_context_get_userdata(a->context);

    struct sockaddr addr;
    socklen_t addr_len = sizeof(addr);
    utp_getpeername(a->socket, &addr, &addr_len);

    int port;
    char ip[17];
    utp_rn_parse_address(&addr, ip, &port);

    self->next_connection->socket = a->socket;
    utp_set_userdata(a->socket, self->next_connection);

    auto ret = self->on_connection.callWithThis(*self->runtime, self->ctx, port, String::createFromUtf8(*self->runtime, ip));
    Uint8Array_t next = get_buffer(*self->runtime, ret, "on_connection ret");
    self->next_connection = (utp_rn_connection_t *) next.data;

    return 0;
}

static uint64 on_utp_sendto(utp_callback_arguments *a) {
    utp_rn_t *self = (utp_rn_t *) utp_context_get_userdata(a->context);
    uv_buf_t buf = uv_buf_init((char *) a->buf, a->len);

    if (uv_udp_try_send(&(self->handle), &buf, 1, a->address) >= 0) return 0;

    char *cpy = (char *) malloc(sizeof(uv_udp_send_t) + a->len);

    buf.base = cpy + sizeof(uv_udp_send_t);
    memcpy(buf.base, a->buf, a->len);

    uv_udp_send((uv_udp_send_t *) cpy, &(self->handle), &buf, 1, a->address, on_sendto_free);

    return 0;
}

static uint64 on_utp_error(utp_callback_arguments *a) {
    utp_rn_connection_t *self = (utp_rn_connection_t *) utp_get_userdata(a->socket);
    self->on_error.callWithThis(*self->runtime, self->ctx, (int) a->error_code);
    return 0;
}

static void on_uv_getaddrinfo(uv_getaddrinfo_t *req, int status, struct addrinfo *res) {
    utp_rn_dns_request_t *request = (utp_rn_dns_request_t *) req->data;

    if (status == 0) {
        char ip[17];
        int err = uv_ip4_name((const sockaddr_in *) res->ai_addr, ip, 17);
        Value jserr = request->runtime->global().getPropertyAsFunction(*request->runtime, "Error").callAsConstructor(*request->runtime, String::createFromUtf8(*request->runtime, uv_strerror(err)));
        if (err < 0) request->cb.call(*request->runtime, jserr);
        else request->cb.call(*request->runtime, Value::null(), String::createFromUtf8(*request->runtime, ip));
    } else {
        Value jserr = request->runtime->global().getPropertyAsFunction(*request->runtime, "Error").callAsConstructor(*request->runtime, String::createFromUtf8(*request->runtime, uv_strerror(status)));
        request->cb.call(*request->runtime, jserr);
    }

    free(req);
    uv_freeaddrinfo(res);
}

void install(Runtime &jsiRuntime) {
    auto utp_rn_run = Function::createFromHostFunction(jsiRuntime,
                                                       PropNameID::forAscii(jsiRuntime,
                                                                            "utp_rn_run"),
                                                                            0,
                                                                            [](Runtime &runtime,
                                                                                    const Value &thisValue,
                                                                                    const Value *arguments,
                                                                                    size_t count) -> Value {
        int ret = uv_run(uv_default_loop(), UV_RUN_NOWAIT);
        return Value(ret);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "utp_rn_run", move(utp_rn_run));

    auto utp_rn_init = Function::createFromHostFunction(jsiRuntime,
                                                        PropNameID::forAscii(jsiRuntime,
                                                                             "utp_rn_init"),
                                                                             9,
                                                                             [](Runtime &runtime,
                                                                                     const Value &thisValue,
                                                                                     const Value *arguments,
                                                                                     size_t count) -> Value {
        utp_rn_t *self = (utp_rn_t *) get_buffer(runtime, arguments[0], "utp").data;

        self->closing = 0;
        self->pending_close = 2;
        self->runtime = &runtime;
        self->ctx = arguments[1].getObject(runtime);

        utp_rn_connection_t *next = (utp_rn_connection_t *) get_buffer(runtime, arguments[2], "conn").data;
        self->next_connection = next;

        uv_timer_t *timer = &(self->timer);
        timer->data = self;

        struct uv_loop_s *loop = uv_default_loop();

        int err = uv_timer_init(loop, timer);
        if (err < 0) throw JSError(runtime, uv_strerror(err));

        Uint8Array_t buf = get_buffer(runtime, arguments[3], "buf");
        self->buf.base = (char *) buf.data;
        self->buf.len = buf.byteLength;

        uv_udp_t *handle = &(self->handle);
        handle->data = self;

        err = uv_udp_init(loop, handle);
        if (err < 0) throw JSError(runtime, uv_strerror(err));

        self->on_message = get_function(runtime, arguments[4], "on_message");
        self->on_send = get_function(runtime, arguments[5], "on_send");
        self->on_connection = get_function(runtime, arguments[6], "on_connection");
        self->on_close = get_function(runtime, arguments[7], "on_close");
        self->realloc = get_function(runtime, arguments[8], "realloc");

        self->utp = utp_init(2);
        utp_context_set_userdata(self->utp, self);

        utp_set_callback(self->utp, UTP_ON_STATE_CHANGE, &on_utp_state_change);
        utp_set_callback(self->utp, UTP_ON_READ, &on_utp_read);
        utp_set_callback(self->utp, UTP_ON_FIREWALL, &on_utp_firewall);
        utp_set_callback(self->utp, UTP_ON_ACCEPT, &on_utp_accept);
        utp_set_callback(self->utp, UTP_SENDTO, &on_utp_sendto);
        utp_set_callback(self->utp, UTP_ON_ERROR, &on_utp_error);

        self->accept_connections = 0;

        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "utp_rn_init", move(utp_rn_init));

    auto utp_rn_close = Function::createFromHostFunction(jsiRuntime,
                                                         PropNameID::forAscii(jsiRuntime,
                                                                              "utp_rn_close"),
                                                                              1,
                                                                              [](Runtime &runtime,
                                                                                      const Value &thisValue,
                                                                                      const Value *arguments,
                                                                                      size_t count) -> Value {
        utp_rn_t *self = (utp_rn_t *) get_buffer(runtime, arguments[0], "utp").data;

        self->closing = 1;

        int err;

        err = uv_timer_stop(&(self->timer));
        if (err < 0) throw JSError(runtime, uv_strerror(err));

        err = uv_udp_recv_stop(&(self->handle));
        if (err < 0) throw JSError(runtime, uv_strerror(err));

        uv_close((uv_handle_t *) &(self->handle), on_uv_close);
        uv_close((uv_handle_t *) &(self->timer), on_uv_close);

        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "utp_rn_close", move(utp_rn_close));

    auto utp_rn_destroy = Function::createFromHostFunction(jsiRuntime,
                                                           PropNameID::forAscii(jsiRuntime,
                                                                                "utp_rn_destroy"),
                                                                                2,
                                                                                [](Runtime &runtime,
                                                                                        const Value &thisValue,
                                                                                        const Value *arguments,
                                                                                        size_t count) -> Value {
        utp_rn_t *self = (utp_rn_t *) get_buffer(runtime, arguments[0], "utp").data;
        Array send_reqs = arguments[1].getObject(runtime).getArray(runtime);

        self->buf.base = NULL;
        self->buf.len = 0;

        utp_destroy(self->utp);
        self->utp = NULL;

        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "utp_rn_destroy", move(utp_rn_destroy));

    auto utp_rn_bind = Function::createFromHostFunction(jsiRuntime,
                                                        PropNameID::forAscii(jsiRuntime,
                                                                             "utp_rn_bind"),
                                                                             3,
                                                                             [](Runtime &runtime,
                                                                                     const Value &thisValue,
                                                                                     const Value *arguments,
                                                                                     size_t count) -> Value {
        utp_rn_t *self = (utp_rn_t *) get_buffer(runtime, arguments[0], "utp").data;
        int port = arguments[1].getNumber();
        char ip[17];
        strcpy(ip, arguments[2].getString(runtime).utf8(runtime).data());

        uv_udp_t *handle = &(self->handle);

        int err;
        struct sockaddr_in addr;

        err = uv_ip4_addr((char *) &ip, port, &addr);
        if (err < 0) throw JSError(runtime, uv_strerror(err));

        err = uv_udp_bind(handle, (const struct sockaddr *) &addr, 0);
        if (err < 0) throw JSError(runtime, uv_strerror(err));

        err = uv_udp_recv_start(handle, on_uv_alloc, on_uv_read);
        if (err < 0) throw JSError(runtime, uv_strerror(err));

        uv_unref((uv_handle_t *) &(self->timer));

        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "utp_rn_bind", move(utp_rn_bind));

    auto utp_rn_local_port = Function::createFromHostFunction(jsiRuntime,
                                                              PropNameID::forAscii(jsiRuntime,
                                                                                   "utp_rn_local_port"),
                                                                                   1,
                                                                                   [](Runtime &runtime,
                                                                                           const Value &thisValue,
                                                                                           const Value *arguments,
                                                                                           size_t count) -> Value {
        utp_rn_t *self = (utp_rn_t *) get_buffer(runtime, arguments[0], "utp").data;

        int err;
        struct sockaddr name;
        int name_len = sizeof(name);

        err = uv_udp_getsockname(&(self->handle), &name, &name_len);
        if (err < 0) throw JSError(runtime, uv_strerror(err));

        struct sockaddr_in *name_in = (struct sockaddr_in *) &name;
        int port = ntohs(name_in->sin_port);

        return Value((int) port);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "utp_rn_local_port", move(utp_rn_local_port));

    auto utp_rn_send_request_init = Function::createFromHostFunction(jsiRuntime,
                                                                     PropNameID::forAscii(jsiRuntime,
                                                                                          "utp_rn_send_request_init"),
                                                                                          2,
                                                                                          [](Runtime &runtime,
                                                                                                  const Value &thisValue,
                                                                                                  const Value *arguments,
                                                                                                  size_t count) -> Value {
        utp_rn_send_request_t *send_req = (utp_rn_send_request_t *) get_buffer(runtime, arguments[0], "send_req").data;

        uv_udp_send_t *req = &(send_req->req);
        req->data = send_req;

        send_req->ctx = arguments[1].getObject(runtime);

        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "utp_rn_send_request_init", move(utp_rn_send_request_init));

    auto utp_rn_send = Function::createFromHostFunction(jsiRuntime,
                                                        PropNameID::forAscii(jsiRuntime,
                                                                             "utp_rn_send"),
                                                                             7,
                                                                             [](Runtime &runtime,
                                                                                     const Value &thisValue,
                                                                                     const Value *arguments,
                                                                                     size_t count) -> Value {
        utp_rn_t *self = (utp_rn_t *) get_buffer(runtime, arguments[0], "utp").data;
        utp_rn_send_request_t *send_req = (utp_rn_send_request_t *) get_buffer(runtime, arguments[1], "send_req").data;
        Uint8Array_t buf = get_buffer(runtime, arguments[2], "buf");
        int offset = arguments[3].getNumber();
        int len = arguments[4].getNumber();
        int port = arguments[5].getNumber();
        char ip[17];
        strcpy(ip, arguments[6].getString(runtime).utf8(runtime).data());

        uv_udp_send_t *req = &(send_req->req);

        uv_buf_t bufs = {};
        bufs.base = ((char *) buf.data) + offset;
        bufs.len = len;

        struct sockaddr_in addr;
        int err;

        err = uv_ip4_addr((char *) &ip, port, &addr);
        if (err) throw JSError(runtime, uv_strerror(err));

        err = uv_udp_send(req, &(self->handle), &bufs, 1, (const struct sockaddr *) &addr, on_uv_send);
        if (err) throw JSError(runtime, uv_strerror(err));

        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "utp_rn_send", move(utp_rn_send));

    auto utp_rn_ref = Function::createFromHostFunction(jsiRuntime,
                                                       PropNameID::forAscii(jsiRuntime,
                                                                            "utp_rn_ref"),
                                                                            1,
                                                                            [](Runtime &runtime,
                                                                                    const Value &thisValue,
                                                                                    const Value *arguments,
                                                                                    size_t count) -> Value {
        utp_rn_t *self = (utp_rn_t *) get_buffer(runtime, arguments[0], "utp").data;
        uv_ref((uv_handle_t *) &(self->handle));
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "utp_rn_ref", move(utp_rn_ref));

    auto utp_rn_unref = Function::createFromHostFunction(jsiRuntime,
                                                         PropNameID::forAscii(jsiRuntime,
                                                                              "utp_rn_unref"),
                                                                              1,
                                                                              [](Runtime &runtime,
                                                                                      const Value &thisValue,
                                                                                      const Value *arguments,
                                                                                      size_t count) -> Value {
        utp_rn_t *self = (utp_rn_t *) get_buffer(runtime, arguments[0], "utp").data;
        uv_unref((uv_handle_t *) &(self->handle));
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "utp_rn_unref", move(utp_rn_unref));

    auto utp_rn_recv_buffer = Function::createFromHostFunction(jsiRuntime,
                                                               PropNameID::forAscii(jsiRuntime,
                                                                                    "utp_rn_recv_buffer"),
                                                                                    2,
                                                                                    [](Runtime &runtime,
                                                                                            const Value &thisValue,
                                                                                            const Value *arguments,
                                                                                            size_t count) -> Value {
        utp_rn_t *self = (utp_rn_t *) get_buffer(runtime, arguments[0], "utp").data;
        int size = arguments[1].getNumber();

        int err;
        err = uv_recv_buffer_size((uv_handle_t *) &(self->handle), &size);
        if (err < 0) throw JSError(runtime, uv_strerror(err));

        return Value(size);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "utp_rn_recv_buffer", move(utp_rn_recv_buffer));

    auto utp_rn_send_buffer = Function::createFromHostFunction(jsiRuntime,
                                                               PropNameID::forAscii(jsiRuntime,
                                                                                    "utp_rn_send_buffer"),
                                                                                    2,
                                                                                    [](Runtime &runtime,
                                                                                            const Value &thisValue,
                                                                                            const Value *arguments,
                                                                                            size_t count) -> Value {
        utp_rn_t *self = (utp_rn_t *) get_buffer(runtime, arguments[0], "utp").data;
        int size = arguments[1].getNumber();

        int err;
        err = uv_send_buffer_size((uv_handle_t *) &(self->handle), &size);
        if (err < 0) throw JSError(runtime, uv_strerror(err));

        return Value(size);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "utp_rn_send_buffer", move(utp_rn_send_buffer));

    auto utp_rn_set_ttl = Function::createFromHostFunction(jsiRuntime,
                                                           PropNameID::forAscii(jsiRuntime,
                                                                                "utp_rn_set_ttl"),
                                                                                2,
                                                                                [](Runtime &runtime,
                                                                                        const Value &thisValue,
                                                                                        const Value *arguments,
                                                                                        size_t count) -> Value {
        utp_rn_t *self = (utp_rn_t *) get_buffer(runtime, arguments[0], "utp").data;
        int ttl = arguments[1].getNumber();

        int err;
        err = uv_udp_set_ttl(&(self->handle), ttl);
        if (err < 0) throw JSError(runtime, uv_strerror(err));

        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "utp_rn_set_ttl", move(utp_rn_set_ttl));

    auto utp_rn_connection_init = Function::createFromHostFunction(jsiRuntime,
                                                                   PropNameID::forAscii(jsiRuntime,
                                                                                        "utp_rn_connection_init"),
                                                                                        10,
                                                                                        [](Runtime &runtime,
                                                                                                const Value &thisValue,
                                                                                                const Value *arguments,
                                                                                                size_t count) -> Value {
        utp_rn_connection_t *self = (utp_rn_connection_t *) get_buffer(runtime, arguments[0], "conn").data;

        self->runtime = &runtime;
        self->ctx = arguments[1].getObject(runtime);

        Uint8Array_t buf = get_buffer(runtime, arguments[2], "buf");
        self->buf.base = (char *) buf.data;
        self->buf.len = buf.byteLength;

        self->on_read = get_function(runtime, arguments[3], "on_read");
        self->on_drain = get_function(runtime, arguments[4], "on_drain");
        self->on_end = get_function(runtime, arguments[5], "on_end");
        self->on_error = get_function(runtime, arguments[6], "on_error");
        self->on_close = get_function(runtime, arguments[7], "on_close");
        self->on_connect = get_function(runtime, arguments[8], "on_connect");
        self->realloc = get_function(runtime, arguments[9], "realloc");

        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "utp_rn_connection_init", move(utp_rn_connection_init));

    auto utp_rn_connection_on_close = Function::createFromHostFunction(jsiRuntime,
                                                                       PropNameID::forAscii(jsiRuntime,
                                                                                            "utp_rn_connection_on_close"),
                                                                                            1,
                                                                                            [](Runtime &runtime,
                                                                                                    const Value &thisValue,
                                                                                                    const Value *arguments,
                                                                                                    size_t count) -> Value {
        utp_rn_connection_t *self = (utp_rn_connection_t *) get_buffer(runtime, arguments[0], "conn").data;
        utp_rn_connection_destroy(self);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "utp_rn_connection_on_close", move(utp_rn_connection_on_close));

    auto utp_rn_connection_write = Function::createFromHostFunction(jsiRuntime,
                                                                    PropNameID::forAscii(jsiRuntime,
                                                                                         "utp_rn_connection_write"),
                                                                                         2,
                                                                                         [](Runtime &runtime,
                                                                                                 const Value &thisValue,
                                                                                                 const Value *arguments,
                                                                                                 size_t count) -> Value {
        utp_rn_connection_t *self = (utp_rn_connection_t *) get_buffer(runtime, arguments[0], "conn").data;
        Uint8Array_t buf = get_buffer(runtime, arguments[1], "buf");

        self->send_buffer_next = self->send_buffer;
        self->send_buffer_next->iov_base = buf.data;
        self->send_buffer_next->iov_len = buf.byteLength;
        self->send_buffer_missing = 1;

        int drained = utp_rn_connection_drain(self);
        return Value(drained);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "utp_rn_connection_write", move(utp_rn_connection_write));

    auto utp_rn_connection_writev = Function::createFromHostFunction(jsiRuntime,
                                                                     PropNameID::forAscii(jsiRuntime,
                                                                                          "utp_rn_connection_writev"),
                                                                                          2,
                                                                                          [](Runtime &runtime,
                                                                                                  const Value &thisValue,
                                                                                                  const Value *arguments,
                                                                                                  size_t count) -> Value {
        utp_rn_connection_t *self = (utp_rn_connection_t *) get_buffer(runtime, arguments[0], "conn").data;
        Array bufs = arguments[1].getObject(runtime).getArray(runtime);
        struct utp_iovec *next = self->send_buffer_next = self->send_buffer;

        for (int i = 0; i < bufs.length(runtime); i++) {
            Uint8Array_t buf = get_buffer(runtime, bufs.getValueAtIndex(runtime, i), "buf");

            next->iov_base = buf.data;
            next->iov_len = buf.byteLength;
            next++;
        }

        self->send_buffer_missing = bufs.length(runtime);

        int drained = utp_rn_connection_drain(self);
        return Value(drained);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "utp_rn_connection_writev", move(utp_rn_connection_writev));

    auto utp_rn_connection_shutdown = Function::createFromHostFunction(jsiRuntime,
                                                                       PropNameID::forAscii(jsiRuntime,
                                                                                            "utp_rn_connection_shutdown"),
                                                                                            1,
                                                                                            [](Runtime &runtime,
                                                                                                    const Value &thisValue,
                                                                                                    const Value *arguments,
                                                                                                    size_t count) -> Value {
        utp_rn_connection_t *self = (utp_rn_connection_t *) get_buffer(runtime, arguments[0], "conn").data;
        utp_shutdown(self->socket, SHUT_WR);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "utp_rn_connection_shutdown", move(utp_rn_connection_shutdown));

    auto utp_rn_connection_close = Function::createFromHostFunction(jsiRuntime,
                                                                    PropNameID::forAscii(jsiRuntime,
                                                                                         "utp_rn_connection_close"),
                                                                                         1,
                                                                                         [](Runtime &runtime,
                                                                                                 const Value &thisValue,
                                                                                                 const Value *arguments,
                                                                                                 size_t count) -> Value {
        utp_rn_connection_t *self = (utp_rn_connection_t *) get_buffer(runtime, arguments[0], "conn").data;
        utp_close(self->socket);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "utp_rn_connection_close", move(utp_rn_connection_close));

    auto utp_rn_connect = Function::createFromHostFunction(jsiRuntime,
                                                           PropNameID::forAscii(jsiRuntime,
                                                                                "utp_rn_connect"),
                                                                                4,
                                                                                [](Runtime &runtime,
                                                                                        const Value &thisValue,
                                                                                        const Value *arguments,
                                                                                        size_t count) -> Value {
        utp_rn_t *self = (utp_rn_t *) get_buffer(runtime, arguments[0], "utp").data;
        utp_rn_connection_t *conn = (utp_rn_connection_t *) get_buffer(runtime, arguments[1], "conn").data;
        int port = arguments[2].getNumber();
        char ip[17];
        strcpy(ip, arguments[3].getString(runtime).utf8(runtime).data());

        int err;
        struct sockaddr_in addr;

        conn->socket = utp_create_socket(self->utp);

        utp_set_userdata(conn->socket, conn);

        err = uv_ip4_addr((char *) &ip, port, &addr);
        if (err) throw JSError(runtime, uv_strerror(err));

        utp_connect(conn->socket, (struct sockaddr *) &addr, sizeof(struct sockaddr_in));

        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "utp_rn_connect", move(utp_rn_connect));

    auto sizeof_utp_rn_t = Function::createFromHostFunction(jsiRuntime,
                                                            PropNameID::forAscii(jsiRuntime,
                                                                                 "sizeof_utp_rn_t"),
                                                                                 0,
                                                                                 [](Runtime &runtime,
                                                                                         const Value &thisValue,
                                                                                         const Value *arguments,
                                                                                         size_t count) -> Value {
        return Value((int) sizeof(utp_rn_t));
    });
    jsiRuntime.global().setProperty(jsiRuntime, "sizeof_utp_rn_t", move(sizeof_utp_rn_t));

    auto sizeof_utp_rn_send_request_t = Function::createFromHostFunction(jsiRuntime,
                                                                         PropNameID::forAscii(jsiRuntime,
                                                                                              "sizeof_utp_rn_send_request_t"),
                                                                                              0,
                                                                                              [](Runtime &runtime,
                                                                                                      const Value &thisValue,
                                                                                                      const Value *arguments,
                                                                                                      size_t count) -> Value {
        return Value((int) sizeof(utp_rn_send_request_t));
    });
    jsiRuntime.global().setProperty(jsiRuntime, "sizeof_utp_rn_send_request_t", move(sizeof_utp_rn_send_request_t));

    auto sizeof_utp_rn_connection_t = Function::createFromHostFunction(jsiRuntime,
                                                                       PropNameID::forAscii(jsiRuntime,
                                                                                            "sizeof_utp_rn_connection_t"),
                                                                                            0,
                                                                                            [](Runtime &runtime,
                                                                                                    const Value &thisValue,
                                                                                                    const Value *arguments,
                                                                                                    size_t count) -> Value {
        return Value((int) sizeof(utp_rn_connection_t));
    });
    jsiRuntime.global().setProperty(jsiRuntime, "sizeof_utp_rn_connection_t", move(sizeof_utp_rn_connection_t));

    auto offsetof_utp_rn_t_accept_connections = Function::createFromHostFunction(jsiRuntime,
                                                                                 PropNameID::forAscii(jsiRuntime,
                                                                                                      "offsetof_utp_rn_t_accept_connections"),
                                                                                                      0,
                                                                                                      [](Runtime &runtime,
                                                                                                              const Value &thisValue,
                                                                                                              const Value *arguments,
                                                                                                              size_t count) -> Value {
        return Value((int) offsetof(utp_rn_t, accept_connections));
    });
    jsiRuntime.global().setProperty(jsiRuntime, "offsetof_utp_rn_t_accept_connections", move(offsetof_utp_rn_t_accept_connections));

    auto utp_rn_dns_lookup = Function::createFromHostFunction(jsiRuntime,
                                                              PropNameID::forAscii(jsiRuntime,
                                                                                   "utp_rn_dns_lookup"),
                                                                                   3,
                                                                                   [](Runtime &runtime,
                                                                                           const Value &thisValue,
                                                                                           const Value *arguments,
                                                                                           size_t count) -> Value {
        utp_rn_dns_request_t *request = (utp_rn_dns_request_t *) get_buffer(runtime, arguments[0], "request").data;
        request->runtime = &runtime;
        request->cb = get_function(runtime, arguments[2], "callback");
        uv_getaddrinfo_t *req = (uv_getaddrinfo_t *) malloc(sizeof(uv_getaddrinfo_t));
        req->data = request;
        request->req = req;
        int err = uv_getaddrinfo(uv_default_loop(), req, &on_uv_getaddrinfo, arguments[1].getString(runtime).utf8(runtime).data(), NULL, NULL);
        if (err < 0) throw JSError(runtime, uv_strerror(err));
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "utp_rn_dns_lookup", move(utp_rn_dns_lookup));

    auto sizeof_utp_rn_dns_request_t = Function::createFromHostFunction(jsiRuntime,
                                                                        PropNameID::forAscii(jsiRuntime,
                                                                                             "sizeof_utp_rn_dns_request_t"),
                                                                                             0,
                                                                                             [](Runtime &runtime,
                                                                                                     const Value &thisValue,
                                                                                                     const Value *arguments,
                                                                                                     size_t count) -> Value {
        return Value((int) sizeof(utp_rn_dns_request_t));
    });
    jsiRuntime.global().setProperty(jsiRuntime, "sizeof_utp_rn_dns_request_t", move(sizeof_utp_rn_dns_request_t));
}

}
