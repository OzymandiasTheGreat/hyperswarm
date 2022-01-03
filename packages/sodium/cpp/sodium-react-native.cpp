#include "sodium-react-native.h"
#include "sodium.h"
#include <jsi/jsi.h>

using namespace facebook::jsi;
using namespace std;

struct Uint8Array {
    unsigned char * data;
    size_t byteLength;
};

Uint8Array get_buffer(Runtime &runtime, const Value &arg, string name) {
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
    Uint8Array arr8;
    arr8.data = arr.data(runtime) + (size_t) byteOffset.getNumber();
    arr8.byteLength = (size_t) byteLength.getNumber();
    return arr8;
}

void validate_length(Runtime &runtime, const Uint8Array &arr, size_t expected, string name) {
    if (arr.byteLength != expected) {
        throw JSError(runtime, "Argument \"" + name + "\" is incorrect length. Expexted " + to_string(expected));
    }
}

void at_least_length(Runtime &runtime, const Uint8Array &arr, size_t expected, string name) {
    if (arr.byteLength < expected) {
        throw JSError(runtime, "Argument \"" + name + "\" is incorrect length. Expexted at least " + to_string(expected));
    }
}

void at_most_length(Runtime &runtime, const Uint8Array &arr, size_t expected, string name) {
    if (arr.byteLength > expected) {
        throw JSError(runtime, "Argument \"" + name + "\" is incorrect length. Expexted at most " + to_string(expected));
    }
}

namespace sodium_react_native {

void install(Runtime &jsiRuntime) {

    sodium_init();

    auto get_randombytes_SEEDBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                      PropNameID::forAscii(jsiRuntime,
                                                                                           "get_randombytes_SEEDBYTES"),
                                                                      0,
                                                                      [](Runtime &runtime,
                                                                              const Value &thisValue,
                                                                              const Value *arguments,
                                                                              size_t count) -> Value {
        const int seed = randombytes_seedbytes();
        return Value(seed);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_randombytes_SEEDBYTES", move(get_randombytes_SEEDBYTES));

    auto get_randombytes_random = Function::createFromHostFunction(jsiRuntime,
                                                               PropNameID::forAscii(jsiRuntime,
                                                                                    "randombytes_random"),
                                                                                    0,
                                                                                    [](Runtime &runtime,
                                                                                            const Value &thisValue,
                                                                                            const Value *arguments,
                                                                                            size_t count) -> Value {
        const int random = randombytes_random();
        return Value(random);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "randombytes_random", move(get_randombytes_random));

    auto get_randombytes_uniform = Function::createFromHostFunction(jsiRuntime,
                                                                    PropNameID::forAscii(jsiRuntime,
                                                                                         "randombytes_uniform"),
                                                                                         1,
                                                                                         [](Runtime &runtime,
                                                                                                 const Value &thisValue,
                                                                                                 const Value *arguments,
                                                                                                 size_t count) -> Value {
        const int upper = arguments[0].getNumber();
        const int random = randombytes_uniform(upper);
        return Value(random);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "randombytes_uniform", move(get_randombytes_uniform));

    auto  get_randombytes_buf = Function::createFromHostFunction(jsiRuntime,
                                                                 PropNameID::forAscii(jsiRuntime,
                                                                         "randombytes_buf"),
                                                                                      1,
                                                                                      [](Runtime &runtime,
                                                                                              const Value &thisValue,
                                                                                              const Value *arguments,
                                                                                              size_t count) -> Value {
        auto out = get_buffer(runtime, arguments[0], "buffer");
        randombytes_buf(out.data, out.byteLength);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "randombytes_buf", move(get_randombytes_buf));

    auto get_randombytes_buf_deterministic = Function::createFromHostFunction(jsiRuntime,
                                                                              PropNameID:: forAscii(jsiRuntime,
                                                                                                    "randombytes_buf_deterministic"),
                                                                                                    2,
                                                                                                    [](Runtime &runtime,
                                                                                                            const Value &thisValue,
                                                                                                            const Value *arguments,
                                                                                                            size_t count) -> Value {
        auto seedBuf = get_buffer(runtime, arguments[1], "seed");
        at_least_length(runtime, seedBuf, randombytes_seedbytes(), "seed");
        auto out = get_buffer(runtime, arguments[0], "buffer");
        randombytes_buf_deterministic(out.data, out.byteLength, seedBuf.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "randombytes_buf_deterministic", move(get_randombytes_buf_deterministic));

    auto get_sodium_memcmp = Function::createFromHostFunction(jsiRuntime,
                                                              PropNameID::forAscii(jsiRuntime,
                                                                                   "sodium_memcmp"),
                                                                                   2,
                                                                                   [](Runtime &runtime,
                                                                                           const Value &thisValue,
                                                                                           const Value *arguments,
                                                                                           size_t count) -> Value {
        auto buf1buf = get_buffer(runtime, arguments[0], "buffer1");
        auto buf2buf = get_buffer(runtime, arguments[1], "buffer2");
        validate_length(runtime, buf2buf, buf1buf.byteLength, "buffer2");
        int out = sodium_memcmp(buf1buf.data, buf2buf.data, buf1buf.byteLength);
        if (!out) {
            return Value(true);
        }
        return Value(false);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "sodium_memcmp", move(get_sodium_memcmp));

    auto get_sodium_compare = Function::createFromHostFunction(jsiRuntime,
                                                               PropNameID::forAscii(jsiRuntime,
                                                                                    "sodium_compare"),
                                                                                    2,
                                                                                    [](Runtime &runtime,
                                                                                            const Value &thisValue,
                                                                                            const Value *arguments,
                                                                                            size_t count) -> Value {
        auto buf1buf = get_buffer(runtime, arguments[0], "buffer1");
        auto buf2buf = get_buffer(runtime, arguments[1], "buffer2");
        validate_length(runtime, buf2buf, buf1buf.byteLength, "buffer2");
        int out = sodium_compare(buf1buf.data, buf2buf.data, buf1buf.byteLength);
        return Value(out);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "sodium_compare", move(get_sodium_compare));

    auto get_sodium_add = Function::createFromHostFunction(jsiRuntime,
                                                               PropNameID::forAscii(jsiRuntime,
                                                                                    "sodium_add"),
                                                               2,
                                                               [](Runtime &runtime,
                                                                        const Value &thisValue,
                                                                        const Value *arguments,
                                                                        size_t count) -> Value {
        auto buf1buf = get_buffer(runtime, arguments[0], "buffer1");
        auto buf2buf = get_buffer(runtime, arguments[1], "buffer2");
        validate_length(runtime, buf2buf, buf1buf.byteLength, "buffer2");
        sodium_add(buf1buf.data, buf2buf.data, buf1buf.byteLength);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "sodium_add", move(get_sodium_add));

    auto get_sodium_sub = Function::createFromHostFunction(jsiRuntime,
                                                               PropNameID::forAscii(jsiRuntime,
                                                                                    "sodium_sub"),
                                                               2,
                                                               [](Runtime &runtime,
                                                                        const Value &thisValue,
                                                                        const Value *arguments,
                                                                        size_t count) -> Value {
        auto buf1buf = get_buffer(runtime, arguments[0], "buffer1");
        auto buf2buf = get_buffer(runtime, arguments[1], "buffer2");
        validate_length(runtime, buf2buf, buf1buf.byteLength, "buffer2");
        sodium_sub(buf1buf.data, buf2buf.data, buf1buf.byteLength);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "sodium_sub", move(get_sodium_sub));

    auto get_sodium_increment = Function::createFromHostFunction(jsiRuntime,
                                                             PropNameID::forAscii(jsiRuntime,
                                                                                  "sodium_increment"),
                                                                                  1,
                                                                                  [](Runtime &runtime,
                                                                                          const Value &thisValue,
                                                                                          const Value *arguments,
                                                                                          size_t count) -> Value {
        auto arr = get_buffer(runtime, arguments[0], "buffer");
        sodium_increment(arr.data, arr.byteLength);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "sodium_increment", move(get_sodium_increment));

    auto get_sodium_is_zero = Function::createFromHostFunction(jsiRuntime,
                                                             PropNameID::forAscii(jsiRuntime,
                                                                                  "sodium_is_zero"),
                                                                                  1,
                                                                                  [](Runtime &runtime,
                                                                                          const Value &thisValue,
                                                                                          const Value *arguments,
                                                                                          size_t count) -> Value {
        auto arr = get_buffer(runtime, arguments[0], "buffer");
        bool out = sodium_is_zero(arr.data, arr.byteLength);
        return Value(out);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "sodium_is_zero", move(get_sodium_is_zero));

    auto get_sodium_pad = Function::createFromHostFunction(jsiRuntime,
                                                           PropNameID::forAscii(jsiRuntime,
                                                                                "sodium_pad"),
                                                                                3,
                                                                                [](Runtime &runtime,
                                                                                        const Value &thisValue,
                                                                                        const Value *arguments,
                                                                                        size_t count) -> Value {
        auto buf = get_buffer(runtime, arguments[0], "buffer");
        size_t unpl = arguments[1].getNumber();
        size_t blks = arguments[2].getNumber();
        size_t newl;
        int out = sodium_pad(&newl, buf.data, unpl, blks, buf.byteLength);
        if (!out) {
            return Value((double) newl);
        }
        return Value(out);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "sodium_pad", move(get_sodium_pad));

    auto get_sodium_unpad = Function::createFromHostFunction(jsiRuntime,
                                                             PropNameID::forAscii(jsiRuntime,
                                                                                  "sodium_unpad"),
                                                                                  3,
                                                                                  [](Runtime &runtime,
                                                                                          const Value &thisValue,
                                                                                          const Value *arguments,
                                                                                          size_t count) -> Value {
        auto buf = get_buffer(runtime, arguments[0], "buffer");
        size_t padl = arguments[1].getNumber();
        size_t blks = arguments[2].getNumber();
        size_t orgl;
        int out = sodium_unpad(&orgl, buf.data, padl, blks);
        if (!out) {
            return Value((double) orgl);
        }
        return Value(out);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "sodium_unpad", move(get_sodium_unpad));

    auto get_crypto_sign_PUBLICKEYBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                           PropNameID::forAscii(jsiRuntime,
                                                                                                "get_crypto_sign_PUBLICKEYBYTES"),
                                                                                                0,
                                                                                                [](Runtime &runtime,
                                                                                                        const Value &thisValue,
                                                                                                        const Value *arguments,
                                                                                                        size_t count) -> Value {
        return Value((double) crypto_sign_PUBLICKEYBYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_sign_PUBLICKEYBYTES", move(get_crypto_sign_PUBLICKEYBYTES));

    auto get_crypto_sign_SECRETKEYBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                           PropNameID::forAscii(jsiRuntime,
                                                                                                "get_crypto_sign_SECRETKEYBYTES"),
                                                                                                0,
                                                                                                [](Runtime &runtime,
                                                                                                        const Value &thisValue,
                                                                                                        const Value *arguments,
                                                                                                        size_t count) -> Value {
        return Value((double) crypto_sign_SECRETKEYBYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_sign_SECRETKEYBYTES", move(get_crypto_sign_SECRETKEYBYTES));

    auto get_crypto_sign_SEEDBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                           PropNameID::forAscii(jsiRuntime,
                                                                                                "get_crypto_sign_SEEDBYTES"),
                                                                                                0,
                                                                                                [](Runtime &runtime,
                                                                                                        const Value &thisValue,
                                                                                                        const Value *arguments,
                                                                                                        size_t count) -> Value {
        return Value((double) crypto_sign_SEEDBYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_sign_SEEDBYTES", move(get_crypto_sign_SEEDBYTES));

    auto get_crypto_sign_BYTES = Function::createFromHostFunction(jsiRuntime,
                                                                           PropNameID::forAscii(jsiRuntime,
                                                                                                "get_crypto_sign_BYTES"),
                                                                                                0,
                                                                                                [](Runtime &runtime,
                                                                                                        const Value &thisValue,
                                                                                                        const Value *arguments,
                                                                                                        size_t count) -> Value {
        return Value((double) crypto_sign_BYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_sign_BYTES", move(get_crypto_sign_BYTES));

    auto get_crypto_box_PUBLICKEYBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                           PropNameID::forAscii(jsiRuntime,
                                                                                                "get_crypto_box_PUBLICKEYBYTES"),
                                                                                                0,
                                                                                                [](Runtime &runtime,
                                                                                                        const Value &thisValue,
                                                                                                        const Value *arguments,
                                                                                                        size_t count) -> Value {
        return Value((double) crypto_box_PUBLICKEYBYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_box_PUBLICKEYBYTES", move(get_crypto_box_PUBLICKEYBYTES));

    auto get_crypto_box_SECRETKEYBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                           PropNameID::forAscii(jsiRuntime,
                                                                                                "get_crypto_box_SECRETKEYBYTES"),
                                                                                                0,
                                                                                                [](Runtime &runtime,
                                                                                                        const Value &thisValue,
                                                                                                        const Value *arguments,
                                                                                                        size_t count) -> Value {
        return Value((double) crypto_box_SECRETKEYBYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_box_SECRETKEYBYTES", move(get_crypto_box_SECRETKEYBYTES));

    auto get_crypto_sign_seed_keypair = Function::createFromHostFunction(jsiRuntime,
                                                                         PropNameID::forAscii(jsiRuntime,
                                                                                              "crypto_sign_seed_keypair"),
                                                                                              3,
                                                                                              [](Runtime &runtime,
                                                                                                      const Value &thisValue,
                                                                                                      const Value *arguments,
                                                                                                      size_t count) -> Value {
        auto pk = get_buffer(runtime, arguments[0], "pk");
        auto sk = get_buffer(runtime, arguments[1], "sk");
        auto seed = get_buffer(runtime, arguments[2], "seed");
        validate_length(runtime, pk, crypto_sign_PUBLICKEYBYTES, "pk");
        validate_length(runtime, sk, crypto_sign_SECRETKEYBYTES, "sk");
        validate_length(runtime, seed, crypto_sign_SEEDBYTES, "seed");
        crypto_sign_seed_keypair(pk.data, sk.data, seed.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_sign_seed_keypair", move(get_crypto_sign_seed_keypair));

    auto get_crypto_sign_seed25519_keypair = Function::createFromHostFunction(jsiRuntime,
                                                                              PropNameID::forAscii(jsiRuntime,
                                                                                                   "crypto_sign_seed25519_keypair"),
                                                                                                   3,
                                                                                                   [](Runtime &runtime,
                                                                                                           const Value &thisValue,
                                                                                                           const Value *arguments,
                                                                                                           size_t count) -> Value {
        auto pkbuf = get_buffer(runtime, arguments[0], "pk");
        auto skbuf = get_buffer(runtime, arguments[1], "sk");
        auto sdbuf = get_buffer(runtime, arguments[2], "seed");
        validate_length(runtime, pkbuf, crypto_sign_PUBLICKEYBYTES, "pk");
        validate_length(runtime, skbuf, crypto_sign_SECRETKEYBYTES, "sk");
        validate_length(runtime, sdbuf, crypto_sign_SEEDBYTES, "seed");
        crypto_sign_seed_keypair(pkbuf.data, skbuf.data, sdbuf.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_sign_seed25519_keypair", move(get_crypto_sign_seed25519_keypair));

    auto get_crypto_sign_keypair = Function::createFromHostFunction(jsiRuntime,
                                                                PropNameID::forAscii(jsiRuntime,
                                                                                     "crypto_sign_keypair"),
                                                                                     2,
                                                                                     [](Runtime &runtime,
                                                                                             const Value &thisValue,
                                                                                             const Value *arguments,
                                                                                             size_t count) -> Value {
        auto pkbuf = get_buffer(runtime, arguments[0], "pk");
        auto skbuf = get_buffer(runtime, arguments[1], "sk");
        validate_length(runtime, pkbuf, crypto_sign_PUBLICKEYBYTES, "pk");
        validate_length(runtime, skbuf, crypto_sign_SECRETKEYBYTES, "sk");
        crypto_sign_keypair(pkbuf.data, skbuf.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_sign_keypair", move(get_crypto_sign_keypair));

    auto get_crypto_sign = Function::createFromHostFunction(jsiRuntime,
                                                            PropNameID::forAscii(jsiRuntime,
                                                                                 "crypto_sign"),
                                                                                 3,
                                                                                 [](Runtime &runtime,
                                                                                         const Value &thisValue,
                                                                                         const Value *arguments,
                                                                                         size_t count) -> Value {
        auto sm = get_buffer(runtime, arguments[0], "sm");
        auto m = get_buffer(runtime, arguments[1], "m");
        auto sk = get_buffer(runtime, arguments[2], "sk");
        unsigned long long int smlen;
        at_least_length(runtime, sm, m.byteLength + crypto_sign_bytes(), "sm");
        crypto_sign(sm.data, &smlen, m.data, m.byteLength, sk.data);
        return Value((double) smlen);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_sign", move(get_crypto_sign));

    auto get_crypto_sign_open = Function::createFromHostFunction(jsiRuntime,
                                                                 PropNameID::forAscii(jsiRuntime,
                                                                                      "crypto_sign_open"),
                                                                                      3,
                                                                                      [](Runtime &runtime,
                                                                                              const Value &thisValue,
                                                                                              const Value *arguments,
                                                                                              size_t count) -> Value {
        auto mbuf = get_buffer(runtime, arguments[0], "m");
        auto smbuf = get_buffer(runtime, arguments[1], "sm");
        auto pkbuf = get_buffer(runtime, arguments[2], "pk");
        at_least_length(runtime, smbuf, crypto_sign_bytes(), "sm");
        validate_length(runtime, pkbuf, crypto_sign_PUBLICKEYBYTES, "pk");
        int out = crypto_sign_open(mbuf.data, nullptr, smbuf.data, smbuf.byteLength, pkbuf.data);
        if (!out) {
            return Value(true);
        }
        return Value(false);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_sign_open", move(get_crypto_sign_open));

    auto get_crypto_sign_detached = Function::createFromHostFunction(jsiRuntime,
                                                                     PropNameID::forAscii(jsiRuntime,
                                                                                          "crypto_sign_detached"),
                                                                                          3,
                                                                                          [](Runtime &runtime,
                                                                                                  const Value &thisValue,
                                                                                                  const Value *arguments,
                                                                                                  size_t count) -> Value {
        auto sigbuf = get_buffer(runtime, arguments[0], "sig");
        auto mbuf = get_buffer(runtime, arguments[1], "m");
        auto skbuf = get_buffer(runtime, arguments[2], "sk");
        crypto_sign_detached(sigbuf.data, nullptr, mbuf.data, mbuf.byteLength, skbuf.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_sign_detached", move(get_crypto_sign_detached));

    auto get_crypto_sign_verify_detached = Function::createFromHostFunction(jsiRuntime,
                                                                            PropNameID::forAscii(jsiRuntime,
                                                                                                 "crypto_sign_verify_detached"),
                                                                                                 3,
                                                                                                 [](Runtime &runtime,
                                                                                                         const Value &thisValue,
                                                                                                         const Value *arguments,
                                                                                                         size_t count) -> Value {
         auto sigbuf = get_buffer(runtime, arguments[0], "sig");
         auto mbuf = get_buffer(runtime, arguments[1], "m");
         auto pkbuf = get_buffer(runtime, arguments[2], "pk");
         int out = crypto_sign_verify_detached(sigbuf.data, mbuf.data, mbuf.byteLength, pkbuf.data);
         if (!out) {
             return Value(true);
         }
         return Value(false);
     });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_sign_verify_detached", move(get_crypto_sign_verify_detached));

    auto get_crypto_sign_ed25519_pk_to_curve25519 = Function::createFromHostFunction(jsiRuntime,
                                                                                     PropNameID::forAscii(jsiRuntime,
                                                                                                          "crypto_sign_ed25519_pk_to_curve25519"),
                                                                                                          2,
                                                                                                          [](Runtime &runtime,
                                                                                                                  const Value &thisValue,
                                                                                                                  const Value *arguments,
                                                                                                                  size_t count) -> Value {
        auto x25519_pk = get_buffer(runtime, arguments[0], "x25519_pk");
        auto ed25519_pk = get_buffer(runtime, arguments[1], "ed25519_pk");
        int out = crypto_sign_ed25519_pk_to_curve25519(x25519_pk.data, ed25519_pk.data);
        if (!out) {
            return Value::undefined();
        }
        throw JSError(runtime, "Incorrect key");
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_sign_ed25519_pk_to_curve25519", move(get_crypto_sign_ed25519_pk_to_curve25519));

    auto get_crypto_sign_ed25519_sk_to_curve25519 = Function::createFromHostFunction(jsiRuntime,
                                                                                     PropNameID::forAscii(jsiRuntime,
                                                                                                          "crypto_sign_ed25519_sk_to_curve25519"),
                                                                                                          2,
                                                                                                          [](Runtime &runtime,
                                                                                                                  const Value &thisValue,
                                                                                                                  const Value *arguments,
                                                                                                                  size_t count) -> Value {
        auto x25519_sk = get_buffer(runtime, arguments[0], "x25519_sk");
        auto ed25519_sk = get_buffer(runtime, arguments[1], "ed25519_sk");
        int out = crypto_sign_ed25519_sk_to_curve25519(x25519_sk.data, ed25519_sk.data);
        if (!out) {
            return Value::undefined();
        }
        throw JSError(runtime, "Incorrect key");
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_sign_ed25519_sk_to_curve25519", move(get_crypto_sign_ed25519_sk_to_curve25519));

    auto get_crypto_sign_ed25519_sk_to_pk = Function::createFromHostFunction(jsiRuntime,
                                                                             PropNameID::forAscii(jsiRuntime,
                                                                                                  "crypto_sign_ed25519_sk_to_pk"),
                                                                                                  2,
                                                                                                  [](Runtime &runtime,
                                                                                                          const Value &thisValue,
                                                                                                          const Value *arguments,
                                                                                                          size_t count) -> Value {
        auto pk = get_buffer(runtime, arguments[0], "pk");
        auto sk = get_buffer(runtime, arguments[1], "sk");
        int out = crypto_sign_ed25519_sk_to_pk(pk.data, sk.data);
        if (!out) {
            return Value::undefined();
        }
        throw JSError(runtime, "Incorrect key");
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_sign_ed25519_sk_to_pk", move(get_crypto_sign_ed25519_sk_to_pk));

    auto get_crypto_generichash_BYTES = Function::createFromHostFunction(jsiRuntime,
                                                                         PropNameID::forAscii(jsiRuntime,
                                                                                              "get_crypto_generichash_BYTES"),
                                                                                              0,
                                                                                              [](Runtime &runtime,
                                                                                                      const Value &thisValue,
                                                                                                      const Value *arguments,
                                                                                                      size_t count) -> Value {
        return Value((double) crypto_generichash_BYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_generichash_BYTES", move(get_crypto_generichash_BYTES));

    auto get_crypto_generichash_BYTES_MIN = Function::createFromHostFunction(jsiRuntime,
                                                                         PropNameID::forAscii(jsiRuntime,
                                                                                              "get_crypto_generichash_BYTES_MIN"),
                                                                                              0,
                                                                                              [](Runtime &runtime,
                                                                                                      const Value &thisValue,
                                                                                                      const Value *arguments,
                                                                                                      size_t count) -> Value {
        return Value((double) crypto_generichash_BYTES_MIN);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_generichash_BYTES_MIN", move(get_crypto_generichash_BYTES_MIN));

    auto get_crypto_generichash_BYTES_MAX = Function::createFromHostFunction(jsiRuntime,
                                                                         PropNameID::forAscii(jsiRuntime,
                                                                                              "get_crypto_generichash_BYTES_MAX"),
                                                                                              0,
                                                                                              [](Runtime &runtime,
                                                                                                      const Value &thisValue,
                                                                                                      const Value *arguments,
                                                                                                      size_t count) -> Value {
        return Value((double) crypto_generichash_BYTES_MAX);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_generichash_BYTES_MAX", move(get_crypto_generichash_BYTES_MAX));

    auto get_crypto_generichash_KEYBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                         PropNameID::forAscii(jsiRuntime,
                                                                                              "get_crypto_generichash_KEYBYTES"),
                                                                                              0,
                                                                                              [](Runtime &runtime,
                                                                                                      const Value &thisValue,
                                                                                                      const Value *arguments,
                                                                                                      size_t count) -> Value {
        return Value((double) crypto_generichash_KEYBYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_generichash_KEYBYTES", move(get_crypto_generichash_KEYBYTES));

    auto get_crypto_generichash_KEYBYTES_MIN = Function::createFromHostFunction(jsiRuntime,
                                                                         PropNameID::forAscii(jsiRuntime,
                                                                                              "get_crypto_generichash_KEYBYTES_MIN"),
                                                                                              0,
                                                                                              [](Runtime &runtime,
                                                                                                      const Value &thisValue,
                                                                                                      const Value *arguments,
                                                                                                      size_t count) -> Value {
        return Value((double) crypto_generichash_KEYBYTES_MIN);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_generichash_KEYBYTES_MIN", move(get_crypto_generichash_KEYBYTES_MIN));

    auto get_crypto_generichash_KEYBYTES_MAX = Function::createFromHostFunction(jsiRuntime,
                                                                         PropNameID::forAscii(jsiRuntime,
                                                                                              "get_crypto_generichash_KEYBYTES_MAX"),
                                                                                              0,
                                                                                              [](Runtime &runtime,
                                                                                                      const Value &thisValue,
                                                                                                      const Value *arguments,
                                                                                                      size_t count) -> Value {
        return Value((double) crypto_generichash_KEYBYTES_MAX);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_generichash_KEYBYTES_MAX", move(get_crypto_generichash_KEYBYTES_MAX));

    auto get_crypto_generichash_STATEBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                         PropNameID::forAscii(jsiRuntime,
                                                                                              "get_crypto_generichash_STATEBYTES"),
                                                                                              0,
                                                                                              [](Runtime &runtime,
                                                                                                      const Value &thisValue,
                                                                                                      const Value *arguments,
                                                                                                      size_t count) -> Value {
        return Value((double) crypto_generichash_statebytes());
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_generichash_STATEBYTES", move(get_crypto_generichash_STATEBYTES));

    auto get_crypto_generichash = Function::createFromHostFunction(jsiRuntime,
                                                                   PropNameID::forAscii(jsiRuntime,
                                                                                        "crypto_generichash"),
                                                                                        3,
                                                                                        [](Runtime &runtime,
                                                                                                const Value &thisValue,
                                                                                                const Value *arguments,
                                                                                                size_t count) -> Value {
        auto out = get_buffer(runtime, arguments[0], "out");
        auto in = get_buffer(runtime, arguments[1], "in");
        size_t keyLen = 0;
        unsigned char * key = nullptr;
        if (!arguments[2].isUndefined()) {
            auto keyArg = get_buffer(runtime, arguments[2], "key");
            keyLen = keyArg.byteLength;
            key = keyArg.data;
        }
        crypto_generichash(out.data, out.byteLength, in.data, in.byteLength, key, keyLen);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_generichash", move(get_crypto_generichash));

    auto get_crypto_generichash_init = Function::createFromHostFunction(jsiRuntime,
                                                                        PropNameID::forAscii(jsiRuntime,
                                                                                             "crypto_generichash_init"),
                                                                                             3,
                                                                                             [](Runtime &runtime,
                                                                                                     const Value &thisValue,
                                                                                                     const Value *arguments,
                                                                                                     size_t count) -> Value {
        auto state = get_buffer(runtime, arguments[0], "state");
        validate_length(runtime, state, crypto_generichash_statebytes(), "state");
        size_t outlen;
        size_t keyLen = 0;
        unsigned char * key = nullptr;
        if (arguments[2].isNumber()) {
            outlen = arguments[2].getNumber();
            if (!arguments[1].isUndefined()) {
                auto keyArg = get_buffer(runtime, arguments[1], "key");
                keyLen = keyArg.byteLength;
                key = keyArg.data;
            }
        } else {
            outlen = arguments[1].getNumber();
        }
        if (outlen < crypto_generichash_BYTES_MIN || outlen > crypto_generichash_BYTES_MAX) {
            throw JSError(runtime, "Invalid \"outlen\"");
        }
        crypto_generichash_state st[crypto_generichash_statebytes()];
        crypto_generichash_init(st, key, keyLen, outlen);
        copy(begin(st->opaque), end(st->opaque), state.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_generichash_init", move(get_crypto_generichash_init));

    auto get_crypto_generichash_update = Function::createFromHostFunction(jsiRuntime,
                                                                      PropNameID::forAscii(jsiRuntime,
                                                                                           "crypto_generichash_update"),
                                                                                           2,
                                                                                           [](Runtime &runtime,
                                                                                                   const Value &thisValue,
                                                                                                   const Value *arguments,
                                                                                                   size_t count) -> Value {
        auto state = get_buffer(runtime, arguments[0], "state");
        auto in = get_buffer(runtime, arguments[1], "in");
        crypto_generichash_state st[crypto_generichash_statebytes()];
        size_t n = state.byteLength;
        for (int i = 0; i < n; i++) {
            st->opaque[i] = state.data[i];
        }
        crypto_generichash_update(st, in.data, in.byteLength);
        copy(begin(st->opaque), end(st->opaque), state.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_generichash_update", move(get_crypto_generichash_update));

    auto get_crypto_generichash_final = Function::createFromHostFunction(jsiRuntime,
                                                                         PropNameID::forAscii(jsiRuntime,
                                                                                              "crypto_generichash_final"),
                                                                                              2,
                                                                                              [](Runtime &runtime,
                                                                                                      const Value &thisValue,
                                                                                                      const Value *arguments,
                                                                                                      size_t count) -> Value {
        auto state = get_buffer(runtime, arguments[0], "state");
        auto out = get_buffer(runtime, arguments[1], "out");
        crypto_generichash_state st[crypto_generichash_statebytes()];
        size_t n = state.byteLength;
        for (int i = 0; i < n; i++) {
            st->opaque[i] = state.data[i];
        }
        crypto_generichash_final(st, out.data, out.byteLength);
        copy(begin(st->opaque), end(st->opaque), state.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_generichash_final", move(get_crypto_generichash_final));

    auto get_crypto_box_SEEDBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                     PropNameID::forAscii(jsiRuntime,
                                                                                          "get_crypto_box_SEEDBYTES"),
                                                                                          0,
                                                                                          [](Runtime &runtime,
                                                                                                  const Value &thisValue,
                                                                                                  const Value *arguments,
                                                                                                  size_t count) -> Value {
        return Value((double) crypto_box_SEEDBYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_box_SEEDBYTES", move(get_crypto_box_SEEDBYTES));

    auto get_crypto_box_MACBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                     PropNameID::forAscii(jsiRuntime,
                                                                                          "get_crypto_box_MACBYTES"),
                                                                                          0,
                                                                                          [](Runtime &runtime,
                                                                                                  const Value &thisValue,
                                                                                                  const Value *arguments,
                                                                                                  size_t count) -> Value {
        return Value((double) crypto_box_MACBYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_box_MACBYTES", move(get_crypto_box_MACBYTES));

    auto get_crypto_box_NONCEBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                     PropNameID::forAscii(jsiRuntime,
                                                                                          "get_crypto_box_NONCEBYTES"),
                                                                                          0,
                                                                                          [](Runtime &runtime,
                                                                                                  const Value &thisValue,
                                                                                                  const Value *arguments,
                                                                                                  size_t count) -> Value {
        return Value((double) crypto_box_NONCEBYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_box_NONCEBYTES", move(get_crypto_box_NONCEBYTES));

    auto get_crypto_box_seed_keypair = Function::createFromHostFunction(jsiRuntime,
                                                                        PropNameID::forAscii(jsiRuntime,
                                                                                             "crypto_box_seed_keypair"),
                                                                                             3,
                                                                                             [](Runtime &runtime,
                                                                                                     const Value &thisValue,
                                                                                                     const Value *arguments,
                                                                                                     size_t count) -> Value {
        auto pk = get_buffer(runtime, arguments[0], "pk");
        auto sk = get_buffer(runtime, arguments[1], "sk");
        auto seed = get_buffer(runtime, arguments[2], "seed");
        crypto_box_seed_keypair(pk.data, sk.data, seed.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_box_seed_keypair", move(get_crypto_box_seed_keypair));

    auto get_crypto_box_keypair = Function::createFromHostFunction(jsiRuntime,
                                                                   PropNameID::forAscii(jsiRuntime,
                                                                                        "crypto_box_keypair"),
                                                                                        2,
                                                                                        [](Runtime &runtime,
                                                                                                const Value &thisValue,
                                                                                                const Value *arguments,
                                                                                                size_t count) -> Value {
        auto pk = get_buffer(runtime, arguments[0], "pk");
        auto sk = get_buffer(runtime, arguments[1], "sk");
        crypto_box_keypair(pk.data, sk.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_box_keypair", move(get_crypto_box_keypair));

    auto get_crypto_box_detached = Function::createFromHostFunction(jsiRuntime,
                                                                    PropNameID::forAscii(jsiRuntime,
                                                                                         "crypto_box_detached"),
                                                                                         6,
                                                                                         [](Runtime &runtime,
                                                                                                 const Value &thisValue,
                                                                                                 const Value *arguments,
                                                                                                 size_t count) -> Value {
        auto c = get_buffer(runtime, arguments[0], "c");
        auto mac = get_buffer(runtime, arguments[1], "mac");
        auto m = get_buffer(runtime, arguments[2], "m");
        auto n = get_buffer(runtime, arguments[3], "n");
        auto pk = get_buffer(runtime, arguments[4], "pk");
        auto sk = get_buffer(runtime, arguments[5], "sk");
        at_least_length(runtime, c, m.byteLength, "c");
        validate_length(runtime, mac, crypto_box_MACBYTES, "mac");
        validate_length(runtime, n, crypto_box_NONCEBYTES, "n");
        validate_length(runtime, pk, crypto_box_PUBLICKEYBYTES, "pk");
        validate_length(runtime, sk, crypto_box_SECRETKEYBYTES, "sk");
        int out = crypto_box_detached(c.data, mac.data, m.data, m.byteLength, n.data, pk.data, sk.data);
        if (!out) {
            return Value(true);
        }
        return Value(false);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_box_detached", move(get_crypto_box_detached));

    auto get_crypto_box_easy = Function::createFromHostFunction(jsiRuntime,
                                                                PropNameID::forAscii(jsiRuntime,
                                                                                     "crypto_box_easy"),
                                                                                     5,
                                                                                     [](Runtime &runtime,
                                                                                             const Value &thisValue,
                                                                                             const Value *arguments,
                                                                                             size_t count) -> Value {
        auto c = get_buffer(runtime, arguments[0], "c");
        auto m = get_buffer(runtime, arguments[1], "m");
        auto n = get_buffer(runtime, arguments[2], "n");
        auto pk = get_buffer(runtime, arguments[3], "pk");
        auto sk = get_buffer(runtime, arguments[4], "sk");
        at_least_length(runtime, c, m.byteLength + crypto_box_MACBYTES, "c");
        validate_length(runtime, n, crypto_box_NONCEBYTES, "n");
        validate_length(runtime, pk, crypto_box_PUBLICKEYBYTES, "pk");
        validate_length(runtime, sk, crypto_box_SECRETKEYBYTES, "sk");
        int out = crypto_box_easy(c.data, m.data, m.byteLength, n.data, pk.data, sk.data);
        if (!out) {
            return Value(true);
        }
        return Value(false);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_box_easy", move(get_crypto_box_easy));

    auto get_crypto_box_open_detached = Function::createFromHostFunction(jsiRuntime,
                                                                         PropNameID::forAscii(jsiRuntime,
                                                                                              "crypto_box_open_detached"),
                                                                                              6,
                                                                                              [](Runtime &runtime,
                                                                                                      const Value &thisValue,
                                                                                                      const Value *arguments,
                                                                                                      size_t count) -> Value {
        auto m = get_buffer(runtime, arguments[0], "m");
        auto c = get_buffer(runtime, arguments[1], "c");
        auto mac = get_buffer(runtime, arguments[2], "mac");
        auto n = get_buffer(runtime, arguments[3], "n");
        auto pk = get_buffer(runtime, arguments[4], "pk");
        auto sk = get_buffer(runtime, arguments[5], "sk");
        validate_length(runtime, mac, crypto_box_MACBYTES, "mac");
        validate_length(runtime, n, crypto_box_NONCEBYTES, "n");
        validate_length(runtime, pk, crypto_box_PUBLICKEYBYTES, "pk");
        validate_length(runtime, sk, crypto_box_SECRETKEYBYTES, "sk");
        int out = crypto_box_open_detached(m.data, c.data, mac.data, c.byteLength, n.data, pk.data, sk.data);
        if (!out) {
            return Value(true);
        }
        return Value(false);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_box_open_detached", move(get_crypto_box_open_detached));

    auto get_crypto_box_open_easy = Function::createFromHostFunction(jsiRuntime,
                                                                     PropNameID::forAscii(jsiRuntime,
                                                                                          "crypto_box_open_easy"),
                                                                                          5,
                                                                                          [](Runtime &runtime,
                                                                                                  const Value &thisValue,
                                                                                                  const Value *arguments,
                                                                                                  size_t count) -> Value {
        auto m = get_buffer(runtime, arguments[0], "m");
        auto c = get_buffer(runtime, arguments[1], "c");
        auto n = get_buffer(runtime, arguments[2], "n");
        auto pk = get_buffer(runtime, arguments[3], "pk");
        auto sk = get_buffer(runtime, arguments[4], "sk");
        validate_length(runtime, n, crypto_box_NONCEBYTES, "n");
        validate_length(runtime, pk, crypto_box_PUBLICKEYBYTES, "pk");
        validate_length(runtime, sk, crypto_box_SECRETKEYBYTES, "sk");
        int out = crypto_box_open_easy(m.data, c.data, c.byteLength, n.data, pk.data, sk.data);
        if (!out) {
            return Value(true);
        }
        return Value(false);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_box_open_easy", move(get_crypto_box_open_easy));

    auto get_crypto_box_SEALBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                     PropNameID::forAscii(jsiRuntime,
                                                                                          "get_crypto_box_SEALBYTES"),
                                                                                          0,
                                                                                          [](Runtime &runtime,
                                                                                                  const Value &thisValue,
                                                                                                  const Value *arguments,
                                                                                                  size_t count) -> Value {
        return Value((int) crypto_box_SEALBYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_box_SEALBYTES", move(get_crypto_box_SEALBYTES));

    auto get_crypto_box_seal = Function::createFromHostFunction(jsiRuntime,
                                                                PropNameID::forAscii(jsiRuntime,
                                                                                     "crypto_box_seal"),
                                                                                     3,
                                                                                     [](Runtime &runtime,
                                                                                             const Value &thisValue,
                                                                                             const Value *arguments,
                                                                                             size_t count) -> Value {
        auto c = get_buffer(runtime, arguments[0], "c");
        auto m = get_buffer(runtime, arguments[1], "m");
        auto pk = get_buffer(runtime, arguments[2], "pk");
        validate_length(runtime, c, m.byteLength + crypto_box_SEALBYTES, "c");
        validate_length(runtime, pk, crypto_box_PUBLICKEYBYTES, "pk");
        int out = crypto_box_seal(c.data, m.data, m.byteLength, pk.data);
        if (!out) {
            return Value(true);
        }
        return Value(false);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_box_seal", move(get_crypto_box_seal));

    auto get_crypto_box_seal_open = Function::createFromHostFunction(jsiRuntime,
                                                                     PropNameID::forAscii(jsiRuntime,
                                                                                          "crypto_box_seal_open"),
                                                                                          4,
                                                                                          [](Runtime &runtime,
                                                                                                  const Value &thisValue,
                                                                                                  const Value *arguments,
                                                                                                  size_t count) -> Value {
        auto m = get_buffer(runtime, arguments[0], "m");
        auto c = get_buffer(runtime, arguments[1], "c");
        auto pk = get_buffer(runtime, arguments[2], "pk");
        auto sk = get_buffer(runtime, arguments[3], "sk");
        at_least_length(runtime, m, c.byteLength - crypto_box_SEALBYTES, "m");
        at_least_length(runtime, c, crypto_box_SEALBYTES, "c");
        validate_length(runtime, pk, crypto_box_PUBLICKEYBYTES, "pk");
        validate_length(runtime, sk, crypto_box_SECRETKEYBYTES, "sk");
        int out = crypto_box_seal_open(m.data, c.data, c.byteLength, pk.data, sk.data);
        if (!out) {
            return Value(true);
        }
        return Value(false);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_box_seal_open", move(get_crypto_box_seal_open));

    auto get_crypto_secretbox_MACBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                          PropNameID::forAscii(jsiRuntime,
                                                                                               "get_crypto_secretbox_MACBYTES"),
                                                                                               0,
                                                                                               [](Runtime &runtime,
                                                                                                       const Value &thisValue,
                                                                                                       const Value *arguments,
                                                                                                       size_t count) -> Value {
        return Value((double) crypto_secretbox_MACBYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_secretbox_MACBYTES", move(get_crypto_secretbox_MACBYTES));

    auto get_crypto_secretbox_NONCEBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                          PropNameID::forAscii(jsiRuntime,
                                                                                               "get_crypto_secretbox_NONCEBYTES"),
                                                                                               0,
                                                                                               [](Runtime &runtime,
                                                                                                       const Value &thisValue,
                                                                                                       const Value *arguments,
                                                                                                       size_t count) -> Value {
        return Value((double) crypto_secretbox_NONCEBYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_secretbox_NONCEBYTES", move(get_crypto_secretbox_NONCEBYTES));

    auto get_crypto_secretbox_KEYBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                          PropNameID::forAscii(jsiRuntime,
                                                                                               "get_crypto_secretbox_KEYBYTES"),
                                                                                               0,
                                                                                               [](Runtime &runtime,
                                                                                                       const Value &thisValue,
                                                                                                       const Value *arguments,
                                                                                                       size_t count) -> Value {
        return Value((double) crypto_secretbox_KEYBYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_secretbox_KEYBYTES", move(get_crypto_secretbox_KEYBYTES));

    auto get_crypto_secretbox_detached = Function::createFromHostFunction(jsiRuntime,
                                                                          PropNameID::forAscii(jsiRuntime,
                                                                                               "crypto_secretbox_detached"),
                                                                                               5,
                                                                                               [](Runtime &runtime,
                                                                                                       const Value &thisValue,
                                                                                                       const Value *arguments,
                                                                                                       size_t count) -> Value {
        auto c = get_buffer(runtime, arguments[0], "c");
        auto mac = get_buffer(runtime, arguments[1], "mac");
        auto m = get_buffer(runtime, arguments[2], "m");
        auto n = get_buffer(runtime, arguments[3], "n");
        auto k = get_buffer(runtime, arguments[4], "k");
        validate_length(runtime, c, m.byteLength, "c");
        validate_length(runtime, mac, crypto_secretbox_MACBYTES, "mac");
        validate_length(runtime, n, crypto_secretbox_NONCEBYTES, "n");
        validate_length(runtime, k, crypto_secretbox_KEYBYTES, "k");
        int out = crypto_secretbox_detached(c.data, mac.data, m.data, m.byteLength, n.data, k.data);
        if (!out) {
            return Value(true);
        }
        return Value(false);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_secretbox_detached", move(get_crypto_secretbox_detached));

    auto get_crypto_secretbox_easy = Function::createFromHostFunction(jsiRuntime,
                                                                      PropNameID::forAscii(jsiRuntime,
                                                                                 "crypto_secretbox_easy"),
                                                                                 4,
                                                                                 [](Runtime &runtime,
                                                                                         const Value &thisValue,
                                                                                         const Value *arguments,
                                                                                         size_t count) -> Value {
        auto c = get_buffer(runtime, arguments[0], "c");
        auto m = get_buffer(runtime, arguments[1], "m");
        auto n = get_buffer(runtime, arguments[2], "n");
        auto k = get_buffer(runtime, arguments[3], "k");
        validate_length(runtime, c, m.byteLength + crypto_secretbox_MACBYTES, "c");
        validate_length(runtime, n, crypto_secretbox_NONCEBYTES, "n");
        validate_length(runtime, k, crypto_secretbox_KEYBYTES, "k");
        int out = crypto_secretbox_easy(c.data, m.data, m.byteLength, n.data, k.data);
        if (!out) {
            return Value(true);
        }
        return Value(false);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_secretbox_easy", move(get_crypto_secretbox_easy));

    auto get_crypto_secretbox_open_detached = Function::createFromHostFunction(jsiRuntime,
                                                                               PropNameID::forAscii(jsiRuntime,
                                                                                                    "crypto_secretbox_open_detached"),
                                                                                                    5,
                                                                                                    [](Runtime &runtime,
                                                                                                            const Value &thisValue,
                                                                                                            const Value *arguments,
                                                                                                            size_t count) -> Value {
        auto m = get_buffer(runtime, arguments[0], "m");
        auto c = get_buffer(runtime, arguments[1], "c");
        auto mac = get_buffer(runtime, arguments[2], "mac");
        auto n = get_buffer(runtime, arguments[3], "n");
        auto k = get_buffer(runtime, arguments[4], "k");
        validate_length(runtime, m, c.byteLength, "m");
        validate_length(runtime, mac, crypto_secretbox_MACBYTES, "mac");
        validate_length(runtime, n, crypto_secretbox_NONCEBYTES, "n");
        validate_length(runtime, k, crypto_secretbox_KEYBYTES, "k");
        int out = crypto_secretbox_open_detached(m.data, c.data, mac.data, c.byteLength, n.data, k.data);
        if (!out) {
            return Value(true);
        }
        return Value(false);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_secretbox_open_detached", move(get_crypto_secretbox_open_detached));

    auto get_crypto_secretbox_open_easy = Function::createFromHostFunction(jsiRuntime,
                                                                           PropNameID::forAscii(jsiRuntime,
                                                                                                "crypto_secretbox_open_easy"),
                                                                                                4,
                                                                                                [](Runtime &runtime,
                                                                                                        const Value &thisValue,
                                                                                                        const Value *arguments,
                                                                                                        size_t count) -> Value {
        auto m = get_buffer(runtime, arguments[0], "m");
        auto c = get_buffer(runtime, arguments[1], "c");
        auto n = get_buffer(runtime, arguments[2], "n");
        auto k = get_buffer(runtime, arguments[3], "k");
        validate_length(runtime, m, c.byteLength - crypto_secretbox_MACBYTES, "m");
        at_least_length(runtime, c, crypto_secretbox_MACBYTES, "c");
        validate_length(runtime, n, crypto_secretbox_NONCEBYTES, "n");
        validate_length(runtime, k, crypto_secretbox_KEYBYTES, "k");
        int out = crypto_secretbox_open_easy(m.data, c.data, c.byteLength, n.data, k.data);
        if (!out) {
            return Value(true);
        }
        return Value(false);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_secretbox_open_easy", move(get_crypto_secretbox_open_easy));

    auto get_crypto_aead_xchacha20poly1305_ietf_ABYTES = Function::createFromHostFunction(jsiRuntime,
                                                                                          PropNameID::forAscii(jsiRuntime,
                                                                                                               "get_crypto_aead_xchacha20poly1305_ietf_ABYTES"),
                                                                                                               0,
                                                                                                               [](Runtime &runtime,
                                                                                                                       const Value &thisValue,
                                                                                                                       const Value *arguments,
                                                                                                                       size_t count) -> Value {
        return Value((double) crypto_aead_xchacha20poly1305_ietf_ABYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_aead_xchacha20poly1305_ietf_ABYTES", move(get_crypto_aead_xchacha20poly1305_ietf_ABYTES));

    auto get_crypto_aead_chacha20poly1305_IETF_ABYTES = Function::createFromHostFunction(jsiRuntime,
                                                                                          PropNameID::forAscii(jsiRuntime,
                                                                                                               "get_crypto_aead_chacha20poly1305_IETF_ABYTES"),
                                                                                                               0,
                                                                                                               [](Runtime &runtime,
                                                                                                                       const Value &thisValue,
                                                                                                                       const Value *arguments,
                                                                                                                       size_t count) -> Value {
        return Value((double) crypto_aead_chacha20poly1305_IETF_ABYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_aead_chacha20poly1305_ietf_ABYTES", move(get_crypto_aead_chacha20poly1305_IETF_ABYTES));

    auto get_crypto_aead_xchacha20poly1305_ietf_KEYBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                                          PropNameID::forAscii(jsiRuntime,
                                                                                                               "get_crypto_aead_xchacha20poly1305_ietf_KEYBYTES"),
                                                                                                               0,
                                                                                                               [](Runtime &runtime,
                                                                                                                       const Value &thisValue,
                                                                                                                       const Value *arguments,
                                                                                                                       size_t count) -> Value {
        return Value((double) crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_aead_xchacha20poly1305_ietf_KEYBYTES", move(get_crypto_aead_xchacha20poly1305_ietf_KEYBYTES));

    auto get_crypto_aead_chacha20poly1305_IETF_KEYBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                                          PropNameID::forAscii(jsiRuntime,
                                                                                                               "get_crypto_aead_chacha20poly1305_IETF_KEYBYTES"),
                                                                                                               0,
                                                                                                               [](Runtime &runtime,
                                                                                                                       const Value &thisValue,
                                                                                                                       const Value *arguments,
                                                                                                                       size_t count) -> Value {
        return Value((double) crypto_aead_chacha20poly1305_IETF_KEYBYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_aead_chacha20poly1305_ietf_KEYBYTES", move(get_crypto_aead_chacha20poly1305_IETF_KEYBYTES));

    auto get_crypto_aead_xchacha20poly1305_ietf_NPUBBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                                          PropNameID::forAscii(jsiRuntime,
                                                                                                               "get_crypto_aead_xchacha20poly1305_ietf_NPUBBYTES"),
                                                                                                               0,
                                                                                                               [](Runtime &runtime,
                                                                                                                       const Value &thisValue,
                                                                                                                       const Value *arguments,
                                                                                                                       size_t count) -> Value {
        return Value((double) crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_aead_xchacha20poly1305_ietf_NPUBBYTES", move(get_crypto_aead_xchacha20poly1305_ietf_NPUBBYTES));

    auto get_crypto_aead_chacha20poly1305_IETF_NPUBBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                                          PropNameID::forAscii(jsiRuntime,
                                                                                                               "get_crypto_aead_chacha20poly1305_IETF_NPUBBYTES"),
                                                                                                               0,
                                                                                                               [](Runtime &runtime,
                                                                                                                       const Value &thisValue,
                                                                                                                       const Value *arguments,
                                                                                                                       size_t count) -> Value {
        return Value((double) crypto_aead_chacha20poly1305_IETF_NPUBBYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_aead_chacha20poly1305_ietf_NPUBBYTES", move(get_crypto_aead_chacha20poly1305_IETF_NPUBBYTES));

    auto get_crypto_aead_xchacha20poly1305_ietf_NSECBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                                          PropNameID::forAscii(jsiRuntime,
                                                                                                               "get_crypto_aead_xchacha20poly1305_ietf_NSECBYTES"),
                                                                                                               0,
                                                                                                               [](Runtime &runtime,
                                                                                                                       const Value &thisValue,
                                                                                                                       const Value *arguments,
                                                                                                                       size_t count) -> Value {
        return Value((double) crypto_aead_xchacha20poly1305_ietf_NSECBYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_aead_xchacha20poly1305_ietf_NSECBYTES", move(get_crypto_aead_xchacha20poly1305_ietf_NSECBYTES));

    auto get_crypto_aead_chacha20poly1305_ietf_NSECBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                                          PropNameID::forAscii(jsiRuntime,
                                                                                                               "get_crypto_aead_chacha20poly1305_ietf_NSECBYTES"),
                                                                                                               0,
                                                                                                               [](Runtime &runtime,
                                                                                                                       const Value &thisValue,
                                                                                                                       const Value *arguments,
                                                                                                                       size_t count) -> Value {
        return Value((double) crypto_aead_chacha20poly1305_ietf_NSECBYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_aead_chacha20poly1305_ietf_NSECBYTES", move(get_crypto_aead_chacha20poly1305_ietf_NSECBYTES));

    auto get_crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX = Function::createFromHostFunction(jsiRuntime,
                                                                                          PropNameID::forAscii(jsiRuntime,
                                                                                                               "get_crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX"),
                                                                                                               0,
                                                                                                               [](Runtime &runtime,
                                                                                                                       const Value &thisValue,
                                                                                                                       const Value *arguments,
                                                                                                                       size_t count) -> Value {
        return Value((double) crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX", move(get_crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX));

    auto get_crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX = Function::createFromHostFunction(jsiRuntime,
                                                                                          PropNameID::forAscii(jsiRuntime,
                                                                                                               "get_crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX"),
                                                                                                               0,
                                                                                                               [](Runtime &runtime,
                                                                                                                       const Value &thisValue,
                                                                                                                       const Value *arguments,
                                                                                                                       size_t count) -> Value {
        return Value((double) crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX", move(get_crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX));

    auto get_crypto_aead_xchacha20poly1305_ietf_keygen = Function::createFromHostFunction(jsiRuntime,
                                                                                          PropNameID::forAscii(jsiRuntime,
                                                                                                               "crypto_aead_xchacha20poly1305_ietf_keygen"),
                                                                                                               1,
                                                                                                               [](Runtime &runtime,
                                                                                                                       const Value &thisValue,
                                                                                                                       const Value *arguments,
                                                                                                                       size_t count) -> Value {
        auto k = get_buffer(runtime, arguments[0], "k");
        validate_length(runtime, k, crypto_aead_xchacha20poly1305_ietf_KEYBYTES, "k");
        crypto_aead_xchacha20poly1305_ietf_keygen(k.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_aead_xchacha20poly1305_ietf_keygen", move(get_crypto_aead_xchacha20poly1305_ietf_keygen));

    auto get_crypto_aead_chacha20poly1305_ietf_keygen = Function::createFromHostFunction(jsiRuntime,
                                                                                          PropNameID::forAscii(jsiRuntime,
                                                                                                               "crypto_aead_chacha20poly1305_ietf_keygen"),
                                                                                                               1,
                                                                                                               [](Runtime &runtime,
                                                                                                                       const Value &thisValue,
                                                                                                                       const Value *arguments,
                                                                                                                       size_t count) -> Value {
        auto k = get_buffer(runtime, arguments[0], "k");
        validate_length(runtime, k, crypto_aead_chacha20poly1305_ietf_KEYBYTES, "k");
        crypto_aead_chacha20poly1305_ietf_keygen(k.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_aead_chacha20poly1305_ietf_keygen", move(get_crypto_aead_chacha20poly1305_ietf_keygen));

    auto get_crypto_aead_xchacha20poly1305_ietf_encrypt = Function::createFromHostFunction(jsiRuntime,
                                                                                           PropNameID::forAscii(jsiRuntime,
                                                                                                                "crypto_aead_xchacha20poly1305_ietf_encrypt"),
                                                                                                                6,
                                                                                                                [](Runtime &runtime,
                                                                                                                        const Value &thisValue,
                                                                                                                        const Value *arguments,
                                                                                                                        size_t count) -> Value {
        auto c = get_buffer(runtime, arguments[0], "c");
        auto m = get_buffer(runtime, arguments[1], "m");
        unsigned long long int clen;
        validate_length(runtime, c, m.byteLength + crypto_aead_xchacha20poly1305_ietf_ABYTES, "c");
        if (arguments[2].isNull() && arguments[5].isUndefined()) {
            auto ad = nullptr;
            auto npub = get_buffer(runtime, arguments[3], "npub");
            auto k = get_buffer(runtime, arguments[4], "k");
            validate_length(runtime, npub, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, "npub");
            validate_length(runtime, k, crypto_aead_xchacha20poly1305_ietf_KEYBYTES, "k");
            int out = crypto_aead_xchacha20poly1305_ietf_encrypt(c.data, &clen, m.data, m.byteLength,
                                                                 ad, 0, nullptr, npub.data, k.data);
            if (!out) {
                return Value((double) clen);
            }
        } else {
            if (arguments[2].isNull()) {
                auto ad = nullptr;
                auto npub = get_buffer(runtime, arguments[4], "npub");
                auto k = get_buffer(runtime, arguments[5], "k");
                validate_length(runtime, npub, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
                                "npub");
                validate_length(runtime, k, crypto_aead_xchacha20poly1305_ietf_KEYBYTES, "k");
                int out = crypto_aead_xchacha20poly1305_ietf_encrypt(c.data, &clen,
                                                                     m.data,
                                                                     m.byteLength,
                                                                     ad, 0, nullptr,
                                                                     npub.data,
                                                                     k.data);
                if (!out) {
                    return Value((double) clen);
                }
            } else {
                auto ad = get_buffer(runtime, arguments[2], "ad");
                auto npub = get_buffer(runtime, arguments[4], "npub");
                auto k = get_buffer(runtime, arguments[5], "k");
                validate_length(runtime, npub, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, "npub");
                validate_length(runtime, k, crypto_aead_xchacha20poly1305_ietf_KEYBYTES, "k");
                int out = crypto_aead_xchacha20poly1305_ietf_encrypt(c.data, &clen,
                                                                     m.data,
                                                                     m.byteLength,
                                                                     ad.data,
                                                                     ad.byteLength,
                                                                     nullptr,
                                                                     npub.data,
                                                                     k.data);
                if (!out) {
                    return Value((double) clen);
                }
            }
        }
        return Value(0);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_aead_xchacha20poly1305_ietf_encrypt", move(get_crypto_aead_xchacha20poly1305_ietf_encrypt));

    auto get_crypto_aead_chacha20poly1305_ietf_encrypt = Function::createFromHostFunction(jsiRuntime,
                                                                                           PropNameID::forAscii(jsiRuntime,
                                                                                                                "crypto_aead_chacha20poly1305_ietf_encrypt"),
                                                                                                                6,
                                                                                                                [](Runtime &runtime,
                                                                                                                        const Value &thisValue,
                                                                                                                        const Value *arguments,
                                                                                                                        size_t count) -> Value {
        auto c = get_buffer(runtime, arguments[0], "c");
        auto m = get_buffer(runtime, arguments[1], "m");
        unsigned long long int clen;
        validate_length(runtime, c, m.byteLength + crypto_aead_chacha20poly1305_ietf_ABYTES, "c");
        if (arguments[2].isNull() && arguments[5].isUndefined()) {
            auto ad = nullptr;
            auto npub = get_buffer(runtime, arguments[3], "npub");
            auto k = get_buffer(runtime, arguments[4], "k");
            validate_length(runtime, npub, crypto_aead_chacha20poly1305_ietf_NPUBBYTES, "npub");
            validate_length(runtime, k, crypto_aead_chacha20poly1305_ietf_KEYBYTES, "k");
            int out = crypto_aead_chacha20poly1305_ietf_encrypt(c.data, &clen, m.data, m.byteLength,
                                                                 ad, 0, nullptr, npub.data, k.data);
            if (!out) {
                return Value((double) clen);
            }
        } else {
            if (arguments[2].isNull()) {
                auto ad = nullptr;
                auto npub = get_buffer(runtime, arguments[4], "npub");
                auto k = get_buffer(runtime, arguments[5], "k");
                validate_length(runtime, npub, crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
                                "npub");
                validate_length(runtime, k, crypto_aead_chacha20poly1305_ietf_KEYBYTES, "k");
                int out = crypto_aead_chacha20poly1305_ietf_encrypt(c.data, &clen,
                                                                     m.data,
                                                                     m.byteLength,
                                                                     ad, 0, nullptr,
                                                                     npub.data,
                                                                     k.data);
                if (!out) {
                    return Value((double) clen);
                }
            } else {
                auto ad = get_buffer(runtime, arguments[2], "ad");
                auto npub = get_buffer(runtime, arguments[4], "npub");
                auto k = get_buffer(runtime, arguments[5], "k");
                validate_length(runtime, npub, crypto_aead_chacha20poly1305_ietf_NPUBBYTES, "npub");
                validate_length(runtime, k, crypto_aead_chacha20poly1305_ietf_KEYBYTES, "k");
                int out = crypto_aead_chacha20poly1305_ietf_encrypt(c.data, &clen,
                                                                     m.data,
                                                                     m.byteLength,
                                                                     ad.data,
                                                                     ad.byteLength,
                                                                     nullptr,
                                                                     npub.data,
                                                                     k.data);
                if (!out) {
                    return Value((double) clen);
                }
            }
        }
        return Value(0);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_aead_chacha20poly1305_ietf_encrypt", move(get_crypto_aead_chacha20poly1305_ietf_encrypt));

    auto get_crypto_aead_xchacha20poly1305_ietf_decrypt = Function::createFromHostFunction(jsiRuntime,
                                                                                           PropNameID::forAscii(jsiRuntime,
                                                                                                                "crypto_aead_xchacha20poly1305_ietf_decrypt"),
                                                                                                                6,
                                                                                                                [](Runtime &runtime,
                                                                                                                        const Value &thisValue,
                                                                                                                        const Value *arguments,
                                                                                                                        size_t count) -> Value {
        auto m = get_buffer(runtime, arguments[0], "m");
        auto nsec = nullptr;
        auto c = get_buffer(runtime, arguments[2], "c");
        unsigned long long int mlen;
        validate_length(runtime, m, c.byteLength - crypto_aead_xchacha20poly1305_ietf_ABYTES, "m");
        if (arguments[5].isUndefined()) {
            auto ad = nullptr;
            auto npub = get_buffer(runtime, arguments[3], "npub");
            auto k = get_buffer(runtime, arguments[4], "k");
            validate_length(runtime, npub, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, "npub");
            validate_length(runtime, k, crypto_aead_xchacha20poly1305_ietf_KEYBYTES, "k");
            int out = crypto_aead_xchacha20poly1305_ietf_decrypt(m.data, &mlen, nsec,
                                                                 c.data, c.byteLength,
                                                                 ad, 0, npub.data,
                                                                 k.data);
            if (!out) {
                return Value((double) mlen);
            }
        } else {
            if (arguments[3].isNull()) {
                auto ad = nullptr;
                auto npub = get_buffer(runtime, arguments[4], "npub");
                auto k = get_buffer(runtime, arguments[5], "k");
                validate_length(runtime, npub, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, "npub");
                validate_length(runtime, k, crypto_aead_xchacha20poly1305_ietf_KEYBYTES, "k");
                int out = crypto_aead_xchacha20poly1305_ietf_decrypt(m.data, &mlen, nsec,
                                                                     c.data, c.byteLength,
                                                                     ad, 0, npub.data,
                                                                     k.data);
                if (!out) {
                    return Value((double) mlen);
                }
            } else {
                auto ad = get_buffer(runtime, arguments[3], "ad");
                auto npub = get_buffer(runtime, arguments[4], "npub");
                auto k = get_buffer(runtime, arguments[5], "k");
                validate_length(runtime, npub, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, "npub");
                validate_length(runtime, k, crypto_aead_xchacha20poly1305_ietf_KEYBYTES, "k");
                int out = crypto_aead_xchacha20poly1305_ietf_decrypt(m.data, &mlen, nsec,
                                                                     c.data, c.byteLength,
                                                                     ad.data, ad.byteLength,
                                                                     npub.data, k.data);
                if (!out) {
                    return Value((double) mlen);
                }
            }
        }
        return Value(0);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_aead_xchacha20poly1305_ietf_decrypt", move(get_crypto_aead_xchacha20poly1305_ietf_decrypt));

    auto get_crypto_aead_chacha20poly1305_ietf_decrypt = Function::createFromHostFunction(jsiRuntime,
                                                                                           PropNameID::forAscii(jsiRuntime,
                                                                                                                "crypto_aead_chacha20poly1305_ietf_decrypt"),
                                                                                                                6,
                                                                                                                [](Runtime &runtime,
                                                                                                                        const Value &thisValue,
                                                                                                                        const Value *arguments,
                                                                                                                        size_t count) -> Value {
        auto m = get_buffer(runtime, arguments[0], "m");
        auto nsec = nullptr;
        auto c = get_buffer(runtime, arguments[2], "c");
        unsigned long long int mlen;
        validate_length(runtime, m, c.byteLength - crypto_aead_chacha20poly1305_ietf_ABYTES, "m");
        if (arguments[5].isUndefined()) {
            auto ad = nullptr;
            auto npub = get_buffer(runtime, arguments[3], "npub");
            auto k = get_buffer(runtime, arguments[4], "k");
            validate_length(runtime, npub, crypto_aead_chacha20poly1305_ietf_NPUBBYTES, "npub");
            validate_length(runtime, k, crypto_aead_chacha20poly1305_ietf_KEYBYTES, "k");
            int out = crypto_aead_chacha20poly1305_ietf_decrypt(m.data, &mlen, nsec,
                                                                 c.data, c.byteLength,
                                                                 ad, 0, npub.data,
                                                                 k.data);
            if (!out) {
                return Value((double) mlen);
            }
        } else {
            if (arguments[3].isNull()) {
                auto ad = nullptr;
                auto npub = get_buffer(runtime, arguments[4], "npub");
                auto k = get_buffer(runtime, arguments[5], "k");
                validate_length(runtime, npub, crypto_aead_chacha20poly1305_ietf_NPUBBYTES, "npub");
                validate_length(runtime, k, crypto_aead_chacha20poly1305_ietf_KEYBYTES, "k");
                int out = crypto_aead_chacha20poly1305_ietf_decrypt(m.data, &mlen, nsec,
                                                                     c.data, c.byteLength,
                                                                     ad, 0, npub.data,
                                                                     k.data);
                if (!out) {
                    return Value((double) mlen);
                }
            } else {
                auto ad = get_buffer(runtime, arguments[3], "ad");
                auto npub = get_buffer(runtime, arguments[4], "npub");
                auto k = get_buffer(runtime, arguments[5], "k");
                validate_length(runtime, npub, crypto_aead_chacha20poly1305_ietf_NPUBBYTES, "npub");
                validate_length(runtime, k, crypto_aead_chacha20poly1305_ietf_KEYBYTES, "k");
                int out = crypto_aead_chacha20poly1305_ietf_decrypt(m.data, &mlen, nsec,
                                                                     c.data, c.byteLength,
                                                                     ad.data, ad.byteLength,
                                                                     npub.data, k.data);
                if (!out) {
                    return Value((double) mlen);
                }
            }
        }
        throw JSError(runtime, "Verification failed");
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_aead_chacha20poly1305_ietf_decrypt", move(get_crypto_aead_chacha20poly1305_ietf_decrypt));

    auto get_crypto_aead_xchacha20poly1305_ietf_encrypt_detached = Function::createFromHostFunction(jsiRuntime,
                                                                                                PropNameID::forAscii(jsiRuntime,
                                                                                                                     "crypto_aead_xchacha20poly1305_ietf_encrypt_detached"),
                                                                                                                     7,
                                                                                                                     [](Runtime &runtime,
                                                                                                                             const Value &thisValue,
                                                                                                                             const Value *arguments,
                                                                                                                             size_t count) -> Value {
        auto c = get_buffer(runtime, arguments[0], "c");
        auto mac = get_buffer(runtime, arguments[1], "mac");
        auto m = get_buffer(runtime, arguments[2], "m");
        validate_length(runtime, c, m.byteLength, "c");
        validate_length(runtime, mac, crypto_aead_xchacha20poly1305_ietf_ABYTES, "mac");
        auto nsec = nullptr;
        unsigned long long int maclen;
        if (arguments[3].isNull() && arguments[6].isUndefined()) {
            auto ad = nullptr;
            auto npub = get_buffer(runtime, arguments[4], "npub");
            auto k = get_buffer(runtime, arguments[5], "k");
            validate_length(runtime, npub, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, "npub");
            validate_length(runtime, k, crypto_aead_xchacha20poly1305_ietf_KEYBYTES, "k");
            int out = crypto_aead_xchacha20poly1305_ietf_encrypt_detached(c.data, mac.data, &maclen,
                                                                          m.data, m.byteLength,
                                                                          ad, 0, nsec,
                                                                          npub.data, k.data);
            if (!out) {
                return Value((double) maclen);
            }
        } else {
            if (arguments[3].isNull()) {
                auto ad = nullptr;
                auto npub = get_buffer(runtime, arguments[5], "npub");
                auto k = get_buffer(runtime, arguments[6], "k");
                validate_length(runtime, npub, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, "npub");
                validate_length(runtime, k, crypto_aead_xchacha20poly1305_ietf_KEYBYTES, "k");
                int out = crypto_aead_xchacha20poly1305_ietf_encrypt_detached(c.data, mac.data, &maclen,
                                                                              m.data, m.byteLength,
                                                                              ad, 0, nsec,
                                                                              npub.data, k.data);
                if (!out) {
                    return Value((double) maclen);
                }
            } else {
                auto ad = get_buffer(runtime, arguments[3], "ad");
                auto npub = get_buffer(runtime, arguments[5], "npub");
                auto k = get_buffer(runtime, arguments[6], "k");
                validate_length(runtime, npub, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, "npub");
                validate_length(runtime, k, crypto_aead_xchacha20poly1305_ietf_KEYBYTES, "k");
                int out = crypto_aead_xchacha20poly1305_ietf_encrypt_detached(c.data, mac.data, &maclen,
                                                                              m.data, m.byteLength,
                                                                              ad.data, ad.byteLength, nsec,
                                                                              npub.data, k.data);
                if (!out) {
                    return Value((double) maclen);
                }
            }
        }
        return Value(0);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_aead_xchacha20poly1305_ietf_encrypt_detached", move(get_crypto_aead_xchacha20poly1305_ietf_encrypt_detached));

    auto get_crypto_aead_chacha20poly1305_ietf_encrypt_detached = Function::createFromHostFunction(jsiRuntime,
                                                                                                PropNameID::forAscii(jsiRuntime,
                                                                                                                     "crypto_aead_chacha20poly1305_ietf_encrypt_detached"),
                                                                                                                     7,
                                                                                                                     [](Runtime &runtime,
                                                                                                                             const Value &thisValue,
                                                                                                                             const Value *arguments,
                                                                                                                             size_t count) -> Value {
        auto c = get_buffer(runtime, arguments[0], "c");
        auto mac = get_buffer(runtime, arguments[1], "mac");
        auto m = get_buffer(runtime, arguments[2], "m");
        validate_length(runtime, c, m.byteLength, "c");
        validate_length(runtime, mac, crypto_aead_chacha20poly1305_ietf_ABYTES, "mac");
        auto nsec = nullptr;
        unsigned long long int maclen;
        if (arguments[3].isNull() && arguments[6].isUndefined()) {
            auto ad = nullptr;
            auto npub = get_buffer(runtime, arguments[4], "npub");
            auto k = get_buffer(runtime, arguments[5], "k");
            validate_length(runtime, npub, crypto_aead_chacha20poly1305_ietf_NPUBBYTES, "npub");
            validate_length(runtime, k, crypto_aead_chacha20poly1305_ietf_KEYBYTES, "k");
            int out = crypto_aead_chacha20poly1305_ietf_encrypt_detached(c.data, mac.data, &maclen,
                                                                          m.data, m.byteLength,
                                                                          ad, 0, nsec,
                                                                          npub.data, k.data);
            if (!out) {
                return Value((double) maclen);
            }
        } else {
            if (arguments[3].isNull()) {
                auto ad = nullptr;
                auto npub = get_buffer(runtime, arguments[5], "npub");
                auto k = get_buffer(runtime, arguments[6], "k");
                validate_length(runtime, npub, crypto_aead_chacha20poly1305_ietf_NPUBBYTES, "npub");
                validate_length(runtime, k, crypto_aead_chacha20poly1305_ietf_KEYBYTES, "k");
                int out = crypto_aead_chacha20poly1305_ietf_encrypt_detached(c.data, mac.data, &maclen,
                                                                              m.data, m.byteLength,
                                                                              ad, 0, nsec,
                                                                              npub.data, k.data);
                if (!out) {
                    return Value((double) maclen);
                }
            } else {
                auto ad = get_buffer(runtime, arguments[3], "ad");
                auto npub = get_buffer(runtime, arguments[5], "npub");
                auto k = get_buffer(runtime, arguments[6], "k");
                validate_length(runtime, npub, crypto_aead_chacha20poly1305_ietf_NPUBBYTES, "npub");
                validate_length(runtime, k, crypto_aead_chacha20poly1305_ietf_KEYBYTES, "k");
                int out = crypto_aead_chacha20poly1305_ietf_encrypt_detached(c.data, mac.data, &maclen,
                                                                              m.data, m.byteLength,
                                                                              ad.data, ad.byteLength, nsec,
                                                                              npub.data, k.data);
                if (!out) {
                    return Value((double) maclen);
                }
            }
        }
        return Value(0);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_aead_chacha20poly1305_ietf_encrypt_detached", move(get_crypto_aead_chacha20poly1305_ietf_encrypt_detached));

    auto get_crypto_aead_xchacha20poly1305_ietf_decrypt_detached = Function::createFromHostFunction(jsiRuntime,
                                                                                                    PropNameID::forAscii(jsiRuntime,
                                                                                                                         "crypto_aead_xchacha20poly1305_ietf_decrypt_detached"),
                                                                                                                         7,
                                                                                                                         [](Runtime &runtime,
                                                                                                                                 const Value &thisValue,
                                                                                                                                 const Value *arguments,
                                                                                                                                 size_t count) -> Value {
        auto m = get_buffer(runtime, arguments[0], "m");
        auto nsec = nullptr;
        auto c = get_buffer(runtime, arguments[2], "c");
        auto mac = get_buffer(runtime, arguments[3], "mac");
        validate_length(runtime, m, c.byteLength, "m");
        validate_length(runtime, mac, crypto_aead_xchacha20poly1305_ietf_ABYTES, "mac");
        if (arguments[6].isUndefined()) {
            auto ad = nullptr;
            auto npub = get_buffer(runtime, arguments[4], "npub");
            auto k = get_buffer(runtime, arguments[5], "k");
            validate_length(runtime, npub, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, "npub");
            validate_length(runtime, k, crypto_aead_xchacha20poly1305_ietf_KEYBYTES, "k");
            int out = crypto_aead_xchacha20poly1305_ietf_decrypt_detached(m.data, nsec,
                                                                          c.data, c.byteLength,
                                                                          mac.data, ad, 0,
                                                                          npub.data, k.data);
            if (out != 0) {
                throw JSError(runtime, "Authentication Error");
            }
        } else {
            if (arguments[4].isNull()) {
                auto ad = nullptr;
                auto npub = get_buffer(runtime, arguments[5], "npub");
                auto k = get_buffer(runtime, arguments[6], "k");
                validate_length(runtime, npub, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, "npub");
                validate_length(runtime, k, crypto_aead_xchacha20poly1305_ietf_KEYBYTES, "k");
                int out = crypto_aead_xchacha20poly1305_ietf_decrypt_detached(m.data, nsec,
                                                                              c.data, c.byteLength,
                                                                              mac.data, ad, 0,
                                                                              npub.data, k.data);
                if (out != 0) {
                    throw JSError(runtime, "Authentication Error");
                }
            } else {
                auto ad = get_buffer(runtime, arguments[4], "ad");
                auto npub = get_buffer(runtime, arguments[5], "npub");
                auto k = get_buffer(runtime, arguments[6], "k");
                validate_length(runtime, npub, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, "npub");
                validate_length(runtime, k, crypto_aead_xchacha20poly1305_ietf_KEYBYTES, "k");
                int out = crypto_aead_xchacha20poly1305_ietf_decrypt_detached(m.data, nsec,
                                                                              c.data, c.byteLength,
                                                                              mac.data,
                                                                              ad.data, ad.byteLength,
                                                                              npub.data, k.data);
                if (out != 0) {
                    throw JSError(runtime, "Authentication Error");
                }
            }
        }
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_aead_xchacha20poly1305_ietf_decrypt_detached", move(get_crypto_aead_xchacha20poly1305_ietf_decrypt_detached));

    auto get_crypto_aead_chacha20poly1305_ietf_decrypt_detached = Function::createFromHostFunction(jsiRuntime,
                                                                                                    PropNameID::forAscii(jsiRuntime,
                                                                                                                         "crypto_aead_chacha20poly1305_ietf_decrypt_detached"),
                                                                                                                         7,
                                                                                                                         [](Runtime &runtime,
                                                                                                                                 const Value &thisValue,
                                                                                                                                 const Value *arguments,
                                                                                                                                 size_t count) -> Value {
        auto m = get_buffer(runtime, arguments[0], "m");
        auto nsec = nullptr;
        auto c = get_buffer(runtime, arguments[2], "c");
        auto mac = get_buffer(runtime, arguments[3], "mac");
        validate_length(runtime, m, c.byteLength, "m");
        validate_length(runtime, mac, crypto_aead_chacha20poly1305_ietf_ABYTES, "mac");
        if (arguments[6].isUndefined()) {
            auto ad = nullptr;
            auto npub = get_buffer(runtime, arguments[4], "npub");
            auto k = get_buffer(runtime, arguments[5], "k");
            validate_length(runtime, npub, crypto_aead_chacha20poly1305_ietf_NPUBBYTES, "npub");
            validate_length(runtime, k, crypto_aead_chacha20poly1305_ietf_KEYBYTES, "k");
            int out = crypto_aead_chacha20poly1305_ietf_decrypt_detached(m.data, nsec,
                                                                          c.data, c.byteLength,
                                                                          mac.data, ad, 0,
                                                                          npub.data, k.data);
            if (out != 0) {
                throw JSError(runtime, "Authentication Error");
            }
        } else {
            if (arguments[4].isNull()) {
                auto ad = nullptr;
                auto npub = get_buffer(runtime, arguments[5], "npub");
                auto k = get_buffer(runtime, arguments[6], "k");
                validate_length(runtime, npub, crypto_aead_chacha20poly1305_ietf_NPUBBYTES, "npub");
                validate_length(runtime, k, crypto_aead_chacha20poly1305_ietf_KEYBYTES, "k");
                int out = crypto_aead_chacha20poly1305_ietf_decrypt_detached(m.data, nsec,
                                                                              c.data, c.byteLength,
                                                                              mac.data, ad, 0,
                                                                              npub.data, k.data);
                if (out != 0) {
                    throw JSError(runtime, "Authentication Error");
                }
            } else {
                auto ad = get_buffer(runtime, arguments[4], "ad");
                auto npub = get_buffer(runtime, arguments[5], "npub");
                auto k = get_buffer(runtime, arguments[6], "k");
                validate_length(runtime, npub, crypto_aead_chacha20poly1305_ietf_NPUBBYTES, "npub");
                validate_length(runtime, k, crypto_aead_chacha20poly1305_ietf_KEYBYTES, "k");
                int out = crypto_aead_chacha20poly1305_ietf_decrypt_detached(m.data, nsec,
                                                                              c.data, c.byteLength,
                                                                              mac.data,
                                                                              ad.data, ad.byteLength,
                                                                              npub.data, k.data);
                if (out != 0) {
                    throw JSError(runtime, "Authentication Error");
                }
            }
        }
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_aead_chacha20poly1305_ietf_decrypt_detached", move(get_crypto_aead_chacha20poly1305_ietf_decrypt_detached));

    auto get_crypto_stream_NONCEBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                         PropNameID::forAscii(jsiRuntime,
                                                                                              "get_crypto_stream_NONCEBYTES"),
                                                                                              0,
                                                                                              [](Runtime &runtime,
                                                                                                      const Value &thisValue,
                                                                                                      const Value *arguments,
                                                                                                      size_t count) -> Value {
        return Value((double) crypto_stream_NONCEBYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_stream_NONCEBYTES", move(get_crypto_stream_NONCEBYTES));

    auto get_crypto_stream_KEYBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                         PropNameID::forAscii(jsiRuntime,
                                                                                              "get_crypto_stream_KEYBYTES"),
                                                                                              0,
                                                                                              [](Runtime &runtime,
                                                                                                      const Value &thisValue,
                                                                                                      const Value *arguments,
                                                                                                      size_t count) -> Value {
        return Value((double) crypto_stream_KEYBYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_stream_KEYBYTES", move(get_crypto_stream_KEYBYTES));

    auto get_crypto_stream_chacha20_NONCEBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                         PropNameID::forAscii(jsiRuntime,
                                                                                              "get_crypto_stream_chacha20_NONCEBYTES"),
                                                                                              0,
                                                                                              [](Runtime &runtime,
                                                                                                      const Value &thisValue,
                                                                                                      const Value *arguments,
                                                                                                      size_t count) -> Value {
        return Value((double) crypto_stream_chacha20_NONCEBYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_stream_chacha20_NONCEBYTES", move(get_crypto_stream_chacha20_NONCEBYTES));

    auto get_crypto_stream_chacha20_KEYBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                         PropNameID::forAscii(jsiRuntime,
                                                                                              "get_crypto_stream_chacha20_KEYBYTES"),
                                                                                              0,
                                                                                              [](Runtime &runtime,
                                                                                                      const Value &thisValue,
                                                                                                      const Value *arguments,
                                                                                                      size_t count) -> Value {
        return Value((double) crypto_stream_chacha20_KEYBYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_stream_chacha20_KEYBYTES", move(get_crypto_stream_chacha20_KEYBYTES));

    auto get_crypto_stream_chacha20_ietf_NONCEBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                         PropNameID::forAscii(jsiRuntime,
                                                                                              "get_crypto_stream_chacha20_ietf_NONCEBYTES"),
                                                                                              0,
                                                                                              [](Runtime &runtime,
                                                                                                      const Value &thisValue,
                                                                                                      const Value *arguments,
                                                                                                      size_t count) -> Value {
        return Value((double) crypto_stream_chacha20_ietf_NONCEBYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_stream_chacha20_ietf_NONCEBYTES", move(get_crypto_stream_chacha20_ietf_NONCEBYTES));

    auto get_crypto_stream_chacha20_ietf_KEYBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                         PropNameID::forAscii(jsiRuntime,
                                                                                              "get_crypto_stream_chacha20_ietf_KEYBYTES"),
                                                                                              0,
                                                                                              [](Runtime &runtime,
                                                                                                      const Value &thisValue,
                                                                                                      const Value *arguments,
                                                                                                      size_t count) -> Value {
        return Value((double) crypto_stream_chacha20_ietf_KEYBYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_stream_chacha20_ietf_KEYBYTES", move(get_crypto_stream_chacha20_ietf_KEYBYTES));

    auto get_crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX = Function::createFromHostFunction(jsiRuntime,
                                                                         PropNameID::forAscii(jsiRuntime,
                                                                                              "get_crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX"),
                                                                                              0,
                                                                                              [](Runtime &runtime,
                                                                                                      const Value &thisValue,
                                                                                                      const Value *arguments,
                                                                                                      size_t count) -> Value {
        return Value((double) crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX", move(get_crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX));

    auto get_crypto_stream = Function::createFromHostFunction(jsiRuntime,
                                                              PropNameID::forAscii(jsiRuntime,
                                                                                   "crypto_stream"),
                                                                                   3,
                                                                                   [](Runtime &runtime,
                                                                                           const Value &thisValue,
                                                                                           const Value *arguments,
                                                                                           size_t count) -> Value {
        auto c = get_buffer(runtime, arguments[0], "c");
        auto n = get_buffer(runtime, arguments[1], "n");
        auto k = get_buffer(runtime, arguments[2], "k");
        validate_length(runtime, n, crypto_stream_NONCEBYTES, "n");
        validate_length(runtime, k, crypto_stream_KEYBYTES, "k");
        crypto_stream(c.data, c.byteLength, n.data, k.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_stream", move(get_crypto_stream));

    auto get_crypto_stream_xor = Function::createFromHostFunction(jsiRuntime,
                                                                  PropNameID::forAscii(jsiRuntime,
                                                                                       "crypto_stream_xor"),
                                                                                       4,
                                                                                       [](Runtime &runtime,
                                                                                               const Value &thisValue,
                                                                                               const Value *arguments,
                                                                                               size_t count) -> Value {
        auto c = get_buffer(runtime, arguments[0], "c");
        auto m = get_buffer(runtime, arguments[1], "m");
        auto n = get_buffer(runtime, arguments[2], "n");
        auto k = get_buffer(runtime, arguments[3], "k");
        validate_length(runtime, c, m.byteLength, "c");
        validate_length(runtime, n, crypto_stream_NONCEBYTES, "n");
        validate_length(runtime, k, crypto_stream_KEYBYTES, "k");
        crypto_stream_xor(c.data, m.data, m.byteLength, n.data, k.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_stream_xor", move(get_crypto_stream_xor));

    auto get_crypto_stream_chacha20_xor = Function::createFromHostFunction(jsiRuntime,
                                                                  PropNameID::forAscii(jsiRuntime,
                                                                                       "crypto_stream_chacha20_xor"),
                                                                                       4,
                                                                                       [](Runtime &runtime,
                                                                                               const Value &thisValue,
                                                                                               const Value *arguments,
                                                                                               size_t count) -> Value {
        auto c = get_buffer(runtime, arguments[0], "c");
        auto m = get_buffer(runtime, arguments[1], "m");
        auto n = get_buffer(runtime, arguments[2], "n");
        auto k = get_buffer(runtime, arguments[3], "k");
        validate_length(runtime, c, m.byteLength, "c");
        validate_length(runtime, n, crypto_stream_chacha20_NONCEBYTES, "n");
        validate_length(runtime, k, crypto_stream_chacha20_KEYBYTES, "k");
        crypto_stream_chacha20_xor(c.data, m.data, m.byteLength, n.data, k.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_stream_chacha20_xor", move(get_crypto_stream_chacha20_xor));

    auto get_crypto_stream_chacha20 = Function::createFromHostFunction(jsiRuntime,
                                                                       PropNameID::forAscii(jsiRuntime,
                                                                                            "crypto_stream_chacha20"),
                                                                                            3,
                                                                                            [](Runtime &runtime,
                                                                                                    const Value &thisValue,
                                                                                                    const Value *arguments,
                                                                                                    size_t count) -> Value {
        auto c = get_buffer(runtime, arguments[0], "c");
        auto n = get_buffer(runtime, arguments[1], "n");
        auto k = get_buffer(runtime, arguments[2], "k");
        validate_length(runtime, n, crypto_stream_chacha20_NONCEBYTES, "n");
        validate_length(runtime, k, crypto_stream_chacha20_KEYBYTES, "k");
        crypto_stream_chacha20(c.data, c.byteLength, n.data, k.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_stream_chacha20", move(get_crypto_stream_chacha20));

    auto get_crypto_stream_chacha20_xor_ic = Function::createFromHostFunction(jsiRuntime,
                                                                              PropNameID::forAscii(jsiRuntime,
                                                                                                   "crypto_stream_chacha20_xor_ic"),
                                                                                                   5,
                                                                                                   [](Runtime &runtime,
                                                                                                           const Value &thisValue,
                                                                                                           const Value *arguments,
                                                                                                           size_t count) -> Value {
        auto c = get_buffer(runtime, arguments[0], "c");
        auto m = get_buffer(runtime, arguments[1], "m");
        auto n = get_buffer(runtime, arguments[2], "n");
        unsigned int ic = arguments[3].getNumber();
        auto k = get_buffer(runtime, arguments[4], "k");
        validate_length(runtime, n, crypto_stream_chacha20_NONCEBYTES, "n");
        validate_length(runtime, k, crypto_stream_chacha20_KEYBYTES, "k");
        crypto_stream_chacha20_xor_ic(c.data, m.data, m.byteLength, n.data, ic, k.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_stream_chacha20_xor_ic", move(get_crypto_stream_chacha20_xor_ic));

    auto get_crypto_stream_chacha20_ietf_xor = Function::createFromHostFunction(jsiRuntime,
                                                                  PropNameID::forAscii(jsiRuntime,
                                                                                       "crypto_stream_chacha20_ietf_xor"),
                                                                                       4,
                                                                                       [](Runtime &runtime,
                                                                                               const Value &thisValue,
                                                                                               const Value *arguments,
                                                                                               size_t count) -> Value {
        auto c = get_buffer(runtime, arguments[0], "c");
        auto m = get_buffer(runtime, arguments[1], "m");
        auto n = get_buffer(runtime, arguments[2], "n");
        auto k = get_buffer(runtime, arguments[3], "k");
        validate_length(runtime, c, m.byteLength, "c");
        validate_length(runtime, n, crypto_stream_chacha20_ietf_NONCEBYTES, "n");
        validate_length(runtime, k, crypto_stream_chacha20_ietf_KEYBYTES, "k");
        crypto_stream_chacha20_ietf_xor(c.data, m.data, m.byteLength, n.data, k.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_stream_chacha20_ietf_xor", move(get_crypto_stream_chacha20_ietf_xor));

    auto get_crypto_stream_chacha20_ietf = Function::createFromHostFunction(jsiRuntime,
                                                                       PropNameID::forAscii(jsiRuntime,
                                                                                            "crypto_stream_chacha20_ietf"),
                                                                                            3,
                                                                                            [](Runtime &runtime,
                                                                                                    const Value &thisValue,
                                                                                                    const Value *arguments,
                                                                                                    size_t count) -> Value {
        auto c = get_buffer(runtime, arguments[0], "c");
        auto n = get_buffer(runtime, arguments[1], "n");
        auto k = get_buffer(runtime, arguments[2], "k");
        validate_length(runtime, n, crypto_stream_chacha20_ietf_NONCEBYTES, "n");
        validate_length(runtime, k, crypto_stream_chacha20_ietf_KEYBYTES, "k");
        crypto_stream_chacha20_ietf(c.data, c.byteLength, n.data, k.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_stream_chacha20_ietf", move(get_crypto_stream_chacha20_ietf));

    auto get_crypto_stream_chacha20_ietf_xor_ic = Function::createFromHostFunction(jsiRuntime,
                                                                              PropNameID::forAscii(jsiRuntime,
                                                                                                   "crypto_stream_chacha20_ietf_xor_ic"),
                                                                                                   5,
                                                                                                   [](Runtime &runtime,
                                                                                                           const Value &thisValue,
                                                                                                           const Value *arguments,
                                                                                                           size_t count) -> Value {
        auto c = get_buffer(runtime, arguments[0], "c");
        auto m = get_buffer(runtime, arguments[1], "m");
        auto n = get_buffer(runtime, arguments[2], "n");
        unsigned int ic = arguments[3].getNumber();
        auto k = get_buffer(runtime, arguments[4], "k");
        validate_length(runtime, n, crypto_stream_chacha20_ietf_NONCEBYTES, "n");
        validate_length(runtime, k, crypto_stream_chacha20_ietf_KEYBYTES, "k");
        crypto_stream_chacha20_ietf_xor_ic(c.data, m.data, m.byteLength, n.data, ic, k.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_stream_chacha20_ietf_xor_ic", move(get_crypto_stream_chacha20_ietf_xor_ic));

    auto get_crypto_auth_BYTES = Function::createFromHostFunction(jsiRuntime,
                                                                  PropNameID::forAscii(jsiRuntime,
                                                                                       "get_crypto_auth_BYTES"),
                                                                                       0,
                                                                                       [](Runtime &runtime,
                                                                                               const Value &thisValue,
                                                                                               const Value *arguments,
                                                                                               size_t count) -> Value {
        return Value((double) crypto_auth_BYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_auth_BYTES", move(get_crypto_auth_BYTES));

    auto get_crypto_auth_KEYBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                  PropNameID::forAscii(jsiRuntime,
                                                                                       "get_crypto_auth_KEYBYTES"),
                                                                                       0,
                                                                                       [](Runtime &runtime,
                                                                                               const Value &thisValue,
                                                                                               const Value *arguments,
                                                                                               size_t count) -> Value {
        return Value((double) crypto_auth_KEYBYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_auth_KEYBYTES", move(get_crypto_auth_KEYBYTES));

    auto get_crypto_auth = Function::createFromHostFunction(jsiRuntime,
                                                            PropNameID::forAscii(jsiRuntime,
                                                                                 "crypto_auth"),
                                                                                 3,
                                                                                 [](Runtime &runtime,
                                                                                         const Value &thisValue,
                                                                                         const Value *arguments,
                                                                                         size_t count) -> Value {
        auto out = get_buffer(runtime, arguments[0], "out");
        auto in = get_buffer(runtime, arguments[1], "in");
        auto k = get_buffer(runtime, arguments[2], "k");
        validate_length(runtime, out, crypto_auth_BYTES, "out");
        validate_length(runtime, k, crypto_auth_KEYBYTES, "k");
        crypto_auth(out.data, in.data, in.byteLength, k.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_auth", move(get_crypto_auth));

    auto get_crypto_auth_verify = Function::createFromHostFunction(jsiRuntime,
                                                                   PropNameID::forAscii(jsiRuntime,
                                                                                        "crypto_auth_verify"),
                                                                                        3,
                                                                                        [](Runtime &runtime,
                                                                                                const Value &thisValue,
                                                                                                const Value *arguments,
                                                                                                size_t count) -> Value {
        auto h = get_buffer(runtime, arguments[0], "h");
        auto in = get_buffer(runtime, arguments[1], "in");
        auto k = get_buffer(runtime, arguments[2], "k");
        validate_length(runtime, h, crypto_auth_BYTES, "h");
        validate_length(runtime, k, crypto_auth_KEYBYTES, "k");
        int out = crypto_auth_verify(h.data, in.data, in.byteLength, k.data);
        if (!out) {
            return Value(true);
        }
        return Value(false);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_auth_verify", move(get_crypto_auth_verify));

    auto get_crypto_secretstream_xchacha20poly1305_TAG_MESSAGE = Function::createFromHostFunction(jsiRuntime,
                                                                                                  PropNameID::forAscii(jsiRuntime,
                                                                                                                       "get_crypto_secretstream_xchacha20poly1305_TAG_MESSAGE"),
                                                                                                                       1,
                                                                                                                       [](Runtime &runtime,
                                                                                                                               const Value &thisValue,
                                                                                                                               const Value *arguments,
                                                                                                                               size_t count) -> Value {
        auto tag = get_buffer(runtime, arguments[0], "tag");
        tag.data[0] = crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_secretstream_xchacha20poly1305_TAG_MESSAGE", move(get_crypto_secretstream_xchacha20poly1305_TAG_MESSAGE));

    auto get_crypto_secretstream_xchacha20poly1305_TAG_PUSH = Function::createFromHostFunction(jsiRuntime,
                                                                                                  PropNameID::forAscii(jsiRuntime,
                                                                                                                       "get_crypto_secretstream_xchacha20poly1305_TAG_PUSH"),
                                                                                                                       1,
                                                                                                                       [](Runtime &runtime,
                                                                                                                               const Value &thisValue,
                                                                                                                               const Value *arguments,
                                                                                                                               size_t count) -> Value {
        auto tag = get_buffer(runtime, arguments[0], "tag");
        tag.data[0] = crypto_secretstream_xchacha20poly1305_TAG_PUSH;
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_secretstream_xchacha20poly1305_TAG_PUSH", move(get_crypto_secretstream_xchacha20poly1305_TAG_PUSH));

    auto get_crypto_secretstream_xchacha20poly1305_TAG_REKEY = Function::createFromHostFunction(jsiRuntime,
                                                                                                  PropNameID::forAscii(jsiRuntime,
                                                                                                                       "get_crypto_secretstream_xchacha20poly1305_TAG_REKEY"),
                                                                                                                       1,
                                                                                                                       [](Runtime &runtime,
                                                                                                                               const Value &thisValue,
                                                                                                                               const Value *arguments,
                                                                                                                               size_t count) -> Value {
        auto tag = get_buffer(runtime, arguments[0], "tag");
        tag.data[0] = crypto_secretstream_xchacha20poly1305_TAG_REKEY;
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_secretstream_xchacha20poly1305_TAG_REKEY", move(get_crypto_secretstream_xchacha20poly1305_TAG_REKEY));

    auto get_crypto_secretstream_xchacha20poly1305_TAG_FINAL = Function::createFromHostFunction(jsiRuntime,
                                                                                                  PropNameID::forAscii(jsiRuntime,
                                                                                                                       "get_crypto_secretstream_xchacha20poly1305_TAG_FINAL"),
                                                                                                                       1,
                                                                                                                       [](Runtime &runtime,
                                                                                                                               const Value &thisValue,
                                                                                                                               const Value *arguments,
                                                                                                                               size_t count) -> Value {
        auto tag = get_buffer(runtime, arguments[0], "tag");
        tag.data[0] = crypto_secretstream_xchacha20poly1305_TAG_FINAL;
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_secretstream_xchacha20poly1305_TAG_FINAL", move(get_crypto_secretstream_xchacha20poly1305_TAG_FINAL));

    auto get_crypto_secretstream_xchacha20poly1305_ABYTES = Function::createFromHostFunction(jsiRuntime,
                                                                                             PropNameID::forAscii(jsiRuntime,
                                                                                                                  "get_crypto_secretstream_xchacha20poly1305_ABYTES"),
                                                                                                                  0,
                                                                                                                  [](Runtime &runtime,
                                                                                                                          const Value &thisValue,
                                                                                                                          const Value *arguments,
                                                                                                                          size_t count) -> Value {
        return Value((double) crypto_secretstream_xchacha20poly1305_ABYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_secretstream_xchacha20poly1305_ABYTES", move(get_crypto_secretstream_xchacha20poly1305_ABYTES));

    auto get_crypto_secretstream_xchacha20poly1305_HEADERBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                                             PropNameID::forAscii(jsiRuntime,
                                                                                                                  "get_crypto_secretstream_xchacha20poly1305_HEADERBYTES"),
                                                                                                                  0,
                                                                                                                  [](Runtime &runtime,
                                                                                                                          const Value &thisValue,
                                                                                                                          const Value *arguments,
                                                                                                                          size_t count) -> Value {
        return Value((double) crypto_secretstream_xchacha20poly1305_HEADERBYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_secretstream_xchacha20poly1305_HEADERBYTES", move(get_crypto_secretstream_xchacha20poly1305_HEADERBYTES));

    auto get_crypto_secretstream_xchacha20poly1305_KEYBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                                             PropNameID::forAscii(jsiRuntime,
                                                                                                                  "get_crypto_secretstream_xchacha20poly1305_KEYBYTES"),
                                                                                                                  0,
                                                                                                                  [](Runtime &runtime,
                                                                                                                          const Value &thisValue,
                                                                                                                          const Value *arguments,
                                                                                                                          size_t count) -> Value {
        return Value((double) crypto_secretstream_xchacha20poly1305_KEYBYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_secretstream_xchacha20poly1305_KEYBYTES", move(get_crypto_secretstream_xchacha20poly1305_KEYBYTES));

    auto get_crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX = Function::createFromHostFunction(jsiRuntime,
                                                                                             PropNameID::forAscii(jsiRuntime,
                                                                                                                  "get_crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX"),
                                                                                                                  0,
                                                                                                                  [](Runtime &runtime,
                                                                                                                          const Value &thisValue,
                                                                                                                          const Value *arguments,
                                                                                                                          size_t count) -> Value {
        return Value((double) crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX", move(get_crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX));

    auto get_crypto_secretstream_xchacha20poly1305_STATEBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                                             PropNameID::forAscii(jsiRuntime,
                                                                                                                  "get_crypto_secretstream_xchacha20poly1305_STATEBYTES"),
                                                                                                                  0,
                                                                                                                  [](Runtime &runtime,
                                                                                                                          const Value &thisValue,
                                                                                                                          const Value *arguments,
                                                                                                                          size_t count) -> Value {
        return Value((double) crypto_secretstream_xchacha20poly1305_statebytes());
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_secretstream_xchacha20poly1305_STATEBYTES", move(get_crypto_secretstream_xchacha20poly1305_STATEBYTES));

    auto get_crypto_secretstream_xchacha20poly1305_keygen = Function::createFromHostFunction(jsiRuntime,
                                                                                             PropNameID::forAscii(jsiRuntime,
                                                                                                                  "crypto_secretstream_xchacha20poly1305_keygen"),
                                                                                                                  1,
                                                                                                                  [](Runtime &runtime,
                                                                                                                          const Value &thisValue,
                                                                                                                          const Value *arguments,
                                                                                                                          size_t count) -> Value {
        auto k = get_buffer(runtime, arguments[0], "k");
        validate_length(runtime, k, crypto_secretstream_xchacha20poly1305_KEYBYTES, "k");
        crypto_secretstream_xchacha20poly1305_keygen(k.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_secretstream_xchacha20poly1305_keygen", move(get_crypto_secretstream_xchacha20poly1305_keygen));

    auto get_crypto_secretstream_xchacha20poly1305_init_push = Function::createFromHostFunction(jsiRuntime,
                                                                                                PropNameID::forAscii(jsiRuntime,
                                                                                                                     "crypto_secretstream_xchacha20poly1305_init_push"),
                                                                                                                     3,
                                                                                                                     [](Runtime &runtime,
                                                                                                                             const Value &thisValue,
                                                                                                                             const Value *arguments,
                                                                                                                             size_t count) -> Value {
        auto state = get_buffer(runtime, arguments[0], "state");
        auto header = get_buffer(runtime, arguments[1], "header");
        auto k = get_buffer(runtime, arguments[2], "k");
        validate_length(runtime, state, crypto_secretstream_xchacha20poly1305_statebytes(), "state");
        validate_length(runtime, header, crypto_secretstream_xchacha20poly1305_HEADERBYTES, "header");
        validate_length(runtime, k, crypto_secretstream_xchacha20poly1305_KEYBYTES, "k");
        crypto_secretstream_xchacha20poly1305_init_push((crypto_secretstream_xchacha20poly1305_state *) state.data, header.data, k.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_secretstream_xchacha20poly1305_init_push", move(get_crypto_secretstream_xchacha20poly1305_init_push));

    auto get_crypto_secretstream_xchacha20poly1305_push = Function::createFromHostFunction(jsiRuntime,
                                                                                           PropNameID::forAscii(jsiRuntime,
                                                                                                                "crypto_secretstream_xchacha20poly1305_push"),
                                                                                                                5,
                                                                                                                [](Runtime &runtime,
                                                                                                                        const Value &thisValue,
                                                                                                                        const Value *arguments,
                                                                                                                        size_t count) -> Value {
        auto state = get_buffer(runtime, arguments[0], "state");
        auto c = get_buffer(runtime, arguments[1], "c");
        auto m = get_buffer(runtime, arguments[2], "m");
        unsigned long long int clen;
        validate_length(runtime, state, crypto_secretstream_xchacha20poly1305_statebytes(), "state");
        validate_length(runtime, c, m.byteLength + crypto_secretstream_xchacha20poly1305_ABYTES, "c");
        if (arguments[4].isUndefined()) {
            auto ad = nullptr;
            auto tagbuf = get_buffer(runtime, arguments[3], "tag");
            validate_length(runtime, tagbuf, 1, "tag");
            unsigned char tag = tagbuf.data[0];
            crypto_secretstream_xchacha20poly1305_push((crypto_secretstream_xchacha20poly1305_state *) state.data,
                                                       c.data, &clen,
                                                       m.data, m.byteLength,
                                                       ad, 0, tag);
        } else if (arguments[3].isNull()) {
            auto ad = nullptr;
            auto tagbuf = get_buffer(runtime, arguments[4], "tag");
            validate_length(runtime, tagbuf, 1, "tag");
            unsigned char tag = tagbuf.data[0];
            crypto_secretstream_xchacha20poly1305_push((crypto_secretstream_xchacha20poly1305_state *) state.data,
                                                       c.data, &clen,
                                                       m.data, m.byteLength,
                                                       ad, 0, tag);
        } else {
            auto ad = get_buffer(runtime, arguments[3], "ad");
            auto tagbuf = get_buffer(runtime, arguments[4], "tag");
            validate_length(runtime, tagbuf, 1, "tag");
            unsigned char tag = tagbuf.data[0];
            crypto_secretstream_xchacha20poly1305_push((crypto_secretstream_xchacha20poly1305_state *) state.data,
                                                       c.data, &clen,
                                                       m.data, m.byteLength,
                                                       ad.data, ad.byteLength, tag);
        }
        return Value((int) clen);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_secretstream_xchacha20poly1305_push", move(get_crypto_secretstream_xchacha20poly1305_push));

    auto get_crypto_secretstream_xchacha20poly1305_init_pull = Function::createFromHostFunction(jsiRuntime,
                                                                                                PropNameID::forAscii(jsiRuntime,
                                                                                                                     "crypto_secretstream_xchacha20poly1305_init_pull"),
                                                                                                                     3,
                                                                                                                     [](Runtime &runtime,
                                                                                                                             const Value &thisValue,
                                                                                                                             const Value *arguments,
                                                                                                                             size_t count) -> Value {
        auto state = get_buffer(runtime, arguments[0], "state");
        auto header = get_buffer(runtime, arguments[1], "header");
        auto k = get_buffer(runtime, arguments[2], "k");
        validate_length(runtime, state, crypto_secretstream_xchacha20poly1305_statebytes(), "state");
        validate_length(runtime, header, crypto_secretstream_xchacha20poly1305_HEADERBYTES, "header");
        validate_length(runtime, k, crypto_secretstream_xchacha20poly1305_KEYBYTES, "k");
        crypto_secretstream_xchacha20poly1305_init_pull((crypto_secretstream_xchacha20poly1305_state *) state.data, header.data, k.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_secretstream_xchacha20poly1305_init_pull", move(get_crypto_secretstream_xchacha20poly1305_init_pull));

    auto get_crypto_secretstream_xchacha20poly1305_pull = Function::createFromHostFunction(jsiRuntime,
                                                                                           PropNameID::forAscii(jsiRuntime,
                                                                                                                "crypto_secretstream_xchacha20poly1305_pull"),
                                                                                                                5,
                                                                                                                [](Runtime &runtime,
                                                                                                                        const Value &thisValue,
                                                                                                                        const Value *arguments,
                                                                                                                        size_t count) -> Value {
        auto state = get_buffer(runtime, arguments[0], "state");
        auto m = get_buffer(runtime, arguments[1], "m");
        auto tag = get_buffer(runtime, arguments[2], "tag");
        auto c = get_buffer(runtime, arguments[3], "c");
        unsigned long long int mlen;
        validate_length(runtime, state, crypto_secretstream_xchacha20poly1305_statebytes(), "state");
        validate_length(runtime, m, c.byteLength - crypto_secretstream_xchacha20poly1305_ABYTES, "m");
        validate_length(runtime, tag, 1, "tag");
        if (arguments[4].isNull() || arguments[4].isUndefined()) {
            auto ad = nullptr;
            crypto_secretstream_xchacha20poly1305_pull((crypto_secretstream_xchacha20poly1305_state *) state.data,
                                                       m.data, &mlen, tag.data,
                                                       c.data, c.byteLength,
                                                       ad, 0);
        } else {
            auto ad = get_buffer(runtime, arguments[4], "ad");
            crypto_secretstream_xchacha20poly1305_pull((crypto_secretstream_xchacha20poly1305_state *) state.data,
                                                       m.data, &mlen, tag.data,
                                                       c.data, c.byteLength,
                                                       ad.data, ad.byteLength);
        }
        return Value((int) mlen);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_secretstream_xchacha20poly1305_pull", move(get_crypto_secretstream_xchacha20poly1305_pull));

    auto get_crypto_secretstream_xchacha20poly1305_rekey = Function::createFromHostFunction(jsiRuntime,
                                                                                            PropNameID::forAscii(jsiRuntime,
                                                                                                                 "crypto_secretstream_xchacha20poly1305_rekey"),
                                                                                                                 1,
                                                                                                                 [](Runtime &runtime,
                                                                                                                         const Value &thisValue,
                                                                                                                         const Value *arguments,
                                                                                                                         size_t count) -> Value {
        auto state = get_buffer(runtime, arguments[0], "state");
        validate_length(runtime, state, crypto_secretstream_xchacha20poly1305_statebytes(), "state");
        crypto_secretstream_xchacha20poly1305_rekey((crypto_secretstream_xchacha20poly1305_state *) state.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_secretstream_xchacha20poly1305_rekey", move(get_crypto_secretstream_xchacha20poly1305_rekey));

    auto get_crypto_onetimeauth_BYTES = Function::createFromHostFunction(jsiRuntime,
                                                                         PropNameID::forAscii(jsiRuntime,
                                                                                              "get_crypto_onetimeauth_BYTES"),
                                                                                              0,
                                                                                              [](Runtime &runtime,
                                                                                                      const Value &thisValue,
                                                                                                      const Value *arguments,
                                                                                                      size_t count) -> Value {
        return Value((double) crypto_onetimeauth_BYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_onetimeauth_BYTES", move(get_crypto_onetimeauth_BYTES));

    auto get_crypto_onetimeauth_KEYBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                         PropNameID::forAscii(jsiRuntime,
                                                                                              "get_crypto_onetimeauth_KEYBYTES"),
                                                                                              0,
                                                                                              [](Runtime &runtime,
                                                                                                      const Value &thisValue,
                                                                                                      const Value *arguments,
                                                                                                      size_t count) -> Value {
        return Value((double) crypto_onetimeauth_KEYBYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_onetimeauth_KEYBYTES", move(get_crypto_onetimeauth_KEYBYTES));

    auto get_crypto_onetimeauth_STATEBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                         PropNameID::forAscii(jsiRuntime,
                                                                                              "get_crypto_onetimeauth_STATEBYTES"),
                                                                                              0,
                                                                                              [](Runtime &runtime,
                                                                                                      const Value &thisValue,
                                                                                                      const Value *arguments,
                                                                                                      size_t count) -> Value {
        return Value((double) crypto_onetimeauth_statebytes());
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_onetimeauth_STATEBYTES", move(get_crypto_onetimeauth_STATEBYTES));

    auto get_crypto_onetimeauth = Function::createFromHostFunction(jsiRuntime,
                                                                   PropNameID::forAscii(jsiRuntime,
                                                                                        "crypto_onetimeauth"),
                                                                                        3,
                                                                                        [](Runtime &runtime,
                                                                                                const Value &thisValue,
                                                                                                const Value *arguments,
                                                                                                size_t count) -> Value {
        auto out = get_buffer(runtime, arguments[0], "out");
        auto in = get_buffer(runtime, arguments[1], "in");
        auto k = get_buffer(runtime, arguments[2], "k");
        validate_length(runtime, out, crypto_onetimeauth_BYTES, "out");
        validate_length(runtime, k, crypto_onetimeauth_KEYBYTES, "k");
        crypto_onetimeauth(out.data, in.data, in.byteLength, k.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_onetimeauth", move(get_crypto_onetimeauth));

    auto get_crypto_onetimeauth_verify = Function::createFromHostFunction(jsiRuntime,
                                                                   PropNameID::forAscii(jsiRuntime,
                                                                                        "crypto_onetimeauth_verify"),
                                                                                        3,
                                                                                        [](Runtime &runtime,
                                                                                                const Value &thisValue,
                                                                                                const Value *arguments,
                                                                                                size_t count) -> Value {
        auto out = get_buffer(runtime, arguments[0], "out");
        auto in = get_buffer(runtime, arguments[1], "in");
        auto k = get_buffer(runtime, arguments[2], "k");
        validate_length(runtime, out, crypto_onetimeauth_BYTES, "out");
        validate_length(runtime, k, crypto_onetimeauth_KEYBYTES, "k");
        int o = crypto_onetimeauth_verify(out.data, in.data, in.byteLength, k.data);
        if (!o) {
            return Value(true);
        }
        return Value(false);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_onetimeauth_verify", move(get_crypto_onetimeauth_verify));

    auto get_crypto_onetimeauth_init = Function::createFromHostFunction(jsiRuntime,
                                                                        PropNameID::forAscii(jsiRuntime,
                                                                                             "crypto_onetimeauth_init"),
                                                                                             2,
                                                                                             [](Runtime &runtime,
                                                                                                     const Value &thisValue,
                                                                                                     const Value *arguments,
                                                                                                     size_t count) -> Value {
        auto state = get_buffer(runtime, arguments[0], "state");
        auto k = get_buffer(runtime, arguments[1], "k");
        validate_length(runtime, state, crypto_onetimeauth_statebytes(), "state");
        validate_length(runtime, k, crypto_onetimeauth_KEYBYTES, "k");
        crypto_onetimeauth_init((crypto_onetimeauth_state *) state.data, k.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_onetimeauth_init", move(get_crypto_onetimeauth_init));

    auto get_crypto_onetimeauth_update = Function::createFromHostFunction(jsiRuntime,
                                                                          PropNameID::forAscii(jsiRuntime,
                                                                                               "crypto_onetimeauth_update"),
                                                                                               2,
                                                                                               [](Runtime &runtime,
                                                                                                       const Value &thisValue,
                                                                                                       const Value *arguments,
                                                                                                       size_t count) -> Value {
        auto state = get_buffer(runtime, arguments[0], "state");
        auto in = get_buffer(runtime, arguments[1], "in");
        validate_length(runtime, state, crypto_onetimeauth_statebytes(), "state");
        crypto_onetimeauth_update((crypto_onetimeauth_state *) state.data, in.data, in.byteLength);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_onetimeauth_update", move(get_crypto_onetimeauth_update));

    auto get_crypto_onetimeauth_final = Function::createFromHostFunction(jsiRuntime,
                                                                         PropNameID::forAscii(jsiRuntime,
                                                                                              "crypto_onetimeauth_final"),
                                                                                              2,
                                                                                              [](Runtime &runtime,
                                                                                                      const Value &thisValue,
                                                                                                      const Value *arguments,
                                                                                                      size_t count) -> Value {
        auto state = get_buffer(runtime, arguments[0], "state");
        auto out = get_buffer(runtime, arguments[1], "out");
        validate_length(runtime, state, crypto_onetimeauth_statebytes(), "state");
        validate_length(runtime, out, crypto_onetimeauth_BYTES, "out");
        crypto_onetimeauth_final((crypto_onetimeauth_state *) state.data, out.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_onetimeauth_final", move(get_crypto_onetimeauth_final));

    auto get_crypto_pwhash_BYTES_MIN = Function::createFromHostFunction(jsiRuntime,
                                                                        PropNameID::forAscii(jsiRuntime,
                                                                                             "get_crypto_pwhash_BYTES_MIN"),
                                                                                             0,
                                                                                             [](Runtime &runtime,
                                                                                                     const Value &thisValue,
                                                                                                     const Value *arguments,
                                                                                                     size_t count) -> Value {
        return Value((double) crypto_pwhash_BYTES_MIN);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_pwhash_BYTES_MIN", move(get_crypto_pwhash_BYTES_MIN));

    auto get_crypto_pwhash_BYTES_MAX = Function::createFromHostFunction(jsiRuntime,
                                                                        PropNameID::forAscii(jsiRuntime,
                                                                                             "get_crypto_pwhash_BYTES_MAX"),
                                                                                             0,
                                                                                             [](Runtime &runtime,
                                                                                                     const Value &thisValue,
                                                                                                     const Value *arguments,
                                                                                                     size_t count) -> Value {
        return Value((double) crypto_pwhash_BYTES_MAX);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_pwhash_BYTES_MAX", move(get_crypto_pwhash_BYTES_MAX));

    auto get_crypto_pwhash_SALTBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                        PropNameID::forAscii(jsiRuntime,
                                                                                             "get_crypto_pwhash_SALTBYTES"),
                                                                                             0,
                                                                                             [](Runtime &runtime,
                                                                                                     const Value &thisValue,
                                                                                                     const Value *arguments,
                                                                                                     size_t count) -> Value {
        return Value((double) crypto_pwhash_SALTBYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_pwhash_SALTBYTES", move(get_crypto_pwhash_SALTBYTES));

    auto get_crypto_pwhash_STRBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                        PropNameID::forAscii(jsiRuntime,
                                                                                             "get_crypto_pwhash_STRBYTES"),
                                                                                             0,
                                                                                             [](Runtime &runtime,
                                                                                                     const Value &thisValue,
                                                                                                     const Value *arguments,
                                                                                                     size_t count) -> Value {
        return Value((double) crypto_pwhash_STRBYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_pwhash_STRBYTES", move(get_crypto_pwhash_STRBYTES));

    auto get_crypto_pwhash_OPSLIMIT_MIN = Function::createFromHostFunction(jsiRuntime,
                                                                        PropNameID::forAscii(jsiRuntime,
                                                                                             "get_crypto_pwhash_OPSLIMIT_MIN"),
                                                                                             0,
                                                                                             [](Runtime &runtime,
                                                                                                     const Value &thisValue,
                                                                                                     const Value *arguments,
                                                                                                     size_t count) -> Value {
        return Value((double) crypto_pwhash_OPSLIMIT_MIN);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_pwhash_OPSLIMIT_MIN", move(get_crypto_pwhash_OPSLIMIT_MIN));

    auto get_crypto_pwhash_OPSLIMIT_MAX = Function::createFromHostFunction(jsiRuntime,
                                                                        PropNameID::forAscii(jsiRuntime,
                                                                                             "get_crypto_pwhash_OPSLIMIT_MAX"),
                                                                                             0,
                                                                                             [](Runtime &runtime,
                                                                                                     const Value &thisValue,
                                                                                                     const Value *arguments,
                                                                                                     size_t count) -> Value {
        return Value((double) crypto_pwhash_OPSLIMIT_MAX);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_pwhash_OPSLIMIT_MAX", move(get_crypto_pwhash_OPSLIMIT_MAX));

    auto get_crypto_pwhash_MEMLIMIT_MIN = Function::createFromHostFunction(jsiRuntime,
                                                                        PropNameID::forAscii(jsiRuntime,
                                                                                             "get_crypto_pwhash_MEMLIMIT_MIN"),
                                                                                             0,
                                                                                             [](Runtime &runtime,
                                                                                                     const Value &thisValue,
                                                                                                     const Value *arguments,
                                                                                                     size_t count) -> Value {
        return Value((double) crypto_pwhash_MEMLIMIT_MIN);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_pwhash_MEMLIMIT_MIN", move(get_crypto_pwhash_MEMLIMIT_MIN));

    auto get_crypto_pwhash_MEMLIMIT_MAX = Function::createFromHostFunction(jsiRuntime,
                                                                        PropNameID::forAscii(jsiRuntime,
                                                                                             "get_crypto_pwhash_MEMLIMIT_MAX"),
                                                                                             0,
                                                                                             [](Runtime &runtime,
                                                                                                     const Value &thisValue,
                                                                                                     const Value *arguments,
                                                                                                     size_t count) -> Value {
        return Value((double) crypto_pwhash_MEMLIMIT_MAX);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_pwhash_MEMLIMIT_MAX", move(get_crypto_pwhash_MEMLIMIT_MAX));

    auto get_crypto_pwhash_STRPREFIX = Function::createFromHostFunction(jsiRuntime,
                                                                        PropNameID::forAscii(jsiRuntime,
                                                                                             "get_crypto_pwhash_STRPREFIX"),
                                                                                             0,
                                                                                             [](Runtime &runtime,
                                                                                                     const Value &thisValue,
                                                                                                     const Value *arguments,
                                                                                                     size_t count) -> Value {
        return Value(runtime, String::createFromUtf8(runtime, crypto_pwhash_STRPREFIX));
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_pwhash_STRPREFIX", move(get_crypto_pwhash_STRPREFIX));

    auto get_crypto_pwhash_ALG_ARGON2I13 = Function::createFromHostFunction(jsiRuntime,
                                                                        PropNameID::forAscii(jsiRuntime,
                                                                                             "get_crypto_pwhash_ALG_ARGON2I13"),
                                                                                             0,
                                                                                             [](Runtime &runtime,
                                                                                                     const Value &thisValue,
                                                                                                     const Value *arguments,
                                                                                                     size_t count) -> Value {
        return Value((double) crypto_pwhash_ALG_ARGON2I13);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_pwhash_ALG_ARGON2I13", move(get_crypto_pwhash_ALG_ARGON2I13));

    auto get_crypto_pwhash_ALG_ARGON2ID13 = Function::createFromHostFunction(jsiRuntime,
                                                                        PropNameID::forAscii(jsiRuntime,
                                                                                             "get_crypto_pwhash_ALG_ARGON2ID13"),
                                                                                             0,
                                                                                             [](Runtime &runtime,
                                                                                                     const Value &thisValue,
                                                                                                     const Value *arguments,
                                                                                                     size_t count) -> Value {
        return Value((double) crypto_pwhash_ALG_ARGON2ID13);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_pwhash_ALG_ARGON2ID13", move(get_crypto_pwhash_ALG_ARGON2ID13));

    auto get_crypto_pwhash_ALG_DEFAULT = Function::createFromHostFunction(jsiRuntime,
                                                                        PropNameID::forAscii(jsiRuntime,
                                                                                             "get_crypto_pwhash_ALG_DEFAULT"),
                                                                                             0,
                                                                                             [](Runtime &runtime,
                                                                                                     const Value &thisValue,
                                                                                                     const Value *arguments,
                                                                                                     size_t count) -> Value {
        return Value((double) crypto_pwhash_ALG_DEFAULT);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_pwhash_ALG_DEFAULT", move(get_crypto_pwhash_ALG_DEFAULT));

    auto get_crypto_pwhash_MEMLIMIT_INTERACTIVE = Function::createFromHostFunction(jsiRuntime,
                                                                        PropNameID::forAscii(jsiRuntime,
                                                                                             "get_crypto_pwhash_MEMLIMIT_INTERACTIVE"),
                                                                                             0,
                                                                                             [](Runtime &runtime,
                                                                                                     const Value &thisValue,
                                                                                                     const Value *arguments,
                                                                                                     size_t count) -> Value {
        return Value((double) crypto_pwhash_MEMLIMIT_INTERACTIVE);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_pwhash_MEMLIMIT_INTERACTIVE", move(get_crypto_pwhash_MEMLIMIT_INTERACTIVE));

    auto get_crypto_pwhash_MEMLIMIT_MODERATE = Function::createFromHostFunction(jsiRuntime,
                                                                        PropNameID::forAscii(jsiRuntime,
                                                                                             "get_crypto_pwhash_MEMLIMIT_MODERATE"),
                                                                                             0,
                                                                                             [](Runtime &runtime,
                                                                                                     const Value &thisValue,
                                                                                                     const Value *arguments,
                                                                                                     size_t count) -> Value {
        return Value((double) crypto_pwhash_MEMLIMIT_MODERATE);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_pwhash_MEMLIMIT_MODERATE", move(get_crypto_pwhash_MEMLIMIT_MODERATE));

    auto get_crypto_pwhash_MEMLIMIT_SENSITIVE = Function::createFromHostFunction(jsiRuntime,
                                                                        PropNameID::forAscii(jsiRuntime,
                                                                                             "get_crypto_pwhash_MEMLIMIT_SENSITIVE"),
                                                                                             0,
                                                                                             [](Runtime &runtime,
                                                                                                     const Value &thisValue,
                                                                                                     const Value *arguments,
                                                                                                     size_t count) -> Value {
        return Value((double) crypto_pwhash_MEMLIMIT_SENSITIVE);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_pwhash_MEMLIMIT_SENSITIVE", move(get_crypto_pwhash_MEMLIMIT_SENSITIVE));

    auto get_crypto_pwhash_OPSLIMIT_INTERACTIVE = Function::createFromHostFunction(jsiRuntime,
                                                                        PropNameID::forAscii(jsiRuntime,
                                                                                             "get_crypto_pwhash_OPSLIMIT_INTERACTIVE"),
                                                                                             0,
                                                                                             [](Runtime &runtime,
                                                                                                     const Value &thisValue,
                                                                                                     const Value *arguments,
                                                                                                     size_t count) -> Value {
        return Value((double) crypto_pwhash_OPSLIMIT_INTERACTIVE);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_pwhash_OPSLIMIT_INTERACTIVE", move(get_crypto_pwhash_OPSLIMIT_INTERACTIVE));

    auto get_crypto_pwhash_OPSLIMIT_MODERATE = Function::createFromHostFunction(jsiRuntime,
                                                                        PropNameID::forAscii(jsiRuntime,
                                                                                             "get_crypto_pwhash_OPSLIMIT_MODERATE"),
                                                                                             0,
                                                                                             [](Runtime &runtime,
                                                                                                     const Value &thisValue,
                                                                                                     const Value *arguments,
                                                                                                     size_t count) -> Value {
        return Value((double) crypto_pwhash_OPSLIMIT_MODERATE);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_pwhash_OPSLIMIT_MODERATE", move(get_crypto_pwhash_OPSLIMIT_MODERATE));

    auto get_crypto_pwhash_OPSLIMIT_SENSITIVE = Function::createFromHostFunction(jsiRuntime,
                                                                        PropNameID::forAscii(jsiRuntime,
                                                                                             "get_crypto_pwhash_OPSLIMIT_SENSITIVE"),
                                                                                             0,
                                                                                             [](Runtime &runtime,
                                                                                                     const Value &thisValue,
                                                                                                     const Value *arguments,
                                                                                                     size_t count) -> Value {
        return Value((double) crypto_pwhash_OPSLIMIT_SENSITIVE);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_pwhash_OPSLIMIT_SENSITIVE", move(get_crypto_pwhash_OPSLIMIT_SENSITIVE));

    auto get_crypto_pwhash_PASSWD_MIN = Function::createFromHostFunction(jsiRuntime,
                                                                        PropNameID::forAscii(jsiRuntime,
                                                                                             "get_crypto_pwhash_PASSWD_MIN"),
                                                                                             0,
                                                                                             [](Runtime &runtime,
                                                                                                     const Value &thisValue,
                                                                                                     const Value *arguments,
                                                                                                     size_t count) -> Value {
        return Value((double) crypto_pwhash_PASSWD_MIN);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_pwhash_PASSWD_MIN", move(get_crypto_pwhash_PASSWD_MIN));

    auto get_crypto_pwhash_PASSWD_MAX = Function::createFromHostFunction(jsiRuntime,
                                                                        PropNameID::forAscii(jsiRuntime,
                                                                                             "get_crypto_pwhash_PASSWD_MAX"),
                                                                                             0,
                                                                                             [](Runtime &runtime,
                                                                                                     const Value &thisValue,
                                                                                                     const Value *arguments,
                                                                                                     size_t count) -> Value {
        return Value((double) crypto_pwhash_PASSWD_MAX);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_pwhash_PASSWD_MAX", move(get_crypto_pwhash_PASSWD_MAX));

    auto get_crypto_pwhash = Function::createFromHostFunction(jsiRuntime,
                                                              PropNameID::forAscii(jsiRuntime,
                                                                                   "crypto_pwhash"),
                                                                                   6,
                                                                                   [](Runtime &runtime,
                                                                                           const Value &thisValue,
                                                                                           const Value *arguments,
                                                                                           size_t count) -> Value {
        auto out = get_buffer(runtime, arguments[0], "out");
        auto passwd = get_buffer(runtime, arguments[1], "passwd");
        auto salt = get_buffer(runtime, arguments[2], "salt");
        auto ops = arguments[3].isNumber() ? arguments[3].getNumber() : 0;
        auto mem = arguments[4].isNumber() ? arguments[4].getNumber() : 0;
        auto alg = arguments[5].isNumber() ? arguments[5].getNumber() : -1;
        at_least_length(runtime, out, crypto_pwhash_BYTES_MIN, "out");
        at_most_length(runtime, out, crypto_pwhash_BYTES_MAX, "out");
        validate_length(runtime, salt, crypto_pwhash_SALTBYTES, "salt");
        if (ops < crypto_pwhash_OPSLIMIT_MIN || ops > crypto_pwhash_OPSLIMIT_MAX) {
            throw JSError(runtime, "opslimit must be between crypto_pwhash_OPSLIMIT_MIN and crypto_pwhash_OPSLIMIT_MAX");
        }
        if (mem < crypto_pwhash_MEMLIMIT_MIN || mem > crypto_pwhash_MEMLIMIT_MAX) {
            throw JSError(runtime, "memlimit must be between crypto_pwhash_MEMLIMIT_MIN and crypto_pwhash_MEMLIMIT_MAX");
        }
        if (alg != crypto_pwhash_ALG_DEFAULT && alg != crypto_pwhash_ALG_ARGON2ID13 && alg != crypto_pwhash_ALG_ARGON2I13) {
            throw JSError(runtime, "alg must be one of crypto_pwhash_ALG_DEFAULT, crypto_pwhash_ALG_ARGON2ID13, crypto_pwhash_ALG_ARGON2I13");
        }
        int o = crypto_pwhash(out.data, out.byteLength, (char *) passwd.data, passwd.byteLength,
                      salt.data, ops, mem, alg);
        if (!o) {
            return Value(true);
        }
        return Value(false);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_pwhash", move(get_crypto_pwhash));

    auto get_crypto_pwhash_str = Function::createFromHostFunction(jsiRuntime,
                                                                  PropNameID::forAscii(jsiRuntime,
                                                                                       "crypto_pwhash_str"),
                                                                                       4,
                                                                                       [](Runtime &runtime,
                                                                                               const Value &thisValue,
                                                                                               const Value *arguments,
                                                                                               size_t count) -> Value {
        auto out = get_buffer(runtime, arguments[0], "out");
        auto passwd = get_buffer(runtime, arguments[1], "passwd");
        auto ops = arguments[2].isNumber() ? arguments[2].getNumber() : 0;
        auto mem = arguments[3].isNumber() ? arguments[3].getNumber() : 0;
        validate_length(runtime, out, crypto_pwhash_STRBYTES, "out");
        if (ops < crypto_pwhash_OPSLIMIT_MIN || ops > crypto_pwhash_OPSLIMIT_MAX) {
            throw JSError(runtime, "opslimit must be between crypto_pwhash_OPSLIMIT_MIN and crypto_pwhash_OPSLIMIT_MAX");
        }
        if (mem < crypto_pwhash_MEMLIMIT_MIN || mem > crypto_pwhash_MEMLIMIT_MAX) {
            throw JSError(runtime, "memlimit must be between crypto_pwhash_MEMLIMIT_MIN and crypto_pwhash_MEMLIMIT_MAX");
        }
        int o = crypto_pwhash_str((char *) out.data, (char *) passwd.data, passwd.byteLength, ops, mem);
        if (!o) {
            return Value(true);
        }
        return Value(false);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_pwhash_str", move(get_crypto_pwhash_str));

    auto get_crypto_pwhash_str_verify = Function::createFromHostFunction(jsiRuntime,
                                                                     PropNameID::forAscii(jsiRuntime,
                                                                                          "crypto_pwhash_str_verify"),
                                                                                          2,
                                                                                          [](Runtime &runtime,
                                                                                                  const Value &thisValue,
                                                                                                  const Value *arguments,
                                                                                                  size_t count) -> Value {
        auto str = get_buffer(runtime, arguments[0], "str");
        auto passwd = get_buffer(runtime, arguments[1], "passwd");
        validate_length(runtime, str, crypto_pwhash_STRBYTES, "str");
        int out = crypto_pwhash_str_verify((char *) str.data, (char *) passwd.data, passwd.byteLength);
        if (!out) {
            return Value(true);
        }
        return Value(false);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_pwhash_str_verify", move(get_crypto_pwhash_str_verify));

    auto get_crypto_pwhash_str_needs_rehash = Function::createFromHostFunction(jsiRuntime,
                                                                               PropNameID::forAscii(jsiRuntime,
                                                                                                    "crypto_pwhash_str_needs_rehash"),
                                                                                                    3,
                                                                                                    [](Runtime &runtime,
                                                                                                            const Value &thisValue,
                                                                                                            const Value *arguments,
                                                                                                            size_t count) -> Value {
        auto hash = get_buffer(runtime, arguments[0], "hash");
        auto ops = arguments[1].isNumber() ? arguments[1].getNumber() : 0;
        auto mem = arguments[2].isNumber() ? arguments[2].getNumber() : 0;
        validate_length(runtime, hash, crypto_pwhash_STRBYTES, "hash");
        if (ops < crypto_pwhash_OPSLIMIT_MIN || ops > crypto_pwhash_OPSLIMIT_MAX) {
            throw JSError(runtime, "opslimit must be between crypto_pwhash_OPSLIMIT_MIN and crypto_pwhash_OPSLIMIT_MAX");
        }
        if (mem < crypto_pwhash_MEMLIMIT_MIN || ops > crypto_pwhash_MEMLIMIT_MAX) {
            throw JSError(runtime, "memlimit must be between crypto_pwhash_MEMLIMIT_MIN and crypto_pwhash_MEMLIMIT_MAX");
        }
        int out = crypto_pwhash_str_needs_rehash((char  *) hash.data, ops, mem);
        if (!out) {
            return Value(true);
        }
        return Value(false);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_pwhash_str_needs_rehash", move(get_crypto_pwhash_str_needs_rehash));

    auto get_crypto_kx_PUBLICKEYBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                         PropNameID::forAscii(jsiRuntime,
                                                                                              "get_crypto_kx_PUBLICKEYBYTES"),
                                                                                              0,
                                                                                              [](Runtime &runtime,
                                                                                                      const Value &thisValue,
                                                                                                      const Value *arguments,
                                                                                                      size_t count) -> Value {
        return Value((double) crypto_kx_PUBLICKEYBYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_kx_PUBLICKEYBYTES", move(get_crypto_kx_PUBLICKEYBYTES));

    auto get_crypto_kx_SECRETKEYBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                         PropNameID::forAscii(jsiRuntime,
                                                                                              "get_crypto_kx_SECRETKEYBYTES"),
                                                                                              0,
                                                                                              [](Runtime &runtime,
                                                                                                      const Value &thisValue,
                                                                                                      const Value *arguments,
                                                                                                      size_t count) -> Value {
        return Value((double) crypto_kx_SECRETKEYBYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_kx_SECRETKEYBYTES", move(get_crypto_kx_SECRETKEYBYTES));

    auto get_crypto_kx_SEEDBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                         PropNameID::forAscii(jsiRuntime,
                                                                                              "get_crypto_kx_SEEDBYTES"),
                                                                                              0,
                                                                                              [](Runtime &runtime,
                                                                                                      const Value &thisValue,
                                                                                                      const Value *arguments,
                                                                                                      size_t count) -> Value {
        return Value((double) crypto_kx_SEEDBYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_kx_SEEDBYTES", move(get_crypto_kx_SEEDBYTES));

    auto get_crypto_kx_SESSIONKEYBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                         PropNameID::forAscii(jsiRuntime,
                                                                                              "get_crypto_kx_SESSIONKEYBYTES"),
                                                                                              0,
                                                                                              [](Runtime &runtime,
                                                                                                      const Value &thisValue,
                                                                                                      const Value *arguments,
                                                                                                      size_t count) -> Value {
        return Value((double) crypto_kx_SESSIONKEYBYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_kx_SESSIONKEYBYTES", move(get_crypto_kx_SESSIONKEYBYTES));

    auto get_crypto_kx_PRIMITIVE = Function::createFromHostFunction(jsiRuntime,
                                                                         PropNameID::forAscii(jsiRuntime,
                                                                                              "get_crypto_kx_PRIMITIVE"),
                                                                                              0,
                                                                                              [](Runtime &runtime,
                                                                                                      const Value &thisValue,
                                                                                                      const Value *arguments,
                                                                                                      size_t count) -> Value {
        return Value(runtime, String::createFromUtf8(runtime, crypto_kx_PRIMITIVE));
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_kx_PRIMITIVE", move(get_crypto_kx_PRIMITIVE));

    auto get_crypto_kx_keypair = Function::createFromHostFunction(jsiRuntime,
                                                                  PropNameID::forAscii(jsiRuntime,
                                                                                       "crypto_kx_keypair"),
                                                                                       2,
                                                                                       [](Runtime &runtime,
                                                                                               const Value &thisValue,
                                                                                               const Value *arguments,
                                                                                               size_t count) -> Value {
        auto pk = get_buffer(runtime, arguments[0], "pk");
        auto sk = get_buffer(runtime, arguments[1], "sk");
        validate_length(runtime, pk, crypto_kx_PUBLICKEYBYTES, "pk");
        validate_length(runtime, sk, crypto_kx_SECRETKEYBYTES, "sk");
        crypto_kx_keypair(pk.data, sk.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_kx_keypair", move(get_crypto_kx_keypair));

    auto get_crypto_kx_seed_keypair = Function::createFromHostFunction(jsiRuntime,
                                                                  PropNameID::forAscii(jsiRuntime,
                                                                                       "crypto_kx_seed_keypair"),
                                                                                       3,
                                                                                       [](Runtime &runtime,
                                                                                               const Value &thisValue,
                                                                                               const Value *arguments,
                                                                                               size_t count) -> Value {
        auto pk = get_buffer(runtime, arguments[0], "pk");
        auto sk = get_buffer(runtime, arguments[1], "sk");
        auto seed = get_buffer(runtime, arguments[2], "seed");
        validate_length(runtime, pk, crypto_kx_PUBLICKEYBYTES, "pk");
        validate_length(runtime, sk, crypto_kx_SECRETKEYBYTES, "sk");
        validate_length(runtime, seed, crypto_kx_SEEDBYTES, "seed");
        crypto_kx_seed_keypair(pk.data, sk.data, seed.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_kx_seed_keypair", move(get_crypto_kx_seed_keypair));

    auto get_crypto_kx_client_session_keys = Function::createFromHostFunction(jsiRuntime,
                                                                              PropNameID::forAscii(jsiRuntime,
                                                                                                   "crypto_kx_client_session_keys"),
                                                                                                   5,
                                                                                                   [](Runtime &runtime,
                                                                                                           const Value &thisValue,
                                                                                                           const Value *arguments,
                                                                                                           size_t count) -> Value {
        auto clientPk = get_buffer(runtime, arguments[2], "clientPk");
        auto clientSk = get_buffer(runtime, arguments[3], "clientSk");
        auto serverPk = get_buffer(runtime, arguments[4], "serverPk");
        validate_length(runtime, clientPk, crypto_kx_PUBLICKEYBYTES, "clientPk");
        validate_length(runtime, clientSk, crypto_kx_SECRETKEYBYTES, "clientSk");
        validate_length(runtime, serverPk, crypto_kx_PUBLICKEYBYTES, "serverPk");
        if (arguments[0].isNull() && arguments[1].isNull()) {
            throw JSError(runtime, "rx and tx can't both be null");
        }
        if (arguments[0].isNull()) {
            auto rx = nullptr;
            auto tx = get_buffer(runtime, arguments[1], "tx");
            validate_length(runtime, tx, crypto_kx_SESSIONKEYBYTES, "tx");
            int out = crypto_kx_client_session_keys(rx, tx.data, clientPk.data, clientSk.data, serverPk.data);
            if (!out) {
                return Value(true);
            }
        } else if (arguments[1].isNull()) {
            auto rx = get_buffer(runtime, arguments[0], "rx");
            auto tx = nullptr;
            validate_length(runtime, rx, crypto_kx_SESSIONKEYBYTES, "rx");
            int out = crypto_kx_client_session_keys(rx.data, tx, clientPk.data, clientSk.data, serverPk.data);
            if (!out) {
                return Value(true);
            }
        } else {
            auto rx = get_buffer(runtime, arguments[0], "rx");
            auto tx = get_buffer(runtime, arguments[1], "tx");
            validate_length(runtime, rx, crypto_kx_SESSIONKEYBYTES, "rx");
            validate_length(runtime, tx, crypto_kx_SESSIONKEYBYTES, "tx");
            int out = crypto_kx_client_session_keys(rx.data, tx.data, clientPk.data, clientSk.data, serverPk.data);
            if (!out) {
                return Value(true);
            }
        }
        return Value(false);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_kx_client_session_keys", move(get_crypto_kx_client_session_keys));

    auto get_crypto_kx_server_session_keys = Function::createFromHostFunction(jsiRuntime,
                                                                              PropNameID::forAscii(jsiRuntime,
                                                                                                   "crypto_kx_server_session_keys"),
                                                                                                   5,
                                                                                                   [](Runtime &runtime,
                                                                                                           const Value &thisValue,
                                                                                                           const Value *arguments,
                                                                                                           size_t count) -> Value {
        auto serverPk = get_buffer(runtime, arguments[2], "serverPk");
        auto serverSk = get_buffer(runtime, arguments[3], "serverSk");
        auto clientPk = get_buffer(runtime, arguments[4], "clientPk");
        validate_length(runtime, serverPk, crypto_kx_PUBLICKEYBYTES, "serverPk");
        validate_length(runtime, serverSk, crypto_kx_SECRETKEYBYTES, "serverSk");
        validate_length(runtime, clientPk, crypto_kx_PUBLICKEYBYTES, "clientPk");
        if (arguments[0].isNull() && arguments[1].isNull()) {
            throw JSError(runtime, "rx and tx can't both be null");
        }
        if (arguments[0].isNull()) {
            auto rx = nullptr;
            auto tx = get_buffer(runtime, arguments[1], "tx");
            validate_length(runtime, tx, crypto_kx_SESSIONKEYBYTES, "tx");
            int out = crypto_kx_server_session_keys(rx, tx.data, serverPk.data, serverSk.data, clientPk.data);
            if (!out) {
                return Value(true);
            }
        } else if (arguments[1].isNull()) {
            auto rx = get_buffer(runtime, arguments[0], "rx");
            auto tx = nullptr;
            validate_length(runtime, rx, crypto_kx_SESSIONKEYBYTES, "rx");
            int out = crypto_kx_server_session_keys(rx.data, tx, serverPk.data, serverSk.data, clientPk.data);
            if (!out) {
                return Value(true);
            }
        } else {
            auto rx = get_buffer(runtime, arguments[0], "rx");
            auto tx = get_buffer(runtime, arguments[1], "tx");
            validate_length(runtime, rx, crypto_kx_SESSIONKEYBYTES, "rx");
            validate_length(runtime, tx, crypto_kx_SESSIONKEYBYTES, "tx");
            int out = crypto_kx_server_session_keys(rx.data, tx.data, serverPk.data, serverSk.data, clientPk.data);
            if (!out) {
                return Value(true);
            }
        }
        return Value(false);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_kx_server_session_keys", move(get_crypto_kx_server_session_keys));

    auto get_crypto_scalarmult_BYTES = Function::createFromHostFunction(jsiRuntime,
                                                                        PropNameID::forAscii(jsiRuntime,
                                                                                             "get_crypto_scalarmult_BYTES"),
                                                                                             0,
                                                                                             [](Runtime &runtime,
                                                                                                     const Value &thisValue,
                                                                                                     const Value *arguments,
                                                                                                     size_t count) -> Value {
        return Value((double) crypto_scalarmult_BYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_scalarmult_BYTES", move(get_crypto_scalarmult_BYTES));

    auto get_crypto_scalarmult_SCALARBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                        PropNameID::forAscii(jsiRuntime,
                                                                                             "get_crypto_scalarmult_SCALARBYTES"),
                                                                                             0,
                                                                                             [](Runtime &runtime,
                                                                                                     const Value &thisValue,
                                                                                                     const Value *arguments,
                                                                                                     size_t count) -> Value {
        return Value((double) crypto_scalarmult_SCALARBYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_scalarmult_SCALARBYTES", move(get_crypto_scalarmult_SCALARBYTES));

    auto get_crypto_scalarmult_base = Function::createFromHostFunction(jsiRuntime,
                                                                       PropNameID::forAscii(jsiRuntime,
                                                                                            "crypto_scalarmult_base"),
                                                                                            2,
                                                                                            [](Runtime &runtime,
                                                                                                    const Value &thisValue,
                                                                                                    const Value *arguments,
                                                                                                    size_t count) -> Value {
        auto q = get_buffer(runtime, arguments[0], "q");
        auto n = get_buffer(runtime, arguments[1], "n");
        validate_length(runtime, q, crypto_scalarmult_BYTES, "q");
        validate_length(runtime, n, crypto_scalarmult_SCALARBYTES, "n");
        crypto_scalarmult_base(q.data, n.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_scalarmult_base", move(get_crypto_scalarmult_base));

    auto get_crypto_scalarmult = Function::createFromHostFunction(jsiRuntime,
                                                                  PropNameID::forAscii(jsiRuntime,
                                                                                       "crypto_scalarmult"),
                                                                                       3,
                                                                                       [](Runtime &runtime,
                                                                                               const Value &thisValue,
                                                                                               const Value *arguments,
                                                                                               size_t count) -> Value {
        auto q = get_buffer(runtime, arguments[0], "q");
        auto n = get_buffer(runtime, arguments[1], "n");
        auto p = get_buffer(runtime, arguments[2], "p");
        validate_length(runtime, q, crypto_scalarmult_BYTES, "q");
        validate_length(runtime, n, crypto_scalarmult_SCALARBYTES, "n");
        validate_length(runtime, p, crypto_scalarmult_BYTES, "p");
        int out = crypto_scalarmult(q.data, n.data, p.data);
        if (!out) {
            return Value(true);
        }
        return Value(false);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_scalarmult", move(get_crypto_scalarmult));

    auto get_crypto_scalarmult_ed25519_BYTES = Function::createFromHostFunction(jsiRuntime,
                                                                                PropNameID::forAscii(jsiRuntime,
                                                                                                     "get_crypto_scalarmult_ed25519_BYTES"),
                                                                                                     0,
                                                                                                     [](Runtime &runtime,
                                                                                                             const Value &thisValue,
                                                                                                             const Value *arguments,
                                                                                                             size_t count) -> Value {
        return Value((double) crypto_scalarmult_ed25519_BYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_scalarmult_ed25519_BYTES", move(get_crypto_scalarmult_ed25519_BYTES));

    auto get_crypto_scalarmult_ed25519_SCALARBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                                PropNameID::forAscii(jsiRuntime,
                                                                                                     "get_crypto_scalarmult_ed25519_SCALARBYTES"),
                                                                                                     0,
                                                                                                     [](Runtime &runtime,
                                                                                                             const Value &thisValue,
                                                                                                             const Value *arguments,
                                                                                                             size_t count) -> Value {
        return Value((double) crypto_scalarmult_ed25519_SCALARBYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_scalarmult_ed25519_SCALARBYTES", move(get_crypto_scalarmult_ed25519_SCALARBYTES));

    auto get_crypto_core_ed25519_BYTES = Function::createFromHostFunction(jsiRuntime,
                                                                                PropNameID::forAscii(jsiRuntime,
                                                                                                     "get_crypto_core_ed25519_BYTES"),
                                                                                                     0,
                                                                                                     [](Runtime &runtime,
                                                                                                             const Value &thisValue,
                                                                                                             const Value *arguments,
                                                                                                             size_t count) -> Value {
        return Value((double) crypto_core_ed25519_BYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_core_ed25519_BYTES", move(get_crypto_core_ed25519_BYTES));

    auto get_crypto_core_ed25519_UNIFORMBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                                PropNameID::forAscii(jsiRuntime,
                                                                                                     "get_crypto_core_ed25519_UNIFORMBYTES"),
                                                                                                     0,
                                                                                                     [](Runtime &runtime,
                                                                                                             const Value &thisValue,
                                                                                                             const Value *arguments,
                                                                                                             size_t count) -> Value {
        return Value((double) crypto_core_ed25519_UNIFORMBYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_core_ed25519_UNIFORMBYTES", move(get_crypto_core_ed25519_UNIFORMBYTES));

    auto get_crypto_core_ed25519_SCALARBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                                PropNameID::forAscii(jsiRuntime,
                                                                                                     "get_crypto_core_ed25519_SCALARBYTES"),
                                                                                                     0,
                                                                                                     [](Runtime &runtime,
                                                                                                             const Value &thisValue,
                                                                                                             const Value *arguments,
                                                                                                             size_t count) -> Value {
        return Value((double) crypto_core_ed25519_SCALARBYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_core_ed25519_SCALARBYTES", move(get_crypto_core_ed25519_SCALARBYTES));

    auto get_crypto_core_ed25519_NONREDUCEDSCALARBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                                PropNameID::forAscii(jsiRuntime,
                                                                                                     "get_crypto_core_ed25519_NONREDUCEDSCALARBYTES"),
                                                                                                     0,
                                                                                                     [](Runtime &runtime,
                                                                                                             const Value &thisValue,
                                                                                                             const Value *arguments,
                                                                                                             size_t count) -> Value {
        return Value((double) crypto_core_ed25519_NONREDUCEDSCALARBYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_core_ed25519_NONREDUCEDSCALARBYTES", move(get_crypto_core_ed25519_NONREDUCEDSCALARBYTES));

    auto get_crypto_scalarmult_PRIMITIVE = Function::createFromHostFunction(jsiRuntime,
                                                                                PropNameID::forAscii(jsiRuntime,
                                                                                                     "get_crypto_scalarmult_PRIMITIVE"),
                                                                                                     0,
                                                                                                     [](Runtime &runtime,
                                                                                                             const Value &thisValue,
                                                                                                             const Value *arguments,
                                                                                                             size_t count) -> Value {
        return Value(runtime, String::createFromUtf8(runtime, crypto_scalarmult_PRIMITIVE));
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_scalarmult_PRIMITIVE", move(get_crypto_scalarmult_PRIMITIVE));

    auto get_crypto_core_ed25519_is_valid_point = Function::createFromHostFunction(jsiRuntime,
                                                                                   PropNameID::forAscii(jsiRuntime,
                                                                                                        "crypto_core_ed25519_is_valid_point"),
                                                                                                        1,
                                                                                                        [](Runtime &runtime,
                                                                                                                const Value &thisValue,
                                                                                                                const Value *arguments,
                                                                                                                size_t count) -> Value {
        auto p = get_buffer(runtime, arguments[0], "p");
        validate_length(runtime, p, crypto_core_ed25519_BYTES, "p");
        int out = crypto_core_ed25519_is_valid_point(p.data);
        if (!out) {
            return Value(false);
        }
        return Value(true);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_core_ed25519_is_valid_point", move(get_crypto_core_ed25519_is_valid_point));

    auto get_crypto_core_ed25519_from_uniform = Function::createFromHostFunction(jsiRuntime,
                                                                                 PropNameID::forAscii(jsiRuntime,
                                                                                                      "crypto_core_ed25519_from_uniform"),
                                                                                                      2,
                                                                                                      [](Runtime &runtime,
                                                                                                              const Value &thisValue,
                                                                                                              const Value *arguments,
                                                                                                              size_t count) -> Value {
        auto p = get_buffer(runtime, arguments[0], "p");
        auto r = get_buffer(runtime, arguments[1], "r");
        validate_length(runtime, p, crypto_core_ed25519_BYTES, "p");
        validate_length(runtime, r, crypto_core_ed25519_UNIFORMBYTES, "r");
        crypto_core_ed25519_from_uniform(p.data, r.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_core_ed25519_from_uniform", move(get_crypto_core_ed25519_from_uniform));

    auto get_crypto_scalarmult_ed25519 = Function::createFromHostFunction(jsiRuntime,
                                                                          PropNameID::forAscii(jsiRuntime,
                                                                                               "crypto_scalarmult_ed25519"),
                                                                                               3,
                                                                                               [](Runtime &runtime,
                                                                                                       const Value &thisValue,
                                                                                                       const Value *arguments,
                                                                                                       size_t count) -> Value {
        auto q = get_buffer(runtime, arguments[0], "q");
        auto n = get_buffer(runtime, arguments[1], "n");
        auto p = get_buffer(runtime, arguments[2], "p");
        validate_length(runtime, q, crypto_scalarmult_ed25519_BYTES, "q");
        validate_length(runtime, n, crypto_scalarmult_ed25519_SCALARBYTES, "n");
        validate_length(runtime, p, crypto_scalarmult_ed25519_BYTES, "p");
        int out = crypto_scalarmult_ed25519(q.data, n.data, p.data);
        if (!out) {
            return Value::undefined();
        }
        throw JSError(runtime, "Invalid point");
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_scalarmult_ed25519", move(get_crypto_scalarmult_ed25519));

    auto get_crypto_scalarmult_ed25519_base = Function::createFromHostFunction(jsiRuntime,
                                                                               PropNameID::forAscii(jsiRuntime,
                                                                                                    "crypto_scalarmult_ed25519_base"),
                                                                                                    2,
                                                                                                    [](Runtime &runtime,
                                                                                                            const Value &thisValue,
                                                                                                            const Value *arguments,
                                                                                                            size_t count) -> Value {
        auto q = get_buffer(runtime, arguments[0], "q");
        auto n = get_buffer(runtime, arguments[1], "n");
        validate_length(runtime, q, crypto_scalarmult_ed25519_BYTES, "q");
        validate_length(runtime, n, crypto_scalarmult_ed25519_SCALARBYTES, "n");
        int out = crypto_scalarmult_ed25519_base(q.data, n.data);
        if (!out) {
            return Value::undefined();
        }
        throw JSError(runtime, "Invalid point");
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_scalarmult_ed25519_base", move(get_crypto_scalarmult_ed25519_base));

    auto get_crypto_scalarmult_ed25519_noclamp = Function::createFromHostFunction(jsiRuntime,
                                                                          PropNameID::forAscii(jsiRuntime,
                                                                                               "crypto_scalarmult_ed25519_noclamp"),
                                                                                               3,
                                                                                               [](Runtime &runtime,
                                                                                                       const Value &thisValue,
                                                                                                       const Value *arguments,
                                                                                                       size_t count) -> Value {
        auto q = get_buffer(runtime, arguments[0], "q");
        auto n = get_buffer(runtime, arguments[1], "n");
        auto p = get_buffer(runtime, arguments[2], "p");
        validate_length(runtime, q, crypto_scalarmult_ed25519_BYTES, "q");
        validate_length(runtime, n, crypto_scalarmult_ed25519_SCALARBYTES, "n");
        validate_length(runtime, p, crypto_scalarmult_ed25519_BYTES, "p");
        int out = crypto_scalarmult_ed25519_noclamp(q.data, n.data, p.data);
        if (!out) {
            return Value::undefined();
        }
        throw JSError(runtime, "Invalid point");
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_scalarmult_ed25519_noclamp", move(get_crypto_scalarmult_ed25519_noclamp));

    auto get_crypto_scalarmult_ed25519_base_noclamp = Function::createFromHostFunction(jsiRuntime,
                                                                               PropNameID::forAscii(jsiRuntime,
                                                                                                    "crypto_scalarmult_ed25519_base_noclamp"),
                                                                                                    2,
                                                                                                    [](Runtime &runtime,
                                                                                                            const Value &thisValue,
                                                                                                            const Value *arguments,
                                                                                                            size_t count) -> Value {
        auto q = get_buffer(runtime, arguments[0], "q");
        auto n = get_buffer(runtime, arguments[1], "n");
        validate_length(runtime, q, crypto_scalarmult_ed25519_BYTES, "q");
        validate_length(runtime, n, crypto_scalarmult_ed25519_SCALARBYTES, "n");
        int out = crypto_scalarmult_ed25519_base_noclamp(q.data, n.data);
        if (!out) {
            return Value::undefined();
        }
        throw JSError(runtime, "Invalid point");
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_scalarmult_ed25519_base_noclamp", move(get_crypto_scalarmult_ed25519_base_noclamp));

    auto get_crypto_core_ed25519_add = Function::createFromHostFunction(jsiRuntime,
                                                                        PropNameID::forAscii(jsiRuntime,
                                                                                             "crypto_core_ed25519_add"),
                                                                                             3,
                                                                                             [](Runtime &runtime,
                                                                                                     const Value &thisValue,
                                                                                                     const Value *arguments,
                                                                                                     size_t count) -> Value {
        auto r = get_buffer(runtime, arguments[0], "r");
        auto p = get_buffer(runtime, arguments[1], "p");
        auto q = get_buffer(runtime, arguments[2], "q");
        validate_length(runtime, r, crypto_core_ed25519_BYTES, "r");
        validate_length(runtime, p, crypto_core_ed25519_BYTES, "p");
        validate_length(runtime, q, crypto_core_ed25519_BYTES, "q");
        int out = crypto_core_ed25519_add(r.data, p.data, q.data);
        if (!out) {
            return Value::undefined();
        }
        throw JSError(runtime, "Invalid point");
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_core_ed25519_add", move(get_crypto_core_ed25519_add));

    auto get_crypto_core_ed25519_sub = Function::createFromHostFunction(jsiRuntime,
                                                                        PropNameID::forAscii(jsiRuntime,
                                                                                             "crypto_core_ed25519_sub"),
                                                                                             3,
                                                                                             [](Runtime &runtime,
                                                                                                     const Value &thisValue,
                                                                                                     const Value *arguments,
                                                                                                     size_t count) -> Value {
        auto r = get_buffer(runtime, arguments[0], "r");
        auto p = get_buffer(runtime, arguments[1], "p");
        auto q = get_buffer(runtime, arguments[2], "q");
        validate_length(runtime, r, crypto_core_ed25519_BYTES, "r");
        validate_length(runtime, p, crypto_core_ed25519_BYTES, "p");
        validate_length(runtime, q, crypto_core_ed25519_BYTES, "q");
        int out = crypto_core_ed25519_sub(r.data, p.data, q.data);
        if (!out) {
            return Value::undefined();
        }
        throw JSError(runtime, "Invalid point");
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_core_ed25519_sub", move(get_crypto_core_ed25519_sub));

    auto get_crypto_core_ed25519_scalar_random = Function::createFromHostFunction(jsiRuntime,
                                                                                  PropNameID::forAscii(jsiRuntime,
                                                                                                       "crypto_core_ed25519_scalar_random"),
                                                                                                       1,
                                                                                                       [] (Runtime &runtime,
                                                                                                               const Value &thisValue,
                                                                                                               const Value *arguments,
                                                                                                               size_t count) -> Value {
        auto r = get_buffer(runtime, arguments[0], "r");
        validate_length(runtime, r, crypto_core_ed25519_SCALARBYTES, "r");
        crypto_core_ed25519_scalar_random(r.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_core_ed25519_scalar_random", move(get_crypto_core_ed25519_scalar_random));

    auto get_crypto_core_ed25519_scalar_reduce = Function::createFromHostFunction(jsiRuntime,
                                                                                  PropNameID::forAscii(jsiRuntime,
                                                                                                       "crypto_core_ed25519_scalar_reduce"),
                                                                                                       2,
                                                                                                       [](Runtime &runtime,
                                                                                                               const Value &thisValue,
                                                                                                               const Value *arguments,
                                                                                                               size_t count) -> Value {
        auto r = get_buffer(runtime, arguments[0], "r");
        auto s = get_buffer(runtime, arguments[1], "s");
        validate_length(runtime, r, crypto_core_ed25519_SCALARBYTES, "r");
        validate_length(runtime, s, crypto_core_ed25519_NONREDUCEDSCALARBYTES, "s");
        crypto_core_ed25519_scalar_reduce(r.data, s.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_core_ed25519_scalar_reduce", move(get_crypto_core_ed25519_scalar_reduce));

    auto get_crypto_core_ed25519_scalar_invert = Function::createFromHostFunction(jsiRuntime,
                                                                                  PropNameID::forAscii(jsiRuntime,
                                                                                                       "crypto_core_ed25519_scalar_invert"),
                                                                                                       2,
                                                                                                       [](Runtime &runtime,
                                                                                                               const Value &thisValue,
                                                                                                               const Value *arguments,
                                                                                                               size_t count) -> Value {
        auto recip = get_buffer(runtime, arguments[0], "recip");
        auto s = get_buffer(runtime, arguments[1], "s");
        validate_length(runtime, recip, crypto_core_ed25519_SCALARBYTES, "recip");
        validate_length(runtime, s, crypto_core_ed25519_SCALARBYTES, "s");
        crypto_core_ed25519_scalar_invert(recip.data, s.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_core_ed25519_scalar_invert", move(get_crypto_core_ed25519_scalar_invert));

    auto get_crypto_core_ed25519_scalar_negate = Function::createFromHostFunction(jsiRuntime,
                                                                                  PropNameID::forAscii(jsiRuntime,
                                                                                                       "crypto_core_ed25519_scalar_negate"),
                                                                                                       2,
                                                                                                       [](Runtime &runtime,
                                                                                                               const Value &thisValue,
                                                                                                               const Value *arguments,
                                                                                                               size_t count) -> Value {
        auto neg = get_buffer(runtime, arguments[0], "neg");
        auto s = get_buffer(runtime, arguments[1], "s");
        validate_length(runtime, neg, crypto_core_ed25519_SCALARBYTES, "neg");
        validate_length(runtime, s, crypto_core_ed25519_SCALARBYTES, "s");
        crypto_core_ed25519_scalar_negate(neg.data, s.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_core_ed25519_scalar_negate", move(get_crypto_core_ed25519_scalar_negate));

    auto get_crypto_core_ed25519_scalar_complement = Function::createFromHostFunction(jsiRuntime,
                                                                                  PropNameID::forAscii(jsiRuntime,
                                                                                                       "crypto_core_ed25519_scalar_complement"),
                                                                                                       2,
                                                                                                       [](Runtime &runtime,
                                                                                                               const Value &thisValue,
                                                                                                               const Value *arguments,
                                                                                                               size_t count) -> Value {
        auto comp = get_buffer(runtime, arguments[0], "comp");
        auto s = get_buffer(runtime, arguments[1], "s");
        validate_length(runtime, comp, crypto_core_ed25519_SCALARBYTES, "comp");
        validate_length(runtime, s, crypto_core_ed25519_SCALARBYTES, "s");
        crypto_core_ed25519_scalar_complement(comp.data, s.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_core_ed25519_scalar_complement", move(get_crypto_core_ed25519_scalar_complement));

    auto get_crypto_core_ed25519_scalar_add = Function::createFromHostFunction(jsiRuntime,
                                                                               PropNameID::forAscii(jsiRuntime,
                                                                                                    "crypto_core_ed25519_scalar_add"),
                                                                                                    3,
                                                                                                    [](Runtime &runtime,
                                                                                                            const Value &thisValue,
                                                                                                            const Value *arguments,
                                                                                                            size_t count) -> Value {
        auto z = get_buffer(runtime, arguments[0], "z");
        auto x = get_buffer(runtime, arguments[1], "x");
        auto y = get_buffer(runtime, arguments[2], "y");
        validate_length(runtime, z, crypto_core_ed25519_SCALARBYTES, "z");
        validate_length(runtime, x, crypto_core_ed25519_SCALARBYTES, "x");
        validate_length(runtime, y, crypto_core_ed25519_SCALARBYTES, "y");
        crypto_core_ed25519_scalar_add(z.data, x.data, y.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_core_ed25519_scalar_add", move(get_crypto_core_ed25519_scalar_add));

    auto get_crypto_core_ed25519_scalar_sub = Function::createFromHostFunction(jsiRuntime,
                                                                               PropNameID::forAscii(jsiRuntime,
                                                                                                    "crypto_core_ed25519_scalar_sub"),
                                                                                                    3,
                                                                                                    [](Runtime &runtime,
                                                                                                            const Value &thisValue,
                                                                                                            const Value *arguments,
                                                                                                            size_t count) -> Value {
        auto z = get_buffer(runtime, arguments[0], "z");
        auto x = get_buffer(runtime, arguments[1], "x");
        auto y = get_buffer(runtime, arguments[2], "y");
        validate_length(runtime, z, crypto_core_ed25519_SCALARBYTES, "z");
        validate_length(runtime, x, crypto_core_ed25519_SCALARBYTES, "x");
        validate_length(runtime, y, crypto_core_ed25519_SCALARBYTES, "y");
        crypto_core_ed25519_scalar_sub(z.data, x.data, y.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_core_ed25519_scalar_sub", move(get_crypto_core_ed25519_scalar_sub));

    auto get_crypto_core_ed25519_scalar_mul = Function::createFromHostFunction(jsiRuntime,
                                                                               PropNameID::forAscii(jsiRuntime,
                                                                                                    "crypto_core_ed25519_scalar_mul"),
                                                                                                    3,
                                                                                                    [](Runtime &runtime,
                                                                                                            const Value &thisValue,
                                                                                                            const Value *arguments,
                                                                                                            size_t count) -> Value {
        auto z = get_buffer(runtime, arguments[0], "z");
        auto x = get_buffer(runtime, arguments[1], "x");
        auto y = get_buffer(runtime, arguments[2], "y");
        validate_length(runtime, z, crypto_core_ed25519_SCALARBYTES, "z");
        validate_length(runtime, x, crypto_core_ed25519_SCALARBYTES, "x");
        validate_length(runtime, y, crypto_core_ed25519_SCALARBYTES, "y");
        crypto_core_ed25519_scalar_mul(z.data, x.data, y.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_core_ed25519_scalar_mul", move(get_crypto_core_ed25519_scalar_mul));

    auto get_crypto_shorthash_BYTES = Function::createFromHostFunction(jsiRuntime,
                                                                       PropNameID::forAscii(jsiRuntime,
                                                                                            "get_crypto_shorthash_BYTES"),
                                                                                            0,
                                                                                            [](Runtime &runtime,
                                                                                                    const Value &thisValue,
                                                                                                    const Value *arguments,
                                                                                                    size_t count) -> Value {
        return Value((double) crypto_shorthash_BYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_shorthash_BYTES", move(get_crypto_shorthash_BYTES));

    auto get_crypto_shorthash_KEYBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                       PropNameID::forAscii(jsiRuntime,
                                                                                            "get_crypto_shorthash_KEYBYTES"),
                                                                                            0,
                                                                                            [](Runtime &runtime,
                                                                                                    const Value &thisValue,
                                                                                                    const Value *arguments,
                                                                                                    size_t count) -> Value {
        return Value((double) crypto_shorthash_KEYBYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_shorthash_KEYBYTES", move(get_crypto_shorthash_KEYBYTES));

    auto get_crypto_shorthash_PRIMITIVE = Function::createFromHostFunction(jsiRuntime,
                                                                       PropNameID::forAscii(jsiRuntime,
                                                                                            "get_crypto_shorthash_PRIMITIVE"),
                                                                                            0,
                                                                                            [](Runtime &runtime,
                                                                                                    const Value &thisValue,
                                                                                                    const Value *arguments,
                                                                                                    size_t count) -> Value {
        return Value(runtime, String::createFromUtf8(runtime, crypto_shorthash_PRIMITIVE));
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_shorthash_PRIMITIVE", move(get_crypto_shorthash_PRIMITIVE));

    auto get_crypto_shorthash = Function::createFromHostFunction(jsiRuntime,
                                                                 PropNameID::forAscii(jsiRuntime,
                                                                                      "crypto_shorthash"),
                                                                                      3,
                                                                                      [](Runtime &runtime,
                                                                                              const Value &thisValue,
                                                                                              const Value *arguments,
                                                                                              size_t count) -> Value {
        auto out = get_buffer(runtime, arguments[0], "out");
        auto in = get_buffer(runtime, arguments[1], "in");
        auto k = get_buffer(runtime, arguments[2], "k");
        validate_length(runtime, out, crypto_shorthash_BYTES, "out");
        validate_length(runtime, k, crypto_shorthash_KEYBYTES, "k");
        crypto_shorthash(out.data, in.data, in.byteLength, k.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_shorthash", move(get_crypto_shorthash));

    auto get_crypto_kdf_KEYBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                    PropNameID::forAscii(jsiRuntime,
                                                                                         "get_crypto_kdf_KEYBYTES"),
                                                                                         0,
                                                                                         [](Runtime &runtime,
                                                                                                 const Value &thisValue,
                                                                                                 const Value *arguments,
                                                                                                 size_t count) -> Value {
        return Value((double) crypto_kdf_KEYBYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_kdf_KEYBYTES", move(get_crypto_kdf_KEYBYTES));

    auto get_crypto_kdf_BYTES_MIN = Function::createFromHostFunction(jsiRuntime,
                                                                    PropNameID::forAscii(jsiRuntime,
                                                                                         "get_crypto_kdf_BYTES_MIN"),
                                                                                         0,
                                                                                         [](Runtime &runtime,
                                                                                                 const Value &thisValue,
                                                                                                 const Value *arguments,
                                                                                                 size_t count) -> Value {
        return Value((double) crypto_kdf_BYTES_MIN);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_kdf_BYTES_MIN", move(get_crypto_kdf_BYTES_MIN));

    auto get_crypto_kdf_BYTES_MAX = Function::createFromHostFunction(jsiRuntime,
                                                                    PropNameID::forAscii(jsiRuntime,
                                                                                         "get_crypto_kdf_BYTES_MAX"),
                                                                                         0,
                                                                                         [](Runtime &runtime,
                                                                                                 const Value &thisValue,
                                                                                                 const Value *arguments,
                                                                                                 size_t count) -> Value {
        return Value((double) crypto_kdf_BYTES_MAX);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_kdf_BYTES_MAX", move(get_crypto_kdf_BYTES_MAX));

    auto get_crypto_kdf_CONTEXTBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                    PropNameID::forAscii(jsiRuntime,
                                                                                         "get_crypto_kdf_CONTEXTBYTES"),
                                                                                         0,
                                                                                         [](Runtime &runtime,
                                                                                                 const Value &thisValue,
                                                                                                 const Value *arguments,
                                                                                                 size_t count) -> Value {
        return Value((double) crypto_kdf_CONTEXTBYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_kdf_CONTEXTBYTES", move(get_crypto_kdf_CONTEXTBYTES));

    auto get_crypto_kdf_PRIMITIVE = Function::createFromHostFunction(jsiRuntime,
                                                                    PropNameID::forAscii(jsiRuntime,
                                                                                         "get_crypto_kdf_PRIMITIVE"),
                                                                                         0,
                                                                                         [](Runtime &runtime,
                                                                                                 const Value &thisValue,
                                                                                                 const Value *arguments,
                                                                                                 size_t count) -> Value {
        return Value(runtime, String::createFromUtf8(runtime, crypto_kdf_PRIMITIVE));
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_kdf_PRIMITIVE", move(get_crypto_kdf_PRIMITIVE));

    auto get_crypto_kdf_keygen = Function::createFromHostFunction(jsiRuntime,
                                                                  PropNameID::forAscii(jsiRuntime,
                                                                                       "crypto_kdf_keygen"),
                                                                                       1,
                                                                                       [](Runtime &runtime,
                                                                                               const Value &thisValue,
                                                                                               const Value *arguments,
                                                                                               size_t count) -> Value {
        auto key = get_buffer(runtime, arguments[0], "key");
        at_least_length(runtime, key, crypto_kdf_KEYBYTES, "key");
        crypto_kdf_keygen(key.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_kdf_keygen", move(get_crypto_kdf_keygen));

    auto get_crypto_kdf_derive_from_key = Function::createFromHostFunction(jsiRuntime,
                                                                           PropNameID::forAscii(jsiRuntime,
                                                                                                "crypto_kdf_derive_from_key"),
                                                                                                4,
                                                                                                [](Runtime &runtime,
                                                                                                        const Value &thisValue,
                                                                                                        const Value *arguments,
                                                                                                        size_t count) -> Value {
        auto subkey = get_buffer(runtime, arguments[0], "subkey");
        auto subkeyId = arguments[1].isNumber() ? arguments[1].getNumber() : -1;
        auto ctx = get_buffer(runtime, arguments[2], "ctx");
        auto key = get_buffer(runtime, arguments[3], "key");
        at_least_length(runtime, subkey, crypto_kdf_BYTES_MIN, "subkey");
        at_most_length(runtime, subkey, crypto_kdf_BYTES_MAX, "subkey");
        validate_length(runtime, ctx, crypto_kdf_CONTEXTBYTES, "ctx");
        validate_length(runtime, key, crypto_kdf_KEYBYTES, "key");
        crypto_kdf_derive_from_key(subkey.data, subkey.byteLength, subkeyId, (char *) ctx.data, key.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_kdf_derive_from_key", move(get_crypto_kdf_derive_from_key));

    auto get_crypto_hash_BYTES = Function::createFromHostFunction(jsiRuntime,
                                                                  PropNameID::forAscii(jsiRuntime,
                                                                                       "get_crypto_hash_BYTES"),
                                                                                       0,
                                                                                       [](Runtime &runtime,
                                                                                               const Value &thisValue,
                                                                                               const Value *arguments,
                                                                                               size_t count) -> Value {
        return Value((double) crypto_hash_BYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_hash_BYTES", move(get_crypto_hash_BYTES));

    auto get_crypto_hash_sha256_BYTES = Function::createFromHostFunction(jsiRuntime,
                                                                  PropNameID::forAscii(jsiRuntime,
                                                                                       "get_crypto_hash_sha256_BYTES"),
                                                                                       0,
                                                                                       [](Runtime &runtime,
                                                                                               const Value &thisValue,
                                                                                               const Value *arguments,
                                                                                               size_t count) -> Value {
        return Value((double) crypto_hash_sha256_BYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_hash_sha256_BYTES", move(get_crypto_hash_sha256_BYTES));

    auto get_crypto_hash_sha512_BYTES = Function::createFromHostFunction(jsiRuntime,
                                                                  PropNameID::forAscii(jsiRuntime,
                                                                                       "get_crypto_hash_sha512_BYTES"),
                                                                                       0,
                                                                                       [](Runtime &runtime,
                                                                                               const Value &thisValue,
                                                                                               const Value *arguments,
                                                                                               size_t count) -> Value {
        return Value((double) crypto_hash_sha512_BYTES);
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_hash_sha512_BYTES", move(get_crypto_hash_sha512_BYTES));

    auto get_crypto_hash_sha512_STATEBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                  PropNameID::forAscii(jsiRuntime,
                                                                                       "get_crypto_hash_sha512_STATEBYTES"),
                                                                                       0,
                                                                                       [](Runtime &runtime,
                                                                                               const Value &thisValue,
                                                                                               const Value *arguments,
                                                                                               size_t count) -> Value {
        return Value((double) crypto_hash_sha512_statebytes());
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_hash_sha512_STATEBYTES", move(get_crypto_hash_sha512_STATEBYTES));

    auto get_crypto_hash_sha256_STATEBYTES = Function::createFromHostFunction(jsiRuntime,
                                                                  PropNameID::forAscii(jsiRuntime,
                                                                                       "get_crypto_hash_sha256_STATEBYTES"),
                                                                                       0,
                                                                                       [](Runtime &runtime,
                                                                                               const Value &thisValue,
                                                                                               const Value *arguments,
                                                                                               size_t count) -> Value {
        return Value((double) crypto_hash_sha256_statebytes());
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_hash_sha256_STATEBYTES", move(get_crypto_hash_sha256_STATEBYTES));

    auto get_crypto_hash_PRIMITIVE = Function::createFromHostFunction(jsiRuntime,
                                                                  PropNameID::forAscii(jsiRuntime,
                                                                                       "get_crypto_hash_PRIMITIVE"),
                                                                                       0,
                                                                                       [](Runtime &runtime,
                                                                                               const Value &thisValue,
                                                                                               const Value *arguments,
                                                                                               size_t count) -> Value {
        return Value(runtime, String::createFromUtf8(runtime, crypto_hash_PRIMITIVE));
    });
    jsiRuntime.global().setProperty(jsiRuntime, "get_crypto_hash_PRIMITIVE", move(get_crypto_hash_PRIMITIVE));

    auto get_crypto_hash = Function::createFromHostFunction(jsiRuntime,
                                                            PropNameID::forAscii(jsiRuntime,
                                                                                 "crypto_hash"),
                                                                                 2,
                                                                                 [](Runtime &runtime,
                                                                                         const Value &thisValue,
                                                                                         const Value *arguments,
                                                                                         size_t count) -> Value {
        auto out = get_buffer(runtime, arguments[0], "out");
        auto in = get_buffer(runtime, arguments[1], "in");
        at_least_length(runtime, out, crypto_hash_BYTES, "out");
        crypto_hash(out.data, in.data, in.byteLength);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_hash", move(get_crypto_hash));

    auto get_crypto_hash_sha256 = Function::createFromHostFunction(jsiRuntime,
                                                            PropNameID::forAscii(jsiRuntime,
                                                                                 "crypto_hash_sha256"),
                                                                                 2,
                                                                                 [](Runtime &runtime,
                                                                                         const Value &thisValue,
                                                                                         const Value *arguments,
                                                                                         size_t count) -> Value {
        auto out = get_buffer(runtime, arguments[0], "out");
        auto in = get_buffer(runtime, arguments[1], "in");
        at_least_length(runtime, out, crypto_hash_BYTES, "out");
        crypto_hash_sha256(out.data, in.data, in.byteLength);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_hash_sha256", move(get_crypto_hash_sha256));

    auto get_crypto_hash_sha512 = Function::createFromHostFunction(jsiRuntime,
                                                            PropNameID::forAscii(jsiRuntime,
                                                                                 "crypto_hash_sha512"),
                                                                                 2,
                                                                                 [](Runtime &runtime,
                                                                                         const Value &thisValue,
                                                                                         const Value *arguments,
                                                                                         size_t count) -> Value {
        auto out = get_buffer(runtime, arguments[0], "out");
        auto in = get_buffer(runtime, arguments[1], "in");
        at_least_length(runtime, out, crypto_hash_sha512_BYTES, "out");
        crypto_hash_sha512(out.data, in.data, in.byteLength);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_hash_sha512", move(get_crypto_hash_sha512));

    auto get_crypto_hash_sha256_init = Function::createFromHostFunction(jsiRuntime,
                                                                        PropNameID::forAscii(jsiRuntime,
                                                                                             "crypto_hash_sha256_init"),
                                                                                             3,
                                                                                             [](Runtime &runtime,
                                                                                                     const Value &thisValue,
                                                                                                     const Value *arguments,
                                                                                                     size_t count) -> Value {
        auto state = get_buffer(runtime, arguments[0], "state");
        validate_length(runtime, state, crypto_hash_sha256_statebytes(), "state");
        crypto_hash_sha256_init((crypto_hash_sha256_state *) state.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_hash_sha256_init", move(get_crypto_hash_sha256_init));

    auto get_crypto_hash_sha256_update = Function::createFromHostFunction(jsiRuntime,
                                                                          PropNameID::forAscii(jsiRuntime,
                                                                                               "crypto_hash_sha256_update"),
                                                                                               2,
                                                                                               [](Runtime &runtime,
                                                                                                       const Value &thisValue,
                                                                                                       const Value *arguments,
                                                                                                       size_t count) -> Value {
        auto state = get_buffer(runtime, arguments[0], "state");
        auto in = get_buffer(runtime, arguments[1], "in");
        validate_length(runtime, state, crypto_hash_sha256_statebytes(), "state");
        crypto_hash_sha256_update((crypto_hash_sha256_state *) state.data, in.data, in.byteLength);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_hash_sha256_update", move(get_crypto_hash_sha256_update));

    auto get_crypto_hash_sha256_final = Function::createFromHostFunction(jsiRuntime,
                                                                         PropNameID::forAscii(jsiRuntime,
                                                                                              "crypto_hash_sha256_final"),
                                                                                              2,
                                                                                              [](Runtime &runtime,
                                                                                                      const Value &thisValue,
                                                                                                      const Value *arguments,
                                                                                                      size_t count) -> Value {
        auto state = get_buffer(runtime, arguments[0], "state");
        auto out = get_buffer(runtime, arguments[1], "out");
        validate_length(runtime, state, crypto_hash_sha256_statebytes(), "state");
        validate_length(runtime, out, crypto_hash_sha256_BYTES, "out");
        crypto_hash_sha256_final((crypto_hash_sha256_state *) state.data, out.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_hash_sha256_final", move(get_crypto_hash_sha256_final));

    auto get_crypto_hash_sha512_init = Function::createFromHostFunction(jsiRuntime,
                                                                        PropNameID::forAscii(jsiRuntime,
                                                                                             "crypto_hash_sha512_init"),
                                                                                             3,
                                                                                             [](Runtime &runtime,
                                                                                                     const Value &thisValue,
                                                                                                     const Value *arguments,
                                                                                                     size_t count) -> Value {
        auto state = get_buffer(runtime, arguments[0], "state");
        validate_length(runtime, state, crypto_hash_sha512_statebytes(), "state");
        crypto_hash_sha512_init((crypto_hash_sha512_state *) state.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_hash_sha512_init", move(get_crypto_hash_sha512_init));

    auto get_crypto_hash_sha512_update = Function::createFromHostFunction(jsiRuntime,
                                                                          PropNameID::forAscii(jsiRuntime,
                                                                                               "crypto_hash_sha512_update"),
                                                                                               2,
                                                                                               [](Runtime &runtime,
                                                                                                       const Value &thisValue,
                                                                                                       const Value *arguments,
                                                                                                       size_t count) -> Value {
        auto state = get_buffer(runtime, arguments[0], "state");
        auto in = get_buffer(runtime, arguments[1], "in");
        validate_length(runtime, state, crypto_hash_sha512_statebytes(), "state");
        crypto_hash_sha512_update((crypto_hash_sha512_state *) state.data, in.data, in.byteLength);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_hash_sha512_update", move(get_crypto_hash_sha512_update));

    auto get_crypto_hash_sha512_final = Function::createFromHostFunction(jsiRuntime,
                                                                         PropNameID::forAscii(jsiRuntime,
                                                                                              "crypto_hash_sha512_final"),
                                                                                              2,
                                                                                              [](Runtime &runtime,
                                                                                                      const Value &thisValue,
                                                                                                      const Value *arguments,
                                                                                                      size_t count) -> Value {
        auto state = get_buffer(runtime, arguments[0], "state");
        auto out = get_buffer(runtime, arguments[1], "out");
        validate_length(runtime, state, crypto_hash_sha512_statebytes(), "state");
        at_least_length(runtime, out, crypto_hash_sha512_BYTES, "out");
        crypto_hash_sha512_final((crypto_hash_sha512_state *) state.data, out.data);
        return Value::undefined();
    });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_hash_sha512_final", move(get_crypto_hash_sha512_final));
}

}
