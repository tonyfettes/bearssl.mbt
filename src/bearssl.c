#include "bearssl.h"
#include "moonbit.h"
#include <stdlib.h>

typedef struct moonbit_br_ssl_client_context {
  br_ssl_client_context context;
} moonbit_br_ssl_client_context;

MOONBIT_FFI_EXPORT
moonbit_br_ssl_client_context *
moonbit_br_ssl_client_context_make(void) {
  return (moonbit_br_ssl_client_context *)moonbit_make_bytes(
    sizeof(moonbit_br_ssl_client_context), 0
  );
}

MOONBIT_FFI_EXPORT
br_ssl_engine_context *
moonbit_br_ssl_client_get_engine(moonbit_br_ssl_client_context *sc) {
  return &sc->context.eng;
}

MOONBIT_FFI_EXPORT
void
moonbit_br_ssl_engine_set_buffer(
  br_ssl_engine_context *eng,
  moonbit_bytes_t buffer
) {
  size_t length = Moonbit_array_length(buffer);
  br_ssl_engine_set_buffer(eng, buffer, length, 1);
}

typedef struct moonbit_br_x509_minimal_context {
  br_x509_minimal_context context;
} moonbit_br_x509_minimal_context;

MOONBIT_FFI_EXPORT
moonbit_br_x509_minimal_context *
moonbit_br_x509_minimal_context_make(void) {
  return (moonbit_br_x509_minimal_context *)moonbit_make_bytes(
    sizeof(moonbit_br_x509_minimal_context), 0
  );
}

typedef struct moonbit_br_rsa_public_key {
  br_rsa_public_key key;
} moonbit_br_rsa_public_key;

static inline void
moonbit_br_rsa_public_key_finalize(void *object) {
  moonbit_br_rsa_public_key *key = (moonbit_br_rsa_public_key *)object;
  if (key->key.n) {
    moonbit_decref(key->key.n);
  }
  if (key->key.e) {
    moonbit_decref(key->key.e);
  }
}

MOONBIT_FFI_EXPORT
moonbit_br_rsa_public_key *
moonbit_br_rsa_public_key_make(moonbit_bytes_t n, moonbit_bytes_t e) {
  moonbit_br_rsa_public_key *key = moonbit_make_external_object(
    moonbit_br_rsa_public_key_finalize, sizeof(moonbit_br_rsa_public_key)
  );
  memset(key, 0, sizeof(moonbit_br_rsa_public_key));
  key->key.n = n;
  key->key.nlen = Moonbit_array_length(n);
  key->key.e = e;
  key->key.elen = Moonbit_array_length(e);
  return key;
}

typedef struct moonbit_br_ec_public_key {
  br_ec_public_key key;
} moonbit_br_ec_public_key;

static inline void
moonbit_br_ec_public_key_finalize(void *object) {
  moonbit_br_ec_public_key *key = (moonbit_br_ec_public_key *)object;
  if (key->key.q) {
    moonbit_decref(key->key.q);
  }
}

typedef struct moonbit_br_x509_pkey {
  br_x509_pkey key;
} moonbit_br_x509_pkey;

static inline void
moonbit_br_x509_pkey_finalize(void *object) {
  moonbit_br_x509_pkey *key = (moonbit_br_x509_pkey *)object;
  switch (key->key.key_type) {
  case BR_KEYTYPE_RSA:
    moonbit_br_rsa_public_key_finalize(&key->key.key);
    break;
  case BR_KEYTYPE_EC:
    moonbit_br_ec_public_key_finalize(&key->key.key);
    break;
  }
}

MOONBIT_FFI_EXPORT
moonbit_br_x509_pkey *
moonbit_br_x509_pkey_rsa(moonbit_br_rsa_public_key *key) {
  moonbit_br_x509_pkey *pkey = moonbit_make_external_object(
    moonbit_br_x509_pkey_finalize, sizeof(moonbit_br_x509_pkey)
  );
  pkey->key.key_type = BR_KEYTYPE_RSA;
  moonbit_incref(key->key.n);
  moonbit_incref(key->key.e);
  pkey->key.key.rsa = key->key;
  moonbit_decref(key);
  return pkey;
}

MOONBIT_FFI_EXPORT
moonbit_br_x509_pkey *
moonbit_br_x509_pkey_ec(moonbit_br_ec_public_key *key) {
  moonbit_br_x509_pkey *pkey = moonbit_make_external_object(
    moonbit_br_x509_pkey_finalize, sizeof(moonbit_br_x509_pkey)
  );
  pkey->key.key_type = BR_KEYTYPE_EC;
  moonbit_incref(key->key.q);
  pkey->key.key.ec = key->key;
  moonbit_decref(key);
  return pkey;
}

typedef struct moonbit_br_x509_trust_anchor {
  br_x509_trust_anchor anchor;
} moonbit_br_x509_trust_anchor;

static inline void
moonbit_br_x509_trust_anchor_finalize(void *object) {
  moonbit_br_x509_trust_anchor *anchor = (moonbit_br_x509_trust_anchor *)object;
  if (anchor->anchor.dn.data) {
    moonbit_decref(anchor->anchor.dn.data);
  }
  moonbit_br_x509_pkey_finalize(&anchor->anchor.pkey);
}

MOONBIT_FFI_EXPORT
moonbit_br_x509_trust_anchor *
moonbit_br_x509_trust_anchor_make(
  moonbit_bytes_t dn,
  uint32_t flags,
  moonbit_br_x509_pkey *pkey
) {
  moonbit_br_x509_trust_anchor *anchor = moonbit_make_external_object(
    moonbit_br_x509_trust_anchor_finalize, sizeof(moonbit_br_x509_trust_anchor)
  );
  anchor->anchor.dn.data = dn;
  anchor->anchor.dn.len = Moonbit_array_length(dn);
  anchor->anchor.flags = flags;
  anchor->anchor.pkey = pkey->key;
  return anchor;
}

MOONBIT_FFI_EXPORT
void
moonbit_br_ssl_client_init_full(
  moonbit_br_ssl_client_context *sc,
  moonbit_br_x509_minimal_context *xc,
  moonbit_br_x509_trust_anchor **ta
) {
  size_t nta = Moonbit_array_length(ta);
  br_x509_trust_anchor *anchors = malloc(sizeof(br_x509_trust_anchor) * nta);
  for (size_t i = 0; i < nta; i++) {
    anchors[i] = ta[i]->anchor;
  }
  br_ssl_client_init_full(&sc->context, &xc->context, anchors, nta);
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_br_ssl_client_reset(
  moonbit_br_ssl_client_context *sc,
  moonbit_bytes_t server_name,
  int32_t resume_session
) {
  int32_t result =
    br_ssl_client_reset(&sc->context, (char *)server_name, resume_session);
  moonbit_decref(server_name);
  return result;
}
