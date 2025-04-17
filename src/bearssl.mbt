///|
type SslClientContext

///|
extern "c" fn br_ssl_client_context_make() -> SslClientContext = "br_ssl_client_context_make"

///|
type X509MinimalContext

///|
extern "c" fn br_x509_minimal_context_make() -> X509MinimalContext = "br_x509_minimal_context_make"

///|
type RsaPublicKey

///|
extern "c" fn br_rsa_public_key(n : Bytes, e : Bytes) -> RsaPublicKey = "br_rsa_public_key"

///|
type EcPublicKey

///|
extern "c" fn br_ec_public_key(q : Bytes) -> EcPublicKey = "br_ec_public_key"

///|
type X509Pkey

///|
extern "c" fn br_x509_pkey_rsa(key : RsaPublicKey) -> X509Pkey = "br_x509_pkey_rsa"

///|
extern "c" fn br_x509_pkey_ec(key : EcPublicKey) -> X509Pkey = "br_x509_pkey_ec"

///|
type X509TrustAnchor

///|
extern "c" fn br_x509_trust_anchor_make(
  dn : Bytes,
  flags : UInt,
  pkey : X509Pkey
) -> X509TrustAnchor = "br_x509_trust_anchor_make"

///|
extern "c" fn br_ssl_client_init_full(
  sc : SslClientContext,
  xc : X509MinimalContext,
  ta : FixedArray[X509TrustAnchor]
) = "br_ssl_client_init_full"

///|
type SslClient SslClientContext

///|
pub fn SslClient::init_full(
  trust_anchors : Array[X509TrustAnchor]
) -> (SslClient, X509MinimalContext) {
  let sc = br_ssl_client_context_make()
  let xc = br_x509_minimal_context_make()
  let ta = FixedArray::from_array(trust_anchors)
  br_ssl_client_init_full(sc, xc, ta)
  (sc, xc)
}

///|
#borrow(cc, server_name)
extern "c" fn br_ssl_client_reset(
  cc : SslClientContext,
  server_name : Bytes,
  resume_session : Bool
) = "br_ssl_client_reset"

///|
fn to_ntbs(s : String) -> Bytes {
  let buffer = @buffer.new()
  @encoding.encode_to(s, buffer, encoding=UTF8)
  buffer.write_byte(0)
  buffer.contents()
}

///|
pub fn SslClient::reset(
  self : SslClient,
  server_name : String,
  resume_session : Bool
) -> Unit {
  br_ssl_client_reset(self._, to_ntbs(server_name), resume_session)
}

///|
extern type SslEngineContext

///|
type SslEngine SslEngineContext

///|
extern "c" fn br_ssl_client_get_engine(
  self : SslClientContext
) -> SslEngineContext = "br_ssl_client_get_engine"

///|
pub fn SslClient::get_engine(self : SslClient) -> SslEngineContext {
  br_ssl_client_get_engine(self._)
}

///|
extern "c" fn br_ssl_engine_set_buffer(self : SslEngineContext, buffer : Bytes) = "br_ssl_engine_set_buffer"

///|
pub fn SslEngine::set_buffer(self : SslEngine, buffer : Bytes) -> Unit {
  br_ssl_engine_set_buffer(self._, buffer)
}

type SslioContext
