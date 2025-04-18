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
struct SslEngine {
  mut buf : @bytes.View
  cc : SslEngineContext
}

///|
extern "c" fn br_ssl_client_get_engine(
  self : SslClientContext
) -> SslEngineContext = "br_ssl_client_get_engine"

///|
pub fn SslClient::get_engine(self : SslClient) -> SslEngineContext {
  br_ssl_client_get_engine(self._)
}

///|
#borrow(cc)
extern "c" fn br_ssl_engine_set_buffer(
  cc : SslEngineContext,
  buf : Bytes,
  buf_off : UInt64,
  buf_len : UInt64
) = "br_ssl_engine_set_buffer"

///|
pub fn SslEngine::set_buffer(self : SslEngine, buf : @bytes.View) -> Unit {
  self.buf = buf
  br_ssl_engine_set_buffer(
    self.cc,
    buf.data(),
    buf.start_offset().to_uint64(),
    buf.length().to_uint64(),
  )
}

///|
type SslioContext

///|
type Sslio SslioContext

///|
extern "c" fn br_sslio_make() -> SslioContext = "moonbit_br_sslio_make"

///|
extern "c" fn br_sslio_init(
  ctx : SslioContext,
  engine : SslEngineContext,
  low_read : (UInt64, UInt64) -> Int,
  low_write : (UInt64, UInt64) -> Int
) = "moonbit_br_sslio_init"

///|
pub fn Sslio::new(
  engine : SslEngine,
  read : (@bytes.View) -> Unit!,
  write : (@bytes.View) -> Unit!
) -> Sslio {
  fn read_cb(data : @c.Pointer[Byte], len : UInt64) -> Int {
    try {
      let view = read!()
      let len = @math.minimum(view.length(), len.to_int())
      for i in 0..<len {
        data[i] = view[i]
      }
      len
    } catch {
      _ => -1
    }
  }

  fn write_cb(data : @c.Pointer[Byte], len : UInt64) -> Int {
    try {
      let len = len.to_int()
      let view = Bytes::makei(len, fn(i) { data[i] })
      write!(view)
      len
    } catch {
      _ => -1
    }
  }

  let cc = br_sslio_make()
  br_sslio_init(cc, engine._, read_cb, write_cb)
  cc
}

///|
extern "c" fn br_sslio_write_all(
  cc : SslioContext,
  src : Bytes,
  src_off : UInt64,
  src_len : UInt64
) -> Int = "moonbit_br_sslio_write_all"

///|
pub fn Sslio::write_all(self : Sslio, bytes : @bytes.View) -> Unit!Failure {
  let src = bytes.data()
  let src_off = bytes.start_offset()
  let src_len = bytes.length()
  let result = br_sslio_write_all(
    self._,
    src,
    src_off.to_uint64(),
    src_len.to_uint64(),
  )
  if result == -1 {
    raise Failure
  }
}

///|
#borrow(cc)
extern "c" fn br_sslio_flush(cc : SslioContext) -> Int = "br_sslio_flush"

///|
pub fn Sslio::flush(self : Sslio) -> Unit!Failure {
  let result = br_sslio_flush(self._)
  if result == -1 {
    raise Failure
  }
}

///|
fn with_bytes[T](bytes : Bytes, f : (@c.Pointer[Byte]) -> T) -> T {
  ...
}

///|
extern "c" fn br_sslio_read(
  cc : SslioContext,
  dst : @c.Pointer[Byte],
  len : UInt64
) -> Int = "moonbit_br_sslio_read"

///|
pub fn Sslio::read(
  self : Sslio,
  size_hint~ : Int = 1024
) -> @bytes.View!Failure {
  let bytes = Bytes::make(size_hint, 0)
  let result = with_bytes(bytes, fn(dst) {
    br_sslio_read(self._, dst, size_hint.to_uint64())
  })
  if result == -1 {
    raise Failure
  }
  bytes[:result]
}

///|
enum ErrorCode {
  BadParam = 1
  BadState = 2
  UnsupportedVersion = 3
  BadVersion = 4
  BadLength = 5
  TooLarge = 6
  BadMac = 7
  NoRandom = 8
  UnknownType = 9
  Unexpected = 10
  BadCcs = 12
  BadAlert = 13
  BadHandshake = 14
  OversidedId = 15
  BadCipherSuite = 16
  BadCompression = 17
  BadFragmentLength = 18
  BadSecureRenegotiation = 19
  ExtraExtension = 20
  BadSni = 21
  BadHelloDone = 22
  LimitExceeded = 23
  BadFinished = 24
  ResumeMismatch = 25
  InvalidAlgorithm = 26
  BadSignature = 27
  WrongKeyUsage = 28
  NoClientAuth = 29
  Io = 31
  RecvFatalAlert = 256
  SendFatalAlert = 512
}

type! SslError ErrorCode {
}
