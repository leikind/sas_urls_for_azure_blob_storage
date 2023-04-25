use base64::{engine::general_purpose, Engine as _};
use std::fmt;

const SERVICE_TYPE: &str = "blob";
const RESOURCE: &str = "b";
const VERSION: &str = "2018-11-09";

pub enum Permission {
  R,
  RW,
}

impl fmt::Display for Permission {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match self {
      Permission::R => write!(f, "r"),
      Permission::RW => write!(f, "rw"),
    }
  }
}

pub struct SignableStringForServiceOptions {
  pub permissions: Permission,
  pub content_disposition: String,
  pub content_type: String,
  pub expiry: String,
}

pub fn signable_string_for_service(
  path: String,
  storage_account_name: String,
  options: SignableStringForServiceOptions,
) -> String {
  format!(
    "{}\n\n{}\n/{}/{}{}\n\n\n\n{}\n{}\n\n\n{}\n\n\n{}",
    options.permissions,
    options.expiry,
    SERVICE_TYPE,
    storage_account_name,
    path,
    VERSION,
    RESOURCE,
    options.content_disposition,
    options.content_type
  )
}

pub fn init_access_key(access_key: &str) -> Vec<u8> {
  general_purpose::STANDARD
    .decode(access_key)
    .expect("invalid access key: not a valid Base64")
}

pub fn sign(body: String, access_key: &[u8]) -> String {
  use hmac::{Hmac, Mac};
  use sha2::Sha256;
  type HmacSha256 = Hmac<Sha256>;

  let mut mac =
    HmacSha256::new_from_slice(access_key).expect("failed to create a MAC out of the access key");

  mac.update(body.as_bytes());

  let result = mac.finalize().into_bytes();

  general_purpose::STANDARD.encode(result)
}
