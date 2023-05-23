use base64::{engine::general_purpose, Engine as _};
use std::fmt;
use url::{ParseError, Url};

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

pub enum ContentDisposition {
  Inline,
  Attachment,
}

impl fmt::Display for ContentDisposition {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match self {
      ContentDisposition::Inline => write!(f, "inline"),
      ContentDisposition::Attachment => write!(f, "attachment"),
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

  let mut mac: HmacSha256 =
    HmacSha256::new_from_slice(access_key).expect("failed to create a MAC out of the access key");

  mac.update(body.as_bytes());

  // GenericArray<u8, <T as OutputSizeUser>::OutputSize>
  let result = mac.finalize().into_bytes();

  general_purpose::STANDARD.encode(result)
}

pub fn build_content_disposition(
  filename: String,
  content_disposition: ContentDisposition,
) -> String {
  format!(
    r#"{}; filename="{}"; filename*=UTF-8''{}"#,
    content_disposition, filename, filename
  )
}

pub fn build_uri(
  storage_account_name: String,
  container: String,
  key: String,
) -> Result<Url, ParseError> {
  let url_str = format!(
    "https://{}.blob.core.windows.net/{}/{}",
    storage_account_name, container, key
  );

  Url::parse(url_str.as_str())
}

pub type KeywordList<'a> = Vec<(&'a str, &'a str)>;

// TODO rename, it is not a map
pub fn map_to_http_params(keyword_list: KeywordList) -> String {
  use urlencoding::encode;

  keyword_list
    .iter()
    .map(|(k, v)| format!("{}={}", k, encode(v)))
    .collect::<Vec<String>>()
    .join("&")
}
