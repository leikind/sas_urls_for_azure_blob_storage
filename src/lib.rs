use base64::{engine::general_purpose, Engine as _};
use url::{ParseError, Url};

const SERVICE_TYPE: &str = "blob";
const RESOURCE: &str = "b";
const VERSION: &str = "2018-11-09";

pub enum Permission {
  R,
  RW,
}

impl ToString for Permission {
  fn to_string(&self) -> String {
    let s = match self {
      Permission::R => "r",
      Permission::RW => "rw",
    };
    s.to_string()
  }
}

pub enum ContentDisposition {
  Inline,
  Attachment,
}

impl ToString for ContentDisposition {
  fn to_string(&self) -> String {
    let s = match self {
      ContentDisposition::Inline => "inline",
      ContentDisposition::Attachment => "attachment",
    };
    s.to_string()
  }
}

pub struct SignableStringForServiceOptions<'a> {
  pub permissions: Permission,
  pub content_disposition: Option<&'a str>,
  pub content_type: Option<&'a str>,
  pub expiry: &'a str,
}

impl SignableStringForServiceOptions<'_> {
  fn get_content_disposition(&self) -> &str {
    match self.content_disposition {
      Some(content_disposition) => content_disposition,
      None => "",
    }
  }

  fn get_content_type(&self) -> &str {
    match self.content_type {
      Some(content_type) => content_type,
      None => "",
    }
  }
}

pub fn signable_string_for_service(
  path: &str,
  storage_account_name: &str,
  options: &SignableStringForServiceOptions,
) -> String {
  let permissions = options.permissions.to_string();

  format!(
    "{}\n\n{}\n/{}/{}{}\n\n\n\n{}\n{}\n\n\n{}\n\n\n{}",
    permissions,
    options.expiry,
    SERVICE_TYPE,
    storage_account_name,
    path,
    VERSION,
    RESOURCE,
    options.get_content_disposition(),
    options.get_content_type()
  )
}

pub fn init_access_key(access_key: &str) -> Vec<u8> {
  general_purpose::STANDARD
    .decode(access_key)
    .expect("invalid access key: not a valid Base64")
}

pub fn sign(body: &str, access_key: &[u8]) -> String {
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
  filename: &str,
  content_disposition: ContentDisposition,
) -> String {
  let cd = content_disposition.to_string();
  format!(
    r#"{}; filename="{}"; filename*=UTF-8''{}"#,
    cd, filename, filename
  )
}

pub fn build_uri(
  storage_account_name: &str,
  container: &str,
  key: &str,
) -> Result<Url, ParseError> {
  let url_str = format!(
    "https://{}.blob.core.windows.net/{}/{}",
    storage_account_name, container, key
  );

  Url::parse(url_str.as_str())
}

pub type KeywordList<'a> = Vec<(&'a str, &'a str)>;

pub fn key_value_list_to_http_params(keyword_list: KeywordList) -> String {
  use urlencoding::encode;

  keyword_list
    .iter()
    .map(|(k, v)| format!("{}={}", k, encode(v)))
    .collect::<Vec<String>>()
    .join("&")
}

pub fn build_expiry(
  now: Option<&str>,
  expires_in: i64,
) -> Result<String, Box<dyn std::error::Error>> {
  use chrono::{DateTime, Duration, SecondsFormat, Timelike, Utc};

  let start_from = match now {
    None => Utc::now(),
    Some(t) => t.parse::<DateTime<Utc>>()?,
  };

  let start_from = start_from.with_nanosecond(0).ok_or("Invalid datetime")?;
  let expiration = start_from + Duration::seconds(expires_in);
  let formatted = expiration.to_rfc3339_opts(SecondsFormat::Secs, true);

  Ok(formatted)
}

pub fn generate_service_sas_token(
  path: &str,
  storage_account_name: &str,
  storage_access_key: &str,
  options: SignableStringForServiceOptions,
) -> String {
  let signable_string_for_service =
    signable_string_for_service(path, storage_account_name, &options);

  let signature = sign(
    signable_string_for_service.as_str(),
    &init_access_key(storage_access_key),
  );

  let permissions = options.permissions.to_string();

  let kv_list: KeywordList = vec![
    ("sp", permissions.as_str()),
    ("sr", RESOURCE),
    ("sv", VERSION),
    ("rscd", options.get_content_disposition()),
    ("rsct", options.get_content_type()),
    ("se", options.expiry),
    ("sig", signature.as_str()),
  ];

  key_value_list_to_http_params(kv_list)
}

pub fn generate_write_sas_url(
  storage_account_name: &str,
  storage_access_key: &str,
  container: &str,
  key: &str,
  expires_in: i64,
) -> Result<String, Box<dyn std::error::Error>> {
  let uri = build_uri(storage_account_name, container, key)?;
  let expiry = build_expiry(None, expires_in)?;

  let opts = SignableStringForServiceOptions {
    permissions: Permission::RW,
    content_disposition: None,
    content_type: None,
    expiry: expiry.as_str(),
  };

  let sas_params =
    generate_service_sas_token(uri.path(), storage_account_name, storage_access_key, opts);

  let signed_rw_url = format!("{}?{}", uri.to_string(), sas_params);

  Ok(signed_rw_url)
}
