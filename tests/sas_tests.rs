use sas::*;

const FAKE_STORAGE_ACCESS_KEY: &str =
  "OxsnQCQBIS4fEgocOTE3HikvIj0UMyYZDgULNSM4KB0HJRc6Fj8qAjAPCDITAy0JBjQgDRosFREEDCs+NjwYEA==";

// cargo test -- --nocapture
// cargo test test_name_test -- --exact  --nocapture

#[test]
fn signable_string_for_service_test() {
  let path = "/dev/l1n3aw3em0x5d5c8xfoteql17e13";
  let storage_account_name = "meecodevstorage0";

  let options = SignableStringForServiceOptions {
    permissions: Permission::R,
    content_disposition: Some("inline; filename=\"myblob\"; filename*=UTF-8''myblob"),
    content_type: Some("image/jpeg"),
    expiry: "2023-01-16T16:06:20Z",
  };

  let res = signable_string_for_service(path, storage_account_name, &options);

  assert_eq!(res, "r\n\n2023-01-16T16:06:20Z\n/blob/meecodevstorage0/dev/l1n3aw3em0x5d5c8xfoteql17e13\n\n\n\n2018-11-09\nb\n\n\ninline; filename=\"myblob\"; filename*=UTF-8''myblob\n\n\nimage/jpeg".to_string());
}

#[test]
fn init_access_key_test() {
  let decoded_access_key = init_access_key(FAKE_STORAGE_ACCESS_KEY);

  assert_eq!(decoded_access_key.len(), 64);

  assert_eq!(
    decoded_access_key,
    vec![
      59, 27, 39, 64, 36, 1, 33, 46, 31, 18, 10, 28, 57, 49, 55, 30, 41, 47, 34, 61, 20, 51, 38,
      25, 14, 5, 11, 53, 35, 56, 40, 29, 7, 37, 23, 58, 22, 63, 42, 2, 48, 15, 8, 50, 19, 3, 45, 9,
      6, 52, 32, 13, 26, 44, 21, 17, 4, 12, 43, 62, 54, 60, 24, 16
    ]
  );
}

#[test]
fn sign_test() {
  let body =
  "r\n\n2023-01-16T16:20:32Z\n/blob/meecodevstorage0/dev/l1n3aw3em0x5d5c8xfoteql17e13\n\n\n\n2018-11-09\nb\n\n\ninline; filename=\"myblob\"; filename*=UTF-8''myblob\n\n\nimage/jpeg";

  let decoded_access_key: Vec<u8> = init_access_key(FAKE_STORAGE_ACCESS_KEY);
  let signature = sign(body, &decoded_access_key[..]);

  assert_eq!(signature, "tAWBKR2gNJXMCoin5fZ7/YbmaOtIHRcJEAD6Z6EvBJA=");
}

#[test]
fn build_content_disposition_test() {
  let res = build_content_disposition("myblob", ContentDisposition::Inline);

  assert_eq!(res, r#"inline; filename="myblob"; filename*=UTF-8''myblob"#);

  let res = build_content_disposition("myblob", ContentDisposition::Attachment);

  assert_eq!(
    res,
    r#"attachment; filename="myblob"; filename*=UTF-8''myblob"#
  );
}

#[test]
fn build_uri_test() {
  let uri = build_uri("meecodevstorage0", "dev", "w1n3aw3em0x5d5c8xfoteql17e1w").unwrap();

  assert_eq!(uri.scheme(), "https");
  assert_eq!(uri.port(), None);
  assert_eq!(uri.path(), "/dev/w1n3aw3em0x5d5c8xfoteql17e1w");
  assert_eq!(uri.query(), None);

  assert_eq!(
    uri.host_str(),
    Some("meecodevstorage0.blob.core.windows.net")
  );
}

#[test]
fn key_value_list_to_http_params_test() {
  let params: KeywordList = vec![
    ("sp", "rw"),
    ("se", "2023-01-17T10:12:39Z"),
    ("sv", "2018-11-09"),
    ("sr", "b"),
    ("sig", "2PS+Ts2SEKi1OEvsSJ8QX8Q/0NN535otqnEYqXJVxkw="),
  ];

  let query = key_value_list_to_http_params(params);

  let chunks = query.split("&").collect::<Vec<&str>>();

  assert!(chunks.contains(&"sp=rw"));
  assert!(chunks.contains(&"se=2023-01-17T10%3A12%3A39Z"));
  assert!(chunks.contains(&"sv=2018-11-09"));
  assert!(chunks.contains(&"sr=b"));
  assert!(chunks.contains(&"sig=2PS%2BTs2SEKi1OEvsSJ8QX8Q%2F0NN535otqnEYqXJVxkw%3D"));
}

#[test]
fn build_expiry_with_specified_current_moment_test() {
  let datetime_formatted = build_expiry(Some("2023-01-16 17:26:22.717865Z"), 360).unwrap();
  assert_eq!(datetime_formatted, "2023-01-16T17:32:22Z");
}

#[test]
fn build_expiry_test() {
  use regex::Regex;

  let datetime_formatted = build_expiry(None, 360).unwrap();

  let re = Regex::new(r"^\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ$").unwrap();
  assert!(re.is_match(datetime_formatted.as_str()));
}

#[test]
fn generate_service_sas_token_test() {
  let opts = SignableStringForServiceOptions {
    permissions: Permission::R,
    content_disposition: Some("inline; filename=\"myblob\"; filename*=UTF-8''myblob"),
    content_type: Some("image/jpeg"),
    expiry: "2023-01-17T10:59:48Z",
  };

  let res = generate_service_sas_token(
    "/dev/w1n3aw3em0x5d5c8xfoteql17e1w",
    "meecodevstorage0",
    FAKE_STORAGE_ACCESS_KEY,
    opts,
  );

  let chunks: Vec<&str> = res.split('&').collect();

  // for c in &chunks {
  //   println!("{}", c);
  // }

  assert_eq!(chunks.len(), 7);

  assert!(chunks.contains(&"sp=r"));
  assert!(chunks.contains(&"sr=b"));
  assert!(chunks.contains(&"sv=2018-11-09"));
  assert!(chunks.contains(&"rsct=image%2Fjpeg"));

  assert!(chunks.contains(&"se=2023-01-17T10%3A59%3A48Z"));
  assert!(chunks.contains(&"sig=UjzXp2R%2F8vNt4fFuKDa%2BefeUhJP6ruUPalTEcG5krZM%3D"));

  // This is how Elixir does it:
  // rscd=inline%3B+filename%3D%22myblob%22%3B+filename*%3DUTF-8%27%27myblob
  assert!(chunks
    .contains(&"rscd=inline%3B%20filename%3D%22myblob%22%3B%20filename%2A%3DUTF-8%27%27myblob"));
}

#[test]
fn generate_write_sas_url_test() {
  use url::Url;

  let uri_str = generate_write_sas_url(
    "meecodevstorage0",
    FAKE_STORAGE_ACCESS_KEY,
    "dev",
    "w1n3aw3em0x5d5c8xfoteql17e1w",
    600,
  )
  .unwrap();

  // println!("{}", uri_str);

  let uri = Url::parse(uri_str.as_str()).unwrap();

  let expected_uri = Url::parse(
    "https://meecodevstorage0.blob.core.windows.net/dev/w1n3aw3em0x5d5c8xfoteql17e1w?sp=rw&se=2023-01-17T11%3A59%3A39Z&sv=2018-11-09&sr=b&sig=1chUrj3Cd%2BOPH2YcBy4gRg7659BhoKrDAWZw4505GKQ%3D"
  ).unwrap();

  assert_eq!(uri.scheme(), expected_uri.scheme());
  assert_eq!(uri.host(), expected_uri.host());
  assert_eq!(uri.port(), expected_uri.port());
  assert_eq!(uri.path(), expected_uri.path());
  assert_eq!(uri.fragment(), expected_uri.fragment());

  // let q = uri.query().unwrap();

  let uri_chunks = uri.query().unwrap().split("&").collect::<Vec<&str>>();
  let expected_uri_chunks = expected_uri
    .query()
    .unwrap()
    .split("&")
    .collect::<Vec<&str>>();

  // println!("{:?}", uri_chunks);

  for expected_uri_chunk in &expected_uri_chunks {
    if !expected_uri_chunk.starts_with("se=") && !expected_uri_chunk.starts_with("sig=") {
      assert!(uri_chunks.contains(&expected_uri_chunk));
    }
  }
}
