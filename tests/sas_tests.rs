use sas::*;

const FAKE_STORAGE_ACCESS_KEY: &str =
  "OxsnQCQBIS4fEgocOTE3HikvIj0UMyYZDgULNSM4KB0HJRc6Fj8qAjAPCDITAy0JBjQgDRosFREEDCs+NjwYEA==";

// cargo test -- --nocapture
// cargo test test_name_test -- --exact  --nocapture

#[test]
fn signable_string_for_service_test() {
  let path = "/dev/l1n3aw3em0x5d5c8xfoteql17e13".to_string();
  let storage_account_name = "meecodevstorage0".to_string();

  let options = SignableStringForServiceOptions {
    permissions: Permission::R,
    content_disposition: "inline; filename=\"myblob\"; filename*=UTF-8''myblob".to_string(),
    content_type: "image/jpeg".to_string(),
    expiry: "2023-01-16T16:06:20Z".to_string(),
  };

  let res = signable_string_for_service(path, storage_account_name, options);

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

  let decoded_access_key = init_access_key(FAKE_STORAGE_ACCESS_KEY);
  let signature = sign(body.to_string(), &decoded_access_key[..]);

  assert_eq!(signature, "tAWBKR2gNJXMCoin5fZ7/YbmaOtIHRcJEAD6Z6EvBJA=");
}
