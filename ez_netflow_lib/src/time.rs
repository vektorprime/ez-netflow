// use log::{error, info, debug};

// use chrono::prelude::*;

// // arithmetic operations
// let dt1 = Utc.with_ymd_and_hms(2014, 11, 14, 8, 9, 10).unwrap();
// let dt2 = Utc.with_ymd_and_hms(2014, 11, 14, 10, 9, 8).unwrap();
// assert_eq!(dt1.signed_duration_since(dt2), TimeDelta::try_seconds(-2 * 3600 + 2).unwrap());
// assert_eq!(dt2.signed_duration_since(dt1), TimeDelta::try_seconds(2 * 3600 - 2).unwrap());
// assert_eq!(
//     Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap()
//         + TimeDelta::try_seconds(1_000_000_000).unwrap(),
//     Utc.with_ymd_and_hms(2001, 9, 9, 1, 46, 40).unwrap()
// );
// assert_eq!(
//     Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap()
//         - TimeDelta::try_seconds(1_000_000_000).unwrap(),
//     Utc.with_ymd_and_hms(1938, 4, 24, 22, 13, 20).unwrap()
// );
