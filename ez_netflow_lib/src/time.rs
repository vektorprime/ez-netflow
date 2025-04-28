use chrono::prelude::*;
use chrono::TimeDelta;

pub fn convert_str_to_time(time_string: String) -> DateTime<FixedOffset> {
    DateTime::parse_from_rfc3339(time_string.as_str()).unwrap()
}


pub fn get_time_delta_in_min(current_time: DateTime<Local>, old_time: DateTime<FixedOffset>) -> i64 {

    let current_time_fixed: DateTime<FixedOffset> = DateTime::from(current_time);
    let diff = current_time_fixed - old_time;
    diff.num_minutes()

}


pub fn get_time_delta_in_sec(current_time: DateTime<Local>, old_time: DateTime<Local>) -> i64 {

    let diff = current_time - old_time;
    diff.num_seconds()

}