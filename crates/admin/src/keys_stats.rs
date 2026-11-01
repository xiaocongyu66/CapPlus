//! Time-series aggregation for key statistics.

use std::collections::{BTreeMap, HashMap};

use super::*;
use crate::keys::DAY;

pub(crate) fn sum_range(h: &HashMap<String, String>, start: i64, end: Option<i64>) -> i64 {
    let mut sum = 0;
    for (k, v) in h {
        if let (Ok(bucket), Ok(count)) = (k.parse::<i64>(), v.parse::<i64>()) {
            if bucket >= start && end.map_or(true, |e| bucket < e) {
                sum += count;
            }
        }
    }
    sum
}

pub(crate) fn aggregate_daily(h: &HashMap<String, String>, start: i64, end: i64) -> BTreeMap<i64, i64> {
    let mut m: BTreeMap<i64, i64> = BTreeMap::new();
    for (k, v) in h {
        if let (Ok(bucket), Ok(count)) = (k.parse::<i64>(), v.parse::<i64>()) {
            if bucket >= start && bucket < end {
                let day_bucket = (bucket / DAY) * DAY;
                *m.entry(day_bucket).or_insert(0) += count;
            }
        }
    }
    m
}

pub(crate) fn empty() -> HashMap<String, String> {
    HashMap::new()
}

pub(crate) fn with_config_or_default(raw: Option<&String>) -> Value {
    match raw {
        Some(s) => serde_json::from_str(s).unwrap_or_else(|_| json!({})),
        None => json!({}),
    }
}
