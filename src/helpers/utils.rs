// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/// Converts a Unix epoch timestamp (seconds) to an RFC 3339 string.
pub(crate) fn epoch_to_rfc3339(epoch: u64) -> String {
    use chrono::{TimeZone, Utc};
    Utc.timestamp_opt(epoch as i64, 0).unwrap().to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epoch_to_rfc3339_known_value() {
        // 2026-01-01T00:00:00Z = 1767225600
        let result = epoch_to_rfc3339(1767225600);
        assert!(result.starts_with("2026-01-01T00:00:00"), "got: {result}");
    }

    #[test]
    fn test_epoch_to_rfc3339_zero() {
        let result = epoch_to_rfc3339(0);
        assert!(result.starts_with("1970-01-01T00:00:00"), "got: {result}");
    }
}
