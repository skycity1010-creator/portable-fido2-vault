//! 產品版本（edition）：單人版或雙群組控管版（dual-control）。
//!
//! 由 Cargo feature `dual-control` 在編譯期決定；同一份 code base 編出兩個執行檔
//! （`portable-fido-vault` / `portable-fido-vault-dual`），見 docs/plans/dual-control.md §5。

/// 執行檔所屬版本。序列化為 `"single"` / `"dual"` 供前端判斷 UI。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Edition {
    Single,
    Dual,
}

/// 純函式：依 feature 是否啟用決定版本（方便兩種組合都能單元測試）。
pub const fn edition_for(dual_control_enabled: bool) -> Edition {
    if dual_control_enabled {
        Edition::Dual
    } else {
        Edition::Single
    }
}

/// 目前這個 build 的版本。
pub const fn current() -> Edition {
    edition_for(cfg!(feature = "dual-control"))
}

#[cfg(test)]
mod tests {
    use super::{current, edition_for, Edition};

    #[test]
    fn feature_disabled_is_single_edition() {
        assert_eq!(edition_for(false), Edition::Single);
    }

    #[test]
    fn feature_enabled_is_dual_edition() {
        assert_eq!(edition_for(true), Edition::Dual);
    }

    #[test]
    fn current_edition_follows_dual_control_feature() {
        let expected = if cfg!(feature = "dual-control") {
            Edition::Dual
        } else {
            Edition::Single
        };
        assert_eq!(current(), expected);
    }

    #[test]
    fn edition_serializes_as_lowercase_ipc_value() {
        assert_eq!(serde_json::to_value(Edition::Single).unwrap(), "single");
        assert_eq!(serde_json::to_value(Edition::Dual).unwrap(), "dual");
    }
}
