use std::collections::HashSet;
use zeroize::Zeroize;

pub const MAX_IMPORT_ROWS: usize = 1_000;
pub const CSV_TEMPLATE: &str = "site,account,password,notes";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsvImportRow {
    pub row_number: usize,
    pub site: String,
    pub account: String,
    pub password: String,
    pub notes: String,
}

impl Drop for CsvImportRow {
    fn drop(&mut self) {
        self.site.zeroize();
        self.account.zeroize();
        self.password.zeroize();
        self.notes.zeroize();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsvImportRowError {
    pub row_number: usize,
    pub reason: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCsvImport {
    pub rows: Vec<CsvImportRow>,
    pub row_errors: Vec<CsvImportRowError>,
}

fn validate_csv_quoting(input: &str) -> Result<(), String> {
    let bytes = input.as_bytes();
    let mut in_quotes = false;
    let mut at_field_start = true;
    let mut after_quote = false;
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'"' if in_quotes => {
                if bytes.get(index + 1) == Some(&b'"') {
                    index += 2;
                } else {
                    in_quotes = false;
                    after_quote = true;
                    index += 1;
                }
            }
            b'"' if at_field_start => {
                in_quotes = true;
                at_field_start = false;
                index += 1;
            }
            b'"' => return Err("CSV 引號格式錯誤".into()),
            b',' if !in_quotes => {
                at_field_start = true;
                after_quote = false;
                index += 1;
            }
            b'\r' | b'\n' if !in_quotes => {
                at_field_start = true;
                after_quote = false;
                index += 1;
            }
            _ if after_quote => return Err("CSV 引號格式錯誤".into()),
            _ => {
                at_field_start = false;
                index += 1;
            }
        }
    }

    if in_quotes {
        Err("CSV 引號格式錯誤".into())
    } else {
        Ok(())
    }
}

/// Parse a UTF-8 CSV import without returning field contents in errors.
pub fn parse_import_csv(input: &str) -> Result<ParsedCsvImport, String> {
    let input = input.strip_prefix('\u{feff}').unwrap_or(input);
    validate_csv_quoting(input)?;
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_reader(input.as_bytes());
    let raw_headers = reader
        .headers()
        .map_err(|_| "CSV 表頭格式錯誤".to_string())?
        .clone();
    if raw_headers.is_empty() {
        return Err("CSV 缺少表頭".into());
    }

    let headers: Vec<String> = raw_headers
        .iter()
        .enumerate()
        .map(|(index, header)| {
            if index == 0 {
                header
                    .strip_prefix('\u{feff}')
                    .unwrap_or(header)
                    .to_string()
            } else {
                header.to_string()
            }
        })
        .collect();
    let mut seen = HashSet::with_capacity(headers.len());
    if headers.iter().any(|header| !seen.insert(header.as_str())) {
        return Err("CSV 表頭不可重複".into());
    }

    let column = |name: &str| {
        headers
            .iter()
            .position(|header| header == name)
            .ok_or_else(|| format!("CSV 缺少必要欄位：{name}"))
    };
    let site_column = column("site")?;
    let account_column = column("account")?;
    let password_column = column("password")?;
    let notes_column = column("notes")?;

    let mut parsed = ParsedCsvImport {
        rows: Vec::new(),
        row_errors: Vec::new(),
    };
    let mut data_row_count = 0usize;
    for record in reader.records() {
        data_row_count += 1;
        if data_row_count > MAX_IMPORT_ROWS {
            return Err("單檔最多匯入 1,000 筆資料列".into());
        }
        let record = record.map_err(|_| "CSV 格式錯誤".to_string())?;
        // `reader.headers()` consumes the header; include it in file line numbers.
        let row_number = record
            .position()
            .map(|position| position.line() as usize + 1)
            .unwrap_or(data_row_count + 1);
        if record.len() != headers.len() {
            parsed.row_errors.push(CsvImportRowError {
                row_number,
                reason: "欄位數不符",
            });
            continue;
        }
        let value = |index: usize| record.get(index).unwrap_or_default().to_string();
        parsed.rows.push(CsvImportRow {
            row_number,
            site: value(site_column),
            account: value(account_column),
            password: value(password_column),
            notes: value(notes_column),
        });
    }
    Ok(parsed)
}

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub struct ImportPreviewRow {
    pub row_number: usize,
    pub action: &'static str,
    pub reason: Option<&'static str>,
}

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub struct ImportPreview {
    pub added: usize,
    pub updated: usize,
    pub skipped: usize,
    pub rows: Vec<ImportPreviewRow>,
}

#[derive(Debug, Clone)]
pub enum ImportAction {
    Add(CsvImportRow),
    Update { entry_id: String, row: CsvImportRow },
}

#[derive(Debug, Clone)]
pub struct ImportPlan {
    pub actions: Vec<ImportAction>,
    pub preview: ImportPreview,
}

fn same_key(left: &str, right: &str) -> bool {
    caseless::canonical_caseless_match_str(left.trim(), right.trim())
}

/// Build a secret-free preview and the corresponding in-memory changes.
pub fn build_import_plan(existing: &[crate::vault::Entry], parsed: ParsedCsvImport) -> ImportPlan {
    let mut preview = ImportPreview {
        added: 0,
        updated: 0,
        skipped: 0,
        rows: parsed
            .row_errors
            .iter()
            .map(|error| ImportPreviewRow {
                row_number: error.row_number,
                action: "skip",
                reason: Some(error.reason),
            })
            .collect(),
    };
    let mut actions = Vec::new();
    let mut skip_reasons = vec![None; parsed.rows.len()];

    for (index, row) in parsed.rows.iter().enumerate() {
        if row.site.trim().is_empty() {
            skip_reasons[index] = Some("網站欄位必填");
        }
    }

    let mut duplicate_flags = vec![false; parsed.rows.len()];
    for (index, row) in parsed.rows.iter().enumerate() {
        if skip_reasons[index].is_some() {
            continue;
        }
        let duplicate_count = parsed
            .rows
            .iter()
            .enumerate()
            .filter(|(other_index, other)| {
                skip_reasons[*other_index].is_none()
                    && same_key(&row.site, &other.site)
                    && same_key(&row.account, &other.account)
            })
            .count();
        duplicate_flags[index] = duplicate_count > 1;
    }
    for (index, is_duplicate) in duplicate_flags.into_iter().enumerate() {
        if is_duplicate {
            skip_reasons[index] = Some("CSV 內有重複配對鍵");
        }
    }

    for (index, row) in parsed.rows.into_iter().enumerate() {
        if let Some(reason) = skip_reasons[index] {
            preview.skipped += 1;
            preview.rows.push(ImportPreviewRow {
                row_number: row.row_number,
                action: "skip",
                reason: Some(reason),
            });
            continue;
        }

        let matching_entries: Vec<&crate::vault::Entry> = existing
            .iter()
            .filter(|entry| {
                same_key(&entry.site, &row.site) && same_key(&entry.account, &row.account)
            })
            .collect();
        match matching_entries.as_slice() {
            [] => {
                preview.added += 1;
                preview.rows.push(ImportPreviewRow {
                    row_number: row.row_number,
                    action: "add",
                    reason: None,
                });
                actions.push(ImportAction::Add(row));
            }
            [entry] => {
                preview.updated += 1;
                preview.rows.push(ImportPreviewRow {
                    row_number: row.row_number,
                    action: "update",
                    reason: None,
                });
                actions.push(ImportAction::Update {
                    entry_id: entry.id.clone(),
                    row,
                });
            }
            _ => {
                preview.skipped += 1;
                preview.rows.push(ImportPreviewRow {
                    row_number: row.row_number,
                    action: "skip",
                    reason: Some("金庫中有多筆相符條目"),
                });
            }
        }
    }

    preview.rows.sort_by_key(|row| row.row_number);
    ImportPlan { actions, preview }
}

#[cfg(test)]
mod tests {
    use super::{build_import_plan, parse_import_csv, CSV_TEMPLATE};

    #[test]
    fn template_contains_only_the_required_header() {
        assert_eq!(CSV_TEMPLATE.as_bytes(), b"site,account,password,notes");
    }

    #[test]
    fn accepts_utf8_bom_reordered_headers_and_quoted_csv_fields() {
        let parsed = parse_import_csv(
            "\u{feff}notes,password,account,site\r\n\"line 1\nline 2\",\"comma, and \"\"quotes\"\"\",alice,example.com\r\n",
        )
        .unwrap();

        assert!(parsed.row_errors.is_empty());
        assert_eq!(parsed.rows.len(), 1);
        let row = &parsed.rows[0];
        assert_eq!(row.site, "example.com");
        assert_eq!(row.account, "alice");
        assert_eq!(row.password, "comma, and \"quotes\"");
        assert_eq!(row.notes, "line 1\nline 2");
        assert_eq!(row.row_number, 2);
    }

    #[test]
    fn reports_physical_line_numbers_after_multiline_csv_fields() {
        let parsed = parse_import_csv(
            "site,account,password,notes\r\nexample.com,alice,pw,\"first line\nsecond line\"\r\nother.com,bob,pw,note\r\n",
        )
        .unwrap();

        assert_eq!(
            parsed
                .rows
                .iter()
                .map(|row| row.row_number)
                .collect::<Vec<_>>(),
            vec![2, 4]
        );
    }

    #[test]
    fn reports_wrong_width_rows_without_discarding_later_valid_rows() {
        let parsed = parse_import_csv(
            "site,account,password,notes\r\nexample.com,alice,secret\r\nother.com,bob,pw,note\r\n",
        )
        .unwrap();

        assert_eq!(parsed.row_errors.len(), 1);
        assert_eq!(parsed.row_errors[0].row_number, 2);
        assert_eq!(parsed.row_errors[0].reason, "欄位數不符");
        assert_eq!(parsed.rows.len(), 1);
        assert_eq!(parsed.rows[0].site, "other.com");
    }

    #[test]
    fn rejects_missing_duplicate_headers_and_malformed_csv() {
        assert!(parse_import_csv("site,account,password\na,b,c\n").is_err());
        assert!(parse_import_csv("site,account,password,notes,site\na,b,c,d,a\n").is_err());
        assert!(parse_import_csv("site,account,password,notes\na,b,\"unterminated,d\n").is_err());
    }

    #[test]
    fn rejects_more_than_one_thousand_data_rows() {
        let mut csv = String::from("site,account,password,notes\n");
        for row in 0..=1_000 {
            csv.push_str(&format!("site-{row},user-{row},pw,note\n"));
        }

        assert!(parse_import_csv(&csv).is_err());
    }

    fn entry(id: &str, site: &str, account: &str) -> crate::vault::Entry {
        crate::vault::Entry {
            id: id.into(),
            site: site.into(),
            account: account.into(),
            password: "old-secret".into(),
            password_history: Vec::new(),
            notes: String::new(),
            created_at: String::new(),
            updated_at: String::new(),
        }
    }

    #[test]
    fn plans_new_unique_and_case_insensitive_updates_without_exposing_passwords() {
        let parsed = parse_import_csv(
            "site,account,password,notes\n EXAMPLE.com , Alice ,new-secret,updated\nnew.example,bob,added-secret,\n",
        )
        .unwrap();
        let existing = vec![entry("existing-id", "example.com", "alice")];
        let plan = build_import_plan(&existing, parsed);

        assert_eq!(plan.preview.added, 1);
        assert_eq!(plan.preview.updated, 1);
        assert_eq!(plan.preview.skipped, 0);
        assert_eq!(plan.actions.len(), 2);
        let safe_preview = serde_json::to_string(&plan.preview).unwrap();
        assert!(!safe_preview.contains("new-secret"));
        assert!(!safe_preview.contains("added-secret"));
    }

    #[test]
    fn skips_every_duplicate_input_key_and_ambiguous_existing_match() {
        let parsed = parse_import_csv(
            "site,account,password,notes\nnew.example,bob,secret-one,\nNEW.example, BOB ,secret-two,\nambiguous.example,mary,secret-three,\n,blank-site,secret-four,\n",
        )
        .unwrap();
        let existing = vec![
            entry("ambiguous-1", "ambiguous.example", "mary"),
            entry("ambiguous-2", "AMBIGUOUS.example", " MARY "),
        ];
        let plan = build_import_plan(&existing, parsed);

        assert_eq!(plan.preview.added, 0);
        assert_eq!(plan.preview.updated, 0);
        assert_eq!(plan.preview.skipped, 4);
        assert!(plan.actions.is_empty());
        assert!(plan.preview.rows.iter().all(|row| row.action == "skip"));
    }
}
