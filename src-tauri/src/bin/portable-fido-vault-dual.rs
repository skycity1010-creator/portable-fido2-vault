// PortableFidoVault 雙群組控管版（dual-control edition）— Tauri 執行檔入口。
// 建置：cargo build --release --locked --features real-ctap,dual-control --bin portable-fido-vault-dual
// 設計：docs/plans/dual-control.md §5。

#[cfg(not(feature = "dual-control"))]
compile_error!("portable-fido-vault-dual must be built with the `dual-control` feature");

fn main() {
    portable_fido_vault::run()
}
