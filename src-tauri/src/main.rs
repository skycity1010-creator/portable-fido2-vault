// PortableFidoVault — Tauri 執行檔入口。
// 單人版執行檔不可編入 dual-control：避免產出名為單人版、實為雙群組控管版的 exe。
#[cfg(feature = "dual-control")]
compile_error!(
    "portable-fido-vault (single edition) must not be built with `dual-control`; \
     build `--bin portable-fido-vault-dual` instead"
);

fn main() {
    portable_fido_vault::run()
}
