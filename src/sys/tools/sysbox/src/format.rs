pub(crate) fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1 << 10;
    const MIB: u64 = 1 << 20;
    const GIB: u64 = 1 << 30;
    const TIB: u64 = 1 << 40;

    if bytes >= TIB {
        format!("{:.2}T", bytes as f64 / TIB as f64)
    } else if bytes >= GIB {
        format!("{:.2}G", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.2}M", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.2}K", bytes as f64 / KIB as f64)
    } else {
        format!("{}", bytes)
    }
}
