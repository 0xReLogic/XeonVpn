pub const VERSION: &str = "0.1.0";

pub fn banner(component: &str) -> String {
    format!("{} using XeonVPN core v{}", component, VERSION)
}
