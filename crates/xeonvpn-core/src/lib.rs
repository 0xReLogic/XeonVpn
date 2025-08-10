pub const VERSION: &str = "0.1.0";

pub fn banner(component: &str) -> String {
    format!("{component} using XeonVPN core v{VERSION}")
}
