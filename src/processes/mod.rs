pub use image;
use std::path::PathBuf;
use once_cell::sync::Lazy;
use std::sync::Mutex;

#[cfg(target_os = "macos")]
mod macos_list;
#[cfg(target_os = "macos")]
pub use self::macos_list::active_executables;

#[cfg(windows)]
mod windows_list;
#[cfg(windows)]
pub use self::windows_list::active_executables;


#[cfg(target_os = "macos")]
mod macos_icons;
#[cfg(target_os = "macos")]
use self::macos_icons::IconCache;

#[cfg(windows)]
mod windows_icons;
#[cfg(windows)]
use self::windows_icons::IconCache;

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub executable: PathBuf,
    pub display_name: String,
    pub is_visible: bool,
    pub is_system: bool,
}

pub type ProcessList = Vec<ProcessInfo>;

#[cfg(any(windows, target_os = "macos"))]
pub static ICON_CACHE: Lazy<Mutex<IconCache>> = Lazy::new(|| Mutex::new(IconCache::default()));


pub mod bench {
    #[cfg(target_os = "macos")]
    pub use super::macos_list::visible_windows;
    #[cfg(windows)]
    pub use super::windows_list::visible_windows;

    #[cfg(target_os = "macos")]
    pub use super::macos_icons::IconCache;
    #[cfg(windows)]
    pub use super::windows_icons::IconCache;

    #[cfg(target_os = "macos")]
    pub use super::macos_icons::{tiff_to_png, tiff_data_for_executable};
}