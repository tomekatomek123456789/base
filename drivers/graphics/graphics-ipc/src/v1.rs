pub use crate::common::Damage;

#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct CursorDamage {
    pub header: u32,
    pub x: i32,
    pub y: i32,
    pub hot_x: i32,
    pub hot_y: i32,
    pub width: i32,
    pub height: i32,
    pub cursor_img_bytes: [u32; 4096],
}
