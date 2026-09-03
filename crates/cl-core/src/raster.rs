//! A tiny 8-bit RGB raster.
//!
//! It lives in `cl-core` because two crates that must not depend on each other both
//! need it: `cl-markers` *creates* the tint carrier, and `cl-report` *embeds and
//! extracts* it. Keeping the type here means the marker scheme and the PDF writer
//! stay independent — either can be replaced without touching the other.

use crate::error::{ClError, ClResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Raster {
    pub width: u32,
    pub height: u32,
    /// `width * height * 3` bytes, row-major, no padding.
    pub rgb: Vec<u8>,
}

impl Raster {
    pub fn new(width: u32, height: u32, fill: [u8; 3]) -> Raster {
        let n = (width as usize) * (height as usize);
        let mut rgb = Vec::with_capacity(n * 3);
        for _ in 0..n {
            rgb.extend_from_slice(&fill);
        }
        Raster { width, height, rgb }
    }

    pub fn from_rgb(width: u32, height: u32, rgb: Vec<u8>) -> ClResult<Raster> {
        let expect = (width as usize) * (height as usize) * 3;
        if rgb.len() != expect {
            return Err(ClError::malformed(
                "raster",
                rgb.len(),
                format!("expected {expect} bytes for {width}x{height}"),
            ));
        }
        Ok(Raster { width, height, rgb })
    }

    pub fn pixel_count(&self) -> usize {
        (self.width as usize) * (self.height as usize)
    }

    pub fn get(&self, x: u32, y: u32) -> Option<[u8; 3]> {
        if x >= self.width || y >= self.height {
            return None;
        }
        let i = ((y as usize) * (self.width as usize) + (x as usize)) * 3;
        Some([self.rgb[i], self.rgb[i + 1], self.rgb[i + 2]])
    }

    pub fn set(&mut self, x: u32, y: u32, px: [u8; 3]) {
        if x >= self.width || y >= self.height {
            return;
        }
        let i = ((y as usize) * (self.width as usize) + (x as usize)) * 3;
        self.rgb[i] = px[0];
        self.rgb[i + 1] = px[1];
        self.rgb[i + 2] = px[2];
    }

    /// Index of the channel byte for a pixel, or `None` when out of range.
    pub fn channel_index(&self, index: usize, channel: usize) -> Option<usize> {
        if index >= self.pixel_count() || channel >= 3 {
            return None;
        }
        Some(index * 3 + channel)
    }

    pub fn digest(&self) -> crate::hash::Digest {
        let mut h = crate::hash::Hasher::new();
        h.update(&self.width.to_be_bytes());
        h.update(&self.height.to_be_bytes());
        h.update(&self.rgb);
        h.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_and_index() {
        let mut r = Raster::new(3, 2, [10, 20, 30]);
        assert_eq!(r.rgb.len(), 18);
        assert_eq!(r.get(2, 1), Some([10, 20, 30]));
        assert_eq!(r.get(3, 0), None);
        r.set(2, 1, [1, 2, 3]);
        assert_eq!(r.get(2, 1), Some([1, 2, 3]));
    }

    #[test]
    fn from_rgb_checks_length() {
        assert!(Raster::from_rgb(2, 2, vec![0; 12]).is_ok());
        assert!(Raster::from_rgb(2, 2, vec![0; 11]).is_err());
    }

    #[test]
    fn digest_changes_with_one_low_order_bit() {
        let a = Raster::new(4, 4, [200, 200, 200]);
        let mut b = a.clone();
        b.set(1, 1, [201, 200, 200]);
        assert_ne!(a.digest(), b.digest());
    }
}
