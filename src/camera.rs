//! The two cameras, and a container holding one value per camera.

use std::fmt;

use serde::Serialize;

/// One of the vessel's two cameras.
///
/// A third camera can't be represented, so code that handles a `Camera` never
/// has to consider an unknown one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Camera {
    Cam1,
    Cam2,
}

impl Camera {
    /// Both cameras, in output order.
    pub const ALL: [Self; 2] = [Self::Cam1, Self::Cam2];

    /// The camera identified by a frame's camera byte, if any.
    #[must_use]
    pub const fn from_wire(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::Cam1),
            0x02 => Some(Self::Cam2),
            _ => None,
        }
    }

    /// The name used in commands and responses.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Cam1 => "cam1",
            Self::Cam2 => "cam2",
        }
    }

    /// The other camera.
    #[must_use]
    pub const fn other(self) -> Self {
        match self {
            Self::Cam1 => Self::Cam2,
            Self::Cam2 => Self::Cam1,
        }
    }
}

impl fmt::Display for Camera {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl Serialize for Camera {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.name())
    }
}

/// One value per camera.
///
/// Lookups take a [`Camera`], so they can't go out of bounds. Serializes as
/// `{"cam1": ..., "cam2": ...}`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct PerCamera<T> {
    cam1: T,
    cam2: T,
}

impl<T> PerCamera<T> {
    /// Builds the value for each camera with `make`.
    pub fn from_fn(mut make: impl FnMut(Camera) -> T) -> Self {
        Self {
            cam1: make(Camera::Cam1),
            cam2: make(Camera::Cam2),
        }
    }

    /// Wraps an existing value for each camera.
    pub const fn new(cam1: T, cam2: T) -> Self {
        Self { cam1, cam2 }
    }

    #[must_use]
    pub const fn get(&self, camera: Camera) -> &T {
        match camera {
            Camera::Cam1 => &self.cam1,
            Camera::Cam2 => &self.cam2,
        }
    }

    pub const fn get_mut(&mut self, camera: Camera) -> &mut T {
        match camera {
            Camera::Cam1 => &mut self.cam1,
            Camera::Cam2 => &mut self.cam2,
        }
    }

    /// Mutable access to one camera's value and the other camera's value at once.
    pub const fn this_and_other_mut(&mut self, camera: Camera) -> (&mut T, &mut T) {
        match camera {
            Camera::Cam1 => (&mut self.cam1, &mut self.cam2),
            Camera::Cam2 => (&mut self.cam2, &mut self.cam1),
        }
    }

    /// Applies `f` to each camera's value.
    pub fn map<U>(&self, mut f: impl FnMut(Camera, &T) -> U) -> PerCamera<U> {
        PerCamera {
            cam1: f(Camera::Cam1, &self.cam1),
            cam2: f(Camera::Cam2, &self.cam2),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_bytes_map_to_cameras() {
        assert_eq!(Camera::from_wire(0x01), Some(Camera::Cam1));
        assert_eq!(Camera::from_wire(0x02), Some(Camera::Cam2));
        for byte in [0x00, 0x03, 0xff] {
            assert_eq!(Camera::from_wire(byte), None);
        }
    }

    #[test]
    fn other_swaps_cameras() {
        assert_eq!(Camera::Cam1.other(), Camera::Cam2);
        assert_eq!(Camera::Cam2.other(), Camera::Cam1);
    }

    #[test]
    fn per_camera_lookups_and_split_borrows() {
        let mut values = PerCamera::new(1, 2);
        assert_eq!(*values.get(Camera::Cam2), 2);
        let (this, other) = values.this_and_other_mut(Camera::Cam2);
        *this = 20;
        *other = 10;
        assert_eq!(values, PerCamera::new(10, 20));
        assert_eq!(
            serde_json::to_string(&values).unwrap(),
            r#"{"cam1":10,"cam2":20}"#
        );
    }
}
