use std::ffi::c_char;
use std::fmt::Debug;

use drm_sys::{DRM_MODE_OBJECT_BLOB, DRM_MODE_OBJECT_PROPERTY, DRM_PROP_NAME_LEN};
use syscall::{Error, Result, EINVAL};

use crate::objects::{DrmObject, DrmObjectId, DrmObjects};
use crate::GraphicsAdapter;

impl<T: GraphicsAdapter> DrmObjects<T> {
    pub fn add_property(
        &mut self,
        name: &str,
        immutable: bool,
        atomic: bool,
        kind: DrmPropertyKind,
    ) -> DrmObjectId {
        if name.len() > DRM_PROP_NAME_LEN as usize {
            panic!("Property name {name} is too long");
        }

        match &kind {
            DrmPropertyKind::Range(start, end) => assert!(start < end),
            DrmPropertyKind::Enum(variants) => {
                // FIXME check duplicate variant numbers
                for (variant_name, _) in variants {
                    if variant_name.len() > DRM_PROP_NAME_LEN as usize {
                        panic!("Property variant name {variant_name} is too long");
                    }
                }
            }
            DrmPropertyKind::Blob => {}
            DrmPropertyKind::Bitmask(bitmask_flags) => {
                // FIXME check overlapping flag numbers
                for (flag_name, _) in bitmask_flags {
                    if flag_name.len() > DRM_PROP_NAME_LEN as usize {
                        panic!("Property bitflag name {flag_name} is too long");
                    }
                }
            }
            DrmPropertyKind::Object => {}
            DrmPropertyKind::SignedRange(start, end) => assert!(start < end),
        }

        let mut name_bytes = [0; DRM_PROP_NAME_LEN as usize];
        for (to, &from) in name_bytes.iter_mut().zip(name.as_bytes()) {
            *to = from as c_char;
        }

        self.add(DrmProperty {
            name: name_bytes,
            immutable,
            atomic,
            kind,
        })
    }

    pub fn get_property(&self, id: DrmObjectId) -> Result<&DrmProperty> {
        self.get(id)
    }

    pub fn add_object_property(&mut self, object: DrmObjectId, property: DrmObjectId, value: u64) {
        let object = self.objects.get_mut(&object).unwrap();
        // FIXME validate property uniqueness and value
        object.properties.push((property, value));
    }

    pub fn set_object_property(&mut self, object: DrmObjectId, property: DrmObjectId, value: u64) {
        let object = self.objects.get_mut(&object).unwrap();
        // FIXME validate property existence and value
        for (prop, val) in object.properties.iter_mut() {
            if *prop == property {
                *val = value;
            }
        }
    }

    pub fn get_object_properties(&self, id: DrmObjectId) -> Result<&[(DrmObjectId, u64)]> {
        let object = self.objects.get(&id).ok_or(Error::new(EINVAL))?;
        Ok(&object.properties)
    }

    pub fn add_blob(&mut self, data: Vec<u8>) -> DrmObjectId {
        self.add(DrmBlob { data })
    }

    pub fn get_blob(&self, id: DrmObjectId) -> Result<&[u8]> {
        Ok(&self.get::<DrmBlob>(id)?.data)
    }
}

#[derive(Debug)]
pub struct DrmProperty {
    pub name: [c_char; DRM_PROP_NAME_LEN as usize],
    pub immutable: bool,
    pub atomic: bool,
    pub kind: DrmPropertyKind,
}

#[derive(Debug)]
pub enum DrmPropertyKind {
    Range(u64, u64),
    Enum(Vec<(&'static str, u64)>),
    Blob,
    Bitmask(Vec<(&'static str, u64)>),
    Object,
    SignedRange(i64, i64),
}

impl DrmObject for DrmProperty {
    fn object_type(&self) -> u32 {
        DRM_MODE_OBJECT_PROPERTY
    }
}

#[derive(Debug)]
pub struct DrmBlob {
    data: Vec<u8>,
}

impl DrmObject for DrmBlob {
    fn object_type(&self) -> u32 {
        DRM_MODE_OBJECT_BLOB
    }
}
