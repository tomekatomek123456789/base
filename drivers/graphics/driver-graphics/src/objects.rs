use std::collections::HashMap;
use std::ffi::c_char;

use drm_sys::{
    drm_mode_modeinfo, DRM_MODE_OBJECT_CONNECTOR, DRM_MODE_OBJECT_ENCODER,
    DRM_MODE_OBJECT_PROPERTY, DRM_PROP_NAME_LEN,
};
use syscall::{Error, Result, EINVAL};

use crate::GraphicsAdapter;

#[derive(Debug)]
pub struct DrmObjects<T: GraphicsAdapter> {
    next_id: DrmObjectId,
    connectors: Vec<DrmObjectId>,
    encoders: Vec<DrmObjectId>,
    objects: HashMap<DrmObjectId, DrmObject<T>>,
}

impl<T: GraphicsAdapter> DrmObjects<T> {
    pub(crate) fn new() -> Self {
        DrmObjects {
            next_id: DrmObjectId(1),
            connectors: vec![],
            encoders: vec![],
            objects: HashMap::new(),
        }
    }

    pub fn object_type(&self, id: DrmObjectId) -> Result<u32> {
        let object = self.objects.get(&id).ok_or(Error::new(EINVAL))?;
        Ok(match object.kind {
            DrmObjectKind::Property(_) => DRM_MODE_OBJECT_PROPERTY,
            DrmObjectKind::Connector(_) => DRM_MODE_OBJECT_CONNECTOR,
            DrmObjectKind::Encoder(_) => DRM_MODE_OBJECT_ENCODER,
        })
    }

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

        let id = self.next_id;
        self.objects.insert(
            id,
            DrmObject {
                kind: DrmObjectKind::Property(DrmProperty {
                    name: name_bytes,
                    immutable,
                    atomic,
                    kind,
                }),
                properties: vec![],
            },
        );
        self.next_id.0 += 1;

        id
    }

    pub fn get_property(&self, id: DrmObjectId) -> Result<&DrmProperty> {
        let object = self.objects.get(&id).ok_or(Error::new(EINVAL))?;
        match &object.kind {
            DrmObjectKind::Property(drm_property) => Ok(drm_property),
            _ => Err(Error::new(EINVAL)),
        }
    }

    pub fn add_object_property(&mut self, object: DrmObjectId, property: DrmObjectId, value: u64) {
        let object = self.objects.get_mut(&object).unwrap();
        // FIXME validate property
        object.properties.push((property, value));
    }

    pub fn get_object_properties(&self, id: DrmObjectId) -> Result<&[(DrmObjectId, u64)]> {
        let object = self.objects.get(&id).ok_or(Error::new(EINVAL))?;
        Ok(&object.properties)
    }

    pub fn add_connector(&mut self, driver_data: T::Connector) -> DrmObjectId {
        let connector_id = self.next_id;
        let encoder_id = DrmObjectId(self.next_id.0 + 1);
        self.objects.insert(
            connector_id,
            DrmObject {
                kind: DrmObjectKind::Connector(DrmConnector {
                    modes: vec![],
                    encoder_id,
                    connector_type: 0,
                    connector_type_id: 0,
                    connection: DrmConnectorStatus::Unknown,
                    mm_width: 0,
                    mm_height: 0,
                    subpixel: DrmSubpixelOrder::Unknown,
                    driver_data,
                }),
                properties: vec![],
            },
        );
        self.connectors.push(connector_id);

        self.objects.insert(
            encoder_id,
            DrmObject {
                kind: DrmObjectKind::Encoder(DrmEncoder {
                    crtc_id: DrmObjectId::INVALID,
                    possible_crtcs: 0,
                    possible_clones: 0,
                }),
                properties: vec![],
            },
        );
        self.encoders.push(encoder_id);
        self.next_id.0 += 2;

        connector_id
    }

    pub fn connector_ids(&self) -> &[DrmObjectId] {
        &self.connectors
    }

    pub fn connectors(&self) -> impl Iterator<Item = &DrmConnector<T>> + use<'_, T> {
        self.connectors
            .iter()
            .map(|&id| match &self.objects[&id].kind {
                DrmObjectKind::Connector(connector) => connector,
                _ => unreachable!(),
            })
    }

    pub fn for_each_connector_mut<'a>(&mut self, mut f: impl FnMut(&mut DrmConnector<T>)) {
        for id in &self.connectors {
            match &mut self.objects.get_mut(&id).unwrap().kind {
                DrmObjectKind::Connector(connector) => f(connector),
                _ => unreachable!(),
            }
        }
    }

    pub fn get_connector(&self, id: DrmObjectId) -> Result<&DrmConnector<T>> {
        let object = self.objects.get(&id).ok_or(Error::new(EINVAL))?;
        match &object.kind {
            DrmObjectKind::Connector(drm_connector) => Ok(drm_connector),
            _ => Err(Error::new(EINVAL)),
        }
    }

    pub fn get_connector_mut(&mut self, id: DrmObjectId) -> Result<&mut DrmConnector<T>> {
        let object = self.objects.get_mut(&id).ok_or(Error::new(EINVAL))?;
        match &mut object.kind {
            DrmObjectKind::Connector(drm_connector) => Ok(drm_connector),
            _ => Err(Error::new(EINVAL)),
        }
    }

    pub fn encoder_ids(&self) -> &[DrmObjectId] {
        &self.encoders
    }

    pub fn get_encoder(&self, id: DrmObjectId) -> Result<&DrmEncoder> {
        let object = self.objects.get(&id).ok_or(Error::new(EINVAL))?;
        match &object.kind {
            DrmObjectKind::Encoder(drm_encoder) => Ok(drm_encoder),
            _ => Err(Error::new(EINVAL)),
        }
    }

    pub fn get_encoder_mut(&mut self, id: DrmObjectId) -> Result<&mut DrmEncoder> {
        let object = self.objects.get_mut(&id).ok_or(Error::new(EINVAL))?;
        match &mut object.kind {
            DrmObjectKind::Encoder(drm_encoder) => Ok(drm_encoder),
            _ => Err(Error::new(EINVAL)),
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct DrmObjectId(pub(crate) u32);

impl DrmObjectId {
    pub const INVALID: DrmObjectId = DrmObjectId(0);
}

#[derive(Debug)]
struct DrmObject<T: GraphicsAdapter> {
    kind: DrmObjectKind<T>,
    properties: Vec<(DrmObjectId, u64)>,
}

#[derive(Debug)]
enum DrmObjectKind<T: GraphicsAdapter> {
    Property(DrmProperty),
    Connector(DrmConnector<T>),
    Encoder(DrmEncoder),
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

#[derive(Debug)]
pub struct DrmConnector<T: GraphicsAdapter> {
    pub modes: Vec<drm_mode_modeinfo>,
    pub encoder_id: DrmObjectId,
    pub connector_type: u32,
    pub connector_type_id: u32,
    pub connection: DrmConnectorStatus,
    pub mm_width: u32,
    pub mm_height: u32,
    pub subpixel: DrmSubpixelOrder,
    pub driver_data: T::Connector,
}

#[derive(Debug, Copy, Clone)]
#[repr(u32)]
pub enum DrmConnectorStatus {
    Disconnected = 0,
    Connected = 1,
    Unknown = 2,
}

#[derive(Debug, Copy, Clone)]
#[repr(u32)]
pub enum DrmSubpixelOrder {
    Unknown = 0,
    HorizontalRGB,
    HorizontalBGR,
    VerticalRGB,
    VerticalBGR,
    None,
}

// FIXME can we represent connector and encoder using a single struct?
#[derive(Debug)]
pub struct DrmEncoder {
    pub crtc_id: DrmObjectId,
    pub possible_crtcs: u32,
    pub possible_clones: u32,
}
