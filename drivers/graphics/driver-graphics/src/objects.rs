use std::collections::HashMap;

use drm_sys::drm_mode_modeinfo;
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
}

#[derive(Debug)]
enum DrmObjectKind<T: GraphicsAdapter> {
    Connector(DrmConnector<T>),
    Encoder(DrmEncoder),
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
