#![feature(slice_as_array)]

use std::collections::{BTreeMap, HashMap};
use std::ffi::c_char;
use std::fmt::Debug;
use std::fs::File;
use std::io::{self, Write};
use std::mem;
use std::mem::transmute;
use std::sync::Arc;

use drm_sys::{
    drm_mode_modeinfo, drm_mode_property_enum, DRM_MODE_DPMS_OFF, DRM_MODE_DPMS_ON,
    DRM_MODE_DPMS_STANDBY, DRM_MODE_DPMS_SUSPEND, DRM_MODE_PROP_ATOMIC, DRM_MODE_PROP_BITMASK,
    DRM_MODE_PROP_BLOB, DRM_MODE_PROP_ENUM, DRM_MODE_PROP_IMMUTABLE, DRM_MODE_PROP_OBJECT,
    DRM_MODE_PROP_RANGE, DRM_MODE_PROP_SIGNED_RANGE, DRM_PROP_NAME_LEN,
};
use graphics_ipc::v1::CursorDamage;
use graphics_ipc::v2::Damage;
use inputd::{VtEvent, VtEventKind};
use libredox::Fd;
use redox_scheme::scheme::SchemeSync;
use redox_scheme::{CallerCtx, OpenResult, RequestKind, SignalBehavior, Socket};
use syscall::schemev2::NewFdFlags;
use syscall::{Error, MapFlags, Result, EAGAIN, EBADF, EINVAL, ENOENT, EOPNOTSUPP};

use crate::objects::{DrmObjectId, DrmObjects, DrmPropertyKind};

pub mod objects;

#[derive(Debug, Copy, Clone)]
pub struct StandardProperties {
    pub edid: DrmObjectId,
    pub dpms: DrmObjectId,
}

pub trait GraphicsAdapter: Sized + Debug {
    type Connector: Debug;

    type Framebuffer: Framebuffer;
    type Cursor: CursorFramebuffer;

    fn name(&self) -> &'static [u8];
    fn desc(&self) -> &'static [u8];

    fn init(&mut self, objects: &mut DrmObjects<Self>, standard_properties: &StandardProperties);

    fn get_cap(&self, cap: u32) -> Result<u64>;
    fn set_client_cap(&self, cap: u32, value: u64) -> Result<()>;

    fn probe_connector(
        &mut self,
        objects: &mut DrmObjects<Self>,
        standard_properties: &StandardProperties,
        id: DrmObjectId,
    );

    /// The maximum amount of displays that could be attached.
    ///
    /// This must be constant for the lifetime of the graphics adapter.
    fn display_count(&self) -> usize;
    fn display_size(&self, display_id: usize) -> (u32, u32);

    fn create_dumb_framebuffer(&mut self, width: u32, height: u32) -> Self::Framebuffer;
    fn map_dumb_framebuffer(&mut self, framebuffer: &Self::Framebuffer) -> *mut u8;

    fn update_plane(&mut self, display_id: usize, framebuffer: &Self::Framebuffer, damage: Damage);

    fn supports_hw_cursor(&self) -> bool;
    fn create_cursor_framebuffer(&mut self) -> Self::Cursor;
    fn map_cursor_framebuffer(&mut self, cursor: &Self::Cursor) -> *mut u8;
    fn handle_cursor(&mut self, cursor: &CursorPlane<Self::Cursor>, dirty_fb: bool);
}

pub trait Framebuffer {
    fn width(&self) -> u32;
    fn height(&self) -> u32;
}

pub struct CursorPlane<C: CursorFramebuffer> {
    pub x: i32,
    pub y: i32,
    pub hot_x: i32,
    pub hot_y: i32,
    pub framebuffer: C,
}

pub trait CursorFramebuffer {}

pub struct GraphicsScheme<T: GraphicsAdapter> {
    adapter: T,

    scheme_name: String,
    disable_graphical_debug: Option<File>,
    socket: Socket,
    objects: DrmObjects<T>,
    standard_properties: StandardProperties,
    next_id: usize,
    handles: BTreeMap<usize, Handle<T>>,

    active_vt: usize,
    vts: HashMap<usize, VtState<T>>,
}

struct VtState<T: GraphicsAdapter> {
    display_fbs: Vec<Arc<T::Framebuffer>>,
    cursor_plane: Option<CursorPlane<T::Cursor>>,
}

enum Handle<T: GraphicsAdapter> {
    V1Screen {
        vt: usize,
        screen: usize,
    },
    V2 {
        vt: usize,
        next_id: u32,
        fbs: HashMap<u32, Arc<T::Framebuffer>>,
    },
}

impl<T: GraphicsAdapter> GraphicsScheme<T> {
    pub fn new(mut adapter: T, scheme_name: String) -> Self {
        assert!(scheme_name.starts_with("display"));
        let socket = Socket::nonblock(&scheme_name).expect("failed to create graphics scheme");

        let disable_graphical_debug = Some(
            File::open("/scheme/debug/disable-graphical-debug")
                .expect("vesad: Failed to open /scheme/debug/disable-graphical-debug"),
        );

        let mut objects = DrmObjects::new();

        let edid = objects.add_property("EDID", true, false, DrmPropertyKind::Blob);
        let dpms = objects.add_property(
            "DPMS",
            false,
            false,
            DrmPropertyKind::Enum(vec![
                ("On", DRM_MODE_DPMS_ON.into()),
                ("Standby", DRM_MODE_DPMS_STANDBY.into()),
                ("Suspend", DRM_MODE_DPMS_SUSPEND.into()),
                ("Off", DRM_MODE_DPMS_OFF.into()),
            ]),
        );
        let standard_properties = StandardProperties { edid, dpms };

        adapter.init(&mut objects, &standard_properties);
        for connector_id in objects.connector_ids().to_vec() {
            adapter.probe_connector(&mut objects, &standard_properties, connector_id)
        }

        GraphicsScheme {
            adapter,
            scheme_name,
            disable_graphical_debug,
            socket,
            objects,
            standard_properties,
            next_id: 0,
            handles: BTreeMap::new(),
            active_vt: 0,
            vts: HashMap::new(),
        }
    }

    pub fn event_handle(&self) -> &Fd {
        self.socket.inner()
    }

    pub fn adapter(&self) -> &T {
        &self.adapter
    }

    pub fn adapter_mut(&mut self) -> &mut T {
        &mut self.adapter
    }

    pub fn objects(&self) -> &DrmObjects<T> {
        &self.objects
    }

    pub fn objects_mut(&mut self) -> &mut DrmObjects<T> {
        &mut self.objects
    }

    pub fn adapter_and_objects_mut(&mut self) -> (&mut T, &mut DrmObjects<T>) {
        (&mut self.adapter, &mut self.objects)
    }

    pub fn standard_properties(&self) -> StandardProperties {
        self.standard_properties
    }

    pub fn handle_vt_event(&mut self, vt_event: VtEvent) {
        match vt_event.kind {
            VtEventKind::Activate => {
                log::info!("activate {}", vt_event.vt);

                // Disable the kernel graphical debug writing once switching vt's for the
                // first time. This way the kernel graphical debug remains enabled if the
                // userspace logging infrastructure doesn't start up because for example a
                // kernel panic happened prior to it starting up or logd crashed.
                if let Some(mut disable_graphical_debug) = self.disable_graphical_debug.take() {
                    let _ = disable_graphical_debug.write(&[1]);
                }

                self.active_vt = vt_event.vt;

                let vt_state =
                    Self::get_or_create_vt(&mut self.adapter, &mut self.vts, vt_event.vt);

                for (display_id, fb) in vt_state.display_fbs.iter().enumerate() {
                    Self::update_whole_screen(&mut self.adapter, display_id, fb);
                }

                if let Some(cursor_plane) = &vt_state.cursor_plane {
                    self.adapter.handle_cursor(cursor_plane, true);
                }
            }

            VtEventKind::Resize => {
                log::warn!("driver-graphics: resize is not implemented yet")
            }
        }
    }

    pub fn notify_displays_changed(&mut self) {
        // FIXME notify clients
    }

    /// Process new scheme requests.
    ///
    /// This needs to be called each time there is a new event on the scheme
    /// file.
    pub fn tick(&mut self) -> io::Result<()> {
        loop {
            let request = match self.socket.next_request(SignalBehavior::Restart) {
                Ok(Some(request)) => request,
                Ok(None) => {
                    // Scheme likely got unmounted
                    std::process::exit(0);
                }
                Err(err) if err.errno == EAGAIN => break,
                Err(err) => panic!("driver-graphics: failed to read display scheme: {err}"),
            };

            match request.kind() {
                RequestKind::Call(call) => {
                    let response = call.handle_sync(self);
                    self.socket
                        .write_response(response, SignalBehavior::Restart)
                        .expect("driver-graphics: failed to write response");
                }
                RequestKind::OnClose { id } => {
                    self.on_close(id);
                }
                _ => (),
            }
        }

        Ok(())
    }

    fn update_whole_screen(adapter: &mut T, screen: usize, framebuffer: &T::Framebuffer) {
        adapter.update_plane(
            screen,
            framebuffer,
            Damage {
                x: 0,
                y: 0,
                width: framebuffer.width(),
                height: framebuffer.height(),
            },
        );
    }

    fn get_or_create_vt<'a>(
        adapter: &mut T,
        vts: &'a mut HashMap<usize, VtState<T>>,
        vt: usize,
    ) -> &'a mut VtState<T> {
        vts.entry(vt).or_insert_with(|| {
            let mut display_fbs = vec![];
            for display_id in 0..adapter.display_count() {
                let (width, height) = adapter.display_size(display_id);
                display_fbs.push(Arc::new(adapter.create_dumb_framebuffer(width, height)));
            }

            let cursor_plane = adapter.supports_hw_cursor().then(|| CursorPlane {
                x: 0,
                y: 0,
                hot_x: 0,
                hot_y: 0,
                framebuffer: adapter.create_cursor_framebuffer(),
            });

            VtState {
                display_fbs,
                cursor_plane,
            }
        })
    }
}

const MAP_FAKE_OFFSET_MULTIPLIER: usize = 0x10_000_000;

impl<T: GraphicsAdapter> SchemeSync for GraphicsScheme<T> {
    fn open(&mut self, path: &str, _flags: usize, _ctx: &CallerCtx) -> Result<OpenResult> {
        if path.is_empty() {
            return Err(Error::new(EINVAL));
        }

        let handle = if path.starts_with("v") {
            if !path.starts_with("v2/") {
                return Err(Error::new(ENOENT));
            }
            let vt = path["v2/".len()..]
                .parse::<usize>()
                .map_err(|_| Error::new(EINVAL))?;

            // Ensure the VT exists such that the rest of the methods can freely access it.
            Self::get_or_create_vt(&mut self.adapter, &mut self.vts, vt);

            Handle::V2 {
                vt,
                next_id: 0,
                fbs: HashMap::new(),
            }
        } else {
            let mut parts = path.split('/');
            let mut screen = parts.next().unwrap_or("").split('.');

            let vt = screen.next().unwrap_or("").parse::<usize>().unwrap();
            let id = screen.next().unwrap_or("").parse::<usize>().unwrap_or(0);

            if id >= self.adapter.display_count() {
                return Err(Error::new(EINVAL));
            }

            // Ensure the VT exists such that the rest of the methods can freely access it.
            Self::get_or_create_vt(&mut self.adapter, &mut self.vts, vt);

            Handle::V1Screen { vt, screen: id }
        };
        self.next_id += 1;
        self.handles.insert(self.next_id, handle);
        Ok(OpenResult::ThisScheme {
            number: self.next_id,
            flags: NewFdFlags::empty(),
        })
    }

    fn fpath(&mut self, id: usize, buf: &mut [u8], _ctx: &CallerCtx) -> syscall::Result<usize> {
        let path = match self.handles.get(&id).ok_or(Error::new(EBADF))? {
            Handle::V1Screen { vt, screen } => {
                let framebuffer = &self.vts[vt].display_fbs[*screen];
                format!(
                    "{}:{vt}.{screen}/{}/{}",
                    self.scheme_name,
                    framebuffer.width(),
                    framebuffer.height()
                )
            }
            Handle::V2 {
                vt,
                next_id: _,
                fbs: _,
            } => format!("/scheme/{}/v2/{vt}", self.scheme_name),
        };
        buf[..path.len()].copy_from_slice(path.as_bytes());
        Ok(path.len())
    }

    fn fsync(&mut self, id: usize, _ctx: &CallerCtx) -> syscall::Result<()> {
        match self.handles.get(&id).ok_or(Error::new(EBADF))? {
            Handle::V1Screen { vt, screen } => {
                if *vt != self.active_vt {
                    // This is a protection against background VT's spamming us with flush requests. We will
                    // flush the framebuffer on the next VT switch anyway
                    return Ok(());
                }
                Self::update_whole_screen(
                    &mut self.adapter,
                    *screen,
                    &self.vts[vt].display_fbs[*screen],
                );
                Ok(())
            }
            Handle::V2 { .. } => Err(Error::new(EOPNOTSUPP)),
        }
    }

    fn read(
        &mut self,
        id: usize,
        buf: &mut [u8],
        _offset: u64,
        _fcntl_flags: u32,
        _ctx: &CallerCtx,
    ) -> Result<usize> {
        match self.handles.get(&id).ok_or(Error::new(EBADF))? {
            Handle::V1Screen { .. } => {
                //Currently read is only used for Orbital to check GPU cursor support
                //and only expects a buf to pass a 0 or 1 flag
                if self.adapter.supports_hw_cursor() {
                    buf[0] = 1;
                } else {
                    buf[0] = 0;
                }

                Ok(1)
            }
            Handle::V2 { .. } => Err(Error::new(EOPNOTSUPP)),
        }
    }

    fn write(
        &mut self,
        id: usize,
        buf: &[u8],
        _offset: u64,
        _fcntl_flags: u32,
        _ctx: &CallerCtx,
    ) -> Result<usize> {
        match self.handles.get(&id).ok_or(Error::new(EBADF))? {
            Handle::V1Screen { vt, screen } => {
                if *vt != self.active_vt {
                    // This is a protection against background VT's spamming us with flush requests. We will
                    // flush the framebuffer on the next VT switch anyway
                    return Ok(buf.len());
                }

                let vt_state = self.vts.get_mut(vt).unwrap();

                if size_of_val(buf) == std::mem::size_of::<CursorDamage>() {
                    let Some(cursor_plane) = &mut vt_state.cursor_plane else {
                        // Hardware cursor not supported
                        return Err(Error::new(EINVAL));
                    };

                    let cursor_damage = unsafe { *buf.as_ptr().cast::<CursorDamage>() };

                    cursor_plane.x = cursor_damage.x;
                    cursor_plane.y = cursor_damage.y;

                    if cursor_damage.header == 0 {
                        self.adapter.handle_cursor(cursor_plane, false);
                    } else {
                        cursor_plane.hot_x = cursor_damage.hot_x;
                        cursor_plane.hot_y = cursor_damage.hot_y;

                        let w: i32 = cursor_damage.width;
                        let h: i32 = cursor_damage.height;
                        let cursor_image = cursor_damage.cursor_img_bytes;
                        let cursor_ptr = self
                            .adapter
                            .map_cursor_framebuffer(&cursor_plane.framebuffer);

                        //Clear previous image from backing storage
                        unsafe {
                            core::ptr::write_bytes(cursor_ptr as *mut u8, 0, 64 * 64 * 4);
                        }

                        //Write image to backing storage
                        for row in 0..h {
                            let start: usize = (w * row) as usize;
                            let end: usize = (w * row + w) as usize;

                            unsafe {
                                core::ptr::copy_nonoverlapping(
                                    cursor_image[start..end].as_ptr(),
                                    cursor_ptr.cast::<u32>().offset(64 * row as isize),
                                    w as usize,
                                );
                            }
                        }

                        self.adapter.handle_cursor(cursor_plane, true);
                    }

                    return Ok(buf.len());
                }

                assert_eq!(buf.len(), std::mem::size_of::<Damage>());
                let damage = unsafe { *buf.as_ptr().cast::<Damage>() };

                self.adapter
                    .update_plane(*screen, &vt_state.display_fbs[*screen], damage);

                Ok(buf.len())
            }
            Handle::V2 { .. } => Err(Error::new(EOPNOTSUPP)),
        }
    }

    fn call(
        &mut self,
        id: usize,
        payload: &mut [u8],
        metadata: &[u64],
        _ctx: &CallerCtx,
    ) -> Result<usize> {
        use graphics_ipc::v2::ipc;

        const DRM_FORMAT_ARGB8888: u32 = 0x34325241; // 'AR24' fourcc code, for ARGB8888

        fn id_index(id: u32) -> u32 {
            id & 0xFF
        }

        fn crtc_id(i: u32) -> u32 {
            id_index(i) | (1 << 10)
        }

        fn fb_id(i: u32) -> u32 {
            id_index(i) | (1 << 11)
        }

        fn fb_handle_id(i: u32) -> u32 {
            id_index(i) | (1 << 12)
        }

        fn plane_id(i: u32) -> u32 {
            id_index(i) | (1 << 13)
        }

        fn dumb_buffer_id(i: u32) -> u32 {
            id_index(i) | (1 << 14)
        }

        match self.handles.get_mut(&id).ok_or(Error::new(EBADF))? {
            Handle::V1Screen { .. } => {
                return Err(Error::new(EOPNOTSUPP));
            }
            Handle::V2 { vt, next_id, fbs } => match metadata[0] {
                ipc::VERSION => ipc::DrmVersion::with(payload, |mut data| {
                    data.set_version_major(1);
                    data.set_version_minor(4);
                    data.set_version_patchlevel(0);

                    data.set_name(unsafe { mem::transmute(self.adapter.name()) });
                    data.set_date(unsafe { mem::transmute(&b"0"[..]) });
                    data.set_desc(unsafe { mem::transmute(self.adapter.desc()) });

                    Ok(0)
                }),
                ipc::GET_CAP => ipc::DrmGetCap::with(payload, |mut data| {
                    data.set_value(
                        self.adapter.get_cap(
                            data.capability()
                                .try_into()
                                .map_err(|_| syscall::Error::new(EINVAL))?,
                        )?,
                    );
                    Ok(0)
                }),
                ipc::SET_CLIENT_CAP => ipc::DrmSetClientCap::with(payload, |data| {
                    self.adapter.set_client_cap(
                        data.capability()
                            .try_into()
                            .map_err(|_| syscall::Error::new(EINVAL))?,
                        data.value(),
                    )?;
                    Ok(0)
                }),
                ipc::MODE_CARD_RES => ipc::DrmModeCardRes::with(payload, |mut data| {
                    let count = self.adapter.display_count();
                    let conn_ids = self
                        .objects
                        .connector_ids()
                        .iter()
                        .map(|id| id.0)
                        .collect::<Vec<_>>();
                    let mut crtc_ids = Vec::with_capacity(count);
                    let enc_ids = self
                        .objects
                        .encoder_ids()
                        .iter()
                        .map(|id| id.0)
                        .collect::<Vec<_>>();
                    let mut fb_ids = Vec::with_capacity(count);
                    for i in 0..(count as u32) {
                        crtc_ids.push(crtc_id(i));
                        fb_ids.push(fb_id(i));
                    }
                    data.set_fb_id_ptr(&fb_ids);
                    data.set_crtc_id_ptr(&crtc_ids);
                    data.set_connector_id_ptr(&conn_ids);
                    data.set_encoder_id_ptr(&enc_ids);
                    data.set_min_width(0);
                    data.set_max_width(16384);
                    data.set_min_height(0);
                    data.set_max_height(16384);
                    Ok(0)
                }),
                ipc::MODE_GET_CRTC => ipc::DrmModeCrtc::with(payload, |mut data| {
                    let i = id_index(data.crtc_id());
                    //TOOD: connectors
                    data.set_fb_id(fb_id(i));
                    data.set_x(0);
                    data.set_y(0);
                    data.set_gamma_size(0);
                    data.set_mode_valid(0);
                    //TODO: mode
                    data.set_mode(Default::default());
                    Ok(0)
                }),
                ipc::MODE_GET_ENCODER => ipc::DrmModeGetEncoder::with(payload, |mut data| {
                    let encoder = self.objects.get_encoder(DrmObjectId(data.encoder_id()))?;
                    data.set_crtc_id(encoder.crtc_id.0);
                    data.set_possible_crtcs(encoder.possible_crtcs);
                    data.set_possible_clones(encoder.possible_clones);
                    Ok(0)
                }),
                ipc::MODE_GET_CONNECTOR => ipc::DrmModeGetConnector::with(payload, |mut data| {
                    if data.count_modes() == 0 {
                        self.adapter.probe_connector(
                            &mut self.objects,
                            &self.standard_properties,
                            DrmObjectId(data.connector_id()),
                        );
                    }
                    let connector = self
                        .objects
                        .get_connector_mut(DrmObjectId(data.connector_id()))?;
                    data.set_connection(connector.connection as u32);
                    data.set_modes_ptr(&connector.modes);
                    data.set_mm_width(connector.mm_width);
                    data.set_mm_height(connector.mm_width);
                    data.set_subpixel(connector.subpixel as u32);
                    data.set_encoders_ptr(&[connector.encoder_id.0]);
                    let props = self
                        .objects
                        .get_object_properties(DrmObjectId(data.connector_id()))?;
                    data.set_props_ptr(&props.iter().map(|&(id, _)| id.0).collect::<Vec<_>>());
                    data.set_prop_values_ptr(
                        &props.iter().map(|&(_, value)| value).collect::<Vec<_>>(),
                    );
                    Ok(0)
                }),
                ipc::MODE_GET_PROPERTY => ipc::DrmModeGetProperty::with(payload, |mut data| {
                    let property = self.objects.get_property(DrmObjectId(data.prop_id()))?;
                    data.set_name(property.name);
                    let mut flags = 0;
                    if property.immutable {
                        flags |= DRM_MODE_PROP_IMMUTABLE;
                    }
                    if property.atomic {
                        flags |= DRM_MODE_PROP_ATOMIC;
                    }
                    match &property.kind {
                        &DrmPropertyKind::Range(start, end) => {
                            data.set_flags(flags | DRM_MODE_PROP_RANGE);
                            data.set_values_ptr(&[start, end]);
                            data.set_enum_blob_ptr(&[]);
                        }
                        DrmPropertyKind::Enum(variants) => {
                            data.set_flags(flags | DRM_MODE_PROP_ENUM);
                            data.set_values_ptr(
                                &variants.iter().map(|&(_, value)| value).collect::<Vec<_>>(),
                            );
                            data.set_enum_blob_ptr(
                                &variants
                                    .iter()
                                    .map(|&(name, value)| {
                                        let mut name_bytes = [0; DRM_PROP_NAME_LEN as usize];
                                        for (to, &from) in
                                            name_bytes.iter_mut().zip(name.as_bytes())
                                        {
                                            *to = from as c_char;
                                        }
                                        drm_mode_property_enum {
                                            name: name_bytes,
                                            value,
                                        }
                                    })
                                    .collect::<Vec<_>>(),
                            );
                        }
                        DrmPropertyKind::Blob => {
                            data.set_flags(flags | DRM_MODE_PROP_BLOB);
                            data.set_values_ptr(&[]);
                            data.set_enum_blob_ptr(&[]);
                        }
                        DrmPropertyKind::Bitmask(bitmask_flags) => {
                            data.set_flags(flags | DRM_MODE_PROP_BITMASK);
                            data.set_values_ptr(
                                &bitmask_flags
                                    .iter()
                                    .map(|&(_, value)| value)
                                    .collect::<Vec<_>>(),
                            );
                            data.set_enum_blob_ptr(
                                &bitmask_flags
                                    .iter()
                                    .map(|&(name, value)| {
                                        let mut name_bytes = [0; DRM_PROP_NAME_LEN as usize];
                                        for (to, &from) in
                                            name_bytes.iter_mut().zip(name.as_bytes())
                                        {
                                            *to = from as c_char;
                                        }
                                        drm_mode_property_enum {
                                            name: name_bytes,
                                            value,
                                        }
                                    })
                                    .collect::<Vec<_>>(),
                            );
                        }
                        DrmPropertyKind::Object => {
                            data.set_flags(flags | DRM_MODE_PROP_OBJECT);
                            data.set_values_ptr(&[]);
                            data.set_enum_blob_ptr(&[]);
                        }
                        &DrmPropertyKind::SignedRange(start, end) => {
                            data.set_flags(flags | DRM_MODE_PROP_SIGNED_RANGE);
                            data.set_values_ptr(&[start as u64, end as u64]);
                            data.set_enum_blob_ptr(&[]);
                        }
                    }
                    Ok(0)
                }),
                ipc::MODE_GET_PROP_BLOB => ipc::DrmModeGetBlob::with(payload, |mut data| {
                    let blob = self.objects.get_blob(DrmObjectId(data.blob_id()))?;
                    data.set_data(&blob);
                    Ok(0)
                }),
                ipc::MODE_GET_FB => ipc::DrmModeFbCmd::with(payload, |mut data| {
                    let i = id_index(data.fb_id());
                    let (width, height) = self.adapter.display_size(i as usize);
                    data.set_width(width);
                    data.set_height(height);
                    data.set_pitch(width * 4); //TODO: stride
                    data.set_bpp(32);
                    data.set_depth(24);
                    data.set_handle(fb_handle_id(i));
                    Ok(0)
                }),
                ipc::MODE_CREATE_DUMB => ipc::DrmModeCreateDumb::with(payload, |mut data| {
                    if data.bpp() != 32 {
                        return Err(Error::new(EINVAL));
                    }

                    let fb = self
                        .adapter
                        .create_dumb_framebuffer(data.width(), data.height());

                    *next_id += 1;
                    fbs.insert(*next_id, Arc::new(fb));
                    data.set_handle(dumb_buffer_id(*next_id as u32));
                    data.set_pitch(data.width() * 4);
                    data.set_size(u64::from(data.width()) * u64::from(data.height()) * 4);
                    Ok(0)
                }),
                ipc::MODE_MAP_DUMB => ipc::DrmModeMapDumb::with(payload, |mut data| {
                    if data.offset() != 0 {
                        return Err(Error::new(EINVAL));
                    }

                    let fb_id = id_index(data.handle());

                    if !fbs.contains_key(&fb_id) {
                        return Err(Error::new(EINVAL));
                    }

                    // FIXME use a better scheme for creating map offsets
                    assert!(
                        ((fbs[&fb_id].width() * fbs[&fb_id].height() * 4) as usize)
                            < MAP_FAKE_OFFSET_MULTIPLIER
                    );

                    data.set_offset((fb_id as usize * MAP_FAKE_OFFSET_MULTIPLIER) as u64);

                    Ok(0)
                }),
                ipc::MODE_DESTROY_DUMB => ipc::DrmModeDestroyDumb::with(payload, |data| {
                    let fb_id = id_index(data.handle());
                    if fbs.remove(&fb_id).is_none() {
                        return Err(Error::new(ENOENT));
                    }
                    Ok(0)
                }),
                ipc::MODE_GET_PLANE_RES => ipc::DrmModeGetPlaneRes::with(payload, |mut data| {
                    let count = self.adapter.display_count();
                    let mut ids = Vec::with_capacity(count);
                    for i in 0..(count as u32) {
                        ids.push(plane_id(i));
                    }
                    data.set_plane_id_ptr(&ids);
                    Ok(0)
                }),
                ipc::MODE_GET_PLANE => ipc::DrmModeGetPlane::with(payload, |mut data| {
                    let i = id_index(data.plane_id());
                    data.set_crtc_id(crtc_id(i));
                    data.set_fb_id(fb_id(i));
                    data.set_possible_crtcs(1 << i);
                    data.set_format_type_ptr(&[DRM_FORMAT_ARGB8888]);
                    Ok(0)
                }),
                ipc::MODE_OBJ_GET_PROPERTIES => {
                    ipc::DrmModeObjGetProperties::with(payload, |mut data| {
                        // FIXME remove once all drm objects are materialized in self.objects
                        if data.obj_id() >= 1 << 10 {
                            data.set_props_ptr(&[]);
                            data.set_prop_values_ptr(&[]);
                            return Ok(0);
                        }

                        let props = self
                            .objects
                            .get_object_properties(DrmObjectId(data.obj_id()))?;
                        data.set_props_ptr(&props.iter().map(|&(id, _)| id.0).collect::<Vec<_>>());
                        data.set_prop_values_ptr(
                            &props.iter().map(|&(_, value)| value).collect::<Vec<_>>(),
                        );
                        data.set_obj_type(self.objects.object_type(DrmObjectId(data.obj_id()))?);
                        Ok(0)
                    })
                }
                ipc::MODE_GET_FB2 => ipc::DrmModeFbCmd2::with(payload, |mut data| {
                    let i = id_index(data.fb_id());
                    let (width, height) = self.adapter.display_size(i as usize);
                    data.set_width(width);
                    data.set_height(height);
                    data.set_pixel_format(DRM_FORMAT_ARGB8888);
                    data.set_handles([fb_handle_id(i), 0, 0, 0]);
                    data.set_pitches([width * 4, 0, 0, 0]);
                    data.set_offsets([0; 4]);
                    data.set_modifier([0; 4]);
                    Ok(0)
                }),
                ipc::UPDATE_PLANE => {
                    if payload.len() < size_of::<ipc::UpdatePlane>() {
                        return Err(Error::new(EINVAL));
                    }
                    let payload = unsafe {
                        transmute::<&mut [u8; size_of::<ipc::UpdatePlane>()], &mut ipc::UpdatePlane>(
                            payload.as_mut_array().unwrap(),
                        )
                    };

                    let display_id = payload.display_id;
                    if display_id >= self.adapter.display_count() {
                        return Err(Error::new(EINVAL));
                    }

                    let Some(framebuffer) = fbs.get(&id_index(payload.fb_id)) else {
                        return Err(Error::new(EINVAL));
                    };

                    self.vts.get_mut(vt).unwrap().display_fbs[display_id] = framebuffer.clone();

                    if *vt == self.active_vt {
                        self.adapter
                            .update_plane(display_id, framebuffer, payload.damage);
                    }

                    Ok(size_of::<ipc::UpdatePlane>())
                }
                _ => return Err(Error::new(EINVAL)),
            },
        }
    }

    fn mmap_prep(
        &mut self,
        id: usize,
        offset: u64,
        _size: usize,
        _flags: MapFlags,
        _ctx: &CallerCtx,
    ) -> syscall::Result<usize> {
        // log::trace!("KSMSG MMAP {} {:?} {} {}", id, _flags, _offset, _size);
        let (framebuffer, offset) = match self.handles.get(&id).ok_or(Error::new(EINVAL))? {
            Handle::V1Screen { vt, screen } => (&self.vts[vt].display_fbs[*screen], offset),
            Handle::V2 {
                vt: _,
                next_id: _,
                fbs,
            } => (
                fbs.get(&((offset as usize / MAP_FAKE_OFFSET_MULTIPLIER) as u32))
                    .ok_or(Error::new(EINVAL))
                    .unwrap(),
                offset & (MAP_FAKE_OFFSET_MULTIPLIER as u64 - 1),
            ),
        };
        let ptr = T::map_dumb_framebuffer(&mut self.adapter, framebuffer);
        Ok(unsafe { ptr.add(offset as usize) } as usize)
    }
}

impl<T: GraphicsAdapter> GraphicsScheme<T> {
    fn on_close(&mut self, id: usize) {
        self.handles.remove(&id);
    }
}

pub fn modeinfo_for_size(width: u32, height: u32) -> drm_mode_modeinfo {
    let mut modeinfo = drm_mode_modeinfo {
        // The actual visible display size
        hdisplay: width as u16,
        vdisplay: height as u16,

        // These are used to calculate the refresh rate
        clock: 60 * width * height / 1000,
        htotal: width as u16,
        vtotal: height as u16,
        vscan: 0,
        vrefresh: 60,

        type_: drm_sys::DRM_MODE_TYPE_PREFERRED | drm_sys::DRM_MODE_TYPE_DRIVER,
        name: [0; 32],

        // These only matter when modesetting physical display adapters. For
        // those we should be able to parse the EDID blob.
        hsync_start: width as u16,
        hsync_end: width as u16,
        hskew: 0,
        vsync_start: height as u16,
        vsync_end: height as u16,
        flags: 0,
    };

    let name = format!("{width}x{height}").into_bytes();
    for (to, from) in modeinfo.name.iter_mut().zip(name) {
        *to = from as c_char;
    }

    modeinfo
}
