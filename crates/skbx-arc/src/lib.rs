//! skbx Arc: a local-first command center for bounded multi-host captures.
//!
//! Arc never replaces a sensor's `traceq` artifact. It validates and indexes
//! complete artifacts, then produces a separate mission view whose
//! cross-sensor edges are explicitly correlated, candidate, or unknown.

mod api;
mod demo;
mod state;

pub use api::{ApiErrorBody, app};
pub use demo::demo_control_plane;
pub use state::{
    ArcError, ConsoleSnapshot, ControlPlane, SensorView, SharedControlPlane, TimelineEvent, shared,
};
