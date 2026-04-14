use bilge::prelude::*;

#[bitsize(8)]
#[derive(DebugBits, FromBits, Clone)]
pub struct TelemetryPermissions {
    base: bool,
    location: bool,
    environment: bool,
    reserved: u5,
}
