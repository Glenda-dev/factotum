#![no_std]
#![no_main]
#![allow(dead_code)]

#[macro_use]
extern crate glenda;
extern crate alloc;

mod layout;
mod manager;
mod server;

use glenda::cap::{CapType, ENDPOINT_CAP, ENDPOINT_SLOT, MONITOR_CAP, RECV_SLOT, REPLY_SLOT};
use glenda::client::{InitClient, ResourceClient};
use glenda::interface::{ResourceService, SystemService};
use glenda::ipc::Badge;
use glenda::protocol::resource::{INIT_ENDPOINT, ResourceType};
use layout::{INIT_CAP, INIT_SLOT};
use server::FactotumService;

#[unsafe(no_mangle)]
fn main() -> usize {
    glenda::console::init_logging("Factotum");
    log!("Starting Authentication Manager...");

    let mut res_client = ResourceClient::new(MONITOR_CAP);

    if let Err(e) = res_client.alloc(Badge::null(), CapType::Endpoint, 0, ENDPOINT_SLOT) {
        error!("Failed to allocate endpoint: {:?}", e);
        return 1;
    }

    if let Err(e) =
        res_client.get_cap(Badge::null(), ResourceType::Endpoint, INIT_ENDPOINT, INIT_SLOT)
    {
        error!("Failed to get init endpoint: {:?}", e);
        return 1;
    }

    let mut init_client = InitClient::new(INIT_CAP);
    let mut server = FactotumService::new(&mut res_client, &mut init_client);

    if let Err(e) = server.listen(ENDPOINT_CAP, REPLY_SLOT, RECV_SLOT) {
        error!("Failed to listen: {:?}", e);
        return 1;
    }

    if let Err(e) = server.init() {
        error!("Failed to init factotum: {:?}", e);
        return 1;
    }

    if let Err(e) = server.run() {
        error!("Factotum exited with error: {:?}", e);
        return 1;
    }

    0
}
