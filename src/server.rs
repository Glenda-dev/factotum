use crate::layout::POLICY_BACKEND_SLOT;
use crate::manager::FactotumManager;
use glenda::cap::{CSPACE_CAP, CapPtr, Endpoint, Reply};
use glenda::client::{InitClient, ResourceClient};
use glenda::error::Error;
use glenda::interface::{InitService, ResourceService, SystemService};
use glenda::ipc::server::handle_call;
use glenda::ipc::{Badge, MsgFlags, MsgTag, UTCB};
use glenda::protocol;
use glenda::protocol::auth::{IdentityInfo, PermissionDecision, PolicyBackendStatus};
use glenda::protocol::init::ServiceState;
use glenda::protocol::resource::{FACTOTUM_ENDPOINT, ResourceType};

pub struct FactotumIpc {
    pub running: bool,
    pub endpoint: Endpoint,
    pub reply: Reply,
    pub recv: CapPtr,
}

pub struct FactotumService<'a> {
    pub ipc: FactotumIpc,
    pub manager: FactotumManager,
    pub res_client: &'a mut ResourceClient,
    pub init_client: &'a mut InitClient,
    pub policy_backend: Option<Endpoint>,
    pub policy_backend_generation: u32,
}

impl<'a> FactotumService<'a> {
    pub fn new(res_client: &'a mut ResourceClient, init_client: &'a mut InitClient) -> Self {
        Self {
            ipc: FactotumIpc {
                running: false,
                endpoint: Endpoint::from(CapPtr::null()),
                reply: Reply::from(CapPtr::null()),
                recv: CapPtr::null(),
            },
            manager: FactotumManager::new(250),
            res_client,
            init_client,
            policy_backend: None,
            policy_backend_generation: 0,
        }
    }

    fn subject_from_args_or_badge(utcb: &UTCB, badge: Badge) -> usize {
        let subject = utcb.get_mr(0);
        if subject == 0 { FactotumManager::caller_subject(badge) } else { subject }
    }

    fn policy_backend_attached(&self) -> bool {
        self.policy_backend.is_some()
    }

    fn warn_policy_backend_missing(label: usize) {
        warn!("Policy backend not configured, directly allow (label={:#x})", label);
    }

    fn set_policy_backend_from_recv(&mut self, utcb: &UTCB) -> Result<(), Error> {
        if !utcb.get_msg_tag().flags().contains(MsgFlags::HAS_CAP) {
            return Err(Error::InvalidArgs);
        }

        if self.policy_backend.is_some() {
            let _ = CSPACE_CAP.delete(POLICY_BACKEND_SLOT);
            self.policy_backend = None;
        }

        CSPACE_CAP.transfer_self(self.ipc.recv, POLICY_BACKEND_SLOT)?;
        self.policy_backend = Some(Endpoint::from(POLICY_BACKEND_SLOT));
        self.policy_backend_generation = self.policy_backend_generation.wrapping_add(1);
        Ok(())
    }

    fn clear_policy_backend(&mut self) {
        if self.policy_backend.take().is_some() {
            let _ = CSPACE_CAP.delete(POLICY_BACKEND_SLOT);
            self.policy_backend_generation = self.policy_backend_generation.wrapping_add(1);
        }
    }

    fn forward_policy_call(
        &mut self,
        utcb: &mut UTCB,
        badge: Badge,
        label: usize,
        normalize_subject: bool,
    ) -> Result<(), Error> {
        let backend = self.policy_backend.ok_or(Error::NotSupported)?;

        if normalize_subject {
            let subject = Self::subject_from_args_or_badge(utcb, badge);
            utcb.set_mr(0, subject);
        }

        let incoming = utcb.get_msg_tag().flags();
        let mut flags = MsgFlags::NONE;
        if incoming.contains(MsgFlags::HAS_BUFFER) || utcb.get_size() > 0 {
            flags |= MsgFlags::HAS_BUFFER;
        }
        if incoming.contains(MsgFlags::HAS_CAP) {
            flags |= MsgFlags::HAS_CAP;
            utcb.set_cap_transfer(self.ipc.recv);
        }

        utcb.set_msg_tag(MsgTag::new(protocol::AUTH_PROTO, label, flags));
        backend.call(utcb)
    }
}

impl<'a> SystemService for FactotumService<'a> {
    fn init(&mut self) -> Result<(), Error> {
        self.init_client.report_service(Badge::null(), ServiceState::Starting)?;
        self.res_client.register_cap(
            Badge::null(),
            ResourceType::Endpoint,
            FACTOTUM_ENDPOINT,
            self.ipc.endpoint.cap(),
        )?;
        Ok(())
    }

    fn listen(&mut self, ep: Endpoint, reply: CapPtr, recv: CapPtr) -> Result<(), Error> {
        self.ipc.endpoint = ep;
        self.ipc.reply = Reply::from(reply);
        self.ipc.recv = recv;
        Ok(())
    }

    fn run(&mut self) -> Result<(), Error> {
        self.ipc.running = true;
        self.init_client.report_service(Badge::null(), ServiceState::Running)?;

        while self.ipc.running {
            let mut utcb = unsafe { UTCB::new() };
            utcb.clear();
            utcb.set_reply_window(self.ipc.reply.cap());
            utcb.set_recv_window(self.ipc.recv);

            if let Err(e) = self.ipc.endpoint.recv(&mut utcb) {
                error!("Recv error: {:?}", e);
                continue;
            }

            self.manager.prune_expired_tickets();

            match self.dispatch(&mut utcb) {
                Ok(()) => {
                    let _ = self.reply(&mut utcb);
                }
                Err(e) => {
                    error!("Dispatch error: {:?}", e);
                    utcb.set_msg_tag(MsgTag::err());
                    utcb.set_mr(0, e as usize);
                    let _ = self.reply(&mut utcb);
                }
            }
        }

        Ok(())
    }

    fn dispatch(&mut self, utcb: &mut UTCB) -> Result<(), Error> {
        let badge = utcb.get_badge();
        glenda::ipc_dispatch! {
            self, utcb,
            (protocol::AUTH_PROTO, protocol::auth::NEGOTIATE) => |_: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| {
                    let packed = u.get_mr(0);
                    let _major = ((packed >> 16) & 0xffff) as u16;
                    let _minor = (packed & 0xffff) as u16;
                    let _flags = u.get_mr(1) as u32;
                    let negotiated = ((1usize) << 16) | 0usize;
                    let feature_flags = 0usize;
                    Ok((negotiated, feature_flags))
                })
            },
            (protocol::AUTH_PROTO, protocol::auth::GET_IDENTITY) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| {
                    let subject = Self::subject_from_args_or_badge(u, badge);
                    let identity = s.manager.get_identity(subject);
                    unsafe { u.write_obj(&identity)?; }
                    Ok(0usize)
                })
            },
            (protocol::AUTH_PROTO, protocol::auth::SET_IDENTITY) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| {
                    let subject = Self::subject_from_args_or_badge(u, badge);
                    let identity = unsafe { u.read_obj::<IdentityInfo>()? };
                    s.manager.set_identity(subject, identity);
                    Ok(0usize)
                })
            },
            (protocol::AUTH_PROTO, protocol::auth::CHECK_PERMISSION) => |s: &mut Self, u: &mut UTCB| {
                if s.policy_backend_attached() {
                    s.forward_policy_call(u, badge, protocol::auth::CHECK_PERMISSION, true)
                } else {
                    Self::warn_policy_backend_missing(protocol::auth::CHECK_PERMISSION);
                    handle_call(u, |u| {
                        let decision = PermissionDecision {
                            allowed: 1,
                            reserved: [0; 3],
                            ttl_ms: 250,
                        };
                        unsafe { u.write_obj(&decision)?; }
                        Ok(0usize)
                    })
                }
            },
            (protocol::AUTH_PROTO, protocol::auth::UPSERT_POLICY) => |s: &mut Self, u: &mut UTCB| {
                if s.policy_backend_attached() {
                    s.forward_policy_call(u, badge, protocol::auth::UPSERT_POLICY, true)
                } else {
                    Self::warn_policy_backend_missing(protocol::auth::UPSERT_POLICY);
                    handle_call(u, |_| Ok(0usize))
                }
            },
            (protocol::AUTH_PROTO, protocol::auth::DELETE_POLICY) => |s: &mut Self, u: &mut UTCB| {
                if s.policy_backend_attached() {
                    s.forward_policy_call(u, badge, protocol::auth::DELETE_POLICY, true)
                } else {
                    Self::warn_policy_backend_missing(protocol::auth::DELETE_POLICY);
                    handle_call(u, |_| Ok(0usize))
                }
            },
            (protocol::AUTH_PROTO, protocol::auth::GET_TICKET) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| {
                    let subject = FactotumManager::caller_subject(badge);
                    let service = unsafe { u.read_str()? };
                    let ticket = s.manager.issue_ticket(subject, &service);
                    u.write(&ticket);
                    Ok(ticket.len())
                })
            },
            (protocol::AUTH_PROTO, protocol::auth::VALIDATE_TICKET) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| {
                    let allowed = s.manager.validate_ticket(u.buffer());
                    Ok(if allowed { 1usize } else { 0usize })
                })
            },
            (protocol::AUTH_PROTO, protocol::auth::LOGOUT) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |_| {
                    let subject = FactotumManager::caller_subject(badge);
                    s.manager.logout(subject);
                    Ok(0usize)
                })
            },
            (protocol::AUTH_PROTO, protocol::auth::SET_POLICY_BACKEND) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| {
                    s.set_policy_backend_from_recv(u)?;
                    Ok(0usize)
                })
            },
            (protocol::AUTH_PROTO, protocol::auth::CLEAR_POLICY_BACKEND) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |_| {
                    s.clear_policy_backend();
                    Ok(0usize)
                })
            },
            (protocol::AUTH_PROTO, protocol::auth::GET_POLICY_BACKEND_STATUS) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| {
                    let status = PolicyBackendStatus {
                        external_attached: if s.policy_backend_attached() { 1 } else { 0 },
                        reserved: [0; 3],
                        generation: s.policy_backend_generation,
                    };
                    unsafe { u.write_obj(&status)?; }
                    Ok(0usize)
                })
            },
            (protocol::AUTH_PROTO, protocol::auth::AUTH_RPC) => |s: &mut Self, u: &mut UTCB| {
                if s.policy_backend_attached() {
                    s.forward_policy_call(u, badge, protocol::auth::AUTH_RPC, false)
                } else {
                    Err(Error::NotSupported)
                }
            },
            (protocol::AUTH_PROTO, protocol::auth::PROXY_CALL) => |s: &mut Self, u: &mut UTCB| {
                if s.policy_backend_attached() {
                    s.forward_policy_call(u, badge, protocol::auth::PROXY_CALL, false)
                } else {
                    Err(Error::NotSupported)
                }
            },
            (_, _) => |_, _| {
                Err(Error::InvalidMethod)
            }
        }
    }

    fn reply(&mut self, utcb: &mut UTCB) -> Result<(), Error> {
        self.ipc.reply.reply(utcb)
    }

    fn stop(&mut self) {
        self.ipc.running = false;
        let _ = self.init_client.report_service(Badge::null(), ServiceState::Stopped);
    }
}
