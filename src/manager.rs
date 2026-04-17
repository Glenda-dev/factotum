use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use glenda::ipc::Badge;
use glenda::protocol::auth::{IdentityInfo, PermissionDecision, PolicyRule};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PolicyKey {
    pub subject: usize,
    pub resource: String,
    pub operation: String,
}

#[derive(Debug, Clone)]
pub struct TicketEntry {
    pub subject: usize,
    pub service: String,
    pub expire_tick: u64,
}

pub struct FactotumManager {
    identities: BTreeMap<usize, IdentityInfo>,
    policies: BTreeMap<PolicyKey, PolicyRule>,
    tickets: BTreeMap<[u8; 32], TicketEntry>,
    default_ttl_ms: u32,
    tick: u64,
    next_nonce: u64,
}

impl FactotumManager {
    pub fn new(default_ttl_ms: u32) -> Self {
        Self {
            identities: BTreeMap::new(),
            policies: BTreeMap::new(),
            tickets: BTreeMap::new(),
            default_ttl_ms,
            tick: 0,
            next_nonce: 1,
        }
    }

    pub fn caller_subject(badge: Badge) -> usize {
        badge.bits()
    }

    pub fn next_tick(&mut self) -> u64 {
        self.tick = self.tick.wrapping_add(1);
        self.tick
    }

    pub fn get_identity(&self, subject: usize) -> IdentityInfo {
        self.identities.get(&subject).copied().unwrap_or_default()
    }

    pub fn set_identity(&mut self, subject: usize, identity: IdentityInfo) {
        self.identities.insert(subject, identity);
    }

    pub fn upsert_policy(
        &mut self,
        subject: usize,
        resource: &str,
        operation: &str,
        mut rule: PolicyRule,
    ) {
        rule.subject = subject as u32;
        if rule.ttl_ms == 0 {
            rule.ttl_ms = self.default_ttl_ms;
        }
        self.policies.insert(
            PolicyKey {
                subject,
                resource: String::from(resource),
                operation: String::from(operation),
            },
            rule,
        );
    }

    pub fn delete_policy(&mut self, subject: usize, resource: &str, operation: &str) {
        self.policies.remove(&PolicyKey {
            subject,
            resource: String::from(resource),
            operation: String::from(operation),
        });
    }

    fn find_rule(&self, subject: usize, resource: &str, operation: &str) -> Option<&PolicyRule> {
        let keys = [
            PolicyKey {
                subject,
                resource: String::from(resource),
                operation: String::from(operation),
            },
            PolicyKey { subject, resource: String::from(resource), operation: String::from("*") },
            PolicyKey { subject, resource: String::from("*"), operation: String::from(operation) },
            PolicyKey { subject, resource: String::from("*"), operation: String::from("*") },
            PolicyKey {
                subject: usize::MAX,
                resource: String::from(resource),
                operation: String::from(operation),
            },
            PolicyKey {
                subject: usize::MAX,
                resource: String::from("*"),
                operation: String::from("*"),
            },
        ];

        for key in keys {
            if let Some(rule) = self.policies.get(&key) {
                return Some(rule);
            }
        }

        None
    }

    pub fn check_permission(
        &self,
        subject: usize,
        resource: &str,
        operation: &str,
    ) -> PermissionDecision {
        let identity = self.get_identity(subject);
        if identity.euid == 0 {
            return PermissionDecision {
                allowed: 1,
                reserved: [0; 3],
                ttl_ms: self.default_ttl_ms,
            };
        }

        if let Some(rule) = self.find_rule(subject, resource, operation) {
            return PermissionDecision {
                allowed: if rule.effect == 0 { 0 } else { 1 },
                reserved: [0; 3],
                ttl_ms: rule.ttl_ms.max(1),
            };
        }

        PermissionDecision {
            // 默认放行，依赖显式 deny 规则收紧。
            allowed: 1,
            reserved: [0; 3],
            ttl_ms: self.default_ttl_ms,
        }
    }

    fn checksum(subject: u64, expire_tick: u64, nonce: u64) -> u64 {
        subject.rotate_left(7)
            ^ expire_tick.rotate_left(17)
            ^ nonce.rotate_left(29)
            ^ 0x5a17_baad_cafe_f00d
    }

    pub fn issue_ticket(&mut self, subject: usize, service: &str) -> [u8; 32] {
        let now = self.next_tick();
        let ttl = self.default_ttl_ms.max(1) as u64;
        let expire_tick = now.saturating_add(ttl);
        let nonce = self.next_nonce;
        self.next_nonce = self.next_nonce.wrapping_add(1);

        let subject_u64 = subject as u64;
        let check = Self::checksum(subject_u64, expire_tick, nonce);

        let mut ticket = [0u8; 32];
        ticket[0..8].copy_from_slice(&subject_u64.to_le_bytes());
        ticket[8..16].copy_from_slice(&expire_tick.to_le_bytes());
        ticket[16..24].copy_from_slice(&nonce.to_le_bytes());
        ticket[24..32].copy_from_slice(&check.to_le_bytes());

        self.tickets
            .insert(ticket, TicketEntry { subject, service: String::from(service), expire_tick });

        ticket
    }

    pub fn validate_ticket(&mut self, ticket_blob: &[u8]) -> bool {
        if ticket_blob.len() < 32 {
            return false;
        }

        let mut ticket = [0u8; 32];
        ticket.copy_from_slice(&ticket_blob[..32]);

        let mut subject_bytes = [0u8; 8];
        let mut expire_bytes = [0u8; 8];
        let mut nonce_bytes = [0u8; 8];
        let mut check_bytes = [0u8; 8];
        subject_bytes.copy_from_slice(&ticket[0..8]);
        expire_bytes.copy_from_slice(&ticket[8..16]);
        nonce_bytes.copy_from_slice(&ticket[16..24]);
        check_bytes.copy_from_slice(&ticket[24..32]);

        let subject = u64::from_le_bytes(subject_bytes);
        let expire_tick = u64::from_le_bytes(expire_bytes);
        let nonce = u64::from_le_bytes(nonce_bytes);
        let check = u64::from_le_bytes(check_bytes);

        if Self::checksum(subject, expire_tick, nonce) != check {
            return false;
        }

        let now = self.next_tick();
        if now > expire_tick {
            self.tickets.remove(&ticket);
            return false;
        }

        self.tickets.get(&ticket).is_some()
    }

    pub fn logout(&mut self, subject: usize) {
        let mut removed = Vec::new();
        for (ticket, meta) in self.tickets.iter() {
            if meta.subject == subject {
                removed.push(*ticket);
            }
        }
        for ticket in removed {
            self.tickets.remove(&ticket);
        }
    }

    pub fn prune_expired_tickets(&mut self) {
        let now = self.next_tick();
        let mut removed = Vec::new();
        for (ticket, meta) in self.tickets.iter() {
            if meta.expire_tick < now {
                removed.push(*ticket);
            }
        }
        for ticket in removed {
            self.tickets.remove(&ticket);
        }
    }
}
