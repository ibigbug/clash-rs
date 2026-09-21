use crate::common::utils::default_bool_true;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use std::collections::HashMap;

use super::config::BindAddress;

/// A single user entry for SS2022 multi-user inbound.
/// `name` is stored in session metadata as `inboundUser` for traffic
/// attribution. `password` is a base64-encoded 32-byte key (for
/// 2022-blake3-aes-256-gcm).
#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
pub struct InboundUser {
    pub name: String,
    pub password: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
#[serde(rename_all = "kebab-case")]
pub enum InboundOpts {
    #[serde(alias = "http")]
    Http {
        #[serde(flatten)]
        common_opts: CommonInboundOpts,
    },
    #[serde(alias = "socks")]
    Socks {
        #[serde(flatten)]
        common_opts: CommonInboundOpts,
        #[serde(default = "default_bool_true")]
        udp: bool,
    },
    #[serde(alias = "mixed")]
    Mixed {
        #[serde(flatten)]
        common_opts: CommonInboundOpts,
        #[serde(default = "default_bool_true")]
        udp: bool, // TODO users
    },
    #[cfg(feature = "tproxy")]
    #[serde(alias = "tproxy")]
    TProxy {
        #[serde(flatten)]
        common_opts: CommonInboundOpts,
        #[serde(default = "default_bool_true")]
        udp: bool,
    },
    #[cfg(feature = "redir")]
    #[serde(alias = "redir")]
    Redir {
        #[serde(flatten)]
        common_opts: CommonInboundOpts,
    },
    #[serde(alias = "tunnel")]
    Tunnel {
        #[serde(flatten)]
        common_opts: CommonInboundOpts,
        network: Vec<String>,
        target: String,
    },
    #[cfg(feature = "shadowsocks")]
    #[serde(alias = "shadowsocks")]
    Shadowsocks {
        #[serde(flatten)]
        common_opts: CommonInboundOpts,
        #[serde(default = "default_bool_true")]
        udp: bool,
        cipher: String,
        password: String,
        /// Multi-user list for SS2022 EIH. Each entry has a name (FAC user_id)
        /// and a base64-encoded 32-byte user key. When non-empty, EIH is used
        /// to identify which user owns each connection.
        #[serde(default)]
        users: Vec<InboundUser>,
    },
    #[serde(alias = "anytls")]
    Anytls {
        #[serde(flatten)]
        common_opts: CommonInboundOpts,
        password: String,
        /// File path or inline PEM certificate chain. When absent, an
        /// ephemeral self-signed certificate is generated at startup.
        #[serde(default)]
        certificate: Option<String>,
        /// File path or inline PEM private key. When absent, an ephemeral
        /// self-signed certificate is generated at startup.
        #[serde(rename = "private-key", default)]
        private_key: Option<String>,
        /// Optional multi-user list. When empty, `password` is used directly
        /// (single-user mode). Each entry uses the plaintext password field.
        #[serde(default)]
        users: Vec<InboundUser>,
        /// Optional fallback address (`host:port`) to which unauthenticated
        /// connections are forwarded, providing camouflage against active
        /// probing. When absent, unauthenticated connections are
        /// silently dropped.
        #[serde(default)]
        fallback: Option<String>,
    },
    #[serde(alias = "hysteria2")]
    Hysteria2 {
        #[serde(flatten)]
        common_opts: CommonInboundOpts,
        password: String,
        /// File path or inline PEM certificate chain. When absent, an
        /// ephemeral self-signed certificate is generated at startup.
        #[serde(default)]
        certificate: Option<String>,
        /// File path or inline PEM private key. When absent, an ephemeral
        /// self-signed certificate is generated at startup.
        #[serde(rename = "private-key", default)]
        private_key: Option<String>,
        /// Optional multi-user list. Each entry's `password` field is the
        /// plaintext Hysteria2 auth password; `name` is used for traffic
        /// attribution. When empty, `password` is used directly.
        #[serde(default)]
        users: Vec<InboundUser>,
    },
}

/// Equality and hashing for `InboundOpts` intentionally exclude the `users`
/// field of the `Shadowsocks` variant so that a change to the user list
/// does not cause a full listener restart. All structural parameters
/// (address, port, cipher, server password) are still compared.
impl PartialEq for InboundOpts {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                InboundOpts::Http { common_opts: a },
                InboundOpts::Http { common_opts: b },
            ) => a == b,
            (
                InboundOpts::Socks {
                    common_opts: a,
                    udp: ua,
                },
                InboundOpts::Socks {
                    common_opts: b,
                    udp: ub,
                },
            ) => a == b && ua == ub,
            (
                InboundOpts::Mixed {
                    common_opts: a,
                    udp: ua,
                },
                InboundOpts::Mixed {
                    common_opts: b,
                    udp: ub,
                },
            ) => a == b && ua == ub,
            #[cfg(feature = "tproxy")]
            (
                InboundOpts::TProxy {
                    common_opts: a,
                    udp: ua,
                },
                InboundOpts::TProxy {
                    common_opts: b,
                    udp: ub,
                },
            ) => a == b && ua == ub,
            #[cfg(feature = "redir")]
            (
                InboundOpts::Redir { common_opts: a },
                InboundOpts::Redir { common_opts: b },
            ) => a == b,
            (
                InboundOpts::Tunnel {
                    common_opts: a,
                    network: na,
                    target: ta,
                },
                InboundOpts::Tunnel {
                    common_opts: b,
                    network: nb,
                    target: tb,
                },
            ) => a == b && na == nb && ta == tb,
            #[cfg(feature = "shadowsocks")]
            (
                InboundOpts::Shadowsocks {
                    common_opts: a,
                    udp: ua,
                    cipher: ca,
                    password: pa,
                    ..
                },
                InboundOpts::Shadowsocks {
                    common_opts: b,
                    udp: ub,
                    cipher: cb,
                    password: pb,
                    ..
                },
            ) => a == b && ua == ub && ca == cb && pa == pb,
            (
                InboundOpts::Anytls {
                    common_opts: a,
                    password: pa,
                    certificate: ca,
                    private_key: pka,
                    fallback: fa,
                    ..
                },
                InboundOpts::Anytls {
                    common_opts: b,
                    password: pb,
                    certificate: cb,
                    private_key: pkb,
                    fallback: fb,
                    ..
                },
            ) => a == b && pa == pb && ca == cb && pka == pkb && fa == fb,
            (
                InboundOpts::Hysteria2 {
                    common_opts: a,
                    password: pa,
                    certificate: ca,
                    private_key: pka,
                    ..
                },
                InboundOpts::Hysteria2 {
                    common_opts: b,
                    password: pb,
                    certificate: cb,
                    private_key: pkb,
                    ..
                },
            ) => a == b && pa == pb && ca == cb && pka == pkb,
            _ => false,
        }
    }
}

impl Eq for InboundOpts {}

impl std::hash::Hash for InboundOpts {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
        match self {
            InboundOpts::Http { common_opts } => common_opts.hash(state),
            InboundOpts::Socks { common_opts, udp } => {
                common_opts.hash(state);
                udp.hash(state);
            }
            InboundOpts::Mixed { common_opts, udp } => {
                common_opts.hash(state);
                udp.hash(state);
            }
            #[cfg(feature = "tproxy")]
            InboundOpts::TProxy { common_opts, udp } => {
                common_opts.hash(state);
                udp.hash(state);
            }
            #[cfg(feature = "redir")]
            InboundOpts::Redir { common_opts } => common_opts.hash(state),
            InboundOpts::Tunnel {
                common_opts,
                network,
                target,
            } => {
                common_opts.hash(state);
                network.hash(state);
                target.hash(state);
            }
            #[cfg(feature = "shadowsocks")]
            InboundOpts::Shadowsocks {
                common_opts,
                udp,
                cipher,
                password,
                ..
            } => {
                common_opts.hash(state);
                udp.hash(state);
                cipher.hash(state);
                password.hash(state);
                // `users` intentionally excluded — handled via watch channel
            }
            InboundOpts::Anytls {
                common_opts,
                password,
                certificate,
                private_key,
                fallback,
                ..
            } => {
                common_opts.hash(state);
                password.hash(state);
                certificate.hash(state);
                private_key.hash(state);
                fallback.hash(state);
                // `users` intentionally excluded — handled via watch channel
            }
            InboundOpts::Hysteria2 {
                common_opts,
                password,
                certificate,
                private_key,
                ..
            } => {
                common_opts.hash(state);
                password.hash(state);
                certificate.hash(state);
                private_key.hash(state);
                // `users` intentionally excluded — handled via watch channel
            }
        }
    }
}

impl InboundOpts {
    pub fn common_opts(&self) -> &CommonInboundOpts {
        match self {
            InboundOpts::Http { common_opts, .. } => common_opts,
            InboundOpts::Socks { common_opts, .. } => common_opts,
            InboundOpts::Mixed { common_opts, .. } => common_opts,
            #[cfg(feature = "tproxy")]
            InboundOpts::TProxy { common_opts, .. } => common_opts,
            InboundOpts::Tunnel { common_opts, .. } => common_opts,
            #[cfg(feature = "redir")]
            InboundOpts::Redir { common_opts, .. } => common_opts,
            #[cfg(feature = "shadowsocks")]
            InboundOpts::Shadowsocks { common_opts, .. } => common_opts,
            InboundOpts::Anytls { common_opts, .. } => common_opts,
            InboundOpts::Hysteria2 { common_opts, .. } => common_opts,
        }
    }

    pub fn common_opts_mut(&mut self) -> &mut CommonInboundOpts {
        match self {
            InboundOpts::Http { common_opts, .. } => common_opts,
            InboundOpts::Socks { common_opts, .. } => common_opts,
            InboundOpts::Mixed { common_opts, .. } => common_opts,
            #[cfg(feature = "tproxy")]
            InboundOpts::TProxy { common_opts, .. } => common_opts,
            InboundOpts::Tunnel { common_opts, .. } => common_opts,
            #[cfg(feature = "redir")]
            InboundOpts::Redir { common_opts, .. } => common_opts,
            #[cfg(feature = "shadowsocks")]
            InboundOpts::Shadowsocks { common_opts, .. } => common_opts,
            InboundOpts::Anytls { common_opts, .. } => common_opts,
            InboundOpts::Hysteria2 { common_opts, .. } => common_opts,
        }
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            InboundOpts::Http { .. } => "http",
            InboundOpts::Socks { .. } => "socks",
            InboundOpts::Mixed { .. } => "mixed",
            #[cfg(feature = "tproxy")]
            InboundOpts::TProxy { .. } => "tproxy",
            InboundOpts::Tunnel { .. } => "tunnel",
            #[cfg(feature = "redir")]
            InboundOpts::Redir { .. } => "redir",
            #[cfg(feature = "shadowsocks")]
            InboundOpts::Shadowsocks { .. } => "shadowsocks",
            InboundOpts::Anytls { .. } => "anytls",
            InboundOpts::Hysteria2 { .. } => "hysteria2",
        }
    }
}

/// Mirrors `OutboundProxyProviderDef` but for inbound listeners.
/// The provider URL/file must return YAML with a top-level `listeners:` key
/// containing a list of `InboundOpts`-compatible objects.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
#[serde(rename_all = "kebab-case")]
pub enum InboundProviderDef {
    Http(InboundHttpProvider),
    File(InboundFileProvider),
}

impl InboundProviderDef {
    pub fn set_name(&mut self, name: String) {
        match self {
            InboundProviderDef::Http(p) => p.name = name,
            InboundProviderDef::File(p) => p.name = name,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct InboundHttpProvider {
    #[serde(skip)]
    pub name: String,
    pub url: String,
    pub interval: Option<u64>,
    pub path: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct InboundFileProvider {
    #[serde(skip)]
    pub name: String,
    pub path: String,
    pub interval: Option<u64>,
}

impl TryFrom<HashMap<String, Value>> for InboundProviderDef {
    type Error = crate::Error;

    fn try_from(mapping: HashMap<String, Value>) -> Result<Self, Self::Error> {
        use serde::de::value::MapDeserializer;
        let name = mapping
            .get("name")
            .and_then(|x| x.as_str())
            .ok_or_else(|| {
                crate::Error::InvalidConfig(
                    "missing field `name` in inbound provider".into(),
                )
            })?
            .to_owned();
        InboundProviderDef::deserialize(MapDeserializer::new(mapping.into_iter()))
            .map_err(|e| {
                crate::Error::InvalidConfig(format!("inbound provider {name}: {e}"))
            })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct CommonInboundOpts {
    pub name: String,
    pub listen: BindAddress,
    #[serde(default)]
    pub allow_lan: bool,
    pub port: u16,
    /// Linux routing mark
    pub fw_mark: Option<u32>,
}
