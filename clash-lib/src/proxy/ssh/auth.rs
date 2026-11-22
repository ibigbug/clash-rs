use std::{collections::HashSet, io, ops::Deref, sync::Arc};

use async_trait::async_trait;
use russh::{
    MethodKind,
    client::{AuthResult, Handle, Prompt},
    keys::{PrivateKey, PrivateKeyWithHashAlg, load_secret_key},
};

use crate::common::errors::new_io_error;

use super::{HandlerOptions, connector::Client};

/// Hashable authentication methods for tracking configured and attempted
/// methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum MethodKindAdapter {
    None,
    Password,
    PublicKey,
    HostBased,
    KeyboardInteractive,
    GssapiWithMic,
}

impl From<MethodKind> for MethodKindAdapter {
    fn from(value: MethodKind) -> Self {
        match value {
            MethodKind::None => MethodKindAdapter::None,
            MethodKind::Password => MethodKindAdapter::Password,
            MethodKind::PublicKey => MethodKindAdapter::PublicKey,
            MethodKind::HostBased => MethodKindAdapter::HostBased,
            MethodKind::GssapiWithMic => MethodKindAdapter::GssapiWithMic,
            MethodKind::KeyboardInteractive => {
                MethodKindAdapter::KeyboardInteractive
            }
        }
    }
}

impl From<MethodKindAdapter> for MethodKind {
    fn from(value: MethodKindAdapter) -> Self {
        match value {
            MethodKindAdapter::None => MethodKind::None,
            MethodKindAdapter::Password => MethodKind::Password,
            MethodKindAdapter::PublicKey => MethodKind::PublicKey,
            MethodKindAdapter::HostBased => MethodKind::HostBased,
            MethodKindAdapter::GssapiWithMic => MethodKind::GssapiWithMic,
            MethodKindAdapter::KeyboardInteractive => {
                MethodKind::KeyboardInteractive
            }
        }
    }
}

/// TODO: make it configurable?
const PASSWORD_PROMPT: &str = "Password: ";
const VERIFICATION_CODE_PROMPT: &str = "Verification code: ";

/// rfc: https://datatracker.ietf.org/doc/html/rfc4252
/// doc: https://github.com/golang/crypto/blob/9290511cd23ab9813a307b7f2615325e3ca98902/ssh/client_auth.go#L24
/// currently, we only support password, public key and keyboard interactive
pub async fn authenticate(
    client: &mut Handle<Client>,
    opts: &HandlerOptions,
) -> core::result::Result<AuthResult, russh::Error> {
    let mut auth: &dyn Auth = &NoneAuth;
    let mut tried: HashSet<MethodKindAdapter> = HashSet::new();

    let mut config_auth = Vec::with_capacity(3);
    if let Some(password) = opts.password.clone() {
        config_auth.push(Box::new(PasswordAuth { password }) as Box<dyn Auth>);
    }
    match load_private_key(opts) {
        Ok(private_key) => {
            config_auth
                .push(Box::new(PublicKeyAuth { private_key }) as Box<dyn Auth>);
        }
        Err(e) => {
            tracing::warn!("load private key failed: {:?}", e);
        }
    }

    let password = opts.password.clone();
    let totp = opts.totp.clone();
    let prompt_handler = move |name: String,
                               _: String,
                               prompts: Vec<Prompt>,
                               _username: &str|
          -> Vec<String> {
        tracing::trace!(
            "ssh interactive auth, name: {}, prompts: {:?}",
            name,
            prompts
        );
        if prompts.iter().any(|p| p.prompt.contains(PASSWORD_PROMPT)) {
            password.clone().map(|p| vec![p]).unwrap_or_default()
        } else if prompts
            .iter()
            .any(|p| p.prompt.contains(VERIFICATION_CODE_PROMPT))
        {
            totp.clone()
                .map(|t| t.generate_current().unwrap())
                .map(|t| vec![t])
                .unwrap_or_default()
        } else {
            vec![]
        }
    };
    config_auth.push(Box::new(KeyboardInteractiveAuth {
        handler: prompt_handler,
        mac_retry: 5,
    }) as Box<dyn Auth>);

    let config_auth = config_auth
        .into_iter()
        .map(|auth| (auth.method().into(), auth))
        .collect::<std::collections::HashMap<MethodKindAdapter, _>>();

    #[allow(unused_assignments)]
    let mut remaining_methods: Vec<MethodKindAdapter> = vec![];
    loop {
        let result = auth.auth(client, &opts.username).await;
        tracing::trace!(
            "trying method: {:?}, ssh auth result: {:?}",
            auth.method(),
            result
        );
        remaining_methods = match result {
            Ok(AuthResult::Success) => return Ok(AuthResult::Success),
            Ok(AuthResult::Failure {
                remaining_methods: methods,
                partial_success: _,
            }) => {
                tried.insert(auth.method().into());
                methods
                    .deref()
                    .iter()
                    .map(|m| (*m).into())
                    .collect::<Vec<_>>()
            }
            Err(e) => return Err(e),
        };

        let mut find = false;

        // find next method
        'outer: for remaining_method in &remaining_methods {
            // let method = a.method().into();
            if tried.contains(remaining_method) {
                continue;
            }

            if let Some(a) = config_auth.get(remaining_method) {
                auth = a.as_ref();
                find = true;
                break 'outer;
            }
        }
        if !find {
            return Err(russh::Error::NoAuthMethod);
        }
    }
}

#[async_trait]
trait Auth: Send + Sync {
    fn method(&self) -> russh::MethodKind;

    /// return (AuthResult, can skip)
    async fn auth(
        &self,
        client: &mut Handle<Client>,
        username: &str,
    ) -> core::result::Result<AuthResult, russh::Error>;
}

struct NoneAuth;

#[async_trait]
impl Auth for NoneAuth {
    fn method(&self) -> russh::MethodKind {
        russh::MethodKind::None
    }

    async fn auth(
        &self,
        client: &mut Handle<Client>,
        username: &str,
    ) -> core::result::Result<AuthResult, russh::Error> {
        client.authenticate_none(username).await
    }
}

struct PasswordAuth {
    password: String,
}

#[async_trait]
impl Auth for PasswordAuth {
    fn method(&self) -> russh::MethodKind {
        russh::MethodKind::Password
    }

    async fn auth(
        &self,
        client: &mut Handle<Client>,
        username: &str,
    ) -> core::result::Result<AuthResult, russh::Error> {
        client.authenticate_password(username, &self.password).await
    }
}

struct PublicKeyAuth {
    private_key: PrivateKey,
}

#[async_trait]
impl Auth for PublicKeyAuth {
    fn method(&self) -> russh::MethodKind {
        russh::MethodKind::PublicKey
    }

    async fn auth(
        &self,
        client: &mut Handle<Client>,
        username: &str,
    ) -> core::result::Result<AuthResult, russh::Error> {
        client
            .authenticate_publickey(
                username,
                PrivateKeyWithHashAlg::new(
                    Arc::new(self.private_key.clone()),
                    client.best_supported_rsa_hash().await.unwrap().flatten(),
                ),
            )
            .await
    }
}

fn load_private_key(opts: &HandlerOptions) -> io::Result<PrivateKey> {
    let key_path_or_content = match opts.private_key.clone() {
        Some(key_path) => key_path,
        None => return Err(new_io_error("private key not found")),
    };
    if key_path_or_content.contains("PRIVATE KEY") {
        // raw content
        PrivateKey::from_openssh(&key_path_or_content).map_err(io::Error::other)
    } else {
        // file path
        let key_path = if key_path_or_content.starts_with("~") {
            let home = dirs::home_dir()
                .ok_or_else(|| new_io_error("home directory not found"))?;
            key_path_or_content.replacen(
                "~",
                home.to_str()
                    .ok_or_else(|| new_io_error("home directory not found"))?,
                1,
            )
        } else {
            key_path_or_content
        };
        load_secret_key(key_path, opts.private_key_passphrase.as_deref())
            .map_err(io::Error::other)
    }
}

struct KeyboardInteractiveAuth<T> {
    mac_retry: u32,
    handler: T,
}

// (name, instruction, prompts) -> response

#[async_trait]
impl<T> Auth for KeyboardInteractiveAuth<T>
where
    T: Sync + Send + Fn(String, String, Vec<Prompt>, &str) -> Vec<String>,
{
    fn method(&self) -> russh::MethodKind {
        russh::MethodKind::KeyboardInteractive
    }

    async fn auth(
        &self,
        client: &mut Handle<Client>,
        username: &str,
    ) -> core::result::Result<AuthResult, russh::Error> {
        let start_resp = client
            .authenticate_keyboard_interactive_start(username, None)
            .await;

        let mut resp = start_resp;
        let mut tried = 0;
        loop {
            if tried >= self.mac_retry {
                return Err(russh::Error::ConnectionTimeout);
            }
            tracing::trace!("KeyboardInteractiveAuth loop, resp: {:?}", resp);
            match resp {
                Ok(r) => {
                    match r {
                        russh::client::KeyboardInteractiveAuthResponse::Success => return Ok(AuthResult::Success),
                        russh::client::KeyboardInteractiveAuthResponse::Failure{remaining_methods,partial_success} => return Ok(AuthResult::Failure{remaining_methods, partial_success}),
                        russh::client::KeyboardInteractiveAuthResponse::InfoRequest { name, instructions, prompts } => {
                            let response = (self.handler)(name, instructions, prompts, username);
                            resp = client.authenticate_keyboard_interactive_respond(response).await;
                            tried += 1;
                        },
                    }
                },
                Err(e) => return Err(e)
            }
        }
    }
}
