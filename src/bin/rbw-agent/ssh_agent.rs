use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Identity, SignRequest};
use ssh_agent_lib::ssh_key;
use signature::Signer;

#[derive(Clone)]
pub struct SshAgent {
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
}

impl SshAgent {
    pub fn new(state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>) -> Self {
        Self {
            state,
        }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let socket = rbw::dirs::ssh_agent_socket_file();

        let _ = std::fs::remove_file(&socket); // Ignore error if it doesn't exist

        let listener = tokio::net::UnixListener::bind(socket)?;
        ssh_agent_lib::agent::listen(listener, self).await?;

        Ok(())
    }
}

#[ssh_agent_lib::async_trait]
impl ssh_agent_lib::agent::Session for SshAgent {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        crate::actions::get_ssh_public_keys(self.state.clone())
            .await
            .map_err(|e| AgentError::Other(e.into()))?
            .into_iter()
            .map(|p| {
                p.parse::<ssh_key::PublicKey>()
                    .map(|pk| Identity {
                        pubkey: pk.key_data().clone(),
                        comment: String::new(),
                    })
                .map_err(AgentError::other)
            })
            .collect()
    }

    async fn sign(&mut self, request: SignRequest) -> Result<ssh_key::Signature, AgentError> {
        let pubkey = ssh_key::PublicKey::new(request.pubkey, "");
        let pubkey_openssh = pubkey
            .to_openssh()
            .map_err(AgentError::other)?;

        let private_key_openssh = crate::actions::find_ssh_private_key(self.state.clone(), pubkey_openssh)
            .await
            .map_err(|e| AgentError::Other(e.into()))?;
        let private_key = ssh_key::PrivateKey::from_openssh(private_key_openssh)
            .map_err(AgentError::other)?;
        let keypair_data = private_key.key_data();

        match keypair_data {
            ssh_key::private::KeypairData::Ed25519(k) =>
                k.try_sign(&request.data).map_err(AgentError::other),

            // TODO: Implement RSA and other keys supported by bitwarden
            other =>
                Err(AgentError::Other(format!("Unsupported key type: {:?}", other).into())),
        }
    }
}
