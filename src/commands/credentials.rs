use serde_json::json;

use crate::cli::CredentialsCommand;
use crate::commands::CommandResult;
use crate::config::expand_path;
use crate::state::cache::{CachedCredential, FileCredentialCache};

pub async fn run(command: CredentialsCommand) -> CommandResult {
    let (profile, path) = match &command {
        CredentialsCommand::List {
            profile,
            cache_path,
        }
        | CredentialsCommand::Show {
            profile,
            cache_path,
            ..
        }
        | CredentialsCommand::Purge {
            profile,
            cache_path,
            ..
        } => (profile, cache_path),
    };
    let namespace = crate::state::normalize_namespace(Some(profile))
        .map_err(|_| ("invalid_request", "invalid profile"))?;
    let path = path.as_ref().map(expand_path).unwrap_or_else(|| {
        FileCredentialCache::default_path(Some(&namespace)).expect("validated namespace")
    });
    let cache = FileCredentialCache::new(path, Some(&namespace))
        .map_err(|_| ("state_unavailable", "credential state is unavailable"))?;
    match command {
        CredentialsCommand::List { .. } => {
            let credentials = cache
                .list()
                .map_err(|_| ("state_unavailable", "credential state is unavailable"))?;
            Ok(
                json!({"ok": true, "credentials": credentials.into_iter().map(redacted_credential).collect::<Vec<_>>() }),
            )
        }
        CredentialsCommand::Show { credential_id, .. } => cache
            .list()
            .map_err(|_| ("state_unavailable", "credential state is unavailable"))?
            .into_iter()
            .find(|c| c.credential_id == credential_id)
            .map(redacted_credential)
            .map(|credential| json!({"ok": true, "credential": credential}))
            .ok_or(("credential_not_found", "credential was not found")),
        CredentialsCommand::Purge {
            host, service, all, ..
        } => {
            let deleted = cache
                .purge(host.as_deref(), service.as_deref(), all)
                .map_err(|_| ("state_unavailable", "credential state is unavailable"))?;
            Ok(json!({"ok": true, "deleted": deleted}))
        }
    }
}

fn redacted_credential(credential: CachedCredential) -> serde_json::Value {
    json!({
        "id": credential.credential_id,
        "scope": credential.scope,
        "authorization": "[REDACTED_CREDENTIAL]",
        "createdAt": credential.created_at,
        "expiresAt": credential.expires_at,
        "maxUses": credential.max_uses,
        "useCount": credential.use_count,
        "lastSuccessAt": credential.last_success_at,
        "lastRejectedAt": credential.last_rejected_at,
        "paymentHash": credential.payment_hash,
        "challengeId": credential.challenge_id,
    })
}
