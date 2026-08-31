//
// Copyright (c) 2025-2026 rustmailer.com (https://rustmailer.com)
//
// This file is part of the Bichon Email Archiving Project
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use crate::{
    common::paginated::DataPage,
    database::{
        delete_impl, find_impl, insert_impl, manager::DB_MANAGER, paginate_impl, update_impl,
        upsert_impl, MemDbModel,
    },
    decrypt, encrypt,
    error::{code::ErrorCode, BichonResult},
    id, raise_error, utc_now,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Determines whether the OAuth2 client authenticates at the token endpoint.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "web-api", derive(poem_openapi::Enum))]
pub enum OAuth2ClientType {
    /// A client with a provider-issued secret.
    #[default]
    Confidential,
    /// A native/public client that relies on PKCE and has no client secret.
    Public,
}

/// Represents the OAuth2 configuration for a client, including initialization and runtime values.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "web-api", derive(poem_openapi::Object))]
pub struct OAuth2 {
    /// A unique identifier for the OAuth2 configuration.
    pub id: u64,
    /// A description of what this configuration is used for.
    pub description: Option<String>,
    /// The client ID used for authenticating the application with the OAuth2 provider.
    pub client_id: String,
    /// The OAuth2 client type. Existing records default to confidential clients.
    #[serde(default)]
    pub client_type: OAuth2ClientType,
    /// The client secret used in conjunction with the client ID.
    ///
    /// Users should provide a plaintext secret.
    /// The server will encrypt it using AES-256-GCM and securely store it.
    /// The plaintext secret is never stored, so users must ensure it is valid for OAuth2 authentication.
    pub client_secret: Option<String>,
    /// The URL to redirect users to for OAuth2 authorization.
    pub auth_url: String,
    /// The URL to exchange authorization codes for access tokens.
    pub token_url: String,
    /// The URI where the OAuth2 provider will redirect to after authorization.
    pub redirect_uri: String,
    /// The scopes of access that are being requested (e.g., email, profile).
    pub scopes: Option<Vec<String>>,
    /// Any additional parameters to include in the OAuth2 requests (e.g., access_type, prompt).
    pub extra_params: Option<BTreeMap<String, String>>,
    /// Indicates whether this configuration is enabled or disabled.
    pub enabled: bool,
    /// route OAuth through proxy (when direct access is blocked)
    pub use_proxy: Option<u64>,
    /// The timestamp when the configuration was created, in milliseconds since the Unix epoch.
    pub created_at: i64,
    /// The timestamp when the configuration was last updated, in milliseconds since the Unix epoch.
    pub updated_at: i64,
}

impl MemDbModel for OAuth2 {
    fn collection() -> &'static str {
        "oauth2_configs"
    }
    fn key(&self) -> String {
        self.id.to_string()
    }
}

impl OAuth2 {
    pub fn new(request: OAuth2CreateRequest) -> BichonResult<Self> {
        let client_secret =
            encrypted_secret_for_create(request.client_type, request.client_secret)?;
        Ok(OAuth2 {
            id: id!(64),
            description: request.description,
            client_id: request.client_id,
            client_type: request.client_type,
            client_secret,
            auth_url: request.auth_url,
            token_url: request.token_url,
            redirect_uri: request.redirect_uri,
            scopes: request.scopes,
            extra_params: request.extra_params,
            enabled: request.enabled,
            created_at: utc_now!(),
            updated_at: utc_now!(),
            use_proxy: request.use_proxy,
        })
    }

    pub fn scrub_sensitive_fields(&mut self) {
        let mask = "********";
        let notice =
            " [REDACTED: You do not have permission to view sensitive configuration details]";

        let original_desc = self
            .description
            .clone()
            .unwrap_or_else(|| "OAuth2 Config".to_string());
        self.description = Some(format!("{}{}", original_desc, notice));

        self.client_id = mask.to_string();
        self.client_secret = self.client_secret.as_ref().map(|_| mask.to_string());
        self.auth_url = self.auth_url.clone();
        self.token_url = self.token_url.clone();
        self.redirect_uri = self.redirect_uri.clone();

        self.scopes = None;
        self.extra_params = None;
    }

    pub fn save(&self) -> BichonResult<()> {
        insert_impl(DB_MANAGER.db(), self.to_owned())?;
        Ok(())
    }

    pub fn paginate_list(
        page: Option<u64>,
        page_size: Option<u64>,
        desc: Option<bool>,
    ) -> BichonResult<DataPage<OAuth2>> {
        let mut paginated = paginate_impl::<OAuth2>(DB_MANAGER.db(), page, page_size, desc)?;
        for oauth2 in &mut paginated.items {
            if oauth2.migrate_legacy_empty_secret()? {
                upsert_impl(DB_MANAGER.db(), oauth2.to_owned())?;
            }
        }
        Ok(DataPage::from(paginated))
    }

    pub fn get(id: u64) -> BichonResult<Option<OAuth2>> {
        let results = find_impl::<OAuth2>(DB_MANAGER.db(), &id.to_string())?;
        let Some(mut oauth2) = results.into_iter().next() else {
            return Ok(None);
        };
        if oauth2.migrate_legacy_empty_secret()? {
            upsert_impl(DB_MANAGER.db(), oauth2.to_owned())?;
        }
        Ok(Some(oauth2))
    }

    pub fn delete(id: u64) -> BichonResult<()> {
        delete_impl::<OAuth2>(DB_MANAGER.db(), &id.to_string())
    }

    pub fn update(id: u64, request: OAuth2UpdateRequest) -> BichonResult<()> {
        update_impl(DB_MANAGER.db(), &id.to_string(), |mut current: OAuth2| {
            current.migrate_legacy_empty_secret()?;
            apply_update(&current, request)
        })?;

        Ok(())
    }

    fn migrate_legacy_empty_secret(&mut self) -> BichonResult<bool> {
        if self.client_type != OAuth2ClientType::Confidential {
            return Ok(false);
        }

        let Some(encrypted_secret) = &self.client_secret else {
            return Ok(false);
        };
        if !decrypt!(encrypted_secret)?.trim().is_empty() {
            return Ok(false);
        }

        self.client_type = OAuth2ClientType::Public;
        self.client_secret = None;
        self.updated_at = utc_now!();
        Ok(true)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "web-api", derive(poem_openapi::Object))]
pub struct OAuth2CreateRequest {
    /// A description of what this configuration is used for.
    pub description: Option<String>,

    /// The client ID used for authenticating the application with the OAuth2 provider.
    pub client_id: String,

    /// Whether the OAuth2 client is confidential or public/native.
    #[serde(default)]
    #[cfg_attr(feature = "web-api", oai(default))]
    pub client_type: OAuth2ClientType,

    /// The client secret used in conjunction with the client ID.
    pub client_secret: Option<String>,

    /// The URL to redirect users to for OAuth2 authorization.
    pub auth_url: String,

    /// The URL to exchange authorization codes for access tokens.
    pub token_url: String,

    /// The URI where the OAuth2 provider will redirect to after authorization.
    pub redirect_uri: String,

    /// The scopes of access that are being requested (e.g., email, profile).
    pub scopes: Option<Vec<String>>,

    /// Any additional parameters to include in the OAuth2 requests (e.g., access_type, prompt).
    pub extra_params: Option<BTreeMap<String, String>>,

    /// Indicates whether this configuration is enabled or disabled.
    pub enabled: bool,

    /// route OAuth through proxy (when direct access is blocked)
    pub use_proxy: Option<u64>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "web-api", derive(poem_openapi::Object))]
pub struct OAuth2UpdateRequest {
    /// A description of what this configuration is used for.
    pub description: Option<String>,

    /// The client ID used for authenticating the application with the OAuth2 provider.
    pub client_id: Option<String>,

    /// Whether the OAuth2 client is confidential or public/native.
    pub client_type: Option<OAuth2ClientType>,

    /// The client secret used in conjunction with the client ID.
    pub client_secret: Option<String>,

    /// The URL to redirect users to for OAuth2 authorization.
    pub auth_url: Option<String>,

    /// The URL to exchange authorization codes for access tokens.
    pub token_url: Option<String>,

    /// The URI where the OAuth2 provider will redirect to after authorization.
    pub redirect_uri: Option<String>,

    /// The scopes of access that are being requested (e.g., email, profile).
    pub scopes: Option<Vec<String>>,

    /// Any additional parameters to include in the OAuth2 requests (e.g., access_type, prompt).
    pub extra_params: Option<BTreeMap<String, String>>,

    /// Indicates whether this configuration is enabled or disabled.
    pub enabled: Option<bool>,

    /// route OAuth through proxy (when direct access is blocked)
    pub use_proxy: Option<u64>,
}

fn apply_update(old: &OAuth2, request: OAuth2UpdateRequest) -> BichonResult<OAuth2> {
    let mut new = old.clone();
    let target_client_type = request.client_type.unwrap_or(old.client_type);
    new.client_secret =
        encrypted_secret_for_update(old, target_client_type, request.client_secret.as_deref())?;
    new.client_type = target_client_type;

    if request.description.is_some() {
        new.description = request.description;
    }
    if let Some(client_id) = request.client_id {
        new.client_id = client_id;
    }
    if let Some(auth_url) = request.auth_url {
        new.auth_url = auth_url;
    }
    if let Some(token_url) = request.token_url {
        new.token_url = token_url;
    }
    if let Some(redirect_uri) = request.redirect_uri {
        new.redirect_uri = redirect_uri;
    }
    if request.scopes.is_some() {
        new.scopes = request.scopes;
    }
    if request.extra_params.is_some() {
        new.extra_params = request.extra_params;
    }
    if let Some(enabled) = request.enabled {
        new.enabled = enabled;
    }
    if let Some(use_proxy) = request.use_proxy {
        new.use_proxy = Some(use_proxy);
    }
    new.updated_at = utc_now!();
    Ok(new)
}

fn nonblank_secret(secret: Option<&str>) -> Option<&str> {
    secret.filter(|value| !value.trim().is_empty())
}

fn encrypted_secret_for_create(
    client_type: OAuth2ClientType,
    client_secret: Option<String>,
) -> BichonResult<Option<String>> {
    match client_type {
        OAuth2ClientType::Confidential => {
            let secret = nonblank_secret(client_secret.as_deref()).ok_or_else(|| {
                raise_error!(
                    "A nonblank client secret is required for confidential OAuth2 clients.".into(),
                    ErrorCode::InvalidParameter
                )
            })?;
            Ok(Some(encrypt!(secret)?))
        }
        OAuth2ClientType::Public => {
            if nonblank_secret(client_secret.as_deref()).is_some() {
                return Err(raise_error!(
                    "Public OAuth2 clients must not include a client secret.".into(),
                    ErrorCode::InvalidParameter
                ));
            }
            Ok(None)
        }
    }
}

fn encrypted_secret_for_update(
    old: &OAuth2,
    target_client_type: OAuth2ClientType,
    supplied_secret: Option<&str>,
) -> BichonResult<Option<String>> {
    match target_client_type {
        OAuth2ClientType::Public => {
            if nonblank_secret(supplied_secret).is_some() {
                return Err(raise_error!(
                    "Public OAuth2 clients must not include a client secret.".into(),
                    ErrorCode::InvalidParameter
                ));
            }
            Ok(None)
        }
        OAuth2ClientType::Confidential => {
            if let Some(secret) = nonblank_secret(supplied_secret) {
                return Ok(Some(encrypt!(secret)?));
            }

            if old.client_type == OAuth2ClientType::Confidential {
                return old.client_secret.clone().map(Some).ok_or_else(|| {
                    raise_error!(
                        "The confidential OAuth2 client has no stored client secret. Supply a new secret."
                            .into(),
                        ErrorCode::InvalidParameter
                    )
                });
            }

            Err(raise_error!(
                "A new client secret is required when changing a public OAuth2 client to confidential."
                    .into(),
                ErrorCode::InvalidParameter
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Once;

    static SET_TEST_PASSWORD: Once = Once::new();

    fn set_test_encryption_password() {
        SET_TEST_PASSWORD.call_once(|| {
            std::env::set_var(
                "BICHON_ENCRYPT_PASSWORD",
                "oauth2-public-client-test-password",
            );
        });
    }

    fn create_request(
        client_type: OAuth2ClientType,
        client_secret: Option<&str>,
    ) -> OAuth2CreateRequest {
        OAuth2CreateRequest {
            description: Some("test".into()),
            client_id: "client-id".into(),
            client_type,
            client_secret: client_secret.map(str::to_owned),
            auth_url: "https://provider.example/authorize".into(),
            token_url: "https://provider.example/token".into(),
            redirect_uri: "http://127.0.0.1:15630/oauth2/callback".into(),
            scopes: None,
            extra_params: None,
            enabled: true,
            use_proxy: None,
        }
    }

    #[test]
    fn existing_records_default_to_confidential() {
        let value = serde_json::json!({
            "id": 1,
            "description": "existing",
            "client_id": "client-id",
            "client_secret": "encrypted-secret",
            "auth_url": "https://provider.example/authorize",
            "token_url": "https://provider.example/token",
            "redirect_uri": "http://127.0.0.1:15630/oauth2/callback",
            "scopes": null,
            "extra_params": null,
            "enabled": true,
            "use_proxy": null,
            "created_at": 1,
            "updated_at": 1
        });

        let oauth2: OAuth2 = serde_json::from_value(value).unwrap();
        assert_eq!(oauth2.client_type, OAuth2ClientType::Confidential);
        assert_eq!(oauth2.client_secret.as_deref(), Some("encrypted-secret"));
    }

    #[test]
    fn migrates_legacy_empty_secrets_to_public_clients() {
        set_test_encryption_password();
        let mut oauth2 = OAuth2::new(create_request(
            OAuth2ClientType::Confidential,
            Some("secret"),
        ))
        .unwrap();
        oauth2.client_secret = Some(encrypt!("").unwrap());

        assert!(oauth2.migrate_legacy_empty_secret().unwrap());
        assert_eq!(oauth2.client_type, OAuth2ClientType::Public);
        assert!(oauth2.client_secret.is_none());
    }

    #[test]
    fn create_validates_secret_for_client_type() {
        set_test_encryption_password();
        assert!(OAuth2::new(create_request(
            OAuth2ClientType::Confidential,
            Some("secret")
        ))
        .is_ok());
        assert!(OAuth2::new(create_request(OAuth2ClientType::Confidential, None)).is_err());

        let public = OAuth2::new(create_request(OAuth2ClientType::Public, None)).unwrap();
        assert!(public.client_secret.is_none());
        assert!(OAuth2::new(create_request(OAuth2ClientType::Public, Some("secret"))).is_err());
    }

    #[test]
    fn update_preserves_or_clears_secrets_and_validates_transitions() {
        set_test_encryption_password();
        let confidential = OAuth2::new(create_request(
            OAuth2ClientType::Confidential,
            Some("secret"),
        ))
        .unwrap();
        let original_secret = confidential.client_secret.clone();

        let preserved = apply_update(&confidential, OAuth2UpdateRequest::default()).unwrap();
        assert_eq!(preserved.client_secret, original_secret);

        let public = apply_update(
            &confidential,
            OAuth2UpdateRequest {
                client_type: Some(OAuth2ClientType::Public),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(public.client_secret.is_none());

        assert!(apply_update(
            &public,
            OAuth2UpdateRequest {
                client_type: Some(OAuth2ClientType::Confidential),
                ..Default::default()
            }
        )
        .is_err());

        let confidential_again = apply_update(
            &public,
            OAuth2UpdateRequest {
                client_type: Some(OAuth2ClientType::Confidential),
                client_secret: Some("new-secret".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            confidential_again.client_type,
            OAuth2ClientType::Confidential
        );
        assert!(confidential_again.client_secret.is_some());
    }
}
