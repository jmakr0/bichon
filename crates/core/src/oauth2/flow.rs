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

use crate::error::code::ErrorCode;
use crate::error::BichonResult;
use crate::oauth2::{
    entity::{OAuth2, OAuth2ClientType},
    pending::OAuth2PendingEntity,
    token::OAuth2AccessToken,
};
use crate::settings::proxy::Proxy;
use crate::utils::net::parse_proxy_url;
use crate::{decrypt, encrypt, raise_error};
use oauth2::{
    basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, RefreshToken, Scope, TokenResponse, TokenUrl,
};
//use poem_openapi::Object;
use serde::{Deserialize, Serialize};

pub type OAuth2Client = oauth2::Client<
    oauth2::StandardErrorResponse<oauth2::basic::BasicErrorResponseType>,
    oauth2::StandardTokenResponse<oauth2::EmptyExtraTokenFields, oauth2::basic::BasicTokenType>,
    oauth2::StandardTokenIntrospectionResponse<
        oauth2::EmptyExtraTokenFields,
        oauth2::basic::BasicTokenType,
    >,
    oauth2::StandardRevocableToken,
    oauth2::StandardErrorResponse<oauth2::RevocationErrorResponseType>,
    oauth2::EndpointSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointSet,
>;

#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "web-api", derive(poem_openapi::Object))]
pub struct AuthorizeUrlRequest {
    /// The ID of the account for which the authorization URL is generated.
    pub account_id: u64,
    /// The name of the OAuth2 configuration to use for generating the authorization URL.
    pub oauth2_id: u64,
}

pub struct OAuth2Flow {
    pub oauth2_id: u64,
}

impl OAuth2Flow {
    pub fn new(oauth2_id: u64) -> Self {
        Self { oauth2_id }
    }

    pub fn authorize_url(&self, account_id: u64) -> BichonResult<String> {
        // Fetch OAuth2 entity or return a custom error if not found
        let entity = self.fetch_oauth2_entity()?;

        if !entity.enabled {
            return Err(raise_error!(
                format!(
                    "OAuth2 authentication is disabled for this client '{}'.",
                    self.oauth2_id
                ),
                ErrorCode::OAuth2ItemDisabled
            ));
        }
        // Create and configure the OAuth2 client
        let client = self.build_oauth2_client(&entity)?;
        // Generate PKCE challenge and verifier
        let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();
        // Build the authorization URL request

        let mut request = client
            .authorize_url(CsrfToken::new_random)
            .set_pkce_challenge(pkce_code_challenge)
            .add_scopes(
                entity
                    .scopes
                    .unwrap_or(Vec::new())
                    .into_iter()
                    .map(Scope::new),
            );
        // Add extra parameters
        if let Some(extra_params) = &entity.extra_params {
            for (name, value) in extra_params {
                request = request.add_extra_param(name.clone(), value.clone());
            }
        }
        // Extract authorization URL and CSRF state
        let (authorize_url, csrf_state) = request.url();
        // Save the pending OAuth2 state
        self.save_pending_oauth2_state(
            account_id,
            csrf_state.secret(),
            pkce_code_verifier.secret(),
        )?;
        // Return the authorization URL
        Ok(authorize_url.to_string())
    }

    pub async fn fetch_save_access_token(
        &self,
        account_id: u64,
        code_verifier: &str,
        code: &str,
    ) -> BichonResult<()> {
        let entity = self.fetch_oauth2_entity()?;
        let client = self.build_oauth2_client(&entity)?;
        let http_client = build_http_client(entity.use_proxy)?;

        let token_response = client
            .exchange_code(AuthorizationCode::new(code.to_owned()))
            .set_pkce_verifier(PkceCodeVerifier::new(code_verifier.to_owned()))
            .request_async(&http_client)
            .await
            .map_err(|e| raise_error!(format!("{:#?}", e), ErrorCode::HttpResponseError))?;

        let access_token = token_response.access_token().secret().to_owned();
        let refresh_token = token_response
            .refresh_token()
            .ok_or_else(|| {
                raise_error!(
                    "Missing refresh token in the token response.".into(),
                    ErrorCode::MissingRefreshToken
                )
            })?
            .secret()
            .to_owned();

        self.save_oauth2_entity(account_id, access_token, refresh_token)?;
        Ok(())
    }

    fn save_oauth2_entity(
        &self,
        account_id: u64,
        access_token: String,
        refresh_token: String,
    ) -> BichonResult<()> {
        let token =
            OAuth2AccessToken::create(account_id, self.oauth2_id, access_token, refresh_token)?;
        token.save_or_update()
    }

    fn update_oauth2_entity(
        &self,
        account_id: u64,
        access_token: String,
        refresh_token: String,
    ) -> BichonResult<()> {
        OAuth2AccessToken::set_access_token(
            account_id,
            encrypt!(&access_token)?,
            encrypt!(&refresh_token)?,
        )
    }

    pub async fn refresh_access_token(&self, token: &OAuth2AccessToken) -> BichonResult<()> {
        let entity = self.fetch_oauth2_entity()?;
        if !entity.enabled {
            OAuth2AccessToken::delete_by_oauth2_id(token.oauth2_id)?;
            return Err(raise_error!(
                "OAuth2 authentication is disabled for this client".into(),
                ErrorCode::OAuth2ItemDisabled
            ));
        }
        let client = self.build_oauth2_client(&entity)?;
        let http_client = build_http_client(entity.use_proxy)?;

        let refresh_token = token.refresh_token.clone().ok_or_else(|| {
            raise_error!(
                "refresh token is null".into(),
                ErrorCode::MissingRefreshToken
            )
        })?;

        let refresh_response = client
            .exchange_refresh_token(&RefreshToken::new(refresh_token.clone()))
            .add_scopes(
                entity
                    .scopes
                    .unwrap_or(Vec::new())
                    .into_iter()
                    .map(Scope::new),
            )
            .request_async(&http_client)
            .await
            .map_err(|e| {
                raise_error!(
                    format!(
                        "Failed to retrieve refresh token response: {}",
                        e.to_string()
                    ),
                    ErrorCode::HttpResponseError
                )
            })?;

        let access_token = refresh_response.access_token().secret().to_owned();
        let new_refresh_token = refresh_response
            .refresh_token()
            .map(|r| r.secret().to_owned())
            .unwrap_or_else(|| refresh_token.clone());
        self.update_oauth2_entity(token.account_id, access_token, new_refresh_token)?;
        Ok(())
    }

    // Helper function to fetch the OAuth2 entity
    fn fetch_oauth2_entity(&self) -> BichonResult<OAuth2> {
        OAuth2::get(self.oauth2_id)?.ok_or_else(|| {
            raise_error!(
                format!("OAuth2 entity with id '{}' not found", self.oauth2_id),
                ErrorCode::ResourceNotFound
            )
        })
    }

    // Helper function to build the OAuth2 client
    fn build_oauth2_client(&self, entity: &OAuth2) -> BichonResult<OAuth2Client> {
        let auth_url = AuthUrl::new(entity.auth_url.clone())
            .map_err(|e| raise_error!(format!("{:#?}", e), ErrorCode::InvalidParameter))?;
        let token_url = TokenUrl::new(entity.token_url.clone())
            .map_err(|e| raise_error!(format!("{:#?}", e), ErrorCode::InvalidParameter))?;
        let redirect_uri = RedirectUrl::new(entity.redirect_uri.clone())
            .map_err(|e| raise_error!(format!("{:#?}", e), ErrorCode::InvalidParameter))?;

        let client = BasicClient::new(ClientId::new(entity.client_id.clone()));
        let client = match entity.client_type {
            OAuth2ClientType::Confidential => {
                let encrypted_secret = entity.client_secret.as_ref().ok_or_else(|| {
                    raise_error!(
                        "The confidential OAuth2 client has no stored client secret. Supply a new secret."
                            .into(),
                        ErrorCode::InvalidParameter
                    )
                })?;
                client.set_client_secret(ClientSecret::new(decrypt!(encrypted_secret)?))
            }
            OAuth2ClientType::Public => client,
        };

        // Both client types use the same PKCE authorization and token exchange paths.
        let client = client
            .set_auth_uri(auth_url)
            .set_token_uri(token_url)
            .set_redirect_uri(redirect_uri);

        Ok(client)
    }

    // Helper function to save the pending OAuth2 state
    fn save_pending_oauth2_state(
        &self,
        account_id: u64,
        csrf_state: &str,
        pkce_code_verifier: &str,
    ) -> BichonResult<()> {
        OAuth2PendingEntity::new(
            self.oauth2_id,
            account_id,
            csrf_state.to_owned(),
            pkce_code_verifier.to_owned(),
        )
        .save()
    }
}

// Helper function to build the HTTP client
fn build_http_client(use_proxy: Option<u64>) -> BichonResult<reqwest::Client> {
    if let Some(proxy_id) = use_proxy {
        let proxy = Proxy::get(proxy_id)?;
        let proxy_url = parse_proxy_url(&proxy.url)?.standard_url();
        return oauth2::reqwest::ClientBuilder::new()
            .redirect(oauth2::reqwest::redirect::Policy::none())
            .proxy(reqwest::Proxy::all(&proxy_url).map_err(|_| {
                raise_error!(
                    "Failed to configure proxy. Please check the proxy configuration.".into(),
                    ErrorCode::InternalError
                )
            })?)
            .build()
            .map_err(|e| raise_error!(format!("{:#?}", e), ErrorCode::InternalError));
    }
    oauth2::reqwest::ClientBuilder::new()
        .redirect(oauth2::reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| raise_error!(format!("{:#?}", e), ErrorCode::InternalError))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth2::entity::OAuth2ClientType;
    use std::{collections::BTreeMap, sync::Once};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::oneshot,
    };

    static SET_TEST_PASSWORD: Once = Once::new();

    fn set_test_encryption_password() {
        SET_TEST_PASSWORD.call_once(|| {
            std::env::set_var(
                "BICHON_ENCRYPT_PASSWORD",
                "oauth2-public-client-test-password",
            );
        });
    }

    fn entity(
        client_type: OAuth2ClientType,
        client_secret: Option<String>,
        token_url: String,
    ) -> OAuth2 {
        OAuth2 {
            id: 1,
            description: Some("test".into()),
            client_id: "test-client-id".into(),
            client_type,
            client_secret,
            auth_url: "https://provider.example/authorize".into(),
            token_url,
            redirect_uri: "http://127.0.0.1:15630/oauth2/callback".into(),
            scopes: Some(vec!["mail.read".into()]),
            extra_params: None,
            enabled: true,
            use_proxy: None,
            created_at: 1,
            updated_at: 1,
        }
    }

    async fn token_endpoint() -> (String, oneshot::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (request_sender, request_receiver) = oneshot::channel();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4096];

            loop {
                let count = stream.read(&mut buffer).await.unwrap();
                if count == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..count]);

                let header_end = request
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .map(|position| position + 4);
                if let Some(header_end) = header_end {
                    let headers = String::from_utf8_lossy(&request[..header_end]);
                    let content_length = headers
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .and_then(|value| value.trim().parse::<usize>().ok())
                        })
                        .unwrap_or_default();
                    if request.len() >= header_end + content_length {
                        break;
                    }
                }
            }

            let body = r#"{"access_token":"access","token_type":"Bearer","expires_in":3600,"refresh_token":"refresh"}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            request_sender
                .send(String::from_utf8(request).unwrap())
                .unwrap();
        });

        (format!("http://{address}/token"), request_receiver)
    }

    fn request_body(request: &str) -> &str {
        request.split_once("\r\n\r\n").unwrap().1
    }

    fn has_authorization_header(request: &str) -> bool {
        request
            .split_once("\r\n\r\n")
            .unwrap()
            .0
            .lines()
            .any(|line| line.to_ascii_lowercase().starts_with("authorization:"))
    }

    #[tokio::test]
    async fn public_code_exchange_uses_pkce_without_client_authentication() {
        let (token_url, captured_request) = token_endpoint().await;
        let entity = entity(OAuth2ClientType::Public, None, token_url);
        let client = OAuth2Flow::new(entity.id)
            .build_oauth2_client(&entity)
            .unwrap();

        client
            .exchange_code(AuthorizationCode::new("authorization-code".into()))
            .set_pkce_verifier(PkceCodeVerifier::new("pkce-verifier".into()))
            .request_async(&reqwest::Client::new())
            .await
            .unwrap();

        let request = captured_request.await.unwrap();
        assert!(!has_authorization_header(&request));
        assert!(!request_body(&request).contains("client_secret="));
        assert!(request_body(&request).contains("code_verifier=pkce-verifier"));
    }

    #[tokio::test]
    async fn public_refresh_omits_client_secret_authentication() {
        let (token_url, captured_request) = token_endpoint().await;
        let entity = entity(OAuth2ClientType::Public, None, token_url);
        let client = OAuth2Flow::new(entity.id)
            .build_oauth2_client(&entity)
            .unwrap();

        client
            .exchange_refresh_token(&RefreshToken::new("refresh-token".into()))
            .request_async(&reqwest::Client::new())
            .await
            .unwrap();

        let request = captured_request.await.unwrap();
        assert!(!has_authorization_header(&request));
        assert!(!request_body(&request).contains("client_secret="));
        assert!(request_body(&request).contains("grant_type=refresh_token"));
    }

    #[tokio::test]
    async fn confidential_exchange_and_refresh_keep_basic_authentication() {
        set_test_encryption_password();
        let encrypted_secret = encrypt!("test-secret").unwrap();

        for refresh in [false, true] {
            let (token_url, captured_request) = token_endpoint().await;
            let entity = entity(
                OAuth2ClientType::Confidential,
                Some(encrypted_secret.clone()),
                token_url,
            );
            let client = OAuth2Flow::new(entity.id)
                .build_oauth2_client(&entity)
                .unwrap();

            if refresh {
                client
                    .exchange_refresh_token(&RefreshToken::new("refresh-token".into()))
                    .request_async(&reqwest::Client::new())
                    .await
                    .unwrap();
            } else {
                client
                    .exchange_code(AuthorizationCode::new("authorization-code".into()))
                    .set_pkce_verifier(PkceCodeVerifier::new("pkce-verifier".into()))
                    .request_async(&reqwest::Client::new())
                    .await
                    .unwrap();
            }

            let request = captured_request.await.unwrap();
            assert!(has_authorization_header(&request));
        }
    }

    #[test]
    fn authorization_urls_include_pkce_challenge_and_state_for_both_types() {
        for client_type in [OAuth2ClientType::Confidential, OAuth2ClientType::Public] {
            set_test_encryption_password();
            let secret = (client_type == OAuth2ClientType::Confidential)
                .then(|| encrypt!("test-secret").unwrap());
            let entity = entity(client_type, secret, "https://provider.example/token".into());
            let client = OAuth2Flow::new(entity.id)
                .build_oauth2_client(&entity)
                .unwrap();
            let (challenge, _) = PkceCodeChallenge::new_random_sha256();
            let (url, state) = client
                .authorize_url(|| CsrfToken::new("expected-state".into()))
                .set_pkce_challenge(challenge)
                .url();

            let query = url.query_pairs().collect::<BTreeMap<_, _>>();
            assert_eq!(state.secret(), "expected-state");
            assert_eq!(query.get("state").unwrap(), "expected-state");
            assert_eq!(query.get("code_challenge_method").unwrap(), "S256");
            assert!(query.contains_key("code_challenge"));
        }
    }

    #[test]
    fn confidential_client_without_secret_is_rejected() {
        let entity = entity(
            OAuth2ClientType::Confidential,
            None,
            "https://provider.example/token".into(),
        );
        assert!(OAuth2Flow::new(entity.id)
            .build_oauth2_client(&entity)
            .is_err());
    }
}
