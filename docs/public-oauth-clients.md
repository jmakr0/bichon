# Public/native OAuth clients

Bichon supports confidential OAuth clients with a provider-issued secret and public/native OAuth clients without a secret. Public clients use the existing authorization-code flow with PKCE and state validation.

The provider redirects an **authorization code**, not an access token, to Bichon. Bichon validates the state value, exchanges the code at the token endpoint without a client secret, encrypts the returned access and refresh tokens, and redirects the browser to `/oauth2-result`.

Use an OAuth application that you own and administer. Do not reuse a client ID copied from Thunderbird or another third-party application.

## Configure and authorize a public client

1. Create the email account in Bichon.
2. Create an OAuth configuration and select **Public/native client**.
3. Enter the client ID, authorization URL, token URL, scopes, and the exact callback URI visible to the browser:

   ```text
   http://127.0.0.1:15630/oauth2/callback
   ```

4. Register that exact callback URI with the OAuth provider.
5. Select the email account and click **Authorize**.
6. Complete the provider login. Bichon adds PKCE and state to the authorization request.
7. The provider redirects the authorization code to `/oauth2/callback`.
8. Bichon validates state, exchanges the code without a client secret, stores the encrypted tokens, and redirects to `/oauth2-result`.

If `BICHON_BASE_URL` is configured, place its path before both endpoints. For example, with `BICHON_BASE_URL=/bichon`, use:

```text
http://127.0.0.1:15630/bichon/oauth2/callback
```

The redirect URI configured in Bichon and at the provider must match exactly, including the scheme, host, port, path, and any base path.

## Recommended: authorize through an SSH tunnel

Forward the Bichon listener to the workstation where the browser runs:

```bash
ssh -N -L 15630:127.0.0.1:15630 bichon-host
```

Keep the SSH process running throughout authorization, open `http://127.0.0.1:15630` in the workstation browser, and use this callback in both Bichon and the provider:

```text
http://127.0.0.1:15630/oauth2/callback
```

This is the preferred method. The provider redirect reaches the workstation loopback address and the SSH tunnel carries it to Bichon. It does not require VNC or an additional public listener.

If local port `15630` is occupied, choose another local port while keeping the remote port unchanged:

```bash
ssh -N -L 25630:127.0.0.1:15630 bichon-host
```

Then open `http://127.0.0.1:25630` and register `http://127.0.0.1:25630/oauth2/callback`. The browser-visible port is part of the redirect URI and must match the provider registration.

## Optional: host-local Chromium through noVNC

Use this fallback only when authorization must run in a browser on the Bichon host. Bichon does not install or manage these components.

The example assumes Debian, a dedicated unprivileged user named `bichon-browser`, Bichon on `127.0.0.1:15630`, display `:1`, VNC on `127.0.0.1:5901`, noVNC on `127.0.0.1:6080`, and a browser-visible callback proxy on `127.0.0.1:58585`.

Install the host-local browser components:

```bash
sudo apt update
sudo apt install chromium xvfb openbox x11vnc novnc websockify nginx
sudo adduser --system --group --home /var/lib/bichon-browser bichon-browser
sudo install -d -o bichon-browser -g bichon-browser -m 0700 /var/lib/bichon-browser/.vnc
sudo -u bichon-browser x11vnc -storepasswd /var/lib/bichon-browser/.vnc/passwd
sudo chmod 0600 /var/lib/bichon-browser/.vnc/passwd
```

Create `/etc/systemd/system/bichon-auth-browser.service`:

```ini
[Unit]
Description=Temporary browser for Bichon OAuth authorization
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=bichon-browser
Group=bichon-browser
Environment=DISPLAY=:1
ExecStart=/bin/sh -c 'Xvfb :1 -screen 0 1440x900x24 & openbox-session & chromium --user-data-dir=/var/lib/bichon-browser/chromium --no-first-run http://127.0.0.1:58585 & exec x11vnc -display :1 -localhost -rfbport 5901 -rfbauth /var/lib/bichon-browser/.vnc/passwd -forever -shared'
Restart=on-failure
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

Create `/etc/systemd/system/bichon-auth-novnc.service`:

```ini
[Unit]
Description=noVNC for the Bichon OAuth browser
After=bichon-auth-browser.service
Requires=bichon-auth-browser.service

[Service]
Type=simple
User=bichon-browser
Group=bichon-browser
ExecStart=/usr/bin/websockify --web=/usr/share/novnc 127.0.0.1:6080 127.0.0.1:5901
Restart=on-failure
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

Create `/etc/nginx/sites-available/bichon-oauth-loopback`:

```nginx
server {
    listen 127.0.0.1:58585;
    server_name 127.0.0.1;

    location / {
        proxy_pass http://127.0.0.1:15630;
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable the configuration and services:

```bash
sudo ln -s /etc/nginx/sites-available/bichon-oauth-loopback /etc/nginx/sites-enabled/bichon-oauth-loopback
sudo nginx -t
sudo systemctl reload nginx
sudo systemctl daemon-reload
sudo systemctl enable --now bichon-auth-browser.service bichon-auth-novnc.service
```

Forward noVNC from the workstation and open `http://127.0.0.1:6080/vnc.html`:

```bash
ssh -N -L 6080:127.0.0.1:6080 bichon-host
```

Register and configure this callback URI:

```text
http://127.0.0.1:58585/oauth2/callback
```

The nginx proxy preserves the callback path and query parameters. No rewrite is needed for an application whose redirect URI you control. Keep VNC, noVNC, and nginx bound to loopback and access them only through SSH.

After authorization, stop and disable the temporary browser services if they are no longer needed. Remove `/var/lib/bichon-browser/chromium` if browser-session persistence is unnecessary; this signs the temporary profile out of provider sessions.

## Microsoft Entra example

Create a user-owned application in Microsoft Entra:

1. Register an application for the intended tenant.
2. Add the exact loopback callback under the **Mobile and desktop applications** platform.
3. Enable public-client flows.
4. Use tenant-specific authorization and token endpoints by default. Use the `common` endpoint only when the application is intentionally multitenant.
5. Add only these delegated scopes for IMAP archiving:

   ```text
   https://outlook.office.com/IMAP.AccessAsUser.All
   offline_access
   ```

6. Do not create or enter a client secret.

For example, replace `{tenant-id}` in these endpoints:

```text
https://login.microsoftonline.com/{tenant-id}/oauth2/v2.0/authorize
https://login.microsoftonline.com/{tenant-id}/oauth2/v2.0/token
```

Native-app loopback redirects and PKCE are described in [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252.html). Also review [Microsoft's redirect URI guidance](https://learn.microsoft.com/en-us/entra/identity-platform/reply-url) before registering the callback.

## Compatibility and security notes

- Existing OAuth records and API create requests without `client_type` remain confidential by default.
- Existing confidential secrets remain encrypted and are preserved when an edit omits the secret.
- Changing a confidential client to public clears the stored secret.
- Changing a public client to confidential requires a new secret.
- Changing a client type or client ID may require reauthorization. Existing tokens are not deleted automatically.
- Downgrading Bichon after creating public-client records is unsupported because older releases require a client secret.
- Public-client support adds no callback routes, VNC dependencies, listeners, environment variables, or embedded provider client IDs.
