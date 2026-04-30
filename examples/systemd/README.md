# systemd Installation

## Steps

1. Copy the binary to `/usr/local/bin/`:
   ```
   install -m 755 ocsp-responder /usr/local/bin/
   ```

2. Copy the config to `/etc/ocsp-responder/ocsp-responder.yaml`:
   ```
   install -d /etc/ocsp-responder
   install -m 640 config/ocsp-responder.yaml /etc/ocsp-responder/
   ```

3. Copy certificates to `/certs/`:
   ```
   install -d /certs
   install -m 600 certs/*.crt certs/*.key /certs/
   ```

4. Create the service user:
   ```
   useradd -r -s /usr/sbin/nologin ocsp
   ```

5. Install and start the service:
   ```
   install -m 644 ocsp-responder.service /etc/systemd/system/
   systemctl daemon-reload
   systemctl enable --now ocsp-responder
   ```

## Checking status

```
systemctl status ocsp-responder
journalctl -u ocsp-responder -f
```
