# Running Family Hub at home, reachable only through Tailscale (Debian 13)

> Written by an AI coding tool (Claude Code) on 2026-10-03, and not yet tried on a real server.
> Read each step before running it, and check commands against the linked official pages:
> package names and paths can change between releases.

Family Hub runs on an always-on Debian 13 machine at home. It listens only on `127.0.0.1`;
`tailscale serve` gives it an HTTPS address on your private tailnet (`https://<machine>.<tailnet>.ts.net`),
so only devices signed in to your Tailscale network can reach it. Nothing is opened on your router.

```
family phone ──(Tailscale, encrypted)──▶ tailscale serve :443 (HTTPS, ts.net certificate)
                                              │ http://127.0.0.1:8000, adds X-Forwarded-For
                                              ▼
                                   waitress (serve.py) ▶ Family Hub ▶ /var/lib/family-hub/family.db
```

## 1. Install Debian 13 with an encrypted disk

1. Download Debian 13 ("trixie") from <https://www.debian.org/download> and install it.
2. At partitioning, choose **Guided – use entire disk and set up encrypted LVM**. Choose a long
   passphrase and keep it in your password manager. This is the disk encryption your notes rely on
   (security-notes.md, V14.1.2).
3. At software selection, untick the desktop and tick only **SSH server** and **standard system utilities**.
4. Give the machine a plain name (for example `hub`): see the note on certificates in step 5.

## 2. Unlock the disk over the network after a reboot

With an encrypted disk, the machine stops at boot and asks for the passphrase. Dropbear, a small
SSH server inside the early-boot system, lets you type it from another computer on your home network.

1. On the computer you'll unlock from, make a key just for this, if you don't have one:
   `ssh-keygen -t ed25519 -f ~/.ssh/hub-unlock`
2. On the server:
   ```bash
   sudo apt install dropbear-initramfs
   ```
3. Allow only that key, and only to unlock (one line, with your public key from `~/.ssh/hub-unlock.pub`):
   ```bash
   sudoedit /etc/dropbear/initramfs/authorized_keys
   ```
   ```
   no-port-forwarding,no-agent-forwarding,no-X11-forwarding,command="cryptroot-unlock" ssh-ed25519 AAAA... you@laptop
   ```
4. Use a different port from the normal SSH server, refuse passwords, and drop idle connections:
   ```bash
   sudoedit /etc/dropbear/initramfs/dropbear.conf
   ```
   ```
   DROPBEAR_OPTIONS="-I 180 -j -k -p 2222 -s -c cryptroot-unlock"
   ```
5. The early-boot system gets its address by DHCP by default. A fixed address is easier to find:
   reserve one for the server in your router's DHCP settings.
6. Rebuild the early-boot image:
   ```bash
   sudo update-initramfs -u
   ```
7. Test it: reboot, then from your other computer run `ssh -i ~/.ssh/hub-unlock -p 2222 root@<server's home IP>`
   and type the disk passphrase when asked.

Notes:
- This works only from your home network: Tailscale isn't running yet at that point in the boot.
- The early-boot image sits unencrypted in `/boot`. Someone with physical access to the machine
  could tamper with it. For a home server that is usually acceptable; keep the machine somewhere private.
- Dropbear has its own host key, so your computer will see a different key on port 2222 than on 22. That's expected.

Debian's own notes: `/usr/share/doc/dropbear-initramfs/README.Debian` on the server.

## 3. Keep it updated and lock down SSH

```bash
sudo apt install unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades
```

Sign in with an SSH key, then turn password sign-in off in `/etc/ssh/sshd_config.d/local.conf`:
```
PasswordAuthentication no
PermitRootLogin no
```
and `sudo systemctl reload ssh`. The app itself listens only on `127.0.0.1`, so nothing about it is
reachable from your network directly.

## 4. Install Tailscale

Follow Tailscale's Debian instructions: <https://tailscale.com/download/linux/debian> (they add
Tailscale's package repository and install `tailscale`). Then:
```bash
sudo tailscale up
```
Sign in with the account that owns your tailnet. Add your family members' devices from their phones
(the Tailscale app) the same way. Tailscale's free Personal plan covers up to 6 users.

In the Tailscale admin console (<https://login.tailscale.com/admin>):
- **DNS:** turn on **MagicDNS** and **HTTPS Certificates**.
- **Machines:** turn off key expiry for the server, so it doesn't drop off the tailnet every few months.

## 5. Install Family Hub

```bash
sudo apt install python3 git
sudo adduser --system --group --home /var/lib/family-hub --shell /usr/sbin/nologin familyhub
sudo chmod 0700 /var/lib/family-hub
sudo git clone https://github.com/abbyshade111/family-hub /opt/family-hub
sudo chown -R root:root /opt/family-hub          # the app can read its code but not change it
sudo mkdir -p /var/backups/family-hub && sudo chown familyhub:familyhub /var/backups/family-hub && sudo chmod 0700 /var/backups/family-hub
```

Settings (the secret key is written straight into the file, never printed):
```bash
sudo mkdir -p /etc/family-hub
sudo cp /opt/family-hub/deploy/family-hub.env.example /etc/family-hub/env
sudo python3 - <<'EOF'
import pathlib, re, secrets
env = pathlib.Path("/etc/family-hub/env")
env.write_text(re.sub(r"(?m)^FAMILY_HUB_SECRET_KEY=.*$", "FAMILY_HUB_SECRET_KEY=" + secrets.token_hex(32), env.read_text()))
EOF
sudo chown root:familyhub /etc/family-hub/env && sudo chmod 0640 /etc/family-hub/env
```

Run the tests once on the server, as the app's user:
```bash
sudo -u familyhub env FAMILY_HUB_DATA=/tmp/fh-test python3 -B /opt/family-hub/tests/run_tests.py
```

Services, logs and backups:
```bash
sudo cp /opt/family-hub/deploy/familyhub.service /opt/family-hub/deploy/familyhub-backup.service /opt/family-hub/deploy/familyhub-backup.timer /etc/systemd/system/
sudo mkdir -p /etc/systemd/journald.conf.d && sudo cp /opt/family-hub/deploy/journald-family-hub.conf /etc/systemd/journald.conf.d/family-hub.conf
sudo systemctl restart systemd-journald
sudo systemctl daemon-reload
sudo systemctl enable --now familyhub.service familyhub-backup.timer
```

Give it its HTTPS address on the tailnet (it keeps this across reboots):
```bash
sudo tailscale serve --bg --https=443 http://127.0.0.1:8000
```

**Never turn on Tailscale Funnel for this machine.** Funnel would publish the app to the whole internet.

**About the certificate:** HTTPS certificates are recorded in public Certificate Transparency logs,
so the machine's ts.net name (for example `hub.tail1234.ts.net`) becomes publicly visible, though
nobody outside your tailnet can connect to it. That's why step 1 suggests a plain machine name.

## 6. Check it

1. `systemctl status familyhub` shows it running. `ss -tlnp | grep 8000` shows it listening on `127.0.0.1:8000` only.
2. On your phone, with Tailscale on, open `https://<machine>.<tailnet>.ts.net`. The padlock should
   show a valid certificate for that exact name (this is the hand check **V12.2.2**). With Tailscale
   off, the address shouldn't load at all.
3. Sign in, then look at the logs:
   ```bash
   journalctl -u familyhub -n 20
   ```
   The request lines and `"event":"sign_in"` lines should show your phone's Tailscale address
   (`100.x.y.z`), **not** `127.0.0.1`. That shows the visitor's real address reaches the app through
   `tailscale serve` (**V4.1.3**, **V15.3.4**), so the per-IP sign-in limit works. If they show
   `127.0.0.1`, stop and tell Claude: the per-IP limit would then count every family member as one.
4. The next morning, `ls -l /var/backups/family-hub` shows a `family-*.db` file. Try a restore on another
   machine once, so you know it works (the steps are at the top of `tools/backup.py`).

## 7. Keep it running

- **Updating the app:** after you merge a reviewed pull request,
  `sudo git -C /opt/family-hub pull && sudo systemctl restart familyhub`.
- **Monthly** (your policy, V15.1.1): run `sv report --run --tools --advisories <OSV folder>` on your
  own computer, and update any package past its deadline.
- **If a key may have leaked** (V11.1.1): replace `FAMILY_HUB_SECRET_KEY` in `/etc/family-hub/env`,
  restart, sign everyone out with
  `sudo -u familyhub env FAMILY_HUB_DATA=/var/lib/family-hub python3 -B /opt/family-hub/tools/sign_out_everyone.py`,
  and read `journalctl -u familyhub`.

## 8. Then update securevibe.toml

Once it really runs this way, ask Claude to update what SecureVibe is told, with your answers:
`deployment` and `audience` under `[app]`, the five "not sure" answers that waited on hosting
(V4.1.3, V4.2.1, V13.2.2, V15.3.4, V16.4.3), and the certificate check V12.2.2.
