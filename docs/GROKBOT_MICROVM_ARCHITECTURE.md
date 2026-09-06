# Reverse-Engineered Grokbot / Cloud Agent MicroVM Architecture & Complete Replication Blueprint

This document provides an exhaustive reverse-engineered architectural specification of the autonomous cloud agent microVM environment (`box@cursor:/workspace`, internally codenamed `sand` / `@anysphere/exec-daemon-runtime`). It details the hypervisor, kernel flags, display multiplexing, multi-screen agent router, inverted WebAuthn proxy, crash-loop prevention mechanics, and turnkey scripts to reproduce this system.

---

## 1. System Inventory & Infrastructure Profiling

### A. Virtualization & Hardware Topology
* **Hypervisor**: KVM (Kernel-based Virtual Machine) via Firecracker or Cloud-Hypervisor.
* **vCPUs**: 8 vCPUs (`GenuineIntel Intel(R) Xeon(R) Pro`).
* **Memory**: 32 GB RAM, 0 MB swap (`systemd.setenv=SWAP_SIZE_MB=0`).
* **Storage**: `/dev/vda` (VirtIO block) with an `overlayfs` root filesystem (`lowerdir` layered over Docker image graph, `upperdir` for volatile state). Enables instantaneous Copy-on-Write microVM branching.
* **Networking**: Point-to-point VirtIO tap interface (`eth0: 172.30.0.2/24` with host gateway `172.30.0.1`).
* **Cgroup Layout**: Cgroup v2 partitioned into two strict scheduling domains via `box-cgroups.sh`:
  * `interactive` (`/sys/fs/cgroup/interactive`): High priority (`cpu.weight`) for X11, window manager, compositor, dock, and VNC daemons.
  * `agent` (`/sys/fs/cgroup/agent`): Lower priority background slice for compilers, agent execution, test suites, and sub-processes.

### B. Monolithic MicroVM Kernel (`Linux 6.12.94+`)
```text
console=ttyS0 root=/dev/vda random.trust_cpu=on ip=172.30.0.2::172.30.0.1:255.255.255.0::eth0:off rw loglevel=7 earlyprintk=ttyS0 print-fatal-signals=1 systemd.unified_cgroup_hierarchy=1 systemd.setenv=SWAP_SIZE_MB=0 reboot=k panic=1 nomodule i8042.noaux=1 i8042.nomux=1 i8042.dumbkbd=1 clocksource=kvm-clock tsc=unstable nosoftlockup root=/dev/vda rw
```

#### Kernel Flag Rationale:
| Flag | Purpose |
| :--- | :--- |
| `console=ttyS0 earlyprintk=ttyS0` | Pure serial console; disables emulated VGA framebuffer for instant boot. |
| `nomodule` | Disables dynamic kernel modules (`.ko`). VirtIO drivers (`virtio_net`, `virtio_blk`, `virtio_pci`, `overlayfs`) compiled statically (`CONFIG_*=y`). |
| `reboot=k panic=1` | Fast failover: kernel exits immediately on fatal panic back to host supervisor. |
| `i8042.noaux=1 i8042.nomux=1 i8042.dumbkbd=1` | Bypasses legacy PS/2 controller probing, saving ~200ms of boot latency. |
| `clocksource=kvm-clock` | Paravirtualized clock for drift-free host/guest time synchronization. |
| `random.trust_cpu=on` | Seeds entropy directly from hardware `RDRAND`/`RDSEED`. |
| `systemd.unified_cgroup_hierarchy=1` | Pure cgroup v2 hierarchy. |
| `systemd.setenv=SWAP_SIZE_MB=0` | Eliminates disk swap thrashing under agent load. |

---

## 2. Process Tree & Supervision Hierarchy

```
[PID 1: Container / MicroVM Entrypoint]
  │
  ├─► [PID 53: /usr/local/bin/sand-exit-watch] (Python subreaper, crash logging, zombie reaping)
  │     │
  │     ├─► [PID 167: sand-window-router.mjs] (HTTP/WS router on port 1339)
  │     ├─► [PID 139: websockify :6081] (Token router for multi-display VNC)
  │     ├─► [PID 733: websockify :6080] (Default direct proxy to :1)
  │     │
  │     ├─► [Display :1 Stack] (start-desktop.sh)
  │     │     ├─► Xvfb :1 (1280x800x24)
  │     │     ├─► x11vnc -display :1 (RFB 5900)
  │     │     ├─► xfwm4 --compositor=off
  │     │     ├─► picom --backend xrender --no-vsync
  │     │     └─► plank --name dock1
  │     │
  │     ├─► [Display :4 Stack]
  │     │     ├─► Xvfb :4 & x11vnc (RFB 5904)
  │     │     └─► /exec-daemon/index.js serve --port 14004 --pty-websocket-port 13604
  │     │
  │     ├─► [Display :6 Stack]
  │     │     ├─► Xvfb :6 & x11vnc (RFB 5906)
  │     │     └─► /exec-daemon/index.js serve --port 14006 --pty-websocket-port 13606
  │     │
  │     └─► [Display :7 Stack] (Active Session)
  │           ├─► Xvfb :7 & x11vnc (RFB 5907)
  │           └─► /exec-daemon/index.js serve --port 14007 --pty-websocket-port 13607
```

---

## 3. Multi-Window Router & Per-Screen Agent Multiplexing

The system routes traffic using `sand-window-router.mjs`:
* **HTTP/WS Ingress**: Port `1339`.
* **Primary Agent Daemon**: Port `1337`.
* **Per-Screen Agent Daemons**: Ports `14000 + DISPLAY_NUM` (e.g., 14004, 14006, 14007).
* **Per-Screen PTY WebSockets**: Ports `13600 + DISPLAY_NUM` (e.g., 13604, 13606, 13607).
* **Routing Headers**:
  * `x-sand-display`: Requested display integer (e.g., `4`, `7`).
  * `x-sand-window-owner`: Security token matching `/tmp/sand-window-tokens.d/<display>`.
* **Security**: Verified via constant-time token comparison (`crypto.timingSafeEqual`).

Each agent instance runs Anthropic Computer Use and terminal tools:
```bash
/exec-daemon/node /exec-daemon/index.js serve \
  --port $((14000 + DISPLAY_NUM)) \
  --pty-websocket-port $((13600 + DISPLAY_NUM)) \
  --auth-token local \
  --rg-path /exec-daemon/rg \
  --computer-use-enabled \
  --origin-cli-enabled
```

---

## 4. Multi-Monitor Chrome Shared Session Architecture

Chrome single-instance behavior prevents multiple displays from attaching to the same `--user-data-dir`. The VM solves this with `link-chrome-session`:

1. **Per-Display User Data Directories**:
   * Screen 1: `/home/box/chrome-profile`
   * Screen N: `/home/box/chrome-profile-N`
   * Remote Debugging Port: `9222 + DISPLAY_NUM` (`127.0.0.1:9222`, `9223`, `9227`).
2. **Session Symlink Sharing ("One Box, One Session")**:
   Inside each fork's `Default/` profile directory:
   * `Cookies` ➔ `/home/box/chrome-profile/Default/Cookies`
   * `Login Data` ➔ `/home/box/chrome-profile/Default/Login Data`
   * `Login Data For Account` ➔ `/home/box/chrome-profile/Default/Login Data For Account`
3. **Rollback-Journal Concurrency**: SQLite flat files in rollback-journal mode allow concurrent read/write across displays, so logging into GitHub or Google on Screen 1 immediately authenticates Screens 4, 6, and 7 without re-authenticating.

---

## 5. Inverted WebAuthn Proxy Architecture

To allow headless Chrome inside the cloud microVM to authenticate with hardware keys (YubiKey, Apple Touch ID, Windows Hello) without passing raw keys into the VM:

1. **Chrome Managed Policy**: Force-installs extension ID `pkjakndclmokfbgfnpgjieoebnbghhgb` via `/etc/opt/chrome/policies/managed/sand-webauthn.json` using `ExtensionSettings`.
2. **Preference Seeding**: Python script modifies `Preferences` while Chrome is down to grant the extension incognito access.
3. **Intercept**: The extension attaches via `chrome.webAuthenticationProxy`.
4. **Native Messaging Forwarding**:
   * Page triggers `navigator.credentials.get(...)` or `create(...)`.
   * Extension intercepts the ceremony and invokes `chrome.runtime.sendNativeMessage("co.anysphere.sand.webauthn_proxy", ...)`.
   * Native host routes the ceremony over the reverse gRPC tunnel to the user's local machine (`1340`).
   * Local laptop authenticates with YubiKey / TouchID / Windows Hello and sends back `credentialJson`.
   * Extension calls `chrome.webAuthenticationProxy.completeGetRequest(...)`.

---

## 6. Crash-Loop Prevention & Orphan Reaping

To prevent headless container crash-loops when agent sessions restart:

* **`box-xvfb`**: Scans `/tmp/.X11-unix/X<N>` and `/proc/*/cmdline` using `ss` and `fuser`, terminates orphan Xvfb processes squatting on the socket, and deletes stale `/tmp/.X<N>-lock`.
* **`box-xfwm4`**: Scans for stale `xfwm4` instances on the target `DISPLAY`, sends `SIGTERM`, waits 1 second, then issues `SIGKILL`.
* **`box-picom`**: Reaps stale compositors holding the `_NET_WM_CM_S0` X11 selection before starting picom, preventing the "Another composite manager is already running" exit 1 crash-loop.
* **`box-plank`**: Waits via a Python ctypes `libX11.so.6` loop until `_NET_WM_CM_S0` selection owner is registered before starting the dock, preventing Plank from painting an opaque slab.
* **`box-x11vnc`**: Reaps processes holding RFB port `5900 + N` before binding.
* **`box-bounded-log.mjs`**: Circular in-memory buffer ring that rotates logs at 1 MB to prevent filling up the VM's ephemeral rootfs.

---

## 7. Turnkey Replication Assets in Repository (`deploy/microvm/`)

| File | Description |
| :--- | :--- |
| [`deploy/microvm/Dockerfile.rootfs`](file:///c:/Users/tyson/.repo/personal/syntropy/deploy/microvm/Dockerfile.rootfs) | Complete container build recipe for rootfs (box user UID 1000, Xvfb, x11vnc, novnc, websockify, openbox, xfce4). |
| [`deploy/microvm/kernel.config`](file:///c:/Users/tyson/.repo/personal/syntropy/deploy/microvm/kernel.config) | Kernel config fragment to compile the monolithic Linux 6.12 microVM kernel. |
| [`deploy/microvm/firecracker-vm.json`](file:///c:/Users/tyson/.repo/personal/syntropy/deploy/microvm/firecracker-vm.json) | Firecracker VM launch specification matching the discovered vCPUs, memory, disk, and `/proc/cmdline`. |
| [`deploy/microvm/window-router.mjs`](file:///c:/Users/tyson/.repo/personal/syntropy/deploy/microvm/window-router.mjs) | HTTP/WS multi-screen router directing traffic to per-screen agent daemons (`14000 + N`). |
| [`deploy/microvm/link-chrome-session.sh`](file:///c:/Users/tyson/.repo/personal/syntropy/deploy/microvm/link-chrome-session.sh) | Symlinks SQLite cookie/login databases across concurrent agent displays. |
| [`deploy/microvm/webauthn-proxy/`](file:///c:/Users/tyson/.repo/personal/syntropy/deploy/microvm/webauthn-proxy/) | Chrome MV3 extension intercepting and proxying WebAuthn ceremonies. |
| [`deploy/microvm/setup-display-mux.sh`](file:///c:/Users/tyson/.repo/personal/syntropy/deploy/microvm/setup-display-mux.sh) | Turnkey supervisor script managing multi-screen Xvfb, x11vnc, and tokenized websockify. |
| [`deploy/microvm/kasmvnc-alternative.sh`](file:///c:/Users/tyson/.repo/personal/syntropy/deploy/microvm/kasmvnc-alternative.sh) | High-performance WebRTC 60FPS KasmVNC service alternative. |
| [`deploy/microvm/gcp-host-setup.sh`](file:///c:/Users/tyson/.repo/personal/syntropy/deploy/microvm/gcp-host-setup.sh) | Single-command GCP Compute Engine host provisioner with nested KVM virtualization. |
