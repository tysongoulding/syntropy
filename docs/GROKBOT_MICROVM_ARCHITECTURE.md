# Reverse-Engineered Grokbot / Cloud Agent MicroVM Architecture & Replication Blueprint

This document details the exact specifications, virtualization layer, kernel build flags, display multiplexing stack, and networking discovered on the cloud agent microVM (`box@cursor:/workspace`). It provides turnkey configuration files and build scripts to replicate this identical infrastructure on GCP and bare-metal KVM hosts.

---

## 1. Target MicroVM Profile & Reverse-Engineered Inventory

### A. Virtualization & Hardware Topology
* **Hypervisor**: KVM (Kernel-based Virtual Machine) via Firecracker / Cloud-Hypervisor.
* **vCPUs**: 8 vCPUs (`GenuineIntel Intel(R) Xeon(R) Pro`).
* **Memory**: ~32 GB RAM (`Swap: 0 MB`, `systemd.setenv=SWAP_SIZE_MB=0`).
* **Block Device**: `/dev/vda` (VirtIO block device) mounted via `overlayfs` for instant Copy-on-Write (CoW) state branching and sub-second rollbacks.
* **NIC**: VirtIO MMIO / PCI network interface (`eth0`) with static point-to-point IP `172.30.0.2/24` routed to host gateway `172.30.0.1`.
* **Cgroup Layout**: Unified cgroup hierarchy (`cgroups v2`) with CPU, memory, and pids controllers enabled.

### B. Linux Kernel Boot Configuration
* **Release**: `Linux 6.12.94+` (Custom monolithic uncompressed `vmlinux`, stripped down for <50ms boot).
* **Command Line (`/proc/cmdline`)**:
```text
console=ttyS0 root=/dev/vda random.trust_cpu=on ip=172.30.0.2::172.30.0.1:255.255.255.0::eth0:off rw loglevel=7 earlyprintk=ttyS0 print-fatal-signals=1 systemd.unified_cgroup_hierarchy=1 systemd.setenv=SWAP_SIZE_MB=0 reboot=k panic=1 nomodule i8042.noaux=1 i8042.nomux=1 i8042.dumbkbd=1 clocksource=kvm-clock tsc=unstable nosoftlockup root=/dev/vda rw
```

#### Parameter Breakdown & Rationale:
| Flag | Architectural Purpose |
| :--- | :--- |
| `console=ttyS0 earlyprintk=ttyS0` | Headless serial console via UART 8250 / VirtIO console; no emulated VGA framebuffer or GPU overhead. |
| `nomodule` | Disables dynamic kernel module loading (`.ko`). All drivers (`virtio_net`, `virtio_blk`, `virtio_pci`, `overlayfs`) are compiled statically (`CONFIG_*=y`). Accelerates boot and hardens security. |
| `reboot=k panic=1` | Fast failover: instant kernel reboot/termination on fatal panic, handing control back to the host hypervisor supervisor. |
| `i8042.noaux=1 i8042.nomux=1 i8042.dumbkbd=1` | Disables legacy PS/2 mouse/keyboard multiplexing probes, saving 150-300ms during kernel initialization. |
| `clocksource=kvm-clock tsc=unstable` | Uses hypervisor paravirtualized clock for zero-drift synchronization across host and microVM. |
| `random.trust_cpu=on` | Seeds Linux CSPRNG directly from CPU `RDRAND`/`RDSEED` instructions without blocking on entropy generation during rapid spin-ups. |
| `systemd.unified_cgroup_hierarchy=1` | Pure cgroup v2 tree for strict process resource containment. |
| `systemd.setenv=SWAP_SIZE_MB=0` | Prevents disk thrashing in cloud agent execution; forces hard out-of-memory killing rather than slow swapping. |

---

## 2. Multi-Display Headless Multiplexer Architecture

The microVM creates independent headless X11 virtual framebuffers per agent or browser session, routing them via tokenized WebSockets to eliminate multi-port firewall overhead.

```
[Web Browser / Syntropy UI]
          │
          │ HTTP / WebSocket (Port 6081)
          ▼
   [websockify Proxy]
     │ (token: agent-1 ➔ localhost:5901)
     │ (token: agent-2 ➔ localhost:5904)
     │ (token: agent-3 ➔ localhost:5907)
     ▼
 ┌───────────────┬───────────────┬───────────────┐
 │ Screen :1     │ Screen :4     │ Screen :7     │
 │ x11vnc (5901) │ x11vnc (5904) │ x11vnc (5907) │
 │ Xvfb :1       │ Xvfb :4       │ Xvfb :7       │
 └───────────────┴───────────────┴───────────────┘
```

### A. Display Server (`Xvfb`)
Headless 24-bit virtual displays running at `1280x800`:
```bash
Xvfb :1 -screen 0 1280x800x24 -ac +extension GLX +render -noreset
```
* `-ac`: Disables host-based access control (trusted local Unix socket `/tmp/.X11-unix/X1`).
* `+extension GLX +render`: Provides hardware acceleration stubs for headless Chromium, Puppeteer, and Electron.
* `-noreset`: Retains display memory when the last client disconnects.

### B. VNC Export Daemon (`x11vnc`)
Each X11 screen is mirrored to a loopback RFB port (`5900 + DISPLAY_NUM`):
```bash
x11vnc -skip_lockkeys -display :1 -localhost -nopw -shared -forever -noxdamage -rfbport 5901 -quiet
```
* `-skip_lockkeys`: Prevents CapsLock/NumLock desync between host browser and remote desktop.
* `-localhost`: Restricts VNC protocol strictly to `127.0.0.1`.
* `-forever -shared`: Keeps server open across disconnections and allows multi-agent observation.
* `-noxdamage`: Eliminates XDamage polling bugs on virtual framebuffers.

### C. Token-Multiplexed WebSocket Gateway (`websockify`)
Instead of exposing dozens of raw VNC ports, a single websockify daemon maps dynamic tokens to internal ports:
```bash
websockify \
  --web=/usr/share/novnc \
  --heartbeat=30 \
  --token-plugin TokenFile \
  --token-source /tmp/sand-novnc-tokens.d \
  0.0.0.0:6081
```

#### Token File Structure (`/tmp/sand-novnc-tokens.d/`):
Each agent writes a token file (e.g., `/tmp/sand-novnc-tokens.d/agent-screen-7.token`):
```text
agent-screen-7: 127.0.0.1:5907
```
The browser client then connects to:
```text
http://<microvm-ip>:6081/vnc.html?token=agent-screen-7&autoconnect=true&resize=remote
```

### D. Process Supervision & Bounded Logging
Processes run wrapped in `/usr/local/bin/box-bounded-log` and managed via `flock`:
```bash
flock -n /tmp/novnc-forks.log.lock /exec-daemon/node /usr/local/bin/box-bounded-log.mjs
```
This guarantees log rotation in RAM, preventing microVM ephemeral root filesystems from filling up under high agent activity.

---

## 3. Directory Layout & User Isolation

* **User**: Non-root `box` (UID `1000`, GID `1000`) with passwordless sudo access.
* **Home**: `/home/box`
* **Workspace**: `/workspace` (shared bind-mount or primary work directory).
* **Exec Daemon**: `/exec-daemon` (host-guest synchronization agent, Node/Rust daemon).
* **Tokens**: `/tmp/sand-novnc-tokens.d` (world-writable or `box`-owned token directory).

---

## 4. Modern Upgrade Path: KasmVNC & WebRTC

While the discovered stack uses standard `Xvfb` + `x11vnc` + `websockify` + `noVNC`, Syntropy can optionally run **KasmVNC**:
* **Bandwidth & Latency**: KasmVNC uses WebP/H.264 video compression over WebSockets/WebRTC, achieving **60 FPS** at a fraction of x11vnc bandwidth.
* **Single Binary**: Replaces `Xvfb`, `x11vnc`, and `websockify` with a single native X server binary (`vncserver` / `Xkasmvnc`).
* **Direct Web UI**: Serves an integrated modern web client directly on HTTPS/WSS (port 8444).

---

## 5. Replication Blueprint: File Index

All runnable assets to recreate this microVM have been placed in `deploy/microvm/`:

1. [`deploy/microvm/Dockerfile.rootfs`](file:///c:/Users/tyson/.repo/personal/syntropy/deploy/microvm/Dockerfile.rootfs): Rootfs image replicating user `box`, Xvfb, x11vnc, noVNC, websockify, and bounded logging.
2. [`deploy/microvm/kernel.config`](file:///c:/Users/tyson/.repo/personal/syntropy/deploy/microvm/kernel.config): Stripped monolithic Linux 6.12 kernel configuration for sub-second KVM boot.
3. [`deploy/microvm/firecracker-vm.json`](file:///c:/Users/tyson/.repo/personal/syntropy/deploy/microvm/firecracker-vm.json): MicroVM launch definition matching the observed vCPU, memory, drive, and boot args.
4. [`deploy/microvm/setup-display-mux.sh`](file:///c:/Users/tyson/.repo/personal/syntropy/deploy/microvm/setup-display-mux.sh): Multi-display and token generator script.
5. [`deploy/microvm/kasmvnc-alternative.sh`](file:///c:/Users/tyson/.repo/personal/syntropy/deploy/microvm/kasmvnc-alternative.sh): High-performance KasmVNC WebRTC service script.
6. [`deploy/microvm/gcp-host-setup.sh`](file:///c:/Users/tyson/.repo/personal/syntropy/deploy/microvm/gcp-host-setup.sh): Single-command host VM provisioner with nested virtualization on GCP.
