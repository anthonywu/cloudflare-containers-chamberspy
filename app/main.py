import os
import platform
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import psutil
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel

app = FastAPI(
    title="ChamberSpy",
    description="Container inspection utility for Cloudflare Cloud Chamber deployments",
    version="0.1.0",
)


def get_available_commands() -> dict[str, str]:
    """Helper function to check which commands are available in the system."""
    commands = [
        "python",
        "python3",
        "uv",
        "curl",
        "wget",
        "nc",
        "telnet",
        "dig",
        "nslookup",
        "host",
        "ps",
        "top",
        "htop",
        "strace",
        "ltrace",
        "gdb",
        "tcpdump",
        "ss",
        "netstat",
        "df",
        "du",
        "mount",
        "capsh",
        "getcap",
        "setcap",
        "ls",
        "cat",
        "grep",
        "find",
        "awk",
        "sed",
        "tar",
        "gzip",
        "unzip",
        "head",
        "tail",
        "less",
        "more",
        "vi",
        "nano",
        "git",
        "make",
        "gcc",
        "g++",
    ]

    available_commands: dict[str, str] = {}
    for cmd in commands:
        try:
            result = subprocess.run(
                ["which", cmd], capture_output=True, text=True, timeout=2
            )
            if result.returncode == 0 and result.stdout.strip():
                available_commands[cmd] = result.stdout.strip()
        except Exception:
            pass

    return available_commands


@app.get("/", response_class=HTMLResponse)
def index():
    """Landing page with available routes."""
    # Read HTML from file
    html_path = Path(__file__).parent / "pages" / "index.html"
    try:
        with open(html_path, "r") as f:
            return f.read()
    except FileNotFoundError:
        return "<h1>Error: index.html not found</h1>"


@app.get("/env")
def env_info(format: str = "json"):
    """Show all environment variables."""
    # Filter out sensitive keys
    env_vars = {k: v for k, v in os.environ.items() if k != "GPG_KEY"}

    if format == "text":
        lines = [f"{k}={v}" for k, v in sorted(env_vars.items())]
        return PlainTextResponse("\n".join(lines))

    return {"vars": env_vars, "count": len(env_vars)}


@app.get("/platform")
def platform_info(format: str = "json"):
    """Show OS and platform information."""
    info = {
        "system": platform.system(),
        "node": platform.node(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "architecture": list(platform.architecture()),
        "platform": platform.platform(),
        "python_build": list(platform.python_build()),
        "python_compiler": platform.python_compiler(),
        "python_branch": platform.python_branch(),
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "python_version_tuple": list(platform.python_version_tuple()),
    }

    if format == "text":
        lines = [f"{k}: {v}" for k, v in info.items()]
        return PlainTextResponse("\n".join(lines))

    return info


@app.get("/python")
def python_info(format: str = "json"):
    """Show Python interpreter details."""
    info = {
        "executable": sys.executable,
        "version": sys.version,
        "version_info": {
            "major": sys.version_info.major,
            "minor": sys.version_info.minor,
            "micro": sys.version_info.micro,
            "releaselevel": sys.version_info.releaselevel,
            "serial": sys.version_info.serial,
        },
        "prefix": sys.prefix,
        "base_prefix": sys.base_prefix,
        "path": sys.path,
        "modules_count": len(sys.modules),
        "builtin_module_names": sorted(sys.builtin_module_names),
        "flags": {
            attr: str(getattr(sys.flags, attr))
            for attr in dir(sys.flags)
            if not (attr.startswith("_") or attr in ("count", "index"))
        },
    }

    if format == "text":
        lines = [
            f"Python Executable: {info['executable']}",
            f"Version: {info['version']}",
            f"Prefix: {info['prefix']}",
            f"Base Prefix: {info['base_prefix']}",
            f"Loaded Modules: {info['modules_count']}",
            "",
            "Python Path:",
        ]
        lines.extend(f"  {p}" for p in info["path"])
        return PlainTextResponse("\n".join(lines))

    return info


@app.get("/pipfreeze", response_class=PlainTextResponse)
def pipfreeze_info() -> str:
    """Show installed packages (pip freeze output) - always returns plain text."""
    try:
        result = subprocess.run(
            ["uv", "pip", "freeze"],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Error running pip freeze: {e}\nStderr: {e.stderr}"


@app.get("/network")
def network_info(format: str = "json"):
    """Show network interfaces and hostname information."""
    interfaces = {}
    for name, addrs in psutil.net_if_addrs().items():
        interface_addrs = []
        for addr in addrs:
            addr_info = {
                "family": str(addr.family.name)
                if hasattr(addr.family, "name")
                else str(addr.family),
                "address": addr.address,
                "netmask": addr.netmask,
                "broadcast": addr.broadcast,
            }
            interface_addrs.append(addr_info)
        interfaces[name] = interface_addrs

    info = {
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "interfaces": interfaces,
    }

    try:
        info["primary_ip"] = socket.gethostbyname(socket.gethostname())
    except Exception:
        info["primary_ip"] = None

    if format == "text":
        lines = [
            f"Hostname: {info['hostname']}",
            f"FQDN: {info['fqdn']}",
            f"Primary IP: {info['primary_ip']}",
            "",
            "Network Interfaces:",
        ]
        for iface, addrs in interfaces.items():
            lines.append(f"\n{iface}:")
            for addr in addrs:
                lines.append(f"  {addr['family']}: {addr['address']}")
        return PlainTextResponse("\n".join(lines))

    return info


@app.get("/disk")
def disk_info(format: str = "json"):
    """Show disk usage information."""
    partitions = []
    for partition in psutil.disk_partitions():
        try:
            usage = psutil.disk_usage(partition.mountpoint)
            partitions.append(
                {
                    "device": partition.device,
                    "mountpoint": partition.mountpoint,
                    "fstype": partition.fstype,
                    "opts": partition.opts,
                    "total": usage.total,
                    "used": usage.used,
                    "free": usage.free,
                    "percent": usage.percent,
                    "total_human": f"{usage.total / (1024**3):.2f} GB",
                    "used_human": f"{usage.used / (1024**3):.2f} GB",
                    "free_human": f"{usage.free / (1024**3):.2f} GB",
                }
            )
        except PermissionError:
            continue

    info = {
        "partitions": partitions,
        "working_directory": os.getcwd(),
    }

    if format == "text":
        lines = [f"Working Directory: {info['working_directory']}"]
        lines.append("\nDisk Partitions:")

        for p in partitions:
            lines.extend(
                [
                    f"\n{p['device']} ({p['fstype']}) at {p['mountpoint']}",
                    f"  Total: {p['total_human']}",
                    f"  Used: {p['used_human']} ({p['percent']:.1f}%)",
                    f"  Free: {p['free_human']}",
                ]
            )
        return PlainTextResponse("\n".join(lines))

    return info


@app.get("/process")
def process_info(format: str = "json"):
    """Show current process information."""
    proc = psutil.Process()

    try:
        exe_path = proc.exe()
    except (PermissionError, AttributeError):
        exe_path = None

    try:
        username = proc.username()
    except (PermissionError, AttributeError):
        username = None

    info = {
        "pid": proc.pid,
        "name": proc.name(),
        "exe": exe_path,
        "cwd": proc.cwd(),
        "cmdline": proc.cmdline(),
        "create_time": datetime.fromtimestamp(
            proc.create_time(), tz=timezone.utc
        ).isoformat(),
        "cpu_percent": proc.cpu_percent(interval=0.1),
        "memory_info": {
            "rss": proc.memory_info().rss,
            "vms": proc.memory_info().vms,
            "rss_human": f"{proc.memory_info().rss / (1024**2):.2f} MB",
            "vms_human": f"{proc.memory_info().vms / (1024**2):.2f} MB",
        },
        "num_threads": proc.num_threads(),
        "username": username,
    }

    if format == "text":
        lines = [
            f"PID: {info['pid']}",
            f"Name: {info['name']}",
            f"Executable: {info['exe']}",
            f"Working Directory: {info['cwd']}",
            f"Command Line: {' '.join(info['cmdline'])}",
            f"Created: {info['create_time']}",
            f"CPU: {info['cpu_percent']:.1f}%",
            f"Memory RSS: {info['memory_info']['rss_human']}",
            f"Memory VMS: {info['memory_info']['vms_human']}",
            f"Threads: {info['num_threads']}",
            f"User: {info['username']}",
        ]
        return PlainTextResponse("\n".join(lines))

    return info


@app.get("/all")
def all_info():
    """Complete system dump - always returns JSON."""
    result = {
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
    }

    # Core system info
    try:
        result["environment"] = env_info(format="json")
    except Exception as e:
        result["environment"] = {"error": str(e)}

    try:
        result["platform"] = platform_info(format="json")
    except Exception as e:
        result["platform"] = {"error": str(e)}

    try:
        result["python"] = python_info(format="json")
    except Exception as e:
        result["python"] = {"error": str(e)}

    try:
        result["network"] = network_info(format="json")
    except Exception as e:
        result["network"] = {"error": str(e)}

    try:
        result["disk"] = disk_info(format="json")
    except Exception as e:
        result["disk"] = {"error": str(e)}

    try:
        result["process"] = process_info(format="json")
    except Exception as e:
        result["process"] = {"error": str(e)}

    # Security & permissions
    try:
        result["security"] = security_info(format="json")
    except Exception as e:
        result["security"] = {"error": str(e)}

    try:
        result["limits"] = limits_info(format="json")
    except Exception as e:
        result["limits"] = {"error": str(e)}

    # Container-specific
    try:
        result["cloudflare"] = cloudflare_info(format="json")
    except Exception as e:
        result["cloudflare"] = {"error": str(e)}

    try:
        result["mounts"] = mounts_info(format="json")
    except Exception as e:
        result["mounts"] = {"error": str(e)}

    # Connectivity & runtime
    try:
        result["dns"] = dns_info(format="json")
    except Exception as e:
        result["dns"] = {"error": str(e)}

    try:
        result["connectivity"] = connectivity_info(format="json")
    except Exception as e:
        result["connectivity"] = {"error": str(e)}

    try:
        result["runtime"] = runtime_info(format="json")
    except Exception as e:
        result["runtime"] = {"error": str(e)}

    return result


@app.get("/debug")
def debug_endpoints():
    """Test each endpoint individually to identify issues."""
    results = {}

    endpoints = [
        # Core system info
        ("env", env_info),
        ("platform", platform_info),
        ("python", python_info),
        ("network", network_info),
        ("disk", disk_info),
        ("process", process_info),
        # Security & permissions
        ("security", security_info),
        ("limits", limits_info),
        # Container-specific
        ("cloudflare", cloudflare_info),
        ("mounts", mounts_info),
        # Connectivity & runtime
        ("dns", dns_info),
        ("connectivity", connectivity_info),
        ("runtime", runtime_info),
    ]

    for name, func in endpoints:
        try:
            # Call with default JSON format
            result = func()
            results[name] = {"status": "ok", "sample": str(result)[:100] + "..."}
        except Exception as e:
            results[name] = {
                "status": "error",
                "error": str(e),
                "type": type(e).__name__,
            }

    return results


@app.get("/security")
def security_info(format: str = "json"):
    """Show user, capabilities, and security context."""
    info = {
        "user": {
            "uid": os.getuid(),
            "gid": os.getgid(),
            "euid": os.geteuid(),
            "egid": os.getegid(),
            "groups": os.getgroups(),
        }
    }

    # Try to get username
    try:
        import pwd

        user_info = pwd.getpwuid(os.getuid())
        info["user"]["name"] = user_info.pw_name
        info["user"]["home"] = user_info.pw_dir
        info["user"]["shell"] = user_info.pw_shell
    except Exception:
        info["user"]["name"] = None

    # Check for capabilities (Linux)
    try:
        # Check if running as root
        info["is_root"] = os.getuid() == 0

        # Try to read capabilities
        cap_result = subprocess.run(
            ["capsh", "--print"], capture_output=True, text=True, timeout=5
        )
        if cap_result.returncode == 0:
            info["capabilities"] = cap_result.stdout
        else:
            info["capabilities"] = None
    except Exception:
        info["capabilities"] = None

    # Check SELinux status
    try:
        selinux_result = subprocess.run(
            ["getenforce"], capture_output=True, text=True, timeout=5
        )
        info["selinux"] = (
            selinux_result.stdout.strip() if selinux_result.returncode == 0 else None
        )
    except Exception:
        info["selinux"] = None

    # Check AppArmor status
    try:
        if Path("/sys/kernel/security/apparmor/profiles").exists():
            info["apparmor"] = "enabled"
        else:
            info["apparmor"] = "disabled"
    except Exception:
        info["apparmor"] = "unknown"

    # Check for container indicators
    container_indicators = {
        "docker": Path("/.dockerenv").exists(),
        "cloudflare": os.environ.get("CLOUDFLARE_APPLICATION_ID") is not None,
        "cgroup_container": False,
    }

    # Check cgroups for container evidence
    try:
        with open("/proc/self/cgroup", "r") as f:
            cgroup_content = f.read()
            container_indicators["cgroup_container"] = "docker" in cgroup_content
    except Exception:
        pass

    info["container_indicators"] = container_indicators

    if format == "text":
        lines = [
            f"User ID: {info['user']['uid']}",
            f"Group ID: {info['user']['gid']}",
            f"Effective UID: {info['user']['euid']}",
            f"Effective GID: {info['user']['egid']}",
            f"Username: {info['user'].get('name', 'Unknown')}",
            f"Groups: {info['user']['groups']}",
            f"Is Root: {info['is_root']}",
            "",
            "Container Indicators:",
        ]
        for key, value in container_indicators.items():
            lines.append(f"  {key}: {value}")

        if info["capabilities"]:
            lines.extend(["", "Capabilities:", info["capabilities"]])

        return PlainTextResponse("\n".join(lines))

    return info


@app.get("/limits")
def limits_info(format: str = "json"):
    """Show resource limits and cgroups information."""
    info = {}

    # Get resource limits
    try:
        import resource

        limits = {}
        limit_names = [
            ("cpu_time", resource.RLIMIT_CPU),
            ("file_size", resource.RLIMIT_FSIZE),
            ("data_size", resource.RLIMIT_DATA),
            ("stack_size", resource.RLIMIT_STACK),
            ("core_size", resource.RLIMIT_CORE),
            ("rss", resource.RLIMIT_RSS),
            ("processes", resource.RLIMIT_NPROC),
            ("open_files", resource.RLIMIT_NOFILE),
            ("memory_lock", resource.RLIMIT_MEMLOCK),
            ("address_space", resource.RLIMIT_AS),
        ]

        for name, res_id in limit_names:
            soft, hard = resource.getrlimit(res_id)
            limits[name] = {
                "soft": soft if soft != resource.RLIM_INFINITY else "unlimited",
                "hard": hard if hard != resource.RLIM_INFINITY else "unlimited",
            }

        info["resource_limits"] = limits
    except Exception as e:
        info["resource_limits"] = {"error": str(e)}

    # Read cgroup information
    cgroup_info = {}

    # Memory cgroup
    try:
        memory_files = {
            "limit_in_bytes": "/sys/fs/cgroup/memory/memory.limit_in_bytes",
            "usage_in_bytes": "/sys/fs/cgroup/memory/memory.usage_in_bytes",
            "max_usage_in_bytes": "/sys/fs/cgroup/memory/memory.max_usage_in_bytes",
        }
        memory_stats = {}
        for key, path in memory_files.items():
            if Path(path).exists():
                with open(path, "r") as f:
                    value = int(f.read().strip())
                    memory_stats[key] = value
                    memory_stats[f"{key}_human"] = (
                        f"{value / (1024**3):.2f} GB"
                        if value < (1 << 62)
                        else "unlimited"
                    )

        cgroup_info["memory"] = memory_stats
    except Exception:
        cgroup_info["memory"] = None

    # CPU cgroup
    try:
        cpu_files = {
            "shares": "/sys/fs/cgroup/cpu/cpu.shares",
            "cfs_quota_us": "/sys/fs/cgroup/cpu/cpu.cfs_quota_us",
            "cfs_period_us": "/sys/fs/cgroup/cpu/cpu.cfs_period_us",
        }
        cpu_stats = {}
        for key, path in cpu_files.items():
            if Path(path).exists():
                with open(path, "r") as f:
                    cpu_stats[key] = int(f.read().strip())

        if "cfs_quota_us" in cpu_stats and "cfs_period_us" in cpu_stats:
            if cpu_stats["cfs_quota_us"] > 0:
                cpu_stats["cpu_limit"] = (
                    cpu_stats["cfs_quota_us"] / cpu_stats["cfs_period_us"]
                )
            else:
                cpu_stats["cpu_limit"] = "unlimited"

        cgroup_info["cpu"] = cpu_stats
    except Exception:
        cgroup_info["cpu"] = None

    info["cgroups"] = cgroup_info

    # System memory info
    try:
        vm = psutil.virtual_memory()
        info["system_memory"] = {
            "total": vm.total,
            "available": vm.available,
            "percent": vm.percent,
            "used": vm.used,
            "free": vm.free,
            "total_human": f"{vm.total / (1024**3):.2f} GB",
            "available_human": f"{vm.available / (1024**3):.2f} GB",
        }
    except Exception:
        info["system_memory"] = None

    if format == "text":
        lines = ["Resource Limits:"]
        if "resource_limits" in info and isinstance(info["resource_limits"], dict):
            for name, limits in info["resource_limits"].items():
                if isinstance(limits, dict) and "soft" in limits:
                    lines.append(
                        f"  {name}: soft={limits['soft']}, hard={limits['hard']}"
                    )

        if info.get("system_memory"):
            lines.extend(
                [
                    "",
                    "System Memory:",
                    f"  Total: {info['system_memory']['total_human']}",
                    f"  Available: {info['system_memory']['available_human']}",
                    f"  Used: {info['system_memory']['percent']:.1f}%",
                ]
            )

        if cgroup_info.get("memory"):
            lines.extend(["", "Memory Cgroup:"])
            for key, value in cgroup_info["memory"].items():
                if "_human" in key:
                    lines.append(f"  {key}: {value}")

        if cgroup_info.get("cpu") and "cpu_limit" in cgroup_info["cpu"]:
            lines.extend(["", f"CPU Limit: {cgroup_info['cpu']['cpu_limit']}"])

        return PlainTextResponse("\n".join(lines))

    return info


@app.get("/cloudflare")
def cloudflare_info(format: str = "json"):
    """Show Cloudflare-specific environment information."""
    # Extract Cloudflare-specific environment variables
    cf_env = {k: v for k, v in os.environ.items() if k.startswith("CLOUDFLARE_")}

    info = {
        "cloudflare_env": cf_env,
        "is_cloudflare_container": "CLOUDFLARE_DEPLOYMENT_ID" in cf_env,
        "is_wrangler_dev": "xxx" in os.environ.get("CLOUDFLARE_APPLICATION_ID", ""),
        "application_id": os.environ.get("CLOUDFLARE_APPLICATION_ID"),
        "durable_object_id": os.environ.get("CLOUDFLARE_DURABLE_OBJECT_ID"),
    }

    # Check kernel version for Firecracker
    try:
        kernel_info = platform.release()
        info["is_firecracker"] = "firecracker" in kernel_info.lower()
        info["kernel"] = kernel_info
    except Exception:
        info["is_firecracker"] = None
        info["kernel"] = None

    if format == "text":
        lines = [f"Is Cloudflare Container: {info['is_cloudflare_container']}"]
        if info["is_firecracker"]:
            lines.append(f"Running on Firecracker (kernel: {info['kernel']})")

        if cf_env:
            lines.extend(["", "Cloudflare Environment Variables:"])
            for k, v in sorted(cf_env.items()):
                lines.append(f"  {k}={v}")

        return PlainTextResponse("\n".join(lines))

    return info


@app.get("/mounts")
def mounts_info(format: str = "json"):
    """Show mounted filesystems and volumes."""
    mounts = []

    # Read /proc/mounts
    try:
        with open("/proc/mounts", "r") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 4:
                    mounts.append(
                        {
                            "device": parts[0],
                            "mountpoint": parts[1],
                            "fstype": parts[2],
                            "options": parts[3].split(","),
                        }
                    )
    except Exception:
        return {"mounts": None, "mount_count": 0}

    # Get disk usage for each mount
    for mount in mounts:
        try:
            usage = psutil.disk_usage(mount["mountpoint"])
            mount["usage"] = {
                "total": usage.total,
                "used": usage.used,
                "free": usage.free,
                "percent": usage.percent,
                "total_human": f"{usage.total / (1024**3):.2f} GB",
                "used_human": f"{usage.used / (1024**3):.2f} GB",
            }
        except Exception:
            mount["usage"] = None

    info = {
        "mounts": mounts,
        "mount_count": len(mounts),
    }

    if format == "text":
        lines = [f"Total Mounts: {len(mounts)}", ""]
        for mount in mounts:
            lines.append(
                f"{mount['device']} -> {mount['mountpoint']} ({mount['fstype']})"
            )
            if mount.get("usage"):
                lines.append(
                    f"  Size: {mount['usage']['total_human']}, Used: {mount['usage']['percent']:.1f}%"
                )
            lines.append(f"  Options: {','.join(mount['options'])}")
            lines.append("")

        return PlainTextResponse("\n".join(lines))

    return info


@app.get("/dns")
def dns_info(format: str = "json"):
    """Show DNS configuration and resolution tests."""
    info = {}

    # Read resolv.conf
    try:
        with open("/etc/resolv.conf", "r") as f:
            resolv_conf = f.read()
            info["resolv_conf"] = resolv_conf

            # Parse nameservers
            nameservers = []
            for line in resolv_conf.splitlines():
                if line.strip().startswith("nameserver"):
                    parts = line.strip().split()
                    if len(parts) > 1:
                        nameservers.append(parts[1])
            info["nameservers"] = nameservers
    except Exception as e:
        info["resolv_conf"] = f"Error reading: {str(e)}"
        info["nameservers"] = []

    # Test DNS resolution
    test_domains = [
        "cloudflare.com",
        "google.com",
        "localhost",
    ]

    resolutions = {}
    for domain in test_domains:
        try:
            ip = socket.gethostbyname(domain)
            resolutions[domain] = {"ip": ip, "success": True}
        except Exception as e:
            resolutions[domain] = {"error": str(e), "success": False}

    info["resolutions"] = resolutions

    # Get all hostnames
    try:
        info["hostname"] = socket.gethostname()
        info["fqdn"] = socket.getfqdn()
    except Exception:
        pass

    if format == "text":
        lines = [
            f"Hostname: {info.get('hostname', 'Unknown')}",
            f"FQDN: {info.get('fqdn', 'Unknown')}",
            "",
            "Nameservers:",
        ]
        for ns in info.get("nameservers", []):
            lines.append(f"  {ns}")

        lines.extend(["", "DNS Resolution Tests:"])
        for domain, result in resolutions.items():
            if result["success"]:
                lines.append(f"  {domain} -> {result['ip']}")
            else:
                lines.append(f"  {domain} -> FAILED ({result['error']})")

        return PlainTextResponse("\n".join(lines))

    return info


@app.get("/connectivity")
def connectivity_info(format: str = "json"):
    """Test external connectivity."""
    info = {}

    # Test HTTP connectivity
    test_urls = [
        ("cloudflare", "http://1.1.1.1"),
        ("cloudflare_api", "https://api.cloudflare.com"),
        ("google", "https://www.google.com"),
    ]

    connectivity_results = {}
    import httpx

    with httpx.Client(timeout=5.0) as client:
        for name, url in test_urls:
            try:
                response = client.get(url)
                connectivity_results[name] = {
                    "url": url,
                    "status": response.status_code,
                    "reachable": True,
                }
            except Exception as e:
                connectivity_results[name] = {
                    "url": url,
                    "error": str(e),
                    "reachable": False,
                }

    info["http_tests"] = connectivity_results

    # Check network interfaces
    interfaces = psutil.net_if_addrs()
    info["interface_count"] = len(interfaces)
    info["interfaces"] = list(interfaces.keys())

    # Check for default route
    try:
        route_result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if route_result.returncode == 0:
            info["default_route"] = route_result.stdout.strip()
        else:
            info["default_route"] = None
    except Exception:
        info["default_route"] = None

    if format == "text":
        lines = [f"Network Interfaces: {', '.join(info['interfaces'])}"]

        if info.get("default_route"):
            lines.extend(["", f"Default Route: {info['default_route']}"])

        lines.extend(["", "Connectivity Tests:"])
        for name, result in connectivity_results.items():
            if result["reachable"]:
                lines.append(f"  {name}: OK (status {result['status']})")
            else:
                lines.append(
                    f"  {name}: FAILED ({result.get('error', 'Unknown error')})"
                )

        return PlainTextResponse("\n".join(lines))

    return info


@app.get("/runtime")
def runtime_info(format: str = "json"):
    """Show runtime capabilities and features."""
    info = {}

    # CPU info
    try:
        with open("/proc/cpuinfo", "r") as f:
            cpuinfo = f.read()
            # Count processors
            info["cpu_count"] = cpuinfo.count("processor\t:")

            # Get CPU model
            for line in cpuinfo.splitlines():
                if "model name" in line:
                    info["cpu_model"] = line.split(":", 1)[1].strip()
                    break
    except Exception:
        info["cpu_count"] = psutil.cpu_count()

    # Memory info
    vm = psutil.virtual_memory()
    info["memory"] = {
        "total": vm.total,
        "available": vm.available,
        "total_human": f"{vm.total / (1024**3):.2f} GB",
    }

    # Check available commands: name -> path
    info["available_commands"]: dict[str, str] = get_available_commands()

    # Check for special files
    special_files = {
        "/proc/self/environ": Path("/proc/self/environ").exists(),
        "/proc/self/cmdline": Path("/proc/self/cmdline").exists(),
        "/sys/fs/cgroup": Path("/sys/fs/cgroup").exists(),
        "/etc/os-release": Path("/etc/os-release").exists(),
        "/.dockerenv": Path("/.dockerenv").exists(),
    }
    info["special_files"] = special_files

    # Get OS info
    try:
        with open("/etc/os-release", "r") as f:
            os_info = {}
            for line in f:
                if "=" in line:
                    key, value = line.strip().split("=", 1)
                    os_info[key] = value.strip('"')
            info["os_release"] = os_info
    except Exception:
        info["os_release"] = None

    if format == "text":
        lines = []
        lines.extend(
            [
                f"CPU: {info.get('cpu_model', 'Unknown')}",
                f"CPU Count: {info.get('cpu_count', 'Unknown')}",
                f"Memory: {info['memory']['total_human']}",
                "",
                "Available Commands:",
            ]
        )
        available = [cmd for cmd, path in info.get("available_commands", {}).items()]

        if available:
            lines.append(f"  {', '.join(sorted(available))}")

        if info.get("os_release"):
            lines.extend(
                [
                    "",
                    "Linux OS Info:",
                    f"  Name: {info['os_release'].get('NAME', 'Unknown')}",
                    f"  Version: {info['os_release'].get('VERSION', 'Unknown')}",
                ]
            )

        return PlainTextResponse("\n".join(lines))

    return info


class ExecRequest(BaseModel):
    cmd: str


@app.get("/commands")
def available_commands():
    """Get list of available commands."""
    commands = get_available_commands()
    return {
        "commands": list(commands.keys()),
        "count": len(commands),
    }


@app.post("/exec")
def exec_command(request: ExecRequest):
    """Execute a shell command (use with caution)."""
    if int(os.environ.get("ENABLE_EXEC_ROUTE", "0")) <= 0:
        return {
            "command": request.cmd,
            "returncode": None,
            "stdout": None,
            "stderr": "Disabled in this demo. Set env var ENABLE_EXEC_ROUTE=1 in your Container envVars to enable.",
            "success": False,
        }

    if not request.cmd:
        raise HTTPException(status_code=400, detail="Command cannot be empty")

    # Safety check - limit command length
    if len(request.cmd) > 1000:
        raise HTTPException(status_code=400, detail="Command too long")

    try:
        result = subprocess.run(
            request.cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30,  # 30 second timeout
        )

        return {
            "command": request.cmd,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "success": result.returncode == 0,
        }
    except subprocess.TimeoutExpired:
        raise HTTPException(
            status_code=408, detail="Command timed out after 30 seconds"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Command execution failed: {str(e)}"
        )
