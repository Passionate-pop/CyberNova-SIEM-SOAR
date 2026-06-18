"""
CyberNova — Linux auditd Log Parser
Parses traditional type= format AND audispd JSON output.
Maps SYSCALL, EXECVE, LOGIN, USER_*, CONFIG_CHANGE events.
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict

log = logging.getLogger("cybernova.ingestion.parsers.auditd")

AUDIT_TYPE_MAP = {
    "SYSCALL": "auditd_syscall",
    "EXECVE": "auditd_execve",
    "PATH": "auditd_path",
    "CWD": "auditd_cwd",
    "PROCTITLE": "auditd_proctitle",
    "USER_AUTH": "auditd_user_auth",
    "USER_ACCT": "auditd_user_account",
    "USER_LOGIN": "auditd_user_login",
    "USER_CMD": "auditd_user_cmd",
    "USER_START": "auditd_user_start",
    "USER_END": "auditd_user_end",
    "USER_ERR": "auditd_user_err",
    "CRED_ACQ": "auditd_cred_acq",
    "CRED_DISP": "auditd_cred_disp",
    "CRED_REFR": "auditd_cred_refr",
    "LOGIN": "auditd_login",
    "ADD_GROUP": "auditd_add_group",
    "DEL_GROUP": "auditd_del_group",
    "CHGRP_ID": "auditd_chgrp_id",
    "ADD_USER": "auditd_add_user",
    "DEL_USER": "auditd_del_user",
    "CHUSER_ID": "auditd_chuser_id",
    "ANOM_ABEND": "auditd_anomaly_abend",
    "ANOM_PROMISCUOUS": "auditd_anomaly_promiscuous",
    "ANOM_LINK": "auditd_anomaly_link",
    "ANOM_EXEC": "auditd_anomaly_exec",
    "ANOM_LOGIN_FAILURES": "auditd_anomaly_login",
    "ANOM_LOGIN_TIME": "auditd_anomaly_logintime",
    "ANOM_ACCESS": "auditd_anomaly_access",
    "DAEMON_START": "auditd_daemon_start",
    "DAEMON_STOP": "auditd_daemon_stop",
    "DAEMON_CONFIG": "auditd_daemon_config",
    "DAEMON_END": "auditd_daemon_end",
    "SERVICE_START": "auditd_service_start",
    "SERVICE_STOP": "auditd_service_stop",
    "CONFIG_CHANGE": "auditd_config_change",
    "MAC_POLICY": "auditd_mac_policy",
    "MAC_STATUS": "auditd_mac_status",
    "MAC_CONFIG": "auditd_mac_config",
    "MAC_UNLBL_ALLOW": "auditd_mac_unlabel",
    "MAC_MAP_INSERT": "auditd_mac_map",
    "NETFILTER_CFG": "auditd_netfilter",
    "VIRT_CONTROL": "auditd_virt_control",
    "VIRT_RESOURCE": "auditd_virt_resource",
    "TTY": "auditd_tty",
}

SENSITIVE_SYSCALLS = {
    "execve", "execveat", "fork", "clone", "clone3",
    "ptrace", "process_vm_readv", "process_vm_writev",
    "init_module", "finit_module", "delete_module",
    "kexec_load", "kexec_file_load",
    "setuid", "setgid", "setreuid", "setregid",
    "chmod", "chown", "setxattr", "removexattr",
    "mount", "umount", "umount2",
    "reboot", "shutdown", "sysctl",
    "swapon", "swapoff",
}

HIGH_SYSCALLS = {"ptrace", "kexec_load", "init_module", "reboot"}

PRIVILEGED_COMMANDS = {
    "sudo", "su", "pkexec", "doas", "docker", "kubectl",
    "passwd", "usermod", "groupmod",
}

SENSITIVE_PATHS = re.compile(
    r'(/etc/(shadow|passwd|sudoers|ssh|pam\.d|crontab)|'
    r'/var/log/(audit|secure|auth)|'
    r'/root/|/home/)',
    re.IGNORECASE,
)

SYSCALL_NUMBERS = {
    0: "read", 1: "write", 2: "open", 3: "close", 4: "stat",
    5: "fstat", 6: "lstat", 7: "poll", 8: "lseek", 9: "mmap",
    10: "mprotect", 11: "munmap", 12: "brk", 13: "rt_sigaction",
    14: "rt_sigprocmask", 15: "rt_sigreturn", 16: "ioctl",
    17: "pread64", 18: "pwrite64", 19: "readv", 20: "writev",
    21: "access", 22: "pipe", 23: "select", 24: "sched_yield",
    25: "mremap", 26: "msync", 27: "mincore", 28: "madvise",
    29: "shmget", 30: "shmat", 31: "shmctl", 32: "dup",
    33: "dup2", 34: "pause", 35: "nanosleep", 36: "getitimer",
    37: "alarm", 38: "setitimer", 39: "getpid", 40: "sendfile",
    41: "socket", 42: "connect", 43: "accept", 44: "sendto",
    45: "recvfrom", 46: "sendmsg", 47: "recvmsg", 48: "shutdown",
    49: "bind", 50: "listen", 51: "getsockname", 52: "getpeername",
    53: "socketpair", 54: "setsockopt", 55: "getsockopt",
    56: "clone", 57: "fork", 58: "vfork", 59: "execve",
    60: "exit", 61: "wait4", 62: "kill", 63: "uname",
    64: "semget", 65: "semop", 66: "semctl", 67: "shmdt",
    68: "msgget", 69: "msgsnd", 70: "msgrcv", 71: "msgctl",
    72: "fcntl", 73: "flock", 74: "fsync", 75: "fdatasync",
    76: "truncate", 77: "ftruncate", 78: "getdents",
    79: "getcwd", 80: "chdir", 81: "fchdir", 82: "rename",
    83: "mkdir", 84: "rmdir", 85: "creat", 86: "link",
    87: "unlink", 88: "symlink", 89: "readlink", 90: "chmod",
    91: "fchmod", 92: "chown", 93: "fchown", 94: "lchown",
    95: "umask", 96: "gettimeofday", 97: "getrlimit",
    98: "getrusage", 99: "sysinfo", 100: "times",
    101: "ptrace", 102: "getuid", 103: "syslog", 104: "getgid",
    105: "setuid", 106: "setgid", 107: "geteuid", 108: "getegid",
    109: "setpgid", 110: "getppid", 111: "getpgrp",
    112: "setsid", 113: "setreuid", 114: "setregid",
    115: "getgroups", 116: "setgroups", 117: "setresuid",
    118: "getresuid", 119: "setresgid", 120: "getresgid",
    121: "getpgid", 122: "setfsuid", 123: "setfsgid",
    124: "getsid", 125: "capget", 126: "capset",
    127: "rt_sigpending", 128: "rt_sigtimedwait",
    129: "rt_sigqueueinfo", 130: "rt_sigsuspend",
    131: "sigaltstack", 132: "utime", 133: "mknod",
    134: "uselib", 135: "personality", 136: "ustat",
    137: "statfs", 138: "fstatfs", 139: "sysfs",
    140: "getpriority", 141: "setpriority", 142: "sched_setparam",
    143: "sched_getparam", 144: "sched_setscheduler",
    145: "sched_getscheduler", 146: "sched_get_priority_max",
    147: "sched_get_priority_min", 148: "sched_rr_get_interval",
    149: "mlock", 150: "munlock", 151: "mlockall",
    152: "munlockall", 153: "vhangup", 154: "modify_ldt",
    155: "pivot_root", 156: "_sysctl", 157: "prctl",
    158: "arch_prctl", 159: "adjtimex", 160: "setrlimit",
    161: "chroot", 162: "sync", 163: "acct", 164: "settimeofday",
    165: "mount", 166: "umount2", 167: "swapon", 168: "swapoff",
    169: "reboot", 170: "sethostname", 171: "setdomainname",
    172: "iopl", 173: "ioperm", 174: "create_module",
    175: "init_module", 176: "delete_module", 177: "get_kernel_syms",
    178: "query_module", 179: "quotactl", 180: "nfsservctl",
    181: "getpmsg", 182: "putpmsg", 183: "afs_syscall",
    184: "tuxcall", 185: "security", 186: "gettid",
    187: "readahead", 188: "setxattr", 189: "lsetxattr",
    190: "fsetxattr", 191: "getxattr", 192: "lgetxattr",
    193: "fgetxattr", 194: "listxattr", 195: "llistxattr",
    196: "flistxattr", 197: "removexattr", 198: "lremovexattr",
    199: "fremovexattr", 200: "tkill", 201: "time",
    202: "futex", 203: "sched_setaffinity",
    204: "sched_getaffinity", 205: "set_thread_area",
    206: "io_setup", 207: "io_destroy", 208: "io_getevents",
    209: "io_submit", 210: "io_cancel", 211: "get_thread_area",
    212: "lookup_dcookie", 213: "epoll_create",
    214: "epoll_ctl_old", 215: "epoll_wait_old",
    216: "remap_file_pages", 217: "getdents64",
    218: "set_tid_address", 219: "restart_syscall",
    220: "semtimedop", 221: "fadvise64", 222: "timer_create",
    223: "timer_settime", 224: "timer_gettime",
    225: "timer_getoverrun", 226: "timer_delete",
    227: "clock_settime", 228: "clock_gettime",
    229: "clock_getres", 230: "clock_nanosleep",
    231: "exit_group", 232: "epoll_wait", 233: "epoll_ctl",
    234: "tgkill", 235: "utimes", 236: "vserver",
    237: "mbind", 238: "set_mempolicy", 239: "get_mempolicy",
    240: "mq_open", 241: "mq_unlink", 242: "mq_timedsend",
    243: "mq_timedreceive", 244: "mq_notify",
    245: "mq_getsetattr", 246: "kexec_load",
    247: "waitid", 248: "add_key", 249: "request_key",
    250: "keyctl", 251: "ioprio_set", 252: "ioprio_get",
    253: "inotify_init", 254: "inotify_add_watch",
    255: "inotify_rm_watch", 256: "migrate_pages",
    257: "openat", 258: "mkdirat", 259: "mknodat",
    260: "fchownat", 261: "futimesat", 262: "newfstatat",
    263: "unlinkat", 264: "renameat", 265: "linkat",
    266: "symlinkat", 267: "readlinkat", 268: "fchmodat",
    269: "faccessat", 270: "pselect6", 271: "ppoll",
    272: "unshare", 273: "set_robust_list",
    274: "get_robust_list", 275: "splice", 276: "tee",
    277: "sync_file_range", 278: "vmsplice",
    279: "move_pages", 280: "utimensat", 281: "epoll_pwait",
    282: "signalfd", 283: "timerfd_create", 284: "eventfd",
    285: "fallocate", 286: "timerfd_settime",
    287: "timerfd_gettime", 288: "accept4", 289: "signalfd4",
    290: "eventfd2", 291: "epoll_create1", 292: "dup3",
    293: "pipe2", 294: "inotify_init1", 295: "preadv",
    296: "pwritev", 297: "rt_tgsigqueueinfo", 298: "perf_event_open",
    299: "recvmmsg", 300: "fanotify_init", 301: "fanotify_mark",
    302: "prlimit64", 303: "name_to_handle_at",
    304: "open_by_handle_at", 305: "clock_adjtime",
    306: "syncfs", 307: "sendmmsg", 308: "setns",
    309: "getcpu", 310: "process_vm_readv",
    311: "process_vm_writev", 312: "kcmp",
    313: "finit_module", 314: "sched_setattr",
    315: "sched_getattr", 316: "renameat2",
    317: "seccomp", 318: "getrandom", 319: "memfd_create",
    320: "kexec_file_load", 321: "bpf",
    322: "execveat", 323: "userfaultfd", 324: "membarrier",
    325: "mlock2", 326: "copy_file_range",
    327: "preadv2", 328: "pwritev2", 329: "pkey_mprotect",
    330: "pkey_alloc", 331: "pkey_free", 332: "statx",
    333: "io_pgetevents", 334: "rseq",
    424: "pidfd_send_signal",
    425: "io_uring_setup", 426: "io_uring_enter",
    427: "io_uring_register", 428: "open_tree",
    429: "move_mount", 430: "fsopen", 431: "fsconfig",
    432: "fsmount", 433: "fspick", 434: "pidfd_open",
    435: "clone3",
}

USER_AUTH_RESULT_MAP = {
    "success": "success",
    "PAM_SUCCESS": "success",
    "authentication failed": "failure",
    "PAM_AUTH_ERR": "failure",
    "PAM_ACCT_EXPIRED": "expired",
    "PAM_AUTHINFO_UNAVAIL": "unavailable",
    "PAM_MAXTRIES": "max_attempts",
    "PAM_PERM_DENIED": "denied",
    "PAM_USER_UNKNOWN": "unknown_user",
    "PAM_CRED_INSUFFICIENT": "insufficient_credentials",
}

USER_EVENT_NAMES = {
    "USER_AUTH": "User Authentication",
    "USER_ACCT": "User Account",
    "USER_LOGIN": "User Login Session",
    "USER_CMD": "User Command",
    "USER_START": "User Session Start",
    "USER_END": "User Session End",
    "USER_ERR": "User Session Error",
}


def _get_syscall_name(num_str: str) -> str:
    try:
        num = int(num_str, 10)
        return SYSCALL_NUMBERS.get(num, f"syscall_{num}")
    except (ValueError, TypeError):
        return num_str


def _parse_timestamp_epoch(ts_str: str) -> str:
    if not ts_str:
        return ""
    try:
        secs = float(ts_str)
        return datetime.fromtimestamp(secs, tz=timezone.utc).isoformat()
    except (ValueError, TypeError) as exc:
        log.debug("Invalid auditd epoch timestamp: %s — %s", ts_str, exc)
        return ts_str


def _parse_event_id(ts_str: str) -> str:
    if not ts_str:
        return ""
    try:
        secs = float(ts_str)
        return datetime.fromtimestamp(secs, tz=timezone.utc).strftime("%Y%m%d%H%M%S%f")
    except (ValueError, TypeError):
        return ts_str.replace(".", "")


def _extract_user_info(body: Dict[str, str]) -> Dict[str, str]:
    uid = body.get("uid", body.get("auid", body.get("loginuid", "")))
    acct = body.get("acct", body.get("account", ""))
    user = body.get("user", "")
    op = body.get("op", "")
    grantors = body.get("grantors", "")
    return {
        "uid": uid, "auid": body.get("auid", ""),
        "acct": acct, "user": user, "op": op, "grantors": grantors,
        "ses": body.get("ses", ""), "terminal": body.get("terminal", body.get("term", "")),
        "hostname": body.get("hostname", body.get("addr", "")),
    }


def _extract_process_info(body: Dict[str, str]) -> Dict[str, str]:
    return {
        "pid": body.get("pid", body.get("PID", "")),
        "ppid": body.get("ppid", body.get("PPID", "")),
        "comm": body.get("comm", body.get("COMM", "")),
        "exe": body.get("exe", body.get("EXE", "")),
        "cmdline": body.get("cmdline", body.get("CMD", "")),
        "cwd": body.get("cwd", body.get("CWD", "")),
        "subj": body.get("subj", body.get("subj", body.get("SUBJ", ""))),
    }


def parse_audispd_json(raw: Dict[str, Any]) -> Dict[str, Any]:
    event_type_raw = raw.get("type", raw.get("Type", "UNKNOWN")).upper()
    mapped_type = AUDIT_TYPE_MAP.get(event_type_raw, f"auditd_{event_type_raw.lower()}")

    body = raw.get("body", raw.get("Body", raw.get("message", raw.get("Message", {}))))
    if isinstance(body, str):
        body = _parse_audit_kv(body)

    timestamp_raw = raw.get("timestamp", raw.get("Timestamp", raw.get("time", raw.get("Time", ""))))
    if isinstance(timestamp_raw, (int, float)):
        timestamp = datetime.fromtimestamp(float(timestamp_raw), tz=timezone.utc).isoformat()
    else:
        timestamp = _parse_timestamp_epoch(timestamp_raw)
    event_id = raw.get("serial", raw.get("Serial", raw.get("event_id", _parse_event_id(str(timestamp_raw)))))

    proc = _extract_process_info(body)
    user_info = _extract_user_info(body)

    result: Dict[str, Any] = {
        "event_type": mapped_type,
        "severity": "info",
        "user": user_info["user"] or user_info["acct"] or user_info["uid"],
        "source_ip": "",
        "timestamp": timestamp,
        "message": raw.get("message", raw.get("msg", str(raw))),
        "metadata": {
            "event_id": str(event_id),
            "audit_type": event_type_raw,
            **user_info,
            **proc,
        },
    }

    hostname = user_info["hostname"] or body.get("hostname", body.get("addr", ""))
    if hostname and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', hostname):
        result["source_ip"] = hostname
    elif hostname:
        result["metadata"]["hostname"] = hostname

    arch = body.get("arch", body.get("Arch", ""))
    syscall_raw = body.get("syscall", body.get("Syscall", body.get("SYSCALL", "")))
    syscall_name = _get_syscall_name(str(syscall_raw)) if syscall_raw else ""

    if event_type_raw in ("SYSCALL", "SYS"):
        result["metadata"]["arch"] = arch
        result["metadata"]["syscall_raw"] = syscall_raw or ""
        result["metadata"]["syscall_name"] = syscall_name
        result["metadata"]["success"] = body.get("success", body.get("Success", ""))
        result["metadata"]["exit"] = body.get("exit", body.get("Exit", ""))
        result["metadata"]["a0"] = body.get("a0", "")
        result["metadata"]["a1"] = body.get("a1", "")
        result["metadata"]["a2"] = body.get("a2", "")
        result["metadata"]["a3"] = body.get("a3", "")

        if syscall_name in SENSITIVE_SYSCALLS:
            result["severity"] = "medium"
            if syscall_name in HIGH_SYSCALLS:
                result["severity"] = "high"
            result["metadata"]["sensitive_syscall"] = syscall_name
            result["message"] = f"Sensitive syscall: {syscall_name} by pid={proc['pid']} comm={proc['comm']} exe={proc['exe']}"

        key = body.get("key", body.get("Key", body.get("audit_key", "")))
        if key:
            result["metadata"]["audit_key"] = key

    elif event_type_raw == "EXECVE":
        argc = body.get("argc", body.get("Argc", ""))
        argv = []
        for i in range(64):
            a = body.get(f"a{i}", body.get(f"arg{i}", ""))
            if a:
                argv.append(a)
            else:
                break
        result["metadata"]["argc"] = argc
        result["metadata"]["argv"] = argv
        result["metadata"]["exec_args"] = " ".join(argv) if argv else ""
        result["message"] = f"EXECVE: {proc.get('comm', '')} {' '.join(argv) if argv else ''}"

    elif event_type_raw == "LOGIN":
        result["metadata"]["login_uid"] = body.get("uid", "")
        result["metadata"]["old_ses"] = body.get("old-ses", body.get("old_ses", ""))
        result["metadata"]["ses"] = body.get("ses", "")
        result["metadata"]["login_id"] = body.get("login-id", body.get("login_id", ""))
        result["metadata"]["machine_id"] = body.get("machine-id", body.get("machine_id", ""))
        result["severity"] = "medium"
        result["message"] = f"LOGIN: uid={user_info['uid']} ses={body.get('ses', '')} terminal={user_info.get('terminal', '')}"

    elif event_type_raw.startswith("USER_"):
        result["metadata"]["acct"] = user_info["acct"]
        result["metadata"]["op"] = user_info["op"]
        result["metadata"]["grantors"] = user_info["grantors"]
        result["metadata"]["terminal"] = user_info["terminal"]
        result["metadata"]["hostname"] = user_info["hostname"] or result["metadata"].get("hostname", "")
        res_val = body.get("res", body.get("result", body.get("Result", "")))
        result["metadata"]["auth_result"] = USER_AUTH_RESULT_MAP.get(res_val, res_val)

        if res_val in ("success", "PAM_SUCCESS"):
            result["severity"] = "info"
        else:
            result["severity"] = "medium"
            if res_val in ("PAM_AUTH_ERR", "authentication failed"):
                result["severity"] = "high"

        event_name = USER_EVENT_NAMES.get(event_type_raw, event_type_raw)
        result["message"] = (
            f"{event_name}: {user_info['acct'] or user_info['user'] or user_info['uid']} "
            f"op={user_info['op']} result={res_val} terminal={user_info['terminal']}"
        )

    elif event_type_raw in ("CONFIG_CHANGE", "CONFIG"):
        result["metadata"]["op"] = body.get("op", "")
        result["metadata"]["auid"] = body.get("auid", "")
        result["metadata"]["subj"] = proc.get("subj", "")
        result["metadata"]["selinux_role"] = body.get("se_role", body.get("selinux_role", ""))
        result["severity"] = "medium"
        result["message"] = f"Audit config change: {body.get('op', '')} by auid={body.get('auid', '')}"

    key = body.get("key", body.get("Key", ""))
    if key:
        result["metadata"]["audit_key"] = key

    path_data = body.get("name", body.get("Name", proc.get("exe", "")))
    if path_data and SENSITIVE_PATHS.search(path_data):
        result["severity"] = "high"
        result["metadata"]["sensitive_path"] = path_data

    if event_type_raw.startswith("ANOM_"):
        result["severity"] = "high"

    return result


def _parse_audit_kv(msg: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    pairs = re.findall(r'(\w+)=("[^"]*"|\S+)', msg)
    for key, value in pairs:
        result[key] = value.strip('"')
    return result


def _merge_related(lines: list[str]) -> str:
    msg_parts = {}
    for line in lines:
        m = re.match(r'type=(\w+).*msg=audit\(([\d.]+):\d+\):', line)
        if not m:
            continue
        audit_type = m.group(1)
        timestamp = m.group(2)
        kv_part = line.split("):", 1)[-1].strip()
        key = (audit_type, timestamp)
        if key in msg_parts:
            msg_parts[key] += " " + kv_part
        else:
            msg_parts[key] = kv_part
    merged = []
    for (atype, ts), kv_str in msg_parts.items():
        merged.append(f"type={atype} msg=audit({ts}:0): {kv_str}")
    return "\n".join(merged) if merged else "\n".join(lines)


def _parse_traditional_kv(msg: str) -> Dict[str, Any]:
    m = re.match(r'type=(\w+)', msg)
    audit_type_raw = m.group(1) if m else "UNKNOWN"
    mapped_type = AUDIT_TYPE_MAP.get(audit_type_raw, f"auditd_{audit_type_raw.lower()}")

    kv_data = _parse_audit_kv(msg)

    ts_raw = kv_data.get("time", "")
    if not ts_raw:
        ts_m = re.search(r'msg=audit\(([\d.]+):', msg)
        if ts_m:
            ts_raw = ts_m.group(1)
    timestamp = _parse_timestamp_epoch(ts_raw)

    uid = kv_data.get("uid", kv_data.get("auid", kv_data.get("loginuid", "")))
    exe = kv_data.get("exe", "")
    comm = kv_data.get("comm", "")
    pid = kv_data.get("pid", "")
    syscall = kv_data.get("syscall", kv_data.get("SYSCALL", ""))
    syscall_name = _get_syscall_name(syscall) if syscall else ""

    result: Dict[str, Any] = {
        "event_type": mapped_type,
        "severity": "info",
        "user": uid,
        "source_ip": "",
        "timestamp": timestamp,
        "message": msg,
        "metadata": {
            "audit_type": audit_type_raw,
            "uid": uid, "auid": kv_data.get("auid", ""),
            "ses": kv_data.get("ses", ""),
            "subj": kv_data.get("subj", ""),
            "comm": comm, "exe": exe, "pid": pid,
        },
    }

    hostname = kv_data.get("hostname", kv_data.get("addr", ""))
    if hostname and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', hostname):
        result["source_ip"] = hostname
    elif hostname:
        result["metadata"]["hostname"] = hostname

    if audit_type_raw == "SYSCALL":
        result["metadata"]["syscall_raw"] = syscall or ""
        result["metadata"]["syscall_name"] = syscall_name
        result["metadata"]["arch"] = kv_data.get("arch", "")
        result["metadata"]["success"] = kv_data.get("success", "")
        if syscall_name in SENSITIVE_SYSCALLS:
            result["severity"] = "medium"
            if syscall_name in HIGH_SYSCALLS:
                result["severity"] = "high"
            result["metadata"]["sensitive_syscall"] = syscall_name
            result["message"] = f"Sensitive syscall: {syscall_name} by pid={pid} comm={comm} exe={exe}"

    elif audit_type_raw == "EXECVE":
        argc = kv_data.get("argc", "")
        argv = []
        for i in range(64):
            a = kv_data.get(f"a{i}", "")
            if a:
                argv.append(a)
            else:
                break
        result["metadata"]["argc"] = argc
        result["metadata"]["argv"] = argv
        result["metadata"]["exec_args"] = " ".join(argv) if argv else ""
        result["message"] = f"EXECVE: {comm} {' '.join(argv) if argv else ''}"

    elif audit_type_raw == "LOGIN":
        result["metadata"]["login_uid"] = kv_data.get("uid", "")
        result["metadata"]["old_ses"] = kv_data.get("old-ses", kv_data.get("old_ses", ""))
        result["metadata"]["ses"] = kv_data.get("ses", "")
        result["severity"] = "medium"

    elif audit_type_raw.startswith("USER_"):
        res_val = kv_data.get("res", kv_data.get("result", ""))
        acct = kv_data.get("acct", "")
        op = kv_data.get("op", "")
        result["metadata"]["acct"] = acct
        result["metadata"]["op"] = op
        result["metadata"]["auth_result"] = USER_AUTH_RESULT_MAP.get(res_val, res_val)
        grantors = kv_data.get("grantors", "")
        if grantors:
            result["metadata"]["grantors"] = grantors
        terminal = kv_data.get("terminal", kv_data.get("term", ""))
        if terminal:
            result["metadata"]["terminal"] = terminal
        if res_val in ("success", "PAM_SUCCESS"):
            result["severity"] = "info"
        else:
            result["severity"] = "medium"
            if res_val in ("PAM_AUTH_ERR", "authentication failed"):
                result["severity"] = "high"
        event_name = USER_EVENT_NAMES.get(audit_type_raw, audit_type_raw)
        result["message"] = (
            f"{event_name}: {acct or uid} op={op} result={res_val} terminal={terminal}"
        )

    key = kv_data.get("key", "")
    if key:
        result["metadata"]["audit_key"] = key

    path_data = kv_data.get("name", "")
    if path_data and SENSITIVE_PATHS.search(path_data):
        result["severity"] = "high"
        result["metadata"]["sensitive_path"] = path_data

    if audit_type_raw.startswith("ANOM_"):
        result["severity"] = "high"

    return result


def parse_auditd_log(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        if "type" in raw and "body" in raw:
            return parse_audispd_json(raw)
        if raw.get("Type") and raw.get("Body"):
            return parse_audispd_json(raw)
        if raw.get("type") and raw.get("timestamp"):
            return parse_audispd_json(raw)
        if raw.get("event_type"):
            return raw
        msg = raw.get("message", raw.get("raw", str(raw)))
        raw_type = raw.get("type", "")
        if raw_type and raw_type != "UNKNOWN":
            body = raw.get("body", raw.get("message", raw.get("raw", "")))
            if isinstance(body, dict):
                return parse_audispd_json(raw)
        lines = msg.split("\n") if isinstance(msg, str) and "type=" in msg else [msg]
        merged = _merge_related(lines) if isinstance(msg, str) else msg
        return _parse_traditional_kv(merged)

    if isinstance(raw, str):
        raw = raw.strip()
        if raw.startswith("{"):
            try:
                parsed = json.loads(raw)
                return parse_auditd_log(parsed)
            except (ValueError, json.JSONDecodeError) as exc:
                log.debug("auditd JSON decode failed: %s", exc)
        lines = raw.split("\n")
        merged = _merge_related(lines)
        return _parse_traditional_kv(merged)

    return {"event_type": "auditd", "severity": "info", "message": str(raw)}


PARSER_REGISTRY_KEY = "auditd"
