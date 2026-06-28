#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Hash map for Threat Intel C2 IPs
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key, __u32);   // IPv4 Address
    __type(value, __u8);  // 1 = Blocked
} c2_blocklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} tls_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64); // inode number
    __type(value, __u8); // 1 = is honeytoken, 2 = write-only trap
} honeytokens SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32); // PID
    __type(value, __u8); // 1 = is ghost
} ghost_pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32); // Agent PID
} agent_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);   // PID
    __type(value, __u64); // Count of file creations
} file_creation_counts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);   // PID
    __type(value, __u64); // Count of syslog/journal socket sends
} journal_spam_counts SEC(".maps");

SEC("tp/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;
    
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = uid_gid & 0xFFFFFFFF;
    
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    // --- Behavioral Trap: Unauthorized Tool Execution (Podman tripwire) ---
    int is_unauthorized_tool = 0;
    if (comm[0] == 'p' && comm[1] == 'o' && comm[2] == 'd' && comm[3] == 'm' && comm[4] == 'a' && comm[5] == 'n') is_unauthorized_tool = 1;

    if (is_unauthorized_tool) {
        bpf_send_signal(19); // SIGSTOP
        
        e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->pid = bpf_get_current_pid_tgid() >> 32;
            e->ppid = -4;
            e->uid = uid;
            __builtin_memcpy(e->comm, comm, sizeof(e->comm));
            const char msg[] = "UNAUTHORIZED_EXEC_TRAP";
            __builtin_memcpy(e->filename, msg, sizeof(msg));
            bpf_ringbuf_submit(e, 0);
        }
        return 0;
    }

    // --- Behavioral Exploit Trap: Browser Sandbox Escape to Root ---
    if (uid == 0) { // Executing as root
        // Check if caller is an unprivileged app prone to RCE/Sandbox escapes (Browsers, Messengers)
        int is_vuln_app = 0;
        if (comm[0] == 'f' && comm[1] == 'i' && comm[2] == 'r' && comm[3] == 'e' && comm[4] == 'f') is_vuln_app = 1; // firefox
        if (comm[0] == 'c' && comm[1] == 'h' && comm[2] == 'r' && comm[3] == 'o' && comm[4] == 'm') is_vuln_app = 1; // chrome/chromium
        if (comm[0] == 's' && comm[1] == 'i' && comm[2] == 'g' && comm[3] == 'n' && comm[4] == 'a') is_vuln_app = 1; // signal/signal-desktop
        if (comm[0] == 't' && comm[1] == 'e' && comm[2] == 'l' && comm[3] == 'e' && comm[4] == 'g') is_vuln_app = 1; // telegram/telegram-desktop
        
        // Catch all Telegram forks containing "gram" (e.g., kotatogram, nekogram, ayugram)
        #pragma unroll
        for (int i = 0; i < 12; i++) {
            if (comm[i] == 'g' && comm[i+1] == 'r' && comm[i+2] == 'a' && comm[i+3] == 'm') is_vuln_app = 1;
        }
        
        if (is_vuln_app) {
            bpf_send_signal(19); // SIGSTOP - Freeze the exploited app instantly
            
            e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
            if (e) {
                e->pid = bpf_get_current_pid_tgid() >> 32;
                e->ppid = -3;
                e->uid = uid;
                __builtin_memcpy(e->comm, comm, sizeof(e->comm));
                const char msg[] = "PRIVILEGE_ESCALATION_TRAP";
                __builtin_memcpy(e->filename, msg, sizeof(msg));
                bpf_ringbuf_submit(e, 0);
            }
            return 0;
        }
    }
    // ---------------------------------------------------------------

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    // Read parent PID safely using BPF CO-RE (Compile Once - Run Everywhere)
    struct task_struct *real_parent;
    bpf_core_read(&real_parent, sizeof(real_parent), &task->real_parent);
    bpf_core_read(&e->ppid, sizeof(e->ppid), &real_parent->tgid);

    __builtin_memcpy(e->comm, comm, sizeof(e->comm));

    // args[0] in sys_enter_execve is the filename pointer
    const char *filename_ptr = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename_ptr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/vfs_open")
int BPF_KPROBE(kprobe_vfs_open, const struct path *path, struct file *file) {
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    __u64 ino = BPF_CORE_READ(inode, i_ino);
    
    __u8 *is_honey = bpf_map_lookup_elem(&honeytokens, &ino);
    if (is_honey) {
        int trigger = 0;
        if (*is_honey == 1) {
            trigger = 1; // Trap on ANY access
        } else if (*is_honey == 2) {
            unsigned int f_flags = BPF_CORE_READ(file, f_flags);
            // Trap on WRITE or APPEND access
            if ((f_flags & 3) != 0 || (f_flags & 02000)) {
                trigger = 1;
            }
        }
        
        if (trigger) {
            struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
            if (e) {
                e->pid = bpf_get_current_pid_tgid() >> 32;
                e->ppid = -1; // Indicator for Honeytoken
                e->uid = bpf_get_current_uid_gid();
                bpf_get_current_comm(&e->comm, sizeof(e->comm));
                const char msg[] = "HONEYTOKEN_TRIGGERED";
                __builtin_memcpy(e->filename, msg, sizeof(msg));
                bpf_ringbuf_submit(e, 0);
            }
        }
    }
    return 0;
}

SEC("tp/syscalls/sys_enter_ptrace")
int handle_ptrace(struct trace_event_raw_sys_enter *ctx) {
    __u32 target_pid = ctx->args[1];
    __u8 *is_ghost = bpf_map_lookup_elem(&ghost_pids, &target_pid);
    if (is_ghost && *is_ghost == 1) {
        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->pid = bpf_get_current_pid_tgid() >> 32;
            e->ppid = -2; 
            e->uid = bpf_get_current_uid_gid();
            bpf_get_current_comm(&e->comm, sizeof(e->comm));
            const char msg[] = "GHOST_PROCESS_TRAP";
            __builtin_memcpy(e->filename, msg, sizeof(msg));
            bpf_ringbuf_submit(e, 0);
        }
    }
    return 0;
}

SEC("tp/syscalls/sys_enter_process_vm_readv")
int handle_process_vm_readv(struct trace_event_raw_sys_enter *ctx) {
    __u32 target_pid = ctx->args[0];
    __u8 *is_ghost = bpf_map_lookup_elem(&ghost_pids, &target_pid);
    if (is_ghost && *is_ghost == 1) {
        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->pid = bpf_get_current_pid_tgid() >> 32;
            e->ppid = -2;
            e->uid = bpf_get_current_uid_gid();
            bpf_get_current_comm(&e->comm, sizeof(e->comm));
            const char msg[] = "GHOST_PROCESS_TRAP";
            __builtin_memcpy(e->filename, msg, sizeof(msg));
            bpf_ringbuf_submit(e, 0);
        }
    }
    return 0;
}

SEC("tp/syscalls/sys_enter_kill")
int handle_kill(struct trace_event_raw_sys_enter *ctx) {
    __u32 target_pid = ctx->args[0];
    __u32 key = 0;
    __u32 *my_pid = bpf_map_lookup_elem(&agent_pid, &key);
    
    if (my_pid && *my_pid == target_pid) {
        // Attack on the EDR detected!
        // Instantly freeze the attacker from kernel space using eBPF helper
        bpf_send_signal(19); // SIGSTOP
        
        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->pid = bpf_get_current_pid_tgid() >> 32;
            e->ppid = target_pid;
            e->uid = bpf_get_current_uid_gid();
            bpf_get_current_comm(&e->comm, sizeof(e->comm));
            const char msg[] = "SELF_DEFENSE_TRAP";
            __builtin_memcpy(e->filename, msg, sizeof(msg));
            bpf_ringbuf_submit(e, 0);
        }
    }
    return 0;
}

#define ETH_P_IP 0x0800

SEC("xdp")
int xdp_c2_inspector(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    // 1. Parse Ethernet Header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
        
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS; // We only care about IPv4 for this check
        
    // 2. Parse IPv4 Header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
        
    // 3. Match Destination IP against C2 Blocklist Map
    __u32 dest_ip = ip->daddr;
    __u8 *is_blocked = bpf_map_lookup_elem(&c2_blocklist, &dest_ip);
    
    if (is_blocked && *is_blocked == 1) {
        // High-confidence Threat Intelligence C2 Match.
        // Drop the packet at the NIC level before it hits the OS TCP stack.
        return XDP_DROP;
    }
    
    // 4. Parse TCP Header for TLS JA3 Fingerprinting
    if (ip->protocol != 6) // IPPROTO_TCP
        return XDP_PASS;
        
    __u8 ip_header_len = (*((__u8 *)ip)) & 0x0F;
    struct tcphdr *tcp = (void *)ip + (ip_header_len * 4);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;
        
    if (tcp->dest == bpf_htons(443)) {
        __u8 *tcp_bytes = (__u8 *)tcp;
        __u8 data_offset = tcp_bytes[12] >> 4;
        __u8 *payload = (void *)tcp + (data_offset * 4);
        if ((void *)(payload + 3) > data_end) 
            return XDP_PASS;
            
        // Check for TLS Handshake (0x16) and SSL/TLS Version (0x03)
        if (payload[0] == 0x16 && payload[1] == 0x03) {
            struct tls_hello_event *e = bpf_ringbuf_reserve(&tls_events, sizeof(*e), 0);
            if (e) {
                e->saddr = ip->saddr;
                e->daddr = ip->daddr;
                e->dport = bpf_ntohs(tcp->dest);
                
                int len = data_end - (void *)payload;
                if (len > 128) len = 128;
                
                // Copy up to 128 bytes of the Client Hello for user-space JA3 hashing
                for (int i = 0; i < 128; i++) {
                    if ((void *)(payload + i + 1) > data_end) break;
                    e->payload[i] = payload[i];
                }
                e->payload_len = len;
                
                bpf_ringbuf_submit(e, 0);
            }
        }
    }
    
    return XDP_PASS;
}

SEC("tp/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx) {
    int flags = ctx->args[2];
    if (flags & 00000100) { // O_CREAT
        __u32 pid = bpf_get_current_pid_tgid() >> 32;
        
        // Skip tracking the EDR agent itself to prevent self-freezing
        __u32 key = 0;
        __u32 *my_pid = bpf_map_lookup_elem(&agent_pid, &key);
        if (my_pid && *my_pid == pid) return 0;

        __u64 *count = bpf_map_lookup_elem(&file_creation_counts, &pid);
        __u64 new_count = 1;
        if (count) {
            new_count = *count + 1;
        }
        bpf_map_update_elem(&file_creation_counts, &pid, &new_count, BPF_ANY);
        
        // If a single process creates > 10,000 files, it's an Inode Exhaustion Attack
        if (new_count > 10000) {
            bpf_send_signal(19); // SIGSTOP
            struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
            if (e) {
                e->pid = pid;
                e->ppid = -5;
                e->uid = bpf_get_current_uid_gid();
                bpf_get_current_comm(&e->comm, sizeof(e->comm));
                const char msg[] = "INODE_EXHAUSTION_TRAP";
                __builtin_memcpy(e->filename, msg, sizeof(msg));
                bpf_ringbuf_submit(e, 0);
            }
            new_count = 0; // Reset to avoid spamming ringbuf
            bpf_map_update_elem(&file_creation_counts, &pid, &new_count, BPF_ANY);
        }
    }
    return 0;
}

SEC("tp/syscalls/sys_enter_sendto")
int handle_sendto(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    __u32 key = 0;
    __u32 *my_pid = bpf_map_lookup_elem(&agent_pid, &key);
    if (my_pid && *my_pid == pid) return 0;

    __u64 *count = bpf_map_lookup_elem(&journal_spam_counts, &pid);
    __u64 new_count = 1;
    if (count) {
        new_count = *count + 1;
    }
    bpf_map_update_elem(&journal_spam_counts, &pid, &new_count, BPF_ANY);
    
    // If a single process sends > 50,000 datagrams rapidly, freeze it
    if (new_count > 50000) {
        bpf_send_signal(19); // SIGSTOP
        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->pid = pid;
            e->ppid = -6;
            e->uid = bpf_get_current_uid_gid();
            bpf_get_current_comm(&e->comm, sizeof(e->comm));
            const char msg[] = "JOURNALD_EXHAUSTION_TRAP";
            __builtin_memcpy(e->filename, msg, sizeof(msg));
            bpf_ringbuf_submit(e, 0);
        }
        new_count = 0; 
        bpf_map_update_elem(&journal_spam_counts, &pid, &new_count, BPF_ANY);
    }
    return 0;
}
