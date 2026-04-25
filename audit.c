/*
 * ubuntu-mate-hardening-audit.c
 * Compile: gcc -o hardening-audit ubuntu-mate-hardening-audit.c
 * Run: sudo ./hardening-audit
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <dirent.h>
#include <errno.h>

#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define BLUE    "\033[1;34m"
#define RESET   "\033[0m"

// Function prototypes
void check_uid_0();
int file_exists(const char *path);
int dir_exists(const char *path);
int check_file_perms(const char *path, mode_t expected);
int check_service_active(const char *service);
int check_package_installed(const char *package);
int check_kernel_param(const char *param, const char *expected);
void print_header(const char *title);
void print_status(const char *item, int pass, const char *good_msg, const char *bad_msg);
char *trim(char *str);

// Global counters
int total_checks = 0;
int passed_checks = 0;
int warning_checks = 0;
int failed_checks = 0;

int main() {
    check_uid_0();
    
    printf("\n");
    printf(BLUE "╔══════════════════════════════════════════════════════════════════╗\n" RESET);
    printf(BLUE "║          UBUNTU MATE HARDENING & OPSEC AUDIT REPORT              ║\n" RESET);
    printf(BLUE "╚══════════════════════════════════════════════════════════════════╝\n" RESET);
    printf("\n");
    
    // Get system info
    FILE *fp = popen("lsb_release -ds 2>/dev/null", "r");
    char distro[128] = "Unknown";
    if (fp) {
        fgets(distro, sizeof(distro), fp);
        pclose(fp);
    }
    printf("System: %s", trim(distro));
    printf("Kernel: ");
    fflush(stdout);
    system("uname -r");
    printf("Hostname: ");
    fflush(stdout);
    system("hostname");
    printf("Date: ");
    fflush(stdout);
    system("date");
    printf("\n");
    
    // ==================== SECTION 1: ACCOUNT SECURITY ====================
    print_header("1. ACCOUNT & AUTHENTICATION SECURITY");
    
    // Check 1: Root password status
    int root_locked = 0;
    fp = popen("passwd -S root 2>/dev/null", "r");
    char root_status[256];
    if (fp && fgets(root_status, sizeof(root_status), fp)) {
        if (strstr(root_status, " L ") || strstr(root_status, " LK ")) {
            root_locked = 1;
        }
        pclose(fp);
    }
    print_status("Root account locked", root_locked, 
                 "Root account is locked (good)", 
                 "Root account has a valid password - consider 'sudo passwd -l root'");
    
    // Check 2: Sudo with password required
    int sudo_nopasswd = 0;
    if (dir_exists("/etc/sudoers.d")) {
        fp = popen("grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v '^#' | grep -v '^$'", "r");
        char buf[1024];
        if (fp && fgets(buf, sizeof(buf), fp)) {
            sudo_nopasswd = 1;
        }
        if (fp) pclose(fp);
    }
    print_status("Sudo requires password", !sudo_nopasswd,
                 "No NOPASSWD entries found (good)",
                 "NOPASSWD sudo entries exist - consider removing them");
    
    // Check 3: Empty passwords
    int empty_pass = 0;
    fp = popen("awk -F: '($2 == \"\") {print $1}' /etc/shadow 2>/dev/null", "r");
    char empty_buf[256];
    if (fp && fgets(empty_buf, sizeof(empty_buf), fp)) {
        empty_pass = 1;
    }
    if (fp) pclose(fp);
    print_status("No accounts with empty passwords", !empty_pass,
                 "No empty password accounts found (good)",
                 "Accounts with empty passwords exist - IMMEDIATE ACTION REQUIRED");
    
    // Check 4: Password aging policy
    int pass_max_days = 99999;
    fp = popen("grep '^PASS_MAX_DAYS' /etc/login.defs | awk '{print $2}'", "r");
    char days_buf[32];
    if (fp && fgets(days_buf, sizeof(days_buf), fp)) {
        pass_max_days = atoi(days_buf);
        pclose(fp);
    }
    int pass_aging_ok = (pass_max_days <= 90);
    char aging_msg[128];
    snprintf(aging_msg, sizeof(aging_msg), "PASS_MAX_DAYS is %d days (recommended ≤ 90)", pass_max_days);
    print_status("Password aging policy configured", pass_aging_ok,
                 aging_msg,
                 aging_msg);
    
    // Check 5: Non-root users with UID 0
    int uid0_users = 0;
    fp = popen("awk -F: '($3 == 0) {print $1}' /etc/passwd | grep -v '^root$'", "r");
    char uid0_buf[256];
    if (fp && fgets(uid0_buf, sizeof(uid0_buf), fp)) {
        uid0_users = 1;
    }
    if (fp) pclose(fp);
    print_status("Only root has UID 0", !uid0_users,
                 "Only root has UID 0 (good)",
                 "Additional users have UID 0 - SECURITY RISK");
    
    // ==================== SECTION 2: NETWORK SECURITY ====================
    print_header("2. NETWORK SECURITY");
    
    // Check 6: Firewall status (UFW)
    int ufw_active = 0;
    fp = popen("ufw status 2>/dev/null | grep -i 'Status: active'", "r");
    char ufw_buf[256];
    if (fp && fgets(ufw_buf, sizeof(ufw_buf), fp)) {
        ufw_active = 1;
    }
    if (fp) pclose(fp);
    print_status("UFW Firewall active", ufw_active,
                 "UFW is active (good)",
                 "UFW is inactive - run 'sudo ufw enable'");
    
    // Check 7: IPv6 status (if not using)
    int ipv6_disabled = 0;
    fp = popen("sysctl net.ipv6.conf.all.disable_ipv6 2>/dev/null | awk '{print $3}'", "r");
    char ipv6_buf[32];
    if (fp && fgets(ipv6_buf, sizeof(ipv6_buf), fp)) {
        if (atoi(ipv6_buf) == 1) ipv6_disabled = 1;
        pclose(fp);
    }
    print_status("IPv6 status", 1,  // Not a pass/fail, just info
                 ipv6_disabled ? "IPv6 is disabled" : "IPv6 is enabled (normal unless intentionally disabled)",
                 "");
    
    // Check 8: DNS over TLS
    int dot_enabled = 0;
    fp = popen("resolvectl status 2>/dev/null | grep -i 'DNSOverTLS' | head -1", "r");
    char dot_buf[256];
    if (fp && fgets(dot_buf, sizeof(dot_buf), fp)) {
        if (strstr(dot_buf, "yes") || strstr(dot_buf, "opportunistic") || strstr(dot_buf, "+")) {
            dot_enabled = 1;
        }
        pclose(fp);
    }
    print_status("DNS over TLS (encrypted DNS)", dot_enabled,
                 "DNS over TLS is enabled (good)",
                 "DNS over TLS not enabled - consider using Quad9/Cloudflare with DoT");
    
    // Check 9: Open ports
    fp = popen("ss -tulpn 2>/dev/null | grep LISTEN | wc -l", "r");
    char port_buf[32];
    int open_ports = 0;
    if (fp && fgets(port_buf, sizeof(port_buf), fp)) {
        open_ports = atoi(port_buf);
        pclose(fp);
    }
    char port_msg[128];
    snprintf(port_msg, sizeof(port_msg), "%d listening port(s) detected", open_ports);
    print_status("Minimal listening services", (open_ports <= 10),  // Heuristic
                 port_msg,
                 port_msg);
    
    // Check 10: CUPS (printing service)
    int cups_disabled = !check_service_active("cups");
    print_status("CUPS (printing) disabled", cups_disabled,
                 "CUPS is not running (good for security)",
                 "CUPS is running - consider 'systemctl disable cups' if not needed");
    
    // Check 11: Avahi (mDNS/Bonjour)
    int avahi_disabled = !check_service_active("avahi-daemon");
    print_status("Avahi/mDNS disabled", avahi_disabled,
                 "Avahi is not running (good)",
                 "Avahi is running - consider 'systemctl disable avahi-daemon'");
    
    // Check 12: Bluetooth status
    int bluetooth_disabled = !check_service_active("bluetooth");
    print_status("Bluetooth service disabled", bluetooth_disabled,
                 "Bluetooth is not running (good if not needed)",
                 "Bluetooth is running - consider disabling if not used");
    
    // ==================== SECTION 3: KERNEL HARDENING ====================
    print_header("3. KERNEL HARDENING (sysctl)");
    
    // Check 13: ASLR
    int aslr_ok = 0;
    fp = popen("sysctl kernel.randomize_va_space 2>/dev/null | awk '{print $3}'", "r");
    char aslr_buf[32];
    if (fp && fgets(aslr_buf, sizeof(aslr_buf), fp)) {
        if (atoi(aslr_buf) == 2) aslr_ok = 1;
        pclose(fp);
    }
    print_status("ASLR fully enabled (value=2)", aslr_ok,
                 "ASLR is fully enabled (good)",
                 "ASLR is not fully enabled - check kernel.randomize_va_space");
    
    // Check 14: Kernel pointer obfuscation
    int kptr_restrict = 0;
    fp = popen("sysctl kernel.kptr_restrict 2>/dev/null | awk '{print $3}'", "r");
    char kptr_buf[32];
    if (fp && fgets(kptr_buf, sizeof(kptr_buf), fp)) {
        if (atoi(kptr_buf) >= 1) kptr_restrict = 1;
        pclose(fp);
    }
    print_status("Kernel pointer obfuscation", kptr_restrict,
                 "kernel.kptr_restrict is enabled (good)",
                 "kernel.kptr_restrict is disabled - kernel pointers exposed");
    
    // Check 15: ptrace restrictions
    int ptrace_restrict = 0;
    fp = popen("sysctl kernel.yama.ptrace_scope 2>/dev/null | awk '{print $3}'", "r");
    char ptrace_buf[32];
    if (fp && fgets(ptrace_buf, sizeof(ptrace_buf), fp)) {
        if (atoi(ptrace_buf) >= 2) ptrace_restrict = 1;
        pclose(fp);
    }
    print_status("ptrace restrictions (Yama)", ptrace_restrict,
                 "kernel.yama.ptrace_scope >= 2 (good)",
                 "ptrace scope too permissive - processes can trace each other");
    
    // Check 16: Core dumps restricted
    int core_restrict = 0;
    fp = popen("sysctl fs.suid_dumpable 2>/dev/null | awk '{print $3}'", "r");
    char core_buf[32];
    if (fp && fgets(core_buf, sizeof(core_buf), fp)) {
        if (atoi(core_buf) == 0) core_restrict = 1;
        pclose(fp);
    }
    print_status("SUID core dumps disabled", core_restrict,
                 "fs.suid_dumpable = 0 (good)",
                 "SUID core dumps allowed - potential information leak");
    
    // Check 17: Magic SysRq disabled
    int sysrq_disabled = 0;
    fp = popen("sysctl kernel.sysrq 2>/dev/null | awk '{print $3}'", "r");
    char sysrq_buf[32];
    if (fp && fgets(sysrq_buf, sizeof(sysrq_buf), fp)) {
        if (atoi(sysrq_buf) == 0) sysrq_disabled = 1;
        pclose(fp);
    }
    print_status("Magic SysRq disabled", sysrq_disabled,
                 "kernel.sysrq = 0 (good for security)",
                 "Magic SysRq enabled - physical access risk");
    
    // Check 18: IP forwarding
    int ip_forward = 0;
    fp = popen("sysctl net.ipv4.ip_forward 2>/dev/null | awk '{print $3}'", "r");
    char forward_buf[32];
    if (fp && fgets(forward_buf, sizeof(forward_buf), fp)) {
        if (atoi(forward_buf) == 1) ip_forward = 1;
        pclose(fp);
    }
    print_status("IP forwarding disabled", !ip_forward,
                 "net.ipv4.ip_forward = 0 (good)",
                 "IP forwarding enabled - router mode (check if intended)");
    
    // Check 19: ICMP redirects
    int icmp_redirects = 0;
    fp = popen("sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null | awk '{print $3}'", "r");
    char icmp_buf[32];
    if (fp && fgets(icmp_buf, sizeof(icmp_buf), fp)) {
        if (atoi(icmp_buf) == 0) icmp_redirects = 1;
        pclose(fp);
    }
    print_status("ICMP redirects disabled", icmp_redirects,
                 "net.ipv4.conf.all.accept_redirects = 0 (good)",
                 "ICMP redirects accepted - potential MITM risk");
    
    // Check 20: Source routed packets
    int src_route = 0;
    fp = popen("sysctl net.ipv4.conf.all.accept_source_route 2>/dev/null | awk '{print $3}'", "r");
    char src_buf[32];
    if (fp && fgets(src_buf, sizeof(src_buf), fp)) {
        if (atoi(src_buf) == 0) src_route = 1;
        pclose(fp);
    }
    print_status("Source routing disabled", src_route,
                 "net.ipv4.conf.all.accept_source_route = 0 (good)",
                 "Source routing accepted - security risk");
    
    // Check 21: SYN cookie protection
    int syn_cookies = 0;
    fp = popen("sysctl net.ipv4.tcp_syncookies 2>/dev/null | awk '{print $3}'", "r");
    char syn_buf[32];
    if (fp && fgets(syn_buf, sizeof(syn_buf), fp)) {
        if (atoi(syn_buf) == 1) syn_cookies = 1;
        pclose(fp);
    }
    print_status("SYN cookies enabled", syn_cookies,
                 "net.ipv4.tcp_syncookies = 1 (good)",
                 "SYN cookies disabled - DoS vulnerability");
    
    // ==================== SECTION 4: PACKAGES & UPDATES ====================
    print_header("4. PACKAGE MANAGEMENT & UPDATES");
    
    // Check 22: Unattended upgrades
    int unattended_upgrades = check_package_installed("unattended-upgrades");
    int uu_configured = 0;
    if (unattended_upgrades) {
        fp = popen("grep -r '^\\s*\"o=Ubuntu,a=' /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null | grep -v '^//' | head -1", "r");
        char uu_buf[256];
        if (fp && fgets(uu_buf, sizeof(uu_buf), fp)) {
            uu_configured = 1;
        }
        if (fp) pclose(fp);
    }
    print_status("Automatic security updates", (unattended_upgrades && uu_configured),
                 "unattended-upgrades is installed and configured (good)",
                 "Automatic security updates not configured - run 'sudo apt install unattended-upgrades'");
    
    // Check 23: Pending updates
    int updates_pending = 0;
    fp = popen("apt list --upgradable 2>/dev/null | grep -c 'upgradable' || echo 0", "r");
    char upd_buf[32];
    if (fp && fgets(upd_buf, sizeof(upd_buf), fp)) {
        if (atoi(upd_buf) > 0) updates_pending = 1;
        pclose(fp);
    }
    char upd_msg[128];
    snprintf(upd_msg, sizeof(upd_msg), "%s pending updates", 
             updates_pending ? "Has" : "No");
    print_status("System up to date", !updates_pending,
                 upd_msg,
                 upd_msg);
    
    // ==================== SECTION 5: FILESYSTEM SECURITY ====================
    print_header("5. FILESYSTEM SECURITY");
    
    // Check 24: /tmp mounted with noexec
    int tmp_noexec = 0;
    fp = popen("mount | grep ' /tmp ' | grep noexec", "r");
    char tmp_buf[256];
    if (fp && fgets(tmp_buf, sizeof(tmp_buf), fp)) {
        tmp_noexec = 1;
    }
    if (fp) pclose(fp);
    print_status("/tmp mounted with noexec", tmp_noexec,
                 "/tmp has noexec (good)",
                 "/tmp does not have noexec - programs can execute from /tmp");
    
    // Check 25: /var/tmp mounted with noexec (stricter)
    int vartmp_noexec = 0;
    fp = popen("mount | grep ' /var/tmp ' | grep noexec", "r");
    char vartmp_buf[256];
    if (fp && fgets(vartmp_buf, sizeof(vartmp_buf), fp)) {
        vartmp_noexec = 1;
    }
    if (fp) pclose(fp);
    print_status("/var/tmp mounted with noexec", vartmp_noexec,
                 "/var/tmp has noexec (good)",
                 "/var/tmp does not have noexec - consider mounting separately");
    
    // Check 26: /home mounted with nosuid
    int home_nosuid = 0;
    fp = popen("mount | grep ' /home ' | grep nosuid", "r");
    char home_buf[256];
    if (fp && fgets(home_buf, sizeof(home_buf), fp)) {
        home_nosuid = 1;
    }
    if (fp) pclose(fp);
    print_status("/home mounted with nosuid", home_nosuid,
                 "/home has nosuid (good)",
                 "/home does not have nosuid - SUID binaries can run from home");
    
    // Check 27: Sticky bit on world-writable dirs
    int sticky_tmp = 0;
    struct stat st;
    if (stat("/tmp", &st) == 0) {
        if (st.st_mode & S_ISVTX) sticky_tmp = 1;
    }
    print_status("Sticky bit on /tmp", sticky_tmp,
                 "/tmp has sticky bit set (good)",
                 "/tmp missing sticky bit - security risk");
    
    // ==================== SECTION 6: PRIVACY & TELEMETRY ====================
    print_header("6. PRIVACY & TELEMETRY (OpSec)");
    
    // Check 28: Ubuntu report (crash reports)
    int apport_disabled = !check_service_active("apport");
    print_status("Apport crash reporting disabled", apport_disabled,
                 "Apport is disabled (good for privacy)",
                 "Apport is running - crash reports may be sent to Canonical");
    
    // Check 29: Whoopsie (error reporting)
    int whoopsie_disabled = !check_service_active("whoopsie");
    print_status("Whoopsie error reporting disabled", whoopsie_disabled,
                 "Whoopsie is not running (good for privacy)",
                 "Whoopsie is running - error reports may be sent");
    
    // Check 30: Package popularity contest
    int popcon_installed = check_package_installed("popularity-contest");
    print_status("Popularity Contest not installed", !popcon_installed,
                 "popularity-contest is not installed (good)",
                 "popularity-contest installed - package usage stats being sent");
    
    // Check 31: Zeitgeist (activity logging)
    int zeitgeist_running = check_service_active("zeitgeist");
    print_status("Zeitgeist activity logging disabled", !zeitgeist_running,
                 "Zeitgeist is not running (good for privacy)",
                 "Zeitgeist is running - user activity is being logged");
    
    // ==================== SECTION 7: MANDATORY ACCESS CONTROL ====================
    print_header("7. MANDATORY ACCESS CONTROL");
    
    // Check 32: AppArmor
    int apparmor_enabled = 0;
    fp = popen("aa-status --enabled 2>/dev/null && echo '1' || echo '0'", "r");
    char aa_buf[32];
    if (fp && fgets(aa_buf, sizeof(aa_buf), fp)) {
        if (atoi(aa_buf) == 1) apparmor_enabled = 1;
        pclose(fp);
    }
    print_status("AppArmor enabled", apparmor_enabled,
                 "AppArmor is enabled and loaded (good)",
                 "AppArmor is not fully enabled - consider enabling");
    
    // ==================== SUMMARY ====================
    printf("\n");
    printf(BLUE "══════════════════════════════════════════════════════════════════\n" RESET);
    printf(BLUE "                          SUMMARY\n" RESET);
    printf(BLUE "══════════════════════════════════════════════════════════════════\n" RESET);
    printf("Total checks performed: %d\n", total_checks);
    printf(GREEN "Passed: %d\n" RESET, passed_checks);
    printf(YELLOW "Warnings/Info: %d\n" RESET, warning_checks);
    printf(RED "Failed (needs attention): %d\n" RESET, failed_checks);
    
    printf("\n");
    if (failed_checks == 0) {
        printf(GREEN "✓ Your system appears to be well-hardened!\n" RESET);
    } else {
        printf(RED "⚠ Review the items marked [FAIL] above and implement fixes.\n" RESET);
        printf(YELLOW "Run this script again after making changes to verify.\n" RESET);
    }
    printf("\n");
    
    return 0;
}

void check_uid_0() {
    if (geteuid() != 0) {
        printf(RED "ERROR: This script must be run as root (sudo)!\n" RESET);
        exit(1);
    }
}

int file_exists(const char *path) {
    return access(path, F_OK) == 0;
}

int dir_exists(const char *path) {
    DIR *dir = opendir(path);
    if (dir) {
        closedir(dir);
        return 1;
    }
    return 0;
}

int check_file_perms(const char *path, mode_t expected) {
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return (st.st_mode & 0777) == expected;
}

int check_service_active(const char *service) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "systemctl is-active %s 2>/dev/null | grep -q '^active'", service);
    return system(cmd) == 0;
}

int check_package_installed(const char *package) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "dpkg -l %s 2>/dev/null | grep -q '^ii'", package);
    return system(cmd) == 0;
}

int check_kernel_param(const char *param, const char *expected) {
    char cmd[256];
    char buf[128];
    snprintf(cmd, sizeof(cmd), "sysctl %s 2>/dev/null | awk '{print $3}'", param);
    FILE *fp = popen(cmd, "r");
    if (!fp) return 0;
    if (fgets(buf, sizeof(buf), fp)) {
        pclose(fp);
        return strcmp(trim(buf), expected) == 0;
    }
    pclose(fp);
    return 0;
}

char *trim(char *str) {
    char *end;
    while (*str == ' ' || *str == '\t' || *str == '\n') str++;
    if (*str == 0) return str;
    end = str + strlen(str) - 1;
    while (end > str && (*end == ' ' || *end == '\t' || *end == '\n')) end--;
    *(end + 1) = 0;
    return str;
}

void print_header(const char *title) {
    printf("\n");
    printf(BLUE "──────────────────────────────────────────────────────────────────\n" RESET);
    printf(BLUE "%s\n" RESET, title);
    printf(BLUE "──────────────────────────────────────────────────────────────────\n" RESET);
}

void print_status(const char *item, int pass, const char *good_msg, const char *bad_msg) {
    total_checks++;
    
    if (pass) {
        passed_checks++;
        printf(GREEN "[✓] %s\n" RESET, item);
        if (strlen(good_msg) > 0) {
            printf("    %s\n", good_msg);
        }
    } else {
        if (strstr(item, "status") || strstr(item, "IPv6")) {
            warning_checks++;
            printf(YELLOW "[i] %s\n" RESET, item);
        } else {
            failed_checks++;
            printf(RED "[✗] %s - FAIL\n" RESET, item);
        }
        if (strlen(bad_msg) > 0) {
            printf("    %s\n", bad_msg);
        }
    }
}
