#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <getopt.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

int tcp = 0;
int udp = 0;
char ipv4[16];
char ipv6[48];
char *connection_state[] = {NULL,
                            "TCP_ESTABLISHED",
                            "TCP_SYN_SENT",
                            "TCP_SYN_RECV",
                            "TCP_FIN_WAIT1",
                            "TCP_FIN_WAIT2",
                            "TCP_TIME_WAIT",
                            "TCP_CLOSE",
                            "TCP_CLOSE_WAIT",
                            "TCP_LAST_ACL",
                            "TCP_LISTEN",
                            "TCP_CLOSING"};

struct option long_optinos[] = {{"tcp", no_argument, NULL, 0},
                                {"udp", no_argument, NULL, 0},
                                {NULL, 0, NULL, 0}};
regex_t socket_pattern1, socket_pattern2;
regex_t grep_pattern;

void helper() {
  printf("./hw1 [-t|--tcp] [-u|--udp] [filter-string]\n");
  exit(0);
}

char *print_ipv4(unsigned int ip) {
  struct in_addr ip_addr;
  ip_addr.s_addr = ip;
  inet_ntop(AF_INET, &ip_addr.s_addr, ipv4, sizeof(ipv4));
  return ipv4;
}
char *print_ipv6(unsigned int ip) {
  struct in_addr ip_addr;
  ip_addr.s_addr = ip;
  inet_ntop(AF_INET6, &ip_addr.s_addr, ipv6, sizeof(ipv6));
  return ipv6;
}

int string2int(char str[]) {
  int num = 0;
  size_t idx = 0;
  while (str[idx] && isdigit(str[idx])) {
    /*printf("%d ", idx);*/
    num *= 10;
    num += (int)str[idx++] - '0';
  }
  return num;
}

void dump_proc(char *proc, int sock, int pid) {
  size_t idx;
  FILE *fp;
  char ga[1024];
  char path[1024];
  snprintf(path, sizeof(path), "%s%s", "/proc/net/", proc);
  fp = fopen(path, "r");
  fgets(ga, 1024, fp);
  if (fp) {
    unsigned int sl, la, lp, ra, rp, st, txq, rxq, tr, tm, re, uid, to, inode;
    while (fscanf(fp, "%d: %X:%X %X:%X %X %X:%X %X:%X %X     %d        %d %d",
                  &sl, &la, &lp, &ra, &rp, &st, &txq, &rxq, &tr, &tm, &re, &uid,
                  &to, &inode) != EOF) {
      fgets(ga, 1024, fp);
      if (sock == inode) {
        FILE *fpp;
        char ppath[1024];
        snprintf(ppath, sizeof(ppath), "/proc/%d/comm", pid);
        fpp = fopen(ppath, "r");
        char program[128];
        fscanf(fpp, "%s", program);
        fclose(fpp);
        char lipport[256], ripport[256];
        if (!strcmp(proc, "tcp") || !strcmp(proc, "udp")) {
          if (lp == 0) {
            snprintf(lipport, sizeof(lipport), "%s:*", print_ipv4(la));
          } else {
            snprintf(lipport, sizeof(lipport), "%s:%d", print_ipv4(la), lp);
          }
          if (rp == 0) {
            snprintf(ripport, sizeof(ripport), "%s:*", print_ipv4(ra));
          } else {
            snprintf(ripport, sizeof(ripport), "%s:%d", print_ipv4(ra), rp);
          }
        } else {
          if (lp == 0) {
            snprintf(lipport, sizeof(lipport), "%s:*", print_ipv6(la));
          } else {
            snprintf(lipport, sizeof(lipport), "%s:%d", print_ipv6(la), lp);
          }
          if (rp == 0) {
            snprintf(ripport, sizeof(ripport), "%s:*", print_ipv6(ra));
          } else {
            snprintf(ripport, sizeof(ripport), "%s:%d", print_ipv6(ra), rp);
          }
        }
        char cmpstr[2048];
        snprintf(cmpstr, sizeof(cmpstr), "%s\t%-35s\t%-35s\t%d/%s\n", proc,
                 lipport, ripport, pid, program);
        if (!regexec(&grep_pattern, cmpstr, 0, NULL, REG_NOTBOL)) {
          printf("%s", cmpstr);
        }
      }
    }
    fclose(fp);
  }
  return;
}

void trivase_pid(char *proc) {
  regcomp(&socket_pattern1, "socket:.*", REG_EXTENDED | REG_NOSUB);
  regcomp(&socket_pattern2, "[0000]:.*", REG_EXTENDED | REG_NOSUB);
  DIR *dir = opendir("/proc");
  if (dir == NULL) {
    printf("Read /proc error");
    exit(0);
  }
  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL) {
    if (entry->d_type == DT_DIR) {
      char path[1024];
      if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 ||
          (!atoi(entry->d_name) && entry->d_name != "0")) {
        continue;
      }
      snprintf(path, sizeof(path), "%s/%s/%s", "/proc", entry->d_name, "fd");
      /*printf("%s\n", path);*/
      struct dirent *subfile;
      DIR *path_dir = opendir(path);
      if (path_dir == NULL) {
        break;
      }
      while ((subfile = readdir(path_dir)) != NULL) {
        if (strcmp(subfile->d_name, ".") == 0 ||
            strcmp(subfile->d_name, "..") == 0) {
          continue;
        }
        char soft[1024];
        char sub_path[1024];
        snprintf(sub_path, sizeof(sub_path), "%s/%s/%s/%s", "/proc",
                 entry->d_name, "fd", subfile->d_name);
        readlink(sub_path, soft, sizeof(soft));
        if (!regexec(&socket_pattern1, soft, 0, NULL, REG_NOTBOL)) {
          int socket_num = string2int(soft + 8);
          dump_proc(proc, socket_num, string2int(entry->d_name));
        } else if (!regexec(&socket_pattern2, soft, 0, NULL, REG_NOTBOL)) {
          int socket_num = string2int(soft + 7);
          dump_proc(proc, socket_num, string2int(entry->d_name));
        }
      }
      closedir(path_dir);
    }
  }
  closedir(dir);
  return;
}

int main(int argc, char *argv[]) {
  int ch;
  int option_idx;
  while ((ch = getopt_long(argc, argv, "tu", long_optinos, &option_idx)) !=
         -1) {
    printf("%d", ch);
    switch (ch) {
    case 't':
      printf("t");
      tcp = 1;
      break;
    case 'u':
      printf("u");
      udp = 1;
      break;
    case 0:
      if (strcmp(long_optinos[option_idx].name, "tcp") == 0) {
        tcp = 1;
      } else if (strcmp(long_optinos[option_idx].name, "udp") == 0) {
        udp = 1;
      } else {
        helper();
      }
      break;
    case '?':
      helper();
      break;
    default:
      helper();
    }
  }
  if (optind < argc) {
    printf("1\n");
    regcomp(&grep_pattern, argv[optind],
            REG_EXTENDED | REG_NOSUB | REG_NEWLINE);
    printf("%s\n", argv[optind]);
  } else {
    printf("2\n");
    regcomp(&grep_pattern, ".*", REG_EXTENDED | REG_NOSUB | REG_NEWLINE);
  }
  if (!tcp && !udp) {
    tcp = 1;
    udp = 1;
  }
  if (tcp) {
    printf("List of TCP connections:\n");
    printf("%s\t%-35s\t%-35s\t%s\n", "Proto", "Local Address",
           "Foreign Address", "PID/Program name and arguments");
    trivase_pid("tcp");
    trivase_pid("tcp6");
  }
  if (udp) {
    printf("\nList of UDP connections:\n");
    printf("%s\t%-35s\t%-35s\t%s\n", "Proto", "Local Address",
           "Foreign Address", "PID/Program name and arguments");
    trivase_pid("udp");
    trivase_pid("udp6");
  }
  regfree(&socket_pattern1);
  regfree(&socket_pattern2);
  regfree(&grep_pattern);
}
