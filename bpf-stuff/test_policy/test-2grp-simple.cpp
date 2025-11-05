#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iostream>
#include <string>
#include <thread>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <errno.h>

#define CPU_NUM 4

#define SCHED_GLOBAL_WEIGHT 4

volatile unsigned long long sink = 0; // prevents optimization

int main() {

    struct sched_param sp = { .sched_priority = 0 };
    if (sched_setscheduler(0, SCHED_GLOBAL_WEIGHT, &sp) == -1) {
        perror("sched_setscheduler");
        return 1;
    }
    
    // Parent will create two children; both children will run indefinitely
    pid_t childLow = fork();
    if (childLow < 0) {
        std::perror("fork low");
        return 1;
    }

    if (childLow == 0) {
        for (int i = 0; i < 50'000; ++i) {
            sink += static_cast<unsigned long long>(i);
        }
    }

    pid_t childHigh = fork();
    if (childHigh < 0) {
        std::perror("fork high");
        return 1;
    }

    if (childHigh == 0) {
        // High weight: cgroup with weight 100
        for (int i = 0; i < 50'000; ++i) {
            sink += static_cast<unsigned long long>(i);
        }
    }

    int status = 0;
    while (true) {
        pid_t done = waitpid(-1, &status, 0);
        if (done == -1) {
            std::perror("waitpid");
            break;
        }
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            std::cout << "Child " << done << " exited.\n";
            std::cout.flush();
        }
    }

    return 0;
}


