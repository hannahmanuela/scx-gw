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

namespace {

bool setAffinityToCpu(int cpuIndex) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpuIndex, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        std::perror("sched_setaffinity");
        return false;
    }
    return true;
}

bool createCgroup(const std::string& cgroupName) {
    std::string cgroupPath = "/sys/fs/cgroup/" + cgroupName;
    
    // Create the cgroup directory
    if (mkdir(cgroupPath.c_str(), 0755) != 0 && errno != EEXIST) {
        std::perror(("mkdir " + cgroupPath).c_str());
        return false;
    }
    
    return true;
}

bool setCgroupWeight(const std::string& cgroupName, int weight) {
    std::string weightPath = "/sys/fs/cgroup/" + cgroupName + "/cpu.weight";
    
    std::ofstream weightFile(weightPath);
    if (!weightFile.is_open()) {
        std::perror(("open " + weightPath).c_str());
        return false;
    }
    
    weightFile << weight << std::endl;
    weightFile.close();
    
    if (weightFile.fail()) {
        std::perror(("write " + weightPath).c_str());
        return false;
    }
    
    return true;
}

bool addProcessToCgroup(const std::string& cgroupName, pid_t pid) {
    std::string procsPath = "/sys/fs/cgroup/" + cgroupName + "/cgroup.procs";
    
    std::ofstream procsFile(procsPath);
    if (!procsFile.is_open()) {
        std::perror(("open " + procsPath).c_str());
        return false;
    }
    
    procsFile << pid << std::endl;
    procsFile.close();
    
    if (procsFile.fail()) {
        std::perror(("write " + procsPath).c_str());
        return false;
    }
    
    return true;
}

bool removeCgroup(const std::string& cgroupName) {
    std::string cgroupPath = "/sys/fs/cgroup/" + cgroupName;
    
    // Remove the cgroup directory
    if (rmdir(cgroupPath.c_str()) != 0 && errno != ENOENT) {
        std::perror(("rmdir " + cgroupPath).c_str());
        return false;
    }
    
    return true;
}

double timespecToSec(const timespec &ts) {
    return static_cast<double>(ts.tv_sec) + static_cast<double>(ts.tv_nsec) / 1e9;
}

struct CpuAndWall {
    double cpuSec;
    double wallSec;
};

CpuAndWall sampleCpuAndWall() {
    timespec cpuTs{};
    timespec wallTs{};
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpuTs);
    clock_gettime(CLOCK_MONOTONIC, &wallTs);
    return {timespecToSec(cpuTs), timespecToSec(wallTs)};
}

volatile unsigned long long sink = 0; // prevents optimization

// Global variables for cleanup
pid_t g_childLow = 0;
pid_t g_childHigh = 0;

void cleanupAndExit(int sig) {
    std::cout << "\nCleaning up cgroups and exiting...\n";
    
    // Kill children first
    if (g_childLow > 0) {
        kill(g_childLow, SIGTERM);
    }
    if (g_childHigh > 0) {
        kill(g_childHigh, SIGTERM);
    }
    
    // Wait a bit for children to exit
    usleep(500000); // 500ms
    
    // Remove cgroups
    // removeCgroup("low_weight");
    // removeCgroup("high_weight");
    
    exit(0);
}

void runBusyAndReport(const std::string &label) {
    // Pin to CPU 0
    // setAffinityToCpu(CPU_NUM);

    // Initial samples
    CpuAndWall prev = sampleCpuAndWall();

    // Busy work + once-per-second reporting
    while (true) {
        // Busy loop chunk
        for (int i = 0; i < 50'000; ++i) {
            sink += static_cast<unsigned long long>(i);
        }

        CpuAndWall now = sampleCpuAndWall();
        double dCpu = now.cpuSec - prev.cpuSec;
        double dWall = now.wallSec - prev.wallSec;

        if (dWall >= 1.0) {
            double pct = (dCpu / dWall) * 100.0;
            std::cout << "PID=" << getpid() << " [" << label << "] CPU="
                      << pct << "% over last ~" << dWall << "s\n";
            std::cout.flush();
            prev = now;
        } 
        // else {
            // Sleep a bit to aim for ~1s cadence, while still staying CPU-bound overall
            // struct timespec req { 0, 50 * 1000 * 1000 }; // 50ms
            // nanosleep(&req, nullptr);
        // }
    }
}

}

int main() {
    // Set up signal handler for cleanup
    signal(SIGINT, cleanupAndExit);
    signal(SIGTERM, cleanupAndExit);
    
    // Parent will create two children; both children will run indefinitely
    pid_t childLow = fork();
    if (childLow < 0) {
        std::perror("fork low");
        return 1;
    }

    if (childLow == 0) {
        // Low weight: cgroup with weight 1
        if (!createCgroup("low_weight")) {
            std::cerr << "PID=" << getpid() << ": failed to create low_weight cgroup.\n";
            return 1;
        }
        if (!setCgroupWeight("low_weight", 1)) {
            std::cerr << "PID=" << getpid() << ": failed to set cgroup weight to 1.\n";
            return 1;
        }
        if (!addProcessToCgroup("low_weight", getpid())) {
            std::cerr << "PID=" << getpid() << ": failed to add process to low_weight cgroup.\n";
            return 1;
        }

        runBusyAndReport("idle");
        return 0;
    }

    pid_t childHigh = fork();
    if (childHigh < 0) {
        std::perror("fork high");
        return 1;
    }

    if (childHigh == 0) {
        // High weight: cgroup with weight 100
        if (!createCgroup("high_weight")) {
            std::cerr << "PID=" << getpid() << ": failed to create high_weight cgroup.\n";
            return 1;
        }
        if (!setCgroupWeight("high_weight", 100)) {
            std::cerr << "PID=" << getpid() << ": failed to set cgroup weight to 100.\n";
            return 1;
        }
        if (!addProcessToCgroup("high_weight", getpid())) {
            std::cerr << "PID=" << getpid() << ": failed to add process to high_weight cgroup.\n";
            return 1;
        }
        
        runBusyAndReport("normal");
        return 0;
    }

    // Store child PIDs for cleanup
    g_childLow = childLow;
    g_childHigh = childHigh;
    
    // Parent: ensure both children share the same CPU as well (optional)
    // setAffinityToCpu(CPU_NUM);

    std::cout << "Spawned children PIDs: low=" << childLow << ", high=" << childHigh
              << ". Both pinned to CPU " << CPU_NUM << ". Press Ctrl+C to stop.\n";
    std::cout.flush();

    // Wait forever (children run until killed)
    // Reap children on exit
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


