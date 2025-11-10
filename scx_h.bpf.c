#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

// =======================================================
// DEFINES
// =======================================================

#define NUM_HEAPS 1
#define MY_SLICE ((__u64)4 * 1000000) // 4ms

// =======================================================
// DATA STRUCTURES
// =======================================================

struct cgroup_info {

    u32 group_id;          // group id
    u32 num_threads;       // total number of threads in group
    u32 threads_queued;    // number of runnable but waiting threads
    u32 weight;            // group weight
};

// =======================================================
// MAPS
// =======================================================

/* Map of cgroup groups */
struct {
    __uint(type, BPF_MAP_TYPE_CGRP_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct cgroup_info);
} cgroup_info SEC(".maps");

// =======================================================
// HELPER FUNCTIONS
// =======================================================

static __always_inline __u64 safe_div_u64(__u64 a, __u64 b)
{
    if (b == 0)
        return (u64)-1;
    return a / b;
}

static s64 signed_div(s64 a, s64 b) { 
    bool aneg = a < 0; 
    bool bneg = b < 0; 
    // get the absolute positive value of both 
    u64 adiv = aneg ? -a : a; 
    u64 bdiv = bneg ? -b : b; 
    // Do udiv 
    u64 out = safe_div_u64(adiv, bdiv);
    // Make output negative if one or the other is negative, not both 
    return aneg != bneg ? -out : out; 
}

/* Helper functions for active groups management */

static struct cgroup_info *get_cgroup_info(struct cgroup *cgrp)
{
    return bpf_cgrp_storage_get(&cgroup_info, cgrp, 0, 0);
}

// =======================================================
// BPF OPS
// =======================================================

s32 BPF_STRUCT_OPS(h_init_task, struct task_struct *p, struct scx_init_task_args *args)
{
    struct cgroup_info *gi;
    struct cgroup *cgrp = args->cgroup;
    
    // group should already exist
    gi = get_cgroup_info(cgrp);
    if (!gi)
        return -1;
    
    gi->threads_queued += 1;
    gi->num_threads += 1;
    
    return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(h_cgroup_init, struct cgroup *cgrp, struct scx_cgroup_init_args *args)
{
    struct cgroup_info *gi;
    
    gi = bpf_cgrp_storage_get(&cgroup_info, cgrp, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!gi)
        return -ENOMEM;
    
    // everything else is initialized to 0
    gi->group_id = cgrp->kn->id;
    gi->weight = args->weight == 0 ? 1 : args->weight;
    gi->num_threads = 0;
    gi->threads_queued = 0;
    
    return 0;
}

void BPF_STRUCT_OPS(h_cgroup_set_weight, struct cgroup *cgrp, u32 weight)
{
    struct cgroup_info *gi;
    gi = get_cgroup_info(cgrp);
    if (!gi) {
        bpf_printk("ERROR: No group info for cgroup %d?", cgrp->kn->id);
        return;
    }

    // TODO: this is a re-weight? We don't know what to do here yet
    gi->weight = weight;
}

void BPF_STRUCT_OPS(h_cgroup_move, struct task_struct *p, struct cgroup *from, struct cgroup *to)
{
    struct cgroup_info *from_gi, *to_gi;
    from_gi = get_cgroup_info(from);
    to_gi = get_cgroup_info(to);
    if (!from_gi || !to_gi) {
        bpf_printk("ERROR: No group info for cgroup %d or %d?", from->kn->id, to->kn->id);
        return;
    }

    // TODO: check if the thread has to be de-qed/re-enqed anyway
    //  if yes, the below is incorrect, or if we also need a way to re-weight this p
    from_gi->num_threads -= 1;
    to_gi->num_threads += 1;
}

void BPF_STRUCT_OPS(h_enqueue, struct task_struct *p, u64 enq_flags)
{
    struct cgroup_info *gi;
    struct cgroup *cgrp = scx_bpf_task_cgroup(p);
    
    if (!cgrp) {
        if (cgrp) bpf_cgroup_release(cgrp);
        return;
    }
    
    gi = get_cgroup_info(cgrp);
    if (!gi) {
        bpf_cgroup_release(cgrp);
        return;
    }
        
    u64 vt_account_existing = (MY_SLICE / gi->weight) * gi->threads_queued;
    
    gi->threads_queued++;
    
    // pick a random dsq
    // peek it's min
    u32 dsq_id = bpf_get_prandom_u32() % NUM_HEAPS;
    s64 curr_min = scx_bpf_dsq_peek_head_vtime(dsq_id);
    if (curr_min < 0) {
        curr_min = 0;
    }
    if (bpf_get_smp_processor_id() == 4) { 
        bpf_printk("ENQ: p=%d, new_vrt=%llu, curr_min=%lld, threads_queued=%lu, weight=%llu", p->pid,  vt_account_existing + (u64)curr_min, curr_min, gi->threads_queued, gi->weight);
    }
    p->scx.dsq_vtime = vt_account_existing + (u64)curr_min;
    p->scx.slice = MY_SLICE;

    // TODO: if it is less than the min, find a cpu running something with less weight to kick

    scx_bpf_dsq_insert_vtime(p, dsq_id, MY_SLICE, p->scx.dsq_vtime, enq_flags);
    
    bpf_cgroup_release(cgrp);
}

void BPF_STRUCT_OPS(h_quiescent, struct task_struct *p, u64 deq_flags)
{
    struct cgroup_info *gi;
    struct cgroup *cgrp = scx_bpf_task_cgroup(p);
    if (!cgrp) {
        if (cgrp) bpf_cgroup_release(cgrp);
        return;
    }
    gi = get_cgroup_info(cgrp);
    if (!gi) {
        bpf_cgroup_release(cgrp);
        return;
    }
    
    // Update group queued count
    if (gi->num_threads > 0) {
        gi->num_threads--;
    } else {
        if (bpf_get_smp_processor_id() == 4) { 
            bpf_printk("ERROR: num_threads is 0 but now task %d is blocking cgrp %d\n", p->pid, cgrp->kn->id);
        }
    }
    

    // hmmm we don't know what heap it was on
    // TODO: FOR NOW just pick a random heap and use its min
    u32 dsq_id = bpf_get_prandom_u32() % NUM_HEAPS;
    s64 curr_min = scx_bpf_dsq_peek_head_vtime(dsq_id);
    if (curr_min < 0) {
        curr_min = 0;
    }
    // this check is needed because p is not on the dsq
    if (curr_min > p->scx.dsq_vtime) {
        curr_min = p->scx.dsq_vtime;
    }
    p->scx.dsq_vtime -= curr_min;
    if (bpf_get_smp_processor_id() == 4) { 
        bpf_printk("QUIESC: p=%d, curr_min=%llu, lag_vtime=%llu", p->pid, curr_min, p->scx.dsq_vtime);
    }
    bpf_cgroup_release(cgrp);
}

struct min_dsq_info {
    int id;
    u64 vtime;
};

static void pick_min_heap(u64 prev_vtime, struct min_dsq_info *result) {
    int curr_min_heap = -1;
    u64 curr_min_vt = prev_vtime; // max int
    
    // Iterate through active groups to find minimum
    for (u32 i = 0; i < 2; i++) {
        
        u64 dsq_id = bpf_get_prandom_u32() % NUM_HEAPS; // TODO: do we want to guard against having the same number twice?
        s64 heap_min = scx_bpf_dsq_peek_head_vtime(dsq_id);
        if (heap_min < 0) {
            continue; // the dsq has no tasks
        }
        
        // Check if this group has the minimum spec_virt_time
        if (heap_min < curr_min_vt) {
            if (bpf_get_smp_processor_id() == 4) {
                bpf_printk("PICK: min_heap=%d, nr_queued=%ld, vrt=%llu", dsq_id, scx_bpf_dsq_nr_queued(dsq_id), heap_min);
            }
            curr_min_heap = dsq_id;
            curr_min_vt = heap_min;
        }
    }
    
    result->id = curr_min_heap;
    result->vtime = curr_min_vt;
}


void BPF_STRUCT_OPS(h_dispatch, s32 cpu, struct task_struct *prev)
{
    u64 dsq_id = 0;
    if (bpf_get_smp_processor_id() == 4) {
        bpf_printk("PICK: prev=%d, prev_vrt=%lld, nr_queued=%d (id=%d)", prev ? prev->pid : -1, prev ? prev->scx.dsq_vtime : -1, scx_bpf_dsq_nr_queued(dsq_id), dsq_id);
    }
    if (prev && (prev->scx.flags & SCX_TASK_QUEUED)) { // have a previous, and it is on the rq
        s64 prev_time_used = MY_SLICE - prev->scx.slice;
        u64 prev_task_vtime = prev->scx.dsq_vtime + signed_div(prev_time_used, prev->scx.weight); // TODO: using task weight here, not group weight. wld need to set


        struct min_dsq_info min_heap;
        pick_min_heap(~(0ULL), &min_heap);
        if (min_heap.id < 0) {
            return;
        }
        if (prev_task_vtime < min_heap.vtime) {
            if (bpf_get_smp_processor_id() == 4) {  
                bpf_printk("  prev was better: prev=%d, flags=%x (queud: %d), saved_vt=%llu, weight=%lu, time_used=%llu, full_vtime=%llu", prev->pid, prev->scx.flags, prev->scx.flags & SCX_TASK_QUEUED, prev->scx.dsq_vtime, prev->scx.weight, prev_time_used, prev_task_vtime);
            }
            prev->scx.dsq_vtime = prev_task_vtime;
            // I guess I don't need to manually reset the slice? TODO: rn it's not scheduling often enough anyway, I need to look into that
            return;
        }
        scx_bpf_dsq_move_to_local(min_heap.id);
        return;
    }

    if (bpf_get_smp_processor_id() == 4) {
        bpf_printk(" no prev");
    }
    // no previous thing
    struct min_dsq_info min_heap;
    pick_min_heap(~(0ULL), &min_heap);
    
    if (min_heap.id < 0) {
        // go idle
        return;
    }

   scx_bpf_dsq_move_to_local(min_heap.id);
}

// I *think* this is where we want to add/track the vtime, but I'm not 100% sure
void BPF_STRUCT_OPS(h_stopping, struct task_struct *p, bool runnable)
{
    struct cgroup_info *gi;
    struct cgroup *cgrp = __COMPAT_scx_bpf_task_cgroup(p);
    
    if (!cgrp) {
        if (cgrp) bpf_cgroup_release(cgrp);
        return;
    }
    
    gi = get_cgroup_info(cgrp);
    if (!gi) {
        bpf_cgroup_release(cgrp);
        return;
    }
    
    s64 time_used = MY_SLICE - p->scx.slice; // time left is kept in p->scx.slice
    p->scx.dsq_vtime += signed_div(time_used, gi->weight);
    if (bpf_get_smp_processor_id() == 4) { 
        bpf_printk("STOP: p=%d, time_used=%lld, weight=%llu, vtime_diff=%lld, new_vtime=%llu", p->pid, time_used, gi->weight, signed_div(time_used, gi->weight), p->scx.dsq_vtime);
    }

    u32 dsq_id = bpf_get_prandom_u32() % NUM_HEAPS;
    // scx_bpf_dsq_insert_vtime(p, dsq_id, MY_SLICE, p->scx.dsq_vtime, enq_flags);
    bpf_cgroup_release(cgrp);
}

void BPF_STRUCT_OPS(h_running, struct task_struct *p)
{
    struct cgroup_info *gi;
    struct cgroup *cgrp = __COMPAT_scx_bpf_task_cgroup(p);
    
    if (!cgrp) {
        if (cgrp) bpf_cgroup_release(cgrp);
        return;
    }
    
    gi = get_cgroup_info(cgrp);
    if (!gi) {
        bpf_cgroup_release(cgrp);
        return;
    }

    // if (gi->threads_queued == 0) {
    //     bpf_printk("ERROR: dec threads_queued in running, but already 0");
    // } else {
    //     gi->threads_queued -= 1;
    // }
    
    if (bpf_get_smp_processor_id() == 4) { 
        bpf_printk("RUN: p=%d", p->pid);
    }
    bpf_cgroup_release(cgrp);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(h_init)
{
    // Initialize active groups map (all entries start as 0)
    // No explicit initialization needed for array maps
    for (int i=0; i < NUM_HEAPS; i++) {
        scx_bpf_create_dsq(i, -1);
    }
    return 0;
}

void BPF_STRUCT_OPS(h_exit, struct scx_exit_info *ei)
{
    UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(h_ops,
        .init_task		= (void *)h_init_task,
        // .select_cpu		= (void *)h_select_cpu,
        .enqueue		= (void *)h_enqueue,
        // .runnable		= (void *)h_runnable,
        .dispatch		= (void *)h_dispatch,
        .running		= (void *)h_running,
        .stopping		= (void *)h_stopping,
        .quiescent		= (void *)h_quiescent,
        // .exit_task		= (void *)h_exit_task,
        // .enable			= (void *)h_enable,
        // .disable		= (void *)h_disable,
        .cgroup_init		= (void *)h_cgroup_init,
        .cgroup_set_weight	= (void *)h_cgroup_set_weight,
        .cgroup_move		= (void *)h_cgroup_move,
        .init			= (void *)h_init,
        .exit			= (void *)h_exit,
        .flags			= SCX_OPS_HAS_CGROUP_WEIGHT | SCX_OPS_ENQ_EXITING,
        .name			= "h");
