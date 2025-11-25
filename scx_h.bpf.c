#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

// =======================================================
// DEFINES
// =======================================================

#define NUM_HEAPS 1
#define MY_SLICE ((__u64)4 * 1000000) // 4ms
#define HWEIGHT_ONE 1LLU << 16 // copied over from flatcg

// used to see if a group's hweight has been updated since the last tree change
u64 hweight_gen = 1;

private(P_HEAP) struct bpf_spin_lock heap_lock;

// =======================================================
// DATA STRUCTURES
// =======================================================

struct cgroup_info {
    u32 group_id;       // group id
    u32 weight;         // group weight

    // used to calculate the extrapolated weight of nested cgroups
    u32 hweight;        
    u32 child_weight_sum;
    u64 hweight_gen;

    u32 nthreads;       // total number of active threads (includes queued and running)

    u64 vtime;          // group vtime
    u64 min_vtime_at_sleep;   // min vt at sleep time
};

struct task_info {
    u64 cgid;
    u64 time_started_running;

    bool runnable_enqed;
};

struct core_info {
    u32 weight_running;
    u32 vtime_running;
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
} cgroup_info_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, s64);
	__uint(max_entries, NUM_HEAPS);
} heap_min_vrt SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_info);
} task_info_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct core_info);
    __uint(max_entries, 1);
} core_info_map SEC(".maps");

// =======================================================
// HELPER FUNCTIONS
// =======================================================

static bool want_to_print()
{
    return false;
    // return true;
    // return bpf_get_smp_processor_id() == 2 || bpf_get_smp_processor_id() == 4;
    // return bpf_get_smp_processor_id() == 4;
    // return bpf_get_smp_processor_id() == 2 || bpf_get_smp_processor_id() == 4 || bpf_get_smp_processor_id() == 6 || bpf_get_smp_processor_id() == 8;
    // return bpf_get_smp_processor_id() == 4 || bpf_get_smp_processor_id() == 6 || bpf_get_smp_processor_id() == 8 || bpf_get_smp_processor_id() == 10;
}


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

static u64 div_round_up(u64 dividend, u64 divisor)
{
	return (dividend + divisor - 1) / divisor;
}

static inline u64 min(u64 a, u64 b)
{
	s64 delta = (s64)(b - a);
	if (delta < 0)
		a = b;
	return a;
}

/* Helper functions for active groups management */

static struct cgroup_info *get_cgroup_info(struct cgroup *cgrp)
{
    return bpf_cgrp_storage_get(&cgroup_info_map, cgrp, 0, 0);
}

// -1 for own core
struct core_info *get_core_info(s64 core_id)
{
    u64 zero = 0; 

    struct core_info *ci;
    if (core_id == -1) {
        ci = bpf_map_lookup_elem(&core_info_map, &zero);
    } else {
        ci = bpf_map_lookup_percpu_elem(&core_info_map, &zero, core_id);
    }
    return ci;
}

static s32 get_cpu_running_min_weight(u64 new_weight, const struct cpumask *task_cpumask)
{
    u64 zero = 0;
    u64 min_weight = new_weight;

    s32 cpu_w_min_weight = -1;
    u64 max_vtime_running = 0;

    int i = 0;
    u32 nr_cpu_ids = scx_bpf_nr_cpu_ids();
    struct core_info *ci;
    bpf_for(i, 0, nr_cpu_ids) {
        if (!bpf_cpumask_test_cpu(i, task_cpumask)) {
            continue;
        }
        ci = get_core_info(i);
        if (ci && 
            ((ci->weight_running < min_weight) || 
            (ci->weight_running == min_weight && ci->vtime_running > max_vtime_running))) {
            cpu_w_min_weight = i;
            min_weight = ci->weight_running;
            max_vtime_running = ci->vtime_running;
        }
    }

    return cpu_w_min_weight;
    
}

static int init_task_info(struct task_struct *p, struct cgroup_info *gi)
{
    struct task_info *task_info = bpf_task_storage_get(&task_info_map, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!task_info)
        return -ENOMEM;
    task_info->cgid = gi->group_id;
    task_info->time_started_running = 0;
    task_info->runnable_enqed = 0;
    return 0;
}

static struct task_info *get_task_info(struct task_struct *p)
{
    return bpf_task_storage_get(&task_info_map, p, 0, 0);
}


static u64 adjusted_grp_vtime(struct cgroup_info *gi, s64 time_passed)
{
    if (time_passed < 0) {
        return gi->vtime;
    }
    u64 weighted_time_passed = signed_div(time_passed, gi->hweight);
    u64 expected = safe_div_u64(MY_SLICE, gi->hweight);
    if (weighted_time_passed < expected) {
        s64 diff = (s64)expected - (s64)weighted_time_passed;
        if (want_to_print()) bpf_printk("ADJ: %d og_vtime=%llu, (sub)diff=%lld", gi->group_id, gi->vtime, diff);
        return gi->vtime - diff;
    } else {
        s64 diff = (s64)weighted_time_passed - (s64)expected;
        if (want_to_print()) bpf_printk("ADJ: %d og_vtime=%llu, (add)diff=%lld", gi->group_id, gi->vtime, diff);
        return gi->vtime + diff;
    }
    return gi->vtime;
}

static struct cgroup_info *get_ancestor_cgroup_info(struct cgroup *cgrp, int level)
{
	struct cgroup_info *cgi;

	cgrp = bpf_cgroup_ancestor(cgrp, level);
	if (!cgrp) {
		scx_bpf_error("ancestor cgroup lookup failed");
		return NULL;
	}

	cgi = get_cgroup_info(cgrp);
	if (!cgi)
		scx_bpf_error("ancestor cgrp_ctx lookup failed");
	bpf_cgroup_release(cgrp);
	return cgi;
}

// checks/updates a groups hweight
static void refresh_cgrp_hweight(struct cgroup *cgrp, struct cgroup_info *gi) {

    if (gi->hweight_gen == hweight_gen) return;

    int level;

	bpf_for(level, 0, cgrp->level + 1) {
		struct cgroup_info *gi;
		bool is_active;

		gi = get_ancestor_cgroup_info(cgrp, level);
		if (!gi)
			break;

		if (!level) {
            // root cg
			gi->hweight = HWEIGHT_ONE;
		} else {
			struct cgroup_info *par_gi;

			par_gi = get_ancestor_cgroup_info(cgrp, level - 1);
			if (!par_gi)
				break;

            gi->hweight_gen = par_gi->hweight_gen;
            gi->hweight = div_round_up(par_gi->hweight * gi->weight,
                            par_gi->child_weight_sum);

		}
	}

}

// when a group is added, propagates the weight change up the tree
static void update_tree_weight_sums(struct cgroup *cgrp)
{
	struct cgroup_info *gi;
	bool updated = false;
	int idx;

	gi = get_cgroup_info(cgrp);
	if (!gi)
		return;

    // add the new weight to add the "child_weight_sum"s in the tree above the new group
	bpf_for(idx, 0, cgrp->level) {
		int level = cgrp->level - idx;
		struct cgroup_info *gi, *par_gi = NULL;
		bool propagate = false;

		gi = get_ancestor_cgroup_info(cgrp, level);
		if (!gi)
			break;
		if (level) {
			par_gi = get_ancestor_cgroup_info(cgrp, level - 1);
			if (!par_gi)
				break;
		}

        if (par_gi) {
            par_gi->child_weight_sum += gi->weight;
        }
	}

	__sync_fetch_and_add(&hweight_gen, 1);
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
    
    bpf_printk("init_task: pid=%d, gid=%d, grp_w=%lu", p->pid, gi->group_id, gi->weight);
    
    return init_task_info(p, gi);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(h_cgroup_init, struct cgroup *cgrp, struct scx_cgroup_init_args *args)
{
    struct cgroup_info *gi;
    
    gi = bpf_cgrp_storage_get(&cgroup_info_map, cgrp, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!gi)
        return -ENOMEM;
    
    // everything else is initialized to 0
    gi->group_id = cgrp->kn->id;
    gi->weight = args->weight;
    gi->hweight = HWEIGHT_ONE;
    gi->nthreads = 0;
    gi->vtime = 0;
    gi->min_vtime_at_sleep = 0;

    update_tree_weight_sums(cgrp);
    
    return 0;
}


void BPF_STRUCT_OPS(h_cgroup_set_weight, struct cgroup *cgrp, u32 weight)
{
    struct cgroup_info *gi, *par_gi = NULL;
    gi = get_cgroup_info(cgrp);
    if (!gi) {
        bpf_printk("ERROR: No group info for cgroup %d?", cgrp->kn->id);
        return;
    }

    if (cgrp->level) {
		par_gi = get_ancestor_cgroup_info(cgrp, cgrp->level - 1);
		if (!par_gi)
			return;
	}

	if (par_gi)
		par_gi->child_weight_sum += (s64)weight - gi->weight;
	gi->weight = weight;

    __sync_fetch_and_add(&hweight_gen, 1);

}

// if the process was queued it got deqed before this and will be re-enqueued after, 
//   if it was running it got put_prev before and will be set_next
void BPF_STRUCT_OPS(h_cgroup_move, struct task_struct *p, struct cgroup *from, struct cgroup *to)
{
    struct cgroup_info *from_gi, *to_gi;
    from_gi = get_cgroup_info(from);
    to_gi = get_cgroup_info(to);
    if (!from_gi || !to_gi) {
        bpf_printk("ERROR: No group info for cgroup %d or %d?", from->kn->id, to->kn->id);
        return;
    }

    // refresh so that the weight we use below is correct
    refresh_cgrp_hweight(to, to_gi);
    
    struct task_info *ti = get_task_info(p);
    if (!ti) {
        scx_bpf_error("task_info lookup failed");
        return;
    }
    
    ti->cgid = to_gi->group_id;

    if (want_to_print()) bpf_printk("cgroup_move: pid=%d, new_grp=%d, new_grp_w=%lu", p->pid, to->kn->id, to_gi->hweight);

}

void BPF_STRUCT_OPS(h_runnable, struct task_struct *p, u64 enq_flags)
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

    struct task_info *ti = get_task_info(p);
    if (!ti) {
        bpf_cgroup_release(cgrp);
        return;
    }

    // refresh so that the weight we use below is correct
    refresh_cgrp_hweight(cgrp, gi);

    if (want_to_print()) bpf_printk("runnable: pid=%d, gid=%d, flags=%x", p->pid, cgrp->kn->id, enq_flags);

    // ENQUEUE_RESTORE is 0x02
    // "Restoring a running task will be immediately followed by set_next_task_scx()"

    // if ((enq_flags & 0x02) || (enq_flags & 0x01)) {
    // somehow this means that there won't be an enqueue after?
    u32 old_nt = __sync_fetch_and_add(&gi->nthreads, 1);

    u32 dsq_id = 0;
    s64 curr_min = scx_bpf_dsq_peek_head_vtime(dsq_id);
    if (curr_min < 0) {
        curr_min = 0;
    }

    if (old_nt == 0) {
        u64 lag = gi->vtime - gi->min_vtime_at_sleep;
        if (lag > curr_min) {
            lag += gi->min_vtime_at_sleep - curr_min;
        }
        if (want_to_print()) bpf_printk("(runnable)enqueue waking grp: pid=%d, curr_min=%llu, old_vt=%llu, min_vt_sleep=%llu, lag=%llu", p->pid, curr_min, gi->vtime, gi->min_vtime_at_sleep, lag);
        // u64 lag = 0;
        gi->vtime = curr_min + lag;
    }

    p->scx.dsq_vtime = gi->vtime;
    p->scx.slice = MY_SLICE;

    u64 weighted_tick = (MY_SLICE / gi->hweight);
    u64 new_grp_vt = __sync_add_and_fetch(&gi->vtime, weighted_tick);

    ti->runnable_enqed = 1;

    if (want_to_print()) bpf_printk("(runnable)enqueue: pid=%d, gid=%d, flags=%x, grp_w=%llu, new_nt=%d, new_grp_vt=%llu, p_vt=%llu", p->pid, cgrp->kn->id, enq_flags, gi->hweight, old_nt +1, new_grp_vt, p->scx.dsq_vtime);

    // }
    
    s32 core_to_kick = get_cpu_running_min_weight(gi->hweight, p->cpus_ptr);
    if (core_to_kick > 0) {
        scx_bpf_kick_cpu((u32)core_to_kick, SCX_KICK_PREEMPT);
    }

    
    bpf_cgroup_release(cgrp);
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

    // refresh so that the weight we use below is correct
    refresh_cgrp_hweight(cgrp, gi);

    u32 dsq_id = 0;

    struct task_info *ti = get_task_info(p);
    if (!ti) {
        scx_bpf_error("task_ctx lookup failed");
        bpf_cgroup_release(cgrp);
        return;
    }

    if (ti->runnable_enqed) {
        if (want_to_print()) bpf_printk("enq %d, skipping b/c runnable enqueued", p->pid);
        scx_bpf_dsq_insert_vtime(p, dsq_id, MY_SLICE, p->scx.dsq_vtime, enq_flags);
        bpf_cgroup_release(cgrp);
        return;
    }

    u32 old_nt = gi->nthreads;
    u32 new_nt = gi->nthreads;
    if (enq_flags) {
        if (want_to_print()) bpf_printk("enq %d is new", p->pid);
        old_nt = __sync_fetch_and_add(&gi->nthreads, 1);
        new_nt = old_nt + 1;
    } else {
        // if nthreads is 0 here, that means we did something wrong -- a task is not waking up, but was dequeued
        if (old_nt == 0) {
            bpf_printk("ERROR?? nT is 0 in enq for grp %d, but flags are %x", gi->group_id, enq_flags);
        }
    }

    s64 curr_min = scx_bpf_dsq_peek_head_vtime(dsq_id);
    if (curr_min < 0) {
        curr_min = 0;
    }

    if (old_nt == 0) {
        u64 lag = gi->vtime - gi->min_vtime_at_sleep;
        if (gi->min_vtime_at_sleep > curr_min) {
            lag += gi->min_vtime_at_sleep - curr_min;
        }
        if (want_to_print()) bpf_printk("wake grp %d: vt=%llu, min_sleep_vt=%llu, curr_min=%llu, lag=%llu", gi->group_id, gi->vtime, gi->min_vtime_at_sleep, curr_min, lag);
        // u64 lag = 0;
        gi->vtime = curr_min + lag;
    }

    p->scx.dsq_vtime = gi->vtime;
    p->scx.slice = MY_SLICE;

    u64 weighted_tick = (MY_SLICE / gi->hweight);
    u64 new_grp_vt = __sync_add_and_fetch(&gi->vtime, weighted_tick);
        
    if (want_to_print()) bpf_printk("enqueue: pid=%d, gid=%d, flags=%x, grp_w=%llu, new_nt=%d, new_grp_vt=%llu, p_vt=%llu", p->pid, cgrp->kn->id, enq_flags, gi->hweight, new_nt, new_grp_vt, p->scx.dsq_vtime);    

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

    // quiesc is not called as part of the set_prev/put_next flow
    u32 new_nt = __sync_sub_and_fetch(&gi->nthreads, 1);

    u32 dsq_id = 0;
    s64 curr_min = scx_bpf_dsq_peek_head_vtime(dsq_id);
    if (curr_min < 0) {
        // because if the heap is empty then it was the min, want to remember that, rather than a "fake" min of 0
        // TODO: what if something enqueued in the middle? ie while the task was off b/c it was scheduled, some new task came in and now has a tiny vt
        curr_min = gi->vtime;
    }

    if (new_nt == 0) {
        gi->min_vtime_at_sleep = curr_min;
    }

    if (want_to_print()) bpf_printk("quiescent: pid=%d, gid=%d, flags=%x, new_nt=%llu, min_sleep=%llu, saved_vt=%llu", p->pid, cgrp->kn->id, deq_flags, new_nt, gi->min_vtime_at_sleep, gi->vtime);
    
    bpf_cgroup_release(cgrp);
}

struct min_dsq_info {
    int id;
    u64 vtime;
};

static void pick_min_heap(struct min_dsq_info *result) {
    int curr_min_heap = -1;
    u64 curr_min_vt = ~(0ULL);
        
    u64 dsq_id = 0;
    s64 heap_min = scx_bpf_dsq_peek_head_vtime(dsq_id);
    if (heap_min >= 0 && heap_min < curr_min_vt) {
        curr_min_heap = dsq_id;
        curr_min_vt = heap_min;
    }
    
    result->id = curr_min_heap;
    result->vtime = curr_min_vt;
}


void BPF_STRUCT_OPS(h_dispatch, s32 cpu, struct task_struct *prev)
{
    u64 dsq_id = 0;

    // pretty sure this is racy - we aren't locking it and so two threads can do this in lockstep
    // for now not a problem since we only have one heap
    struct min_dsq_info min_heap;
    pick_min_heap(&min_heap);

    // there is nothing on the q, keep running prev if possible (is automatic), else we have nothing to run
    if (min_heap.id < 0) {
        // if (want_to_print()) bpf_printk("dispatch: cpu=%ld, prev=%d, prev_queued=%d, heap_empty", cpu, prev ? prev->pid : -1, prev ? (prev->scx.flags & SCX_TASK_QUEUED) : 0);
        return;
    }

    if (prev && (prev->scx.flags & SCX_TASK_QUEUED)) { // have a previous, and it is on the rq

        struct task_info *prev_i = get_task_info(prev);
        if (!prev_i) 
            goto no_prev;

        struct cgroup_info *prev_gi;
        struct cgroup *cgrp = bpf_cgroup_from_id(prev_i->cgid);
        if (!cgrp) {
            if (cgrp) bpf_cgroup_release(cgrp);
            goto no_prev;
        }
        prev_gi = get_cgroup_info(cgrp);
        if (!prev_gi) {
            bpf_cgroup_release(cgrp);
            goto no_prev;
        }

        // refresh so that the weight we use below is correct
        refresh_cgrp_hweight(cgrp, prev_gi);

        // only actually advance the time if the process is chosen to run next, otherwise "stopping" will do that for us
        s64 prev_time_used = (s64)bpf_ktime_get_ns() - (s64)prev_i->time_started_running;

        u64 new_p_vt = adjusted_grp_vtime(prev_gi, prev_time_used);
        
        if (new_p_vt <= min_heap.vtime) {
            prev->scx.slice = MY_SLICE;

            u64 weighted_tick = (MY_SLICE / prev_gi->hweight);
            u64 new_grp_vt = new_p_vt + weighted_tick;
            __sync_lock_test_and_set(&prev_gi->vtime, new_grp_vt);

            // "running" is not called again, so time_started_running is never reset; do it here instead
            prev_i->time_started_running = bpf_ktime_get_ns();

            // effectively we are doing a yield->enqueue->pick, print that explicitly for cmp with spec
            if (want_to_print()) bpf_printk("(dispatch, using_prev)stopping: pid=%d, gid=%d, runnable=%d, time_used=%llu, grp_w=%lu, new_grp_vt=%llu", prev->pid, prev_gi->group_id, 1, prev_time_used, prev_gi->hweight, new_p_vt);
            if (want_to_print()) bpf_printk("(dispatch, using_prev)enqueue: pid=%d, gid=%d, flags=0, grp_w=%llu, new_nt=%d, new_grp_vt=%llu, p_vt=%llu", prev->pid, prev_gi->group_id, prev_gi->hweight, prev_gi->nthreads, new_grp_vt, new_p_vt);
            if (want_to_print()) bpf_printk("(dispatch, using_prev)running: pid=%d, gid=%d, ts=%llu, grp_w=%lu", prev->pid, prev_gi->group_id, prev_i->time_started_running, prev_gi->hweight);

            bpf_cgroup_release(cgrp);
            return;
        }
        bpf_cgroup_release(cgrp);

        if (want_to_print()) bpf_printk("dispatch: cpu=%ld, prev=%d, pot_new_vt=%llu, curr_min=%llu, pulling_from_heap", cpu, prev->pid, new_p_vt, min_heap.vtime);

        scx_bpf_dsq_move_to_local(min_heap.id);
        return;
    }

no_prev:
    // if (want_to_print()) bpf_printk("dispatch: cpu=%ld, prev=-1, prev_queued=0, pulling_from_heap", cpu);
    scx_bpf_dsq_move_to_local(min_heap.id);
}

void BPF_STRUCT_OPS(h_stopping, struct task_struct *p, bool runnable)
{
    struct task_info *ti = get_task_info(p);
    if (!ti) {
        return;
    }

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

    // refresh so that the weight we use below is correct
    refresh_cgrp_hweight(cgrp, gi);

    if (p->scx.slice > 0 && runnable) {
        // it was just interrupted by a higher order process, and will keep running anyway (see comment in put_prev_task_scx in ext.c)
        bpf_cgroup_release(cgrp);
        return;
    }

    s64 time_used = (s64)bpf_ktime_get_ns() - (s64)ti->time_started_running;
    gi->vtime = adjusted_grp_vtime(gi, time_used);

    if (want_to_print()) bpf_printk("stopping: pid=%d, gid=%d, runnable=%d, time_used=%llu, grp_w=%lu, new_grp_vt=%llu", p->pid, cgrp->kn->id, runnable, time_used, gi->hweight, gi->vtime);

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

    // refresh so that the weight we use below is correct
    refresh_cgrp_hweight(cgrp, gi);

    struct task_info *ti = get_task_info(p);
    if (!ti) {
        scx_bpf_error("task_ctx lookup failed");
        bpf_cgroup_release(cgrp);
        return;
    }
    ti->time_started_running = bpf_ktime_get_ns();
    
    ti->runnable_enqed = 0;

    struct core_info *ci = get_core_info(-1);
    if (ci) {
        ci->vtime_running = p->scx.dsq_vtime;
        ci->weight_running = gi->hweight;
    }

    if (want_to_print()) bpf_printk("running: pid=%d, gid=%d, ts=%llu, grp_w=%lu", p->pid, cgrp->kn->id, ti->time_started_running, gi->hweight);

    bpf_cgroup_release(cgrp);
}

void BPF_STRUCT_OPS(h_tick, struct task_struct *p)
{
    if (want_to_print()) bpf_printk("tick: pid=%d", p->pid);

    p->scx.slice = 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(h_init)
{
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
        .runnable		= (void *)h_runnable,
        .enqueue        = (void *)h_enqueue,
        .dispatch		= (void *)h_dispatch,
        .running		= (void *)h_running,
        .stopping		= (void *)h_stopping,
        .quiescent		= (void *)h_quiescent,
        .tick               = (void *)h_tick,
        .cgroup_init		= (void *)h_cgroup_init,
        .cgroup_set_weight	= (void *)h_cgroup_set_weight,
        .cgroup_move		= (void *)h_cgroup_move,
        .init			= (void *)h_init,
        .exit			= (void *)h_exit,
        .flags			= SCX_OPS_HAS_CGROUP_WEIGHT | SCX_OPS_ENQ_EXITING | SCX_OPS_SWITCH_PARTIAL,
        .name			= "h");
