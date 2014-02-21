/*
 * io_latency.h
 *
 * informations for IO latency and size
 *
 * Copyright (C) 2013,  Coly Li <i@coly.li>
 * 			Robin Dong <sanbai@taobao.com>
 *			Sha Zhengju <handai.szj@taobao.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License, version 2,  as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 */

#include <asm-generic/div64.h>
#include <linux/slab.h>
#include <linux/clocksource.h>
#include <linux/percpu.h>

/* 300s is max disk I/O latency which application may accept */
#define IO_LATENCY_STATS_S_NR		100
#define IO_LATENCY_STATS_S_GRAINSIZE	(1000/IO_LATENCY_STATS_S_NR)
#define IO_LATENCY_STATS_MS_NR		100
#define IO_LATENCY_STATS_MS_GRAINSIZE	(1000/IO_LATENCY_STATS_MS_NR)
#define IO_LATENCY_STATS_US_NR		100
#define IO_LATENCY_STATS_US_GRAINSIZE	(1000/IO_LATENCY_STATS_S_NR)

#define IO_SIZE_MAX			(1024 * 1024)
#define IO_SIZE_STATS_GRAINSIZE		4096
#define IO_SIZE_STATS_NR		(IO_SIZE_MAX / IO_SIZE_STATS_GRAINSIZE)

struct latency_stats {
	/* latency statistic buckets */
	unsigned long latency_stats_s[IO_LATENCY_STATS_S_NR];
	unsigned long latency_stats_ms[IO_LATENCY_STATS_MS_NR];
	unsigned long latency_stats_us[IO_LATENCY_STATS_US_NR];
	unsigned long latency_read_stats_s[IO_LATENCY_STATS_S_NR];
	unsigned long latency_read_stats_ms[IO_LATENCY_STATS_MS_NR];
	unsigned long latency_read_stats_us[IO_LATENCY_STATS_US_NR];
	unsigned long latency_write_stats_s[IO_LATENCY_STATS_S_NR];
	unsigned long latency_write_stats_ms[IO_LATENCY_STATS_MS_NR];
	unsigned long latency_write_stats_us[IO_LATENCY_STATS_US_NR];
	/* latency statistic for block-layer buckets */
	unsigned long soft_latency_stats_s[IO_LATENCY_STATS_S_NR];
	unsigned long soft_latency_stats_ms[IO_LATENCY_STATS_MS_NR];
	unsigned long soft_latency_stats_us[IO_LATENCY_STATS_US_NR];
	unsigned long soft_latency_read_stats_s[IO_LATENCY_STATS_S_NR];
	unsigned long soft_latency_read_stats_ms[IO_LATENCY_STATS_MS_NR];
	unsigned long soft_latency_read_stats_us[IO_LATENCY_STATS_US_NR];
	unsigned long soft_latency_write_stats_s[IO_LATENCY_STATS_S_NR];
	unsigned long soft_latency_write_stats_ms[IO_LATENCY_STATS_MS_NR];
	unsigned long soft_latency_write_stats_us[IO_LATENCY_STATS_US_NR];
	/* io size statistic buckets */
	unsigned long io_size_stats[IO_SIZE_STATS_NR];
	unsigned long io_read_size_stats[IO_SIZE_STATS_NR];
	unsigned long io_write_size_stats[IO_SIZE_STATS_NR];
};

static struct kmem_cache *latency_stats_cache;

static inline unsigned long long io_us2msecs(unsigned long long usec)
{
	usec += 500;
	do_div(usec, 1000);
	return usec;
}

static inline unsigned long long io_us2secs(unsigned long long usec)
{
	usec += 500;
	do_div(usec, 1000);
	usec += 500;
	do_div(usec, 1000);
	return usec;
}

/*
static unsigned long long ms2secs(unsigned long long msec)
{
	msec += 500;
	do_div(msec, 1000);
	return msec;
}*/

static inline int init_latency_stats(void)
{
	latency_stats_cache = kmem_cache_create("io-latency-stats",
			sizeof(struct latency_stats), 0, 0, NULL);
	if (!latency_stats_cache)
		return -ENOMEM;
	return 0;
}

static inline void exit_latency_stats(void)
{
	if (latency_stats_cache) {
		kmem_cache_destroy(latency_stats_cache);
		latency_stats_cache = NULL;
	}
}

static inline void reset_latency_stats(struct latency_stats __percpu *lstats)
{
	int r, cpu;
	struct latency_stats *pstats;

	for_each_possible_cpu(cpu) {
		pstats = per_cpu_ptr(lstats, cpu);
		/* reset latency stats buckets */
		for (r = 0; r < IO_LATENCY_STATS_S_NR; r++) {
			pstats->latency_stats_s[r] = 0;
			pstats->latency_read_stats_s[r] = 0;
			pstats->latency_write_stats_s[r] = 0;
			pstats->soft_latency_stats_s[r] = 0;
			pstats->soft_latency_read_stats_s[r] = 0;
			pstats->soft_latency_write_stats_s[r] = 0;
		}
		for (r = 0; r < IO_LATENCY_STATS_MS_NR; r++) {
			pstats->latency_stats_ms[r] = 0;
			pstats->latency_read_stats_ms[r] = 0;
			pstats->latency_write_stats_ms[r] = 0;
			pstats->soft_latency_stats_ms[r] = 0;
			pstats->soft_latency_read_stats_ms[r] = 0;
			pstats->soft_latency_write_stats_ms[r] = 0;
		}
		for (r = 0; r < IO_LATENCY_STATS_US_NR; r++) {
			pstats->latency_stats_us[r] = 0;
			pstats->latency_read_stats_us[r] = 0;
			pstats->latency_write_stats_us[r] = 0;
			pstats->soft_latency_stats_us[r] = 0;
			pstats->soft_latency_read_stats_us[r] = 0;
			pstats->soft_latency_write_stats_us[r] = 0;
		}
		for (r = 0; r < IO_SIZE_STATS_NR; r++) {
			pstats->io_size_stats[r] = 0;
			pstats->io_read_size_stats[r] = 0;
			pstats->io_write_size_stats[r] = 0;
		}
	}
}

static inline struct latency_stats __percpu *create_latency_stats(void)
{
	return alloc_percpu(struct latency_stats);
}

static inline void destroy_latency_stats(struct latency_stats __percpu *lstats)
{
	if (lstats)
		free_percpu(lstats);
}

#define INC_LATENCY(lstats, idx, soft, rw, grain)			\
do {									\
									\
if (soft) {								\
	lstats->soft_latency_stats_##grain[idx]++;			\
	if (rw)								\
		lstats->soft_latency_write_stats_##grain[idx]++;	\
	else								\
		lstats->soft_latency_read_stats_##grain[idx]++;		\
} else {								\
	lstats->latency_stats_##grain[idx]++;				\
	if (rw)								\
		lstats->latency_write_stats_##grain[idx]++;		\
	else								\
		lstats->latency_read_stats_##grain[idx]++;		\
}									\
									\
} while (0)

/* microseconds */
#define INC_MICRO_LATENCY(latency, lstats, soft, rw, grain)		\
do {									\
	int idx = latency / IO_LATENCY_STATS_US_GRAINSIZE;		\
	if (idx > (IO_LATENCY_STATS_US_NR - 1))				\
		idx = IO_LATENCY_STATS_US_NR - 1;			\
	INC_LATENCY(lstats, idx, soft, rw, us);				\
} while (0)

/* milliseconds */
#define INC_MILLI_LATENCY(latency, lstats, soft, rw, grain)		\
do {									\
	int idx = io_us2msecs(latency) / IO_LATENCY_STATS_MS_GRAINSIZE;	\
	if (idx > (IO_LATENCY_STATS_MS_NR - 1))				\
		idx = IO_LATENCY_STATS_MS_NR - 1;			\
	INC_LATENCY(lstats, idx, soft, rw, ms);				\
} while (0)

/* seconds */
#define	INC_SECON_LATENCY(latency, lstats, soft, rw, grain)		\
do {									\
	int idx = io_us2secs(latency) / IO_LATENCY_STATS_S_GRAINSIZE;	\
	if (idx > (IO_LATENCY_STATS_S_NR - 1))				\
		idx = IO_LATENCY_STATS_S_NR - 1;			\
	INC_LATENCY(lstats, idx, soft, rw, s);				\
} while (0)

static  inline void update_io_latency_stats(struct latency_stats *lstats, unsigned long stime,
			unsigned long now, int soft, int rw, int use_us)
{
	unsigned long latency;

	/*
	 * if now <= io->start_time_usec, it means counter
	 * in ktime_get() over flows, just ignore this I/O
	*/
	if (unlikely(now <= stime))
		return;

	latency = now - stime;
	if (!use_us)
		latency *= 1000;

	if (latency < 1000)
		INC_MICRO_LATENCY(latency, lstats, soft, rw, grain);
	else if (latency < 1000000)
		INC_MILLI_LATENCY(latency, lstats, soft, rw, grain);
	else
		INC_SECON_LATENCY(latency, lstats, soft, rw, grain);
}

static inline void update_io_size_stats(struct latency_stats *lstats,
				unsigned long size, int rw)
{
	int idx;

	if (size < IO_SIZE_MAX) {
		idx = size/IO_SIZE_STATS_GRAINSIZE;
		if (idx > (IO_SIZE_STATS_NR - 1))
			idx = IO_SIZE_STATS_NR - 1;
		lstats->io_size_stats[idx]++;
		if (rw)
			lstats->io_write_size_stats[idx]++;
		else
			lstats->io_read_size_stats[idx]++;
	}
}
