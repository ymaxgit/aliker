/*
 * ipmi_si_sm.h
 *
 * State machine interface for low-level IPMI system management
 * interface state machines.  This code is the interface between
 * the ipmi_smi code (that handles the policy of a KCS, SMIC, or
 * BT interface) and the actual low-level state machine.
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2002 MontaVista Software Inc.
 *
 *  This program is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License as published by the
 *  Free Software Foundation; either version 2 of the License, or (at your
 *  option) any later version.
 *
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 *  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 *  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 *  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 *  OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 *  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 *  TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 *  USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  675 Mass Ave, Cambridge, MA 02139, USA.
 */

/*
 * This is defined by the state machines themselves, it is an opaque
 * data type for them to use.
 */
struct si_sm_data;

/*
 * The structure for doing I/O in the state machine.  The state
 * machine doesn't have the actual I/O routines, they are done through
 * this interface.
 */
struct si_sm_io {
	unsigned char (*inputb)(struct si_sm_io *io, unsigned int offset);
	void (*outputb)(struct si_sm_io *io,
			unsigned int  offset,
			unsigned char b);

	/*
	 * Generic info used by the actual handling routines, the
	 * state machine shouldn't touch these.
	 */
	void __iomem *addr;
	int  regspacing;
	int  regsize;
	int  regshift;
	int addr_type;
	long addr_data;
};

/* Results of SMI events. */
enum si_sm_result {
	SI_SM_CALL_WITHOUT_DELAY, /* Call the driver again immediately */
	SI_SM_CALL_WITH_DELAY,	/* Delay some before calling again. */
	SI_SM_CALL_WITH_TICK_DELAY,/* Delay >=1 tick before calling again. */
	SI_SM_TRANSACTION_COMPLETE, /* A transaction is finished. */
	SI_SM_IDLE,		/* The SM is in idle state. */
	SI_SM_HOSED,		/* The hardware violated the state machine. */

	/*
	 * The hardware is asserting attn and the state machine is
	 * idle.
	 */
	SI_SM_ATTN
};

/* Handlers for the SMI state machine. */
struct si_sm_handlers {
	/*
	 * Put the version number of the state machine here so the
	 * upper layer can print it.
	 */
	char *version;

	/*
	 * Initialize the data and return the amount of I/O space to
	 * reserve for the space.
	 */
	unsigned int (*init_data)(struct si_sm_data *smi,
				  struct si_sm_io   *io);

	/*
	 * Start a new transaction in the state machine.  This will
	 * return -2 if the state machine is not idle, -1 if the size
	 * is invalid (to large or too small), or 0 if the transaction
	 * is successfully completed.
	 */
	int (*start_transaction)(struct si_sm_data *smi,
				 unsigned char *data, unsigned int size);

	/*
	 * Return the results after the transaction.  This will return
	 * -1 if the buffer is too small, zero if no transaction is
	 * present, or the actual length of the result data.
	 */
	int (*get_result)(struct si_sm_data *smi,
			  unsigned char *data, unsigned int length);

	/*
	 * Call this periodically (for a polled interface) or upon
	 * receiving an interrupt (for a interrupt-driven interface).
	 * If interrupt driven, you should probably poll this
	 * periodically when not in idle state.  This should be called
	 * with the time that passed since the last call, if it is
	 * significant.  Time is in microseconds.
	 */
	enum si_sm_result (*event)(struct si_sm_data *smi, long time);

	/*
	 * Attempt to detect an SMI.  Returns 0 on success or nonzero
	 * on failure.
	 */
	int (*detect)(struct si_sm_data *smi);

	/* The interface is shutting down, so clean it up. */
	void (*cleanup)(struct si_sm_data *smi);

	/* Return the size of the SMI structure in bytes. */
	int (*size)(void);
};

/* Current state machines that we can use. */
extern struct si_sm_handlers kcs_smi_handlers;
extern struct si_sm_handlers smic_smi_handlers;
extern struct si_sm_handlers bt_smi_handlers;

#ifdef IPMI_SI_OR_MSGHANDLER

/* The below defitions are moved from ipmi_si_intf.c to
 * compile ipmi_si and ipmi_msghandler as module.
 *
 * The better way to do this may be using an independent
 * header file to hold these defitions, but as a small fix
 * we don't want to add an extra file to the tree, so here
 * it is. ^_^
 */

enum si_intf_state {
	SI_NORMAL,
	SI_GETTING_FLAGS,
	SI_GETTING_EVENTS,
	SI_CLEARING_FLAGS,
	SI_CLEARING_FLAGS_THEN_SET_IRQ,
	SI_GETTING_MESSAGES,
	SI_ENABLE_INTERRUPTS1,
	SI_ENABLE_INTERRUPTS2,
	SI_DISABLE_INTERRUPTS1,
	SI_DISABLE_INTERRUPTS2
	/* FIXME - add watchdog stuff. */
};

enum si_type {
    SI_KCS, SI_SMIC, SI_BT
};

/*
 * Indexes into stats[] in smi_info below.
 */
enum si_stat_indexes {
	/*
	 * Number of times the driver requested a timer while an operation
	 * was in progress.
	 */
	SI_STAT_short_timeouts = 0,

	/*
	 * Number of times the driver requested a timer while nothing was in
	 * progress.
	 */
	SI_STAT_long_timeouts,

	/* Number of times the interface was idle while being polled. */
	SI_STAT_idles,

	/* Number of interrupts the driver handled. */
	SI_STAT_interrupts,

	/* Number of time the driver got an ATTN from the hardware. */
	SI_STAT_attentions,

	/* Number of times the driver requested flags from the hardware. */
	SI_STAT_flag_fetches,

	/* Number of times the hardware didn't follow the state machine. */
	SI_STAT_hosed_count,

	/* Number of completed messages. */
	SI_STAT_complete_transactions,

	/* Number of IPMI events received from the hardware. */
	SI_STAT_events,

	/* Number of watchdog pretimeouts. */
	SI_STAT_watchdog_pretimeouts,

	/* Number of asyncronous messages received. */
	SI_STAT_incoming_messages,


	/* This *must* remain last, add new values above this. */
	SI_NUM_STATS
};

#define SI_INTF_TOKEN 0x6188709B

struct smi_info {
	int		       token;
	int                    intf_num;
	ipmi_smi_t             intf;
	struct si_sm_data      *si_sm;
	struct si_sm_handlers  *handlers;
	enum si_type           si_type;
	spinlock_t             si_lock;
	spinlock_t             msg_lock;
	struct list_head       xmit_msgs;
	struct list_head       hp_xmit_msgs;
	struct ipmi_smi_msg    *curr_msg;
	enum si_intf_state     si_state;

	/*
	 * Used to handle the various types of I/O that can occur with
	 * IPMI
	 */
	struct si_sm_io io;
	int (*io_setup)(struct smi_info *info);
	void (*io_cleanup)(struct smi_info *info);
	int (*irq_setup)(struct smi_info *info);
	void (*irq_cleanup)(struct smi_info *info);
	unsigned int io_size;
	enum ipmi_addr_src addr_source; /* ACPI, PCI, SMBIOS, hardcode, etc. */
	void (*addr_source_cleanup)(struct smi_info *info);
	void *addr_source_data;

	/*
	 * Per-OEM handler, called from handle_flags().  Returns 1
	 * when handle_flags() needs to be re-run or 0 indicating it
	 * set si_state itself.
	 */
	int (*oem_data_avail_handler)(struct smi_info *smi_info);

	/*
	 * Flags from the last GET_MSG_FLAGS command, used when an ATTN
	 * is set to hold the flags until we are done handling everything
	 * from the flags.
	 */
#define RECEIVE_MSG_AVAIL	0x01
#define EVENT_MSG_BUFFER_FULL	0x02
#define WDT_PRE_TIMEOUT_INT	0x08
#define OEM0_DATA_AVAIL     0x20
#define OEM1_DATA_AVAIL     0x40
#define OEM2_DATA_AVAIL     0x80
#define OEM_DATA_AVAIL      (OEM0_DATA_AVAIL | \
			     OEM1_DATA_AVAIL | \
			     OEM2_DATA_AVAIL)
	unsigned char       msg_flags;

	/* Does the BMC have an event buffer? */
	char		    has_event_buffer;

	/*
	 * If set to true, this will request events the next time the
	 * state machine is idle.
	 */
	atomic_t            req_events;

	/*
	 * If true, run the state machine to completion on every send
	 * call.  Generally used after a panic to make sure stuff goes
	 * out.
	 */
	int                 run_to_completion;

	/* The I/O port of an SI interface. */
	int                 port;

	/*
	 * The space between start addresses of the two ports.  For
	 * instance, if the first port is 0xca2 and the spacing is 4, then
	 * the second port is 0xca6.
	 */
	unsigned int        spacing;

	/* zero if no irq; */
	int                 irq;

	/* The timer for this si. */
	struct timer_list   si_timer;

	/* The time (in jiffies) the last timeout occurred at. */
	unsigned long       last_timeout_jiffies;

	/* Used to gracefully stop the timer without race conditions. */
	atomic_t            stop_operation;

	/*
	 * The driver will disable interrupts when it gets into a
	 * situation where it cannot handle messages due to lack of
	 * memory.  Once that situation clears up, it will re-enable
	 * interrupts.
	 */
	int interrupt_disabled;

	/* From the get device id response... */
	struct ipmi_device_id device_id;

	/* Driver model stuff. */
	struct device *dev;
	struct platform_device *pdev;

	/*
	 * True if we allocated the device, false if it came from
	 * someplace else (like PCI).
	 */
	int dev_registered;

	/* Slave address, could be reported from DMI. */
	unsigned char slave_addr;

	/* Counters and things for the proc filesystem. */
	atomic_t stats[SI_NUM_STATS];

	struct task_struct *thread;

	struct list_head link;
	union ipmi_smi_info_union addr_info;
};

#endif /* IPMI_SI_OR_MSGHANDLER */

