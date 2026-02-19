#include "timer.h"
#include "riscv.h"
#include "sbi.h"

uint64 get_cycle()
{
	return r_time();
}

void timer_init()
{
	w_sie(r_sie() | SIE_STIE);
	set_next_timer();
}

void set_next_timer()
{
	const uint64 timebase = CPU_FREQ / TICKS_PER_SEC;
	set_timer(get_cycle() + timebase);
}
