/*
 * 3i arch-specific native syscall dispatch for x86_64.
 * Called from make_threei_call when no handler is registered in the
 * current grate's table and the syscall must execute natively.
 */
#include <linux/threei.h>
#include <linux/ptrace.h>
#include <asm/syscall.h>

long native_syscall(u32 nr, unsigned long args[6])
{
	struct pt_regs *regs = current_pt_regs();

	regs->ax  = nr;
	regs->di  = args[0];
	regs->si  = args[1];
	regs->dx  = args[2];
	regs->r10 = args[3];
	regs->r8  = args[4];
	regs->r9  = args[5];

	return x64_sys_call(regs, nr);
}
