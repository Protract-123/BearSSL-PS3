#include <stdio.h>
#include <netex/net.h>
#include <sys/process.h>
#include <cell/sysmodule.h>

extern int32_t userMain(void);

SYS_PROCESS_PARAM(1001, 0x10000)

int main(void)
{
	int ret;

	ret = cellSysmoduleLoadModule(CELL_SYSMODULE_HTTPS);
	if (ret < 0) {
		printf("cellSysmoduleLoadModule failed (0x%x)\n", ret);
		return 0;
	}

	/*E start network */
	ret = sys_net_initialize_network();
	if (ret < 0) {
		printf("sys_net_initialize_network() failed (0x%x)\n", ret);
		return 0;
	}

	/*E entry point of user program */
	userMain();

	sys_net_finalize_network();

	/*E unload relocatable modules */
	ret = cellSysmoduleUnloadModule(CELL_SYSMODULE_HTTPS);
	if (ret < 0) {
		printf("cellSysmoduleUnloadModule failed (0x%x)\n", ret);
		return 0;
	}
	return 0;
}