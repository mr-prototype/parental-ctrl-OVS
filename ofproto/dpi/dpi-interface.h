#ifndef DPI_INTERFACE_H_
#define DPI_INTERFACE_H_

#include <openvswitch/vlog.h>



typedef signed long int32;
typedef unsigned long uint32;

enum DPILOGLEVEL
{
	DPIERR=1,
	DPIINFO,
	DPIWARN,
	DPIDEBUG,
	DPIMAX
};



void DpiWriteLog(int nlevel, char *format, ...);

// library init
//int32 dpiInit(const char* pszDpiLib, const char* szErrMsgBuf);

// Process ethernet packet for DPI
// DPI implementing library should convert the void *packet to ethernet packet
int32 dpiProcessPacket(void *packet, uint32 nSize);

// library exit
//int32 dpiExit();

#endif /* DPI_INTERFACE_H_ */

