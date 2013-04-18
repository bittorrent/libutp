#ifndef __WIN32_TCPIP_H__
#define __WIN32_TCPIP_H__

// Before Windows SDK 8.0A, PREfast incorrectly reports buffer
// overruns in getsourcefilter and getipv4sourcefilter.
#pragma warning(push)
#pragma warning(disable: 6386)
#include <ws2tcpip.h>
#pragma warning(pop)

#endif //__WIN32_TCPIP_H__
