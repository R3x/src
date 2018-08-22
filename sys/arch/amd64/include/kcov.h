#ifndef _SYS_KCOV_H_
#define _SYS_KCOV_H_

#include <sys/ioccom.h>

#define KIOSETBUFSIZE	_IOW('K', 1, unsigned long)
#define KIOENABLE	_IO('K', 2)
#define KIODISABLE	_IO('K', 3)


#define KCOV_BUF_MAX_NMEMB	(256 << 10)

void kcov_exit(struct lwp *);
void __sanitizer_cov_trace_pc(void);
#endif /* !_SYS_KCOV_H_ */