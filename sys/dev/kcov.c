#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/module.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/device.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/malloc.h>
#include <sys/stdint.h>
#include <sys/queue.h>

#include <uvm/uvm_extern.h>
#include <sys/kcov.h>

/* #define KCOV_DEBUG */
#ifdef KCOV_DEBUG
#define DPRINTF(x...) do { if (kcov_debug) printf(x); } while (0)
#else
#define DPRINTF(x...)
#endif

/* kcov descriptor */
struct kd {
	enum {
		KCOV_MODE_DISABLED,
		KCOV_MODE_INIT,
		KCOV_MODE_TRACE_PC,
	}		 kd_mode;
	int		 kd_unit;	/* device minor */
	pid_t		 kd_pid;	/* process being traced */
	uintptr_t	*kd_buf;	/* traced coverage */
	size_t		 kd_nmemb;
	size_t		 kd_size;

	TAILQ_ENTRY(kd)	 kd_entry;
};

void kcovattach(int);

int kd_alloc(struct kd *, unsigned long);
struct kd *kd_lookup(int);

static inline struct kd *kd_lookup_pid(pid_t);
static inline int inintr(void);

TAILQ_HEAD(, kd) kd_list = TAILQ_HEAD_INITIALIZER(kd_list);

#ifdef KCOV_DEBUG
int kcov_debug = 1;
#endif

static dev_type_open(kcovopen);
static dev_type_close(kcovclose);
static dev_type_ioctl(kcovioctl);
static dev_type_mmap(kcovmmap);

const struct cdevsw kcov_cdevsw = {
	.d_open = kcovopen,
	.d_close = kcovclose,
	.d_read = noread,
	.d_write = nowrite,
	.d_ioctl = kcovioctl,
	.d_stop = nostop,
	.d_tty = notty,
	.d_poll = nopoll,
	.d_mmap = kcovmmap,
	.d_kqfilter = nokqfilter,
	.d_discard = nodiscard,
	.d_flag = D_OTHER 
};

/*
 * Compiling the kernel with the `-fsanitize-coverage=trace-pc' option will
 * cause the following function to be called upon function entry and before
 * each block instructions that maps to a single line in the original source
 * code.
 *
 * If kcov is enabled for the current process, the executed address will be
 * stored in the corresponding coverage buffer.
 * The first element in the coverage buffer holds the index of next available
 * element.
 */
void
__sanitizer_cov_trace_pc(void)
{
	extern int cold;
	struct kd *kd;
	uint64_t idx;

	/* Do not trace during boot. */
	if (cold)
		return;

	/* Do not trace in interrupts to prevent noisy coverage. */
	if (inintr())
		return;

	kd = kd_lookup_pid(curproc->p_pid);
	if (kd == NULL)
		return;

	idx = kd->kd_buf[0];
	if (idx < kd->kd_nmemb) {
		kd->kd_buf[idx + 1] = (uintptr_t)__builtin_return_address(0);
		kd->kd_buf[0] = idx + 1;
	}
}

void
kcovattach(int count)
{
}

int
kcovopen(dev_t dev, int flag, int mode, struct lwp *l)
{
	struct kd *kd;

	printf("Opened Kcov device\n");
	if (kd_lookup(minor(dev)) != NULL)
		return (EBUSY);

	DPRINTF("%s: unit=%d\n", __func__, minor(dev));

	kd = malloc(sizeof(*kd), M_SUBPROC, M_WAITOK | M_ZERO);
	kd->kd_unit = minor(dev);
	TAILQ_INSERT_TAIL(&kd_list, kd, kd_entry);
	return (0);
}

int
kcovclose(dev_t dev, int flag, int mode, struct lwp *l)
{
	struct kd *kd;

	printf("Closed Kcov device\n");
	kd = kd_lookup(minor(dev));
	if (kd == NULL)
		return (EINVAL);

	DPRINTF("%s: unit=%d\n", __func__, minor(dev));

	TAILQ_REMOVE(&kd_list, kd, kd_entry);
	free(kd->kd_buf, kd->kd_size);
	free(kd, sizeof(struct kd));
	return (0);
}

int
kcovioctl(dev_t dev, u_long cmd, void *addr, int flag, struct lwp *l)
{

	struct kd *kd;
	int error = 0;

	printf("IOCTL for KCOV\n");
	kd = kd_lookup(minor(dev));
	if (kd == NULL)
		return (ENXIO);

	switch (cmd) {
	case KIOSETBUFSIZE:
		printf("set buffer IOCTL for KCOV\n");
		if (kd->kd_mode != KCOV_MODE_DISABLED) {
			error = EBUSY;
			break;
		}
		error = kd_alloc(kd, *((unsigned long *)addr));
		if (error == 0)
			kd->kd_mode = KCOV_MODE_INIT;
		break;
	case KIOENABLE:
		printf("enable IOCTL for KCOV\n");
		if (kd->kd_mode != KCOV_MODE_INIT) {
			error = EBUSY;
			break;
		}
		kd->kd_mode = KCOV_MODE_TRACE_PC;
		kd->kd_pid = l->l_proc->p_pid;
		break;
	case KIODISABLE:
		printf("disable IOCTL for KCOV\n");
		/* Only the enabled process may disable itself. */
		if (kd->kd_pid != l->l_proc->p_pid ||
		    kd->kd_mode != KCOV_MODE_TRACE_PC) {
			error = EBUSY;
			break;
		}
		kd->kd_mode = KCOV_MODE_INIT;
		kd->kd_pid = 0;
		break;
	default:
		printf("unknown IOCTL for KCOV\n");
		error = EINVAL;
		DPRINTF("%s: %lu: unknown command\n", __func__, cmd);
	}

	DPRINTF("%s: unit=%d, mode=%d, pid=%d, error=%d\n",
		    __func__, kd->kd_unit, kd->kd_mode, kd->kd_pid, error);

	return (error);
}

paddr_t
kcovmmap(dev_t dev, off_t offset, int prot)
{
	struct kd *kd;
	paddr_t pa;
	vaddr_t va;
	printf("Mmap buffer for KCOV device\n");
	kd = kd_lookup(minor(dev));
	if (kd == NULL) {
		printf("Device not found");
		return (paddr_t)(-1);
	}
	if (offset < 0 || offset >= kd->kd_nmemb * sizeof(uintptr_t)){
		printf("Offset is not proper");
		return (paddr_t)(-1);
	}
	va = (vaddr_t)kd->kd_buf + offset;
	if (pmap_extract(pmap_kernel(), va, &pa) == FALSE) {
		printf("Address Not found in the kernel");
		return (paddr_t)(-1);
	}
	return (pa);
}

void
kcov_exit(struct proc *p)
{
	struct kd *kd;

	printf("Process exit for KCOV\n");
	kd = kd_lookup_pid(p->p_pid);
	if (kd == NULL)
		return;

	kd->kd_mode = KCOV_MODE_INIT;
	kd->kd_pid = 0;
}

struct kd *
kd_lookup(int unit)
{
	struct kd *kd;
	
	printf("Lookup for KCOV\n");

	TAILQ_FOREACH(kd, &kd_list, kd_entry) {
		if (kd->kd_unit == unit)
			return (kd);
	}
	return (NULL);
}

int
kd_alloc(struct kd *kd, unsigned long nmemb)
{
	size_t size;
	
	printf("alloc for KCOV\n");

	KASSERT(kd->kd_buf == NULL);

	if (nmemb == 0 || nmemb > KCOV_BUF_MAX_NMEMB)
		return (EINVAL);

	size = roundup(nmemb * sizeof(uintptr_t), PAGE_SIZE);
	kd->kd_buf = (uintptr_t *)uvm_km_alloc(kernel_map, size, 0, UVM_KMF_WIRED|UVM_KMF_ZERO);
	/* The first element is reserved to hold the number of used elements. */
	kd->kd_nmemb = nmemb - 1;
	kd->kd_size = size;
	return (0);
}

static inline struct kd *
kd_lookup_pid(pid_t pid)
{
	struct kd *kd;

	TAILQ_FOREACH(kd, &kd_list, kd_entry) {
		if (kd->kd_pid == pid && kd->kd_mode == KCOV_MODE_TRACE_PC)
			return (kd);
	}
	return (NULL);
}

static inline int
inintr(void)
{
#if defined(__amd64__) || defined(__i386__)
	return (curcpu()->ci_idepth > 0);
#else
	return (0);
#endif
}

MODULE(MODULE_CLASS_MISC, kcov, NULL); 

static int
kcov_modcmd(modcmd_t cmd, void *arg __unused)
{
	int bmajor = -1, cmajor = -1;
	switch (cmd) {
	case MODULE_CMD_INIT:
		printf("Init called\n");
		if (devsw_attach("kcov", NULL, &bmajor, &kcov_cdevsw,
				 &cmajor))
			return ENXIO;
		return 0;
	case MODULE_CMD_FINI:
		devsw_detach(NULL, &kcov_cdevsw);
		return 0;
	default:
		return ENOTTY;
	}
}
