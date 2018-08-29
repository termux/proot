#include <unistd.h>      /* get*id(2),  */
#include <sys/socket.h>  /* cmsghdr, */
#include <sys/types.h>   /* uid_t, gid_t, get*id(2), */
#include <linux/net.h>   /* SYS_SENDMSG, */

#include "tracee/mem.h"
#include "syscall/sysnum.h"
#include "syscall/syscall.h"
#include "extension/fake_id0/sendmsg.h"

int handle_sendmsg_enter_end(Tracee *tracee, word_t sysnum)
{
	/* Read sendmsg header.  */
	int status;
	unsigned long socketcall_args[3];
	struct msghdr msg = {};
	bool is_socketcall = sysnum == PR_socketcall;

	if (!is_socketcall)
	{
		status = read_data(tracee, &msg, peek_reg(tracee, CURRENT, SYSARG_2), sizeof(struct msghdr));
		if (status < 0) return status;
	}
	else
	{
		/* Check if socketcall(2) is a sendmsg(2)  */
		if (peek_reg(tracee, CURRENT, SYSARG_1) != SYS_SENDMSG) return 0;

		/* Read socketcall args structure */
		status = read_data(tracee, socketcall_args, peek_reg(tracee, CURRENT, SYSARG_2), sizeof(socketcall_args));
		if (status < 0) return status;

		/* Read sendmsg header */
		status = read_data(tracee, &msg, socketcall_args[1], sizeof(struct msghdr));
		if (status < 0) return status;
	}
	if (msg.msg_control != NULL && msg.msg_controllen != 0)
	{
		bool did_modify = 0;

		/* Read cmsg header.  */
		char cmsg_buf[msg.msg_controllen];
		status = read_data(tracee, cmsg_buf, (word_t) msg.msg_control, msg.msg_controllen);
		if (status < 0) return status;

		/* Set msg_control to address of buffer in proot so CMSG_FIRSTHDR can access it */
		msg.msg_control = cmsg_buf;

		/* Iterate over control messages.  */
		struct cmsghdr *cmsg;
		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg))
		{
			if (!(
					cmsg->cmsg_len >= sizeof(struct cmsghdr) &&
					cmsg->cmsg_len <= msg.msg_controllen - ((char*)cmsg - (char*)msg.msg_control)
				))
			{
				/* Malformed cmsg - header or body didn't fit in entry.  */
				return 0;
			}

			/* Look into cmsg data.  */
			if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_CREDENTIALS)
			{
				if (cmsg->cmsg_len != CMSG_LEN(sizeof(struct ucred)))
				{
					/* Malformed cmsg - struct ucred size mismatch.  */
					return 0;
				}
				struct ucred *ucred = (struct ucred *) CMSG_DATA(cmsg);
				/* Set uid and gid of SCM_CREDENTIALS to ones that proot really has.
				 * Pid is not changed as we don't fiddle with getpid()  */
				ucred->uid = getuid();
				ucred->gid = getgid();
				did_modify = true;
			}
		}
		if (did_modify)
		{
			/* Write cmsg data into tracee. */
			msg.msg_control = (void *) alloc_mem(tracee, msg.msg_controllen);
			if (msg.msg_control == 0) return -ENOMEM;

			status = write_data(tracee, (word_t) msg.msg_control, cmsg_buf, msg.msg_controllen);
			if (status < 0) return -ENOMEM;

			/* Write sendmsg header.  */
			word_t sendmsg_header_addr = alloc_mem(tracee, sizeof(struct msghdr));
			if (sendmsg_header_addr == 0) return -ENOMEM;

			status = write_data(tracee, sendmsg_header_addr, &msg, sizeof(struct msghdr));
			if (status < 0) return -ENOMEM;

			/* Write address of new sendmsg header.  */
			if (!is_socketcall)
			{
				poke_reg(tracee, SYSARG_2, sendmsg_header_addr);
			}
			else
			{
				socketcall_args[1] = sendmsg_header_addr;
				status = set_sysarg_data(tracee, socketcall_args, sizeof(socketcall_args), SYSARG_2);
				if (status < 0) return status;
			}
		}
	}

	return 0;
}
