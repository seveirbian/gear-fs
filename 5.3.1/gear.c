#include <uapi/linux/magic.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/sched/task.h>
#include <linux/namei.h>
#include <linux/xattr.h>
#include <linux/mount.h>
#include <linux/parser.h>
#include <linux/module.h>
#include <linux/statfs.h>
#include <linux/seq_file.h>
#include <linux/posix_acl_xattr.h>
#include <linux/exportfs.h>
#include "overlayfs.h"

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/un.h>
#include <net/sock.h>

#include "gear.h"

// 定义socks_ctr
struct socks_ctr socks_ctr = {
	.inited = 0
};

void connect_sock(struct socket **sock) {
	int sfd;
	struct sockaddr_un addr;
	int ret;

	sfd = sock_create_kern(&init_net, AF_UNIX, SOCK_STREAM, 0, sock); 
	if (sfd < 0) {
		printk("sock_create_kern err: %d\n", sfd);
	}

	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, GEAR_DAEMON_SOCKET);

	printk("connect\n");
	printk("%s\n", GEAR_DAEMON_SOCKET);
	ret = kernel_connect(*sock, (struct sockaddr *)&addr, sizeof(addr), 0);
	if (ret < 0) {
		printk("kernel_connect err: %d\n", ret);
	}
}

int init_socks_ctr(void) {
	int i;

	if (socks_ctr.inited == 0) {
		mutex_init(&(socks_ctr.mutex));

		for (i = 0; i < socks_len; i++) {
			mutex_init(&((socks_ctr.socks)[i]).mutex);

			connect_sock(&(((socks_ctr.socks)[i]).sock));
		}

		socks_ctr.inited = 1;
	}

	return 0;
}

void release_socks_ctr(void) {
	int i;
	for (i = 0; i < socks_len; i++) {
		if (((socks_ctr.socks)[i]).sock != NULL) {
			sock_release(((socks_ctr.socks)[i]).sock);
		}
	}
}

int choose_a_socket(struct socket **sock_address) {
	int i;

	mutex_lock(&(socks_ctr.mutex));

	for (i = 0; i < socks_len; i++) {
		if (mutex_trylock(&(((socks_ctr.socks)[i]).mutex))) {
			*sock_address = ((socks_ctr.socks)[i]).sock;

			break;
		}

		// 如果当前socket都被使用了，则无限循环直到有可用socket
		if (i == socks_len-1) {
			i = 0;
		}
	}

	mutex_unlock(&(socks_ctr.mutex));

	return i;
}

void return_a_socket(int i) {
	mutex_unlock(&(((socks_ctr.socks)[i]).mutex));
}

struct file *inode_open_file(struct inode *inode) {
	struct path root;
	struct file *file;

	task_lock(&init_task);
	get_fs_root(init_task.fs, &root);
	task_unlock(&init_task);

	root.dentry = d_find_alias(inode);

	file = file_open_root(root.dentry->d_parent, root.mnt, root.dentry->d_name.name, O_RDONLY, 0);

	return file;
}

ssize_t read_file (struct file* f, char * buf, size_t count, loff_t pos) {
	ssize_t ret;

	ret = kernel_read(f, buf, count, &pos);

	return ret;
}

// 比较读取的文件内容和预期是否相符，完全相同返回1，否则返回0
int compare_content (char *buf, char *target, size_t count) {
	int i;

	for (i = 0; i < count; i++) {
		if (buf[i] != target[i]) {
			return 0;
		}
	}

	return 1;
}

int need_update_gear_file(struct dentry *dentry, char *finger_print, int finger_print_len) {	
	struct file *f;
	char content[6];
	size_t count = 6;
	char target[6] = "SHA-1:";

	int is_equal = 0;

	f = inode_open_file(dentry->d_inode);

	read_file(f, content, count, 0);

	is_equal = compare_content(content, target, count);

	if (is_equal) {
		read_file(f, finger_print, finger_print_len, 0);
	}

	return is_equal;
}

int connect_gear_daemon(char *path, int path_len, char *finger_print, int finger_print_len) {
	struct socket *sock = NULL;
	int i;
	int ret;
	struct kvec vec;
    struct msghdr msg;
	char info[800];
	int info_len = 800;
	char recvbuf[2];
	int recvbuf_len = 2;
	recvbuf[0] = ' ';
	recvbuf[1] = '\0';
	memset(info, 0, info_len);

	i = choose_a_socket(&sock);
	if (sock == NULL) {
		return 0;
	}

	printk("<<using %d socket>>\n", i);

	// 拼接需要发送的信息
	strcpy(info, path);
	strcat(info, finger_print);
	strcat(info, "\n");

	// 发送信息
	memset(&msg, 0, sizeof(msg));
	memset(&vec, 0, sizeof(vec));
	vec.iov_base = info;
	vec.iov_len = info_len;
	ret=kernel_sendmsg(sock,&msg,&vec,1,info_len);
	if (ret < 0) {
		printk("kernel_sendmsg err: %d\n", ret);
	}

	// 接收返回信息
    memset(&msg,0,sizeof(msg));
	memset(&vec,0,sizeof(vec));
    vec.iov_base=recvbuf;
    vec.iov_len=recvbuf_len;
    ret=kernel_recvmsg(sock,&msg,&vec,1,recvbuf_len,0);
	if (ret < 0) {
		printk("kernel_recvmsg err: %d\n", ret);
	}

	printk("message received: %s\n", recvbuf);

	return_a_socket(i);

	return 0;
}

struct dentry *update_gear_file(struct dentry *dentry, char *finger_print, int finger_print_len) {
	char buf[500];
	int buf_len = 500;
	char *path = NULL;
	int path_len;
	memset(buf, 0, buf_len);

	// gear
	path = dentry_path_raw(dentry, buf, buf_len);
	path_len = (int)strlen(path);
	printk("path: %s\n", path);
	printk("finger print: %s\n", finger_print);

	connect_gear_daemon(path, path_len, finger_print, finger_print_len);
	return NULL;
}

struct dentry *gear_judge(struct dentry *dentry, struct dentry *real) {
	// 添加指纹域
	char finger_print[46];
	size_t finger_print_len = 46;
	struct ovl_entry *oe = dentry->d_fsdata;

	memset(finger_print, 0, finger_print_len);
	// struct dentry *gear_dentry = NULL;

	if (need_update_gear_file(real, finger_print, finger_print_len)) {
		printk(">>>>\n");
		update_gear_file(real, finger_print, finger_print_len);
		oe->is_gear_file = 0;
		printk("<<<<\n");
	}

	real = ovl_dentry_lowerdata(dentry);

	return real;
}

int send_path(char *path, int path_len) {
	struct socket *sock = NULL;
	int i;
	int ret;
	struct kvec vec;
    struct msghdr msg;
	char info[800];
	int info_len = 800;
	char recvbuf[2];
	int recvbuf_len = 2;
	int times;
	recvbuf[0] = ' ';
	recvbuf[1] = '\0';
	memset(info, 0, info_len);

	i = choose_a_socket(&sock);
	if (sock == NULL) {
		return 0;
	}

	printk("<<using %d socket>>\n", i);

	// 拼接需要发送的信息
	strcpy(info, path);
	strcat(info, "\n");

	// 发送信息
	memset(&msg, 0, sizeof(msg));
	memset(&vec, 0, sizeof(vec));
	vec.iov_base = info;
	vec.iov_len = info_len;
	ret=kernel_sendmsg(sock,&msg,&vec,1,info_len);
	if (ret < 0) {
		printk("kernel_sendmsg err: %d\n", ret);
	}

	// 接收返回信息
	ret = -1000;
	times = 1024*1024*1024;
	// while (ret < 0 && times > 0) {
	while (ret < 0) {
		memset(&msg,0,sizeof(msg));
		memset(&vec,0,sizeof(vec));
		vec.iov_base=recvbuf;
		vec.iov_len=recvbuf_len;
		ret=kernel_recvmsg(sock,&msg,&vec,1,recvbuf_len,0);
		if (ret < 0) {
			printk("kernel_recvmsg err: %d\n", ret);
		}
		// times--;
	}

	printk("message received: %s\n", recvbuf);

	return_a_socket(i);

	return 0;
}