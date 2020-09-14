// 定义和Gear daemon通讯的unix domain socket地址
#define GEAR_DAEMON_SOCKET "/run/gear.sock"
#define socks_len 20
struct socks {
	struct mutex mutex;
	struct socket *sock;
};
struct socks_ctr {
	struct mutex mutex;
	int inited;
	struct socks socks[socks_len];
};

extern struct socks_ctr socks_ctr;

void connect_sock(struct socket **sock);
int init_socks_ctr(void);
void release_socks_ctr(void);
int choose_a_socket(struct socket **sock_address);
void return_a_socket(int i);
struct file *inode_open_file(struct inode *inode);
ssize_t read_file (struct file* f, char * buf, size_t count, loff_t pos);
// 比较读取的文件内容和预期是否相符，完全相同返回1，否则返回0
int compare_content (char *buf, char *target, size_t count);
int need_update_gear_file(struct dentry *dentry, char *finger_print, int finger_print_len);
int connect_gear_daemon(char *path, int path_len, char *finger_print, int finger_print_len);
struct dentry *update_gear_file(struct dentry *dentry, char *finger_print, int finger_print_len);
struct dentry *gear_judge(struct dentry *dentry, struct dentry *real);
int send_path(char *path, int path_len);