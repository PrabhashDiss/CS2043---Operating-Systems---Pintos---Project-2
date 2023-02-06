#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "devices/shutdown.h"
#include "devices/block.h"

const int MIN_FILENAME = 1;
const int MAX_FILENAME = 14;

typedef int pid_t;    /* A data type that represents a process id. */

struct file_descriptor
{
  int fd;
  struct file *file;
  struct list_elem fdelem;
};
static struct lock filesys_lock;    /* The lock used for file system operations. */

static void syscall_handler (struct intr_frame *);
bool is_valid_ptr(const void *ptr);
bool is_valid_filename(const void *file);
static void halt(void);
void exit(int status);
static pid_t exec(const char *cmd_line);
static int wait(pid_t pid);
static bool create(const char *file, unsigned initial_size);
static bool remove(const char *file);
static int open(const char *file);
static filesize(int fd);
static int read(int fd, void *buffer, unsigned size);
static int write(int fd, const void *buffer, unsigned size);
static void seek(int fd, unsigned position);
static unsigned tell(int fd);
static void close(int fd);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  //printf("syscall_handler\n");

  /* Pointers to the arguments of the system call. */
  uint32_t *esp = f->esp;
  uint32_t *argv0 = esp + 1;
  uint32_t *argv1 = esp + 2;
  uint32_t *argv2 = esp + 3;

  /* Check if the pointers are not valid. */
  if (!is_valid_ptr(esp))
    exit(-1);   /* If the pointer is invalid, terminate the process with exit status -1. */

  /* The system call number. */
  uint32_t syscall_num = *esp;
  switch (syscall_num)
  {
    case SYS_HALT:
      halt();
  		break;
    case SYS_EXIT:
      exit(*argv0);
      break;
    case SYS_EXEC:
      f->eax = exec((char *)*argv0);
  		break;
  	case SYS_WAIT:
      f->eax = wait(*argv0);
  		break;
  	case SYS_CREATE:
      f->eax = create((char *)*argv0, *argv1);
  		break;
  	case SYS_REMOVE:
      f->eax = remove((char *)*argv0);
  		break;
  	case SYS_OPEN:
      f->eax = open((char *)*argv0);
  		break;
  	case SYS_FILESIZE:
      f->eax = filesize(*argv0);
  		break;
  	case SYS_READ:
      f->eax = read(*argv0, (void *)*argv1, *argv2);
  		break;
  	case SYS_WRITE:
  		f->eax = write(*argv0, (void *)*argv1, *argv2);
  		break;
    case SYS_SEEK:
      seek(*argv0, *argv1);
  		break;
  	case SYS_TELL:
      f->eax = tell(*argv0);
  		break;
  	case SYS_CLOSE:
      close(*argv0);
  		break;
    default:
  		break;
  }
}

/* Check whether the given pointer is valid
   1. ptr shouldn't be a null pointer.
   2. ptr should point to an user memory.
   3. ptr shouldn't point to an unmapped virtual memory. */
bool
is_valid_ptr(const void *ptr)
{
  //printf("is_valid_ptr\n");
  if (ptr == NULL 
    || !is_user_vaddr(ptr) 
    || pagedir_get_page(thread_current()->pagedir, ptr) == NULL)
    return false;
  return true;
}

/* Check whether *file is a valid filename. */
bool
is_valid_filename(const void *file)
{
  if (!is_valid_ptr(file))
    exit(-1);

  int len = strlen(file);
  return len >= MIN_FILENAME && len <= MAX_FILENAME;
}

struct file_descriptor *
get_openfile(int fd)
{
  struct list *list = &thread_current()->fds;
  for (struct list_elem *e = list_begin (list); 
                          e != list_end (list); 
                          e = list_next (e))
  {
    struct file_descriptor *f = 
        list_entry(e, struct file_descriptor, fdelem);
    if (f->fd == fd)
      return f;
    else if (f->fd > fd)
      return NULL;
  }
  return NULL;
}

/* Close the open file of the given file descriptor.
   Iterate through the list of open files in the current thread and
   remove the file with the matching file descriptor.
   If the file descriptor is not found, return without doing anything. */
void
close_openfile(int fd)
{
  struct list *list = &thread_current()->fds;
  for (struct list_elem *e = list_begin (list); 
                          e != list_end (list); 
                          e = list_next (e))
  {
    struct file_descriptor *f = 
        list_entry(e, struct file_descriptor, fdelem);
    if (f->fd == fd)
    {
      list_remove(e);
      file_close(f->file);
      free(f);
      return;
    }
    else if (f->fd > fd)
      return;
  }
  return;
}

/* Terminates Pintos. */
static void
halt(void)
{
  shutdown_power_off();
}

/* Terminate the current user program.
   Return the status to the kernel.
   If the status is 0, it indicates success.
   Otherwise, it indicates an error. */
void
exit(int status)
{
  struct thread *cur = thread_current();

  printf("%s: exit(%d)\n", cur->name, status);

  /* If its parent is still waiting for it,
     inform its parent of its exit status. */
  if (cur->parent != NULL)
  {
    cur->parent->child_exit_status = status;
  }

  /* Close all the files that have been opened. */
  while (!list_empty(&cur->fds))
  {
    close(list_entry(list_begin(&cur->fds), struct file_descriptor, fdelem)->fd);
  }

  /* Close the executable file. */
  file_close(cur->file);

  thread_exit();
}

/* Run the executable whose name is given in cmd_line,
   passing any given arguments.
   Return the new process's program id(pid).
   Must return pid -1, which otherwise should not be a valid pid,
   if the program cannot load or run for any reason. */
static pid_t
exec(const char *cmd_line)
{
  if (!is_valid_ptr(cmd_line))    /* Check if the cmd_line is a valid pointer in the user address space. */
    exit(-1);

  lock_acquire(&filesys_lock);    /* Acquire the lock for the file system before executing the new process. */
  tid_t tid = process_execute(cmd_line);    /* Execute the new process and get its thread id(tid). */
  lock_release(&filesys_lock);    /* Release the lock for the file system after executing the new process. */
  
  return tid;
}

/* Wait for a child process pid.
   If pid is still alive, wait until it terminates.
   Return the child's exit status. */
static int
wait(pid_t pid)
{
  return process_wait(pid);
}

/* Assign unique fd to a file.
   Return fd. */
int
assign_fd()
{
  struct list *list = &thread_current()->fds;
  if (list_empty(list))
    return 2;
  else
  {
    struct file_descriptor *f = 
        list_entry(list_back(list), struct file_descriptor, fdelem);
    return f->fd + 1;
  }
}

/* Compare fd values as list_elem.
   Return true if fd(a) < fd(b), otherwise false. */
bool
cmp_fd(const struct list_elem *a, const struct list_elem *b, void *aux)
{
  struct file_descriptor *left = list_entry(a, struct file_descriptor, fdelem);
  struct file_descriptor *right = list_entry(b, struct file_descriptor, fdelem);
  return left->fd < right->fd;
}

/* Create a new file called *file that has intial_size size.
   Return true if successful, false otherwise. */
static bool
create(const char *file, unsigned initial_size)
{
  if (!is_valid_filename(file))   /* Check if the file name is valid. */
    return false;

  /* Acquire the file system lock to prevent other threads from accessing the file system. */
  lock_acquire(&filesys_lock);

  bool success = filesys_create (file, initial_size);

  lock_release(&filesys_lock);    /* Release the file system lock. */

  return success;
}

/* Delete the file called *file.
   Return true if successful, false otherwise. */
static bool
remove(const char *file)
{
  if (!is_valid_filename(file))
    return false;

  bool status;
  lock_acquire(&filesys_lock);
  status = filesys_remove(file);
  lock_release(&filesys_lock);

  return status;
}

/* Open the file called *file, assign the opened file a fd
   and the current process should keep track of it in fds list.
   Return fd if the file can be opend, otherwise -1. */
static int
open(const char *file)
{
  int fd = -1;

  if (!is_valid_filename(file))
    return fd;

  lock_acquire(&filesys_lock);
  struct list *list = &thread_current()->fds;
  struct file *file_struct = filesys_open(file);
  if (file_struct != NULL)
  {
    struct file_descriptor *tmp = malloc(sizeof(struct file_descriptor));
    tmp->fd = assign_fd();
    tmp->file = file_struct;
    fd = tmp->fd;
    list_insert_ordered(list, &tmp->fdelem, (list_less_func *)cmp_fd, NULL);
  }
  lock_release(&filesys_lock);

  return fd;
}

/* Get the size of fd file.
   Return its size. */
static int
filesize(int fd)
{
  int size = -1;

  lock_acquire(&filesys_lock);
  struct file_descriptor *file_descriptor = get_openfile(fd);
    if (file_descriptor != NULL)
      size = file_length(file_descriptor->file);
  lock_release(&filesys_lock);

  return size;
}

/* Read size bytes from fd into buffer.
   Return the number of bytes actully read. */
static int
read(int fd, void *buffer, unsigned size)
{
  int status = -1;

  if (!is_valid_ptr(buffer) || !is_valid_ptr(buffer + size - 1))
    exit(-1);

  lock_acquire(&filesys_lock);
  if (fd == STDIN_FILENO) /* Fead from the keyboard.*/
  {
    uint8_t *p = buffer;
    uint8_t c;
    unsigned counter = 0;
    while (counter < size && (c = input_getc()) != 0)
    {
      *p = c;
      p++;
      counter++;
    }
    *p = 0;
    status = size - counter;
  } else if (fd != STDOUT_FILENO)
  {
    struct file_descriptor *file_descriptor = get_openfile(fd);
    if (file_descriptor != NULL)
      status = file_read(file_descriptor->file, buffer, size);
  }
  lock_release(&filesys_lock);

  return status;
}

/* Write size bytes from buffer to fd.
   Return the number of bytes actually written. */
static int
write(int fd, const void *buffer, unsigned size)
{
  int status = 0;

  /* Check if buffer is a valid memory region.
     If not, exit the program with -1 status. */
  if (buffer == NULL || !is_valid_ptr(buffer) || !is_valid_ptr(buffer + size - 1))
    exit(-1);

  lock_acquire(&filesys_lock);
	if (fd == STDOUT_FILENO) /* Write to the console.*/
	{
		putbuf(buffer, size);
		status = size;
	} else if (fd != STDIN_FILENO)
  {
    struct file_descriptor *file_descriptor = get_openfile(fd);

    if (file_descriptor != NULL)
      status = file_write(file_descriptor->file, buffer, size);
  }
  lock_release(&filesys_lock);

  return status;
}

/* Change the next byte to be read/written in open fd to position,
   expressed in bytes from the beginning of the file. */
static void
seek(int fd, unsigned position)
{
  lock_acquire(&filesys_lock);
  struct file_descriptor *file_descriptor = get_openfile(fd);
    if (file_descriptor != NULL)
      file_seek(file_descriptor->file, position);
  lock_release(&filesys_lock);

  return;
}

/* Get the position of the next byte te be read/writen in open fd,
   expressed in bytes from the beginning of the file. */
static unsigned
tell(int fd)
{
  int status = -1;

  lock_acquire(&filesys_lock);
  struct file_descriptor *file_descriptor = get_openfile(fd);
    if (file_descriptor != NULL)
      status = file_tell(file_descriptor->file);
  lock_release(&filesys_lock);

  return status;
}

/* Close the file associated with file descriptor. */
static void
close(int fd)
{
  lock_acquire(&filesys_lock);
  close_openfile(fd);
  lock_release(&filesys_lock);
}
