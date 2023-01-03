#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

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
static pid_t exec(const char *cmd_line);
static int write(int fd, const void *buffer, unsigned size);
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
  /* Pointers to the arguments of the system call. */
  uint32_t *esp = f->esp;
  uint32_t *argv0 = esp + 1;
  uint32_t *argv1 = esp + 2;
  uint32_t *argv2 = esp + 3;

  /* Check if the pointers are not valid. */
  if (!is_valid_ptr(esp) || !is_valid_ptr(argv0) || !is_valid_ptr(argv1) || !is_valid_ptr(argv2))
  {
    exit(-1);   /* If any of the pointers are invalid, terminate the process with exit status -1. */
  }

  /* The system call number. */
  uint32_t syscall_num = *esp;
  switch (syscall_num)
  {
    case SYS_EXIT:
      exit(*argv0);
      break;
  	case SYS_WRITE:
  		f->eax = write(*argv0, (void *)*argv1, *argv2);
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
  if (ptr == NULL 
    || !is_user_vaddr(ptr) 
    || pagedir_get_page(thread_current()->pagedir, ptr) == NULL)
    return false;
  return true;
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

/* Close the file associated with file descriptor. */
static void
close(int fd)
{
  lock_acquire(&filesys_lock);
  close_openfile(fd);
  lock_release(&filesys_lock);
}
