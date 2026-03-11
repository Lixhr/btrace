#ifndef BTRACE_H
# define BTRACE_H

typedef struct {
    void (*handler)();  
    void *retaddr; // where to go after the hook 
}   t_handler;

extern t_handler __start_handlers[];
extern t_handler __stop_handlers[];

#define REGISTER_HANDLER(fn, ret) \
    const t_handler __handler_##fn \
    __attribute__((section(".handlers"), used)) = { \
        .handler = fn, \
        .retaddr = (void*)(ret) \
    }

#endif
