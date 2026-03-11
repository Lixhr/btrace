#include "btrace.h"

__attribute__((section(".core")))
// __attribute__((naked)) 
void btrace_core(void)  {
    for (t_handler *h = __start_handlers; h < __stop_handlers; h++) {
        if (h->retaddr != 0)
            h->handler();  // appel de la fonction
    }
}