/* A minimal CRT/platform shim, hand-written so that the object carries no
   CodeView and its COFF symbols carry no function complex type. That is what
   leaves PUBLIC_FLAG_FUNCTION clear on a code public: the linker records what
   the object told it, and an assembly stub tells it nothing. */
        .text

        .globl  _platform_seed
_platform_seed:
        movl    $0x9E3779B9, %eax
        ret

        .globl  _platform_report
_platform_report:
        ret

        .globl  ___chkstk
___chkstk:
        ret

        .globl  _platform_ticks
_platform_ticks:
        xorl    %eax, %eax
        ret
