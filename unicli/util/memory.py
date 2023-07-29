

PAGE_SIZE = 4096
PAGE_MASK = ~(PAGE_SIZE - 1)


def page_start(x: int) -> int:
    return x & PAGE_MASK


def page_offset(x: int) -> int:
    return x & ~PAGE_MASK


def page_end(x: int) -> int:
    return page_start(x + (PAGE_SIZE-1))


def mem_align(v: int, a: int) -> int:
    return (v + a - 1) & ~(a - 1)


def page_align(x: int) -> int:
    return mem_align(x, PAGE_SIZE)
