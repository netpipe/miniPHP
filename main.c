#define _GNU_SOURCE 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <stdarg.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <signal.h>
#include <stdint.h>
#include <limits.h>
#include <sys/types.h>
#include <fcntl.h>

enum {
    T_NULL, T_INT, T_FLOAT, T_BOOL, T_STRING, T_ARRAY
};

enum {
    NT_ECHO, NT_ASSIGN, NT_IF, NT_WHILE, NT_FOR, NT_FUNC, NT_RETURN, NT_EXPR,
    NT_INT, NT_FLOAT, NT_STR, NT_BOOL, NT_NULL, NT_VAR, NT_BINOP, NT_UNOP,
    NT_CALL, NT_INDEX, NT_ARRAY,
    NT_INCDEC, NT_TERNARY, NT_COALESCE, NT_BREAK, NT_CONTINUE,
    NT_FOREACH, NT_UNSET
};

enum {
    OP_ADD, OP_SUB, OP_MUL, OP_DIV, OP_MOD, OP_CONCAT,
    OP_EQ, OP_NEQ, OP_LT, OP_GT, OP_LE, OP_GE,
    OP_SAME, OP_DIFF, OP_AND, OP_OR, OP_NOT, OP_NEG, OP_POS,
    OP_COALESCE                 /* ??= only; ?? itself is NT_COALESCE */
};

enum {
    TK_EOF, TK_ECHO, TK_IF, TK_ELSEIF, TK_ELSE, TK_WHILE, TK_FOR,
    TK_FUNCTION, TK_RETURN, TK_TRUE, TK_FALSE, TK_NULL_KW, TK_ARRAY,
    TK_VAR, TK_IDENT, TK_INT, TK_FLOAT, TK_STR,
    TK_SEMI, TK_COMMA, TK_DOT, TK_ASSIGN, TK_EQEQ, TK_NEQ,
    TK_LT, TK_GT, TK_LE, TK_GE, TK_SAME, TK_DIFF,
    TK_LPAREN, TK_RPAREN, TK_LBRACE, TK_RBRACE, TK_LBRACK, TK_RBRACK,
    TK_ARROW, TK_BANG, TK_ANDAND, TK_OROR,
    TK_PLUS, TK_MINUS, TK_STAR, TK_SLASH, TK_PERCENT, TK_UNKNOWN,
    TK_INC, TK_DEC, TK_OPASSIGN, TK_QUESTION, TK_COLON, TK_COALESCE,
    TK_BREAK, TK_CONTINUE, TK_FOREACH, TK_AS
};

typedef struct Value Value;
typedef struct Node Node;

typedef struct NodeList {
    Node* node;
    struct NodeList* next;
} NodeList;

typedef struct Pair {
    Node* key;
    Node* val;
    struct Pair* next;
} Pair;

struct Node {
    int type, op;
    long long i;
    double d;
    char* s;
    Node *a, *b, *c;
    NodeList *l1, *l2;
    Pair* pairs;
};

typedef struct ArrayItem {
    Value* key;
    Value* val;
    struct ArrayItem* next;
} ArrayItem;

struct Value {
    int type;
    long long i;
    double d;
    char* s;
    int b;
    ArrayItem* items;
};

typedef struct Func {
    char* name;
    NodeList* params;
    NodeList* body;
    struct Func* next;
} Func;

typedef struct Var {
    char* name;
    Value* val;
    struct Var* next;
} Var;

typedef struct Env {
    Var* vars;
    struct Env* parent;   /* the typedef is not complete yet inside its own body */
} Env;

typedef struct Token {
    int type;
    char* text;
    long long i;
    double d;
} Token;

typedef struct Buf {
    char* data;
    size_t len;
    size_t cap;
} Buf;

typedef struct Header {
    char* line;
    struct Header* next;
} Header;

static Func* funcs = 0;
static Value* ret_val = 0;
static int in_ret = 0;
/* Pending `break N` / `continue N`: how many enclosing loops still have to
   act on it. Like in_ret, a nonzero value stops exec_list early. */
static long long brk_n = 0;
static long long cont_n = 0;
static Env* global_env = 0;

static char* lex_src = 0;
static size_t lex_pos = 0, lex_len = 0;
static Token cur;

static int cgi_mode = 0;

static Value *V_GET = 0;
static Value *V_POST = 0;
static Value *V_COOKIE = 0;
static Value *V_SESSION = 0;
static Value *V_SERVER = 0;
static Value *V_REQUEST = 0;

static Header* response_headers = 0;
static Buf response_body = {0};
static int response_status = 200;
static int response_flushed = 0;

static int session_started = 0;
static int session_saved = 0;
static char session_id[129] = {0};

static void fatal(const char* fmt, ...);

/* AUDIT (follow-up): memory_limit.
   Nothing bounded memory, and nothing is ever freed while a script runs, so a
   trivial loop grew at ~900 MB per SECOND (measured). The 30 s CPU limit does
   not help: the machine runs out of RAM long before that, and the kernel's
   OOM killer may take the database or the web server with it.

   So under CGI the process gets a memory_limit (256 MB by default) on top
   of what it already uses at startup, enforced by the kernel through
   RLIMIT_DATA. Every allocation in this file goes through the wrappers below,
   so running out is PHP's "Allowed memory size exhausted" error instead of a
   NULL pointer somewhere -- 21 allocation sites, several of which never
   checked. Override with PHPMINI_MEMORY_LIMIT ("512M", "1G", 0 = unlimited).

   Why 256 and not PHP's 128: PHP frees memory as it goes and this interpreter
   never does -- every loop iteration costs ~500 bytes for good (measured).
   At 128 MB an ordinary loop died at ~260,000 iterations; 256 MB allows
   ~520,000. The real fix is memory management (reference counting), which
   is a larger change than an audit should make. */
static size_t mem_limit_bytes = 0;            /* 0 = no limit was applied */

static void mem_exhausted(size_t want) {
    static int in_error = 0;
    if (in_error) {                    /* failed again while reporting: stop */
        static const char m[] = "PHP error: out of memory\n";
        ssize_t w = write(2, m, sizeof m - 1);
        (void)w;
        _exit(1);
    }
    in_error = 1;
    if (mem_limit_bytes) {
        /* raise the soft limit to the hard one, so the error path itself
           (output flush, session save) has room to run */
        struct rlimit rl;
        if (getrlimit(RLIMIT_DATA, &rl) == 0) { rl.rlim_cur = rl.rlim_max; setrlimit(RLIMIT_DATA, &rl); }
        fatal("Allowed memory size of %zu bytes exhausted (tried to allocate %zu bytes)",
              mem_limit_bytes, want);
    }
    fatal("Out of memory (tried to allocate %zu bytes)", want);
}

static void* mp_malloc(size_t n) {
    void* p = malloc(n);
    if (!p && n) mem_exhausted(n);
    return p;
}
static void* mp_calloc(size_t a, size_t b) {
    void* p = calloc(a, b);
    if (!p && a && b) mem_exhausted(a * b);
    return p;
}
static void* mp_realloc(void* q, size_t n) {
    void* p = realloc(q, n);
    if (!p && n) mem_exhausted(n);
    return p;
}
#define malloc(n)     mp_malloc(n)
#define calloc(a, b)  mp_calloc(a, b)
#define realloc(q, n) mp_realloc(q, n)
static char* xstrdup(const char* s);
static char* lower_dup(const char* s);
static char* case_dup(const char* s, int up);

static Node* parse_expr(void);
static Node* parse_statement(void);   /* used by parse_block before it is defined */
static Node* parse_unary(void);       /* recursive; wrapped with a depth limit */
static int is_lvalue(Node* e);
static Node* parse_postfix(void);
static Node* new_incdec(Node* target, int delta, int prefix);

/* AUDIT: a stack guard instead of recursion counters.
   The parser and the evaluator are both recursive, so a script nested deeply
   enough -- 200,000 parentheses, or a function that calls itself forever --
   ran off the end of the C stack and the process died with SIGSEGV. Under CGI
   that is one request killing its worker with no message.
   Counting levels does not bound it: a call level and a bracket level cost
   different amounts of stack, they COMBINE (a recursive call inside a deeply
   nested expression stacks both), and a sanitizer build's frames are several
   times larger again. So this measures the stack itself -- the same approach
   PHP 8.3 takes with zend.max_allowed_stack_size -- and stops with a normal
   error while there is still a safe margin left. */
/* How many loops enclose the statement being parsed, so `break` outside a
   loop -- or `break 3` inside two -- is a parse error as in PHP, instead of
   a flag that leaks out and stops some unrelated loop later. Reset to 0 for
   a function body: a break cannot cross a call. */
static int loop_depth = 0;

static uintptr_t stack_base = 0;
static size_t stack_budget = 0;

static void stack_guard_init(void* base) {
    struct rlimit rl;
    size_t total = (size_t)8 << 20;                     /* the usual default */
    if (getrlimit(RLIMIT_STACK, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY && rl.rlim_cur > 0)
        total = (size_t)rl.rlim_cur;
    stack_base = (uintptr_t)base;
    /* keep a quarter of the stack (at least 256 KB) as headroom for the
       frames between one check and the next, and for the error path */
    size_t keep = total / 4;
    if (keep < ((size_t)256 << 10)) keep = (size_t)256 << 10;
    stack_budget = total > keep ? total - keep : total / 2;
}

static void stack_guard(void) {
    /* The FRAME address, not the address of a local: under AddressSanitizer
       locals can live on a heap "fake stack", which would make a local's
       address meaningless as a depth measurement. */
    uintptr_t p = (uintptr_t)__builtin_frame_address(0);
    if (stack_base && p < stack_base && stack_base - p > stack_budget)
        fatal("Maximum call stack size of %zu bytes reached. Infinite recursion?",
              stack_budget);
}
static Value* eval(Node* n, Env* env);
static void exec(Node* n, Env* env);
static void exec_list(NodeList* l, Env* env);
static void assign_to(Node* target, Value* val, Env* env);
static long long array_next_index(Value* arr);
static Value* call_user(Func* f, Value** args, int argc);
static Value* builtin(const char* name, Value** args, int argc);

static void emit_string(const char* s);
static void add_response_header_ex(const char* line, int replace);
static void session_start_impl(void);
static void session_destroy_impl(void);
static void web_bootstrap(Env* env);
static void web_atexit(void);

static void fatal(const char* fmt, ...) {
    va_list ap;
    fprintf(stderr, "PHP error: ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
    exit(1);
}

static char* xstrdup(const char* s) {
    if (!s) s = "";
    size_t n = strlen(s) + 1;
    char* r = malloc(n);
    if (!r) fatal("out of memory");
    memcpy(r, s, n);
    return r;
}

static char* lower_dup(const char* s) {
    char* r = xstrdup(s);
    for (char* p = r; *p; p++) *p = (char)tolower((unsigned char)*p);
    return r;
}

static char* case_dup(const char* s, int up) {
    char* r = xstrdup(s);
    for (char* p = r; *p; p++)
        *p = (char)(up ? toupper((unsigned char)*p) : tolower((unsigned char)*p));
    return r;
}

static void buf_init(Buf* b) {
    b->data = 0;
    b->len = 0;
    b->cap = 0;
}

static void buf_reserve(Buf* b, size_t extra) {
    /* AUDIT: this used to set cap = 64 on an empty buffer WITHOUT allocating,
       so the grow loop below saw "64 is plenty" and never called realloc.
       data stayed NULL and the first byte written went to address 0. Every
       Buf in the interpreter starts empty, so this crashed on the first
       character of every script. Allocate whenever there is no storage. */
    size_t need = b->len + extra + 1;
    if (b->data && need <= b->cap) return;
    size_t cap = b->cap ? b->cap : 64;
    while (cap < need) cap *= 2;
    char* p = realloc(b->data, cap);
    if (!p) fatal("out of memory");
    b->data = p;
    b->cap = cap;
}

static void buf_add(Buf* b, const char* s, size_t n) {
    if (!n) return;
    buf_reserve(b, n);
    memcpy(b->data + b->len, s, n);
    b->len += n;
    b->data[b->len] = 0;
}

static void buf_addz(Buf* b, const char* s) {
    if (s) buf_add(b, s, strlen(s));
}

static void buf_ch(Buf* b, char c) {
    buf_reserve(b, 1);
    b->data[b->len++] = c;
    b->data[b->len] = 0;
}

static void buf_fmt(Buf* b, const char* fmt, ...) {
    va_list ap, ap2;
    va_start(ap, fmt);
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0) {
        va_end(ap2);
        return;
    }
    char* tmp = malloc((size_t)n + 1);
    if (!tmp) fatal("out of memory");
    vsnprintf(tmp, (size_t)n + 1, fmt, ap2);
    va_end(ap2);
    buf_add(b, tmp, (size_t)n);
    free(tmp);
}

static char* read_all(FILE* f) {
    Buf b;
    buf_init(&b);
    int c;
    while ((c = fgetc(f)) != EOF)
        buf_ch(&b, (char)c);
    if (!b.data) return xstrdup("");
    return b.data;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static char* url_decode(const char* s) {
    Buf b;
    buf_init(&b);
    if (!s) return xstrdup("");

    for (size_t i = 0; s[i]; i++) {
        if (s[i] == '+') {
            buf_ch(&b, ' ');
        } else if (s[i] == '%' && hexval(s[i+1]) >= 0 && hexval(s[i+2]) >= 0) {
            char h[3] = { s[i+1], s[i+2], 0 };
            buf_ch(&b, (char)strtol(h, 0, 16));
            i += 2;
        } else {
            buf_ch(&b, s[i]);
        }
    }

    return b.data ? b.data : xstrdup("");
}

static int url_unreserved(char c) {
    return isalnum((unsigned char)c) || c == '-' || c == '_' || c == '.' || c == '~';
}

static char* url_encode(const char* s) {
    Buf b;
    buf_init(&b);
    if (!s) return xstrdup("");

    for (size_t i = 0; s[i]; i++) {
        unsigned char c = (unsigned char)s[i];
        if (url_unreserved((char)c)) buf_ch(&b, (char)c);
        else buf_fmt(&b, "%%%02X", c);
    }

    return b.data ? b.data : xstrdup("");
}

static char* html_escape(const char* s) {
    Buf b;
    buf_init(&b);
    if (!s) return xstrdup("");

    for (size_t i = 0; s[i]; i++) {
        switch (s[i]) {
            case '&': buf_addz(&b, "&amp;"); break;
            case '<': buf_addz(&b, "&lt;"); break;
            case '>': buf_addz(&b, "&gt;"); break;
            case '"': buf_addz(&b, "&quot;"); break;
            case '\'': buf_addz(&b, "&#039;"); break;
            default: buf_ch(&b, s[i]); break;
        }
    }

    return b.data ? b.data : xstrdup("");
}

static void format_http_date(time_t t, char* out, size_t n) {
    static const char* wd[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
    static const char* mon[] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };

    struct tm* g = gmtime(&t);
    if (!g) {
        snprintf(out, n, "Thu, 01 Jan 1970 00:00:00 GMT");
        return;
    }

    snprintf(out, n, "%s, %02d %s %04d %02d:%02d:%02d GMT",
        wd[g->tm_wday],
        g->tm_mday,
        mon[g->tm_mon],
        g->tm_year + 1900,
        g->tm_hour,
        g->tm_min,
        g->tm_sec);
}

static int tag_at(const char* p, int* type) {
    if (strncmp(p, "<?php", 5) == 0) {
        *type = 1;
        return 5;
    }
    if (strncmp(p, "<?=", 3) == 0) {
        *type = 2;
        return 3;
    }
    return 0;
}

static const char* find_tag(const char* s) {
    for (const char* p = s; *p; p++) {
        int type;
        if (tag_at(p, &type)) return p;
    }
    return 0;
}

static const char* find_short_close(const char* p) {
    char q = 0;
    for (; *p; p++) {
        if (q) {
            if (*p == '\\' && p[1]) {
                p++;
                continue;
            }
            if (*p == q) q = 0;
            continue;
        }

        if (*p == '"' || *p == '\'') {
            q = *p;
            continue;
        }

        if (*p == '?' && p[1] == '>') return p;
    }
    return p;
}

static const char* find_php_close(const char* p) {
    int state = 0; /* 0 normal, 1 single, 2 double, 3 line comment, 4 block comment */

    while (*p) {
        if (state == 0) {
            if (p[0] == '/' && p[1] == '/') { state = 3; p += 2; continue; }
            if (p[0] == '#') { state = 3; p++; continue; }
            if (p[0] == '/' && p[1] == '*') { state = 4; p += 2; continue; }
            if (p[0] == '\'') { state = 1; p++; continue; }
            if (p[0] == '"') { state = 2; p++; continue; }
            if (p[0] == '?' && p[1] == '>') return p;
            p++;
        } else if (state == 1) {
            if (*p == '\\' && p[1]) p += 2;
            else {
                if (*p == '\'') state = 0;
                p++;
            }
        } else if (state == 2) {
            if (*p == '\\' && p[1]) p += 2;
            else {
                if (*p == '"') state = 0;
                p++;
            }
        } else if (state == 3) {
            if (*p == '\n') state = 0;
            p++;
        } else if (state == 4) {
            if (*p == '*' && p[1] == '/') {
                state = 0;
                p += 2;
            } else {
                p++;
            }
        }
    }

    return p;
}

static void append_html_echo(Buf* out, const char* s, size_t n) {
    if (!n) return;

    buf_addz(out, "echo \"");
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];

        if (c == '\\') buf_addz(out, "\\\\");
        else if (c == '"') buf_addz(out, "\\\"");
        else if (c == '\n') buf_addz(out, "\\n");
        else if (c == '\r') buf_addz(out, "\\r");
        else if (c == '\t') buf_addz(out, "\\t");
        else buf_ch(out, (char)c);
    }
    buf_addz(out, "\";\n");
}

static char* preprocess_source(const char* src) {
    const char* first = find_tag(src);

    int looks_html = 0;
    for (const char* p = src; *p; p++) {
        if (!isspace((unsigned char)*p)) {
            if (*p == '<') looks_html = 1;
            break;
        }
    }

    if (!first && !looks_html)
        return xstrdup(src);

    Buf out;
    buf_init(&out);

    const char* p = src;
    while (*p) {
        const char* tag = find_tag(p);
        if (!tag) {
            append_html_echo(&out, p, strlen(p));
            break;
        }

        if (tag > p)
            append_html_echo(&out, p, (size_t)(tag - p));

        int type = 0;
        int tl = tag_at(tag, &type);
        p = tag + tl;

        if (type == 2) {
            const char* close = find_short_close(p);
            size_t n = (size_t)(close - p);

            buf_addz(&out, "echo ");
            buf_add(&out, p, n);
            buf_addz(&out, ";\n");

            if (*close == '?') p = close + 2;
            else p = close;
        } else {
            const char* close = find_php_close(p);
            size_t n = (size_t)(close - p);

            buf_add(&out, p, n);
            buf_addz(&out, ";\n");

            if (*close == '?') p = close + 2;
            else p = close;
        }
    }

    return out.data ? out.data : xstrdup("");
}

static Node* new_node(int type) {
    Node* n = calloc(1, sizeof(Node));
    if (!n) fatal("out of memory");
    n->type = type;
    return n;
}

static Node* new_binop(int op, Node* a, Node* b) {
    Node* n = new_node(NT_BINOP);
    n->op = op;
    n->a = a;
    n->b = b;
    return n;
}

static Node* new_unop(int op, Node* a) {
    Node* n = new_node(NT_UNOP);
    n->op = op;
    n->a = a;
    return n;
}

static void list_add(NodeList** head, Node* n) {
    NodeList* x = calloc(1, sizeof(NodeList));
    if (!x) fatal("out of memory");
    x->node = n;

    if (!*head) {
        *head = x;
    } else {
        NodeList* p = *head;
        while (p->next) p = p->next;
        p->next = x;
    }
}

static void pair_add(Pair** head, Node* k, Node* v) {
    Pair* x = calloc(1, sizeof(Pair));
    if (!x) fatal("out of memory");
    x->key = k;
    x->val = v;

    if (!*head) {
        *head = x;
    } else {
        Pair* p = *head;
        while (p->next) p = p->next;
        p->next = x;
    }
}

static int list_count(NodeList* l) {
    int c = 0;
    while (l) {
        c++;
        l = l->next;
    }
    return c;
}

static Token lex_next(void) {
    Token t;
    memset(&t, 0, sizeof t);

    while (lex_pos < lex_len) {
        if (isspace((unsigned char)lex_src[lex_pos])) {
            lex_pos++;
        } else if (lex_pos + 1 < lex_len && lex_src[lex_pos] == '/' && lex_src[lex_pos + 1] == '/') {
            while (lex_pos < lex_len && lex_src[lex_pos] != '\n') lex_pos++;
        } else if (lex_src[lex_pos] == '#') {
            while (lex_pos < lex_len && lex_src[lex_pos] != '\n') lex_pos++;
        } else if (lex_pos + 1 < lex_len && lex_src[lex_pos] == '/' && lex_src[lex_pos + 1] == '*') {
            lex_pos += 2;
            while (lex_pos + 1 < lex_len && !(lex_src[lex_pos] == '*' && lex_src[lex_pos + 1] == '/'))
                lex_pos++;
            if (lex_pos + 1 < lex_len) lex_pos += 2;
            else lex_pos = lex_len;
        } else {
            break;
        }
    }

    if (lex_pos >= lex_len) {
        t.type = TK_EOF;
        return t;
    }

    char c = lex_src[lex_pos];

    if (isalpha((unsigned char)c) || c == '_') {
        size_t st = lex_pos;
        while (lex_pos < lex_len && (isalnum((unsigned char)lex_src[lex_pos]) || lex_src[lex_pos] == '_'))
            lex_pos++;

        size_t n = lex_pos - st;
        char* word = malloc(n + 1);
        if (!word) fatal("out of memory");
        memcpy(word, lex_src + st, n);
        word[n] = 0;

        char* lw = lower_dup(word);
        int tt = TK_IDENT;

        if (!strcmp(lw, "echo")) tt = TK_ECHO;
        else if (!strcmp(lw, "if")) tt = TK_IF;
        else if (!strcmp(lw, "elseif")) tt = TK_ELSEIF;
        else if (!strcmp(lw, "else")) tt = TK_ELSE;
        else if (!strcmp(lw, "while")) tt = TK_WHILE;
        else if (!strcmp(lw, "for")) tt = TK_FOR;
        else if (!strcmp(lw, "break")) tt = TK_BREAK;
        else if (!strcmp(lw, "foreach")) tt = TK_FOREACH;
        else if (!strcmp(lw, "as")) tt = TK_AS;
        else if (!strcmp(lw, "continue")) tt = TK_CONTINUE;
        else if (!strcmp(lw, "function")) tt = TK_FUNCTION;
        else if (!strcmp(lw, "return")) tt = TK_RETURN;
        else if (!strcmp(lw, "true")) tt = TK_TRUE;
        else if (!strcmp(lw, "false")) tt = TK_FALSE;
        else if (!strcmp(lw, "null")) tt = TK_NULL_KW;
        else if (!strcmp(lw, "array")) tt = TK_ARRAY;

        if (tt != TK_IDENT) {
            t.type = tt;
            t.text = lw;
        } else {
            t.type = TK_IDENT;
            t.text = word;
            free(lw);
        }

        return t;
    }

    if (c == '$') {
        lex_pos++;
        if (lex_pos >= lex_len || !(isalpha((unsigned char)lex_src[lex_pos]) || lex_src[lex_pos] == '_'))
            fatal("Bad variable name");

        size_t st = lex_pos;
        while (lex_pos < lex_len && (isalnum((unsigned char)lex_src[lex_pos]) || lex_src[lex_pos] == '_'))
            lex_pos++;

        size_t n = lex_pos - st;
        char* word = malloc(n + 1);
        if (!word) fatal("out of memory");
        memcpy(word, lex_src + st, n);
        word[n] = 0;

        t.type = TK_VAR;
        t.text = word;
        return t;
    }

    if (c == '0' && lex_pos + 1 < lex_len && (lex_src[lex_pos + 1] == 'x' || lex_src[lex_pos + 1] == 'X')) {
        lex_pos += 2;
        char* end = 0;
        long long v = strtoll(lex_src + lex_pos, &end, 16);
        if (end == lex_src + lex_pos) v = 0;
        lex_pos = (size_t)(end - lex_src);

        t.type = TK_INT;
        t.i = v;
        return t;
    }

    if (isdigit((unsigned char)c) || (c == '.' && lex_pos + 1 < lex_len && isdigit((unsigned char)lex_src[lex_pos + 1]))) {
        char* start = lex_src + lex_pos;
        char* end = 0;
        double d = strtod(start, &end);

        if (end == start) {
            t.type = TK_UNKNOWN;
            lex_pos++;
            return t;
        }

        int isf = 0;
        for (char* q = start; q < end; q++)
            if (*q == '.' || *q == 'e' || *q == 'E') isf = 1;

        lex_pos = (size_t)(end - lex_src);

        if (isf) {
            t.type = TK_FLOAT;
            t.d = d;
        } else {
            char* e2 = 0;
            long long li = strtoll(start, &e2, 10);
            t.type = TK_INT;
            t.i = (e2 == end) ? li : (long long)d;
        }

        return t;
    }

    if (c == '"' || c == '\'') {
        char quote = c;
        lex_pos++;

        Buf b;
        buf_init(&b);

        while (lex_pos < lex_len && lex_src[lex_pos] != quote) {
            if (lex_src[lex_pos] == '\\' && lex_pos + 1 < lex_len) {
                char e = lex_src[lex_pos + 1];
                lex_pos += 2;

                if (quote == '\'') {
                    if (e == '\\') buf_ch(&b, '\\');
                    else if (e == '\'') buf_ch(&b, '\'');
                    else {
                        buf_ch(&b, '\\');
                        buf_ch(&b, e);
                    }
                } else {
                    switch (e) {
                        case 'n': buf_ch(&b, '\n'); break;
                        case 't': buf_ch(&b, '\t'); break;
                        case 'r': buf_ch(&b, '\r'); break;
                        case '\\': buf_ch(&b, '\\'); break;
                        case '"': buf_ch(&b, '"'); break;
                        case '\'': buf_ch(&b, '\''); break;
                        case '0': buf_ch(&b, '0'); break;
                        default:
                            buf_ch(&b, '\\');
                            buf_ch(&b, e);
                    }
                }
            } else {
                buf_ch(&b, lex_src[lex_pos++]);
            }
        }

        if (lex_pos >= lex_len) fatal("Unterminated string");
        lex_pos++;

        t.type = TK_STR;
        t.text = b.data ? b.data : xstrdup("");
        return t;
    }

    if (c == '=') {
        if (lex_pos + 1 < lex_len && lex_src[lex_pos + 1] == '=') {
            if (lex_pos + 2 < lex_len && lex_src[lex_pos + 2] == '=') {
                t.type = TK_SAME;
                lex_pos += 3;
            } else {
                t.type = TK_EQEQ;
                lex_pos += 2;
            }
        } else if (lex_pos + 1 < lex_len && lex_src[lex_pos + 1] == '>') {
            t.type = TK_ARROW;
            lex_pos += 2;
        } else {
            t.type = TK_ASSIGN;
            lex_pos++;
        }
        return t;
    }

    if (c == '!') {
        if (lex_pos + 1 < lex_len && lex_src[lex_pos + 1] == '=') {
            if (lex_pos + 2 < lex_len && lex_src[lex_pos + 2] == '=') {
                t.type = TK_DIFF;
                lex_pos += 3;
            } else {
                t.type = TK_NEQ;
                lex_pos += 2;
            }
        } else {
            t.type = TK_BANG;
            lex_pos++;
        }
        return t;
    }

    if (c == '<') {
        if (lex_pos + 1 < lex_len && lex_src[lex_pos + 1] == '=') {
            t.type = TK_LE;
            lex_pos += 2;
        } else {
            t.type = TK_LT;
            lex_pos++;
        }
        return t;
    }

    if (c == '>') {
        if (lex_pos + 1 < lex_len && lex_src[lex_pos + 1] == '=') {
            t.type = TK_GE;
            lex_pos += 2;
        } else {
            t.type = TK_GT;
            lex_pos++;
        }
        return t;
    }

    if (c == '&') {
        if (lex_pos + 1 < lex_len && lex_src[lex_pos + 1] == '&') {
            t.type = TK_ANDAND;
            lex_pos += 2;
        } else {
            t.type = TK_UNKNOWN;
            lex_pos++;
        }
        return t;
    }

    if (c == '|') {
        if (lex_pos + 1 < lex_len && lex_src[lex_pos + 1] == '|') {
            t.type = TK_OROR;
            lex_pos += 2;
        } else {
            t.type = TK_UNKNOWN;
            lex_pos++;
        }
        return t;
    }

    /* ++ --, compound assignment, ?: and ?? -- checked before the single-
       character switch below so "+=" never lexes as "+" then "=". The
       operator behind a compound assignment travels in t.i. */
    {
        char n1 = (lex_pos + 1 < lex_len) ? lex_src[lex_pos + 1] : 0;
        char n2 = (lex_pos + 2 < lex_len) ? lex_src[lex_pos + 2] : 0;

        if (c == '+' && n1 == '+') { t.type = TK_INC; lex_pos += 2; return t; }
        if (c == '-' && n1 == '-') { t.type = TK_DEC; lex_pos += 2; return t; }

        if (n1 == '=' && strchr("+-*/.%", c)) {
            t.type = TK_OPASSIGN;
            t.i = c == '+' ? OP_ADD : c == '-' ? OP_SUB : c == '*' ? OP_MUL :
                  c == '/' ? OP_DIV : c == '.' ? OP_CONCAT : OP_MOD;
            lex_pos += 2;
            return t;
        }

        if (c == '?' && n1 == '?' && n2 == '=') { t.type = TK_OPASSIGN; t.i = OP_COALESCE; lex_pos += 3; return t; }
        if (c == '?' && n1 == '?') { t.type = TK_COALESCE; lex_pos += 2; return t; }
        if (c == '?') { t.type = TK_QUESTION; lex_pos++; return t; }
        if (c == ':') { t.type = TK_COLON; lex_pos++; return t; }
    }

    switch (c) {
        case ';': t.type = TK_SEMI; lex_pos++; return t;
        case ',': t.type = TK_COMMA; lex_pos++; return t;
        case '.': t.type = TK_DOT; lex_pos++; return t;
        case '(': t.type = TK_LPAREN; lex_pos++; return t;
        case ')': t.type = TK_RPAREN; lex_pos++; return t;
        case '{': t.type = TK_LBRACE; lex_pos++; return t;
        case '}': t.type = TK_RBRACE; lex_pos++; return t;
        case '[': t.type = TK_LBRACK; lex_pos++; return t;
        case ']': t.type = TK_RBRACK; lex_pos++; return t;
        case '+': t.type = TK_PLUS; lex_pos++; return t;
        case '-': t.type = TK_MINUS; lex_pos++; return t;
        case '*': t.type = TK_STAR; lex_pos++; return t;
        case '/': t.type = TK_SLASH; lex_pos++; return t;
        case '%': t.type = TK_PERCENT; lex_pos++; return t;
        default:
            t.type = TK_UNKNOWN;
            lex_pos++;
            return t;
    }
}

static void adv(void) {
    cur = lex_next();
}

static int match(int t) {
    if (cur.type == t) {
        adv();
        return 1;
    }
    return 0;
}

static void expect(int t, const char* msg) {
    if (cur.type != t) fatal("Syntax error: expected %s", msg);
    adv();
}

static NodeList* parse_call_args(void) {
    NodeList* args = 0;

    if (!match(TK_RPAREN)) {
        do {
            list_add(&args, parse_expr());
        } while (match(TK_COMMA));
        expect(TK_RPAREN, ")");
    }

    return args;
}

static NodeList* parse_params(void) {
    NodeList* params = 0;

    if (!match(TK_RPAREN)) {
        do {
            if (cur.type != TK_VAR) fatal("Expected parameter");
            Node* p = new_node(NT_VAR);
            p->s = cur.text;
            adv();
            list_add(&params, p);
        } while (match(TK_COMMA));
        expect(TK_RPAREN, ")");
    }

    return params;
}

static Pair* parse_array_items(int close) {
    Pair* items = 0;

    if (!match(close)) {
        do {
            if (cur.type == close) break;

            Node* first = parse_expr();
            if (match(TK_ARROW)) {
                Node* second = parse_expr();
                pair_add(&items, first, second);
            } else {
                pair_add(&items, 0, first);
            }
        } while (match(TK_COMMA));

        expect(close, close == TK_RBRACK ? "]" : ")");
    }

    return items;
}

static NodeList* parse_block(void) {
    NodeList* l = 0;

    if (match(TK_LBRACE)) {
        while (cur.type != TK_RBRACE && cur.type != TK_EOF)
            list_add(&l, parse_statement());
        expect(TK_RBRACE, "}");
    } else {
        list_add(&l, parse_statement());
    }

    return l;
}

static Node* parse_if(int is_elseif) {
    if (is_elseif) expect(TK_ELSEIF, "elseif");
    else expect(TK_IF, "if");

    expect(TK_LPAREN, "(");
    Node* cond = parse_expr();
    expect(TK_RPAREN, ")");

    NodeList* then = parse_block();
    NodeList* els = 0;

    if (cur.type == TK_ELSEIF) {
        Node* nested = parse_if(1);
        list_add(&els, nested);
    } else if (match(TK_ELSE)) {
        els = parse_block();
    }

    Node* n = new_node(NT_IF);
    n->a = cond;
    n->l1 = then;
    n->l2 = els;
    return n;
}

/* One parser for "expression or assignment", used by statements AND by the
   init/step parts of for(). It used to exist twice, which is how compound
   assignment would have ended up working in one place and not the other.
   NT_ASSIGN: i = 0 plain, i = 1 compound with the operator in op. */
static Node* parse_simple_stmt(void) {
    Node* e = parse_expr();

    if (cur.type == TK_ASSIGN || cur.type == TK_OPASSIGN) {
        int compound = cur.type == TK_OPASSIGN;
        int op = (int)cur.i;
        adv();
        Node* v = parse_expr();
        if (!is_lvalue(e)) fatal("Invalid assignment");
        /* ??= has to READ the target first, so $a[] ??= v is an error in PHP;
           the arithmetic forms (+=, .= ...) append instead. */
        if (compound && op == OP_COALESCE && e->type == NT_INDEX && !e->b)
            fatal("Cannot use [] for reading");

        Node* n = new_node(NT_ASSIGN);
        n->a = e;
        n->b = v;
        n->i = compound;
        n->op = compound ? op : 0;
        return n;
    }

    if (e->type == NT_INDEX && !e->b) fatal("Cannot use [] for reading");

    Node* n = new_node(NT_EXPR);
    n->a = e;
    return n;
}

static Node* parse_statement_inner(void) {
    switch (cur.type) {
        case TK_SEMI: {
            adv();
            Node* n = new_node(NT_EXPR);
            n->a = new_node(NT_NULL);
            return n;
        }

        case TK_ECHO: {
            adv();
            NodeList* args = 0;
            do {
                list_add(&args, parse_expr());
            } while (match(TK_COMMA));
            expect(TK_SEMI, ";");

            Node* n = new_node(NT_ECHO);
            n->l1 = args;
            return n;
        }

        case TK_IF:
            return parse_if(0);

        case TK_ELSEIF:
            return parse_if(1);

        case TK_WHILE: {
            adv();
            expect(TK_LPAREN, "(");
            Node* cond = parse_expr();
            expect(TK_RPAREN, ")");
            loop_depth++;
            NodeList* body = parse_block();
            loop_depth--;

            Node* n = new_node(NT_WHILE);
            n->a = cond;
            n->l1 = body;
            return n;
        }

        case TK_FOR: {
            adv();
            expect(TK_LPAREN, "(");

            Node* init = 0;
            if (cur.type != TK_SEMI) init = parse_simple_stmt();
            expect(TK_SEMI, ";");

            Node* cond = 0;
            if (cur.type != TK_SEMI) cond = parse_expr();
            expect(TK_SEMI, ";");

            Node* upd = 0;
            if (cur.type != TK_RPAREN) upd = parse_simple_stmt();
            expect(TK_RPAREN, ")");

            loop_depth++;
            NodeList* body = parse_block();
            loop_depth--;

            Node* n = new_node(NT_FOR);
            n->a = init;
            n->b = cond;
            n->c = upd;
            n->l1 = body;
            return n;
        }

        case TK_FUNCTION: {
            adv();
            if (cur.type != TK_IDENT) fatal("Expected function name");

            Node* n = new_node(NT_FUNC);
            n->s = cur.text;
            adv();

            expect(TK_LPAREN, "(");
            n->l1 = parse_params();
            int outer_loops = loop_depth;
            loop_depth = 0;                 /* a break cannot cross a call */
            n->l2 = parse_block();
            loop_depth = outer_loops;
            return n;
        }

        case TK_RETURN: {
            adv();
            Node* e = 0;
            if (cur.type != TK_SEMI) e = parse_expr();
            expect(TK_SEMI, ";");

            Node* n = new_node(NT_RETURN);
            n->a = e;
            return n;
        }

        case TK_FOREACH: {
            /* foreach ($arr as $v) / foreach ($arr as $k => $v). The targets
               may be anything assignable, $a["x"] included, as in PHP. */
            adv();
            expect(TK_LPAREN, "(");
            Node* src = parse_expr();
            expect(TK_AS, "as");
            if (cur.type == TK_UNKNOWN)          /* '&' lexes as unknown */
                fatal("foreach by reference (&$v) is not supported");
            Node* first = parse_postfix();
            Node* key = 0;
            Node* val = first;
            if (match(TK_ARROW)) {
                if (cur.type == TK_UNKNOWN) fatal("foreach by reference (&$v) is not supported");
                key = first;
                val = parse_postfix();
            }
            if (!is_lvalue(val) || (key && !is_lvalue(key))) fatal("Cannot assign to this foreach target");
            if ((val->type == NT_INDEX && !val->b) || (key && key->type == NT_INDEX && !key->b))
                fatal("Cannot use [] for reading");
            expect(TK_RPAREN, ")");

            loop_depth++;
            NodeList* body = parse_block();
            loop_depth--;

            Node* n = new_node(NT_FOREACH);
            n->a = src;
            n->b = key;
            n->c = val;
            n->l1 = body;
            return n;
        }

        case TK_BREAK:
        case TK_CONTINUE: {
            int is_break = cur.type == TK_BREAK;
            adv();
            long long levels = 1;
            if (cur.type == TK_INT) { levels = cur.i; adv(); }
            expect(TK_SEMI, ";");

            if (levels < 1) fatal("'%s' operator accepts only positive integers",
                                  is_break ? "break" : "continue");
            if (loop_depth == 0) fatal("'%s' not in the 'loop' context",
                                       is_break ? "break" : "continue");
            if (levels > loop_depth) fatal("Cannot '%s' %lld levels",
                                           is_break ? "break" : "continue", levels);

            Node* n = new_node(is_break ? NT_BREAK : NT_CONTINUE);
            n->i = levels;
            return n;
        }

        default: {
            Node* n = parse_simple_stmt();
            expect(TK_SEMI, ";");

            /* unset() is a statement in PHP, not a function: it needs the
               variable or element ITSELF, and a function call would only
               receive its value. Recognised here and turned into NT_UNSET. */
            if (n->type == NT_EXPR && n->a->type == NT_CALL && !strcasecmp(n->a->s, "unset")) {
                for (NodeList* l = n->a->l1; l; l = l->next)
                    if (!is_lvalue(l->node) || (l->node->type == NT_INDEX && !l->node->b))
                        fatal("unset() can only remove a variable or an array element");
                Node* u = new_node(NT_UNSET);
                u->l1 = n->a->l1;
                return u;
            }
            return n;
        }
    }
}

static Node* parse_statement(void) {
    stack_guard();
    return parse_statement_inner();
}

static NodeList* parse_program(void) {
    NodeList* l = 0;
    while (cur.type != TK_EOF)
        list_add(&l, parse_statement());
    return l;
}

static Node* parse_primary(void) {
    switch (cur.type) {
        case TK_INT: {
            Node* n = new_node(NT_INT);
            n->i = cur.i;
            adv();
            return n;
        }

        case TK_FLOAT: {
            Node* n = new_node(NT_FLOAT);
            n->d = cur.d;
            adv();
            return n;
        }

        case TK_STR: {
            Node* n = new_node(NT_STR);
            n->s = cur.text;
            adv();
            return n;
        }

        case TK_TRUE: {
            Node* n = new_node(NT_BOOL);
            n->i = 1;
            adv();
            return n;
        }

        case TK_FALSE: {
            Node* n = new_node(NT_BOOL);
            n->i = 0;
            adv();
            return n;
        }

        case TK_NULL_KW: {
            Node* n = new_node(NT_NULL);
            adv();
            return n;
        }

        case TK_VAR: {
            Node* n = new_node(NT_VAR);
            n->s = cur.text;
            adv();
            return n;
        }

        case TK_LBRACK: {
            adv();
            Pair* items = parse_array_items(TK_RBRACK);
            Node* n = new_node(NT_ARRAY);
            n->pairs = items;
            return n;
        }

        case TK_ARRAY: {
            adv();
            expect(TK_LPAREN, "(");
            Pair* items = parse_array_items(TK_RPAREN);
            Node* n = new_node(NT_ARRAY);
            n->pairs = items;
            return n;
        }

        case TK_LPAREN: {
            adv();
            Node* e = parse_expr();
            expect(TK_RPAREN, ")");
            return e;
        }

        case TK_IDENT: {
            char* name = cur.text;
            adv();

            if (match(TK_LPAREN)) {
                NodeList* args = parse_call_args();
                Node* n = new_node(NT_CALL);
                n->s = name;
                n->l1 = args;
                return n;
            }

            Node* n = new_node(NT_STR);
            n->s = name;
            return n;
        }

        default:
            fatal("Unexpected token");
            return NULL;
    }
}

static int is_lvalue(Node* e) {
    return e && (e->type == NT_VAR || e->type == NT_INDEX);
}

static Node* new_incdec(Node* target, int delta, int prefix) {
    if (!is_lvalue(target)) fatal("Cannot increment or decrement this expression");
    if (target->type == NT_INDEX && !target->b) fatal("Cannot use [] for reading");
    Node* n = new_node(NT_INCDEC);
    n->a = target;
    n->op = delta;
    n->i = prefix;
    return n;
}

static Node* parse_postfix(void) {
    Node* e = parse_primary();

    while (match(TK_LBRACK)) {
        /* $a[] -- an append target. b stays NULL; reading through it is
           rejected when it is evaluated, as PHP rejects it. */
        Node* idx = 0;
        if (cur.type != TK_RBRACK) idx = parse_expr();
        expect(TK_RBRACK, "]");

        Node* n = new_node(NT_INDEX);
        n->a = e;
        n->b = idx;
        e = n;
    }

    if (cur.type == TK_INC || cur.type == TK_DEC) {
        int delta = cur.type == TK_INC ? 1 : -1;
        adv();
        e = new_incdec(e, delta, 0);
    }

    return e;
}

static Node* parse_unary_inner(void) {
    if (match(TK_INC)) return new_incdec(parse_unary(), 1, 1);
    if (match(TK_DEC)) return new_incdec(parse_unary(), -1, 1);
    if (match(TK_BANG)) return new_unop(OP_NOT, parse_unary());
    if (match(TK_MINUS)) return new_unop(OP_NEG, parse_unary());
    if (match(TK_PLUS)) return new_unop(OP_POS, parse_unary());
    return parse_postfix();
}

static Node* parse_unary(void) {
    stack_guard();
    return parse_unary_inner();
}

static Node* parse_multiplicative(void) {
    Node* l = parse_unary();

    for (;;) {
        if (match(TK_STAR)) l = new_binop(OP_MUL, l, parse_unary());
        else if (match(TK_SLASH)) l = new_binop(OP_DIV, l, parse_unary());
        else if (match(TK_PERCENT)) l = new_binop(OP_MOD, l, parse_unary());
        else break;
    }

    return l;
}

static Node* parse_additive(void) {
    Node* l = parse_multiplicative();

    for (;;) {
        if (match(TK_PLUS)) l = new_binop(OP_ADD, l, parse_multiplicative());
        else if (match(TK_MINUS)) l = new_binop(OP_SUB, l, parse_multiplicative());
        else if (match(TK_DOT)) l = new_binop(OP_CONCAT, l, parse_multiplicative());
        else break;
    }

    return l;
}

static Node* parse_relational(void) {
    Node* l = parse_additive();

    for (;;) {
        if (match(TK_LT)) l = new_binop(OP_LT, l, parse_additive());
        else if (match(TK_GT)) l = new_binop(OP_GT, l, parse_additive());
        else if (match(TK_LE)) l = new_binop(OP_LE, l, parse_additive());
        else if (match(TK_GE)) l = new_binop(OP_GE, l, parse_additive());
        else break;
    }

    return l;
}

static Node* parse_equality(void) {
    Node* l = parse_relational();

    for (;;) {
        if (match(TK_EQEQ)) l = new_binop(OP_EQ, l, parse_relational());
        else if (match(TK_NEQ)) l = new_binop(OP_NEQ, l, parse_relational());
        else if (match(TK_SAME)) l = new_binop(OP_SAME, l, parse_relational());
        else if (match(TK_DIFF)) l = new_binop(OP_DIFF, l, parse_relational());
        else break;
    }

    return l;
}

static Node* parse_and(void) {
    Node* l = parse_equality();
    while (match(TK_ANDAND))
        l = new_binop(OP_AND, l, parse_equality());
    return l;
}

static Node* parse_or(void) {
    Node* l = parse_and();
    while (match(TK_OROR))
        l = new_binop(OP_OR, l, parse_and());
    return l;
}

/* ?? binds tighter than ?: and is right-associative: a ?? b ?? c. */
static Node* parse_coalesce(void) {
    Node* l = parse_or();
    if (match(TK_COALESCE)) {
        Node* n = new_node(NT_COALESCE);
        n->a = l;
        n->b = parse_coalesce();
        return n;
    }
    return l;
}

/* a ? b : c, and the short form a ?: c (b left NULL). Chains group to the
   left, which is what PHP 7 did; PHP 8 refuses an unbracketed chain, so code
   written for 8 already has the brackets and means the same thing here. */
static Node* parse_expr_inner(void) {
    Node* e = parse_coalesce();
    while (match(TK_QUESTION)) {
        Node* n = new_node(NT_TERNARY);
        n->a = e;
        n->b = (cur.type == TK_COLON) ? 0 : parse_expr();
        expect(TK_COLON, ":");
        n->c = parse_coalesce();
        e = n;
    }
    return e;
}

static Node* parse_expr(void) {
    stack_guard();
    return parse_expr_inner();
}

static Value* v_new(int type) {
    Value* v = calloc(1, sizeof(Value));
    if (!v) fatal("out of memory");
    v->type = type;
    return v;
}

static Value* v_int(long long i) {
    Value* v = v_new(T_INT);
    v->i = i;
    return v;
}

static Value* v_float(double d) {
    Value* v = v_new(T_FLOAT);
    v->d = d;
    return v;
}

static Value* v_bool(int b) {
    Value* v = v_new(T_BOOL);
    v->b = b ? 1 : 0;
    return v;
}

static Value* v_null(void) {
    return v_new(T_NULL);
}

static Value* v_str(const char* s) {
    Value* v = v_new(T_STRING);
    v->s = xstrdup(s);
    return v;
}

static void array_append_raw(Value* arr, Value* key, Value* val) {
    ArrayItem* it = calloc(1, sizeof(ArrayItem));
    if (!it) fatal("out of memory");
    it->key = key;
    it->val = val;

    if (!arr->items) {
        arr->items = it;
    } else {
        ArrayItem* p = arr->items;
        while (p->next) p = p->next;
        p->next = it;
    }
}

static Value* val_clone(Value* v) {
    if (!v) return v_null();

    if (v->type == T_STRING) return v_str(v->s);

    if (v->type == T_ARRAY) {
        Value* n = v_new(T_ARRAY);
        for (ArrayItem* it = v->items; it; it = it->next)
            array_append_raw(n, val_clone(it->key), val_clone(it->val));
        return n;
    }

    Value* n = v_new(v->type);
    n->i = v->i;
    n->d = v->d;
    n->b = v->b;
    return n;
}

static Value* normalize_key(Value* k) {
    if (!k) return v_str("");

    switch (k->type) {
        case T_INT: return v_int(k->i);
        case T_BOOL: return v_int(k->b);
        case T_FLOAT: return v_int((long long)k->d);
        case T_NULL: return v_str("");
        case T_STRING: {
            const char* s = k->s ? k->s : "";
            char* end = 0;
            long long iv = strtoll(s, &end, 10);
            if (end != s && *end == '\0') return v_int(iv);
            return v_str(s);
        }
        default:
            return v_str("Array");
    }
}

static int scalar_same(Value* a, Value* b) {
    if (!a || !b) return 0;
    if (a->type != b->type) return 0;

    switch (a->type) {
        case T_INT: return a->i == b->i;
        case T_FLOAT: return a->d == b->d;
        case T_BOOL: return a->b == b->b;
        case T_STRING: return strcmp(a->s ? a->s : "", b->s ? b->s : "") == 0;
        case T_NULL: return 1;
        default: return 0;
    }
}

static ArrayItem* array_find(Value* arr, Value* key) {
    if (!arr || arr->type != T_ARRAY) return 0;

    for (ArrayItem* it = arr->items; it; it = it->next)
        if (scalar_same(it->key, key)) return it;

    return 0;
}

static int array_count(Value* arr) {
    if (!arr || arr->type != T_ARRAY) return 0;

    int c = 0;
    for (ArrayItem* it = arr->items; it; it = it->next) c++;
    return c;
}

/* Unlink one key. The item is not freed: nothing is freed while a script
   runs, and a foreach over this array may still hold its pointers. */
static void array_remove(Value* arr, Value* key) {
    if (!arr || arr->type != T_ARRAY) return;
    for (ArrayItem** pp = &arr->items; *pp; pp = &(*pp)->next) {
        if (scalar_same((*pp)->key, key)) { *pp = (*pp)->next; return; }
    }
}

static void array_clear(Value* arr) {
    if (arr && arr->type == T_ARRAY) arr->items = 0;
}

static void array_put(Value* arr, Value* key, Value* val) {
    if (!arr) fatal("Cannot write to null array");

    if (arr->type == T_NULL) {
        arr->type = T_ARRAY;
        arr->items = 0;
    }

    if (arr->type != T_ARRAY) fatal("Cannot write index to non-array");

    Value* nk = normalize_key(key);
    ArrayItem* it = array_find(arr, nk);

    if (it) it->val = val;
    else array_append_raw(arr, nk, val);
}

static char* concat_str(const char* a, const char* b) {
    if (!a) a = "";
    if (!b) b = "";

    size_t la = strlen(a), lb = strlen(b);
    char* r = malloc(la + lb + 1);
    if (!r) fatal("out of memory");

    memcpy(r, a, la);
    memcpy(r + la, b, lb);
    r[la + lb] = 0;
    return r;
}

/* Floats formatted the way PHP prints them.
   This used "%g", which keeps SIX significant digits: echo 1234567.89 printed
   "1.23457e+06" and echo 1/3 printed "0.333333". PHP's echo uses 14
   (precision), and var_dump uses the shortest form that reads back as the
   same number (serialize_precision -1). PHP also writes the exponent its own
   way: 1.0E+25, 1.0E-5 -- a ".0" on a bare mantissa and no zero padding. */
static char* php_float_str(double d, int precision) {
    if (d != d) return xstrdup("NAN");
    if (d == HUGE_VAL) return xstrdup("INF");
    if (d == -HUGE_VAL) return xstrdup("-INF");

    /* 1. the significant digits and the decimal exponent, from %e:
          echo uses `precision` digits, var_dump the fewest that read back
          as the same double. */
    char e[64];
    if (precision < 0) {
        int p;
        for (p = 1; p <= 17; p++) {
            snprintf(e, sizeof e, "%.*e", p - 1, d);
            if (strtod(e, 0) == d) break;
        }
    } else {
        snprintf(e, sizeof e, "%.*e", precision - 1, d);
    }

    int neg = (e[0] == '-');
    const char* m = e + neg;
    char digits[32];
    int nd = 0;
    for (const char* q = m; *q && *q != 'e' && nd < 30; q++)
        if (*q >= '0' && *q <= '9') digits[nd++] = *q;
    while (nd > 1 && digits[nd - 1] == '0') nd--;       /* trailing zeros */
    digits[nd] = 0;
    int x = atoi(strchr(m, 'e') + 1);

    /* 2. where the point goes. PHP switches to E-notation when the exponent
          is below -4 or at least the precision -- 14 for echo, 17 for
          var_dump (measured against PHP 8.3: echo 1e14 is "1.0E+14" while
          var_dump(1e16) is still "float(10000000000000000)"). */
    int limit = precision < 0 ? 17 : precision;
    char out[96];
    char* o = out;
    if (neg) *o++ = '-';

    if (x < -4 || x >= limit) {
        *o++ = digits[0];
        *o++ = '.';
        if (nd > 1) { memcpy(o, digits + 1, (size_t)nd - 1); o += nd - 1; }
        else *o++ = '0';                                  /* 1.0E+25 */
        o += sprintf(o, "E%c%d", x < 0 ? '-' : '+', x < 0 ? -x : x);
    } else if (x >= 0) {
        for (int i = 0; i <= x; i++) *o++ = i < nd ? digits[i] : '0';
        if (nd > x + 1) {
            *o++ = '.';
            memcpy(o, digits + x + 1, (size_t)(nd - x - 1));
            o += nd - x - 1;
        }
    } else {
        *o++ = '0';
        *o++ = '.';
        for (int i = 0; i < -x - 1; i++) *o++ = '0';
        memcpy(o, digits, (size_t)nd);
        o += nd;
    }
    *o = 0;
    return xstrdup(out);
}

static char* val_to_string(Value* v) {
    if (!v) return xstrdup("");

    char buf[64];

    switch (v->type) {
        case T_INT:
            snprintf(buf, sizeof buf, "%lld", v->i);
            return xstrdup(buf);
        case T_FLOAT:
            (void)buf;
            return php_float_str(v->d, 14);
        case T_BOOL:
            return xstrdup(v->b ? "1" : "");
        case T_STRING:
            return xstrdup(v->s ? v->s : "");
        case T_ARRAY:
            return xstrdup("Array");
        default:
            return xstrdup("");
    }
}

static int val_is_numeric(Value* v) {
    if (!v) return 0;
    if (v->type == T_INT || v->type == T_FLOAT) return 1;

    if (v->type == T_STRING) {
        const char* s = v->s ? v->s : "";
        if (!*s) return 0;

        char* end = 0;
        strtod(s, &end);
        while (end && isspace((unsigned char)*end)) end++;
        return end && *end == '\0';
    }

    return 0;
}

/* AUDIT: casting a double outside long long's range (1e300, INF, NAN) to
   long long is undefined behaviour. Anything that does not fit becomes 0. */
static long long double_to_ll(double d) {
    if (!(d == d)) return 0;                                  /* NaN */
    if (d >= 9223372036854775807.0 || d < -9223372036854775808.0) return 0;
    return (long long)d;
}

static long long val_to_int(Value* v) {
    if (!v) return 0;

    switch (v->type) {
        case T_INT: return v->i;
        case T_FLOAT: return double_to_ll(v->d);
        case T_BOOL: return v->b;
        case T_STRING: return strtoll(v->s ? v->s : "", 0, 10);
        case T_ARRAY: return 1;
        default: return 0;
    }
}

static double val_to_double(Value* v) {
    if (!v) return 0.0;

    switch (v->type) {
        case T_INT: return (double)v->i;
        case T_FLOAT: return v->d;
        case T_BOOL: return v->b ? 1.0 : 0.0;
        case T_STRING: return strtod(v->s ? v->s : "", 0);
        case T_ARRAY: return 1.0;
        default: return 0.0;
    }
}

static int val_truthy(Value* v) {
    if (!v) return 0;

    switch (v->type) {
        case T_NULL: return 0;
        case T_INT: return v->i != 0;
        case T_FLOAT: return v->d != 0.0;
        case T_BOOL: return v->b != 0;
        case T_STRING: return v->s && v->s[0] && strcmp(v->s, "0") != 0;
        case T_ARRAY: return v->items != 0;
        default: return 0;
    }
}

static int val_same(Value* a, Value* b) {
    if (a == b) return 1;
    if (!a || !b) return 0;
    if (a->type != b->type) return 0;

    switch (a->type) {
        case T_NULL: return 1;
        case T_INT: return a->i == b->i;
        case T_FLOAT: return a->d == b->d;
        case T_BOOL: return a->b == b->b;
        case T_STRING: return strcmp(a->s ? a->s : "", b->s ? b->s : "") == 0;
        case T_ARRAY: {
            if (array_count(a) != array_count(b)) return 0;

            for (ArrayItem* it = a->items; it; it = it->next) {
                ArrayItem* jt = array_find(b, it->key);
                if (!jt || !val_same(it->val, jt->val)) return 0;
            }

            return 1;
        }
        default: return 0;
    }
}

static int val_equals(Value* a, Value* b) {
    if (a == b) return 1;
    if (!a || !b) return (!a && !b);

    int an = (a->type == T_NULL);
    int bn = (b->type == T_NULL);

    if (an || bn) {
        if (an && bn) return 1;
        Value* o = an ? b : a;
        return !val_truthy(o);
    }

    if (a->type == T_BOOL || b->type == T_BOOL)
        return val_truthy(a) == val_truthy(b);

    if (a->type == T_ARRAY && b->type == T_ARRAY) {
        if (array_count(a) != array_count(b)) return 0;

        for (ArrayItem* it = a->items; it; it = it->next) {
            ArrayItem* jt = array_find(b, it->key);
            if (!jt || !val_equals(it->val, jt->val)) return 0;
        }

        return 1;
    }

    int anum = val_is_numeric(a);
    int bnum = val_is_numeric(b);

    if (anum && bnum)
        return val_to_double(a) == val_to_double(b);

    if (a->type == T_STRING && b->type == T_STRING)
        return strcmp(a->s ? a->s : "", b->s ? b->s : "") == 0;

    char* sa = val_to_string(a);
    char* sb = val_to_string(b);
    int r = strcmp(sa, sb) == 0;
    free(sa);
    free(sb);
    return r;
}

static int val_cmp(Value* a, Value* b) {
    if (val_is_numeric(a) && val_is_numeric(b)) {
        double x = val_to_double(a);
        double y = val_to_double(b);

        if (x < y) return -1;
        if (x > y) return 1;
        return 0;
    }

    char* sa = val_to_string(a);
    char* sb = val_to_string(b);
    int r = strcmp(sa, sb);
    free(sa);
    free(sb);

    if (r < 0) return -1;
    if (r > 0) return 1;
    return 0;
}

/* AUDIT: % on integers, made safe.
   - y == 0 used to return 0 silently; PHP 8 raises "Modulo by zero".
   - LLONG_MIN % -1 is undefined in C, and on x86 it is a HARDWARE TRAP
     (SIGFPE): one expression in a script killed the whole process. The
     mathematical answer is 0, which is what PHP gives. */
static long long int_mod(long long x, long long y) {
    if (y == 0) fatal("Modulo by zero");
    if (y == -1) return 0;
    return x % y;
}

static Value* arith(int op, Value* a, Value* b) {
    if (op == OP_CONCAT) {
        char* sa = val_to_string(a);
        char* sb = val_to_string(b);
        char* r = concat_str(sa, sb);
        free(sa);
        free(sb);

        Value* v = v_new(T_STRING);
        v->s = r;
        return v;
    }

    if (op == OP_ADD && a && b && a->type == T_ARRAY && b->type == T_ARRAY) {
        Value* r = val_clone(a);

        for (ArrayItem* it = b->items; it; it = it->next) {
            if (!array_find(r, it->key))
                array_put(r, val_clone(it->key), val_clone(it->val));
        }

        return r;
    }

    int both_int = a && b && a->type == T_INT && b->type == T_INT;

    if (both_int && op != OP_DIV) {
        long long x = a->i, y = b->i, r;

        /* AUDIT: integer + - * used to overflow with undefined behaviour
           (PHP_INT_MAX + 1). PHP's rule is that an int result which does not
           fit becomes a float, so on overflow this falls through to the
           floating-point path below instead of wrapping. */
        switch (op) {
            case OP_ADD: if (!__builtin_add_overflow(x, y, &r)) return v_int(r); break;
            case OP_SUB: if (!__builtin_sub_overflow(x, y, &r)) return v_int(r); break;
            case OP_MUL: if (!__builtin_mul_overflow(x, y, &r)) return v_int(r); break;
            case OP_MOD: return v_int(int_mod(x, y));
            default: break;
        }
    }

    double x = val_to_double(a);
    double y = val_to_double(b);

    switch (op) {
        case OP_ADD: return v_float(x + y);
        case OP_SUB: return v_float(x - y);
        case OP_MUL: return v_float(x * y);
        /* AUDIT: x / 0 used to return 0 silently. PHP 8 raises
           DivisionByZeroError, which uncaught is a fatal error -- and with no
           exceptions in this runtime, fatal is the faithful equivalent. A
           silent 0 lets a bad calculation carry on into whatever it feeds. */
        case OP_DIV:
            if (y == 0.0) fatal("Division by zero");
            return v_float(x / y);
        case OP_MOD:
            return v_int(int_mod(double_to_ll(x), double_to_ll(y)));
        default:
            fatal("Bad arithmetic operator");
            return v_null();
    }
}

static Value* eval_binop(int op, Value* a, Value* b) {
    switch (op) {
        case OP_ADD: return arith(OP_ADD, a, b);
        case OP_SUB: return arith(OP_SUB, a, b);
        case OP_MUL: return arith(OP_MUL, a, b);
        case OP_DIV: return arith(OP_DIV, a, b);
        case OP_MOD: return arith(OP_MOD, a, b);
        case OP_CONCAT: return arith(OP_CONCAT, a, b);
        case OP_EQ: return v_bool(val_equals(a, b));
        case OP_NEQ: return v_bool(!val_equals(a, b));
        case OP_SAME: return v_bool(val_same(a, b));
        case OP_DIFF: return v_bool(!val_same(a, b));
        case OP_LT: return v_bool(val_cmp(a, b) < 0);
        case OP_GT: return v_bool(val_cmp(a, b) > 0);
        case OP_LE: return v_bool(val_cmp(a, b) <= 0);
        case OP_GE: return v_bool(val_cmp(a, b) >= 0);
        case OP_AND: return v_bool(val_truthy(a) && val_truthy(b));
        case OP_OR: return v_bool(val_truthy(a) || val_truthy(b));
        default:
            fatal("Bad binary operator");
            return v_null();
    }
}

static Value* eval_unop(int op, Value* a) {
    switch (op) {
        case OP_NOT: return v_bool(!val_truthy(a));
        case OP_NEG:
            /* AUDIT: -PHP_INT_MIN overflows; PHP gives a float. */
            if (a && a->type == T_INT) {
                if (a->i == (-9223372036854775807LL - 1)) return v_float(9223372036854775808.0);
                return v_int(-a->i);
            }
            if (a && a->type == T_FLOAT) return v_float(-a->d);
            return v_float(-val_to_double(a));
        case OP_POS:
            if (a && (a->type == T_INT || a->type == T_FLOAT)) return val_clone(a);
            return v_float(val_to_double(a));
        default:
            fatal("Bad unary operator");
            return v_null();
    }
}

static Env* new_env(Env* parent) {
    Env* e = calloc(1, sizeof(Env));
    if (!e) fatal("out of memory");
    e->parent = parent;
    return e;
}

static Var* env_find_current(Env* e, const char* name) {
    if (!e || !name) return 0;

    for (Var* v = e->vars; v; v = v->next)
        if (!strcmp(v->name, name)) return v;

    return 0;
}

/* Remove a variable from ONE scope -- unset() inside a function removes the
   local, as in PHP. */
static void env_unset(Env* e, const char* name) {
    if (!e) return;
    for (Var** pp = &e->vars; *pp; pp = &(*pp)->next) {
        if (!strcmp((*pp)->name, name)) { *pp = (*pp)->next; return; }
    }
}

static Value* env_get(Env* e, const char* name) {
    for (; e; e = e->parent) {
        Var* v = env_find_current(e, name);
        if (v) return v->val;
    }

    return v_null();
}

static void env_set(Env* e, const char* name, Value* val) {
    Var* v = env_find_current(e, name);

    if (v) {
        v->val = val;
    } else {
        v = calloc(1, sizeof(Var));
        if (!v) fatal("out of memory");
        v->name = xstrdup(name);
        v->val = val;
        v->next = e->vars;
        e->vars = v;
    }
}

static Func* find_func_lower(const char* lname) {
    for (Func* f = funcs; f; f = f->next)
        if (!strcmp(f->name, lname)) return f;

    return 0;
}

static void ser_value(Buf* b, Value* v) {
    if (!v) {
        buf_addz(b, "N\n");
        return;
    }

    switch (v->type) {
        case T_NULL:
            buf_addz(b, "N\n");
            break;

        case T_BOOL:
            buf_fmt(b, "b:%d\n", v->b ? 1 : 0);
            break;

        case T_INT:
            buf_fmt(b, "i:%lld\n", v->i);
            break;

        case T_FLOAT:
            buf_fmt(b, "d:%.17g\n", v->d);
            break;

        case T_STRING: {
            size_t n = strlen(v->s ? v->s : "");
            buf_fmt(b, "s:%zu:", n);
            buf_add(b, v->s ? v->s : "", n);
            buf_ch(b, '\n');
            break;
        }

        case T_ARRAY: {
            int count = array_count(v);
            buf_fmt(b, "a:%d:{\n", count);

            for (ArrayItem* it = v->items; it; it = it->next) {
                ser_value(b, it->key);
                ser_value(b, it->val);
            }

            buf_addz(b, "}\n");
            break;
        }

        default:
            buf_addz(b, "N\n");
            break;
    }
}

static void skip_ws(const char** pp, const char* end) {
    while (*pp < end && isspace((unsigned char)**pp)) (*pp)++;
}

static int eat(const char** pp, const char* end, char c) {
    skip_ws(pp, end);
    if (*pp < end && **pp == c) {
        (*pp)++;
        return 1;
    }
    return 0;
}

static int parse_ll(const char** pp, const char* end, long long* out) {
    skip_ws(pp, end);
    char* ep = 0;
    long long v = strtoll(*pp, &ep, 10);
    if (ep == *pp) return 0;
    *pp = ep;
    *out = v;
    return 1;
}

static int parse_dd(const char** pp, const char* end, double* out) {
    skip_ws(pp, end);
    char* ep = 0;
    double v = strtod(*pp, &ep);
    if (ep == *pp) return 0;
    *pp = ep;
    *out = v;
    return 1;
}

static Value* parse_ser(const char** pp, const char* end) {
    stack_guard();     /* AUDIT: nested arrays in a corrupt file recurse here */
    skip_ws(pp, end);
    if (*pp >= end) return v_null();

    char c = **pp;
    (*pp)++;

    if (c == 'N') return v_null();

    if (c == 'b') {
        eat(pp, end, ':');
        long long x = 0;
        parse_ll(pp, end, &x);
        return v_bool(x != 0);
    }

    if (c == 'i') {
        eat(pp, end, ':');
        long long x = 0;
        parse_ll(pp, end, &x);
        return v_int(x);
    }

    if (c == 'd') {
        eat(pp, end, ':');
        double x = 0;
        parse_dd(pp, end, &x);
        return v_float(x);
    }

    if (c == 's') {
        eat(pp, end, ':');

        long long len = 0;
        if (!parse_ll(pp, end, &len)) return v_null();

        if (*pp < end && **pp == ':') (*pp)++;
        else return v_null();

        if (len < 0) len = 0;
        /* AUDIT: compare lengths, not pointers. `*pp + len` with a huge len
           from a corrupt file overflows the pointer, which is undefined
           behaviour before the comparison even runs. */
        if (len > (long long)(end - *pp)) len = (long long)(end - *pp);

        char* s = malloc((size_t)len + 1);
        if (!s) fatal("out of memory");

        memcpy(s, *pp, (size_t)len);
        s[len] = 0;
        *pp += len;

        Value* v = v_new(T_STRING);
        v->s = s;
        return v;
    }

    if (c == 'a') {
        eat(pp, end, ':');

        long long cnt = 0;
        if (!parse_ll(pp, end, &cnt)) return v_null();
        if (cnt < 0) cnt = 0;

        /* AUDIT: ser_value writes "a:<count>:{" -- a colon BEFORE the brace --
           but this expected the brace straight after the count. Every array
           failed to parse, so load_session_file got null and $_SESSION came
           back EMPTY on every request after the first. Sessions have never
           carried anything from one request to the next. */
        if (*pp < end && **pp == ':') (*pp)++;
        if (!eat(pp, end, '{')) return v_null();

        Value* arr = v_new(T_ARRAY);

        /* AUDIT: the count comes from the file. "a:999999999999:{" used to
           spin for that many iterations after the data ran out; stop at the
           end of the input instead of trusting the number. */
        for (long long i = 0; i < cnt && *pp < end; i++) {
            Value* k = parse_ser(pp, end);
            Value* val = parse_ser(pp, end);
            array_put(arr, k, val);
        }

        eat(pp, end, '}');
        return arr;
    }

    return v_null();
}

static void emit_string(const char* s) {
    if (!s) return;

    if (!cgi_mode) {
        fputs(s, stdout);
    } else {
        buf_addz(&response_body, s);
    }
}

static void emitf(const char* fmt, ...) {
    va_list ap, ap2;
    va_start(ap, fmt);
    va_copy(ap2, ap);

    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);

    if (n < 0) {
        va_end(ap2);
        return;
    }

    char* tmp = malloc((size_t)n + 1);
    if (!tmp) fatal("out of memory");

    vsnprintf(tmp, (size_t)n + 1, fmt, ap2);
    va_end(ap2);

    emit_string(tmp);
    free(tmp);
}

static void emit_indent(int n) {
    for (int i = 0; i < n; i++) emit_string("  ");
}

static int header_name_eq(const char* a, const char* b) {
    if (!a || !b) return 0;

    const char* ca = strchr(a, ':');
    const char* cb = strchr(b, ':');

    size_t la = ca ? (size_t)(ca - a) : strlen(a);
    size_t lb = cb ? (size_t)(cb - b) : strlen(b);

    if (la != lb) return 0;
    return strncasecmp(a, b, la) == 0;
}

static void add_response_header_ex(const char* line, int replace) {
    if (!line) return;

    /* AUDIT: header injection. A CR or LF inside a header line used to be
       written straight into the response, so header("Location: " . $_GET[...])
       let a visitor add their own headers -- set cookies in someone else's
       browser, or split the response in two. setcookie() goes through here
       too, and its path/domain/samesite options were not encoded either.
       PHP has refused this since 5.1.2 with the same rule: drop the header,
       warn, carry on. */
    if (strpbrk(line, "\r\n")) {
        fprintf(stderr, "PHP warning: header may not contain more than a single header, "
                        "new line detected\n");
        return;
    }

    if (strncasecmp(line, "HTTP/", 5) == 0) {
        const char* sp = strchr(line, ' ');
        if (sp) response_status = (int)strtol(sp + 1, 0, 10);
        return;
    }

    if (strncasecmp(line, "Status:", 7) == 0) {
        const char* v = line + 7;
        while (*v == ' ') v++;
        response_status = (int)strtol(v, 0, 10);
        return;
    }

    if (strncasecmp(line, "Location:", 9) == 0 && response_status == 200)
        response_status = 302;

    int is_set_cookie = (strncasecmp(line, "Set-Cookie:", 11) == 0);

    if (replace && !is_set_cookie) {
        Header** pp = &response_headers;
        while (*pp) {
            if (header_name_eq((*pp)->line, line)) {
                Header* dead = *pp;
                *pp = dead->next;
                free(dead->line);
                free(dead);
            } else {
                pp = &(*pp)->next;
            }
        }
    }

    Header* h = calloc(1, sizeof(Header));
    if (!h) fatal("out of memory");
    h->line = xstrdup(line);

    if (!response_headers) {
        response_headers = h;
    } else {
        Header* p = response_headers;
        while (p->next) p = p->next;
        p->next = h;
    }
}

static const char* status_reason(int code) {
    switch (code) {
        case 200: return "OK";
        case 201: return "Created";
        case 204: return "No Content";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 303: return "See Other";
        case 304: return "Not Modified";
        case 307: return "Temporary Redirect";
        case 308: return "Permanent Redirect";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 408: return "Request Timeout";
        case 413: return "Payload Too Large";
        case 414: return "URI Too Long";
        case 429: return "Too Many Requests";
        case 500: return "Internal Server Error";
        case 501: return "Not Implemented";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        case 504: return "Gateway Timeout";
        default: return "OK";
    }
}

static void flush_response(void) {
    if (!cgi_mode || response_flushed) return;
    response_flushed = 1;

    printf("Status: %d %s\r\n", response_status, status_reason(response_status));

    int has_content_type = 0;
    for (Header* h = response_headers; h; h = h->next) {
        if (strncasecmp(h->line, "Content-Type:", 13) == 0) {
            has_content_type = 1;
            break;
        }
    }

    if (!has_content_type)
        printf("Content-Type: text/html; charset=UTF-8\r\n");

    for (Header* h = response_headers; h; h = h->next)
        printf("%s\r\n", h->line);

    printf("\r\n");

    if (response_body.data && response_body.len)
        fwrite(response_body.data, 1, response_body.len, stdout);

    fflush(stdout);
}

static void add_set_cookie_full(
    const char* name,
    const char* value,
    long long expires,
    const char* path,
    const char* domain,
    int secure,
    int httponly,
    const char* samesite
) {
    char* en = url_encode(name);
    char* ev = url_encode(value);

    Buf b;
    buf_init(&b);

    buf_fmt(&b, "Set-Cookie: %s=%s", en, ev);

    if (expires > 0) {
        char date[128];
        format_http_date((time_t)expires, date, sizeof date);
        buf_fmt(&b, "; Expires=%s", date);
    }

    if (path && *path)
        buf_fmt(&b, "; Path=%s", path);

    if (domain && *domain)
        buf_fmt(&b, "; Domain=%s", domain);

    if (secure)
        buf_addz(&b, "; Secure");

    if (httponly)
        buf_addz(&b, "; HttpOnly");

    if (samesite && *samesite)
        buf_fmt(&b, "; SameSite=%s", samesite);

    add_response_header_ex(b.data ? b.data : "Set-Cookie: =", 0);

    free(en);
    free(ev);
}

static const char* session_dir(void) {
    const char* d = getenv("PHPMINI_SESSION_PATH");
    return (d && *d) ? d : "/tmp/phpmini-sessions";
}

/* AUDIT: the session directory defaults to /tmp, which every account on the
   machine can write. mkdir() used to be called and its result ignored, so if
   someone else had created /tmp/phpmini-sessions first, sessions were quietly
   written into a directory THEY own -- readable by them, and open to the
   symlink trick below. Now the directory must be a real directory (not a
   link), owned by us, and closed to group and others; if it is not, sessions
   are refused with a message rather than written somewhere unsafe. */
static int session_dir_trusted(void) {
    const char* d = session_dir();
    mkdir(d, 0700);

    struct stat st;
    if (lstat(d, &st) != 0) return 0;
    if (!S_ISDIR(st.st_mode)) {
        fprintf(stderr, "PHP warning: session path %s is not a directory; sessions disabled\n", d);
        return 0;
    }
    if (st.st_uid != geteuid() || (st.st_mode & 077)) {
        fprintf(stderr, "PHP warning: session path %s is not private to this user "
                        "(owner/permissions); sessions disabled\n", d);
        return 0;
    }
    return 1;
}

static int valid_session_id(const char* s) {
    if (!s) return 0;

    size_t n = strlen(s);
    if (n < 16 || n > 128) return 0;

    for (size_t i = 0; i < n; i++)
        if (!isalnum((unsigned char)s[i])) return 0;

    return 1;
}

static void gen_sid(char* out, size_t n) {
    if (n < 33) return;

    unsigned char raw[16];
    ssize_t r = -1;

    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        r = read(fd, raw, sizeof raw);
        close(fd);
    }

    /* AUDIT: this used to fall back to rand() seeded with time ^ pid when
       /dev/urandom could not be read. Those are guessable -- the time is
       public and pids are small -- and a guessable session ID is a stolen
       login. With no good randomness there is no safe ID to issue, so fail
       like PHP does ("Failed to create session ID") instead of issuing one. */
    if (r != (ssize_t)sizeof raw)
        fatal("Failed to create session ID: /dev/urandom unavailable");

    for (size_t i = 0; i < sizeof raw; i++)
        sprintf(out + (i * 2), "%02x", raw[i]);

    out[32] = 0;
}

static void session_file_path(char* path, size_t n, const char* sid) {
    snprintf(path, n, "%s/sess_%s", session_dir(), sid);
}

static void load_session_file(const char* sid) {
    char path[1024];
    session_file_path(path, sizeof path, sid);

    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return;
    FILE* f = fdopen(fd, "rb");
    if (!f) { close(fd); return; }

    char* data = read_all(f);
    fclose(f);

    const char* p = data;
    const char* end = data + strlen(data);

    Value* v = parse_ser(&p, end);
    if (v && v->type == T_ARRAY) {
        V_SESSION->type = T_ARRAY;
        V_SESSION->items = v->items;
    }
}

static void save_session_file(void) {
    if (!session_started || session_saved) return;
    if (!valid_session_id(session_id)) return;

    session_saved = 1;
    if (!session_dir_trusted()) return;

    char path[1024];
    session_file_path(path, sizeof path, session_id);

    Buf b;
    buf_init(&b);
    ser_value(&b, V_SESSION);

    /* AUDIT: fopen(path, "wb") followed symlinks and created the file 0644.
       Demonstrated before this fix: with a link planted at sess_<id> and that
       id sent as the cookie, saving the session OVERWROTE the file the link
       pointed to. And 0644 meant every account on the machine could read
       every session. O_NOFOLLOW refuses the link; 0600 keeps it private. */
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        fprintf(stderr, "PHP warning: could not write session file %s\n", path);
        free(b.data);
        return;
    }
    FILE* f = fdopen(fd, "wb");
    if (!f) { close(fd); free(b.data); return; }
    if (b.data && b.len)
        fwrite(b.data, 1, b.len, f);
    fclose(f);
    free(b.data);
}

/* A session file exists for this id: a regular file, not a link. */
static int session_file_exists(const char* sid) {
    char path[1024];
    session_file_path(path, sizeof path, sid);
    struct stat st;
    return lstat(path, &st) == 0 && S_ISREG(st.st_mode);
}

/* The request arrived over TLS, as the web server reports it. */
static int request_is_https(void) {
    const char* h = getenv("HTTPS");
    if (h && *h && strcasecmp(h, "off") != 0) return 1;
    const char* sch = getenv("REQUEST_SCHEME");
    return sch && strcasecmp(sch, "https") == 0;
}

static void session_start_impl(void) {
    if (session_started) return;
    session_started = 1;

    if (!cgi_mode) return;

    /* Untrusted storage: $_SESSION still works for this request, but nothing
       is read from or written to a directory someone else controls. */
    if (!session_dir_trusted()) return;

    ArrayItem* it = array_find(V_COOKIE, v_str("PHPSESSID"));
    char* sid = it ? val_to_string(it->val) : xstrdup("");

    /* AUDIT: strict mode. Any well-formed id from the cookie used to be
       adopted, even one this server never issued -- so a visitor could pick
       the id (session fixation), and choosing it in advance is what made the
       symlink overwrite aimable. An id with no session behind it is now
       replaced with a fresh one, which is PHP's session.use_strict_mode. */
    if (valid_session_id(sid) && session_file_exists(sid)) {
        strncpy(session_id, sid, sizeof session_id - 1);
        session_id[sizeof session_id - 1] = 0;
        load_session_file(session_id);
    } else {
        gen_sid(session_id, sizeof session_id);
        /* Secure when the request came over HTTPS, so the cookie is never
           sent back in clear text. HttpOnly and SameSite=Lax as before. */
        add_set_cookie_full("PHPSESSID", session_id, 0, "/", "",
                            request_is_https(), 1, "Lax");
    }

    free(sid);
}

static void session_destroy_impl(void) {
    if (session_started && valid_session_id(session_id)) {
        char path[1024];
        session_file_path(path, sizeof path, session_id);
        unlink(path);
    }

    if (V_SESSION) array_clear(V_SESSION);
    session_started = 0;
    session_id[0] = 0;
}

static char* trim_dup(const char* s, size_t n) {
    while (n && isspace((unsigned char)s[0])) {
        s++;
        n--;
    }

    while (n && isspace((unsigned char)s[n - 1]))
        n--;

    char* r = malloc(n + 1);
    if (!r) fatal("out of memory");

    memcpy(r, s, n);
    r[n] = 0;
    return r;
}

static void parse_urlencoded_pair(const char* s, size_t len, Value* dest) {
    char* pair = malloc(len + 1);
    if (!pair) fatal("out of memory");

    memcpy(pair, s, len);
    pair[len] = 0;

    char* eq = strchr(pair, '=');

    if (eq) {
        *eq = 0;

        char* k = url_decode(pair);
        char* v = url_decode(eq + 1);

        if (*k) array_put(dest, v_str(k), v_str(v));

        free(k);
        free(v);
    } else {
        char* k = url_decode(pair);
        if (*k) array_put(dest, v_str(k), v_str(""));
        free(k);
    }

    free(pair);
}

/* AUDIT: max_input_vars.
   Arrays here are linked lists, and every insert scans the whole list for a
   duplicate key, so building $_GET / $_POST / $_COOKIE from N variables costs
   O(N^2). Measured before this fix: a 629 KB POST of short distinct keys took
   78 seconds of CPU, and the 2 MB the body limit allows works out at roughly
   13 minutes per request -- a handful of requests pins every core. PHP defends
   the same spot the same way, with max_input_vars (default 1000). Variables
   past the limit are dropped and the request carries on. Override with
   PHPMINI_MAX_INPUT_VARS. */
static long max_input_vars(void) {
    const char* e = getenv("PHPMINI_MAX_INPUT_VARS");
    long n = (e && *e) ? strtol(e, 0, 10) : 1000;
    return n > 0 ? n : 1000;
}

static int input_vars_ok(long* used, const char* what) {
    if (*used < max_input_vars()) { (*used)++; return 1; }
    if (*used == max_input_vars()) {
        fprintf(stderr, "PHP warning: input variables exceeded %ld for %s; "
                        "the rest were dropped (PHPMINI_MAX_INPUT_VARS)\n",
                max_input_vars(), what);
        (*used)++;                     /* warn once */
    }
    return 0;
}

static void parse_urlencoded_into(const char* s, Value* dest) {
    if (!s || !dest) return;
    long used = 0;

    while (*s) {
        const char* amp = strchr(s, '&');
        size_t len = amp ? (size_t)(amp - s) : strlen(s);

        if (len) {
            if (!input_vars_ok(&used, "the query string or form body")) break;
            parse_urlencoded_pair(s, len, dest);
        }

        if (!amp) break;
        s = amp + 1;
    }
}

static void parse_cookies_into(const char* s, Value* dest) {
    if (!s || !dest) return;
    long used = 0;

    while (*s) {
        const char* sc = strchr(s, ';');
        size_t len = sc ? (size_t)(sc - s) : strlen(s);

        if (!input_vars_ok(&used, "cookies")) break;

        char* pair = trim_dup(s, len);
        char* eq = strchr(pair, '=');

        if (eq) {
            *eq = 0;

            char* k = trim_dup(pair, (size_t)(eq - pair));
            char* v = trim_dup(eq + 1, strlen(eq + 1));

            size_t lv = strlen(v);
            char* vp = v;

            if (lv >= 2 && v[0] == '"' && v[lv - 1] == '"') {
                vp++;
                vp[lv - 2] = 0;
            }

            char* dk = url_decode(k);
            char* dv = url_decode(vp);

            if (*dk) array_put(dest, v_str(dk), v_str(dv));

            free(k);
            free(v);
            free(dk);
            free(dv);
        }

        free(pair);

        if (!sc) break;
        s = sc + 1;
    }
}

static void add_server_str(const char* k, const char* v) {
    if (!V_SERVER) return;
    array_put(V_SERVER, v_str(k), v_str(v ? v : ""));
}

static void fill_server_globals(void) {
    const char* rm = getenv("REQUEST_METHOD");
    cgi_mode = rm && *rm;

    add_server_str("REQUEST_METHOD", rm ? rm : "CLI");
    add_server_str("QUERY_STRING", getenv("QUERY_STRING"));
    add_server_str("CONTENT_TYPE", getenv("CONTENT_TYPE"));
    add_server_str("CONTENT_LENGTH", getenv("CONTENT_LENGTH"));
    add_server_str("HTTP_COOKIE", getenv("HTTP_COOKIE"));
    add_server_str("HTTP_USER_AGENT", getenv("HTTP_USER_AGENT"));
    add_server_str("HTTP_REFERER", getenv("HTTP_REFERER"));
    add_server_str("HTTP_ACCEPT", getenv("HTTP_ACCEPT"));
    add_server_str("SCRIPT_NAME", getenv("SCRIPT_NAME"));
    add_server_str("SCRIPT_FILENAME", getenv("SCRIPT_FILENAME"));
    add_server_str("REQUEST_URI", getenv("REQUEST_URI"));
    add_server_str("REMOTE_ADDR", getenv("REMOTE_ADDR"));
    add_server_str("REMOTE_HOST", getenv("REMOTE_HOST"));
    add_server_str("SERVER_NAME", getenv("SERVER_NAME"));
    add_server_str("SERVER_PORT", getenv("SERVER_PORT"));
    add_server_str("SERVER_PROTOCOL", getenv("SERVER_PROTOCOL"));
    add_server_str("SERVER_SOFTWARE", "phpmini/0.1");
    add_server_str("GATEWAY_INTERFACE", cgi_mode ? "CGI/1.1" : "");
}

static void read_post_into(Value* dest) {
    const char* cl = getenv("CONTENT_LENGTH");
    long len = cl ? strtol(cl, 0, 10) : 0;

    if (len <= 0) return;
    if (len > 2 * 1024 * 1024) len = 2 * 1024 * 1024;

    char* body = malloc((size_t)len + 1);
    if (!body) fatal("out of memory");

    size_t got = fread(body, 1, (size_t)len, stdin);
    body[got] = 0;

    const char* ct = getenv("CONTENT_TYPE");

    if (!ct || strncasecmp(ct, "application/x-www-form-urlencoded", 33) == 0)
        parse_urlencoded_into(body, dest);

    free(body);
}

static void copy_array(Value* dest, Value* src) {
    if (!dest || !src || src->type != T_ARRAY) return;

    for (ArrayItem* it = src->items; it; it = it->next)
        array_put(dest, val_clone(it->key), val_clone(it->val));
}

static void web_atexit(void) {
    save_session_file();
    flush_response();
}

/* AUDIT: max_execution_time.
   Nothing stopped a runaway script, so under CGI a single request with an
   endless loop -- a bug, or a loop whose bound comes from the request --
   pinned a CPU core until someone killed it by hand. PHP's web default is 30
   seconds; same here, enforced by the kernel through a CPU-time limit so it
   costs nothing while the script runs. CLI runs are left unlimited, as in PHP.
   Override with PHPMINI_MAX_EXECUTION_TIME (seconds, 0 = unlimited). */
static void on_cpu_limit(int sig) {
    (void)sig;
    static const char msg[] = "PHP error: Maximum execution time exceeded\n";
    ssize_t w = write(2, msg, sizeof msg - 1);
    (void)w;
    _exit(1);
}

static void apply_execution_limit(void) {
    const char* e = getenv("PHPMINI_MAX_EXECUTION_TIME");
    long secs = (e && *e) ? strtol(e, 0, 10) : 30;
    if (secs <= 0) return;
    struct rlimit rl;
    rl.rlim_cur = (rlim_t)secs;
    rl.rlim_max = (rlim_t)secs + 5;        /* hard kill if the handler cannot run */
    signal(SIGXCPU, on_cpu_limit);
    setrlimit(RLIMIT_CPU, &rl);
}

/* VmData from /proc: what the process already holds before the script runs.
   The limit is added ON TOP of it, so it means "the script may use this
   much", as PHP's does -- and so a sanitizer build, whose baseline is huge,
   is not refused at the first allocation. 0 if it cannot be read. */
static size_t current_data_bytes(void) {
    FILE* f = fopen("/proc/self/status", "r");
    if (!f) return 0;
    char line[256];
    size_t kb = 0;
    while (fgets(line, sizeof line, f))
        if (!strncmp(line, "VmData:", 7)) { kb = (size_t)strtoull(line + 7, 0, 10); break; }
    fclose(f);
    return kb * 1024;
}

static void apply_memory_limit(void) {
    const char* e = getenv("PHPMINI_MEMORY_LIMIT");
    long long lim = 256LL << 20;
    if (e && *e) {
        char* end = 0;
        lim = strtoll(e, &end, 10);
        if (end && (*end == 'k' || *end == 'K')) lim <<= 10;
        else if (end && (*end == 'm' || *end == 'M')) lim <<= 20;
        else if (end && (*end == 'g' || *end == 'G')) lim <<= 30;
    }
    if (lim <= 0) return;                               /* unlimited */

    struct rlimit rl;
    size_t base = current_data_bytes();
    rl.rlim_cur = (rlim_t)(base + (size_t)lim);
    rl.rlim_max = rl.rlim_cur + ((rlim_t)16 << 20);     /* headroom for the error path */
    if (setrlimit(RLIMIT_DATA, &rl) == 0) mem_limit_bytes = (size_t)lim;
}

static void web_bootstrap(Env* env) {
    V_GET = v_new(T_ARRAY);
    V_POST = v_new(T_ARRAY);
    V_COOKIE = v_new(T_ARRAY);
    V_SESSION = v_new(T_ARRAY);
    V_SERVER = v_new(T_ARRAY);
    V_REQUEST = v_new(T_ARRAY);

    env_set(env, "_GET", V_GET);
    env_set(env, "_POST", V_POST);
    env_set(env, "_COOKIE", V_COOKIE);
    env_set(env, "_SESSION", V_SESSION);
    env_set(env, "_SERVER", V_SERVER);
    env_set(env, "_REQUEST", V_REQUEST);

    fill_server_globals();
    if (cgi_mode) { apply_execution_limit(); apply_memory_limit(); }

    parse_urlencoded_into(getenv("QUERY_STRING"), V_GET);
    parse_cookies_into(getenv("HTTP_COOKIE"), V_COOKIE);

    if (cgi_mode && getenv("REQUEST_METHOD") && !strcmp(getenv("REQUEST_METHOD"), "POST"))
        read_post_into(V_POST);

    copy_array(V_REQUEST, V_COOKIE);
    copy_array(V_REQUEST, V_GET);
    copy_array(V_REQUEST, V_POST);

    atexit(web_atexit);
}

/* var_dump in PHP's exact layout: two spaces per level, string keys quoted,
   "=>" with no spaces, floats in their shortest exact form. It used to print
   `[k] =>` and `float(%g)`, which reads like PHP but is not it -- so output
   pasted from real PHP never matched. */
static void dump_value(Value* v, int d) {
    emit_indent(d);

    if (!v) { emit_string("NULL\n"); return; }

    switch (v->type) {
        case T_NULL:   emit_string("NULL\n"); break;
        case T_INT:    emitf("int(%lld)\n", v->i); break;
        case T_BOOL:   emitf("bool(%s)\n", v->b ? "true" : "false"); break;
        case T_FLOAT: {
            char* fs = php_float_str(v->d, -1);
            emitf("float(%s)\n", fs);
            free(fs);
            break;
        }
        case T_STRING:
            emitf("string(%zu) \"%s\"\n", strlen(v->s ? v->s : ""), v->s ? v->s : "");
            break;
        case T_ARRAY:
            emitf("array(%d) {\n", array_count(v));
            for (ArrayItem* it = v->items; it; it = it->next) {
                emit_indent(d + 1);
                if (it->key && it->key->type == T_INT) emitf("[%lld]=>\n", it->key->i);
                else {
                    char* ks = val_to_string(it->key);
                    emitf("[\"%s\"]=>\n", ks);
                    free(ks);
                }
                dump_value(it->val, d + 1);
            }
            emit_indent(d);
            emit_string("}\n");
            break;
        default:
            emit_string("NULL\n");
            break;
    }
}

/* print_r's own layout -- it printed var_dump's before, so every print_r()
   in a script produced the wrong format. Rendered into a buffer so that
   print_r($x, true) can return it as a string, as in PHP. */
static void pr_pad(Buf* b, int n) { while (n-- > 0) buf_ch(b, ' '); }

static void pr_render(Buf* b, Value* v, int level) {
    if (v && v->type == T_ARRAY) {
        buf_addz(b, "Array\n");
        pr_pad(b, level * 8);
        buf_addz(b, "(\n");
        for (ArrayItem* it = v->items; it; it = it->next) {
            char* ks = val_to_string(it->key);
            pr_pad(b, level * 8 + 4);
            buf_ch(b, '[');
            buf_addz(b, ks);
            buf_addz(b, "] => ");
            free(ks);
            pr_render(b, it->val, level + 1);
            buf_ch(b, '\n');
        }
        pr_pad(b, level * 8);
        buf_addz(b, ")\n");
    } else {
        char* sv = val_to_string(v);
        buf_addz(b, sv);
        free(sv);
    }
}

/* Building a NEW array whose keys are known to be unique: keep the tail, so
   each append is O(1). array_put() scans the whole list for a duplicate key
   and then walks it again to the end, which makes a 100,000-element
   explode() quadratic. Only for fresh arrays -- never for one a script can
   also be writing to. */
typedef struct { Value* arr; ArrayItem* tail; long long next; } ArrBuild;

static void ab_init(ArrBuild* b) { b->arr = v_new(T_ARRAY); b->tail = 0; b->next = 0; }

static void ab_put(ArrBuild* b, Value* key, Value* val) {
    ArrayItem* it = calloc(1, sizeof(ArrayItem));
    it->key = key;
    it->val = val;
    if (b->tail) b->tail->next = it; else b->arr->items = it;
    b->tail = it;
    if (key->type == T_INT && key->i >= b->next) b->next = key->i + 1;
}

static void ab_push(ArrBuild* b, Value* val) { ab_put(b, v_int(b->next), val); }

static Value* v_str_n(const char* s, size_t n) {
    Value* v = v_new(T_STRING);
    v->s = malloc(n + 1);
    memcpy(v->s, s, n);
    v->s[n] = 0;
    return v;
}

static Value* arr_get(Value* arr, const char* key) {
    if (!arr || arr->type != T_ARRAY) return 0;

    ArrayItem* it = array_find(arr, v_str(key));
    return it ? it->val : 0;
}

static char* arr_get_str(Value* arr, const char* key, const char* def) {
    Value* v = arr_get(arr, key);
    return v ? val_to_string(v) : xstrdup(def);
}

static long long arr_get_int(Value* arr, const char* key, long long def) {
    Value* v = arr_get(arr, key);
    return v ? val_to_int(v) : def;
}

static int arr_get_bool(Value* arr, const char* key, int def) {
    Value* v = arr_get(arr, key);
    return v ? val_truthy(v) : def;
}

/* str_replace for one subject string. search/replace follow PHP: a string
   search uses the string replacement; an array of searches is applied in
   order, each with the matching replacement (or "" when the replacement array
   runs out, or the one string when replace is a string). An empty search
   string replaces nothing. */
static char* replace_one(const char* in, const char* from, const char* to) {
    size_t fl = strlen(from);
    if (!fl) return xstrdup(in);
    Buf b;
    buf_init(&b);
    const char* p = in;
    for (;;) {
        const char* hit = strstr(p, from);
        if (!hit) { buf_addz(&b, p); break; }
        buf_add(&b, p, (size_t)(hit - p));
        buf_addz(&b, to);
        p = hit + fl;
    }
    return b.data ? b.data : xstrdup("");
}

static char* str_replace_all(const char* in, Value* search, Value* repl) {
    if (search->type != T_ARRAY) {
        char* from = val_to_string(search);
        char* to = repl->type == T_ARRAY ? xstrdup("Array") : val_to_string(repl);
        char* out = replace_one(in, from, to);
        free(from);
        free(to);
        return out;
    }

    char* cur = xstrdup(in);
    ArrayItem* r = repl->type == T_ARRAY ? repl->items : 0;
    for (ArrayItem* it = search->items; it; it = it->next) {
        char* from = val_to_string(it->val);
        char* to;
        if (repl->type == T_ARRAY) { to = r ? val_to_string(r->val) : xstrdup(""); if (r) r = r->next; }
        else to = val_to_string(repl);
        char* next = replace_one(cur, from, to);
        free(cur);
        free(from);
        free(to);
        cur = next;
    }
    return cur;
}

static Value* builtin(const char* name, Value** args, int argc) {
#define NEED(n) do { if (argc < (n)) fatal("%s expects at least %d argument(s)", name, n); } while (0)

    if (!strcmp(name, "strlen")) {
        NEED(1);
        char* s = val_to_string(args[0]);
        long long l = (long long)strlen(s);
        free(s);
        return v_int(l);
    }

    if (!strcmp(name, "count")) {
        NEED(1);
        if (args[0]->type == T_ARRAY) return v_int(array_count(args[0]));
        return v_int(args[0]->type == T_NULL ? 0 : 1);
    }

    /* ---------- strings (milestone 2) ----------
       Each follows PHP 8's rules, including its errors: where PHP 8 throws a
       ValueError the call is a fatal error here, since this runtime has no
       exceptions to throw. */

    if (!strcmp(name, "substr")) {
        NEED(2);
        char* str = val_to_string(args[0]);
        long long len = (long long)strlen(str);
        long long start = val_to_int(args[1]);
        long long cnt = (argc > 2 && args[2]->type != T_NULL) ? val_to_int(args[2]) : len;

        if (start < 0) { start += len; if (start < 0) start = 0; }
        if (start > len) start = len;               /* PHP 8: "" past the end */
        long long avail = len - start;
        if (cnt < 0) { cnt += avail; if (cnt < 0) cnt = 0; }
        if (cnt > avail) cnt = avail;

        Value* r = v_str_n(str + start, (size_t)cnt);
        free(str);
        return r;
    }

    if (!strcmp(name, "strpos")) {
        NEED(2);
        char* hay = val_to_string(args[0]);
        char* ndl = val_to_string(args[1]);
        long long hl = (long long)strlen(hay);
        long long off = argc > 2 ? val_to_int(args[2]) : 0;

        if (off < 0) off += hl;
        if (off < 0 || off > hl)
            fatal("strpos(): Argument #3 ($offset) must be contained in argument #1 ($haystack)");

        char* hit = strstr(hay + off, ndl);         /* "" matches at off, as PHP 8 */
        Value* r = hit ? v_int((long long)(hit - hay)) : v_bool(0);
        free(hay);
        free(ndl);
        return r;
    }

    if (!strcmp(name, "str_repeat")) {
        NEED(2);
        char* str = val_to_string(args[0]);
        long long times = val_to_int(args[1]);
        if (times < 0)
            fatal("str_repeat(): Argument #2 ($times) must be greater than or equal to 0");

        size_t sl = strlen(str);
        /* sl * times can overflow size_t; refuse rather than allocate a wrap-
           around size and write past it. (Real sizes stop at memory_limit.) */
        if (sl && (unsigned long long)times > (SIZE_MAX - 1) / sl)
            fatal("str_repeat(): result is too big");

        size_t total = sl * (size_t)times;
        Value* r = v_new(T_STRING);
        r->s = malloc(total + 1);
        for (long long i = 0; i < times; i++) memcpy(r->s + (size_t)i * sl, str, sl);
        r->s[total] = 0;
        free(str);
        return r;
    }

    if (!strcmp(name, "trim") || !strcmp(name, "ltrim") || !strcmp(name, "rtrim")) {
        NEED(1);
        char* str = val_to_string(args[0]);
        unsigned char strip[256] = {0};

        if (argc > 1) {
            /* the character list, including PHP's "a..z" ranges */
            char* cl = val_to_string(args[1]);
            size_t n = strlen(cl);
            for (size_t i = 0; i < n; i++) {
                unsigned char c0 = (unsigned char)cl[i];
                if (i + 3 < n && cl[i + 1] == '.' && cl[i + 2] == '.' &&
                    (unsigned char)cl[i + 3] >= c0) {
                    for (unsigned c = c0; c <= (unsigned char)cl[i + 3]; c++) strip[c] = 1;
                    i += 3;
                } else {
                    strip[c0] = 1;
                }
            }
            free(cl);
        } else {
            const char* def = " \t\n\r\v";            /* plus NUL, as PHP */
            for (const char* p = def; *p; p++) strip[(unsigned char)*p] = 1;
            strip[0] = 1;
        }

        size_t a = 0, z = strlen(str);
        if (strcmp(name, "rtrim")) while (a < z && strip[(unsigned char)str[a]]) a++;
        if (strcmp(name, "ltrim")) while (z > a && strip[(unsigned char)str[z - 1]]) z--;

        Value* r = v_str_n(str + a, z - a);
        free(str);
        return r;
    }

    if (!strcmp(name, "explode")) {
        NEED(2);
        char* sep = val_to_string(args[0]);
        char* str = val_to_string(args[1]);
        long long limit = argc > 2 ? val_to_int(args[2]) : LLONG_MAX;
        size_t sepl = strlen(sep);

        if (!sepl) fatal("explode(): Argument #1 ($separator) cannot be empty");
        if (limit == 0) limit = 1;

        /* split everything first; the limit rules are easier on the list */
        size_t np = 0, cap = 8;
        const char** starts = malloc(cap * sizeof *starts);
        size_t* lens = malloc(cap * sizeof *lens);
        const char* p = str;
        for (;;) {
            const char* hit = strstr(p, sep);
            if (np == cap) {
                cap *= 2;
                starts = realloc(starts, cap * sizeof *starts);
                lens = realloc(lens, cap * sizeof *lens);
            }
            starts[np] = p;
            lens[np] = hit ? (size_t)(hit - p) : strlen(p);
            np++;
            if (!hit) break;
            p = hit + sepl;
        }

        ArrBuild ab;
        ab_init(&ab);
        if (limit > 0) {
            size_t keep = (size_t)limit < np ? (size_t)limit : np;
            for (size_t i = 0; i < keep; i++) {
                /* the last kept piece runs to the end of the string */
                size_t l = (i + 1 == keep && keep < np) ? strlen(starts[i]) : lens[i];
                ab_push(&ab, v_str_n(starts[i], l));
            }
        } else {
            long long keep = (long long)np + limit;   /* drop the last -limit */
            for (long long i = 0; i < keep; i++) ab_push(&ab, v_str_n(starts[i], lens[i]));
        }

        free(starts);
        free(lens);
        free(sep);
        free(str);
        return ab.arr;
    }

    if (!strcmp(name, "implode") || !strcmp(name, "join")) {
        NEED(1);
        Value* arr;
        char* glue;
        if (argc == 1) {
            if (args[0]->type != T_ARRAY)
                fatal("implode(): Argument #1 ($array) must be of type array");
            arr = args[0];
            glue = xstrdup("");
        } else {
            if (args[1]->type != T_ARRAY)
                fatal("implode(): Argument #2 ($array) must be of type ?array");
            arr = args[1];
            glue = val_to_string(args[0]);
        }

        Buf b;
        buf_init(&b);
        for (ArrayItem* it = arr->items; it; it = it->next) {
            if (it != arr->items) buf_addz(&b, glue);
            char* part = val_to_string(it->val);
            buf_addz(&b, part);
            free(part);
        }
        free(glue);
        Value* r = v_new(T_STRING);
        r->s = b.data ? b.data : xstrdup("");
        return r;
    }

    if (!strcmp(name, "str_replace")) {
        NEED(3);
        /* search and replace may each be a string or an array, and the
           subject may be an array -- every combination PHP accepts. */
        Value* search = args[0];
        Value* repl = args[1];
        Value* subj = args[2];

        if (subj->type == T_ARRAY) {
            ArrBuild ab;
            ab_init(&ab);
            for (ArrayItem* it = subj->items; it; it = it->next) {
                char* in = val_to_string(it->val);
                char* out = str_replace_all(in, search, repl);
                free(in);
                Value* v = v_new(T_STRING);
                v->s = out;
                ab_put(&ab, val_clone(it->key), v);
            }
            return ab.arr;
        }

        char* in = val_to_string(subj);
        Value* r = v_new(T_STRING);
        r->s = str_replace_all(in, search, repl);
        free(in);
        return r;
    }

    /* ---------- arrays (milestone 2) ---------- */

    if (!strcmp(name, "in_array")) {
        NEED(2);
        if (args[1]->type != T_ARRAY)
            fatal("in_array(): Argument #2 ($haystack) must be of type array");
        int strict = argc > 2 && val_truthy(args[2]);
        for (ArrayItem* it = args[1]->items; it; it = it->next)
            if (strict ? val_same(it->val, args[0]) : val_equals(it->val, args[0]))
                return v_bool(1);
        return v_bool(0);
    }

    if (!strcmp(name, "array_keys")) {
        NEED(1);
        if (args[0]->type != T_ARRAY)
            fatal("array_keys(): Argument #1 ($array) must be of type array");
        int strict = argc > 2 && val_truthy(args[2]);
        ArrBuild ab;
        ab_init(&ab);
        for (ArrayItem* it = args[0]->items; it; it = it->next) {
            /* array_keys($a, $value): only the keys holding that value */
            if (argc > 1 && !(strict ? val_same(it->val, args[1]) : val_equals(it->val, args[1])))
                continue;
            ab_push(&ab, val_clone(it->key));
        }
        return ab.arr;
    }

    if (!strcmp(name, "array_values")) {
        NEED(1);
        if (args[0]->type != T_ARRAY)
            fatal("array_values(): Argument #1 ($array) must be of type array");
        ArrBuild ab;
        ab_init(&ab);
        for (ArrayItem* it = args[0]->items; it; it = it->next) ab_push(&ab, val_clone(it->val));
        return ab.arr;
    }

    if (!strcmp(name, "array_push")) {
        NEED(1);
        /* The first argument is the caller's own array, not a copy (builtins
           receive the stored value), so this appends in place -- PHP's
           by-reference parameter. A variable that does not hold an array is
           PHP 8's TypeError. */
        if (args[0]->type != T_ARRAY)
            fatal("array_push(): Argument #1 ($array) must be of type array");
        for (int i = 1; i < argc; i++)
            array_put(args[0], v_int(array_next_index(args[0])), val_clone(args[i]));
        return v_int(array_count(args[0]));
    }

    if (!strcmp(name, "array_key_exists") || !strcmp(name, "key_exists")) {
        NEED(2);
        if (args[1]->type != T_ARRAY)
            fatal("array_key_exists(): Argument #2 ($array) must be of type array");
        /* unlike isset(), a key holding null still exists */
        return v_bool(array_find(args[1], normalize_key(args[0])) != 0);
    }

    if (!strcmp(name, "strtoupper")) {
        NEED(1);
        char* s = val_to_string(args[0]);
        char* u = case_dup(s, 1);
        free(s);

        Value* v = v_new(T_STRING);
        v->s = u;
        return v;
    }

    if (!strcmp(name, "strtolower")) {
        NEED(1);
        char* s = val_to_string(args[0]);
        char* l = case_dup(s, 0);
        free(s);

        Value* v = v_new(T_STRING);
        v->s = l;
        return v;
    }

    if (!strcmp(name, "abs")) {
        NEED(1);
        if (args[0]->type == T_INT) return v_int(llabs(args[0]->i));
        if (args[0]->type == T_FLOAT) return v_float(fabs(args[0]->d));
        return v_float(fabs(val_to_double(args[0])));
    }

    if (!strcmp(name, "intval")) {
        NEED(1);
        return v_int(val_to_int(args[0]));
    }

    if (!strcmp(name, "floatval")) {
        NEED(1);
        return v_float(val_to_double(args[0]));
    }

    if (!strcmp(name, "boolval")) {
        NEED(1);
        return v_bool(val_truthy(args[0]));
    }

    if (!strcmp(name, "is_array")) {
        NEED(1);
        return v_bool(args[0]->type == T_ARRAY);
    }

    if (!strcmp(name, "is_int") || !strcmp(name, "is_integer") || !strcmp(name, "is_long")) {
        NEED(1);
        return v_bool(args[0]->type == T_INT);
    }

    if (!strcmp(name, "is_float") || !strcmp(name, "is_double") || !strcmp(name, "is_real")) {
        NEED(1);
        return v_bool(args[0]->type == T_FLOAT);
    }

    if (!strcmp(name, "is_string")) {
        NEED(1);
        return v_bool(args[0]->type == T_STRING);
    }

    if (!strcmp(name, "is_bool")) {
        NEED(1);
        return v_bool(args[0]->type == T_BOOL);
    }

    if (!strcmp(name, "is_null")) {
        NEED(1);
        return v_bool(args[0]->type == T_NULL);
    }

    if (!strcmp(name, "is_numeric")) {
        NEED(1);
        return v_bool(val_is_numeric(args[0]));
    }

    if (!strcmp(name, "empty")) {
        NEED(1);
        return v_bool(!val_truthy(args[0]));
    }

    if (!strcmp(name, "isset")) {
        NEED(1);
        for (int i = 0; i < argc; i++)
            if (args[i]->type == T_NULL) return v_bool(0);
        return v_bool(1);
    }

    if (!strcmp(name, "var_dump")) {
        NEED(1);
        for (int i = 0; i < argc; i++) dump_value(args[i], 0);
        return v_null();
    }

    if (!strcmp(name, "print_r")) {
        NEED(1);
        Buf b;
        buf_init(&b);
        pr_render(&b, args[0], 0);
        if (argc > 1 && val_truthy(args[1])) {
            Value* r = v_new(T_STRING);
            r->s = b.data ? b.data : xstrdup("");
            return r;
        }
        if (b.data) emit_string(b.data);
        free(b.data);
        return v_bool(1);
    }

    if (!strcmp(name, "exit") || !strcmp(name, "die")) {
        int code = 0;

        if (argc > 0) {
            if (args[0]->type == T_INT) {
                code = (int)args[0]->i;
            } else {
                char* s = val_to_string(args[0]);
                emit_string(s);
                free(s);
            }
        }

        exit(code);
        return v_null();
    }

    if (!strcmp(name, "min") || !strcmp(name, "max")) {
        NEED(1);

        int ismax = !strcmp(name, "max");
        Value* best = 0;

        if (argc == 1 && args[0]->type == T_ARRAY) {
            if (!args[0]->items) return v_null();

            best = val_clone(args[0]->items->val);

            for (ArrayItem* it = args[0]->items->next; it; it = it->next) {
                int c = val_cmp(it->val, best);
                if ((ismax && c > 0) || (!ismax && c < 0)) {
                    Value* old = best;
                    best = val_clone(it->val);
                    (void)old;
                }
            }
        } else {
            best = val_clone(args[0]);

            for (int i = 1; i < argc; i++) {
                int c = val_cmp(args[i], best);
                if ((ismax && c > 0) || (!ismax && c < 0)) {
                    Value* old = best;
                    best = val_clone(args[i]);
                    (void)old;
                }
            }
        }

        return best;
    }

    if (!strcmp(name, "session_start")) {
        session_start_impl();
        return v_bool(1);
    }

    if (!strcmp(name, "session_destroy")) {
        session_destroy_impl();
        return v_bool(1);
    }

    if (!strcmp(name, "session_id")) {
        return v_str(session_id);
    }

    if (!strcmp(name, "header")) {
        NEED(1);

        char* line = val_to_string(args[0]);
        int replace = 1;
        int code = 0;

        if (argc > 1) replace = val_truthy(args[1]);
        if (argc > 2) code = (int)val_to_int(args[2]);

        if (code) response_status = code;

        add_response_header_ex(line, replace);
        free(line);

        return v_null();
    }

    if (!strcmp(name, "setcookie")) {
        NEED(1);

        char* cname = val_to_string(args[0]);
        char* cvalue = argc > 1 ? val_to_string(args[1]) : xstrdup("");

        long long expires = 0;
        char* path = xstrdup("");
        char* domain = xstrdup("");
        int secure = 0;
        int httponly = 0;
        char* samesite = xstrdup("");

        if (argc > 2 && args[2] && args[2]->type == T_ARRAY) {
            Value* opt = args[2];

            free(path);
            free(domain);
            free(samesite);

            expires = arr_get_int(opt, "expires", 0);
            path = arr_get_str(opt, "path", "");
            domain = arr_get_str(opt, "domain", "");
            secure = arr_get_bool(opt, "secure", 0);
            httponly = arr_get_bool(opt, "httponly", 0);
            samesite = arr_get_str(opt, "samesite", "");
        } else {
            if (argc > 2) expires = val_to_int(args[2]);

            if (argc > 3) {
                free(path);
                path = val_to_string(args[3]);
            }

            if (argc > 4) {
                free(domain);
                domain = val_to_string(args[4]);
            }

            if (argc > 5) secure = val_truthy(args[5]);
            if (argc > 6) httponly = val_truthy(args[6]);
        }

        add_set_cookie_full(cname, cvalue, expires, path, domain, secure, httponly, samesite);

        free(cname);
        free(cvalue);
        free(path);
        free(domain);
        free(samesite);

        return v_bool(1);
    }

    if (!strcmp(name, "urlencode")) {
        NEED(1);
        char* s = val_to_string(args[0]);
        char* e = url_encode(s);
        free(s);

        Value* v = v_new(T_STRING);
        v->s = e;
        return v;
    }

    if (!strcmp(name, "urldecode")) {
        NEED(1);
        char* s = val_to_string(args[0]);
        char* d = url_decode(s);
        free(s);

        Value* v = v_new(T_STRING);
        v->s = d;
        return v;
    }

    if (!strcmp(name, "htmlspecialchars")) {
        NEED(1);
        char* s = val_to_string(args[0]);
        char* h = html_escape(s);
        free(s);

        Value* v = v_new(T_STRING);
        v->s = h;
        return v;
    }

    if (!strcmp(name, "php_sapi_name")) {
        return v_str(cgi_mode ? "cgi" : "cli");
    }

#undef NEED

    return 0;
}

static Value* eval_index(Value* cont, Value* key) {
    if (!cont) return v_null();

    if (cont->type == T_ARRAY) {
        Value* nk = normalize_key(key);
        ArrayItem* it = array_find(cont, nk);
        return it ? it->val : v_null();
    }

    if (cont->type == T_STRING) {
        long long idx = val_to_int(key);
        size_t len = strlen(cont->s ? cont->s : "");

        if (idx < 0) idx += (long long)len;
        if (idx < 0 || idx >= (long long)len) return v_str("");

        char buf[2];
        buf[0] = cont->s[idx];
        buf[1] = 0;

        return v_str(buf);
    }

    return v_null();
}

static void set_index(Value* cont, Value* key, Value* val) {
    if (!cont) fatal("Cannot write to index");

    if (cont->type == T_NULL) {
        cont->type = T_ARRAY;
        cont->items = 0;
    }

    if (cont->type == T_ARRAY) {
        array_put(cont, key, val);
        return;
    }

    if (cont->type == T_STRING) {
        long long idx = val_to_int(key);
        size_t len = strlen(cont->s ? cont->s : "");

        if (idx < 0) idx += (long long)len;
        if (idx < 0 || idx >= (long long)len) fatal("Illegal string offset");

        char* tmp = val_to_string(val);
        if (tmp[0]) cont->s[idx] = tmp[0];
        else cont->s[idx] = '\0';
        free(tmp);

        return;
    }

    fatal("Cannot use a scalar value as an array");
}

static Value* eval(Node* n, Env* env) {
    stack_guard();
    if (!n) return v_null();

    switch (n->type) {
        case NT_INT:
            return v_int(n->i);

        case NT_FLOAT:
            return v_float(n->d);

        case NT_STR:
            return v_str(n->s);

        case NT_BOOL:
            return v_bool((int)n->i);

        case NT_NULL:
            return v_null();

        case NT_VAR:
            return env_get(env, n->s);

        case NT_BINOP:
            if (n->op == OP_AND) {
                Value* a = eval(n->a, env);
                if (!val_truthy(a)) return v_bool(0);
                Value* b = eval(n->b, env);
                return v_bool(val_truthy(b));
            }

            if (n->op == OP_OR) {
                Value* a = eval(n->a, env);
                if (val_truthy(a)) return v_bool(1);
                Value* b = eval(n->b, env);
                return v_bool(val_truthy(b));
            }

            return eval_binop(n->op, eval(n->a, env), eval(n->b, env));

        case NT_UNOP:
            return eval_unop(n->op, eval(n->a, env));

        case NT_CALL: {
            int argc = list_count(n->l1);
            Value** args = malloc(sizeof(Value*) * (argc ? argc : 1));
            if (!args) fatal("out of memory");

            int i = 0;
            for (NodeList* l = n->l1; l; l = l->next, i++)
                args[i] = eval(l->node, env);

            char* lname = lower_dup(n->s);
            Func* f = find_func_lower(lname);

            Value* r;
            if (f) {
                r = call_user(f, args, argc);
            } else {
                r = builtin(lname, args, argc);
                if (!r) fatal("Undefined function %s()", n->s);
            }

            free(lname);
            free(args);

            return r;
        }

        case NT_INDEX:
            if (!n->b) fatal("Cannot use [] for reading");
            return eval_index(eval(n->a, env), eval(n->b, env));

        case NT_INCDEC: {
            /* null++ is 1 and null-- stays null, as in PHP. Everything else
               goes through arith(), so PHP_INT_MAX++ becomes a float rather
               than overflowing. (PHP's "a"++ == "b" string increment is not
               implemented; a non-numeric string counts as 0.) */
            Value* old = val_clone(eval(n->a, env));
            Value* nv;
            if (old->type == T_NULL) nv = n->op > 0 ? v_int(1) : v_null();
            else nv = arith(n->op > 0 ? OP_ADD : OP_SUB, old, v_int(1));
            assign_to(n->a, nv, env);
            return n->i ? nv : old;
        }

        case NT_TERNARY: {
            Value* c = eval(n->a, env);
            if (val_truthy(c)) return n->b ? eval(n->b, env) : c;
            return eval(n->c, env);
        }

        case NT_COALESCE: {
            Value* l = eval(n->a, env);
            if (l && l->type != T_NULL) return l;
            return eval(n->b, env);
        }

        case NT_ARRAY: {
            Value* arr = v_new(T_ARRAY);
            int auto_idx = 0;

            for (Pair* p = n->pairs; p; p = p->next) {
                Value* key = p->key ? normalize_key(eval(p->key, env)) : v_int(auto_idx);
                Value* val = val_clone(eval(p->val, env));

                array_put(arr, key, val);

                if (key->type == T_INT && key->i >= auto_idx)
                    auto_idx = (int)key->i + 1;
            }

            return arr;
        }

        case NT_EXPR:
            return eval(n->a, env);

        default:
            fatal("Cannot evaluate node");
            return v_null();
    }
}

/* Called by a loop after each pass of its body. Returns 1 if the loop must
   stop. break N: this loop stops and N-1 more outer loops will too.
   continue N: N == 1 continues THIS loop; N > 1 stops it so the loop N
   levels out continues. */
static int loop_control_done(void) {
    if (brk_n) { brk_n--; return 1; }
    if (cont_n) { cont_n--; return cont_n > 0; }
    return 0;
}

/* The one place a value is stored into a variable or an array element.
   Was inline in NT_ASSIGN; pulled out so ++, --, op= and $a[] all write
   through exactly the same code as plain assignment. */
static long long array_next_index(Value* arr) {
    long long next = 0;
    if (!arr || arr->type != T_ARRAY) return 0;
    for (ArrayItem* it = arr->items; it; it = it->next)
        if (it->key && it->key->type == T_INT && it->key->i >= next)
            next = it->key->i + 1;
    return next;
}

/* AUDIT: superglobals are the same array in every scope. Writes used to go
   to the CURRENT scope only, so $_SESSION["user"] = ... inside a function
   created a local array and was thrown away when the function returned --
   which is where login code lives, so sessions were effectively broken for
   real applications even after the file format was fixed. */
static int is_superglobal(const char* name) {
    static const char* sg[] = { "_GET", "_POST", "_COOKIE", "_SESSION", "_SERVER", "_REQUEST", 0 };
    for (int i = 0; sg[i]; i++) if (!strcmp(name, sg[i])) return 1;
    return 0;
}

static Env* scope_for(Env* env, const char* name) {
    return (global_env && is_superglobal(name)) ? global_env : env;
}

static void assign_to(Node* target, Value* val, Env* env) {
    if (target->type == NT_VAR) {
        env_set(scope_for(env, target->s), target->s, val_clone(val));
    } else if (target->type == NT_INDEX) {
        Node* base = target->a;
        Value* cont;

        if (base->type == NT_VAR) {
            env = scope_for(env, base->s);
            Var* cv = env_find_current(env, base->s);
            if (cv) {
                cont = cv->val;
            } else {
                cont = v_new(T_ARRAY);
                env_set(env, base->s, cont);
            }
        } else {
            cont = eval(base, env);
        }

        /* $a[] = v: append at one past the highest integer key, as PHP does. */
        Value* key;
        if (!target->b) {
            if (cont && cont->type == T_NULL) { cont->type = T_ARRAY; cont->items = 0; }
            if (!cont || cont->type != T_ARRAY) fatal("[] operator not supported for this value");
            key = v_int(array_next_index(cont));
        } else {
            key = eval(target->b, env);
        }
        set_index(cont, key, val_clone(val));
    } else {
        fatal("Invalid assignment target");
    }
}

static void exec_list(NodeList* l, Env* env) {
    for (; l && !in_ret && !brk_n && !cont_n; l = l->next)
        exec(l->node, env);
}

static void register_func_node(Node* n) {
    Func* f = calloc(1, sizeof(Func));
    if (!f) fatal("out of memory");

    f->name = lower_dup(n->s);
    f->params = n->l1;
    f->body = n->l2;
    f->next = funcs;

    funcs = f;
}

static void hoist_functions(NodeList* l) {
    for (; l; l = l->next)
        if (l->node->type == NT_FUNC)
            register_func_node(l->node);
}

static Value* call_user(Func* f, Value** args, int argc) {
    Env* env = new_env(global_env);

    int i = 0;
    for (NodeList* p = f->params; p; p = p->next, i++) {
        Value* av = (i < argc) ? val_clone(args[i]) : v_null();
        env_set(env, p->node->s, av);
    }

    stack_guard();
    exec_list(f->body, env);

    Value* r = v_null();
    if (in_ret) {
        r = ret_val ? ret_val : v_null();
        ret_val = 0;
        in_ret = 0;
    }

    return r;
}

static void exec(Node* n, Env* env) {
    stack_guard();
    if (!n) return;

    switch (n->type) {
        case NT_ECHO:
            for (NodeList* l = n->l1; l; l = l->next) {
                Value* v = eval(l->node, env);
                char* s = val_to_string(v);
                emit_string(s);
                free(s);
            }
            break;

        case NT_ASSIGN:
            if (!n->i) {
                assign_to(n->a, eval(n->b, env), env);
            } else {
                /* Compound: read the target, combine, write it back. The
                   index expression of $a[k] op= v is evaluated twice (once
                   to read, once to write), so a key with side effects runs
                   twice -- the price of keeping one write path. */
                /* $a[] op= v appends (null op v), as PHP does. */
                int append = n->a->type == NT_INDEX && !n->a->b;
                Value* curv = append ? v_null() : eval(n->a, env);
                if (n->op == OP_COALESCE) {
                    if (!curv || curv->type == T_NULL)
                        assign_to(n->a, eval(n->b, env), env);
                } else {
                    assign_to(n->a, arith(n->op, curv, eval(n->b, env)), env);
                }
            }
            break;

        case NT_FOREACH: {
            Value* src = eval(n->a, env);
            if (!src || src->type != T_ARRAY) {
                fprintf(stderr, "PHP warning: foreach() argument must be of type array\n");
                break;
            }

            /* PHP iterates a by-value foreach over a COPY: changing the array
               inside the loop does not change what the loop visits. Copying
               the whole array would be O(n^2) here (every append walks the
               list), so the loop takes the current key and value POINTERS up
               front instead -- O(n). A write replaces an element's value
               pointer rather than changing the old value, and nothing is
               freed while a script runs, so the pointers taken here keep
               showing exactly what the array held when the loop began. */
            int cnt = array_count(src);
            Value** ks = malloc(sizeof(Value*) * (size_t)(cnt ? cnt : 1));
            Value** vs = malloc(sizeof(Value*) * (size_t)(cnt ? cnt : 1));
            int k = 0;
            for (ArrayItem* it = src->items; it && k < cnt; it = it->next, k++) {
                ks[k] = it->key;
                vs[k] = it->val;
            }

            for (int i = 0; i < k && !in_ret; i++) {
                if (n->b) assign_to(n->b, ks[i], env);
                assign_to(n->c, vs[i], env);
                exec_list(n->l1, env);
                if (loop_control_done()) break;
            }
            free(ks);
            free(vs);
            break;
        }

        case NT_UNSET:
            for (NodeList* l = n->l1; l; l = l->next) {
                Node* t = l->node;
                if (t->type == NT_VAR) {
                    env_unset(scope_for(env, t->s), t->s);
                } else {
                    /* the element's container, found without creating it:
                       unsetting a key of a missing array is a no-op */
                    Value* cont = 0;
                    if (t->a->type == NT_VAR) {
                        Var* cv = env_find_current(scope_for(env, t->a->s), t->a->s);
                        cont = cv ? cv->val : 0;
                    } else {
                        cont = eval(t->a, env);
                    }
                    if (cont && cont->type == T_ARRAY)
                        array_remove(cont, normalize_key(eval(t->b, env)));
                }
            }
            break;

        case NT_BREAK:
            brk_n = n->i;
            break;

        case NT_CONTINUE:
            cont_n = n->i;
            break;

        case NT_IF: {
            Value* c = eval(n->a, env);
            if (val_truthy(c)) exec_list(n->l1, env);
            else exec_list(n->l2, env);
            break;
        }

        case NT_WHILE:
            while (!in_ret) {
                Value* c = eval(n->a, env);
                if (!val_truthy(c)) break;
                exec_list(n->l1, env);
                if (loop_control_done()) break;
            }
            break;

        case NT_FOR:
            if (n->a) exec(n->a, env);

            while (!in_ret) {
                if (n->b) {
                    Value* c = eval(n->b, env);
                    if (!val_truthy(c)) break;
                }

                exec_list(n->l1, env);
                if (in_ret || loop_control_done()) break;

                if (n->c) exec(n->c, env);
            }
            break;

        case NT_FUNC:
            register_func_node(n);
            break;

        case NT_RETURN:
            ret_val = n->a ? eval(n->a, env) : v_null();
            in_ret = 1;
            break;

        case NT_EXPR:
            eval(n->a, env);
            break;

        default:
            eval(n, env);
            break;
    }
}

int main(int argc, char** argv) {
    stack_guard_init(__builtin_frame_address(0));

    FILE* f = stdin;
    int close_f = 0;

    const char* src = (argc > 1) ? argv[1] : getenv("SCRIPT_FILENAME");

    if (src && *src) {
        char* fname = xstrdup(src);
        char* q = strchr(fname, '?');

        if (q) {
            *q = 0;
            if (!getenv("QUERY_STRING"))
                setenv("QUERY_STRING", q + 1, 1);
        }

        f = fopen(fname, "rb");
        if (!f) {
            perror(fname);
            free(fname);
            return 1;
        }

        close_f = 1;
        free(fname);
    }

    char* raw = read_all(f);
    if (close_f) fclose(f);

    char* code = preprocess_source(raw);

    lex_src = code;
    lex_len = strlen(code);
    lex_pos = 0;

    adv();

    NodeList* program = parse_program();

    Env* global = new_env(0);
    global_env = global;

    hoist_functions(program);
    web_bootstrap(global);

    exec_list(program, global);

    return 0;
}