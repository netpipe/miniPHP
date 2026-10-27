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
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>
#ifndef MINIPHP_NO_SQLITE
#include "sqlite/sqlite3.h"
#endif
#ifdef MINIPHP_SODIUM
#include <sodium.h>       /* bundled in libsodium/, built by make SODIUM=1 */
#endif

enum {
    T_NULL, T_INT, T_FLOAT, T_BOOL, T_STRING, T_ARRAY
};

enum {
    NT_ECHO, NT_ASSIGN, NT_IF, NT_WHILE, NT_FOR, NT_FUNC, NT_RETURN, NT_EXPR,
    NT_INT, NT_FLOAT, NT_STR, NT_BOOL, NT_NULL, NT_VAR, NT_BINOP, NT_UNOP,
    NT_CALL, NT_INDEX, NT_ARRAY,
    NT_INCDEC, NT_TERNARY, NT_COALESCE, NT_BREAK, NT_CONTINUE,
    NT_FOREACH, NT_UNSET, NT_INCLUDE
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
    TK_BREAK, TK_CONTINUE, TK_FOREACH, TK_AS, TK_INCLUDE
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
    size_t n;          /* NT_STR from a literal: byte length (0: use strlen) */
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
    /* BINARY-SAFE STRINGS: a string's length lives here, not in a
       terminating zero, so "a\0b" is three bytes long (crypto keys, SQLite
       blobs and uploaded data are full of zero bytes). s is still always
       zero-terminated after its n bytes, for C APIs. SIZE_MAX means "not
       recorded" and falls back to strlen() -- see slen() below. */
    size_t n;
};

typedef struct Func {
    char* name;
    NodeList* params;
    NodeList* body;
    struct Func* next;
    Node* def;          /* the declaring node: the same one again is not a redeclaration */
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
    size_t n;          /* TK_STR: byte length -- "\0" makes strlen wrong */
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
static Value *V_FILES = 0;
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

/* The file the parser is reading, for __FILE__ / __DIR__ and for include
   resolution ("the directory of the file doing the including"). */
static const char* parse_file = "Standard input code";

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
static long long double_to_ll(double d);
static Value* v_str_n(const char* s, size_t n);
static char* val_to_string(Value* v);
static Value* do_include(Node* n, Env* env);
static Func* find_func_lower(const char* lname);
static void hoist_functions(NodeList* l);
static NodeList* parse_program(void);
static char* read_all(FILE* f);
static char* preprocess_source(const char* src);
static Value* call_user(Func* f, Value** args, int argc);
static Value* builtin(const char* name, Value** args, int argc);
#ifdef MINIPHP_SODIUM
static int sodium_constant(const char* name, Node* n);
#endif

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

static char* case_dup_n(const char* s, size_t n, int up) {
    char* r = malloc(n + 1);
    if (!r) fatal("out of memory");
    for (size_t i = 0; i < n; i++)
        r[i] = (char)(up ? toupper((unsigned char)s[i]) : tolower((unsigned char)s[i]));
    r[n] = 0;
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

/* The whole stream; *n (if given) gets the byte count, which zero bytes
   inside the data would otherwise hide from strlen. */
static char* read_all_n(FILE* f, size_t* n) {
    Buf b;
    buf_init(&b);
    int c;
    while ((c = fgetc(f)) != EOF)
        buf_ch(&b, (char)c);
    if (n) *n = b.len;
    if (!b.data) return xstrdup("");
    return b.data;
}

static char* read_all(FILE* f) { return read_all_n(f, 0); }

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decodes n bytes; %00 becomes a real zero byte, and the decoded length
   comes back in *outn. (It used to stop there: ?v=a%00b arrived as "a".) */
static char* url_decode_raw(const char* s, size_t n, size_t* outn, int plus) {
    Buf b;
    buf_init(&b);
    for (size_t i = 0; s && i < n; i++) {
        if (plus && s[i] == '+') {
            buf_ch(&b, ' ');
        } else if (s[i] == '%' && i + 2 < n && hexval(s[i+1]) >= 0 && hexval(s[i+2]) >= 0) {
            buf_ch(&b, (char)(hexval(s[i+1]) * 16 + hexval(s[i+2])));
            i += 2;
        } else {
            buf_ch(&b, s[i]);
        }
    }
    *outn = b.len;
    return b.data ? b.data : xstrdup("");
}

/* urldecode(): "+" is a space, as in a query string or form body */
static char* url_decode_n(const char* s, size_t n, size_t* outn) {
    return url_decode_raw(s, n, outn, 1);
}

static char* url_decode(const char* s) {
    size_t n;
    return url_decode_n(s ? s : "", s ? strlen(s) : 0, &n);
}

static int url_unreserved(char c) {
    return isalnum((unsigned char)c) || c == '-' || c == '_' || c == '.' || c == '~';
}

/* raw: rawurlencode() (RFC 3986, a space is %20) -- also what setcookie()
   uses. Otherwise urlencode(): a space is "+" and "~" is encoded. */
static char* url_encode_n(const char* s, size_t n, int raw) {
    Buf b;
    buf_init(&b);
    if (!s) return xstrdup("");

    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!raw && c == ' ') buf_ch(&b, '+');
        else if (url_unreserved((char)c) && (raw || c != '~')) buf_ch(&b, (char)c);
        else buf_fmt(&b, "%%%02X", c);
    }

    return b.data ? b.data : xstrdup("");
}

static char* url_encode(const char* s) { return url_encode_n(s, s ? strlen(s) : 0, 1); }

/* 0 if a valid UTF-8 character starts at s[i] (or it is ASCII); otherwise
   how many bytes PHP's decoder (ext/standard/html.c) swallows as one invalid
   sequence. Those exact counts decide how many U+FFFD come out. */
static int utf8_lead(unsigned char c) { return c < 0x80 || (c >= 0xC2 && c <= 0xF4); }
static int utf8_trail(unsigned char c) { return c >= 0x80 && c <= 0xBF; }

static size_t utf8_invalid_len(const char* str, size_t n, size_t i) {
    const unsigned char* s = (const unsigned char*)str + i;
    size_t avail = n - i;
    unsigned c = s[0], cp;
    if (c < 0x80) return 0;
    if (c < 0xC2) return 1;
    if (c < 0xE0) {
        if (avail < 2) return 1;
        if (!utf8_trail(s[1])) return utf8_lead(s[1]) ? 1 : 2;
        return 0;
    }
    if (c < 0xF0) {
        if (avail < 3 || !utf8_trail(s[1]) || !utf8_trail(s[2])) {
            if (avail < 2 || utf8_lead(s[1])) return 1;
            if (avail < 3 || utf8_lead(s[2])) return 2;
            return 3;
        }
        cp = ((c & 0x0F) << 12) | ((s[1] & 0x3F) << 6) | (s[2] & 0x3F);
        if (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF)) return 3;   /* overlong, surrogate */
        return 0;
    }
    if (c < 0xF5) {
        if (avail < 4 || !utf8_trail(s[1]) || !utf8_trail(s[2]) || !utf8_trail(s[3])) {
            if (avail < 2 || utf8_lead(s[1])) return 1;
            if (avail < 3 || utf8_lead(s[2])) return 2;
            if (avail < 4 || utf8_lead(s[3])) return 3;
            return 4;
        }
        cp = ((c & 0x07) << 18) | ((s[1] & 0x3F) << 12) | ((s[2] & 0x3F) << 6) | (s[3] & 0x3F);
        if (cp < 0x10000 || cp > 0x10FFFF) return 4;
        return 0;
    }
    return 1;
}

static char* html_escape_n(const char* s, size_t n, size_t* outn) {
    Buf b;
    buf_init(&b);
    *outn = 0;
    if (!s) return xstrdup("");

    for (size_t i = 0; i < n; ) {
        size_t bad = utf8_invalid_len(s, n, i);
        if (bad) {
            /* ENT_SUBSTITUTE, PHP 8.1's default: a broken UTF-8 sequence
               becomes U+FFFD instead of passing through to the page */
            buf_addz(&b, "\xEF\xBF\xBD");
            i += bad;
            continue;
        }
        unsigned char c = (unsigned char)s[i];
        if (c >= 0x80) {        /* a valid multi-byte character, whole */
            size_t len = c < 0xE0 ? 2 : c < 0xF0 ? 3 : 4;
            buf_add(&b, s + i, len);
            i += len;
            continue;
        }
        switch (s[i]) {
            case '&': buf_addz(&b, "&amp;"); break;
            case '<': buf_addz(&b, "&lt;"); break;
            case '>': buf_addz(&b, "&gt;"); break;
            case '"': buf_addz(&b, "&quot;"); break;
            case '\'': buf_addz(&b, "&#039;"); break;
            default: buf_ch(&b, s[i]); break;
        }
        i++;
    }

    *outn = b.len;
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

/* PHP's closing tag swallows ONE newline straight after it ("\n" or
   "\r\n"), for <?php ... ?> and <?= ... ?> alike. Without this every
   template ending in "?>" plus a newline printed a stray line break -- and
   in a page built from includes those add up. */
static const char* skip_close_newline(const char* p) {
    if (p[0] == '\n') return p + 1;
    if (p[0] == '\r' && p[1] == '\n') return p + 2;
    return p;
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

            if (*close == '?') p = skip_close_newline(close + 2);
            else p = close;
        } else {
            const char* close = find_php_close(p);
            size_t n = (size_t)(close - p);

            buf_add(&out, p, n);
            buf_addz(&out, ";\n");

            if (*close == '?') p = skip_close_newline(close + 2);
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
        else if (!strcmp(lw, "include")) { tt = TK_INCLUDE; t.i = 0; }
        else if (!strcmp(lw, "include_once")) { tt = TK_INCLUDE; t.i = 1; }
        else if (!strcmp(lw, "require")) { tt = TK_INCLUDE; t.i = 2; }
        else if (!strcmp(lw, "require_once")) { tt = TK_INCLUDE; t.i = 3; }
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
                    /* PHP's double-quoted escapes. An unknown one (including
                       \') keeps its backslash, as in PHP. */
                    switch (e) {
                        case 'n': buf_ch(&b, '\n'); break;
                        case 't': buf_ch(&b, '\t'); break;
                        case 'r': buf_ch(&b, '\r'); break;
                        case 'v': buf_ch(&b, '\v'); break;
                        case 'e': buf_ch(&b, 0x1b); break;
                        case 'f': buf_ch(&b, '\f'); break;
                        case '\\': buf_ch(&b, '\\'); break;
                        case '"': buf_ch(&b, '"'); break;
                        case '$': buf_ch(&b, '$'); break;
                        case '0': case '1': case '2': case '3':
                        case '4': case '5': case '6': case '7': {
                            /* \0 .. \377, one to three octal digits; PHP keeps
                               the low byte of anything larger */
                            size_t from = lex_pos - 1;
                            int v = e - '0';
                            for (int k = 0; k < 2 && lex_pos < lex_len &&
                                 lex_src[lex_pos] >= '0' && lex_src[lex_pos] <= '7'; k++)
                                v = v * 8 + (lex_src[lex_pos++] - '0');
                            if (v > 0xff)
                                fprintf(stderr, "PHP warning: Octal escape sequence overflow \\%.*s is greater than \\377\n",
                                        (int)(lex_pos - from), lex_src + from);
                            buf_ch(&b, (char)(v & 0xff));
                            break;
                        }
                        case 'x': {
                            int v = 0, k = 0;
                            while (k < 2 && lex_pos < lex_len && hexval(lex_src[lex_pos]) >= 0)
                                v = v * 16 + hexval(lex_src[lex_pos++]), k++;
                            if (k) buf_ch(&b, (char)v);
                            else { buf_ch(&b, '\\'); buf_ch(&b, 'x'); }
                            break;
                        }
                        case 'u': {
                            /* \u{1F600} -> UTF-8; "\u" without a brace is literal */
                            if (lex_pos >= lex_len || lex_src[lex_pos] != '{') {
                                buf_ch(&b, '\\'); buf_ch(&b, 'u');
                                break;
                            }
                            size_t q = lex_pos + 1;
                            unsigned long cp = 0;
                            int k = 0;
                            while (q < lex_len && hexval(lex_src[q]) >= 0 && k < 8)
                                cp = cp * 16 + hexval(lex_src[q++]), k++;
                            if (!k || q >= lex_len || lex_src[q] != '}')
                                fatal("Syntax error: Invalid UTF-8 codepoint escape sequence");
                            if (cp > 0x10FFFF)
                                fatal("Syntax error: Invalid UTF-8 codepoint escape sequence: Codepoint too large");
                            lex_pos = q + 1;
                            if (cp < 0x80) buf_ch(&b, (char)cp);
                            else if (cp < 0x800) {
                                buf_ch(&b, (char)(0xC0 | (cp >> 6)));
                                buf_ch(&b, (char)(0x80 | (cp & 0x3F)));
                            } else if (cp < 0x10000) {
                                buf_ch(&b, (char)(0xE0 | (cp >> 12)));
                                buf_ch(&b, (char)(0x80 | ((cp >> 6) & 0x3F)));
                                buf_ch(&b, (char)(0x80 | (cp & 0x3F)));
                            } else {
                                buf_ch(&b, (char)(0xF0 | (cp >> 18)));
                                buf_ch(&b, (char)(0x80 | ((cp >> 12) & 0x3F)));
                                buf_ch(&b, (char)(0x80 | ((cp >> 6) & 0x3F)));
                                buf_ch(&b, (char)(0x80 | (cp & 0x3F)));
                            }
                            break;
                        }
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
        t.n = b.len;
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
            n->n = cur.n;
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

#ifdef MINIPHP_SODIUM
            {
                Node* c = new_node(NT_INT);
                if (sodium_constant(name, c)) return c;
                free(c);
            }
#endif

            /* Magic constants, fixed per file when it is parsed -- the
               standard include idiom is include __DIR__ . "/lib.php". They
               used to be plain strings: __DIR__ was the text "__DIR__". */
            Node* n = new_node(NT_STR);
            if (!strcasecmp(name, "__FILE__")) {
                n->s = xstrdup(parse_file);
            } else if (!strcasecmp(name, "__DIR__")) {
                char* d = xstrdup(parse_file);
                char* sl = strrchr(d, '/');
                if (!sl) { free(d); d = xstrdup("."); }
                else if (sl == d) d[1] = 0;            /* a file in / */
                else *sl = 0;
                n->s = d;
            } else {
                n->s = name;
            }
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
    if (cur.type == TK_INCLUDE) {
        /* include/require take a whole expression: include $dir . "/a.php"
           includes the concatenation, as in PHP. */
        int kind = (int)cur.i;
        adv();
        Node* n = new_node(NT_INCLUDE);
        n->i = kind;
        n->a = parse_expr();
        n->s = xstrdup(parse_file);           /* where the statement lives */
        return n;
    }
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
    v->n = SIZE_MAX;            /* a string's length is set by whoever fills s */
    return v;
}

/* A string's length. Every string Value made by v_str/v_str_n/v_str_own
   records it; SIZE_MAX (never recorded) means a C string, and is measured. */
static size_t slen(Value* v) {
    if (!v || !v->s) return 0;
    return v->n != SIZE_MAX ? v->n : strlen(v->s);
}

/* Take ownership of a malloc'd buffer of n bytes (zero-terminated at n). */
static Value* v_str_own(char* p, size_t n) {
    Value* v = v_new(T_STRING);
    v->s = p;
    v->n = n;
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
    v->s = xstrdup(s ? s : "");
    v->n = strlen(v->s);
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

    if (v->type == T_STRING) return v_str_n(v->s ? v->s : "", slen(v));

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
        case T_FLOAT: return v_int(double_to_ll(k->d));
        case T_NULL: return v_str("");
        case T_STRING: {
            /* PHP turns a string key into an integer only when it is the
               CANONICAL form of one: "0", or an optional "-" then a digit
               1-9 then digits, and it fits in 64 bits. strtoll accepted
               more, so "05", " 5" and "+5" all became 5 and overwrote each
               other -- a zip code "05" and an id "5" were the same key, and
               "99999999999999999999" landed on PHP_INT_MAX. */
            const char* s = k->s ? k->s : "";
            size_t n = slen(k);
            size_t i = 0;
            int canonical = 0;
            if (i < n && s[i] == '-') i++;
            if (n == 1 && s[0] == '0') canonical = 1;                       /* "0" */
            else if (i < n && s[i] >= '1' && s[i] <= '9') {
                size_t q = i;
                while (q < n && s[q] >= '0' && s[q] <= '9') q++;
                canonical = (q == n) && (q - i) <= 19;   /* "5\0x" is NOT 5 */
            }
            if (canonical) {
                errno = 0;
                char* end = 0;
                long long iv = strtoll(s, &end, 10);
                if (errno == 0 && end == s + n) return v_int(iv);      /* fits */
            }
            return v_str_n(s, n);
        }
        default:
            return v_str("Array");
    }
}

/* Compare two strings byte for byte, zero bytes included: memcmp over the
   shorter length, then the shorter one sorts first -- what strcmp does for
   C strings, and what PHP does for binary strings. */
static int str_cmp_v(Value* a, Value* b) {
    size_t la = slen(a), lb = slen(b);
    int r = memcmp(a->s ? a->s : "", b->s ? b->s : "", la < lb ? la : lb);
    if (r) return r;
    return la < lb ? -1 : (la > lb ? 1 : 0);
}

/* A Value's bytes as a malloc'd, zero-terminated copy, with the real
   length in *n. For a string that is every byte, zero bytes included --
   val_to_string() is the C-string view and stops at the first zero. */
static char* val_bin(Value* v, size_t* n) {
    if (v && v->type == T_STRING) {
        size_t l = slen(v);
        char* p = malloc(l + 1);
        memcpy(p, v->s ? v->s : "", l);
        p[l] = 0;
        *n = l;
        return p;
    }
    char* p = val_to_string(v);
    *n = strlen(p);
    return p;
}

/* A string about to become a C string for the OS -- a path, a header. A
   zero byte inside it would make the C side see a SHORTER string than PHP
   does: "secret\0.php" names the file "secret". Before strings were
   binary-safe the zero byte was cut off long before it got here; now it
   survives, so every such boundary checks for it, as PHP 8 does. */
static int has_nul(Value* v) {
    return v && v->type == T_STRING && v->s && memchr(v->s, 0, slen(v)) != 0;
}

static int scalar_same(Value* a, Value* b) {
    if (!a || !b) return 0;
    if (a->type != b->type) return 0;

    switch (a->type) {
        case T_INT: return a->i == b->i;
        case T_FLOAT: return a->d == b->d;
        case T_BOOL: return a->b == b->b;
        case T_STRING: return str_cmp_v(a, b) == 0;
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

/* PHP 8's numeric string: optional whitespace, sign, digits with an optional
   fraction (at least one digit), optional exponent, optional trailing
   whitespace -- and nothing else, up to the real end. strtod() alone also
   accepted "", " ", "0x1A", "inf" and "1\0junk", so " " == 0 was true. */
static int is_numeric_bytes(const char* s, size_t n) {
    size_t i = 0, digits = 0;
    while (i < n && strchr(" \t\n\r\v\f", s[i]) && s[i]) i++;
    if (i < n && (s[i] == '+' || s[i] == '-')) i++;
    while (i < n && isdigit((unsigned char)s[i])) i++, digits++;
    if (i < n && s[i] == '.') {
        i++;
        while (i < n && isdigit((unsigned char)s[i])) i++, digits++;
    }
    if (!digits) return 0;
    if (i < n && (s[i] == 'e' || s[i] == 'E')) {
        size_t j = i + 1;
        if (j < n && (s[j] == '+' || s[j] == '-')) j++;
        if (j < n && isdigit((unsigned char)s[j])) {
            while (j < n && isdigit((unsigned char)s[j])) j++;
            i = j;
        }
    }
    while (i < n && strchr(" \t\n\r\v\f", s[i]) && s[i]) i++;
    return i == n;
}

static int val_is_numeric(Value* v) {
    if (!v) return 0;
    if (v->type == T_INT || v->type == T_FLOAT) return 1;

    if (v->type == T_STRING) {
        const char* s = v->s ? v->s : "";
        if (!*s) return 0;

        return is_numeric_bytes(s, slen(v));
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
        case T_STRING: {
            size_t n = slen(v);
            return n > 1 || (n == 1 && v->s[0] != '0');
        }
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
        case T_STRING: return str_cmp_v(a, b) == 0;
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
        return str_cmp_v(a, b) == 0;

    size_t na, nb;
    char* sa = val_bin(a, &na);
    char* sb = val_bin(b, &nb);
    int r = na == nb && memcmp(sa, sb, na) == 0;
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

    size_t na, nb;
    char* sa = val_bin(a, &na);
    char* sb = val_bin(b, &nb);
    int r = memcmp(sa, sb, na < nb ? na : nb);
    if (!r) r = na < nb ? -1 : (na > nb ? 1 : 0);
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
        size_t na, nb;
        char* sa = val_bin(a, &na);
        char* sb = val_bin(b, &nb);
        char* r = malloc(na + nb + 1);
        memcpy(r, sa, na);
        memcpy(r + na, sb, nb);
        r[na + nb] = 0;
        free(sa);
        free(sb);
        return v_str_own(r, na + nb);
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
            size_t n = slen(v);
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
        v->n = (size_t)len;                 /* zero bytes survive the round trip */
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

static void emit_bytes(const char* p, size_t n) {
    if (!p || !n) return;
    if (!cgi_mode) fwrite(p, 1, n, stdout);
    else buf_add(&response_body, p, n);
}

static void emit_string(const char* s) {
    if (s) emit_bytes(s, strlen(s));
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

    size_t len = 0;
    char* data = read_all_n(f, &len);
    fclose(f);

    const char* p = data;
    const char* end = data + len;   /* not strlen: a value may hold a zero byte */

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

/* PHP's form-variable registration (php_register_variable_ex), shared by
   the query string, form bodies, cookies and $_FILES:
     - leading spaces are dropped; in the base name ' ' and '.' become '_'
     - a[b][c] nests, a[] appends, a[][x] appends an array and fills it
     - an unmatched '[' turns into '_' and the rest is a plain name
       ("e[" -> "e_", "f[x" -> "f_x"); text after a closing ']' that is not
       another '[' is ignored ("a[b]c" -> a[b])
     - a scalar met where an array is needed is replaced by the array
     - nesting deeper than 64 drops the variable (max_input_nesting_level)
   Before this, "opts[]" from a checkbox list or "files[]" from a multi-file
   input arrived as a single key literally named "opts[]". Checked against
   PHP's own parse_str(), which uses the same code as $_GET. */
static void register_variable(Value* dest, const char* raw, Value* val) {
    while (*raw == ' ') raw++;
    char* var = xstrdup(raw);
    char* p = var;
    char* ip = 0;

    for (; *p; p++) {
        if (*p == ' ' || *p == '.') *p = '_';
        else if (*p == '[') { ip = p; *p = 0; break; }
    }
    if (!var[0]) { free(var); return; }          /* empty name: dropped */

    Value* table = dest;
    char* index = var;                           /* NULL means "append" */
    int nest = 0;

    while (ip) {
        if (++nest > 64) { free(var); return; }
        ip++;
        char* index_s = ip;
        if (*ip == ' ') ip++;
        if (*ip == ']') {
            index_s = 0;
        } else {
            char* close = strchr(ip, ']');
            if (!close) {
                /* not an index after all: un-terminate and treat as a name */
                *(index_s - 1) = '_';
                for (char* q = index_s; *q; q++)
                    if (*q == ' ' || *q == '.' || *q == '[') *q = '_';
                ip = 0;
                break;
            }
            ip = close;
            *ip = 0;
        }

        /* descend into (or create) the array at the CURRENT index */
        Value* next;
        if (!index) {
            next = v_new(T_ARRAY);
            array_put(table, v_int(array_next_index(table)), next);
        } else {
            Value* key = normalize_key(v_str(index));
            ArrayItem* it = array_find(table, key);
            if (!it) {
                next = v_new(T_ARRAY);
                array_put(table, key, next);
            } else {
                if (!it->val || it->val->type != T_ARRAY) it->val = v_new(T_ARRAY);
                next = it->val;
            }
        }
        table = next;
        index = index_s;

        ip++;
        if (*ip == '[') { *ip = 0; continue; }  /* another level */
        ip = 0;                                  /* anything else is ignored */
    }

    if (!index) array_put(table, v_int(array_next_index(table)), val);
    else array_put(table, normalize_key(v_str(index)), val);
    free(var);
}

static void parse_urlencoded_pair(const char* s, size_t len, Value* dest) {
    char* pair = malloc(len + 1);
    if (!pair) fatal("out of memory");

    memcpy(pair, s, len);
    pair[len] = 0;

    char* eq = strchr(pair, '=');

    if (eq) {
        *eq = 0;

        char* k = url_decode(pair);              /* a NAME stops at %00, as in PHP */
        size_t vn;
        char* v = url_decode_n(eq + 1, strlen(eq + 1), &vn);
        register_variable(dest, k, v_str_own(v, vn));   /* the VALUE keeps it */

        free(k);
    } else {
        char* k = url_decode(pair);
        register_variable(dest, k, v_str(""));
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
            size_t dvn;
            char* dv = url_decode_n(vp, strlen(vp), &dvn);

            register_variable(dest, dk, v_str_own(dv, dvn));

            free(k);
            free(v);
            free(dk);
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

/* ---------- request body: forms and file uploads (milestone 4) ---------- */

/* A size from the environment, in PHP's ini style: "8M", "512K", "1G", or
   plain bytes. 0 or negative means "no limit". */
static long long env_size(const char* name, long long def) {
    const char* e = getenv(name);
    if (!e || !*e) return def;
    char* end = 0;
    long long v = strtoll(e, &end, 10);
    if (end && (*end == 'k' || *end == 'K')) v <<= 10;
    else if (end && (*end == 'm' || *end == 'M')) v <<= 20;
    else if (end && (*end == 'g' || *end == 'G')) v <<= 30;
    return v;
}

/* The files that arrived in THIS request. is_uploaded_file() and
   move_uploaded_file() accept a path only if it is in this list -- that is
   the whole of their security: it is what stops a script being tricked
   into "moving" /etc/passwd or its own config somewhere public, because the
   path came from the visitor. Anything not moved is deleted at exit. */
#define MAX_UPLOADS_TRACKED 1024
static char* up_path[MAX_UPLOADS_TRACKED];
static int up_moved[MAX_UPLOADS_TRACKED];
static int up_count = 0;

static int find_upload(const char* path) {
    for (int i = 0; i < up_count; i++)
        if (!up_moved[i] && up_path[i] && !strcmp(up_path[i], path)) return i;
    return -1;
}

static void cleanup_uploads(void) {
    for (int i = 0; i < up_count; i++)
        if (!up_moved[i] && up_path[i]) unlink(up_path[i]);
    up_count = 0;
}

/* PHP's UPLOAD_ERR_* codes, same values. */
#define UPLOAD_ERR_OK         0
#define UPLOAD_ERR_INI_SIZE   1
#define UPLOAD_ERR_FORM_SIZE  2
#define UPLOAD_ERR_PARTIAL    3
#define UPLOAD_ERR_NO_FILE    4
#define UPLOAD_ERR_NO_TMP_DIR 6
#define UPLOAD_ERR_CANT_WRITE 7

/* The name a visitor sent is cut to its last path component -- both '/' and
   '\\', because old Windows browsers send "C:\\Users\\me\\photo.jpg".
   So "../../shell.php" arrives as "shell.php", and a script that does
   move_uploaded_file($f["tmp_name"], "uploads/" . $f["name"]) cannot be
   steered out of uploads/. (Which file TYPES to accept is still the
   script's decision, as in PHP.) */
static const char* upload_basename(const char* s) {
    const char* b = s;
    for (const char* p = s; *p; p++) if (*p == '/' || *p == '\\') b = p + 1;
    return b;
}

/* $_FILES["f"]["name"] for "f", $_FILES["f"]["name"][0] for "f[]" -- PHP
   builds the attribute into the name and lets the normal registration
   nest it, which is why multi-file inputs come out "transposed". */
static void register_file_attr(const char* field, const char* attr, Value* val) {
    const char* br = strchr(field, '[');
    size_t base = br ? (size_t)(br - field) : strlen(field);
    Buf b;
    buf_init(&b);
    buf_add(&b, field, base);
    buf_ch(&b, '[');
    buf_addz(&b, attr);
    buf_ch(&b, ']');
    if (br) buf_addz(&b, br);
    register_variable(V_FILES, b.data, val);
    free(b.data);
}

static void register_file(const char* field, const char* sent_name, const char* type,
                          const char* tmp, int err, long long size) {
    register_file_attr(field, "name", v_str(upload_basename(sent_name)));
    register_file_attr(field, "full_path", v_str(sent_name));
    register_file_attr(field, "type", v_str(type));
    register_file_attr(field, "tmp_name", v_str(tmp));
    register_file_attr(field, "error", v_int(err));
    register_file_attr(field, "size", v_int(size));
}

/* Store one uploaded file's bytes in a fresh temp file. mkstemp() creates
   it 0600 under a name nobody can predict, so another account on the
   machine can neither read it nor pre-plant something at that path. */
static int store_upload(const char* data, size_t len, char* out, size_t outsz) {
    const char* dir = getenv("PHPMINI_UPLOAD_TMP_DIR");
    if (!dir || !*dir) dir = getenv("TMPDIR");
    if (!dir || !*dir) dir = "/tmp";

    struct stat st;
    if (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode)) return UPLOAD_ERR_NO_TMP_DIR;
    if (up_count >= MAX_UPLOADS_TRACKED) return UPLOAD_ERR_CANT_WRITE;

    snprintf(out, outsz, "%s/phpXXXXXX", dir);
    int fd = mkstemp(out);
    if (fd < 0) return UPLOAD_ERR_CANT_WRITE;

    size_t done = 0;
    while (done < len) {
        ssize_t w = write(fd, data + done, len - done);
        if (w <= 0) { close(fd); unlink(out); return UPLOAD_ERR_CANT_WRITE; }
        done += (size_t)w;
    }
    close(fd);

    up_path[up_count] = xstrdup(out);
    up_moved[up_count] = 0;
    up_count++;
    return UPLOAD_ERR_OK;
}

/* One parameter of a header like
     Content-Disposition: form-data; name="f"; filename="a b.txt"
   Quoted values may contain ';' and backslash-escaped characters. The
   match is on the whole parameter NAME, so asking for "name" does not
   find the tail of "filename". Returns a malloc'd value or NULL. */
static char* header_param(const char* h, const char* want) {
    size_t wl = strlen(want);
    const char* p = strchr(h, ';');
    while (p) {
        p++;
        while (*p == ' ' || *p == '\t') p++;
        const char* eq = p;
        while (*eq && *eq != '=' && *eq != ';') eq++;
        size_t kl = (size_t)(eq - p);
        while (kl && (p[kl - 1] == ' ' || p[kl - 1] == '\t')) kl--;

        int hit = (kl == wl && !strncasecmp(p, want, wl));
        const char* v = (*eq == '=') ? eq + 1 : eq;
        while (*v == ' ' || *v == '\t') v++;

        Buf b;
        buf_init(&b);
        const char* next;
        if (*eq == '=' && (*v == '"' || *v == '\'')) {
            /* PHP's rule (substring_conf): a quoted value may use " or ',
               and a backslash escapes ONLY a backslash or the quote. Any
               other backslash is kept, so "C:\Users\me\a.jpg" from an old
               Windows browser survives intact -- unescaping every backslash
               turned it into "C:Usersmea.jpg". */
            char quote = *v;
            const char* q = v + 1;
            while (*q && *q != quote) {
                if (*q == '\\' && (q[1] == '\\' || q[1] == quote)) q++;
                buf_ch(&b, *q++);
            }
            next = *q ? strchr(q + 1, ';') : 0;
        } else {
            const char* q = v;
            while (*q && *q != ';') q++;
            size_t vl = (size_t)(q - v);
            while (vl && (v[vl - 1] == ' ' || v[vl - 1] == '\t')) vl--;
            if (*eq == '=') buf_add(&b, v, vl);
            next = *q ? q : 0;
        }
        if (hit) return b.data ? b.data : xstrdup("");
        free(b.data);
        p = next;
    }
    return 0;
}

/* boundary=... from the Content-Type, quoted or bare, as PHP reads it.
   0 if missing or unusable (RFC 2046 caps it at 70; anything over 200 is
   refused rather than searched for in every body). */
static int multipart_boundary(const char* ct, char* out, size_t outsz) {
    const char* b = strcasestr(ct, "boundary");
    if (!b || !(b = strchr(b, '='))) return 0;
    b++;
    size_t n;
    if (*b == '"') {
        b++;
        const char* e = strchr(b, '"');
        if (!e) return 0;
        n = (size_t)(e - b);
    } else {
        n = strcspn(b, ",;");
    }
    if (n == 0 || n > 200 || n + 1 > outsz) return 0;
    memcpy(out, b, n);
    out[n] = 0;
    return 1;
}

/* Parse a multipart/form-data body (RFC 7578) into $_POST and $_FILES.
   Works on lengths, never on C-string functions, because file data is
   binary and NUL bytes are normal in it. Every way the body can be wrong --
   no closing boundary, headers that never end, a part with no name -- stops
   or skips cleanly; the bytes are the visitor's, not ours. */
static void parse_multipart(const char* body, size_t n, const char* boundary, Value* post) {
    char delim[256];
    size_t dl = (size_t)snprintf(delim, sizeof delim, "--%s", boundary);
    char next_delim[260];
    size_t ndl = (size_t)snprintf(next_delim, sizeof next_delim, "\n--%s", boundary);

    long long upload_max = env_size("PHPMINI_UPLOAD_MAX_FILESIZE", 2LL << 20);
    long long max_files = env_size("PHPMINI_MAX_FILE_UPLOADS", 20);
    long long form_max = 0;                  /* the MAX_FILE_SIZE form field */
    long vars_used = 0;
    long long files_seen = 0;
    int warned_files = 0;
    int anon_index = 0;

    const char* end = body + n;
    /* the first boundary sits at the very start or at the start of a line */
    const char* hit = 0;
    for (const char* p = body; p < end; ) {
        const char* m = memmem(p, (size_t)(end - p), delim, dl);
        if (!m) break;
        if (m == body || m[-1] == '\n') { hit = m; break; }
        p = m + 1;
    }

    while (hit) {
        const char* p = hit + dl;
        if (end - p >= 2 && p[0] == '-' && p[1] == '-') break;    /* closing */
        const char* nl = memchr(p, '\n', (size_t)(end - p));
        if (!nl) break;
        p = nl + 1;

        /* part headers, up to the empty line; 16 KB is generous */
        char* disp = 0;
        char* ctype = 0;
        const char* hstart = p;
        int headers_ok = 0;
        int ran_out = 1;                /* stopped because the body ended */
        while (p < end) {
            const char* le = memchr(p, '\n', (size_t)(end - p));
            if (!le) break;
            if (le - hstart > 16384) { ran_out = 0; break; }
            size_t ll = (size_t)(le - p);
            if (ll && p[ll - 1] == '\r') ll--;
            if (ll == 0) { p = le + 1; headers_ok = 1; break; }
            char* line = malloc(ll + 1);
            memcpy(line, p, ll);
            line[ll] = 0;
            if (!strncasecmp(line, "Content-Disposition:", 20)) { free(disp); disp = line; }
            else if (!strncasecmp(line, "Content-Type:", 13)) { free(ctype); ctype = line; }
            else free(line);
            p = le + 1;
        }
        if (!headers_ok) {
            /* Headers that run off the END of the body still describe a
               part -- PHP registers such a file as UPLOAD_ERR_PARTIAL. An
               oversized header block is garbage, and parsing stops. */
            if (!ran_out) { free(disp); free(ctype); break; }
            p = end;
        }

        /* the data runs to the next delimiter line */
        const char* nx = memmem(p, (size_t)(end - p), next_delim, ndl);
        const char* data_end = nx ? nx : end;
        if (nx && data_end > p && data_end[-1] == '\r') data_end--;
        size_t len = (size_t)(data_end - p);

        char* name = disp ? header_param(disp, "name") : 0;
        char* fname = disp ? header_param(disp, "filename") : 0;
        char* type = 0;
        if (ctype) {
            const char* tv = ctype + 13;
            while (*tv == ' ' || *tv == '\t') tv++;
            type = xstrdup(tv);
        }

        if (!name && !fname) {
            /* neither a name nor a filename: PHP calls this garbled and
               stops reading the body here */
            fprintf(stderr, "PHP warning: File Upload Mime headers garbled\n");
            free(type); free(disp); free(ctype);
            break;
        }
        if (!name && fname) {
            /* a file part with no name gets PHP's "anonymous" index */
            char an[32];
            snprintf(an, sizeof an, "%d", anon_index++);
            name = xstrdup(an);
        }

        if (name && *name) {
            if (!fname) {
                if (input_vars_ok(&vars_used, "the form body")) {
                    Value* v = v_str_n(p, len);
                    if (!strcmp(name, "MAX_FILE_SIZE")) form_max = val_to_int(v);
                    register_variable(post, name, v);
                }
            } else if (++files_seen > max_files && max_files > 0) {
                if (!warned_files++)
                    fprintf(stderr, "PHP warning: Maximum number of allowable file uploads "
                                    "has been exceeded\n");
            } else {
                char tmp[1024] = "";
                int err;
                long long size = (long long)len;
                if (!*fname)                                   err = UPLOAD_ERR_NO_FILE;
                else if (!nx)                                  err = UPLOAD_ERR_PARTIAL;
                else if (upload_max > 0 && size > upload_max)  err = UPLOAD_ERR_INI_SIZE;
                else if (form_max > 0 && size > form_max)      err = UPLOAD_ERR_FORM_SIZE;
                else err = store_upload(p, len, tmp, sizeof tmp);
                /* an upload that failed reports no tmp file, size 0 and an
                   empty type -- what the browser claimed is not echoed back
                   for a file that never arrived */
                if (err != UPLOAD_ERR_OK) { tmp[0] = 0; size = 0; }
                register_file(name, fname, err == UPLOAD_ERR_OK && type ? type : "", tmp, err, size);
            }
        }
        free(name);
        free(fname);
        free(type);
        free(disp);
        free(ctype);

        if (!nx) break;                                    /* body ended early */
        hit = nx + 1;                                      /* at "--boundary" */
    }
}

static void read_post_into(Value* dest) {
    const char* cl = getenv("CONTENT_LENGTH");
    long long len = cl ? strtoll(cl, 0, 10) : 0;
    if (len <= 0) return;

    /* post_max_size, PHP's 8 MB default. A body over it is NOT read at all
       and $_POST/$_FILES stay empty -- PHP's behaviour, and the reason the
       limit protects anything: reading it first would already have cost the
       memory. (This replaces the old fixed 2 MB cap.) */
    long long post_max = env_size("PHPMINI_POST_MAX_SIZE", 8LL << 20);
    if (post_max > 0 && len > post_max) {
        fprintf(stderr, "PHP warning: POST Content-Length of %lld bytes exceeds the limit "
                        "of %lld bytes\n", len, post_max);
        return;
    }

    /* Grow the buffer as bytes ARRIVE instead of allocating what the
       Content-Length header claims. The header is the visitor's word: with
       post_max_size set to unlimited, "Content-Length: 1000000000000" used to
       make the process try to allocate a terabyte before reading a byte. Now
       memory follows the data actually received. */
    size_t cap = (size_t)(len < 65536 ? len : 65536) + 1;
    size_t got = 0;
    char* body = malloc(cap);
    while (got < (size_t)len) {
        if (got + 1 >= cap) {
            size_t want = cap * 2;
            if (want > (size_t)len + 1) want = (size_t)len + 1;
            body = realloc(body, want);
            cap = want;
        }
        size_t room = cap - 1 - got;
        size_t chunk = (size_t)len - got < room ? (size_t)len - got : room;
        size_t r = fread(body + got, 1, chunk, stdin);
        if (r == 0) break;                    /* the body ended early */
        got += r;
    }
    body[got] = 0;

    const char* ct = getenv("CONTENT_TYPE");
    if (!ct || strncasecmp(ct, "application/x-www-form-urlencoded", 33) == 0) {
        parse_urlencoded_into(body, dest);
    } else if (strncasecmp(ct, "multipart/form-data", 19) == 0) {
        char boundary[256];
        if (multipart_boundary(ct, boundary, sizeof boundary))
            parse_multipart(body, got, boundary, dest);
        else
            fprintf(stderr, "PHP warning: Missing boundary in multipart/form-data POST data\n");
    }

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
    cleanup_uploads();       /* uploads the script did not move are deleted */
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
    /* Only the soft limit is lowered. The hard one stays, so the error path
       can raise the soft limit to report, and libsodium's Argon2 can be given
       its working memory for one call (PHP does not count that either). A
       script has no way to call setrlimit itself. */
    if (getrlimit(RLIMIT_DATA, &rl) != 0) return;
    rlim_t want = (rlim_t)(base + (size_t)lim);
    if (rl.rlim_max != RLIM_INFINITY && want > rl.rlim_max) want = rl.rlim_max;
    rl.rlim_cur = want;
    if (setrlimit(RLIMIT_DATA, &rl) == 0) mem_limit_bytes = (size_t)lim;
}

static void web_bootstrap(Env* env) {
    V_GET = v_new(T_ARRAY);
    V_POST = v_new(T_ARRAY);
    V_FILES = v_new(T_ARRAY);
    V_COOKIE = v_new(T_ARRAY);
    V_SESSION = v_new(T_ARRAY);
    V_SERVER = v_new(T_ARRAY);
    V_REQUEST = v_new(T_ARRAY);

    env_set(env, "_GET", V_GET);
    env_set(env, "_POST", V_POST);
    env_set(env, "_FILES", V_FILES);
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
            emitf("string(%zu) \"", slen(v));
            emit_bytes(v->s, slen(v));
            emit_string("\"\n");
            break;
        case T_ARRAY:
            emitf("array(%d) {\n", array_count(v));
            for (ArrayItem* it = v->items; it; it = it->next) {
                emit_indent(d + 1);
                if (it->key && it->key->type == T_INT) emitf("[%lld]=>\n", it->key->i);
                else {
                    emit_string("[\"");
                    emit_bytes(it->key ? it->key->s : "", it->key ? slen(it->key) : 0);
                    emit_string("\"]=>\n");
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
            size_t kn;
            char* ks = val_bin(it->key, &kn);
            pr_pad(b, level * 8 + 4);
            buf_ch(b, '[');
            buf_add(b, ks, kn);
            buf_addz(b, "] => ");
            free(ks);
            pr_render(b, it->val, level + 1);
            buf_ch(b, '\n');
        }
        pr_pad(b, level * 8);
        buf_addz(b, ")\n");
    } else {
        size_t sn;
        char* sv = val_bin(v, &sn);
        buf_add(b, sv, sn);
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
    v->n = n;
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
static Value* replace_one(const char* in, size_t inl, const char* from, size_t fl,
                          const char* to, size_t tl) {
    if (!fl) return v_str_n(in, inl);
    Buf b;
    buf_init(&b);
    size_t p = 0;
    for (;;) {
        const char* hit = memmem(in + p, inl - p, from, fl);
        if (!hit) { buf_add(&b, in + p, inl - p); break; }
        buf_add(&b, in + p, (size_t)(hit - (in + p)));
        buf_add(&b, to, tl);
        p = (size_t)(hit - in) + fl;
    }
    size_t n = b.len;
    return v_str_own(b.data ? b.data : xstrdup(""), n);
}

/* str_replace for one subject. search/replace follow PHP: a string search
   uses the string replacement; an array of searches is applied in order,
   each with the matching replacement (or "" when the replacement array runs
   out, or the one string when replace is a string). An empty search string
   replaces nothing. Byte strings throughout. */
static Value* str_replace_all(Value* subject, Value* search, Value* repl) {
    size_t inl;
    char* in = val_bin(subject, &inl);

    if (search->type != T_ARRAY) {
        size_t fl, tl;
        char* from = val_bin(search, &fl);
        char* to = repl->type == T_ARRAY ? xstrdup("Array") : val_bin(repl, &tl);
        if (repl->type == T_ARRAY) tl = 5;
        Value* out = replace_one(in, inl, from, fl, to, tl);
        free(in);
        free(from);
        free(to);
        return out;
    }

    Value* cur = v_str_own(in, inl);
    ArrayItem* r = repl->type == T_ARRAY ? repl->items : 0;
    for (ArrayItem* it = search->items; it; it = it->next) {
        size_t fl, tl;
        char* from = val_bin(it->val, &fl);
        char* to;
        if (repl->type == T_ARRAY) {
            if (r) { to = val_bin(r->val, &tl); r = r->next; } else { to = xstrdup(""); tl = 0; }
        } else {
            to = val_bin(repl, &tl);
        }
        cur = replace_one(cur->s, slen(cur), from, fl, to, tl);
        free(from);
        free(to);
    }
    return cur;
}

#ifndef MINIPHP_NO_SQLITE
/* ---------- SQLite (milestone 5) ----------
   miniPHP has no objects, so this is not PDO or the SQLite3 class: it is a
   small set of functions over the same library.

     $db   = sqlite_open("app.db");
     $rows = sqlite_query($db, "SELECT * FROM users WHERE id = ?", [$id]);
     $n    = sqlite_exec($db, "UPDATE users SET name = :n WHERE id = :id",
                         ["n" => $name, "id" => $id]);

   Values go in through BOUND parameters (? or :name), never by pasting them
   into the SQL text, so SQL injection is closed by default. Rows come back
   as arrays keyed by column name, with SQLite's own types: INTEGER -> int,
   REAL -> float, TEXT/BLOB -> string, NULL -> null -- the same mapping as
   PHP's SQLite3::fetchArray(SQLITE3_ASSOC). Any failure returns false,
   warns, and leaves the message for sqlite_error(). */

#define MAX_SQLITE_HANDLES 64
static sqlite3* sq_db[MAX_SQLITE_HANDLES];
static int sq_count = 0;                 /* handles are never reused in a request */

static void sqlite_close_all(void) {
    for (int i = 0; i < sq_count; i++)
        if (sq_db[i]) { sqlite3_close_v2(sq_db[i]); sq_db[i] = 0; }
}

static sqlite3* sq_handle(Value* v, const char* fn) {
    long long h = v ? val_to_int(v) : 0;
    if (h < 1 || h > sq_count || !sq_db[h - 1]) {
        fprintf(stderr, "PHP warning: %s(): not an open SQLite handle\n", fn);
        return 0;
    }
    return sq_db[h - 1];
}

/* Bind an array of parameters: a plain list binds ?1, ?2 ... in order; string
   keys bind by name, with or without the leading ":" / "@" / "$". The count
   must match the statement -- a missing value is a bug in the calling code,
   not something to fill in with NULL behind its back. */
static int sq_bind(sqlite3* db, sqlite3_stmt* st, Value* params, const char* fn) {
    int want = sqlite3_bind_parameter_count(st);
    int given = (params && params->type == T_ARRAY) ? array_count(params) : 0;
    if (given != want) {
        fprintf(stderr, "PHP warning: %s(): the statement has %d parameter(s), %d given\n", fn, want, given);
        return 0;
    }
    if (!given) return 1;

    int pos = 0;
    for (ArrayItem* it = params->items; it; it = it->next) {
        int idx;
        if (it->key->type == T_INT) {
            idx = ++pos;
        } else {
            const char* k = it->key->s ? it->key->s : "";
            idx = 0;
            if (k[0] == ':' || k[0] == '@' || k[0] == '$') idx = sqlite3_bind_parameter_index(st, k);
            else {
                char nm[512];
                const char* pre = ":@$";
                for (int p = 0; p < 3 && !idx; p++) {
                    snprintf(nm, sizeof nm, "%c%s", pre[p], k);
                    idx = sqlite3_bind_parameter_index(st, nm);
                }
            }
            if (!idx) {
                fprintf(stderr, "PHP warning: %s(): the statement has no parameter named \"%s\"\n", fn, k);
                return 0;
            }
        }

        Value* v = it->val;
        int rc;
        if (!v || v->type == T_NULL)  rc = sqlite3_bind_null(st, idx);
        else if (v->type == T_INT)    rc = sqlite3_bind_int64(st, idx, v->i);
        else if (v->type == T_BOOL)   rc = sqlite3_bind_int64(st, idx, v->b ? 1 : 0);
        else if (v->type == T_FLOAT)  rc = sqlite3_bind_double(st, idx, v->d);
        else if (v->type == T_STRING) rc = sqlite3_bind_text(st, idx, v->s ? v->s : "", (int)slen(v), SQLITE_TRANSIENT);
        else {
            fprintf(stderr, "PHP warning: %s(): an array cannot be bound as a parameter\n", fn);
            return 0;
        }
        if (rc != SQLITE_OK) {
            fprintf(stderr, "PHP warning: %s(): %s\n", fn, sqlite3_errmsg(db));
            return 0;
        }
    }
    return 1;
}

/* Prepare exactly ONE statement. Text after it (other than whitespace and
   comments) is refused rather than silently ignored: "SELECT ...; DROP ..."
   either runs both or neither, and quietly running half of what was asked
   is the worse of the two. sqlite_exec() without parameters is the place
   for a multi-statement script. */
static sqlite3_stmt* sq_prepare(sqlite3* db, const char* sql, const char* fn) {
    sqlite3_stmt* st = 0;
    const char* tail = 0;
    if (sqlite3_prepare_v2(db, sql, -1, &st, &tail) != SQLITE_OK) {
        fprintf(stderr, "PHP warning: %s(): Unable to prepare statement: %s\n", fn, sqlite3_errmsg(db));
        return 0;
    }
    if (!st) {
        fprintf(stderr, "PHP warning: %s(): the SQL is empty\n", fn);
        return 0;
    }
    if (tail && *tail) {
        sqlite3_stmt* more = 0;
        const char* t2 = 0;
        if (sqlite3_prepare_v2(db, tail, -1, &more, &t2) == SQLITE_OK && more) {
            sqlite3_finalize(more);
            sqlite3_finalize(st);
            fprintf(stderr, "PHP warning: %s(): only one statement is allowed here; "
                            "use sqlite_exec() without parameters for a script\n", fn);
            return 0;
        }
        if (more) sqlite3_finalize(more);
    }
    return st;
}

static Value* sq_column(sqlite3_stmt* st, int c) {
    switch (sqlite3_column_type(st, c)) {
        case SQLITE_INTEGER: return v_int(sqlite3_column_int64(st, c));
        case SQLITE_FLOAT:   return v_float(sqlite3_column_double(st, c));
        case SQLITE_NULL:    return v_null();
        default: {
            const void* p = sqlite3_column_blob(st, c);
            int n = sqlite3_column_bytes(st, c);
            return v_str_n(p ? (const char*)p : "", (size_t)(n > 0 ? n : 0));
        }
    }
}

static Value* sqlite_builtin(const char* name, Value** args, int argc, int* handled) {
    *handled = 1;
#define SQNEED(n) do { if (argc < (n)) fatal("%s expects at least %d argument(s)", name, n); } while (0)

    if (!strcmp(name, "sqlite_open")) {
        SQNEED(1);
        if (has_nul(args[0]))
            fatal("Uncaught ValueError: sqlite_open(): Argument #1 ($filename) must not contain any null bytes");
        if (sq_count >= MAX_SQLITE_HANDLES) {
            fprintf(stderr, "PHP warning: sqlite_open(): too many databases opened in one request\n");
            return v_bool(0);
        }
        char* path = val_to_string(args[0]);
        sqlite3* db = 0;
        int rc = sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, 0);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "PHP warning: sqlite_open(%s): %s\n", path, db ? sqlite3_errmsg(db) : sqlite3_errstr(rc));
            if (db) sqlite3_close_v2(db);
            free(path);
            return v_bool(0);
        }
        free(path);
        /* Several web requests can write at once: wait up to 5 s for a lock
           instead of failing at once with "database is locked". */
        sqlite3_busy_timeout(db, 5000);
        /* SQL cannot corrupt the database file itself (writable_schema and
           friends are refused) -- harmless for normal use. */
        sqlite3_db_config(db, SQLITE_DBCONFIG_DEFENSIVE, 1, (int*)0);
        if (!sq_count) atexit(sqlite_close_all);
        sq_db[sq_count++] = db;
        return v_int(sq_count);
    }

    if (!strcmp(name, "sqlite_close")) {
        SQNEED(1);
        sqlite3* db = sq_handle(args[0], name);
        if (!db) return v_bool(0);
        sqlite3_close_v2(db);
        sq_db[val_to_int(args[0]) - 1] = 0;
        return v_bool(1);
    }

    if (!strcmp(name, "sqlite_query") || !strcmp(name, "sqlite_exec")) {
        SQNEED(2);
        int is_query = name[7] == 'q';
        sqlite3* db = sq_handle(args[0], name);
        if (!db) return v_bool(0);
        char* sql = val_to_string(args[1]);
        Value* params = argc > 2 ? args[2] : 0;
        if (params && params->type != T_ARRAY && params->type != T_NULL) {
            fprintf(stderr, "PHP warning: %s(): parameters must be an array\n", name);
            free(sql);
            return v_bool(0);
        }

        /* sqlite_exec with no parameters: a whole script, several statements */
        if (!is_query && (!params || params->type == T_NULL || !array_count(params))) {
            char* err = 0;
            int rc = sqlite3_exec(db, sql, 0, 0, &err);
            free(sql);
            if (rc != SQLITE_OK) {
                fprintf(stderr, "PHP warning: sqlite_exec(): %s\n", err ? err : sqlite3_errmsg(db));
                sqlite3_free(err);
                return v_bool(0);
            }
            return v_int(sqlite3_changes(db));
        }

        sqlite3_stmt* st = sq_prepare(db, sql, name);
        free(sql);
        if (!st) return v_bool(0);
        if (!sq_bind(db, st, params, name)) { sqlite3_finalize(st); return v_bool(0); }

        ArrBuild rows;
        ab_init(&rows);
        int cols = sqlite3_column_count(st);
        int rc;
        while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
            if (!is_query) continue;
            Value* row = v_new(T_ARRAY);
            for (int c = 0; c < cols; c++) {
                const char* cn = sqlite3_column_name(st, c);
                /* a repeated column name keeps the LAST value, as PHP does */
                array_put(row, normalize_key(v_str(cn ? cn : "")), sq_column(st, c));
            }
            ab_push(&rows, row);
        }
        if (rc != SQLITE_DONE) {
            fprintf(stderr, "PHP warning: %s(): %s\n", name, sqlite3_errmsg(db));
            sqlite3_finalize(st);
            return v_bool(0);
        }
        sqlite3_finalize(st);
        return is_query ? rows.arr : v_int(sqlite3_changes(db));
    }

    if (!strcmp(name, "sqlite_last_insert_id")) {
        SQNEED(1);
        sqlite3* db = sq_handle(args[0], name);
        return db ? v_int(sqlite3_last_insert_rowid(db)) : v_bool(0);
    }

    if (!strcmp(name, "sqlite_changes")) {
        SQNEED(1);
        sqlite3* db = sq_handle(args[0], name);
        return db ? v_int(sqlite3_changes(db)) : v_bool(0);
    }

    if (!strcmp(name, "sqlite_error")) {
        SQNEED(1);
        sqlite3* db = sq_handle(args[0], name);
        return v_str(db ? sqlite3_errmsg(db) : "not an open SQLite handle");
    }

#undef SQNEED
    *handled = 0;
    return 0;
}
#endif

#ifdef MINIPHP_SODIUM
/* ---------- libsodium (make SODIUM=1) ----------
   PHP's sodium extension, function for function: same names, arguments,
   return values and errors, checked byte for byte against PHP 8.3's own
   ext/sodium. Where PHP throws SodiumException the call is a fatal error
   with PHP's message, as elsewhere in this file (no exceptions here).

   Key pairs are concatenations, as in PHP: box and kx key pairs are
   secret(32) . public(32); a sign key pair is secret(64) . public(32). */

typedef struct { const char* fn; Value** a; int c; } Sod;

static void sod_throw(const char* msg) {
    fatal("Uncaught SodiumException: %s", msg);
}

static void sod_argerr(Sod* k, int i, const char* pname, const char* msg) {
    fatal("Uncaught SodiumException: %s(): Argument #%d ($%s) %s", k->fn, i, pname, msg);
}

/* PHP's ArgumentCountError wording */
static void sod_argc(Sod* k, int min, int max) {
    if (k->c >= min && k->c <= max) return;
    const char* how = min == max ? "exactly" : k->c < min ? "at least" : "at most";
    int n = k->c < min ? min : max;
    fatal("Uncaught ArgumentCountError: %s() expects %s %d argument%s, %d given",
          k->fn, how, n, n == 1 ? "" : "s", k->c);
}

/* String argument i (1-based) as bytes, malloc'd with a terminating zero.
   A missing optional one is "". Numbers convert as in PHP; an array is
   PHP's TypeError. */
static unsigned char* sod_str(Sod* k, int i, const char* pname, size_t* n) {
    if (i > k->c) { *n = 0; return (unsigned char*)xstrdup(""); }
    Value* v = k->a[i - 1];
    if (v && v->type == T_ARRAY)
        fatal("Uncaught TypeError: %s(): Argument #%d ($%s) must be of type string, array given",
              k->fn, i, pname);
    return (unsigned char*)val_bin(v, n);
}

static long long sod_int(Sod* k, int i, const char* pname, long long def) {
    if (i > k->c) return def;
    Value* v = k->a[i - 1];
    if (v && v->type == T_ARRAY)
        fatal("Uncaught TypeError: %s(): Argument #%d ($%s) must be of type int, array given",
              k->fn, i, pname);
    /* not a number, or one too big for an int: PHP's TypeError */
    double d = v && v->type == T_FLOAT ? v->d
             : v && v->type == T_STRING && val_is_numeric(v) ? strtod(v->s, 0) : 0;
    if ((v && v->type == T_STRING && !val_is_numeric(v)) ||
        !(d >= -9223372036854775808.0 && d < 9223372036854775808.0))
        fatal("Uncaught TypeError: %s(): Argument #%d ($%s) must be of type int, %s given",
              k->fn, i, pname, v->type == T_FLOAT ? "float" : "string");
    return val_to_int(v);
}

/* "must be SODIUM_CRYPTO_..._KEYBYTES bytes long" */
static void sod_len(Sod* k, int i, const char* pname, size_t got, size_t want, const char* cname) {
    if (got == want) return;
    char m[160];
    snprintf(m, sizeof m, "must be %s bytes long", cname);
    sod_argerr(k, i, pname, m);
}

/* Inputs often hold keys: wipe before freeing */
static void sod_free(unsigned char* p, size_t n) {
    if (!p) return;
    sodium_memzero(p, n);
    free(p);
}

static unsigned char* sod_buf(size_t n) {
    unsigned char* p = malloc(n + 1);
    p[n] = 0;
    return p;
}

static Value* sod_ret(unsigned char* p, size_t n) {
    p[n] = 0;
    return v_str_own((char*)p, n);
}

/* A by-reference string argument (&$state): the caller's own variable,
   since builtins receive the stored value. Replaced in place. */
static Value* sod_ref(Sod* k, int i) {
    return i <= k->c ? k->a[i - 1] : 0;
}

static void sod_set(Value* v, const unsigned char* p, size_t n) {
    if (v->type == T_STRING && v->s) { sodium_memzero(v->s, slen(v)); free(v->s); }
    v->type = T_STRING;
    v->s = (char*)sod_buf(n);
    memcpy(v->s, p, n);
    v->n = n;
}

static void sod_null(Value* v) {
    if (v->type == T_STRING && v->s) { sodium_memzero(v->s, slen(v)); free(v->s); }
    v->type = T_NULL;
    v->s = 0;
    v->n = SIZE_MAX;
}

static Value* sod_pair(Value* x, Value* y) {
    Value* arr = v_new(T_ARRAY);
    array_put(arr, v_int(0), x);
    array_put(arr, v_int(1), y);
    return arr;
}

/* Argon2 works in its own memory (64 MB at "interactive", 1 GB at
   "sensitive"), which PHP does not count against memory_limit. Lift the
   limit by exactly that much for the call, then put it back. */
static void sod_lift_limit(size_t extra, struct rlimit* saved) {
    getrlimit(RLIMIT_DATA, saved);
    if (saved->rlim_cur == RLIM_INFINITY) return;
    struct rlimit r = *saved;
    r.rlim_cur = saved->rlim_cur + extra;
    if (r.rlim_max != RLIM_INFINITY && r.rlim_cur > r.rlim_max) r.rlim_cur = r.rlim_max;
    setrlimit(RLIMIT_DATA, &r);
}

static void sod_restore_limit(struct rlimit* saved) {
    if (saved->rlim_cur != RLIM_INFINITY) setrlimit(RLIMIT_DATA, saved);
}

/* sodium_*_keygen(): every one is random bytes of the key size */
static const struct { const char* name; size_t len; } sod_keygens[] = {
    { "sodium_crypto_aead_aes256gcm_keygen",                 crypto_aead_aes256gcm_KEYBYTES },
    { "sodium_crypto_aead_chacha20poly1305_keygen",          crypto_aead_chacha20poly1305_KEYBYTES },
    { "sodium_crypto_aead_chacha20poly1305_ietf_keygen",     crypto_aead_chacha20poly1305_ietf_KEYBYTES },
    { "sodium_crypto_aead_xchacha20poly1305_ietf_keygen",    crypto_aead_xchacha20poly1305_ietf_KEYBYTES },
    { "sodium_crypto_auth_keygen",                           crypto_auth_KEYBYTES },
    { "sodium_crypto_generichash_keygen",                    crypto_generichash_KEYBYTES },
    { "sodium_crypto_kdf_keygen",                            crypto_kdf_KEYBYTES },
    { "sodium_crypto_secretbox_keygen",                      crypto_secretbox_KEYBYTES },
    { "sodium_crypto_shorthash_keygen",                      crypto_shorthash_KEYBYTES },
    { "sodium_crypto_stream_keygen",                         crypto_stream_KEYBYTES },
    { "sodium_crypto_stream_xchacha20_keygen",               crypto_stream_xchacha20_KEYBYTES },
    { "sodium_crypto_secretstream_xchacha20poly1305_keygen", crypto_secretstream_xchacha20poly1305_KEYBYTES },
};

/* The three ChaCha20-Poly1305 AEAD flavours share one shape */
typedef int (*sod_aead_enc)(unsigned char*, unsigned long long*, const unsigned char*, unsigned long long,
                            const unsigned char*, unsigned long long, const unsigned char*,
                            const unsigned char*, const unsigned char*);
typedef int (*sod_aead_dec)(unsigned char*, unsigned long long*, unsigned char*, const unsigned char*,
                            unsigned long long, const unsigned char*, unsigned long long,
                            const unsigned char*, const unsigned char*);
static const struct {
    const char* name;       /* after "sodium_crypto_aead_" */
    sod_aead_enc enc;
    sod_aead_dec dec;
    size_t npub, key, abytes;
    const char *npub_c, *key_c;
    int ietf_limit;         /* 64 * 2^32 - 64 bytes per message */
} sod_aeads[] = {
    { "chacha20poly1305", crypto_aead_chacha20poly1305_encrypt, crypto_aead_chacha20poly1305_decrypt,
      crypto_aead_chacha20poly1305_NPUBBYTES, crypto_aead_chacha20poly1305_KEYBYTES,
      crypto_aead_chacha20poly1305_ABYTES,
      "SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES", "SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES", 0 },
    { "chacha20poly1305_ietf", crypto_aead_chacha20poly1305_ietf_encrypt, crypto_aead_chacha20poly1305_ietf_decrypt,
      crypto_aead_chacha20poly1305_ietf_NPUBBYTES, crypto_aead_chacha20poly1305_ietf_KEYBYTES,
      crypto_aead_chacha20poly1305_ietf_ABYTES,
      "SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES", "SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES", 1 },
    { "xchacha20poly1305_ietf", crypto_aead_xchacha20poly1305_ietf_encrypt, crypto_aead_xchacha20poly1305_ietf_decrypt,
      crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
      crypto_aead_xchacha20poly1305_ietf_ABYTES,
      "SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES", "SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES", 0 },
};

static Value* sodium_builtin(const char* name, Value** args, int argc, int* handled) {
    Sod K = { name, args, argc }, *k = &K;
    *handled = 1;
    size_t n1, n2, n3, n4;
    unsigned char *s1, *s2, *s3, *s4, *out;

    for (size_t i = 0; i < sizeof sod_keygens / sizeof sod_keygens[0]; i++) {
        if (strcmp(name, sod_keygens[i].name)) continue;
        sod_argc(k, 0, 0);
        out = sod_buf(sod_keygens[i].len);
        randombytes_buf(out, sod_keygens[i].len);
        return sod_ret(out, sod_keygens[i].len);
    }

    if (!strncmp(name, "sodium_crypto_aead_", 19)) {
        const char* rest = name + 19;
        if (!strcmp(rest, "aes256gcm_is_available")) {
            sod_argc(k, 0, 0);
            return v_bool(0);   /* the portable build has no AES-NI code path */
        }
        for (size_t i = 0; i < sizeof sod_aeads / sizeof sod_aeads[0]; i++) {
            size_t bl = strlen(sod_aeads[i].name);
            if (strncmp(rest, sod_aeads[i].name, bl)) continue;
            int enc = !strcmp(rest + bl, "_encrypt");
            if (!enc && strcmp(rest + bl, "_decrypt")) continue;
            sod_argc(k, 4, 4);
            s1 = sod_str(k, 1, enc ? "message" : "ciphertext", &n1);
            s2 = sod_str(k, 2, "additional_data", &n2);
            s3 = sod_str(k, 3, "nonce", &n3);
            s4 = sod_str(k, 4, "key", &n4);
            sod_len(k, 3, "nonce", n3, sod_aeads[i].npub, sod_aeads[i].npub_c);
            sod_len(k, 4, "key", n4, sod_aeads[i].key, sod_aeads[i].key_c);
            Value* r;
            unsigned long long rl = 0;
            if (enc) {
                if ((unsigned long long)n1 > 64ULL * (1ULL << 32) - 64ULL && sod_aeads[i].ietf_limit)
                    sod_throw("message too long for a single key");
                out = sod_buf(n1 + sod_aeads[i].abytes);
                if (sod_aeads[i].enc(out, &rl, s1, n1, s2, n2, 0, s3, s4) != 0) sod_throw("internal error");
                r = sod_ret(out, (size_t)rl);
            } else if (n1 < sod_aeads[i].abytes) {
                r = v_bool(0);
            } else {
                out = sod_buf(n1 - sod_aeads[i].abytes);
                if (sod_aeads[i].dec(out, &rl, 0, s1, n1, s2, n2, s3, s4) != 0) { free(out); r = v_bool(0); }
                else r = sod_ret(out, (size_t)rl);
            }
            sod_free(s1, n1); sod_free(s2, n2); sod_free(s3, n3); sod_free(s4, n4);
            return r;
        }
        *handled = 0;
        return 0;
    }

    /* ---- secretbox: XSalsa20-Poly1305 ---- */

    if (!strcmp(name, "sodium_crypto_secretbox") || !strcmp(name, "sodium_crypto_secretbox_open")) {
        int open = name[23] == '_';
        sod_argc(k, 3, 3);
        s1 = sod_str(k, 1, open ? "ciphertext" : "message", &n1);
        s2 = sod_str(k, 2, "nonce", &n2);
        s3 = sod_str(k, 3, "key", &n3);
        sod_len(k, 2, "nonce", n2, crypto_secretbox_NONCEBYTES, "SODIUM_CRYPTO_SECRETBOX_NONCEBYTES");
        sod_len(k, 3, "key", n3, crypto_secretbox_KEYBYTES, "SODIUM_CRYPTO_SECRETBOX_KEYBYTES");
        Value* r;
        if (!open) {
            out = sod_buf(n1 + crypto_secretbox_MACBYTES);
            if (crypto_secretbox_easy(out, s1, n1, s2, s3) != 0) sod_throw("internal error");
            r = sod_ret(out, n1 + crypto_secretbox_MACBYTES);
        } else if (n1 < crypto_secretbox_MACBYTES) {
            r = v_bool(0);
        } else {
            out = sod_buf(n1 - crypto_secretbox_MACBYTES);
            if (crypto_secretbox_open_easy(out, s1, n1, s2, s3) != 0) { free(out); r = v_bool(0); }
            else r = sod_ret(out, n1 - crypto_secretbox_MACBYTES);
        }
        sod_free(s1, n1); sod_free(s2, n2); sod_free(s3, n3);
        return r;
    }

    /* ---- box: X25519 + XSalsa20-Poly1305 ---- */

    if (!strcmp(name, "sodium_crypto_box_keypair") || !strcmp(name, "sodium_crypto_kx_keypair")) {
        sod_argc(k, 0, 0);
        out = sod_buf(64);
        if (name[14] == 'b' ? crypto_box_keypair(out + 32, out) : crypto_kx_keypair(out + 32, out))
            sod_throw("internal error");
        return sod_ret(out, 64);
    }

    if (!strcmp(name, "sodium_crypto_box_seed_keypair") || !strcmp(name, "sodium_crypto_kx_seed_keypair")) {
        int box = name[14] == 'b';
        sod_argc(k, 1, 1);
        s1 = sod_str(k, 1, "seed", &n1);
        sod_len(k, 1, "seed", n1, 32, box ? "SODIUM_CRYPTO_BOX_SEEDBYTES" : "SODIUM_CRYPTO_KX_SEEDBYTES");
        out = sod_buf(64);
        if (box ? crypto_box_seed_keypair(out + 32, out, s1) : crypto_kx_seed_keypair(out + 32, out, s1))
            sod_throw("internal error");
        sod_free(s1, n1);
        return sod_ret(out, 64);
    }

    if (!strcmp(name, "sodium_crypto_box_keypair_from_secretkey_and_publickey")) {
        sod_argc(k, 2, 2);
        s1 = sod_str(k, 1, "secret_key", &n1);
        s2 = sod_str(k, 2, "public_key", &n2);
        sod_len(k, 1, "secret_key", n1, crypto_box_SECRETKEYBYTES, "SODIUM_CRYPTO_BOX_SECRETKEYBYTES");
        sod_len(k, 2, "public_key", n2, crypto_box_PUBLICKEYBYTES, "SODIUM_CRYPTO_BOX_PUBLICKEYBYTES");
        out = sod_buf(64);
        memcpy(out, s1, 32);
        memcpy(out + 32, s2, 32);
        sod_free(s1, n1); sod_free(s2, n2);
        return sod_ret(out, 64);
    }

    /* the halves of a 64-byte box or kx key pair */
    if (!strcmp(name, "sodium_crypto_box_secretkey") || !strcmp(name, "sodium_crypto_box_publickey") ||
        !strcmp(name, "sodium_crypto_kx_secretkey") || !strcmp(name, "sodium_crypto_kx_publickey")) {
        int box = name[14] == 'b', pub = strstr(name, "publickey") != 0;
        sod_argc(k, 1, 1);
        s1 = sod_str(k, 1, "key_pair", &n1);
        sod_len(k, 1, "key_pair", n1, 64, box ? "SODIUM_CRYPTO_BOX_KEYPAIRBYTES" : "SODIUM_CRYPTO_KX_KEYPAIRBYTES");
        out = sod_buf(32);
        memcpy(out, s1 + (pub ? 32 : 0), 32);
        sod_free(s1, n1);
        return sod_ret(out, 32);
    }

    if (!strcmp(name, "sodium_crypto_box_publickey_from_secretkey") ||
        !strcmp(name, "sodium_crypto_scalarmult_base")) {
        sod_argc(k, 1, 1);
        s1 = sod_str(k, 1, "secret_key", &n1);
        /* sic: PHP names the box constant for scalarmult_base too */
        sod_len(k, 1, "secret_key", n1, 32, "SODIUM_CRYPTO_BOX_SECRETKEYBYTES");
        out = sod_buf(32);
        crypto_scalarmult_base(out, s1);
        sod_free(s1, n1);
        return sod_ret(out, 32);
    }

    if (!strcmp(name, "sodium_crypto_box") || !strcmp(name, "sodium_crypto_box_open")) {
        int open = name[17] == '_';
        sod_argc(k, 3, 3);
        s1 = sod_str(k, 1, open ? "ciphertext" : "message", &n1);
        s2 = sod_str(k, 2, "nonce", &n2);
        s3 = sod_str(k, 3, "key_pair", &n3);
        sod_len(k, 2, "nonce", n2, crypto_box_NONCEBYTES, "SODIUM_CRYPTO_BOX_NONCEBYTES");
        sod_len(k, 3, "key_pair", n3, 64, "SODIUM_CRYPTO_BOX_KEYPAIRBYTES");
        Value* r;
        if (!open) {
            out = sod_buf(n1 + crypto_box_MACBYTES);
            if (crypto_box_easy(out, s1, n1, s2, s3 + 32, s3) != 0) sod_throw("internal error");
            r = sod_ret(out, n1 + crypto_box_MACBYTES);
        } else if (n1 < crypto_box_MACBYTES) {
            r = v_bool(0);
        } else {
            out = sod_buf(n1 - crypto_box_MACBYTES);
            if (crypto_box_open_easy(out, s1, n1, s2, s3 + 32, s3) != 0) { free(out); r = v_bool(0); }
            else r = sod_ret(out, n1 - crypto_box_MACBYTES);
        }
        sod_free(s1, n1); sod_free(s2, n2); sod_free(s3, n3);
        return r;
    }

    if (!strcmp(name, "sodium_crypto_box_seal")) {
        sod_argc(k, 2, 2);
        s1 = sod_str(k, 1, "message", &n1);
        s2 = sod_str(k, 2, "public_key", &n2);
        sod_len(k, 2, "public_key", n2, crypto_box_PUBLICKEYBYTES, "SODIUM_CRYPTO_BOX_PUBLICKEYBYTES");
        out = sod_buf(n1 + crypto_box_SEALBYTES);
        if (crypto_box_seal(out, s1, n1, s2) != 0) sod_throw("internal error");
        sod_free(s1, n1); sod_free(s2, n2);
        return sod_ret(out, n1 + crypto_box_SEALBYTES);
    }

    if (!strcmp(name, "sodium_crypto_box_seal_open")) {
        sod_argc(k, 2, 2);
        s1 = sod_str(k, 1, "ciphertext", &n1);
        s2 = sod_str(k, 2, "key_pair", &n2);
        sod_len(k, 2, "key_pair", n2, 64, "SODIUM_CRYPTO_BOX_KEYPAIRBYTES");
        Value* r;
        if (n1 < crypto_box_SEALBYTES) r = v_bool(0);
        else {
            out = sod_buf(n1 - crypto_box_SEALBYTES);
            if (crypto_box_seal_open(out, s1, n1, s2 + 32, s2) != 0) { free(out); r = v_bool(0); }
            else r = sod_ret(out, n1 - crypto_box_SEALBYTES);
        }
        sod_free(s1, n1); sod_free(s2, n2);
        return r;
    }

    if (!strcmp(name, "sodium_crypto_scalarmult")) {
        sod_argc(k, 2, 2);
        s1 = sod_str(k, 1, "n", &n1);
        s2 = sod_str(k, 2, "p", &n2);
        sod_len(k, 1, "n", n1, crypto_scalarmult_SCALARBYTES, "SODIUM_CRYPTO_SCALARMULT_SCALARBYTES");
        /* sic: PHP names the scalar size for the point too */
        sod_len(k, 2, "p", n2, crypto_scalarmult_BYTES, "SODIUM_CRYPTO_SCALARMULT_SCALARBYTES");
        out = sod_buf(crypto_scalarmult_BYTES);
        if (crypto_scalarmult(out, s1, s2) != 0) sod_throw("internal error");
        sod_free(s1, n1); sod_free(s2, n2);
        return sod_ret(out, crypto_scalarmult_BYTES);
    }

    /* ---- kx: session keys from X25519 ---- */

    if (!strcmp(name, "sodium_crypto_kx_client_session_keys") ||
        !strcmp(name, "sodium_crypto_kx_server_session_keys")) {
        int client = name[17] == 'c';
        sod_argc(k, 2, 2);
        s1 = sod_str(k, 1, client ? "client_key_pair" : "server_key_pair", &n1);
        s2 = sod_str(k, 2, client ? "server_key" : "client_key", &n2);
        sod_len(k, 1, client ? "client_key_pair" : "server_key_pair", n1, 64, "SODIUM_CRYPTO_KX_KEYPAIRBYTES");
        sod_len(k, 2, client ? "server_key" : "client_key", n2, 32, "SODIUM_CRYPTO_KX_PUBLICKEYBYTES");
        unsigned char* rx = sod_buf(32);
        unsigned char* tx = sod_buf(32);
        if ((client ? crypto_kx_client_session_keys : crypto_kx_server_session_keys)(rx, tx, s1 + 32, s1, s2) != 0)
            sod_throw("internal error");
        sod_free(s1, n1); sod_free(s2, n2);
        return sod_pair(sod_ret(rx, 32), sod_ret(tx, 32));
    }

    /* ---- sign: Ed25519 ---- */

    if (!strcmp(name, "sodium_crypto_sign_keypair")) {
        sod_argc(k, 0, 0);
        out = sod_buf(96);
        if (crypto_sign_keypair(out + 64, out) != 0) sod_throw("internal error");
        return sod_ret(out, 96);
    }

    if (!strcmp(name, "sodium_crypto_sign_seed_keypair")) {
        sod_argc(k, 1, 1);
        s1 = sod_str(k, 1, "seed", &n1);
        sod_len(k, 1, "seed", n1, crypto_sign_SEEDBYTES, "SODIUM_CRYPTO_SIGN_SEEDBYTES");
        out = sod_buf(96);
        if (crypto_sign_seed_keypair(out + 64, out, s1) != 0) sod_throw("internal error");
        sod_free(s1, n1);
        return sod_ret(out, 96);
    }

    if (!strcmp(name, "sodium_crypto_sign_keypair_from_secretkey_and_publickey")) {
        sod_argc(k, 2, 2);
        s1 = sod_str(k, 1, "secret_key", &n1);
        s2 = sod_str(k, 2, "public_key", &n2);
        sod_len(k, 1, "secret_key", n1, crypto_sign_SECRETKEYBYTES, "SODIUM_CRYPTO_SIGN_SECRETKEYBYTES");
        sod_len(k, 2, "public_key", n2, crypto_sign_PUBLICKEYBYTES, "SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES");
        out = sod_buf(96);
        memcpy(out, s1, 64);
        memcpy(out + 64, s2, 32);
        sod_free(s1, n1); sod_free(s2, n2);
        return sod_ret(out, 96);
    }

    if (!strcmp(name, "sodium_crypto_sign_secretkey") || !strcmp(name, "sodium_crypto_sign_publickey")) {
        int pub = name[19] == 'p';
        sod_argc(k, 1, 1);
        s1 = sod_str(k, 1, "key_pair", &n1);
        sod_len(k, 1, "key_pair", n1, 96, "SODIUM_CRYPTO_SIGN_KEYPAIRBYTES");
        size_t len = pub ? 32 : 64;
        out = sod_buf(len);
        memcpy(out, s1 + (pub ? 64 : 0), len);
        sod_free(s1, n1);
        return sod_ret(out, len);
    }

    if (!strcmp(name, "sodium_crypto_sign_publickey_from_secretkey") ||
        !strcmp(name, "sodium_crypto_sign_ed25519_sk_to_curve25519")) {
        int conv = name[19] == 'e';
        sod_argc(k, 1, 1);
        s1 = sod_str(k, 1, "secret_key", &n1);
        sod_len(k, 1, "secret_key", n1, crypto_sign_SECRETKEYBYTES, "SODIUM_CRYPTO_SIGN_SECRETKEYBYTES");
        out = sod_buf(32);
        if (conv ? crypto_sign_ed25519_sk_to_curve25519(out, s1) : crypto_sign_ed25519_sk_to_pk(out, s1))
            sod_throw(conv ? "conversion failed" : "internal error");
        sod_free(s1, n1);
        return sod_ret(out, 32);
    }

    if (!strcmp(name, "sodium_crypto_sign_ed25519_pk_to_curve25519")) {
        sod_argc(k, 1, 1);
        s1 = sod_str(k, 1, "public_key", &n1);
        sod_len(k, 1, "public_key", n1, crypto_sign_PUBLICKEYBYTES, "SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES");
        out = sod_buf(32);
        if (crypto_sign_ed25519_pk_to_curve25519(out, s1) != 0) sod_throw("conversion failed");
        sod_free(s1, n1);
        return sod_ret(out, 32);
    }

    if (!strcmp(name, "sodium_crypto_sign") || !strcmp(name, "sodium_crypto_sign_detached")) {
        int det = name[18] == '_';
        sod_argc(k, 2, 2);
        s1 = sod_str(k, 1, "message", &n1);
        s2 = sod_str(k, 2, "secret_key", &n2);
        sod_len(k, 2, "secret_key", n2, crypto_sign_SECRETKEYBYTES, "SODIUM_CRYPTO_SIGN_SECRETKEYBYTES");
        unsigned long long rl = 0;
        if (det) {
            out = sod_buf(crypto_sign_BYTES);
            if (crypto_sign_detached(out, &rl, s1, n1, s2) != 0) sod_throw("signature creation failed");
        } else {
            out = sod_buf(n1 + crypto_sign_BYTES);
            if (crypto_sign(out, &rl, s1, n1, s2) != 0) sod_throw("internal error");
        }
        sod_free(s1, n1); sod_free(s2, n2);
        return sod_ret(out, (size_t)rl);
    }

    if (!strcmp(name, "sodium_crypto_sign_open")) {
        sod_argc(k, 2, 2);
        s1 = sod_str(k, 1, "signed_message", &n1);
        s2 = sod_str(k, 2, "public_key", &n2);
        sod_len(k, 2, "public_key", n2, crypto_sign_PUBLICKEYBYTES, "SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES");
        unsigned long long rl = 0;
        out = sod_buf(n1);
        Value* r;
        if (crypto_sign_open(out, &rl, s1, n1, s2) != 0) { free(out); r = v_bool(0); }
        else r = sod_ret(out, (size_t)rl);
        sod_free(s1, n1); sod_free(s2, n2);
        return r;
    }

    if (!strcmp(name, "sodium_crypto_sign_verify_detached")) {
        sod_argc(k, 3, 3);
        s1 = sod_str(k, 1, "signature", &n1);
        s2 = sod_str(k, 2, "message", &n2);
        s3 = sod_str(k, 3, "public_key", &n3);
        sod_len(k, 1, "signature", n1, crypto_sign_BYTES, "SODIUM_CRYPTO_SIGN_BYTES");
        sod_len(k, 3, "public_key", n3, crypto_sign_PUBLICKEYBYTES, "SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES");
        int ok = crypto_sign_verify_detached(s1, s2, n2, s3) == 0;
        sod_free(s1, n1); sod_free(s2, n2); sod_free(s3, n3);
        return v_bool(ok);
    }

    /* ---- generichash: BLAKE2b ---- */

    if (!strcmp(name, "sodium_crypto_generichash")) {
        sod_argc(k, 1, 3);
        s1 = sod_str(k, 1, "message", &n1);
        s2 = sod_str(k, 2, "key", &n2);
        long long len = sod_int(k, 3, "length", crypto_generichash_BYTES);
        if (len < crypto_generichash_BYTES_MIN || len > crypto_generichash_BYTES_MAX)
            sod_throw("unsupported output length");
        if (n2 && (n2 < crypto_generichash_KEYBYTES_MIN || n2 > crypto_generichash_KEYBYTES_MAX))
            sod_throw("unsupported key length");
        out = sod_buf((size_t)len);
        if (crypto_generichash(out, (size_t)len, s1, n1, n2 ? s2 : 0, n2) != 0) sod_throw("internal error");
        sod_free(s1, n1); sod_free(s2, n2);
        return sod_ret(out, (size_t)len);
    }

    /* The streaming state is a string holding the raw libsodium state, as in
       PHP. _update and _final take it by reference; _final wipes it to null. */
    if (!strcmp(name, "sodium_crypto_generichash_init")) {
        sod_argc(k, 0, 2);
        s1 = sod_str(k, 1, "key", &n1);
        long long len = sod_int(k, 2, "length", crypto_generichash_BYTES);
        if (len < crypto_generichash_BYTES_MIN || len > crypto_generichash_BYTES_MAX)
            sod_throw("unsupported output length");
        if (n1 && (n1 < crypto_generichash_KEYBYTES_MIN || n1 > crypto_generichash_KEYBYTES_MAX))
            sod_throw("unsupported key length");
        crypto_generichash_state st;
        if (crypto_generichash_init(&st, n1 ? s1 : 0, n1, (size_t)len) != 0) sod_throw("internal error");
        out = sod_buf(sizeof st);
        memcpy(out, &st, sizeof st);
        sodium_memzero(&st, sizeof st);
        sod_free(s1, n1);
        return sod_ret(out, sizeof st);
    }

    if (!strcmp(name, "sodium_crypto_generichash_update") || !strcmp(name, "sodium_crypto_generichash_final")) {
        int fin = name[26] == 'f';
        if (fin) sod_argc(k, 1, 2); else sod_argc(k, 2, 2);
        Value* sv = sod_ref(k, 1);
        if (!sv || sv->type != T_STRING) sod_argerr(k, 1, "state", "must be a reference to a state");
        crypto_generichash_state st;
        if (slen(sv) != sizeof st) sod_throw("incorrect state length");
        if (!fin) {
            s2 = sod_str(k, 2, "message", &n2);
            memcpy(&st, sv->s, sizeof st);
            if (crypto_generichash_update(&st, s2, n2) != 0) sod_throw("internal error");
            sod_set(sv, (unsigned char*)&st, sizeof st);
            sodium_memzero(&st, sizeof st);
            sod_free(s2, n2);
            return v_bool(1);
        }
        long long len = sod_int(k, 2, "length", crypto_generichash_BYTES);
        if (len < crypto_generichash_BYTES_MIN || len > crypto_generichash_BYTES_MAX)
            sod_throw("unsupported output length");
        memcpy(&st, sv->s, sizeof st);
        out = sod_buf((size_t)len);
        if (crypto_generichash_final(&st, out, (size_t)len) != 0) sod_throw("internal error");
        sodium_memzero(&st, sizeof st);
        sod_null(sv);
        return sod_ret(out, (size_t)len);
    }

    /* ---- auth (HMAC-SHA512-256), shorthash (SipHash-2-4), kdf ---- */

    if (!strcmp(name, "sodium_crypto_auth")) {
        sod_argc(k, 2, 2);
        s1 = sod_str(k, 1, "message", &n1);
        s2 = sod_str(k, 2, "key", &n2);
        sod_len(k, 2, "key", n2, crypto_auth_KEYBYTES, "SODIUM_CRYPTO_AUTH_KEYBYTES");
        out = sod_buf(crypto_auth_BYTES);
        if (crypto_auth(out, s1, n1, s2) != 0) sod_throw("internal error");
        sod_free(s1, n1); sod_free(s2, n2);
        return sod_ret(out, crypto_auth_BYTES);
    }

    if (!strcmp(name, "sodium_crypto_auth_verify")) {
        sod_argc(k, 3, 3);
        s1 = sod_str(k, 1, "mac", &n1);
        s2 = sod_str(k, 2, "message", &n2);
        s3 = sod_str(k, 3, "key", &n3);
        sod_len(k, 3, "key", n3, crypto_auth_KEYBYTES, "SODIUM_CRYPTO_AUTH_KEYBYTES");
        sod_len(k, 1, "mac", n1, crypto_auth_BYTES, "SODIUM_CRYPTO_AUTH_BYTES");
        int ok = crypto_auth_verify(s1, s2, n2, s3) == 0;
        sod_free(s1, n1); sod_free(s2, n2); sod_free(s3, n3);
        return v_bool(ok);
    }

    if (!strcmp(name, "sodium_crypto_shorthash")) {
        sod_argc(k, 2, 2);
        s1 = sod_str(k, 1, "message", &n1);
        s2 = sod_str(k, 2, "key", &n2);
        sod_len(k, 2, "key", n2, crypto_shorthash_KEYBYTES, "SODIUM_CRYPTO_SHORTHASH_KEYBYTES");
        out = sod_buf(crypto_shorthash_BYTES);
        if (crypto_shorthash(out, s1, n1, s2) != 0) sod_throw("internal error");
        sod_free(s1, n1); sod_free(s2, n2);
        return sod_ret(out, crypto_shorthash_BYTES);
    }

    if (!strcmp(name, "sodium_crypto_kdf_derive_from_key")) {
        sod_argc(k, 4, 4);
        long long len = sod_int(k, 1, "subkey_length", 0);
        long long id = sod_int(k, 2, "subkey_id", 0);
        s3 = sod_str(k, 3, "context", &n3);
        s4 = sod_str(k, 4, "key", &n4);
        if (len < crypto_kdf_BYTES_MIN)
            sod_argerr(k, 1, "subkey_length", "must be greater than or equal to SODIUM_CRYPTO_KDF_BYTES_MIN");
        if (len > crypto_kdf_BYTES_MAX)
            sod_argerr(k, 1, "subkey_length", "must be less than or equal to SODIUM_CRYPTO_KDF_BYTES_MAX");
        if (id < 0) sod_argerr(k, 2, "subkey_id", "must be greater than or equal to 0");
        sod_len(k, 3, "context", n3, crypto_kdf_CONTEXTBYTES, "SODIUM_CRYPTO_KDF_CONTEXTBYTES");
        /* sic: PHP's message names BYTES_MIN for the key length */
        sod_len(k, 4, "key", n4, crypto_kdf_KEYBYTES, "SODIUM_CRYPTO_KDF_BYTES_MIN");
        out = sod_buf((size_t)len);
        if (crypto_kdf_derive_from_key(out, (size_t)len, (uint64_t)id, (const char*)s3, s4) != 0)
            sod_throw("internal error");
        sod_free(s3, n3); sod_free(s4, n4);
        return sod_ret(out, (size_t)len);
    }

    /* ---- pwhash: Argon2 ---- */

    if (!strcmp(name, "sodium_crypto_pwhash_str")) {
        sod_argc(k, 3, 3);
        s1 = sod_str(k, 1, "password", &n1);
        long long ops = sod_int(k, 2, "opslimit", 0);
        long long mem = sod_int(k, 3, "memlimit", 0);
        if (ops <= 0) sod_argerr(k, 2, "opslimit", "must be greater than 0");
        if (mem <= 0) sod_argerr(k, 3, "memlimit", "must be greater than 0");
        if (n1 >= 0xffffffffUL) sod_argerr(k, 1, "password", "is too long");
        if (!n1) fprintf(stderr, "PHP warning: empty password\n");
        char m[80];
        if ((unsigned long long)ops < crypto_pwhash_OPSLIMIT_MIN) {
            snprintf(m, sizeof m, "must be greater than or equal to %d", (int)crypto_pwhash_OPSLIMIT_MIN);
            sod_argerr(k, 2, "opslimit", m);
        }
        if ((unsigned long long)mem < crypto_pwhash_MEMLIMIT_MIN) {
            snprintf(m, sizeof m, "must be greater than or equal to %d", (int)crypto_pwhash_MEMLIMIT_MIN);
            sod_argerr(k, 3, "memlimit", m);
        }
        char h[crypto_pwhash_STRBYTES];
        struct rlimit saved;
        sod_lift_limit((size_t)mem, &saved);
        int rc = crypto_pwhash_str(h, (const char*)s1, n1, (unsigned long long)ops, (size_t)mem);
        sod_restore_limit(&saved);
        if (rc != 0) sod_throw("internal error");
        sod_free(s1, n1);
        return v_str(h);
    }

    if (!strcmp(name, "sodium_crypto_pwhash_str_verify")) {
        sod_argc(k, 2, 2);
        s1 = sod_str(k, 1, "hash", &n1);
        s2 = sod_str(k, 2, "password", &n2);
        if (n2 >= 0xffffffffUL) sod_argerr(k, 2, "password", "is too long");
        if (!n2) fprintf(stderr, "PHP warning: empty password\n");
        /* the hash names its own memory cost; lift the limit by that much */
        unsigned long long mem = 0;
        const char* mp = strstr((const char*)s1, "$m=");
        if (mp) mem = strtoull(mp + 3, 0, 10) * 1024ULL;
        struct rlimit saved;
        sod_lift_limit(mem < ((size_t)1 << 40) ? (size_t)mem : 0, &saved);
        int ok = crypto_pwhash_str_verify((const char*)s1, (const char*)s2, n2) == 0;
        sod_restore_limit(&saved);
        sod_free(s1, n1); sod_free(s2, n2);
        return v_bool(ok);
    }

    if (!strcmp(name, "sodium_crypto_pwhash_str_needs_rehash")) {
        sod_argc(k, 3, 3);
        s1 = sod_str(k, 1, "password", &n1);   /* sic: PHP names the hash $password */
        long long ops = sod_int(k, 2, "opslimit", 0);
        long long mem = sod_int(k, 3, "memlimit", 0);
        int r = crypto_pwhash_str_needs_rehash((const char*)s1, (unsigned long long)ops, (size_t)mem) != 0;
        sod_free(s1, n1);
        return v_bool(r);
    }

    if (!strcmp(name, "sodium_crypto_pwhash")) {
        sod_argc(k, 5, 6);
        long long len = sod_int(k, 1, "length", 0);
        s2 = sod_str(k, 2, "password", &n2);
        s3 = sod_str(k, 3, "salt", &n3);
        long long ops = sod_int(k, 4, "opslimit", 0);
        long long mem = sod_int(k, 5, "memlimit", 0);
        long long alg = sod_int(k, 6, "algo", crypto_pwhash_ALG_DEFAULT);
        if (len <= 0) sod_argerr(k, 1, "length", "must be greater than 0");
        if (len >= 0xffffffffLL) sod_argerr(k, 1, "length", "is too large");
        if (n2 >= 0xffffffffUL) sod_argerr(k, 2, "password", "is too long");
        if (ops <= 0) sod_argerr(k, 4, "opslimit", "must be greater than 0");
        if (mem <= 0) sod_argerr(k, 5, "memlimit", "must be greater than 0");
        if (alg != crypto_pwhash_ALG_ARGON2I13 && alg != crypto_pwhash_ALG_ARGON2ID13 &&
            alg != crypto_pwhash_ALG_DEFAULT)
            sod_throw("unsupported password hashing algorithm");
        if (!n2) fprintf(stderr, "PHP warning: empty password\n");
        sod_len(k, 3, "salt", n3, crypto_pwhash_SALTBYTES, "SODIUM_CRYPTO_PWHASH_SALTBYTES");
        char m[80];
        if ((unsigned long long)ops < crypto_pwhash_OPSLIMIT_MIN) {
            snprintf(m, sizeof m, "must be greater than or equal to %d", (int)crypto_pwhash_OPSLIMIT_MIN);
            sod_argerr(k, 4, "opslimit", m);
        }
        if ((unsigned long long)mem < crypto_pwhash_MEMLIMIT_MIN) {
            snprintf(m, sizeof m, "must be greater than or equal to %d", (int)crypto_pwhash_MEMLIMIT_MIN);
            sod_argerr(k, 5, "memlimit", m);
        }
        out = sod_buf((size_t)len);
        struct rlimit saved;
        sod_lift_limit((size_t)mem, &saved);
        int rc = crypto_pwhash(out, (unsigned long long)len, (const char*)s2, n2, s3,
                               (unsigned long long)ops, (size_t)mem, (int)alg);
        sod_restore_limit(&saved);
        if (rc != 0) sod_throw("internal error");
        sod_free(s2, n2); sod_free(s3, n3);
        return sod_ret(out, (size_t)len);
    }

    /* ---- stream ciphers ---- */

    if (!strcmp(name, "sodium_crypto_stream") || !strcmp(name, "sodium_crypto_stream_xchacha20")) {
        int xc = strstr(name, "xchacha20") != 0;
        sod_argc(k, 3, 3);
        long long len = sod_int(k, 1, "length", 0);
        s2 = sod_str(k, 2, "nonce", &n2);
        s3 = sod_str(k, 3, "key", &n3);
        if (len <= 0) sod_argerr(k, 1, "length", "must be greater than 0");
        sod_len(k, 2, "nonce", n2, 24, xc ? "SODIUM_CRYPTO_STREAM_XCHACHA20_NONCEBYTES" : "SODIUM_CRYPTO_STREAM_NONCEBYTES");
        sod_len(k, 3, "key", n3, 32, xc ? "SODIUM_CRYPTO_STREAM_XCHACHA20_KEYBYTES" : "SODIUM_CRYPTO_STREAM_KEYBYTES");
        out = sod_buf((size_t)len);
        if ((xc ? crypto_stream_xchacha20 : crypto_stream)(out, (unsigned long long)len, s2, s3) != 0)
            sod_throw("internal error");
        sod_free(s2, n2); sod_free(s3, n3);
        return sod_ret(out, (size_t)len);
    }

    if (!strcmp(name, "sodium_crypto_stream_xor") || !strcmp(name, "sodium_crypto_stream_xchacha20_xor") ||
        !strcmp(name, "sodium_crypto_stream_xchacha20_xor_ic")) {
        int xc = strstr(name, "xchacha20") != 0, ic = strstr(name, "_ic") != 0;
        sod_argc(k, ic ? 4 : 3, ic ? 4 : 3);
        s1 = sod_str(k, 1, "message", &n1);
        s2 = sod_str(k, 2, "nonce", &n2);
        long long ctr = ic ? sod_int(k, 3, "counter", 0) : 0;
        s3 = sod_str(k, ic ? 4 : 3, "key", &n3);
        sod_len(k, 2, "nonce", n2, 24, xc ? "SODIUM_CRYPTO_STREAM_XCHACHA20_NONCEBYTES" : "SODIUM_CRYPTO_STREAM_NONCEBYTES");
        /* sic: in _xor_ic PHP reports a bad key as argument #3 ($counter) */
        sod_len(k, 3, ic ? "counter" : "key", n3, 32,
                xc ? "SODIUM_CRYPTO_STREAM_XCHACHA20_KEYBYTES" : "SODIUM_CRYPTO_STREAM_KEYBYTES");
        out = sod_buf(n1);
        int rc = ic ? crypto_stream_xchacha20_xor_ic(out, s1, n1, s2, (uint64_t)ctr, s3)
               : xc ? crypto_stream_xchacha20_xor(out, s1, n1, s2, s3)
                    : crypto_stream_xor(out, s1, n1, s2, s3);
        if (rc != 0) sod_throw("internal error");
        sod_free(s1, n1); sod_free(s2, n2); sod_free(s3, n3);
        return sod_ret(out, n1);
    }

    /* ---- secretstream: XChaCha20-Poly1305 for long or chunked data ---- */

    if (!strcmp(name, "sodium_crypto_secretstream_xchacha20poly1305_init_push")) {
        sod_argc(k, 1, 1);
        s1 = sod_str(k, 1, "key", &n1);
        sod_len(k, 1, "key", n1, crypto_secretstream_xchacha20poly1305_KEYBYTES,
                "SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES");
        crypto_secretstream_xchacha20poly1305_state st;
        unsigned char* hdr = sod_buf(crypto_secretstream_xchacha20poly1305_HEADERBYTES);
        if (crypto_secretstream_xchacha20poly1305_init_push(&st, hdr, s1) != 0) sod_throw("internal error");
        out = sod_buf(sizeof st);
        memcpy(out, &st, sizeof st);
        sodium_memzero(&st, sizeof st);
        sod_free(s1, n1);
        return sod_pair(sod_ret(out, sizeof st), sod_ret(hdr, crypto_secretstream_xchacha20poly1305_HEADERBYTES));
    }

    if (!strcmp(name, "sodium_crypto_secretstream_xchacha20poly1305_init_pull")) {
        sod_argc(k, 2, 2);
        s1 = sod_str(k, 1, "header", &n1);
        s2 = sod_str(k, 2, "key", &n2);
        sod_len(k, 1, "header", n1, crypto_secretstream_xchacha20poly1305_HEADERBYTES,
                "SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES");
        sod_len(k, 2, "key", n2, crypto_secretstream_xchacha20poly1305_KEYBYTES,
                "SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES");
        crypto_secretstream_xchacha20poly1305_state st;
        if (crypto_secretstream_xchacha20poly1305_init_pull(&st, s1, s2) != 0) sod_throw("internal error");
        out = sod_buf(sizeof st);
        memcpy(out, &st, sizeof st);
        sodium_memzero(&st, sizeof st);
        sod_free(s1, n1); sod_free(s2, n2);
        return sod_ret(out, sizeof st);
    }

    if (!strcmp(name, "sodium_crypto_secretstream_xchacha20poly1305_push") ||
        !strcmp(name, "sodium_crypto_secretstream_xchacha20poly1305_pull") ||
        !strcmp(name, "sodium_crypto_secretstream_xchacha20poly1305_rekey")) {
        const char* op = strrchr(name, '_') + 1;
        int push = !strcmp(op, "push"), rekey = !strcmp(op, "rekey");
        if (rekey) sod_argc(k, 1, 1); else if (push) sod_argc(k, 2, 4); else sod_argc(k, 2, 3);
        Value* sv = sod_ref(k, 1);
        if (!sv || sv->type != T_STRING) sod_argerr(k, 1, "state", "must be a reference to a state");
        crypto_secretstream_xchacha20poly1305_state st;
        if (slen(sv) != sizeof st) {
            if (push) sod_argerr(k, 1, "state", "must have a correct length");
            sod_throw("incorrect state length");
        }
        memcpy(&st, sv->s, sizeof st);
        if (rekey) {
            crypto_secretstream_xchacha20poly1305_rekey(&st);
            sod_set(sv, (unsigned char*)&st, sizeof st);
            sodium_memzero(&st, sizeof st);
            return v_null();
        }
        s2 = sod_str(k, 2, push ? "message" : "ciphertext", &n2);
        s3 = sod_str(k, 3, "additional_data", &n3);
        Value* r;
        if (push) {
            long long tag = sod_int(k, 4, "tag", crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);
            if ((unsigned long long)n2 > crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX)
                sod_argerr(k, 2, "message", "must be at most SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_MESSAGEBYTES_MAX bytes long");
            if (tag < 0 || tag > 255) sod_argerr(k, 4, "tag", "must be in the range of 0-255");
            unsigned long long rl = 0;
            out = sod_buf(n2 + crypto_secretstream_xchacha20poly1305_ABYTES);
            if (crypto_secretstream_xchacha20poly1305_push(&st, out, &rl, s2, n2, n3 ? s3 : 0, n3,
                                                           (unsigned char)tag) != 0)
                sod_throw("internal error");
            r = sod_ret(out, (size_t)rl);
            sod_set(sv, (unsigned char*)&st, sizeof st);
        } else if (n2 < crypto_secretstream_xchacha20poly1305_ABYTES) {
            r = v_bool(0);
        } else {
            unsigned long long rl = 0;
            unsigned char tag = 0;
            out = sod_buf(n2 - crypto_secretstream_xchacha20poly1305_ABYTES);
            if (crypto_secretstream_xchacha20poly1305_pull(&st, out, &rl, &tag, s2, n2, n3 ? s3 : 0, n3) != 0) {
                free(out);
                r = v_bool(0);
            } else {
                r = sod_pair(sod_ret(out, (size_t)rl), v_int(tag));
                sod_set(sv, (unsigned char*)&st, sizeof st);
            }
        }
        sodium_memzero(&st, sizeof st);
        sod_free(s2, n2); sod_free(s3, n3);
        return r;
    }

    /* ---- helpers: encoding, comparison, counters, padding ---- */

    if (!strcmp(name, "sodium_bin2hex")) {
        sod_argc(k, 1, 1);
        s1 = sod_str(k, 1, "string", &n1);
        out = sod_buf(n1 * 2);
        sodium_bin2hex((char*)out, n1 * 2 + 1, s1, n1);
        sod_free(s1, n1);
        return sod_ret(out, n1 * 2);
    }

    if (!strcmp(name, "sodium_hex2bin")) {
        sod_argc(k, 1, 2);
        s1 = sod_str(k, 1, "string", &n1);
        s2 = sod_str(k, 2, "ignore", &n2);
        size_t bl = n1 / 2, real = 0;
        const char* end = 0;
        out = sod_buf(bl);
        if (sodium_hex2bin(out, bl, (const char*)s1, n1, n2 ? (const char*)s2 : 0, &real, &end) != 0 ||
            end != (const char*)s1 + n1)
            sod_argerr(k, 1, "string", "must be a valid hexadecimal string");
        sod_free(s1, n1); sod_free(s2, n2);
        return sod_ret(out, real);
    }

    if (!strcmp(name, "sodium_bin2base64")) {
        sod_argc(k, 2, 2);
        s1 = sod_str(k, 1, "string", &n1);
        long long var = sod_int(k, 2, "id", 0);
        if ((((unsigned int)var) & ~0x6U) != 0x1U)
            sod_argerr(k, 2, "id", "must be a valid base64 variant identifier");
        size_t el = sodium_base64_ENCODED_LEN(n1, (int)var);
        out = sod_buf(el - 1);
        sodium_bin2base64((char*)out, el, s1, n1, (int)var);
        sod_free(s1, n1);
        return sod_ret(out, el - 1);
    }

    if (!strcmp(name, "sodium_base642bin")) {
        sod_argc(k, 2, 3);
        s1 = sod_str(k, 1, "string", &n1);
        long long var = sod_int(k, 2, "id", 0);
        s3 = sod_str(k, 3, "ignore", &n3);
        if ((((unsigned int)var) & ~0x6U) != 0x1U)
            sod_argerr(k, 2, "id", "must be a valid base64 variant identifier");
        size_t bl = n1 / 4 * 3 + 2, real = 0;
        const char* end = 0;
        out = sod_buf(bl);
        if (sodium_base642bin(out, bl, (const char*)s1, n1, n3 ? (const char*)s3 : 0, &real, &end, (int)var) != 0 ||
            end != (const char*)s1 + n1)
            sod_argerr(k, 1, "string", "must be a valid base64 string");
        sod_free(s1, n1); sod_free(s3, n3);
        return sod_ret(out, real);
    }

    if (!strcmp(name, "sodium_memcmp") || !strcmp(name, "sodium_compare")) {
        sod_argc(k, 2, 2);
        s1 = sod_str(k, 1, "string1", &n1);
        s2 = sod_str(k, 2, "string2", &n2);
        if (n1 != n2) sod_argerr(k, 1, "string1", "and argument #2 ($string_2) must have the same length");
        int r = name[7] == 'm' ? sodium_memcmp(s1, s2, n1) : sodium_compare(s1, s2, n1);
        sod_free(s1, n1); sod_free(s2, n2);
        return v_int(r);
    }

    if (!strcmp(name, "sodium_memzero")) {
        sod_argc(k, 1, 1);
        Value* v = sod_ref(k, 1);
        if (v->type != T_STRING) sod_throw("a PHP string is required");
        sod_null(v);          /* bytes wiped, variable becomes null -- as in PHP */
        return v_null();
    }

    if (!strcmp(name, "sodium_increment")) {
        sod_argc(k, 1, 1);
        Value* v = sod_ref(k, 1);
        if (v->type != T_STRING) sod_throw("a PHP string is required");
        size_t n = slen(v);
        unsigned char* p = (unsigned char*)val_bin(v, &n);
        sodium_increment(p, n);
        sod_set(v, p, n);
        sod_free(p, n);
        return v_null();
    }

    if (!strcmp(name, "sodium_add")) {
        sod_argc(k, 2, 2);
        Value* v = sod_ref(k, 1);
        if (v->type != T_STRING) sod_throw("PHP strings are required");
        s2 = sod_str(k, 2, "string2", &n2);
        size_t n = slen(v);
        if (n != n2) sod_argerr(k, 1, "string1", "and argument #2 ($string_2) must have the same length");
        unsigned char* p = (unsigned char*)val_bin(v, &n);
        sodium_add(p, s2, n);
        sod_set(v, p, n);
        sod_free(p, n); sod_free(s2, n2);
        return v_null();
    }

    if (!strcmp(name, "sodium_pad") || !strcmp(name, "sodium_unpad")) {
        int pad = name[7] == 'p';
        sod_argc(k, 2, 2);
        s1 = sod_str(k, 1, "string", &n1);
        long long bs = sod_int(k, 2, "block_size", 0);
        if (bs <= 0) sod_argerr(k, 2, "block_size", "must be greater than 0");
        Value* r;
        if (pad) {
            size_t xpad = (size_t)bs - 1U - n1 % (size_t)bs;
            if (SIZE_MAX - n1 <= xpad) sod_throw("input is too large");
            size_t total = n1 + xpad + 1U;
            out = sod_buf(total);
            memcpy(out, s1, n1);
            size_t pl = 0;
            if (sodium_pad(&pl, out, n1, (size_t)bs, total) != 0) sod_throw("internal error");
            r = sod_ret(out, pl);
        } else {
            if (n1 < (size_t)bs) sod_argerr(k, 1, "string", "must be at least as long as the block size");
            size_t ul = 0;
            if (sodium_unpad(&ul, s1, n1, (size_t)bs) != 0) sod_throw("invalid padding");
            out = sod_buf(ul);
            memcpy(out, s1, ul);
            r = sod_ret(out, ul);
        }
        sod_free(s1, n1);
        return r;
    }

    *handled = 0;
    return 0;
}

/* SODIUM_* constants, resolved when the script is parsed. Values are
   libsodium's own; the names are PHP's. */
static const struct { const char* name; long long i; const char* s; } sod_consts[] = {
    { "SODIUM_LIBRARY_VERSION", 0, SODIUM_VERSION_STRING },
    { "SODIUM_LIBRARY_MAJOR_VERSION", SODIUM_LIBRARY_VERSION_MAJOR, 0 },
    { "SODIUM_LIBRARY_MINOR_VERSION", SODIUM_LIBRARY_VERSION_MINOR, 0 },
    { "SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES", crypto_aead_aes256gcm_KEYBYTES, 0 },
    { "SODIUM_CRYPTO_AEAD_AES256GCM_NSECBYTES", crypto_aead_aes256gcm_NSECBYTES, 0 },
    { "SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES", crypto_aead_aes256gcm_NPUBBYTES, 0 },
    { "SODIUM_CRYPTO_AEAD_AES256GCM_ABYTES", crypto_aead_aes256gcm_ABYTES, 0 },
    { "SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES", crypto_aead_chacha20poly1305_KEYBYTES, 0 },
    { "SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_NSECBYTES", crypto_aead_chacha20poly1305_NSECBYTES, 0 },
    { "SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES", crypto_aead_chacha20poly1305_NPUBBYTES, 0 },
    { "SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_ABYTES", crypto_aead_chacha20poly1305_ABYTES, 0 },
    { "SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES", crypto_aead_chacha20poly1305_ietf_KEYBYTES, 0 },
    { "SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NSECBYTES", crypto_aead_chacha20poly1305_ietf_NSECBYTES, 0 },
    { "SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES", crypto_aead_chacha20poly1305_ietf_NPUBBYTES, 0 },
    { "SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES", crypto_aead_chacha20poly1305_ietf_ABYTES, 0 },
    { "SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES", crypto_aead_xchacha20poly1305_ietf_KEYBYTES, 0 },
    { "SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NSECBYTES", crypto_aead_xchacha20poly1305_ietf_NSECBYTES, 0 },
    { "SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES", crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, 0 },
    { "SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES", crypto_aead_xchacha20poly1305_ietf_ABYTES, 0 },
    { "SODIUM_CRYPTO_AUTH_BYTES", crypto_auth_BYTES, 0 },
    { "SODIUM_CRYPTO_AUTH_KEYBYTES", crypto_auth_KEYBYTES, 0 },
    { "SODIUM_CRYPTO_BOX_SEALBYTES", crypto_box_SEALBYTES, 0 },
    { "SODIUM_CRYPTO_BOX_SECRETKEYBYTES", crypto_box_SECRETKEYBYTES, 0 },
    { "SODIUM_CRYPTO_BOX_PUBLICKEYBYTES", crypto_box_PUBLICKEYBYTES, 0 },
    { "SODIUM_CRYPTO_BOX_KEYPAIRBYTES", crypto_box_SECRETKEYBYTES + crypto_box_PUBLICKEYBYTES, 0 },
    { "SODIUM_CRYPTO_BOX_MACBYTES", crypto_box_MACBYTES, 0 },
    { "SODIUM_CRYPTO_BOX_NONCEBYTES", crypto_box_NONCEBYTES, 0 },
    { "SODIUM_CRYPTO_BOX_SEEDBYTES", crypto_box_SEEDBYTES, 0 },
    { "SODIUM_CRYPTO_KDF_BYTES_MIN", crypto_kdf_BYTES_MIN, 0 },
    { "SODIUM_CRYPTO_KDF_BYTES_MAX", crypto_kdf_BYTES_MAX, 0 },
    { "SODIUM_CRYPTO_KDF_CONTEXTBYTES", crypto_kdf_CONTEXTBYTES, 0 },
    { "SODIUM_CRYPTO_KDF_KEYBYTES", crypto_kdf_KEYBYTES, 0 },
    { "SODIUM_CRYPTO_KX_SEEDBYTES", crypto_kx_SEEDBYTES, 0 },
    { "SODIUM_CRYPTO_KX_SESSIONKEYBYTES", crypto_kx_SESSIONKEYBYTES, 0 },
    { "SODIUM_CRYPTO_KX_PUBLICKEYBYTES", crypto_kx_PUBLICKEYBYTES, 0 },
    { "SODIUM_CRYPTO_KX_SECRETKEYBYTES", crypto_kx_SECRETKEYBYTES, 0 },
    { "SODIUM_CRYPTO_KX_KEYPAIRBYTES", crypto_kx_SECRETKEYBYTES + crypto_kx_PUBLICKEYBYTES, 0 },
    { "SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES", crypto_secretstream_xchacha20poly1305_ABYTES, 0 },
    { "SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES", crypto_secretstream_xchacha20poly1305_HEADERBYTES, 0 },
    { "SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES", crypto_secretstream_xchacha20poly1305_KEYBYTES, 0 },
    { "SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_MESSAGEBYTES_MAX",
      (long long)crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX, 0 },
    { "SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE", crypto_secretstream_xchacha20poly1305_TAG_MESSAGE, 0 },
    { "SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_PUSH", crypto_secretstream_xchacha20poly1305_TAG_PUSH, 0 },
    { "SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_REKEY", crypto_secretstream_xchacha20poly1305_TAG_REKEY, 0 },
    { "SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL", crypto_secretstream_xchacha20poly1305_TAG_FINAL, 0 },
    { "SODIUM_CRYPTO_GENERICHASH_BYTES", crypto_generichash_BYTES, 0 },
    { "SODIUM_CRYPTO_GENERICHASH_BYTES_MIN", crypto_generichash_BYTES_MIN, 0 },
    { "SODIUM_CRYPTO_GENERICHASH_BYTES_MAX", crypto_generichash_BYTES_MAX, 0 },
    { "SODIUM_CRYPTO_GENERICHASH_KEYBYTES", crypto_generichash_KEYBYTES, 0 },
    { "SODIUM_CRYPTO_GENERICHASH_KEYBYTES_MIN", crypto_generichash_KEYBYTES_MIN, 0 },
    { "SODIUM_CRYPTO_GENERICHASH_KEYBYTES_MAX", crypto_generichash_KEYBYTES_MAX, 0 },
    { "SODIUM_CRYPTO_PWHASH_ALG_ARGON2I13", crypto_pwhash_ALG_ARGON2I13, 0 },
    { "SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13", crypto_pwhash_ALG_ARGON2ID13, 0 },
    { "SODIUM_CRYPTO_PWHASH_ALG_DEFAULT", crypto_pwhash_ALG_DEFAULT, 0 },
    { "SODIUM_CRYPTO_PWHASH_SALTBYTES", crypto_pwhash_SALTBYTES, 0 },
    { "SODIUM_CRYPTO_PWHASH_STRPREFIX", 0, crypto_pwhash_STRPREFIX },
    { "SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE", crypto_pwhash_OPSLIMIT_INTERACTIVE, 0 },
    { "SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE", crypto_pwhash_MEMLIMIT_INTERACTIVE, 0 },
    { "SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE", crypto_pwhash_OPSLIMIT_MODERATE, 0 },
    { "SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE", crypto_pwhash_MEMLIMIT_MODERATE, 0 },
    { "SODIUM_CRYPTO_PWHASH_OPSLIMIT_SENSITIVE", crypto_pwhash_OPSLIMIT_SENSITIVE, 0 },
    { "SODIUM_CRYPTO_PWHASH_MEMLIMIT_SENSITIVE", crypto_pwhash_MEMLIMIT_SENSITIVE, 0 },
    { "SODIUM_CRYPTO_SCALARMULT_BYTES", crypto_scalarmult_BYTES, 0 },
    { "SODIUM_CRYPTO_SCALARMULT_SCALARBYTES", crypto_scalarmult_SCALARBYTES, 0 },
    { "SODIUM_CRYPTO_SHORTHASH_BYTES", crypto_shorthash_BYTES, 0 },
    { "SODIUM_CRYPTO_SHORTHASH_KEYBYTES", crypto_shorthash_KEYBYTES, 0 },
    { "SODIUM_CRYPTO_SECRETBOX_KEYBYTES", crypto_secretbox_KEYBYTES, 0 },
    { "SODIUM_CRYPTO_SECRETBOX_MACBYTES", crypto_secretbox_MACBYTES, 0 },
    { "SODIUM_CRYPTO_SECRETBOX_NONCEBYTES", crypto_secretbox_NONCEBYTES, 0 },
    { "SODIUM_CRYPTO_SIGN_BYTES", crypto_sign_BYTES, 0 },
    { "SODIUM_CRYPTO_SIGN_SEEDBYTES", crypto_sign_SEEDBYTES, 0 },
    { "SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES", crypto_sign_PUBLICKEYBYTES, 0 },
    { "SODIUM_CRYPTO_SIGN_SECRETKEYBYTES", crypto_sign_SECRETKEYBYTES, 0 },
    { "SODIUM_CRYPTO_SIGN_KEYPAIRBYTES", crypto_sign_SECRETKEYBYTES + crypto_sign_PUBLICKEYBYTES, 0 },
    { "SODIUM_CRYPTO_STREAM_NONCEBYTES", crypto_stream_NONCEBYTES, 0 },
    { "SODIUM_CRYPTO_STREAM_KEYBYTES", crypto_stream_KEYBYTES, 0 },
    { "SODIUM_CRYPTO_STREAM_XCHACHA20_NONCEBYTES", crypto_stream_xchacha20_NONCEBYTES, 0 },
    { "SODIUM_CRYPTO_STREAM_XCHACHA20_KEYBYTES", crypto_stream_xchacha20_KEYBYTES, 0 },
    { "SODIUM_BASE64_VARIANT_ORIGINAL", sodium_base64_VARIANT_ORIGINAL, 0 },
    { "SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING", sodium_base64_VARIANT_ORIGINAL_NO_PADDING, 0 },
    { "SODIUM_BASE64_VARIANT_URLSAFE", sodium_base64_VARIANT_URLSAFE, 0 },
    { "SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING", sodium_base64_VARIANT_URLSAFE_NO_PADDING, 0 },
};

/* 1 and the node filled in if name is a SODIUM_* constant */
static int sodium_constant(const char* name, Node* n) {
    if (strncmp(name, "SODIUM_", 7)) return 0;
    for (size_t i = 0; i < sizeof sod_consts / sizeof sod_consts[0]; i++) {
        if (strcmp(name, sod_consts[i].name)) continue;
        if (sod_consts[i].s) { n->type = NT_STR; n->s = xstrdup(sod_consts[i].s); }
        else { n->type = NT_INT; n->i = sod_consts[i].i; }
        return 1;
    }
    return 0;
}
#endif /* MINIPHP_SODIUM */

static Value* builtin(const char* name, Value** args, int argc) {
#ifndef MINIPHP_NO_SQLITE
    if (!strncmp(name, "sqlite_", 7)) {
        int handled = 0;
        Value* r = sqlite_builtin(name, args, argc, &handled);
        if (handled) return r;
    }
#endif
#ifdef MINIPHP_SODIUM
    if (!strncmp(name, "sodium_", 7)) {
        int handled = 0;
        Value* r = sodium_builtin(name, args, argc, &handled);
        if (handled) return r;
    }
#endif
#define NEED(n) do { if (argc < (n)) fatal("%s expects at least %d argument(s)", name, n); } while (0)

    if (!strcmp(name, "strlen")) {
        NEED(1);
        size_t n;
        char* s = val_bin(args[0], &n);          /* bytes, zeros included */
        free(s);
        return v_int((long long)n);
    }

    if (!strcmp(name, "count")) {
        NEED(1);
        if (args[0]->type == T_ARRAY) return v_int(array_count(args[0]));
        return v_int(args[0]->type == T_NULL ? 0 : 1);
    }

    /* ---------- uploads (milestone 4) ---------- */

    if (!strcmp(name, "is_uploaded_file")) {
        NEED(1);
        if (has_nul(args[0]))
            fatal("Uncaught ValueError: is_uploaded_file(): Argument #1 ($filename) must not contain any null bytes");
        char* path = val_to_string(args[0]);
        int ok = find_upload(path) >= 0;
        free(path);
        return v_bool(ok);
    }

    if (!strcmp(name, "move_uploaded_file")) {
        NEED(2);
        /* PHP's split: $to is a path and a zero byte in it is an error;
           $from is matched against this request's uploads, so it just fails */
        if (has_nul(args[1]))
            fatal("Uncaught ValueError: move_uploaded_file(): Argument #2 ($to) must not contain any null bytes");
        if (has_nul(args[0])) return v_bool(0);
        /* Only a file that arrived in THIS request -- anything else is
           refused with false and no warning, exactly as PHP does. */
        char* from = val_to_string(args[0]);
        char* to = val_to_string(args[1]);
        int idx = find_upload(from);
        int ok = 0;
        if (idx >= 0) {
            if (rename(from, to) == 0) {
                ok = 1;
            } else if (errno == EXDEV) {
                /* a different filesystem: copy, then remove the temp file */
                int in = open(from, O_RDONLY);
                int out = in >= 0 ? open(to, O_WRONLY | O_CREAT | O_TRUNC, 0666) : -1;
                if (in >= 0 && out >= 0) {
                    char buf[65536];
                    ssize_t r;
                    ok = 1;
                    while ((r = read(in, buf, sizeof buf)) > 0)
                        if (write(out, buf, (size_t)r) != r) { ok = 0; break; }
                    if (r < 0) ok = 0;
                }
                if (in >= 0) close(in);
                if (out >= 0) close(out);
                if (ok) unlink(from); else if (out >= 0) unlink(to);
            }
            if (ok) {
                /* the temp file was private (0600); a moved upload gets the
                   normal permissions, 0666 less the umask, as in PHP */
                mode_t um = umask(0);
                umask(um);
                chmod(to, 0666 & ~um);
                up_moved[idx] = 1;
            } else {
                fprintf(stderr, "PHP warning: move_uploaded_file(): Unable to move \"%s\" to \"%s\"\n", from, to);
            }
        }
        free(from);
        free(to);
        return v_bool(ok);
    }

    if (!strcmp(name, "basename")) {
        NEED(1);
        /* POSIX basename as PHP does it on Linux: trailing slashes dropped,
           the last component kept, and an optional suffix removed unless
           it is the whole name. */
        size_t n;
        char* path = val_bin(args[0], &n);       /* a pure string function: bytes */
        while (n > 1 && path[n - 1] == '/') n--;
        if (n == 1 && path[0] == '/') n = 0;
        size_t st = n;
        while (st > 0 && path[st - 1] != '/') st--;
        size_t bl = n - st;
        if (argc > 1) {
            char* suf = val_to_string(args[1]);
            size_t sl = strlen(suf);
            if (sl && sl < bl && !memcmp(path + st + bl - sl, suf, sl)) bl -= sl;
            free(suf);
        }
        Value* r = v_str_n(path + st, bl);
        free(path);
        return r;
    }

    /* ---------- binary data (binary-safe strings) ---------- */

    if (!strcmp(name, "chr")) {
        NEED(1);
        long long c = val_to_int(args[0]) % 256;        /* PHP 8: wraps, negatives too */
        if (c < 0) c += 256;
        char b = (char)c;
        return v_str_n(&b, 1);
    }

    if (!strcmp(name, "ord")) {
        NEED(1);
        size_t n;
        char* p = val_bin(args[0], &n);
        long long r = n ? (unsigned char)p[0] : 0;
        free(p);
        return v_int(r);
    }

    if (!strcmp(name, "random_bytes")) {
        NEED(1);
        long long n = val_to_int(args[0]);
        if (n < 1) fatal("Uncaught ValueError: random_bytes(): Argument #1 ($length) must be greater than 0");
        char* out = malloc((size_t)n + 1);
#ifdef MINIPHP_SODIUM
        randombytes_buf(out, (size_t)n);
#else
        /* the kernel's CSPRNG, as PHP uses; never a fallback to rand() */
        int fd = open("/dev/urandom", O_RDONLY);
        size_t got = 0;
        while (fd >= 0 && got < (size_t)n) {
            ssize_t r = read(fd, out + got, (size_t)n - got);
            if (r <= 0) break;
            got += (size_t)r;
        }
        if (fd >= 0) close(fd);
        if (got < (size_t)n) fatal("Uncaught Random\\RandomException: Cannot open source device");
#endif
        out[n] = 0;
        return v_str_own(out, (size_t)n);
    }

    if (!strcmp(name, "bin2hex")) {
        NEED(1);
        size_t n;
        char* p = val_bin(args[0], &n);
        char* h = malloc(n * 2 + 1);
        static const char hx[] = "0123456789abcdef";
        for (size_t i = 0; i < n; i++) {
            h[2 * i] = hx[(unsigned char)p[i] >> 4];
            h[2 * i + 1] = hx[(unsigned char)p[i] & 15];
        }
        h[n * 2] = 0;
        free(p);
        return v_str_own(h, n * 2);
    }

    if (!strcmp(name, "hex2bin")) {
        NEED(1);
        size_t n;
        char* p = val_bin(args[0], &n);
        if (n % 2) {
            fprintf(stderr, "PHP warning: hex2bin(): Hexadecimal input string must have an even length\n");
            free(p);
            return v_bool(0);
        }
        char* out = malloc(n / 2 + 1);
        for (size_t i = 0; i < n; i += 2) {
            int hi = hexval(p[i]), lo = hexval(p[i + 1]);
            if (hi < 0 || lo < 0) {
                fprintf(stderr, "PHP warning: hex2bin(): Input string must be hexadecimal string\n");
                free(p);
                free(out);
                return v_bool(0);
            }
            out[i / 2] = (char)(hi * 16 + lo);
        }
        out[n / 2] = 0;
        free(p);
        return v_str_own(out, n / 2);
    }

    /* ---------- strings (milestone 2) ----------
       Each follows PHP 8's rules, including its errors: where PHP 8 throws a
       ValueError the call is a fatal error here, since this runtime has no
       exceptions to throw. */

    if (!strcmp(name, "substr")) {
        NEED(2);
        size_t sl;
        char* str = val_bin(args[0], &sl);
        long long len = (long long)sl;
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
        size_t hl_, nl;
        char* hay = val_bin(args[0], &hl_);
        char* ndl = val_bin(args[1], &nl);
        long long hl = (long long)hl_;
        long long off = argc > 2 ? val_to_int(args[2]) : 0;

        if (off < 0) off += hl;
        if (off < 0 || off > hl)
            fatal("strpos(): Argument #3 ($offset) must be contained in argument #1 ($haystack)");

        /* memmem, not strstr: a zero byte in either string is just a byte */
        char* hit = nl ? memmem(hay + off, (size_t)(hl - off), ndl, nl) : hay + off;
        Value* r = hit ? v_int((long long)(hit - hay)) : v_bool(0);
        free(hay);
        free(ndl);
        return r;
    }
    if (!strcmp(name, "str_repeat")) {
        NEED(2);
        size_t sl;
        char* str = val_bin(args[0], &sl);
        long long times = val_to_int(args[1]);
        if (times < 0)
            fatal("str_repeat(): Argument #2 ($times) must be greater than or equal to 0");

        /* sl * times can overflow size_t; refuse rather than allocate a wrap-
           around size and write past it. (Real sizes stop at memory_limit.) */
        if (sl && (unsigned long long)times > (SIZE_MAX - 1) / sl)
            fatal("str_repeat(): result is too big");

        size_t total = sl * (size_t)times;
        char* out = malloc(total + 1);
        for (long long i = 0; i < times; i++) memcpy(out + (size_t)i * sl, str, sl);
        out[total] = 0;
        free(str);
        return v_str_own(out, total);
    }
    if (!strcmp(name, "trim") || !strcmp(name, "ltrim") || !strcmp(name, "rtrim")) {
        NEED(1);
        size_t z;
        char* str = val_bin(args[0], &z);
        unsigned char strip[256] = {0};

        if (argc > 1) {
            /* the character list, including PHP's "a..z" ranges */
            size_t n;
            char* cl = val_bin(args[1], &n);
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

        size_t a = 0;
        if (strcmp(name, "rtrim")) while (a < z && strip[(unsigned char)str[a]]) a++;
        if (strcmp(name, "ltrim")) while (z > a && strip[(unsigned char)str[z - 1]]) z--;

        Value* r = v_str_n(str + a, z - a);
        free(str);
        return r;
    }
    if (!strcmp(name, "explode")) {
        NEED(2);
        size_t sepl, sl;
        char* sep = val_bin(args[0], &sepl);
        char* str = val_bin(args[1], &sl);
        long long limit = argc > 2 ? val_to_int(args[2]) : LLONG_MAX;

        if (!sepl) fatal("explode(): Argument #1 ($separator) cannot be empty");
        if (limit == 0) limit = 1;

        /* split everything first; the limit rules are easier on the list */
        size_t np = 0, cap = 8;
        size_t* starts = malloc(cap * sizeof *starts);
        size_t* lens = malloc(cap * sizeof *lens);
        size_t p = 0;
        for (;;) {
            char* hit = memmem(str + p, sl - p, sep, sepl);
            if (np == cap) {
                cap *= 2;
                starts = realloc(starts, cap * sizeof *starts);
                lens = realloc(lens, cap * sizeof *lens);
            }
            starts[np] = p;
            lens[np] = hit ? (size_t)(hit - (str + p)) : sl - p;
            np++;
            if (!hit) break;
            p = (size_t)(hit - str) + sepl;
        }

        ArrBuild ab;
        ab_init(&ab);
        if (limit > 0) {
            size_t keep = (size_t)limit < np ? (size_t)limit : np;
            for (size_t i = 0; i < keep; i++) {
                /* the last kept piece runs to the end of the string */
                size_t l = (i + 1 == keep && keep < np) ? sl - starts[i] : lens[i];
                ab_push(&ab, v_str_n(str + starts[i], l));
            }
        } else {
            long long keep = (long long)np + limit;   /* drop the last -limit */
            for (long long i = 0; i < keep; i++) ab_push(&ab, v_str_n(str + starts[i], lens[i]));
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
        size_t gl;
        if (argc == 1) {
            if (args[0]->type != T_ARRAY)
                fatal("implode(): Argument #1 ($array) must be of type array");
            arr = args[0];
            glue = xstrdup("");
            gl = 0;
        } else {
            if (args[1]->type != T_ARRAY)
                fatal("implode(): Argument #2 ($array) must be of type ?array");
            arr = args[1];
            glue = val_bin(args[0], &gl);
        }

        Buf b;
        buf_init(&b);
        for (ArrayItem* it = arr->items; it; it = it->next) {
            if (it != arr->items) buf_add(&b, glue, gl);
            size_t pl;
            char* part = val_bin(it->val, &pl);
            buf_add(&b, part, pl);
            free(part);
        }
        free(glue);
        size_t total = b.len;
        return v_str_own(b.data ? b.data : xstrdup(""), total);
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
            for (ArrayItem* it = subj->items; it; it = it->next)
                ab_put(&ab, val_clone(it->key), str_replace_all(it->val, search, repl));
            return ab.arr;
        }
        return str_replace_all(subj, search, repl);
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
        size_t n;
        char* s = val_bin(args[0], &n);
        char* r = case_dup_n(s, n, 1);
        free(s);
        return v_str_own(r, n);
    }

    if (!strcmp(name, "strtolower")) {
        NEED(1);
        size_t n;
        char* s = val_bin(args[0], &n);
        char* r = case_dup_n(s, n, 0);
        free(s);
        return v_str_own(r, n);
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
            size_t bn = b.len;
            return v_str_own(b.data ? b.data : xstrdup(""), bn);
        }
        if (b.data) emit_bytes(b.data, b.len);
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

        /* a zero byte would cut the header short on the C side; PHP refuses
           the whole header with this warning, and so does this */
        if (has_nul(args[0])) {
            fprintf(stderr, "PHP warning: Header may not contain NUL bytes\n");
            return v_null();
        }
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

    if (!strcmp(name, "urlencode") || !strcmp(name, "rawurlencode")) {
        NEED(1);
        size_t n;
        char* s = val_bin(args[0], &n);
        char* e = url_encode_n(s, n, name[0] == 'r');   /* a zero byte becomes %00 */
        free(s);
        return v_str_own(e, strlen(e));         /* encoded output has no zero bytes */
    }

    if (!strcmp(name, "urldecode") || !strcmp(name, "rawurldecode")) {
        NEED(1);
        size_t n, dn;
        char* s = val_bin(args[0], &n);
        /* %00 becomes a zero byte; only urldecode() turns "+" into a space */
        char* d = url_decode_raw(s, n, &dn, name[0] != 'r');
        free(s);
        return v_str_own(d, dn);
    }

    if (!strcmp(name, "htmlspecialchars")) {
        NEED(1);
        size_t n, hn;
        char* s = val_bin(args[0], &n);
        char* h = html_escape_n(s, n, &hn);
        free(s);
        return v_str_own(h, hn);
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
        size_t len = slen(cont);

        if (idx < 0) idx += (long long)len;
        if (idx < 0 || idx >= (long long)len) return v_str("");

        return v_str_n(cont->s + idx, 1);          /* a zero byte is a byte */
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
        size_t len = slen(cont);

        if (idx < 0) idx += (long long)len;
        if (idx < 0 || idx >= (long long)len) fatal("Illegal string offset");

        size_t tl;
        char* tmp = val_bin(val, &tl);
        /* PHP 8: assigning "" to an offset is an error. It used to write a
           zero byte, which with binary-safe strings would silently put a
           NUL into the middle of the string. */
        if (!tl) { free(tmp); fatal("Cannot assign an empty string to a string offset"); }
        cont->s[idx] = tmp[0];
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
            return n->n ? v_str_n(n->s, n->n) : v_str(n->s);

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

        case NT_INCLUDE:
            return do_include(n, env);

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
    static const char* sg[] = { "_GET", "_POST", "_COOKIE", "_SESSION", "_SERVER", "_REQUEST", "_FILES", 0 };
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

/* ---------- include / require (milestone 3) ---------- */

/* Files already included, by REAL path, so include_once of "a.php",
   "./a.php" and "/full/path/a.php" all count as the same file. The main
   script is in the list too: include_once __FILE__ does nothing, as in PHP. */
static char** inc_seen = 0;
static int inc_n = 0, inc_cap = 0;

static int inc_was_seen(const char* real) {
    for (int i = 0; i < inc_n; i++) if (!strcmp(inc_seen[i], real)) return 1;
    return 0;
}

static void inc_mark(const char* real) {
    if (inc_n == inc_cap) {
        inc_cap = inc_cap ? inc_cap * 2 : 16;
        inc_seen = realloc(inc_seen, sizeof(char*) * (size_t)inc_cap);
    }
    inc_seen[inc_n++] = xstrdup(real);
}

static int readable_file(const char* p) {
    struct stat st;
    return stat(p, &st) == 0 && S_ISREG(st.st_mode) && access(p, R_OK) == 0;
}

/* PHP's search order:
     - an absolute path, or one starting "./" or "../", is used as given
       (the last two relative to the current directory)
     - anything else is looked for along include_path (PHPMINI_INCLUDE_PATH,
       colon-separated, default "."), then in the directory of the file
       that contains the include statement. */
static char* resolve_include(const char* path, const char* from_file) {
    if (!*path) return 0;
    if (path[0] == '/' || !strncmp(path, "./", 2) || !strncmp(path, "../", 3))
        return readable_file(path) ? xstrdup(path) : 0;

    const char* ip = getenv("PHPMINI_INCLUDE_PATH");
    if (!ip || !*ip) ip = ".";
    char cand[4096];
    const char* p = ip;
    while (*p) {
        const char* c = strchr(p, ':');
        size_t dl = c ? (size_t)(c - p) : strlen(p);
        if (dl) {
            snprintf(cand, sizeof cand, "%.*s/%s", (int)dl, p, path);
            if (readable_file(cand)) return xstrdup(cand);
        }
        if (!c) break;
        p = c + 1;
    }

    const char* sl = from_file ? strrchr(from_file, '/') : 0;
    if (sl) {
        snprintf(cand, sizeof cand, "%.*s/%s", (int)(sl - from_file), from_file, path);
        if (readable_file(cand)) return xstrdup(cand);
    }
    return 0;
}

/* Parse a whole file into a program. The lexer is global, and this runs in
   the MIDDLE of executing another file, so everything it holds -- source,
   position, current token, loop nesting, the file name -- is saved first
   and put back after, or the including file would resume parsing nonsense. */
static NodeList* parse_file_at(const char* real, char* code) {
    char* s_src = lex_src;
    size_t s_pos = lex_pos, s_len = lex_len;
    Token s_cur = cur;
    int s_loops = loop_depth;
    const char* s_file = parse_file;

    lex_src = code;
    lex_len = strlen(code);
    lex_pos = 0;
    loop_depth = 0;          /* a break in an included file cannot reach out */
    parse_file = real;
    adv();
    NodeList* prog = parse_program();

    lex_src = s_src;
    lex_pos = s_pos;
    lex_len = s_len;
    cur = s_cur;
    loop_depth = s_loops;
    parse_file = s_file;
    return prog;
}

static Value* do_include(Node* n, Env* env) {
    int once = n->i & 1, req = n->i & 2;
    const char* what = req ? (once ? "require_once" : "require") : (once ? "include_once" : "include");
    Value* pv = eval(n->a, env);
    char* path = val_to_string(pv);
    /* "secret\0.php" must not open "secret" -- PHP refuses it the same way */
    char* found = has_nul(pv) ? 0 : resolve_include(path, n->s);

    if (!found) {
        const char* ip = getenv("PHPMINI_INCLUDE_PATH");
        if (!ip || !*ip) ip = ".";
        /* include warns and carries on with false; require stops -- PHP's
           split, and its wording */
        if (!has_nul(pv))   /* PHP never tries to open a path with a zero byte */
            fprintf(stderr, "PHP warning: %s(%s): Failed to open stream: No such file or directory\n", what, path);
        if (req) fatal("Uncaught Error: Failed opening required '%s' (include_path='%s')", path, ip);
        fprintf(stderr, "PHP warning: %s(): Failed opening '%s' for inclusion (include_path='%s')\n", what, path, ip);
        free(path);
        return v_bool(0);
    }

    char* real = realpath(found, 0);
    if (!real) real = xstrdup(found);
    free(found);
    free(path);

    if (once && inc_was_seen(real)) { free(real); return v_bool(1); }
    if (!inc_was_seen(real)) inc_mark(real);

    FILE* fp = fopen(real, "rb");
    if (!fp) {
        if (req) fatal("Uncaught Error: Failed opening required '%s'", real);
        fprintf(stderr, "PHP warning: %s(%s): Failed to open stream\n", what, real);
        free(real);
        return v_bool(0);
    }
    char* raw = read_all(fp);
    fclose(fp);

    NodeList* prog = parse_file_at(real, preprocess_source(raw));
    hoist_functions(prog);

    /* The included code runs in the CURRENT scope -- inside a function its
       variables are that function's locals, as in PHP. A top-level return
       in the included file ends only that file, and is the include's value
       ($config = include "config.php"); otherwise the value is 1. */
    exec_list(prog, env);
    Value* r = v_int(1);
    if (in_ret) {
        r = ret_val ? ret_val : v_null();
        in_ret = 0;
        ret_val = 0;
    }
    return r;
}

static void exec_list(NodeList* l, Env* env) {
    for (; l && !in_ret && !brk_n && !cont_n; l = l->next)
        exec(l->node, env);
}

/* A function is registered twice for the same declaration -- once when its
   file is hoisted, once when execution reaches it -- and that is fine. A
   DIFFERENT declaration of the same name is PHP's fatal "Cannot redeclare",
   which matters now that a file can be included twice: before, the second
   definition silently replaced the first. */
static void register_func_node(Node* n) {
    char* lname = lower_dup(n->s);
    Func* old = find_func_lower(lname);
    if (old) {
        free(lname);
        if (old->def == n) return;
        fatal("Cannot redeclare function %s()", n->s);
    }
    Func* f = calloc(1, sizeof(Func));
    if (!f) fatal("out of memory");

    f->def = n;
    f->name = lname;
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
                size_t n;
                char* s = val_bin(v, &n);          /* every byte, zeros too */
                emit_bytes(s, n);
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
#ifdef MINIPHP_SODIUM
    if (sodium_init() < 0) fatal("libsodium could not be initialised");
#endif

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

        /* The main script's real path: __FILE__, and the first entry in the
           include_once list. */
        char* real = realpath(fname, 0);
        if (real) {
            parse_file = real;
            inc_mark(real);
            /* Under CGI, run from the script's own directory, as php-cgi and
               PHP-FPM do -- so include "lib.php", fopen("data.txt") and
               move_uploaded_file(..., "uploads/x") mean what they mean on a
               real PHP server, wherever the web server happened to start. */
            const char* rm = getenv("REQUEST_METHOD");
            if (rm && *rm) {
                char* d = xstrdup(real);
                char* sl = strrchr(d, '/');
                if (sl) { if (sl == d) sl[1] = 0; else *sl = 0; }
                if (chdir(d) != 0) { /* stay where we are */ }
                free(d);
            }
        }
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