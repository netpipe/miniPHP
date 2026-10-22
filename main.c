#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <stdarg.h>
#include <strings.h>

enum {
    T_NULL, T_INT, T_FLOAT, T_BOOL, T_STRING, T_ARRAY
};

enum {
    NT_ECHO, NT_ASSIGN, NT_IF, NT_WHILE, NT_FOR, NT_FUNC, NT_RETURN, NT_EXPR,
    NT_INT, NT_FLOAT, NT_STR, NT_BOOL, NT_NULL, NT_VAR, NT_BINOP, NT_UNOP,
    NT_CALL, NT_INDEX, NT_ARRAY
};

enum {
    OP_ADD, OP_SUB, OP_MUL, OP_DIV, OP_MOD, OP_CONCAT,
    OP_EQ, OP_NEQ, OP_LT, OP_GT, OP_LE, OP_GE,
    OP_SAME, OP_DIFF, OP_AND, OP_OR, OP_NOT, OP_NEG, OP_POS
};

enum {
    TK_EOF, TK_ECHO, TK_IF, TK_ELSEIF, TK_ELSE, TK_WHILE, TK_FOR,
    TK_FUNCTION, TK_RETURN, TK_TRUE, TK_FALSE, TK_NULL_KW, TK_ARRAY,
    TK_VAR, TK_IDENT, TK_INT, TK_FLOAT, TK_STR,
    TK_SEMI, TK_COMMA, TK_DOT, TK_ASSIGN, TK_EQEQ, TK_NEQ,
    TK_LT, TK_GT, TK_LE, TK_GE, TK_SAME, TK_DIFF,
    TK_LPAREN, TK_RPAREN, TK_LBRACE, TK_RBRACE, TK_LBRACK, TK_RBRACK,
    TK_ARROW, TK_BANG, TK_ANDAND, TK_OROR,
    TK_PLUS, TK_MINUS, TK_STAR, TK_SLASH, TK_PERCENT, TK_UNKNOWN
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
    Env* parent;
} Env;

typedef struct Token {
    int type;
    char* text;
    long long i;
    double d;
} Token;

static Func* funcs = 0;
static Value* ret_val = 0;
static int in_ret = 0;
static Env* global_env = 0;

static char* lex_src = 0;
static size_t lex_pos = 0, lex_len = 0;
static Token cur;

static void fatal(const char* fmt, ...);
static char* xstrdup(const char* s);
static char* lower_dup(const char* s);
static void sb_push(char** b, size_t* l, size_t* c, char ch);

static Node* parse_expr(void);
static Node* parse_statement(void);
static NodeList* parse_block(void);
static Pair* parse_array_items(int close);

static Value* eval(Node* n, Env* env);
static void exec(Node* n, Env* env);
static void exec_list(NodeList* l, Env* env);
static Value* call_user(Func* f, Value** args, int argc);
static Value* builtin(const char* name, Value** args, int argc);
static Value* eval_index(Value* cont, Value* key);
static void set_index(Value* cont, Value* key, Value* val);

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
    memcpy(r, s, n);
    return r;
}

static char* lower_dup(const char* s) {
    char* r = xstrdup(s);
    for (char* p = r; *p; p++) *p = (char)tolower((unsigned char)*p);
    return r;
}

static void sb_push(char** b, size_t* l, size_t* c, char ch) {
    if (*l + 1 >= *c) {
        *c *= 2;
        *b = realloc(*b, *c);
    }
    (*b)[(*l)++] = ch;
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
        size_t bcap = 32, blen = 0;
        char* buf = malloc(bcap);
        while (lex_pos < lex_len && lex_src[lex_pos] != quote) {
            if (lex_src[lex_pos] == '\\' && lex_pos + 1 < lex_len) {
                char e = lex_src[lex_pos + 1];
                lex_pos += 2;
                if (quote == '\'') {
                    if (e == '\\') sb_push(&buf, &blen, &bcap, '\\');
                    else if (e == '\'') sb_push(&buf, &blen, &bcap, '\'');
                    else {
                        sb_push(&buf, &blen, &bcap, '\\');
                        sb_push(&buf, &blen, &bcap, e);
                    }
                } else {
                    switch (e) {
                        case 'n': sb_push(&buf, &blen, &bcap, '\n'); break;
                        case 't': sb_push(&buf, &blen, &bcap, '\t'); break;
                        case 'r': sb_push(&buf, &blen, &bcap, '\r'); break;
                        case '\\': sb_push(&buf, &blen, &bcap, '\\'); break;
                        case '"': sb_push(&buf, &blen, &bcap, '"'); break;
                        case '\'': sb_push(&buf, &blen, &bcap, '\''); break;
                        case '0': sb_push(&buf, &blen, &bcap, '0'); break;
                        default:
                            sb_push(&buf, &blen, &bcap, '\\');
                            sb_push(&buf, &blen, &bcap, e);
                    }
                }
            } else {
                sb_push(&buf, &blen, &bcap, lex_src[lex_pos++]);
            }
        }
        if (lex_pos >= lex_len) fatal("Unterminated string");
        lex_pos++;
        buf[blen] = 0;
        t.type = TK_STR;
        t.text = buf;
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

static Node* new_node(int type) {
    Node* n = calloc(1, sizeof(Node));
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

static Node* parse_simple_stmt(void) {
    Node* e = parse_expr();
    if (cur.type == TK_ASSIGN) {
        adv();
        Node* v = parse_expr();
        if (e->type != NT_VAR && e->type != NT_INDEX) fatal("Invalid assignment");
        Node* n = new_node(NT_ASSIGN);
        n->a = e;
        n->b = v;
        return n;
    }
    Node* n = new_node(NT_EXPR);
    n->a = e;
    return n;
}

static Node* parse_statement(void) {
    switch (cur.type) {
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
            NodeList* body = parse_block();
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
            NodeList* body = parse_block();
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
            n->l2 = parse_block();
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
        default: {
            Node* e = parse_expr();
            if (cur.type == TK_ASSIGN) {
                adv();
                Node* v = parse_expr();
                expect(TK_SEMI, ";");
                if (e->type != NT_VAR && e->type != NT_INDEX) fatal("Invalid assignment");
                Node* n = new_node(NT_ASSIGN);
                n->a = e;
                n->b = v;
                return n;
            }
            expect(TK_SEMI, ";");
            Node* n = new_node(NT_EXPR);
            n->a = e;
            return n;
        }
    }
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

static Node* parse_postfix(void) {
    Node* e = parse_primary();
    while (match(TK_LBRACK)) {
        Node* idx = parse_expr();
        expect(TK_RBRACK, "]");
        Node* n = new_node(NT_INDEX);
        n->a = e;
        n->b = idx;
        e = n;
    }
    return e;
}

static Node* parse_unary(void) {
    if (match(TK_BANG)) return new_unop(OP_NOT, parse_unary());
    if (match(TK_MINUS)) return new_unop(OP_NEG, parse_unary());
    if (match(TK_PLUS)) return new_unop(OP_POS, parse_unary());
    return parse_postfix();
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

static Node* parse_expr(void) {
    return parse_or();
}

static Value* v_new(int type) {
    Value* v = calloc(1, sizeof(Value));
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
    memcpy(r, a, la);
    memcpy(r + la, b, lb);
    r[la + lb] = 0;
    return r;
}

static char* val_to_string(Value* v) {
    if (!v) return xstrdup("");
    char buf[64];
    switch (v->type) {
        case T_INT:
            snprintf(buf, sizeof buf, "%lld", v->i);
            return xstrdup(buf);
        case T_FLOAT:
            snprintf(buf, sizeof buf, "%g", v->d);
            return xstrdup(buf);
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

static long long val_to_int(Value* v) {
    if (!v) return 0;
    switch (v->type) {
        case T_INT: return v->i;
        case T_FLOAT: return (long long)v->d;
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
        long long x = a->i, y = b->i;
        switch (op) {
            case OP_ADD: return v_int(x + y);
            case OP_SUB: return v_int(x - y);
            case OP_MUL: return v_int(x * y);
            case OP_MOD: return v_int(y == 0 ? 0 : x % y);
            default: break;
        }
    }

    double x = val_to_double(a);
    double y = val_to_double(b);
    switch (op) {
        case OP_ADD: return v_float(x + y);
        case OP_SUB: return v_float(x - y);
        case OP_MUL: return v_float(x * y);
        case OP_DIV: return v_float(y == 0.0 ? 0.0 : x / y);
        case OP_MOD: {
            long long ix = (long long)x;
            long long iy = (long long)y;
            return v_int(iy == 0 ? 0 : ix % iy);
        }
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
            if (a && a->type == T_INT) return v_int(-a->i);
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

static char* case_dup(const char* s, int up) {
    char* r = xstrdup(s);
    for (char* p = r; *p; p++)
        *p = (char)(up ? toupper((unsigned char)*p) : tolower((unsigned char)*p));
    return r;
}

static void indent(int n) {
    for (int i = 0; i < n; i++) fputs("  ", stdout);
}

static void dump_value(Value* v, int d) {
    if (!v) {
        indent(d);
        printf("NULL\n");
        return;
    }
    indent(d);
    switch (v->type) {
        case T_NULL:
            printf("NULL\n");
            break;
        case T_INT:
            printf("int(%lld)\n", v->i);
            break;
        case T_FLOAT:
            printf("float(%g)\n", v->d);
            break;
        case T_BOOL:
            printf("bool(%s)\n", v->b ? "true" : "false");
            break;
        case T_STRING:
            printf("string(%zu) \"%s\"\n", strlen(v->s ? v->s : ""), v->s ? v->s : "");
            break;
        case T_ARRAY:
            printf("array(%d) {\n", array_count(v));
            for (ArrayItem* it = v->items; it; it = it->next) {
                char* ks = val_to_string(it->key);
                indent(d + 1);
                printf("[%s] =>\n", ks);
                free(ks);
                dump_value(it->val, d + 1);
            }
            indent(d);
            printf("}\n");
            break;
        default:
            printf("unknown\n");
    }
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
        dump_value(args[0], 0);
        return v_int(1);
    }
    if (!strcmp(name, "exit") || !strcmp(name, "die")) {
        if (argc > 0) {
            char* s = val_to_string(args[0]);
            fputs(s, stdout);
            free(s);
        }
        exit(0);
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

#undef NEED
    return 0;
}

static Env* new_env(Env* parent) {
    Env* e = calloc(1, sizeof(Env));
    e->parent = parent;
    return e;
}

static Var* env_find_current(Env* e, const char* name) {
    if (!e || !name) return 0;
    for (Var* v = e->vars; v; v = v->next)
        if (!strcmp(v->name, name)) return v;
    return 0;
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

static Value* call_user(Func* f, Value** args, int argc) {
    Env* env = new_env(global_env);
    int i = 0;
    for (NodeList* p = f->params; p; p = p->next, i++) {
        Value* av = (i < argc) ? val_clone(args[i]) : v_null();
        env_set(env, p->node->s, av);
    }

    exec_list(f->body, env);

    Value* r = v_null();
    if (in_ret) {
        r = ret_val ? ret_val : v_null();
        ret_val = 0;
        in_ret = 0;
    }
    return r;
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
            return eval_index(eval(n->a, env), eval(n->b, env));
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

static void exec_list(NodeList* l, Env* env) {
    for (; l && !in_ret; l = l->next)
        exec(l->node, env);
}

static void exec(Node* n, Env* env) {
    if (!n) return;

    switch (n->type) {
        case NT_ECHO:
            for (NodeList* l = n->l1; l; l = l->next) {
                Value* v = eval(l->node, env);
                char* s = val_to_string(v);
                fputs(s, stdout);
                free(s);
            }
            break;

        case NT_ASSIGN:
            if (n->a->type == NT_VAR) {
                Value* v = eval(n->b, env);
                env_set(env, n->a->s, val_clone(v));
            } else if (n->a->type == NT_INDEX) {
                Node* base = n->a->a;
                Value* cont;
                if (base->type == NT_VAR) {
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
                Value* key = eval(n->a->b, env);
                Value* val = eval(n->b, env);
                set_index(cont, key, val_clone(val));
            } else {
                fatal("Invalid assignment target");
            }
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
                if (in_ret) break;
                if (n->c) exec(n->c, env);
            }
            break;

        case NT_FUNC: {
            Func* f = calloc(1, sizeof(Func));
            f->name = lower_dup(n->s);
            f->params = n->l1;
            f->body = n->l2;
            f->next = funcs;
            funcs = f;
            break;
        }

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

static char* extract_php(char* in) {
    size_t n = strlen(in);
    char* out = malloc(n + 2);
    size_t j = 0, i = 0;
    int inside = 0, found = 0;

    while (i < n) {
        if (!inside && in[i] == '<' && i + 1 < n && in[i + 1] == '?') {
            found = 1;
            i += 2;
            if (i + 3 <= n && strncasecmp(in + i, "php", 3) == 0) i += 3;
            inside = 1;
            continue;
        }
        if (inside && in[i] == '?' && i + 1 < n && in[i + 1] == '>') {
            inside = 0;
            out[j++] = '\n';
            i += 2;
            continue;
        }
        out[j++] = in[i++];
    }
    out[j] = 0;

    if (!found) {
        free(out);
        return xstrdup(in);
    }
    return out;
}

static char* read_all(FILE* f) {
    size_t cap = 4096, len = 0;
    char* b = malloc(cap);
    int c;
    while ((c = fgetc(f)) != EOF) {
        if (len + 2 > cap) {
            cap *= 2;
            b = realloc(b, cap);
        }
        b[len++] = (char)c;
    }
    b[len] = 0;
    return b;
}

int main(int argc, char** argv) {
    FILE* f = (argc > 1) ? fopen(argv[1], "rb") : stdin;
    if (!f) {
        perror("open");
        return 1;
    }

    char* raw = read_all(f);
    if (argc > 1) fclose(f);

    char* code = extract_php(raw);
    lex_src = code;
    lex_len = strlen(code);
    lex_pos = 0;

    adv();
    NodeList* program = parse_program();

    Env* global = new_env(0);
    global_env = global;

    exec_list(program, global);
    return 0;
}