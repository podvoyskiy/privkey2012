#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <gost_lcl.h>
#include <gosthash2012.h>

#define MAX_BUF_SIZE 8192
#define MAX_PATH_LEN 2048

#define ERROR(msg) fprintf(stderr,"ERROR: %s\n",msg)

/* Packet structure for handling binary data streams */
typedef struct {
  unsigned char* data;  /* Pointer to data buffer */
  int size;             /* Current data size */
  int limit;            /* Maximum buffer capacity */
  int pos;              /* Current read/write position */
  int ovf;              /* Overflow flag */
} packet_t;

void pkt_init(packet_t *p,unsigned char* buf,int buf_size) {
  if (!p || !buf || buf_size <= 0) return;
  p->data=buf;
  p->size=0;
  p->limit=buf_size;
  p->pos=0;
  p->ovf=0;
}

int pkt_is_end(packet_t *p) { return p->pos>=p->size; }

int pkt_bytes_left(packet_t *p) { return p->size-p->pos; }

int pkt_get_byte(packet_t *p) { return p->pos<p->size ? p->data[p->pos++] : 0; }

int pkt_put(packet_t *p,int v) {
  if (p->pos >= p->size) {
    if (p->size >= p->limit) return p->ovf = 1;
    p->size++;
  }
  p->data[p->pos++] = v;
  return p->ovf;
}

int pkt_skip(packet_t *p,int size) {
  if (size>0) {
    p->pos+=size;
    if (p->pos>p->size) { p->ovf=1; p->pos=p->size; }
  }
  return p->ovf;
}

void pkt_sub(packet_t* dst,packet_t *src,int size) {
  *dst=*src;
  dst->size=src->pos+size;
  if (dst->size>src->size) { dst->size=src->size; dst->ovf=1; }
}

int pkt_readfile(packet_t* p,const char* name) {
  FILE *f;
  f=fopen(name,"rb"); if (!f) return 2;
  fseek(f,0,SEEK_END);
  if (ftell(f)>p->limit) p->ovf=1; 
  fseek(f,0,SEEK_SET);
  p->size=fread(p->data,1,p->limit,f);
  p->pos=0;
  fclose(f);
  return p->ovf;
}

int asn1_len(packet_t *p) {
  int x,r;
  x=pkt_get_byte(p);
  if (x<128) return x;
  x&=127;
  for(r=0;x>0;--x) {
    r<<=8;
    r|=pkt_get_byte(p);
  }
  return r;
}

int asn1_num(packet_t *p) {
  int x,r=0;
  do { 
    x=pkt_get_byte(p);
    r=(r<<7)|(x&127);
  } while(x&128);
  return r;
}

typedef struct {
  int level, index;
  int value;
  int is_composite;
  int position;
  int class;
  int type;
  int length;
  packet_t body[1];
} asn1_parser_tag_t;

typedef struct {
  void *tag_ctx;
  int (*tag)(void* ctx,asn1_parser_tag_t* tag);
} asn1_parser_cfg_t;

/* Main ASN.1 parser - processes nested ASN.1 structures */
static int asn1_parse_tag(packet_t *p, asn1_parser_cfg_t *cfg, asn1_parser_tag_t *parent, int stream) {
  enum {
    ASN1_MASK_MULTI=0x20, ASN1_MASK_TYPE=0x1F,
    ASN1_MASK_CLASS=0xC0, ASN1_SHIFT_CLASS=6,
    ASN1_TYPE_NULL=5, ASN1_CLASS_UNIVERSAL=0
  };
  asn1_parser_tag_t tag[1];packet_t ps[1];int rc;

  tag->index=0;
  tag->level=parent ? parent->level+1 : 0;
  while(!pkt_is_end(p)) {
    if (stream) {
      if (p->pos+1<p->size && p->data[p->pos]==0 && p->data[p->pos+1]==0) {
        p->pos+=2; break;
      }
    }
    tag->position=p->pos;
    tag->value=pkt_get_byte(p);
    tag->type=tag->value&ASN1_MASK_TYPE;
    if (tag->type==ASN1_MASK_TYPE) tag->type=asn1_num(p);
    tag->class=(tag->value&ASN1_MASK_CLASS)>>ASN1_SHIFT_CLASS;
    tag->is_composite=tag->value&ASN1_MASK_MULTI;
    tag->length=asn1_len(p);
    if (tag->length==0 &&
      !(tag->type==ASN1_TYPE_NULL && tag->class==ASN1_CLASS_UNIVERSAL)) 
    {
      pkt_sub(ps,p,pkt_bytes_left(p));
      if (tag->is_composite) rc=asn1_parse_tag(ps,cfg,tag,1); else {
        for(rc=2;ps->pos<ps->size;) {
          while(ps->pos<ps->size && ps->data[ps->pos]!=0) ps->pos++;
          if (ps->pos+1<ps->size && ps->data[++ps->pos]==0) {
            ps->pos++; rc=0; break;
          }
        }
      }
      if (rc) return rc;
      tag->length=ps->pos-p->pos-2;
      pkt_sub(tag->body,p,tag->length);
      rc=cfg->tag(cfg->tag_ctx,tag); if (rc) return rc;
      p->pos=ps->pos;
    } else {
      pkt_sub(tag->body,p,tag->length);
      rc=cfg->tag(cfg->tag_ctx,tag); if (rc) return rc;
      if (tag->is_composite) {
        pkt_sub(tag->body,p,tag->length);
        rc=asn1_parse_tag(tag->body,cfg,tag,0); if (rc) return rc;
      }
      pkt_skip(p,tag->length);
    }
    tag->index++;
    if (tag->level==0) break;
  }
  return 0;
}
int asn1_parse(packet_t *p,asn1_parser_cfg_t *cfg) { 
  return asn1_parse_tag(p,cfg,0,0);
}

typedef struct {
  int cert_len;
  unsigned char *cert;
  void *trace_ctx; void (*trace)(void *ctx,const char* fmt,...);
} my_data_t;

#ifdef CFG_DEBUG
static void trace_body(packet_t *src,my_data_t *data) {
  enum { w=16 };
  int a,i,n; unsigned char line[w];
  packet_t p[1];
  if (!data->trace) return;

  for(a=0;!pkt_is_end(p);a+=w) {
    for(n=0;!pkt_is_end(p) && n<w;++n) line[n]=pkt_get_byte(p);
    data->trace(data->trace_ctx,"\n\t\t%04X:",a);
    for(i=0;i<n;i++) data->trace(data->trace_ctx," %02X",line[i]);
    for(;i<w;++i) data->trace(data->trace_ctx,"   ");
    data->trace(data->trace_ctx," |");
    for(i=0;i<n;i++) data->trace(data->trace_ctx,"%c",
      line[i]>=32 && line[i]<127 ? line[i] : '.');
    for(;i<w;++i) data->trace(data->trace_ctx," ");
    data->trace(data->trace_ctx,"|");
  }
}

static int dump_handler(void* ctx, const asn1_parser_tag_t *tag) {
  my_data_t *data;
  data=(my_data_t*)ctx;
  data->trace(data->trace_ctx,"%04d\t",tag->position);
  {int i;for(i=0;i<tag->level;++i) data->trace(data->trace_ctx,"  ");}
  data->trace(data->trace_ctx,"L%d class=%d type=%d size=%d ",tag->level,
    tag->class,tag->type,pkt_bytes_left(tag->body));
  if (!tag->is_composite) trace_body(tag->body,data);
  data->trace(data->trace_ctx,"\n");
  return 0;
}
#endif

/* Extracts certificate from ASN.1 structure */
static int header_handler(void* ctx,asn1_parser_tag_t *tag) {
  enum {
    CLASS_CONTEXT_SPECIFIC = 2,
    CERTIFICATE_TAG = 5
  };

  my_data_t *data;
  data=(my_data_t*)ctx;
  #ifdef CFG_DEBUG
  dump_handler(ctx,tag);
  #endif
  if (tag->class==CLASS_CONTEXT_SPECIFIC) {
    if (tag->type==CERTIFICATE_TAG) {
      data->cert=tag->body->data+tag->body->pos;
      data->cert_len=pkt_bytes_left(tag->body);
    }
  }
  return 0;
}

static int print_cert(my_data_t *data,FILE* output) {
  BIO *bio; int rc = 0;

  bio=BIO_new_fp(output,BIO_NOCLOSE|BIO_FP_TEXT);
  if (!bio) { ERROR("no bio"); rc=1; goto err; }
  
  if (data->cert && data->cert_len > 0) {
    if (!PEM_write_bio(bio,"CERTIFICATE","",data->cert,data->cert_len)) {
      ERROR("write failed");
      rc = 4;
    }
  } else {
    ERROR("no certificate data");
    rc=2;
  }
  
err:
  if (bio) BIO_free(bio);
  return rc;
}

static void dbg_trace(void* ctx,const char* fmt,...) {
  va_list v; va_start(v,fmt); vfprintf(stderr,fmt,v); va_end(v);
}

/* Main function to extract certificate from file */
int get_cert(const char* path) {
  enum { buf_size=MAX_BUF_SIZE };
  unsigned char buf[buf_size];
  packet_t header[1];
  asn1_parser_cfg_t cfg[1];
  my_data_t data[1]; int rc;
  enum { max_fn=MAX_PATH_LEN }; char fn[max_fn];

  memset(data,0,sizeof(*data));
  data->trace_ctx=0;
  data->trace=dbg_trace;
  cfg->tag_ctx=data;

  cfg->tag=header_handler;
  pkt_init(header,buf,buf_size);
  if (snprintf(fn, MAX_PATH_LEN, "%s%cheader.key", path, '/') >= MAX_PATH_LEN) {
    ERROR("path too long");
    return 1;
  }
  #ifdef CFG_DEBUG
  data->trace(data->trace_ctx,"[%s]\n",fn);
  #endif
  if (pkt_readfile(header,fn)) { ERROR("read header"); rc=1; goto err; }
  if (asn1_parse(header,cfg)) { ERROR("parse header"); rc=2; goto err; }

  if (print_cert(data,stdout)) { ERROR("print"); rc=3; goto err; }
  rc=0;
  
err:
  return rc;
}

int main(int argc,char** argv) {
  if (argc<2) {
    fprintf(stderr,"storage not found\n");
    return -1;
  }
  return get_cert(argv[1]);
}