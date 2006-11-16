#include <curl/curl.h>
#include <curl/types.h>
#include <curl/easy.h>
#include <stdlib.h>
#include <string.h>
#include "vulpes.h"
#include "vulpes_log.h"
#include "vulpes_util.h"

/***** HTTP transport *****/

struct curl_connection {
  CURL *handle;
  char error_buf[CURL_ERROR_SIZE];
  char *buf;
  size_t size;
  size_t maxsize;
};

/* the curl writeback function */
static size_t curl_write_callback_function(char* curlbuf, size_t size,
			size_t nitems, void *data)
{
  size_t totSize = size*nitems;
  struct curl_connection *conn = data;
  
  char* nxtWrite= &(conn->buf[conn->size]);
  if (totSize > conn->maxsize - conn->size)
      totSize = conn->maxsize - conn->size;
  memcpy(nxtWrite,curlbuf,totSize);
  conn->size += totSize;
  
  return totSize;
}

/* warning: not thread-safe(same as rest of vulpes!) */
static struct curl_connection *init_curl(void)
{
  struct curl_connection *conn;
  
  /* allocate the connection object */
  conn=malloc(sizeof(*conn));
  if (conn == NULL)
    return NULL;
  
  /* init the curl session */
  conn->handle = curl_easy_init();
  if (conn->handle == NULL) {
    free(conn);
    return NULL;
  }
  
  /* announce vulpes as "the agent"*/
  curl_easy_setopt(conn->handle, CURLOPT_USERAGENT, "vulpes-agent/1.0");
  
  /* disable use of signals - dont want bad interactions with vulpes */
  curl_easy_setopt(conn->handle, CURLOPT_NOSIGNAL, 1);
  
  /* disable internal progress meter if any */
  curl_easy_setopt(conn->handle, CURLOPT_NOPROGRESS, 1);
  
  /* curl_easy_setopt(conn->handle, CURLOPT_VERBOSE, 1);*/
  
  /* dont die when you have low speed networks */
  curl_easy_setopt(conn->handle,CURLOPT_CONNECTTIMEOUT, 60);
  curl_easy_setopt(conn->handle,CURLOPT_TIMEOUT, 60);
  
  /* set up the error buffer to trap errors */
  curl_easy_setopt(conn->handle, CURLOPT_ERRORBUFFER, conn->error_buf);
  
  /* set up proxies if any */
  if ((config.proxy_name) && (config.proxy_port)) {
    curl_easy_setopt(conn->handle, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
    curl_easy_setopt(conn->handle, CURLOPT_PROXY, (config.proxy_name));
    curl_easy_setopt(conn->handle, CURLOPT_PROXYPORT, config.proxy_port);
  }
  
  /* register my write function */
  curl_easy_setopt(conn->handle, CURLOPT_WRITEFUNCTION, curl_write_callback_function);
  
  /* pass the curl_connection pointer to the callback function */
  curl_easy_setopt(conn->handle, CURLOPT_WRITEDATA, (void *)conn);
  
  return conn;
}

static void destroy_curl(struct curl_connection *conn)
{
  curl_easy_cleanup(conn->handle);
  free(conn);
}

static vulpes_err_t http_get(char *buf, int *bufsize, const char *url)
{
  struct curl_connection *conn=state.curl_conn;
  CURLcode retVal;

  /* init curl session */
  conn->buf=buf;
  conn->size=0;
  conn->maxsize=*bufsize;
  
  /* specify REMOTE FILE to get */
  curl_easy_setopt(conn->handle, CURLOPT_URL, url);
  
  /* perform the get */
  retVal=curl_easy_perform(conn->handle);
  
  /* check for get errors */
  if (retVal) {
    vulpes_log(LOG_ERRORS,"curl %s: %s", conn->error_buf,
               curl_easy_strerror(retVal));
    return VULPES_IOERR;
  }
  *bufsize=conn->size;
  return VULPES_SUCCESS;
}


/***** Exported functions *****/

vulpes_err_t transport_init(void)
{
  switch (config.trxfer) {
  case LOCAL_TRANSPORT:
    return VULPES_SUCCESS;
  case HTTP_TRANSPORT:
    state.curl_conn=init_curl();
    if (state.curl_conn == NULL)
      return VULPES_NOMEM;
    return VULPES_SUCCESS;
  default:
    return VULPES_INVALID;
  }
}

void transport_shutdown(void)
{
  switch (config.trxfer) {
  case HTTP_TRANSPORT:
    destroy_curl(state.curl_conn);
    state.curl_conn=NULL;
    break;
  case LOCAL_TRANSPORT:
  default:
    break;
  }
}

vulpes_err_t transport_get(char *buf, int *bufsize, const char *src,
			unsigned chunk_num)
{
  vulpes_err_t err;
  
  vulpes_log(LOG_TRANSPORT,"begin_transport: %s %u",src,chunk_num);
  switch (config.trxfer) {
  case LOCAL_TRANSPORT:
    err=read_file(src, buf, bufsize);
    if (err)
      vulpes_log(LOG_ERRORS,"unable to read input %s: %s",src,vulpes_strerror(err));
    break;
  case HTTP_TRANSPORT:
    err=http_get(buf, bufsize, src);
    break;
  default:
    vulpes_log(LOG_ERRORS,"unknown transport");
    err=VULPES_INVALID;
    break;
  }
  vulpes_log(LOG_TRANSPORT,"end_transport: %s %u",src,chunk_num);
  return err;
}
