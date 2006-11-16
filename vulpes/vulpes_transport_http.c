#include <curl/curl.h>
#include <curl/types.h>
#include <curl/easy.h>
#include <stdlib.h>
#include <string.h>
#include "vulpes.h"
#include "vulpes_log.h"

struct curl_connection {
  CURL *handle;
  char *buf;
  size_t size;
  size_t maxsize;
  char error_buf[CURL_ERROR_SIZE];
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
static struct curl_connection *init_curl(char *buf, int bufsize)
{
  struct curl_connection *conn;
  
  /* allocate the connection object */
  conn=malloc(sizeof(*conn));
  if (conn == NULL)
    return NULL;
  memset(conn, 0, sizeof(*conn));
  
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
  
  conn->buf=buf;
  conn->maxsize=bufsize;
  
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

vulpes_err_t http_get(char *buf, int *bufsize, const char *url)
{
  struct curl_connection *conn;
  CURLcode retVal;
  vulpes_err_t retstatus=VULPES_IOERR;

  /* init curl session */
  conn=init_curl(buf, *bufsize);
  if (conn == NULL)
    return VULPES_NOMEM;
  
  /* specify REMOTE FILE to get */
  curl_easy_setopt(conn->handle, CURLOPT_URL, url);
  
  /* perform the get */
  retVal=curl_easy_perform(conn->handle);
  
  /* check for get errors */
  if ((strlen(conn->error_buf)!=0) || (retVal!=0)) {
    /* problems */
    vulpes_log(LOG_ERRORS,"curl %s: %s", conn->error_buf,
               curl_easy_strerror(retVal));
    goto out;
  }
  *bufsize=conn->size;
  retstatus=VULPES_SUCCESS;

out:
  destroy_curl(conn);
  return retstatus;
}
