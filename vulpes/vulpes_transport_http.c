#include <curl/curl.h>
#include <curl/types.h>
#include <curl/easy.h>
#include <stdlib.h>
#include <string.h>
#include "vulpes.h"
#include "vulpes_log.h"

struct curl_buffer {
  char *buf;
  size_t size;
  size_t maxsize;
};
static CURL *curl_handle;
static struct curl_buffer *curl_buffer;
static char curl_error_buffer[CURL_ERROR_SIZE];

/* the curl writeback function */
/* XXX: should check for buffer overflows and report it back somehow */
static size_t curl_write_callback_function(char* curlbuf, size_t size,
			size_t nitems, void *myPtr)
{
  size_t totSize = size*nitems;
  struct curl_buffer *ptr = (struct curl_buffer *)myPtr;
  
  char* nxtWrite= &(ptr->buf[ptr->size]);
  if (totSize > ptr->maxsize - ptr->size)
      totSize = ptr->maxsize - ptr->size;
  memcpy(nxtWrite,curlbuf,totSize);
  ptr->size += totSize;
  
  return totSize;
}

/* warning: not thread-safe(same as rest of vulpes!) */
static void init_curl(char *buf, int bufsize)
{
  /* init the curl session */
  curl_handle = curl_easy_init();
  
  /* announce vulpes as "the agent"*/
  curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "vulpes-agent/1.0");
  
  /* disable use of signals - dont want bad interactions with vulpes */
  curl_easy_setopt(curl_handle, CURLOPT_NOSIGNAL, 1);
  
  /* disable internal progress meter if any */
  curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1);
  
  /* curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1);*/
  
  /* dont die when you have low speed networks */
  curl_easy_setopt(curl_handle,CURLOPT_CONNECTTIMEOUT, 60);
  curl_easy_setopt(curl_handle,CURLOPT_TIMEOUT, 60);
  
  /* set up the error buffer to trap errors */
  memset(curl_error_buffer, 0, CURL_ERROR_SIZE);
  curl_easy_setopt(curl_handle, CURLOPT_ERRORBUFFER, curl_error_buffer);
  
  /* set up proxies if any */
  if ((config.proxy_name) && (config.proxy_port)) {
    curl_easy_setopt(curl_handle, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
    curl_easy_setopt(curl_handle, CURLOPT_PROXY, (config.proxy_name));
    curl_easy_setopt(curl_handle, CURLOPT_PROXYPORT, config.proxy_port);
  }
  
  /* disable Nagle's algorithm 
     curl_easy_setopt(curl_handle, CURLOPT_TCP_NODELAY, 1);*/
  
  curl_buffer = (struct curl_buffer*) malloc(sizeof(struct curl_buffer));
  curl_buffer->size=0;
  curl_buffer->maxsize=bufsize;
  curl_buffer->buf=buf;
  
  /* register my write function */
  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, curl_write_callback_function);
  
  /* pass the curl_buffer as the place to write to in callback function */
  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)curl_buffer);
}

static void destroy_curl(void)
{
  curl_easy_cleanup(curl_handle);
  free(curl_buffer);
}

vulpes_err_t http_get(char *buf, int *bufsize, const char *url)
{
  CURLcode retVal;
  vulpes_err_t retstatus=VULPES_IOERR;

  /* init curl session */
  init_curl(buf, *bufsize);
  
  /* specify REMOTE FILE to get */
  curl_easy_setopt(curl_handle, CURLOPT_URL, url);
  
  /* perform the get */
  retVal=curl_easy_perform(curl_handle);
  
  /* check for get errors */
  if ((strlen(curl_error_buffer)!=0) || (retVal!=0)) {
    /* problems */
    vulpes_log(LOG_ERRORS,"HTTP_GET","curl %s: %s",
	       curl_error_buffer, curl_easy_strerror(retVal));
    goto out;
  }
  *bufsize=curl_buffer->size;
  retstatus=VULPES_SUCCESS;

out:
  destroy_curl();
  return retstatus;
}
