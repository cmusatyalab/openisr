#include <curl/curl.h>
#include <curl/types.h>
#include <curl/easy.h>
#include <stdlib.h>
#include <string.h>
#include "vulpes_log.h"
#include "vulpes_map.h"

typedef struct curl_buffer_s {
  char *buf;
  size_t size;
  size_t maxsize;
} curl_buffer_t;
static CURL *curl_handle;
static curl_buffer_t* curl_buffer;
static char curl_error_buffer[CURL_ERROR_SIZE];

/* the curl writeback function */
/* XXX: should check for buffer overflows and report it back somehow */
static size_t curl_write_callback_function(char* curlbuf, size_t size,
			size_t nitems, void *myPtr)
{
  size_t totSize = size*nitems;
  curl_buffer_t* ptr = (curl_buffer_t *)myPtr;
  
  char* nxtWrite= &(ptr->buf[ptr->size]);
  if (totSize > ptr->maxsize - ptr->size)
      totSize = ptr->maxsize - ptr->size;
  memcpy(nxtWrite,curlbuf,totSize);
  ptr->size += totSize;
  
  return totSize;
}

/* warning: not thread-safe(same as rest of vulpes!) */
static void init_curl(const vulpes_mapping_t *map_ptr,
  		char *buf, int bufsize)
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
  if ( (map_ptr->proxy_name) && (map_ptr->proxy_port))
    {
      curl_easy_setopt(curl_handle, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
      curl_easy_setopt(curl_handle, CURLOPT_PROXY, (map_ptr->proxy_name));
      curl_easy_setopt(curl_handle, CURLOPT_PROXYPORT, map_ptr->proxy_port);
    }
  
  /* disable Nagle's algorithm 
     curl_easy_setopt(curl_handle, CURLOPT_TCP_NODELAY, 1);*/
  
  curl_buffer = (curl_buffer_t*) malloc(sizeof(curl_buffer_t));
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

int http_get(const vulpes_mapping_t *map_ptr, char *buf, int *bufsize,
	  	const char *url)
{
  CURLcode retVal;
  int retstatus=-1;

  /* init curl session */
  init_curl(map_ptr, buf, *bufsize);
  
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
  retstatus=0;

out:
  destroy_curl();
  return retstatus;
}
