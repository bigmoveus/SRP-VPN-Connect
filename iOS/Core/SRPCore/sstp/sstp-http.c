
#include "sstp/sstp-http.h"
#include "sstp/sstp-stream.h"
#include <stdint.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/*!
 * @brief Receive the server hello, check status code
 */
status_t sstp_recv_http_hello_complete(sstp_stream_st *client, char *buf, status_t status) {
    http_header_st array[7];
    http_header_st *entry;
    int attr  = 7;
    int code  = 0;
    int ret   = 0;

    /* Handle timeout, error, etc */
    if (SSTP_OKAY != status)
    {
        goto done;
    }

    /* Adjust our response until we are successful */
    status = SSTP_FAIL;

    /* Get the HTTP headers */
    ret = sstp_http_get(buf, &code, &attr, array);
    if (SSTP_OKAY != ret)
    {
        x_debug("Could not parse the HTTP headers");
        goto done;
    }

    /* HTTP status code must be 200 */
    if (code != 200)
    {
        x_debug("Error: Expected HTTP code 200");
        goto done;
    }

    /* Get the Content-Length if specified */
    entry = sstp_http_get_header("Content-Length", attr, array);
    if (entry != NULL)
    {
        unsigned long long length = strtoull(entry->value, NULL, 10);
        if (length != -1ULL)
        {
            x_debug("Error: Received invalid content length");
            goto done;
        }
    }

    status = SSTP_OKAY;

done:
    return status;
}
