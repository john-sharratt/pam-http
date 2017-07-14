// standard stuff
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// pam stuff
#include <security/pam_modules.h>

// libcurl
#include <curl/curl.h>

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE  1
#endif
#ifndef PAM_CONST
#define PAM_CONST const
#endif

#define DEBUG

/* expected hook */
PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
#ifdef DEBUG
    printf("pam-http::pam_sm_acct_mgmt - Acct mgmt\n");
#endif
    return PAM_SUCCESS;
}

/*
 * Makes getting arguments easier. Accepted arguments are of the form: name=value
 *
 * @param pName- name of the argument to get
 * @param argc- number of total arguments
 * @param argv- arguments
 * @return Pointer to value or NULL
 */
static const char* getArgStr(const char* pName, int argc, const char** argv) {
    int len = strlen(pName);
    int i;

    for (i = 0; i < argc; i++) {
        if (strncmp(pName, argv[i], len) == 0 && argv[i][len] == '=') {
            // only give the part url part (after the equals sign)
            return argv[i] + len + 1;
        }
    }
    return 0;
}

#ifdef DEBUG
static char* curl_error_to_string(int err) {
    switch (err) {
        case CURLE_OK:
            return "Ok";
        case CURLE_UNSUPPORTED_PROTOCOL:
            return "Unsupported Protocol";
        case CURLE_FAILED_INIT:
            return "Failed Init";
        case CURLE_URL_MALFORMAT:
            return "URL Malformat";
        case CURLE_NOT_BUILT_IN:
            return "Not Built In";
        case CURLE_COULDNT_RESOLVE_PROXY:
            return "Couldn't Resolve Proxy";
        case CURLE_COULDNT_RESOLVE_HOST:
            return "Couldn't Resolve Host";
        case CURLE_COULDNT_CONNECT:
            return "Couldn't Connect";
        case CURLE_FTP_WEIRD_SERVER_REPLY:
            return "FTP Weird Server Reply";
        case CURLE_REMOTE_ACCESS_DENIED:
            return "Remote Access Denied";
        case CURLE_FTP_ACCEPT_FAILED:
            return "FTP Accept Failed";
        case CURLE_FTP_WEIRD_PASS_REPLY:
            return "FTP Weird Pass Reply";
        case CURLE_FTP_ACCEPT_TIMEOUT:
            return "FTP Accept Timeout";
        case CURLE_FTP_WEIRD_PASV_REPLY:
            return "FTP Weird Passive Reply";
        case CURLE_FTP_WEIRD_227_FORMAT:
            return "FTP Weird 227 Format";
        case CURLE_FTP_CANT_GET_HOST:
            return "FTP Can't Get Host";
        case CURLE_OBSOLETE16:
            return "Obsolete 16";
        case CURLE_FTP_COULDNT_SET_TYPE:
            return "FTP Couldn't Set Type";
        case CURLE_PARTIAL_FILE:
            return "Partial File";
        case CURLE_FTP_COULDNT_RETR_FILE:
            return "FTP Couldn't Return File";
        case CURLE_OBSOLETE20:
            return "Obsolete 20";
        case CURLE_QUOTE_ERROR:
            return "Quote Error";
        case CURLE_HTTP_RETURNED_ERROR:
            return "HTTP Returned Error";
        case CURLE_WRITE_ERROR:
            return "Write Error";
        case CURLE_OBSOLETE24:
            return "Obsolete 24";
        case CURLE_UPLOAD_FAILED:
            return "Upload Failed";
        case CURLE_READ_ERROR:
            return "Read Error";
        case CURLE_OUT_OF_MEMORY:
            return "Out Of Memory";
        case CURLE_OPERATION_TIMEDOUT:
            return "Operation Timeout";
        case CURLE_OBSOLETE29:
            return "Obsolete 29";
        case CURLE_FTP_PORT_FAILED:
            return "FTP Port Failed";
        case CURLE_FTP_COULDNT_USE_REST:
            return "FTP Couldn't Use REST";
        case CURLE_OBSOLETE32:
            return "Obsolete 32";
        case CURLE_RANGE_ERROR:
            return "Range Error";
        case CURLE_HTTP_POST_ERROR:
            return "HTTP Post Error";
        case CURLE_SSL_CONNECT_ERROR:
            return "SSL Connect Error";
        case CURLE_BAD_DOWNLOAD_RESUME:
            return "Bad Download Resume";
        case CURLE_FILE_COULDNT_READ_FILE:
            return "File Couldn't Read File";
        case CURLE_LDAP_CANNOT_BIND:
            return "LDAP Cannot Bind";
        case CURLE_LDAP_SEARCH_FAILED:
            return "LDAP Search Failed";
        case CURLE_OBSOLETE40:
            return "Obsolete 40";
        case CURLE_FUNCTION_NOT_FOUND:
            return "Function Not Found";
        case CURLE_ABORTED_BY_CALLBACK:
            return "Aborted By Callback";
        case CURLE_BAD_FUNCTION_ARGUMENT:
            return "Bad Function Argument";
        case CURLE_OBSOLETE44:
            return "Obsolete 44";
        case CURLE_INTERFACE_FAILED:
            return "Interface Failed";
        case CURLE_OBSOLETE46:
            return "Obsolete 46";
        case CURLE_TOO_MANY_REDIRECTS:
            return "Too Many Redirects";
        case CURLE_UNKNOWN_OPTION:
            return "Unknown Option";
        case CURLE_TELNET_OPTION_SYNTAX:
            return "Telnet Option Syntax";
        case CURLE_OBSOLETE50:
            return "Obsolete 50";
        case CURLE_PEER_FAILED_VERIFICATION:
            return "Peer Failed Verification";
        case CURLE_GOT_NOTHING:
            return "Got Nothing";
        case CURLE_SSL_ENGINE_NOTFOUND:
            return "SSL Engine Not Found";
        case CURLE_SSL_ENGINE_SETFAILED:
            return "SSL Engine Set Failed";
        case CURLE_SEND_ERROR:
            return "Send Error";
        case CURLE_RECV_ERROR:
            return "Receive Error";
        case CURLE_OBSOLETE57:
            return "Obsolete 57";
        case CURLE_SSL_CERTPROBLEM:
            return "SSL Certificate Problem";
        case CURLE_SSL_CIPHER:
            return "SSL Couldn't Use The Specified Cipher";
        case CURLE_SSL_CACERT:
            return "SSL Problem With The CA Certificate";
        case CURLE_BAD_CONTENT_ENCODING:
            return "BAD Content Encoding";
        case CURLE_LDAP_INVALID_URL:
            return "LDAP Invalid UURL";
        case CURLE_FILESIZE_EXCEEDED:
            return "File size Exceeded";
        case CURLE_USE_SSL_FAILED:
            return "Use SSL Failed";
        case CURLE_SEND_FAIL_REWIND:
            return "Send Fail Rewind";
        case CURLE_SSL_ENGINE_INITFAILED:
            return "SSL Engine Initialization Failed";
        case CURLE_LOGIN_DENIED:
            return "Login Denied";
        case CURLE_TFTP_NOTFOUND:
            return "TFTP Not Found";
        case CURLE_TFTP_PERM:
            return "TFTP Perm";
        case CURLE_REMOTE_DISK_FULL:
            return "Remote Disk Full";
        case CURLE_TFTP_ILLEGAL:
            return "TFTP Illegal";
        case CURLE_TFTP_UNKNOWNID:
            return "TFTP Unknown ID";
        case CURLE_REMOTE_FILE_EXISTS:
            return "Remote File Exists";
        case CURLE_TFTP_NOSUCHUSER:
            return "TFTP No Such User";
        case CURLE_CONV_FAILED:
            return "Conversion Failed";
        case CURLE_CONV_REQD:
            return "Called Must Register Conversion";
        case CURLE_SSL_CACERT_BADFILE:
            return "SSL CA Certificate Bad File";
        case CURLE_REMOTE_FILE_NOT_FOUND:
            return "Remote File Not Found";
        case CURLE_SSH:
            return "SSH Error";
        case CURLE_SSL_SHUTDOWN_FAILED:
            return "SSL Shutdown Failed";
        case CURLE_AGAIN:
            return "Not Ready Try Again";
        case CURLE_SSL_CRL_BADFILE:
            return "SSL CRL Bad File";
        case CURLE_SSL_ISSUER_ERROR:
            return "SSL Issuer Error";
        case CURLE_FTP_PRET_FAILED:
            return "FTP Pret Failed";
        case CURLE_RTSP_CSEQ_ERROR:
            return "RTSP CSEQ Error";
        case CURLE_RTSP_SESSION_ERROR:
            return "RTSP Session Error";
        case CURLE_FTP_BAD_FILE_LIST:
            return "FTP Bad File List";
        case CURLE_CHUNK_FAILED:
            return "Chunk Failed";
        case CURL_LAST:
        default:
            return "Unknown";
    }
}
#endif

/*
 * Makes getting arguments easier. Accepted arguments are of the form: name=value
 *
 * @param pName- name of the argument to get
 * @param argc- number of total arguments
 * @param argv- arguments
 * @return Pointer to value or NULL
 */
static int getArgBoolean(const char* pName, int argc, const char** argv) {
    int len = strlen(pName);
    int i;

    for (i = 0; i < argc; i++) {
        if (strncmp(pName, argv[i], len) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

/*
 * Function to handle stuff from HTTP response.
 *
 * @param buf- Raw buffer from libcurl.
 * @param len- number of indices
 * @param size- size of each index
 * @param userdata- any extra user data needed
 * @return Number of bytes actually handled. If different from len * size, curl will throw an error
 */
static int writeFn(void* buf, size_t len, size_t size, void* userdata) {
    return len * size;
}

static char *replace_str(const char *str, const char *orig, const char *rep)
{
    char buffer[4096];
    if (strlen(str) + strlen(orig) + strlen(rep)+ 2 > 4096)
        return NULL;

    char *p;
    if(!(p = strstr(str, orig)))  // Is 'orig' even in 'str'?
    {
#ifdef DEBUG
        printf("pam-http::replace_str() URL replace field - no match (search=%s)\n", orig);
#endif
        return strdup(str);
    }

    strncpy(buffer, str, p-str); // Copy characters from 'str' start to 'orig' st$
    buffer[p-str] = '\0';
    
    sprintf(buffer+(p-str), "%s%s", rep, p+strlen(orig));

    return strdup(buffer);
}

static int converse(pam_handle_t *pamh, int nargs,
                    PAM_CONST struct pam_message **message,
                    struct pam_response **response) {
    struct pam_conv *conv;
    int retval = pam_get_item(pamh, PAM_CONV, (void *)&conv);
    if (retval != PAM_SUCCESS) {
        return retval;
    }
    return conv->conv(nargs, message, response, conv->appdata_ptr);
}

static char *request_pass(pam_handle_t *pamh, int echocode, PAM_CONST char *prompt) {
    // Query user for verification code
    PAM_CONST struct pam_message msg = { .msg_style = echocode,
                                         .msg       = prompt };
    PAM_CONST struct pam_message *msgs = &msg;
    struct pam_response *resp = NULL;
    int retval = converse(pamh, 1, &msgs, &resp);
    char *ret = NULL;
    
    if (retval != PAM_SUCCESS || resp == NULL || resp->resp == NULL ||
        *resp->resp == '\000')
    {
        if (retval == PAM_SUCCESS && resp && resp->resp) {
            ret = resp->resp;
        }
    } else {
        ret = resp->resp;
    }

    // Deallocate temporary storage
    if (resp) {
        if (!ret) {
            free(resp->resp);
        }
        free(resp);
    }

    return ret;
}

static int invokeHttpService(const char* pUrl, const char* pUsername, const char* pPassword, const char* pCode, int bBasicAuth) {
#ifdef DEBUG
    if (pCode != NULL && strlen(pCode) > 0) {
        printf("pam-http::invokeHttpService() url=%s, username=%s, password=[hidden], code=[hidden]\n", pUrl, pUsername);
    } else {
        printf("pam-http::invokeHttpService() url=%s, username=%s, password=[hidden]\n", pUrl, pUsername);
    }
#endif

    CURL* pCurl = curl_easy_init();
    if (!pCurl) {
#ifdef DEBUG
        printf("pam-http::invokeHttpService() curl_easy_init - failed\n");
#endif
        return PAM_SERVICE_ERR;
    }

    char* pUserPass = NULL;
    if (bBasicAuth == TRUE && pUsername != NULL && pPassword != NULL) {
        int len = strlen(pUsername) + strlen(pPassword) + 2; // : separator & trailing null
        pUserPass = malloc(len + 512);
        sprintf(pUserPass, "%s:%s", pUsername, pPassword);
    }

    char *pUrlMorphed1 = NULL;
    char *pUrlMorphed2 = NULL;
    char *pUrlMorphed3 = NULL;

    pUrlMorphed1 = replace_str(pUrl, "{username}", pUsername != NULL ? pUsername : "");
    if (!pUrlMorphed1) {
#ifdef DEBUG
        printf("pam-http::invokeHttpService() failed to inject username into URL\n");
#endif
        return PAM_CRED_INSUFFICIENT;
    }
    
    pUrlMorphed2 = replace_str(pUrlMorphed1, "{password}", pPassword != NULL ? pPassword : "");
    if (!pUrlMorphed2) {
#ifdef DEBUG
        printf("pam-http::invokeHttpService() failed to inject password into URL\n");
#endif
        free(pUrlMorphed1);
        return PAM_CRED_INSUFFICIENT;
    }
    
    pUrlMorphed3 = replace_str(pUrlMorphed2, "{code}", pCode != NULL ? pCode : "");
    if (!pUrlMorphed3) {
#ifdef DEBUG
        printf("pam-http::invokeHttpService() failed to inject code into URL\n");
#endif
        free(pUrlMorphed1);
        free(pUrlMorphed2);
        return PAM_CRED_INSUFFICIENT;
    }

    curl_easy_setopt(pCurl, CURLOPT_URL, pUrlMorphed3);
    curl_easy_setopt(pCurl, CURLOPT_WRITEFUNCTION, writeFn);
    if (pUserPass != NULL) {
        curl_easy_setopt(pCurl, CURLOPT_USERPWD, pUserPass);
    }
    curl_easy_setopt(pCurl, CURLOPT_NOPROGRESS, 1);
    curl_easy_setopt(pCurl, CURLOPT_FAILONERROR, 1);
    curl_easy_setopt(pCurl, CURLOPT_TIMEOUT, 10);

    curl_easy_setopt(pCurl, CURLOPT_RANDOM_FILE, "/dev/urandom");
    curl_easy_setopt(pCurl, CURLOPT_SSL_VERIFYPEER, 0);
    curl_easy_setopt(pCurl, CURLOPT_SSL_VERIFYHOST, 2);
    curl_easy_setopt(pCurl, CURLOPT_USE_SSL, CURLUSESSL_ALL);

    int res = curl_easy_perform(pCurl);

    if (pUserPass != NULL) {
        memset(pUserPass, '\0', strlen(pUserPass));
        free(pUserPass);
        pUserPass = NULL;
    }
    if (pUrlMorphed1 != NULL) {
        memset(pUrlMorphed1, '\0', strlen(pUrlMorphed1));
        free(pUrlMorphed1);
        pUrlMorphed1 = NULL;
    }
    if (pUrlMorphed2 != NULL) {
        memset(pUrlMorphed2, '\0', strlen(pUrlMorphed2));
        free(pUrlMorphed2);
        pUrlMorphed2 = NULL;
    }
    if (pUrlMorphed3 != NULL) {
        memset(pUrlMorphed3, '\0', strlen(pUrlMorphed3));
        free(pUrlMorphed3);
        pUrlMorphed3 = NULL;
    }
    
    // Get the HTTP code
    long http_code = 0;
    curl_easy_getinfo(pCurl, CURLINFO_RESPONSE_CODE, &http_code);
#ifdef DEBUG
    printf("pam-http::invokeHttpService() http_code=%d\n", (int)http_code);
#endif
    
    // Cleanup
    curl_easy_cleanup(pCurl);
    
    // Check for errors
    if (res != 0) {
#ifdef DEBUG
        printf("pam-http::invokeHttpService() error - %s\n", curl_error_to_string(res));
#endif
        return PAM_SERVICE_ERR;
    }
    
    // Check the response code
    if (http_code >= 200 && http_code < 300) {
        return PAM_SUCCESS;
    } else {
        return PAM_PERM_DENIED;
    }
}

/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t* pamh, int flags, int argc, const char **argv)
{
    const char* pUsername = NULL;
    char*       pPassword = NULL;
    char*       pCode = NULL;
    const char* pUrl = NULL;
    
    int bBasicAuth = FALSE;
    int bRequestCode = FALSE;
    int bNullOk = FALSE;

#ifdef DEBUG
    printf("pam-http::pam_sm_authenticate() invoked\n");
#endif
    
    int ret = pam_get_user(pamh, &pUsername, NULL);
    if (ret != PAM_SUCCESS) {
#ifdef DEBUG
        printf("pam-http::pam_sm_authenticate() failed to get username [ret=%d]\n", ret);
#endif
        return ret;
    }
#ifdef DEBUG
    printf("pam-http::pam_sm_authenticate() username='%s'\n", pUsername);
#endif

    pUrl = getArgStr("url", argc, argv);
    if (!pUrl) {
#ifdef DEBUG
        printf("pam-http::pam_sm_authenticate() url = '%s'\n", pUrl);
#endif
        return PAM_AUTH_ERR;
    }

    bBasicAuth = getArgBoolean("basicauth", argc, argv);
#ifdef DEBUG
    printf("pam-http::pam_sm_authenticate() basicauth=%d\n", bBasicAuth);
#endif

    bRequestCode = getArgBoolean("requestcode", argc, argv);
#ifdef DEBUG
    printf("pam-http::pam_sm_authenticate() requestcode=%d\n", bRequestCode);
#endif

    bNullOk = getArgBoolean("nullok", argc, argv);
#ifdef DEBUG
    printf("pam-http::pam_sm_authenticate() nullok=%d\n", bNullOk);
#endif
    
    pPassword = request_pass(pamh, PAM_PROMPT_ECHO_OFF, "Password: ");
    if (!pPassword) {
#ifdef DEBUG
        printf("pam-http::pam_sm_authenticate() failed to read password\n");
#endif
        return PAM_CONV_ERR;
    }
#ifdef DEBUG
    printf("pam-http::pam_sm_authenticate() password=[hidden]\n");
#endif

    if (bRequestCode == TRUE) {
        pCode = request_pass(pamh, PAM_PROMPT_ECHO_OFF, "Verification code: ");
        if (!pCode && bNullOk == FALSE)  {
#ifdef DEBUG
            printf("pam-http::pam_sm_authenticate() failed to read vertification code\n");
#endif
            ret = PAM_CONV_ERR;
        }
#ifdef DEBUG
        printf("pam-http::pam_sm_authenticate() code=[hidden]\n");
#endif
    }

    // Perform the authentication check
    ret = invokeHttpService(pUrl, pUsername, pPassword, pCode, bBasicAuth);

    if (pPassword != NULL) {
        memset(pPassword, 0, strlen(pPassword));
        free(pPassword);
        pPassword = NULL;
    }
    if (pCode != NULL) {
        memset(pCode, 0, strlen(pCode));
        free(pCode);
        pCode = NULL;
    }

#ifdef DEBUG
    printf("pam-http::pam_sm_authenticate() ret=%d\n", ret);
#endif
    return ret;
}
