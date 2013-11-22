#ifndef _LOG_H_
#define _LOG_H_

#ifdef	__cplusplus
extern "C" {
#endif

    int log_error_write(void *, const char *, unsigned int, const char *, ...);

#ifdef	__cplusplus
}
#endif

#endif	/* _LOG_H_ */
