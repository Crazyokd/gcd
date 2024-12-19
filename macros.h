#ifndef GTP_MACROS_H_
#define GTP_MACROS_H_

#if defined _WIN32 || defined __CYGWIN__
  #ifdef BUILDING_DLL
    #ifdef __GNUC__
      #define GCD_PUBLIC __attribute__((dllexport))
    #else
      #define GCD_PUBLIC __declspec(dllexport)
    #endif
  #else
    #ifdef __GNUC__
      #define GCD_PUBLIC __attribute__((dllimport))
    #else
      #define GCD_PUBLIC __declspec(dllimport)
    #endif
  #endif
  #define GCD_LOCAL
#else
  #if __GNUC__ >= 4
    #define GCD_PUBLIC __attribute__((visibility("default")))
    #define GCD_LOCAL  __attribute__((visibility("hidden")))
  #else
    #define GCD_PUBLIC
    #define GCD_LOCAL
  #endif
#endif

#define MAX_MCC_SIZE         3
#define MAX_MNC_SIZE         3

#endif
