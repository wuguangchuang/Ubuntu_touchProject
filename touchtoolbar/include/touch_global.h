#ifndef TOUCH_GLOBAL_H
#define TOUCH_GLOBAL_H

#include <QtCore/qglobal.h>

#if defined(TOUCH_LIBRARY)
#  define TOUCHSHARED_EXPORT Q_DECL_EXPORT
#else
#  define TOUCHSHARED_EXPORT Q_DECL_IMPORT
#endif

#endif // TOUCH_GLOBAL_H
