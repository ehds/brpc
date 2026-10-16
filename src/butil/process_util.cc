// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

// Process-related Info

// Date: Wed Apr 11 14:35:56 CST 2018

#include <fcntl.h>                      // open
#include <string.h>                     // memcpy, strnlen
#include <sys/types.h>  
#include <sys/uio.h>
#include <unistd.h>                     // read, getpid
#include "butil/fd_guard.h"             // butil::fd_guard
#include "butil/logging.h"
#include "butil/process_util.h"

#if defined(OS_MACOSX)
#include <crt_externs.h>                // _NSGetArgc, _NSGetArgv
#include <libproc.h>                   // proc_pidpath
#endif
namespace butil {

ssize_t ReadCommandLine(char* buf, size_t len, bool with_args) {
#if defined(OS_LINUX)
    butil::fd_guard fd(open("/proc/self/cmdline", O_RDONLY));
    if (fd < 0) {
        LOG(ERROR) << "Fail to open /proc/self/cmdline";
        return -1;
    }
    ssize_t nr = read(fd, buf, len);
    if (nr <= 0) {
        LOG(ERROR) << "Fail to read /proc/self/cmdline";
        return -1;
    }
    if (with_args) {
        if ((size_t)nr == len) {
            return len;
        }
        for (ssize_t i = 0; i < nr; ++i) {
            if (buf[i] == '\0') {
                buf[i] = '\n';
            }
        }
        return nr;
    } else {
        for (ssize_t i = 0; i < nr; ++i) {
            if (buf[i] == '\0' || buf[i] == '\n' || buf[i] == ' ') {
                return i;
            }
        }
        if ((size_t)nr == len) {
            LOG(ERROR) << "buf is not big enough";
            return -1;
        }
        return nr;
    }
#elif defined(OS_MACOSX)
    const int argc = *_NSGetArgc();
    char* const* argv = *_NSGetArgv();
    if (argc <= 0 || !argv || !argv[0]) {
        LOG(ERROR) << "Fail to read cmdline";
        return -1;
    }
    if (!with_args) {
        const size_t nr = strnlen(argv[0], len);
        if (nr == len) {
            LOG(ERROR) << "buf is not big enough";
            return -1;
        }
        if (nr != 0) memcpy(buf, argv[0], nr);
        return nr;
    }
    size_t nr = 0;
    // A flag parser may compact argv without updating the runtime argc.
    for (int i = 0; i < argc && argv[i] && nr < len; ++i) {
        const size_t size = strnlen(argv[i], len - nr);
        if (size != 0) memcpy(buf + nr, argv[i], size);
        nr += size;
        // Preserve ps's display format without starting a subprocess. Do not
        // append a NUL; a full buffer returns len, including truncated output.
        if (nr < len) {
            buf[nr++] = (i + 1 == argc || !argv[i + 1] ? '\n' : ' ');
        }
    }
    return nr;
#else
    #error Not Implemented
#endif
}

ssize_t GetProcessAbsolutePath(char *buf, size_t len) {
#if defined(OS_LINUX)
    memset(buf, 0, len);
    ssize_t nr = readlink("/proc/self/exe", buf, len);
    return nr;
#elif defined(OS_MACOSX)
    memset(buf, 0, len);
    int ret = proc_pidpath(getpid(), buf, len);
    return ret;
#endif
}

} // namespace butil
