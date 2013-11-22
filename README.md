nginx tcp2http module
=============
A tcp2http module for nginx.

Most code are copied from ngx-tcp-module  ngx-http-module , and the directives/constants/APIs are 
using it with ngx-lua module. 

Still need ngx-tcp-module's ngx.req.socket() to read data;

Thanks for great job of ngx-lua module, ngx-tcp module.

Directives
============



Nginx API for Lua
============

Core constants
#todo
ngx.socket.tcp
------------

    connect
    send
    receive
    close
    settimeout
    setoption
    receiveuntil
    setkeepalive
    getreusedtimes

ngx.req.socket
------------

    receive
    receiveuntil


Installation
============

    wget http://luajit.org/download/LuaJIT-2.0.0.tar.gz
    tar -xvfz LuaJIT-2.0.0.tar.gz
    cd LuaJIT-2.0.0
    make install

    wget 'http://nginx.org/download/nginx-1.0.15.tar.gz'
    tar -xzvf nginx-1.0.15.tar.gz
    cd nginx-1.0.15/

    # tell nginx's build system where to find luajit:
    export LUAJIT_LIB=/usr/local/lib
    export LUAJIT_INC=/usr/local/include/luajit-2.0

    # or tell where to find Lua
    #export LUA_LIB=/path/to/lua/lib
    #export LUA_INC=/path/to/lua/include

    # Here we assume Nginx is to be installed under /opt/nginx/.
    ./configure --prefix=/opt/nginx \
            --add-module=/path/to/ngx-tcp-lua-module

    make -j2
    make install

    # on 64bit os, the soft link maybe needed to run nginx:

    ln -s /usr/local/lib/libluajit-5.1.so.2.0.0 /lib64/libluajit-5.1.so.2

Example
============

nginx.conf:

    tcp2http {
        server {
            listen 8000;
			location  /
			{
				content_by_lua '
				local sock = ngx.req.socket()
				local re = sock:receive()
				if re == nil then
					ngx.print("error")
				end
				ngx.print(re)
				';
			}
        }
    }

test.lua:

    local a = 0
    a = a + 1

    local f = io.open("/tmp/aaaa", "wb")
    f:write("xxxx")
    f:close()

    local sock = ngx.req.socket()

    while true do
        local re = sock:receive(10)
        if re == nil then
            break
        end
        ngx.print(re)
    end

------------

Also there is a redis proxy example:

1. cp examples/redis.lua path-to-nginx/conf
2. vi nginx.conf add:

     tcp {
         server {
             listen 8000;
             location /
			 {
				content_by_lua_file conf/redis.lua;
			 }
         }
     }

3. run redis on default port
    
    redis-server

4. issue a redis-benchmark test:

    redis-benchmark -q -p 8000 -c 200 -n 100000 

Copyright and License
===========

    This module is licensed under the BSD license.

    Copyright (C) 2012-, by Simon LEE(bigplum@gmail.com).

    All rights reserved.

    Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

    Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
    USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

See Also
============

*[lua-nginx-module](https://github.com/chaoslawful/lua-nginx-module)

