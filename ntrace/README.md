ntraceとsandbox
=====

システムコールトレーサとシステムコールサンドボックスのプログラム例です．

このシステムコールサンドボックスには固定的なセキュリティポリシーが実装されています．それは書き込み可能なファイルオープン（フラグにO_WRONLYまたはO_RDWRが与えられたopenまたはopenatシステムコール）の実行を拒否します．

ビルド
-----

Makefileのあるディレクトリでmakeを実行すると，ntraceとsandboxという実行可能ファイルができます．

実行例
-----

Ubuntu上で実行．

````aaa
$ ./ntrace /bin/ls
execve("/bin/ls", 94644714877600, 140724349098496) = 0 (0x00000000)
brk(0, 140312385977645, 77) = 94560089829376 (0x56007c907000)
arch_prctl(12289, 140724963923280, 140312385937568) = -22 (0xffffffffffffffea)
access("/etc/ld.so.preload", 4) = -2 (0xfffffffffffffffe)
openat(4294967196, "/etc/ld.so.cache", 524288, 0x00000000) = 3 (0x00000003)
...

$ ./sandbox touch newfile
Child process 4008 attempted to open file "newfile" with a write-access flag.
Security violation in process 4008. I will kill that process... Killed.
$ /sandbox ping www.google.co.jp
Child process 4012 attempted network communication.
Security violation in process 4012. I will kill that process... Killed.
$ ./sandbox wget https://www.google.co.jp
--2020-03-21 XX:XX:XX--  https://www.google.co.jp/
Resolving www.google.co.jp (www.google.co.jp)... Child process 4018 attempted network communication.
Security violation in process 4018. I will kill that process... Killed.
````

動作確認環境
-----
- Ubuntu 19.10, x86_64, gcc 9.2.1
- Raspbian 8.0 (jessie), Raspberry Pi Model B V1.2, gcc 4.9.2
