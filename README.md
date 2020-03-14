# ptrace-book-ntrace

「[ptrace入門](https://www.amazon.co.jp/dp/B07X2PCH7K/)」（大山恵弘 著）で説明されているシステムコールトレーサntraceとシステムコールサンドボックスのプログラム例です．

ビルド
-----

Makefileのあるディレクトリでmakeを実行すると，ntraceとsandboxという実行可能ファイルができます．

動作確認環境
-----
- Ubuntu 19.10, x86_64, gcc 9.2.1
- Raspbian 8.0 (jessie), Raspberry Pi Model B V1.2, gcc 4.9.2
