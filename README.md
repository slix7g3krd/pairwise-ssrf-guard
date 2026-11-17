# pairwise-ssrf-guard

图片转存服务一开放 URL 导入，SSRF 就来了：只检查 URL 字符串里有没有内网网段，域名解析到 127.0.0.1 照样能打；跳转链只检查第一跳，302 到 metadata 地址没有复核；IPv4-mapped IPv6 和十进制 IP 编码绕过黑名单；DNS rebinding 在检查和连接之间换了解析结果；重定向到 file:// 或 gopher:// 没有限制。security/ssrf_guard.py 是核心，tests/test_ssrf_guard.py 15个红。要修的是：解析后 IP 校验；每跳重定向复核；IPv6/编码归一；DNS 固定；协议白名单。

## 运行

```bash
python -m pytest tests -q
```

初始状态：15 个用例失败。修复实现使全部用例通过，不要修改 `tests/` 下的测试。

子方向：漏洞检测与攻防；任务类型：Bugfix；语言/框架：Python 3, pytest；环境可复现等级：无外部依赖。
