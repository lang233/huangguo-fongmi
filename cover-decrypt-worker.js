// cover-decrypt-worker.js
// Cloudflare Worker：把 AES-CBC 加密的封面在线解密成明文图，直接返回给客户端。
// 用途：让 TV 端封面 URL 直接指向本 Worker（明文图），彻底绕开蜘蛛 proxy() 的
//       同步请求 + 超时 + 路由问题，解决"大部分封面不显示"。
//
// 部署：
//   1) dashboard.cloudflare.com -> Workers & Pages -> 创建 Worker -> 粘贴本文件内容
//   2) 部署后得到地址  https://<your-worker>.workers.dev
//   3) 把该地址填到 fongmi_optimized.js 顶部的 DECRYPT_HOST
//
// 用法：  https://<your-worker>.workers.dev/?url=<urlencode(封面原地址)>
// 注：封面密文自带合法 PKCS7 填充，WebCrypto AES-CBC 默认自动去填充，无需手写 AES。

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const target = url.searchParams.get('url') || url.searchParams.get('src');
    if (!target) return new Response('missing url', { status: 400 });
    if (!/^https?:\/\//i.test(target)) return new Response('bad url', { status: 400 });

    // 1) 拉取加密密文（带与蜘蛛一致的 UA/Referer）
    let src;
    try {
      src = await fetch(target, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
          'Referer': 'https://huangguoai.com/'
        }
      });
    } catch (e) {
      return new Response('upstream fetch error', { status: 502 });
    }
    if (!src.ok) return new Response('upstream ' + src.status, { status: 502 });
    const cipher = new Uint8Array(await src.arrayBuffer());
    if (cipher.length === 0 || cipher.length % 16 !== 0) {
      return new Response('bad ciphertext', { status: 502 });
    }

    // 2) WebCrypto AES-128-CBC 解密（密钥/IV 与爬虫 IMG_KEY / IMG_IV 一致，自动去 PKCS7 填充）
    const keyBytes = new TextEncoder().encode('f5d965df75336270'); // 16 字节
    const ivBytes  = new TextEncoder().encode('97b60394abc2fbe1'); // 16 字节
    let plain;
    try {
      const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-CBC' }, false, ['decrypt']);
      plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-CBC', iv: ivBytes }, key, cipher));
    } catch (e) {
      return new Response('decrypt failed', { status: 502 });
    }

    // 3) 判定图片类型并返回
    const isJpg = plain.length > 2 && plain[0] === 0xff && plain[1] === 0xd8;
    const isPng = plain.length > 8 && plain[0] === 0x89 && plain[1] === 0x50 && plain[2] === 0x4e && plain[3] === 0x47;
    const contentType = isJpg ? 'image/jpeg' : (isPng ? 'image/png' : 'application/octet-stream');

    return new Response(plain, {
      headers: {
        'Content-Type': contentType,
        'Cache-Control': 'public, max-age=86400',
        'Access-Control-Allow-Origin': '*'
      }
    });
  }
};
