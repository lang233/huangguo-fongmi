// fongmi_optimized.js
// FongMi / 影视TV QuickJS Spider adapter —— 优化版
// 基于 huangguo_fongmi.js 重构，站点抓取/解析逻辑保持不变，重点修复：
import 'assets://js/lib/crypto-js.js';

const SITE = 'https://huangguoai.com';
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
const IMG_KEY = 'f5d965df75336270';
const IMG_IV = '97b60394abc2fbe1';
const TIMEOUT_MS = 7000;      // 单封面取图超时(ms)
const DEBUG = false;          // 置 true 可打印取图/解密失败原因
// 服务端解密Worker地址。填上后封面 URL 直接指向明文图（TV端稳定，推荐）：
// 留空 '' 则回退到蜘蛛 proxy() 运行时解密（依赖 app 把封面请求走代理，TV 上不稳）。
const DECRYPT_HOST = 'https://cover-decrypt.qq308375072.workers.dev';

const EMPTY_IMAGE = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/lXcAAAAASUVORK5CYII=';

const HEADERS = {
  'User-Agent': UA,
  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'Accept-Language': 'zh-CN,zh;q=0.9',
  'Referer': SITE + '/'
};

const CLASSES = [
  { type_id: 'ai-duanju',  type_name: 'AI成人短剧' },
  { type_id: 'ai-manju',   type_name: 'AI成人漫剧' },
  { type_id: 'ai-huanlian', type_name: 'AI换脸' },
  { type_id: 'ai-mogai',   type_name: 'AI魔改' },
  { type_id: 'ranks/hot',  type_name: '排行榜' }
];

function log(msg) {
  if (!DEBUG) return;
  try {
    if (typeof console !== 'undefined' && console.log) console.log('[huangguo] ' + msg);
  } catch (e) {}
}

function fix(u) {
  if (!u) return '';
  u = String(u).replace(/&amp;/g, '&');
  if (u.indexOf('//') === 0) return 'https:' + u;
  if (u.indexOf('/') === 0) return SITE + u;
  return u;
}

function coverUrl(u) {
  u = fix(u).replace(/\?.*$/, '');
  if (!/^https?:\/\//i.test(u)) return '';
  // 优先走服务端解密：封面变成明文图，TV 端直接加载，稳定可靠，绕开 proxy() 链路。
  // 未配置 DECRYPT_HOST 时回退到蜘蛛 proxy() 运行时解密。
  if (DECRYPT_HOST) return DECRYPT_HOST + '/?url=' + encodeURIComponent(u);
  return getProxy(true) + '&siteKey=huangguo_fongmi&url=' + encodeURIComponent(u);
}

function imageType(b64) {
  if (b64.indexOf('/9j/') === 0) return 'image/jpeg';
  if (b64.indexOf('iVBOR') === 0) return 'image/png';
  if (b64.indexOf('UklGR') === 0) return 'image/webp';
  if (b64.indexOf('R0lGOD') === 0) return 'image/gif';
  return '';
}

// ---------- 解密（优化核心） ----------

// 字节数组 -> 小写十六进制
function bytesToHex(buf) {
  let h = '';
  for (let i = 0; i < buf.length; i++) {
    const c = buf[i] & 0xff;
    h += (c < 16 ? '0' : '') + c.toString(16);
  }
  return h;
}

// 把 req 返回的“任意形态”响应体，统一转成【原始密文的十六进制】
// 覆盖四种情况：base64 字符串 / latin1 原始字节字符串 / ArrayBuffer / Uint8Array
function toCipherHex(content) {
  if (content == null) return '';
  if (typeof content === 'string') {
    const s = String(content).replace(/\s+/g, '');
    // 形态A：base64 字符串（buffer:2 的常见返回），解码后长度须为 16 的倍数
    if (s.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(s)) {
      try {
        const wa = CryptoJS.enc.Base64.parse(s);
        if (wa.sigBytes && wa.sigBytes % 16 === 0) return CryptoJS.enc.Hex.stringify(wa);
      } catch (e) { log('base64 parse failed: ' + e); }
    }
    // 形态B：latin1 原始字节字符串（部分引擎把 buffer:2 当成原始字节返回）
    const arr = new Array(s.length);
    for (let i = 0; i < s.length; i++) arr[i] = s.charCodeAt(i);
    return bytesToHex(arr);
  }
  // 形态C：ArrayBuffer / Uint8Array / 数字数组
  if (content instanceof ArrayBuffer) return bytesToHex(new Uint8Array(content));
  if (content instanceof Uint8Array) return bytesToHex(content);
  if (Array.isArray(content)) return bytesToHex(Uint8Array.from(content));
  if (content && typeof content.byteLength === 'number') {
    try { return bytesToHex(new Uint8Array(content.buffer || content)); } catch (e) { log('arraybuffer convert failed'); }
  }
  return '';
}

// 对密文 hex 做 AES-128-CBC(NoPadding) 解密，去填充、截尾，返回 base64 图片；失败返回 ''
function decryptHex(hex) {
  if (!hex || hex.length % 32) { log('cipher hex length invalid: ' + (hex || '').length); return ''; }
  const ciphertext = CryptoJS.enc.Hex.parse(hex);
  const plaintext = CryptoJS.AES.decrypt(
    { ciphertext: ciphertext },
    CryptoJS.enc.Utf8.parse(IMG_KEY),
    { iv: CryptoJS.enc.Utf8.parse(IMG_IV), mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.NoPadding }
  );
  let h = CryptoJS.enc.Hex.stringify(plaintext).toLowerCase();
  if (!/^(ffd8|89504e470d0a1a0a|52494646|47494638)/.test(h)) { log('bad image magic: ' + h.slice(0, 8)); return ''; }
  // 去 PKCS#7 填充
  const pad = parseInt(h.slice(-2), 16);
  if (pad > 0 && pad <= 16 && h.slice(-2 * pad) === pad.toString(16).padStart(2, '0').repeat(pad)) {
    h = h.slice(0, -2 * pad);
  }
  // 截断到图片真正结尾，丢弃尾部多余字节（JPEG 到 FFD9，PNG 到 IEND）
  let end = h.lastIndexOf('ffd9');
  if (h.indexOf('ffd8') === 0 && end >= 0) h = h.slice(0, end + 4);
  end = h.lastIndexOf('49454e44ae426082');
  if (h.indexOf('89504e47') === 0 && end >= 0) h = h.slice(0, end + 16);
  const out = CryptoJS.enc.Base64.stringify(CryptoJS.enc.Hex.parse(h));
  if (!imageType(out)) { log('decoded output is not a valid image'); return ''; }
  return out;
}

// ---------- HTML 解析（保持原逻辑不变） ----------

function stripTags(s) {
  return String(s || '')
    .replace(/<script[\s\S]*?<\/script>/gi, '')
    .replace(/<style[\s\S]*?<\/style>/gi, '')
    .replace(/<[^>]*>/g, '')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .trim();
}

function getHtml(url, referer) {
  const headers = Object.assign({}, HEADERS);
  if (referer) headers.Referer = referer;
  const r = req(url, { method: 'get', headers: headers, timeout: TIMEOUT_MS });
  if (!r) return '';
  return typeof r.content === 'string' ? r.content : '';
}

function gridSlices(html, allGrids) {
  const re = /<div\s+class="[^"]*\bhg-card-grid\b[^"]*"[^>]*>/g;
  const starts = [];
  let m;
  while ((m = re.exec(html)) !== null) starts.push(m.index + m[0].length);
  if (!starts.length) return [html];
  const slices = [];
  const n = allGrids ? starts.length : 1;
  for (let i = 0; i < n; i++) {
    const to = i + 1 < starts.length ? starts[i + 1] : html.length;
    slices.push(html.slice(starts[i], to));
  }
  return slices;
}

function cardBlocks(slice) {
  const re = /<div\s+class="[^"]*\bhg-drama-card\b[^"]*"[^>]*>/g;
  const starts = [];
  let m;
  while ((m = re.exec(slice)) !== null) starts.push(m.index + m[0].length);
  const blocks = [];
  for (let i = 0; i < starts.length; i++) {
    const to = i + 1 < starts.length ? starts[i + 1] : slice.length;
    blocks.push(slice.slice(starts[i], to));
  }
  return blocks;
}

function parseCardBlock(block) {
  // New site uses /video/ID/ ; old source used /detail/ID/
  const a = block.match(/href="[^"]*\/(?:detail|video)\/(\d+)\/[^"]*"/);
  if (!a) return null;
  const vid = a[1];

  const imgM = block.match(/data-src="([^"]+)"/) || block.match(/src="([^"]+)"/);
  let title = '';

  const t = block.match(/hg-drama-card__title[^>]*>([\s\S]*?)<\/a>/);
  if (t) title = stripTags(t[1]);

  if (!title) {
    const tt = block.match(/<a[^>]+href="[^"]*\/(?:detail|video)\/\d+\/[^"]*"[^>]*>([\s\S]*?)<\/a>/);
    if (tt) title = stripTags(tt[1]);
  }
  if (!title) return null;

  const ep = block.match(/hg-drama-card__episode[^>]*>([\s\S]*?)<\/span>/);
  const score = block.match(/hg-drama-card__score[^>]*>([\s\S]*?)<\/span>/);
  const rem = ep ? stripTags(ep[1]) : '';
  const sc = score ? stripTags(score[1]) : '';

  return {
    vod_id: vid,
    vod_name: title,
    vod_pic: coverUrl(imgM ? imgM[1] : ''),
    vod_remarks: rem && sc ? rem + ' · ' + sc : (rem || sc)
  };
}

function parseGridCards(html, allGrids) {
  if (!html) return [];
  const list = [];
  const seen = {};
  const slices = gridSlices(html, allGrids);

  for (let si = 0; si < slices.length; si++) {
    const blocks = cardBlocks(slices[si]);
    for (let bi = 0; bi < blocks.length; bi++) {
      try {
        const item = parseCardBlock(blocks[bi]);
        if (!item || seen[item.vod_id]) continue;
        seen[item.vod_id] = true;
        list.push(item);
      } catch (e) {}
    }
  }

  // Fallback for site layout changes: parse links around /video/ID/
  if (!list.length) {
    const re = /<a\b[^>]*href="([^"]*\/video\/(\d+)\/)[^"]*"[^>]*>([\s\S]*?)<\/a>/g;
    let m;
    while ((m = re.exec(html)) !== null) {
      const id = m[2];
      if (seen[id]) continue;
      let name = stripTags(m[3]);
      name = name.replace(/全集在线观看\s*$/g, '').trim();
      if (!name || /^\d+$/.test(name)) continue;
      seen[id] = true;
      list.push({ vod_id: id, vod_name: name, vod_pic: '', vod_remarks: '' });
    }
  }

  return list;
}

function parseRanks(html) {
  if (!html) return [];
  const list = [];
  const seen = {};

  const listM = html.match(/<div\s+class="[^"]*\bhg-rank-list\b[^"]*"[^>]*>/);
  const slice = html.slice(listM ? listM.index + listM[0].length : 0);
  const re = /<div\s+class="[^"]*\bhg-rank-item\b[^"]*"[^>]*>/g;
  const starts = [];
  let m;
  while ((m = re.exec(slice)) !== null) starts.push(m.index + m[0].length);

  for (let i = 0; i < starts.length; i++) {
    const to = i + 1 < starts.length ? starts[i + 1] : slice.length;
    const block = slice.slice(starts[i], to);
    const a = block.match(/href="[^"]*\/(?:detail|video)\/(\d+)\/[^"]*"/);
    if (!a || seen[a[1]]) continue;

    const id = a[1];
    const imgM = block.match(/data-src="([^"]+)"/) || block.match(/src="([^"]+)"/);
    let title = '';
    const t = block.match(/hg-rank-item__title[^>]*>([\s\S]*?)<\/h2>/);
    if (t) title = stripTags(t[1]);
    if (!title) {
      const tt = block.match(/<a[^>]+href="[^"]*\/(?:detail|video)\/\d+\/[^"]*"[^>]*>([\s\S]*?)<\/a>/);
      if (tt) title = stripTags(tt[1]);
    }
    if (!title) continue;

    const tags = block.match(/hg-rank-item__tags[^>]*>([\s\S]*?)<\/div>/);
    seen[id] = true;
    list.push({
      vod_id: id,
      vod_name: title,
      vod_pic: coverUrl(imgM ? imgM[1] : ''),
      vod_remarks: tags ? stripTags(tags[1]) : ''
    });
  }

  return list.length ? list : parseGridCards(html, true);
}

function parseTitle(html, fallback) {
  const h1 = html.match(/<h1\b[^>]*>([\s\S]*?)<\/h1>/i);
  if (h1) return stripTags(h1[1]);
  const title = html.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i);
  if (title) return stripTags(title[1]).replace(/\s*[-|｜].*$/, '').trim();
  return fallback || '';
}

function parsePic(html) {
  const data = html.match(/id=["']videoInitialData["'][^>]*>([\s\S]*?)<\/script>/i);
  if (data) {
    try {
      const pic = JSON.parse(data[1]).coverSrc;
      if (pic) return coverUrl(pic);
    } catch (e) {}
  }
  const og = html.match(/<meta\b[^>]*(?:property|name)="og:image"[^>]*content="([^"]+)"[^>]*>/i) ||
             html.match(/<meta\b[^>]*content="([^"]+)"[^>]*(?:property|name)="og:image"[^>]*>/i);
  if (og) return coverUrl(og[1]);
  const pic = html.match(/<img\b[^>]*(?:class="[^"]*hg-web-detail[^\"]*"[^>]*)?(?:data-src|src)="([^"]+)"/i);
  return coverUrl(pic ? pic[1] : '');
}

function parseEpisodes(html, id) {
  const eps = [];
  const seen = {};

  // First try the dedicated episode grid used by the original site source.
  const gridM = html.match(/<div\s+class="[^"]*\bhg-web-detail__ep-grid\b[^"]*"[^>]*>([\s\S]*?)<\/div>/);
  const scope = gridM ? gridM[1] : html;
  const are = /<a\b[^>]*>[\s\S]*?<\/a>/g;
  let m;
  while ((m = are.exec(scope)) !== null) {
    const tag = m[0];
    const hrefM = tag.match(/href="([^"]+)"/);
    if (!hrefM) continue;
    const href = fix(hrefM[1]);
    if (href.indexOf('/video/' + id + '/') === -1 && href.indexOf('/detail/' + id + '/') === -1) continue;

    let ep = '';
    const eidM = tag.match(/data-ep-id="([^"]*)"/);
    if (eidM && eidM[1]) ep = eidM[1];
    if (!ep) {
      const p = href.match(/\/ep-(\d+)\/?/);
      if (p) ep = p[1];
    }
    if (!ep) {
      const tx = stripTags(tag).match(/(\d+)/);
      if (tx) ep = String(parseInt(tx[1], 10));
    }
    if (!ep) ep = '1';
    if (seen[ep]) continue;
    seen[ep] = true;
    eps.push({ ep: ep, url: href });
  }

  // If the grid selector changed, search the full page for /video/ID/ep-N/ links.
  const vre = new RegExp('href="([^"]*/video/' + id + '/(?:ep-(\\d+)/)?)"', 'g');
  while ((m = vre.exec(html)) !== null) {
    const ep = m[2] || '1';
    if (seen[ep]) continue;
    seen[ep] = true;
    eps.push({ ep: ep, url: fix(m[1]) });
  }

  if (!eps.length) eps.push({ ep: '1', url: SITE + '/video/' + id + '/' });
  eps.sort(function (a, b) { return parseInt(a.ep, 10) - parseInt(b.ep, 10); });
  return eps;
}

function normalizePlayUrl(u) {
  if (!u) return '';
  u = String(u)
    .replace(/\\u0026/g, '&')
    .replace(/\\\//g, '/')
    .replace(/&amp;/g, '&')
    .trim();
  if (u.indexOf('//') === 0) u = 'https:' + u;
  if (u.indexOf('/') === 0) u = SITE + u;
  return u;
}

function extractPlay(html, ep) {
  let play = '';
  const m = html.match(/id=["']videoInitialData["'][^>]*>([\s\S]*?)<\/script>/i);
  if (m) {
    try {
      const data = JSON.parse(m[1]);
      const srcs = data && data.epPlaySrcs ? data.epPlaySrcs : {};
      play = srcs[String(ep || '1')] || (data && data.videoSrc) || '';
    } catch (e) {}
  }

  play = normalizePlayUrl(play);

  if (!/^https?:\/\//i.test(play)) {
    const direct = html.match(/https?:\\?\/\\?\/[^"]+?\.m3u8(?:\?[^"'<>\s]*)?/i) ||
                   html.match(/https?:\/\/[^"'<>\s]+?\.m3u8(?:\?[^"'<>\s]*)?/i);
    if (direct) play = normalizePlayUrl(direct[0]);
  }
  return play;
}

// ---------- 对外接口 ----------

export default {
  init(ext) {
    this.ext = ext || {};
  },

  home(filter) {
    return JSON.stringify({ class: CLASSES });
  },

  homeVod() {
    try {
      const html = getHtml(SITE + '/');
      return JSON.stringify({ list: parseGridCards(html, true) });
    } catch (e) {
      return JSON.stringify({ list: [] });
    }
  },

  category(tid, pg, filter, extend) {
    const page = Math.max(1, parseInt(pg || '1', 10) || 1);
    try {
      let url;
      if (tid === 'home') {
        url = SITE + '/';
      } else {
        const id = String(tid || '').replace(/^\/+|\/+$/g, '');
        url = SITE + '/' + id + '/' + (page > 1 ? page + '/' : '');
      }
      const html = getHtml(url);
      const isRank = String(tid).indexOf('rank') !== -1;
      const list = isRank ? parseRanks(html) : parseGridCards(html, false);
      // 排行榜是单页固定列表：站点 /ranks/hot/N/ 在 N>1 时并不分页，只会返回兜底重复内容，
      // 若宣称“有下一页”会让 app 持续请求并追加重复条目（实测第2页==第3页，永不返回空）。
      // 故只有“非排行榜且有数据”才宣称有下一页；普通分类页在下一页返回空时仍会自然终止。
      const hasNext = !isRank && list.length > 0;
      const n = list.length || 20;
      return JSON.stringify({
        list: list,
        page: page,
        pagecount: hasNext ? page + 1 : page,
        limit: n,
        total: hasNext ? (page + 1) * n : page * n
      });
    } catch (e) {
      return JSON.stringify({ list: [], page: page, pagecount: page });
    }
  },

  detail(id) {
    id = String(id || '').trim();
    if (!id) return JSON.stringify({ list: [] });
    try {
      const url = SITE + '/video/' + id + '/';
      const html = getHtml(url, SITE + '/');
      const eps = parseEpisodes(html, id);
      const playList = [];
      for (let i = 0; i < eps.length; i++) {
        const ep = eps[i];
        const name = '第' + ep.ep + '集';
        // Pass exact episode page URL + episode number to play().
        playList.push(name + '$' + ep.url + '|||' + ep.ep);
      }

      const vod = {
        vod_id: id,
        vod_name: parseTitle(html, id),
        vod_pic: parsePic(html),
        vod_play_from: '黄果',
        vod_play_url: playList.join('#')
      };
      return JSON.stringify({ list: [vod] });
    } catch (e) {
      return JSON.stringify({ list: [] });
    }
  },

  search(wd, quick, pg) {
    const key = String(wd || '').trim();
    const page = Math.max(1, parseInt(pg || '1', 10) || 1);
    if (!key) return JSON.stringify({ list: [], page: page, pagecount: page });
    try {
      let url = SITE + '/search/video/' + encodeURIComponent(key) + '/';
      if (page > 1) url += page + '/';
      const html = getHtml(url, SITE + '/');
      const list = parseGridCards(html, false);
      return JSON.stringify({
        list: list,
        page: page,
        pagecount: list.length ? page + 1 : page,
        limit: list.length || 20,
        total: list.length ? (page + 1) * (list.length || 20) : page * 20
      });
    } catch (e) {
      return JSON.stringify({ list: [], page: page, pagecount: page });
    }
  },

  play(flag, id, vipFlags) {
    try {
      const raw = String(id || '');
      const parts = raw.split('|||');
      const pageUrl = fix(parts[0]);
      const ep = parts.length > 1 ? parts[1] : '1';
      if (!pageUrl) return JSON.stringify({ parse: 0, url: '' });

      const html = getHtml(pageUrl, SITE + '/');
      const play = extractPlay(html, ep);
      if (!play) return JSON.stringify({ parse: 0, url: '' });

      return JSON.stringify({
        parse: 0,
        url: play,
        header: {
          'User-Agent': UA,
          'Referer': SITE + '/'
        }
      });
    } catch (e) {
      return JSON.stringify({ parse: 0, url: '' });
    }
  },

  proxy(params) {
    try {
      const url = String(params && params.url || '');
      if (!/^https?:\/\//i.test(url)) { log('proxy: invalid url'); return [200, 'image/png', EMPTY_IMAGE, {}, 1]; }
      const r = req(url, { method: 'get', headers: HEADERS, buffer: 2, timeout: TIMEOUT_MS });
      if (!r || Number(r.code) !== 200 || !r.content) {
        log('proxy: fetch fail for ' + url + ' code=' + (r && r.code));
        return [200, 'image/png', EMPTY_IMAGE, {}, 1];
      }
      // 统一归一化响应体 -> 密文 hex -> 解密（自动适配 buffer 返回形态）
      const image = decryptHex(toCipherHex(r.content));
      if (!image) {
        log('proxy: decrypt fail for ' + url);
        return [200, 'image/png', EMPTY_IMAGE, {}, 1];
      }
      return [200, imageType(image), image, { 'Cache-Control': 'public, max-age=3600' }, 1];
    } catch (e) {
      log('proxy: error ' + e);
      return [200, 'image/png', EMPTY_IMAGE, {}, 1];
    }
  }
};
