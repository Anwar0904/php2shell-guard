import assert from 'node:assert/strict'
import { readFile, stat } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const builtRoot = resolve(repositoryRoot, 'dist/client')
const canonicalUrl = 'https://php2shell-guard.anwar-labs.workers.dev/'

async function readText(path) {
  return readFile(resolve(repositoryRoot, path), 'utf8')
}

function collectMeta(html, attribute, value) {
  const tags = html.match(/<meta\b[^>]*>/gi) ?? []
  return tags.filter((tag) => new RegExp(`\\b${attribute}=["']${value}["']`, 'i').test(tag))
}

function collectLink(html, rel) {
  const tags = html.match(/<link\b[^>]*>/gi) ?? []
  return tags.filter((tag) => new RegExp(`\\brel=["']${rel}["']`, 'i').test(tag))
}

function metaContent(html, attribute, value) {
  const tags = collectMeta(html, attribute, value)
  assert.equal(tags.length, 1, `Expected exactly one meta tag for ${value}`)
  return tags[0].match(/\bcontent=["']([^"']*)["']/i)?.[1] ?? ''
}

const sourceHtml = await readText('index.html')
const builtHtml = await readFile(resolve(builtRoot, 'index.html'), 'utf8')
const appSource = await readText('src/App.tsx')
assert.equal((appSource.match(/<h1\b/gi) ?? []).length, 1, 'React application must have one H1')

for (const [label, html] of [['source', sourceHtml], ['built', builtHtml]]) {
  const titles = html.match(/<title\b[^>]*>[\s\S]*?<\/title>/gi) ?? []
  assert.equal(titles.length, 1, `${label} HTML must have one title`)
  assert.match(titles[0], /PHP2Shell Guard — PHP Version &amp; CVE Security Checker/)

  const descriptions = collectMeta(html, 'name', 'description')
  assert.equal(descriptions.length, 1, `${label} HTML must have one description`)
  assert.ok(metaContent(html, 'name', 'description').length >= 50, 'Meta description must be meaningful')
  assert.equal(collectLink(html, 'canonical').length, 1, `${label} HTML must have one canonical URL`)
  assert.match(collectLink(html, 'canonical')[0], new RegExp(`href=["']${canonicalUrl.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}["']`))
  assert.match(metaContent(html, 'name', 'robots'), /\bindex\b/i)
  assert.doesNotMatch(metaContent(html, 'name', 'robots'), /\bnoindex\b/i)
  assert.doesNotMatch(html, /<meta\b[^>]*(?:name|http-equiv)=["']X-Robots-Tag["'][^>]*>/i)

  for (const [key, value] of [
    ['property', 'og:type'],
    ['property', 'og:title'],
    ['property', 'og:description'],
    ['property', 'og:url'],
    ['property', 'og:site_name'],
    ['property', 'og:image'],
    ['property', 'og:image:alt'],
    ['name', 'twitter:card'],
    ['name', 'twitter:title'],
    ['name', 'twitter:description'],
    ['name', 'twitter:image'],
    ['name', 'twitter:image:alt'],
  ]) {
    assert.equal(collectMeta(html, key, value).length, 1, `${label} HTML must include ${value} once`)
  }

  assert.equal(collectMeta(html, 'property', 'og:url')[0].match(/\bcontent=["']([^"']*)["']/i)?.[1], canonicalUrl)
  assert.equal(
    metaContent(html, 'property', 'og:image'),
    'https://php2shell-guard.anwar-labs.workers.dev/php2shell.png',
  )
  assert.equal(
    metaContent(html, 'name', 'twitter:image'),
    'https://php2shell-guard.anwar-labs.workers.dev/php2shell.png',
  )
  assert.equal(metaContent(html, 'name', 'twitter:card'), 'summary_large_image')
  assert.equal((html.match(/<h1\b/gi) ?? []).length, 1, `${label} HTML must have one H1`)

  const jsonLdBlocks = [...html.matchAll(/<script\b[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi)]
  assert.equal(jsonLdBlocks.length, 1, `${label} HTML must have one JSON-LD graph`)
  const structuredData = JSON.parse(jsonLdBlocks[0][1])
  assert.equal(structuredData['@context'], 'https://schema.org')
  assert.deepEqual(
    structuredData['@graph'].map(({ '@type': type }) => type),
    ['WebSite', 'WebApplication'],
  )
  assert.doesNotMatch(jsonLdBlocks[0][1], /aggregateRating|review|ratingValue/i)
  assert.match(html, /CVE-2026-109618/)
  assert.match(html, /CVE-2026-109619/)
  assert.match(html, /vendor packages may backport fixes/i)
  assert.match(html, /CLI PHP may differ/i)
}

const robots = await readFile(resolve(builtRoot, 'robots.txt'), 'utf8')
assert.match(robots, /^User-agent:\s*\*\s*$/m)
assert.match(robots, /^Allow:\s*\/\s*$/m)
assert.doesNotMatch(robots, /^Disallow:\s*\/\s*$/m)
assert.match(robots, new RegExp(`^Sitemap: ${canonicalUrl.replace(/\/$/, '')}/sitemap\\.xml$`, 'm'))

const sitemap = await readFile(resolve(builtRoot, 'sitemap.xml'), 'utf8')
assert.match(sitemap, /^\s*<\?xml version="1\.0" encoding="UTF-8"\?>\s*<urlset xmlns="http:\/\/www\.sitemaps\.org\/schemas\/sitemap\/0\.9">[\s\S]*<\/urlset>\s*$/)
const sitemapUrls = [...sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)].map(([, url]) => new URL(url))
assert.equal(sitemapUrls.length, 1, 'Sitemap must include only the indexable homepage')
assert.equal(sitemapUrls[0].href, canonicalUrl)
assert.doesNotMatch(sitemap, /<lastmod>|<changefreq>|<priority>|\/api\/|#/i)

for (const asset of ['favicon.png', 'php2shell.png']) {
  const path = resolve(builtRoot, asset)
  assert.ok((await stat(path)).isFile(), `${asset} must exist in the production output`)
  const bytes = await readFile(path)
  assert.deepEqual(
    bytes.subarray(0, 8),
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    `${asset} must be a valid PNG asset`,
  )
}

const builtAssetPaths = [...builtHtml.matchAll(/(?:href|src)=["'](\/[^"']+)["']/g)]
for (const [, assetPath] of builtAssetPaths) {
  const assetUrl = new URL(assetPath, canonicalUrl)
  if (assetUrl.origin === new URL(canonicalUrl).origin) {
    const filePath = resolve(builtRoot, `.${assetUrl.pathname}`)
    assert.ok((await stat(filePath)).isFile(), `Built HTML asset ${assetUrl.pathname} must exist`)
  }
}

const staticHeaders = await readText('public/_headers')
assert.doesNotMatch(staticHeaders, /^\s*X-Robots-Tag\s*:/im, 'Static headers must not restrict indexing')
assert.match(staticHeaders, /^\/assets\/\*\s*\n\s*Cache-Control: public, max-age=31536000, immutable/m)

console.log('SEO validation passed: metadata, structured data, crawlable content, robots, sitemap, and built assets.')
