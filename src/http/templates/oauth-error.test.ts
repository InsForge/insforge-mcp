import { describe, it, expect } from 'vitest';
import { renderOAuthErrorPage } from './oauth-error.js';

describe('renderOAuthErrorPage', () => {
  it('renders the heading, message and action', () => {
    const html = renderOAuthErrorPage({
      heading: 'Set this up again',
      message: 'The app is not registered any more.',
      action: 'npx @insforge/install',
    });

    expect(html).toContain('<h1>Set this up again</h1>');
    expect(html).toContain('The app is not registered any more.');
    expect(html).toContain('<code>npx @insforge/install</code>');
    expect(html.startsWith('<!DOCTYPE html>')).toBe(true);
  });

  it('omits the code block when there is no action', () => {
    const html = renderOAuthErrorPage({ heading: 'Nope', message: 'No action here.' });
    expect(html).not.toContain('<code>');
  });

  it('escapes every field, so a reflected value cannot become markup', () => {
    // Nothing untrusted is passed today, but this page sits on an unauthenticated
    // endpoint reached straight from a URL — the escaping is what keeps it safe
    // if someone later renders the client_id or redirect_uri into it.
    const html = renderOAuthErrorPage({
      heading: '<script>alert(1)</script>',
      message: '"quoted" & <b>bold</b>',
      action: "';DROP--<img src=x onerror=alert(1)>",
    });

    expect(html).not.toContain('<script>');
    expect(html).not.toContain('<img src=x');
    expect(html).not.toContain('<b>bold</b>');
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
    expect(html).toContain('&quot;quoted&quot; &amp; &lt;b&gt;bold&lt;/b&gt;');
  });

  it('escapes the heading in the title as well as the body', () => {
    const html = renderOAuthErrorPage({ heading: '</title><script>x</script>', message: 'm' });
    expect(html).not.toContain('</title><script>');
  });
});

describe('the escape survives a value that is not a string', () => {
  /**
   * The deployed build rendered express's own stack trace — absolute paths and
   * the dependency tree — to anyone who crafted
   * `?error=x&error_description=a&error_description=b`, because express parses
   * a repeated parameter as an array and `.replace` is not a function on one.
   *
   * `humanFormOf` normalises that field now, so this is the second layer. It is
   * here because this renderer owns every browser-visible field and trusted its
   * input, which is one level below where anyone was looking.
   */
  it.each([
    ['an array', ['a', 'b']],
    ['a number', 42],
    ['null', null],
    ['undefined', undefined],
    ['an object', { toString: () => 'obj' }],
  ])('renders rather than throwing for %s', (_label, value) => {
    const render = () =>
      renderOAuthErrorPage({ heading: value as unknown as string, message: 'm' });
    expect(render).not.toThrow();
    expect(render()).toContain('<!DOCTYPE html>');
  });

  it('still escapes when the value is a string', () => {
    const html = renderOAuthErrorPage({ heading: 'h', message: '<script>alert(1)</script>' });
    expect(html).not.toContain('<script>');
    expect(html).toContain('&lt;script&gt;');
  });
});
