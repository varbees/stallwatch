/**
 * The smallest possible Worker in front of the static assets.
 *
 * The site itself is still one hand-written HTML file with no build step — that
 * constraint is unchanged. This exists for exactly one reason: the published
 * installer is
 *
 *   curl -fsSL https://stallwatch.antharmaya.com/install.sh | sh
 *
 * and every copy of that already pasted into a terminal history, a blog post or
 * a CI script is unfixable. When the site moved to a path under antharmaya.com
 * that hostname had to keep resolving, or every one of those breaks.
 *
 * -fsSL includes -L, so curl follows the 301. Had the published flags been
 * -fsS this redirect would be useless and the move would have been unsafe.
 *
 * The alternative was a zone-level Redirect Rule in the Cloudflare dashboard.
 * This is better: it ships with the site, it is reviewable, and it cannot be
 * silently deleted by someone tidying up rules they do not recognise.
 */

const OLD_HOST = "stallwatch.antharmaya.com";
const NEW_PREFIX = "https://antharmaya.com/tools/stallwatch";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Read the Host header, not url.hostname. In production both carry the real
    // hostname, but `wrangler dev` always puts localhost in request.url no
    // matter what Host is sent — so a check on url.hostname alone cannot be
    // exercised before deploying, and an untestable redirect is one you find
    // out about from a broken installer.
    const host = request.headers.get("host") ?? url.hostname;

    if (host === OLD_HOST) {
      // Preserve the path and query so /install.sh lands on /install.sh and
      // not on the homepage — a redirect that drops the path would still
      // return 200 to curl and pipe an HTML page into sh.
      const path = url.pathname === "/" ? "" : url.pathname;
      return Response.redirect(`${NEW_PREFIX}${path}${url.search}`, 301);
    }

    return env.ASSETS.fetch(request);
  },
};
