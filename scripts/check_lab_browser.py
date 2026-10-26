"""Browser isolation and real WEB-01 navigation on the isolated test stack."""

import json
import os

from ctf_smoke import BASE


def main():
    from playwright.sync_api import sync_playwright

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            context = browser.new_context()
            page = context.new_page()
            page.set_default_timeout(15000)
            page.goto(BASE + '/login')
            page.locator('input[name="username"]').fill('ctfcheckplayer')
            page.locator('input[name="password"]').fill(os.environ['CTF_CHECK_ADMIN_PASSWORD'])
            page.locator('button[type="submit"]').click()
            page.wait_for_url(BASE + '/profile')
            # Positive control: this browser really holds a valid platform session.
            assert context.request.get(BASE + '/api/challenges').status == 200

            page.goto(BASE + '/')
            page.evaluate("""() => {
                const frame = document.createElement('iframe');
                frame.id = 'lab-isolation-probe';
                frame.src = '/lab/';
                document.body.append(frame);
            }""")
            frame = page.frame_locator('#lab-isolation-probe')
            frame.get_by_role('heading', name='Реестр документов').wait_for()
            parent_access = page.evaluate("""() => {
                try { return document.querySelector('iframe').contentWindow.document.title; }
                catch (error) { return error.name; }
            }""")
            assert parent_access == 'SecurityError', 'Platform can read the lab DOM'
            child = next(item for item in page.frames if item != page.main_frame)
            child_access = child.evaluate("""() => {
                try { return parent.document.title; }
                catch (error) { return error.name; }
            }""")
            assert child_access == 'SecurityError', 'Lab can read the platform DOM'

            page.goto(BASE + '/lab/')
            # CORS failures have no Playwright Response; CDP records the actual HTTP status.
            network = context.new_cdp_session(page)
            network.send('Network.enable')
            urls, statuses = {}, {}
            network.on('Network.requestWillBeSent',
                       lambda event: urls.update({event['requestId']: event['request']['url']}))
            network.on('Network.responseReceivedExtraInfo',
                       lambda event: statuses.update({event['requestId']: event['statusCode']}))
            with page.expect_event('requestfailed', predicate=lambda req: req.url == BASE + '/api/challenges'):
                result = page.evaluate("""async () => {
                    let cookieAccess;
                    try { cookieAccess = document.cookie; }
                    catch (error) { cookieAccess = error.name; }
                    let apiReadable = false;
                    try {
                        await (await fetch('/api/challenges', {credentials: 'include'})).text();
                        apiReadable = true;
                    } catch {}
                    return {cookieAccess, apiReadable};
                }""")
            assert result['cookieAccess'] == 'SecurityError', 'Lab can read platform cookies'
            assert not result['apiReadable'], 'Lab can read a platform API response'
            api_statuses = [statuses.get(key) for key, url in urls.items() if url == BASE + '/api/challenges']
            assert api_statuses == [401], f'Expected unauthenticated lab request, got {api_statuses}'
            network.detach()

            page.locator('a[href="document?id=101"]').click()
            page.get_by_role('heading', name='Правила работы с архивом').wait_for()
            page.get_by_role('link', name='← Вернуться в архив').click()
            page.get_by_role('heading', name='Реестр документов').wait_for()
            # The intended IDOR exercise still works; never print the flag.
            page.goto(BASE + '/lab/document?id=103')
            page.get_by_role('heading', name='Служебный документ').wait_for()
            assert page.locator('code').count() == 1
            assert context.request.get(BASE + '/api/challenges').status == 200
            print(json.dumps({'phase': 'lab-browser', 'cookie_access_blocked': True,
                              'cross_frame_dom_blocked': True, 'api_read_blocked': True,
                              'lab_api_status': 401, 'web01_navigation': True}))
        finally:
            browser.close()


if __name__ == '__main__':
    main()
