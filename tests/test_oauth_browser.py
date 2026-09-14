import os

import pytest

from utils.agentrouter_oauth import perform_oauth, run_agentrouter_oauth
from utils.config import AppConfig


@pytest.mark.asyncio
@pytest.mark.parametrize('method', ['github', 'linuxdo'])
@pytest.mark.parametrize('reward', [True, False])
async def test_real_browser_oauth_and_actual_balance(method, reward):
	from playwright.async_api import async_playwright

	executable = os.getenv('CHECKIN_TEST_BROWSER')
	if not executable:
		pytest.skip('Set CHECKIN_TEST_BROWSER for the browser integration test')
	async with async_playwright() as p:
		browser = await p.chromium.launch(executable_path=executable, headless=True)
		ctx = await browser.new_context()

		async def route(r):
			path = r.request.url.split('?')[0]
			if path.endswith('/api/oauth/' + method):
				await r.fulfill(
					json={'success': True, 'data': {'id': 42, 'checked_in': reward, 'quota': 0, 'used_quota': 0}}
				)
			elif path.endswith('/api/user/self'):
				assert r.request.headers['new-api-user'] == '42'
				await r.fulfill(json={'success': True, 'data': {'id': 42, 'quota': 12500000, 'used_quota': 5000000}})
			else:
				label = 'GitHub' if method == 'github' else 'Linux DO'
				await r.fulfill(
					content_type='text/html',
					body=f"""<button onclick="fetch('/api/oauth/{method}?code=PRIVATE&state=PRIVATE')">{label}</button>""",
				)

		await ctx.route('**/*', route)
		try:
			success, before, after = await perform_oauth(ctx, '42', method, timeout=5)
			assert success is reward and before is None
			if reward:
				assert after['quota'] == 25 and after['used_quota'] == 10
			else:
				assert after['success'] is False and 'quota' not in after
			assert 'PRIVATE' not in str(after)
		finally:
			await browser.close()


@pytest.mark.asyncio
async def test_bad_secret_does_not_launch_browser_or_leak(monkeypatch, capsys):
	monkeypatch.setenv('AGENTROUTER_OAUTH_STATES', 'PRIVATE broken json')
	result = await run_agentrouter_oauth('test', '42', AppConfig.load_from_env().get_provider('agentrouter'))
	assert result[0] is False
	assert 'PRIVATE' not in capsys.readouterr().out
	assert 'AGENTROUTER_OAUTH_STATES' in result[2]['check_in_message']


@pytest.mark.asyncio
async def test_browser_timeout_does_not_become_success():
	from playwright.async_api import async_playwright

	executable = os.getenv('CHECKIN_TEST_BROWSER')
	if not executable:
		pytest.skip('Set CHECKIN_TEST_BROWSER')
	async with async_playwright() as p:
		browser = await p.chromium.launch(executable_path=executable, headless=True)
		ctx = await browser.new_context()
		await ctx.route('**/*', lambda r: r.fulfill(content_type='text/html', body='<button>GitHub</button>'))
		try:
			with pytest.raises(TimeoutError):
				await perform_oauth(ctx, '42', timeout=0.5)
		finally:
			await browser.close()
