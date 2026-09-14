"""Agentrouter-only OAuth check-in for GitHub and Linux DO."""

import asyncio
import json
import os
import re
import time
from urllib.parse import parse_qs, urlsplit

# This is an environment variable name, not a credential.
SECRET = 'AGENTROUTER_OAUTH_STATES'  # nosec B105
ORIGIN = 'https://agentrouter.org'
LOGIN_METHODS = {'github': ('GitHub', r'github'), 'linuxdo': ('Linux DO', r'linux\s*do')}


def oauth_cookies(cookies, method):
	"""Filter only the chosen identity provider; never export Agentrouter sessions."""
	if method not in LOGIN_METHODS:
		raise ValueError('Unsupported login provider')
	if not isinstance(cookies, list):
		raise ValueError('Invalid cookies')
	result = []
	for cookie in cookies:
		if not isinstance(cookie, dict):
			continue
		domain = str(cookie.get('domain', '')).lstrip('.')
		allowed = domain == 'github.com' if method == 'github' else domain == 'linux.do' or domain.endswith('.linux.do')
		if not allowed:
			continue
		if not isinstance(cookie.get('name'), str) or not isinstance(cookie.get('value'), str):
			continue
		expires = cookie.get('expires', -1)
		if not isinstance(expires, (float, int)) or (expires != -1 and expires <= time.time()):
			continue
		item = {
			key: cookie[key]
			for key in ('name', 'value', 'domain', 'path', 'expires', 'httpOnly', 'secure', 'sameSite')
			if key in cookie
		}
		item.setdefault('path', '/')
		result.append(item)
	if not result or (
		method == 'github'
		and not any(c['name'] in ('user_session', '__Host-user_session_same_site') and c['value'] for c in result)
	):
		raise ValueError('Third-party session missing or expired')
	return result


def load_state(api_user):
	raw = os.getenv(SECRET, '')
	if not raw or len(raw.encode('utf-8')) > 48000:
		raise ValueError('Missing or oversized state')
	payload = json.loads(raw)
	if not isinstance(payload, dict) or payload.get('version') != 1 or not isinstance(payload.get('accounts'), dict):
		raise ValueError('Invalid state format')
	entry = payload['accounts'].get(str(api_user))
	if not isinstance(entry, dict):
		raise ValueError('No OAuth state for this account')
	method = entry.get('provider')
	return method, {'cookies': oauth_cookies(entry.get('cookies'), method), 'origins': []}


def classify_callback(url, status, payload, api_user, method='github'):
	parsed = urlsplit(url)
	if (
		method not in LOGIN_METHODS
		or parsed.scheme != 'https'
		or parsed.netloc != 'agentrouter.org'
		or parsed.path != f'/api/oauth/{method}'
	):
		return None
	if parse_qs(parsed.query).get('mode', ['login'])[0] != 'login':
		return None
	if not isinstance(payload, dict):
		return {'confirmed': False, 'message': 'OAuth 响应不是有效 JSON 对象。'}
	if payload.get('message') == 'bind':
		return None
	data = payload.get('data')
	if status != 200 or payload.get('success') is not True or not isinstance(data, dict):
		return {'confirmed': False, 'message': 'OAuth 登录失败，请重新导出登录态或检查平台状态。'}
	if type(data.get('id')) is not int or str(data['id']) != str(api_user):
		return {'confirmed': False, 'message': '第三方登录对应的 Agentrouter 账号与 api_user 不一致，停止确认签到。'}
	if data.get('checked_in') is not True:
		return {
			'confirmed': False,
			'message': 'OAuth 登录成功，本轮未确认新增奖励（checked_in 不为 true），请核对领取间隔。',
		}
	return {'confirmed': True, 'message': f'{LOGIN_METHODS[method][0]} OAuth 签到成功：服务器 checked_in=true。'}


async def perform_oauth(context, api_user, method='github', timeout=90):
	"""Use fresh context with third-party-only state; return a redacted result."""
	future = asyncio.get_running_loop().create_future()
	tasks = set()

	async def inspect(response):
		parsed = urlsplit(response.url)
		if parsed.scheme != 'https' or parsed.netloc != 'agentrouter.org' or parsed.path != f'/api/oauth/{method}':
			return
		try:
			payload = await response.json()
		except Exception:
			payload = None
		verdict = classify_callback(response.url, response.status, payload, api_user, method)
		if verdict is not None and not future.done():
			future.set_result((verdict, response.frame.page))

	def on_response(response):
		task = asyncio.create_task(inspect(response))
		tasks.add(task)
		task.add_done_callback(tasks.discard)

	context.on('response', on_response)

	async def navigate():
		page = await context.new_page()
		await page.goto(ORIGIN + '/login', wait_until='domcontentloaded', timeout=45000)
		await page.get_by_role('button', name=re.compile(LOGIN_METHODS[method][1], re.I)).first.click(timeout=20000)
		while not future.done():
			# Previously approved grants usually redirect automatically. Only click the
			# standard consent button on GitHub's own OAuth authorization page.
			for candidate in context.pages:
				url = urlsplit(candidate.url)
				if url.scheme == 'https' and url.netloc == 'github.com' and url.path == '/login/oauth/authorize':
					button = candidate.locator('button[name="authorize"]').first
					if await button.is_visible():
						await button.click(timeout=3000)
				elif (
					method == 'linuxdo'
					and url.scheme == 'https'
					and url.netloc == 'connect.linux.do'
					and url.path == '/oauth2/authorize'
				):
					button = candidate.get_by_role(
						'button', name=re.compile(r'^(授权|允许|Authorize|Allow)$', re.I)
					).first
					if await button.is_visible():
						await button.click(timeout=3000)
			await asyncio.sleep(0.25)
		return future.result()

	try:
		verdict, page = await asyncio.wait_for(navigate(), timeout=timeout)
		after = {'success': False, 'check_in_message': verdict['message']}
		if verdict['confirmed']:
			# OAuth quota fields can be zero placeholders; obtain actual balance only
			# from self, and only when the server identity matches the configured ID.
			try:
				data = await asyncio.wait_for(
					page.evaluate(
						"""async (id) => {
					const r = await fetch('/api/user/self', {headers: {'new-api-user': id}});
					if (!r.ok) return null;
					return await r.json();
				}""",
						str(api_user),
					),
					timeout=10,
				)
				profile = data.get('data') if isinstance(data, dict) and data.get('success') is True else None
				if (
					isinstance(profile, dict)
					and str(profile.get('id')) == str(api_user)
					and all(type(profile.get(k)) is int and profile[k] >= 0 for k in ('quota', 'used_quota'))
				):
					after.update(
						success=True,
						quota=round(profile['quota'] / 500000, 2),
						used_quota=round(profile['used_quota'] / 500000, 2),
					)
					after['display'] = f'余额: ${after["quota"]:.2f} | 累计消耗: ${after["used_quota"]:.2f}'
			except Exception:
				after['check_in_message'] += ' 余额暂时读取失败，未用 OAuth 占位余额代替。'
		return verdict['confirmed'], None, after
	finally:
		context.remove_listener('response', on_response)
		for task in tuple(tasks):
			task.cancel()
		if tasks:
			await asyncio.gather(*tuple(tasks), return_exceptions=True)


async def run_agentrouter_oauth(account_name, api_user, provider):
	def failure(message):
		print(f'[FAIL] {account_name}: {message}')
		return False, None, {'success': False, 'check_in_message': message}

	if provider.domain.rstrip('/') != ORIGIN:
		return failure('OAuth 仅支持内置 https://agentrouter.org 域名。')
	try:
		method, state = load_state(api_user)
	except Exception:
		return failure(f'未配置有效的 {SECRET} 登录态：此账号未执行签到。请导出对应账号的 GitHub 或 Linux DO 登录态。')
	browser = None
	try:
		from cloakbrowser import launch_async

		from utils.proxy import get_playwright_proxy

		kwargs: dict = {'headless': os.getenv('CHECKIN_HEADLESS', 'true').lower() != 'false'}
		proxy = get_playwright_proxy(use_proxy=provider.use_proxy)
		if proxy:
			kwargs['proxy'] = proxy
		browser = await launch_async(**kwargs)
		context = await browser.new_context(storage_state=state, locale='en-US', service_workers='block')
		print(f'[AUTH] {account_name}: {LOGIN_METHODS[method][0]} OAuth browser flow started')
		result = await perform_oauth(context, api_user, method)
		print(f'[{"SUCCESS" if result[0] else "FAIL"}] {account_name}: {result[2]["check_in_message"]}')
		return result
	except Exception as exc:
		# Driver errors can embed cookies, request bodies and OAuth codes.
		return failure(
			f'OAuth 未完成（{type(exc).__name__}）。请检查代理或重新导出登录态；Cloudflare/验证码/重新登录需要人工处理。'
		)
	finally:
		if browser is not None:
			try:
				await browser.close()
			except Exception:
				print(f'[WARN] {account_name}: Browser cleanup did not finish normally')
