import json
from unittest.mock import AsyncMock

import httpx
import pytest

import checkin
from scripts.export_agentrouter_state import export_payload
from utils.agentrouter_oauth import classify_callback, load_state, oauth_cookies
from utils.config import AccountConfig, AppConfig


def test_callback_requires_matching_identity_and_boolean_reward():
	url = 'https://agentrouter.org/api/oauth/github?code=SECRET&state=SECRET'
	data = {'success': True, 'data': {'id': 42, 'checked_in': True, 'quota': 0}}
	assert classify_callback(url, 200, data, '42')['confirmed'] is True
	assert classify_callback(url, 200, data, '99')['confirmed'] is False
	for value in (False, None, 'true', 1):
		data['data']['checked_in'] = value
		assert classify_callback(url, 200, data, '42')['confirmed'] is False
	assert classify_callback(url.replace('agentrouter.org', 'evil.test'), 200, data, '42') is None
	assert classify_callback(url.replace('/github?', '/github/bind?'), 200, data, '42') is None
	assert classify_callback(url + '&mode=bind', 200, data, '42') is None
	data['message'] = 'bind'
	assert classify_callback(url, 200, data, '42') is None


def test_only_github_cookies_export_and_import(monkeypatch):
	cookies = [
		{
			'name': 'user_session',
			'value': 'PRIVATE',
			'domain': 'github.com',
			'path': '/',
			'expires': -1,
			'secure': True,
			'httpOnly': True,
			'sameSite': 'Lax',
		},
		{'name': 'session', 'value': 'AGENT_SECRET', 'domain': 'agentrouter.org', 'path': '/'},
	]
	filtered = oauth_cookies(cookies, 'github')
	assert len(filtered) == 1 and filtered[0]['name'] == 'user_session'
	secret = json.dumps({'version': 1, 'accounts': {'42': {'provider': 'github', 'cookies': filtered}}})
	monkeypatch.setenv('AGENTROUTER_OAUTH_STATES', secret)
	assert load_state('42') == ('github', {'cookies': filtered, 'origins': []})
	with pytest.raises(ValueError):
		load_state('99')


def test_linuxdo_export_uses_own_domains_and_correct_callback(monkeypatch):
	cookies = [
		{'name': '_t', 'value': 'PRIVATE', 'domain': '.linux.do', 'path': '/'},
		{'name': 'cf_clearance', 'value': 'PRIVATE', 'domain': 'connect.linux.do', 'path': '/'},
		{'name': 'user_session', 'value': 'UNRELATED', 'domain': 'github.com', 'path': '/'},
	]
	text = export_payload({'43': {'provider': 'linuxdo', 'cookies': cookies}})
	assert 'UNRELATED' not in text and 'github.com' not in text
	monkeypatch.setenv('AGENTROUTER_OAUTH_STATES', text)
	method, state = load_state('43')
	assert method == 'linuxdo' and len(state['cookies']) == 2
	payload = {'success': True, 'data': {'id': 43, 'checked_in': True}}
	assert (
		classify_callback('https://agentrouter.org/api/oauth/linuxdo', 200, payload, '43', method)['confirmed'] is True
	)
	assert classify_callback('https://agentrouter.org/api/oauth/oidc', 200, payload, '43', method) is None


def test_export_preserves_both_accounts_and_excludes_agentrouter(monkeypatch):
	text = export_payload(
		{
			'42': {'provider': 'github', 'cookies': [{'name': 'user_session', 'value': 'GH', 'domain': 'github.com'}]},
			'43': {
				'provider': 'linuxdo',
				'cookies': [
					{'name': '_t', 'value': 'LD', 'domain': '.linux.do'},
					{'name': 'session', 'value': 'AR', 'domain': 'agentrouter.org'},
				],
			},
		}
	)
	monkeypatch.setenv('AGENTROUTER_OAUTH_STATES', text)
	assert load_state('42')[0] == 'github'
	assert load_state('43')[0] == 'linuxdo'
	assert '"AR"' not in text


@pytest.mark.asyncio
async def test_agentrouter_missing_state_does_not_prevent_anyrouter(monkeypatch):
	monkeypatch.delenv('AGENTROUTER_OAUTH_STATES', raising=False)
	accounts = [
		AccountConfig(cookies={'session': 'old'}, api_user='42', provider='agentrouter', name='Ag'),
		AccountConfig(cookies={'session': 'ANY'}, api_user='77', name='Any'),
	]
	monkeypatch.setattr(checkin, 'load_accounts_config', lambda: accounts)
	monkeypatch.setattr(checkin, 'load_balance_hash', lambda: None)
	monkeypatch.setattr(checkin, 'save_balance_hash', lambda _: None)
	monkeypatch.setattr(checkin, 'prepare_cookies', AsyncMock(return_value={'session': 'ANY'}))
	monkeypatch.setattr(
		checkin,
		'run_check_in_requests',
		lambda *a, **kw: (
			True,
			{'success': True, 'quota': 0, 'used_quota': 0},
			{'success': True, 'quota': 25, 'used_quota': 0},
		),
	)
	messages = []
	monkeypatch.setattr(checkin.notify, 'push_message', lambda title, message, **kw: messages.append(message))
	with pytest.raises(SystemExit) as exc:
		await checkin.main()
	assert exc.value.code == 0
	assert 'AGENTROUTER_OAUTH_STATES' in messages[0] and '+$25.00' in messages[0]
	assert 'Success: 1/2' in messages[0]


@pytest.mark.asyncio
async def test_agentrouter_uses_separate_oauth_and_preserves_account_id(monkeypatch):
	config = AppConfig.load_from_env()
	account = AccountConfig(cookies={'session': 'old'}, api_user='42', provider='agentrouter')

	async def oauth(account_name, api_user, provider):
		assert api_user == '42' and provider.domain == 'https://agentrouter.org'
		return True, None, {'success': False, 'check_in_message': 'confirmed'}

	monkeypatch.setattr(checkin, 'run_agentrouter_oauth', oauth)
	monkeypatch.setattr(checkin, 'prepare_cookies', AsyncMock(side_effect=AssertionError('old path must not run')))
	success, before, after = await checkin.check_in_account(account, 0, config)
	assert success is True and before is None and after['check_in_message'] == 'confirmed'


@pytest.mark.asyncio
async def test_anyrouter_keeps_original_get_post_get_and_cookies(monkeypatch):
	config = AppConfig.load_from_env()
	account = AccountConfig(cookies={'session': 'ANY'}, api_user='77')
	monkeypatch.setattr(checkin, 'prepare_cookies', AsyncMock(return_value={'session': 'ANY'}))
	requests = []

	def handler(req):
		requests.append((req.method, req.url.path))
		assert req.headers['new-api-user'] == '77' and 'session=ANY' in req.headers['cookie']
		if req.method == 'POST':
			return httpx.Response(200, json={'success': True})
		return httpx.Response(
			200, json={'success': True, 'data': {'quota': (25 if len(requests) > 1 else 0) * 500000, 'used_quota': 0}}
		)

	client = httpx.Client
	monkeypatch.setattr(checkin.httpx, 'Client', lambda **kw: client(transport=httpx.MockTransport(handler)))
	success, before, after = await checkin.check_in_account(account, 0, config)
	assert success is True and after['quota'] - before['quota'] == 25
	assert requests == [('GET', '/api/user/self'), ('POST', '/api/user/sign_in'), ('GET', '/api/user/self')]


@pytest.mark.asyncio
async def test_oauth_notice_and_anyrouter_result_both_reach_notification(monkeypatch):
	accounts = [
		AccountConfig(cookies={}, api_user='42', provider='agentrouter', name='Ag'),
		AccountConfig(cookies={}, api_user='77', name='Any'),
	]
	monkeypatch.setattr(checkin, 'load_accounts_config', lambda: accounts)
	monkeypatch.setattr(checkin, 'load_balance_hash', lambda: None)
	monkeypatch.setattr(checkin, 'save_balance_hash', lambda _: None)
	monkeypatch.setattr(
		checkin,
		'check_in_account',
		AsyncMock(
			side_effect=[
				(True, None, {'success': False, 'check_in_message': 'OAuth checked_in=true'}),
				(True, {'success': True, 'quota': 0, 'used_quota': 0}, {'success': True, 'quota': 25, 'used_quota': 0}),
			]
		),
	)
	messages = []
	monkeypatch.setattr(checkin.notify, 'push_message', lambda title, message, **kw: messages.append(message))
	with pytest.raises(SystemExit) as exc:
		await checkin.main()
	assert exc.value.code == 0
	assert 'OAuth checked_in=true' in messages[0] and '+$25.00' in messages[0]
