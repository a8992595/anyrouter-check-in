"""Local GUI: export only selected OAuth provider cookies to the clipboard."""

import asyncio
import json
import os
import queue
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from utils.agentrouter_oauth import SECRET, oauth_cookies


def export_payload(accounts):
	clean = {}
	for api_user, entry in accounts.items():
		if not str(api_user).isdigit() or int(api_user) <= 0:
			raise ValueError('Invalid account ID')
		clean[str(int(api_user))] = {
			'provider': entry['provider'],
			'cookies': oauth_cookies(entry['cookies'], entry['provider']),
		}
	if not clean:
		raise ValueError('No accounts')
	text = json.dumps({'version': 1, 'accounts': clean}, ensure_ascii=True, separators=(',', ':'))
	if len(text.encode('utf-8')) > 48000:
		raise ValueError('Secret exceeds size limit')
	return text


async def read_profile(profile, executable):
	from playwright.async_api import async_playwright

	if not profile.is_dir():
		raise ValueError('Profile not found')
	async with async_playwright() as p:
		context = await p.chromium.launch_persistent_context(
			str(profile),
			executable_path=str(executable),
			headless=True,
			offline=True,
			service_workers='block',
		)
		try:
			return await context.cookies()
		finally:
			await context.close()


class Exporter:
	def __init__(self, root):
		self.root = root
		self.accounts = {}
		self.queue: queue.Queue[tuple] = queue.Queue()
		self.busy = False
		self.copied = None
		self.profile_root = Path(
			os.getenv(
				'AGENTROUTER_PROFILE_ROOT', str(Path(__file__).resolve().parents[2] / 'oauth-local-test' / 'profiles')
			)
		)
		self.edge = (
			Path(os.getenv('PROGRAMFILES(X86)', 'C:/Program Files (x86)')) / 'Microsoft/Edge/Application/msedge.exe'
		)
		root.title('导出 Agentrouter Actions 登录态')
		root.geometry('750x430')
		ttk.Label(root, text='先关闭本地验证工具及其测试浏览器。这里不导出 Agentrouter session。', padding=12).pack(
			anchor='w'
		)
		self.method = tk.StringVar(value='GitHub')
		self.api_user = tk.StringVar()
		row = ttk.Frame(root, padding=10)
		row.pack(fill='x')
		ttk.Combobox(row, textvariable=self.method, values=['GitHub', 'Linux DO'], state='readonly', width=12).pack(
			side='left'
		)
		ttk.Label(row, text='Agentrouter api_user：').pack(side='left', padx=8)
		ttk.Entry(row, textvariable=self.api_user, width=15).pack(side='left')
		self.add_button = ttk.Button(row, text='添加/更新该账号', command=self.add)
		self.add_button.pack(side='left', padx=8)
		self.status = tk.StringVar(value='填写已有 ANYROUTER_ACCOUNTS 中对应账号的 api_user，再添加登录态。')
		ttk.Label(root, textvariable=self.status, padding=10, wraplength=710).pack(anchor='w')
		self.listing = tk.Listbox(root, height=6)
		self.listing.pack(fill='x', padx=12)
		ttk.Label(
			root,
			text=f'Secret 名称：{SECRET}\n可先添加 GitHub，再添加 Linux DO，最后一次性复制。新内容会整体替换该 Secret。',
			padding=10,
		).pack(anchor='w')
		self.copy_button = ttk.Button(root, text='复制完整 Secret 到剪贴板', command=self.copy, state='disabled')
		self.copy_button.pack(pady=6)
		root.protocol('WM_DELETE_WINDOW', self.close)
		root.after(100, self.poll)

	def add(self):
		if self.busy:
			return
		api_user = self.api_user.get().strip()
		if not api_user.isdigit() or int(api_user) <= 0:
			messagebox.showerror('账号 ID', '请填写对应 Agentrouter 账号的数字 api_user。')
			return
		api_user = str(int(api_user))
		method = 'github' if self.method.get() == 'GitHub' else 'linuxdo'
		self.busy = True
		self.add_button.configure(state='disabled')
		self.copy_button.configure(state='disabled')
		self.status.set('正在离线读取指定测试浏览器配置，不访问网站、不保存明文登录态文件……')

		def worker():
			try:
				cookies = asyncio.run(read_profile(self.profile_root / method, self.edge))
				entry = {'provider': method, 'cookies': oauth_cookies(cookies, method)}
				export_payload({**self.accounts, api_user: entry})
				self.queue.put(('ok', api_user, entry))
			except Exception as exc:
				# Never expose driver exception text, which can contain cookie values.
				self.queue.put(('error', type(exc).__name__, None))

		threading.Thread(target=worker, daemon=True).start()

	def poll(self):
		while not self.queue.empty():
			kind, value, entry = self.queue.get_nowait()
			self.busy = False
			self.add_button.configure(state='normal')
			if kind == 'ok':
				self.accounts[value] = entry
				self.listing.delete(0, 'end')
				for account_id, state in self.accounts.items():
					self.listing.insert('end', f'{account_id} — {state["provider"]}')
				self.status.set('已添加。仅验证登录态格式；有效性与 CF 验证以 Actions 实际运行为准。')
			else:
				self.status.set(f'导出未完成（{value}）。请关闭测试工具/浏览器，并确认已在该平台的测试窗口完成登录。')
			self.copy_button.configure(state='normal' if self.accounts else 'disabled')
		self.root.after(100, self.poll)

	def copy(self):
		try:
			text = export_payload(self.accounts)
			self.root.clipboard_clear()
			self.root.clipboard_append(text)
			self.root.update_idletasks()
			self.copied = text
			self.status.set(
				'已复制。请粘贴到 production 的 AGENTROUTER_OAUTH_STATES Secret。保存后关闭本窗口，会清除仍属于本工具的剪贴板内容。'
			)
		except Exception:
			self.status.set('无法复制，请重新检查账号与登录态。')

	def close(self):
		if self.busy:
			messagebox.showinfo('正在读取', '请等待当前离线读取结束后关闭。')
			return
		try:
			if self.copied and self.root.clipboard_get() == self.copied:
				self.root.clipboard_clear()
		except tk.TclError:
			pass
		self.accounts.clear()
		self.root.destroy()


if __name__ == '__main__':
	root = tk.Tk()
	app = Exporter(root)
	if '--self-test' in sys.argv:
		root.withdraw()
		root.after(100, app.close)
	root.mainloop()
