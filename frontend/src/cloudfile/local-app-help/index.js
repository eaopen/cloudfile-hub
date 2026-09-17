import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { gettext } from '../../utils/constants';
import { loadFeatures, isEnabled } from '../features';

import './index.css';

const EXTENSION_ID = 'nafehcgbhfodbocmoghcigmfgjneogom';

function ExtensionStatus() {
  const [status, setStatus] = useState('checking'); // checking | installed | missing | blocked
  const [message, setMessage] = useState('');

  useEffect(() => {
    const runtime = window.chrome && window.chrome.runtime;
    if (!runtime || typeof runtime.sendMessage !== 'function') {
      setStatus('missing');
      return;
    }
    // 用一次空消息探测扩展是否可达；不可达时 Chrome 置 lastError 并固定为
    // "Could not establish connection. Receiving end does not exist."
    runtime.sendMessage(EXTENSION_ID, { type: 'ping' }, () => {
      if (runtime.lastError) {
        const msg = (runtime.lastError && runtime.lastError.message) || '';
        if (/receiving end does not exist/i.test(msg)) {
          setStatus('missing');
        } else {
          setStatus('blocked');
          setMessage(msg);
        }
      } else {
        setStatus('installed');
      }
    });
  }, []);

  if (status === 'checking') {
    return <p className="cf-help-status is-checking">{gettext('正在检测扩展…')}</p>;
  }
  if (status === 'installed') {
    return <p className="cf-help-status is-ok">{gettext('✅ 已检测到扩展，本地打开功能可用。')}</p>;
  }
  if (status === 'missing') {
    return <p className="cf-help-status is-missing">{gettext('⚠ 未检测到扩展，请按下方步骤安装。')}</p>;
  }
  return <p className="cf-help-status is-missing">{gettext('⚠ 无法连接扩展：')}{message}</p>;
}

function Step({ index, title, children }) {
  return (
    <li className="cf-help-step">
      <span className="cf-help-step__index">{index}</span>
      <div>
        <h3>{title}</h3>
        <div className="cf-help-step__body">{children}</div>
      </div>
    </li>
  );
}

function Code({ children }) {
  return <code className="cf-help-code">{children}</code>;
}

function LocalAppHelp() {
  return (
    <main className="cf-help-shell">
      <header className="cf-help-hero">
        <span className="cf-help-eyebrow">CLOUDFILE / LOCAL APP</span>
        <h1>{gettext('安装本地打开组件')}</h1>
        <p>{gettext('要使用「本地查看 / 本地编辑」，需要在浏览器安装扩展，并在本机注册 Native Messaging Agent。')}</p>
      </header>

      <ExtensionStatus />

      <section className="cf-help-section">
        <h2>{gettext('第一步：安装 Chrome 扩展')}</h2>
        <ol className="cf-help-steps">
          <Step index="1" title={gettext('获取扩展文件')}>
            <p>{gettext('联系管理员获取 cloudfile-chrome-extension 扩展目录，或从 CloudFile 发布包中解压得到。')}</p>
          </Step>
          <Step index="2" title={gettext('打开扩展管理页')}>
            <p>{gettext('在 Chrome 地址栏输入 ')}<Code>chrome://extensions</Code>{gettext(' 并回车。')}</p>
          </Step>
          <Step index="3" title={gettext('启用开发者模式')}>
            <p>{gettext('打开页面右上角的「开发者模式」开关。')}</p>
          </Step>
          <Step index="4" title={gettext('加载扩展')}>
            <p>{gettext('点击「加载已解压的扩展程序」，选择扩展所在目录（包含 manifest.json 的那一层）。')}</p>
          </Step>
          <Step index="5" title={gettext('记录扩展 ID')}>
            <p>{gettext('加载后，扩展卡片上会显示一个 ID，例如 ')}<Code>{EXTENSION_ID}</Code>{gettext('，后面注册 Agent 时要用到。')}</p>
          </Step>
        </ol>
      </section>

      <section className="cf-help-section">
        <h2>{gettext('第二步：安装本地 Agent')}</h2>
        <ol className="cf-help-steps">
          <Step index="1" title={gettext('获取 Agent 绿色包')}>
            <p>{gettext('联系管理员获取 cloudfile-local-agent 绿色包（单文件 exe，无需安装运行时）。')}</p>
          </Step>
          <Step index="2" title={gettext('运行注册脚本（Windows）')}>
            <p>{gettext('在 PowerShell 中执行：')}</p>
            <Code>.\scripts\register-windows.ps1 -ExtensionId {EXTENSION_ID} -ServerOrigin http://10.9.8.162:6111</Code>
            <p>{gettext('该脚本会写入 Native Messaging Host 注册表项，并把站点加入信任 origin。')}</p>
          </Step>
          <Step index="3" title={gettext('（可选）手动信任站点')}>
            <p>{gettext('也可以直接运行 Agent 信任你的 CloudFile 站点：')}</p>
            <Code>.\cloudfile-local-agent.exe --allow-origin http://10.9.8.162:6111</Code>
          </Step>
          <Step index="4" title={gettext('验证安装')}>
            <p>{gettext('点击浏览器工具栏上的 CloudFile 扩展图标，看到「Agent 已就绪」即安装成功。')}</p>
          </Step>
        </ol>
      </section>

      <aside className="cf-help-note">
        {gettext('安全说明：扩展不读取 Cookie、不访问 localhost、不保存 Seafile Token；Agent 仅接收一次性短命会话票据，并独立校验受信任站点 origin。')}
      </aside>
    </main>
  );
}

loadFeatures().then(() => {
  const root = createRoot(document.getElementById('wrapper'));
  if (!isEnabled('CF_ENABLE_LOCAL_APP')) {
    root.render(<p>{gettext('本地打开功能未在此服务器上启用。')}</p>);
    return;
  }
  root.render(<LocalAppHelp />);
});
