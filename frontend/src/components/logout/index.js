import React, { useRef, useState } from 'react';
import PropTypes from 'prop-types';
import { seafileAPI } from '@/api/seafile-api';
import { siteRoot, gettext, cloudFileWebEnabled } from '@/utils/constants';
import { Utils } from '@/utils/utils';
import Icon from '../icon';
import toaster from '../toast';

export default function Logout({ className = 'logout-icon sf-icon-color-mode border-0 bg-transparent p-0', children, onLoggedOut = () => window.location.assign(siteRoot + 'accounts/login/') }) {
  const pending = useRef(false);
  const [busy, setBusy] = useState(false);
  const label = children || <Icon symbol="logout" />;
  const logout = async () => {
    if (pending.current) return;
    pending.current = true;
    setBusy(true);
    try {
      await seafileAPI.cloudFileLogout();
      onLoggedOut();
    } catch (error) {
      toaster.danger(Utils.getErrorMsg(error));
      pending.current = false;
      setBusy(false);
    }
  };
  if (!cloudFileWebEnabled) {
    return <a className={className} href={`${siteRoot}accounts/logout/`} title={gettext('Log out')}>{label}</a>;
  }
  return <button type="button" className={className} onClick={logout} disabled={busy} title={gettext('Log out')}>{label}</button>;
}

Logout.propTypes = {
  className: PropTypes.string,
  children: PropTypes.node,
  onLoggedOut: PropTypes.func,
};
