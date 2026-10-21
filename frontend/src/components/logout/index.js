import React from 'react';
import PropTypes from 'prop-types';
import { siteRoot, gettext } from '@/utils/constants';
import Icon from '../icon';

export default function Logout({ className = 'logout-icon sf-icon-color-mode border-0 bg-transparent p-0', children }) {
  return <a className={className} href={`${siteRoot}accounts/logout/`} title={gettext('Log out')}>{children || <Icon symbol="logout" />}</a>;
}
Logout.propTypes = { className: PropTypes.string, children: PropTypes.node };
