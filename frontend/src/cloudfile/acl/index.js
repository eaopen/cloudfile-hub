import React from 'react';
import { createRoot } from 'react-dom/client';
import { gettext } from '../../utils/constants';
import { loadFeatures, isEnabled } from '../features';
import DirACLPanel from './dir-acl-panel';

const query = new URLSearchParams(window.location.search);
const repoID = query.get('repo_id') || '';
const path = query.get('path') || '/';

/*
 * Entry point for the directory ACL page.
 *
 * The feature check here only decides what to render; it is not what enforces
 * the rules. Enforcement lives in seahub's check_folder_permission and, below
 * that, in seafile-server -- so hiding this page does not grant anyone access
 * and showing it does not bypass anything.
 */
loadFeatures().then(() => {
  const root = createRoot(document.getElementById('wrapper'));
  if (!isEnabled('CF_ENABLE_DIR_ACL')) {
    root.render(<p>{gettext('Directory permissions are not enabled on this server.')}</p>);
    return;
  }
  if (!repoID) {
    root.render(<p>{gettext('A library ID is required.')}</p>);
    return;
  }
  root.render(<DirACLPanel repoID={repoID} path={path || '/'} />);
});
