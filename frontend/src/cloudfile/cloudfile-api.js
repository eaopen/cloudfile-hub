import axios from 'axios';
import Cookies from 'js-cookie';
import FormData from 'form-data';
import { siteRoot } from '../utils/constants';

class CloudFileAPI {

  initForSeahubUsage({ siteRoot, xcsrfHeaders }) {
    if (siteRoot && siteRoot.charAt(siteRoot.length - 1) === '/') {
      this.server = siteRoot.substring(0, siteRoot.length - 1);
    } else {
      this.server = siteRoot;
    }

    this.req = axios.create({
      headers: {
        'X-CSRFToken': xcsrfHeaders,
      }
    });
    return this;
  }

  // -- feature switches ---------------------------------------------------

  getFeatures() {
    const url = this.server + '/api/v2.1/cloudfile/features/';
    return this.req.get(url);
  }

  // -- directory ACL ------------------------------------------------------

  listDirACL(repoID, path) {
    const url = this.server + '/api/v2.1/cloudfile/repos/' + repoID + '/dir-acl/';
    return this.req.get(url, { params: { path: path } });
  }

  setDirACL(repoID, path, subjectType, subject, permission, inherit) {
    const url = this.server + '/api/v2.1/cloudfile/repos/' + repoID + '/dir-acl/';
    const form = new FormData();
    form.append('path', path);
    form.append('subject_type', subjectType);
    form.append('subject', subject);
    form.append('permission', permission);
    form.append('inherit', inherit ? 'true' : '');
    return this.req.post(url, form);
  }

  deleteDirACL(repoID, path, subjectType, subject) {
    const url = this.server + '/api/v2.1/cloudfile/repos/' + repoID + '/dir-acl/';
    return this.req.delete(url, {
      params: { path: path, subject_type: subjectType, subject: subject }
    });
  }

  // Answers "why can this user not open that folder" -- inheritance across
  // levels and subject types is hard to read off the raw rule list.
  getEffectivePermission(repoID, path, user) {
    const url = this.server + '/api/v2.1/cloudfile/repos/' + repoID + '/dir-acl/effective/';
    return this.req.get(url, { params: { path: path, user: user } });
  }
}

let cloudFileAPI = new CloudFileAPI();
let xcsrfHeaders = Cookies.get('sfcsrftoken');
cloudFileAPI.initForSeahubUsage({ siteRoot, xcsrfHeaders });

export { cloudFileAPI };
