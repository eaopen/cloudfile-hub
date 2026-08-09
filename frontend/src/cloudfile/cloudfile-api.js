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

  // -- file actions -------------------------------------------------------

  getFileActions(repoID, path) {
    const url = this.server + '/api/v2.1/cloudfile/repos/' + repoID + '/file-actions/';
    return this.req.get(url, { params: { path: path } });
  }

  createLocalSession(repoID, path, mode = 'local-view') {
    const url = this.server + '/api/v2.1/cloudfile/repos/' + repoID + '/local-sessions/';
    return this.req.post(url, { path: path, mode: mode });
  }

  checkoutFile(repoID, path, source = 'manual') {
    const url = this.server + '/api/v2.1/cloudfile/repos/' + repoID + '/checkout/';
    return this.req.post(url, { path: path, source: source });
  }

  releaseCheckout(repoID, path, generation) {
    const url = this.server + '/api/v2.1/cloudfile/repos/' + repoID + '/checkout/';
    return this.req.delete(url, { data: { path: path, generation: generation } });
  }

  // -- external sources ---------------------------------------------------

  listExternalSources() {
    return this.req.get(this.server + '/api/v2.1/cloudfile/external-sources/');
  }

  listExternalSourceDir(sourceID, path = '/') {
    return this.req.get(this.server + '/api/v2.1/cloudfile/external-sources/' + sourceID + '/dir/', {
      params: { p: path }
    });
  }

  externalSourceDownloadUrl(sourceID, path) {
    return this.server + '/api/v2.1/cloudfile/external-sources/' + sourceID + '/file/?' +
      new URLSearchParams({ p: path, op: 'download' }).toString();
  }

  searchExternalSources(query) {
    return this.req.get(this.server + '/api/v2.1/cloudfile/external-sources/search/', {
      params: { q: query }
    });
  }

  listAdminExternalSources() {
    return this.req.get(this.server + '/api/v2.1/admin/cloudfile/external-sources/');
  }

  createExternalSource(payload) {
    return this.req.post(this.server + '/api/v2.1/admin/cloudfile/external-sources/', payload);
  }

  updateExternalSource(sourceID, payload) {
    return this.req.put(this.server + '/api/v2.1/admin/cloudfile/external-sources/' + sourceID + '/', payload);
  }

  deleteExternalSource(sourceID) {
    return this.req.delete(this.server + '/api/v2.1/admin/cloudfile/external-sources/' + sourceID + '/');
  }

  listExternalSourceGrants(sourceID) {
    return this.req.get(this.server + '/api/v2.1/admin/cloudfile/external-sources/' + sourceID + '/grants/');
  }

  grantExternalSource(sourceID, payload) {
    return this.req.post(this.server + '/api/v2.1/admin/cloudfile/external-sources/' + sourceID + '/grants/', payload);
  }

  revokeExternalSourceGrant(sourceID, subjectType, subject) {
    return this.req.delete(this.server + '/api/v2.1/admin/cloudfile/external-sources/' + sourceID + '/grants/', {
      params: { subject_type: subjectType, subject: subject }
    });
  }

}

let cloudFileAPI = new CloudFileAPI();
let xcsrfHeaders = Cookies.get('sfcsrftoken');
cloudFileAPI.initForSeahubUsage({ siteRoot, xcsrfHeaders });

export { cloudFileAPI };
