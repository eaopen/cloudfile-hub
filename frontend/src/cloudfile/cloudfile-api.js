import axios from 'axios';
import Cookies from 'js-cookie';
import { siteRoot } from '@/utils/constants';

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

  listDirectoryPolicy(repoID, path) {
    return this.req.get(this.server + '/api/v2.1/cloudfile/authorization/v1/directory-rules/',
      { params: { repo_id: repoID, path } });
  }

  writeDirectoryRule(rule, remove = false) {
    const url = this.server + '/api/v2.1/cloudfile/authorization/v1/directory-rules/';
    return remove ? this.req.delete(url, { data: rule }) : this.req.post(url, rule);
  }

  // -- file actions -------------------------------------------------------

  // V2 Agent2: the Hub issues one short-lived scoped JWT from the browser
  // session. Agent2 keeps its own Journal; no Device, Session or Intent SQL.
  openLocalFile(repoID, path, mode = 'optimistic-edit') {
    if (!['local-view', 'optimistic-edit', 'exclusive-edit'].includes(mode)) {
      return Promise.reject(new Error('Unsupported V2 local edit mode'));
    }
    return this.req.post(this.server + '/api/v2.1/cloudfile/edit/v1/open/',
      { repo_id: repoID, path, mode });
  }

  getLocalCheckoutInfo(repoID, path) {
    return this.req.get(this.server + '/api/v2.1/cloudfile/edit/v1/lock-info/',
      { params: { repo_id: repoID, path } });
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
