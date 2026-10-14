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

  listDirectoryPolicy(repoID, path, domain = 'rules', after = null) {
    const url = this.server + '/api/v2.1/cloudfile/extensions/authorization/v1/directory-' + domain + '/';
    return this.req.get(url, { params: { repo_id: repoID, path, kind: 'dir', limit: 50, ...(after ? { after } : {}) } });
  }

  createDirectoryPolicy(reference, value, domain, requestKey) {
    const url = this.server + '/api/v2.1/cloudfile/extensions/authorization/v1/directory-' + domain + '/';
    return this.req.post(url, { reference, value }, { headers: { 'Idempotency-Key': requestKey } });
  }

  deleteDirectoryPolicy(reference, rule, domain, requestKey) {
    const url = this.server + '/api/v2.1/cloudfile/extensions/authorization/v1/directory-' + domain + '/' + rule.id + '/';
    return this.req.delete(url, { data: { reference }, headers: {
      'If-Match': rule.etag, 'Idempotency-Key': requestKey,
    } });
  }

  replaceDirectoryRule(reference, value, rule, requestKey) {
    const url = this.server + '/api/v2.1/cloudfile/extensions/authorization/v1/directory-rules/' + rule.id + '/';
    return this.req.put(url, { reference, value }, { headers: {
      'If-Match': rule.etag, 'Idempotency-Key': requestKey,
    } });
  }

  // Answers "why can this user not open that folder" -- inheritance across
  // levels and subject types is hard to read off the raw rule list.
  getEffectivePermission(repoID, path, user) {
    const url = this.server + '/api/v2.1/cloudfile/repos/' + repoID + '/dir-acl/effective/';
    return this.req.get(url, { params: { path: path, user: user } });
  }

  // -- file actions -------------------------------------------------------

  // The caller retains this key and original body through an unknown reply.
  // Retrying must never silently mint another Checkout or session identity.
  listLocalEditingDevices() {
    // Server checks current OIDC/CSRF actor and returns only owned active IDs.
    return this.req.post(this.server +
      '/api/v2.1/cloudfile/extensions/local-edit/v1/devices/list/', {});
  }

  startOrdinaryAgentEdit(reference, deviceID) {
    return this.req.post(this.server +
      '/api/v2.1/cloudfile/extensions/local-edit/v1/sessions/create/',
    { reference, device_id: deviceID, mode: 'optimistic-edit' });
  }

  startExclusiveEdit(reference, deviceID, baseFileID, requestKey) {
    if (typeof requestKey !== 'string' || !/^[\x21-\x7e]{1,128}$/.test(requestKey)) {
      return Promise.reject(new Error('Stable exclusive request key required'));
    }
    return this.req.post(this.server + '/api/v2.1/cloudfile/extensions/local-edit/v1/sessions/start-exclusive/', {
      reference, device_id: deviceID, base_file_id: baseFileID,
    }, { headers: { 'Idempotency-Key': requestKey } });
  }

  abandonExclusiveEdit(reference, deviceID, originalBaseFileID, checkout, requestKey) {
    if (typeof requestKey !== 'string' || !/^[\x21-\x7e]{1,128}$/.test(requestKey)) {
      return Promise.reject(new Error('Original exclusive request key required'));
    }
    return this.req.post(this.server + '/api/v2.1/cloudfile/extensions/local-edit/v1/sessions/abandon-exclusive/', {
      reference, device_id: deviceID, base_file_id: originalBaseFileID,
      guard_id: checkout.guard_id, generation: checkout.generation,
      credential_epoch: checkout.credential_epoch,
    }, { headers: { 'Idempotency-Key': requestKey } });
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
