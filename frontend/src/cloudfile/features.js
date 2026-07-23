import { cloudFileAPI } from './cloudfile-api';

/*
 * CloudFile feature switches, fetched once per page load.
 *
 * These come from an API call rather than a template variable because Seahub's
 * TEMPLATES context_processors list is nested inside a dict, which the EXTRA_*
 * settings mechanism cannot append to. Reading them here keeps the number of
 * patched upstream files at two.
 *
 * This is only for hiding entry points the deployment does not have. It is NOT
 * a security boundary: every switch is re-checked server side, and directory
 * ACL is enforced all the way down in seafile-server.
 */

let cachedFeatures = null;
let pendingRequest = null;

export function loadFeatures() {
  if (cachedFeatures) {
    return Promise.resolve(cachedFeatures);
  }
  if (!pendingRequest) {
    pendingRequest = cloudFileAPI.getFeatures().then((res) => {
      cachedFeatures = res.data.features;
      pendingRequest = null;
      return cachedFeatures;
    }).catch(() => {
      // An older server, or one without cloudfile_ext, has no such endpoint.
      // Treat that as "nothing enabled" so the UI degrades to native CE.
      cachedFeatures = {};
      pendingRequest = null;
      return cachedFeatures;
    });
  }
  return pendingRequest;
}

export function isEnabled(name) {
  return Boolean(cachedFeatures && cachedFeatures[name]);
}
