import React, { useEffect, useRef, useState } from 'react';
import PropTypes from 'prop-types';
import { seafileAPI } from '@/api/seafile-api';
import { gettext } from '@/utils/constants';
import { Utils } from '@/utils/utils';

export default function ResourceAnnotations({ repoID, path, kind }) {
  const [snapshot, setSnapshot] = useState(null);
  const [description, setDescription] = useState('');
  const [labels, setLabels] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const generation = useRef(0);
  const writing = useRef(false);
  const reference = { repo_id: repoID, path, kind };

  useEffect(() => {
    const current = ++generation.current;
    setSnapshot(null);
    setError('');
    seafileAPI.cloudFileResolveAnnotations({ repo_id: repoID, path, kind }).then(({ data }) => {
      if (current !== generation.current) return;
      setSnapshot(data);
      setDescription(data.description);
      setLabels(data.tags.filter(tag => tag.kind === 'user').map(tag => tag.label).join('\n'));
    }).catch(err => {
      if (current === generation.current) setError(Utils.getErrorMsg(err));
    });
    return () => { generation.current = current + 1; };
  }, [repoID, path, kind]);

  const save = async operation => {
    if (writing.current || !snapshot?.access?.write) return;
    const current = generation.current;
    writing.current = true;
    setBusy(true);
    setError('');
    try {
      const key = window.crypto.randomUUID();
      if (operation === 'description') {
        await seafileAPI.cloudFileUpdateDescription(reference, snapshot.revision, description, key);
      } else {
        const values = labels.split('\n').map(label => label.trim().normalize('NFC')).filter(Boolean);
        if (values.length > 128 || values.some(label => label.length > 64) || new Set(values).size !== values.length) {
          throw new Error(gettext('Invalid tags'));
        }
        await seafileAPI.cloudFileReplaceUserTags(reference, snapshot.revision,
          values.map(label => ({ label })), key);
      }
      // Re-read current access and revision; do not replay a failed/unknown write.
      const { data } = await seafileAPI.cloudFileResolveAnnotations(reference);
      if (current !== generation.current) return;
      setSnapshot(data);
      // Saving one field must not discard the other field's unsaved draft.
      if (operation === 'description') {
        setDescription(data.description);
      } else {
        setLabels(data.tags.filter(tag => tag.kind === 'user').map(tag => tag.label).join('\n'));
      }
    } catch (err) {
      if (current === generation.current) setError(Utils.getErrorMsg(err));
    } finally {
      writing.current = false;
      setBusy(false);
    }
  };

  const writable = snapshot?.access?.write === true && !busy;
  return (
    <div className="detail-content p-3" aria-busy={busy}>
      {error && <div role="alert" className="text-danger">{error}</div>}
      {!snapshot && !error && <span>{gettext('Loading...')}</span>}
      {snapshot && (
        <>
          <label className="d-block">
            {gettext('Description')}
            <textarea className="form-control" value={description} maxLength={4096}
              disabled={!writable} onChange={event => setDescription(event.target.value)} />
          </label>
          <button type="button" className="btn btn-primary mb-3" disabled={!writable}
            onClick={() => save('description')}>{gettext('Save description')}
          </button>
          <div>{gettext('System tags')}</div>
          <ul>
            {snapshot.tags.filter(tag => tag.kind === 'system').map(tag => (
              <li key={tag.tag_id}>{tag.label}{!tag.enabled && ` (${gettext('Disabled')})`}</li>
            ))}
          </ul>
          <label className="d-block">
            {gettext('User tags (one per line)')}
            <textarea className="form-control" value={labels} disabled={!writable}
              onChange={event => setLabels(event.target.value)} />
          </label>
          <button type="button" className="btn btn-primary" disabled={!writable}
            onClick={() => save('tags')}>{gettext('Save tags')}
          </button>
        </>
      )}
    </div>
  );
}

ResourceAnnotations.propTypes = {
  repoID: PropTypes.string.isRequired,
  path: PropTypes.string.isRequired,
  kind: PropTypes.oneOf(['file', 'dir']).isRequired,
};
