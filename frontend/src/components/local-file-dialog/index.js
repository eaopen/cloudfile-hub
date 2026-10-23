import React, { useEffect, useRef, useState } from 'react';
import PropTypes from 'prop-types';
import { Modal, ModalHeader, ModalBody, Button } from 'reactstrap';
import { cloudFileAPI } from '@/cloudfile/cloudfile-api';
import { openV2LocalFile } from '@/cloudfile/agent-local-edit';
import { gettext } from '@/utils/constants';

// Shared by the library selection toolbar and the file preview toolbar.
// Permission props are presentation hints only; Hub/Server authorize each ticket.
export default function LocalFileDialog({ repoID, path, permission, readOnly = false, onClose, onOpen = openV2LocalFile }) {
  const [checkout, setCheckout] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const launching = useRef(false);
  const canRead = permission === 'r' || permission === 'rw';
  const canWrite = permission === 'rw' && !readOnly;

  useEffect(() => {
    let active = true;
    setCheckout(null);
    if (canRead) {
      cloudFileAPI.getLocalCheckoutInfo(repoID, path).then(response => {
        if (active) setCheckout(response.data);
      }).catch(() => {
        // Unknown Guard capability disables only exclusive editing.
        if (active) setCheckout(null);
      });
    }
    return () => { active = false; };
  }, [repoID, path, canRead]);

  const locked = checkout?.checked_out === true;
  const exclusive = checkout?.checkout_supported === true && checkout?.checked_out === false;
  const launch = async mode => {
    if (launching.current || !canRead || (mode !== 'local-view' && (!canWrite || locked)) ||
        (mode === 'exclusive-edit' && !exclusive)) return;
    launching.current = true;
    setBusy(true);
    setError('');
    try {
      await onOpen({ repoID, path, mode });
      onClose();
    } catch (e) {
      // No V1/download/ordinary-edit fallback, and no automatic ticket retry.
      const code = e.response?.data?.code;
      setError(code === 'VIEW_DENIED' || code === 'EDIT_DENIED' || e.response?.status === 403
        ? gettext('Access denied. Refresh the page to check your permissions.')
        : code === 'CHECKOUT_UNSUPPORTED'
          ? gettext('Exclusive editing is unavailable. You can choose ordinary editing.')
          : gettext('Local operation was not confirmed. Check the Agent2 task center before trying again.'));
    } finally {
      launching.current = false;
      setBusy(false);
    }
  };

  return (
    <Modal isOpen toggle={busy ? undefined : onClose}>
      <ModalHeader toggle={busy ? undefined : onClose}>{gettext('Local file operations')}</ModalHeader>
      <ModalBody>
        <p className="text-break">{path}</p>
        <div className="d-flex flex-wrap">
          <Button className="mr-2 mb-2" disabled={busy || !canRead} onClick={() => launch('local-view')}>
            {gettext('View locally')}
          </Button>
          <Button className="mr-2 mb-2" disabled={busy || !canWrite || locked} onClick={() => launch('optimistic-edit')}>
            {gettext('Edit locally')}
          </Button>
          <Button className="mb-2" disabled={busy || !canWrite || locked || !exclusive} onClick={() => launch('exclusive-edit')}>
            {gettext('Edit exclusively')}
          </Button>
        </div>
        <p>{gettext('Local viewing never uploads changes. Ordinary editing publishes saved changes automatically. Exclusive editing requires Commit or Checkin in Agent2 to publish; saving locally does not confirm a cloud version.')}</p>
        {!canWrite && <p>{gettext('Editing requires write permission and a writable library.')}</p>}
        {locked && <p role="status">{gettext('This file is checked out. Use the existing Agent2 task to continue; local viewing remains available.')}</p>}
        {canWrite && !locked && !exclusive && <p role="status">{gettext('Checkout is unavailable or has not been confirmed. Ordinary editing remains available.')}</p>}
        {error && <p role="alert" className="text-danger">{error}</p>}
      </ModalBody>
    </Modal>
  );
}

LocalFileDialog.propTypes = {
  repoID: PropTypes.string.isRequired,
  path: PropTypes.string.isRequired,
  permission: PropTypes.string,
  readOnly: PropTypes.bool,
  onClose: PropTypes.func.isRequired,
  onOpen: PropTypes.func,
};
