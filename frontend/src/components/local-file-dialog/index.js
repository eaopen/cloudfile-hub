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
  const [lockUnknown, setLockUnknown] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const launching = useRef(false);
  const canRead = permission === 'r' || permission === 'rw';
  const canWrite = permission === 'rw' && !readOnly;

  useEffect(() => {
    let active = true;
    setCheckout(null);
    setLockUnknown(false);
    if (canRead) {
      cloudFileAPI.getLocalCheckoutInfo(repoID, path).then(response => {
        if (!active) return;
        const data = response?.data;
        if (data && typeof data.checkout_supported === 'boolean' &&
            typeof data.checked_out === 'boolean' &&
            (data.checkout_supported || !data.checked_out)) {
          setCheckout(data);
        } else {
          // A partial/unknown response must not be mistaken for an OFF library.
          setCheckout(null);
          setLockUnknown(true);
        }
      }).catch(() => {
        // Unknown is not "unlocked": disable new write tasks (including ordinary
        // editing) until the lock state can be confirmed again.
        if (active) {
          setCheckout(null);
          setLockUnknown(true);
        }
      });
    }
    return () => { active = false; };
  }, [repoID, path, canRead]);

  const checkedOut = checkout?.checked_out === true;
  const checkedOutByMe = checkedOut && checkout?.checked_out_by_me === true;
  const locked = checkedOut && !checkedOutByMe;
  const exclusive = canWrite && !lockUnknown && checkout?.checkout_supported === true && !checkedOut;
  // Pending lock-info is not a confirmed unlocked state. Never launch a
  // write task before the first authoritative response has arrived.
  const canEditNormally = canWrite && checkout?.checked_out === false && !lockUnknown;
  const canResume = canWrite && checkedOutByMe && !lockUnknown;
  const launch = async mode => {
    const allowed = mode === 'local-view'
      ? canRead
      : mode === 'optimistic-edit'
        ? canEditNormally
        : canResume || exclusive;
    if (launching.current || !allowed) return;
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
          <Button className="mr-2 mb-2" disabled={busy || !canEditNormally} onClick={() => launch('optimistic-edit')}>
            {gettext('Edit locally')}
          </Button>
          <Button className="mb-2" disabled={busy || !(exclusive || canResume)} onClick={() => launch('exclusive-edit')}>
            {canResume ? gettext('Resume exclusive editing') : gettext('Edit exclusively')}
          </Button>
        </div>
        <p>{gettext('Local viewing never uploads changes. Ordinary editing publishes saved changes automatically. Exclusive editing requires Commit or Checkin in Agent2 to publish; saving locally does not confirm a cloud version.')}</p>
        {!canWrite && <p>{gettext('Editing requires write permission and a writable library.')}</p>}
        {lockUnknown && <p role="status">{gettext('The lock state could not be confirmed. Editing is disabled until the service is restored; local viewing remains available.')}</p>}
        {checkedOutByMe && <p role="status">{gettext('You have checked out this file. Resume the existing Agent2 task to continue; local viewing remains available.')}</p>}
        {locked && <p role="status">{gettext('This file is checked out by another user. Use the existing Agent2 task to continue; local viewing remains available.')}</p>}
        {canWrite && !lockUnknown && !checkedOut && !exclusive && <p role="status">{gettext('Checkout is unavailable or has not been confirmed. Ordinary editing remains available.')}</p>}
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
